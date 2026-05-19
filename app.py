"""
app.py - Servidor Flask para DiamondEye Threat Intelligence Dashboard
=====================================================================

Flujo de comunicacion Frontend <-> Backend:

    [Usuario] -> Sube .txt -> [main.js] POST /api/escanear -> [app.py]
    1. app.py recibe el archivo, lo guarda temporalmente
    2. Crea un task_id UUID unico
    3. Lanza un hilo (threading.Thread) para procesar las IPs
    4. Retorna INMEDIATAMENTE { "task_id": "uuid" } al frontend
    ----------------------------------------------------------------
    [main.js] -> cada 2s: GET /api/estado/<task_id> -> [app.py]
    5. El hilo worker actualiza tasks[task_id]["progress"] en cada IP
    6. app.py devuelve el progreso actual al frontend
    7. main.js actualiza la barra de progreso en el DOM
    ----------------------------------------------------------------
    [main.js] -> recibe status="done" -> [Chart.js + Tabla]
    8. El hilo worker termino, tasks[task_id]["status"] = "done"
    9. frontend recibe resultados y dibuja grafica + tabla
"""

import os
import uuid
import time
import json
import logging
import threading
import tempfile
from typing import Dict, Any, List
from datetime import datetime

from flask import Flask, request, jsonify, render_template

from bot import (
    DatabaseManager,
    VTClient,
    cargar_api_key,
    cargar_objetivos,
    crear_sesion_retry,
)

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger("app")

app = Flask(__name__)

# ─── Diccionario global de tareas asincronas ──────────────────────────────────
# Cada tarea almacena: status, progress, total, results, metadata, error
# El acceso concurrente se protege con tasks_lock
tasks: Dict[str, Dict[str, Any]] = {}
tasks_lock = threading.Lock()


def escanear_worker(task_id: str, filepath: str) -> None:
    """
    Hilo worker que ejecuta el escaneo de IPs en segundo plano.
    Va actualizando tasks[task_id] a medida que procesa cada IP.
    """
    global tasks

    try:
        api_key = cargar_api_key()
        ips = cargar_objetivos(filepath)

        if not ips:
            with tasks_lock:
                tasks[task_id]["status"] = "error"
                tasks[task_id]["error"] = (
                    "El archivo no contiene IPs validas para escanear."
                )
            return

        with tasks_lock:
            tasks[task_id]["total"] = len(ips)

        db_manager = DatabaseManager()
        sesion = crear_sesion_retry()
        vt_client = VTClient(api_key, sesion)

        resultados: List[Dict[str, Any]] = []

        for idx, ip in enumerate(ips, start=1):
            with tasks_lock:
                tasks[task_id]["progress"] = idx

            logger.info("[%d/%d] Procesando %s...", idx, len(ips), ip)

            # 1. Consultar cache SQLite (TTL 7 dias)
            cached_count = db_manager.get_cached(ip)

            if cached_count is not None:
                # Cache hit
                estado = "malicious" if cached_count > 0 else "clean"
                resultados.append({
                    "ip": ip,
                    "status": estado,
                    "malicious_count": cached_count,
                    "date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                })
            else:
                # Cache miss -> consultar VirusTotal
                estado, malicious_count = vt_client.consultar(ip)

                if estado not in ("bogon", "error"):
                    db_manager.set_cached(ip, malicious_count)

                resultados.append({
                    "ip": ip,
                    "status": estado,
                    "malicious_count": malicious_count if estado == "malicious" else 0,
                    "date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                })

            # Delay entre consultas para respetar rate limits de VT
            if idx < len(ips):
                time.sleep(15)

        db_manager.close()

        total = len(resultados)
        clean_count = sum(1 for r in resultados if r["status"] == "clean")
        malicious_count = sum(1 for r in resultados if r["status"] == "malicious")
        bogon_count = sum(1 for r in resultados if r["status"] == "bogon")
        error_count = sum(1 for r in resultados if r["status"] == "error")

        metadata = {
            "scan_date": datetime.now().isoformat(),
            "total": total,
            "clean": clean_count,
            "malicious": malicious_count,
            "bogons": bogon_count,
            "errors": error_count,
        }

        with tasks_lock:
            tasks[task_id]["status"] = "done"
            tasks[task_id]["results"] = resultados
            tasks[task_id]["metadata"] = metadata

        logger.info(
            "Escaneo %s completado: %d IPs (%d limpias, %d maliciosas, %d bogons, %d errores)",
            task_id[:8], total, clean_count, malicious_count, bogon_count, error_count,
        )

    except Exception as e:
        logger.error("Error en escaneo worker [%s]: %s", task_id[:8], str(e))
        with tasks_lock:
            tasks[task_id]["status"] = "error"
            tasks[task_id]["error"] = str(e)

    finally:
        try:
            if os.path.exists(filepath):
                os.unlink(filepath)
        except OSError:
            pass


# ─── Rutas ───────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    """Renderiza el dashboard HTML principal."""
    return render_template("index.html")


@app.route("/api/escanear", methods=["POST"])
def iniciar_escaneo():
    """
    Recibe un archivo .txt, crea una tarea asincrona y retorna el task_id.
    El frontend usara este task_id para hacer polling del progreso.
    """
    if "file" not in request.files:
        return jsonify({"error": "No se envio ningun archivo"}), 400

    file = request.files["file"]

    if file.filename == "" or file.filename is None:
        return jsonify({"error": "Ningun archivo seleccionado"}), 400

    if not file.filename.lower().endswith(".txt"):
        return jsonify({"error": "Solo se permiten archivos .txt"}), 400

    try:
        tmp = tempfile.NamedTemporaryFile(suffix=".txt", delete=False, mode="wb")
        file.save(tmp.name)
        tmp.close()
        logger.info("Archivo recibido: %s -> %s", file.filename, tmp.name)
    except OSError as e:
        logger.error("Error al guardar archivo temporal: %s", str(e))
        return jsonify({"error": "Error interno al procesar el archivo"}), 500

    task_id = str(uuid.uuid4())

    with tasks_lock:
        tasks[task_id] = {
            "status": "running",
            "progress": 0,
            "total": 0,
            "results": [],
            "metadata": {},
            "error": None,
        }

    thread = threading.Thread(target=escanear_worker, args=(task_id, tmp.name))
    thread.daemon = True
    thread.start()

    logger.info("Tarea %s iniciada con %d IP(s)", task_id[:8], 0)
    return jsonify({"task_id": task_id})


@app.route("/api/estado/<task_id>")
def consultar_estado(task_id: str):
    """
    Endpoint de polling para que el frontend consulte el progreso.
    Retorna el estado actual de la tarea.
    """
    with tasks_lock:
        task = tasks.get(task_id)

    if task is None:
        return jsonify({"error": "Task ID no encontrado"}), 404

    if task["status"] == "running":
        return jsonify({
            "status": "running",
            "progress": task["progress"],
            "total": task["total"],
        })
    elif task["status"] == "done":
        return jsonify({
            "status": "done",
            "results": task["results"],
            "metadata": task["metadata"],
        })
    elif task["status"] == "error":
        return jsonify({
            "status": "error",
            "error": task["error"],
        })

    return jsonify({"error": "Estado desconocido"}), 500


if __name__ == "__main__":
    logger.info("=" * 55)
    logger.info("  DiamondEye Threat Intelligence Dashboard v3.0")
    logger.info("  Servidor: http://127.0.0.1:5000")
    logger.info("=" * 55)
    app.run(host="127.0.0.1", port=5000, debug=False, threaded=True)
