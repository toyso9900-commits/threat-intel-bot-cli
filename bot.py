"""
bot.py - Threat Intel Bot CLI v3.0 Enterprise
Refactorización completa con caché SQLite, filtro bogon, exportación dual JSON/CSV,
graceful shutdown, webhooks y tipado estricto.
"""

import os
import sys
import csv
import json
import signal
import sqlite3
import argparse
import ipaddress
import logging
import time
from typing import List, Dict, Tuple, Optional, Any
from datetime import datetime, timedelta
from collections import Counter

import requests
from dotenv import load_dotenv
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


logger = logging.getLogger("threatintel")

# Variable global para graceful shutdown
shutdown_flag: bool = False


def manejador_shutdown(signum: int, frame: Any) -> None:
    global shutdown_flag
    shutdown_flag = True
    logger.critical(
        "Señal SIGINT recibida. Finalizando escaneo de forma controlada..."
    )


def configurar_logging(verbose: bool = False) -> None:
    nivel = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=nivel,
        format="%(levelname)s: %(message)s",
        handlers=[logging.StreamHandler(sys.stdout)],
    )


def crear_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Threat Intel Bot CLI v3.0 Enterprise - Consulta VirusTotal por IP"
    )
    parser.add_argument(
        "--input",
        default="objetivos.txt",
        help="Archivo con lista de IPs (default: objetivos.txt)",
    )
    parser.add_argument(
        "--output",
        default="reporte_alertas.csv",
        help="Archivo de salida CSV o JSON (default: reporte_alertas.csv)",
    )
    parser.add_argument(
        "--delay",
        type=int,
        default=15,
        help="Segundos de espera entre consultas (default: 15)",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Activar logs de depuracion (DEBUG)",
    )
    parser.add_argument(
        "--format",
        choices=["csv", "json"],
        default="csv",
        help="Formato de exportacion: csv o json (default: csv)",
    )
    parser.add_argument(
        "--webhook",
        type=str,
        default=None,
        help="URL de webhook para alertas criticas (malicious_count >= 5)",
    )
    return parser


def cargar_api_key() -> str:
    load_dotenv()
    api_key = os.getenv("VIRUSTOTAL_API_KEY")

    if not api_key:
        logger.critical("No se encontro VIRUSTOTAL_API_KEY en el archivo .env")
        logger.critical("Crea un archivo .env con: VIRUSTOTAL_API_KEY=\"tu_api_key\"")
        sys.exit(1)

    logger.debug("API Key cargada exitosamente")
    return api_key


def cargar_objetivos(ruta: str) -> List[str]:
    ruta_abs = os.path.abspath(ruta)
    logger.info("Leyendo IPs desde %s", ruta_abs)

    try:
        with open(ruta, "r") as f:
            raw = [linea.strip() for linea in f if linea.strip()]
    except FileNotFoundError:
        logger.critical("No se encontro el archivo '%s'", ruta)
        logger.critical("Crea el archivo con una IP por linea")
        sys.exit(1)

    if not raw:
        logger.warning("El archivo '%s' esta vacio", ruta)
        return []

    validas: List[str] = []
    invalidas: int = 0
    for linea in raw:
        try:
            ipaddress.ip_address(linea)
            validas.append(linea)
        except ValueError:
            logger.warning("'%s' no es una IP valida, se omite", linea)
            invalidas += 1

    if invalidas > 0:
        logger.info("%d linea(s) invalida(s) omitidas", invalidas)

    dups = [ip for ip, count in Counter(validas).items() if count > 1]
    if dups:
        for ip in dups:
            logger.warning(
                "IP duplicada encontrada: %s (%d veces)", ip, Counter(validas)[ip]
            )
        validas = list(dict.fromkeys(validas))
        logger.info("Duplicados eliminados, quedan %d IP(s) unicas", len(validas))

    logger.info("Se cargaron %d IP(s) validas", len(validas))
    return validas


def crear_sesion_retry(
    total_retries: int = 3,
    backoff_factor: float = 2.0,
) -> requests.Session:
    sesion = requests.Session()

    retry = Retry(
        total=total_retries,
        read=total_retries,
        connect=total_retries,
        backoff_factor=backoff_factor,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET"],
        raise_on_status=False,
    )

    adapter = HTTPAdapter(max_retries=retry)
    sesion.mount("https://", adapter)
    sesion.mount("http://", adapter)

    return sesion


class DatabaseManager:
    """Maneja la caché local SQLite con TTL de 7 dias."""

    def __init__(self, db_path: str = "intel_cache.db") -> None:
        self.db_path: str = db_path
        self.conn: sqlite3.Connection
        try:
            self.conn = sqlite3.connect(db_path)
            self._crear_tabla()
            logger.debug("Base de datos SQLite inicializada: %s", db_path)
        except sqlite3.Error as e:
            logger.error("Error al conectar con SQLite: %s", e)
            raise

    def _crear_tabla(self) -> None:
        cursor = self.conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS intel_cache (
                ip TEXT PRIMARY KEY,
                malicious_count INTEGER NOT NULL,
                last_checked DATETIME NOT NULL
            )
        """)
        self.conn.commit()

    def get_cached(self, ip: str) -> Optional[int]:
        """
        Busca la IP en caché. Si existe y el TTL de 7 días es válido,
        retorna malicious_count. Si no existe o expiró, retorna None.
        """
        try:
            cursor = self.conn.cursor()
            cursor.execute(
                "SELECT malicious_count, last_checked FROM intel_cache WHERE ip = ?",
                (ip,),
            )
            fila = cursor.fetchone()
            if fila is None:
                return None

            malicious_count, last_checked_str = fila
            last_checked = datetime.strptime(last_checked_str, "%Y-%m-%d %H:%M:%S")
            limite = datetime.now() - timedelta(days=7)

            if last_checked >= limite:
                logger.info(
                    "IP %s recuperada del cache local (TTL valido)", ip
                )
                return malicious_count
            else:
                logger.debug("IP %s encontrada en cache pero TTL expirado", ip)
                return None

        except sqlite3.Error as e:
            logger.error("Error al leer cache SQLite para %s: %s", ip, e)
            return None

    def set_cached(self, ip: str, malicious_count: int) -> None:
        """Inserta o actualiza el registro de una IP en la caché."""
        try:
            cursor = self.conn.cursor()
            ahora = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            cursor.execute(
                """
                INSERT INTO intel_cache (ip, malicious_count, last_checked)
                VALUES (?, ?, ?)
                ON CONFLICT(ip) DO UPDATE SET
                    malicious_count = excluded.malicious_count,
                    last_checked = excluded.last_checked
                """,
                (ip, malicious_count, ahora),
            )
            self.conn.commit()
            logger.debug("Cache actualizado para IP %s", ip)
        except sqlite3.Error as e:
            logger.error("Error al escribir cache SQLite para %s: %s", ip, e)

    def close(self) -> None:
        """Cierra la conexión a la base de datos de forma segura."""
        try:
            if self.conn:
                self.conn.close()
                logger.debug("Conexion SQLite cerrada correctamente")
        except sqlite3.Error as e:
            logger.error("Error al cerrar SQLite: %s", e)


class VTClient:
    """Cliente para consultar la API v3 de VirusTotal con filtro bogon."""

    def __init__(self, api_key: str, sesion: requests.Session) -> None:
        self.api_key: str = api_key
        self.sesion: requests.Session = sesion

    def es_bogon(self, ip: str) -> bool:
        """Verifica si una IP es privada, loopback o multicast."""
        try:
            direccion = ipaddress.ip_address(ip)
            if direccion.is_private:
                logger.debug("IP privada descartada %s", ip)
                return True
            if direccion.is_loopback:
                logger.debug("IP loopback descartada %s", ip)
                return True
            if direccion.is_multicast:
                logger.debug("IP multicast descartada %s", ip)
                return True
            return False
        except ValueError:
            return False

    def consultar(self, ip: str) -> Tuple[str, int]:
        """
        Consulta VirusTotal para una IP.
        Retorna (estado, malicious_count).
        Estados: "clean", "malicious", "error", "bogon"
        """
        if self.es_bogon(ip):
            return ("bogon", 0)

        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        headers = {"x-apikey": self.api_key}

        try:
            response = self.sesion.get(url, headers=headers, timeout=30)
        except requests.exceptions.ConnectionError:
            logger.error("Error de conexion al consultar %s", ip)
            return ("error", 0)
        except requests.exceptions.Timeout:
            logger.error("Timeout al consultar %s", ip)
            return ("error", 0)
        except requests.exceptions.RetryError:
            logger.error("Se agotaron los reintentos para %s", ip)
            return ("error", 0)
        except requests.exceptions.RequestException as e:
            logger.error("Error inesperado al consultar %s: %s", ip, e)
            return ("error", 0)

        if response.status_code == 200:
            try:
                datos = response.json()
                malicious = (
                    datos
                    .get("data", {})
                    .get("attributes", {})
                    .get("last_analysis_stats", {})
                    .get("malicious", 0)
                )
            except (ValueError, AttributeError, KeyError) as e:
                logger.error("Error al parsear JSON de %s: %s", ip, e)
                return ("error", 0)

            if malicious > 0:
                logger.warning(
                    "ALERTA! %s tiene %d deteccion(es) maliciosa(s)", ip, malicious
                )
                return ("malicious", malicious)
            else:
                logger.info("%s esta limpia (0 detecciones)", ip)
                return ("clean", 0)

        elif response.status_code == 401:
            logger.critical("API Key no autorizada para %s. Verifica tu clave.", ip)
            return ("error", 0)

        elif response.status_code == 429:
            logger.error("Rate Limit persistente para %s incluso tras reintentos", ip)
            return ("error", 0)

        else:
            logger.warning(
                "Respuesta inesperada (HTTP %d) para %s", response.status_code, ip
            )
            return ("error", 0)


class ReportGenerator:
    """Genera reportes en formato CSV o JSON con estructura SIEM-ready."""

    def __init__(self, ruta: str, formato: str = "csv") -> None:
        self.ruta: str = ruta
        self.formato: str = formato
        self.detections: List[Dict[str, Any]] = []

    def agregar_deteccion(self, ip: str, malicious_count: int) -> None:
        """Acumula una detección maliciosa para exportación posterior."""
        self.detections.append({
            "ip": ip,
            "malicious_count": malicious_count,
            "date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        })

    def exportar(
        self,
        resultados: List[Tuple[str, str, int]],
        tiempo_total: float,
    ) -> None:
        """
        Exporta los resultados según el formato elegido.
        resultados: lista de (ip, estado, malicious_count)
        """
        if self.formato == "csv":
            self._exportar_csv(resultados)
        else:
            self._exportar_json(resultados, tiempo_total)

    def _exportar_csv(self, resultados: List[Tuple[str, str, int]]) -> None:
        """Exporta en formato CSV con todas las IPs procesadas."""
        ruta_csv = self.ruta if self.ruta.endswith(".csv") else self.ruta + ".csv"
        try:
            with open(ruta_csv, mode="w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(["IP", "Estado", "Motores_Maliciosos", "Timestamp"])
                for ip, estado, count in resultados:
                    writer.writerow([
                        ip,
                        estado,
                        count,
                        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    ])
            logger.info("Reporte CSV exportado: %s", os.path.abspath(ruta_csv))
        except OSError as e:
            logger.error("Error al escribir CSV %s: %s", ruta_csv, e)

    def _exportar_json(
        self,
        resultados: List[Tuple[str, str, int]],
        tiempo_total: float,
    ) -> None:
        """Exporta en formato JSON con estructura SIEM-ready."""
        ruta_json = self.ruta if self.ruta.endswith(".json") else self.ruta + ".json"

        total = len(resultados)
        clean = sum(1 for _, e, _ in resultados if e == "clean")
        malicious = sum(1 for _, e, _ in resultados if e == "malicious")
        errors = sum(1 for _, e, _ in resultados if e == "error")
        bogons = sum(1 for _, e, _ in resultados if e == "bogon")

        # Construir arreglo de detecciones solo con IPs maliciosas
        detecciones = [
            {
                "ip": ip,
                "malicious_count": count,
                "date": d["date"],
            }
            for ip, estado, count in resultados
            for d in self.detections
            if d["ip"] == ip and estado == "malicious"
        ]

        # Eliminar duplicados en detecciones
        vistos: set = set()
        detecciones_unicas: List[Dict[str, Any]] = []
        for d in detecciones:
            if d["ip"] not in vistos:
                vistos.add(d["ip"])
                detecciones_unicas.append(d)

        payload: Dict[str, Any] = {
            "metadata": {
                "scan_date": datetime.now().isoformat(),
                "total": total,
                "clean": clean,
                "malicious": malicious,
                "errors": errors,
                "bogons": bogons,
                "execution_time_seconds": round(tiempo_total, 2),
            },
            "detections": detecciones_unicas,
        }

        try:
            with open(ruta_json, mode="w") as f:
                json.dump(payload, f, indent=2)
            logger.info("Reporte JSON exportado: %s", os.path.abspath(ruta_json))
        except OSError as e:
            logger.error("Error al escribir JSON %s: %s", ruta_json, e)

    def exportar_parcial(
        self,
        resultados: List[Tuple[str, str, int]],
        tiempo_total: float,
    ) -> None:
        """Exporta datos parciales durante un graceful shutdown."""
        logger.info("Guardando datos parciales en %s ...", self.ruta)
        self.exportar(resultados, tiempo_total)


def enviar_webhook(
    url: str, ip: str, malicious_count: int, timeout: int = 10
) -> None:
    """Envía una alerta crítica vía webhook si malicious_count >= 5."""
    payload: Dict[str, Any] = {
        "ip": ip,
        "malicious_count": malicious_count,
        "timestamp": datetime.now().isoformat(),
        "alert": "CRITICAL",
        "source": "Threat Intel Bot v3.0",
    }
    try:
        resp = requests.post(url, json=payload, timeout=timeout)
        if resp.status_code in (200, 201, 202, 204):
            logger.info("Webhook enviado exitosamente para IP %s", ip)
        else:
            logger.warning(
                "Webhook respondio con HTTP %d para IP %s", resp.status_code, ip
            )
    except requests.exceptions.ConnectionError:
        logger.error("Error de conexion al enviar webhook para IP %s", ip)
    except requests.exceptions.Timeout:
        logger.error("Timeout al enviar webhook para IP %s", ip)
    except requests.exceptions.RequestException as e:
        logger.error("Error al enviar webhook para IP %s: %s", ip, e)


def mostrar_resumen(
    resultados: List[Tuple[str, str, int]], tiempo_total: float
) -> None:
    total = len(resultados)
    clean = sum(1 for _, e, _ in resultados if e == "clean")
    malicious = sum(1 for _, e, _ in resultados if e == "malicious")
    errors = sum(1 for _, e, _ in resultados if e == "error")
    bogons = sum(1 for _, e, _ in resultados if e == "bogon")

    logger.info("")
    logger.info("=" * 50)
    logger.info("  RESUMEN DEL ESCANEO")
    logger.info("=" * 50)
    logger.info("  Total IPs:       %d", total)
    logger.info("  Limpias:         %d", clean)
    logger.info("  Maliciosas:      %d", malicious)
    logger.info("  Bogons:          %d", bogons)
    logger.info("  Errores:         %d", errors)
    logger.info("  Tiempo total:    %.1f segundos", tiempo_total)
    logger.info("=" * 50)


def main() -> None:
    global shutdown_flag

    parser = crear_parser()
    args = parser.parse_args()

    configurar_logging(verbose=args.verbose)

    logger.debug("Argumentos recibidos: %s", vars(args))

    # Configurar manejador de señal SIGINT para graceful shutdown
    signal.signal(signal.SIGINT, manejador_shutdown)

    api_key = cargar_api_key()
    objetivos = cargar_objetivos(args.input)

    if not objetivos:
        logger.warning("No hay IPs para escanear. Saliendo.")
        sys.exit(0)

    # Inicializar componentes modulares
    db_manager: DatabaseManager
    try:
        db_manager = DatabaseManager()
    except sqlite3.Error:
        logger.critical("No se pudo inicializar la base de datos SQLite. Abortando.")
        sys.exit(1)

    sesion = crear_sesion_retry()
    vt_client = VTClient(api_key, sesion)
    report_gen = ReportGenerator(args.output, args.formato)

    logger.info("")
    logger.info("=" * 60)
    logger.info("  Threat Intel Bot CLI v3.0 Enterprise - Escaneo OSINT")
    logger.info("=" * 60)

    inicio = datetime.now()
    resultados: List[Tuple[str, str, int]] = []

    for idx, ip in enumerate(objetivos, start=1):
        # Verificar graceful shutdown
        if shutdown_flag:
            logger.critical(
                "Escaneo interrumpido por el usuario. "
                "Datos parciales guardados de forma segura."
            )
            break

        logger.info("[%d/%d] Procesando %s...", idx, len(objetivos), ip)

        # 1. Consultar caché SQLite
        cached_count = db_manager.get_cached(ip)

        if cached_count is not None:
            # Recuperado del caché
            if cached_count > 0:
                resultados.append((ip, "malicious", cached_count))
                report_gen.agregar_deteccion(ip, cached_count)

                # Webhook si aplica
                if args.webhook and cached_count >= 5:
                    enviar_webhook(args.webhook, ip, cached_count)
            else:
                resultados.append((ip, "clean", 0))
        else:
            # No está en caché o expiró → consultar a VirusTotal
            estado, malicious_count = vt_client.consultar(ip)

            if estado == "bogon":
                resultados.append((ip, "bogon", 0))
                # No guardar bogons en caché
            elif estado == "error":
                resultados.append((ip, "error", 0))
                # No guardar errores en caché
            else:
                # Insertar/actualizar en caché
                db_manager.set_cached(ip, malicious_count)

                if estado == "malicious":
                    resultados.append((ip, "malicious", malicious_count))
                    report_gen.agregar_deteccion(ip, malicious_count)

                    # Webhook si aplica
                    if args.webhook and malicious_count >= 5:
                        enviar_webhook(args.webhook, ip, malicious_count)
                else:
                    resultados.append((ip, "clean", 0))

        # Delay entre consultas (excepto última o si se activó shutdown)
        if idx < len(objetivos) and not shutdown_flag:
            logger.debug("Esperando %ds para respetar rate limit...", args.delay)
            # Usar sleep en segmentos para responder rápido a SIGINT
            for _ in range(args.delay):
                if shutdown_flag:
                    break
                time.sleep(1)

    tiempo_total = (datetime.now() - inicio).total_seconds()

    # Exportar resultados
    if shutdown_flag:
        report_gen.exportar_parcial(resultados, tiempo_total)
    else:
        report_gen.exportar(resultados, tiempo_total)

    # Cerrar base de datos de forma segura
    db_manager.close()

    mostrar_resumen(resultados, tiempo_total)


if __name__ == "__main__":
    main()
