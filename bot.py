"""
bot.py - Threat Intel Bot CLI (Mejorado)
CLI con argparse, validacion de IPs, reintentos inteligentes,
resumen estadistico, logging por niveles y deteccion de duplicados.
"""

import os
import sys
import csv
import argparse
import ipaddress
import logging
from datetime import datetime
from collections import Counter

import requests
from dotenv import load_dotenv
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


logger = logging.getLogger("threatintel")


def configurar_logging(verbose: bool = False) -> None:
    nivel = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=nivel,
        format="%(levelname)s: %(message)s",
        handlers=[logging.StreamHandler(sys.stdout)],
    )

    
def crear_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Threat Intel Bot CLI - Consulta VirusTotal por IP"
    )
    parser.add_argument(
        "--input",
        default="objetivos.txt",
        help="Archivo con lista de IPs (default: objetivos.txt)",
    )
    parser.add_argument(
        "--output",
        default="reporte_alertas.csv",
        help="Archivo CSV de salida para alertas (default: reporte_alertas.csv)",
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


def cargar_objetivos(ruta: str) -> list[str]:
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

    validas = []
    invalidas = 0
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
            logger.warning("IP duplicada encontrada: %s (%d veces)", ip, Counter(validas)[ip])
        validas = list(dict.fromkeys(validas))
        logger.info("Duplicados eliminados, quedan %d IP(s) unicas", len(validas))

    logger.info("Se cargaron %d IP(s) validas: %s", len(validas), validas)
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


def guardar_alerta_csv(ip: str, motores: int, ruta: str) -> None:
    existe = os.path.isfile(ruta)
    with open(ruta, mode="a", newline="") as f:
        writer = csv.writer(f)
        if not existe:
            writer.writerow(["IP", "Motores_Maliciosos", "Timestamp"])
        writer.writerow([ip, motores, datetime.now().strftime("%Y-%m-%d %H:%M:%S")])
    logger.debug("Alerta guardada en %s", os.path.abspath(ruta))


def consultar_virustotal(
    ip: str,
    api_key: str,
    sesion: requests.Session,
    ruta_csv: str,
) -> str:
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": api_key}

    try:
        response = sesion.get(url, headers=headers, timeout=30)
    except requests.exceptions.ConnectionError:
        logger.error("Error de conexion al consultar %s", ip)
        return "error"
    except requests.exceptions.Timeout:
        logger.error("Timeout al consultar %s", ip)
        return "error"
    except requests.exceptions.RetryError:
        logger.error("Se agotaron los reintentos para %s", ip)
        return "error"
    except requests.exceptions.RequestException as e:
        logger.error("Error inesperado al consultar %s: %s", ip, e)
        return "error"

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
            return "error"

        if malicious > 0:
            logger.warning("ALERTA! %s tiene %d deteccion(es) maliciosa(s)", ip, malicious)
            guardar_alerta_csv(ip, malicious, ruta_csv)
            return "malicious"
        else:
            logger.info("%s esta limpia (0 detecciones)", ip)
            return "clean"

    elif response.status_code == 401:
        logger.critical("API Key no autorizada para %s. Verifica tu clave.", ip)
        return "error"

    elif response.status_code == 429:
        logger.error("Rate Limit persistente para %s incluso tras reintentos", ip)
        return "error"

    else:
        logger.warning("Respuesta inesperada (HTTP %d) para %s", response.status_code, ip)
        return "error"


def mostrar_resumen(resultados: list[tuple[str, str]], tiempo_total: float) -> None:
    total = len(resultados)
    clean = sum(1 for _, v in resultados if v == "clean")
    malicious = sum(1 for _, v in resultados if v == "malicious")
    errors = sum(1 for _, v in resultados if v == "error")

    logger.info("")
    logger.info("=" * 50)
    logger.info("  RESUMEN DEL ESCANEO")
    logger.info("=" * 50)
    logger.info("  Total IPs:       %d", total)
    logger.info("  Limpias:         %d", clean)
    logger.info("  Maliciosas:      %d", malicious)
    logger.info("  Errores:         %d", errors)
    logger.info("  Tiempo total:    %.1f segundos", tiempo_total)
    logger.info("=" * 50)


def main() -> None:
    parser = crear_parser()
    args = parser.parse_args()

    configurar_logging(verbose=args.verbose)

    logger.debug("Argumentos recibidos: %s", vars(args))

    api_key = cargar_api_key()
    objetivos = cargar_objetivos(args.input)

    if not objetivos:
        logger.warning("No hay IPs para escanear. Saliendo.")
        sys.exit(0)

    sesion = crear_sesion_retry()

    logger.info("")
    logger.info("=" * 60)
    logger.info("  Threat Intel Bot CLI - Escaneo OSINT")
    logger.info("=" * 60)

    inicio = datetime.now()
    resultados: list[tuple[str, str]] = []

    for idx, ip in enumerate(objetivos, start=1):
        logger.info("[%d/%d] Consultando %s...", idx, len(objetivos), ip)
        resultado = consultar_virustotal(ip, api_key, sesion, args.output)
        resultados.append((ip, resultado))

        if idx < len(objetivos):
            logger.debug("Esperando %ds para respetar rate limit...", args.delay)

    tiempo_total = (datetime.now() - inicio).total_seconds()

    mostrar_resumen(resultados, tiempo_total)


if __name__ == "__main__":
    main()
