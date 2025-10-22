#!/usr/bin/env python3
"""
Domain Analyzer Pro v2.3 (Stable Release)
🔍 Comprehensive domain analysis: WHOIS, DNS, SSL, OWASP Top 10 Vulnerabilities, IP Geolocation, Subdomain Enumeration, PDF Report

Author: BlueQuantum Security
GitHub: https://github.com/esanchezprs-droid/domain-analyzer
"""

import argparse
import logging
import os
import re
import socket
import ssl
import sys
import subprocess
import shutil
import urllib3
from datetime import datetime
from urllib.parse import quote, urljoin

import requests
from bs4 import BeautifulSoup
from tenacity import retry, stop_after_attempt, wait_exponential

# Disable SSL warnings for scanning HTTPS without verify=True
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("domain_analyzer.log"),
        logging.StreamHandler(sys.stdout),
    ],
)
logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 10

COMMON_SUBDOMAINS = [
    "www", "mail", "api", "blog", "dev", "test", "staging", "shop",
    "ftp", "admin", "secure", "vpn", "web", "app", "portal", "login"
]

def validar_dominio(dominio):
    """Validate that the input is a valid domain."""
    patron = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$'
    return bool(re.match(patron, dominio)) and len(dominio) <= 253

def obtener_ip_socket(dominio):
    """Resolve domain to IP addresses using socket."""
    try:
        ips = socket.gethostbyname_ex(dominio)[2]
        logger.info(f"Resolved IPs for {dominio}: {ips}")
        return ips
    except socket.gaierror as e:
        logger.debug(f"DNS resolution failed for {dominio}: {e}")
        return []

def analizar_subdominios(dominio):
    """Enumerate and resolve common subdomains."""
    logger.info(f"Starting subdomain analysis for {dominio}")
    subdomains_data = []
    for subdomain in COMMON_SUBDOMAINS:
        full_domain = f"{subdomain}.{dominio}"
        ips = obtener_ip_socket(full_domain)
        status = "✅ Activo" if ips else "❌ Inactivo"
        subdomains_data.append({"subdomain": full_domain, "ips": ips, "status": status})
    if not any(s["ips"] for s in subdomains_data):
        logger.warning(f"No active subdomains found for {dominio}")
    return subdomains_data

@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
def obtener_whois_api(dominio):
    """Fetch WHOIS data via free API."""
    try:
        api_url = os.getenv("WHOIS_API_URL", f"https://whoisjson.com/v1/{quote(dominio)}")
        headers = {"User-Agent": "Mozilla/5.0 (compatible; DomainAnalyzer)"}
        response = requests.get(api_url, headers=headers, timeout=DEFAULT_TIMEOUT)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        logger.error(f"WHOIS API request failed for {dominio}: {e}")
        return None

def parsear_whois_api(data):
    """Parse WHOIS API response into structured data."""
    if not data or "domain" not in data:
        logger.warning("No valid WHOIS data received")
        return None
    info = {
        "Dominio": data.get("domain", "N/A"),
        "Estado": data.get("status", "N/A"),
        "Creado": data.get("created_at", "N/A"),
        "Expira": data.get("expires_at", data.get("expiration_date", "N/A")),
        "Registrar": data.get("registrar", {}).get("name", "N/A"),
        "Servidores DNS": ", ".join(data.get("nameservers", [])),
        "Registrante": data.get("registrant", {}).get("name", "Privado"),
        "Email": data.get("registrant", {}).get("email", "Privado"),
        "País": data.get("registrant", {}).get("country", "N/A"),
    }
    logger.info(f"Parsed WHOIS data: {info}")
    return info

@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
def geolocalizar_ip(ip):
    """Geolocate an IP address."""
    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,regionName,city,lat,lon,isp,org"
        response = requests.get(url, timeout=DEFAULT_TIMEOUT)
        response.raise_for_status()
        data = response.json()
        if data.get("status") == "success":
            geo_data = {
                "IP": ip,
                "País": data.get("country", "N/A"),
                "Código": data.get("countryCode", "N/A"),
                "Región": data.get("regionName", "N/A"),
                "Ciudad": data.get("city", "N/A"),
                "Latitud": str(data.get("lat", "N/A")),
                "Longitud": str(data.get("lon", "N/A")),
                "ISP": data.get("isp", "N/A"),
                "Organización": data.get("org", "N/A"),
            }
            logger.info(f"Geolocation data for {ip}: {geo_data}")
            return geo_data
        return None
    except requests.RequestException as e:
        logger.error(f"IP geolocation failed for {ip}: {e}")
        return None

def obtener_ssl(dominio):
    """Analyze SSL certificate."""
    logger.info(f"Analyzing SSL certificate for {dominio}")
    try:
        context = ssl.create_default_context()
        with socket.create_connection((dominio, 443), timeout=DEFAULT_TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=dominio) as ssock:
                cert = ssock.getpeercert()
        if not cert:
            logger.warning(f"No SSL certificate found for {dominio}")
            return None

        try:
            not_before = datetime.strptime(cert["notBefore"], "%b %d %H:%M:%S %Y %Z")
            not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
        except Exception:
            logger.warning(f"Unexpected date format in SSL cert for {dominio}")
            not_before = not_after = datetime.utcnow()

        ahora = datetime.utcnow()
        dias_restantes = (not_after - ahora).days
        estado = "✅ Válido" if ahora < not_after else "❌ Expirado"
        if dias_restantes < 30:
            estado += " ⚠️ Expira pronto"

        info = {
            "Sujeto": ", ".join(f"{k}: {v}" for k, v in cert.get("subject", [])),
            "Emisor": ", ".join(f"{k}: {v}" for k, v in cert.get("issuer", [])),
            "Válido Desde": not_before.strftime("%Y-%m-%d"),
            "Válido Hasta": not_after.strftime("%Y-%m-%d"),
            "Días Restantes": dias_restantes,
            "Estado": estado,
            "Nombres Alternativos": ", ".join(name[1] for name in cert.get("subjectAltName", [])) if "subjectAltName" in cert else "N/A",
        }
        return info
    except Exception as e:
        logger.error(f"SSL analysis failed for {dominio}: {e}")
        return {"Error": str(e)}

def analizar_vulnerabilidades(dominio, verbose=False):
    """Analyze OWASP Top 10 headers and vulnerabilities."""
    base_url = f"https://{dominio}"
    session = requests.Session()
    session.headers.update({"User-Agent": "Mozilla/5.0 (DomainAnalyzer)"})
    vulnerabilidades, puntuacion = [], 100

    try:
        response = session.get(base_url, timeout=DEFAULT_TIMEOUT, verify=False)
        headers = response.headers

        # Security headers
        if "Strict-Transport-Security" not in headers:
            vulnerabilidades.append("❌ HSTS ausente - MITM posible")
            puntuacion -= 15
        if "Content-Security-Policy" not in headers:
            vulnerabilidades.append("❌ CSP ausente - Riesgo XSS")
            puntuacion -= 12
        if "X-Frame-Options" not in headers:
            vulnerabilidades.append("❌ X-Frame ausente - Clickjacking")
            puntuacion -= 10
        if headers.get("X-Content-Type-Options") != "nosniff":
            vulnerabilidades.append("❌ X-Content-Type-Options mal configurado")
            puntuacion -= 8
        if "Referrer-Policy" not in headers:
            vulnerabilidades.append("⚠️ Referrer-Policy ausente")
            puntuacion -= 5

        # HTTP Methods check
        try:
            resp = session.options(base_url, timeout=DEFAULT_TIMEOUT)
            allow = resp.headers.get("Allow", "")
            if "TRACE" in allow:
                vulnerabilidades.append("🚨 TRACE habilitado - XST Attack")
                puntuacion -= 18
            if len(allow.split(",")) > 3:
                vulnerabilidades.append(f"⚠️ Métodos HTTP expuestos: {allow}")
                puntuacion -= 8
        except requests.RequestException:
            pass

        # CORS
        if headers.get("Access-Control-Allow-Origin") == "*":
            vulnerabilidades.append("🚨 CORS abierto (*)")
            puntuacion -= 15

        # Cookies
        cookies_secure = all(c.secure for c in response.cookies)
        if not cookies_secure:
            vulnerabilidades.append("❌ Cookies sin Secure flag")
            puntuacion -= 10

        # Server info leak
        if "Server" in headers and len(headers["Server"]) > 5:
            vulnerabilidades.append(f"ℹ️ Server expuesto: {headers['Server']}")
            puntuacion -= 3

    except requests.RequestException as e:
        vulnerabilidades.append(f"❌ No se pudo analizar headers ({e})")
        puntuacion -= 20

    return {
        "puntuacion": max(0, puntuacion),
        "vulnerabilidades": vulnerabilidades,
        "recomendaciones": [
            "Habilitar HSTS y CSP.",
            "Deshabilitar TRACE.",
            "Configurar CORS restrictivo.",
            "Asegurar cookies con Secure flag."
        ] if puntuacion < 80 else []
    }

def generar_reporte_pdf(dominio, results):
    """Generate PDF report using LaTeX."""
    if not shutil.which("pdflatex"):
        print("⚠️ pdflatex no instalado. Solo se generará el archivo .tex")
        return

    logger.info(f"Generating PDF for {dominio}")
    tex_content = rf"""
\documentclass[a4paper,12pt]{{article}}
\usepackage[utf8]{{inputenc}}
\usepackage[spanish]{{babel}}
\usepackage{{geometry}}
\geometry{{margin=1in}}
\usepackage{{booktabs,longtable,xcolor,hyperref,fontenc,lmodern}}
\begin{{document}}
\title{{Análisis de Dominio: {dominio}}}
\author{{Domain Analyzer Pro v2.3}}
\date{{Generado el {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}}}
\maketitle

\section*{{Resumen DNS}}
IPs: {", ".join(results["dns"]["ips"]) if results["dns"]["ips"] else "Ninguna"}

\section*{{Vulnerabilidades}}
Puntuación: {results["vulnerabilities"]["puntuacion"]}/100
\begin{{itemize}}
""" + "\n".join([f"\\item {v}" for v in results["vulnerabilities"]["vulnerabilidades"]]) + r"""
\end{itemize}
\end{document}
"""

    tex_file = f"report_{dominio.replace('.', '_')}.tex"
    with open(tex_file, "w", encoding="utf-8") as f:
        f.write(tex_content)

    try:
        subprocess.run(["pdflatex", tex_file], check=True, capture_output=True)
        print(f"✅ PDF generado: report_{dominio.replace('.', '_')}.pdf")
    except subprocess.CalledProcessError:
        print(f"❌ Error al compilar {tex_file}")

def main(dominio, verbose=False, generate_pdf=False):
    if verbose:
        logger.setLevel(logging.DEBUG)

    if not validar_dominio(dominio):
        print(f"❌ '{dominio}' no es un dominio válido")
        return

    print("🔍 Análisis completo del dominio:", dominio)
    results = {
        "dns": {"ips": obtener_ip_socket(dominio)},
        "subdomains": analizar_subdominios(dominio),
        "whois": parsear_whois_api(obtener_whois_api(dominio)),
        "ssl": obtener_ssl(dominio),
        "vulnerabilities": analizar_vulnerabilidades(dominio, verbose),
        "geolocation": {}
    }

    if results["dns"]["ips"]:
        results["geolocation"][dominio] = geolocalizar_ip(results["dns"]["ips"][0])

    if generate_pdf:
        generar_reporte_pdf(dominio, results)

    print("✅ Análisis completado correctamente.")

def parse_arguments():
    parser = argparse.ArgumentParser(description="🔍 Domain Analyzer Pro v2.3")
    parser.add_argument("domain", nargs="?", help="Dominio a analizar (e.g. google.com)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Modo detallado")
    parser.add_argument("--pdf", action="store_true", help="Generar reporte PDF")
    return parser.parse_args()

if __name__ == "__main__":
    args = parse_arguments()
    dominio = args.domain or input("🔍 Ingrese el dominio a analizar: ").strip()
    main(dominio, args.verbose, args.pdf)
