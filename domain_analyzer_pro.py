#!/usr/bin/env python3
"""
Domain Analyzer Pro v2.3 (Stable Release) - CORREGIDO
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
import json
import urllib3
from datetime import datetime, timezone
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
    
    # Manejar diferentes estructuras de respuesta de WHOIS
    registrar_info = data.get("registrar", {})
    if isinstance(registrar_info, str):
        registrar_name = registrar_info
    else:
        registrar_name = registrar_info.get("name", "N/A")
    
    registrant_info = data.get("registrant", {})
    if isinstance(registrant_info, str):
        registrant_name = registrant_info
    else:
        registrant_name = registrant_info.get("name", "Privado")
    
    info = {
        "Dominio": data.get("domain", "N/A"),
        "Estado": data.get("status", "N/A"),
        "Creado": data.get("created_at", data.get("creation_date", "N/A")),
        "Expira": data.get("expires_at", data.get("expiration_date", "N/A")),
        "Registrar": registrar_name,
        "Servidores DNS": ", ".join(data.get("nameservers", [])),
        "Registrante": registrant_name,
        "Email": registrant_info.get("email", "Privado") if isinstance(registrant_info, dict) else "Privado",
        "País": registrant_info.get("country", "N/A") if isinstance(registrant_info, dict) else "N/A",
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

def obtener_ssl(dominio, port=443):
    """Analyze SSL certificate with enhanced error handling and debugging."""
    logger.info(f"Analyzing SSL certificate for {dominio} on port {port}")
    try:
        # Crear contexto SSL con validación estricta
        context = ssl.create_default_context()
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        logger.debug(f"Attempting strict SSL connection to {dominio}:{port}")

        # Intentar conexión con validación estricta
        try:
            with socket.create_connection((dominio, port), timeout=DEFAULT_TIMEOUT) as sock:
                with context.wrap_socket(sock, server_hostname=dominio) as ssock:
                    cert = ssock.getpeercert()
                    logger.debug(f"Certificate retrieved for {dominio} with strict validation")
        except (ssl.SSLError, socket.timeout) as strict_error:
            logger.warning(f"Strict SSL connection failed for {dominio}: {type(strict_error).__name__} - {str(strict_error)}")
            # Fallback a validación relajada
            logger.debug(f"Falling back to relaxed SSL validation for {dominio}")
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with socket.create_connection((dominio, port), timeout=DEFAULT_TIMEOUT) as sock:
                with context.wrap_socket(sock, server_hostname=dominio) as ssock:
                    cert = ssock.getpeercert()
                    logger.debug(f"Certificate retrieved for {dominio} with relaxed validation")

        if not cert:
            logger.warning(f"No SSL certificate found for {dominio}")
            return {"Error": "No certificate found"}

        # Extraer información del certificado
        issuer = dict(x[0] for x in cert.get('issuer', []))
        subject = dict(x[0] for x in cert.get('subject', []))
        
        # Parsear fechas con manejo seguro
        try:
            not_before = datetime.strptime(cert.get("notBefore", ""), "%b %d %H:%M:%S %Y %Z")
            not_after = datetime.strptime(cert.get("notAfter", ""), "%b %d %H:%M:%S %Y %Z")
        except (ValueError, KeyError) as e:
            logger.warning(f"Error parsing SSL certificate dates: {type(e).__name__} - {str(e)}")
            not_before = not_after = datetime.now(timezone.utc)
        
        # Hacer las fechas timezone-aware
        if not_before.tzinfo is None:
            not_before = not_before.replace(tzinfo=timezone.utc)
        if not_after.tzinfo is None:
            not_after = not_after.replace(tzinfo=timezone.utc)
        
        # Calcular días restantes y estado
        ahora = datetime.now(timezone.utc)
        dias_restantes = (not_after - ahora).days
        estado = "✅ Válido" if ahora < not_after else "❌ Expirado"
        if 0 < dias_restantes < 30:
            estado += " ⚠️ Expira pronto"

        # Formatear issuer y subject
        def parse_name_components(components):
            if not components:
                return "N/A"
            try:
                return ", ".join([f"{k}: {v}" for k, v in components.items()])
            except Exception as e:
                logger.warning(f"Error parsing certificate components: {type(e).__name__} - {str(e)}")
                return str(components)

        # Construir información del certificado
        info = {
            "Sujeto": parse_name_components(subject),
            "Emisor": parse_name_components(issuer),
            "Válido Desde": not_before.strftime("%Y-%m-%d"),
            "Válido Hasta": not_after.strftime("%Y-%m-%d"),
            "Días Restantes": dias_restantes,
            "Estado": estado,
            "Versión": str(cert.get("version", "N/A")),
            "Número de Serie": cert.get("serialNumber", "N/A"),
            "Algoritmo de Firma": cert.get("signatureAlgorithm", "Not available"),
            "Algoritmo de Clave": cert.get("keyAlgorithm", "Not available"),
            "Tamaño de Clave": str(cert.get("keySize", "Not available")),
            "Nombres Alternativos": ", ".join([name[1] for name in cert.get("subjectAltName", [])]) if cert.get("subjectAltName") else "N/A",
        }
        logger.info(f"SSL certificate analysis completed for {dominio}")
        return info
    except socket.gaierror as e:
        logger.error(f"DNS resolution failed for {dominio}: {type(e).__name__} - {str(e)}")
        return {"Error": f"DNS resolution failed: {str(e)}"}
    except socket.timeout as e:
        logger.error(f"Connection timeout for {dominio}: {type(e).__name__} - {str(e)}")
        return {"Error": f"Connection timeout: {str(e)}"}
    except ssl.SSLError as e:
        logger.error(f"SSL error for {dominio}: {type(e).__name__} - {str(e)}")
        return {"Error": f"SSL error: {str(e)}"}
    except Exception as e:
        logger.error(f"SSL analysis failed for {dominio}: {type(e).__name__} - {str(e)}")
        return {"Error": f"{type(e).__name__}: {str(e)}"}

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
        cookies_secure = all(hasattr(c, 'secure') and c.secure for c in response.cookies)
        if response.cookies and not cookies_secure:
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

def generar_reporte_txt(dominio, results):
    """Generate comprehensive text report."""
    filename = f"report_{dominio.replace('.', '_')}.txt"
    
    with open(filename, "w", encoding="utf-8") as f:
        f.write("=" * 60 + "\n")
        f.write(f"DOMAIN ANALYZER PRO - REPORTE COMPLETO\n")
        f.write("=" * 60 + "\n")
        f.write(f"Dominio: {dominio}\n")
        f.write(f"Fecha: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("=" * 60 + "\n\n")
        
        # Información DNS
        f.write("1. INFORMACIÓN DNS\n")
        f.write("-" * 40 + "\n")
        if results["dns"]["ips"]:
            f.write(f"IPs resueltas: {', '.join(results['dns']['ips'])}\n")
        else:
            f.write("❌ No se pudieron resolver las IPs\n")
        f.write("\n")
        
        # Subdominios
        f.write("2. SUBDOMINIOS ANALIZADOS\n")
        f.write("-" * 40 + "\n")
        for sub in results["subdomains"]:
            f.write(f"{sub['status']} {sub['subdomain']}")
            if sub["ips"]:
                f.write(f" → {', '.join(sub['ips'])}")
            f.write("\n")
        f.write("\n")
        
        # WHOIS
        f.write("3. INFORMACIÓN WHOIS\n")
        f.write("-" * 40 + "\n")
        if results["whois"]:
            for key, value in results["whois"].items():
                f.write(f"{key}: {value}\n")
        else:
            f.write("❌ No se pudo obtener información WHOIS\n")
        f.write("\n")
        
        # SSL
        f.write("4. CERTIFICADO SSL\n")
        f.write("-" * 40 + "\n")
        if results["ssl"] and "Error" not in results["ssl"]:
            for key, value in results["ssl"].items():
                f.write(f"{key}: {value}\n")
        else:
            f.write("❌ No se pudo analizar el certificado SSL\n")
        f.write("\n")
        
        # Geolocalización
        f.write("5. GEOLOCALIZACIÓN\n")
        f.write("-" * 40 + "\n")
        if results["geolocation"]:
            for ip, geo_data in results["geolocation"].items():
                if geo_data:
                    for key, value in geo_data.items():
                        f.write(f"{key}: {value}\n")
        else:
            f.write("❌ No se pudo obtener geolocalización\n")
        f.write("\n")
        
        # Vulnerabilidades
        f.write("6. ANÁLISIS DE VULNERABILIDADES\n")
        f.write("-" * 40 + "\n")
        vuln = results["vulnerabilities"]
        f.write(f"PUNTUACIÓN DE SEGURIDAD: {vuln['puntuacion']}/100\n\n")
        
        if vuln["vulnerabilidades"]:
            f.write("VULNERABILIDADES ENCONTRADAS:\n")
            for v in vuln["vulnerabilidades"]:
                f.write(f"• {v}\n")
        else:
            f.write("✅ No se encontraron vulnerabilidades críticas\n")
        
        if vuln["recomendaciones"]:
            f.write("\nRECOMENDACIONES:\n")
            for r in vuln["recomendaciones"]:
                f.write(f"• {r}\n")
    
    print(f"✅ Reporte de texto generado: {filename}")
    return filename

def generar_reporte_json(dominio, results):
    """Generate JSON report for programmatic access."""
    filename = f"report_{dominio.replace('.', '_')}.json"
    
    with open(filename, "w", encoding="utf-8") as f:
        json.dump({
            "dominio": dominio,
            "fecha_analisis": datetime.now().isoformat(),
            "resultados": results
        }, f, indent=2, ensure_ascii=False)
    
    print(f"✅ Reporte JSON generado: {filename}")
    return filename

def generar_reporte_pdf(dominio, results):
    """Generate PDF report using LaTeX."""
    if not shutil.which("pdflatex"):
        print("⚠️ pdflatex no instalado. Solo se generará el archivo .tex")
        return None

    logger.info(f"Generating PDF for {dominio}")
    
    # Construir contenido del reporte
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

\section{{Resumen del Análisis}}
\textbf{{Dominio:}} {dominio} \\
\textbf{{Fecha:}} {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} \\

\section{{Información DNS}}
IPs Resueltas: {", ".join(results["dns"]["ips"]) if results["dns"]["ips"] else "No encontradas"} \\

\section{{Subdominios}}
\begin{{longtable}}{{l l p{{6cm}}}}
\textbf{{Subdominio}} & \textbf{{Estado}} & \textbf{{IPs}} \\
\midrule
"""
    # Agregar subdominios
    for sub in results["subdomains"]:
        tex_content += f"{sub['subdomain']} & {sub['status']} & {', '.join(sub['ips']) if sub['ips'] else 'N/A'} \\\\ \n"

    tex_content += r"""
\end{longtable}

\section{Vulnerabilidades}
\textbf{Puntuación de Seguridad:} """ + str(results["vulnerabilities"]["puntuacion"]) + r"""/100

\begin{itemize}
""" + "\n".join([f"\\item {v}" for v in results["vulnerabilities"]["vulnerabilidades"]]) + r"""
\end{itemize}

\end{document}
"""

    tex_file = f"report_{dominio.replace('.', '_')}.tex"
    with open(tex_file, "w", encoding="utf-8") as f:
        f.write(tex_content)

    try:
        subprocess.run(["pdflatex", "-interaction=nonstopmode", tex_file], 
                      check=True, capture_output=True)
        pdf_file = f"report_{dominio.replace('.', '_')}.pdf"
        print(f"✅ PDF generado: {pdf_file}")
        return pdf_file
    except subprocess.CalledProcessError as e:
        print(f"❌ Error al compilar PDF: {e}")
        return None

def main(dominio, verbose=False, generate_pdf=False, output_format="txt"):
    if verbose:
        logger.setLevel(logging.DEBUG)

    if not validar_dominio(dominio):
        print(f"❌ '{dominio}' no es un dominio válido")
        return

    print(f"🔍 Análisis completo del dominio: {dominio}")
    
    # Realizar análisis
    results = {
        "dns": {"ips": obtener_ip_socket(dominio)},
        "subdomains": analizar_subdominios(dominio),
        "whois": parsear_whois_api(obtener_whois_api(dominio)),
        "ssl": obtener_ssl(dominio),
        "vulnerabilities": analizar_vulnerabilidades(dominio, verbose),
        "geolocation": {}
    }

    # Geolocalización para todas las IPs encontradas
    all_ips = set()
    if results["dns"]["ips"]:
        all_ips.update(results["dns"]["ips"])
    
    for sub in results["subdomains"]:
        if sub["ips"]:
            all_ips.update(sub["ips"])
    
    for ip in all_ips:
        geo_data = geolocalizar_ip(ip)
        if geo_data:
            results["geolocation"][ip] = geo_data

    # Generar reportes según el formato solicitado
    report_files = []
    
    if output_format in ["txt", "all"]:
        report_files.append(generar_reporte_txt(dominio, results))
    
    if output_format in ["json", "all"]:
        report_files.append(generar_reporte_json(dominio, results))
    
    if generate_pdf or output_format in ["pdf", "all"]:
        pdf_file = generar_reporte_pdf(dominio, results)
        if pdf_file:
            report_files.append(pdf_file)

    print(f"✅ Análisis completado correctamente.")
    print(f"📁 Reportes generados: {', '.join(report_files)}")

def parse_arguments():
    parser = argparse.ArgumentParser(description="🔍 Domain Analyzer Pro v2.3")
    parser.add_argument("domain", nargs="?", help="Dominio a analizar (e.g. google.com)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Modo detallado")
    parser.add_argument("--pdf", action="store_true", help="Generar reporte PDF")
    parser.add_argument("--format", choices=["txt", "json", "pdf", "all"], 
                       default="txt", help="Formato de salida del reporte")
    return parser.parse_args()

if __name__ == "__main__":
    args = parse_arguments()
    dominio = args.domain or input("🔍 Ingrese el dominio a analizar: ").strip()
    main(dominio, args.verbose, args.pdf, args.format)