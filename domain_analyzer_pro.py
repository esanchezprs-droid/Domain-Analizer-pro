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
from datetime import datetime, timezone, timedelta
from urllib.parse import quote, urljoin
import requests
from bs4 import BeautifulSoup
from tenacity import retry, stop_after_attempt, wait_exponential
from importlib import import_module
from functools import lru_cache
import idna
from typing import Optional, Dict, Any
import whois

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

# Precompiled regex for domain validation (from whois_lookup.py)
DOMAIN_REGEX = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$")

# Cache settings (from whois_lookup.py)
TLD_CACHE_FILE = "tld_cache.json"
WHOIS_CACHE_FILE = "whois_cache.json"
CACHE_REFRESH_DAYS = 7
WHOIS_TIMEOUT = 10  # seconds

# TLD cache (from whois_lookup.py)
_tld_cache = None

# WHOIS cache (from whois_lookup.py)
_whois_cache = {}

def load_tld_cache() -> set:
    """Load TLD cache from file if valid, otherwise fetch from IANA."""
    global _tld_cache
    if _tld_cache is not None:
        return _tld_cache
    
    if not os.path.exists(TLD_CACHE_FILE):
        _tld_cache = fetch_tld_list()
        return _tld_cache
    
    try:
        with open(TLD_CACHE_FILE, 'r') as f:
            cache = json.load(f)
            last_updated = datetime.fromisoformat(cache['last_updated'])
            if datetime.now() < last_updated + timedelta(days=CACHE_REFRESH_DAYS):
                _tld_cache = set(cache['tlds'])
                return _tld_cache
    except (json.JSONDecodeError, KeyError, ValueError) as e:
        logger.warning(f"Failed to load TLD cache: {str(e)}. Fetching new TLD list.")
    
    _tld_cache = fetch_tld_list()
    return _tld_cache

def fetch_tld_list() -> set:
    """Fetch IANA TLD list and save to cache."""
    try:
        response = requests.get("https://data.iana.org/TLD/tlds-alpha-by-domain.txt", timeout=5)
        response.raise_for_status()
        tld_list = {line.strip().lower() for line in response.text.splitlines() if line and not line.startswith('#')}
        
        cache_data = {
            'last_updated': datetime.now().isoformat(),
            'tlds': list(tld_list)
        }
        with open(TLD_CACHE_FILE, 'w') as f:
            json.dump(cache_data, f)
        return tld_list
    except requests.RequestException as e:
        logger.warning(f"Could not fetch TLD list: {str(e)}. Skipping TLD validation.")
        return set()

@lru_cache(maxsize=500)
def validate_domain(domain: str, validate_tld: bool = True) -> Optional[str]:
    """Validate a domain name efficiently and convert IDNs to Punycode."""
    if not isinstance(domain, str):
        raise ValueError("Domain must be a string")
    
    domain = domain.strip().lower()
    if len(domain) > 255:
        raise ValueError("Domain too long (max 255 characters)")
    if len(domain) < 3:
        raise ValueError("Domain is too short or empty")
    
    punycode_domain = domain
    if any(ord(c) > 127 for c in domain):
        try:
            punycode_domain = idna.encode(domain).decode('ascii')
        except idna.IDNAError as e:
            raise ValueError(f"Invalid IDN domain: {str(e)}")
    
    if not DOMAIN_REGEX.match(punycode_domain):
        raise ValueError(f"Invalid domain format: {domain}")
    
    if validate_tld:
        load_tld_cache()
        if _tld_cache and punycode_domain.split('.')[-1] not in _tld_cache:
            raise ValueError(f"Invalid TLD: {punycode_domain.split('.')[-1]}")
    
    return punycode_domain

def load_whois_cache() -> Dict[str, dict]:
    """Load WHOIS cache from file, reformatting legacy entries if needed."""
    if not os.path.exists(WHOIS_CACHE_FILE):
        return {}
    
    try:
        with open(WHOIS_CACHE_FILE, 'r') as f:
            cache = json.load(f)
            now = datetime.now().timestamp()
            reformatted_cache = {}
            for domain, data in cache.items():
                if not isinstance(data, dict) or 'timestamp' not in data or 'data' not in data:
                    logger.warning(f"Invalid cache entry for {domain}, skipping.")
                    continue
                if data['timestamp'] + (CACHE_REFRESH_DAYS * 86400) <= now:
                    logger.info(f"Cache entry for {domain} expired, skipping.")
                    continue
                reformatted_data = {}
                for key in ['domain_name', 'registrar', 'creation_date', 'expiration_date', 'name_servers']:
                    if key in data['data']:
                        try:
                            reformatted_data[key] = format_whois_value(data['data'][key], key)
                        except Exception as e:
                            logger.warning(f"Failed to reformat {key} for {domain}: {str(e)}")
                            reformatted_data[key] = 'N/A'
                reformatted_cache[domain] = {
                    'data': reformatted_data,
                    'timestamp': data['timestamp']
                }
            save_whois_cache(reformatted_cache)
            return reformatted_cache
    except (json.JSONDecodeError, KeyError, TypeError) as e:
        logger.error(f"Failed to load WHOIS cache: {str(e)}. Starting with empty cache.")
        return {}

def save_whois_cache(cache: Dict[str, dict]) -> None:
    """Save WHOIS cache to file."""
    try:
        with open(WHOIS_CACHE_FILE, 'w') as f:
            json.dump(cache, f, default=str)
    except Exception as e:
        logger.error(f"Could not save WHOIS cache: {str(e)}")

def format_whois_value(value: Any, key: str) -> str:
    """Format WHOIS field values, handling lists and other types efficiently."""
    if value is None:
        return 'N/A'
    
    if isinstance(value, list):
        if not value:
            return 'N/A'
        if key in ['creation_date', 'expiration_date']:
            for item in value:
                if item is not None:
                    return item.replace(tzinfo=None).strftime('%Y-%m-%d %H:%M:%S')
            return 'N/A'
        else:
            return ', '.join(str(item) for item in value if item is not None)
    
    if isinstance(value, datetime):
        return value.replace(tzinfo=None).strftime('%Y-%m-%d %H:%M:%S')
    
    return str(value)

def obtener_whois(dominio: str) -> Optional[Dict[str, str]]:
    """Perform a WHOIS lookup with caching, adapted from whois_lookup.py."""
    global _whois_cache
    if not _whois_cache:
        _whois_cache = load_whois_cache()
    
    try:
        # Validate domain
        validated_domain = validate_domain(dominio)
        logger.info(f"Validated domain: {validated_domain}")
    except ValueError as e:
        logger.error(f"Domain validation failed for {dominio}: {str(e)}")
        return None

    # Check cache
    if validated_domain in _whois_cache:
        logger.info(f"Returning cached WHOIS data for {validated_domain}")
        data = _whois_cache[validated_domain]['data']
        return {
            "Dominio": data.get("domain_name", "N/A"),
            "Estado": "N/A",  # Not explicitly in whois_lookup.py, default to N/A
            "Creado": data.get("creation_date", "N/A"),
            "Expira": data.get("expiration_date", "N/A"),
            "Registrar": data.get("registrar", "N/A"),
            "Servidores DNS": data.get("name_servers", "N/A"),
            "Registrante": "Privado",  # Not provided by whois_lookup.py
            "Email": "Privado",  # Not provided by whois_lookup.py
            "País": "N/A"  # Not provided by whois_lookup.py
        }
    
    try:
        if not check_library("whois"):
            raise ImportError("python-whois library is not installed. Install it with 'pip install python-whois'")
        
        w = whois.whois(validated_domain, timeout=WHOIS_TIMEOUT)
        if not w:
            logger.warning(f"No WHOIS data found for {validated_domain}")
            return None
        
        essential_data = {}
        for key in ['domain_name', 'registrar', 'creation_date', 'expiration_date', 'name_servers']:
            if key in w:
                essential_data[key] = format_whois_value(w[key], key)
        
        _whois_cache[validated_domain] = {
            'data': essential_data,
            'timestamp': datetime.now().timestamp()
        }
        save_whois_cache(_whois_cache)
        
        return {
            "Dominio": essential_data.get("domain_name", "N/A"),
            "Estado": "N/A",  # Not explicitly in whois_lookup.py
            "Creado": essential_data.get("creation_date", "N/A"),
            "Expira": essential_data.get("expiration_date", "N/A"),
            "Registrar": essential_data.get("registrar", "N/A"),
            "Servidores DNS": essential_data.get("name_servers", "N/A"),
            "Registrante": "Privado",  # Not provided by whois_lookup.py
            "Email": "Privado",  # Not provided by whois_lookup.py
            "País": "N/A"  # Not provided by whois_lookup.py
        }
    except Exception as e:
        logger.error(f"WHOIS query failed for {validated_domain}: {str(e)}")
        return None

def check_library(library_name: str) -> bool:
    """Check if a library is installed."""
    try:
        import_module(library_name)
        return True
    except ImportError:
        return False

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

def validar_dominio(dominio):
    """Validate that the input is a valid domain."""
    try:
        validate_domain(dominio)
        return True
    except ValueError:
        return False

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

def obtener_ssl(dominio, port=443):
    """Analyze SSL certificate with enhanced error handling and debugging."""
    logger.info(f"Analyzing SSL certificate for {dominio} on port {port}")
    try:
        context = ssl.create_default_context()
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        logger.debug(f"Attempting strict SSL connection to {dominio}:{port}")

        try:
            with socket.create_connection((dominio, port), timeout=DEFAULT_TIMEOUT) as sock:
                with context.wrap_socket(sock, server_hostname=dominio) as ssock:
                    cert = ssock.getpeercert()
                    logger.debug(f"Certificate retrieved for {dominio} with strict validation")
        except (ssl.SSLError, socket.timeout) as strict_error:
            logger.warning(f"Strict SSL connection failed for {dominio}: {type(strict_error).__name__} - {str(strict_error)}")
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

        issuer = dict(x[0] for x in cert.get('issuer', []))
        subject = dict(x[0] for x in cert.get('subject', []))
        
        try:
            not_before = datetime.strptime(cert.get("notBefore", ""), "%b %d %H:%M:%S %Y %Z")
            not_after = datetime.strptime(cert.get("notAfter", ""), "%b %d %H:%M:%S %Y %Z")
        except (ValueError, KeyError) as e:
            logger.warning(f"Error parsing SSL certificate dates: {type(e).__name__} - {str(e)}")
            not_before = not_after = datetime.now(timezone.utc)
        
        if not_before.tzinfo is None:
            not_before = not_before.replace(tzinfo=timezone.utc)
        if not_after.tzinfo is None:
            not_after = not_after.replace(tzinfo=timezone.utc)
        
        ahora = datetime.now(timezone.utc)
        dias_restantes = (not_after - ahora).days
        estado = "✅ Válido" if ahora < not_after else "❌ Expirado"
        if 0 < dias_restantes < 30:
            estado += " ⚠️ Expira pronto"

        def parse_name_components(components):
            if not components:
                return "N/A"
            try:
                return ", ".join([f"{k}: {v}" for k, v in components.items()])
            except Exception as e:
                logger.warning(f"Error parsing certificate components: {type(e).__name__} - {str(e)}")
                return str(components)

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

        if headers.get("Access-Control-Allow-Origin") == "*":
            vulnerabilidades.append("🚨 CORS abierto (*)")
            puntuacion -= 15

        cookies_secure = all(hasattr(c, 'secure') and c.secure for c in response.cookies)
        if response.cookies and not cookies_secure:
            vulnerabilidades.append("❌ Cookies sin Secure flag")
            puntuacion -= 10

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
        
        f.write("1. INFORMACIÓN DNS\n")
        f.write("-" * 40 + "\n")
        if results["dns"]["ips"]:
            f.write(f"IPs resueltas: {', '.join(results['dns']['ips'])}\n")
        else:
            f.write("❌ No se pudieron resolver las IPs\n")
        f.write("\n")
        
        f.write("2. SUBDOMINIOS ANALIZADOS\n")
        f.write("-" * 40 + "\n")
        for sub in results["subdomains"]:
            f.write(f"{sub['status']} {sub['subdomain']}")
            if sub["ips"]:
                f.write(f" → {', '.join(sub['ips'])}")
            f.write("\n")
        f.write("\n")
        
        f.write("3. INFORMACIÓN WHOIS\n")
        f.write("-" * 40 + "\n")
        if results["whois"]:
            for key, value in results["whois"].items():
                f.write(f"{key}: {value}\n")
        else:
            f.write("❌ No se pudo obtener información WHOIS\n")
        f.write("\n")
        
        f.write("4. CERTIFICADO SSL\n")
        f.write("-" * 40 + "\n")
        if results["ssl"] and "Error" not in results["ssl"]:
            for key, value in results["ssl"].items():
                f.write(f"{key}: {value}\n")
        else:
            f.write("❌ No se pudo analizar el certificado SSL\n")
        f.write("\n")
        
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
    
    results = {
        "dns": {"ips": obtener_ip_socket(dominio)},
        "subdomains": analizar_subdominios(dominio),
        "whois": obtener_whois(dominio),
        "ssl": obtener_ssl(dominio),
        "vulnerabilities": analizar_vulnerabilidades(dominio, verbose),
        "geolocation": {}
    }

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