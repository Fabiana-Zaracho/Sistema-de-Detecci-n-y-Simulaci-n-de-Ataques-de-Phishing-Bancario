"""
Extracción de features de una URL, en tiempo real, para la API.
Usa la MISMA lógica que el notebook de entrenamiento (PhishGuard_Modelo_IA.ipynb)
para que las columnas que ve el modelo sean idénticas a las de entrenamiento.

Acá SÍ consultamos WHOIS y SSL en vivo (a diferencia del entrenamiento masivo),
porque el usuario analiza una sola URL por vez y podemos esperar 1-3 segundos.
"""
import re
import math
import ssl
import socket
from datetime import datetime
from urllib.parse import urlparse

import tldextract
import whois
import Levenshtein

MARCAS_BANCARIAS = [
    # Bancos de Paraguay confirmados (fuente: ABC Color, abril 2026, datos del BCP).
    # IMPORTANTE: estos nombres deben parecerse al nombre que usa cada banco en su dirección web
    # oficial (por ej. el 'itau' de itau.com.py). Verificá cada uno en el sitio real del banco y
    # ajustalo si usa otro nombre. Faltan 4 bancos de la lista oficial del BCP: agregalos acá.
    'continental', 'itau', 'gnb', 'bnf', 'familiar', 'atlas',
    'interfisa', 'zeta', 'basa', 'solar',
]

# Nombres que usan los bancos en sus direcciones web reales (verificados a mano). Esta lista es SOLO
# para la regla de suplantación; es independiente de MARCAS_BANCARIAS, que alimenta al modelo y
# no se puede cambiar sin reentrenar. Los nombres cortos se comparan de forma exacta.
MARCAS_REGLAS = [
    "itau", "familiar", "continental", "bancontinental", "gnb", "bancognb", "bnf",
    "atlas", "bancoatlas", "interfisa", "zeta", "zbanco", "basa", "bancobasa", "solar",
]

PALABRAS_SOSPECHOSAS = ["login", "verify", "secure", "account", "update", "confirm"]


def _calcular_entropia(cadena: str) -> float:
    if not cadena:
        return 0.0
    prob = [cadena.count(c) / len(cadena) for c in set(cadena)]
    return -sum(p * math.log2(p) for p in prob)


def _distancia_a_marca_conocida(dominio: str) -> int:
    if not dominio:
        return 99
    return min(Levenshtein.distance(dominio, marca) for marca in MARCAS_BANCARIAS)


def _tiene_ip_en_url(url: str) -> int:
    patron_ip = r"(\d{1,3}\.){3}\d{1,3}"
    return 1 if re.search(patron_ip, url) else 0


def _contar_subdominios(dominio_completo: str) -> int:
    return dominio_completo.count(".")


def extraer_features(url: str) -> dict:
    """Devuelve el mismo diccionario de features que se usó para entrenar el modelo.
    El orden/nombres de claves debe coincidir con columnas_features.pkl."""
    parsed = urlparse(url if url.startswith("http") else "http://" + url)
    ext = tldextract.extract(url)
    dominio = ext.domain
    dominio_completo = (
        f"{ext.subdomain}.{ext.domain}.{ext.suffix}" if ext.subdomain else f"{ext.domain}.{ext.suffix}"
    )

    dominio_registrado = ext.registered_domain or dominio_completo

    features = {
        "longitud_url": len(url),
        "longitud_dominio": len(dominio),
        "cantidad_puntos": dominio_completo.count("."),
        "cantidad_guiones": dominio.count("-"),
        "cantidad_arrobas": url.count("@"),
        "cantidad_digitos": sum(c.isdigit() for c in dominio),
        "tiene_https": 1 if parsed.scheme == "https" else 0,
        "tiene_ip": _tiene_ip_en_url(url),
        "cantidad_subdominios": _contar_subdominios(dominio_completo),
        "entropia_dominio": _calcular_entropia(dominio),
        "distancia_marca_bancaria": _distancia_a_marca_conocida(dominio),
        "longitud_path": len(parsed.path),
        "tiene_palabra_sospechosa": 1 if any(p in url.lower() for p in PALABRAS_SOSPECHOSAS) else 0,
    }
    return features, dominio_completo, dominio_registrado


def consultar_whois(dominio_completo: str) -> dict:
    """Antigüedad del dominio en días. -1 si no se pudo determinar (dominio
    privado, WHOIS caído, etc. - no tratamos esto como error fatal)."""
    try:
        info = whois.whois(dominio_completo)
        fecha_creacion = info.creation_date
        if isinstance(fecha_creacion, list):
            fecha_creacion = fecha_creacion[0]
        if fecha_creacion:
            dias = (datetime.now() - fecha_creacion).days
            return {"antiguedad_dias": dias, "disponible": True}
        return {"antiguedad_dias": None, "disponible": False}
    except Exception:
        return {"antiguedad_dias": None, "disponible": False}


def consultar_ssl(dominio: str) -> dict:
    """Verifica el certificado SSL. Devuelve tiene_ssl_valido:
       True  -> certificado válido
       False -> el sitio respondió pero el certificado NO es válido (señal de riesgo real)
       None  -> no se pudo verificar (sin conexión, timeout, bloqueo de red local...).
                No se usa como señal de riesgo, porque el problema puede estar en tu red."""
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((dominio, 443), timeout=6) as sock:
            with ctx.wrap_socket(sock, server_hostname=dominio) as ssock:
                cert = ssock.getpeercert()
                emisor = dict(x[0] for x in cert.get("issuer", []))
                return {"tiene_ssl_valido": True, "emisor": emisor.get("organizationName", "desconocido")}
    except ssl.SSLCertVerificationError:
        return {"tiene_ssl_valido": False, "emisor": None}
    except Exception:
        return {"tiene_ssl_valido": None, "emisor": None}


# Sustituciones típicas de "leetspeak" que usan los atacantes (1tau -> itau, b4nco -> banco)
_LEET = str.maketrans("01345@$", "oieasas")


def detectar_suplantacion_marca(dominio_completo: str) -> str | None:
    """Devuelve la marca bancaria que el dominio parece suplantar, o None.

    Divide el dominio en palabras (por puntos y guiones) y busca la marca:
      - igual a la marca, o igual tras deshacer sustituciones tipo 1->i, 0->o  (itau, 1tau)
      - para nombres largos (7+ letras), contenida en una palabra o con 1-2 letras de diferencia
        (continental, continenta1, bancontinental)
    Los nombres cortos (gnb, bnf, basa, zeta) solo se comparan de forma exacta, porque la
    comparación aproximada daría demasiados falsos positivos (ej. 'beta' vs 'zeta').
    OJO: esto solo se usa para dominios que NO están en la lista de confianza; el sitio oficial
    de cada banco debe estar en dominios_confiables.txt, o también quedaría marcado.
    """
    tokens = [t for t in re.split(r"[.\-_]", dominio_completo.lower()) if t and t != "www"]
    for token in tokens:
        normal = token.translate(_LEET)
        for marca in MARCAS_REGLAS:
            if token == marca or normal == marca:
                return marca
            if len(marca) >= 7:
                if marca in token or marca in normal:
                    return marca
                if len(normal) >= 7 and Levenshtein.distance(normal, marca) <= 2:
                    return marca
    return None
