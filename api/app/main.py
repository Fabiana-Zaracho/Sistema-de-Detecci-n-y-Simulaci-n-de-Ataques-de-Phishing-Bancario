"""
PhishGuard API
Carga el modelo entrenado en el notebook (modelo_phishing.pkl, columnas_features.pkl,
umbral_decision.pkl) y expone un endpoint para analizar URLs en tiempo real.

Correr en desarrollo:
    uvicorn app.main:app --reload
Documentación interactiva en: http://127.0.0.1:8000/docs
"""
import ipaddress
import logging
import os
import socket
import time
from collections import defaultdict, deque

import joblib
import numpy as np
import pandas as pd
import xgboost as xgb
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware

from app.features import consultar_ssl, consultar_whois, detectar_suplantacion_marca, extraer_features
from app.schemas import AnalizarURLRequest, AnalizarURLResponse, SenalDetalle

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("phishguard")

MODELS_DIR = os.path.join(os.path.dirname(__file__), "..", "models")
API_KEY = os.environ.get("PHISHGUARD_API_KEY", "clave-de-desarrollo-cambiar-en-produccion")
RATE_LIMIT_REQUESTS = 30       # pedidos
RATE_LIMIT_VENTANA_SEG = 60    # por minuto, por API key

app = FastAPI(title="PhishGuard API", version="0.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # ajustar a dominios reales en producción
    allow_methods=["POST", "GET"],
    allow_headers=["*"],
)

# ---- Carga del modelo al iniciar la API (una sola vez, no en cada request) ----
try:
    modelo = joblib.load(os.path.join(MODELS_DIR, "modelo_phishing.pkl"))
    columnas = joblib.load(os.path.join(MODELS_DIR, "columnas_features.pkl"))
    umbral = joblib.load(os.path.join(MODELS_DIR, "umbral_decision.pkl"))
    logger.info(f"Modelo cargado. Umbral de decisión: {umbral}")
except FileNotFoundError:
    modelo = columnas = umbral = None
    logger.warning(
        "No se encontraron los .pkl en /models. Copiá ahí modelo_phishing.pkl, "
        "columnas_features.pkl y umbral_decision.pkl (descargados del notebook)."
    )

# ---- Lista de dominios de confianza (allowlist) ----
# Práctica estándar en sistemas reales: los dominios conocidos y verificados no pasan por el
# modelo, así no se generan falsos positivos sobre sitios legítimos famosos.
RUTA_ALLOWLIST = os.path.join(os.path.dirname(__file__), "..", "dominios_confiables.txt")


def _cargar_allowlist() -> set[str]:
    try:
        with open(RUTA_ALLOWLIST, encoding="utf-8") as f:
            return {l.strip().lower() for l in f if l.strip() and not l.startswith("#")}
    except FileNotFoundError:
        return set()


DOMINIOS_CONFIABLES = _cargar_allowlist()
logger.info(f"Dominios de confianza cargados: {len(DOMINIOS_CONFIABLES)}")

# ---- Rate limiting simple en memoria (alcanza para desarrollo/demo; en producción
# real conviene Redis si hay más de una instancia de la API corriendo) ----
_historial_requests: dict[str, deque] = defaultdict(deque)


def _chequear_rate_limit(api_key: str):
    ahora = time.time()
    cola = _historial_requests[api_key]
    while cola and ahora - cola[0] > RATE_LIMIT_VENTANA_SEG:
        cola.popleft()
    if len(cola) >= RATE_LIMIT_REQUESTS:
        raise HTTPException(status_code=429, detail="Demasiados pedidos. Esperá un minuto e intentá de nuevo.")
    cola.append(ahora)


def _validar_api_key(x_api_key: str | None):
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="API key inválida o faltante (header X-API-Key).")


def _bloquear_ips_privadas(dominio: str):
    """Evita que alguien use tu API para escanear tu propia red interna (SSRF):
    si el 'dominio' resuelve a una IP privada/localhost, se rechaza el análisis."""
    try:
        ip = socket.gethostbyname(dominio)
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
            raise HTTPException(status_code=400, detail="No se permite analizar direcciones de red privada/local.")
    except socket.gaierror:
        pass  # el dominio no resuelve - lo dejamos seguir, el análisis lo va a marcar como sospechoso igual


def _nivel_riesgo(prob: float) -> str:
    if prob >= 0.70:
        return "alto"
    if prob >= umbral:
        return "medio"
    return "bajo"


@app.get("/health")
def health():
    return {"status": "ok", "modelo_cargado": modelo is not None}


@app.post("/analizar", response_model=AnalizarURLResponse)
def analizar_url(req: AnalizarURLRequest, request: Request, x_api_key: str | None = Header(default=None)):
    if modelo is None:
        raise HTTPException(status_code=503, detail="El modelo no está cargado en el servidor. Ver logs.")

    _validar_api_key(x_api_key)
    _chequear_rate_limit(x_api_key)

    features_dict, dominio_completo, dominio_registrado = extraer_features(req.url)
    _bloquear_ips_privadas(dominio_completo)

    # Dominio de confianza verificado: no se evalúa con el modelo
    if dominio_registrado.lower() in DOMINIOS_CONFIABLES:
        logger.info(f"Analizado: {dominio_completo} -> en lista de confianza")
        return AnalizarURLResponse(
            url=req.url,
            dominio=dominio_completo,
            es_phishing=False,
            probabilidad_phishing=0.0,
            probabilidad_modelo=0.0,
            reglas_activadas=[],
            nivel_riesgo="bajo",
            umbral_usado=umbral,
            antiguedad_dominio_dias=None,
            ssl_valido=None,
            senales_principales=[],
            explicacion=f"{dominio_registrado} está en la lista de dominios de confianza verificados, por lo que no se evaluó con el modelo.",
        )

    # Reordenar features exactamente como las vio el modelo en entrenamiento
    X = pd.DataFrame([features_dict])[columnas]

    probabilidad = float(modelo.predict_proba(X)[0][1])

    # WHOIS y SSL en vivo (solo para mostrarle contexto al usuario, no entran al modelo
    # porque no estaban en el set de entrenamiento masivo - ver notebook)
    info_whois = consultar_whois(dominio_registrado)
    info_ssl = consultar_ssl(dominio_completo)

    # Explicabilidad de ESTA predicción puntual. XGBoost calcula valores SHAP (TreeSHAP) de forma
    # nativa con pred_contribs=True: una contribución por columna y, al final, el valor base
    # (que descartamos con [:-1]). Así no hace falta la librería 'shap' ni 'numba' en la API.
    shap_vals = modelo.get_booster().predict(xgb.DMatrix(X), pred_contribs=True)[0][:-1]
    contribuciones = sorted(
        zip(columnas, X.iloc[0].values, shap_vals), key=lambda t: abs(t[2]), reverse=True
    )[:4]
    senales = [
        SenalDetalle(nombre=nombre, valor=float(valor), peso_en_decision=float(peso))
        for nombre, valor, peso in contribuciones
    ]

    # ---- Capa de reglas: combina el puntaje del modelo con evidencia concreta ----
    # Las reglas SOLO SUBEN el riesgo, nunca lo bajan: un dominio viejo con SSL válido igual puede
    # estar comprometido y alojando phishing, así que "antigüedad" no sirve para dar por seguro.
    reglas = []
    prob_final = probabilidad

    marca = detectar_suplantacion_marca(dominio_completo)
    if marca:
        prob_final = max(prob_final, 0.60)
        reglas.append(f"el dominio contiene o imita el nombre '{marca}' pero no es un dominio oficial verificado")

    antiguedad = info_whois["antiguedad_dias"]
    if antiguedad is not None and antiguedad < 30:
        prob_final = min(1.0, prob_final + 0.25)
        reglas.append(f"el dominio se registró hace solo {antiguedad} días")

    if info_ssl["tiene_ssl_valido"] is False:
        prob_final = min(1.0, prob_final + 0.15)
        reglas.append("su certificado SSL no es válido")

    es_phishing = prob_final >= umbral

    if reglas:
        explicacion = "Se detectó que " + "; ".join(reglas) + "."
    else:
        explicacion = "El modelo se basó principalmente en patrones estructurales de la URL (ver señales principales)."

    logger.info(
        f"Analizado: {dominio_completo} -> modelo={probabilidad:.3f} final={prob_final:.3f} "
        f"phishing={es_phishing} reglas={len(reglas)}"
    )

    return AnalizarURLResponse(
        url=req.url,
        dominio=dominio_completo,
        es_phishing=es_phishing,
        probabilidad_phishing=round(prob_final, 4),
        probabilidad_modelo=round(probabilidad, 4),
        reglas_activadas=reglas,
        nivel_riesgo=_nivel_riesgo(prob_final),
        umbral_usado=umbral,
        antiguedad_dominio_dias=antiguedad,
        ssl_valido=info_ssl["tiene_ssl_valido"],
        senales_principales=senales,
        explicacion=explicacion,
    )
