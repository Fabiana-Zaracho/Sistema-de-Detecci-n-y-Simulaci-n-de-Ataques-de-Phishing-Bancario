# PhishGuard API

Backend que carga el modelo entrenado en `PhishGuard_Modelo_IA.ipynb` y analiza
URLs en tiempo real: features léxicas + WHOIS + SSL + explicación con SHAP.

## 1. Preparar el entorno (una sola vez)

Abrí una terminal en VS Code, parado en esta carpeta (`phishguard-api/`), y corré:

```bash
python -m venv venv

# Activar el entorno virtual:
# En Windows:
venv\Scripts\activate
# En Mac/Linux:
source venv/bin/activate

pip install -r requirements.txt
```

## 2. Copiar los archivos del modelo

Del notebook de Colab descargaste 3 archivos:
- `modelo_phishing.pkl`
- `columnas_features.pkl`
- `umbral_decision.pkl`

Copialos dentro de la carpeta `models/` de este proyecto (ya está creada, vacía).
La estructura final debe quedar así:

```
phishguard-api/
├── app/
├── models/
│   ├── modelo_phishing.pkl
│   ├── columnas_features.pkl
│   └── umbral_decision.pkl
├── requirements.txt
└── README.md
```

## 3. Configurar la API key (opcional pero recomendado)

Por defecto usa una clave de desarrollo. Para poner la tuya, antes de levantar el servidor:

```bash
# Mac/Linux:
export PHISHGUARD_API_KEY="tu-clave-secreta"
# Windows (PowerShell):
$env:PHISHGUARD_API_KEY="tu-clave-secreta"
```

## 4. Levantar el servidor

```bash
uvicorn app.main:app --reload
```

Si todo salió bien, en la terminal vas a ver `Modelo cargado. Umbral de decisión: ...`

## 5. Probarlo

Abrí en el navegador: **http://127.0.0.1:8000/docs**

Ahí Swagger te muestra una interfaz para probar el endpoint `/analizar` sin escribir
código. Hacé clic en "Try it out", pegá una URL, poné tu API key en el candado, y
ejecutá.

También podés probarlo por terminal:

```bash
curl -X POST "http://127.0.0.1:8000/analizar" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: clave-de-desarrollo-cambiar-en-produccion" \
  -d '{"url": "http://bancosegur0-login.verificar-cuenta.com/update"}'
```

## Qué devuelve la API

```json
{
  "url": "...",
  "dominio": "...",
  "es_phishing": true,
  "probabilidad_phishing": 0.94,
  "nivel_riesgo": "alto",
  "umbral_usado": 0.35,
  "antiguedad_dominio_dias": 3,
  "ssl_valido": false,
  "senales_principales": [...],
  "explicacion": "Se detectó que el dominio se registró hace solo 3 días, ..."
}
```

## Notas de seguridad ya incluidas

- **Rate limiting**: máximo 30 pedidos por minuto por API key (evita que alguien use
  tu API para escanear masivamente).
- **Autenticación**: header `X-API-Key` obligatorio.
- **Protección contra SSRF**: rechaza analizar dominios que resuelven a IPs privadas
  o localhost (para que no puedan usar tu servidor para escanear tu propia red).
- **Logging**: cada análisis queda registrado (dominio, probabilidad, resultado).

## Siguiente paso

Este backend es el que después va a conectar con:
- El **dashboard/frontend** donde el usuario pega la URL.
- El **módulo de typosquatting** (genera dominios falsos para autoevaluar el modelo).
- **AdGuard Home** (para que las detecciones alimenten automáticamente una blocklist real).
