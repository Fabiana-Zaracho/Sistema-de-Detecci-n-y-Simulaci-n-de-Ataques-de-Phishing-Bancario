from flask import Flask, render_template, request
from urllib.parse import urlparse

app = Flask(__name__)


def analizar_url(url):
    resultados = []
    riesgo = 0

    # Agregar protocolo si el usuario no lo escribió
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    datos = urlparse(url)
    dominio = datos.netloc.lower()

    # 1. Comprobar HTTPS
    if datos.scheme == "https":
        resultados.append("✅ Utiliza HTTPS")
    else:
        resultados.append("⚠️ No utiliza HTTPS")
        riesgo += 15

    # 2. Comprobar longitud de la URL
    if len(url) > 75:
        resultados.append("⚠️ La URL es demasiado larga")
        riesgo += 15
    else:
        resultados.append("✅ Longitud de URL normal")

    # 3. Comprobar si utiliza una dirección IP
    dominio_sin_puntos = dominio.replace(".", "")

    if dominio_sin_puntos.isdigit():
        resultados.append("⚠️ Utiliza una dirección IP en lugar de un dominio")
        riesgo += 30
    else:
        resultados.append("✅ Utiliza un nombre de dominio")

    # 4. Buscar palabras relacionadas con phishing
    palabras_sospechosas = [
        "login",
        "verify",
        "verification",
        "verificar",
        "secure",
        "seguridad",
        "account",
        "cuenta",
        "password",
        "banco",
        "bank",
        "confirm",
        "confirmation"
    ]

    encontradas = []

    for palabra in palabras_sospechosas:
        if palabra in url.lower():
            encontradas.append(palabra)

    if encontradas:
        resultados.append(
            "⚠️ Contiene palabras sospechosas: "
            + ", ".join(encontradas)
        )
        riesgo += 10
    else:
        resultados.append(
            "✅ No se detectaron palabras sospechosas"
        )

    # 5. Comprobar cantidad de subdominios
    cantidad_puntos = dominio.count(".")

    if cantidad_puntos >= 3:
        resultados.append(
            "⚠️ El dominio posee varios subdominios"
        )
        riesgo += 10
    else:
        resultados.append(
            "✅ Estructura de dominio normal"
        )

    # 6. Comprobar símbolo @
    if "@" in url:
        resultados.append(
            "⚠️ La URL contiene el símbolo @"
        )
        riesgo += 20
    else:
        resultados.append(
            "✅ No contiene el símbolo @"
        )

    # No permitir que el riesgo supere 100
    riesgo = min(riesgo, 100)

    # Clasificación
    if riesgo >= 60:
        clasificacion = "🔴 POSIBLE PHISHING"
    elif riesgo >= 30:
        clasificacion = "🟡 SOSPECHOSO"
    else:
        clasificacion = "🟢 PROBABLEMENTE SEGURO"

    return clasificacion, riesgo, resultados


@app.route("/", methods=["GET", "POST"])
def inicio():

    resultado = None
    riesgo = None
    detalles = []
    url_analizada = ""

    if request.method == "POST":

        url_analizada = request.form.get("url", "").strip()

        if url_analizada:
            resultado, riesgo, detalles = analizar_url(
                url_analizada
            )

    return render_template(
        "index.html",
        resultado=resultado,
        riesgo=riesgo,
        detalles=detalles,
        url_analizada=url_analizada
    )


if __name__ == "__main__":
    app.run(debug=True)