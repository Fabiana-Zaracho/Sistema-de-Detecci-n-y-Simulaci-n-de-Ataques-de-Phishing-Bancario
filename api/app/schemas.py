from pydantic import BaseModel, Field


class AnalizarURLRequest(BaseModel):
    url: str = Field(..., min_length=4, max_length=2048, description="URL a analizar")


class SenalDetalle(BaseModel):
    nombre: str
    valor: float
    peso_en_decision: float


class AnalizarURLResponse(BaseModel):
    url: str
    dominio: str
    es_phishing: bool
    probabilidad_phishing: float  # resultado final (modelo + reglas)
    probabilidad_modelo: float    # lo que dijo solo el modelo de ML
    reglas_activadas: list[str] = []
    nivel_riesgo: str  # "bajo" | "medio" | "alto"
    umbral_usado: float
    antiguedad_dominio_dias: int | None
    ssl_valido: bool | None
    senales_principales: list[SenalDetalle]
    explicacion: str
