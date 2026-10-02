# config.py
# Carga las llaves desde el archivo .env (variables de entorno).
# Las llaves NUNCA se escriben en el código, solo se leen desde el entorno.

import os
import re
import base64
from dotenv import load_dotenv

load_dotenv()


def _decodificar(nombre, valor):
    llave = base64.b64decode(valor)
    if len(llave) != 32:
        raise RuntimeError(f"{nombre} debe ser de 32 bytes (256 bits)")
    return llave


def _leer_llave(nombre):
    valor = os.getenv(nombre)
    if not valor:
        # si falta la llave el programa no parte, así no se usa una llave por defecto
        raise RuntimeError(f"Falta la variable de entorno {nombre}. Ejecuta generar_llaves.py primero.")
    return _decodificar(nombre, valor)


def _leer_llaves_cifrado():
    """
    Lee todas las versiones de la llave de cifrado (NORTISHOP_LLAVE_CIFRADO_V1, _V2, ...).
    Para rotar se agrega una versión nueva: los datos nuevos se cifran con la más reciente
    y los antiguos se siguen pudiendo leer con la versión que indica su prefijo (v1:, v2:, ...).
    """
    llaves = {}
    for nombre, valor in os.environ.items():
        m = re.fullmatch(r"NORTISHOP_LLAVE_CIFRADO_V(\d+)", nombre)
        if m and valor:
            llaves[f"v{m.group(1)}"] = _decodificar(nombre, valor)
    if not llaves:
        raise RuntimeError("Falta la variable de entorno NORTISHOP_LLAVE_CIFRADO_V1. Ejecuta generar_llaves.py primero.")
    return llaves


# llaves para cifrar con AES-256-GCM (RUT, dirección, correos, etc), por versión
LLAVES_CIFRADO = _leer_llaves_cifrado()

# versión con la que se cifran los datos nuevos (la más reciente)
VERSION_ACTUAL = max(LLAVES_CIFRADO, key=lambda v: int(v[1:]))

# llave aparte para el índice de búsqueda (HMAC) del correo
LLAVE_INDICE = _leer_llave("NORTISHOP_LLAVE_INDICE")

# secreto compartido con la pasarela para verificar la firma de sus respuestas
LLAVE_PASARELA = _leer_llave("NORTISHOP_LLAVE_PASARELA")

# factor de costo de bcrypt para las contraseñas
BCRYPT_COSTO = 12

RUTA_BD = os.getenv("NORTISHOP_RUTA_BD", "nortishop.db")
