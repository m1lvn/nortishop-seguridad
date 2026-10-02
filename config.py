# config.py
# Carga las llaves desde el archivo .env (variables de entorno).
# Las llaves NUNCA se escriben en el código, solo se leen desde el entorno.

import os
import base64
from dotenv import load_dotenv

load_dotenv()


def _leer_llave(nombre):
    valor = os.getenv(nombre)
    if not valor:
        # si falta la llave el programa no parte, así no se usa una llave por defecto
        raise RuntimeError(f"Falta la variable de entorno {nombre}. Ejecuta generar_llaves.py primero.")
    llave = base64.b64decode(valor)
    if len(llave) != 32:
        raise RuntimeError(f"{nombre} debe ser de 32 bytes (256 bits)")
    return llave


# llave para cifrar con AES-256-GCM (RUT, dirección, correos, etc)
LLAVE_CIFRADO = _leer_llave("NORTISHOP_LLAVE_CIFRADO")

# llave aparte para el índice de búsqueda (HMAC) del correo
LLAVE_INDICE = _leer_llave("NORTISHOP_LLAVE_INDICE")

# factor de costo de bcrypt para las contraseñas
BCRYPT_COSTO = 12

RUTA_BD = os.getenv("NORTISHOP_RUTA_BD", "nortishop.db")
