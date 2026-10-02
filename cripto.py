# cripto.py
# Funciones de protección de datos:
#   - hashing de contraseñas (bcrypt)
#   - cifrado / descifrado AES-256-GCM
#   - índice de búsqueda con HMAC-SHA256 (para buscar por correo sin descifrar todo)

import os
import base64
import hmac
import hashlib
import json

import bcrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from config import LLAVE_CIFRADO, LLAVE_INDICE, BCRYPT_COSTO


# ---------------- HASHING (contraseñas) ----------------

def hashear_password(password):
    """Genera el hash bcrypt con salt aleatorio. No se puede revertir."""
    salt = bcrypt.gensalt(rounds=BCRYPT_COSTO)
    return bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")


def verificar_password(password_ingresada, hash_guardado):
    """Valida la contraseña comparando hashes (no se descifra nada)."""
    return bcrypt.checkpw(password_ingresada.encode("utf-8"), hash_guardado.encode("utf-8"))


# ---------------- CIFRADO (AES-256-GCM) ----------------

def cifrar(texto):
    """Cifra un texto. Devuelve nonce + texto cifrado en base64."""
    if texto is None:
        return None
    aes = AESGCM(LLAVE_CIFRADO)
    nonce = os.urandom(12)  # nonce distinto en cada cifrado
    cifrado = aes.encrypt(nonce, texto.encode("utf-8"), None)
    return base64.b64encode(nonce + cifrado).decode("utf-8")


def descifrar(texto_cifrado):
    """Recupera el texto original. Si alguien modificó el dato, GCM lo detecta y falla."""
    if texto_cifrado is None:
        return None
    datos = base64.b64decode(texto_cifrado)
    nonce, cifrado = datos[:12], datos[12:]
    aes = AESGCM(LLAVE_CIFRADO)
    return aes.decrypt(nonce, cifrado, None).decode("utf-8")


def cifrar_json(objeto):
    """Para datos con estructura (historial, comportamiento de compra)."""
    return cifrar(json.dumps(objeto, ensure_ascii=False))


def descifrar_json(texto_cifrado):
    return json.loads(descifrar(texto_cifrado))


# ---------------- ÍNDICE DE BÚSQUEDA ----------------

def indice_busqueda(valor):
    """
    Como el cifrado usa un nonce aleatorio, el mismo correo cifrado dos veces
    da resultados distintos y no se puede buscar con WHERE. Por eso se guarda
    además un HMAC del correo (con otra llave) que sirve solo para buscar.
    """
    normalizado = valor.strip().lower().encode("utf-8")
    return hmac.new(LLAVE_INDICE, normalizado, hashlib.sha256).hexdigest()


def enmascarar(valor, visibles=4):
    """Para mostrar en pantalla/logs sin exponer el dato completo."""
    if not valor:
        return valor
    return "*" * max(len(valor) - visibles, 0) + valor[-visibles:]
