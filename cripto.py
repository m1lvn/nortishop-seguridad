# cripto.py
# Funciones de protección de datos:
#   - hashing de contraseñas (bcrypt)
#   - cifrado / descifrado AES-256-GCM con contexto (AAD) y versión de llave
#   - índice de búsqueda con HMAC-SHA256 (para buscar por correo sin descifrar todo)
#   - firma HMAC-SHA256 de las respuestas de la pasarela

import os
import base64
import hmac
import hashlib
import json

import bcrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from config import LLAVES_CIFRADO, VERSION_ACTUAL, LLAVE_INDICE, BCRYPT_COSTO


# ---------------- HASHING (contraseñas) ----------------

def hashear_password(password):
    """Genera el hash bcrypt con salt aleatorio. No se puede revertir."""
    salt = bcrypt.gensalt(rounds=BCRYPT_COSTO)
    return bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")


def verificar_password(password_ingresada, hash_guardado):
    """Valida la contraseña comparando hashes (no se descifra nada)."""
    return bcrypt.checkpw(password_ingresada.encode("utf-8"), hash_guardado.encode("utf-8"))


# ---------------- CIFRADO (AES-256-GCM) ----------------
# Formato guardado en la BD:  v1:<base64(nonce + texto cifrado + etiqueta)>
#   - "v1" indica con qué versión de llave se cifró (permite rotar llaves)
#   - el contexto (AAD) amarra el dato a su tabla, columna y fila: no se cifra,
#     pero si no coincide al descifrar, GCM rechaza el dato. Así un valor cifrado
#     no se puede copiar a otra fila o columna.

def cifrar(texto, contexto):
    """Cifra un texto con la llave actual. Devuelve 'version:base64'."""
    if texto is None:
        return None
    aes = AESGCM(LLAVES_CIFRADO[VERSION_ACTUAL])
    nonce = os.urandom(12)  # nonce distinto en cada cifrado
    cifrado = aes.encrypt(nonce, texto.encode("utf-8"), contexto.encode("utf-8"))
    return VERSION_ACTUAL + ":" + base64.b64encode(nonce + cifrado).decode("utf-8")


def descifrar(texto_cifrado, contexto):
    """
    Recupera el texto original. Si el dato fue modificado, se movió a otra fila
    o la llave no corresponde, GCM lo detecta y lanza InvalidTag.
    """
    if texto_cifrado is None:
        return None
    version, b64 = texto_cifrado.split(":", 1)
    if version not in LLAVES_CIFRADO:
        raise ValueError(f"No existe la llave de cifrado {version}")
    datos = base64.b64decode(b64)
    nonce, cifrado = datos[:12], datos[12:]
    aes = AESGCM(LLAVES_CIFRADO[version])
    return aes.decrypt(nonce, cifrado, contexto.encode("utf-8")).decode("utf-8")


def cifrar_json(objeto, contexto):
    """Para datos con estructura (historial, comportamiento de compra)."""
    return cifrar(json.dumps(objeto, ensure_ascii=False), contexto)


def descifrar_json(texto_cifrado, contexto):
    return json.loads(descifrar(texto_cifrado, contexto))


# ---------------- ÍNDICE DE BÚSQUEDA ----------------

def indice_busqueda(valor):
    """
    Como el cifrado usa un nonce aleatorio, el mismo correo cifrado dos veces
    da resultados distintos y no se puede buscar con WHERE. Por eso se guarda
    además un HMAC del correo (con otra llave) que sirve solo para buscar.
    """
    normalizado = valor.strip().lower().encode("utf-8")
    return hmac.new(LLAVE_INDICE, normalizado, hashlib.sha256).hexdigest()


# ---------------- FIRMA (respuesta de la pasarela) ----------------

def _mensaje_pago(resp):
    return f"{resp['orden']}|{resp['aprobado']}|{resp['codigo']}|{resp['autorizacion']}|{resp['monto']}"


def firmar_respuesta(llave, resp):
    """HMAC-SHA256 de los campos de la respuesta. Lo calcula la pasarela."""
    return hmac.new(llave, _mensaje_pago(resp).encode("utf-8"), hashlib.sha256).hexdigest()


def firma_valida(llave, resp):
    """Recalcula la firma y la compara en tiempo constante. Lo hace NortiShop."""
    esperada = firmar_respuesta(llave, resp)
    return hmac.compare_digest(esperada, resp.get("firma", ""))


def enmascarar(valor, visibles=4):
    """Para mostrar en pantalla/logs sin exponer el dato completo."""
    if not valor:
        return valor
    return "*" * max(len(valor) - visibles, 0) + valor[-visibles:]
