# db.py
# Estructura de la base de datos (SQLite).
# Los nombres de columna indican cómo está protegido cada campo:
#   *_cifrado  -> AES-256-GCM (con contexto tabla.columna:identificador de la fila)
#   *_hash     -> bcrypt
#   *_indice   -> HMAC (solo para buscar)
#   token_*    -> token de la pasarela

import sqlite3
from config import RUTA_BD

ESQUEMA = """
CREATE TABLE IF NOT EXISTS clientes (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    nombre              TEXT NOT NULL,
    correo_cifrado      TEXT NOT NULL,
    correo_indice       TEXT NOT NULL UNIQUE,
    password_hash       TEXT NOT NULL,
    rut_cifrado         TEXT,
    telefono_cifrado    TEXT,
    direccion_cifrado   TEXT,
    nortipuntos         INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS tarjetas_guardadas (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    cliente_id      INTEGER NOT NULL REFERENCES clientes(id),
    token_pasarela  TEXT NOT NULL,
    ultimos4        TEXT NOT NULL,
    marca           TEXT
);

CREATE TABLE IF NOT EXISTS pedidos (
    id                       INTEGER PRIMARY KEY AUTOINCREMENT,
    codigo                   TEXT NOT NULL UNIQUE,
    cliente_id               INTEGER REFERENCES clientes(id),
    es_invitado              INTEGER DEFAULT 0,
    invitado_correo_cifrado  TEXT,
    invitado_telefono_cifrado TEXT,
    direccion_cifrado        TEXT NOT NULL,
    detalle_cifrado          TEXT NOT NULL,
    monto                    INTEGER NOT NULL,
    token_pasarela           TEXT NOT NULL,
    ultimos4                 TEXT NOT NULL,
    autorizacion             TEXT,
    fecha                    TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS administradores (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    usuario         TEXT NOT NULL UNIQUE,
    password_hash   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS boletin_suscriptores (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    correo_cifrado  TEXT NOT NULL,
    correo_indice   TEXT NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS comportamiento_compra (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    cliente_id          INTEGER NOT NULL REFERENCES clientes(id),
    datos_cifrado       TEXT NOT NULL
);
"""


def conectar():
    con = sqlite3.connect(RUTA_BD)
    con.row_factory = sqlite3.Row
    return con


def crear_tablas():
    con = conectar()
    con.executescript(ESQUEMA)
    con.commit()
    con.close()
