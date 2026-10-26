# db.py
# Estructura de la base de datos (SQLite), rediseñada para minimizar datos y aplicar RBAC.
# Los nombres de columna indican cómo está protegido cada campo:
#   *_cifrado  -> AES-256-GCM (con contexto tabla.columna:identificador de la fila)
#   *_hash     -> bcrypt
#   *_indice   -> HMAC (solo para buscar)
#   seudonimo  -> HMAC del id del cliente (sin tabla de correspondencia)
#   token_*    -> token de la pasarela
# Cambios frente al Item II: sin RUT, campos opcionales, consentimiento, bloqueo por intentos,
# region_envio, estado del pedido, rol del personal, seudónimo y bitácora inmutable.

import sqlite3
from config import RUTA_BD

ESQUEMA = """
CREATE TABLE IF NOT EXISTS clientes (
    id                       INTEGER PRIMARY KEY AUTOINCREMENT,
    nombre                   TEXT NOT NULL,
    correo_cifrado           TEXT NOT NULL,
    correo_indice            TEXT NOT NULL UNIQUE,
    password_hash            TEXT NOT NULL,
    telefono_cifrado         TEXT,          -- opcional
    direccion_cifrado        TEXT,          -- opcional
    nortipuntos              INTEGER DEFAULT 0,   -- no es dato personal: su riesgo es de integridad
    consentimiento_analitica INTEGER NOT NULL DEFAULT 0,
    intentos_fallidos        INTEGER NOT NULL DEFAULT 0,
    bloqueado_hasta          TEXT
);

CREATE TABLE IF NOT EXISTS tarjetas_guardadas (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    cliente_id      INTEGER NOT NULL REFERENCES clientes(id),
    token_pasarela  TEXT NOT NULL,
    ultimos4        TEXT NOT NULL,
    marca           TEXT
);

CREATE TABLE IF NOT EXISTS pedidos (
    id                        INTEGER PRIMARY KEY AUTOINCREMENT,
    codigo                    TEXT NOT NULL UNIQUE,
    cliente_id                INTEGER REFERENCES clientes(id),
    es_invitado               INTEGER DEFAULT 0,
    invitado_correo_cifrado   TEXT,
    invitado_telefono_cifrado TEXT,          -- opcional
    direccion_cifrado         TEXT,          -- pasa a NULL con la retención
    detalle_cifrado           TEXT NOT NULL,
    monto                     INTEGER NOT NULL,
    token_pasarela            TEXT NOT NULL,
    ultimos4                  TEXT NOT NULL,
    autorizacion              TEXT,
    fecha                     TEXT DEFAULT CURRENT_TIMESTAMP,
    region_envio              TEXT,
    estado                    TEXT NOT NULL DEFAULT 'pagado'
                              CHECK (estado IN ('pagado','despachado','entregado'))
);

CREATE TABLE IF NOT EXISTS administradores (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    usuario           TEXT NOT NULL UNIQUE,
    password_hash     TEXT NOT NULL,
    rol               TEXT NOT NULL DEFAULT 'soporte'
                      CHECK (rol IN ('administrador','soporte','logistica','marketing')),
    intentos_fallidos INTEGER NOT NULL DEFAULT 0,
    bloqueado_hasta   TEXT
);

CREATE TABLE IF NOT EXISTS boletin_suscriptores (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    correo_cifrado  TEXT NOT NULL,
    correo_indice   TEXT NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS comportamiento_compra (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    seudonimo      TEXT NOT NULL UNIQUE,     -- sin clave foránea a clientes
    datos_cifrado  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS auditoria (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    fecha       TEXT DEFAULT CURRENT_TIMESTAMP,
    actor_tipo  TEXT,
    actor_id    INTEGER,
    rol         TEXT,
    permiso     TEXT NOT NULL,
    recurso     TEXT,
    resultado   TEXT NOT NULL CHECK (resultado IN ('permitido','denegado'))
);

CREATE TRIGGER IF NOT EXISTS auditoria_sin_update BEFORE UPDATE ON auditoria
BEGIN SELECT RAISE(ABORT, 'auditoria es inmutable'); END;

CREATE TRIGGER IF NOT EXISTS auditoria_sin_delete BEFORE DELETE ON auditoria
BEGIN SELECT RAISE(ABORT, 'auditoria es inmutable'); END;
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
