# db.py
# Estructura de la base de datos (SQLite), rediseñada para minimizar datos y aplicar RBAC.
# Los nombres de columna indican cómo está protegido cada campo:
#   *_cifrado  -> AES-256-GCM (con contexto tabla.columna:identificador de la fila)
#   *_hash     -> bcrypt (contraseñas) o SHA-256/HMAC (tokens, códigos, bitácora)
#   *_indice   -> HMAC (solo para buscar)
#   seudonimo  -> HMAC del id del cliente (sin tabla de correspondencia)
#   token_*    -> token de la pasarela
# Actividad 4: sin RUT, campos opcionales, bloqueo por intentos, region_envio, estado del pedido,
# rol del personal, seudónimo y bitácora inmutable.
# Actividad 5: consentimiento por finalidad, solicitudes de derechos, sesiones, bitácora encadenada,
# alertas, incidentes y contención (cuentas deshabilitadas, permisos suspendidos).

import os
import stat
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
    mayoria_edad_declarada   TEXT NOT NULL,       -- fecha en que declaró ser mayor de 18 (no se guarda la edad)
    intentos_fallidos        INTEGER NOT NULL DEFAULT 0,
    bloqueado_hasta          TEXT,
    deshabilitada            INTEGER NOT NULL DEFAULT 0   -- contención de incidentes
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
                      CHECK (rol IN ('administrador','soporte','logistica','marketing','privacidad','seguridad')),
    intentos_fallidos INTEGER NOT NULL DEFAULT 0,
    bloqueado_hasta   TEXT,
    deshabilitada     INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS boletin_suscriptores (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    correo_cifrado  TEXT NOT NULL,
    correo_indice   TEXT NOT NULL UNIQUE,
    cliente_id      INTEGER REFERENCES clientes(id)   -- NULL si se suscribió sin cuenta
);

CREATE TABLE IF NOT EXISTS comportamiento_compra (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    seudonimo      TEXT NOT NULL UNIQUE,     -- sin clave foránea a clientes
    datos_cifrado  TEXT NOT NULL
);

-- ---------------- Consentimiento (Actividad 5) ----------------

CREATE TABLE IF NOT EXISTS finalidades (
    codigo                  TEXT PRIMARY KEY,
    descripcion             TEXT NOT NULL,
    base_legal              TEXT NOT NULL,
    requiere_consentimiento INTEGER NOT NULL CHECK (requiere_consentimiento IN (0,1))
);

CREATE TABLE IF NOT EXISTS textos_consentimiento (
    finalidad         TEXT NOT NULL REFERENCES finalidades(codigo),
    version           INTEGER NOT NULL,
    texto             TEXT NOT NULL,
    texto_hash        TEXT NOT NULL,        -- SHA-256 del texto: prueba qué se informó exactamente
    cambio_material   INTEGER NOT NULL DEFAULT 0,   -- 1 = los consentimientos anteriores dejan de valer
    vigente_desde     TEXT NOT NULL,
    PRIMARY KEY (finalidad, version)
);

-- Solo de agregar: cada fila es un otorgamiento o una revocación. El estado vigente es el último evento.
CREATE TABLE IF NOT EXISTS consentimientos (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    titular_tipo  TEXT NOT NULL CHECK (titular_tipo IN ('cliente','suscriptor','seudonimo')),
    titular_ref   TEXT NOT NULL,            -- id del cliente, índice HMAC del correo o seudónimo
    finalidad     TEXT NOT NULL REFERENCES finalidades(codigo),
    version       INTEGER NOT NULL,
    accion        TEXT NOT NULL CHECK (accion IN ('otorgado','revocado')),
    fecha         TEXT NOT NULL,
    canal         TEXT NOT NULL,
    FOREIGN KEY (finalidad, version) REFERENCES textos_consentimiento(finalidad, version)
);
CREATE INDEX IF NOT EXISTS consentimientos_titular ON consentimientos (titular_tipo, titular_ref, finalidad);

-- Lo único modificable es el titular, y solo para seudonimizarlo al suprimir la cuenta.
CREATE TRIGGER IF NOT EXISTS consentimientos_sin_update BEFORE UPDATE ON consentimientos
WHEN NEW.titular_tipo <> 'seudonimo' OR NEW.id IS NOT OLD.id OR NEW.finalidad IS NOT OLD.finalidad
  OR NEW.version IS NOT OLD.version OR NEW.accion IS NOT OLD.accion OR NEW.fecha IS NOT OLD.fecha
  OR NEW.canal IS NOT OLD.canal
BEGIN SELECT RAISE(ABORT, 'el historial de consentimientos no se modifica'); END;

-- Solo se borra el historial seudonimizado que cumplió su plazo de conservación (2 años).
CREATE TRIGGER IF NOT EXISTS consentimientos_sin_delete BEFORE DELETE ON consentimientos
WHEN OLD.titular_tipo <> 'seudonimo' OR OLD.fecha >= datetime('now', '-730 days')
BEGIN SELECT RAISE(ABORT, 'el historial de consentimientos no se borra'); END;

-- ---------------- Ejercicio de derechos (Actividad 5) ----------------

CREATE TABLE IF NOT EXISTS solicitudes_derechos (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    codigo              TEXT NOT NULL UNIQUE,
    cliente_id          INTEGER REFERENCES clientes(id),   -- NULL tras la supresión
    titular_seudonimo   TEXT NOT NULL,                     -- permite el seguimiento sin identificar
    tipo                TEXT NOT NULL CHECK (tipo IN ('acceso','portabilidad','rectificacion','supresion')),
    estado              TEXT NOT NULL DEFAULT 'recibida'
                        CHECK (estado IN ('recibida','verificada','en_evaluacion','ejecutada','rechazada','cerrada')),
    fecha_recepcion     TEXT NOT NULL,
    fecha_verificacion  TEXT,
    fecha_evaluacion    TEXT,
    fecha_respuesta     TEXT,
    fecha_cierre        TEXT,
    plazo_vence         TEXT NOT NULL,
    prorrogada          INTEGER NOT NULL DEFAULT 0,
    resultado           TEXT,                              -- respuesta fundamentada, sin datos personales
    detalle_cifrado     TEXT,                              -- valores nuevos de una rectificación
    evaluador_id        INTEGER REFERENCES administradores(id)
);

CREATE TABLE IF NOT EXISTS verificaciones_identidad (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    solicitud_id  INTEGER NOT NULL REFERENCES solicitudes_derechos(id),
    proposito     TEXT NOT NULL CHECK (proposito IN ('titular','correo_nuevo')),
    codigo_hash   TEXT NOT NULL,            -- HMAC del código de un solo uso; el código no se guarda
    expira        TEXT NOT NULL,
    intentos      INTEGER NOT NULL DEFAULT 0,
    usado         INTEGER NOT NULL DEFAULT 0
);

-- Índices de correos suprimidos: al restaurar un respaldo se vuelven a aplicar las supresiones.
CREATE TABLE IF NOT EXISTS lista_supresion (
    correo_indice  TEXT PRIMARY KEY,
    fecha          TEXT NOT NULL
);

-- ---------------- Sesiones (Actividad 5) ----------------

CREATE TABLE IF NOT EXISTS sesiones (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    token_hash  TEXT NOT NULL UNIQUE,      -- SHA-256 del token; el token solo lo tiene el navegador
    actor_tipo  TEXT NOT NULL CHECK (actor_tipo IN ('cliente','personal')),
    actor_id    INTEGER NOT NULL,
    creada      TEXT NOT NULL,
    expira      TEXT NOT NULL,
    revocada    INTEGER NOT NULL DEFAULT 0
);

-- ---------------- Auditoría ----------------

CREATE TABLE IF NOT EXISTS auditoria (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    fecha        TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    actor_tipo   TEXT,
    actor_id     INTEGER,
    rol          TEXT,
    permiso      TEXT NOT NULL,            -- operación realizada (p. ej. derechos.exportar)
    categoria    TEXT NOT NULL,
    recurso      TEXT,                     -- id interno o código, nunca un dato personal
    resultado    TEXT NOT NULL CHECK (resultado IN ('permitido','denegado','exito','fallido')),
    canal        TEXT NOT NULL,            -- web | api | sistema
    origen       TEXT,                     -- IP truncada (/24 o /48)
    detalle      TEXT,                     -- nombres de campos o motivos, nunca valores
    hash_previo  TEXT NOT NULL,
    hash         TEXT NOT NULL             -- HMAC(llave de auditoría, campos + hash_previo)
);

CREATE TRIGGER IF NOT EXISTS auditoria_sin_update BEFORE UPDATE ON auditoria
BEGIN SELECT RAISE(ABORT, 'auditoria es inmutable'); END;

-- Solo se pueden eliminar registros que superaron el plazo de conservación (2 años).
CREATE TRIGGER IF NOT EXISTS auditoria_sin_delete BEFORE DELETE ON auditoria
WHEN OLD.fecha >= datetime('now', '-730 days')
BEGIN SELECT RAISE(ABORT, 'auditoria es inmutable'); END;

-- ---------------- Detección e incidentes (Actividad 5) ----------------

CREATE TABLE IF NOT EXISTS alertas (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    fecha        TEXT NOT NULL,
    regla        TEXT NOT NULL,
    severidad    TEXT NOT NULL CHECK (severidad IN ('baja','media','alta','critica')),
    actor_tipo   TEXT,
    actor_id     INTEGER,
    descripcion  TEXT NOT NULL,            -- sin datos personales
    objeto       TEXT,                     -- cuenta o actor observado: evita duplicar la misma alerta
    estado       TEXT NOT NULL DEFAULT 'abierta'
                 CHECK (estado IN ('abierta','en_analisis','descartada','incidente')),
    incidente_id INTEGER REFERENCES incidentes(id)
);

CREATE TABLE IF NOT EXISTS incidentes (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    codigo                TEXT NOT NULL UNIQUE,
    fecha_deteccion       TEXT NOT NULL,
    inicio_estimado       TEXT,
    fin_estimado          TEXT,
    tipo                  TEXT NOT NULL,
    severidad             TEXT NOT NULL CHECK (severidad IN ('baja','media','alta','critica')),
    fase                  TEXT NOT NULL DEFAULT 'analisis'
                          CHECK (fase IN ('analisis','contencion','erradicacion','recuperacion',
                                          'notificacion','lecciones','cerrado')),
    descripcion           TEXT NOT NULL,
    datos_afectados       TEXT,           -- categorías (correo, dirección, ...), no los datos
    titulares_afectados   INTEGER,
    notificar_agencia     INTEGER,        -- NULL = sin decidir
    notificar_titulares   INTEGER,
    fecha_notificacion    TEXT,
    medidas               TEXT,
    lecciones             TEXT,
    responsable_id        INTEGER REFERENCES administradores(id),
    fecha_cierre          TEXT
);

CREATE TABLE IF NOT EXISTS permisos_suspendidos (
    permiso     TEXT PRIMARY KEY,
    desde       TEXT NOT NULL,
    incidente   TEXT
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
    from consentimiento import cargar_finalidades     # import local: consentimiento usa db
    cargar_finalidades(con)
    con.close()
    # la base contiene datos protegidos: solo el dueño del proceso la puede leer
    os.chmod(RUTA_BD, stat.S_IRUSR | stat.S_IWUSR)
