# auditoria.py
# Bitácora de auditoría con cadena de HMAC.
#   - registrar_evento: único punto de escritura. Cada fila guarda el HMAC de sus campos más el
#     hash de la fila anterior, con una llave que no está en la base. Si alguien altera, borra o
#     inserta filas (incluso quitando los triggers), verificar_cadena lo detecta.
#   - Nunca se registran contraseñas, códigos de verificación, tokens, llaves ni valores de campos:
#     solo ids internos, códigos de operación y nombres de campos.
#   - El canal (web/api/sistema) y la IP truncada los fija la capa web con fijar_contexto.

import hmac
import hashlib
import ipaddress
from contextvars import ContextVar
from datetime import datetime, timezone

import db
from config import LLAVE_AUDITORIA

GENESIS = "0" * 64
DIAS_CONSERVACION = 730

_contexto = ContextVar("contexto_auditoria", default=("sistema", None))

# prefijo de la operación -> categoría del evento
_CATEGORIAS = [
    ("auth.", "autenticacion"),
    ("sesion.", "autenticacion"),
    ("consentimiento.", "consentimiento"),
    ("derechos.exportar", "exportacion"),
    ("derechos.suprimir", "supresion"),
    ("cuenta.eliminar", "supresion"),
    ("derechos.rectificar", "modificacion"),
    ("derechos.", "derechos"),
    ("roles.", "administracion"),
    ("retencion.", "administracion"),
    ("auditoria.", "administracion"),
    ("alertas.", "seguridad"),
    ("incidentes.", "seguridad"),
    ("contencion.", "seguridad"),
]


def categoria_de(permiso):
    for prefijo, categoria in _CATEGORIAS:
        if permiso.startswith(prefijo):
            return categoria
    return "acceso" if permiso.endswith(".leer") else "modificacion"


def truncar_ip(ip):
    """La IP completa es un dato personal: se guarda solo la red (/24 en IPv4, /48 en IPv6)."""
    try:
        direccion = ipaddress.ip_address(ip)
    except ValueError:
        return None
    prefijo = 24 if direccion.version == 4 else 48
    return str(ipaddress.ip_network(f"{ip}/{prefijo}", strict=False))


def fijar_contexto(canal, ip=None):
    """Lo llama la capa web al inicio de cada petición. Devuelve un token para restaurar el contexto."""
    return _contexto.set((canal, truncar_ip(ip) if ip else None))


def restaurar_contexto(token):
    _contexto.reset(token)


def _ahora():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


_CAMPOS = ("fecha", "actor_tipo", "actor_id", "rol", "permiso", "categoria", "recurso", "resultado",
           "canal", "origen", "detalle", "hash_previo")


def _calcular_hash(fila):
    mensaje = "|".join("" if fila[c] is None else str(fila[c]) for c in _CAMPOS)
    return hmac.new(LLAVE_AUDITORIA, mensaje.encode("utf-8"), hashlib.sha256).hexdigest()


def registrar_evento(sesion, permiso, recurso=None, resultado="exito", detalle=None):
    """
    Escribe un evento. sesion puede ser None (proceso del sistema o actor no autenticado).
    BEGIN IMMEDIATE toma el bloqueo de escritura antes de leer el último hash, así dos
    procesos no pueden encadenar dos filas al mismo eslabón.
    """
    canal, origen = _contexto.get()
    fila = {
        "fecha": _ahora(),
        "actor_tipo": getattr(sesion, "tipo", None),
        "actor_id": getattr(sesion, "id", None),
        "rol": getattr(sesion, "rol", None),
        "permiso": permiso,
        "categoria": categoria_de(permiso),
        "recurso": None if recurso is None else str(recurso),
        "resultado": resultado,
        "canal": canal,
        "origen": origen,
        "detalle": detalle,
    }
    con = db.conectar()
    con.isolation_level = None
    try:
        con.execute("BEGIN IMMEDIATE")
        ultimo = con.execute("SELECT hash FROM auditoria ORDER BY id DESC LIMIT 1").fetchone()
        fila["hash_previo"] = ultimo["hash"] if ultimo else GENESIS
        fila["hash"] = _calcular_hash(fila)
        columnas = list(fila)
        cur = con.execute(f"INSERT INTO auditoria ({', '.join(columnas)}) VALUES ({', '.join('?' * len(columnas))})",
                          [fila[c] for c in columnas])
        con.execute("COMMIT")
    except Exception:
        con.execute("ROLLBACK")
        raise
    finally:
        con.close()
    if not permiso.startswith("alertas."):
        import deteccion                 # import local: deteccion también registra eventos
        deteccion.revisar(fila, cur.lastrowid)
    return cur.lastrowid


def verificar_cadena():
    """
    Recorre la bitácora y comprueba cada HMAC y cada enlace con la fila anterior.
    Devuelve {"ok", "filas", "error_en"}; error_en es el id de la primera fila que no cuadra.
    Si la primera fila no apunta al génesis, debe existir un evento de purga que lo justifique.
    """
    con = db.conectar()
    filas = con.execute("SELECT * FROM auditoria ORDER BY id").fetchall()
    purgas = {f["detalle"] for f in filas if f["permiso"] == "auditoria.purgar" and f["resultado"] == "exito"}
    con.close()
    anterior = None
    for f in filas:
        esperado_previo = anterior["hash"] if anterior else f["hash_previo"]
        if anterior is None and f["hash_previo"] != GENESIS and not any(
                p and f"ultimo_hash={f['hash_previo']}" in p for p in purgas):
            return {"ok": False, "filas": len(filas), "error_en": f["id"]}
        if f["hash_previo"] != esperado_previo or not hmac.compare_digest(_calcular_hash(f), f["hash"]):
            return {"ok": False, "filas": len(filas), "error_en": f["id"]}
        anterior = f
    return {"ok": True, "filas": len(filas), "error_en": None}


def ancla():
    """Último (id, hash). Guardarlo fuera del servidor permite detectar si se borraron las filas finales."""
    con = db.conectar()
    f = con.execute("SELECT id, hash FROM auditoria ORDER BY id DESC LIMIT 1").fetchone()
    con.close()
    return (f["id"], f["hash"]) if f else (0, GENESIS)


def purgar_vencidos(dias=DIAS_CONSERVACION):
    """
    Elimina los registros que superaron el plazo de conservación (el trigger impide borrar los
    recientes) y deja un evento de purga con el último hash eliminado, que mantiene la cadena verificable.
    Lo invoca nortishop.purgar_auditoria, que exige el permiso auditoria.purgar.
    """
    con = db.conectar()
    vencidas = con.execute("SELECT id, hash FROM auditoria WHERE fecha < datetime('now', ?) ORDER BY id",
                           (f"-{int(dias)} days",)).fetchall()
    if not vencidas:
        con.close()
        return 0, None, None
    ultimo = vencidas[-1]
    con.execute("DELETE FROM auditoria WHERE id <= ? AND fecha < datetime('now', ?)", (ultimo["id"], f"-{int(dias)} days"))
    con.commit()
    con.close()
    return len(vencidas), ultimo["id"], ultimo["hash"]
