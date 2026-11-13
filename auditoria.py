# auditoria.py
# Bitácora de auditoría con cadena de HMAC.
#   - registrar_evento: único punto de escritura. Cada fila guarda el HMAC de sus campos más el
#     hash de la fila anterior, con una llave que no está en la base. Si alguien altera, borra o
#     inserta filas (incluso quitando los triggers), verificar_cadena lo detecta.
#   - Nunca se registran contraseñas, códigos de verificación, tokens, llaves ni valores de campos:
#     solo ids internos, códigos de operación y nombres de campos.
#   - El canal (web/api/sistema) y la IP truncada los fija la capa web con fijar_contexto.
#   - Actividad 7: cada código debe estar en catalogo_eventos (categoría, recurso y claves del detalle);
#     un detalle o recurso que no cumple el catálogo se reemplaza por una marca, sin perder el evento.
#     La hora sale de reloj.py y el último id/hash se puede copiar fuera de la base (anclas).

import os
import json
import hmac
import stat
import hashlib
import logging
import ipaddress
from contextvars import ContextVar

import db
import reloj
import catalogo_eventos
from config import LLAVE_AUDITORIA

GENESIS = "0" * 64
DIAS_CONSERVACION = 730
RUTA_ANCLAS = os.getenv("NORTISHOP_RUTA_ANCLAS", "anclas_auditoria.jsonl")
DETALLE_RECHAZADO = "detalle_rechazado"
RECURSO_RECHAZADO = "recurso_rechazado"

_log = logging.getLogger("nortishop.auditoria")

_contexto = ContextVar("contexto_auditoria", default=("sistema", None))

def categoria_de(permiso):
    evento = catalogo_eventos.buscar(permiso)
    if evento is None:
        raise ValueError(f"Evento no catalogado: {permiso}")
    return evento.categoria


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
    return reloj.ahora()


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
    evento = catalogo_eventos.buscar(permiso)
    if evento is None:
        raise ValueError(f"Evento no catalogado: {permiso}")      # error de programación: se agrega al catálogo
    if not catalogo_eventos.detalle_valido(evento, detalle):
        _log.warning(f"detalle descartado en {permiso}")          # no se escribe el contenido
        detalle = DETALLE_RECHAZADO
    if not catalogo_eventos.recurso_valido(recurso):
        _log.warning(f"recurso descartado en {permiso}")
        recurso = RECURSO_RECHAZADO
    canal, origen = _contexto.get()
    fila = {
        "fecha": _ahora(),
        "actor_tipo": getattr(sesion, "tipo", None),
        "actor_id": getattr(sesion, "id", None),
        "rol": getattr(sesion, "rol", None),
        "permiso": permiso,
        "categoria": evento.categoria,
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


def anclar():
    """
    Agrega el último (id, hash) al archivo de anclas, fuera de la base. En producción ese archivo va a otro
    servidor o a un almacenamiento de solo agregar; si alguien borra las últimas filas de la bitácora y
    rehace la cadena desde ahí, el ancla ya no cuadra. Lo ejecuta una tarea programada (cada hora).
    """
    ultimo_id, ultimo_hash = ancla()
    nuevo = not os.path.exists(RUTA_ANCLAS)
    with open(RUTA_ANCLAS, "a") as f:
        f.write(json.dumps({"fecha": _ahora(), "ultimo_id": ultimo_id, "hash": ultimo_hash}) + "\n")
    if nuevo:
        os.chmod(RUTA_ANCLAS, stat.S_IRUSR | stat.S_IWUSR)
    registrar_evento(None, "auditoria.anclar", None, "exito", f"ultimo_id={ultimo_id}")
    return ultimo_id, ultimo_hash


def verificar_anclas():
    """
    Cada ancla debe seguir en la bitácora con el mismo hash, salvo que una purga registrada la haya
    eliminado por plazo. Detecta que se borraron o reescribieron filas, incluidas las últimas.
    """
    if not os.path.exists(RUTA_ANCLAS):
        return {"ok": True, "anclas": 0, "error_en": None}
    with open(RUTA_ANCLAS) as f:
        anclas = [json.loads(linea) for linea in f if linea.strip()]
    con = db.conectar()
    purgado_hasta = 0
    for p in con.execute("SELECT detalle FROM auditoria WHERE permiso='auditoria.purgar' AND resultado='exito'"):
        for parte in (p["detalle"] or "").split():
            if parte.startswith("hasta_id="):
                purgado_hasta = max(purgado_hasta, int(parte.split("=", 1)[1]))
    error_en = None
    for a in anclas:
        if a["ultimo_id"] == 0:
            continue
        f = con.execute("SELECT hash FROM auditoria WHERE id=?", (a["ultimo_id"],)).fetchone()
        if (f is None and a["ultimo_id"] > purgado_hasta) or (f is not None and f["hash"] != a["hash"]):
            error_en = a["ultimo_id"]
            break
    con.close()
    return {"ok": error_en is None, "anclas": len(anclas), "error_en": error_en}


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
