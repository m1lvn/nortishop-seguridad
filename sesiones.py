# sesiones.py
# Sesiones para la capa web y la API.
#   - El token es aleatorio (256 bits) y solo lo tiene el navegador o el cliente de la API;
#     en la base se guarda su SHA-256, así una copia de la base no permite suplantar a nadie.
#   - Cada petición vuelve a construir la Sesion desde la base: si la cuenta se deshabilitó o
#     cambió de rol, el token deja de servir de inmediato. No se confía en datos que mande el cliente.
#   - Expiración absoluta de 30 minutos y revocación individual, por cuenta o total (contención).

import hashlib
import secrets
from datetime import datetime, timedelta, timezone

from db import conectar
from rbac import Sesion
from auditoria import registrar_evento

MINUTOS_SESION = 30


def _ahora():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def _hash(token):
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def crear(sesion):
    """Devuelve el token (se entrega una sola vez; no se guarda)."""
    token = secrets.token_urlsafe(32)
    expira = (datetime.now(timezone.utc) + timedelta(minutes=MINUTOS_SESION)).strftime("%Y-%m-%d %H:%M:%S")
    con = conectar()
    con.execute("INSERT INTO sesiones (token_hash, actor_tipo, actor_id, creada, expira) VALUES (?,?,?,?,?)",
                (_hash(token), sesion.tipo, sesion.id, _ahora(), expira))
    con.commit()
    con.close()
    registrar_evento(sesion, "sesion.crear", None, "exito")
    return token


def resolver(token):
    """Token -> Sesion vigente, o None si no existe, expiró, fue revocada o la cuenta ya no está habilitada."""
    if not isinstance(token, str) or not (20 <= len(token) <= 100):
        return None
    con = conectar()
    s = con.execute("SELECT actor_tipo, actor_id FROM sesiones WHERE token_hash=? AND revocada=0 AND expira > ?",
                    (_hash(token), _ahora())).fetchone()
    if s is None:
        con.close()
        return None
    if s["actor_tipo"] == "cliente":
        f = con.execute("SELECT deshabilitada FROM clientes WHERE id=?", (s["actor_id"],)).fetchone()
        sesion = Sesion("cliente", s["actor_id"], "cliente") if f and not f["deshabilitada"] else None
    else:
        f = con.execute("SELECT rol, deshabilitada FROM administradores WHERE id=?", (s["actor_id"],)).fetchone()
        sesion = Sesion("personal", s["actor_id"], f["rol"]) if f and not f["deshabilitada"] else None
    con.close()
    return sesion


def csrf(token):
    """Valor anti-CSRF derivado del token: un sitio externo no lo conoce porque no puede leer la cookie."""
    return hashlib.sha256(f"csrf:{token}".encode("utf-8")).hexdigest()[:40]


def cerrar(token):
    con = conectar()
    con.execute("UPDATE sesiones SET revocada=1 WHERE token_hash=?", (_hash(token),))
    con.commit()
    con.close()


def revocar_de_actor(actor_tipo, actor_id):
    con = conectar()
    cur = con.execute("UPDATE sesiones SET revocada=1 WHERE actor_tipo=? AND actor_id=? AND revocada=0",
                      (actor_tipo, actor_id))
    con.commit()
    con.close()
    return cur.rowcount


def revocar_todas():
    con = conectar()
    cur = con.execute("UPDATE sesiones SET revocada=1 WHERE revocada=0")
    con.commit()
    con.close()
    return cur.rowcount


def activas():
    con = conectar()
    n = con.execute("SELECT COUNT(*) FROM sesiones WHERE revocada=0 AND expira > ?", (_ahora(),)).fetchone()[0]
    con.close()
    return n
