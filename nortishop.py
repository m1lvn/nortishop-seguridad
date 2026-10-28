# nortishop.py
# Funciones del sistema que guardan y leen los datos personales y financieros ya protegidos.
#
# Cada valor cifrado lleva un contexto "tabla.columna:identificador" que lo amarra
# a su fila. El identificador es uno que no cambia y se conoce antes del INSERT:
#   clientes / boletín -> correo_indice      pedidos -> codigo del pedido
#   comportamiento     -> seudónimo del cliente
#
# Toda función que entrega o modifica información sensible recibe una Sesion como primer
# parámetro y está protegida por @requiere_permiso (rbac.py), que además la audita.

import re
import secrets
from datetime import datetime, timedelta, timezone

from db import conectar
from config import LLAVE_PASARELA
from cripto import (hashear_password, verificar_password, cifrar, descifrar,
                    cifrar_json, descifrar_json, indice_busqueda, firma_valida)
from rbac import Sesion, AccesoDenegado, requiere_permiso, log

MAX_INTENTOS = 5                 # intentos fallidos antes del bloqueo
MINUTOS_BLOQUEO = 15
UMBRAL_K = 5                     # tamaño mínimo de grupo en los reportes anonimizados
ROLES_PERSONAL = ("administrador", "soporte", "logistica", "marketing")
ESTADOS_PEDIDO = ("pagado", "despachado", "entregado")

REGIONES = (
    "Arica y Parinacota", "Tarapacá", "Antofagasta", "Atacama", "Coquimbo", "Valparaíso",
    "Metropolitana de Santiago", "Libertador General Bernardo O'Higgins", "Maule", "Ñuble",
    "Biobío", "La Araucanía", "Los Ríos", "Los Lagos",
    "Aysén del General Carlos Ibáñez del Campo", "Magallanes y de la Antártica Chilena",
)


def _ctx_cliente(columna, correo_indice):
    return f"clientes.{columna}:{correo_indice}"


def _ctx_pedido(columna, codigo):
    return f"pedidos.{columna}:{codigo}"


def _cifrar_opcional(valor, contexto):
    return None if valor is None else cifrar(valor, contexto)


def _ahora():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


# ---------- Validaciones (los errores nombran el campo, nunca el valor) ----------

_RE_CORREO = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}$")
_RE_TELEFONO = re.compile(r"^\+?[0-9 ]{8,16}$")
_RE_USUARIO = re.compile(r"^[a-z0-9_]{4,32}$")
_CLAVES_TRIVIALES = {"1234567890", "contraseña", "password12", "qwertyuiop", "nortishop1"}


def validar_correo(correo):
    if not isinstance(correo, str) or len(correo) > 254 or not _RE_CORREO.match(correo.strip()):
        raise ValueError("El correo no tiene un formato válido")
    return correo.strip().lower()


def validar_password(password):
    if not isinstance(password, str) or not (10 <= len(password) <= 128):
        raise ValueError("La contraseña debe tener entre 10 y 128 caracteres")
    if password.lower() in _CLAVES_TRIVIALES or len(set(password)) < 4:
        raise ValueError("La contraseña es demasiado simple")
    return password


def validar_opcional(valor, campo, largo_max, patron=None):
    """Campo opcional: None o vacío se guarda como NULL; si viene, debe cumplir largo y formato."""
    if valor is None or (isinstance(valor, str) and not valor.strip()):
        return None
    if not isinstance(valor, str) or len(valor.strip()) > largo_max:
        raise ValueError(f"El campo {campo} supera el largo permitido")
    valor = valor.strip()
    if patron is not None and not patron.match(valor):
        raise ValueError(f"El campo {campo} no tiene un formato válido")
    return valor


def validar_region(region):
    if region not in REGIONES:
        raise ValueError("La región de envío no es una región oficial de Chile")
    return region


# ---------- Autenticación con bloqueo por intentos ----------

_hash_relleno = None


def _verificar_hash_relleno(password):
    """Si el usuario no existe se verifica igual un hash, para que la respuesta tarde lo mismo."""
    global _hash_relleno
    if _hash_relleno is None:
        _hash_relleno = hashear_password(secrets.token_hex(16))
    verificar_password(password, _hash_relleno)


def _verificar_con_bloqueo(tabla, columna, valor, password):
    """
    Devuelve la fila si la clave es correcta y la cuenta no está bloqueada; si no, None.
    tabla y columna vienen siempre del código (nunca del usuario); valor va como parámetro.
    """
    con = conectar()
    f = con.execute(f"SELECT * FROM {tabla} WHERE {columna} = ?", (valor,)).fetchone()
    if f is None:
        con.close()
        _verificar_hash_relleno(password)
        return None
    if f["bloqueado_hasta"] and f["bloqueado_hasta"] > _ahora():
        con.close()
        _verificar_hash_relleno(password)
        return None
    if verificar_password(password, f["password_hash"]):
        con.execute(f"UPDATE {tabla} SET intentos_fallidos = 0, bloqueado_hasta = NULL WHERE id = ?", (f["id"],))
        con.commit()
        con.close()
        return f
    intentos = f["intentos_fallidos"] + 1
    if intentos >= MAX_INTENTOS:
        hasta = (datetime.now(timezone.utc) + timedelta(minutes=MINUTOS_BLOQUEO)).strftime("%Y-%m-%d %H:%M:%S")
        con.execute(f"UPDATE {tabla} SET intentos_fallidos = 0, bloqueado_hasta = ? WHERE id = ?", (hasta, f["id"]))
        log.warning(f"cuenta bloqueada temporalmente ({tabla} id={f['id']})")
    else:
        con.execute(f"UPDATE {tabla} SET intentos_fallidos = ? WHERE id = ?", (intentos, f["id"]))
    con.commit()
    con.close()
    return None


# ---------- Cliente registrado ----------

def registrar_cliente(nombre, correo, password, telefono=None, direccion=None, consentimiento_analitica=False):
    """Solo se exige lo necesario para operar la cuenta: nombre, correo y contraseña."""
    nombre = validar_opcional(nombre, "nombre", 80)
    if nombre is None:
        raise ValueError("El campo nombre es obligatorio")
    correo = validar_correo(correo)
    validar_password(password)
    telefono = validar_opcional(telefono, "teléfono", 16, _RE_TELEFONO)
    direccion = validar_opcional(direccion, "dirección", 200)
    idx = indice_busqueda(correo)
    con = conectar()
    cur = con.execute(
        """INSERT INTO clientes (nombre, correo_cifrado, correo_indice, password_hash,
                                 telefono_cifrado, direccion_cifrado, consentimiento_analitica)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (nombre, cifrar(correo, _ctx_cliente("correo", idx)), idx, hashear_password(password),
         _cifrar_opcional(telefono, _ctx_cliente("telefono", idx)),
         _cifrar_opcional(direccion, _ctx_cliente("direccion", idx)),
         1 if consentimiento_analitica else 0),
    )
    con.commit()
    con.close()
    log.info(f"cliente registrado id={cur.lastrowid}")
    return cur.lastrowid


def login_cliente(correo, password):
    """Devuelve una Sesion de cliente o None (igual para clave mala, correo inexistente o bloqueo)."""
    try:
        idx = indice_busqueda(validar_correo(correo))
    except ValueError:
        _verificar_hash_relleno(password)
        return None
    f = _verificar_con_bloqueo("clientes", "correo_indice", idx, password)
    return None if f is None else Sesion("cliente", f["id"], "cliente")


def _es_propio(sesion, cliente_id, *_):
    return sesion.id == cliente_id


@requiere_permiso("cuenta.propia.leer", recurso_en_arg1=True, regla=_es_propio)
def obtener_datos_cliente(sesion, cliente_id):
    """Recupera (descifra) los datos del propio cliente."""
    con = conectar()
    f = con.execute("SELECT * FROM clientes WHERE id = ?", (cliente_id,)).fetchone()
    con.close()
    if f is None:
        raise AccesoDenegado("Acceso denegado")
    idx = f["correo_indice"]
    return {
        "nombre": f["nombre"],
        "correo": descifrar(f["correo_cifrado"], _ctx_cliente("correo", idx)),
        "telefono": descifrar(f["telefono_cifrado"], _ctx_cliente("telefono", idx)),
        "direccion": descifrar(f["direccion_cifrado"], _ctx_cliente("direccion", idx)),
    }


@requiere_permiso("tarjeta.registrar")
def guardar_tarjeta(sesion, pasarela, numero, vencimiento, cvv):
    """La tarjeta se manda a la pasarela y solo se guarda el token."""
    resp = pasarela.tokenizar(numero, vencimiento, cvv)
    con = conectar()
    con.execute("INSERT INTO tarjetas_guardadas (cliente_id, token_pasarela, ultimos4, marca) VALUES (?,?,?,?)",
                (sesion.id, resp["token"], resp["ultimos4"], resp["marca"]))
    con.commit()
    con.close()
    return resp["token"]


# ---------- Compras ----------

def verificar_respuesta_pago(pago, monto, orden):
    """
    Antes de registrar un pedido se comprueba que la respuesta venga de la pasarela
    (firma HMAC válida) y que corresponda a ESTE pedido y a ESTE monto. Así no se
    puede falsificar un "aprobado" ni reutilizar la respuesta de otra compra.
    """
    return (firma_valida(LLAVE_PASARELA, pago)
            and pago["orden"] == orden
            and pago["monto"] == monto)


def _nuevo_codigo_pedido():
    return "NS-" + secrets.token_hex(6).upper()


def _pagar(pasarela, token, monto, orden):
    pago = pasarela.cobrar(token, monto, orden)
    if not verificar_respuesta_pago(pago, monto, orden):
        return {"aprobado": False, "codigo": "RESPUESTA_NO_VALIDA", "orden": orden}
    return pago


def _registrar_pedido(con, codigo, cliente_id, es_invitado, correo_inv, tel_inv, direccion, productos, monto,
                      token, ultimos4, autorizacion, region):
    con.execute(
        """INSERT INTO pedidos (codigo, cliente_id, es_invitado, invitado_correo_cifrado, invitado_telefono_cifrado,
                                direccion_cifrado, detalle_cifrado, monto, token_pasarela, ultimos4, autorizacion,
                                region_envio)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
        (codigo, cliente_id, es_invitado,
         _cifrar_opcional(correo_inv, _ctx_pedido("invitado_correo", codigo)),
         _cifrar_opcional(tel_inv, _ctx_pedido("invitado_telefono", codigo)),
         cifrar(direccion, _ctx_pedido("direccion", codigo)),
         cifrar_json(productos, _ctx_pedido("detalle", codigo)),
         monto, token, ultimos4, autorizacion, region),
    )


@requiere_permiso("compra.tarjeta_guardada")
def comprar_con_tarjeta_guardada(sesion, pasarela, productos, monto, direccion=None, region=None):
    """Si no se indica dirección se usa la guardada en la cuenta (si existe)."""
    if region is not None:
        validar_region(region)
    direccion = validar_opcional(direccion, "dirección", 200)
    con = conectar()
    t = con.execute("SELECT token_pasarela, ultimos4 FROM tarjetas_guardadas WHERE cliente_id = ?",
                    (sesion.id,)).fetchone()
    c = con.execute("SELECT direccion_cifrado, correo_indice FROM clientes WHERE id=?", (sesion.id,)).fetchone()
    if t is None or c is None:
        con.close()
        raise AccesoDenegado("Acceso denegado")
    if direccion is None:
        direccion = descifrar(c["direccion_cifrado"], _ctx_cliente("direccion", c["correo_indice"]))
    if direccion is None:
        con.close()
        raise ValueError("El campo dirección es obligatorio para despachar")
    codigo = _nuevo_codigo_pedido()
    pago = _pagar(pasarela, t["token_pasarela"], monto, codigo)
    if pago["aprobado"]:
        _registrar_pedido(con, codigo, sesion.id, 0, None, None, direccion, productos, monto,
                          t["token_pasarela"], t["ultimos4"], pago["autorizacion"], region)
        con.commit()
    con.close()
    return pago


def comprar_como_invitado(pasarela, correo, telefono, direccion, numero, vencimiento, cvv, productos, monto,
                          region=None):
    """El invitado no tiene cuenta: su tarjeta se tokeniza para esta compra y sus datos se cifran."""
    correo = validar_correo(correo)
    telefono = validar_opcional(telefono, "teléfono", 16, _RE_TELEFONO)
    direccion = validar_opcional(direccion, "dirección", 200)
    if direccion is None:
        raise ValueError("El campo dirección es obligatorio para despachar")
    if region is not None:
        validar_region(region)
    tok = pasarela.tokenizar(numero, vencimiento, cvv)
    codigo = _nuevo_codigo_pedido()
    pago = _pagar(pasarela, tok["token"], monto, codigo)
    if pago["aprobado"]:
        con = conectar()
        _registrar_pedido(con, codigo, None, 1, correo, telefono, direccion, productos, monto,
                          tok["token"], tok["ultimos4"], pago["autorizacion"], region)
        con.commit()
        con.close()
    return pago


@requiere_permiso("pedidos.propios.leer", recurso_en_arg1=True, regla=_es_propio)
def historial_compras(sesion, cliente_id):
    con = conectar()
    filas = con.execute("SELECT codigo, detalle_cifrado, monto, ultimos4 FROM pedidos WHERE cliente_id=?",
                        (cliente_id,)).fetchall()
    con.close()
    return [{"pedido": f["codigo"], "productos": descifrar_json(f["detalle_cifrado"], _ctx_pedido("detalle", f["codigo"])),
             "monto": f["monto"], "tarjeta": "**** " + f["ultimos4"]} for f in filas]


# ---------- Soporte y logística ----------

@requiere_permiso("contacto.cliente.leer", recurso_en_arg1=True)
def contacto_cliente(sesion, cliente_id):
    """Soporte ve el contacto del cliente (correo y teléfono), nunca su dirección."""
    con = conectar()
    f = con.execute("SELECT nombre, correo_cifrado, correo_indice, telefono_cifrado FROM clientes WHERE id=?",
                    (cliente_id,)).fetchone()
    con.close()
    if f is None:
        raise AccesoDenegado("Acceso denegado")
    idx = f["correo_indice"]
    return {"nombre": f["nombre"],
            "correo": descifrar(f["correo_cifrado"], _ctx_cliente("correo", idx)),
            "telefono": descifrar(f["telefono_cifrado"], _ctx_cliente("telefono", idx))}


@requiere_permiso("contacto.invitado.leer", recurso_en_arg1=True)
def datos_contacto_invitado(sesion, pedido_id):
    con = conectar()
    f = con.execute("SELECT codigo, es_invitado, invitado_correo_cifrado, invitado_telefono_cifrado "
                    "FROM pedidos WHERE id=?", (pedido_id,)).fetchone()
    con.close()
    if f is None or not f["es_invitado"] or f["invitado_correo_cifrado"] is None:
        raise AccesoDenegado("Acceso denegado")
    return {"correo": descifrar(f["invitado_correo_cifrado"], _ctx_pedido("invitado_correo", f["codigo"])),
            "telefono": descifrar(f["invitado_telefono_cifrado"], _ctx_pedido("invitado_telefono", f["codigo"]))}


@requiere_permiso("despacho.direccion.leer", recurso_en_arg1=True)
def direccion_despacho(sesion, pedido_id):
    """Se descifra la dirección solo para envíos activos (pagado o despachado)."""
    con = conectar()
    f = con.execute("SELECT codigo, estado, direccion_cifrado FROM pedidos WHERE id=?", (pedido_id,)).fetchone()
    con.close()
    if f is None or f["estado"] == "entregado" or f["direccion_cifrado"] is None:
        raise AccesoDenegado("Acceso denegado")       # igual que "no autorizado"
    return descifrar(f["direccion_cifrado"], _ctx_pedido("direccion", f["codigo"]))


@requiere_permiso("pedidos.estado.actualizar", recurso_en_arg1=True)
def actualizar_estado(sesion, pedido_id, estado):
    """El estado solo avanza (pagado -> despachado -> entregado)."""
    if estado not in ESTADOS_PEDIDO:
        raise ValueError("Estado de pedido no válido")
    con = conectar()
    f = con.execute("SELECT estado FROM pedidos WHERE id=?", (pedido_id,)).fetchone()
    if f is None:
        con.close()
        raise AccesoDenegado("Acceso denegado")
    if ESTADOS_PEDIDO.index(estado) <= ESTADOS_PEDIDO.index(f["estado"]):
        con.close()
        raise ValueError("El estado de un pedido solo puede avanzar")
    con.execute("UPDATE pedidos SET estado=? WHERE id=?", (estado, pedido_id))
    con.commit()
    con.close()


@requiere_permiso("pedidos.resumen.leer")
def resumen_pedidos(sesion):
    """Vista sin datos personales: código, monto, estado y fecha."""
    con = conectar()
    filas = con.execute("SELECT codigo, monto, estado, fecha FROM pedidos ORDER BY id").fetchall()
    con.close()
    return [dict(f) for f in filas]


# ---------- Administración ----------

def crear_primer_admin(usuario, password):
    """Solo en el primer arranque: si ya existe un administrador, se rechaza."""
    con = conectar()
    existe = con.execute("SELECT 1 FROM administradores WHERE rol='administrador'").fetchone()
    con.close()
    if existe:
        raise RuntimeError("Ya existe un administrador")
    _insertar_personal(usuario, password, "administrador")


def _insertar_personal(usuario, password, rol):
    if not isinstance(usuario, str) or not _RE_USUARIO.match(usuario):
        raise ValueError("El usuario debe tener entre 4 y 32 caracteres: minúsculas, números o _")
    validar_password(password)
    if rol not in ROLES_PERSONAL:
        raise ValueError("Rol no válido")
    con = conectar()
    con.execute("INSERT INTO administradores (usuario, password_hash, rol) VALUES (?,?,?)",
                (usuario, hashear_password(password), rol))
    con.commit()
    con.close()


@requiere_permiso("roles.gestionar")
def crear_admin(sesion, usuario, password, rol="soporte"):
    """Crea una cuenta de personal. Sin rol explícito queda con el de menor privilegio."""
    _insertar_personal(usuario, password, rol)


def login_admin(usuario, password):
    if not isinstance(usuario, str):
        return None
    f = _verificar_con_bloqueo("administradores", "usuario", usuario, password)
    return None if f is None else Sesion("personal", f["id"], f["rol"])


@requiere_permiso("auditoria.leer")
def leer_auditoria(sesion):
    con = conectar()
    filas = con.execute("SELECT * FROM auditoria ORDER BY id").fetchall()
    con.close()
    return [dict(f) for f in filas]


# ---------- Marketing ----------

def suscribir_boletin(correo):
    correo = validar_correo(correo)
    idx = indice_busqueda(correo)
    con = conectar()
    con.execute("INSERT OR IGNORE INTO boletin_suscriptores (correo_cifrado, correo_indice) VALUES (?,?)",
                (cifrar(correo, f"boletin.correo:{idx}"), idx))
    con.commit()
    con.close()


@requiere_permiso("boletin.enviar")
def correos_para_envio_boletin(sesion):
    """Se descifra la lista solo al momento de enviar la campaña."""
    con = conectar()
    filas = con.execute("SELECT correo_cifrado, correo_indice FROM boletin_suscriptores").fetchall()
    con.close()
    return [descifrar(f["correo_cifrado"], f"boletin.correo:{f['correo_indice']}") for f in filas]


def seudonimo_cliente(cliente_id):
    # HMAC del id con la llave de índice; no hay tabla de correspondencia.
    return indice_busqueda(f"seudonimo:{cliente_id}")


def guardar_comportamiento(cliente_id, datos):
    """Solo con consentimiento y bajo seudónimo (la tabla no tiene cliente_id)."""
    con = conectar()
    c = con.execute("SELECT consentimiento_analitica FROM clientes WHERE id=?", (cliente_id,)).fetchone()
    if c is None or not c["consentimiento_analitica"]:
        con.close()
        return False
    seud = seudonimo_cliente(cliente_id)
    con.execute("INSERT OR REPLACE INTO comportamiento_compra (seudonimo, datos_cifrado) VALUES (?,?)",
                (seud, cifrar_json(datos, f"comportamiento.datos:{seud}")))
    con.commit()
    con.close()
    return True


@requiere_permiso("analitica.leer_seudonimizada")
def leer_analitica(sesion):
    con = conectar()
    filas = con.execute("SELECT seudonimo, datos_cifrado FROM comportamiento_compra").fetchall()
    con.close()
    return [{"seudonimo": f["seudonimo"],
             "datos": descifrar_json(f["datos_cifrado"], f"comportamiento.datos:{f['seudonimo']}")} for f in filas]


@requiere_permiso("reportes.leer")
def reporte_ventas(sesion):
    """Generalización (mes, región), agregación y supresión de grupos con menos de UMBRAL_K pedidos."""
    con = conectar()
    filas = con.execute(
        """SELECT substr(fecha,1,7) AS mes, COALESCE(region_envio,'Sin región') AS region,
                  COUNT(*) AS pedidos, SUM(monto) AS total
           FROM pedidos GROUP BY mes, region""").fetchall()
    con.close()
    return [dict(f) for f in filas if f["pedidos"] >= UMBRAL_K]


# ---------- Retención y supresión ----------

@requiere_permiso("retencion.ejecutar")
def aplicar_retencion(sesion, dias=365):
    """Pedidos entregados hace más de N días: se borran dirección y contacto. Queda lo contable."""
    con = conectar()
    cur = con.execute(
        """UPDATE pedidos SET direccion_cifrado=NULL, invitado_correo_cifrado=NULL, invitado_telefono_cifrado=NULL
           WHERE estado='entregado' AND fecha < datetime('now', ?)
             AND (direccion_cifrado IS NOT NULL OR invitado_correo_cifrado IS NOT NULL
                  OR invitado_telefono_cifrado IS NOT NULL)""",
        (f"-{int(dias)} days",))
    con.commit()
    con.close()
    return cur.rowcount


@requiere_permiso("cuenta.eliminar", recurso_en_arg1=True, regla=_es_propio)
def eliminar_cuenta(sesion, cliente_id):
    """Borra al cliente, sus tarjetas, su comportamiento y su suscripción; los pedidos quedan sin vínculo."""
    con = conectar()
    c = con.execute("SELECT correo_indice FROM clientes WHERE id=?", (cliente_id,)).fetchone()
    if c is None:
        con.close()
        raise AccesoDenegado("Acceso denegado")
    con.execute("DELETE FROM tarjetas_guardadas WHERE cliente_id=?", (cliente_id,))
    con.execute("DELETE FROM comportamiento_compra WHERE seudonimo=?", (seudonimo_cliente(cliente_id),))
    con.execute("DELETE FROM boletin_suscriptores WHERE correo_indice=?", (c["correo_indice"],))
    con.execute("UPDATE pedidos SET cliente_id=NULL, direccion_cifrado=NULL WHERE cliente_id=?", (cliente_id,))
    con.execute("DELETE FROM clientes WHERE id=?", (cliente_id,))
    con.commit()
    con.close()
    log.info(f"cuenta eliminada id={cliente_id}")
