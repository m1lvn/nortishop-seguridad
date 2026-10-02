# nortishop.py
# Funciones del sistema que guardan y leen los datos sensibles ya protegidos.
#
# Cada valor cifrado lleva un contexto "tabla.columna:identificador" que lo amarra
# a su fila. El identificador es uno que no cambia y se conoce antes del INSERT:
#   clientes / boletín -> correo_indice      pedidos -> codigo del pedido
#   comportamiento     -> cliente_id

import secrets

from db import conectar
from config import LLAVE_PASARELA
from cripto import (hashear_password, verificar_password, cifrar, descifrar,
                    cifrar_json, descifrar_json, indice_busqueda, firma_valida)


def _ctx_cliente(columna, correo_indice):
    return f"clientes.{columna}:{correo_indice}"


def _ctx_pedido(columna, codigo):
    return f"pedidos.{columna}:{codigo}"


# ---------- Cliente registrado ----------

def registrar_cliente(nombre, correo, password, rut, telefono, direccion):
    idx = indice_busqueda(correo)
    con = conectar()
    cur = con.execute(
        """INSERT INTO clientes (nombre, correo_cifrado, correo_indice, password_hash,
                                 rut_cifrado, telefono_cifrado, direccion_cifrado)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (nombre, cifrar(correo, _ctx_cliente("correo", idx)), idx, hashear_password(password),
         cifrar(rut, _ctx_cliente("rut", idx)), cifrar(telefono, _ctx_cliente("telefono", idx)),
         cifrar(direccion, _ctx_cliente("direccion", idx))),
    )
    con.commit()
    con.close()
    return cur.lastrowid


def login_cliente(correo, password):
    """Valida el login: busca por el índice HMAC y compara el hash bcrypt."""
    con = conectar()
    fila = con.execute("SELECT id, password_hash FROM clientes WHERE correo_indice = ?",
                       (indice_busqueda(correo),)).fetchone()
    con.close()
    if fila is None:
        return None
    return fila["id"] if verificar_password(password, fila["password_hash"]) else None


def obtener_datos_cliente(cliente_id):
    """Recupera (descifra) los datos del cliente solo cuando se necesitan."""
    con = conectar()
    f = con.execute("SELECT * FROM clientes WHERE id = ?", (cliente_id,)).fetchone()
    con.close()
    idx = f["correo_indice"]
    return {
        "nombre": f["nombre"],
        "correo": descifrar(f["correo_cifrado"], _ctx_cliente("correo", idx)),
        "rut": descifrar(f["rut_cifrado"], _ctx_cliente("rut", idx)),
        "telefono": descifrar(f["telefono_cifrado"], _ctx_cliente("telefono", idx)),
        "direccion": descifrar(f["direccion_cifrado"], _ctx_cliente("direccion", idx)),
    }


def guardar_tarjeta(cliente_id, pasarela, numero, vencimiento, cvv):
    """La tarjeta se manda a la pasarela y solo se guarda el token."""
    resp = pasarela.tokenizar(numero, vencimiento, cvv)
    con = conectar()
    con.execute("INSERT INTO tarjetas_guardadas (cliente_id, token_pasarela, ultimos4, marca) VALUES (?,?,?,?)",
                (cliente_id, resp["token"], resp["ultimos4"], resp["marca"]))
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
                      token, ultimos4, autorizacion):
    con.execute(
        """INSERT INTO pedidos (codigo, cliente_id, es_invitado, invitado_correo_cifrado, invitado_telefono_cifrado,
                                direccion_cifrado, detalle_cifrado, monto, token_pasarela, ultimos4, autorizacion)
           VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
        (codigo, cliente_id, es_invitado,
         cifrar(correo_inv, _ctx_pedido("invitado_correo", codigo)),
         cifrar(tel_inv, _ctx_pedido("invitado_telefono", codigo)),
         cifrar(direccion, _ctx_pedido("direccion", codigo)),
         cifrar_json(productos, _ctx_pedido("detalle", codigo)),
         monto, token, ultimos4, autorizacion),
    )


def comprar_con_tarjeta_guardada(cliente_id, pasarela, productos, monto):
    con = conectar()
    t = con.execute("SELECT token_pasarela, ultimos4 FROM tarjetas_guardadas WHERE cliente_id = ?",
                    (cliente_id,)).fetchone()
    c = con.execute("SELECT direccion_cifrado, correo_indice FROM clientes WHERE id=?", (cliente_id,)).fetchone()
    direccion = descifrar(c["direccion_cifrado"], _ctx_cliente("direccion", c["correo_indice"]))
    codigo = _nuevo_codigo_pedido()
    pago = _pagar(pasarela, t["token_pasarela"], monto, codigo)
    if pago["aprobado"]:
        _registrar_pedido(con, codigo, cliente_id, 0, None, None, direccion, productos, monto,
                          t["token_pasarela"], t["ultimos4"], pago["autorizacion"])
        con.commit()
    con.close()
    return pago


def comprar_como_invitado(pasarela, correo, telefono, direccion, numero, vencimiento, cvv, productos, monto):
    """El invitado no tiene cuenta: su tarjeta se tokeniza para esta compra y sus datos se cifran."""
    tok = pasarela.tokenizar(numero, vencimiento, cvv)
    codigo = _nuevo_codigo_pedido()
    pago = _pagar(pasarela, tok["token"], monto, codigo)
    if pago["aprobado"]:
        con = conectar()
        _registrar_pedido(con, codigo, None, 1, correo, telefono, direccion, productos, monto,
                          tok["token"], tok["ultimos4"], pago["autorizacion"])
        con.commit()
        con.close()
    return pago


def historial_compras(cliente_id):
    con = conectar()
    filas = con.execute("SELECT id, codigo, detalle_cifrado, monto, ultimos4 FROM pedidos WHERE cliente_id=?",
                        (cliente_id,)).fetchall()
    con.close()
    return [{"pedido": f["codigo"], "productos": descifrar_json(f["detalle_cifrado"], _ctx_pedido("detalle", f["codigo"])),
             "monto": f["monto"], "tarjeta": "**** " + f["ultimos4"]} for f in filas]


def datos_contacto_invitado(pedido_id):
    con = conectar()
    f = con.execute("SELECT codigo, invitado_correo_cifrado, invitado_telefono_cifrado FROM pedidos WHERE id=?",
                    (pedido_id,)).fetchone()
    con.close()
    return {"correo": descifrar(f["invitado_correo_cifrado"], _ctx_pedido("invitado_correo", f["codigo"])),
            "telefono": descifrar(f["invitado_telefono_cifrado"], _ctx_pedido("invitado_telefono", f["codigo"]))}


def direccion_despacho(pedido_id):
    """Se descifra la dirección solo al generar la orden de despacho."""
    con = conectar()
    f = con.execute("SELECT codigo, direccion_cifrado FROM pedidos WHERE id=?", (pedido_id,)).fetchone()
    con.close()
    return descifrar(f["direccion_cifrado"], _ctx_pedido("direccion", f["codigo"]))


# ---------- Administrador ----------

def crear_admin(usuario, password):
    con = conectar()
    con.execute("INSERT INTO administradores (usuario, password_hash) VALUES (?,?)",
                (usuario, hashear_password(password)))
    con.commit()
    con.close()


def login_admin(usuario, password):
    con = conectar()
    f = con.execute("SELECT password_hash FROM administradores WHERE usuario=?", (usuario,)).fetchone()
    con.close()
    return f is not None and verificar_password(password, f[0])


# ---------- Marketing ----------

def suscribir_boletin(correo):
    idx = indice_busqueda(correo)
    con = conectar()
    con.execute("INSERT OR IGNORE INTO boletin_suscriptores (correo_cifrado, correo_indice) VALUES (?,?)",
                (cifrar(correo, f"boletin.correo:{idx}"), idx))
    con.commit()
    con.close()


def correos_para_envio_boletin():
    """Se descifra la lista solo al momento de enviar la campaña."""
    con = conectar()
    filas = con.execute("SELECT correo_cifrado, correo_indice FROM boletin_suscriptores").fetchall()
    con.close()
    return [descifrar(f["correo_cifrado"], f"boletin.correo:{f['correo_indice']}") for f in filas]


def guardar_comportamiento(cliente_id, datos):
    con = conectar()
    con.execute("INSERT INTO comportamiento_compra (cliente_id, datos_cifrado) VALUES (?,?)",
                (cliente_id, cifrar_json(datos, f"comportamiento.datos:{cliente_id}")))
    con.commit()
    con.close()


def leer_comportamiento(cliente_id):
    con = conectar()
    f = con.execute("SELECT datos_cifrado FROM comportamiento_compra WHERE cliente_id=?",
                    (cliente_id,)).fetchone()
    con.close()
    return descifrar_json(f["datos_cifrado"], f"comportamiento.datos:{cliente_id}")
