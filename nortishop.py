# nortishop.py
# Funciones del sistema que guardan y leen los datos sensibles ya protegidos.

from db import conectar
from cripto import (hashear_password, verificar_password, cifrar, descifrar,
                    cifrar_json, descifrar_json, indice_busqueda)


# ---------- Cliente registrado ----------

def registrar_cliente(nombre, correo, password, rut, direccion):
    con = conectar()
    con.execute(
        """INSERT INTO clientes (nombre, correo_cifrado, correo_indice, password_hash,
                                 rut_cifrado, direccion_cifrado)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (nombre, cifrar(correo), indice_busqueda(correo), hashear_password(password),
         cifrar(rut), cifrar(direccion)),
    )
    con.commit()
    cid = con.execute("SELECT last_insert_rowid()").fetchone()[0]
    con.close()
    return cid


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
    return {
        "nombre": f["nombre"],
        "correo": descifrar(f["correo_cifrado"]),
        "rut": descifrar(f["rut_cifrado"]),
        "direccion": descifrar(f["direccion_cifrado"]),
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

def _registrar_pedido(con, cliente_id, es_invitado, correo_inv, tel_inv, direccion, productos, monto, token, ultimos4, autorizacion):
    con.execute(
        """INSERT INTO pedidos (cliente_id, es_invitado, invitado_correo_cifrado, invitado_telefono_cifrado,
                                direccion_cifrado, detalle_cifrado, monto, token_pasarela, ultimos4, autorizacion)
           VALUES (?,?,?,?,?,?,?,?,?,?)""",
        (cliente_id, es_invitado, cifrar(correo_inv), cifrar(tel_inv), cifrar(direccion),
         cifrar_json(productos), monto, token, ultimos4, autorizacion),
    )


def comprar_con_tarjeta_guardada(cliente_id, pasarela, productos, monto):
    con = conectar()
    t = con.execute("SELECT token_pasarela, ultimos4 FROM tarjetas_guardadas WHERE cliente_id = ?",
                    (cliente_id,)).fetchone()
    direccion = descifrar(con.execute("SELECT direccion_cifrado FROM clientes WHERE id=?",
                                      (cliente_id,)).fetchone()[0])
    pago = pasarela.cobrar(t["token_pasarela"], monto)
    if pago["aprobado"]:
        _registrar_pedido(con, cliente_id, 0, None, None, direccion, productos, monto,
                          t["token_pasarela"], t["ultimos4"], pago["autorizacion"])
        con.commit()
    con.close()
    return pago


def comprar_como_invitado(pasarela, correo, telefono, direccion, numero, vencimiento, cvv, productos, monto):
    """El invitado no tiene cuenta: su tarjeta se tokeniza para esta compra y sus datos se cifran."""
    tok = pasarela.tokenizar(numero, vencimiento, cvv)
    pago = pasarela.cobrar(tok["token"], monto)
    if pago["aprobado"]:
        con = conectar()
        _registrar_pedido(con, None, 1, correo, telefono, direccion, productos, monto,
                          tok["token"], tok["ultimos4"], pago["autorizacion"])
        con.commit()
        con.close()
    return pago


def historial_compras(cliente_id):
    con = conectar()
    filas = con.execute("SELECT id, detalle_cifrado, monto, ultimos4 FROM pedidos WHERE cliente_id=?",
                        (cliente_id,)).fetchall()
    con.close()
    return [{"pedido": f["id"], "productos": descifrar_json(f["detalle_cifrado"]),
             "monto": f["monto"], "tarjeta": "**** " + f["ultimos4"]} for f in filas]


def datos_contacto_invitado(pedido_id):
    con = conectar()
    f = con.execute("SELECT invitado_correo_cifrado, invitado_telefono_cifrado FROM pedidos WHERE id=?",
                    (pedido_id,)).fetchone()
    con.close()
    return {"correo": descifrar(f[0]), "telefono": descifrar(f[1])}


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
    con = conectar()
    con.execute("INSERT OR IGNORE INTO boletin_suscriptores (correo_cifrado, correo_indice) VALUES (?,?)",
                (cifrar(correo), indice_busqueda(correo)))
    con.commit()
    con.close()


def correos_para_envio_boletin():
    """Se descifra la lista solo al momento de enviar la campaña."""
    con = conectar()
    filas = con.execute("SELECT correo_cifrado FROM boletin_suscriptores").fetchall()
    con.close()
    return [descifrar(f[0]) for f in filas]


def guardar_comportamiento(cliente_id, datos):
    con = conectar()
    con.execute("INSERT INTO comportamiento_compra (cliente_id, datos_cifrado) VALUES (?,?)",
                (cliente_id, cifrar_json(datos)))
    con.commit()
    con.close()


def leer_comportamiento(cliente_id):
    con = conectar()
    f = con.execute("SELECT datos_cifrado FROM comportamiento_compra WHERE cliente_id=?",
                    (cliente_id,)).fetchone()
    con.close()
    return descifrar_json(f[0])
