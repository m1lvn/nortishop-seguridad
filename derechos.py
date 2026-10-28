# derechos.py
# Ejercicio de derechos del titular: acceso, portabilidad, rectificación y supresión.
#
# Flujo de cada solicitud (máquina de estados, con fecha en cada etapa):
#   recibida -> verificada -> en_evaluacion -> ejecutada | rechazada -> cerrada
#   (una solicitud recibida también puede rechazarse si la identidad no se verifica)
#
# Verificación de identidad proporcional al riesgo, sin pedir datos nuevos:
#   1. sesión iniciada (algo que sabe: contraseña) + reingreso de la contraseña al solicitar;
#   2. código de un solo uso enviado al correo registrado (algo que tiene: su correo).
#   El código no se guarda: solo su HMAC, con vencimiento de 10 minutos y máximo 3 intentos.
#   Cambiar el correo exige además un código enviado al correo nuevo.
#
# Plazo: 30 días corridos desde la recepción, prorrogable una vez por 30 días (privacidad).

import hmac
import secrets
from datetime import datetime, timedelta, timezone

from db import conectar
from cripto import cifrar, descifrar, cifrar_json, descifrar_json, indice_busqueda
from rbac import AccesoDenegado, requiere_permiso
from auditoria import registrar_evento
import notificador
import nortishop as ns

TIPOS = ("acceso", "portabilidad", "rectificacion", "supresion")
TRANSICIONES = {
    "recibida": {"verificada", "rechazada"},
    "verificada": {"en_evaluacion"},
    "en_evaluacion": {"ejecutada", "rechazada"},
    "ejecutada": {"cerrada"},
    "rechazada": {"cerrada"},
    "cerrada": set(),
}
_COLUMNA_FECHA = {"verificada": "fecha_verificacion", "en_evaluacion": "fecha_evaluacion",
                  "ejecutada": "fecha_respuesta", "rechazada": "fecha_respuesta", "cerrada": "fecha_cierre"}
CAMPOS_RECTIFICABLES = ("nombre", "telefono", "direccion", "correo")
PLAZO_DIAS = 30
PRORROGA_DIAS = 30
MINUTOS_CODIGO = 10
INTENTOS_CODIGO = 3
ENVIOS_CODIGO = 3                 # códigos que se pueden emitir por solicitud y propósito (incluye el primero)
# art. 11: al denegar, el responsable debe indicar al titular el plazo para reclamar ante la Agencia
AVISO_RECLAMO = (" Si no está de acuerdo, puede presentar una reclamación ante la Agencia de Protección de Datos "
                 "Personales dentro de 30 días hábiles desde esta respuesta.")
VERSION_EXPORTACION = "nortishop-export/1.0"


def _ahora():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def _en(dias=0, minutos=0):
    return (datetime.now(timezone.utc) + timedelta(days=dias, minutes=minutos)).strftime("%Y-%m-%d %H:%M:%S")


def _ctx_solicitud(codigo):
    return f"solicitudes.detalle:{codigo}"


def _cambiar_estado(con, solicitud, nuevo, **campos):
    """Única forma de cambiar el estado: valida la transición y registra la fecha de la etapa."""
    if nuevo not in TRANSICIONES[solicitud["estado"]]:
        raise ValueError("Transición de estado no permitida")
    campos[_COLUMNA_FECHA[nuevo]] = _ahora()
    if nuevo == "rechazada":
        motivo = (campos.get("resultado") or "Solicitud rechazada").rstrip().rstrip(".")
        campos["resultado"] = motivo + "." + AVISO_RECLAMO
    asignaciones = ", ".join(f"{c}=?" for c in campos)
    con.execute(f"UPDATE solicitudes_derechos SET estado=?, {asignaciones} WHERE id=?",
                (nuevo, *campos.values(), solicitud["id"]))
    return con.execute("SELECT * FROM solicitudes_derechos WHERE id=?", (solicitud["id"],)).fetchone()


def _solicitud_propia(con, sesion, codigo):
    """Inexistente o ajena dan el mismo error (no se revela si el código existe)."""
    s = con.execute("SELECT * FROM solicitudes_derechos WHERE codigo=?", (codigo,)).fetchone()
    if s is None or s["cliente_id"] != sesion.id:
        con.close()
        raise AccesoDenegado("Acceso denegado")
    return s


def _correo_registrado(con, cliente_id):
    c = con.execute("SELECT correo_cifrado, correo_indice FROM clientes WHERE id=?", (cliente_id,)).fetchone()
    return descifrar(c["correo_cifrado"], ns._ctx_cliente("correo", c["correo_indice"]))


def _hash_codigo(solicitud_id, proposito, codigo):
    return indice_busqueda(f"otp:{solicitud_id}:{proposito}:{codigo}")


def _emitir_codigo(con, solicitud, proposito, destino):
    """Genera el código, guarda solo su HMAC y lo envía al correo indicado."""
    codigo = f"{secrets.randbelow(10 ** 6):06d}"
    con.execute("UPDATE verificaciones_identidad SET usado=1 WHERE solicitud_id=? AND proposito=? AND usado=0",
                (solicitud["id"], proposito))
    con.execute("INSERT INTO verificaciones_identidad (solicitud_id, proposito, codigo_hash, expira) VALUES (?,?,?,?)",
                (solicitud["id"], proposito, _hash_codigo(solicitud["id"], proposito, codigo), _en(minutos=MINUTOS_CODIGO)))
    notificador.enviar(destino, f"NortiShop: código de verificación de la solicitud {solicitud['codigo']}",
                       f"Tu código es {codigo}. Vence en {MINUTOS_CODIGO} minutos. "
                       "Si no hiciste esta solicitud, ignora este mensaje y cambia tu contraseña.")


def _comprobar_codigo(con, solicitud, proposito, codigo):
    """True si el código es correcto y vigente. Cada fallo cuenta; al tercero el código deja de servir."""
    v = con.execute("SELECT * FROM verificaciones_identidad WHERE solicitud_id=? AND proposito=? AND usado=0 "
                    "ORDER BY id DESC LIMIT 1", (solicitud["id"], proposito)).fetchone()
    if v is None or v["expira"] <= _ahora() or v["intentos"] >= INTENTOS_CODIGO:
        return False
    esperado = _hash_codigo(solicitud["id"], proposito, str(codigo).strip())
    if hmac.compare_digest(esperado, v["codigo_hash"]):
        con.execute("UPDATE verificaciones_identidad SET usado=1 WHERE id=?", (v["id"],))
        return True
    intentos = v["intentos"] + 1
    con.execute("UPDATE verificaciones_identidad SET intentos=?, usado=? WHERE id=?",
                (intentos, 1 if intentos >= INTENTOS_CODIGO else 0, v["id"]))
    return False


def _validar_cambios(cambios, cliente_id):
    """Lista blanca de campos y las mismas validaciones del registro. Otros campos (rol, puntos) se rechazan."""
    if not isinstance(cambios, dict) or not cambios:
        raise ValueError("Indica al menos un campo a rectificar")
    if set(cambios) - set(CAMPOS_RECTIFICABLES):
        raise ValueError("Solo se pueden rectificar: nombre, teléfono, dirección y correo")
    limpio = {}
    if "nombre" in cambios:
        limpio["nombre"] = ns.validar_opcional(cambios["nombre"], "nombre", 80)
        if limpio["nombre"] is None:
            raise ValueError("El campo nombre es obligatorio")
    if "telefono" in cambios:
        limpio["telefono"] = ns.validar_opcional(cambios["telefono"], "teléfono", 16, ns._RE_TELEFONO)
    if "direccion" in cambios:
        limpio["direccion"] = ns.validar_opcional(cambios["direccion"], "dirección", 200)
    if "correo" in cambios:
        limpio["correo"] = ns.validar_correo(cambios["correo"])
        con = conectar()
        otro = con.execute("SELECT id FROM clientes WHERE correo_indice=?", (indice_busqueda(limpio["correo"]),)).fetchone()
        con.close()
        if otro is not None and otro["id"] != cliente_id:
            raise ValueError("No es posible usar ese correo")       # no confirma si pertenece a otra cuenta
    return limpio


# ---------------- Titular ----------------

@requiere_permiso("derechos.solicitar")
def crear_solicitud(sesion, tipo, password, cambios=None):
    """Recepción: reautentica, registra la solicitud con su plazo y envía el código al correo registrado."""
    if tipo not in TIPOS:
        raise ValueError("Tipo de solicitud no válido")
    if not ns.reautenticar(sesion, password):
        registrar_evento(sesion, "derechos.solicitar", None, "fallido", f"tipo={tipo} reautenticacion_fallida")
        raise AccesoDenegado("Acceso denegado")
    detalle = _validar_cambios(cambios, sesion.id) if tipo == "rectificacion" else None
    con = conectar()
    abierta = con.execute("SELECT 1 FROM solicitudes_derechos WHERE cliente_id=? AND tipo=? AND estado NOT IN "
                          "('cerrada')", (sesion.id, tipo)).fetchone()
    if abierta:
        con.close()
        raise ValueError("Ya tienes una solicitud de este tipo en curso")
    codigo = "SD-" + secrets.token_hex(5).upper()
    cur = con.execute("INSERT INTO solicitudes_derechos (codigo, cliente_id, titular_seudonimo, tipo, fecha_recepcion, "
                      "plazo_vence, detalle_cifrado) VALUES (?,?,?,?,?,?,?)",
                      (codigo, sesion.id, ns.seudonimo_cliente(sesion.id), tipo, _ahora(), _en(dias=PLAZO_DIAS),
                       cifrar_json(detalle, _ctx_solicitud(codigo)) if detalle else None))
    solicitud = con.execute("SELECT * FROM solicitudes_derechos WHERE id=?", (cur.lastrowid,)).fetchone()
    _emitir_codigo(con, solicitud, "titular", _correo_registrado(con, sesion.id))
    con.commit()
    con.close()
    campos = f" campos={','.join(sorted(detalle))}" if detalle else ""
    registrar_evento(sesion, "derechos.solicitar", codigo, "exito", f"tipo={tipo}{campos}")
    return codigo


@requiere_permiso("derechos.solicitar")
def verificar_identidad(sesion, codigo, codigo_correo):
    """Verificación y evaluación automática. Devuelve el estado en que queda la solicitud."""
    con = conectar()
    s = _solicitud_propia(con, sesion, codigo)
    if s["estado"] != "recibida":
        con.close()
        raise ValueError("La solicitud ya fue verificada")
    if not _comprobar_codigo(con, s, "titular", codigo_correo):
        agotado = con.execute("SELECT COUNT(*) FROM verificaciones_identidad WHERE solicitud_id=? AND proposito='titular' "
                              "AND usado=0", (s["id"],)).fetchone()[0] == 0
        if agotado:
            s = _cambiar_estado(con, s, "rechazada", resultado="No se pudo verificar la identidad del solicitante")
            _cambiar_estado(con, s, "cerrada")
        con.commit()
        con.close()
        registrar_evento(sesion, "derechos.verificar_identidad", codigo, "fallido",
                         "intentos_agotados" if agotado else "codigo_incorrecto")
        raise ValueError("El código es incorrecto o venció")
    s = _cambiar_estado(con, s, "verificada")
    s = _cambiar_estado(con, s, "en_evaluacion")
    s, rectificacion = _evaluar(con, s)
    con.commit()
    con.close()
    registrar_evento(sesion, "derechos.verificar_identidad", codigo, "exito", f"tipo={s['tipo']} estado={s['estado']}")
    if rectificacion:
        registrar_evento(sesion, "derechos.rectificar", codigo, "exito", rectificacion)
    return s["estado"]


def _pedidos_en_curso(con, cliente_id):
    return con.execute("SELECT COUNT(*) FROM pedidos WHERE cliente_id=? AND estado IN ('pagado','despachado')",
                       (cliente_id,)).fetchone()[0]


def _evaluar(con, s):
    """
    Reglas de negocio de cada tipo, aplicadas apenas se verifica la identidad.
    Devuelve (solicitud, detalle de la rectificación o None): el evento se registra después del commit.
    """
    if s["tipo"] == "rectificacion":
        cambios = descifrar_json(s["detalle_cifrado"], _ctx_solicitud(s["codigo"]))
        if "correo" in cambios:
            _emitir_codigo(con, s, "correo_nuevo", cambios["correo"])      # queda esperando el segundo código
            return s, None
        return _ejecutar_rectificacion(con, s, cambios)
    if s["tipo"] == "supresion" and _pedidos_en_curso(con, s["cliente_id"]):
        s = _cambiar_estado(con, s, "rechazada", resultado=(
            "Existen pedidos en curso (pagados o despachados). Sus datos se necesitan para cumplir el contrato de "
            "compraventa y el despacho. Puede volver a solicitar la supresión cuando los pedidos se hayan entregado."))
        return _cambiar_estado(con, s, "cerrada"), None
    return s, None      # acceso y portabilidad: listos para exportar; supresión: espera la evaluación de privacidad


@requiere_permiso("derechos.solicitar")
def reenviar_codigo(sesion, codigo):
    """Emite un código nuevo si el anterior venció o se agotó (máximo ENVIOS_CODIGO por propósito)."""
    con = conectar()
    s = _solicitud_propia(con, sesion, codigo)
    if s["estado"] == "recibida":
        proposito, destino = "titular", _correo_registrado(con, sesion.id)
    elif s["tipo"] == "rectificacion" and s["estado"] == "en_evaluacion":
        proposito = "correo_nuevo"
        destino = descifrar_json(s["detalle_cifrado"], _ctx_solicitud(s["codigo"]))["correo"]
    else:
        con.close()
        raise ValueError("La solicitud no espera un código")
    emitidos = con.execute("SELECT COUNT(*) FROM verificaciones_identidad WHERE solicitud_id=? AND proposito=?",
                           (s["id"], proposito)).fetchone()[0]
    if emitidos >= ENVIOS_CODIGO:
        if s["estado"] == "recibida":
            s = _cambiar_estado(con, s, "rechazada", resultado="No se pudo verificar la identidad del solicitante")
        else:
            s = _cambiar_estado(con, s, "rechazada", detalle_cifrado=None,
                                resultado="No se pudo confirmar el correo nuevo; los datos no se modificaron")
        _cambiar_estado(con, s, "cerrada")
        con.commit()
        con.close()
        registrar_evento(sesion, "derechos.reenviar_codigo", codigo, "fallido", "envios_agotados")
        raise ValueError("Se agotaron los envíos de código; la solicitud se cerró. Puedes crear una nueva.")
    _emitir_codigo(con, s, proposito, destino)
    con.commit()
    con.close()
    registrar_evento(sesion, "derechos.reenviar_codigo", codigo, "exito", f"proposito={proposito}")


@requiere_permiso("derechos.solicitar")
def confirmar_correo_nuevo(sesion, codigo, codigo_correo):
    """Segundo factor para cambiar el correo: prueba que el titular controla la dirección nueva."""
    con = conectar()
    s = _solicitud_propia(con, sesion, codigo)
    if s["tipo"] != "rectificacion" or s["estado"] != "en_evaluacion":
        con.close()
        raise ValueError("La solicitud no espera la confirmación del correo nuevo")
    if not _comprobar_codigo(con, s, "correo_nuevo", codigo_correo):
        con.commit()
        con.close()
        registrar_evento(sesion, "derechos.confirmar_correo", codigo, "fallido")
        raise ValueError("El código es incorrecto o venció")
    s, rectificacion = _ejecutar_rectificacion(con, s, descifrar_json(s["detalle_cifrado"], _ctx_solicitud(s["codigo"])))
    con.commit()
    con.close()
    registrar_evento(sesion, "derechos.rectificar", codigo, "exito", rectificacion)
    return s["estado"]


def _ejecutar_rectificacion(con, s, cambios):
    """
    Actualiza la cuenta y los módulos relacionados en una sola transacción:
      - si cambia el correo, cambia el índice y por eso se vuelven a cifrar correo, teléfono y dirección
        (su contexto AAD incluye el índice) y la fila del boletín;
      - la dirección nueva se copia a los pedidos aún no despachados;
      - los valores nuevos se borran de la solicitud: la traza guarda qué campos cambiaron, no los valores.
    """
    cliente_id = s["cliente_id"]
    c = con.execute("SELECT * FROM clientes WHERE id=?", (cliente_id,)).fetchone()
    idx = c["correo_indice"]
    actual = {"correo": descifrar(c["correo_cifrado"], ns._ctx_cliente("correo", idx)),
              "telefono": descifrar(c["telefono_cifrado"], ns._ctx_cliente("telefono", idx)),
              "direccion": descifrar(c["direccion_cifrado"], ns._ctx_cliente("direccion", idx))}
    nuevo = {**actual, **{k: v for k, v in cambios.items() if k != "nombre"}}
    nuevo_idx = indice_busqueda(nuevo["correo"])
    con.execute("UPDATE clientes SET nombre=?, correo_indice=?, correo_cifrado=?, telefono_cifrado=?, direccion_cifrado=? "
                "WHERE id=?",
                (cambios.get("nombre", c["nombre"]), nuevo_idx,
                 cifrar(nuevo["correo"], ns._ctx_cliente("correo", nuevo_idx)),
                 ns._cifrar_opcional(nuevo["telefono"], ns._ctx_cliente("telefono", nuevo_idx)),
                 ns._cifrar_opcional(nuevo["direccion"], ns._ctx_cliente("direccion", nuevo_idx)), cliente_id))
    if nuevo_idx != idx:
        con.execute("UPDATE boletin_suscriptores SET correo_indice=?, correo_cifrado=? WHERE cliente_id=?",
                    (nuevo_idx, cifrar(nuevo["correo"], f"boletin.correo:{nuevo_idx}"), cliente_id))
    pedidos_actualizados = 0
    if "direccion" in cambios and nuevo["direccion"] is not None:
        for p in con.execute("SELECT id, codigo FROM pedidos WHERE cliente_id=? AND estado='pagado'", (cliente_id,)).fetchall():
            con.execute("UPDATE pedidos SET direccion_cifrado=? WHERE id=?",
                        (cifrar(nuevo["direccion"], ns._ctx_pedido("direccion", p["codigo"])), p["id"]))
            pedidos_actualizados += 1
    campos = ",".join(sorted(cambios))
    s = _cambiar_estado(con, s, "ejecutada", detalle_cifrado=None,
                        resultado=f"Datos rectificados: {campos}. Pedidos no despachados actualizados: {pedidos_actualizados}.")
    s = _cambiar_estado(con, s, "cerrada")
    return s, f"cliente={cliente_id} campos={campos} pedidos_actualizados={pedidos_actualizados}"


@requiere_permiso("derechos.solicitar")
def exportar(sesion, codigo):
    """Ejecuta una solicitud de acceso o portabilidad verificada: devuelve el JSON y cierra la solicitud."""
    con = conectar()
    s = _solicitud_propia(con, sesion, codigo)
    if s["tipo"] not in ("acceso", "portabilidad") or s["estado"] != "en_evaluacion":
        con.close()
        raise ValueError("La solicitud no está lista para exportar o ya fue respondida")
    datos = _construir_exportacion(con, sesion.id, s)
    s = _cambiar_estado(con, s, "ejecutada", resultado="Copia de los datos entregada en formato JSON")
    _cambiar_estado(con, s, "cerrada")
    con.commit()
    con.close()
    registrar_evento(sesion, "derechos.exportar", codigo, "exito",
                     f"tipo={s['tipo']} formato=json secciones={','.join(k for k in datos if k != 'formato')}")
    return datos


def _construir_exportacion(con, cliente_id, s):
    """
    Lista blanca de lo que se entrega. NO incluye: hash de la contraseña, tokens de la pasarela,
    índices HMAC, seudónimo, códigos de autorización, contadores de bloqueo, bitácora ni datos de terceros
    (solo pedidos con cliente_id del titular, nunca los de invitados).
    """
    c = con.execute("SELECT * FROM clientes WHERE id=?", (cliente_id,)).fetchone()
    idx = c["correo_indice"]
    pedidos = con.execute("SELECT codigo, fecha, estado, monto, ultimos4, region_envio, detalle_cifrado, direccion_cifrado "
                          "FROM pedidos WHERE cliente_id=? ORDER BY id", (cliente_id,)).fetchall()
    datos = {
        "formato": VERSION_EXPORTACION,
        "generado": _ahora(),
        "solicitud": s["codigo"],
        "cuenta": {
            "nombre": c["nombre"],
            "correo": descifrar(c["correo_cifrado"], ns._ctx_cliente("correo", idx)),
            "telefono": descifrar(c["telefono_cifrado"], ns._ctx_cliente("telefono", idx)),
            "direccion": descifrar(c["direccion_cifrado"], ns._ctx_cliente("direccion", idx)),
            "nortipuntos": c["nortipuntos"],
            "mayoria_edad_declarada": c["mayoria_edad_declarada"],
        },
        "tarjetas": [{"marca": t["marca"], "terminacion": t["ultimos4"]} for t in
                     con.execute("SELECT marca, ultimos4 FROM tarjetas_guardadas WHERE cliente_id=?", (cliente_id,))],
        "pedidos": [{"codigo": p["codigo"], "fecha": p["fecha"], "estado": p["estado"], "monto": p["monto"],
                     "tarjeta": "**** " + p["ultimos4"], "region": p["region_envio"],
                     "direccion": descifrar(p["direccion_cifrado"], ns._ctx_pedido("direccion", p["codigo"])),
                     "productos": descifrar_json(p["detalle_cifrado"], ns._ctx_pedido("detalle", p["codigo"]))}
                    for p in pedidos],
        "consentimientos": [dict(f) for f in con.execute(
            "SELECT finalidad, version, accion, fecha, canal FROM consentimientos "
            "WHERE titular_tipo='cliente' AND titular_ref=? ORDER BY id", (str(cliente_id),))],
    }
    if s["tipo"] == "acceso":
        # el derecho de acceso incluye información sobre el tratamiento, además de los datos
        datos["informacion_tratamiento"] = {
            "finalidades": [{"finalidad": f["codigo"], "descripcion": f["descripcion"], "base_legal": f["base_legal"]}
                            for f in con.execute("SELECT * FROM finalidades")],
            "destinatarios": ["Pasarela de pago (tokenización y cobro)", "Empresa de despacho (solo dirección del envío)"],
            "conservacion": "Dirección y contacto de pedidos: hasta 365 días después de la entrega. "
                            "Registros contables de pedidos: plazo tributario. Cuenta: hasta que se solicite su supresión.",
            "solicitudes": [dict(f) for f in con.execute(
                "SELECT codigo, tipo, estado, fecha_recepcion, fecha_cierre FROM solicitudes_derechos "
                "WHERE cliente_id=? ORDER BY id", (cliente_id,))],
        }
    return datos


@requiere_permiso("derechos.solicitar", recurso_en_arg1=True, regla=lambda sesion, cliente_id, *_: sesion.id == cliente_id)
def mis_solicitudes(sesion, cliente_id):
    con = conectar()
    filas = con.execute("SELECT codigo, tipo, estado, fecha_recepcion, fecha_verificacion, fecha_respuesta, fecha_cierre, "
                        "plazo_vence, prorrogada, resultado FROM solicitudes_derechos WHERE cliente_id=? ORDER BY id DESC",
                        (cliente_id,)).fetchall()
    con.close()
    return [dict(f) for f in filas]


# ---------------- Privacidad (evaluación y respuesta fundamentada) ----------------

@requiere_permiso("derechos.gestionar")
def bandeja(sesion, solo_abiertas=True):
    """Lo que privacidad necesita para hacer seguimiento: sin nombres, correos ni valores."""
    con = conectar()
    filtro = "WHERE estado <> 'cerrada'" if solo_abiertas else ""
    filas = con.execute(f"SELECT codigo, tipo, estado, fecha_recepcion, fecha_verificacion, fecha_respuesta, fecha_cierre, "
                        f"plazo_vence, prorrogada, resultado, CAST(julianday(plazo_vence) - julianday('now') AS INTEGER) "
                        f"AS dias_restantes, substr(titular_seudonimo, 1, 12) AS titular FROM solicitudes_derechos "
                        f"{filtro} ORDER BY plazo_vence").fetchall()
    con.close()
    return [dict(f) for f in filas]


def _solicitud_por_codigo(con, codigo):
    s = con.execute("SELECT * FROM solicitudes_derechos WHERE codigo=?", (codigo,)).fetchone()
    if s is None:
        con.close()
        raise AccesoDenegado("Acceso denegado")
    return s


@requiere_permiso("derechos.gestionar", recurso_en_arg1=True)
def resolver_supresion(sesion, codigo, aprobar, motivo=None, pasarela=None):
    """
    Privacidad evalúa la supresión verificada. Si la aprueba se ejecuta nortishop.suprimir_cliente;
    si la rechaza debe dar un motivo fundamentado (p. ej. una obligación legal de conservar).
    """
    con = conectar()
    s = _solicitud_por_codigo(con, codigo)
    if s["tipo"] != "supresion" or s["estado"] != "en_evaluacion":
        con.close()
        raise ValueError("La solicitud no está en evaluación")
    destino = _correo_registrado(con, s["cliente_id"])
    if not aprobar:
        if not motivo or len(motivo.strip()) < 20:
            con.close()
            raise ValueError("El rechazo requiere un motivo fundamentado (mínimo 20 caracteres)")
        s = _cambiar_estado(con, s, "rechazada", resultado=motivo.strip(), evaluador_id=sesion.id)
        _cambiar_estado(con, s, "cerrada")
        con.commit()
        con.close()
        notificador.enviar(destino, f"NortiShop: respuesta a la solicitud {codigo}", f"Tu solicitud fue rechazada: {s['resultado']}")
        registrar_evento(sesion, "derechos.suprimir", codigo, "fallido", "rechazada_con_fundamento")
        return "rechazada"
    if _pedidos_en_curso(con, s["cliente_id"]):
        con.close()
        raise ValueError("El titular tiene pedidos en curso: no se puede suprimir todavía")
    cliente_id = s["cliente_id"]
    s = _cambiar_estado(con, s, "ejecutada", evaluador_id=sesion.id, resultado=(
        "Datos suprimidos: cuenta, tarjetas, preferencias, boletín y analítica. Se conservan, sin vínculo con la "
        "persona, los registros contables de los pedidos (obligación tributaria) y el historial de consentimientos "
        "bajo seudónimo (prueba de licitud, 2 años)."))
    _cambiar_estado(con, s, "cerrada")
    con.commit()
    con.close()
    notificador.enviar(destino, f"NortiShop: solicitud {codigo} ejecutada", "Tus datos personales fueron suprimidos.")
    ns.suprimir_cliente(cliente_id, pasarela)
    registrar_evento(sesion, "derechos.suprimir", codigo, "exito")
    return "cerrada"


@requiere_permiso("derechos.gestionar", recurso_en_arg1=True)
def prorrogar(sesion, codigo, motivo):
    """Una sola prórroga por igual plazo, con motivo y aviso al titular."""
    if not motivo or len(motivo.strip()) < 20:
        raise ValueError("La prórroga requiere un motivo (mínimo 20 caracteres)")
    con = conectar()
    s = _solicitud_por_codigo(con, codigo)
    if s["prorrogada"] or s["estado"] in ("ejecutada", "rechazada", "cerrada"):
        con.close()
        raise ValueError("La solicitud no admite prórroga")
    nuevo = (datetime.strptime(s["plazo_vence"], "%Y-%m-%d %H:%M:%S") + timedelta(days=PRORROGA_DIAS)).strftime("%Y-%m-%d %H:%M:%S")
    con.execute("UPDATE solicitudes_derechos SET plazo_vence=?, prorrogada=1 WHERE id=?", (nuevo, s["id"]))
    destino = _correo_registrado(con, s["cliente_id"]) if s["cliente_id"] else None
    con.commit()
    con.close()
    if destino:
        notificador.enviar(destino, f"NortiShop: prórroga de la solicitud {codigo}", f"Nuevo plazo: {nuevo}. Motivo: {motivo.strip()}")
    registrar_evento(sesion, "derechos.prorrogar", codigo, "exito")
    return nuevo
