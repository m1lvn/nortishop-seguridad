# derechos.py
# Ejercicio de derechos del titular: acceso, portabilidad, rectificación, supresión (Actividad 5),
# oposición y bloqueo temporal del tratamiento (Actividad 6).
#
# Canal: Mi cuenta > Mis derechos (web) y POST /api/v1/derechos (API). Cada solicitud queda en
# solicitudes_derechos con su canal, tipo, estado, fechas de cada etapa, plazo y resultado fundamentado.
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
import json
import secrets
from datetime import datetime, timedelta, timezone

from db import conectar
from cripto import cifrar, descifrar, cifrar_json, descifrar_json, indice_busqueda
from rbac import AccesoDenegado, requiere_permiso
from auditoria import registrar_evento
import notificador
import nortishop as ns

TIPOS = ("acceso", "portabilidad", "rectificacion", "supresion", "oposicion", "bloqueo")
CANALES = ("web", "api")
TIPOS_BLOQUEABLES = ("rectificacion", "supresion", "oposicion")      # art. 8 ter
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


def _ctx_rectificacion(codigo, campo, momento):
    return f"rectificacion.{campo}.{momento}:{codigo}"


def tratamientos_oponibles(con):
    """Art. 8 letra a: tratamientos cuya base de licitud es el interés legítimo del responsable."""
    return {f["codigo"] for f in con.execute("SELECT codigo FROM finalidades WHERE base_legal LIKE 'Interés legítimo%'")}


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
    if nuevo == "cerrada":
        # el bloqueo dura hasta que se resuelve la solicitud que lo motivó (art. 8 ter)
        con.execute("UPDATE bloqueos SET hasta=? WHERE asociada=? AND hasta IS NULL", (_ahora(), solicitud["codigo"]))
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

def _validar_oposicion(con, cliente_id, tratamiento, motivo):
    """Art. 8 a) y art. 11 d): tratamiento basado en interés legítimo y una breve fundamentación."""
    f = con.execute("SELECT requiere_consentimiento FROM finalidades WHERE codigo=?", (tratamiento,)).fetchone()
    if f is None:
        raise ValueError("Tratamiento desconocido")
    if tratamiento not in tratamientos_oponibles(con):
        if f["requiere_consentimiento"]:
            raise ValueError("Ese tratamiento se basa en tu consentimiento: puedes revocarlo en Consentimientos")
        raise ValueError("Ese tratamiento es necesario para cumplir el contrato de compraventa: no admite oposición")
    if not isinstance(motivo, str) or not (10 <= len(motivo.strip()) <= 500):
        raise ValueError("Indica brevemente el motivo de la oposición (entre 10 y 500 caracteres)")
    if con.execute("SELECT 1 FROM oposiciones WHERE cliente_id=? AND tratamiento=?", (cliente_id, tratamiento)).fetchone():
        raise ValueError("Ya existe una oposición acogida para ese tratamiento")
    return {"motivo": motivo.strip()}


def _validar_bloqueo(con, cliente_id, asociada):
    """Art. 8 ter: el bloqueo acompaña a una rectificación, supresión u oposición propia y en curso."""
    a = con.execute("SELECT tipo, estado, cliente_id FROM solicitudes_derechos WHERE codigo=?", (asociada or "",)).fetchone()
    if a is None or a["cliente_id"] != cliente_id or a["tipo"] not in TIPOS_BLOQUEABLES or a["estado"] == "cerrada":
        raise ValueError("El bloqueo debe asociarse a una solicitud propia en curso de rectificación, supresión u oposición")
    if con.execute("SELECT 1 FROM bloqueos WHERE asociada=? AND hasta IS NULL", (asociada,)).fetchone():
        raise ValueError("Esa solicitud ya tiene un bloqueo vigente")


@requiere_permiso("derechos.solicitar")
def crear_solicitud(sesion, tipo, password, cambios=None, *, canal="web", tratamiento=None, motivo=None, asociada=None):
    """
    Recepción: reautentica, valida lo que exige cada tipo, registra la solicitud con su canal y plazo
    y envía el código al correo registrado. Nada se ejecuta antes de verificar la identidad.
      rectificacion -> cambios {campo: valor nuevo}
      oposicion     -> tratamiento + motivo
      bloqueo       -> asociada (código de la rectificación, supresión u oposición en curso)
    """
    if tipo not in TIPOS:
        raise ValueError("Tipo de solicitud no válido")
    if canal not in CANALES:
        raise ValueError("Canal no válido")
    if not ns.reautenticar(sesion, password):
        registrar_evento(sesion, "derechos.solicitar", None, "fallido", f"tipo={tipo} reautenticacion_fallida")
        raise AccesoDenegado("Acceso denegado")
    detalle = _validar_cambios(cambios, sesion.id) if tipo == "rectificacion" else None
    con = conectar()
    try:
        if tipo == "oposicion":
            detalle = _validar_oposicion(con, sesion.id, tratamiento, motivo)
        elif tipo == "bloqueo":
            _validar_bloqueo(con, sesion.id, asociada)
    except ValueError:
        con.close()
        raise
    abierta = con.execute("SELECT 1 FROM solicitudes_derechos WHERE cliente_id=? AND tipo=? AND estado NOT IN "
                          "('cerrada')", (sesion.id, tipo)).fetchone()
    if abierta:
        con.close()
        raise ValueError("Ya tienes una solicitud de este tipo en curso")
    codigo = "SD-" + secrets.token_hex(5).upper()
    cur = con.execute("INSERT INTO solicitudes_derechos (codigo, cliente_id, titular_seudonimo, tipo, canal, tratamiento, "
                      "asociada, fecha_recepcion, plazo_vence, detalle_cifrado) VALUES (?,?,?,?,?,?,?,?,?,?)",
                      (codigo, sesion.id, ns.seudonimo_cliente(sesion.id), tipo, canal,
                       tratamiento if tipo == "oposicion" else None, asociada if tipo == "bloqueo" else None,
                       _ahora(), _en(dias=PLAZO_DIAS),
                       cifrar_json(detalle, _ctx_solicitud(codigo)) if detalle else None))
    solicitud = con.execute("SELECT * FROM solicitudes_derechos WHERE id=?", (cur.lastrowid,)).fetchone()
    _emitir_codigo(con, solicitud, "titular", _correo_registrado(con, sesion.id))
    con.commit()
    con.close()
    campos = f" campos={','.join(sorted(detalle))}" if tipo == "rectificacion" else ""
    extra = f" tratamiento={tratamiento}" if tipo == "oposicion" else f" asociada={asociada}" if tipo == "bloqueo" else ""
    registrar_evento(sesion, "derechos.solicitar", codigo, "exito", f"tipo={tipo} canal={canal}{campos}{extra}")
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
    if s["tipo"] == "bloqueo":
        aplicado = s["resultado"].startswith("Tratamiento bloqueado")
        registrar_evento(sesion, "derechos.bloquear", codigo, "exito" if aplicado else "fallido", f"asociada={s['asociada']}")
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
    if s["tipo"] == "bloqueo":
        return _ejecutar_bloqueo(con, s), None
    if s["tipo"] == "supresion" and _pedidos_en_curso(con, s["cliente_id"]):
        s = _cambiar_estado(con, s, "rechazada", resultado=(
            "Existen pedidos en curso (pagados o despachados). Sus datos se necesitan para cumplir el contrato de "
            "compraventa y el despacho. Puede volver a solicitar la supresión cuando los pedidos se hayan entregado."))
        return _cambiar_estado(con, s, "cerrada"), None
    # acceso y portabilidad: listos para exportar; supresión y oposición: esperan la evaluación de privacidad
    return s, None


def _ejecutar_bloqueo(con, s):
    """Suspende todo tratamiento salvo el almacenamiento hasta que se cierre la solicitud asociada."""
    a = con.execute("SELECT estado FROM solicitudes_derechos WHERE codigo=?", (s["asociada"],)).fetchone()
    if a is None or a["estado"] == "cerrada":
        s = _cambiar_estado(con, s, "rechazada", resultado="La solicitud asociada ya fue resuelta; no corresponde bloquear")
        return _cambiar_estado(con, s, "cerrada")
    con.execute("INSERT INTO bloqueos (cliente_id, solicitud, asociada, desde) VALUES (?,?,?,?)",
                (s["cliente_id"], s["codigo"], s["asociada"], _ahora()))
    s = _cambiar_estado(con, s, "ejecutada", resultado=(
        f"Tratamiento bloqueado mientras se resuelve la solicitud {s['asociada']}: los datos solo se almacenan. "
        "Se suspenden boletín, analítica, ofertas personalizadas, encuesta de satisfacción y consultas de soporte. "
        "Se mantiene el despacho de pedidos ya pagados (contrato)."))
    return _cambiar_estado(con, s, "cerrada")


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
    suscrito = con.execute("SELECT 1 FROM boletin_suscriptores WHERE cliente_id=?", (cliente_id,)).fetchone() is not None
    if nuevo_idx != idx and suscrito:
        con.execute("UPDATE boletin_suscriptores SET correo_indice=?, correo_cifrado=? WHERE cliente_id=?",
                    (nuevo_idx, cifrar(nuevo["correo"], f"boletin.correo:{nuevo_idx}"), cliente_id))
    pedidos_actualizados = 0
    if "direccion" in cambios and nuevo["direccion"] is not None:
        for p in con.execute("SELECT id, codigo FROM pedidos WHERE cliente_id=? AND estado='pagado'", (cliente_id,)).fetchall():
            con.execute("UPDATE pedidos SET direccion_cifrado=? WHERE id=?",
                        (cifrar(nuevo["direccion"], ns._ctx_pedido("direccion", p["codigo"])), p["id"]))
            pedidos_actualizados += 1

    # Registro del cambio (art. 6): un renglón por campo con el valor anterior y el nuevo (cifrados),
    # la fecha, la solicitud y los destinatarios a los que se comunicó la corrección.
    anterior = {**actual, "nombre": c["nombre"]}
    fecha = _ahora()
    for campo in sorted(cambios):
        destinos = ["cuenta del cliente"]
        if campo == "direccion" and pedidos_actualizados:
            destinos.append(f"empresa de despacho ({pedidos_actualizados} pedido(s) no despachado(s))")
        if campo == "correo" and suscrito:
            destinos.append("lista del boletín")
        con.execute("INSERT INTO registro_rectificaciones (solicitud, cliente_id, campo, valor_anterior_cifrado, "
                    "valor_nuevo_cifrado, fecha, comunicado_a) VALUES (?,?,?,?,?,?,?)",
                    (s["codigo"], cliente_id, campo,
                     ns._cifrar_opcional(anterior[campo], _ctx_rectificacion(s["codigo"], campo, "anterior")),
                     ns._cifrar_opcional(cambios[campo], _ctx_rectificacion(s["codigo"], campo, "nuevo")),
                     fecha, "; ".join(destinos)))
    campos = ",".join(sorted(cambios))
    s = _cambiar_estado(con, s, "ejecutada", detalle_cifrado=None,
                        resultado=f"Datos rectificados: {campos}. Pedidos no despachados actualizados: {pedidos_actualizados}.")
    s = _cambiar_estado(con, s, "cerrada")
    # aviso al correo anterior (y al nuevo si cambió): si no fue el titular, puede reaccionar
    for destino in {actual["correo"], nuevo["correo"]}:
        notificador.enviar(destino, f"NortiShop: se rectificaron tus datos ({s['codigo']})",
                           f"Campos modificados: {campos}. Si no hiciste este cambio, contáctanos de inmediato.")
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
        "tipo": s["tipo"],
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
    if s["tipo"] == "portabilidad":
        # art. 9: solo lo que el titular entregó; los puntos los genera NortiShop (dato derivado)
        del datos["cuenta"]["nortipuntos"]
        return datos
    # acceso: además de los datos, el historial de sus rectificaciones, oposiciones y bloqueos
    datos["rectificaciones"] = [{"solicitud": f["solicitud"], "campo": f["campo"], "fecha": f["fecha"],
                                 "valor_anterior": descifrar(f["valor_anterior_cifrado"], _ctx_rectificacion(f["solicitud"], f["campo"], "anterior")) if f["valor_anterior_cifrado"] else None,
                                 "valor_nuevo": descifrar(f["valor_nuevo_cifrado"], _ctx_rectificacion(f["solicitud"], f["campo"], "nuevo")) if f["valor_nuevo_cifrado"] else None,
                                 "comunicado_a": f["comunicado_a"]}
                                for f in con.execute("SELECT * FROM registro_rectificaciones WHERE cliente_id=? ORDER BY id",
                                                     (cliente_id,))]
    datos["oposiciones"] = [dict(f) for f in con.execute(
        "SELECT tratamiento, solicitud, desde FROM oposiciones WHERE cliente_id=? ORDER BY id", (cliente_id,))]
    datos["bloqueos"] = [dict(f) for f in con.execute(
        "SELECT solicitud, asociada, desde, hasta FROM bloqueos WHERE cliente_id=? ORDER BY id", (cliente_id,))]
    if s["tipo"] == "acceso":
        # el derecho de acceso incluye información sobre el tratamiento, además de los datos
        datos["informacion_tratamiento"] = {
            "finalidades": [{"finalidad": f["codigo"], "descripcion": f["descripcion"], "base_legal": f["base_legal"]}
                            for f in con.execute("SELECT * FROM finalidades")],
            "destinatarios": ["Pasarela de pago (tokenización y cobro)", "Empresa de despacho (solo dirección del envío)"],
            "interes_legitimo": "Encuesta de satisfacción tras la entrega: mejorar el servicio. Puede oponerse.",
            "conservacion": "Dirección y contacto de pedidos: hasta 365 días después de la entrega. "
                            "Registros contables de pedidos: plazo tributario. Cuenta: hasta que se solicite su supresión.",
            "solicitudes": [dict(f) for f in con.execute(
                "SELECT codigo, tipo, canal, estado, fecha_recepcion, fecha_cierre FROM solicitudes_derechos "
                "WHERE cliente_id=? ORDER BY id", (cliente_id,))],
        }
    return datos


@requiere_permiso("derechos.solicitar", recurso_en_arg1=True, regla=lambda sesion, cliente_id, *_: sesion.id == cliente_id)
def mis_solicitudes(sesion, cliente_id):
    con = conectar()
    filas = con.execute("SELECT codigo, tipo, canal, tratamiento, asociada, estado, fecha_recepcion, fecha_verificacion, "
                        "fecha_respuesta, fecha_cierre, plazo_vence, prorrogada, resultado FROM solicitudes_derechos "
                        "WHERE cliente_id=? ORDER BY id DESC",
                        (cliente_id,)).fetchall()
    con.close()
    return [dict(f) for f in filas]


# ---------------- Privacidad (evaluación y respuesta fundamentada) ----------------

@requiere_permiso("derechos.gestionar")
def bandeja(sesion, solo_abiertas=True):
    """Lo que privacidad necesita para hacer seguimiento: sin nombres, correos ni valores."""
    con = conectar()
    filtro = "WHERE estado <> 'cerrada'" if solo_abiertas else ""
    filas = con.execute(f"SELECT codigo, tipo, canal, tratamiento, asociada, estado, fecha_recepcion, fecha_verificacion, fecha_respuesta, fecha_cierre, "
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
    con.close()
    # primero se suprime; si falla, la solicitud sigue en evaluación (no se informa algo que no ocurrió)
    acta = ns.suprimir_cliente(cliente_id, pasarela)
    e, b = acta["eliminado"], acta["bloqueado_por_obligacion_legal"]
    resultado = (
        f"Eliminado: cuenta, {e['tarjetas_guardadas']} tarjeta(s), preferencias, boletín ({e['suscripcion_boletin']}), "
        f"analítica ({e['comportamiento_compra']}), {e['registro_rectificaciones']} registro(s) de rectificación y "
        f"{e['direcciones_de_pedidos']} dirección(es) de pedidos. "
        f"Bloqueado por obligación legal: {b['pedidos_bloqueo_legal']} pedido(s) sin vínculo con la persona hasta "
        f"{b['bloqueo_legal_hasta'][:10]} (Código Tributario); historial de consentimientos bajo seudónimo "
        f"(prueba de licitud, 2 años). Propagado a: pasarela de pago ({acta['propagado_a']['pasarela_pago']}) "
        "y lista de supresión de respaldos.")
    con = conectar()
    s = con.execute("SELECT * FROM solicitudes_derechos WHERE id=?", (s["id"],)).fetchone()
    s = _cambiar_estado(con, s, "ejecutada", evaluador_id=sesion.id, resultado=resultado,
                        acta=json.dumps(acta, ensure_ascii=False))
    _cambiar_estado(con, s, "cerrada")
    con.commit()
    con.close()
    notificador.enviar(destino, f"NortiShop: solicitud {codigo} ejecutada", resultado)
    registrar_evento(sesion, "derechos.suprimir", codigo, "exito",
                     f"pedidos_bloqueados={b['pedidos_bloqueo_legal']} tarjetas={e['tarjetas_guardadas']}")
    return "cerrada"


@requiere_permiso("derechos.gestionar", recurso_en_arg1=True)
def acta_supresion(sesion, codigo):
    """El acta de una supresión ejecutada: qué se eliminó, qué quedó bloqueado por ley y a quién se propagó."""
    con = conectar()
    s = _solicitud_por_codigo(con, codigo)
    con.close()
    if s["tipo"] != "supresion" or not s["acta"]:
        raise ValueError("La solicitud no es una supresión ejecutada")
    return json.loads(s["acta"])


@requiere_permiso("derechos.gestionar", recurso_en_arg1=True)
def detalle_oposicion(sesion, codigo):
    """Lo que privacidad necesita para evaluar una oposición: tratamiento y motivo (sin identificar al titular)."""
    con = conectar()
    s = _solicitud_por_codigo(con, codigo)
    con.close()
    if s["tipo"] != "oposicion" or s["detalle_cifrado"] is None:
        raise ValueError("La solicitud no es una oposición en curso")
    return {"tratamiento": s["tratamiento"], "motivo": descifrar_json(s["detalle_cifrado"], _ctx_solicitud(codigo))["motivo"]}


@requiere_permiso("derechos.gestionar", recurso_en_arg1=True)
def resolver_oposicion(sesion, codigo, aprobar, motivo=None):
    """
    Art. 8 a): el responsable debe dejar de tratar los datos salvo que acredite motivos legítimos imperiosos.
    Acoger registra la oposición (el tratamiento consulta la tabla oposiciones en cada envío); rechazar exige
    ese fundamento por escrito. Cerrar la solicitud levanta el bloqueo que estuviera asociado.
    """
    con = conectar()
    s = _solicitud_por_codigo(con, codigo)
    if s["tipo"] != "oposicion" or s["estado"] != "en_evaluacion":
        con.close()
        raise ValueError("La solicitud no está en evaluación")
    destino = _correo_registrado(con, s["cliente_id"])
    if aprobar:
        con.execute("INSERT OR IGNORE INTO oposiciones (cliente_id, tratamiento, solicitud, desde) VALUES (?,?,?,?)",
                    (s["cliente_id"], s["tratamiento"], codigo, _ahora()))
        s = _cambiar_estado(con, s, "ejecutada", evaluador_id=sesion.id, detalle_cifrado=None, resultado=(
            f"Oposición acogida: se dejó de aplicar el tratamiento '{s['tratamiento']}' a sus datos."))
    else:
        if not motivo or len(motivo.strip()) < 20:
            con.close()
            raise ValueError("El rechazo requiere acreditar motivos legítimos imperiosos (mínimo 20 caracteres)")
        s = _cambiar_estado(con, s, "rechazada", evaluador_id=sesion.id, detalle_cifrado=None, resultado=motivo.strip())
    s = _cambiar_estado(con, s, "cerrada")
    con.commit()
    con.close()
    notificador.enviar(destino, f"NortiShop: respuesta a la solicitud {codigo}", s["resultado"])
    registrar_evento(sesion, "derechos.oponer", codigo, "exito" if aprobar else "fallido",
                     f"tratamiento={s['tratamiento']} {'acogida' if aprobar else 'rechazada_con_fundamento'}")
    return "acogida" if aprobar else "rechazada"


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
