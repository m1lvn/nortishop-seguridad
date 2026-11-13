# deteccion.py
# Reglas de detección sobre la bitácora de auditoría. registrar_evento llama a revisar() después de
# cada evento; si una regla se cumple, se crea una alerta (sin datos personales) para el rol seguridad.
# Una alerta no es un incidente: seguridad la analiza y la descarta o la escala (incidentes.py).
# Actividad 7: las ventanas se miden desde la fecha del evento (reloj.py) y se agregan cuatro reglas de
# acceso anómalo propias de NortiShop: fuera_de_horario, red_nueva_personal, lectura_secuencial y
# direcciones_historicas.

import reloj
from db import conectar
from rbac import requiere_permiso, AccesoDenegado

UMBRAL_FALLOS_CUENTA = 5          # fallos de login de una misma cuenta en 15 minutos
UMBRAL_FALLOS_GLOBAL = 10         # cuentas distintas con fallos en 10 minutos (relleno de credenciales)
UMBRAL_EXPORTACIONES = 3          # exportaciones de un mismo titular en 24 horas
UMBRAL_CONSULTAS_PERSONAL = 30    # contactos o direcciones descifrados por una persona en 1 hora
UMBRAL_DENEGACIONES = 5           # accesos denegados de un mismo actor en 10 minutos
PERMISOS_DATOS_PERSONALES = ("contacto.cliente.leer", "contacto.invitado.leer", "despacho.direccion.leer")
ESTADOS_ALERTA = ("abierta", "en_analisis", "descartada", "incidente")
# Actividad 7
HORARIO_OPERACION = (8, 21)       # soporte y logística atienden de 08:00 a 21:00 (hora de Chile), lunes a sábado
DIAS_HISTORIAL_RED = 90           # redes desde las que una cuenta del personal inició sesión antes
UMBRAL_SECUENCIA = 8              # ids consecutivos consultados por una persona en 15 minutos
UMBRAL_DIRECCIONES_HISTORICAS = 3  # direcciones de pedidos ya entregados pedidas por logística en 1 hora
ROLES_PRIVILEGIADOS = ("administrador", "seguridad")
GUARDIA_SEGURIDAD = "guardia-seguridad@nortishop.cl"   # turno de guardia 24/7 (correo y SMS en producción)


def _ahora():
    return reloj.ahora()


def _racha_consecutiva(ids):
    """Largo de la mayor secuencia de enteros consecutivos (3,4,5,6 -> 4)."""
    mejor = actual = 0
    anterior = None
    for i in sorted(set(ids)):
        actual = actual + 1 if anterior is not None and i == anterior + 1 else 1
        mejor = max(mejor, actual)
        anterior = i
    return mejor


def _contar(con, sql, params):
    return con.execute(sql, params).fetchone()[0]


def crear_alerta(regla, severidad, descripcion, actor_tipo=None, actor_id=None, objeto=None):
    """No duplica una alerta abierta de la misma regla sobre el mismo objeto (cuenta o actor) en la última hora:
    mientras se analiza, los eventos que siguen llegando quedan en la bitácora y no generan alertas nuevas."""
    con = conectar()
    existe = con.execute("SELECT 1 FROM alertas WHERE regla=? AND objeto IS ? AND estado IN ('abierta','en_analisis') "
                         "AND fecha >= datetime(?,'-1 hour')", (regla, objeto, _ahora())).fetchone()
    if existe:
        con.close()
        return None
    cur = con.execute("INSERT INTO alertas (fecha, regla, severidad, actor_tipo, actor_id, descripcion, objeto) "
                      "VALUES (?,?,?,?,?,?,?)", (_ahora(), regla, severidad, actor_tipo, actor_id, descripcion, objeto))
    con.commit()
    con.close()
    from auditoria import registrar_evento
    registrar_evento(None, "alertas.generar", cur.lastrowid, "exito", f"regla={regla} severidad={severidad}")
    if severidad in ("alta", "critica"):
        # Actividad 7: una alerta alta no puede esperar al día hábil siguiente. El aviso no lleva la
        # descripción (ids de cuentas): solo la regla, la severidad y el número de alerta.
        import notificador
        notificador.enviar(GUARDIA_SEGURIDAD, f"[NortiShop] Alerta {severidad} #{cur.lastrowid}: {regla}",
                           f"Se generó la alerta #{cur.lastrowid} ({regla}, severidad {severidad}) a las {_ahora()} UTC. "
                           "Revísela en el panel de seguridad y aplique el plan de respuesta.")
        registrar_evento(None, "alertas.avisar", cur.lastrowid, "exito", "destino=guardia")
    return cur.lastrowid


def revisar(fila, evento_id):
    """Evalúa las reglas que aplican al evento recién registrado. Las ventanas se cuentan hacia atrás desde
    la fecha del evento (t)."""
    permiso, resultado = fila["permiso"], fila["resultado"]
    actor_tipo, actor_id = fila["actor_tipo"], fila["actor_id"]
    t = fila["fecha"]
    con = conectar()
    alertas = []

    if permiso == "auth.login" and resultado == "fallido":
        if fila["recurso"] is not None:
            n = _contar(con, "SELECT COUNT(*) FROM auditoria WHERE permiso='auth.login' AND resultado='fallido' "
                             "AND recurso=? AND fecha >= datetime(?,'-15 minutes')", (fila["recurso"], t))
            if n >= UMBRAL_FALLOS_CUENTA:
                alertas.append(("fuerza_bruta_cuenta", "media",
                                f"{n} intentos fallidos de inicio de sesión sobre la cuenta {fila['recurso']}", fila["recurso"]))
        n = _contar(con, "SELECT COUNT(DISTINCT COALESCE(recurso, 'inexistente:' || id)) FROM auditoria "
                         "WHERE permiso='auth.login' AND resultado='fallido' AND fecha >= datetime(?,'-10 minutes')", (t,))
        if n >= UMBRAL_FALLOS_GLOBAL:
            alertas.append(("relleno_credenciales", "alta",
                            f"Fallos de inicio de sesión sobre {n} cuentas distintas en 10 minutos", "global"))

    # (A7) Cuenta del personal que entra desde una red desde la que nunca lo había hecho
    if (permiso == "auth.login" and resultado == "exito" and fila["origen"]
            and (fila["recurso"] or "").startswith("personal:")):
        previos = con.execute("SELECT origen FROM auditoria WHERE permiso='auth.login' AND resultado='exito' AND recurso=? "
                              "AND origen IS NOT NULL AND id < ? AND fecha >= datetime(?, ?)",
                              (fila["recurso"], evento_id, t, f"-{DIAS_HISTORIAL_RED} days")).fetchall()
        if previos and fila["origen"] not in {p["origen"] for p in previos}:
            r = con.execute("SELECT rol FROM administradores WHERE id=?", (int(fila["recurso"].split(":")[1]),)).fetchone()
            rol = r["rol"] if r else "desconocido"
            alertas.append(("red_nueva_personal", "alta" if rol in ROLES_PRIVILEGIADOS else "media",
                            f"{fila['recurso']} ({rol}) inició sesión desde la red {fila['origen']}, "
                            f"no usada en los últimos {DIAS_HISTORIAL_RED} días", fila["recurso"]))

    if permiso == "derechos.exportar" and resultado == "exito" and actor_id is not None:
        n = _contar(con, "SELECT COUNT(*) FROM auditoria WHERE permiso='derechos.exportar' AND resultado='exito' "
                         "AND actor_tipo=? AND actor_id=? AND fecha >= datetime(?,'-1 day')", (actor_tipo, actor_id, t))
        if n >= UMBRAL_EXPORTACIONES:
            alertas.append(("exportacion_anomala", "alta", f"{n} exportaciones de datos de {actor_tipo}:{actor_id} en 24 horas",
                            f"{actor_tipo}:{actor_id}"))
        cambio = _contar(con, "SELECT COUNT(*) FROM auditoria WHERE permiso='derechos.rectificar' AND resultado='exito' "
                              "AND actor_tipo=? AND actor_id=? AND detalle LIKE '%correo%' "
                              "AND fecha >= datetime(?,'-1 day')", (actor_tipo, actor_id, t))
        if cambio:
            alertas.append(("cambio_correo_y_exportacion", "alta",
                            f"{actor_tipo}:{actor_id} cambió su correo y exportó sus datos en menos de 24 horas", f"{actor_tipo}:{actor_id}"))

    if permiso in PERMISOS_DATOS_PERSONALES and resultado == "permitido" and actor_tipo == "personal":
        n = _contar(con, f"SELECT COUNT(*) FROM auditoria WHERE permiso IN ({','.join('?' * len(PERMISOS_DATOS_PERSONALES))}) "
                         "AND resultado='permitido' AND actor_tipo='personal' AND actor_id=? "
                         "AND fecha >= datetime(?,'-1 hour')", (*PERMISOS_DATOS_PERSONALES, actor_id, t))
        if n >= UMBRAL_CONSULTAS_PERSONAL:
            alertas.append(("consulta_masiva", "alta", f"personal:{actor_id} ({fila['rol']}) descifró {n} registros en 1 hora",
                            f"{actor_tipo}:{actor_id}"))

        # (A7) Datos de clientes consultados fuera del horario en que atienden soporte y logística
        local = reloj.hora_local(t)
        if not (HORARIO_OPERACION[0] <= local.hour < HORARIO_OPERACION[1]) or local.weekday() == 6:
            alertas.append(("fuera_de_horario", "media",
                            f"personal:{actor_id} ({fila['rol']}) usó {permiso} a las {local:%H:%M} "
                            f"(horario de atención {HORARIO_OPERACION[0]:02d}:00-{HORARIO_OPERACION[1]:02d}:00)",
                            f"{actor_tipo}:{actor_id}"))

        # (A7) Recorrido de ids consecutivos: patrón de extracción, no de atención de casos
        recursos = [int(f["recurso"]) for f in con.execute(
            "SELECT recurso FROM auditoria WHERE permiso=? AND resultado='permitido' AND actor_tipo='personal' "
            "AND actor_id=? AND fecha >= datetime(?,'-15 minutes')", (permiso, actor_id, t)) if (f["recurso"] or "").isdigit()]
        racha = _racha_consecutiva(recursos)
        if racha >= UMBRAL_SECUENCIA:
            alertas.append(("lectura_secuencial", "alta",
                            f"personal:{actor_id} ({fila['rol']}) consultó {racha} registros de ids consecutivos con "
                            f"{permiso} en 15 minutos", f"{actor_tipo}:{actor_id}"))

    # (A7) Logística pide direcciones de pedidos ya entregados (la regla de negocio se las niega)
    if (permiso == "despacho.direccion.leer" and resultado == "denegado" and actor_tipo == "personal"
            and "motivo=regla_negocio" in (fila["detalle"] or "")):
        n = _contar(con, "SELECT COUNT(*) FROM auditoria WHERE permiso='despacho.direccion.leer' AND resultado='denegado' "
                         "AND detalle LIKE '%motivo=regla_negocio%' AND actor_tipo='personal' AND actor_id=? "
                         "AND fecha >= datetime(?,'-1 hour')", (actor_id, t))
        if n >= UMBRAL_DIRECCIONES_HISTORICAS:
            alertas.append(("direcciones_historicas", "media",
                            f"personal:{actor_id} ({fila['rol']}) pidió {n} direcciones de pedidos sin envío activo en 1 hora",
                            f"{actor_tipo}:{actor_id}"))

    if resultado == "denegado" and actor_id is not None:
        n = _contar(con, "SELECT COUNT(*) FROM auditoria WHERE resultado='denegado' AND actor_tipo=? AND actor_id=? "
                         "AND fecha >= datetime(?,'-10 minutes')", (actor_tipo, actor_id, t))
        if n >= UMBRAL_DENEGACIONES:
            alertas.append(("denegaciones_repetidas", "media",
                            f"{actor_tipo}:{actor_id} acumula {n} accesos denegados en 10 minutos", f"{actor_tipo}:{actor_id}"))

    if permiso == "roles.crear_cuenta" and fila["detalle"] in ("rol=administrador", "rol=seguridad"):
        alertas.append(("cambio_privilegios", "media", f"Se creó una cuenta privilegiada ({fila['detalle']})", fila["recurso"]))

    con.close()
    for regla, severidad, descripcion, objeto in alertas:
        crear_alerta(regla, severidad, descripcion, actor_tipo, actor_id, objeto)


# ---------- Operaciones del rol seguridad ----------

@requiere_permiso("alertas.gestionar")
def listar_alertas(sesion, estado=None):
    con = conectar()
    if estado:
        filas = con.execute("SELECT * FROM alertas WHERE estado=? ORDER BY id DESC", (estado,)).fetchall()
    else:
        filas = con.execute("SELECT * FROM alertas ORDER BY id DESC").fetchall()
    con.close()
    return [dict(f) for f in filas]


@requiere_permiso("alertas.gestionar", recurso_en_arg1=True)
def cambiar_estado_alerta(sesion, alerta_id, estado):
    """Analizar o descartar. Para convertirla en incidente se usa incidentes.escalar_alerta."""
    if estado not in ("en_analisis", "descartada"):
        raise ValueError("Estado de alerta no válido")
    con = conectar()
    f = con.execute("SELECT estado FROM alertas WHERE id=?", (alerta_id,)).fetchone()
    if f is None:
        con.close()
        raise AccesoDenegado("Acceso denegado")
    if f["estado"] in ("descartada", "incidente"):
        con.close()
        raise ValueError("La alerta ya fue resuelta")
    con.execute("UPDATE alertas SET estado=? WHERE id=?", (estado, alerta_id))
    con.commit()
    con.close()
    from auditoria import registrar_evento
    registrar_evento(sesion, "alertas.estado", alerta_id, "exito", f"estado={estado}")   # Actividad 7


@requiere_permiso("auditoria.verificar")
def verificar_integridad(sesion):
    """Comprueba la cadena de la bitácora y (Actividad 7) las anclas externas; si algo no cuadra, alerta crítica."""
    from auditoria import verificar_cadena, verificar_anclas, registrar_evento
    resultado = verificar_cadena()
    if not resultado["ok"]:
        crear_alerta("integridad_auditoria", "critica",
                     f"La cadena de la bitácora no cuadra desde el registro {resultado['error_en']}")
    anclas = verificar_anclas()
    resultado["anclas"] = anclas
    if anclas["anclas"]:
        registrar_evento(sesion, "auditoria.verificar_anclas", None, "exito" if anclas["ok"] else "fallido",
                         f"anclas={anclas['anclas']}" + (f" error_en={anclas['error_en']}" if anclas["error_en"] else ""))
    if not anclas["ok"]:
        resultado["ok"] = False
        crear_alerta("integridad_auditoria", "critica",
                     f"La bitácora no coincide con el ancla externa del registro {anclas['error_en']} "
                     "(se borraron o reescribieron registros)")
    return resultado
