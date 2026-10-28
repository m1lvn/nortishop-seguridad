# deteccion.py
# Reglas de detección sobre la bitácora de auditoría. registrar_evento llama a revisar() después de
# cada evento; si una regla se cumple, se crea una alerta (sin datos personales) para el rol seguridad.
# Una alerta no es un incidente: seguridad la analiza y la descarta o la escala (incidentes.py).

from datetime import datetime, timezone

from db import conectar
from rbac import requiere_permiso, AccesoDenegado

UMBRAL_FALLOS_CUENTA = 5          # fallos de login de una misma cuenta en 15 minutos
UMBRAL_FALLOS_GLOBAL = 10         # cuentas distintas con fallos en 10 minutos (relleno de credenciales)
UMBRAL_EXPORTACIONES = 3          # exportaciones de un mismo titular en 24 horas
UMBRAL_CONSULTAS_PERSONAL = 30    # contactos o direcciones descifrados por una persona en 1 hora
UMBRAL_DENEGACIONES = 5           # accesos denegados de un mismo actor en 10 minutos
PERMISOS_DATOS_PERSONALES = ("contacto.cliente.leer", "contacto.invitado.leer", "despacho.direccion.leer")
ESTADOS_ALERTA = ("abierta", "en_analisis", "descartada", "incidente")


def _ahora():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def _contar(con, sql, params):
    return con.execute(sql, params).fetchone()[0]


def crear_alerta(regla, severidad, descripcion, actor_tipo=None, actor_id=None):
    """No duplica una alerta abierta de la misma regla y descripción creada en la última hora."""
    con = conectar()
    existe = con.execute("SELECT 1 FROM alertas WHERE regla=? AND descripcion=? AND estado IN ('abierta','en_analisis') "
                         "AND fecha >= datetime('now','-1 hour')", (regla, descripcion)).fetchone()
    if existe:
        con.close()
        return None
    cur = con.execute("INSERT INTO alertas (fecha, regla, severidad, actor_tipo, actor_id, descripcion) "
                      "VALUES (?,?,?,?,?,?)", (_ahora(), regla, severidad, actor_tipo, actor_id, descripcion))
    con.commit()
    con.close()
    from auditoria import registrar_evento
    registrar_evento(None, "alertas.generar", cur.lastrowid, "exito", f"regla={regla} severidad={severidad}")
    return cur.lastrowid


def revisar(fila, evento_id):
    """Evalúa las reglas que aplican al evento recién registrado."""
    permiso, resultado = fila["permiso"], fila["resultado"]
    actor_tipo, actor_id = fila["actor_tipo"], fila["actor_id"]
    con = conectar()
    alertas = []

    if permiso == "auth.login" and resultado == "fallido":
        if fila["recurso"] is not None:
            n = _contar(con, "SELECT COUNT(*) FROM auditoria WHERE permiso='auth.login' AND resultado='fallido' "
                             "AND recurso=? AND fecha >= datetime('now','-15 minutes')", (fila["recurso"],))
            if n >= UMBRAL_FALLOS_CUENTA:
                alertas.append(("fuerza_bruta_cuenta", "media",
                                f"{n} intentos fallidos de inicio de sesión sobre la cuenta {fila['recurso']}"))
        n = _contar(con, "SELECT COUNT(DISTINCT COALESCE(recurso, 'inexistente:' || id)) FROM auditoria "
                         "WHERE permiso='auth.login' AND resultado='fallido' AND fecha >= datetime('now','-10 minutes')", ())
        if n >= UMBRAL_FALLOS_GLOBAL:
            alertas.append(("relleno_credenciales", "alta",
                            f"Fallos de inicio de sesión sobre {n} cuentas distintas en 10 minutos"))

    if permiso == "derechos.exportar" and resultado == "exito" and actor_id is not None:
        n = _contar(con, "SELECT COUNT(*) FROM auditoria WHERE permiso='derechos.exportar' AND resultado='exito' "
                         "AND actor_tipo=? AND actor_id=? AND fecha >= datetime('now','-1 day')", (actor_tipo, actor_id))
        if n >= UMBRAL_EXPORTACIONES:
            alertas.append(("exportacion_anomala", "alta", f"{n} exportaciones de datos de {actor_tipo}:{actor_id} en 24 horas"))
        cambio = _contar(con, "SELECT COUNT(*) FROM auditoria WHERE permiso='derechos.rectificar' AND resultado='exito' "
                              "AND actor_tipo=? AND actor_id=? AND detalle LIKE '%correo%' "
                              "AND fecha >= datetime('now','-1 day')", (actor_tipo, actor_id))
        if cambio:
            alertas.append(("cambio_correo_y_exportacion", "alta",
                            f"{actor_tipo}:{actor_id} cambió su correo y exportó sus datos en menos de 24 horas"))

    if permiso in PERMISOS_DATOS_PERSONALES and resultado == "permitido" and actor_tipo == "personal":
        n = _contar(con, f"SELECT COUNT(*) FROM auditoria WHERE permiso IN ({','.join('?' * len(PERMISOS_DATOS_PERSONALES))}) "
                         "AND resultado='permitido' AND actor_tipo='personal' AND actor_id=? "
                         "AND fecha >= datetime('now','-1 hour')", (*PERMISOS_DATOS_PERSONALES, actor_id))
        if n >= UMBRAL_CONSULTAS_PERSONAL:
            alertas.append(("consulta_masiva", "alta", f"personal:{actor_id} ({fila['rol']}) descifró {n} registros en 1 hora"))

    if resultado == "denegado" and actor_id is not None:
        n = _contar(con, "SELECT COUNT(*) FROM auditoria WHERE resultado='denegado' AND actor_tipo=? AND actor_id=? "
                         "AND fecha >= datetime('now','-10 minutes')", (actor_tipo, actor_id))
        if n >= UMBRAL_DENEGACIONES:
            alertas.append(("denegaciones_repetidas", "media",
                            f"{actor_tipo}:{actor_id} acumula {n} accesos denegados en 10 minutos"))

    if permiso == "roles.crear_cuenta" and fila["detalle"] in ("rol=administrador", "rol=seguridad"):
        alertas.append(("cambio_privilegios", "media", f"Se creó una cuenta privilegiada ({fila['detalle']})"))

    con.close()
    for regla, severidad, descripcion in alertas:
        crear_alerta(regla, severidad, descripcion, actor_tipo, actor_id)


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


@requiere_permiso("auditoria.verificar")
def verificar_integridad(sesion):
    """Comprueba la cadena de la bitácora; si está rota, genera una alerta crítica."""
    from auditoria import verificar_cadena
    resultado = verificar_cadena()
    if not resultado["ok"]:
        crear_alerta("integridad_auditoria", "critica",
                     f"La cadena de la bitácora no cuadra desde el registro {resultado['error_en']}")
    return resultado
