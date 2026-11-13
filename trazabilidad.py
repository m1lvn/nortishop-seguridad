# trazabilidad.py
# Actividad 7: consulta controlada de la bitácora y reconstrucción de un incidente.
#   - resumen_auditoria: lo único que ve el administrador (conteos por categoría y resultado, sin actores).
#   - consultar: el rol seguridad filtra la bitácora y debe declarar un motivo (incidente, alerta o revisión
#     periódica). La consulta queda registrada con el motivo y los filtros usados, no con sus valores.
#   - reconstruir: arma la línea de tiempo de un actor en una ventana y calcula el alcance: a qué registros
#     accedió de verdad (descontando los que la regla de negocio negó después), qué categorías de datos vio
#     y cuántos titulares distintos hay detrás. Primero verifica la cadena y las anclas: si la bitácora no
#     está íntegra, la reconstrucción lo dice y no se puede usar como prueba.
#   - PLAZOS_CONSERVACION: plazo de cada registro relacionado con la trazabilidad.

import re
from collections import defaultdict

import db
import reloj
from rbac import requiere_permiso, AccesoDenegado
from auditoria import registrar_evento, verificar_cadena, verificar_anclas

MOTIVOS_CONSULTA = ("revision_periodica", "requerimiento_agencia", "reclamo_titular")
RE_ALERTA = re.compile(r"ALERTA-(\d{1,9})")
RE_INCIDENTE = re.compile(r"INC-\d{8}-[0-9A-F]{4}")
MAX_FILAS = 2000

# Qué categorías de datos personales entrega cada operación (nombres de incidentes.CATEGORIAS_DATOS).
CATEGORIAS_POR_PERMISO = {
    "contacto.cliente.leer": ("nombre", "correo", "telefono"),
    "contacto.invitado.leer": ("correo", "telefono"),
    "despacho.direccion.leer": ("direccion",),
    "cuenta.propia.leer": ("nombre", "correo", "telefono", "direccion"),
    "pedidos.propios.leer": ("historial_compras", "tarjeta_ultimos4"),
    "encuesta.enviar": ("correo",),
    "boletin.enviar": ("correo",),
    "analitica.leer_seudonimizada": ("comportamiento_seudonimizado",),
}

PLAZOS_CONSERVACION = [
    ("Bitácora de auditoría (tabla auditoria)", "2 años", "Trigger auditoria_sin_delete + purgar_auditoria (rol seguridad)"),
    ("Anclas externas de la bitácora", "2 años (igual que la bitácora)", "Archivo de solo agregar fuera de la base"),
    ("Alertas descartadas (falsos positivos)", "2 años", "purgar_auditoria las borra junto con la bitácora vencida"),
    ("Alertas escaladas y registro de incidentes", "5 años desde el cierre", "No se borran desde la aplicación (art. 14 sexies inc. 2)"),
    ("Copia de la base preservada como evidencia", "1 año desde el cierre del incidente", "incidentes.purgar_evidencia"),
    ("Logs de la aplicación (archivo, con FiltroDatosPersonales)", "90 días", "Rotación del sistema operativo (logrotate)"),
]


def _validar_motivo(motivo):
    """Motivo de una consulta: un incidente o una alerta que existan, o un motivo general de la lista."""
    if motivo in MOTIVOS_CONSULTA:
        return motivo
    con = db.conectar()
    try:
        if isinstance(motivo, str) and RE_INCIDENTE.fullmatch(motivo):
            if con.execute("SELECT 1 FROM incidentes WHERE codigo=?", (motivo,)).fetchone():
                return motivo
        elif isinstance(motivo, str) and RE_ALERTA.fullmatch(motivo):
            if con.execute("SELECT 1 FROM alertas WHERE id=?", (int(motivo.split("-")[1]),)).fetchone():
                return motivo
    finally:
        con.close()
    raise ValueError("Indique el motivo de la consulta: un incidente (INC-...), una alerta (ALERTA-N) o "
                     + ", ".join(MOTIVOS_CONSULTA))


def _validar_fecha(valor):
    if valor is None:
        return None
    if not isinstance(valor, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}( \d{2}:\d{2}:\d{2})?", valor):
        raise ValueError("Fecha no válida (AAAA-MM-DD HH:MM:SS, en UTC)")
    return valor


def _filtrar(actor=None, recurso=None, permiso=None, desde=None, hasta=None, limite=MAX_FILAS):
    condiciones, params, usados = [], [], []
    if actor is not None:
        tipo, _, ident = str(actor).partition(":")
        if tipo not in ("cliente", "personal") or not ident.isdigit():
            raise ValueError("Actor no válido (cliente:ID o personal:ID)")
        # los inicios de sesión se registran sin actor y con la cuenta como recurso
        condiciones.append("((actor_tipo=? AND actor_id=?) OR (permiso='auth.login' AND recurso=?))")
        params += [tipo, int(ident), actor]
        usados.append("actor")
    if recurso is not None:
        condiciones.append("recurso=?")
        params.append(str(recurso))
        usados.append("recurso")
    if permiso is not None:
        condiciones.append("permiso=?")
        params.append(permiso)
        usados.append("permiso")
    if desde is not None:
        condiciones.append("fecha >= ?")
        params.append(_validar_fecha(desde))
        usados.append("desde")
    if hasta is not None:
        condiciones.append("fecha <= ?")
        params.append(_validar_fecha(hasta))
        usados.append("hasta")
    sql = "SELECT * FROM auditoria" + (" WHERE " + " AND ".join(condiciones) if condiciones else "")
    sql += " ORDER BY id LIMIT ?"
    params.append(max(1, min(int(limite), MAX_FILAS)))
    con = db.conectar()
    filas = [dict(f) for f in con.execute(sql, params)]
    con.close()
    return filas, usados


@requiere_permiso("auditoria.resumen")
def resumen_auditoria(sesion, dias=30):
    """Para el administrador: cuántos eventos hubo por categoría y resultado. Sin actores, recursos ni detalle."""
    con = db.conectar()
    filas = con.execute("SELECT categoria, resultado, COUNT(*) AS eventos FROM auditoria "
                        "WHERE fecha >= datetime(?, ?) GROUP BY categoria, resultado ORDER BY categoria, resultado",
                        (reloj.ahora(), f"-{int(dias)} days")).fetchall()
    con.close()
    return [dict(f) for f in filas]


@requiere_permiso("auditoria.leer")
def consultar(sesion, motivo, actor=None, recurso=None, permiso=None, desde=None, hasta=None, limite=500):
    motivo = _validar_motivo(motivo)
    filas, usados = _filtrar(actor, recurso, permiso, desde, hasta, limite)
    registrar_evento(sesion, "auditoria.consultar", None, "exito",
                     f"motivo={motivo} filtros={','.join(usados) or 'ninguno'} filas={len(filas)}")
    return filas


def _fallas_posteriores(filas):
    """ids de eventos 'permitido' que tuvieron después un evento de falla (tras=<id>)."""
    fallidos = set()
    for f in filas:
        m = re.search(r"\btras=(\d+)", f["detalle"] or "")
        if m:
            fallidos.add(int(m.group(1)))
    return fallidos


def _titular_de(con, permiso, recurso):
    """Titular detrás de un recurso, como referencia interna (cliente:ID o invitado:pedido ID). Sin datos."""
    if permiso in ("contacto.cliente.leer", "cuenta.propia.leer", "pedidos.propios.leer"):
        return f"cliente:{recurso}"
    if permiso in ("contacto.invitado.leer", "despacho.direccion.leer"):
        p = con.execute("SELECT cliente_id FROM pedidos WHERE id=?", (int(recurso),)).fetchone()
        if p is not None and p["cliente_id"] is not None:
            return f"cliente:{p['cliente_id']}"
        return f"invitado:pedido{recurso}"
    return None


@requiere_permiso("incidentes.gestionar", recurso_en_arg1=True)
def reconstruir(sesion, codigo, actor, desde=None, hasta=None):
    """
    Reconstruye lo que hizo `actor` (personal:ID o cliente:ID) entre `desde` y `hasta` (UTC), para el
    incidente `codigo`. Devuelve la línea de tiempo y el alcance listo para incidentes.registrar_evaluacion.
    """
    con = db.conectar()
    if con.execute("SELECT 1 FROM incidentes WHERE codigo=?", (codigo,)).fetchone() is None:
        con.close()
        raise AccesoDenegado("Acceso denegado")
    integridad = {"cadena": verificar_cadena(), "anclas": verificar_anclas()}
    filas, _ = _filtrar(actor=actor, desde=desde, hasta=hasta)
    fallidos = _fallas_posteriores(filas)

    logins, redes = [], set()
    efectivos = defaultdict(list)          # permiso -> recursos a los que accedió de verdad
    denegados = defaultdict(list)          # permiso -> recursos negados
    otras = []
    for f in filas:
        if f["permiso"] == "auth.login":
            logins.append({"fecha": f["fecha"], "resultado": f["resultado"], "origen": f["origen"], "motivo": f["detalle"]})
            if f["resultado"] == "exito" and f["origen"]:
                redes.add(f["origen"])
        elif f["resultado"] == "permitido" and f["id"] not in fallidos:
            efectivos[f["permiso"]].append(f["recurso"])
        elif f["resultado"] == "denegado":
            denegados[f["permiso"]].append(f["recurso"])
        elif f["resultado"] in ("exito", "fallido"):
            otras.append({"fecha": f["fecha"], "permiso": f["permiso"], "resultado": f["resultado"], "recurso": f["recurso"]})

    categorias, titulares = set(), set()
    for permiso, recursos in efectivos.items():
        if permiso in CATEGORIAS_POR_PERMISO:
            categorias.update(CATEGORIAS_POR_PERMISO[permiso])
            for r in recursos:
                if r is not None and str(r).isdigit():
                    t = _titular_de(con, permiso, r)
                    if t:
                        titulares.add(t)
    con.close()

    accesos_datos = [f for f in filas if f["permiso"] in CATEGORIAS_POR_PERMISO and f["resultado"] == "permitido"
                     and f["id"] not in fallidos]
    resultado = {
        "incidente": codigo,
        "actor": actor,
        "integridad": integridad,
        "confiable": integridad["cadena"]["ok"] and integridad["anclas"]["ok"],
        "eventos": len(filas),
        "primer_evento": filas[0]["fecha"] if filas else None,
        "ultimo_evento": filas[-1]["fecha"] if filas else None,
        "inicio_acceso_datos": accesos_datos[0]["fecha"] if accesos_datos else None,
        "fin_acceso_datos": accesos_datos[-1]["fecha"] if accesos_datos else None,
        "logins": logins,
        "redes": sorted(redes),
        "accesos_efectivos": {p: sorted(set(r), key=lambda x: (len(str(x)), str(x))) for p, r in efectivos.items()},
        "denegados": {p: r for p, r in denegados.items()},
        "otras_operaciones": otras,
        "categorias_datos": sorted(categorias),
        "titulares": sorted(titulares),
        "linea_de_tiempo": filas,
    }
    registrar_evento(sesion, "incidentes.reconstruir", codigo, "exito",
                     f"actor={actor} eventos={len(filas)} "
                     f"recursos={sum(len(set(r)) for p, r in efectivos.items() if p in CATEGORIAS_POR_PERMISO)}")
    return resultado
