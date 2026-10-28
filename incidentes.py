# incidentes.py
# Procedimientos técnicos del plan de respuesta a incidentes (rol seguridad):
#   - registro del incidente y avance por fases (análisis -> contención -> erradicación ->
#     recuperación -> notificación -> lecciones -> cerrado);
#   - contención: revocar sesiones, deshabilitar cuentas, suspender permisos;
#   - preservación de evidencia ANTES de cambiar nada (copia de la base + SHA-256 + ancla de la bitácora);
#   - recuperación: recifrado con una llave nueva y comprobaciones previas a restablecer el servicio;
#   - evaluación de notificación y borrador del aviso con el contenido mínimo.

import os
import json
import stat
import hashlib
import secrets
import sqlite3
from datetime import datetime, timezone

import db
from config import VERSION_ACTUAL
from cripto import cifrar, descifrar
from rbac import AccesoDenegado, requiere_permiso, PERMISOS
from auditoria import registrar_evento, verificar_cadena, ancla
import sesiones

FASES = ("analisis", "contencion", "erradicacion", "recuperacion", "notificacion", "lecciones", "cerrado")
SEVERIDADES = ("baja", "media", "alta", "critica")
DIR_EVIDENCIA = os.getenv("NORTISHOP_DIR_EVIDENCIA", "evidencia_incidentes")

# categorías de datos que se pueden ver afectadas y las que obligan a comunicar a los titulares
CATEGORIAS_DATOS = ("correo", "telefono", "direccion", "nombre", "historial_compras", "tarjeta_ultimos4",
                    "token_pago", "credenciales", "comportamiento_seudonimizado")
CATEGORIAS_ECONOMICAS = {"historial_compras", "tarjeta_ultimos4", "token_pago"}
CONTACTO = "privacidad@nortishop.cl"


def _ahora():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def _incidente(con, codigo):
    f = con.execute("SELECT * FROM incidentes WHERE codigo=?", (codigo,)).fetchone()
    if f is None:
        con.close()
        raise AccesoDenegado("Acceso denegado")
    return f


def _actor(actor):
    """'cliente:3' o 'personal:2' -> ('cliente', 3). Se valida contra la base."""
    try:
        tipo, ident = actor.split(":", 1)
        ident = int(ident)
    except (AttributeError, ValueError):
        raise ValueError("Actor no válido")
    if tipo not in ("cliente", "personal"):
        raise ValueError("Actor no válido")
    return tipo, ident


# ---------------- Registro y fases ----------------

@requiere_permiso("incidentes.gestionar")
def registrar_incidente(sesion, tipo, severidad, descripcion, alerta_id=None):
    """Un incidente nace de una alerta escalada o de un reporte recibido por los canales del plan."""
    if severidad not in SEVERIDADES:
        raise ValueError("Severidad no válida")
    if not descripcion or len(descripcion) > 1000:
        raise ValueError("La descripción es obligatoria (máximo 1000 caracteres)")
    codigo = "INC-" + datetime.now(timezone.utc).strftime("%Y%m%d") + "-" + secrets.token_hex(2).upper()
    con = db.conectar()
    cur = con.execute("INSERT INTO incidentes (codigo, fecha_deteccion, tipo, severidad, descripcion, responsable_id) "
                      "VALUES (?,?,?,?,?,?)", (codigo, _ahora(), tipo, severidad, descripcion, sesion.id))
    if alerta_id is not None:
        con.execute("UPDATE alertas SET estado='incidente', incidente_id=? WHERE id=? AND estado IN ('abierta','en_analisis')",
                    (cur.lastrowid, alerta_id))
    con.commit()
    con.close()
    registrar_evento(sesion, "incidentes.registrar", codigo, "exito",
                     f"severidad={severidad} alerta={alerta_id if alerta_id is not None else 'reporte'}")
    return codigo


@requiere_permiso("incidentes.gestionar", recurso_en_arg1=True)
def avanzar_fase(sesion, codigo, fase, medidas=None):
    """Las fases solo avanzan. Para pasar a 'cerrado' se usa cerrar_incidente (tiene condiciones)."""
    if fase not in FASES or fase == "cerrado":
        raise ValueError("Fase no válida")
    con = db.conectar()
    inc = _incidente(con, codigo)
    if FASES.index(fase) <= FASES.index(inc["fase"]):
        con.close()
        raise ValueError("Las fases del incidente solo avanzan")
    medidas_total = "\n".join(m for m in (inc["medidas"], medidas) if m)
    con.execute("UPDATE incidentes SET fase=?, medidas=? WHERE id=?", (fase, medidas_total or None, inc["id"]))
    con.commit()
    con.close()
    registrar_evento(sesion, "incidentes.fase", codigo, "exito", f"fase={fase}")


def evaluar_notificacion(categorias, llaves_comprometidas, titulares_afectados):
    """
    Criterio del plan (Ley 21.719, art. 14 sexies):
      - a la Agencia: si hay riesgo razonable para los titulares. Si solo se filtró información cifrada y las
        llaves NO se comprometieron, los datos no son inteligibles y el riesgo se considera no razonable
        (se documenta igual la decisión). Credenciales o datos en claro: siempre hay riesgo.
      - a los titulares: además, cuando los datos se refieren a obligaciones de carácter económico, financiero,
        bancario o comercial (historial de compras, tarjeta, token de pago).
    """
    categorias = set(categorias)
    if categorias - set(CATEGORIAS_DATOS):
        raise ValueError("Categoría de datos desconocida")
    riesgo = bool(categorias) and (llaves_comprometidas or "credenciales" in categorias) and titulares_afectados > 0
    return {"notificar_agencia": riesgo, "notificar_titulares": riesgo and bool(categorias & CATEGORIAS_ECONOMICAS)}


@requiere_permiso("incidentes.gestionar", recurso_en_arg1=True)
def registrar_evaluacion(sesion, codigo, categorias, titulares_afectados, llaves_comprometidas,
                         inicio_estimado=None, fin_estimado=None):
    decision = evaluar_notificacion(categorias, llaves_comprometidas, int(titulares_afectados))
    con = db.conectar()
    inc = _incidente(con, codigo)
    con.execute("UPDATE incidentes SET datos_afectados=?, titulares_afectados=?, inicio_estimado=?, fin_estimado=?, "
                "notificar_agencia=?, notificar_titulares=? WHERE id=?",
                (",".join(sorted(categorias)), int(titulares_afectados), inicio_estimado, fin_estimado,
                 int(decision["notificar_agencia"]), int(decision["notificar_titulares"]), inc["id"]))
    con.commit()
    con.close()
    registrar_evento(sesion, "incidentes.evaluar", codigo, "exito",
                     f"agencia={int(decision['notificar_agencia'])} titulares={int(decision['notificar_titulares'])}")
    return decision


@requiere_permiso("incidentes.gestionar", recurso_en_arg1=True)
def borrador_notificacion(sesion, codigo, destinatario="titulares"):
    """Texto con el contenido mínimo del aviso. Lo revisa y autoriza el responsable de comunicación."""
    con = db.conectar()
    inc = _incidente(con, codigo)
    con.close()
    periodo = (f"entre {inc['inicio_estimado']} y {inc['fin_estimado']}" if inc["inicio_estimado"]
               else "en investigación")
    datos = (inc["datos_afectados"] or "en evaluación").replace(",", ", ")
    encabezado = ("A la Agencia de Protección de Datos Personales" if destinatario == "agencia"
                  else "Estimado/a cliente de NortiShop")
    return "\n".join([
        f"{encabezado}:",
        f"1. Qué ocurrió: {inc['descripcion']}",
        f"2. Fecha de detección: {inc['fecha_deteccion']} (UTC). Período en que ocurrió: {periodo}.",
        f"3. Datos personales potencialmente afectados: {datos}. "
        f"Titulares afectados (estimación): {inc['titulares_afectados'] if inc['titulares_afectados'] is not None else 'en evaluación'}.",
        "4. Posibles consecuencias: uso de los datos para correos o llamadas fraudulentas (phishing) y, si hubo "
        "credenciales, acceso no autorizado a la cuenta.",
        f"5. Medidas adoptadas: {inc['medidas'] or 'contención en curso'}.",
        "6. Recomendaciones: cambie su contraseña de NortiShop y la de otros sitios donde use la misma; desconfíe de "
        "mensajes que pidan datos de pago o claves; NortiShop nunca le pedirá su contraseña.",
        f"7. Contacto para consultas y seguimiento: {CONTACTO} (indique el código {inc['codigo']}).",
    ])


@requiere_permiso("incidentes.gestionar", recurso_en_arg1=True)
def cerrar_incidente(sesion, codigo, lecciones):
    """
    Condiciones de cierre: la notificación está decidida (y hecha si correspondía), quedaron documentadas
    las lecciones aprendidas, no hay permisos suspendidos ni alertas abiertas del incidente y la bitácora está íntegra.
    """
    if not lecciones or len(lecciones.strip()) < 30:
        raise ValueError("Documente causas y medidas correctivas (mínimo 30 caracteres)")
    con = db.conectar()
    inc = _incidente(con, codigo)
    faltas = []
    if inc["notificar_agencia"] is None:
        faltas.append("la decisión de notificación no está registrada")
    elif (inc["notificar_agencia"] or inc["notificar_titulares"]) and not inc["fecha_notificacion"]:
        faltas.append("falta registrar la notificación")
    if inc["fase"] != "lecciones":
        faltas.append("el incidente no llegó a la fase de lecciones aprendidas")
    if con.execute("SELECT COUNT(*) FROM permisos_suspendidos").fetchone()[0]:
        faltas.append("hay permisos suspendidos")
    if not verificar_cadena()["ok"]:
        faltas.append("la bitácora de auditoría no está íntegra")
    if faltas:
        con.close()
        raise ValueError("No se puede cerrar: " + "; ".join(faltas))
    con.execute("UPDATE incidentes SET fase='cerrado', lecciones=?, fecha_cierre=? WHERE id=?",
                (lecciones.strip(), _ahora(), inc["id"]))
    con.commit()
    con.close()
    registrar_evento(sesion, "incidentes.cerrar", codigo, "exito")


@requiere_permiso("incidentes.gestionar", recurso_en_arg1=True)
def registrar_notificacion(sesion, codigo):
    con = db.conectar()
    inc = _incidente(con, codigo)
    con.execute("UPDATE incidentes SET fecha_notificacion=? WHERE id=?", (_ahora(), inc["id"]))
    con.commit()
    con.close()
    registrar_evento(sesion, "incidentes.notificar", codigo, "exito")


@requiere_permiso("incidentes.gestionar")
def listar_incidentes(sesion):
    con = db.conectar()
    filas = con.execute("SELECT * FROM incidentes ORDER BY id DESC").fetchall()
    con.close()
    return [dict(f) for f in filas]


# ---------------- Contención ----------------

@requiere_permiso("contencion.ejecutar", recurso_en_arg1=True)
def revocar_sesiones(sesion, actor):
    """actor = 'cliente:3', 'personal:2' o 'todas'."""
    n = sesiones.revocar_todas() if actor == "todas" else sesiones.revocar_de_actor(*_actor(actor))
    registrar_evento(sesion, "contencion.revocar_sesiones", actor, "exito", f"sesiones={n}")
    return n


def _fijar_habilitacion(sesion, actor, deshabilitada):
    tipo, ident = _actor(actor)
    if tipo == "personal" and ident == sesion.id:
        raise ValueError("No puedes deshabilitar tu propia cuenta")
    tabla = "clientes" if tipo == "cliente" else "administradores"
    con = db.conectar()
    cur = con.execute(f"UPDATE {tabla} SET deshabilitada=? WHERE id=?", (deshabilitada, ident))
    con.commit()
    con.close()
    if not cur.rowcount:
        raise AccesoDenegado("Acceso denegado")
    return tipo, ident


@requiere_permiso("contencion.ejecutar", recurso_en_arg1=True)
def deshabilitar_cuenta(sesion, actor, incidente=None):
    """La cuenta deja de poder iniciar sesión y sus sesiones se revocan; sus datos no se tocan (evidencia)."""
    tipo, ident = _fijar_habilitacion(sesion, actor, 1)
    n = sesiones.revocar_de_actor(tipo, ident)
    registrar_evento(sesion, "contencion.deshabilitar_cuenta", actor, "exito", f"incidente={incidente} sesiones={n}")


@requiere_permiso("contencion.ejecutar", recurso_en_arg1=True)
def habilitar_cuenta(sesion, actor, incidente=None):
    _fijar_habilitacion(sesion, actor, 0)
    registrar_evento(sesion, "contencion.habilitar_cuenta", actor, "exito", f"incidente={incidente}")


@requiere_permiso("contencion.ejecutar", recurso_en_arg1=True)
def suspender_permiso(sesion, permiso, incidente=None):
    """
    Corta una operación para todos los roles (p. ej. 'derechos.solicitar' si se abusa de la exportación).
    Los permisos del propio rol seguridad no se pueden suspender, para no bloquear la respuesta.
    """
    todos = set().union(*PERMISOS.values())
    if permiso not in todos or permiso in PERMISOS["seguridad"]:
        raise ValueError("Permiso no suspendible")
    con = db.conectar()
    con.execute("INSERT OR IGNORE INTO permisos_suspendidos (permiso, desde, incidente) VALUES (?,?,?)",
                (permiso, _ahora(), incidente))
    con.commit()
    con.close()
    registrar_evento(sesion, "contencion.suspender_permiso", permiso, "exito", f"incidente={incidente}")


@requiere_permiso("contencion.ejecutar", recurso_en_arg1=True)
def reactivar_permiso(sesion, permiso, incidente=None):
    con = db.conectar()
    con.execute("DELETE FROM permisos_suspendidos WHERE permiso=?", (permiso,))
    con.commit()
    con.close()
    registrar_evento(sesion, "contencion.reactivar_permiso", permiso, "exito", f"incidente={incidente}")


@requiere_permiso("contencion.ejecutar", recurso_en_arg1=True)
def preservar_evidencia(sesion, codigo):
    """
    Primera acción de la contención: copia consistente de la base (API de respaldo de SQLite) con su SHA-256
    y el ancla de la bitácora, en una carpeta con permisos 700 fuera del repositorio. La copia queda cifrada
    igual que la base (los datos personales siguen protegidos) y no se modifica después.
    """
    con = db.conectar()
    _incidente(con, codigo)
    con.close()
    carpeta = os.path.join(DIR_EVIDENCIA, codigo)
    os.makedirs(carpeta, mode=0o700, exist_ok=True)
    marca = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    destino = os.path.join(carpeta, f"bd_{marca}.db")
    origen = sqlite3.connect(db.RUTA_BD)
    copia = sqlite3.connect(destino)
    origen.backup(copia)
    copia.close()
    origen.close()
    os.chmod(destino, stat.S_IRUSR)                    # solo lectura para el dueño
    with open(destino, "rb") as f:
        sha256 = hashlib.sha256(f.read()).hexdigest()
    ultimo_id, ultimo_hash = ancla()
    manifiesto = {"incidente": codigo, "archivo": os.path.basename(destino), "sha256": sha256, "fecha": _ahora(),
                  "preservado_por": f"personal:{sesion.id}", "auditoria_ultimo_id": ultimo_id,
                  "auditoria_ultimo_hash": ultimo_hash}
    ruta_manifiesto = os.path.join(carpeta, f"manifiesto_{marca}.json")
    with open(ruta_manifiesto, "w") as f:
        json.dump(manifiesto, f, indent=2)
    os.chmod(ruta_manifiesto, stat.S_IRUSR)
    registrar_evento(sesion, "contencion.preservar_evidencia", codigo, "exito", f"sha256={sha256}")
    return manifiesto


# ---------------- Erradicación y recuperación ----------------

# columnas cifradas y cómo se arma su contexto (AAD) a partir de la fila
COLUMNAS_CIFRADAS = [
    ("clientes", "correo_cifrado", lambda f: f"clientes.correo:{f['correo_indice']}"),
    ("clientes", "telefono_cifrado", lambda f: f"clientes.telefono:{f['correo_indice']}"),
    ("clientes", "direccion_cifrado", lambda f: f"clientes.direccion:{f['correo_indice']}"),
    ("pedidos", "invitado_correo_cifrado", lambda f: f"pedidos.invitado_correo:{f['codigo']}"),
    ("pedidos", "invitado_telefono_cifrado", lambda f: f"pedidos.invitado_telefono:{f['codigo']}"),
    ("pedidos", "direccion_cifrado", lambda f: f"pedidos.direccion:{f['codigo']}"),
    ("pedidos", "detalle_cifrado", lambda f: f"pedidos.detalle:{f['codigo']}"),
    ("boletin_suscriptores", "correo_cifrado", lambda f: f"boletin.correo:{f['correo_indice']}"),
    ("comportamiento_compra", "datos_cifrado", lambda f: f"comportamiento.datos:{f['seudonimo']}"),
    ("solicitudes_derechos", "detalle_cifrado", lambda f: f"solicitudes.detalle:{f['codigo']}"),
]


def valores_con_llave_antigua():
    """Cuántos valores siguen cifrados con una versión distinta de la actual."""
    con = db.conectar()
    n = 0
    for tabla, columna, _ in COLUMNAS_CIFRADAS:
        n += con.execute(f"SELECT COUNT(*) FROM {tabla} WHERE {columna} IS NOT NULL AND {columna} NOT LIKE ?",
                         (f"{VERSION_ACTUAL}:%",)).fetchone()[0]
    con.close()
    return n


def recifrar_datos():
    """
    Tras agregar una llave nueva (generar_llaves.py --rotar), vuelve a cifrar todo con VERSION_ACTUAL en una
    sola transacción. Si una llave antigua se filtró, después de esto puede retirarse del .env.
    Lo ejecuta rotar_llaves.py en el servidor.
    """
    con = db.conectar()
    n = 0
    for tabla, columna, contexto in COLUMNAS_CIFRADAS:
        for f in con.execute(f"SELECT * FROM {tabla} WHERE {columna} IS NOT NULL AND {columna} NOT LIKE ?",
                             (f"{VERSION_ACTUAL}:%",)).fetchall():
            ctx = contexto(f)
            con.execute(f"UPDATE {tabla} SET {columna}=? WHERE id=?", (cifrar(descifrar(f[columna], ctx), ctx), f["id"]))
            n += 1
    con.commit()
    con.close()
    registrar_evento(None, "contencion.recifrar_datos", None, "exito", f"valores={n} version={VERSION_ACTUAL}")
    return n


@requiere_permiso("incidentes.gestionar")
def comprobar_recuperacion(sesion):
    """Comprobaciones antes de restablecer el servicio. 'listo' solo si todas se cumplen."""
    con = db.conectar()
    deshabilitadas = (con.execute("SELECT COUNT(*) FROM clientes WHERE deshabilitada=1").fetchone()[0]
                      + con.execute("SELECT COUNT(*) FROM administradores WHERE deshabilitada=1").fetchone()[0])
    suspendidos = [f["permiso"] for f in con.execute("SELECT permiso FROM permisos_suspendidos")]
    criticas = con.execute("SELECT COUNT(*) FROM alertas WHERE severidad IN ('alta','critica') "
                           "AND estado IN ('abierta','en_analisis')").fetchone()[0]
    con.close()
    cadena = verificar_cadena()
    resultado = {
        "bitacora_integra": cadena["ok"],
        "valores_con_llave_antigua": valores_con_llave_antigua(),
        "permisos_suspendidos": suspendidos,
        "cuentas_deshabilitadas": deshabilitadas,
        "alertas_altas_sin_resolver": criticas,
    }
    resultado["listo"] = (cadena["ok"] and resultado["valores_con_llave_antigua"] == 0
                          and not suspendidos and criticas == 0)
    registrar_evento(sesion, "incidentes.comprobar_recuperacion", None, "exito", f"listo={int(resultado['listo'])}")
    return resultado
