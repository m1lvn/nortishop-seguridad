# app.py
# Capa web (pantallas HTML) y API JSON de NortiShop, sobre las mismas funciones de servicio.
# La web y la API no tienen reglas de acceso propias: toda decisión la toma @requiere_permiso en
# el servicio. Por eso una petición directa a la API, con un id ajeno, un rol que no corresponde o
# campos extra, recibe la misma respuesta que en la pantalla (401, 403 o 400).
#
#   - Web: cookie HttpOnly + SameSite=Strict + Secure, y token anti-CSRF en cada formulario.
#   - API: solo "Authorization: Bearer <token>" (la cookie no sirve en /api, así no hay CSRF).
#   - Límite de intentos de login por IP, cabeceras de seguridad y errores sin detalles internos.
#
# Ejecutar:  flask --app app run         (NORTISHOP_MODO_DEMO=1 muestra el buzón de correo simulado)

import os
import hmac
import json
import time
from functools import wraps
from collections import defaultdict, deque

from flask import Flask, request, g, render_template, redirect, url_for, jsonify, abort, Response

import nortishop as ns
import consentimiento as cs
import derechos
import deteccion
import incidentes
import sesiones
import notificador
import auditoria
from rbac import AccesoDenegado
from config import LLAVE_PASARELA
from pasarela_simulada import PasarelaPago

app = Flask(__name__)
app.config.update(MAX_CONTENT_LENGTH=64 * 1024)
MODO_DEMO = os.getenv("NORTISHOP_MODO_DEMO") == "1"
COOKIE = "ns_sesion"
INTENTOS_LOGIN_IP = 10            # por IP cada 5 minutos
pasarela = PasarelaPago(LLAVE_PASARELA)
_intentos_por_ip = defaultdict(deque)


class NoAutenticado(Exception):
    pass


def es_api():
    return request.path.startswith("/api/")


# ---------------- Ciclo de cada petición ----------------

@app.before_request
def antes_de_cada_peticion():
    g.contexto = auditoria.fijar_contexto("api" if es_api() else "web", request.remote_addr)
    if es_api():
        cabecera = request.headers.get("Authorization", "")
        g.token = cabecera[7:].strip() if cabecera.startswith("Bearer ") else None
    else:
        g.token = request.cookies.get(COOKIE)
    g.sesion = sesiones.resolver(g.token) if g.token else None
    if not es_api() and request.method == "POST" and request.endpoint not in ("login", "login_personal", "registro"):
        if g.sesion is None:
            raise NoAutenticado()
        if not hmac.compare_digest(request.form.get("csrf", ""), sesiones.csrf(g.token)):
            abort(400)


@app.teardown_request
def despues_de_cada_peticion(_):
    try:
        auditoria.restaurar_contexto(g.contexto)
    except (AttributeError, ValueError):
        pass


@app.after_request
def cabeceras_de_seguridad(resp):
    resp.headers["Content-Security-Policy"] = ("default-src 'self'; style-src 'self'; form-action 'self'; "
                                               "frame-ancestors 'none'; base-uri 'none'")
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Cache-Control"] = "no-store"
    return resp


@app.context_processor
def variables_de_plantilla():
    return {"sesion": g.get("sesion"), "csrf": sesiones.csrf(g.token) if g.get("sesion") else "",
            "modo_demo": MODO_DEMO}


# ---------------- Errores: mismo mensaje en web y API, sin detalles internos ----------------

def _error(codigo, mensaje):
    if es_api():
        return jsonify({"error": mensaje}), codigo
    return render_template("error.html", codigo=codigo, mensaje=mensaje), codigo


@app.errorhandler(NoAutenticado)
def no_autenticado(_):
    if es_api():
        return jsonify({"error": "Se requiere iniciar sesión"}), 401
    # si traía una cookie es porque la sesión venció o fue revocada (p. ej. en una contención)
    return redirect(url_for("login", motivo="sesion" if request.cookies.get(COOKIE) else None))


@app.errorhandler(AccesoDenegado)
def acceso_denegado(_):
    return _error(403, "Acceso denegado")


@app.errorhandler(ValueError)
def solicitud_invalida(e):
    return _error(400, str(e))            # los mensajes de validación nombran el campo, nunca el valor


@app.errorhandler(400)
def peticion_mala(_):
    return _error(400, "Solicitud no válida")


@app.errorhandler(404)
def no_encontrado(_):
    return _error(404, "No encontrado")


@app.errorhandler(429)
def demasiados(_):
    return _error(429, "Demasiados intentos. Espera unos minutos.")


@app.errorhandler(500)
def error_interno(_):
    return _error(500, "Error interno")


def con_sesion(fn):
    @wraps(fn)
    def envoltura(*args, **kwargs):
        if g.sesion is None:
            raise NoAutenticado()
        return fn(*args, **kwargs)
    return envoltura


def _limitar_login():
    ahora = time.monotonic()
    cola = _intentos_por_ip[request.remote_addr]
    while cola and ahora - cola[0] > 300:
        cola.popleft()
    if len(cola) >= INTENTOS_LOGIN_IP:
        auditoria.registrar_evento(None, "auth.login", None, "denegado", "limite_por_ip")
        abort(429)
    cola.append(ahora)


def _entero(valor):
    """int() repite el valor en su mensaje de error; aquí el mensaje es fijo."""
    try:
        return int(valor)
    except (TypeError, ValueError):
        raise ValueError("Se esperaba un valor numérico") from None


def _datos():
    """Cuerpo JSON de la API (objeto) o formulario de la web."""
    if es_api():
        datos = request.get_json(silent=True)
        if not isinstance(datos, dict):
            raise ValueError("Se esperaba un objeto JSON")
        return datos
    return request.form


# ---------------- Web: autenticación y registro ----------------

def _iniciar_sesion_web(sesion, destino):
    token = sesiones.crear(sesion)
    resp = redirect(url_for(destino))
    resp.set_cookie(COOKIE, token, max_age=sesiones.MINUTOS_SESION * 60, httponly=True, secure=True,
                    samesite="Strict", path="/")
    return resp


@app.route("/")
def inicio():
    if g.sesion is None:
        return redirect(url_for("login"))
    return redirect(url_for("cuenta" if g.sesion.tipo == "cliente" else "panel"))


# avisos fijos de la pantalla de login: el parámetro solo elige uno, nunca se muestra su valor
AVISOS_LOGIN = {"sesion": "Tu sesión terminó o fue cerrada por seguridad. Inicia sesión de nuevo.",
                "registrada": "Cuenta creada. Ya puedes iniciar sesión."}


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        _limitar_login()
        sesion = ns.login_cliente(request.form.get("correo", ""), request.form.get("password", ""))
        if sesion:
            return _iniciar_sesion_web(sesion, "cuenta")
        return render_template("login.html", error="Correo o contraseña incorrectos", personal=False), 401
    return render_template("login.html", personal=False, aviso=AVISOS_LOGIN.get(request.args.get("motivo")))


@app.route("/personal/login", methods=["GET", "POST"])
def login_personal():
    if request.method == "POST":
        _limitar_login()
        sesion = ns.login_admin(request.form.get("usuario", ""), request.form.get("password", ""))
        if sesion:
            return _iniciar_sesion_web(sesion, "panel")
        return render_template("login.html", error="Usuario o contraseña incorrectos", personal=True), 401
    return render_template("login.html", personal=True, aviso=AVISOS_LOGIN.get(request.args.get("motivo")))


@app.route("/logout", methods=["POST"])
def logout():
    sesiones.cerrar(g.token)
    resp = redirect(url_for("login"))
    resp.delete_cookie(COOKIE, path="/")
    return resp


def _textos():
    return {f: cs.texto_vigente(f) for f, _, _, requiere in cs.FINALIDADES if requiere}


@app.route("/registro", methods=["GET", "POST"])
def registro():
    if request.method == "POST":
        f = request.form
        textos = _textos()
        # cada casilla es independiente y viene desmarcada; se acepta solo si la versión mostrada es la vigente
        marcadas = [fin for fin in textos if f.get(f"consiente_{fin}") == str(textos[fin]["version"])]
        ns.registrar_cliente(f.get("nombre"), f.get("correo"), f.get("password"),
                             telefono=f.get("telefono") or None, direccion=f.get("direccion") or None,
                             declara_mayor_edad=f.get("mayor_edad") == "si", consentimientos=marcadas, canal="web")
        return redirect(url_for("login", motivo="registrada"))
    return render_template("registro.html", textos=_textos(), descripciones={f: d for f, d, _, _ in cs.FINALIDADES})


# ---------------- Web: cliente ----------------

@app.route("/cuenta")
@con_sesion
def cuenta():
    return render_template("cuenta.html", datos=ns.obtener_datos_cliente(g.sesion, g.sesion.id),
                           ofertas=ns.ofertas(g.sesion))


@app.route("/consentimientos")
@con_sesion
def consentimientos():
    return render_template("consentimientos.html", estado=cs.estado_cliente(g.sesion, g.sesion.id),
                           historial=cs.historial(g.sesion, g.sesion.id), textos=_textos())


@app.route("/consentimientos/<finalidad>/<accion>", methods=["POST"])
@con_sesion
def cambiar_consentimiento(finalidad, accion):
    if accion == "otorgar":
        cs.otorgar(g.sesion, finalidad, _entero(request.form.get("version")), canal="web")
    elif accion == "revocar":
        cs.revocar(g.sesion, finalidad, canal="web")
    else:
        abort(404)
    return redirect(url_for("consentimientos"))


@app.route("/derechos")
@con_sesion
def mis_derechos():
    return render_template("derechos.html", solicitudes=derechos.mis_solicitudes(g.sesion, g.sesion.id))


@app.route("/derechos/solicitar", methods=["POST"])
@con_sesion
def solicitar_derecho():
    f = request.form
    cambios = None
    if f.get("tipo") == "rectificacion":
        # la web solo arma el diccionario con los 4 campos del formulario; el servicio vuelve a validarlo
        cambios = {c: f.get(c) for c in derechos.CAMPOS_RECTIFICABLES if f.get(c)}
    codigo = derechos.crear_solicitud(g.sesion, f.get("tipo"), f.get("password", ""), cambios)
    return redirect(url_for("verificar_derecho", codigo=codigo))


@app.route("/derechos/<codigo>/verificar", methods=["GET", "POST"])
@con_sesion
def verificar_derecho(codigo):
    if request.method == "POST":
        if request.form.get("etapa") == "reenviar":
            derechos.reenviar_codigo(g.sesion, codigo)
        elif request.form.get("etapa") == "correo_nuevo":
            derechos.confirmar_correo_nuevo(g.sesion, codigo, request.form.get("codigo_correo", ""))
        else:
            derechos.verificar_identidad(g.sesion, codigo, request.form.get("codigo_correo", ""))
        return redirect(url_for("verificar_derecho", codigo=codigo))
    solicitud = next((s for s in derechos.mis_solicitudes(g.sesion, g.sesion.id) if s["codigo"] == codigo), None)
    if solicitud is None:
        raise AccesoDenegado("Acceso denegado")
    return render_template("verificar.html", s=solicitud)


@app.route("/derechos/<codigo>/descargar", methods=["POST"])
@con_sesion
def descargar_datos(codigo):
    datos = derechos.exportar(g.sesion, codigo)
    return Response(json.dumps(datos, ensure_ascii=False, indent=2), mimetype="application/json",
                    headers={"Content-Disposition": f"attachment; filename=nortishop_{codigo}.json"})


@app.route("/buzon")
@con_sesion
def buzon():
    """Solo en modo demo: la bandeja de entrada simulada del propio titular (reemplaza al correo real)."""
    if not MODO_DEMO or g.sesion.tipo != "cliente":
        abort(404)
    correo = ns.obtener_datos_cliente(g.sesion, g.sesion.id)["correo"]
    return render_template("buzon.html", mensajes=list(reversed(notificador.mensajes_para(correo))))


# ---------------- Web: personal ----------------

@app.route("/panel")
@con_sesion
def panel():
    if g.sesion.tipo != "personal":
        raise AccesoDenegado("Acceso denegado")
    return render_template("panel.html")


@app.route("/privacidad/solicitudes")
@con_sesion
def bandeja_privacidad():
    return render_template("privacidad.html", solicitudes=derechos.bandeja(g.sesion, solo_abiertas=False))


@app.route("/privacidad/solicitudes/<codigo>/<accion>", methods=["POST"])
@con_sesion
def resolver_solicitud(codigo, accion):
    motivo = request.form.get("motivo")
    if accion == "aprobar":
        derechos.resolver_supresion(g.sesion, codigo, True, pasarela=pasarela)
    elif accion == "rechazar":
        derechos.resolver_supresion(g.sesion, codigo, False, motivo)
    elif accion == "prorrogar":
        derechos.prorrogar(g.sesion, codigo, motivo)
    else:
        abort(404)
    return redirect(url_for("bandeja_privacidad"))


@app.route("/seguridad")
@con_sesion
def seguridad():
    return render_template("seguridad.html", alertas=deteccion.listar_alertas(g.sesion),
                           incidentes=incidentes.listar_incidentes(g.sesion),
                           eventos=ns.leer_auditoria(g.sesion, limite=15),
                           integridad=deteccion.verificar_integridad(g.sesion))


@app.route("/seguridad/alertas/<int:alerta_id>/<accion>", methods=["POST"])
@con_sesion
def gestionar_alerta(alerta_id, accion):
    if accion == "escalar":
        f = request.form
        codigo = incidentes.registrar_incidente(g.sesion, f.get("tipo", "sin_clasificar"), f.get("severidad"),
                                                f.get("descripcion"), alerta_id)
        return redirect(url_for("ver_incidente", codigo=codigo))
    deteccion.cambiar_estado_alerta(g.sesion, alerta_id, accion)
    return redirect(url_for("seguridad"))


ACCIONES_CONTENCION = {
    "revocar_sesiones": incidentes.revocar_sesiones,
    "deshabilitar_cuenta": incidentes.deshabilitar_cuenta,
    "habilitar_cuenta": incidentes.habilitar_cuenta,
    "suspender_permiso": incidentes.suspender_permiso,
    "reactivar_permiso": incidentes.reactivar_permiso,
}


def _contener(datos):
    accion = ACCIONES_CONTENCION.get(datos.get("accion"))
    if accion is None:
        raise ValueError("Acción de contención no válida")
    if accion is incidentes.revocar_sesiones:
        return accion(g.sesion, datos.get("objetivo"))
    return accion(g.sesion, datos.get("objetivo"), datos.get("incidente"))


@app.route("/seguridad/contencion", methods=["POST"])
@con_sesion
def contencion():
    _contener(request.form)
    destino = request.form.get("incidente")
    return redirect(url_for("ver_incidente", codigo=destino) if destino else url_for("seguridad"))


@app.route("/seguridad/incidentes/<codigo>", methods=["GET", "POST"])
@con_sesion
def ver_incidente(codigo):
    if request.method == "POST":
        f = request.form
        accion = f.get("accion")
        if accion == "preservar":
            incidentes.preservar_evidencia(g.sesion, codigo)
        elif accion == "fase":
            incidentes.avanzar_fase(g.sesion, codigo, f.get("fase"), f.get("medidas") or None)
        elif accion == "evaluar":
            incidentes.registrar_evaluacion(g.sesion, codigo, f.getlist("categorias"), _entero(f.get("titulares") or 0),
                                            f.get("llaves") == "si", f.get("inicio") or None, f.get("fin") or None)
        elif accion == "notificar":
            incidentes.registrar_notificacion(g.sesion, codigo)
        elif accion == "cerrar":
            incidentes.cerrar_incidente(g.sesion, codigo, f.get("lecciones"))
        else:
            abort(400)
        return redirect(url_for("ver_incidente", codigo=codigo))
    inc = next((i for i in incidentes.listar_incidentes(g.sesion) if i["codigo"] == codigo), None)
    if inc is None:
        raise AccesoDenegado("Acceso denegado")
    return render_template("incidente.html", inc=inc, fases=incidentes.FASES, categorias=incidentes.CATEGORIAS_DATOS,
                           borrador=incidentes.borrador_notificacion(g.sesion, codigo),
                           recuperacion=incidentes.comprobar_recuperacion(g.sesion))


# ---------------- API JSON (/api/v1) ----------------

@app.route("/api/v1/sesiones", methods=["POST"])
def api_login():
    _limitar_login()
    datos = _datos()
    if "usuario" in datos:
        sesion = ns.login_admin(datos.get("usuario", ""), datos.get("password", ""))
    else:
        sesion = ns.login_cliente(datos.get("correo", ""), datos.get("password", ""))
    if sesion is None:
        return jsonify({"error": "Credenciales incorrectas"}), 401
    return jsonify({"token": sesiones.crear(sesion), "expira_en_segundos": sesiones.MINUTOS_SESION * 60})


@app.route("/api/v1/sesiones", methods=["DELETE"])
@con_sesion
def api_logout():
    sesiones.cerrar(g.token)
    return "", 204


@app.route("/api/v1/clientes/<int:cliente_id>")
@con_sesion
def api_cliente(cliente_id):
    return jsonify(ns.obtener_datos_cliente(g.sesion, cliente_id))


@app.route("/api/v1/consentimientos")
@con_sesion
def api_consentimientos():
    return jsonify({"estado": cs.estado_cliente(g.sesion, g.sesion.id),
                    "historial": cs.historial(g.sesion, g.sesion.id)})


@app.route("/api/v1/consentimientos/<finalidad>", methods=["POST"])
@con_sesion
def api_cambiar_consentimiento(finalidad):
    datos = _datos()
    if datos.get("accion") == "otorgar":
        cs.otorgar(g.sesion, finalidad, _entero(datos.get("version")), canal="api")
    elif datos.get("accion") == "revocar":
        cs.revocar(g.sesion, finalidad, canal="api")
    else:
        raise ValueError("La acción debe ser otorgar o revocar")
    return jsonify(cs.estado_cliente(g.sesion, g.sesion.id))


@app.route("/api/v1/derechos", methods=["GET", "POST"])
@con_sesion
def api_derechos():
    if request.method == "GET":
        return jsonify(derechos.mis_solicitudes(g.sesion, g.sesion.id))
    datos = _datos()
    codigo = derechos.crear_solicitud(g.sesion, datos.get("tipo"), datos.get("password", ""), datos.get("cambios"))
    return jsonify({"codigo": codigo, "estado": "recibida"}), 201


@app.route("/api/v1/derechos/<codigo>/verificacion", methods=["POST"])
@con_sesion
def api_verificar(codigo):
    return jsonify({"estado": derechos.verificar_identidad(g.sesion, codigo, _datos().get("codigo_correo", ""))})


@app.route("/api/v1/derechos/<codigo>/codigo", methods=["POST"])
@con_sesion
def api_reenviar(codigo):
    derechos.reenviar_codigo(g.sesion, codigo)
    return jsonify({"enviado": True})


@app.route("/api/v1/derechos/<codigo>/correo-nuevo", methods=["POST"])
@con_sesion
def api_correo_nuevo(codigo):
    return jsonify({"estado": derechos.confirmar_correo_nuevo(g.sesion, codigo, _datos().get("codigo_correo", ""))})


@app.route("/api/v1/derechos/<codigo>/exportacion")
@con_sesion
def api_exportar(codigo):
    return jsonify(derechos.exportar(g.sesion, codigo))


@app.route("/api/v1/privacidad/solicitudes")
@con_sesion
def api_bandeja():
    return jsonify(derechos.bandeja(g.sesion, solo_abiertas=False))


@app.route("/api/v1/privacidad/solicitudes/<codigo>", methods=["POST"])
@con_sesion
def api_resolver(codigo):
    datos = _datos()
    estado = derechos.resolver_supresion(g.sesion, codigo, datos.get("decision") == "aprobar", datos.get("motivo"),
                                         pasarela=pasarela)
    return jsonify({"estado": estado})


@app.route("/api/v1/auditoria")
@con_sesion
def api_auditoria():
    return jsonify(ns.leer_auditoria(g.sesion, limite=min(_entero(request.args.get("limite", 100)), 1000)))


@app.route("/api/v1/auditoria/integridad")
@con_sesion
def api_integridad():
    return jsonify(deteccion.verificar_integridad(g.sesion))


@app.route("/api/v1/alertas")
@con_sesion
def api_alertas():
    return jsonify(deteccion.listar_alertas(g.sesion))


@app.route("/api/v1/contencion", methods=["POST"])
@con_sesion
def api_contencion():
    resultado = _contener(_datos())
    return jsonify({"resultado": resultado})


@app.route("/api/v1/incidentes")
@con_sesion
def api_incidentes():
    return jsonify(incidentes.listar_incidentes(g.sesion))
