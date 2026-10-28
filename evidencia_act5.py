# evidencia_act5.py
# Evidencia de la Actividad 5 con una base temporal y datos ficticios (no toca nortishop.db).
# Ejecuta operaciones reales de consentimiento, derechos, auditoría, detección, incidentes e intentos
# de elusión, y guarda la salida de cada sección en evidencia/ev_act5_<seccion>.txt.
# Uso: python evidencia_act5.py

import os
import re
import json
import shutil
import sqlite3
import tempfile

import db
fd, ruta = tempfile.mkstemp(suffix=".db")
os.close(fd)
db.RUTA_BD = ruta
db.crear_tablas()

from config import LLAVE_PASARELA
from pasarela_simulada import PasarelaPago
from rbac import AccesoDenegado
import nortishop as ns
import consentimiento as cs
import derechos
import deteccion
import incidentes
import notificador
import auditoria
import app as web

CLAVE = "Clave#Segura1"
CARPETA = "evidencia"
incidentes.DIR_EVIDENCIA = tempfile.mkdtemp()
_archivo = None


def seccion(nombre, titulo):
    global _archivo
    if _archivo:
        _archivo.close()
    _archivo = open(os.path.join(CARPETA, f"ev_act5_{nombre}.txt"), "w")
    linea("=" * 78)
    linea(titulo)
    linea("=" * 78)


def linea(texto=""):
    print(texto)
    _archivo.write(str(texto) + "\n")


def intentar(etiqueta, f, *args, **kwargs):
    try:
        r = f(*args, **kwargs)
        linea(f"  {etiqueta:58} -> OK {'' if r is None else r}")
        return r
    except (AccesoDenegado, ValueError, sqlite3.DatabaseError) as e:
        linea(f"  {etiqueta:58} -> {type(e).__name__}: {e}")


def codigo(correo):
    return re.search(r"\b(\d{6})\b", notificador.ultimo_para(correo)["cuerpo"]).group(1)


def tabla(filas, columnas):
    anchos = [max(len(c), *(len(str(f[c])) for f in filas)) if filas else len(c) for c in columnas]
    linea("  " + " | ".join(c.ljust(a) for c, a in zip(columnas, anchos)))
    linea("  " + "-+-".join("-" * a for a in anchos))
    for f in filas:
        linea("  " + " | ".join(str(f[c]).ljust(a) for c, a in zip(columnas, anchos)))


def sql(consulta, params=()):
    con = db.conectar()
    filas = [dict(f) for f in con.execute(consulta, params).fetchall()]
    con.close()
    return filas


# ---------------- Datos de prueba (ficticios) ----------------
pasarela = PasarelaPago(LLAVE_PASARELA)
ns.crear_primer_admin("admin_norti", "Adm!nPanel2026")
admin = ns.login_admin("admin_norti", "Adm!nPanel2026")
for usuario, rol in [("sol_soporte", "soporte"), ("lau_logistica", "logistica"), ("mar_marketing", "marketing"),
                     ("pia_privacidad", "privacidad"), ("seba_seguridad", "seguridad")]:
    ns.crear_admin(admin, usuario, CLAVE, rol)
soporte, logistica, marketing, privacidad, seguridad = (
    ns.login_admin(u, CLAVE) for u in ("sol_soporte", "lau_logistica", "mar_marketing", "pia_privacidad", "seba_seguridad"))

# =====================================================================
seccion("consentimiento", "1. MÓDULO DE CONSENTIMIENTO")
linea("Finalidades y base legal:")
tabla(sql("SELECT codigo, base_legal, requiere_consentimiento FROM finalidades"),
      ["codigo", "base_legal", "requiere_consentimiento"])
linea("\nRegistro de Ana marcando solo 'boletin' (las demás casillas vienen desmarcadas):")
id_ana = ns.registrar_cliente("Ana Prueba", "ana@prueba.cl", CLAVE, telefono="+56 9 1111 2222",
                              direccion="Av. Los Leones 1234, Providencia", declara_mayor_edad=True,
                              consentimientos=["boletin"], canal="web")
ana = ns.login_cliente("ana@prueba.cl", CLAVE)
tabla(cs.estado_cliente(ana, id_ana), ["finalidad", "estado", "version", "fecha"])
linea("\nRegistro sin declarar mayoría de edad:")
intentar("registrar_cliente(declara_mayor_edad=False)", ns.registrar_cliente, "Menor", "menor@prueba.cl", CLAVE,
         declara_mayor_edad=False)

linea("\nUna finalidad no habilita otra:")
intentar("Ana otorga analitica_comportamiento (v1)", cs.otorgar, ana, "analitica_comportamiento", 1)
linea(f"  vigente(analitica_comportamiento) = {cs.vigente('cliente', id_ana, 'analitica_comportamiento')}")
linea(f"  vigente(ofertas_personalizadas)   = {cs.vigente('cliente', id_ana, 'ofertas_personalizadas')}")
linea(f"  ofertas() personalizadas          = {ns.ofertas(ana)['personalizadas']}")
intentar("Ana otorga una versión que no se le mostró (v7)", cs.otorgar, ana, "ofertas_personalizadas", 7)
intentar("Ana 'consiente' la finalidad contractual 'compra'", cs.otorgar, ana, "compra", 1)

linea("\nRevocación y su efecto en los procesos:")
intentar("guardar_comportamiento (con consentimiento)", ns.guardar_comportamiento, id_ana, {"categorias": ["audio"]})
linea(f"  filas en comportamiento_compra    = {sql('SELECT COUNT(*) AS n FROM comportamiento_compra')[0]['n']}")
linea(f"  boletín: ana en la campaña       = {'ana@prueba.cl' in ns.correos_para_envio_boletin(marketing)}")
intentar("Ana revoca analitica_comportamiento", cs.revocar, ana, "analitica_comportamiento")
intentar("Ana revoca boletin", cs.revocar, ana, "boletin")
linea(f"  filas en comportamiento_compra    = {sql('SELECT COUNT(*) AS n FROM comportamiento_compra')[0]['n']}")
intentar("guardar_comportamiento (revocado)", ns.guardar_comportamiento, id_ana, {"categorias": ["audio"]})
linea(f"  boletín: ana en la campaña       = {'ana@prueba.cl' in ns.correos_para_envio_boletin(marketing)}")

linea("\nNueva versión del texto con cambio material:")
cs.otorgar(ana, "boletin", 1)
intentar("privacidad publica v2 (cambio menor)", cs.publicar_texto, privacidad, "boletin",
         "Acepto recibir el boletín de NortiShop. Puedo darme de baja cuando quiera.", False)
intentar("privacidad publica v3 (cambio material)", cs.publicar_texto, privacidad, "boletin",
         "Acepto recibir el boletín de NortiShop, que ahora incluye ofertas de marcas asociadas.", True)
tabla([e for e in cs.estado_cliente(ana, id_ana) if e["finalidad"] == "boletin"],
      ["finalidad", "estado", "version", "version_vigente"])
intentar("marketing publica un texto", cs.publicar_texto, marketing, "boletin", "Texto que marketing no puede publicar.", True)

linea("\nHistorial de Ana (consultar_historial):")
tabla(cs.historial(ana, id_ana), ["fecha", "finalidad", "accion", "version", "canal"])
linea("\nFilas crudas de la tabla consentimientos (sin datos personales: titular por id):")
tabla(sql("SELECT id, titular_tipo, titular_ref, finalidad, version, accion, fecha, canal FROM consentimientos"),
      ["id", "titular_tipo", "titular_ref", "finalidad", "version", "accion", "fecha", "canal"])
linea("\nIntentos de modificar el historial directamente en la base:")
con = db.conectar()
for s in ("UPDATE consentimientos SET accion='otorgado' WHERE id=2", "DELETE FROM consentimientos WHERE id=1"):
    intentar(s, con.execute, s)
con.close()
linea("\nOtro cliente intenta ver el estado de Ana:")
id_beto = ns.registrar_cliente("Beto Prueba", "beto@prueba.cl", CLAVE, declara_mayor_edad=True)
beto = ns.login_cliente("beto@prueba.cl", CLAVE)
intentar("estado_cliente(beto, id_ana)", cs.estado_cliente, beto, id_ana)

# =====================================================================
seccion("derechos", "2. EJERCICIO DE DERECHOS")
ns.guardar_tarjeta(ana, pasarela, "4111 1111 1111 1111", "12/28", "123")
ns.comprar_con_tarjeta_guardada(ana, pasarela, [{"producto": "Audífonos Bluetooth", "cantidad": 1, "precio": 39990}],
                                39990, region="Metropolitana de Santiago")
ns.comprar_como_invitado(pasarela, "invitado@prueba.cl", "+56 9 8765 4321", "Av. Falsa 123, Santiago",
                         "5555 4444 3333 2222", "05/27", "456",
                         [{"producto": "Mouse", "cantidad": 1, "precio": 14990}], 14990, region="Metropolitana de Santiago")

linea("a) Acceso / portabilidad")
intentar("crear_solicitud con contraseña incorrecta", derechos.crear_solicitud, ana, "acceso", "clave_mala_1234")
sol = intentar("crear_solicitud('portabilidad') con contraseña", derechos.crear_solicitud, ana, "portabilidad", CLAVE)
linea(f"  correo recibido: \"{notificador.ultimo_para('ana@prueba.cl')['asunto']}\"")
linea(f"  en la base solo queda el HMAC del código: {sql('SELECT codigo_hash FROM verificaciones_identidad')[0]['codigo_hash'][:24]}...")
intentar("exportar antes de verificar", derechos.exportar, ana, sol)
intentar("Beto intenta verificar la solicitud de Ana", derechos.verificar_identidad, beto, sol, codigo("ana@prueba.cl"))
intentar("verificar_identidad con código incorrecto", derechos.verificar_identidad, ana, sol, "000000")
intentar("verificar_identidad con el código del correo", derechos.verificar_identidad, ana, sol, codigo("ana@prueba.cl"))
datos = derechos.exportar(ana, sol)
with open(os.path.join(CARPETA, "ev_act5_exportacion.json"), "w") as f:
    json.dump(datos, f, ensure_ascii=False, indent=2)
linea(f"  exportar -> JSON con secciones {list(datos)} (guardado en evidencia/ev_act5_exportacion.json)")
texto = json.dumps(datos, ensure_ascii=False)
for nombre, valor in [("hash de contraseña", "$2b$"), ("token de pasarela", "tok_"), ("datos del invitado", "invitado@prueba.cl"),
                      ("índice HMAC del correo", sql("SELECT correo_indice FROM clientes WHERE id=?", (id_ana,))[0]["correo_indice"]),
                      ("seudónimo", ns.seudonimo_cliente(id_ana))]:
    linea(f"  ¿la exportación incluye {nombre}? {valor in texto}")
intentar("exportar por segunda vez", derechos.exportar, ana, sol)

linea("\nb) Rectificación")
intentar("rectificar campo 'rol'", derechos.crear_solicitud, ana, "rectificacion", CLAVE, {"rol": "administrador"})
intentar("rectificar teléfono con formato inválido", derechos.crear_solicitud, ana, "rectificacion", CLAVE, {"telefono": "abc"})
sol = derechos.crear_solicitud(ana, "rectificacion", CLAVE, {"telefono": "+56 9 7777 8888", "direccion": "Calle Nueva 99, Ñuñoa"})
intentar("verificar y ejecutar rectificación de teléfono y dirección", derechos.verificar_identidad, ana, sol, codigo("ana@prueba.cl"))
linea(f"  dirección del pedido no despachado ahora: {ns.direccion_despacho(logistica, 1)}")
sol = derechos.crear_solicitud(ana, "rectificacion", CLAVE, {"correo": "ana.nueva@prueba.cl"})
intentar("verificar identidad (cambio de correo)", derechos.verificar_identidad, ana, sol, codigo("ana@prueba.cl"))
intentar("confirmar con el código enviado al correo NUEVO", derechos.confirmar_correo_nuevo, ana, sol, codigo("ana.nueva@prueba.cl"))
linea(f"  login con el correo antiguo: {ns.login_cliente('ana@prueba.cl', CLAVE)}")
linea(f"  login con el correo nuevo:   {ns.login_cliente('ana.nueva@prueba.cl', CLAVE)}")
linea(f"  teléfono tras el recifrado:  {ns.obtener_datos_cliente(ana, id_ana)['telefono']}")

linea("\nc) Supresión")
sol = derechos.crear_solicitud(ana, "supresion", CLAVE)
intentar("supresión con un pedido en curso", derechos.verificar_identidad, ana, sol, codigo("ana.nueva@prueba.cl"))
linea(f"  respuesta: {sql('SELECT resultado FROM solicitudes_derechos WHERE codigo=?', (sol,))[0]['resultado']}")
ns.actualizar_estado(logistica, 1, "entregado")
sol = derechos.crear_solicitud(ana, "supresion", CLAVE)
intentar("supresión sin pedidos en curso", derechos.verificar_identidad, ana, sol, codigo("ana.nueva@prueba.cl"))
linea("  bandeja de privacidad (sin nombres ni correos):")
tabla(derechos.bandeja(privacidad), ["codigo", "tipo", "estado", "fecha_recepcion", "plazo_vence", "dias_restantes", "titular"])
intentar("soporte intenta resolver la supresión", derechos.resolver_supresion, soporte, sol, True)
intentar("privacidad aprueba la supresión", derechos.resolver_supresion, privacidad, sol, True, pasarela=pasarela)
linea("  después de la supresión:")
linea(f"    clientes con id de Ana:          {sql('SELECT COUNT(*) AS n FROM clientes WHERE id=?', (id_ana,))[0]['n']}")
linea(f"    tarjetas guardadas:              {sql('SELECT COUNT(*) AS n FROM tarjetas_guardadas')[0]['n']}")
linea(f"    pedido 1 (contable):             {sql('SELECT codigo, cliente_id, direccion_cifrado, monto, estado FROM pedidos WHERE id=1')[0]}")
linea(f"    consentimientos seudonimizados:  {sql('SELECT COUNT(*) AS n FROM consentimientos WHERE titular_tipo=?', ('seudonimo',))[0]['n']}")
linea(f"    lista de supresión (respaldos):  {sql('SELECT COUNT(*) AS n FROM lista_supresion')[0]['n']} índice(s)")
linea(f"    login de Ana:                    {ns.login_cliente('ana.nueva@prueba.cl', CLAVE)}")
linea("\nSeguimiento de todas las solicitudes (estado y fechas de cada etapa):")
tabla(sql("SELECT codigo, tipo, estado, fecha_recepcion, fecha_verificacion, fecha_respuesta, fecha_cierre, cliente_id "
          "FROM solicitudes_derechos ORDER BY id"),
      ["codigo", "tipo", "estado", "fecha_recepcion", "fecha_verificacion", "fecha_respuesta", "fecha_cierre", "cliente_id"])

# =====================================================================
seccion("deteccion_incidentes", "3. DETECCIÓN DE EVENTOS SOSPECHOSOS Y RESPUESTA A INCIDENTES")
linea("Eventos que disparan reglas:")
for _ in range(5):
    ns.login_cliente("beto@prueba.cl", "clave_incorrecta_9")
linea("  5 inicios de sesión fallidos sobre la cuenta de Beto")
for i in range(deteccion.UMBRAL_FALLOS_GLOBAL):
    ns.login_cliente(f"usuario{i}@prueba.cl", "clave_incorrecta_9")
linea(f"  {deteccion.UMBRAL_FALLOS_GLOBAL} inicios de sesión fallidos sobre cuentas distintas")
for _ in range(deteccion.UMBRAL_CONSULTAS_PERSONAL):
    ns.contacto_cliente(soporte, id_beto)
linea(f"  soporte descifra {deteccion.UMBRAL_CONSULTAS_PERSONAL} veces el contacto de un cliente en 1 hora")
for _ in range(deteccion.UMBRAL_DENEGACIONES):
    try:
        ns.direccion_despacho(soporte, 2)
    except AccesoDenegado:
        pass
linea(f"  soporte acumula {deteccion.UMBRAL_DENEGACIONES} accesos denegados")
linea("\nAlertas generadas (una alerta no es un incidente hasta que seguridad la analiza):")
tabla(list(reversed(deteccion.listar_alertas(seguridad))), ["id", "regla", "severidad", "descripcion", "estado"])
alerta = [a for a in deteccion.listar_alertas(seguridad) if a["regla"] == "consulta_masiva"][0]
falso = [a for a in deteccion.listar_alertas(seguridad) if a["regla"] == "cambio_privilegios"][0]
intentar("seguridad descarta alerta de cambio de privilegios", deteccion.cambiar_estado_alerta, seguridad, falso["id"], "descartada")
inc = intentar("seguridad escala la consulta masiva a incidente", incidentes.registrar_incidente, seguridad,
               "acceso_indebido_interno", "alta", alerta["descripcion"], alerta["id"])

linea("\nContención (preservando evidencia primero):")
m = incidentes.preservar_evidencia(seguridad, inc)
linea(f"  preservar_evidencia -> {m['archivo']} sha256={m['sha256'][:24]}... ancla auditoría id={m['auditoria_ultimo_id']}")
intentar("deshabilitar cuenta personal de soporte", incidentes.deshabilitar_cuenta, seguridad, f"personal:{soporte.id}", inc)
intentar("soporte (sesión ya iniciada) lee un contacto", ns.contacto_cliente, soporte, id_beto)
linea(f"  {'soporte intenta iniciar sesión':58} -> {ns.login_admin('sol_soporte', CLAVE)} (cuenta deshabilitada)")
intentar("suspender permiso contacto.cliente.leer para todos", incidentes.suspender_permiso, seguridad, "contacto.cliente.leer", inc)
intentar("suspender un permiso del propio rol seguridad", incidentes.suspender_permiso, seguridad, "contencion.ejecutar", inc)
intentar("administrador intenta ejecutar contención", incidentes.revocar_sesiones, admin, "todas")
incidentes.avanzar_fase(seguridad, inc, "contencion", "Evidencia preservada; cuenta de soporte deshabilitada; permiso "
                                                      "contacto.cliente.leer suspendido")

linea("\nEvaluación y decisión de notificación:")
intentar("registrar_evaluacion", incidentes.registrar_evaluacion, seguridad, inc, ["correo", "telefono", "nombre"], 30, True,
         "2026-10-28 09:00", "2026-10-28 10:00")
linea("  criterios (evaluar_notificacion):")
for cats, legibles, n in [({"correo"}, False, 100), ({"correo", "telefono"}, True, 30),
                        ({"historial_compras", "tarjeta_ultimos4"}, True, 200), ({"credenciales"}, False, 3)]:
    linea(f"    {sorted(cats)}, datos legibles={legibles}, titulares={n} -> {incidentes.evaluar_notificacion(cats, legibles, n)}")

linea("\nErradicación y recuperación:")
for fase, medida in [("erradicacion", "Se revisaron los permisos de soporte y se exigió MFA al personal"),
                     ("recuperacion", "Cuenta de soporte rehabilitada con contraseña nueva; permiso reactivado")]:
    incidentes.avanzar_fase(seguridad, inc, fase, medida)
    linea(f"  fase -> {fase}")
linea(f"  comprobaciones antes de restablecer: {incidentes.comprobar_recuperacion(seguridad)}")
incidentes.habilitar_cuenta(seguridad, f"personal:{soporte.id}", inc)
incidentes.reactivar_permiso(seguridad, "contacto.cliente.leer", inc)
deteccion.cambiar_estado_alerta(seguridad, [a for a in deteccion.listar_alertas(seguridad) if a["regla"] == "relleno_credenciales"][0]["id"], "descartada")
for a in deteccion.listar_alertas(seguridad, "abierta"):
    deteccion.cambiar_estado_alerta(seguridad, a["id"], "en_analisis")
    deteccion.cambiar_estado_alerta(seguridad, a["id"], "descartada")
linea(f"  comprobaciones tras rehabilitar:     {incidentes.comprobar_recuperacion(seguridad)}")

linea("\nNotificación (borrador para los titulares):")
for fila in incidentes.borrador_notificacion(seguridad, inc).splitlines():
    linea("  " + fila)
incidentes.avanzar_fase(seguridad, inc, "notificacion")
intentar("cerrar sin registrar la notificación", incidentes.cerrar_incidente, seguridad, inc,
         "Causa: permisos amplios de soporte. Medidas: MFA, alerta de consulta masiva y revisión mensual.")
incidentes.registrar_notificacion(seguridad, inc)
incidentes.avanzar_fase(seguridad, inc, "lecciones")
intentar("cerrar con lecciones aprendidas", incidentes.cerrar_incidente, seguridad, inc,
         "Causa: permisos amplios de soporte. Medidas: MFA, alerta de consulta masiva y revisión mensual.")
tabla(incidentes.listar_incidentes(seguridad), ["codigo", "tipo", "severidad", "fase", "notificar_agencia",
                                                "notificar_titulares", "fecha_notificacion", "fecha_cierre"])

# =====================================================================
seccion("elusion", "4. INTENTOS DE ELUDIR LOS CONTROLES (API, WEB Y BASE)")
cliente = web.app.test_client()
web._intentos_por_ip.clear()
# Beto quedó bloqueado por los intentos fallidos de la sección 3: se usa una cuenta nueva
id_carla = ns.registrar_cliente("Carla Prueba", "carla@prueba.cl", CLAVE, declara_mayor_edad=True)


def peticion(etiqueta, metodo, ruta_api, token=None, **kw):
    cabeceras = {"Authorization": f"Bearer {token}"} if token else {}
    r = cliente.open(ruta_api, method=metodo, headers=cabeceras, base_url="https://localhost", **kw)
    cuerpo = r.get_data(as_text=True).strip().replace("\n", " ")
    if r.is_json:
        datos_r = r.get_json()
        if "token" in datos_r:
            datos_r = {**datos_r, "token": "<oculto>"}
        cuerpo = json.dumps(datos_r, ensure_ascii=False)
    linea(f"  {etiqueta:52} {metodo:6} {ruta_api:38} -> {r.status_code} {cuerpo[:100]}")
    return r


linea(f"  (Beto sigue bloqueado tras la fuerza bruta: login_cliente -> {ns.login_cliente('beto@prueba.cl', CLAVE)})")
t_carla = peticion("login de Carla (API)", "POST", "/api/v1/sesiones",
                  json={"correo": "carla@prueba.cl", "password": CLAVE}).get_json()["token"]
t_mkt = peticion("login de marketing (API)", "POST", "/api/v1/sesiones",
                 json={"usuario": "mar_marketing", "password": CLAVE}).get_json()["token"]
peticion("sin token", "GET", "/api/v1/consentimientos")
peticion("token inventado", "GET", "/api/v1/consentimientos", token="x" * 43)
peticion("Carla lee sus propios datos", "GET", f"/api/v1/clientes/{id_carla}", token=t_carla)
peticion("Carla pide los datos de Beto (IDOR)", "GET", f"/api/v1/clientes/{id_carla - 1}", token=t_carla)
peticion("Carla lee la auditoría", "GET", "/api/v1/auditoria", token=t_carla)
peticion("marketing lee la auditoría", "GET", "/api/v1/auditoria", token=t_mkt)
peticion("marketing ejecuta contención", "POST", "/api/v1/contencion", token=t_mkt,
         json={"accion": "revocar_sesiones", "objetivo": "todas"})
peticion("Carla rectifica con campo extra 'rol'", "POST", "/api/v1/derechos", token=t_carla,
         json={"tipo": "rectificacion", "password": CLAVE, "cambios": {"rol": "administrador"}})
peticion("Carla otorga con versión no numérica", "POST", "/api/v1/consentimientos/boletin", token=t_carla,
         json={"accion": "otorgar", "version": "1 OR 1=1"})
cliente.set_cookie(web.COOKIE, t_carla, domain="localhost")
peticion("cookie de sesión usada en la API", "GET", "/api/v1/consentimientos")
r = cliente.post("/consentimientos/boletin/otorgar", data={"version": "1"}, base_url="https://localhost")
linea(f"  {'formulario web sin token CSRF':52} POST   {'/consentimientos/boletin/otorgar':38} -> {r.status_code}")
peticion("cierre de sesión", "DELETE", "/api/v1/sesiones", token=t_carla)
peticion("token después de cerrar sesión", "GET", "/api/v1/consentimientos", token=t_carla)
linea("\nCambios directos en la base (triggers y restricciones):")
con = db.conectar()
for s in ("UPDATE administradores SET rol='superadmin' WHERE id=2", "UPDATE consentimientos SET version=99",
          "DELETE FROM auditoria", "UPDATE solicitudes_derechos SET estado='aprobada'"):
    intentar(s, con.execute, s)
con.close()

# =====================================================================
seccion("auditoria", "5. REGISTRO DE AUDITORÍA (eventos reales de toda la ejecución, incluidas las peticiones a la API)")
eventos = ns.leer_auditoria(seguridad)
linea(f"Eventos generados durante esta ejecución: {len(eventos)}. Por categoría:")
tabla(sql("SELECT categoria, resultado, COUNT(*) AS eventos FROM auditoria GROUP BY categoria, resultado ORDER BY categoria"),
      ["categoria", "resultado", "eventos"])
linea("\nMuestra de eventos (uno por operación relevante):")
muestra, vistos = [], set()
for e in eventos:
    clave = (e["permiso"], e["resultado"])
    if clave not in vistos and not e["permiso"].endswith(".gestionar"):
        vistos.add(clave)
        muestra.append(e)
for e in muestra:
    e["hash"] = e["hash"][:12] + "..."
    e["actor"] = f"{e['actor_tipo']}:{e['actor_id']}" if e["actor_tipo"] else "-"
tabla(muestra, ["id", "fecha", "actor", "rol", "permiso", "categoria", "recurso", "resultado", "canal", "detalle", "hash"])

texto = json.dumps(eventos, ensure_ascii=False)
linea("\nInformación que NO aparece en la bitácora:")
for nombre, valor in [("correos", "@"), ("contraseñas", CLAVE), ("teléfonos", "+56 9"), ("direcciones", "Av. Los Leones"),
                      ("productos comprados", "Audífonos"), ("hash bcrypt", "$2b$"), ("tokens de pasarela", "tok_")]:
    linea(f"  {nombre:22} presentes: {valor in texto}")

linea("\nProtección de la bitácora:")
linea(f"  verificar_integridad -> {deteccion.verificar_integridad(seguridad)}")
for s, f in [("marketing", marketing), ("privacidad", privacidad), ("soporte", soporte)]:
    intentar(f"{s} lee la bitácora", ns.leer_auditoria, f)
intentar("administrador purga la bitácora", ns.purgar_auditoria, admin)
intentar("seguridad purga (nada supera los 2 años)", ns.purgar_auditoria, seguridad)
con = db.conectar()
for s in ("UPDATE auditoria SET resultado='permitido' WHERE resultado='denegado'", "DELETE FROM auditoria WHERE id=10"):
    intentar(s, con.execute, s)
con.close()
linea("\nAtaque con acceso al archivo (se quitan los triggers sobre una COPIA de la base):")
copia = ruta + ".copia"
shutil.copy(ruta, copia)
original = db.RUTA_BD
db.RUTA_BD = copia
con = db.conectar()
con.execute("DROP TRIGGER auditoria_sin_update")
con.execute("UPDATE auditoria SET resultado='permitido' WHERE id=(SELECT MIN(id) FROM auditoria WHERE resultado='denegado')")
con.commit()
con.close()
linea(f"  se cambió un 'denegado' por 'permitido' -> verificar_cadena: {auditoria.verificar_cadena()}")
db.RUTA_BD = original
os.remove(copia)

_archivo.close()
os.remove(ruta)
shutil.rmtree(incidentes.DIR_EVIDENCIA, ignore_errors=True)
print("\nEvidencia guardada en evidencia/ev_act5_*.txt y evidencia/ev_act5_exportacion.json")
