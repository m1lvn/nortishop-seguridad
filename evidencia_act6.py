# evidencia_act6.py
# Evidencia de la Actividad 6 (mecanismos de derechos) con una base temporal y datos ficticios.
# Cada sección ejecuta una solicitud concreta y guarda la salida en evidencia/ev_act6_<seccion>.txt.
# Uso: python evidencia_act6.py

import os
import re
import json
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
import notificador
import app as web

CLAVE = "Clave#Segura1"
CARPETA = "evidencia"
_archivo = None


def seccion(nombre, titulo):
    global _archivo
    if _archivo:
        _archivo.close()
    _archivo = open(os.path.join(CARPETA, f"ev_act6_{nombre}.txt"), "w")
    linea("=" * 78)
    linea(titulo)
    linea("=" * 78)


def linea(texto=""):
    print(texto)
    _archivo.write(str(texto) + "\n")


def intentar(etiqueta, f, *args, **kwargs):
    try:
        r = f(*args, **kwargs)
        linea(f"  {etiqueta:62} -> OK {'' if r is None else r}")
        return r
    except (AccesoDenegado, ValueError, sqlite3.DatabaseError) as e:
        linea(f"  {etiqueta:62} -> {type(e).__name__}: {e}")


def codigo(correo):
    return re.search(r"\b(\d{6})\b", notificador.ultimo_para(correo)["cuerpo"]).group(1)


def tabla(filas, columnas):
    filas = [{c: ("" if f[c] is None else f[c]) for c in columnas} for f in filas]
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


def solicitud(cod):
    return sql("SELECT codigo, tipo, canal, tratamiento, asociada, estado, fecha_recepcion, fecha_verificacion, "
               "fecha_respuesta, fecha_cierre, plazo_vence, resultado FROM solicitudes_derechos WHERE codigo=?", (cod,))[0]


def auditoria(permisos):
    marcas = ",".join("?" * len(permisos))
    tabla(sql(f"SELECT id, actor_tipo, actor_id, permiso, recurso, resultado, canal, detalle FROM auditoria "
              f"WHERE permiso IN ({marcas}) AND resultado <> 'permitido' ORDER BY id", permisos),
          ["id", "actor_tipo", "actor_id", "permiso", "recurso", "resultado", "canal", "detalle"])


def entregar(pedido_id):
    ns.actualizar_estado(logistica, pedido_id, "despachado")
    ns.actualizar_estado(logistica, pedido_id, "entregado")


# ---------------- Datos de prueba (ficticios) ----------------
pasarela = PasarelaPago(LLAVE_PASARELA)
ns.crear_primer_admin("admin_norti", "Adm!nPanel2026")
admin = ns.login_admin("admin_norti", "Adm!nPanel2026")
for usuario, rol in [("sol_soporte", "soporte"), ("lau_logistica", "logistica"), ("mar_marketing", "marketing"),
                     ("pia_privacidad", "privacidad")]:
    ns.crear_admin(admin, usuario, CLAVE, rol)
soporte, logistica, marketing, privacidad = (
    ns.login_admin(u, CLAVE) for u in ("sol_soporte", "lau_logistica", "mar_marketing", "pia_privacidad"))

id_ana = ns.registrar_cliente("Ana Prueba", "ana@prueba.cl", CLAVE, telefono="+56 9 1111 2222",
                              direccion="Av. Los Leones 1234, Providencia", declara_mayor_edad=True,
                              consentimientos=["boletin", "analitica_comportamiento"])
id_beto = ns.registrar_cliente("Beto Prueba", "beto@prueba.cl", CLAVE, telefono="+56 9 3333 4444",
                               declara_mayor_edad=True)
id_carla = ns.registrar_cliente("Carla Prueba", "carla@prueba.cl", CLAVE, declara_mayor_edad=True,
                                consentimientos=["boletin"])
ana, beto, carla = (ns.login_cliente(f"{n}@prueba.cl", CLAVE) for n in ("ana", "beto", "carla"))
ns.comprar_como_invitado(pasarela, "invitado@prueba.cl", "+56 9 8765 4321", "Av. Falsa 123, Santiago",
                         "5555 4444 3333 2222", "05/27", "456", [{"producto": "Mouse", "cantidad": 1, "precio": 14990}],
                         14990, region="Metropolitana de Santiago")                                     # pedido 1
for sesion, numero, producto, precio, direccion in [
        (ana, "4111 1111 1111 1111", "Audífonos", 39990, None),                                        # pedido 2
        (beto, "5555 5555 5555 4444", "Teclado", 25990, "Calle Beto 99, Ñuñoa"),                       # pedido 3
        (carla, "4012 8888 8888 1881", "Parlante", 19990, "Calle Carla 7, Maipú")]:                    # pedido 4
    ns.guardar_tarjeta(sesion, pasarela, numero, "12/28", "123")
    ns.comprar_con_tarjeta_guardada(sesion, pasarela, [{"producto": producto, "cantidad": 1, "precio": precio}],
                                    precio, direccion=direccion, region="Metropolitana de Santiago")
ns.guardar_comportamiento(id_ana, {"categorias": ["audio"]})
ns.comprar_con_tarjeta_guardada(ana, pasarela, [{"producto": "Cable USB-C", "cantidad": 2, "precio": 4990}], 9980,
                                region="Metropolitana de Santiago")                                     # pedido 5 (pagado)

# =====================================================================
seccion("canal_modelo", "1. CANAL DE SOLICITUDES Y MODELO DE DATOS")
linea("Canales: web (Mi cuenta > Mis derechos, cookie + CSRF) y API (POST /api/v1/derechos, Bearer).")
linea("\nColumnas de solicitudes_derechos:")
tabla(sql("SELECT name AS columna, type AS tipo FROM pragma_table_info('solicitudes_derechos')"), ["columna", "tipo"])
linea("\nTablas de apoyo (Actividad 6):")
for t in ("verificaciones_identidad", "registro_rectificaciones", "oposiciones", "bloqueos", "lista_supresion"):
    linea(f"  {t:26} " + ", ".join(f["name"] for f in sql(f"SELECT name FROM pragma_table_info('{t}')")))
linea("\nSolicitud concreta por la web: Carla pide acceso a sus datos (seguimiento de cada etapa)")
c1 = derechos.crear_solicitud(carla, "acceso", CLAVE, canal="web")
linea(f"  recibida  : {solicitud(c1)['estado']}  plazo_vence={solicitud(c1)['plazo_vence']}")
derechos.verificar_identidad(carla, c1, codigo("carla@prueba.cl"))
linea(f"  verificada: {solicitud(c1)['estado']}")
derechos.exportar(carla, c1)
tabla([solicitud(c1)], ["codigo", "tipo", "canal", "estado", "fecha_recepcion", "fecha_verificacion", "fecha_cierre", "plazo_vence"])
linea("\nSolicitud concreta por la API: Beto pide portabilidad")
cliente = web.app.test_client()
tok_beto = cliente.post("/api/v1/sesiones", json={"correo": "beto@prueba.cl", "password": CLAVE},
                        base_url="https://localhost").get_json()["token"]
r = cliente.post("/api/v1/derechos", json={"tipo": "portabilidad", "password": CLAVE},
                 headers={"Authorization": f"Bearer {tok_beto}"}, base_url="https://localhost")
c_api = r.get_json()["codigo"]
linea(f"  POST /api/v1/derechos -> {r.status_code} {r.get_json()}")
tabla([solicitud(c_api)], ["codigo", "tipo", "canal", "estado", "fecha_recepcion", "plazo_vence"])
linea("\nBandeja de privacidad (seguimiento sin datos personales: el titular es un seudónimo):")
tabla(derechos.bandeja(privacidad, solo_abiertas=False), ["codigo", "tipo", "canal", "estado", "dias_restantes", "titular"])

# =====================================================================
seccion("verificacion", "2. VERIFICACIÓN DE IDENTIDAD (INCLUYE SOLICITANTES NO VERIFICADOS)")
linea("Factor 1: contraseña reingresada al solicitar. Factor 2: código de 6 dígitos al correo registrado")
linea("(solo se guarda su HMAC; vence en 10 min; 3 intentos; 3 envíos). Cambiar el correo exige un código al nuevo.\n")
linea("Caso A - alguien con la sesión abierta de Ana pero sin su contraseña pide la supresión:")
intentar("crear_solicitud(supresion, password incorrecta)", derechos.crear_solicitud, ana, "supresion", "ClaveAdivinada1")
linea(f"  solicitudes de supresión registradas: {sql('SELECT COUNT(*) AS n FROM solicitudes_derechos WHERE tipo=?', ('supresion',))[0]['n']}")
linea("\nCaso B - atacante con la contraseña robada de Ana, sin acceso a su correo, quiere cambiar el correo:")
cB = derechos.crear_solicitud(ana, "rectificacion", CLAVE, {"correo": "atacante@malo.cl"})
for intento in ("000000", "123456", "999999"):
    intentar(f"verificar_identidad(código {intento})", derechos.verificar_identidad, ana, cB, intento)
tabla([solicitud(cB)], ["codigo", "tipo", "estado", "fecha_verificacion", "resultado"])
linea(f"  correo de Ana sigue siendo: {ns.obtener_datos_cliente(ana, id_ana)['correo']}")
linea(f"  mensajes enviados a atacante@malo.cl: {len(notificador.mensajes_para('atacante@malo.cl'))}")
linea("\nCaso C - Beto obtiene el código de una solicitud de Ana e intenta usarlo:")
cC = derechos.crear_solicitud(ana, "acceso", CLAVE)
otp = codigo("ana@prueba.cl")
intentar("Beto verifica la solicitud de Ana", derechos.verificar_identidad, beto, cC, otp)
intentar("Beto descarga la exportación de Ana", derechos.exportar, beto, cC)
linea(f"  estado de la solicitud de Ana: {solicitud(cC)['estado']}")
linea("\nCaso D - personal y peticiones sin sesión:")
intentar("soporte crea una solicitud de acceso", derechos.crear_solicitud, soporte, "acceso", CLAVE)
r = cliente.post("/api/v1/derechos", json={"tipo": "acceso", "password": CLAVE}, base_url="https://localhost")
linea(f"  POST /api/v1/derechos sin token -> {r.status_code} {r.get_json()}")
linea("\nCaso E - la verdadera Ana verifica con el código de su correo:")
intentar("Ana verifica su solicitud de acceso", derechos.verificar_identidad, ana, cC, otp)
linea("\nBitácora de los intentos (sin valores):")
auditoria(["derechos.solicitar", "derechos.verificar_identidad", "derechos.exportar"])

# =====================================================================
seccion("acceso_portabilidad", "3. ACCESO Y PORTABILIDAD")
datos = derechos.exportar(ana, cC)
with open(os.path.join(CARPETA, "ev_act6_acceso_ana.json"), "w") as f:
    json.dump(datos, f, ensure_ascii=False, indent=2)
texto = json.dumps(datos, ensure_ascii=False)
linea("Solicitud de acceso de Ana -> evidencia/ev_act6_acceso_ana.json")
linea(f"  secciones: {', '.join(datos)}")
linea(f"  pedidos exportados: {[p['codigo'] for p in datos['pedidos']]}")
linea(f"  pedidos de Ana en la base: {[f['codigo'] for f in sql('SELECT codigo FROM pedidos WHERE cliente_id=?', (id_ana,))]}")
linea(f"  consentimientos exportados / en la base: {len(datos['consentimientos'])} / "
      f"{sql('SELECT COUNT(*) AS n FROM consentimientos WHERE titular_ref=?', (str(id_ana),))[0]['n']}")
linea("\nSolo los datos de Ana (búsqueda de datos ajenos o internos en el archivo):")
for etiqueta, valor in [("correo de Beto", "beto@prueba.cl"), ("dirección de Beto", "Calle Beto"),
                        ("datos de Carla", "Carla"), ("invitado", "invitado@prueba.cl"),
                        ("hash de contraseña", "$2b$"), ("token de pasarela", "tok_"),
                        ("índice HMAC del correo", sql("SELECT correo_indice FROM clientes WHERE id=?", (id_ana,))[0]["correo_indice"]),
                        ("seudónimo", ns.seudonimo_cliente(id_ana))]:
    linea(f"  {etiqueta:24} presente: {valor in texto}")
linea("\nPortabilidad de Beto (API): solo lo que él aportó, en JSON estructurado")
derechos.verificar_identidad(beto, c_api, codigo("beto@prueba.cl"))
r = cliente.get(f"/api/v1/derechos/{c_api}/exportacion", headers={"Authorization": f"Bearer {tok_beto}"},
                base_url="https://localhost")
port = r.get_json()
with open(os.path.join(CARPETA, "ev_act6_portabilidad_beto.json"), "w") as f:
    json.dump(port, f, ensure_ascii=False, indent=2)
linea(f"  GET /api/v1/derechos/{c_api}/exportacion -> {r.status_code}, guardado en evidencia/ev_act6_portabilidad_beto.json")
linea(f"  secciones: {', '.join(port)}")
linea(f"  campos de la cuenta: {', '.join(port['cuenta'])}  (sin nortipuntos: dato generado por NortiShop)")
intentar("Beto pide de nuevo la misma exportación", derechos.exportar, beto, c_api)

# =====================================================================
seccion("rectificacion", "4. RECTIFICACIÓN CON REGISTRO DEL CAMBIO")
linea("Solicitud concreta: Beto corrige su dirección y teléfono. Tiene el pedido 3 pagado (aún no despachado).")
cR = derechos.crear_solicitud(beto, "rectificacion", CLAVE, {"direccion": "Pasaje Nuevo 55, Ñuñoa", "telefono": "+56 9 7777 8888"})
linea(f"  detalle_cifrado de la solicitud (valores nuevos): {solicitud(cR)['estado']}, "
      f"{sql('SELECT detalle_cifrado FROM solicitudes_derechos WHERE codigo=?', (cR,))[0]['detalle_cifrado'][:40]}...")
intentar("Beto verifica con el código del correo", derechos.verificar_identidad, beto, cR, codigo("beto@prueba.cl"))
tabla([solicitud(cR)], ["codigo", "estado", "fecha_verificacion", "fecha_cierre", "resultado"])
linea("\nregistro_rectificaciones (crudo: valores cifrados):")
tabla([{**f, "valor_anterior_cifrado": (f["valor_anterior_cifrado"] or "NULL")[:22] + "…",
        "valor_nuevo_cifrado": f["valor_nuevo_cifrado"][:22] + "…"}
       for f in sql("SELECT * FROM registro_rectificaciones WHERE solicitud=?", (cR,))],
      ["id", "solicitud", "cliente_id", "campo", "valor_anterior_cifrado", "valor_nuevo_cifrado", "fecha", "comunicado_a"])
linea("\nEl mismo registro descifrado (lo que verá Beto en su próxima solicitud de acceso):")
for f in sql("SELECT * FROM registro_rectificaciones WHERE solicitud=?", (cR,)):
    ant = derechos.descifrar(f["valor_anterior_cifrado"], derechos._ctx_rectificacion(cR, f["campo"], "anterior")) \
        if f["valor_anterior_cifrado"] else None
    nue = derechos.descifrar(f["valor_nuevo_cifrado"], derechos._ctx_rectificacion(cR, f["campo"], "nuevo"))
    linea(f"  {f['campo']:10} {str(ant):30} -> {nue}")
linea("\nPropagación:")
linea(f"  dirección que ve logística para el pedido 3: {ns.direccion_despacho(logistica, 3)}")
linea(f"  aviso al correo del titular: {notificador.ultimo_para('beto@prueba.cl')['asunto']}")
linea("\nEl registro no se puede alterar:")
con = db.conectar()
intentar("UPDATE registro_rectificaciones SET campo='nombre'", con.execute, "UPDATE registro_rectificaciones SET campo='nombre'")
con.close()
linea("\nRectificación del correo (exige un segundo código enviado al correo nuevo):")
cR2 = derechos.crear_solicitud(carla, "rectificacion", CLAVE, {"correo": "carla.nueva@prueba.cl"})
intentar("Carla verifica (código del correo actual)", derechos.verificar_identidad, carla, cR2, codigo("carla@prueba.cl"))
intentar("Carla confirma (código del correo nuevo)", derechos.confirmar_correo_nuevo, carla, cR2, codigo("carla.nueva@prueba.cl"))
tabla(sql("SELECT solicitud, campo, fecha, comunicado_a FROM registro_rectificaciones WHERE solicitud=?", (cR2,)),
      ["solicitud", "campo", "fecha", "comunicado_a"])
linea(f"  avisos: correo anterior='{notificador.ultimo_para('carla@prueba.cl')['asunto']}'")
linea(f"          correo nuevo   ='{notificador.ultimo_para('carla.nueva@prueba.cl')['asunto']}'")
linea("\nRectificación con un campo no permitido:")
intentar("cambios={'nortipuntos': 99999}", derechos.crear_solicitud, beto, "rectificacion", CLAVE, {"nortipuntos": 99999})
linea("\nBitácora:")
auditoria(["derechos.rectificar"])

# =====================================================================
seccion("supresion", "5. SUPRESIÓN: QUÉ SE ELIMINA, QUÉ SE BLOQUEA POR LEY Y CÓMO SE PROPAGA")
linea("Solicitud concreta 1: Ana pide la supresión teniendo el pedido 5 pagado (en curso).")
cS1 = derechos.crear_solicitud(ana, "supresion", CLAVE)
intentar("Ana verifica", derechos.verificar_identidad, ana, cS1, codigo("ana@prueba.cl"))
linea(f"  resultado: {solicitud(cS1)['resultado']}")
linea("\nSe entregan los pedidos 2 y 5. Solicitud concreta 2: Ana vuelve a pedir la supresión.")
entregar(2)
entregar(5)
cS2 = derechos.crear_solicitud(ana, "supresion", CLAVE)
intentar("Ana verifica", derechos.verificar_identidad, ana, cS2, codigo("ana@prueba.cl"))
tokens = [f["token_pasarela"] for f in sql("SELECT token_pasarela FROM tarjetas_guardadas WHERE cliente_id=?", (id_ana,))]
linea("\nAntes de ejecutar:")
for t, cond in [("clientes", "id=?"), ("tarjetas_guardadas", "cliente_id=?"), ("boletin_suscriptores", "cliente_id=?"),
                ("pedidos", "cliente_id=?"), ("registro_rectificaciones", "cliente_id=?")]:
    linea(f"  {t:26} filas de Ana: {sql(f'SELECT COUNT(*) AS n FROM {t} WHERE {cond}', (id_ana,))[0]['n']}")
linea(f"  comportamiento_compra      filas de Ana: "
      f"{sql('SELECT COUNT(*) AS n FROM comportamiento_compra WHERE seudonimo=?', (ns.seudonimo_cliente(id_ana),))[0]['n']}")
linea(f"  tokens en la bóveda de la pasarela: {sum(t in pasarela._boveda for t in tokens)}")
intentar("marketing intenta aprobar la supresión", derechos.resolver_supresion, marketing, cS2, True)
intentar("privacidad aprueba la supresión", derechos.resolver_supresion, privacidad, cS2, True, pasarela=pasarela)
acta = derechos.acta_supresion(privacidad, cS2)
linea("\nActa de la supresión (guardada en solicitudes_derechos.acta, sin datos personales):")
linea(json.dumps(acta, ensure_ascii=False, indent=2))
linea("\nDespués de ejecutar:")
for t, cond in [("clientes", "id=?"), ("tarjetas_guardadas", "cliente_id=?"), ("boletin_suscriptores", "cliente_id=?"),
                ("registro_rectificaciones", "cliente_id=?")]:
    linea(f"  {t:26} filas de Ana: {sql(f'SELECT COUNT(*) AS n FROM {t} WHERE {cond}', (id_ana,))[0]['n']}")
linea(f"  tokens en la bóveda de la pasarela: {sum(t in pasarela._boveda for t in tokens)}")
linea("\nPedidos conservados con bloqueo legal (sin vínculo con Ana ni dirección):")
tabla(sql("SELECT id, cliente_id, direccion_cifrado, monto, estado, bloqueo_legal_hasta FROM pedidos WHERE id IN (2,5)"),
      ["id", "cliente_id", "direccion_cifrado", "monto", "estado", "bloqueo_legal_hasta"])
bloqueados = {f["codigo"] for f in sql("SELECT codigo FROM pedidos WHERE id IN (2,5)")}
linea(f"  aparecen en resumen_pedidos (vista operativa): {any(p['codigo'] in bloqueados for p in ns.resumen_pedidos(soporte))}")
intentar("logística cambia el estado del pedido 2", ns.actualizar_estado, logistica, 2, "entregado")
linea(f"  consentimientos de Ana bajo seudónimo: "
      f"{sql('SELECT COUNT(*) AS n FROM consentimientos WHERE titular_ref=?', (ns.seudonimo_cliente(id_ana),))[0]['n']}")
linea(f"  login de Ana: {ns.login_cliente('ana@prueba.cl', CLAVE)}")
linea(f"\nRespuesta enviada al titular: {notificador.ultimo_para('ana@prueba.cl')['cuerpo']}")
linea("\nRespaldo restaurado con la cuenta de Ana -> se reaplica la lista de supresión:")
ns.registrar_cliente("Ana Prueba", "ana@prueba.cl", CLAVE, declara_mayor_edad=True)      # simula el respaldo
linea(f"  reaplicar_supresiones() -> {ns.reaplicar_supresiones()} cuenta(s) suprimida(s) otra vez")
linea("\nFin del bloqueo legal (se simula que pasaron los 6 años del pedido 2):")
con = db.conectar()
con.execute("UPDATE pedidos SET bloqueo_legal_hasta='2020-01-01 00:00:00' WHERE id=2")
con.commit()
con.close()
ns.aplicar_retencion(admin)
linea(f"  pedidos 2 y 5 tras aplicar_retencion: {[f['id'] for f in sql('SELECT id FROM pedidos WHERE id IN (2,5)')]}")
linea("\nBitácora:")
auditoria(["derechos.suprimir", "cuenta.suprimir"])

# =====================================================================
seccion("oposicion_bloqueo", "6. OPOSICIÓN Y BLOQUEO DEL TRATAMIENTO")
linea("Tratamiento elegido: encuesta de satisfacción por correo tras la entrega (base: interés legítimo, art. 8 a).")
tabla(sql("SELECT codigo, base_legal, requiere_consentimiento FROM finalidades"), ["codigo", "base_legal", "requiere_consentimiento"])
entregar(3)
entregar(4)
linea(f"\nDestinatarios de la encuesta antes: {ns.correos_para_encuesta(marketing)}")
linea("\nOposiciones que no proceden:")
intentar("Beto se opone al boletín (se basa en consentimiento)", derechos.crear_solicitud, beto, "oposicion", CLAVE,
         tratamiento="boletin", motivo="No quiero el boletín, gracias.")
intentar("Beto se opone a 'compra' (contrato)", derechos.crear_solicitud, beto, "oposicion", CLAVE,
         tratamiento="compra", motivo="No quiero que procesen mis pedidos.")
intentar("Beto se opone sin motivo", derechos.crear_solicitud, beto, "oposicion", CLAVE, tratamiento="encuesta_satisfaccion")
linea("\nSolicitud concreta: Beto se opone a la encuesta y pide el bloqueo mientras se evalúa.")
cO = derechos.crear_solicitud(beto, "oposicion", CLAVE, tratamiento="encuesta_satisfaccion",
                              motivo="Recibo demasiados correos y no quiero responder encuestas.")
intentar("Beto verifica la oposición", derechos.verificar_identidad, beto, cO, codigo("beto@prueba.cl"))
linea("\nBloqueos que no proceden:")
intentar("Beto bloquea asociado a una solicitud de acceso", derechos.crear_solicitud, beto, "bloqueo", CLAVE, asociada=c_api)
intentar("Carla bloquea asociado a la oposición de Beto", derechos.crear_solicitud, carla, "bloqueo", CLAVE, asociada=cO)
cB2 = derechos.crear_solicitud(beto, "bloqueo", CLAVE, asociada=cO)
intentar("Beto verifica el bloqueo", derechos.verificar_identidad, beto, cB2, codigo("beto@prueba.cl"))
tabla([solicitud(cO), solicitud(cB2)], ["codigo", "tipo", "tratamiento", "asociada", "estado", "resultado"])
tabla(sql("SELECT * FROM bloqueos"), ["id", "cliente_id", "solicitud", "asociada", "desde", "hasta"])
linea("\nCon el bloqueo vigente (los datos de Beto solo se almacenan):")
linea(f"  destinatarios de la encuesta: {ns.correos_para_encuesta(marketing)}")
intentar("soporte consulta el contacto de Beto", ns.contacto_cliente, soporte, id_beto)
intentar("soporte consulta el contacto de Carla", ns.contacto_cliente, soporte, id_carla)
linea(f"  la cuenta de Beto sigue almacenada: {sql('SELECT COUNT(*) AS n FROM clientes WHERE id=?', (id_beto,))[0]['n'] == 1}")
linea("\nPrivacidad evalúa la oposición:")
linea(f"  detalle_oposicion -> {derechos.detalle_oposicion(privacidad, cO)}")
intentar("marketing intenta resolverla", derechos.resolver_oposicion, marketing, cO, False, "x" * 30)
intentar("privacidad la rechaza sin fundamento", derechos.resolver_oposicion, privacidad, cO, False, "no")
intentar("privacidad acoge la oposición", derechos.resolver_oposicion, privacidad, cO, True)
tabla(sql("SELECT * FROM oposiciones"), ["id", "cliente_id", "tratamiento", "solicitud", "desde"])
tabla(sql("SELECT * FROM bloqueos"), ["id", "cliente_id", "solicitud", "asociada", "desde", "hasta"])
linea("\nDespués: el bloqueo se levantó al cerrarse la oposición, pero la oposición sigue vigente.")
linea(f"  destinatarios de la encuesta: {ns.correos_para_encuesta(marketing)}")
intentar("soporte consulta el contacto de Beto", ns.contacto_cliente, soporte, id_beto)
linea(f"  respuesta enviada a Beto: {notificador.ultimo_para('beto@prueba.cl')['cuerpo']}")
linea("\nBitácora:")
auditoria(["derechos.oponer", "derechos.bloquear", "encuesta.destinatarios"])

_archivo.close()
os.remove(ruta)
print("\nEvidencia guardada en evidencia/ev_act6_*.txt y evidencia/ev_act6_*.json")
