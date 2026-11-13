# simulacro_act7.py
# Actividad 7: simulacro de incidente sobre una base temporal con datos ficticios.
#
# Escenario: la contraseña de Carla (soporte) se filtró por phishing. El viernes 13/11/2026 a las 03:07
# (hora de Chile) alguien entra con ella desde una red desconocida, recorre los contactos de los clientes
# uno por uno, intenta ver direcciones y la bitácora, y se lleva también contactos de compras de invitados.
#
# El script:
#   1. prepara la tienda y un día normal de trabajo (jueves), con anclas horarias de la bitácora;
#   2. ejecuta el ataque y guarda aparte lo que el atacante hizo de verdad ("verdad de terreno");
#   3. ejecuta la respuesta según el plan (alertas, consulta con motivo, incidente, evidencia, contención);
#   4. reconstruye lo ocurrido SOLO con la bitácora y lo compara con la verdad de terreno;
#   5. comprueba que la bitácora no contiene los datos y que borrar el final se detecta con las anclas.
# Salida: evidencia/ev_act7_simulacro.txt y evidencia/ev_act7_reconstruccion.json
# Uso: python simulacro_act7.py

import os
import json
import shutil
import sqlite3
import tempfile
from datetime import datetime
from zoneinfo import ZoneInfo

import cripto
cripto.BCRYPT_COSTO = 4            # solo el simulacro: bcrypt rápido para crear 28 clientes

import db
import reloj
import auditoria

carpeta_tmp = tempfile.mkdtemp(prefix="simulacro_")
db.RUTA_BD = os.path.join(carpeta_tmp, "nortishop.db")
auditoria.RUTA_ANCLAS = os.path.join(carpeta_tmp, "anclas_auditoria.jsonl")
db.crear_tablas()

from config import LLAVE_PASARELA
from pasarela_simulada import PasarelaPago
from rbac import AccesoDenegado
import nortishop as ns
import deteccion
import incidentes
import trazabilidad

incidentes.DIR_EVIDENCIA = os.path.join(carpeta_tmp, "evidencia_incidentes")
CHILE = ZoneInfo("America/Santiago")
CLAVE = "Clave#Segura1"
CLAVE_CARLA = "Soporte#Norti26"
RED_OFICINA = os.getenv("NORTISHOP_SIMULACRO_RED", "200.27.14.{}")
RED_ATACANTE = "181.43.77.{}"
SALIDA = os.getenv("NORTISHOP_SIMULACRO_SALIDA", "evidencia")
CONSERVAR = os.getenv("NORTISHOP_SIMULACRO_CONSERVAR")      # carpeta donde dejar la base (para ver la web)
os.makedirs(SALIDA, exist_ok=True)
_archivo = open(os.path.join(SALIDA, "ev_act7_simulacro.txt"), "w")


def linea(texto=""):
    print(texto)
    _archivo.write(texto + "\n")


def titulo(texto):
    linea()
    linea("=" * 100)
    linea(texto)
    linea("=" * 100)


def en_chile(dia, hora, minuto=0, segundo=0):
    reloj.fijar(datetime(2026, 11, dia, hora, minuto, segundo, tzinfo=CHILE))


def desde_red(ip):
    """Las peticiones web fijan canal e IP; aquí se simula lo mismo."""
    return auditoria.fijar_contexto("web", ip)


def intentar(fn, *args):
    try:
        return fn(*args), None
    except (AccesoDenegado, ValueError) as e:
        return None, type(e).__name__


def tabla(filas, columnas):
    anchos = [max(len(c), *(len(str(f.get(c, "") if f.get(c) is not None else "—")) for f in filas)) for c in columnas] \
        if filas else [len(c) for c in columnas]
    linea("  " + " | ".join(c.ljust(a) for c, a in zip(columnas, anchos)))
    linea("  " + "-+-".join("-" * a for a in anchos))
    for f in filas:
        linea("  " + " | ".join(str(f.get(c) if f.get(c) is not None else "—").ljust(a) for c, a in zip(columnas, anchos)))


# ------------------------------------------------------------------------------------------------
titulo("1. Preparación: tienda con 28 clientes, 6 compras de invitados y el personal (miércoles 11/11)")
en_chile(11, 9)
pasarela = PasarelaPago(LLAVE_PASARELA)
ns.crear_primer_admin("admin_norti", "Adm!nPanel2026")
admin = ns.login_admin("admin_norti", "Adm!nPanel2026")
ns.crear_admin(admin, "carla_soporte", CLAVE_CARLA, "soporte")
ns.crear_admin(admin, "luis_logistica", CLAVE, "logistica")
ns.crear_admin(admin, "milan_seguridad", CLAVE, "seguridad")
con = db.conectar()
ids_personal = {f["usuario"]: f["id"] for f in con.execute("SELECT id, usuario FROM administradores")}
con.close()
CARLA = f"personal:{ids_personal['carla_soporte']}"

datos_ficticios = []                 # para comprobar al final que nada de esto llegó a la bitácora
for n in range(1, 29):
    nombre, correo = f"Cliente{n:02d} Ficticio", f"cliente{n:02d}@correo-ficticio.cl"
    telefono, direccion = f"+56 9 5555 {n:04d}", f"Calle Simulada {100 + n}, Ñuñoa"
    ns.registrar_cliente(nombre, correo, CLAVE, telefono=telefono, direccion=direccion, declara_mayor_edad=True)
    datos_ficticios += [nombre, correo, telefono, direccion]
pedidos_invitado = []
for n in range(1, 7):
    correo, telefono, direccion = f"invitado{n}@correo-ficticio.cl", f"+56 9 4444 {n:04d}", f"Pasaje Prueba {n}, Maipú"
    ns.comprar_como_invitado(pasarela, correo, telefono, direccion, "4111 1111 1111 1111", "12/28", "123",
                             [{"producto": "Polera", "cantidad": 1, "precio": 9990}], 9990, region="Metropolitana de Santiago")
    datos_ficticios += [correo, telefono, direccion]
con = db.conectar()
pedidos_invitado = [f["id"] for f in con.execute("SELECT id FROM pedidos WHERE es_invitado=1 ORDER BY id")]
con.close()
linea(f"  personal: {ids_personal}")
linea(f"  clientes: 28 (ids 1-28) · pedidos de invitados: {pedidos_invitado}")
auditoria.anclar()

# ------------------------------------------------------------------------------------------------
titulo("2. Jueves 12/11: un día normal (línea base). Todo desde la red de la oficina, en horario de atención")
en_chile(12, 9, 2)
tok = desde_red(RED_OFICINA.format(31))
carla = ns.login_admin("carla_soporte", CLAVE_CARLA)
for cid in (7, 19, 3):                                    # casos de clientes que llamaron
    reloj.avanzar(minutes=40)
    ns.contacto_cliente(carla, cid)
auditoria.restaurar_contexto(tok)
en_chile(12, 10, 15)
tok = desde_red(RED_OFICINA.format(44))
luis = ns.login_admin("luis_logistica", CLAVE)
for pid in pedidos_invitado[:4]:
    reloj.avanzar(minutes=5)
    ns.direccion_despacho(luis, pid)
    ns.actualizar_estado(luis, pid, "despachado")
auditoria.restaurar_contexto(tok)
en_chile(12, 11, 0)
tok = desde_red(RED_OFICINA.format(50))
milan = ns.login_admin("milan_seguridad", CLAVE)
auditoria.restaurar_contexto(tok)
for hora in (12, 15, 18, 21):
    en_chile(12, hora)
    auditoria.anclar()                                    # tarea programada: ancla cada hora (aquí, algunas)
linea("  Carla consultó 3 contactos; Luis despachó 4 pedidos; Milan inició sesión. Anclas: "
      f"{sum(1 for _ in open(auditoria.RUTA_ANCLAS))}")

# ------------------------------------------------------------------------------------------------
titulo("3. Viernes 13/11, 03:07: alguien usa la contraseña de Carla desde otra red")
verdad = {"redes": [], "logins_fallidos": 0, "contactos_cliente": [], "contactos_invitado": [],
          "denegados": [], "inicio": None, "fin": None}
en_chile(13, 3, 7, 12)
tok = desde_red(RED_ATACANTE.format(201))
for clave in ("Soporte#Norti25", "soporte#norti26"):      # prueba variantes antes de acertar
    ns.login_admin("carla_soporte", clave)
    verdad["logins_fallidos"] += 1
    reloj.avanzar(seconds=25)
intruso = ns.login_admin("carla_soporte", CLAVE_CARLA)
verdad["redes"].append(auditoria.truncar_ip(RED_ATACANTE.format(201)))
verdad["inicio"] = reloj.ahora()
for cid in range(1, 27):                                  # recorre los clientes por id
    reloj.avanzar(seconds=18)
    ns.contacto_cliente(intruso, cid)
    verdad["contactos_cliente"].append(cid)
for permiso, fn, arg in (("despacho.direccion.leer", ns.direccion_despacho, pedidos_invitado[0]),
                         ("despacho.direccion.leer", ns.direccion_despacho, pedidos_invitado[1]),
                         ("auditoria.leer", ns.leer_auditoria, None)):
    reloj.avanzar(seconds=30)
    _, error = intentar(fn, intruso, *(() if arg is None else (arg,)))
    verdad["denegados"].append((permiso, arg, error))
reloj.avanzar(seconds=20)
_, error = intentar(ns.contacto_cliente, intruso, 999)     # id que no existe: autorizado, pero falla
verdad["denegados"].append(("contacto.cliente.leer", 999, error))
for pid in pedidos_invitado[2:6]:
    reloj.avanzar(seconds=22)
    ns.datos_contacto_invitado(intruso, pid)
    verdad["contactos_invitado"].append(pid)
verdad["fin"] = reloj.ahora()
auditoria.restaurar_contexto(tok)
en_chile(13, 4, 0)
auditoria.anclar()
linea(f"  El atacante leyó {len(verdad['contactos_cliente'])} contactos de clientes y "
      f"{len(verdad['contactos_invitado'])} de invitados entre {verdad['inicio']} y {verdad['fin']} (UTC).")
linea(f"  Intentos negados: {verdad['denegados']}")
linea("  (Esta es la verdad de terreno: la guarda el simulacro, NO la bitácora. Se usa solo para comparar.)")

titulo("4. Alertas generadas automáticamente por las reglas (sin intervención humana)")
con = db.conectar()
alertas = [dict(f) for f in con.execute("SELECT id, fecha, regla, severidad, descripcion, estado FROM alertas ORDER BY id")]
con.close()
for a in alertas:
    a["hora_chile"] = reloj.hora_local(a["fecha"]).strftime("%d/%m %H:%M")
tabla(alertas, ["id", "hora_chile", "regla", "severidad", "descripcion"])

# ------------------------------------------------------------------------------------------------
titulo("5. Respuesta: la guardia recibe el aviso y aplica el plan")
import notificador
avisos = notificador.mensajes_para(deteccion.GUARDIA_SEGURIDAD)
for m in avisos:
    linea(f"  aviso a la guardia {reloj.hora_local(m['fecha']):%H:%M:%S}: {m['asunto']}")
en_chile(13, 3, 24)
tok = desde_red(RED_OFICINA.format(50))                  # la guardia entra por la VPN de la oficina
milan = ns.login_admin("milan_seguridad", CLAVE)
integridad = deteccion.verificar_integridad(milan)
linea(f"  03:24 verificar_integridad -> cadena ok={integridad['ok']} filas={integridad['filas']} "
      f"anclas={integridad['anclas']['anclas']} anclas_ok={integridad['anclas']['ok']}")
privilegio = next(a for a in alertas if a["regla"] == "cambio_privilegios")
deteccion.cambiar_estado_alerta(milan, privilegio["id"], "descartada")
linea(f"  alerta {privilegio['id']} (cambio_privilegios del miércoles): descartada, fue el alta planificada de seguridad")
_, error = intentar(trazabilidad.consultar, milan, "porque_si", CARLA)
linea(f"  consultar sin un motivo válido                       -> {error}")
secuencial = next(a for a in alertas if a["regla"] == "lectura_secuencial")
deteccion.cambiar_estado_alerta(milan, secuencial["id"], "en_analisis")
eventos = trazabilidad.consultar(milan, f"ALERTA-{secuencial['id']}", CARLA, desde="2026-11-13 00:00:00")
linea(f"  consultar(motivo=ALERTA-{secuencial['id']}, actor={CARLA}, desde=13/11) -> {len(eventos)} eventos")
linea("  Cuatro reglas distintas sobre la misma cuenta: red nueva, fuera de horario, lectura secuencial y masiva.")
linea("  Según el plan, una posible toma de cuenta se contiene primero (es reversible) y se confirma después.")
reloj.avanzar(minutes=3)
codigo = incidentes.registrar_incidente(milan, "credenciales_comprometidas", "alta",
                                        "Acceso con la cuenta de una agente de soporte desde una red desconocida, "
                                        "fuera de horario, con lectura secuencial de contactos de clientes",
                                        secuencial["id"])
linea(f"  {reloj.hora_local(reloj.ahora()):%H:%M} incidente registrado: {codigo} (alerta {secuencial['id']} escalada)")
reloj.avanzar(minutes=1)
manifiesto = incidentes.preservar_evidencia(milan, codigo)
linea(f"  {reloj.hora_local(reloj.ahora()):%H:%M} evidencia preservada: sha256={manifiesto['sha256'][:24]}... "
      f"ancla de la bitácora id={manifiesto['auditoria_ultimo_id']}")
reloj.avanzar(minutes=1)
incidentes.deshabilitar_cuenta(milan, CARLA, codigo)
incidentes.avanzar_fase(milan, codigo, "contencion", "Cuenta de soporte deshabilitada y sus sesiones revocadas")
linea(f"  {reloj.hora_local(reloj.ahora()):%H:%M} contención: {CARLA} deshabilitada y sus sesiones revocadas")
tok_intruso = desde_red(RED_ATACANTE.format(201))
reloj.avanzar(seconds=40)
_, error = intentar(ns.contacto_cliente, intruso, 27)
verdad["denegados"].append(("contacto.cliente.leer", 27, error))
auditoria.restaurar_contexto(tok_intruso)
linea(f"  {reloj.hora_local(reloj.ahora()):%H:%M} la sesión del intruso intenta seguir leyendo contactos -> {error}")
for a in alertas:                                        # las demás alertas del mismo hecho quedan en el incidente
    if a["regla"] != "cambio_privilegios" and a["id"] != secuencial["id"]:
        con = db.conectar()
        con.execute("UPDATE alertas SET estado='incidente', incidente_id=(SELECT id FROM incidentes WHERE codigo=?) "
                    "WHERE id=?", (codigo, a["id"]))
        con.commit()
        con.close()
auditoria.restaurar_contexto(tok)
en_chile(13, 8, 10)
linea("  08:10 se llama a Carla al iniciar su turno: no inició sesión en la noche y recordó un correo que le pidió")
linea("        \"validar\" su cuenta. Se confirma el uso indebido de sus credenciales (phishing).")
tok = desde_red(RED_OFICINA.format(50))

# ------------------------------------------------------------------------------------------------
titulo("6. Reconstrucción SOLO con la bitácora")
reloj.avanzar(minutes=5)
r = trazabilidad.reconstruir(milan, codigo, CARLA, "2026-11-13 00:00:00", "2026-11-13 10:00:00")
linea(f"  bitácora confiable (cadena y anclas): {r['confiable']}")
linea(f"  eventos del actor en la ventana: {r['eventos']}")
linea("  inicios de sesión: " + "; ".join(f"{reloj.hora_local(l['fecha']):%H:%M:%S} {l['resultado']} {l['origen']}"
                                         + (f" ({l['motivo']})" if l['motivo'] else "") for l in r["logins"]))
linea(f"  redes usadas: {r['redes']}  (red habitual de Carla: {auditoria.truncar_ip(RED_OFICINA.format(31))})")
linea(f"  acceso a datos entre {reloj.hora_local(r['inicio_acceso_datos']):%H:%M:%S} y "
      f"{reloj.hora_local(r['fin_acceso_datos']):%H:%M:%S} (hora de Chile)")
for permiso, recursos in r["accesos_efectivos"].items():
    linea(f"  accesos efectivos {permiso}: {len(recursos)} -> {recursos}")
for permiso, recursos in r["denegados"].items():
    linea(f"  denegados {permiso}: {recursos}")
linea(f"  categorías de datos vistas: {r['categorias_datos']}")
linea(f"  titulares distintos afectados: {len(r['titulares'])}")
linea()
linea("  Línea de tiempo (extracto):")
tl = r["linea_de_tiempo"]
medio = [e for e in tl[6:-3] if e["resultado"] in ("denegado", "fallido")
         or any((x["detalle"] or "").startswith(f"tras={e['id']} ") for x in tl)]
extracto = tl[:6] + [{"id": "…"}] + medio + [{"id": "…"}] + tl[-3:]
for e in extracto:
    if e["id"] == "…":
        continue
    e["hora"] = reloj.hora_local(e["fecha"]).strftime("%H:%M:%S")
    e["actor"] = f"{e['actor_tipo']}:{e['actor_id']}" if e["actor_tipo"] else None
tabla(extracto, ["id", "hora", "actor", "permiso", "recurso", "resultado", "origen", "detalle"])

titulo("7. ¿La bitácora permite reconstruir lo ocurrido? Comparación con la verdad de terreno")
leidos_cli = sorted(int(x) for x in r["accesos_efectivos"].get("contacto.cliente.leer", []))
leidos_inv = sorted(int(x) for x in r["accesos_efectivos"].get("contacto.invitado.leer", []))
negados = sorted((p, str(x)) for p, xs in r["denegados"].items() for x in xs)
esperados_negados = sorted((p, str(a) if a is not None else "None") for p, a, _ in verdad["denegados"])
comprobaciones = [
    ("red de origen", r["redes"] == verdad["redes"], r["redes"]),
    ("inicios de sesión fallidos", sum(1 for l in r["logins"] if l["resultado"] == "fallido") == verdad["logins_fallidos"],
     sum(1 for l in r["logins"] if l["resultado"] == "fallido")),
    ("contactos de clientes leídos", leidos_cli == verdad["contactos_cliente"], f"{len(leidos_cli)} ids"),
    ("contactos de invitados leídos", leidos_inv == verdad["contactos_invitado"], leidos_inv),
    ("intentos negados (incluye el id inexistente)", negados == esperados_negados, negados),
    ("inicio del acceso a datos", r["inicio_acceso_datos"] >= verdad["inicio"], r["inicio_acceso_datos"]),
    ("fin del acceso a datos", r["fin_acceso_datos"] <= verdad["fin"], r["fin_acceso_datos"]),
    ("la actividad legítima del jueves no se mezcla", all(e["fecha"] >= "2026-11-13" for e in r["linea_de_tiempo"]), "ventana"),
]
for nombre, ok, valor in comprobaciones:
    linea(f"  [{'OK' if ok else 'NO'}] {nombre:48} {valor}")
todo_ok = all(ok for _, ok, _ in comprobaciones)
linea(f"  Resultado: {'la bitácora reconstruye exactamente lo que hizo el atacante' if todo_ok else 'HAY DIFERENCIAS'}")

# ------------------------------------------------------------------------------------------------
titulo("8. Evaluación y notificación con el alcance reconstruido")
decision = incidentes.registrar_evaluacion(milan, codigo, r["categorias_datos"], len(r["titulares"]), True,
                                           r["inicio_acceso_datos"], r["fin_acceso_datos"])
linea(f"  categorías={r['categorias_datos']} titulares={len(r['titulares'])} datos_legibles=True (la aplicación descifra)")
linea(f"  decisión: {decision}")
tok_admin = desde_red(RED_OFICINA.format(12))
admin = ns.login_admin("admin_norti", "Adm!nPanel2026")
ns.restablecer_clave_personal(admin, ids_personal["carla_soporte"], "Nueva#Clave2026x")
auditoria.restaurar_contexto(tok_admin)
n_sesiones = incidentes.revocar_sesiones(milan, "todas")
incidentes.avanzar_fase(milan, codigo, "erradicacion",
                        "Contraseña de la cuenta de soporte restablecida por el administrador; sesiones de todo el "
                        "personal revocadas por precaución")
_, error = intentar(ns.login_admin, "carla_soporte", CLAVE_CARLA)
linea(f"  erradicación: contraseña restablecida; la contraseña filtrada ya no sirve -> login devuelve "
      f"{ns.login_admin('carla_soporte', CLAVE_CARLA)}")
incidentes.habilitar_cuenta(milan, CARLA, codigo)
incidentes.avanzar_fase(milan, codigo, "recuperacion", "Cuenta rehabilitada con la contraseña nueva")
linea(f"  recuperación: comprobar_recuperacion -> {incidentes.comprobar_recuperacion(milan)}")
incidentes.avanzar_fase(milan, codigo, "notificacion")
linea()
for linea_aviso in incidentes.borrador_notificacion(milan, codigo, "agencia").splitlines():
    linea("  " + linea_aviso)
reloj.avanzar(hours=3)
incidentes.registrar_notificacion(milan, codigo)
incidentes.avanzar_fase(milan, codigo, "lecciones")
incidentes.cerrar_incidente(milan, codigo, "Causa: phishing a una agente de soporte y acceso sin segundo factor. "
                                            "Medidas: segundo factor obligatorio para el personal, restringir el acceso "
                                            "de soporte a la red de la oficina y capacitación sobre phishing.")
linea(f"\n  incidente {codigo} cerrado")

# ------------------------------------------------------------------------------------------------
titulo("9. La bitácora no guarda los datos y no se puede recortar sin que se note")
con = db.conectar()
texto_bitacora = json.dumps([dict(f) for f in con.execute("SELECT * FROM auditoria")], ensure_ascii=False)
total = con.execute("SELECT COUNT(*) FROM auditoria").fetchone()[0]
con.close()
encontrados = [d for d in datos_ficticios if d in texto_bitacora]
linea(f"  {len(datos_ficticios)} datos personales ficticios buscados en {total} eventos -> encontrados: {len(encontrados)}")
linea(f"  ¿contraseña de Carla en la bitácora? {CLAVE_CARLA in texto_bitacora}")
linea(f"  ¿IP completa del atacante? {RED_ATACANTE.format(201) in texto_bitacora} (solo se guarda la red /24)")

# Ataque a la bitácora sobre una COPIA: quien tiene el archivo borra las filas del ataque y las siguientes.
copia = os.path.join(carpeta_tmp, "copia_atacada.db")
shutil.copy(db.RUTA_BD, copia)
os.chmod(copia, 0o600)
c = sqlite3.connect(copia)
primer_evento_ataque = r["linea_de_tiempo"][0]["id"]
c.execute("DROP TRIGGER auditoria_sin_delete")
c.execute("DELETE FROM auditoria WHERE id >= ?", (primer_evento_ataque,))
c.commit()
c.close()
original = db.RUTA_BD
db.RUTA_BD = copia
cadena, anclas = auditoria.verificar_cadena(), auditoria.verificar_anclas()
db.RUTA_BD = original
linea(f"  en una copia se quitan el trigger y todas las filas desde el id {primer_evento_ataque} (el ataque y lo que siguió):")
linea(f"    verificar_cadena  -> ok={cadena['ok']} (lo que queda es una cadena válida: recortar el final no la rompe)")
linea(f"    verificar_anclas  -> ok={anclas['ok']} error_en={anclas['error_en']} (el ancla externa de las 04:00 ya no existe)")

reloj.fijar(None)
json.dump({k: v for k, v in r.items() if k != "linea_de_tiempo"} | {
    "linea_de_tiempo": [{c: e[c] for c in ("id", "fecha", "actor_tipo", "actor_id", "rol", "permiso", "categoria",
                                           "recurso", "resultado", "canal", "origen", "detalle")}
                        for e in r["linea_de_tiempo"]]},
          open(os.path.join(SALIDA, "ev_act7_reconstruccion.json"), "w"), ensure_ascii=False, indent=2)
_archivo.close()
if CONSERVAR:
    os.makedirs(CONSERVAR, exist_ok=True)
    shutil.copy(db.RUTA_BD, os.path.join(CONSERVAR, "nortishop.db"))
    shutil.copy(auditoria.RUTA_ANCLAS, os.path.join(CONSERVAR, "anclas_auditoria.jsonl"))
shutil.rmtree(carpeta_tmp, ignore_errors=True)
if not todo_ok or encontrados or anclas["ok"]:
    raise SystemExit("El simulacro no cumplió alguna comprobación")
