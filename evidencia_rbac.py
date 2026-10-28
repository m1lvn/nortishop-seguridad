# evidencia_rbac.py
# Muestra, con una base temporal de ejemplo (datos ficticios), las filas crudas protegidas,
# los accesos permitidos y denegados por rol y la bitácora resultante.
# Uso: python evidencia_rbac.py   (no toca nortishop.db)

import os
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

pasarela = PasarelaPago(LLAVE_PASARELA)
ns.crear_primer_admin("admin_norti", "Adm!nPanel2026")
admin = ns.login_admin("admin_norti", "Adm!nPanel2026")
for u, rol in [("sol_soporte", "soporte"), ("lau_logistica", "logistica"), ("mar_marketing", "marketing")]:
    ns.crear_admin(admin, u, "Clave#Segura1", rol)
soporte, logistica, marketing = (ns.login_admin(u, "Clave#Segura1")
                                 for u in ("sol_soporte", "lau_logistica", "mar_marketing"))
ana = ns.registrar_cliente("Ana Prueba", "ana@prueba.cl", "Clave#Segura1", telefono="+56 9 1111 2222",
                           consentimiento_analitica=True, declara_mayor_edad=True)
ns.guardar_comportamiento(ana, {"categorias": ["tecnologia"]})
ns.comprar_como_invitado(pasarela, "invitado@prueba.cl", "+56 9 8765 4321", "Av. Falsa 123, Santiago",
                         "5555 4444 3333 2222", "05/27", "456",
                         [{"producto": "Mouse", "cantidad": 1, "precio": 14990}], 14990,
                         region="Metropolitana de Santiago")


def corto(v, n=34):
    v = str(v)
    return v if len(v) <= n else v[:n] + "..."


con = db.conectar()
f = con.execute("SELECT id, nombre, correo_cifrado, telefono_cifrado, direccion_cifrado, "
                "mayoria_edad_declarada FROM clientes").fetchone()
print("== clientes (fila cruda)")
print({k: (corto(f[k]) if isinstance(f[k], str) else f[k]) for k in f.keys()})
c = con.execute("SELECT seudonimo, datos_cifrado FROM comportamiento_compra").fetchone()
print("== comportamiento_compra (fila cruda)")
print(corto(c["seudonimo"], 24), corto(c["datos_cifrado"], 24))
con.close()


def probar(nombre, f, *args):
    try:
        print(f"== {nombre}: {f(*args)}")
    except AccesoDenegado as e:
        print(f"== {nombre}: AccesoDenegado('{e}')")


probar("logistica -> direccion_despacho", ns.direccion_despacho, logistica, 1)
probar("soporte -> direccion_despacho", ns.direccion_despacho, soporte, 1)
probar("logistica -> datos_contacto_invitado", ns.datos_contacto_invitado, logistica, 1)
probar("administrador -> datos_contacto_invitado", ns.datos_contacto_invitado, admin, 1)
probar("marketing -> datos_contacto_invitado", ns.datos_contacto_invitado, marketing, 1)
for f in ns.leer_analitica(marketing):
    print(f"== marketing -> leer_analitica: {corto(f['seudonimo'], 18)} {f['datos']}")
ns.leer_analitica(marketing)
print("== auditoria:")
for a in ns.leer_auditoria(admin):
    if a["resultado"] in ("permitido", "denegado") and a["permiso"] != "roles.gestionar":   # solo controles RBAC
        print("  ", a["rol"], a["permiso"], a["recurso"], a["resultado"])
os.remove(ruta)
