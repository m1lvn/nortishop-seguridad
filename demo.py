# demo.py
# Prueba de funcionamiento: carga datos de ejemplo (ficticios) y muestra
# cómo se validan, recuperan y restringen los datos protegidos (RBAC).

import os
import base64
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from config import RUTA_BD, LLAVE_PASARELA
from db import crear_tablas, conectar
from pasarela_simulada import PasarelaPago
from cripto import cifrar, descifrar, enmascarar
from rbac import AccesoDenegado
import nortishop as ns


def titulo(t):
    print("\n" + "=" * 70)
    print(t)
    print("=" * 70)


def r(x):
    return "ACEPTADO" if x else "RECHAZADO"


def intentar(etiqueta, f, *args):
    """Ejecuta una operación protegida y muestra si se permitió o se denegó."""
    try:
        print(f"  {etiqueta:44}-> PERMITIDO: {f(*args)}")
    except AccesoDenegado as e:
        print(f"  {etiqueta:44}-> DENEGADO: {e}")


if os.path.exists(RUTA_BD):
    os.remove(RUTA_BD)
crear_tablas()
pasarela = PasarelaPago(LLAVE_PASARELA)

# ---------------------------------------------------------------
titulo("1. REGISTRO DE CLIENTE (sin RUT; teléfono y dirección opcionales; todo cifrado)")
cid = ns.registrar_cliente("Camila Rojas", "camila.rojas@correo.cl", "MiClave#2026",
                           telefono="+56 9 1234 5678", direccion="Av. Los Leones 1234, Providencia",
                           consentimiento_analitica=True, declara_mayor_edad=True)
print(f"Cliente registrado con id {cid} (con consentimiento de analítica)")
cid2 = ns.registrar_cliente("Pedro Soto", "pedro.soto@correo.cl", "OtraClave#2026", declara_mayor_edad=True)
print(f"Cliente registrado con id {cid2} (solo datos mínimos: teléfono y dirección = NULL)")
try:
    ns.registrar_cliente("X", "correo-invalido", "MiClave#2026", declara_mayor_edad=True)
except ValueError as e:
    print("Registro con correo inválido ->", e, "(el mensaje no repite el valor)")

# ---------------------------------------------------------------
titulo("2. AUTENTICACIÓN (bcrypt, sesión con rol, bloqueo por intentos)")
camila = ns.login_cliente("camila.rojas@correo.cl", "MiClave#2026")
print("Login cliente con clave correcta   ->", camila)
print("Login cliente con clave incorrecta ->", ns.login_cliente("camila.rojas@correo.cl", "clave_mala_123"))
print("Login con correo en MAYÚSCULAS     ->", r(ns.login_cliente("CAMILA.ROJAS@correo.cl", "MiClave#2026")))
ns.crear_primer_admin("admin_norti", "Adm!nPanel2026")
admin = ns.login_admin("admin_norti", "Adm!nPanel2026")
print("Login administrador                ->", admin)
ns.crear_admin(admin, "sol_soporte", "Soporte#2026", "soporte")
ns.crear_admin(admin, "lau_logistica", "Logistica#2026", "logistica")
ns.crear_admin(admin, "mar_marketing", "Marketing#2026", "marketing")
soporte = ns.login_admin("sol_soporte", "Soporte#2026")
logistica = ns.login_admin("lau_logistica", "Logistica#2026")
marketing = ns.login_admin("mar_marketing", "Marketing#2026")
for _ in range(5):
    ns.login_cliente("pedro.soto@correo.cl", "123456")
print("Pedro: 5 intentos fallidos y luego la clave correcta ->",
      ns.login_cliente("pedro.soto@correo.cl", "OtraClave#2026"), "(cuenta bloqueada 15 min)")

# ---------------------------------------------------------------
titulo("3. TOKENIZACIÓN DE TARJETAS Y PAGO CON RESPUESTA FIRMADA")
token = ns.guardar_tarjeta(camila, pasarela, "4111 1111 1111 1111", "12/28", "123")
print("Tarjeta guardada del cliente -> token:", token)
pago = ns.comprar_con_tarjeta_guardada(camila, pasarela,
                                       [{"producto": "Audífonos Bluetooth", "cantidad": 1, "precio": 39990},
                                        {"producto": "Cable USB-C", "cantidad": 2, "precio": 5990}], 51970,
                                       region="Metropolitana de Santiago")
print(f"Compra con tarjeta guardada -> {pago['codigo']}, pedido {pago['orden']}, monto ${pago['monto']}")
pago_inv = ns.comprar_como_invitado(pasarela, "invitado.perez@mail.com", "+56 9 8765 4321",
                                    "Calle Prat 456, Valparaíso", "5555 4444 3333 2222", "05/27", "456",
                                    [{"producto": "Mouse inalámbrico", "cantidad": 1, "precio": 14990}], 14990,
                                    region="Valparaíso")
print(f"Compra como invitado        -> {pago_inv['codigo']}, pedido {pago_inv['orden']}, monto ${pago_inv['monto']}")

# ---------------------------------------------------------------
titulo("4. RBAC: CADA ROL VE SOLO LO QUE SU FUNCIÓN NECESITA")
print("Cliente (sus propios datos):")
intentar("cliente lee sus datos", ns.obtener_datos_cliente, camila, cid)
intentar("cliente lee datos de OTRO cliente", ns.obtener_datos_cliente, camila, cid2)
print("Logística:")
intentar("logística lee dirección (pedido activo)", ns.direccion_despacho, logistica, 2)
intentar("logística lee contacto del invitado", ns.datos_contacto_invitado, logistica, 2)
print("Soporte:")
intentar("soporte lee contacto del invitado", ns.datos_contacto_invitado, soporte, 2)
intentar("soporte lee dirección de despacho", ns.direccion_despacho, soporte, 2)
intentar("soporte lee contacto de un cliente", ns.contacto_cliente, soporte, cid)
print("Marketing:")
intentar("marketing lee contacto del invitado", ns.datos_contacto_invitado, marketing, 2)
print("Administrador (gestiona cuentas, NO lee datos personales):")
intentar("administrador lee contacto del invitado", ns.datos_contacto_invitado, admin, 2)
intentar("administrador lee dirección de despacho", ns.direccion_despacho, admin, 2)
intentar("administrador ve resumen de pedidos", lambda s: [(p["codigo"], p["monto"], p["estado"]) for p in ns.resumen_pedidos(s)], admin)
print("Soporte intenta crear una cuenta:")
intentar("soporte crea cuenta de personal", ns.crear_admin, soporte, "intruso", "Intruso#2026", "administrador")
ns.actualizar_estado(logistica, 2, "entregado")
print("Pedido 2 entregado:")
intentar("logística lee dirección (pedido entregado)", ns.direccion_despacho, logistica, 2)

# ---------------------------------------------------------------
titulo("5. SEUDONIMIZACIÓN Y ANONIMIZACIÓN")
for c in ["camila.rojas@correo.cl", "juan.soto@gmail.com", "maria.diaz@outlook.com"]:
    ns.suscribir_boletin(c)
print("Boletín (solo marketing descifra, y solo al enviar):", ns.correos_para_envio_boletin(marketing))
print("Comportamiento sin consentimiento (Pedro) guardado:",
      ns.guardar_comportamiento(cid2, {"categorias": ["moda"]}))
print("Comportamiento con consentimiento (Camila) guardado:",
      ns.guardar_comportamiento(cid, {"categorias": ["audio", "accesorios"], "ticket_promedio": 32500}))
for f in ns.leer_analitica(marketing):
    print("  Marketing ve seudónimo:", f["seudonimo"][:24] + "...", "->", f["datos"])
print("Reporte de ventas anonimizado (grupos < 5 pedidos suprimidos):", ns.reporte_ventas(marketing))

# ---------------------------------------------------------------
titulo("6. PRUEBAS DE SEGURIDAD DEL CIFRADO Y DE LA PASARELA")
ctx = "clientes.correo:prueba"
c1 = cifrar("camila.rojas@correo.cl", ctx)
c2 = cifrar("camila.rojas@correo.cl", ctx)
print("Mismo correo cifrado dos veces da resultados distintos:", c1 != c2)
version, b64 = c1.split(":", 1)
datos_mod = bytearray(base64.b64decode(b64))
datos_mod[-1] ^= 0x01
try:
    descifrar(version + ":" + base64.b64encode(bytes(datos_mod)).decode(), ctx)
    print("Dato alterado: se descifró (ESTO NO DEBERÍA PASAR)")
except InvalidTag:
    print("Dato alterado en la BD                  -> InvalidTag: el sistema rechaza el dato modificado")
raw = base64.b64decode(b64)
try:
    AESGCM(os.urandom(32)).decrypt(raw[:12], raw[12:], ctx.encode())
except InvalidTag:
    print("Llave incorrecta                        -> InvalidTag: sin la llave del .env no se recupera nada")

con = conectar()
original = con.execute("SELECT direccion_cifrado FROM pedidos WHERE id=2").fetchone()[0]
con.execute("UPDATE pedidos SET direccion_cifrado = (SELECT direccion_cifrado FROM pedidos WHERE id=1) WHERE id=2")
con.commit()
con.execute("UPDATE pedidos SET estado='despachado' WHERE id=2")
con.commit()
try:
    ns.direccion_despacho(logistica, 2)
    print("Dato movido de fila: se descifró (ESTO NO DEBERÍA PASAR)")
except InvalidTag:
    print("Dirección copiada a otro pedido         -> InvalidTag: el contexto no coincide")
con.execute("UPDATE pedidos SET direccion_cifrado = ?, estado='entregado' WHERE id=2", (original,))
con.commit()
con.close()

rechazo = pasarela.cobrar("tok_inexistente", 9990, "NS-PRUEBA")
falsa = dict(rechazo, aprobado=True, codigo="APROBADO")
print("Pago 'rechazado' cambiado a 'aprobado'  ->", r(ns.verificar_respuesta_pago(falsa, 9990, "NS-PRUEBA")))
real = pasarela.cobrar(token, 990, "NS-BARATO")
print("Pago de $990 reutilizado en otro pedido ->", r(ns.verificar_respuesta_pago(real, 51970, "NS-CARO")))
print("Pago auténtico para su propio pedido    ->", r(ns.verificar_respuesta_pago(real, 990, "NS-BARATO")))

# ---------------------------------------------------------------
titulo("7. RETENCIÓN Y DERECHO DE SUPRESIÓN")
con = conectar()
con.execute("UPDATE pedidos SET fecha='2024-01-15 10:00:00' WHERE id=2")   # simula un pedido de hace casi 3 años
con.commit()
con.close()
print("Pedidos a los que la retención borró dirección y contacto:", ns.aplicar_retencion(admin, 365))
ns.eliminar_cuenta(camila, cid)
print("Cuenta de Camila eliminada: sus pedidos quedan sin cliente ni dirección")
print("\nTarjeta mostrada en pantalla enmascarada:", enmascarar("4111111111111111"))
print("\nDemo terminada.")
