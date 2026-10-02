# demo.py
# Prueba de funcionamiento: carga datos de ejemplo (ficticios) y muestra
# cómo se valida o recupera cada campo protegido.

import os
import base64
from cryptography.exceptions import InvalidTag

from db import crear_tablas
from pasarela_simulada import PasarelaPago
from cripto import cifrar, descifrar, enmascarar
import nortishop as ns


def titulo(t):
    print("\n" + "=" * 70)
    print(t)
    print("=" * 70)


if os.path.exists("nortishop.db"):
    os.remove("nortishop.db")
crear_tablas()
pasarela = PasarelaPago()

# ---------------------------------------------------------------
titulo("1. REGISTRO DE CLIENTE (correo cifrado, contraseña hasheada, RUT y dirección cifrados)")
cid = ns.registrar_cliente("Camila Rojas", "camila.rojas@correo.cl", "MiClave#2026",
                           "12.345.678-5", "Av. Los Leones 1234, Providencia")
print(f"Cliente registrado con id {cid}")

# ---------------------------------------------------------------
titulo("2. VALIDACIÓN DE CONTRASEÑAS (hashing bcrypt: se compara, no se recupera)")
def r(x):
    return "ACEPTADO" if x else "RECHAZADO"


print("Login cliente con clave correcta   ->", r(ns.login_cliente("camila.rojas@correo.cl", "MiClave#2026")))
print("Login cliente con clave incorrecta ->", r(ns.login_cliente("camila.rojas@correo.cl", "clave_mala")))
print("Login con correo en MAYÚSCULAS     ->", r(ns.login_cliente("CAMILA.ROJAS@correo.cl", "MiClave#2026")),
      "(el índice HMAC normaliza el correo)")
ns.crear_admin("admin_norti", "Adm!nPanel2026")
print("Login admin con clave correcta     ->", r(ns.login_admin("admin_norti", "Adm!nPanel2026")))
print("Login admin con clave incorrecta   ->", r(ns.login_admin("admin_norti", "123456")))

# ---------------------------------------------------------------
titulo("3. RECUPERACIÓN DE DATOS CIFRADOS (AES-256-GCM, solo con la llave)")
datos = ns.obtener_datos_cliente(cid)
for k, v in datos.items():
    print(f"  {k:10}: {v}")

# ---------------------------------------------------------------
titulo("4. TOKENIZACIÓN DE TARJETAS (la tarjeta va a la pasarela, NortiShop guarda el token)")
token = ns.guardar_tarjeta(cid, pasarela, "4111 1111 1111 1111", "12/28", "123")
print("Tarjeta guardada del cliente -> token:", token)
pago = ns.comprar_con_tarjeta_guardada(cid, pasarela,
                                       [{"producto": "Audífonos Bluetooth", "cantidad": 1, "precio": 39990},
                                        {"producto": "Cable USB-C", "cantidad": 2, "precio": 5990}], 51970)
print(f"Compra con tarjeta guardada      -> {pago['codigo']}, monto ${pago['monto']}, autorización {pago['autorizacion']}")

pago_inv = ns.comprar_como_invitado(pasarela, "invitado.perez@mail.com", "+56 9 8765 4321",
                                    "Calle Prat 456, Valparaíso", "5555 4444 3333 2222", "05/27", "456",
                                    [{"producto": "Mouse inalámbrico", "cantidad": 1, "precio": 14990}], 14990)
print(f"Compra como invitado             -> {pago_inv['codigo']}, monto ${pago_inv['monto']}, autorización {pago_inv['autorizacion']}")

# ---------------------------------------------------------------
titulo("5. HISTORIAL DE COMPRAS Y DATOS DEL INVITADO (se descifran al consultar)")
for p in ns.historial_compras(cid):
    print(f"  Pedido {p['pedido']} - total ${p['monto']} - pagado con {p['tarjeta']}")
    for item in p["productos"]:
        print(f"     {item['cantidad']} x {item['producto']} (${item['precio']})")
print("  Contacto invitado pedido 2:", ns.datos_contacto_invitado(2))

# ---------------------------------------------------------------
titulo("6. MARKETING: BOLETÍN Y COMPORTAMIENTO DE COMPRA (cifrados)")
for c in ["camila.rojas@correo.cl", "juan.soto@gmail.com", "maria.diaz@outlook.com"]:
    ns.suscribir_boletin(c)
print("Correos descifrados solo al momento de enviar el boletín:")
for c in ns.correos_para_envio_boletin():
    print("   ", c)
ns.guardar_comportamiento(cid, {"categorias_favoritas": ["audio", "accesorios"],
                                "compras_ultimo_anio": 7, "ticket_promedio": 32500})
print("Comportamiento de compra descifrado:")
for k, v in ns.leer_comportamiento(cid).items():
    print(f"    {k}: {v}")

# ---------------------------------------------------------------
titulo("7. PRUEBAS DE SEGURIDAD")
c1 = cifrar("camila.rojas@correo.cl")
c2 = cifrar("camila.rojas@correo.cl")
print("Mismo correo cifrado dos veces da resultados distintos:", c1 != c2)
print("  ", c1[:50], "...")
print("  ", c2[:50], "...")

# a) si alguien modifica el dato cifrado en la BD, GCM lo detecta
datos_mod = bytearray(base64.b64decode(c1))
datos_mod[-1] ^= 0x01
try:
    descifrar(base64.b64encode(bytes(datos_mod)).decode())
    print("Dato alterado: se descifró (ESTO NO DEBERÍA PASAR)")
except InvalidTag:
    print("Dato alterado en la BD  -> InvalidTag: el sistema rechaza el dato modificado")

# b) sin la llave correcta no se puede descifrar
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
raw = base64.b64decode(c1)
try:
    AESGCM(os.urandom(32)).decrypt(raw[:12], raw[12:], None)
    print("Llave incorrecta: se descifró (ESTO NO DEBERÍA PASAR)")
except InvalidTag:
    print("Llave incorrecta        -> InvalidTag: sin la llave del .env no se recupera nada")

print("\nTarjeta mostrada en pantalla enmascarada:", enmascarar("4111111111111111"))
print("\nDemo terminada.")
