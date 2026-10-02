# demo.py
# Prueba de funcionamiento: carga datos de ejemplo (ficticios) y muestra
# cómo se valida o recupera cada campo protegido.

import os
import base64
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from config import RUTA_BD, LLAVE_PASARELA
from db import crear_tablas, conectar
from pasarela_simulada import PasarelaPago
from cripto import cifrar, descifrar, enmascarar
import nortishop as ns


def titulo(t):
    print("\n" + "=" * 70)
    print(t)
    print("=" * 70)


def r(x):
    return "ACEPTADO" if x else "RECHAZADO"


if os.path.exists(RUTA_BD):
    os.remove(RUTA_BD)
crear_tablas()
# la pasarela y NortiShop comparten el secreto con el que se firman las respuestas de pago
pasarela = PasarelaPago(LLAVE_PASARELA)

# ---------------------------------------------------------------
titulo("1. REGISTRO DE CLIENTE (correo, RUT, teléfono y dirección cifrados; contraseña hasheada)")
cid = ns.registrar_cliente("Camila Rojas", "camila.rojas@correo.cl", "MiClave#2026",
                           "12.345.678-5", "+56 9 1234 5678", "Av. Los Leones 1234, Providencia")
print(f"Cliente registrado con id {cid}")

# ---------------------------------------------------------------
titulo("2. VALIDACIÓN DE CONTRASEÑAS (hashing bcrypt: se compara, no se recupera)")
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
titulo("4. TOKENIZACIÓN DE TARJETAS Y PAGO CON RESPUESTA FIRMADA")
token = ns.guardar_tarjeta(cid, pasarela, "4111 1111 1111 1111", "12/28", "123")
print("Tarjeta guardada del cliente -> token:", token)
pago = ns.comprar_con_tarjeta_guardada(cid, pasarela,
                                       [{"producto": "Audífonos Bluetooth", "cantidad": 1, "precio": 39990},
                                        {"producto": "Cable USB-C", "cantidad": 2, "precio": 5990}], 51970)
print(f"Compra con tarjeta guardada      -> {pago['codigo']}, pedido {pago['orden']}, monto ${pago['monto']}, "
      f"autorización {pago['autorizacion']}")

pago_inv = ns.comprar_como_invitado(pasarela, "invitado.perez@mail.com", "+56 9 8765 4321",
                                    "Calle Prat 456, Valparaíso", "5555 4444 3333 2222", "05/27", "456",
                                    [{"producto": "Mouse inalámbrico", "cantidad": 1, "precio": 14990}], 14990)
print(f"Compra como invitado             -> {pago_inv['codigo']}, pedido {pago_inv['orden']}, "
      f"monto ${pago_inv['monto']}, autorización {pago_inv['autorizacion']}")
print("Firma de la pasarela verificada antes de registrar cada pedido (HMAC-SHA256)")

# ---------------------------------------------------------------
titulo("5. HISTORIAL, DATOS DEL INVITADO Y DESPACHO (se descifran al consultar)")
for p in ns.historial_compras(cid):
    print(f"  Pedido {p['pedido']} - total ${p['monto']} - pagado con {p['tarjeta']}")
    for item in p["productos"]:
        print(f"     {item['cantidad']} x {item['producto']} (${item['precio']})")
print("  Contacto invitado pedido 2:", ns.datos_contacto_invitado(2))
print("  Dirección de despacho pedido 2:", ns.direccion_despacho(2))

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
ctx = "clientes.correo:prueba"
c1 = cifrar("camila.rojas@correo.cl", ctx)
c2 = cifrar("camila.rojas@correo.cl", ctx)
print("Mismo correo cifrado dos veces da resultados distintos:", c1 != c2)
print("  ", c1[:50], "...")
print("  ", c2[:50], "...")
print("El prefijo 'v1:' indica la versión de la llave usada (permite rotar llaves)")

# a) si alguien modifica el dato cifrado en la BD, GCM lo detecta
version, b64 = c1.split(":", 1)
datos_mod = bytearray(base64.b64decode(b64))
datos_mod[-1] ^= 0x01
try:
    descifrar(version + ":" + base64.b64encode(bytes(datos_mod)).decode(), ctx)
    print("Dato alterado: se descifró (ESTO NO DEBERÍA PASAR)")
except InvalidTag:
    print("Dato alterado en la BD                  -> InvalidTag: el sistema rechaza el dato modificado")

# b) sin la llave correcta no se puede descifrar
raw = base64.b64decode(b64)
try:
    AESGCM(os.urandom(32)).decrypt(raw[:12], raw[12:], ctx.encode())
    print("Llave incorrecta: se descifró (ESTO NO DEBERÍA PASAR)")
except InvalidTag:
    print("Llave incorrecta                        -> InvalidTag: sin la llave del .env no se recupera nada")

# c) un valor cifrado no se puede mover a otra fila (contexto AAD)
con = conectar()
original = con.execute("SELECT direccion_cifrado FROM pedidos WHERE id=2").fetchone()[0]
con.execute("UPDATE pedidos SET direccion_cifrado = (SELECT direccion_cifrado FROM pedidos WHERE id=1) WHERE id=2")
con.commit()
try:
    ns.direccion_despacho(2)
    print("Dato movido de fila: se descifró (ESTO NO DEBERÍA PASAR)")
except InvalidTag:
    print("Dirección copiada a otro pedido         -> InvalidTag: el contexto no coincide, no se despacha a otra dirección")
con.execute("UPDATE pedidos SET direccion_cifrado = ? WHERE id=2", (original,))
con.commit()
con.close()

# d) una respuesta de pago falsificada o reutilizada no se acepta
rechazo = pasarela.cobrar("tok_inexistente", 9990, "NS-PRUEBA")
falsa = dict(rechazo, aprobado=True, codigo="APROBADO")
print("Pago 'rechazado' cambiado a 'aprobado'  ->",
      r(ns.verificar_respuesta_pago(falsa, 9990, "NS-PRUEBA")), "(la firma ya no coincide)")
real = pasarela.cobrar(token, 990, "NS-BARATO")
print("Pago de $990 reutilizado en otro pedido ->",
      r(ns.verificar_respuesta_pago(real, 51970, "NS-CARO")), "(no corresponde al pedido ni al monto)")
print("Pago auténtico para su propio pedido    ->",
      r(ns.verificar_respuesta_pago(real, 990, "NS-BARATO")))

print("\nTarjeta mostrada en pantalla enmascarada:", enmascarar("4111111111111111"))
print("\nDemo terminada.")
