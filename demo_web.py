# demo_web.py
# Recrea nortishop.db con cuentas y pedidos ficticios para usar la aplicación web.
# Uso:
#   python demo_web.py
#   NORTISHOP_MODO_DEMO=1 flask --app app run      (y abrir http://localhost:5000)
# Todas las cuentas usan la contraseña que se imprime al final. Los datos son ficticios.

import os

from config import RUTA_BD, LLAVE_PASARELA
from db import crear_tablas
from pasarela_simulada import PasarelaPago
import nortishop as ns

CLAVE = "Demo#NortiShop26"

if os.path.exists(RUTA_BD):
    os.remove(RUTA_BD)
crear_tablas()
pasarela = PasarelaPago(LLAVE_PASARELA)

ns.crear_primer_admin("admin_norti", CLAVE)
admin = ns.login_admin("admin_norti", CLAVE)
for usuario, rol in [("sol_soporte", "soporte"), ("lau_logistica", "logistica"), ("mar_marketing", "marketing"),
                     ("pia_privacidad", "privacidad"), ("seba_seguridad", "seguridad")]:
    ns.crear_admin(admin, usuario, CLAVE, rol)
logistica = ns.login_admin("lau_logistica", CLAVE)

cid = ns.registrar_cliente("Camila Rojas", "camila.rojas@correo.cl", CLAVE, telefono="+56 9 1234 5678",
                           direccion="Av. Los Leones 1234, Providencia", declara_mayor_edad=True,
                           consentimientos=["boletin"], canal="web")
camila = ns.login_cliente("camila.rojas@correo.cl", CLAVE)
ns.guardar_tarjeta(camila, pasarela, "4111 1111 1111 1111", "12/28", "123")
ns.comprar_con_tarjeta_guardada(camila, pasarela, [{"producto": "Audífonos Bluetooth", "cantidad": 1, "precio": 39990}],
                                39990, region="Metropolitana de Santiago")
ns.actualizar_estado(logistica, 1, "entregado")
ns.registrar_cliente("Pedro Soto", "pedro.soto@correo.cl", CLAVE, declara_mayor_edad=True, canal="web")
ns.comprar_como_invitado(pasarela, "invitado.perez@mail.com", "+56 9 8765 4321", "Calle Prat 456, Valparaíso",
                         "5555 4444 3333 2222", "05/27", "456",
                         [{"producto": "Mouse inalámbrico", "cantidad": 1, "precio": 14990}], 14990, region="Valparaíso")

print("Base de demostración creada en", RUTA_BD)
print("Clientes: camila.rojas@correo.cl, pedro.soto@correo.cl  (http://localhost:5000/login)")
print("Personal: admin_norti, sol_soporte, lau_logistica, mar_marketing, pia_privacidad, seba_seguridad"
      "  (http://localhost:5000/personal/login)")
print("Contraseña de todas las cuentas de demostración:", CLAVE)
