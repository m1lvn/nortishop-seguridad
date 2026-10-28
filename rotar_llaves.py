# rotar_llaves.py
# Procedimiento de recuperación: vuelve a cifrar todos los datos con la llave más reciente.
#   1. python generar_llaves.py --rotar     (agrega NORTISHOP_LLAVE_CIFRADO_V<n+1> al .env)
#   2. python rotar_llaves.py               (este script: recifra con la versión nueva)
#   3. si la llave anterior se comprometió, se retira del .env cuando el script informa 0 valores pendientes.
# Se ejecuta en el servidor, con acceso al .env: no está expuesto en la web ni en la API.

from config import VERSION_ACTUAL
from incidentes import recifrar_datos, valores_con_llave_antigua

print(f"Versión de llave actual: {VERSION_ACTUAL}")
print(f"Valores cifrados con una versión anterior: {valores_con_llave_antigua()}")
print(f"Valores recifrados: {recifrar_datos()}")
print(f"Pendientes después de la rotación: {valores_con_llave_antigua()}")
