# generar_llaves.py
# Genera llaves aleatorias de 256 bits y las guarda en .env
# (el .env está en .gitignore, así que nunca se sube al repositorio)
#
#   python generar_llaves.py           crea el .env, o agrega las llaves que falten sin tocar las existentes
#   python generar_llaves.py --rotar   agrega una versión nueva de la llave de cifrado (luego: rotar_llaves.py)

import os
import re
import sys
import base64
import stat

RUTA = ".env"
LLAVES = ["NORTISHOP_LLAVE_CIFRADO_V1", "NORTISHOP_LLAVE_INDICE", "NORTISHOP_LLAVE_PASARELA",
          "NORTISHOP_LLAVE_AUDITORIA"]


def nueva_llave():
    return base64.b64encode(os.urandom(32)).decode()


def nombres_existentes():
    if not os.path.exists(RUTA):
        return []
    with open(RUTA) as f:
        return [linea.split("=", 1)[0].strip() for linea in f if "=" in linea]


def agregar(lineas):
    nuevo = not os.path.exists(RUTA)
    with open(RUTA, "a") as f:
        f.writelines(lineas)
    # permisos 600: solo el dueño del archivo lo puede leer
    os.chmod(RUTA, stat.S_IRUSR | stat.S_IWUSR)
    return nuevo


existentes = nombres_existentes()

if "--rotar" in sys.argv:
    versiones = [int(m.group(1)) for n in existentes if (m := re.fullmatch(r"NORTISHOP_LLAVE_CIFRADO_V(\d+)", n))]
    if not versiones:
        sys.exit("No hay llave de cifrado que rotar. Ejecuta primero generar_llaves.py sin opciones.")
    nombre = f"NORTISHOP_LLAVE_CIFRADO_V{max(versiones) + 1}"
    agregar([f"{nombre}={nueva_llave()}\n"])
    print(f"{nombre} agregada. Ejecuta rotar_llaves.py para volver a cifrar los datos con ella.")
else:
    # nunca se sobrescribe una llave: si se pierde, los datos cifrados con ella no se pueden recuperar
    faltan = [n for n in LLAVES if n not in existentes]
    lineas = [f"{n}={nueva_llave()}\n" for n in faltan]
    if "NORTISHOP_RUTA_BD" not in existentes:
        lineas.append("NORTISHOP_RUTA_BD=nortishop.db\n")
    if not lineas:
        print(".env ya tiene todas las llaves; no se modifica.")
    elif agregar(lineas):
        print(".env creado con llaves nuevas (permisos 600).")
    else:
        print(f".env ya existía: se agregaron {', '.join(faltan) or 'variables faltantes'} (permisos 600).")
