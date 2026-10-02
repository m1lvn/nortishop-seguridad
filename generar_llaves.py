# generar_llaves.py
# Genera llaves aleatorias de 256 bits y las guarda en .env
# (el .env está en .gitignore, así que nunca se sube al repositorio)

import os
import base64
import stat

RUTA = ".env"

if os.path.exists(RUTA):
    print(".env ya existe, no se sobrescribe (si se pierde la llave no se pueden descifrar los datos).")
else:
    llave_cifrado = base64.b64encode(os.urandom(32)).decode()
    llave_indice = base64.b64encode(os.urandom(32)).decode()
    with open(RUTA, "w") as f:
        f.write(f"NORTISHOP_LLAVE_CIFRADO={llave_cifrado}\n")
        f.write(f"NORTISHOP_LLAVE_INDICE={llave_indice}\n")
        f.write("NORTISHOP_RUTA_BD=nortishop.db\n")
    # permisos 600: solo el dueño del archivo lo puede leer
    os.chmod(RUTA, stat.S_IRUSR | stat.S_IWUSR)
    print(".env creado con llaves nuevas (permisos 600).")
