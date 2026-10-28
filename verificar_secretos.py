# verificar_secretos.py
# Revisa que las llaves no queden expuestas:
#   1. .env está en .gitignore
#   2. .env tiene permisos 600 (solo lo lee el dueño)
#   3. ninguna llave aparece escrita en el código, las plantillas, el README ni la evidencia
#   4. ninguna llave aparece dentro de la base de datos
#   5. ningún dato personal o financiero quedó en texto plano en la base de datos
#   6. la base tiene permisos 600 y las copias de evidencia de incidentes no se suben al repositorio
#   7. la bitácora de auditoría no contiene correos, contraseñas ni códigos, y su cadena HMAC está íntegra

import os
import re
import stat
import glob
import base64
import sqlite3
from dotenv import dotenv_values

resultados = []


def check(descripcion, ok):
    resultados.append(ok)
    print(f"[{'OK' if ok else 'FALLA'}] {descripcion}")


def leer_bytes(ruta):
    with open(ruta, "rb") as f:
        return f.read()


env = dotenv_values(".env")
llaves = {k: v for k, v in env.items() if "LLAVE" in k}
ruta_bd = env.get("NORTISHOP_RUTA_BD", "nortishop.db")

# 1
with open(".gitignore") as f:
    ignorados = f.read().split()
check(".env está incluido en .gitignore (no se sube al repositorio)", ".env" in ignorados)

# 2
modo = stat.S_IMODE(os.stat(".env").st_mode)
check(f".env tiene permisos {oct(modo)[2:]} (solo el dueño puede leerlo)", modo == 0o600)

# 3
archivos_codigo = (glob.glob("*.py") + glob.glob("templates/*.html") + glob.glob("static/*")
                   + [".env.example", "README.md"] + glob.glob("evidencia/*.txt") + glob.glob("evidencia/*.json"))
for nombre, valor in llaves.items():
    crudo = base64.b64decode(valor)
    encontrado = []
    for a in archivos_codigo:
        contenido = leer_bytes(a)
        if valor.encode() in contenido or crudo in contenido or crudo.hex().encode() in contenido:
            encontrado.append(a)
    check(f"{nombre} no aparece en el código, plantillas, README ni evidencia ({len(archivos_codigo)} archivos revisados)",
          not encontrado)

# 4
bd = leer_bytes(ruta_bd)
for nombre, valor in llaves.items():
    crudo = base64.b64decode(valor)
    check(f"{nombre} no aparece dentro de la base de datos", valor.encode() not in bd and crudo not in bd)

# 5
datos_personales = ["4111111111111111", "5555444433332222", "12.345.678-5", "camila.rojas@correo.cl",
                   "Los Leones", "MiClave#2026", "Adm!nPanel2026", "invitado.perez@mail.com",
                   "8765 4321", "1234 5678", "Calle Prat", "Audífonos", "juan.soto@gmail.com", "ticket_promedio"]
en_claro = [d for d in datos_personales if d.encode() in bd]
check(f"Ningún dato personal o financiero en texto plano en la BD ({len(datos_personales)} valores buscados)",
      not en_claro)
if en_claro:
    print("    encontrados:", en_claro)

# 6
modo_bd = stat.S_IMODE(os.stat(ruta_bd).st_mode)
check(f"La base de datos tiene permisos {oct(modo_bd)[2:]} (solo el dueño puede leerla)", modo_bd == 0o600)
check("Las copias de evidencia de incidentes están en .gitignore", "evidencia_incidentes/" in ignorados)

# 7
con = sqlite3.connect(ruta_bd)
bitacora = "\n".join("|".join(str(c) for c in f) for f in con.execute("SELECT * FROM auditoria"))
con.close()
en_bitacora = [d for d in datos_personales if d in bitacora] + re.findall(r"[\w.+-]+@[\w-]+\.[\w.]+", bitacora)
check("La bitácora de auditoría no contiene correos, contraseñas ni datos personales", not en_bitacora)
from auditoria import verificar_cadena
cadena = verificar_cadena()
check(f"La cadena HMAC de la bitácora está íntegra ({cadena['filas']} registros)", cadena["ok"])

print(f"\nResultado: {sum(resultados)}/{len(resultados)} verificaciones correctas")
