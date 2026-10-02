# verificar_secretos.py
# Revisa que las llaves no queden expuestas:
#   1. .env está en .gitignore
#   2. .env tiene permisos 600 (solo lo lee el dueño)
#   3. ninguna llave aparece escrita en el código, el README ni la evidencia
#   4. ninguna llave aparece dentro de la base de datos
#   5. ningún dato personal o financiero quedó en texto plano en la base de datos

import os
import stat
import glob
import base64
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
    check(".env está incluido en .gitignore (no se sube al repositorio)", ".env" in f.read().split())

# 2
modo = stat.S_IMODE(os.stat(".env").st_mode)
check(f".env tiene permisos {oct(modo)[2:]} (solo el dueño puede leerlo)", modo == 0o600)

# 3
archivos_codigo = glob.glob("*.py") + [".env.example", "README.md"] + glob.glob("evidencia/*.txt")
for nombre, valor in llaves.items():
    crudo = base64.b64decode(valor)
    encontrado = []
    for a in archivos_codigo:
        contenido = leer_bytes(a)
        if valor.encode() in contenido or crudo in contenido or crudo.hex().encode() in contenido:
            encontrado.append(a)
    check(f"{nombre} no aparece en el código, README ni evidencia ({len(archivos_codigo)} archivos revisados)",
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

print(f"\nResultado: {sum(resultados)}/{len(resultados)} verificaciones correctas")
