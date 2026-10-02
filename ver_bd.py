# ver_bd.py
# Muestra la base de datos "en crudo", tal como la vería alguien que la roba
# o un administrador de BD sin acceso a las llaves.

import sqlite3
from config import RUTA_BD

con = sqlite3.connect(RUTA_BD)
con.row_factory = sqlite3.Row

TABLAS = ["clientes", "tarjetas_guardadas", "pedidos", "administradores",
          "boletin_suscriptores", "comportamiento_compra"]


def corto(v, n=48):
    v = str(v)
    return v if len(v) <= n else v[:n] + "..."


for t in TABLAS:
    print("\n" + "-" * 70)
    print("TABLA:", t)
    print("-" * 70)
    filas = con.execute(f"SELECT * FROM {t}").fetchall()
    for f in filas:
        for col in f.keys():
            print(f"  {col:27}= {corto(f[col])}")
        print()
con.close()
