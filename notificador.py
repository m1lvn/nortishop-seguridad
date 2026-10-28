# notificador.py
# Envío de correos SIMULADO. El proyecto no tiene servidor de correo (SMTP): los mensajes quedan
# en un buzón en memoria que representa la bandeja de entrada del titular. La demo web lo muestra
# solo al dueño del correo y solo con NORTISHOP_MODO_DEMO=1. En producción, enviar() usaría un
# proveedor de correo con TLS; el resto del flujo no cambia.

from datetime import datetime, timezone

_BUZON = []


def enviar(destino, asunto, cuerpo):
    _BUZON.append({"destino": destino, "asunto": asunto, "cuerpo": cuerpo,
                   "fecha": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")})


def mensajes_para(destino):
    return [m for m in _BUZON if m["destino"] == destino]


def ultimo_para(destino):
    mensajes = mensajes_para(destino)
    return mensajes[-1] if mensajes else None
