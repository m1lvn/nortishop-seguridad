# reloj.py
# Hora única para la bitácora, la detección y los incidentes (Actividad 7).
#   - Todas las fechas de la bitácora son UTC con formato "AAAA-MM-DD HH:MM:SS".
#   - Las reglas de detección miden sus ventanas desde la fecha del evento, no desde "ahora": así una
#     ráfaga se evalúa igual aunque se procese con atraso.
#   - fijar() existe solo para el simulacro y las pruebas (reproducir un incidente a las 03:00);
#     no se expone en la web ni en la API.

from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

ZONA_LOCAL = ZoneInfo("America/Santiago")      # horario de la operación de NortiShop
FORMATO = "%Y-%m-%d %H:%M:%S"

_fijo = None


def ahora_dt():
    return _fijo if _fijo is not None else datetime.now(timezone.utc)


def ahora():
    return ahora_dt().strftime(FORMATO)


def fijar(momento):
    """momento: datetime con zona, o None para volver al reloj real."""
    global _fijo
    _fijo = None if momento is None else momento.astimezone(timezone.utc)


def avanzar(**delta):
    """Solo con el reloj fijado: avanza el tiempo simulado (p. ej. avanzar(seconds=40))."""
    global _fijo
    if _fijo is None:
        raise RuntimeError("El reloj no está fijado")
    _fijo = _fijo + timedelta(**delta)


def hora_local(fecha_utc):
    """'2026-11-13 06:12:00' (UTC) -> datetime en hora de Chile."""
    return datetime.strptime(fecha_utc, FORMATO).replace(tzinfo=timezone.utc).astimezone(ZONA_LOCAL)
