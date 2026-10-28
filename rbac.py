# rbac.py
# Control de acceso basado en roles (RBAC), bitácora de auditoría y filtro de logs.
#   - PERMISOS: matriz rol -> permisos. Lo que no está listado está DENEGADO.
#   - Sesion: quién es la persona (cliente o personal) y su rol.
#   - @requiere_permiso: único punto de control; audita cada intento (permitido o denegado).
#   - FiltroDatosPersonales: enmascara correos, RUT y tarjetas antes de escribir un log.

import re
import logging
from dataclasses import dataclass
from functools import wraps

from db import conectar


class AccesoDenegado(Exception):
    pass


@dataclass(frozen=True)
class Sesion:
    tipo: str          # "cliente" | "personal"
    id: int
    rol: str


PERMISOS = {
    "cliente": {"cuenta.propia.leer", "pedidos.propios.leer", "tarjeta.registrar",
                "compra.tarjeta_guardada", "cuenta.eliminar"},
    "soporte": {"pedidos.resumen.leer", "contacto.cliente.leer", "contacto.invitado.leer"},
    "logistica": {"pedidos.resumen.leer", "despacho.direccion.leer", "pedidos.estado.actualizar"},
    "marketing": {"boletin.enviar", "analitica.leer_seudonimizada", "reportes.leer"},
    "administrador": {"roles.gestionar", "pedidos.resumen.leer", "reportes.leer",
                      "auditoria.leer", "retencion.ejecutar"},
}
# No existe ningún permiso "claves.leer" ni "analitica.reidentificar": ningún rol los tiene.


def tiene_permiso(sesion, permiso):
    """Denegado por defecto: sesión inválida, rol desconocido o permiso no listado."""
    if not isinstance(sesion, Sesion):
        return False
    if sesion.tipo not in ("cliente", "personal"):
        return False
    if (sesion.tipo == "cliente") != (sesion.rol == "cliente"):
        return False
    return permiso in PERMISOS.get(sesion.rol, set())


def _auditar(sesion, permiso, recurso, resultado):
    """Guarda quién, con qué rol, qué permiso, sobre qué id y con qué resultado. Sin datos personales."""
    s = sesion if isinstance(sesion, Sesion) else None
    con = conectar()
    con.execute("INSERT INTO auditoria (actor_tipo, actor_id, rol, permiso, recurso, resultado) VALUES (?,?,?,?,?,?)",
                (s.tipo if s else None, s.id if s else None, s.rol if s else None,
                 permiso, None if recurso is None else str(recurso), resultado))
    con.commit()
    con.close()


def requiere_permiso(permiso, recurso_en_arg1=False, regla=None):
    """
    regla(sesion, *args) es un control por recurso (p. ej. "solo lo propio"). Se evalúa ANTES
    de auditar, para que la bitácora diga "denegado" y no "permitido" cuando la regla falla.
    """
    def decorador(fn):
        @wraps(fn)
        def envoltura(sesion, *args, **kwargs):
            recurso = args[0] if (recurso_en_arg1 and args) else None
            if not tiene_permiso(sesion, permiso) or (regla is not None and not regla(sesion, *args)):
                _auditar(sesion, permiso, recurso, "denegado")
                raise AccesoDenegado("Acceso denegado")
            _auditar(sesion, permiso, recurso, "permitido")
            return fn(sesion, *args, **kwargs)
        return envoltura
    return decorador


# ---------------- Logs sin datos personales ----------------

_RE_CORREO = re.compile(r"([A-Za-z0-9])[A-Za-z0-9._%+-]*@([A-Za-z0-9.-]+\.[A-Za-z]{2,})")
_RE_RUT = re.compile(r"\b\d{1,2}\.?\d{3}\.?\d{3}-[\dkK]\b")
_RE_TARJETA = re.compile(r"\b(?:\d[ -]?){13,19}\b")


def limpiar_texto(texto):
    texto = _RE_RUT.sub("[RUT]", texto)
    texto = _RE_TARJETA.sub("[TARJETA]", texto)
    return _RE_CORREO.sub(lambda m: f"{m.group(1)}***@{m.group(2)}", texto)


class FiltroDatosPersonales(logging.Filter):
    # Última línea de defensa: un dato personal escrito por error no llega al disco.
    def filter(self, record):
        record.msg = limpiar_texto(record.getMessage())
        record.args = ()
        return True


log = logging.getLogger("nortishop")
log.addFilter(FiltroDatosPersonales())
