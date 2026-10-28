# rbac.py
# Control de acceso basado en roles (RBAC) y filtro de logs.
#   - PERMISOS: matriz rol -> permisos. Lo que no está listado está DENEGADO.
#   - Sesion: quién es la persona (cliente o personal) y su rol.
#   - tiene_permiso: además de la matriz, comprueba contra la base que la cuenta exista, no esté
#     deshabilitada, que el rol sea el que tiene hoy y que el permiso no esté suspendido.
#   - @requiere_permiso: único punto de control; audita cada intento (permitido o denegado).
#   - FiltroDatosPersonales: enmascara correos, RUT y tarjetas antes de escribir un log.

import re
import logging
from dataclasses import dataclass
from functools import wraps

from db import conectar
from auditoria import registrar_evento


class AccesoDenegado(Exception):
    pass


@dataclass(frozen=True)
class Sesion:
    tipo: str          # "cliente" | "personal"
    id: int
    rol: str


PERMISOS = {
    "cliente": {"cuenta.propia.leer", "pedidos.propios.leer", "tarjeta.registrar",
                "compra.tarjeta_guardada", "cuenta.eliminar",
                "consentimiento.gestionar", "derechos.solicitar"},
    "soporte": {"pedidos.resumen.leer", "contacto.cliente.leer", "contacto.invitado.leer"},
    "logistica": {"pedidos.resumen.leer", "despacho.direccion.leer", "pedidos.estado.actualizar"},
    "marketing": {"boletin.enviar", "analitica.leer_seudonimizada", "reportes.leer"},
    "administrador": {"roles.gestionar", "pedidos.resumen.leer", "reportes.leer",
                      "auditoria.leer", "retencion.ejecutar"},
    # Actividad 5
    "privacidad": {"derechos.gestionar", "consentimiento.textos.publicar"},
    "seguridad": {"auditoria.leer", "auditoria.verificar", "auditoria.purgar", "alertas.gestionar",
                  "incidentes.gestionar", "contencion.ejecutar"},
}
# No existe ningún permiso "claves.leer" ni "analitica.reidentificar": ningún rol los tiene.
# Ningún rol puede modificar la bitácora: "auditoria.purgar" solo borra lo que superó el plazo.


def _cuenta_vigente(sesion):
    """La sesión debe corresponder a una cuenta que existe, está habilitada y tiene hoy ese rol."""
    con = conectar()
    if sesion.tipo == "cliente":
        f = con.execute("SELECT deshabilitada FROM clientes WHERE id=?", (sesion.id,)).fetchone()
        ok = f is not None and not f["deshabilitada"]
    else:
        f = con.execute("SELECT rol, deshabilitada FROM administradores WHERE id=?", (sesion.id,)).fetchone()
        ok = f is not None and not f["deshabilitada"] and f["rol"] == sesion.rol
    con.close()
    return ok


def permiso_suspendido(permiso):
    con = conectar()
    f = con.execute("SELECT 1 FROM permisos_suspendidos WHERE permiso=?", (permiso,)).fetchone()
    con.close()
    return f is not None


def tiene_permiso(sesion, permiso):
    """Denegado por defecto: sesión inválida, rol desconocido, permiso no listado o suspendido."""
    if not isinstance(sesion, Sesion):
        return False
    if sesion.tipo not in ("cliente", "personal"):
        return False
    if (sesion.tipo == "cliente") != (sesion.rol == "cliente"):
        return False
    if permiso not in PERMISOS.get(sesion.rol, set()):
        return False
    return _cuenta_vigente(sesion) and not permiso_suspendido(permiso)


def _auditar(sesion, permiso, recurso, resultado):
    """Guarda quién, con qué rol, qué permiso, sobre qué id y con qué resultado. Sin datos personales."""
    registrar_evento(sesion if isinstance(sesion, Sesion) else None, permiso, recurso, resultado)


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
