# catalogo_eventos.py
# Catálogo de eventos auditados (Actividad 7).
#   - Cada código de operación que se escribe en la bitácora debe estar aquí, con su categoría, qué se
#     guarda como recurso y qué claves admite el detalle. auditoria.registrar_evento rechaza un código
#     que no esté catalogado (error de programación) y descarta un detalle que no cumpla el catálogo.
#   - El detalle tiene la forma "clave=valor clave=valor motivo": valores cortos sin espacios ni '@'
#     (ids, códigos, conteos, nombres de campos). Así la bitácora no puede guardar un correo, un nombre,
#     una dirección ni un texto libre aunque un desarrollador se equivoque.
#   - Los controles de acceso (@requiere_permiso) generan un evento por cada permiso de rbac.PERMISOS,
#     con resultado permitido o denegado; si la operación falla después de autorizada, queda un segundo
#     evento con tras=<id del permitido> y el motivo.

import re
from dataclasses import dataclass, field

CATEGORIAS = ("autenticacion", "creacion", "acceso", "exportacion", "modificacion", "supresion", "tratamiento",
              "consentimiento", "derechos", "administracion", "seguridad")

RE_VALOR = re.compile(r"[A-Za-z0-9_.,:\-]{1,200}")
RE_RECURSO = re.compile(r"[A-Za-z0-9_.,:\-]{1,64}")


@dataclass(frozen=True)
class Evento:
    categoria: str
    descripcion: str
    recurso: str = "—"
    claves: frozenset = field(default_factory=frozenset)
    motivos: frozenset = field(default_factory=frozenset)


def _e(categoria, descripcion, recurso="—", claves=(), motivos=()):
    return Evento(categoria, descripcion, recurso, frozenset(claves), frozenset(motivos))


EVENTOS = {
    # --- autenticación ---
    "auth.login": _e("autenticacion", "Inicio de sesión de un cliente o del personal", "cuenta (cliente:ID / personal:ID); vacío si no existe",
                     motivos=("clave_incorrecta", "bloqueo_activado", "cuenta_bloqueada", "cuenta_deshabilitada",
                              "cuenta_inexistente", "limite_por_ip")),
    "sesion.crear": _e("autenticacion", "Se entrega un token de sesión (web o API)"),
    "sesion.cerrar": _e("autenticacion", "Cierre de sesión"),
    # --- creación de datos personales ---
    "cuenta.registrar": _e("creacion", "Registro de un cliente", "id del cliente", ("consentimientos",)),
    "pedido.crear": _e("creacion", "Compra con cuenta o como invitado (crea dirección y, si es invitado, correo y teléfono)",
                       "id del pedido", ("origen",), ("pago_rechazado",)),
    # --- tratamiento ---
    "analitica.guardar": _e("tratamiento", "Registro del comportamiento de compra bajo seudónimo", "id del cliente",
                            motivos=("sin_consentimiento", "tratamiento_suspendido")),
    "encuesta.destinatarios": _e("acceso", "Marketing obtiene los correos para la encuesta de satisfacción", "—",
                                 ("incluidos", "excluidos")),
    "pedido.estado": _e("modificacion", "Cambio de estado de un pedido", "id del pedido", ("estado",)),
    "retencion.aplicar": _e("supresion", "Retención: se borran dirección y contacto de pedidos antiguos",
                            claves=("pedidos_anonimizados", "pedidos_eliminados")),
    # --- consentimiento ---
    "consentimiento.otorgar": _e("consentimiento", "El titular otorga un consentimiento", "finalidad", ("version",)),
    "consentimiento.revocar": _e("consentimiento", "El titular revoca un consentimiento", "finalidad"),
    "consentimiento.texto.publicar": _e("consentimiento", "Privacidad publica una versión del texto", "finalidad",
                                        ("version", "cambio_material")),
    "consentimiento.suscribir_boletin": _e("consentimiento", "Suscripción al boletín desde el formulario"),
    "consentimiento.baja_boletin": _e("consentimiento", "Baja del boletín desde el enlace del correo", motivos=("token_invalido",)),
    # --- derechos ---
    "derechos.solicitar": _e("derechos", "El titular crea una solicitud", "código de la solicitud",
                             ("tipo", "canal", "campos", "tratamiento", "asociada"), ("reautenticacion_fallida",)),
    "derechos.verificar_identidad": _e("derechos", "Código de verificación ingresado", "código de la solicitud",
                                       ("tipo", "estado"), ("codigo_incorrecto", "intentos_agotados")),
    "derechos.reenviar_codigo": _e("derechos", "Reenvío del código", "código de la solicitud", ("proposito",), ("envios_agotados",)),
    "derechos.confirmar_correo": _e("derechos", "Confirmación del correo nuevo", "código de la solicitud"),
    "derechos.prorrogar": _e("derechos", "Prórroga del plazo (art. 11)", "código de la solicitud"),
    "derechos.oponer": _e("derechos", "Resolución de una oposición", "código de la solicitud", ("tratamiento",),
                          ("acogida", "rechazada_con_fundamento")),
    "derechos.bloquear": _e("derechos", "Bloqueo temporal del tratamiento", "código de la solicitud", ("asociada",)),
    "derechos.exportar": _e("exportacion", "Entrega de la copia (acceso o portabilidad)", "código de la solicitud",
                            ("tipo", "formato", "secciones")),
    "derechos.rectificar": _e("modificacion", "Rectificación ejecutada (solo nombres de campos)", "código de la solicitud",
                              ("cliente", "campos", "pedidos_actualizados")),
    "derechos.suprimir": _e("supresion", "Resolución de una supresión", "código de la solicitud",
                            ("pedidos_bloqueados", "tarjetas"), ("rechazada_con_fundamento",)),
    "cuenta.suprimir": _e("supresion", "Supresión efectiva de la cuenta", "id del cliente",
                          ("tarjetas", "pedidos_bloqueados", "consentimientos", "tokens_pasarela")),
    # --- administración ---
    "roles.crear_cuenta": _e("administracion", "Alta de una cuenta del personal", "personal:ID", ("rol",)),
    "roles.restablecer_clave": _e("administracion", "Cambio forzado de la contraseña de una cuenta del personal",
                                  "personal:ID", ("sesiones",)),
    "auditoria.consultar": _e("administracion", "Consulta filtrada de la bitácora con motivo", "—",
                              ("motivo", "filtros", "filas")),
    "auditoria.purgar": _e("administracion", "Purga de lo que superó el plazo de conservación", "—",
                           ("filas", "hasta_id", "ultimo_hash", "alertas")),
    "auditoria.anclar": _e("administracion", "Copia del último id y hash fuera de la base", "—", ("ultimo_id",)),
    "auditoria.verificar_anclas": _e("seguridad", "Comparación de la bitácora con las anclas externas", "—",
                                     ("anclas", "error_en")),
    # --- seguridad ---
    "alertas.generar": _e("seguridad", "Una regla de detección generó una alerta", "id de la alerta", ("regla", "severidad")),
    "alertas.avisar": _e("seguridad", "Aviso inmediato a la guardia de seguridad (alertas altas y críticas)",
                         "id de la alerta", ("destino",)),
    "alertas.estado": _e("seguridad", "Seguridad analiza o descarta una alerta", "id de la alerta", ("estado",)),
    "incidentes.registrar": _e("seguridad", "Registro de un incidente", "código INC", ("severidad", "alerta")),
    "incidentes.fase": _e("seguridad", "Avance de fase del incidente", "código INC", ("fase",)),
    "incidentes.evaluar": _e("seguridad", "Decisión de notificación", "código INC", ("agencia", "titulares")),
    "incidentes.notificar": _e("seguridad", "Notificación enviada", "código INC"),
    "incidentes.cerrar": _e("seguridad", "Cierre del incidente", "código INC"),
    "incidentes.comprobar_recuperacion": _e("seguridad", "Comprobaciones antes de restablecer", "—", ("listo",)),
    "incidentes.reconstruir": _e("seguridad", "Reconstrucción de lo ocurrido a partir de la bitácora", "código INC",
                                 ("actor", "eventos", "recursos")),
    "incidentes.purgar_evidencia": _e("seguridad", "Eliminación de copias de evidencia vencidas", "—", ("carpetas",)),
    "contencion.revocar_sesiones": _e("seguridad", "Contención: revocar sesiones", "cuenta o 'todas'", ("sesiones",)),
    "contencion.deshabilitar_cuenta": _e("seguridad", "Contención: deshabilitar cuenta", "cuenta", ("incidente", "sesiones")),
    "contencion.habilitar_cuenta": _e("seguridad", "Rehabilitar cuenta", "cuenta", ("incidente",)),
    "contencion.suspender_permiso": _e("seguridad", "Contención: suspender un permiso", "permiso", ("incidente",)),
    "contencion.reactivar_permiso": _e("seguridad", "Reactivar un permiso", "permiso", ("incidente",)),
    "contencion.preservar_evidencia": _e("seguridad", "Copia de la base con SHA-256 y ancla", "código INC", ("sha256",)),
    "contencion.recifrar_datos": _e("seguridad", "Recifrado con la llave nueva", "—", ("valores", "version")),
}

# Claves que agrega @requiere_permiso cuando una operación autorizada termina en error.
CLAVES_CONTROL = frozenset({"tras", "motivo"})
MOTIVOS_FALLA = ("regla_negocio", "validacion", "error")

# Categoría de los eventos de control de acceso según el prefijo del permiso.
_CATEGORIAS_PERMISO = [
    ("consentimiento.", "consentimiento"), ("derechos.", "derechos"), ("cuenta.eliminar", "supresion"),
    ("encuesta.", "acceso"), ("roles.", "administracion"), ("retencion.", "administracion"),
    ("auditoria.", "administracion"), ("alertas.", "seguridad"), ("incidentes.", "seguridad"),
    ("contencion.", "seguridad"),
]


def _evento_de_permiso(permiso):
    from rbac import PERMISOS              # import local: rbac importa auditoria, que importa este módulo
    if not any(permiso in permisos for permisos in PERMISOS.values()):
        return None
    for prefijo, categoria in _CATEGORIAS_PERMISO:
        if permiso.startswith(prefijo):
            break
    else:
        categoria = "acceso" if permiso.endswith(".leer") else "modificacion"
    return Evento(categoria, f"Control de acceso al permiso {permiso}", "id o código del recurso, si aplica",
                  CLAVES_CONTROL, frozenset(MOTIVOS_FALLA))


def buscar(codigo):
    """Evento del catálogo, o None si el código no está catalogado. Si el código es además un permiso
    (p. ej. derechos.solicitar), admite también las claves del control de acceso."""
    explicito, control = EVENTOS.get(codigo), _evento_de_permiso(codigo)
    if explicito and control:
        return Evento(explicito.categoria, explicito.descripcion, explicito.recurso,
                      explicito.claves | control.claves, explicito.motivos | control.motivos)
    return explicito or control


def detalle_valido(evento, detalle):
    """True si cada parte del detalle es una clave permitida con un valor seguro, o un motivo catalogado."""
    if detalle is None:
        return True
    if not isinstance(detalle, str) or len(detalle) > 400:
        return False
    for parte in detalle.split(" "):
        clave, igual, valor = parte.partition("=")
        if igual:
            if clave not in evento.claves or not RE_VALOR.fullmatch(valor):
                return False
        elif parte not in evento.motivos:
            return False
    return True


def recurso_valido(recurso):
    return recurso is None or bool(RE_RECURSO.fullmatch(str(recurso)))


def tabla():
    """Catálogo completo (para el informe y la documentación): código, categoría, recurso, claves y motivos."""
    from rbac import PERMISOS
    filas = [(c, e.categoria, e.descripcion, e.recurso, sorted(e.claves), sorted(e.motivos)) for c, e in EVENTOS.items()]
    for permiso in sorted(set().union(*PERMISOS.values()) - set(EVENTOS)):
        e = _evento_de_permiso(permiso)
        filas.append((permiso, e.categoria, e.descripcion, e.recurso, sorted(e.claves), sorted(e.motivos)))
    return filas
