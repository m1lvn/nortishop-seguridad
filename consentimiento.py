# consentimiento.py
# Gestión del consentimiento por finalidad.
#   - Cada finalidad se consiente por separado: no existe "aceptar todo" ni una finalidad que
#     habilite otra. Los procesos preguntan por su finalidad exacta con vigente().
#   - El historial es solo de agregar (triggers en db.py): otorgar y revocar agregan un evento;
#     el estado vigente es el último evento del titular para esa finalidad.
#   - Cada evento guarda la versión del texto informado. Si se publica una versión con cambio
#     material, los consentimientos de versiones anteriores dejan de valer hasta que se renueven.
#   - Revocar tiene efecto inmediato en los procesos que dependen de la finalidad (_efectos_revocacion).

import hashlib
from datetime import datetime, timezone

from db import conectar
from cripto import indice_busqueda
from rbac import requiere_permiso
from auditoria import registrar_evento

FINALIDADES = [
    # (código, descripción, base legal, requiere consentimiento)
    ("compra", "Procesar, cobrar y despachar los pedidos", "Ejecución del contrato de compraventa", 0),
    ("boletin", "Enviar el boletín con novedades y ofertas por correo", "Consentimiento", 1),
    ("analitica_comportamiento", "Analizar las categorías que compra el cliente (bajo seudónimo)", "Consentimiento", 1),
    ("ofertas_personalizadas", "Mostrar ofertas personalizadas en la cuenta según sus compras", "Consentimiento", 1),
]

TEXTOS_INICIALES = {
    "boletin": "Acepto recibir el boletín de NortiShop en mi correo. Puedo darme de baja en cualquier momento "
               "desde el enlace del correo o desde Mi cuenta > Consentimientos.",
    "analitica_comportamiento": "Acepto que NortiShop analice las categorías de productos que compro, bajo un "
                                "seudónimo y sin vincularlas a mi nombre, para conocer tendencias de compra. "
                                "Puedo revocarlo en cualquier momento y los datos analizados se eliminan.",
    "ofertas_personalizadas": "Acepto que NortiShop me muestre ofertas personalizadas en mi cuenta según las "
                              "categorías que compro. Si no acepto, veré las ofertas generales.",
}

ESTADOS = ("otorgado", "revocado", "sin_registro", "requiere_renovacion")


def _ahora():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def _hash_texto(texto):
    return hashlib.sha256(texto.encode("utf-8")).hexdigest()


def cargar_finalidades(con):
    """Carga las finalidades y la versión 1 de cada texto (solo si no existen)."""
    con.executemany("INSERT OR IGNORE INTO finalidades VALUES (?,?,?,?)", FINALIDADES)
    for finalidad, texto in TEXTOS_INICIALES.items():
        con.execute("INSERT OR IGNORE INTO textos_consentimiento (finalidad, version, texto, texto_hash, "
                    "cambio_material, vigente_desde) VALUES (?,1,?,?,0,?)",
                    (finalidad, texto, _hash_texto(texto), _ahora()))
    con.commit()


def _finalidad_con_consentimiento(con, finalidad):
    f = con.execute("SELECT requiere_consentimiento FROM finalidades WHERE codigo=?", (finalidad,)).fetchone()
    if f is None:
        raise ValueError("Finalidad desconocida")
    if not f["requiere_consentimiento"]:
        raise ValueError("Esta finalidad no se basa en el consentimiento")


def _versiones(con, finalidad):
    """(versión vigente, versión mínima válida). La mínima es la última publicada con cambio material."""
    f = con.execute("SELECT MAX(version) AS vigente, "
                    "COALESCE(MAX(CASE WHEN cambio_material=1 THEN version END), 1) AS minima "
                    "FROM textos_consentimiento WHERE finalidad=?", (finalidad,)).fetchone()
    return f["vigente"], f["minima"]


def texto_vigente(finalidad):
    """Lo que se muestra al titular antes de pedir el consentimiento (público)."""
    con = conectar()
    try:
        _finalidad_con_consentimiento(con, finalidad)
        version, _ = _versiones(con, finalidad)
        f = con.execute("SELECT version, texto, texto_hash FROM textos_consentimiento WHERE finalidad=? AND version=?",
                        (finalidad, version)).fetchone()
    finally:
        con.close()
    return dict(f)


def _ultimo_evento(con, titular_tipo, titular_ref, finalidad):
    return con.execute("SELECT * FROM consentimientos WHERE titular_tipo=? AND titular_ref=? AND finalidad=? "
                       "ORDER BY id DESC LIMIT 1", (titular_tipo, str(titular_ref), finalidad)).fetchone()


def _estado(con, titular_tipo, titular_ref, finalidad):
    ultimo = _ultimo_evento(con, titular_tipo, titular_ref, finalidad)
    if ultimo is None:
        return "sin_registro", None
    if ultimo["accion"] == "revocado":
        return "revocado", ultimo
    _, minima = _versiones(con, finalidad)
    return ("otorgado" if ultimo["version"] >= minima else "requiere_renovacion"), ultimo


def vigente(titular_tipo, titular_ref, finalidad):
    """Única pregunta que hacen los procesos: ¿hay consentimiento válido para ESTA finalidad?"""
    con = conectar()
    estado, _ = _estado(con, titular_tipo, titular_ref, finalidad)
    con.close()
    return estado == "otorgado"


def registrar_evento_consentimiento(con, titular_tipo, titular_ref, finalidad, accion, canal, version=None):
    """Agrega un evento al historial. Usa la conexión del llamador (misma transacción que la operación)."""
    _finalidad_con_consentimiento(con, finalidad)
    vigente_v, _ = _versiones(con, finalidad)
    if version is None:
        version = vigente_v
    if accion == "otorgado" and version != vigente_v:
        raise ValueError("El texto aceptado no corresponde a la versión vigente")
    con.execute("INSERT INTO consentimientos (titular_tipo, titular_ref, finalidad, version, accion, fecha, canal) "
                "VALUES (?,?,?,?,?,?,?)", (titular_tipo, str(titular_ref), finalidad, version, accion, _ahora(), canal))
    return version


def _efectos_revocacion(con, cliente_id, finalidad):
    """Lo que deja de hacerse (y se borra) cuando se revoca cada finalidad."""
    import nortishop                 # import local: nortishop usa este módulo
    if finalidad == "analitica_comportamiento":
        con.execute("DELETE FROM comportamiento_compra WHERE seudonimo=?", (nortishop.seudonimo_cliente(cliente_id),))
    elif finalidad == "boletin":
        con.execute("DELETE FROM boletin_suscriptores WHERE cliente_id=?", (cliente_id,))
    # ofertas_personalizadas no guarda datos propios: nortishop.ofertas() consulta vigente() en cada llamada


def _efectos_otorgamiento(con, cliente_id, finalidad):
    if finalidad == "boletin":
        import nortishop
        nortishop.agregar_suscriptor_cliente(con, cliente_id)


def _es_propio(sesion, cliente_id=None, *_):
    return cliente_id is None or sesion.id == cliente_id


@requiere_permiso("consentimiento.gestionar")
def otorgar(sesion, finalidad, version, canal="web"):
    """El cliente acepta el texto de la versión indicada (la que se le mostró)."""
    con = conectar()
    try:
        _finalidad_con_consentimiento(con, finalidad)
        estado, ultimo = _estado(con, "cliente", sesion.id, finalidad)
        if estado == "otorgado" and ultimo["version"] == version:
            return version                       # ya estaba otorgado sobre ese mismo texto
        version = registrar_evento_consentimiento(con, "cliente", sesion.id, finalidad, "otorgado", canal, version)
        _efectos_otorgamiento(con, sesion.id, finalidad)
        con.commit()
    finally:
        con.close()
    registrar_evento(sesion, "consentimiento.otorgar", finalidad, "exito", f"version={version}")
    return version


@requiere_permiso("consentimiento.gestionar")
def revocar(sesion, finalidad, canal="web"):
    """Registra la revocación con fecha y hora y aplica de inmediato sus efectos."""
    con = conectar()
    try:
        _finalidad_con_consentimiento(con, finalidad)
        estado, ultimo = _estado(con, "cliente", sesion.id, finalidad)
        if estado not in ("otorgado", "requiere_renovacion"):
            raise ValueError("No hay un consentimiento vigente que revocar para esta finalidad")
        registrar_evento_consentimiento(con, "cliente", sesion.id, finalidad, "revocado", canal, version=ultimo["version"])
        _efectos_revocacion(con, sesion.id, finalidad)
        con.commit()
    finally:
        con.close()
    registrar_evento(sesion, "consentimiento.revocar", finalidad, "exito")


@requiere_permiso("consentimiento.gestionar", recurso_en_arg1=True, regla=_es_propio)
def estado_cliente(sesion, cliente_id):
    """Estado actual de cada finalidad que requiere consentimiento."""
    con = conectar()
    resultado = []
    for codigo, descripcion, _, requiere in FINALIDADES:
        if not requiere:
            continue
        estado, ultimo = _estado(con, "cliente", cliente_id, codigo)
        vigente_v, _ = _versiones(con, codigo)
        resultado.append({"finalidad": codigo, "descripcion": descripcion, "estado": estado,
                          "version": ultimo["version"] if ultimo else None,
                          "fecha": ultimo["fecha"] if ultimo else None, "version_vigente": vigente_v})
    con.close()
    return resultado


@requiere_permiso("consentimiento.gestionar", recurso_en_arg1=True, regla=_es_propio)
def historial(sesion, cliente_id):
    """Todos los otorgamientos y revocaciones, en orden."""
    con = conectar()
    filas = con.execute("SELECT finalidad, version, accion, fecha, canal FROM consentimientos "
                        "WHERE titular_tipo='cliente' AND titular_ref=? ORDER BY id", (str(cliente_id),)).fetchall()
    con.close()
    return [dict(f) for f in filas]


@requiere_permiso("consentimiento.textos.publicar")
def publicar_texto(sesion, finalidad, texto, cambio_material):
    """Nueva versión del texto. Con cambio material, los consentimientos anteriores requieren renovación."""
    if not isinstance(texto, str) or not (20 <= len(texto.strip()) <= 2000):
        raise ValueError("El texto debe tener entre 20 y 2000 caracteres")
    con = conectar()
    try:
        _finalidad_con_consentimiento(con, finalidad)
        version = _versiones(con, finalidad)[0] + 1
        con.execute("INSERT INTO textos_consentimiento (finalidad, version, texto, texto_hash, cambio_material, "
                    "vigente_desde) VALUES (?,?,?,?,?,?)",
                    (finalidad, version, texto.strip(), _hash_texto(texto.strip()), 1 if cambio_material else 0, _ahora()))
        con.commit()
    finally:
        con.close()
    registrar_evento(sesion, "consentimiento.texto.publicar", finalidad, "exito",
                     f"version={version} cambio_material={1 if cambio_material else 0}")
    return version


# ---------- Suscriptores del boletín sin cuenta ----------

def token_baja(correo_indice):
    """Token del enlace de baja: solo quien recibió el correo puede darse de baja."""
    return indice_busqueda(f"baja:{correo_indice}")[:32]


def baja_boletin(correo_indice, token, canal="enlace_correo"):
    """Revocación desde el enlace del correo (no requiere sesión, sí el token del enlace)."""
    import hmac
    if not hmac.compare_digest(token_baja(correo_indice), token or ""):
        registrar_evento(None, "consentimiento.baja_boletin", None, "fallido", "token_invalido")
        return False
    con = conectar()
    f = con.execute("SELECT cliente_id FROM boletin_suscriptores WHERE correo_indice=?", (correo_indice,)).fetchone()
    if f is not None:
        if f["cliente_id"] is not None:
            registrar_evento_consentimiento(con, "cliente", f["cliente_id"], "boletin", "revocado", canal)
        else:
            registrar_evento_consentimiento(con, "suscriptor", correo_indice, "boletin", "revocado", canal)
        con.execute("DELETE FROM boletin_suscriptores WHERE correo_indice=?", (correo_indice,))
        con.commit()
    con.close()
    registrar_evento(None, "consentimiento.baja_boletin", None, "exito")
    return True


# ---------- Supresión y conservación ----------

def seudonimizar_titular(con, cliente_id, seudonimo):
    """Al suprimir la cuenta el historial deja de apuntar al cliente (lo permite el trigger)."""
    con.execute("UPDATE consentimientos SET titular_tipo='seudonimo', titular_ref=? "
                "WHERE titular_tipo='cliente' AND titular_ref=?", (seudonimo, str(cliente_id)))


@requiere_permiso("retencion.ejecutar")
def purgar_historial_seudonimizado(sesion, dias=730):
    """Elimina el historial seudonimizado que ya cumplió su plazo de conservación."""
    con = conectar()
    cur = con.execute("DELETE FROM consentimientos WHERE titular_tipo='seudonimo' AND fecha < datetime('now', ?)",
                      (f"-{int(dias)} days",))
    con.commit()
    con.close()
    return cur.rowcount
