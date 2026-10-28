# pruebas_actividad5.py
# Pruebas automatizadas de la Actividad 5: consentimiento (C), ejercicio de derechos (D), auditoría (A),
# detección e incidentes (I) e intentos de eludir los controles por la API, la web o la base (W).
# Usan una base temporal y datos ficticios (la clase Base de pruebas_seguridad.py): no tocan nortishop.db.
#
# Ejecutar:  python -m unittest pruebas_actividad5 -v

import os
import re
import json
import base64
import sqlite3
import hashlib
import tempfile
import unittest

from pruebas_seguridad import Base, CLAVE        # también fija bcrypt en costo 4 para las pruebas
import db
import config
import cripto
import nortishop as ns
import consentimiento as cs
import derechos
import deteccion
import incidentes
import sesiones
import notificador
import auditoria
import app as web
from rbac import Sesion, AccesoDenegado


def codigo_enviado(correo):
    """Lee el último código de 6 dígitos del buzón simulado (equivale a abrir el correo)."""
    return re.search(r"\b(\d{6})\b", notificador.ultimo_para(correo)["cuerpo"]).group(1)


class Base5(Base):
    def setUp(self):
        super().setUp()
        ns.crear_admin(self.admin, "pia_privacidad", CLAVE, "privacidad")
        ns.crear_admin(self.admin, "seba_seguridad", CLAVE, "seguridad")
        self.privacidad = ns.login_admin("pia_privacidad", CLAVE)
        self.seguridad = ns.login_admin("seba_seguridad", CLAVE)
        incidentes.DIR_EVIDENCIA = tempfile.mkdtemp()
        web._intentos_por_ip.clear()

    def solicitud_verificada(self, sesion, correo, tipo, cambios=None):
        codigo = derechos.crear_solicitud(sesion, tipo, CLAVE, cambios)
        estado = derechos.verificar_identidad(sesion, codigo, codigo_enviado(correo))
        return codigo, estado

    def auditoria_completa(self):
        return [dict(f) for f in self.sql("SELECT * FROM auditoria ORDER BY id")]


# =====================================================================
class PruebasConsentimiento(Base5):

    def test_C01_registro_registra_solo_las_finalidades_marcadas(self):
        i = ns.registrar_cliente("Carla", "carla@prueba.cl", CLAVE, declara_mayor_edad=True, consentimientos=["boletin"])
        carla = ns.login_cliente("carla@prueba.cl", CLAVE)
        estado = {e["finalidad"]: e["estado"] for e in cs.estado_cliente(carla, i)}
        self.assertEqual(estado, {"boletin": "otorgado", "analitica_comportamiento": "sin_registro",
                                  "ofertas_personalizadas": "sin_registro"})

    def test_C02_una_finalidad_no_habilita_otra(self):
        # Ana aceptó solo analítica: no recibe boletín ni ofertas personalizadas
        self.assertTrue(cs.vigente("cliente", self.id_ana, "analitica_comportamiento"))
        self.assertFalse(cs.vigente("cliente", self.id_ana, "boletin"))
        self.assertFalse(cs.vigente("cliente", self.id_ana, "ofertas_personalizadas"))
        self.assertFalse(ns.ofertas(self.ana)["personalizadas"])
        self.assertNotIn("ana@prueba.cl", ns.correos_para_envio_boletin(self.marketing))
        cs.otorgar(self.ana, "ofertas_personalizadas", 1)
        self.assertTrue(ns.ofertas(self.ana)["personalizadas"])
        self.assertFalse(cs.vigente("cliente", self.id_ana, "boletin"))

    def test_C03_evento_guarda_fecha_version_y_estado(self):
        cs.otorgar(self.beto, "boletin", 1)
        cs.revocar(self.beto, "boletin")
        h = [e for e in cs.historial(self.beto, self.id_beto) if e["finalidad"] == "boletin"]
        self.assertEqual([e["accion"] for e in h], ["otorgado", "revocado"])
        for e in h:
            self.assertEqual(e["version"], 1)
            self.assertRegex(e["fecha"], r"^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d$")
        self.assertEqual({e["finalidad"]: e["estado"] for e in cs.estado_cliente(self.beto, self.id_beto)}["boletin"],
                         "revocado")

    def test_C04_revocar_analitica_borra_el_comportamiento_y_lo_impide(self):
        ns.guardar_comportamiento(self.id_ana, {"categorias": ["tecnologia"]})
        self.assertEqual(len(ns.leer_analitica(self.marketing)), 1)
        cs.revocar(self.ana, "analitica_comportamiento")
        self.assertEqual(ns.leer_analitica(self.marketing), [])
        self.assertFalse(ns.guardar_comportamiento(self.id_ana, {"categorias": ["tecnologia"]}))

    def test_C05_revocar_boletin_saca_el_correo_de_la_campana(self):
        cs.otorgar(self.beto, "boletin", 1)
        self.assertIn("beto@prueba.cl", ns.correos_para_envio_boletin(self.marketing))
        cs.revocar(self.beto, "boletin")
        self.assertNotIn("beto@prueba.cl", ns.correos_para_envio_boletin(self.marketing))
        self.assertEqual(self.sql("SELECT COUNT(*) FROM boletin_suscriptores WHERE cliente_id=?", (self.id_beto,))[0][0], 0)

    def test_C06_version_del_texto_y_cambio_material(self):
        with self.assertRaises(ValueError):
            cs.otorgar(self.beto, "boletin", 7)                      # versión que no se le mostró
        cs.otorgar(self.beto, "boletin", 1)
        cs.publicar_texto(self.privacidad, "boletin", "Texto nuevo del boletín con una corrección menor.", False)
        self.assertTrue(cs.vigente("cliente", self.id_beto, "boletin"))
        cs.publicar_texto(self.privacidad, "boletin", "Texto nuevo: ahora el boletín incluye ofertas de terceros.", True)
        self.assertFalse(cs.vigente("cliente", self.id_beto, "boletin"))
        estado = {e["finalidad"]: e for e in cs.estado_cliente(self.beto, self.id_beto)}["boletin"]
        self.assertEqual((estado["estado"], estado["version"], estado["version_vigente"]), ("requiere_renovacion", 1, 3))
        self.assertNotIn("beto@prueba.cl", ns.correos_para_envio_boletin(self.marketing))
        cs.otorgar(self.beto, "boletin", 3)
        self.assertTrue(cs.vigente("cliente", self.id_beto, "boletin"))

    def test_C07_finalidad_contractual_no_se_consiente(self):
        for f in ("compra", "finalidad_inventada"):
            with self.assertRaises(ValueError):
                cs.otorgar(self.ana, f, 1)

    def test_C08_historial_no_se_modifica_ni_se_borra(self):
        con = db.conectar()
        with self.assertRaises(sqlite3.DatabaseError):
            con.execute("UPDATE consentimientos SET accion='revocado'")
        with self.assertRaises(sqlite3.DatabaseError):
            con.execute("UPDATE consentimientos SET fecha='2020-01-01 00:00:00'")
        with self.assertRaises(sqlite3.DatabaseError):
            con.execute("DELETE FROM consentimientos")
        con.close()

    def test_C09_cada_cliente_ve_solo_sus_consentimientos(self):
        with self.assertRaises(AccesoDenegado):
            cs.estado_cliente(self.beto, self.id_ana)
        with self.assertRaises(AccesoDenegado):
            cs.historial(self.soporte, self.id_ana)
        with self.assertRaises(AccesoDenegado):
            cs.publicar_texto(self.marketing, "boletin", "Texto que marketing no puede publicar.", True)

    def test_C10_registro_exige_declarar_mayoria_de_edad(self):
        for valor in (False, None, "si"):
            with self.assertRaises(ValueError):
                ns.registrar_cliente("Menor", "menor@prueba.cl", CLAVE, declara_mayor_edad=valor)
        columnas = [c["name"] for c in self.sql("PRAGMA table_info(clientes)")]
        self.assertNotIn("fecha_nacimiento", columnas)
        self.assertNotIn("consentimiento_analitica", columnas)

    def test_C11_baja_del_boletin_con_el_enlace(self):
        token = ns.suscribir_boletin("lector@prueba.cl")
        idx = cripto.indice_busqueda("lector@prueba.cl")
        self.assertFalse(cs.baja_boletin(idx, "token-falso"))
        self.assertIn("lector@prueba.cl", ns.correos_para_envio_boletin(self.marketing))
        self.assertTrue(cs.baja_boletin(idx, token))
        self.assertNotIn("lector@prueba.cl", ns.correos_para_envio_boletin(self.marketing))


# =====================================================================
class PruebasDerechos(Base5):

    def test_D01_recepcion_con_reautenticacion_y_codigo_al_correo(self):
        with self.assertRaises(AccesoDenegado):
            derechos.crear_solicitud(self.ana, "acceso", "clave_incorrecta_1")
        self.assertEqual(self.sql("SELECT COUNT(*) FROM solicitudes_derechos")[0][0], 0)
        codigo = derechos.crear_solicitud(self.ana, "acceso", CLAVE)
        s = self.sql("SELECT * FROM solicitudes_derechos WHERE codigo=?", (codigo,))[0]
        self.assertEqual(s["estado"], "recibida")
        self.assertEqual(self.sql("SELECT CAST(julianday(plazo_vence) - julianday(fecha_recepcion) AS INTEGER) "
                                  "FROM solicitudes_derechos")[0][0], 30)
        otp = codigo_enviado("ana@prueba.cl")
        guardado = self.sql("SELECT codigo_hash FROM verificaciones_identidad")[0][0]
        self.assertNotIn(otp, guardado)                            # se guarda el HMAC, no el código
        self.assertEqual(len(guardado), 64)

    def test_D02_tres_codigos_incorrectos_rechazan_la_solicitud(self):
        codigo = derechos.crear_solicitud(self.ana, "acceso", CLAVE)
        correcto = codigo_enviado("ana@prueba.cl")
        malo = "000000" if correcto != "000000" else "111111"
        for _ in range(derechos.INTENTOS_CODIGO):
            with self.assertRaises(ValueError):
                derechos.verificar_identidad(self.ana, codigo, malo)
        s = self.sql("SELECT estado, resultado FROM solicitudes_derechos WHERE codigo=?", (codigo,))[0]
        self.assertEqual(s["estado"], "cerrada")
        self.assertIn("identidad", s["resultado"])
        with self.assertRaises(ValueError):
            derechos.verificar_identidad(self.ana, codigo, correcto)

    def test_D03_codigo_vencido_no_sirve(self):
        codigo = derechos.crear_solicitud(self.ana, "acceso", CLAVE)
        self.sql("UPDATE verificaciones_identidad SET expira='2020-01-01 00:00:00'")
        with self.assertRaises(ValueError):
            derechos.verificar_identidad(self.ana, codigo, codigo_enviado("ana@prueba.cl"))

    def test_D03b_reenvio_de_codigo_limitado(self):
        codigo = derechos.crear_solicitud(self.ana, "acceso", CLAVE)
        self.sql("UPDATE verificaciones_identidad SET expira='2020-01-01 00:00:00'")
        derechos.reenviar_codigo(self.ana, codigo)                      # el anterior venció: se emite otro
        self.assertEqual(derechos.verificar_identidad(self.ana, codigo, codigo_enviado("ana@prueba.cl")), "en_evaluacion")
        otra = derechos.crear_solicitud(self.ana, "portabilidad", CLAVE)
        with self.assertRaises(AccesoDenegado):
            derechos.reenviar_codigo(self.beto, otra)                   # solicitud ajena
        derechos.reenviar_codigo(self.ana, otra)
        derechos.reenviar_codigo(self.ana, otra)
        with self.assertRaises(ValueError):
            derechos.reenviar_codigo(self.ana, otra)                    # cuarto envío: se cierra
        self.assertEqual(self.sql("SELECT estado FROM solicitudes_derechos WHERE codigo=?", (otra,))[0][0], "cerrada")

    def test_D04_exportacion_estructurada_sin_datos_internos_ni_de_terceros(self):
        self.pedido_de_ana()
        codigo, estado = self.solicitud_verificada(self.ana, "ana@prueba.cl", "portabilidad")
        self.assertEqual(estado, "en_evaluacion")
        datos = derechos.exportar(self.ana, codigo)
        texto = json.dumps(datos, ensure_ascii=False)
        self.assertEqual(datos["formato"], derechos.VERSION_EXPORTACION)
        self.assertEqual(datos["cuenta"]["correo"], "ana@prueba.cl")
        self.assertEqual(len(datos["pedidos"]), 1)
        self.assertEqual(datos["pedidos"][0]["productos"][0]["producto"], "Audífonos")
        tok, auto, idx, seud = self.sql("SELECT p.token_pasarela, p.autorizacion, c.correo_indice, ? FROM pedidos p "
                                        "JOIN clientes c ON c.id=p.cliente_id", (ns.seudonimo_cliente(self.id_ana),))[0]
        for interno in (tok, auto, idx, seud, "password_hash", "$2b$", "intentos_fallidos", "invitado@prueba.cl",
                        "beto@prueba.cl", "Av. Falsa 123"):
            self.assertNotIn(interno, texto)
        self.assertNotIn("informacion_tratamiento", datos)          # portabilidad: solo los datos
        with self.assertRaises(ValueError):
            derechos.exportar(self.ana, codigo)                     # una sola entrega
        codigo, _ = self.solicitud_verificada(self.ana, "ana@prueba.cl", "acceso")
        self.assertIn("informacion_tratamiento", derechos.exportar(self.ana, codigo))

    def test_D05_solicitudes_ajenas_y_roles_sin_permiso(self):
        codigo = derechos.crear_solicitud(self.ana, "acceso", CLAVE)
        otp = codigo_enviado("ana@prueba.cl")
        with self.assertRaises(AccesoDenegado):
            derechos.verificar_identidad(self.beto, codigo, otp)
        derechos.verificar_identidad(self.ana, codigo, otp)
        for s in (self.beto, self.soporte, self.privacidad, self.admin):
            with self.assertRaises(AccesoDenegado):
                derechos.exportar(s, codigo)
        with self.assertRaises(AccesoDenegado):
            derechos.crear_solicitud(self.soporte, "acceso", CLAVE)
        with self.assertRaises(AccesoDenegado):
            derechos.mis_solicitudes(self.beto, self.id_ana)

    def test_D06_rectificacion_solo_campos_permitidos_y_validos(self):
        for cambios in ({"rol": "administrador"}, {"nortipuntos": 99999}, {"nombre": "Ana", "password_hash": "x"},
                        {"telefono": "abc-no-es-telefono"}, {"correo": "no-es-correo"}, {"nombre": ""}, {}):
            with self.assertRaises(ValueError):
                derechos.crear_solicitud(self.ana, "rectificacion", CLAVE, cambios)
        with self.assertRaises(ValueError):
            derechos.crear_solicitud(self.ana, "rectificacion", CLAVE, {"correo": "beto@prueba.cl"})   # de otra cuenta

    def test_D07_rectificacion_actualiza_cuenta_y_pedidos_no_despachados(self):
        self.pedido_de_ana()
        codigo, estado = self.solicitud_verificada(self.ana, "ana@prueba.cl", "rectificacion",
                                                   {"telefono": "+56 9 7777 8888", "direccion": "Calle Nueva 99, Ñuñoa"})
        self.assertEqual(estado, "cerrada")
        datos = ns.obtener_datos_cliente(self.ana, self.id_ana)
        self.assertEqual((datos["telefono"], datos["direccion"]), ("+56 9 7777 8888", "Calle Nueva 99, Ñuñoa"))
        self.assertEqual(ns.direccion_despacho(self.logistica, 2), "Calle Nueva 99, Ñuñoa")
        s = self.sql("SELECT detalle_cifrado, resultado FROM solicitudes_derechos WHERE codigo=?", (codigo,))[0]
        self.assertIsNone(s["detalle_cifrado"])                     # el valor nuevo no queda en la solicitud
        evento = [e for e in self.auditoria_completa() if e["permiso"] == "derechos.rectificar"][0]
        self.assertIn("campos=direccion,telefono", evento["detalle"])
        self.assertNotIn("7777", str(self.auditoria_completa()))

    def test_D08_cambio_de_correo_con_segundo_codigo_y_recifrado(self):
        cs.otorgar(self.ana, "boletin", 1)
        codigo, estado = self.solicitud_verificada(self.ana, "ana@prueba.cl", "rectificacion", {"correo": "ana.nueva@prueba.cl"})
        self.assertEqual(estado, "en_evaluacion")                   # espera el código del correo nuevo
        self.assertIsNotNone(ns.login_cliente("ana@prueba.cl", CLAVE))
        derechos.confirmar_correo_nuevo(self.ana, codigo, codigo_enviado("ana.nueva@prueba.cl"))
        self.assertIsNone(ns.login_cliente("ana@prueba.cl", CLAVE))
        self.assertIsNotNone(ns.login_cliente("ana.nueva@prueba.cl", CLAVE))
        self.assertEqual(ns.obtener_datos_cliente(self.ana, self.id_ana)["telefono"], "+56 9 1111 2222")
        self.assertIn("ana.nueva@prueba.cl", ns.correos_para_envio_boletin(self.marketing))
        self.assertNotIn("ana@prueba.cl", ns.correos_para_envio_boletin(self.marketing))

    def test_D09_supresion_condiciones_y_ejecucion(self):
        self.pedido_de_ana()                                        # pedido 2, pagado
        cs.otorgar(self.ana, "boletin", 1)
        token_web = sesiones.crear(self.ana)
        token_tarjeta = self.sql("SELECT token_pasarela FROM tarjetas_guardadas")[0][0]
        codigo, estado = self.solicitud_verificada(self.ana, "ana@prueba.cl", "supresion")
        self.assertEqual(estado, "cerrada")                         # rechazada: pedido en curso
        self.assertIn("pedidos en curso", self.sql("SELECT resultado FROM solicitudes_derechos WHERE codigo=?", (codigo,))[0][0])
        ns.actualizar_estado(self.logistica, 2, "entregado")
        codigo, estado = self.solicitud_verificada(self.ana, "ana@prueba.cl", "supresion")
        self.assertEqual(estado, "en_evaluacion")                   # espera la evaluación de privacidad
        self.assertEqual(derechos.resolver_supresion(self.privacidad, codigo, True, pasarela=self.pasarela), "cerrada")
        self.assertEqual(self.sql("SELECT COUNT(*) FROM clientes WHERE id=?", (self.id_ana,))[0][0], 0)
        self.assertEqual(self.sql("SELECT COUNT(*) FROM boletin_suscriptores")[0][0], 0)
        self.assertNotIn(token_tarjeta, self.pasarela._boveda)
        self.assertIsNone(sesiones.resolver(token_web))
        self.assertEqual(self.sql("SELECT COUNT(*) FROM consentimientos WHERE titular_tipo='cliente' AND titular_ref=?",
                                  (str(self.id_ana),))[0][0], 0)
        self.assertGreater(self.sql("SELECT COUNT(*) FROM consentimientos WHERE titular_tipo='seudonimo'")[0][0], 0)
        p = self.sql("SELECT cliente_id, direccion_cifrado, monto FROM pedidos WHERE id=2")[0]
        self.assertEqual((p["cliente_id"], p["direccion_cifrado"], p["monto"]), (None, None, 39990))
        self.assertEqual(self.sql("SELECT COUNT(*) FROM lista_supresion")[0][0], 1)
        self.assertIsNone(ns.login_cliente("ana@prueba.cl", CLAVE))

    def test_D10_rechazo_fundamentado_y_una_sola_prorroga(self):
        codigo, _ = self.solicitud_verificada(self.ana, "ana@prueba.cl", "supresion")
        with self.assertRaises(ValueError):
            derechos.resolver_supresion(self.privacidad, codigo, False, "no")
        derechos.prorrogar(self.privacidad, codigo, "Se revisa una obligación de conservación tributaria.")
        with self.assertRaises(ValueError):
            derechos.prorrogar(self.privacidad, codigo, "Segunda prórroga que la norma no permite.")
        self.assertEqual(self.sql("SELECT CAST(julianday(plazo_vence) - julianday(fecha_recepcion) AS INTEGER) "
                                  "FROM solicitudes_derechos WHERE codigo=?", (codigo,))[0][0], 60)
        self.assertEqual(derechos.resolver_supresion(self.privacidad, codigo, False,
                                                     "Existe un reclamo pendiente ante el SERNAC sobre esta cuenta."), "rechazada")
        self.assertEqual(self.sql("SELECT COUNT(*) FROM clientes WHERE id=?", (self.id_ana,))[0][0], 1)
        # art. 11: la respuesta indica el fundamento y el plazo para reclamar ante la Agencia
        resultado = self.sql("SELECT resultado FROM solicitudes_derechos WHERE codigo=?", (codigo,))[0][0]
        self.assertTrue(resultado.startswith("Existe un reclamo pendiente"))
        self.assertIn("30 días hábiles", resultado)
        self.assertIn("30 días hábiles", notificador.ultimo_para("ana@prueba.cl")["cuerpo"])

    def test_D11_bandeja_de_privacidad_sin_datos_personales(self):
        self.solicitud_verificada(self.ana, "ana@prueba.cl", "supresion")
        filas = derechos.bandeja(self.privacidad)
        self.assertEqual(len(filas), 1)
        self.assertNotIn("ana", str(filas).lower())
        self.assertNotIn("cliente_id", filas[0])
        for s in (self.admin, self.soporte, self.seguridad, self.ana):
            with self.assertRaises(AccesoDenegado):
                derechos.bandeja(s)
            with self.assertRaises(AccesoDenegado):
                derechos.resolver_supresion(s, "SD-X", True)

    def test_D12_supresiones_se_reaplican_al_restaurar_un_respaldo(self):
        fila = dict(self.sql("SELECT * FROM clientes WHERE id=?", (self.id_ana,))[0])
        ns.eliminar_cuenta(self.ana, self.id_ana)
        columnas = ", ".join(fila)
        self.sql(f"INSERT INTO clientes ({columnas}) VALUES ({', '.join('?' * len(fila))})", tuple(fila.values()))
        self.assertEqual(ns.reaplicar_supresiones(), 1)              # el respaldo traía a Ana de vuelta
        self.assertEqual(self.sql("SELECT COUNT(*) FROM clientes WHERE id=?", (self.id_ana,))[0][0], 0)


# =====================================================================
class PruebasAuditoria(Base5):

    def test_A01_operaciones_relevantes_quedan_registradas_sin_datos_personales(self):
        self.pedido_de_ana()
        cs.otorgar(self.ana, "boletin", 1)
        cs.revocar(self.ana, "boletin")
        codigo, _ = self.solicitud_verificada(self.ana, "ana@prueba.cl", "acceso")
        otp = re.search(r"\d{6}", notificador.ultimo_para("ana@prueba.cl")["cuerpo"]).group()
        derechos.exportar(self.ana, codigo)
        ns.login_cliente("ana@prueba.cl", "clave_incorrecta_9")
        token = sesiones.crear(self.ana)
        eventos = self.auditoria_completa()
        categorias = {(e["permiso"], e["categoria"]) for e in eventos}
        for esperado in [("consentimiento.otorgar", "consentimiento"), ("consentimiento.revocar", "consentimiento"),
                         ("derechos.solicitar", "derechos"), ("derechos.exportar", "exportacion"),
                         ("auth.login", "autenticacion"), ("roles.crear_cuenta", "administracion"),
                         ("cuenta.registrar", "modificacion")]:
            self.assertIn(esperado, categorias)
        texto = json.dumps(eventos, ensure_ascii=False)
        for prohibido in ["ana@prueba.cl", "prueba.cl", "+56 9", "Av. Los Leones", CLAVE, "clave_incorrecta_9",
                          otp, token, sesiones._hash(token), "$2b$", "Audífonos"]:
            self.assertNotIn(prohibido, texto)
        for clave in (config.LLAVE_AUDITORIA, config.LLAVE_INDICE):
            self.assertNotIn(base64.b64encode(clave).decode(), texto)

    def test_A02_cadena_detecta_alteraciones_aunque_se_quiten_los_triggers(self):
        self.assertTrue(auditoria.verificar_cadena()["ok"])
        con = db.conectar()
        con.execute("DROP TRIGGER auditoria_sin_update")
        con.execute("DROP TRIGGER auditoria_sin_delete")
        con.execute("UPDATE auditoria SET resultado='permitido' WHERE id=3")
        con.commit()
        con.close()
        r = deteccion.verificar_integridad(self.seguridad)
        self.assertEqual((r["ok"], r["error_en"]), (False, 3))
        self.assertIn("integridad_auditoria", {a["regla"] for a in deteccion.listar_alertas(self.seguridad)})

    def test_A03_borrar_una_fila_intermedia_rompe_la_cadena(self):
        con = db.conectar()
        con.execute("DROP TRIGGER auditoria_sin_delete")
        con.execute("DELETE FROM auditoria WHERE id=5")
        con.commit()
        con.close()
        self.assertEqual(auditoria.verificar_cadena()["error_en"], 6)

    def test_A04_ip_truncada_y_canal(self):
        self.assertEqual(auditoria.truncar_ip("200.14.85.37"), "200.14.85.0/24")
        self.assertEqual(auditoria.truncar_ip("2800:150:1:2::5"), "2800:150:1::/48")
        self.assertIsNone(auditoria.truncar_ip("no-es-ip"))
        token = auditoria.fijar_contexto("api", "200.14.85.37")
        try:
            ns.resumen_pedidos(self.soporte)
        finally:
            auditoria.restaurar_contexto(token)
        ultimo = self.auditoria_completa()[-1]
        self.assertEqual((ultimo["canal"], ultimo["origen"]), ("api", "200.14.85.0/24"))

    def test_A05_solo_administrador_y_seguridad_leen_la_bitacora(self):
        self.assertTrue(ns.leer_auditoria(self.seguridad))
        self.assertTrue(ns.leer_auditoria(self.admin))
        for s in (self.privacidad, self.marketing, self.soporte, self.logistica, self.ana):
            with self.assertRaises(AccesoDenegado):
                ns.leer_auditoria(s)
        with self.assertRaises(AccesoDenegado):
            ns.purgar_auditoria(self.admin)                          # el administrador no puede purgar
        self.assertEqual(ns.purgar_auditoria(self.seguridad), 0)     # nada supera el plazo


class PruebaPurgaAuditoria(unittest.TestCase):
    """Base separada: los eventos antiguos tienen que estar al comienzo de la cadena."""

    def test_A06_purga_segura_solo_de_lo_vencido_y_la_cadena_sigue_verificable(self):
        fd, ruta = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        original_ruta, original_ahora = db.RUTA_BD, auditoria._ahora
        db.RUTA_BD = ruta
        try:
            db.crear_tablas()
            auditoria._ahora = lambda: "2023-03-01 10:00:00"
            for _ in range(4):
                auditoria.registrar_evento(None, "sistema.prueba", None, "exito")
            auditoria._ahora = original_ahora
            ns.crear_primer_admin("admin_norti", "Adm!nPanel2026")
            admin = ns.login_admin("admin_norti", "Adm!nPanel2026")
            ns.crear_admin(admin, "seba_seguridad", CLAVE, "seguridad")
            seguridad = ns.login_admin("seba_seguridad", CLAVE)
            self.assertEqual(ns.purgar_auditoria(seguridad), 4)
            self.assertTrue(auditoria.verificar_cadena()["ok"])
            with open(ruta, "rb") as f:                              # secure_delete: no quedan restos en el archivo
                self.assertNotIn(b"sistema.prueba", f.read())
            con = db.conectar()
            with self.assertRaises(sqlite3.DatabaseError):
                con.execute("DELETE FROM auditoria")                 # lo reciente sigue protegido
            con.close()
        finally:
            auditoria._ahora = original_ahora
            db.RUTA_BD = original_ruta
            os.remove(ruta)


# =====================================================================
class PruebasIncidentes(Base5):

    def reglas(self):
        return {a["regla"] for a in deteccion.listar_alertas(self.seguridad)}

    def test_I01_fuerza_bruta_y_relleno_de_credenciales_sin_duplicar(self):
        for _ in range(5):
            ns.login_cliente("beto@prueba.cl", "incorrecta_1234")
        self.assertIn("fuerza_bruta_cuenta", self.reglas())
        for i in range(deteccion.UMBRAL_FALLOS_GLOBAL + 5):
            ns.login_cliente(f"inexistente{i}@prueba.cl", "incorrecta_1234")
        self.assertIn("relleno_credenciales", self.reglas())
        # los fallos que siguen llegando mientras la alerta está abierta no generan alertas nuevas
        reglas = [a["regla"] for a in deteccion.listar_alertas(self.seguridad)]
        self.assertEqual(reglas.count("relleno_credenciales"), 1)
        self.assertEqual(reglas.count("fuerza_bruta_cuenta"), 1)

    def test_I02_consulta_masiva_de_datos_personales(self):
        for _ in range(deteccion.UMBRAL_CONSULTAS_PERSONAL):
            ns.contacto_cliente(self.soporte, self.id_ana)
        alerta = [a for a in deteccion.listar_alertas(self.seguridad) if a["regla"] == "consulta_masiva"][0]
        self.assertEqual((alerta["actor_tipo"], alerta["actor_id"]), ("personal", self.soporte.id))
        self.assertNotIn("ana", alerta["descripcion"].lower())

    def test_I03_exportaciones_anomalas_y_denegaciones_repetidas(self):
        for _ in range(deteccion.UMBRAL_EXPORTACIONES):
            codigo, _ = self.solicitud_verificada(self.ana, "ana@prueba.cl", "portabilidad")
            derechos.exportar(self.ana, codigo)
        for _ in range(deteccion.UMBRAL_DENEGACIONES):
            with self.assertRaises(AccesoDenegado):
                ns.obtener_datos_cliente(self.beto, self.id_ana)
        self.assertTrue({"exportacion_anomala", "denegaciones_repetidas"} <= self.reglas())

    def test_I04_contencion_deshabilitar_cuenta_y_suspender_permiso(self):
        token = sesiones.crear(self.soporte)
        incidentes.deshabilitar_cuenta(self.seguridad, f"personal:{self.soporte.id}", "INC-PRUEBA")
        self.assertIsNone(sesiones.resolver(token))
        self.assertIsNone(ns.login_admin("sol_soporte", CLAVE))
        with self.assertRaises(AccesoDenegado):
            ns.contacto_cliente(self.soporte, self.id_ana)           # la Sesion en memoria tampoco sirve
        incidentes.habilitar_cuenta(self.seguridad, f"personal:{self.soporte.id}")
        self.assertIsNotNone(ns.login_admin("sol_soporte", CLAVE))
        incidentes.suspender_permiso(self.seguridad, "derechos.solicitar", "INC-PRUEBA")
        with self.assertRaises(AccesoDenegado):
            derechos.crear_solicitud(self.ana, "acceso", CLAVE)
        for permiso in ("contencion.ejecutar", "auditoria.leer", "permiso.inventado"):
            with self.assertRaises(ValueError):
                incidentes.suspender_permiso(self.seguridad, permiso)
        incidentes.reactivar_permiso(self.seguridad, "derechos.solicitar")
        self.assertTrue(derechos.crear_solicitud(self.ana, "acceso", CLAVE))
        with self.assertRaises(AccesoDenegado):
            incidentes.deshabilitar_cuenta(self.admin, f"cliente:{self.id_ana}")   # solo seguridad contiene

    def test_I05_preservar_evidencia_antes_de_contener(self):
        codigo = incidentes.registrar_incidente(self.seguridad, "acceso_indebido", "alta", "Consulta masiva de soporte")
        m = incidentes.preservar_evidencia(self.seguridad, codigo)
        ruta = os.path.join(incidentes.DIR_EVIDENCIA, codigo, m["archivo"])
        with open(ruta, "rb") as f:
            self.assertEqual(hashlib.sha256(f.read()).hexdigest(), m["sha256"])
        self.assertEqual(oct(os.stat(ruta).st_mode & 0o777), "0o400")
        copia = sqlite3.connect(ruta)
        self.assertEqual(copia.execute("SELECT COUNT(*) FROM clientes").fetchone()[0], 2)
        copia.close()

    def test_I06_evaluacion_notificacion_y_cierre(self):
        self.assertEqual(incidentes.evaluar_notificacion({"correo"}, False, 100),
                         {"notificar_agencia": False, "notificar_titulares": False})     # solo datos cifrados, llaves a salvo
        self.assertEqual(incidentes.evaluar_notificacion({"correo", "historial_compras"}, True, 100),
                         {"notificar_agencia": True, "notificar_titulares": True})
        self.assertEqual(incidentes.evaluar_notificacion({"credenciales"}, False, 3),
                         {"notificar_agencia": True, "notificar_titulares": False})
        for _ in range(5):
            ns.login_cliente("beto@prueba.cl", "incorrecta_1234")
        alerta = [a for a in deteccion.listar_alertas(self.seguridad) if a["regla"] == "fuerza_bruta_cuenta"][0]
        codigo = incidentes.registrar_incidente(self.seguridad, "fuerza_bruta", "media", alerta["descripcion"], alerta["id"])
        self.assertEqual(self.sql("SELECT estado FROM alertas WHERE id=?", (alerta["id"],))[0][0], "incidente")
        with self.assertRaises(ValueError):
            incidentes.cerrar_incidente(self.seguridad, codigo, "Causa: contraseña débil. Medida: bloqueo y MFA.")
        incidentes.registrar_evaluacion(self.seguridad, codigo, ["credenciales"], 1, False)
        borrador = incidentes.borrador_notificacion(self.seguridad, codigo)
        for punto in range(1, 8):
            self.assertIn(f"{punto}.", borrador)
        self.assertIn(incidentes.CONTACTO, borrador)
        for fase in ("contencion", "erradicacion", "recuperacion", "notificacion", "lecciones"):
            incidentes.avanzar_fase(self.seguridad, codigo, fase)
        with self.assertRaises(ValueError):
            incidentes.avanzar_fase(self.seguridad, codigo, "analisis")              # no retrocede
        with self.assertRaises(ValueError):
            incidentes.cerrar_incidente(self.seguridad, codigo, "Causa: contraseña débil. Medida: bloqueo y MFA.")
        incidentes.registrar_notificacion(self.seguridad, codigo)
        incidentes.cerrar_incidente(self.seguridad, codigo, "Causa: contraseña débil. Medida: bloqueo y MFA.")
        self.assertEqual(self.sql("SELECT fase FROM incidentes WHERE codigo=?", (codigo,))[0][0], "cerrado")

    def test_I07_rotacion_de_llave_y_comprobaciones_de_recuperacion(self):
        self.pedido_de_ana()
        nueva = os.urandom(32)
        version_original = cripto.VERSION_ACTUAL
        config.LLAVES_CIFRADO["v99"] = nueva
        cripto.VERSION_ACTUAL = incidentes.VERSION_ACTUAL = "v99"
        try:
            self.assertGreater(incidentes.valores_con_llave_antigua(), 0)
            self.assertFalse(incidentes.comprobar_recuperacion(self.seguridad)["listo"])
            incidentes.recifrar_datos()
            self.assertEqual(incidentes.valores_con_llave_antigua(), 0)
            antigua = config.LLAVES_CIFRADO.pop(version_original)        # la llave antigua se retira
            try:
                self.assertEqual(ns.obtener_datos_cliente(self.ana, self.id_ana)["correo"], "ana@prueba.cl")
                self.assertEqual(ns.direccion_despacho(self.logistica, 2), "Av. Los Leones 1234, Providencia")
            finally:
                config.LLAVES_CIFRADO[version_original] = antigua
            self.assertTrue(incidentes.comprobar_recuperacion(self.seguridad)["listo"])
        finally:
            config.LLAVES_CIFRADO.pop("v99", None)
            cripto.VERSION_ACTUAL = incidentes.VERSION_ACTUAL = version_original


# =====================================================================
class PruebasElusion(Base5):
    """Intentos de saltarse los controles con solicitudes directas al servidor o a la base."""

    def setUp(self):
        super().setUp()
        self.cliente = web.app.test_client()

    def api(self, metodo, ruta, token=None, **kw):
        cabeceras = {"Authorization": f"Bearer {token}"} if token else {}
        return self.cliente.open(ruta, method=metodo, headers=cabeceras, base_url="https://localhost", **kw)

    def token(self, **credenciales):
        return self.api("POST", "/api/v1/sesiones", json=credenciales).get_json()["token"]

    def test_W01_sin_token_token_inventado_o_cerrado(self):
        self.assertEqual(self.api("GET", "/api/v1/consentimientos").status_code, 401)
        self.assertEqual(self.api("GET", "/api/v1/consentimientos", token="x" * 43).status_code, 401)
        t = self.token(correo="ana@prueba.cl", password=CLAVE)
        self.assertEqual(self.api("GET", "/api/v1/consentimientos", token=t).status_code, 200)
        self.assertEqual(self.api("DELETE", "/api/v1/sesiones", token=t).status_code, 204)
        self.assertEqual(self.api("GET", "/api/v1/consentimientos", token=t).status_code, 401)
        self.assertEqual([tuple(f) for f in self.sql("SELECT canal FROM auditoria WHERE permiso='sesion.cerrar'")], [("api",)])

    def test_W02_idor_datos_de_otro_cliente(self):
        t = self.token(correo="ana@prueba.cl", password=CLAVE)
        self.assertEqual(self.api("GET", f"/api/v1/clientes/{self.id_ana}", token=t).status_code, 200)
        r = self.api("GET", f"/api/v1/clientes/{self.id_beto}", token=t)
        self.assertEqual((r.status_code, r.get_json()), (403, {"error": "Acceso denegado"}))
        self.assertEqual(self.api("GET", "/api/v1/clientes/9999", token=t).get_json(), {"error": "Acceso denegado"})

    def test_W03_rol_sin_permiso_en_la_api(self):
        t = self.token(usuario="mar_marketing", password=CLAVE)
        for ruta in ("/api/v1/auditoria", "/api/v1/alertas", "/api/v1/privacidad/solicitudes", "/api/v1/incidentes"):
            self.assertEqual(self.api("GET", ruta, token=t).status_code, 403)
        self.assertEqual(self.api("POST", "/api/v1/contencion", token=t,
                                  json={"accion": "revocar_sesiones", "objetivo": "todas"}).status_code, 403)
        t = self.token(usuario="seba_seguridad", password=CLAVE)
        self.assertEqual(self.api("GET", "/api/v1/auditoria", token=t).status_code, 200)

    def test_W04_asignacion_masiva_en_rectificacion(self):
        t = self.token(correo="ana@prueba.cl", password=CLAVE)
        r = self.api("POST", "/api/v1/derechos", token=t,
                     json={"tipo": "rectificacion", "password": CLAVE, "cambios": {"nombre": "Ana", "rol": "administrador"}})
        self.assertEqual(r.status_code, 400)
        self.assertEqual(self.sql("SELECT COUNT(*) FROM solicitudes_derechos")[0][0], 0)

    def test_W05_flujo_completo_por_api(self):
        t = self.token(correo="ana@prueba.cl", password=CLAVE)
        r = self.api("POST", "/api/v1/derechos", token=t, json={"tipo": "acceso", "password": CLAVE})
        codigo = r.get_json()["codigo"]
        self.assertEqual(self.api("GET", f"/api/v1/derechos/{codigo}/exportacion", token=t).status_code, 400)  # sin verificar
        r = self.api("POST", f"/api/v1/derechos/{codigo}/verificacion", token=t,
                     json={"codigo_correo": codigo_enviado("ana@prueba.cl")})
        self.assertEqual(r.get_json()["estado"], "en_evaluacion")
        t_beto = self.token(correo="beto@prueba.cl", password=CLAVE)
        self.assertEqual(self.api("GET", f"/api/v1/derechos/{codigo}/exportacion", token=t_beto).status_code, 403)
        r = self.api("GET", f"/api/v1/derechos/{codigo}/exportacion", token=t)
        self.assertEqual((r.status_code, r.get_json()["cuenta"]["correo"]), (200, "ana@prueba.cl"))

    def test_W06_la_cookie_no_sirve_en_la_api_y_la_web_exige_csrf(self):
        t = sesiones.crear(self.ana)
        self.cliente.set_cookie(web.COOKIE, t, domain="localhost")
        self.assertEqual(self.api("GET", "/api/v1/consentimientos").status_code, 401)        # solo Bearer
        r = self.cliente.post("/consentimientos/boletin/otorgar", data={"version": "1"}, base_url="https://localhost")
        self.assertEqual(r.status_code, 400)                                                  # falta el token CSRF
        self.assertFalse(cs.vigente("cliente", self.id_ana, "boletin"))
        r = self.cliente.post("/consentimientos/boletin/otorgar", data={"version": "1", "csrf": sesiones.csrf(t)},
                              base_url="https://localhost")
        self.assertEqual(r.status_code, 302)
        self.assertTrue(cs.vigente("cliente", self.id_ana, "boletin"))

    def test_W07_rol_cambiado_o_forjado_no_sirve(self):
        t = self.token(usuario="sol_soporte", password=CLAVE)
        self.sql("UPDATE administradores SET rol='marketing' WHERE usuario='sol_soporte'")
        self.assertEqual(sesiones.resolver(t).rol, "marketing")            # el rol se lee de la base, no del token
        with self.assertRaises(AccesoDenegado):
            ns.contacto_cliente(Sesion("personal", self.soporte.id, "soporte"), self.id_ana)
        with self.assertRaises(AccesoDenegado):
            ns.leer_auditoria(Sesion("personal", self.soporte.id, "administrador"))

    def test_W08_limite_de_intentos_y_cabeceras_de_seguridad(self):
        for _ in range(web.INTENTOS_LOGIN_IP):
            self.api("POST", "/api/v1/sesiones", json={"correo": "beto@prueba.cl", "password": "incorrecta_1234"})
        self.assertEqual(self.api("POST", "/api/v1/sesiones", json={"correo": "ana@prueba.cl", "password": CLAVE}).status_code, 429)
        r = self.cliente.get("/login", base_url="https://localhost")
        for cabecera in ("Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy"):
            self.assertIn(cabecera, r.headers)

    def test_W09_la_base_rechaza_cambios_directos(self):
        con = db.conectar()
        for sentencia in ("UPDATE consentimientos SET accion='otorgado'", "DELETE FROM consentimientos",
                          "UPDATE auditoria SET detalle='x'", "DELETE FROM auditoria",
                          "UPDATE administradores SET rol='superadmin'"):
            with self.assertRaises(sqlite3.DatabaseError):
                con.execute(sentencia)
        con.close()
        self.assertEqual(oct(os.stat(db.RUTA_BD).st_mode & 0o777), "0o600")

    def test_W10_errores_no_revelan_valores(self):
        t = self.token(correo="ana@prueba.cl", password=CLAVE)
        r = self.api("POST", "/api/v1/consentimientos/boletin", token=t, json={"accion": "otorgar", "version": "abc'--"})
        self.assertEqual(r.status_code, 400)
        self.assertNotIn("abc", r.get_data(as_text=True))


if __name__ == "__main__":
    unittest.main(verbosity=2)
