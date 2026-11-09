# pruebas_actividad6.py
# Pruebas de la Actividad 6: cada mecanismo de derechos se prueba con una solicitud concreta.
#   R1  canal y modelo de datos de la solicitud
#   R2  verificación de identidad (incluye solicitantes NO verificados)
#   R3  acceso y portabilidad
#   R4  rectificación con registro del cambio
#   R5  supresión: qué se elimina, qué se bloquea por obligación legal y cómo se propaga
#   R6  oposición (encuesta de satisfacción, interés legítimo) y bloqueo temporal (art. 8 ter)
# Usan una base temporal y datos ficticios: no tocan nortishop.db.
#
# Ejecutar:  python -m unittest pruebas_actividad6 -v

import json
import sqlite3
import unittest
from datetime import datetime, timedelta

from pruebas_seguridad import CLAVE
from pruebas_actividad5 import Base5, codigo_enviado
import nortishop as ns
import consentimiento as cs
import derechos
import notificador
import app as web
from rbac import AccesoDenegado


class Base6(Base5):
    def setUp(self):
        super().setUp()
        self.cliente = web.app.test_client()
        notificador._BUZON.clear()            # cada prueba parte con el buzón simulado vacío

    def entregar(self, pedido_id):
        ns.actualizar_estado(self.logistica, pedido_id, "despachado")
        ns.actualizar_estado(self.logistica, pedido_id, "entregado")

    def pedido_de_beto(self):
        ns.guardar_tarjeta(self.beto, self.pasarela, "5555 5555 5555 4444", "11/28", "321")
        ns.comprar_con_tarjeta_guardada(self.beto, self.pasarela, [{"producto": "Teclado", "cantidad": 1, "precio": 25990}],
                                        25990, direccion="Calle Beto 99, Ñuñoa", region="Metropolitana de Santiago")

    def solicitud(self, codigo):
        return self.sql("SELECT * FROM solicitudes_derechos WHERE codigo=?", (codigo,))[0]

    def api(self, metodo, ruta, token=None, **kw):
        cabeceras = {"Authorization": f"Bearer {token}"} if token else {}
        return self.cliente.open(ruta, method=metodo, headers=cabeceras, base_url="https://localhost", **kw)

    def token(self, **credenciales):
        return self.api("POST", "/api/v1/sesiones", json=credenciales).get_json()["token"]


# =====================================================================
class PruebasCanalYModelo(Base6):

    def test_R1_01_solicitud_registrada_con_canal_tipo_fechas_y_plazo(self):
        codigo = derechos.crear_solicitud(self.ana, "acceso", CLAVE)
        s = self.solicitud(codigo)
        self.assertEqual((s["tipo"], s["canal"], s["estado"]), ("acceso", "web", "recibida"))
        self.assertEqual(s["titular_seudonimo"], ns.seudonimo_cliente(self.id_ana))
        dias = (datetime.strptime(s["plazo_vence"], "%Y-%m-%d %H:%M:%S")
                - datetime.strptime(s["fecha_recepcion"], "%Y-%m-%d %H:%M:%S")).days
        self.assertEqual(dias, 30)                                       # art. 11: 30 días corridos
        derechos.verificar_identidad(self.ana, codigo, codigo_enviado("ana@prueba.cl"))
        derechos.exportar(self.ana, codigo)
        s = self.solicitud(codigo)
        for etapa in ("fecha_verificacion", "fecha_evaluacion", "fecha_respuesta", "fecha_cierre"):
            self.assertIsNotNone(s[etapa])                               # seguimiento de cada etapa
        self.assertEqual(s["estado"], "cerrada")

    def test_R1_02_canal_api_y_detalle_cifrado(self):
        t = self.token(correo="ana@prueba.cl", password=CLAVE)
        r = self.api("POST", "/api/v1/derechos", token=t,
                     json={"tipo": "rectificacion", "password": CLAVE, "cambios": {"telefono": "+56 9 5555 6666"}})
        self.assertEqual(r.status_code, 201)
        s = self.solicitud(r.get_json()["codigo"])
        self.assertEqual(s["canal"], "api")
        self.assertNotIn("5555 6666", s["detalle_cifrado"])              # el valor nuevo va cifrado
        evento = self.sql("SELECT canal, detalle FROM auditoria WHERE permiso='derechos.solicitar' AND resultado='exito'")[0]
        self.assertEqual(evento["canal"], "api")
        self.assertIn("canal=api", evento["detalle"])
        self.assertNotIn("5555", evento["detalle"])                      # la bitácora guarda campos, no valores
        with self.assertRaises(ValueError):
            derechos.crear_solicitud(self.beto, "acceso", CLAVE, canal="telefono")


# =====================================================================
class PruebasVerificacionIdentidad(Base6):

    def test_R2_01_contraseña_incorrecta_no_crea_solicitud(self):
        with self.assertRaises(AccesoDenegado):
            derechos.crear_solicitud(self.ana, "supresion", "ClaveAdivinada1")
        self.assertEqual(self.sql("SELECT COUNT(*) FROM solicitudes_derechos")[0][0], 0)
        self.assertIsNone(notificador.ultimo_para("ana@prueba.cl"))
        self.assertEqual(self.sql("SELECT detalle FROM auditoria WHERE permiso='derechos.solicitar' AND resultado='fallido'")[0][0],
                         "tipo=supresion reautenticacion_fallida")

    def test_R2_02_contraseña_robada_sin_acceso_al_correo_no_rectifica(self):
        # el atacante conoce la contraseña de Ana pero no puede leer su correo: prueba códigos al azar
        codigo = derechos.crear_solicitud(self.ana, "rectificacion", CLAVE, {"correo": "atacante@malo.cl"})
        for intento in ("000000", "123456", "999999"):
            with self.assertRaises(ValueError):
                derechos.verificar_identidad(self.ana, codigo, intento)
        s = self.solicitud(codigo)
        self.assertEqual(s["estado"], "cerrada")
        self.assertIn("No se pudo verificar la identidad", s["resultado"])
        self.assertIsNone(s["fecha_verificacion"])
        self.assertEqual(ns.obtener_datos_cliente(self.ana, self.id_ana)["correo"], "ana@prueba.cl")   # sin cambios
        self.assertEqual(self.sql("SELECT COUNT(*) FROM registro_rectificaciones")[0][0], 0)
        self.assertIsNone(notificador.ultimo_para("atacante@malo.cl"))  # nunca se escribe al correo propuesto

    def test_R2_03_tercero_con_el_codigo_de_otra_persona(self):
        codigo = derechos.crear_solicitud(self.ana, "acceso", CLAVE)
        otp = codigo_enviado("ana@prueba.cl")
        with self.assertRaises(AccesoDenegado):
            derechos.verificar_identidad(self.beto, codigo, otp)         # Beto intercepta el código
        with self.assertRaises(AccesoDenegado):
            derechos.exportar(self.beto, codigo)
        self.assertEqual(self.solicitud(codigo)["estado"], "recibida")

    def test_R2_04_sin_verificar_nada_se_ejecuta(self):
        self.pedido_de_ana()
        self.entregar(2)
        for tipo in ("acceso", "supresion"):
            derechos.crear_solicitud(self.ana, tipo, CLAVE)
        acceso = self.sql("SELECT codigo FROM solicitudes_derechos WHERE tipo='acceso'")[0][0]
        supresion = self.sql("SELECT codigo FROM solicitudes_derechos WHERE tipo='supresion'")[0][0]
        with self.assertRaises(ValueError):
            derechos.exportar(self.ana, acceso)                          # aún 'recibida'
        with self.assertRaises(ValueError):
            derechos.resolver_supresion(self.privacidad, supresion, True, pasarela=self.pasarela)
        self.assertEqual(self.sql("SELECT COUNT(*) FROM clientes WHERE id=?", (self.id_ana,))[0][0], 1)

    def test_R2_05_personal_y_peticiones_sin_sesion_por_la_api(self):
        with self.assertRaises(AccesoDenegado):
            derechos.crear_solicitud(self.soporte, "acceso", CLAVE)      # el personal no ejerce derechos ajenos
        r = self.api("POST", "/api/v1/derechos", json={"tipo": "acceso", "password": CLAVE})
        self.assertEqual(r.status_code, 401)
        self.assertEqual(self.sql("SELECT COUNT(*) FROM solicitudes_derechos")[0][0], 0)


# =====================================================================
class PruebasAccesoPortabilidad(Base6):

    def test_R3_01_acceso_entrega_todos_los_datos_del_titular_y_solo_los_suyos(self):
        self.pedido_de_ana()                                             # pedido 2 (Ana)
        self.pedido_de_beto()                                            # pedido 3 (Beto); el 1 es de un invitado
        cs.otorgar(self.ana, "boletin", 1)
        codigo, _ = self.solicitud_verificada(self.ana, "ana@prueba.cl", "acceso")
        datos = derechos.exportar(self.ana, codigo)
        texto = json.dumps(datos, ensure_ascii=False)
        self.assertEqual(json.loads(texto), datos)                       # JSON válido y completo
        # todos los suyos
        self.assertEqual(datos["cuenta"]["nombre"], "Ana Prueba")
        self.assertEqual(datos["cuenta"]["telefono"], "+56 9 1111 2222")
        self.assertEqual([p["codigo"] for p in datos["pedidos"]],
                         [f[0] for f in self.sql("SELECT codigo FROM pedidos WHERE cliente_id=?", (self.id_ana,))])
        self.assertEqual(len(datos["tarjetas"]), 1)
        self.assertEqual(len(datos["consentimientos"]),
                         self.sql("SELECT COUNT(*) FROM consentimientos WHERE titular_ref=?", (str(self.id_ana),))[0][0])
        for seccion in ("rectificaciones", "oposiciones", "bloqueos", "informacion_tratamiento"):
            self.assertIn(seccion, datos)
        self.assertIn("interes_legitimo", datos["informacion_tratamiento"])
        # solo los suyos: nada de Beto, del invitado ni datos internos
        for ajeno in ("beto@prueba.cl", "Beto", "Teclado", "Calle Beto", "invitado@prueba.cl", "Av. Falsa", "4444",
                      "password_hash", "$2b$", "tok_", ns.seudonimo_cliente(self.id_ana)):
            self.assertNotIn(ajeno, texto)

    def test_R3_02_portabilidad_solo_lo_aportado_en_formato_estructurado(self):
        self.pedido_de_ana()
        codigo, _ = self.solicitud_verificada(self.ana, "ana@prueba.cl", "portabilidad")
        datos = derechos.exportar(self.ana, codigo)
        self.assertEqual((datos["formato"], datos["tipo"]), (derechos.VERSION_EXPORTACION, "portabilidad"))
        self.assertNotIn("nortipuntos", datos["cuenta"])                 # dato generado por NortiShop
        for seccion in ("informacion_tratamiento", "rectificaciones", "oposiciones", "bloqueos"):
            self.assertNotIn(seccion, datos)
        self.assertEqual(datos["pedidos"][0]["direccion"], "Av. Los Leones 1234, Providencia")
        evento = self.sql("SELECT detalle FROM auditoria WHERE permiso='derechos.exportar' AND resultado='exito'")[0][0]
        self.assertIn("tipo=portabilidad formato=json", evento)


# =====================================================================
class PruebasRectificacion(Base6):

    def test_R4_01_rectificacion_con_registro_del_cambio_y_propagacion(self):
        self.pedido_de_ana()                                             # pedido 2, pagado (no despachado)
        codigo, estado = self.solicitud_verificada(self.ana, "ana@prueba.cl", "rectificacion",
                                                   {"direccion": "Pasaje Nuevo 55, Ñuñoa", "telefono": "+56 9 7777 8888"})
        self.assertEqual(estado, "cerrada")
        filas = self.sql("SELECT * FROM registro_rectificaciones WHERE solicitud=? ORDER BY campo", (codigo,))
        self.assertEqual([f["campo"] for f in filas], ["direccion", "telefono"])
        d, t = filas
        self.assertIsNone(derechos.descifrar(d["valor_anterior_cifrado"], derechos._ctx_rectificacion(codigo, "direccion", "anterior"))
                          if d["valor_anterior_cifrado"] else None)      # Ana no tenía dirección en la cuenta
        self.assertEqual(derechos.descifrar(t["valor_anterior_cifrado"], derechos._ctx_rectificacion(codigo, "telefono", "anterior")),
                         "+56 9 1111 2222")
        self.assertEqual(derechos.descifrar(t["valor_nuevo_cifrado"], derechos._ctx_rectificacion(codigo, "telefono", "nuevo")),
                         "+56 9 7777 8888")
        self.assertIn("empresa de despacho (1 pedido(s)", d["comunicado_a"])   # art. 6: se comunica al destinatario
        self.assertEqual(ns.direccion_despacho(self.logistica, 2), "Pasaje Nuevo 55, Ñuñoa")
        self.assertNotIn("7777", t["valor_nuevo_cifrado"])               # el registro guarda los valores cifrados
        self.assertIn("Campos modificados: direccion,telefono", notificador.ultimo_para("ana@prueba.cl")["cuerpo"])
        evento = self.sql("SELECT detalle FROM auditoria WHERE permiso='derechos.rectificar'")[0][0]
        self.assertEqual(evento, f"cliente={self.id_ana} campos=direccion,telefono pedidos_actualizados=1")
        with self.assertRaises(sqlite3.IntegrityError):
            self.sql("UPDATE registro_rectificaciones SET campo='nombre' WHERE id=?", (d["id"],))

    def test_R4_02_cambio_de_correo_registrado_y_avisado_a_ambos_correos(self):
        cs.otorgar(self.ana, "boletin", 1)
        codigo, estado = self.solicitud_verificada(self.ana, "ana@prueba.cl", "rectificacion", {"correo": "ana.nueva@prueba.cl"})
        self.assertEqual(estado, "en_evaluacion")                        # espera el código del correo nuevo
        self.assertEqual(self.sql("SELECT COUNT(*) FROM registro_rectificaciones")[0][0], 0)
        derechos.confirmar_correo_nuevo(self.ana, codigo, codigo_enviado("ana.nueva@prueba.cl"))
        f = self.sql("SELECT comunicado_a FROM registro_rectificaciones WHERE solicitud=?", (codigo,))[0]
        self.assertIn("lista del boletín", f[0])
        self.assertIn("ana.nueva@prueba.cl", ns.correos_para_envio_boletin(self.marketing))
        self.assertIn("se rectificaron", notificador.ultimo_para("ana@prueba.cl")["asunto"])        # aviso al anterior
        self.assertIn("se rectificaron", notificador.ultimo_para("ana.nueva@prueba.cl")["asunto"])
        acceso, _ = self.solicitud_verificada(self.ana, "ana.nueva@prueba.cl", "acceso")
        r = derechos.exportar(self.ana, acceso)["rectificaciones"][0]
        self.assertEqual((r["campo"], r["valor_anterior"], r["valor_nuevo"]), ("correo", "ana@prueba.cl", "ana.nueva@prueba.cl"))


# =====================================================================
class PruebasSupresion(Base6):

    def preparar_ana(self):
        self.pedido_de_ana()                                             # pedido 2 con tarjeta guardada
        self.entregar(2)
        cs.otorgar(self.ana, "boletin", 1)
        ns.guardar_comportamiento(self.id_ana, {"categorias": ["audio"]})
        self.solicitud_verificada(self.ana, "ana@prueba.cl", "rectificacion", {"telefono": "+56 9 2222 3333"})

    def test_R5_01_acta_elimina_bloquea_y_propaga(self):
        self.preparar_ana()
        token = self.sql("SELECT token_pasarela FROM tarjetas_guardadas WHERE cliente_id=?", (self.id_ana,))[0][0]
        codigo, estado = self.solicitud_verificada(self.ana, "ana@prueba.cl", "supresion")
        self.assertEqual(estado, "en_evaluacion")
        self.assertEqual(derechos.resolver_supresion(self.privacidad, codigo, True, pasarela=self.pasarela), "cerrada")
        acta = derechos.acta_supresion(self.privacidad, codigo)
        # qué se elimina
        e = acta["eliminado"]
        self.assertEqual((e["cuenta"], e["tarjetas_guardadas"], e["suscripcion_boletin"], e["comportamiento_compra"],
                          e["registro_rectificaciones"], e["direcciones_de_pedidos"]), (1, 1, 1, 1, 1, 1))
        for tabla in ("clientes WHERE id=?", "tarjetas_guardadas WHERE cliente_id=?", "registro_rectificaciones WHERE cliente_id=?",
                      "boletin_suscriptores WHERE cliente_id=?"):
            self.assertEqual(self.sql(f"SELECT COUNT(*) FROM {tabla}", (self.id_ana,))[0][0], 0)
        # qué se bloquea por obligación legal
        b = acta["bloqueado_por_obligacion_legal"]
        self.assertEqual(b["pedidos_bloqueo_legal"], 1)
        p = self.sql("SELECT cliente_id, direccion_cifrado, monto, bloqueo_legal_hasta FROM pedidos WHERE id=2")[0]
        self.assertEqual((p["cliente_id"], p["direccion_cifrado"], p["monto"]), (None, None, 39990))
        años = (datetime.strptime(p["bloqueo_legal_hasta"], "%Y-%m-%d %H:%M:%S") - datetime.now()).days / 365
        self.assertAlmostEqual(años, ns.AÑOS_CONSERVACION_TRIBUTARIA, delta=0.1)
        codigo_pedido = self.sql("SELECT codigo FROM pedidos WHERE id=2")[0][0]
        self.assertNotIn(codigo_pedido, [f["codigo"] for f in ns.resumen_pedidos(self.soporte)])   # fuera de las vistas operativas
        with self.assertRaises(AccesoDenegado):
            ns.actualizar_estado(self.logistica, 2, "entregado")         # no se puede tratar
        self.assertGreater(b["consentimientos_seudonimizados"], 0)
        # cómo se propaga
        self.assertNotIn(token, self.pasarela._boveda)
        self.assertIn("1 de 1 tokens", acta["propagado_a"]["pasarela_pago"])
        self.assertEqual(self.sql("SELECT COUNT(*) FROM lista_supresion")[0][0], 1)
        # la respuesta al titular explica las tres cosas
        resultado = self.solicitud(codigo)["resultado"]
        for parte in ("Eliminado:", "Bloqueado por obligación legal:", "Propagado a:"):
            self.assertIn(parte, resultado)
        self.assertIn("Bloqueado por obligación legal", notificador.ultimo_para("ana@prueba.cl")["cuerpo"])
        for personal in ("ana@prueba.cl", "Ana Prueba", "2222 3333", "Los Leones", token):
            self.assertNotIn(personal, json.dumps(acta, ensure_ascii=False))     # el acta no tiene datos personales

    def test_R5_02_el_bloqueo_legal_vence_y_el_pedido_se_elimina(self):
        self.preparar_ana()
        codigo, _ = self.solicitud_verificada(self.ana, "ana@prueba.cl", "supresion")
        derechos.resolver_supresion(self.privacidad, codigo, True, pasarela=self.pasarela)
        ns.aplicar_retencion(self.admin)
        self.assertEqual(self.sql("SELECT COUNT(*) FROM pedidos WHERE id=2")[0][0], 1)        # aún vigente
        self.sql("UPDATE pedidos SET bloqueo_legal_hasta='2020-01-01 00:00:00' WHERE id=2")     # simula 6 años después
        ns.aplicar_retencion(self.admin)
        self.assertEqual(self.sql("SELECT COUNT(*) FROM pedidos WHERE id=2")[0][0], 0)

    def test_R5_03_supresion_rechazada_por_pedido_en_curso(self):
        self.pedido_de_ana()                                             # pagado: contrato en ejecución
        codigo, estado = self.solicitud_verificada(self.ana, "ana@prueba.cl", "supresion")
        self.assertEqual(estado, "cerrada")
        resultado = self.solicitud(codigo)["resultado"]
        self.assertIn("pedidos en curso", resultado)
        self.assertIn("Agencia de Protección de Datos", resultado)
        self.assertEqual(self.sql("SELECT COUNT(*) FROM clientes WHERE id=?", (self.id_ana,))[0][0], 1)


# =====================================================================
class PruebasOposicionYBloqueo(Base6):

    def con_pedidos_entregados(self):
        self.pedido_de_ana()                                             # pedido 2
        self.pedido_de_beto()                                            # pedido 3
        self.entregar(2)
        self.entregar(3)

    def test_R6_01_oposicion_a_la_encuesta_acogida(self):
        self.con_pedidos_entregados()
        self.assertEqual(sorted(ns.correos_para_encuesta(self.marketing)), ["ana@prueba.cl", "beto@prueba.cl"])
        codigo = derechos.crear_solicitud(self.ana, "oposicion", CLAVE, tratamiento="encuesta_satisfaccion",
                                          motivo="No quiero recibir encuestas después de mis compras.")
        estado = derechos.verificar_identidad(self.ana, codigo, codigo_enviado("ana@prueba.cl"))
        self.assertEqual(estado, "en_evaluacion")
        self.assertEqual(derechos.detalle_oposicion(self.privacidad, codigo)["tratamiento"], "encuesta_satisfaccion")
        self.assertEqual(derechos.resolver_oposicion(self.privacidad, codigo, True), "acogida")
        self.assertEqual(ns.correos_para_encuesta(self.marketing), ["beto@prueba.cl"])   # Ana sale, Beto sigue
        self.assertEqual(self.sql("SELECT tratamiento, solicitud FROM oposiciones WHERE cliente_id=?", (self.id_ana,))[0][:],
                         ("encuesta_satisfaccion", codigo))
        self.assertIsNone(self.solicitud(codigo)["detalle_cifrado"])     # el motivo no se conserva tras resolver
        self.assertIn("Oposición acogida", notificador.ultimo_para("ana@prueba.cl")["cuerpo"])
        self.assertEqual(self.sql("SELECT detalle FROM auditoria WHERE permiso='encuesta.destinatarios' "
                                  "ORDER BY id DESC LIMIT 1")[0][0], "incluidos=1 excluidos=1")
        with self.assertRaises(ValueError):                              # no se duplica
            derechos.crear_solicitud(self.ana, "oposicion", CLAVE, tratamiento="encuesta_satisfaccion",
                                     motivo="Otra vez la misma oposición.")

    def test_R6_02_oposicion_no_procede_o_se_rechaza_con_fundamento(self):
        casos = [("boletin", "No quiero el boletín, gracias.", "consentimiento"),
                 ("compra", "No quiero que procesen mis pedidos.", "contrato"),
                 ("encuesta_satisfaccion", "corto", "motivo")]
        for tratamiento, motivo, esperado in casos:
            with self.assertRaises(ValueError) as e:
                derechos.crear_solicitud(self.ana, "oposicion", CLAVE, tratamiento=tratamiento, motivo=motivo)
            self.assertIn(esperado, str(e.exception))
        codigo = derechos.crear_solicitud(self.ana, "oposicion", CLAVE, tratamiento="encuesta_satisfaccion",
                                          motivo="Prefiero no recibir encuestas.")
        derechos.verificar_identidad(self.ana, codigo, codigo_enviado("ana@prueba.cl"))
        with self.assertRaises(ValueError):
            derechos.resolver_oposicion(self.privacidad, codigo, False, "no")           # sin fundamento
        for s in (self.marketing, self.soporte, self.beto):
            with self.assertRaises(AccesoDenegado):
                derechos.resolver_oposicion(s, codigo, True)
        derechos.resolver_oposicion(self.privacidad, codigo, False,
                                    "Existe un reclamo abierto del titular y la encuesta es parte de su resolución.")
        resultado = self.solicitud(codigo)["resultado"]
        self.assertIn("30 días hábiles", resultado)
        self.assertEqual(self.sql("SELECT COUNT(*) FROM oposiciones")[0][0], 0)

    def test_R6_03_bloqueo_suspende_el_tratamiento_mientras_se_resuelve(self):
        self.con_pedidos_entregados()
        cs.otorgar(self.ana, "boletin", 1)
        cs.otorgar(self.ana, "ofertas_personalizadas", 1)
        supresion, estado = self.solicitud_verificada(self.ana, "ana@prueba.cl", "supresion")
        self.assertEqual(estado, "en_evaluacion")
        bloqueo = derechos.crear_solicitud(self.ana, "bloqueo", CLAVE, asociada=supresion)
        self.assertTrue(ns.guardar_comportamiento(self.id_ana, {"x": 1}))   # antes de verificar, nada cambia
        self.assertEqual(derechos.verificar_identidad(self.ana, bloqueo, codigo_enviado("ana@prueba.cl")), "cerrada")
        self.assertTrue(self.solicitud(bloqueo)["resultado"].startswith("Tratamiento bloqueado"))
        # con el bloqueo vigente los datos solo se almacenan
        self.assertNotIn("ana@prueba.cl", ns.correos_para_envio_boletin(self.marketing))
        self.assertNotIn("ana@prueba.cl", ns.correos_para_encuesta(self.marketing))
        self.assertFalse(ns.guardar_comportamiento(self.id_ana, {"x": 2}))
        self.assertFalse(ns.ofertas(self.ana)["personalizadas"])
        with self.assertRaises(ValueError):
            ns.contacto_cliente(self.soporte, self.id_ana)
        self.assertEqual(ns.contacto_cliente(self.soporte, self.id_beto)["nombre"], "Beto Prueba")  # Beto no se afecta
        self.assertEqual(self.sql("SELECT COUNT(*) FROM clientes WHERE id=?", (self.id_ana,))[0][0], 1)  # se almacenan
        # privacidad rechaza la supresión con fundamento: al cerrarse, el bloqueo se levanta
        derechos.resolver_supresion(self.privacidad, supresion, False,
                                    "Existe un reclamo pendiente ante el SERNAC que requiere conservar la cuenta.")
        hasta = self.sql("SELECT hasta FROM bloqueos WHERE solicitud=?", (bloqueo,))[0][0]
        self.assertIsNotNone(hasta)
        self.assertIn("ana@prueba.cl", ns.correos_para_envio_boletin(self.marketing))
        self.assertTrue(ns.ofertas(self.ana)["personalizadas"])
        self.assertEqual(ns.contacto_cliente(self.soporte, self.id_ana)["correo"], "ana@prueba.cl")

    def test_R6_04_bloqueo_invalido_o_sin_verificar(self):
        acceso = derechos.crear_solicitud(self.ana, "acceso", CLAVE)
        oposicion_beto = derechos.crear_solicitud(self.beto, "oposicion", CLAVE, tratamiento="encuesta_satisfaccion",
                                                  motivo="No quiero encuestas, gracias.")
        for asociada in (None, "SD-NOEXISTE", acceso, oposicion_beto):   # sin asociada, inexistente, no bloqueable, ajena
            with self.assertRaises(ValueError):
                derechos.crear_solicitud(self.ana, "bloqueo", CLAVE, asociada=asociada)
        oposicion = derechos.crear_solicitud(self.ana, "oposicion", CLAVE, tratamiento="encuesta_satisfaccion",
                                             motivo="No quiero encuestas, gracias.")
        derechos.verificar_identidad(self.ana, oposicion, codigo_enviado("ana@prueba.cl"))
        bloqueo = derechos.crear_solicitud(self.ana, "bloqueo", CLAVE, asociada=oposicion)
        for _ in range(3):
            with self.assertRaises(ValueError):
                derechos.verificar_identidad(self.ana, bloqueo, "000000")   # solicitante no verificado
        self.assertEqual(self.sql("SELECT COUNT(*) FROM bloqueos")[0][0], 0)
        self.assertIn("No se pudo verificar", self.solicitud(bloqueo)["resultado"])

    def test_R6_05_oposicion_y_bloqueo_por_la_api(self):
        self.con_pedidos_entregados()
        t = self.token(correo="beto@prueba.cl", password=CLAVE)
        r = self.api("POST", "/api/v1/derechos", token=t, json={"tipo": "oposicion", "password": CLAVE,
                     "tratamiento": "encuesta_satisfaccion", "motivo": "Recibo demasiados correos."})
        oposicion = r.get_json()["codigo"]
        self.api("POST", f"/api/v1/derechos/{oposicion}/verificacion", token=t,
                 json={"codigo_correo": codigo_enviado("beto@prueba.cl")})
        r = self.api("POST", "/api/v1/derechos", token=t, json={"tipo": "bloqueo", "password": CLAVE, "asociada": oposicion})
        bloqueo = r.get_json()["codigo"]
        r = self.api("POST", f"/api/v1/derechos/{bloqueo}/verificacion", token=t,
                     json={"codigo_correo": codigo_enviado("beto@prueba.cl")})
        self.assertEqual(r.get_json()["estado"], "cerrada")
        self.assertEqual(ns.correos_para_encuesta(self.marketing), ["ana@prueba.cl"])   # bloqueado ya
        tp = self.token(usuario="pia_privacidad", password=CLAVE)
        r = self.api("POST", f"/api/v1/privacidad/solicitudes/{oposicion}", token=tp, json={"decision": "aprobar"})
        self.assertEqual(r.get_json()["estado"], "acogida")
        self.assertIsNotNone(self.sql("SELECT hasta FROM bloqueos")[0][0])               # bloqueo levantado
        self.assertEqual(ns.correos_para_encuesta(self.marketing), ["ana@prueba.cl"])   # la oposición sigue
        self.assertEqual({f[0] for f in self.sql("SELECT canal FROM solicitudes_derechos")}, {"api"})


if __name__ == "__main__":
    unittest.main()
