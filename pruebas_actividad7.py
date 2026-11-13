# pruebas_actividad7.py
# Pruebas de la Actividad 7: catálogo de eventos (E), protección y conservación de los registros (P),
# alertas de acceso anómalo propias de NortiShop (L) y reconstrucción de incidentes (R).
# Base temporal y datos ficticios (clase Base5 de pruebas_actividad5.py).
#
# Ejecutar:  python -m unittest pruebas_actividad7 -v

import os
import json
import tempfile
import subprocess
import sys
import unittest
from datetime import datetime
from zoneinfo import ZoneInfo

import pruebas_actividad5 as p5
from pruebas_actividad5 import Base5, CLAVE
import db
import reloj
import auditoria
import catalogo_eventos
import deteccion
import incidentes
import notificador
import trazabilidad
import sesiones
import nortishop as ns
import app as web
from rbac import AccesoDenegado, PERMISOS

CHILE = ZoneInfo("America/Santiago")


class Base7(Base5):
    def setUp(self):
        fd, self.anclas = tempfile.mkstemp(suffix=".jsonl")
        os.close(fd)
        os.remove(self.anclas)
        self._anclas_original = auditoria.RUTA_ANCLAS
        auditoria.RUTA_ANCLAS = self.anclas
        super().setUp()

    def tearDown(self):
        reloj.fijar(None)
        auditoria.RUTA_ANCLAS = self._anclas_original
        if os.path.exists(self.anclas):
            os.remove(self.anclas)
        super().tearDown()

    def a_las(self, dia, hora, minuto=0):
        reloj.fijar(datetime(2026, 11, dia, hora, minuto, tzinfo=CHILE))

    def alertas(self, regla):
        return [dict(f) for f in self.sql("SELECT * FROM alertas WHERE regla=?", (regla,))]

    def eventos(self, permiso):
        return [dict(f) for f in self.sql("SELECT * FROM auditoria WHERE permiso=? ORDER BY id", (permiso,))]

    def incidente(self):
        return incidentes.registrar_incidente(self.seguridad, "prueba", "media", "Incidente de prueba")


# =====================================================================
class PruebasCatalogo(Base7):

    def test_E01_todo_evento_registrado_esta_catalogado(self):
        self.pedido_de_ana()
        ns.direccion_despacho(self.logistica, 1)
        ns.contacto_cliente(self.soporte, self.id_ana)
        ns.aplicar_retencion(self.admin)
        for e in self.auditoria_completa():
            self.assertIsNotNone(catalogo_eventos.buscar(e["permiso"]), e["permiso"])
            self.assertIn(e["categoria"], catalogo_eventos.CATEGORIAS)
        with self.assertRaises(ValueError):
            auditoria.registrar_evento(None, "operacion.inventada", None, "exito")
        # cada permiso de la matriz de roles tiene su evento de control de acceso
        for permiso in set().union(*PERMISOS.values()):
            self.assertIsNotNone(catalogo_eventos.buscar(permiso), permiso)

    def test_E02_detalle_o_recurso_con_datos_personales_no_se_guardan(self):
        auditoria.registrar_evento(None, "pedido.estado", 1, "exito", "estado=ana@prueba.cl")
        auditoria.registrar_evento(None, "pedido.estado", 1, "exito", "nota=Calle Falsa 123")
        auditoria.registrar_evento(None, "pedido.estado", "ana@prueba.cl", "exito", "estado=entregado")
        filas = self.eventos("pedido.estado")[-3:]
        self.assertEqual([f["detalle"] for f in filas], ["detalle_rechazado", "detalle_rechazado", "estado=entregado"])
        self.assertEqual(filas[2]["recurso"], "recurso_rechazado")
        texto = json.dumps(self.auditoria_completa(), ensure_ascii=False)
        for dato in ("ana@prueba.cl", "Calle Falsa"):
            self.assertNotIn(dato, texto)
        self.assertTrue(auditoria.verificar_cadena()["ok"])          # el evento no se pierde, solo su detalle

    def test_E03_falla_despues_de_autorizar_queda_registrada(self):
        ns.actualizar_estado(self.logistica, 1, "entregado")
        with self.assertRaises(AccesoDenegado):
            ns.direccion_despacho(self.logistica, 1)                  # pedido entregado: la regla de negocio lo niega
        ultimos = self.eventos("despacho.direccion.leer")[-2:]
        self.assertEqual([e["resultado"] for e in ultimos], ["permitido", "denegado"])
        self.assertEqual(ultimos[1]["detalle"], f"tras={ultimos[0]['id']} motivo=regla_negocio")
        with self.assertRaises(ValueError):
            ns.actualizar_estado(self.logistica, 1, "pagado")          # el estado no retrocede
        self.assertEqual(self.eventos("pedidos.estado.actualizar")[-1]["resultado"], "fallido")

    def test_E04_compras_retencion_y_cambios_de_estado_se_auditan(self):
        crear = self.eventos("pedido.crear")
        self.assertEqual((crear[0]["actor_tipo"], crear[0]["recurso"], crear[0]["resultado"], crear[0]["detalle"]),
                         (None, "1", "exito", "origen=invitado"))
        self.pedido_de_ana()
        self.assertEqual(self.eventos("pedido.crear")[-1]["detalle"], "origen=cuenta")
        token = self.sql("SELECT token_pasarela FROM tarjetas_guardadas")[0][0]
        self.pasarela.eliminar_token(token)                              # la pasarela rechazará el cobro
        ns.comprar_con_tarjeta_guardada(self.ana, self.pasarela, [{"producto": "Cable", "cantidad": 1, "precio": 990}], 990,
                                        direccion="Calle 2")
        rechazo = self.eventos("pedido.crear")[-1]
        self.assertEqual((rechazo["recurso"], rechazo["resultado"], rechazo["detalle"]), (None, "fallido", "origen=cuenta pago_rechazado"))
        ns.actualizar_estado(self.logistica, 1, "despachado")
        self.assertEqual(self.eventos("pedido.estado")[-1]["detalle"], "estado=despachado")
        ns.aplicar_retencion(self.admin)
        self.assertEqual(self.eventos("retencion.aplicar")[-1]["detalle"], "pedidos_anonimizados=0 pedidos_eliminados=0")
        ns.guardar_comportamiento(self.id_beto, {"categorias": ["audio"]})   # Beto no consintió
        self.assertEqual(self.eventos("analitica.guardar")[-1]["detalle"], "sin_consentimiento")


# =====================================================================
class PruebasProteccion(Base7):

    def test_P01_administrador_ve_solo_el_resumen(self):
        with self.assertRaises(AccesoDenegado):
            ns.leer_auditoria(self.admin)
        with self.assertRaises(AccesoDenegado):
            trazabilidad.consultar(self.admin, "revision_periodica")
        resumen = trazabilidad.resumen_auditoria(self.admin)
        self.assertTrue(resumen)
        self.assertEqual(set(resumen[0]), {"categoria", "resultado", "eventos"})
        for s in (self.soporte, self.privacidad, self.ana):
            with self.assertRaises(AccesoDenegado):
                trazabilidad.resumen_auditoria(s)

    def test_P02_consulta_exige_motivo_y_queda_registrada_sin_los_valores_filtrados(self):
        for motivo in (None, "", "curiosidad", "INC-20991231-FFFF", "ALERTA-999"):
            with self.assertRaises(ValueError):
                trazabilidad.consultar(self.seguridad, motivo)
        codigo = self.incidente()
        filas = trazabilidad.consultar(self.seguridad, codigo, actor=f"personal:{self.soporte.id}", desde="2026-01-01")
        self.assertTrue(all(f["actor_id"] == self.soporte.id or f["permiso"] == "auth.login" for f in filas))
        registro = self.eventos("auditoria.consultar")[-1]
        self.assertEqual(registro["detalle"], f"motivo={codigo} filtros=actor,desde filas={len(filas)}")
        self.assertEqual(registro["actor_id"], self.seguridad.id)

    def test_P03_anclas_detectan_que_se_borro_el_final_de_la_bitacora(self):
        auditoria.anclar()
        ns.contacto_cliente(self.soporte, self.id_ana)
        auditoria.anclar()
        self.assertTrue(deteccion.verificar_integridad(self.seguridad)["ok"])
        self.assertEqual(oct(os.stat(self.anclas).st_mode & 0o777), "0o600")
        ultimo_id = auditoria.ancla()[0]
        con = db.conectar()                                             # quien tiene el archivo quita el trigger
        con.execute("DROP TRIGGER auditoria_sin_delete")
        con.execute("DELETE FROM auditoria WHERE id >= ?", (ultimo_id - 3,))
        con.commit()
        con.close()
        self.assertTrue(auditoria.verificar_cadena()["ok"])            # la cadena sola no lo ve
        resultado = deteccion.verificar_integridad(self.seguridad)
        self.assertFalse(resultado["ok"])
        self.assertFalse(resultado["anclas"]["ok"])
        self.assertTrue(self.alertas("integridad_auditoria"))

    def test_P04_evidencia_se_elimina_un_año_despues_del_cierre(self):
        viejo, nuevo = self.incidente(), self.incidente()
        for codigo in (viejo, nuevo):
            incidentes.preservar_evidencia(self.seguridad, codigo)
        self.sql("UPDATE incidentes SET fase='cerrado', fecha_cierre=datetime('now','-400 days') WHERE codigo=?", (viejo,))
        self.sql("UPDATE incidentes SET fase='cerrado', fecha_cierre=datetime('now','-10 days') WHERE codigo=?", (nuevo,))
        self.assertEqual(incidentes.purgar_evidencia(self.seguridad), 1)
        self.assertFalse(os.path.exists(os.path.join(incidentes.DIR_EVIDENCIA, viejo)))
        self.assertTrue(os.path.exists(os.path.join(incidentes.DIR_EVIDENCIA, nuevo)))
        self.assertEqual(self.sql("SELECT COUNT(*) FROM incidentes")[0][0], 2)     # el registro del incidente se conserva
        with self.assertRaises(AccesoDenegado):
            incidentes.purgar_evidencia(self.admin)

    def test_P05_alertas_descartadas_siguen_el_plazo_de_la_bitacora(self):
        con = db.conectar()
        con.execute("INSERT INTO alertas (fecha, regla, severidad, descripcion, estado) VALUES "
                    "(datetime('now','-800 days'),'x','baja','vieja','descartada'), "
                    "(datetime('now','-800 days'),'x','alta','vieja escalada','incidente'), "
                    "(datetime('now','-5 days'),'x','baja','reciente','descartada')")
        con.commit()
        con.close()
        ns.purgar_auditoria(self.seguridad)
        self.assertEqual(sorted(f[0] for f in self.sql("SELECT descripcion FROM alertas WHERE regla='x'")),
                         ["reciente", "vieja escalada"])
        self.assertEqual(self.eventos("auditoria.purgar")[-1]["detalle"], "filas=0 alertas=1")


# =====================================================================
class PruebasAlertas(Base7):

    def test_L01_fuera_de_horario(self):
        self.a_las(12, 11)                                           # jueves 11:00: normal
        ns.contacto_cliente(self.soporte, self.id_ana)
        self.assertFalse(self.alertas("fuera_de_horario"))
        self.a_las(13, 3, 10)                                        # viernes 03:10
        ns.contacto_cliente(self.soporte, self.id_ana)
        alerta = self.alertas("fuera_de_horario")
        self.assertEqual(len(alerta), 1)
        self.assertIn("03:10", alerta[0]["descripcion"])
        self.a_las(15, 12)                                           # domingo al mediodía: no hay atención
        ns.direccion_despacho(self.logistica, 1)
        self.assertEqual(self.alertas("fuera_de_horario")[-1]["actor_id"], self.logistica.id)

    def test_L02_red_nueva_para_una_cuenta_del_personal(self):
        self.a_las(12, 9)
        token = auditoria.fijar_contexto("web", "200.27.14.31")
        ns.login_admin("sol_soporte", CLAVE)                          # primera vez con red: no hay base, no alerta
        auditoria.restaurar_contexto(token)
        token = auditoria.fijar_contexto("web", "200.27.14.77")
        ns.login_admin("sol_soporte", CLAVE)                          # misma red /24
        auditoria.restaurar_contexto(token)
        self.assertFalse(self.alertas("red_nueva_personal"))
        token = auditoria.fijar_contexto("web", "181.43.77.201")
        ns.login_admin("sol_soporte", CLAVE)
        auditoria.restaurar_contexto(token)
        alerta = self.alertas("red_nueva_personal")
        self.assertEqual((len(alerta), alerta[0]["severidad"]), (1, "media"))
        self.assertIn("181.43.77.0/24", alerta[0]["descripcion"])
        self.assertNotIn("181.43.77.201", alerta[0]["descripcion"])

    def test_L03_lectura_secuencial(self):
        self.a_las(12, 10)
        for i in range(1, 8):
            ns.registrar_cliente(f"C{i}", f"c{i}@prueba.cl", CLAVE, declara_mayor_edad=True)
        for cid in (1, 3, 5, 7, 9, 2, 4, 6):                           # 8 consultas sin racha de 8
            ns.contacto_cliente(self.soporte, cid)
        self.assertFalse(self.alertas("lectura_secuencial"))
        ns.contacto_cliente(self.soporte, 8)                           # ahora 1..9 están todos
        self.assertEqual(len(self.alertas("lectura_secuencial")), 1)
        self.assertEqual(deteccion._racha_consecutiva([5, 1, 2, 3, 9, 4]), 5)

    def test_L04_direcciones_de_pedidos_ya_entregados(self):
        self.a_las(12, 10)
        for _ in range(3):
            ns.comprar_como_invitado(self.pasarela, "otro@prueba.cl", None, "Calle 1", "4111 1111 1111 1111", "12/28", "1",
                                     [{"producto": "x", "cantidad": 1, "precio": 1}], 1)
        for pid in (2, 3, 4):
            ns.actualizar_estado(self.logistica, pid, "entregado")
        for pid in (2, 3):
            with self.assertRaises(AccesoDenegado):
                ns.direccion_despacho(self.logistica, pid)
        self.assertFalse(self.alertas("direcciones_historicas"))
        with self.assertRaises(AccesoDenegado):
            ns.direccion_despacho(self.logistica, 4)
        self.assertEqual(len(self.alertas("direcciones_historicas")), 1)
        with self.assertRaises(AccesoDenegado):
            ns.direccion_despacho(self.soporte, 1)                      # soporte sin permiso: no es esta regla
        self.assertEqual(len(self.alertas("direcciones_historicas")), 1)

    def test_L05_alertas_altas_avisan_a_la_guardia_sin_detalles(self):
        notificador._BUZON.clear()
        deteccion.crear_alerta("prueba_media", "media", "personal:2 hizo algo")
        self.assertFalse(notificador.mensajes_para(deteccion.GUARDIA_SEGURIDAD))
        n = deteccion.crear_alerta("prueba_alta", "alta", "personal:2 hizo algo")
        aviso = notificador.ultimo_para(deteccion.GUARDIA_SEGURIDAD)
        self.assertIn(f"#{n}", aviso["asunto"])
        self.assertNotIn("personal:2", aviso["asunto"] + aviso["cuerpo"])
        self.assertEqual(self.eventos("alertas.avisar")[-1]["recurso"], str(n))

    def test_L06_las_ventanas_se_miden_desde_el_evento(self):
        # 5 fallos espaciados 4 minutos (16 minutos en total): no es fuerza bruta en 15 minutos
        self.a_las(12, 10)
        for _ in range(5):
            ns.login_cliente("beto@prueba.cl", "Clave#Mala0")
            reloj.avanzar(minutes=4)
        self.assertFalse(self.alertas("fuerza_bruta_cuenta"))


# =====================================================================
class PruebasReconstruccion(Base7):

    def test_R01_reconstruye_accesos_efectivos_y_alcance(self):
        self.a_las(13, 3)
        token = auditoria.fijar_contexto("web", "181.43.77.10")
        intruso = ns.login_admin("lau_logistica", CLAVE)
        ns.direccion_despacho(intruso, 1)
        ns.actualizar_estado(self.logistica, 1, "entregado")
        with self.assertRaises(AccesoDenegado):
            ns.direccion_despacho(intruso, 1)                           # ya entregado: no cuenta como acceso
        with self.assertRaises(AccesoDenegado):
            ns.contacto_cliente(intruso, self.id_ana)                   # sin permiso
        auditoria.restaurar_contexto(token)
        self.a_las(13, 9)
        codigo = self.incidente()
        r = trazabilidad.reconstruir(self.seguridad, codigo, f"personal:{self.logistica.id}", "2026-11-13 05:00:00")
        self.assertTrue(r["confiable"])
        self.assertEqual(r["redes"], ["181.43.77.0/24"])
        self.assertEqual(r["accesos_efectivos"]["despacho.direccion.leer"], ["1"])
        self.assertEqual(r["denegados"], {"despacho.direccion.leer": ["1"], "contacto.cliente.leer": [str(self.id_ana)]})
        self.assertEqual((r["categorias_datos"], r["titulares"]), (["direccion"], ["invitado:pedido1"]))
        self.assertIn(("pedido.estado", "exito"), {(o["permiso"], o["resultado"]) for o in r["otras_operaciones"]})
        self.assertEqual(self.eventos("incidentes.reconstruir")[-1]["detalle"],
                         f"actor=personal:{self.logistica.id} eventos={r['eventos']} recursos=1")
        with self.assertRaises(AccesoDenegado):
            trazabilidad.reconstruir(self.admin, codigo, f"personal:{self.logistica.id}")

    def test_R02_restablecer_clave_del_personal(self):
        token = sesiones.crear(self.soporte)
        ns.restablecer_clave_personal(self.admin, self.soporte.id, "Nueva#Clave2026x")
        self.assertIsNone(sesiones.resolver(token))
        self.assertIsNone(ns.login_admin("sol_soporte", CLAVE))
        self.assertIsNotNone(ns.login_admin("sol_soporte", "Nueva#Clave2026x"))
        self.assertEqual(self.eventos("roles.restablecer_clave")[-1]["detalle"], "sesiones=1")
        self.assertNotIn("Nueva#Clave2026x", json.dumps(self.auditoria_completa()))
        with self.assertRaises(AccesoDenegado):
            ns.restablecer_clave_personal(self.seguridad, self.soporte.id, "Otra#Clave2026x")

    def test_R03_api_y_web_de_la_bitacora(self):
        self.cliente = web.app.test_client()
        self.api = lambda *a, **kw: p5.PruebasElusion.api(self, *a, **kw)
        self.token = lambda **kw: p5.PruebasElusion.token(self, **kw)
        t = self.token(usuario="seba_seguridad", password=CLAVE)
        r = self.api("GET", "/api/v1/auditoria?motivo=revision_periodica&permiso=auth.login", token=t)
        self.assertEqual(r.status_code, 200)
        self.assertTrue(all(e["permiso"] == "auth.login" for e in r.get_json()))
        self.assertEqual(self.api("GET", "/api/v1/auditoria?motivo=revision_periodica&desde=ayer", token=t).status_code, 400)
        t_admin = self.token(usuario="admin_norti", password="Adm!nPanel2026")
        self.assertEqual(self.api("GET", "/api/v1/auditoria/resumen", token=t_admin).status_code, 200)
        self.assertEqual(self.api("GET", "/api/v1/auditoria?motivo=revision_periodica", token=t_admin).status_code, 403)


class PruebaSimulacro(unittest.TestCase):

    def test_S01_simulacro_completo(self):
        """El simulacro termina con código 0 solo si la reconstrucción coincide con lo ocurrido, la bitácora no
        contiene ninguno de los datos ficticios y el recorte de la bitácora se detecta con las anclas."""
        r = subprocess.run([sys.executable, "simulacro_act7.py"], capture_output=True, text=True, timeout=120)
        self.assertEqual(r.returncode, 0, r.stdout[-2000:] + r.stderr[-2000:])
        self.assertIn("reconstruye exactamente", r.stdout)


if __name__ == "__main__":
    unittest.main()
