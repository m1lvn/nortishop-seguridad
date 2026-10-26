# pruebas_seguridad.py
# 26 pruebas automatizadas de los controles de minimización, seudonimización, anonimización,
# RBAC, auditoría y manejo seguro de errores/logs. Usan una base temporal y datos ficticios:
# no tocan nortishop.db.
#
# Ejecutar:  python -m unittest pruebas_seguridad -v

import os
import logging
import sqlite3
import tempfile
import unittest

from cryptography.exceptions import InvalidTag

import cripto
cripto.BCRYPT_COSTO = 4          # solo en las pruebas: bcrypt más rápido (en producción es 12)

import db
from config import LLAVE_PASARELA
from pasarela_simulada import PasarelaPago
import nortishop as ns
from rbac import Sesion, AccesoDenegado, limpiar_texto, log

CLAVE = "Clave#Segura1"
TARJETA = "4111 1111 1111 1111"


class Captura(logging.Handler):
    def __init__(self):
        super().__init__()
        self.lineas = []

    def emit(self, record):
        self.lineas.append(record.getMessage())


class Base(unittest.TestCase):
    def setUp(self):
        fd, self.ruta = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        self._ruta_original = db.RUTA_BD
        db.RUTA_BD = self.ruta
        db.crear_tablas()
        self.pasarela = PasarelaPago(LLAVE_PASARELA)
        # personal: un administrador (primer arranque) y una cuenta por rol
        ns.crear_primer_admin("admin_norti", "Adm!nPanel2026")
        self.admin = ns.login_admin("admin_norti", "Adm!nPanel2026")
        for usuario, rol in [("sol_soporte", "soporte"), ("lau_logistica", "logistica"), ("mar_marketing", "marketing")]:
            ns.crear_admin(self.admin, usuario, CLAVE, rol)
        self.soporte = ns.login_admin("sol_soporte", CLAVE)
        self.logistica = ns.login_admin("lau_logistica", CLAVE)
        self.marketing = ns.login_admin("mar_marketing", CLAVE)
        # clientes: Ana (acepta analítica, con teléfono) y Beto (sin consentimiento)
        self.id_ana = ns.registrar_cliente("Ana Prueba", "ana@prueba.cl", CLAVE, telefono="+56 9 1111 2222",
                                           consentimiento_analitica=True)
        self.id_beto = ns.registrar_cliente("Beto Prueba", "beto@prueba.cl", CLAVE, telefono="+56 9 3333 4444")
        self.ana = ns.login_cliente("ana@prueba.cl", CLAVE)
        self.beto = ns.login_cliente("beto@prueba.cl", CLAVE)
        # un pedido de invitado (id 1)
        ns.comprar_como_invitado(self.pasarela, "invitado@prueba.cl", "+56 9 8765 4321",
                                 "Av. Falsa 123, Santiago", "5555 4444 3333 2222", "05/27", "456",
                                 [{"producto": "Mouse", "cantidad": 1, "precio": 14990}], 14990,
                                 region="Metropolitana de Santiago")

    def tearDown(self):
        db.RUTA_BD = self._ruta_original
        os.remove(self.ruta)

    def sql(self, consulta, params=()):
        con = db.conectar()
        cur = con.execute(consulta, params)
        filas = cur.fetchall()
        con.commit()
        con.close()
        return filas

    def pedido_de_ana(self):
        ns.guardar_tarjeta(self.ana, self.pasarela, TARJETA, "12/28", "123")
        return ns.comprar_con_tarjeta_guardada(self.ana, self.pasarela,
                                               [{"producto": "Audífonos", "cantidad": 1, "precio": 39990}], 39990,
                                               direccion="Av. Los Leones 1234, Providencia",
                                               region="Metropolitana de Santiago")

    def pedido_directo(self, region, estado="pagado"):
        self.sql("""INSERT INTO pedidos (codigo, es_invitado, direccion_cifrado, detalle_cifrado, monto,
                                         token_pasarela, ultimos4, region_envio, estado)
                    VALUES (?,1,'x','x',1000,'tok','1111',?,?)""", (ns._nuevo_codigo_pedido(), region, estado))


class PruebasSeguridad(Base):

    # ---------- Minimización y validación ----------
    def test_T01_registro_con_datos_minimos(self):
        i = ns.registrar_cliente("Carla", "carla@prueba.cl", CLAVE)
        f = self.sql("SELECT telefono_cifrado, direccion_cifrado FROM clientes WHERE id=?", (i,))[0]
        self.assertIsNone(f["telefono_cifrado"])
        self.assertIsNone(f["direccion_cifrado"])

    def test_T02_rut_no_existe(self):
        columnas = [c["name"] for c in self.sql("PRAGMA table_info(clientes)")]
        self.assertNotIn("rut_cifrado", columnas)
        with self.assertRaises(TypeError):
            ns.registrar_cliente("Carla", "carla@prueba.cl", CLAVE, rut="12.345.678-5")

    def test_T03_entradas_invalidas_sin_exponer_valor(self):
        casos = [lambda: ns.registrar_cliente("X", "esto-no-es-correo", CLAVE),
                 lambda: ns.registrar_cliente("X", "x@prueba.cl", "corta1"),
                 lambda: ns.registrar_cliente("X", "x@prueba.cl", CLAVE, telefono="abc-telefono-malo")]
        valores = ["esto-no-es-correo", "corta1", "abc-telefono-malo"]
        for caso, valor in zip(casos, valores):
            with self.assertRaises(ValueError) as cm:
                caso()
            self.assertNotIn(valor, str(cm.exception))

    def test_T04_bd_sin_datos_personales_en_claro(self):
        self.pedido_de_ana()
        con = db.conectar()
        volcado = "\n".join(con.iterdump())
        con.close()
        for dato in ["ana@prueba.cl", "beto@prueba.cl", "invitado@prueba.cl", "+56 9 1111 2222",
                     "+56 9 8765 4321", "Av. Falsa 123", "Av. Los Leones", "Audífonos", "4111 1111", "5555 4444"]:
            self.assertNotIn(dato, volcado)

    def test_T05_cifrado_amarrado_a_la_fila(self):
        tel_ana = self.sql("SELECT telefono_cifrado FROM clientes WHERE id=?", (self.id_ana,))[0][0]
        self.sql("UPDATE clientes SET telefono_cifrado=? WHERE id=?", (tel_ana, self.id_beto))
        with self.assertRaises(InvalidTag):
            ns.contacto_cliente(self.soporte, self.id_beto)

    def test_T06_region_debe_ser_oficial(self):
        self.assertEqual(len(ns.REGIONES), 16)
        with self.assertRaises(ValueError):
            ns.validar_region("Calle Falsa 123, Narnia")
        with self.assertRaises(ValueError):
            ns.comprar_como_invitado(self.pasarela, "z@prueba.cl", None, "Dir 1", "4111111111111111", "12/28",
                                     "123", [], 1000, region="Narnia")
        self.assertEqual(ns.validar_region("Valparaíso"), "Valparaíso")

    # ---------- Autenticación ----------
    def test_T07_login_y_respuestas_uniformes(self):
        self.assertIsInstance(ns.login_cliente("ana@prueba.cl", CLAVE), Sesion)
        mala = ns.login_cliente("ana@prueba.cl", "clave_mala_123")
        inexistente = ns.login_cliente("nadie@prueba.cl", CLAVE)
        self.assertIsNone(mala)
        self.assertEqual(mala, inexistente)
        self.assertIsNone(ns.login_admin("usuario_inexistente", CLAVE))

    def test_T08_bloqueo_tras_5_intentos(self):
        for _ in range(ns.MAX_INTENTOS):
            self.assertIsNone(ns.login_cliente("beto@prueba.cl", "incorrecta_1234"))
        self.assertIsNone(ns.login_cliente("beto@prueba.cl", CLAVE))       # correcta, pero bloqueada
        for _ in range(ns.MAX_INTENTOS):
            ns.login_admin("sol_soporte", "incorrecta_1234")
        self.assertIsNone(ns.login_admin("sol_soporte", CLAVE))

    def test_T09_primer_admin_solo_una_vez(self):
        with self.assertRaises(RuntimeError):
            ns.crear_primer_admin("otro_admin", "Adm!nPanel2026")

    def test_T10_sesiones_invalidas(self):
        invalidas = [None, {"tipo": "personal", "id": 1, "rol": "administrador"},
                     Sesion("personal", 1, "superadmin"), Sesion("cliente", 1, "administrador"),
                     Sesion("personal", 1, "cliente")]
        for s in invalidas:
            with self.assertRaises(AccesoDenegado):
                ns.resumen_pedidos(s)

    # ---------- RBAC ----------
    def test_T11_cliente_solo_ve_lo_suyo(self):
        self.assertEqual(ns.obtener_datos_cliente(self.ana, self.id_ana)["correo"], "ana@prueba.cl")
        with self.assertRaises(AccesoDenegado):
            ns.obtener_datos_cliente(self.ana, self.id_beto)
        with self.assertRaises(AccesoDenegado):
            ns.historial_compras(self.ana, self.id_beto)

    def test_T12_logistica_direccion_solo_envios_activos(self):
        self.assertEqual(ns.direccion_despacho(self.logistica, 1), "Av. Falsa 123, Santiago")
        with self.assertRaises(AccesoDenegado):
            ns.datos_contacto_invitado(self.logistica, 1)
        ns.actualizar_estado(self.logistica, 1, "entregado")
        with self.assertRaises(AccesoDenegado):
            ns.direccion_despacho(self.logistica, 1)

    def test_T13_soporte_contacto_sin_direccion(self):
        self.assertEqual(ns.datos_contacto_invitado(self.soporte, 1)["correo"], "invitado@prueba.cl")
        c = ns.contacto_cliente(self.soporte, self.id_ana)
        self.assertNotIn("direccion", c)
        for fila in ns.resumen_pedidos(self.soporte):
            self.assertEqual(set(fila), {"codigo", "monto", "estado", "fecha"})
        with self.assertRaises(AccesoDenegado):
            ns.direccion_despacho(self.soporte, 1)

    def test_T14_marketing_boletin_y_reportes_no_contactos(self):
        ns.suscribir_boletin("lector@prueba.cl")
        self.assertIn("lector@prueba.cl", ns.correos_para_envio_boletin(self.marketing))
        ns.reporte_ventas(self.marketing)
        for f in (ns.datos_contacto_invitado, ns.direccion_despacho):
            with self.assertRaises(AccesoDenegado):
                f(self.marketing, 1)
        with self.assertRaises(AccesoDenegado):
            ns.contacto_cliente(self.marketing, self.id_ana)

    def test_T15_administrador_no_lee_datos_personales(self):
        ns.crear_admin(self.admin, "nuevo_soporte", CLAVE)             # rol por defecto: soporte
        self.assertEqual(self.sql("SELECT rol FROM administradores WHERE usuario='nuevo_soporte'")[0][0], "soporte")
        with self.assertRaises(AccesoDenegado):
            ns.datos_contacto_invitado(self.admin, 1)
        with self.assertRaises(AccesoDenegado):
            ns.contacto_cliente(self.admin, self.id_ana)
        with self.assertRaises(AccesoDenegado):
            ns.direccion_despacho(self.admin, 1)
        with self.assertRaises(AccesoDenegado):
            ns.correos_para_envio_boletin(self.admin)
        with self.assertRaises(AccesoDenegado):
            ns.leer_analitica(self.admin)

    def test_T16_solo_admin_crea_cuentas_y_lee_auditoria(self):
        for s in (self.soporte, self.logistica, self.marketing, self.ana):
            with self.assertRaises(AccesoDenegado):
                ns.crear_admin(s, "intruso", CLAVE, "administrador")
            with self.assertRaises(AccesoDenegado):
                ns.leer_auditoria(s)

    def test_T17_inexistente_y_no_autorizado_dan_el_mismo_error(self):
        errores = []
        for pedido in (1, 9999):
            with self.assertRaises(AccesoDenegado) as cm:
                ns.direccion_despacho(self.soporte, pedido)            # no autorizado (rol)
            errores.append(str(cm.exception))
        ns.actualizar_estado(self.logistica, 1, "entregado")
        for pedido in (1, 9999):
            with self.assertRaises(AccesoDenegado) as cm:
                ns.direccion_despacho(self.logistica, pedido)          # entregado vs inexistente
            errores.append(str(cm.exception))
        self.assertEqual(set(errores), {"Acceso denegado"})

    # ---------- Seudonimización, anonimización, retención ----------
    def test_T18_comportamiento_exige_consentimiento(self):
        self.assertFalse(ns.guardar_comportamiento(self.id_beto, {"categorias": ["moda"]}))
        self.assertTrue(ns.guardar_comportamiento(self.id_ana, {"categorias": ["tecnologia"]}))
        self.assertEqual(self.sql("SELECT COUNT(*) FROM comportamiento_compra")[0][0], 1)

    def test_T19_comportamiento_seudonimizado(self):
        columnas = [c["name"] for c in self.sql("PRAGMA table_info(comportamiento_compra)")]
        self.assertNotIn("cliente_id", columnas)
        ns.guardar_comportamiento(self.id_ana, {"categorias": ["tecnologia"]})
        filas = ns.leer_analitica(self.marketing)
        self.assertEqual(len(filas), 1)
        self.assertEqual(set(filas[0]), {"seudonimo", "datos"})
        self.assertEqual(filas[0]["seudonimo"], ns.seudonimo_cliente(self.id_ana))
        self.assertEqual(len(filas[0]["seudonimo"]), 64)

    def test_T20_reporte_k_anonimato(self):
        for _ in range(5):
            self.pedido_directo("Biobío")
        for _ in range(2):
            self.pedido_directo("Aysén")
        reporte = ns.reporte_ventas(self.marketing)
        regiones = {f["region"] for f in reporte}
        self.assertIn("Biobío", regiones)
        self.assertNotIn("Aysén", regiones)
        for f in reporte:
            self.assertEqual(set(f), {"mes", "region", "pedidos", "total"})

    def test_T21_retencion_borra_direccion_y_contacto(self):
        ns.actualizar_estado(self.logistica, 1, "entregado")
        self.sql("UPDATE pedidos SET fecha='2024-01-15 10:00:00' WHERE id=1")        # pedido antiguo
        self.pedido_de_ana()
        self.sql("UPDATE pedidos SET estado='entregado' WHERE id=2")                 # entregado hace poco
        n = ns.aplicar_retencion(self.admin, 365)
        self.assertEqual(n, 1)
        viejo = self.sql("SELECT direccion_cifrado, invitado_correo_cifrado, invitado_telefono_cifrado FROM pedidos WHERE id=1")[0]
        self.assertEqual(tuple(viejo), (None, None, None))
        reciente = self.sql("SELECT direccion_cifrado FROM pedidos WHERE id=2")[0][0]
        self.assertIsNotNone(reciente)

    def test_T22_derecho_de_supresion(self):
        self.pedido_de_ana()
        ns.guardar_comportamiento(self.id_ana, {"categorias": ["audio"]})
        with self.assertRaises(AccesoDenegado):
            ns.eliminar_cuenta(self.beto, self.id_ana)                               # no puede borrar la ajena
        ns.eliminar_cuenta(self.ana, self.id_ana)
        self.assertEqual(self.sql("SELECT COUNT(*) FROM clientes WHERE id=?", (self.id_ana,))[0][0], 0)
        self.assertEqual(self.sql("SELECT COUNT(*) FROM tarjetas_guardadas")[0][0], 0)
        self.assertEqual(self.sql("SELECT COUNT(*) FROM comportamiento_compra")[0][0], 0)
        p = self.sql("SELECT cliente_id, direccion_cifrado, monto FROM pedidos WHERE id=2")[0]
        self.assertIsNone(p["cliente_id"])
        self.assertIsNone(p["direccion_cifrado"])
        self.assertEqual(p["monto"], 39990)                                          # lo contable se conserva

    # ---------- Auditoría y logs ----------
    def test_T23_bitacora_registra_accesos_sin_datos_personales(self):
        ns.direccion_despacho(self.logistica, 1)
        with self.assertRaises(AccesoDenegado):
            ns.direccion_despacho(self.soporte, 1)
        filas = ns.leer_auditoria(self.admin)
        resultados = {(f["rol"], f["permiso"], f["resultado"]) for f in filas}
        self.assertIn(("logistica", "despacho.direccion.leer", "permitido"), resultados)
        self.assertIn(("soporte", "despacho.direccion.leer", "denegado"), resultados)
        texto = str(filas)
        for dato in ["prueba.cl", "Av. Falsa", "+56 9"]:
            self.assertNotIn(dato, texto)

    def test_T24_bitacora_inmutable(self):
        ns.resumen_pedidos(self.soporte)
        con = db.conectar()
        with self.assertRaises(sqlite3.DatabaseError):
            con.execute("UPDATE auditoria SET resultado='denegado'")
        with self.assertRaises(sqlite3.DatabaseError):
            con.execute("DELETE FROM auditoria")
        con.close()

    def test_T25_filtro_de_logs(self):
        captura = Captura()
        log.addHandler(captura)
        log.setLevel(logging.INFO)
        try:
            log.info("correo juan.soto@gmail.com rut 12.345.678-5 tarjeta 4111 1111 1111 1111")
        finally:
            log.removeHandler(captura)
        linea = captura.lineas[0]
        self.assertIn("j***@gmail.com", linea)
        self.assertIn("[RUT]", linea)
        self.assertIn("[TARJETA]", linea)
        for crudo in ["juan.soto", "12.345.678-5", "4111 1111"]:
            self.assertNotIn(crudo, linea)
        self.assertNotIn("@", limpiar_texto("a@b.cl").replace("***@", ""))

    def test_T26_registro_y_login_no_dejan_correos_en_logs(self):
        captura = Captura()
        log.addHandler(captura)
        log.setLevel(logging.INFO)
        try:
            i = ns.registrar_cliente("Diego", "diego.log@prueba.cl", CLAVE)
            ns.login_cliente("diego.log@prueba.cl", CLAVE)
            for _ in range(ns.MAX_INTENTOS):
                ns.login_cliente("diego.log@prueba.cl", "incorrecta_1234")
        finally:
            log.removeHandler(captura)
        todo = "\n".join(captura.lineas)
        self.assertIn(f"cliente registrado id={i}", todo)
        self.assertIn("cuenta bloqueada temporalmente", todo)
        self.assertNotIn("diego.log", todo)
        self.assertNotIn("@", todo)


if __name__ == "__main__":
    unittest.main(verbosity=2)
