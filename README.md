# NortiShop – Protección de datos personales

Implementación en Python de los controles de protección de datos del caso NortiShop (comercio electrónico):
- **Actividad 2:** hashing, cifrado y tokenización.
- **Actividad 4:** minimización, seudonimización, anonimización y RBAC.
- **Actividad 5:** consentimiento por finalidad, ejercicio de derechos, auditoría protegida y respuesta a incidentes, con una interfaz web y una API.

**Ramo:** Seguridad y Protección de Datos – Universidad del Desarrollo
**Integrantes:** Ignacia Castillo, Milan Kurte, Francisco Polo

## Qué se protege y cómo

| Técnica | Campos | Cómo se recupera o valida |
|---|---|---|
| **Hashing** bcrypt (costo 12, salt único) | Contraseña del cliente y del personal | No se recupera: se valida con `bcrypt.checkpw()` |
| **Cifrado** AES-256-GCM | Correo, teléfono, direcciones, datos del invitado, historial, boletín, comportamiento de compra, valores de una rectificación en curso | Se descifra con la llave del `.env`, solo cuando se necesita |
| **Tokenización** (pasarela de pago) | Número de tarjeta (guardada y de invitado) | NortiShop nunca lo tiene: cobra con el token |
| **Índice HMAC-SHA256** | Correo (cliente y boletín), seudónimo, códigos de verificación | Permite buscar o comparar sin guardar el valor |
| **Firma HMAC-SHA256** | Respuesta de la pasarela | Se verifica la firma, el pedido y el monto antes de registrar el pedido |
| **Cadena HMAC-SHA256** | Bitácora de auditoría | Cada registro incluye el hash del anterior: alterar, borrar o insertar filas rompe la cadena |

Detalles del cifrado:
- **Contexto (AAD):** cada valor cifrado queda amarrado a su tabla, columna y fila (p. ej. `pedidos.direccion:NS-…`). Si se copia a otra fila, el descifrado falla.
- **Versión de llave:** cada valor se guarda como `v1:<base64>`. Para rotar se ejecuta `generar_llaves.py --rotar` y luego `rotar_llaves.py`.

## Actividad 5: módulos

| Módulo | Qué implementa |
|---|---|
| `consentimiento.py` | Finalidades independientes (`boletin`, `analitica_comportamiento`, `ofertas_personalizadas`; `compra` se basa en el contrato). Textos versionados con hash. Historial solo de agregar (triggers). La revocación tiene efecto inmediato. Baja del boletín con enlace. |
| `derechos.py` | Acceso, portabilidad (JSON), rectificación y supresión. Flujo `recibida → verificada → en_evaluacion → ejecutada/rechazada → cerrada`, con fechas y plazo de 30 días. La identidad se verifica con la contraseña más un código de un solo uso enviado al correo. |
| `auditoria.py` | Único punto de escritura de la bitácora: categoría, canal, IP truncada y cadena HMAC con llave propia. Verificación de integridad y purga por plazo (2 años). |
| `rbac.py` | Matriz de permisos con los roles `privacidad` y `seguridad`. Cada sesión se valida contra la base: la cuenta debe estar habilitada, tener ese rol hoy y no tener el permiso suspendido. |
| `deteccion.py` | Reglas que generan alertas: fuerza bruta, relleno de credenciales, exportaciones anómalas, cambio de correo seguido de exportación, consultas masivas, denegaciones repetidas, cuentas privilegiadas e integridad de la bitácora. |
| `incidentes.py` | Fases del incidente, contención (revocar sesiones, deshabilitar cuentas, suspender permisos), preservación de evidencia, recifrado, comprobaciones de recuperación y borrador de notificación. |
| `sesiones.py` | Tokens de 256 bits; en la base solo se guarda su SHA-256. Expiran a los 30 minutos y se pueden revocar. |
| `app.py`, `templates/`, `static/` | Pantallas web (cookie segura + CSRF) y API JSON `/api/v1` (solo Bearer). Usan las mismas funciones de servicio, así que los controles no se pueden eludir llamando directo a la API. |
| `notificador.py` | Correo **simulado** (buzón en memoria): el proyecto no tiene servidor SMTP. |

## Requisitos
- Python 3.10 o superior
- Dependencias: `pip install -r requirements.txt` (se recomienda un entorno virtual: `python -m venv .venv`)

## Cómo ejecutar
```
python generar_llaves.py                       # 1. crea el .env (o agrega las llaves que falten)
python -m unittest pruebas_seguridad pruebas_actividad5 -v   # 2. pruebas (base temporal)
python demo.py                                 # 3. demo de las actividades 2 y 4 (recrea nortishop.db)
python evidencia_act5.py                       # 4. evidencia de la actividad 5 (base temporal)
python ver_bd.py                               # 5. base de datos en crudo
python verificar_secretos.py                   # 6. llaves no expuestas, base sin datos en claro, bitácora íntegra
```
Aplicación web (datos ficticios):
```
python demo_web.py                             # recrea nortishop.db con cuentas de cada rol
NORTISHOP_MODO_DEMO=1 flask --app app run      # http://localhost:5000  (personal: /personal/login)
```
`NORTISHOP_MODO_DEMO=1` habilita la página "Buzón (demo)", que reemplaza al correo para leer los códigos de verificación.

## Variables de entorno (`.env`)
| Variable | Uso |
|---|---|
| `NORTISHOP_LLAVE_CIFRADO_V1` | Llave AES-256 para cifrar (versionada: `_V2`, `_V3`… para rotar) |
| `NORTISHOP_LLAVE_INDICE` | Llave HMAC del índice de búsqueda, seudónimos y códigos de verificación |
| `NORTISHOP_LLAVE_PASARELA` | Secreto compartido con la pasarela para verificar sus respuestas |
| `NORTISHOP_LLAVE_AUDITORIA` | Llave HMAC de la cadena de la bitácora de auditoría |
| `NORTISHOP_RUTA_BD` | Ruta de la base de datos SQLite |
| `NORTISHOP_MODO_DEMO` | `1` muestra el buzón simulado en la web (solo demostración) |
| `NORTISHOP_DIR_EVIDENCIA` | Carpeta de las copias preservadas en incidentes (por defecto `evidencia_incidentes/`) |

`.env.example` tiene los nombres sin valores reales. El `.env` lo crea `generar_llaves.py` con permisos 600.

## Archivos
| Archivo | Qué hace |
|---|---|
| `config.py` | Lee las llaves desde el `.env`; si falta una, el programa no parte |
| `cripto.py` | bcrypt, AES-256-GCM con contexto y versión de llave, índice HMAC, firma de pagos y enmascarado |
| `db.py` | Esquema SQLite, restricciones `CHECK` y triggers (historial de consentimientos y bitácora inmutables) |
| `nortishop.py` | Funciones del sistema: registro, login con bloqueo, compras, despacho, boletín, retención, supresión |
| `rbac.py` | Roles, permisos, `@requiere_permiso` y filtro de logs |
| `consentimiento.py`, `derechos.py`, `auditoria.py`, `deteccion.py`, `incidentes.py`, `sesiones.py`, `notificador.py` | Módulos de la Actividad 5 (ver tabla anterior) |
| `app.py`, `templates/`, `static/` | Interfaz web y API JSON |
| `pasarela_simulada.py` | Simula la pasarela de pago: tokeniza, firma sus respuestas y borra tokens |
| `generar_llaves.py` | Genera las llaves de 256 bits (y la versión nueva con `--rotar`) |
| `rotar_llaves.py` | Recifra todos los datos con la llave más reciente (recuperación ante incidentes) |
| `pruebas_seguridad.py` | 26 pruebas de la Actividad 4 |
| `pruebas_actividad5.py` | 47 pruebas de la Actividad 5: consentimiento (C), derechos (D), auditoría (A), incidentes (I) e intentos de elusión (W) |
| `demo.py`, `evidencia_rbac.py` | Demostraciones de las actividades 2 y 4 |
| `evidencia_act5.py` | Genera la evidencia de la Actividad 5 en `evidencia/ev_act5_*.txt` |
| `demo_web.py` | Carga cuentas y pedidos ficticios para usar la web |
| `ver_bd.py` | Muestra la BD tal como quedó guardada |
| `verificar_secretos.py` | Comprueba llaves, permisos, ausencia de datos en claro y la integridad de la bitácora |
| `evidencia/` | Salidas de los scripts y capturas de los informes |
| `docs/` | PDF de los entregables |

## Entregables
- [`docs/Actividad2_Item1_NortiShop.pdf`](docs/Actividad2_Item1_NortiShop.pdf) – Actividad 2, Item I.
- [`docs/Actividad2_Item2_NortiShop.pdf`](docs/Actividad2_Item2_NortiShop.pdf) – Actividad 2, Item II.
- [`docs/Informe Técnico Nortishop.pdf`](docs/Informe%20Técnico%20Nortishop.pdf) – Actividad 4: rediseño, seudonimización, anonimización y RBAC.
- [`docs/Actividad5_NortiShop.pdf`](docs/Actividad5_NortiShop.pdf) – Actividad 5: consentimiento, derechos, auditoría, plan de respuesta a incidentes e implementación.

## Evidencia
- `ev_demo.txt`, `ev_bd.txt`, `ev_secretos.txt`, `ev_git.txt` y `cap_*.png` (sin `act5`): figuras del informe de la Actividad 2.
- `ev_act5_*.txt` y `ev_act5_exportacion.json`: salida de `evidencia_act5.py` (consentimiento, derechos, detección e incidente, intentos de elusión y auditoría).
- `ev_act5_pruebas.txt`: ejecución de las 73 pruebas (`-v`). `ev_act5_exportacion_web.json`: copia descargada desde la web.
- `cap_act5_*.png`: capturas de la aplicación web, en el orden del recorrido (registro, consentimientos, derechos, privacidad, seguridad y contención).

El archivo `.env`, la base de datos `nortishop.db` y la carpeta `evidencia_incidentes/` NO se incluyen en el repositorio.
Todos los datos de las demos son ficticios.
