# NortiShop – Protección de datos personales (Actividad N°2, Item II)

Implementación en Python de hashing, cifrado y tokenización para los datos personales y financieros del caso NortiShop (comercio electrónico).

**Ramo:** Seguridad y Protección de Datos – Universidad del Desarrollo
**Integrantes:** Ignacia Castillo, Milan Kurte, Francisco Polo

## Qué se protege y cómo

| Técnica | Campos | Cómo se recupera o valida |
|---|---|---|
| **Hashing** bcrypt (costo 12, salt único) | Contraseña del cliente y del administrador | No se recupera: se valida con `bcrypt.checkpw()` |
| **Cifrado** AES-256-GCM | Correo, RUT, teléfono, direcciones, datos del invitado, historial, boletín, comportamiento de compra | Se descifra con la llave del `.env`, solo cuando se necesita |
| **Tokenización** (pasarela de pago) | Número de tarjeta (guardada y de invitado) | NortiShop nunca lo tiene: cobra con el token |
| **Índice HMAC-SHA256** | Correo (cliente y boletín) | Permite buscar por correo sin descifrar la tabla |
| **Firma HMAC-SHA256** | Respuesta de la pasarela | Se verifica la firma, el pedido y el monto antes de registrar el pedido |

Detalles del cifrado:
- **Contexto (AAD):** cada valor cifrado queda amarrado a su tabla, columna y fila (p. ej. `pedidos.direccion:NS-…`). Si se copia a otra fila, el descifrado falla.
- **Versión de llave:** cada valor se guarda como `v1:<base64>`. Para rotar se agrega `NORTISHOP_LLAVE_CIFRADO_V2` al `.env`: los datos nuevos se cifran con v2 y los antiguos se siguen leyendo con v1.

## Requisitos
- Python 3.10 o superior
- Dependencias: `pip install -r requirements.txt` (se recomienda un entorno virtual: `python -m venv .venv`)

## Cómo ejecutar (en este orden)
```
python generar_llaves.py      # 1. crea el .env con llaves aleatorias (solo la primera vez)
python demo.py                # 2. recrea la BD con datos de prueba y muestra cómo se valida/recupera cada campo
python ver_bd.py              # 3. muestra la base de datos en crudo (datos protegidos)
python verificar_secretos.py  # 4. revisa que las llaves no queden expuestas
```
`demo.py` borra y vuelve a crear la base de datos, por eso va antes que `ver_bd.py` y `verificar_secretos.py`.

## Variables de entorno (`.env`)
| Variable | Uso |
|---|---|
| `NORTISHOP_LLAVE_CIFRADO_V1` | Llave AES-256 para cifrar (versionada: `_V2`, `_V3`… para rotar) |
| `NORTISHOP_LLAVE_INDICE` | Llave del índice de búsqueda HMAC |
| `NORTISHOP_LLAVE_PASARELA` | Secreto compartido con la pasarela para verificar sus respuestas |
| `NORTISHOP_RUTA_BD` | Ruta de la base de datos SQLite |

`.env.example` tiene los nombres sin valores reales. El `.env` lo crea `generar_llaves.py` con permisos 600.

## Archivos
| Archivo | Qué hace |
|---|---|
| `config.py` | Lee las llaves desde el `.env`; si falta una, el programa no parte |
| `cripto.py` | bcrypt, AES-256-GCM con contexto y versión de llave, índice HMAC, firma de pagos y enmascarado |
| `db.py` | Estructura de la base de datos SQLite |
| `nortishop.py` | Funciones del sistema: registro, login, compras, despacho, boletín, etc. |
| `pasarela_simulada.py` | Simula la pasarela de pago: tokeniza tarjetas y firma sus respuestas |
| `generar_llaves.py` | Genera las llaves aleatorias de 256 bits y crea el `.env` |
| `demo.py` | Prueba de funcionamiento y pruebas de seguridad |
| `ver_bd.py` | Muestra la BD tal como quedó guardada |
| `verificar_secretos.py` | Comprueba que las llaves no quedan expuestas y que no hay datos personales en claro |
| `.env.example` | Plantilla de variables sin valores reales |
| `.gitignore` | Excluye `.env`, `*.db`, `__pycache__/` y `.venv/` del repositorio |
| `evidencia/` | Salida de cada script y capturas usadas en el informe |
| `docs/` | PDF de los entregables: cuadro del Item I e informe del Item II |

## Entregables
- [`docs/Actividad2_Item1_NortiShop.pdf`](docs/Actividad2_Item1_NortiShop.pdf) – Item I: cuadro de protección de datos personales y financieros.
- [`docs/Actividad2_Item2_NortiShop.pdf`](docs/Actividad2_Item2_NortiShop.pdf) – Item II: implementación, evidencia y explicación de cómo se recupera o valida cada dato.

## Evidencia
| Archivo | Figura del informe (Item II) | Qué muestra |
|---|---|---|
| `evidencia/ev_demo.txt`, `cap_demo_1.png` | Figura 1 | Registro, validación de contraseñas y recuperación de datos (secciones 1–3 de la demo) |
| `evidencia/ev_demo.txt`, `cap_demo_2.png` | Figura 2 | Tokenización, historial, marketing y pruebas de seguridad (secciones 4–7) |
| `evidencia/ev_bd.txt`, `cap_bd_1.png` | Figura 3 | Tablas `clientes`, `tarjetas_guardadas` y `pedidos` en crudo |
| `evidencia/ev_bd.txt`, `cap_bd_2.png` | Figura 4 | Tablas `administradores`, `boletin_suscriptores` y `comportamiento_compra` en crudo |
| `evidencia/ev_secretos.txt`, `cap_secretos.png` | Figura 5 | Resultado de `verificar_secretos.py` |
| `evidencia/ev_git.txt`, `cap_git.png` | Figura 6 | `.env` y la BD fuera del repositorio |

El archivo `.env` y la base de datos `nortishop.db` NO se incluyen en el repositorio.
Todos los datos de la demo son ficticios.
