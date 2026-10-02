# NortiShop – Protección de datos sensibles (Actividad N°2, Item II)

Implementación en Python de hashing, cifrado y tokenización para los campos sensibles del caso NortiShop.

## Requisitos
- Python 3.10 o superior
- `pip install -r requirements.txt`

## Cómo ejecutar
```
python generar_llaves.py      # crea el .env con llaves aleatorias (solo la primera vez)
python demo.py                # carga datos de prueba y muestra cómo se valida/recupera cada campo
python ver_bd.py              # muestra la base de datos en crudo (datos protegidos)
python verificar_secretos.py  # revisa que las llaves no queden expuestas
```

## Archivos
| Archivo | Qué hace |
|---|---|
| config.py | Lee las llaves desde variables de entorno (.env) |
| cripto.py | bcrypt, AES-256-GCM, índice HMAC y enmascarado |
| pasarela_simulada.py | Simula la pasarela de pago que entrega los tokens |
| db.py | Estructura de la base de datos SQLite |
| nortishop.py | Funciones del sistema (registro, login, compras, boletín, etc.) |
| demo.py | Prueba de funcionamiento |
| ver_bd.py | Muestra la BD tal como quedó guardada |
| verificar_secretos.py | Prueba de que las llaves no quedan expuestas |

El archivo `.env` y la base de datos `nortishop.db` NO se incluyen (están en `.gitignore`).
Todos los datos de la demo son ficticios.
