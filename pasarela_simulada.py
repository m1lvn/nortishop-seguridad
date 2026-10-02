# pasarela_simulada.py
# Simula la pasarela de pago externa (tipo Transbank / Stripe).
# En la vida real esto es un servicio de un tercero: NortiShop le manda la
# tarjeta UNA vez y recibe de vuelta un token. El número real queda guardado
# solo en la bóveda de la pasarela, nunca en la base de datos de NortiShop.

import secrets


class PasarelaPago:
    def __init__(self):
        # "bóveda" de la pasarela: vive fuera de NortiShop (aquí, solo en memoria)
        self._boveda = {}

    def tokenizar(self, numero_tarjeta, vencimiento, cvv):
        """Recibe la tarjeta y devuelve un token + los últimos 4 dígitos."""
        numero = numero_tarjeta.replace(" ", "")
        if not numero.isdigit() or not (13 <= len(numero) <= 19):
            raise ValueError("Número de tarjeta inválido")
        token = "tok_" + secrets.token_hex(12)
        # el CVV no se guarda nunca, ni siquiera en la pasarela (norma PCI)
        self._boveda[token] = {"numero": numero, "vencimiento": vencimiento}
        return {"token": token, "ultimos4": numero[-4:], "marca": self._marca(numero)}

    def cobrar(self, token, monto):
        """Cobra usando el token. NortiShop nunca necesita el número real."""
        if token not in self._boveda:
            return {"aprobado": False, "codigo": "TOKEN_INVALIDO"}
        return {"aprobado": True, "codigo": "APROBADO", "autorizacion": secrets.token_hex(4).upper(), "monto": monto}

    @staticmethod
    def _marca(numero):
        if numero.startswith("4"):
            return "VISA"
        if numero[:2] in ("51", "52", "53", "54", "55"):
            return "MASTERCARD"
        return "OTRA"
