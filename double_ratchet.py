import json
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from funciones import DECRYPT, DH, ENCRYPT, GENERATE_DH, KDF_CK, KDF_RK, KDF_RK
from cryptography.hazmat.primitives import serialization


class DoubleRatchetState:
    def __init__(self):
        self.DHs = None  # Par de claves DH propio (privada, pública)
        self.DHr = None  # Clave pública DH remota recibida
        self.RK = None  # Root Key actual
        self.CKs = None  # Sending Chain Key (Clave de la cadena de envío)
        self.CKr = None  # Receiving Chain Key (Clave de la cadena de recepción)
        self.Ns = 0  # Contador de mensajes enviados en la cadena actual
        self.Nr = 0  # Contador de mensajes recibidos en la cadena actual
        self.PN = 0  # Nº de mensajes enviados en la cadena previa
        self.MKSKIPPED = (
            {}
        )  # Diccionario de claves de mensajes omitidos: {(dh_pub, n): mk}


def serialize_public_key(pub_key) -> str:
    """Convierte la clave pública X25519 a un String hexadecimal para transmisión."""
    raw_bytes = pub_key.public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    return raw_bytes.hex()


def deserialize_public_key(pub_hex: str):
    """Reconstruye la clave pública X25519 desde un String hexadecimal."""
    raw_bytes = bytes.fromhex(pub_hex)
    return X25519PublicKey.from_public_bytes(raw_bytes)


def init_alice(state, shared_rk, bob_dh_pub_key):
    """
    Inicializa el estado de Alice.
    Alice conoce la clave pública de Bob y realiza el primer paso DH para preparar su CKs.
    """
    state.DHs = GENERATE_DH()
    state.DHr = bob_dh_pub_key

    dh_out = DH(
        state.DHs[0], state.DHr
    )  # calcula el secreto con su privada y la publica de bob
    state.RK, state.CKs = KDF_RK(shared_rk, dh_out)

    state.CKr = None  # Se derivará cuando reciba la respuesta de Bob
    state.Ns = 0
    state.Nr = 0
    state.PN = 0
    state.MKSKIPPED = {}


def init_bob(state, shared_rk, bob_dh_pair):
    """
    Inicializa el estado de Bob.
    Bob arranca a la espera del primer mensaje de Alice.
    """
    state.DHs = bob_dh_pair
    state.DHr = None
    state.RK = shared_rk
    state.CKs = None
    state.CKr = None
    state.Ns = 0
    state.Nr = 0
    state.PN = 0
    state.MKSKIPPED = {}


def dh_ratchet(state, remote_dh_pub):
    """
    Realiza el ratchet DH cuando se recibe una nueva clave pública remota.
    """
    state.PN = state.Ns
    state.Ns = 0
    state.Nr = 0
    state.DHr = remote_dh_pub

    state.RK, state.CKr = KDF_RK(state.RK, DH(state.DHs[0], state.DHr))

    state.DHs = GENERATE_DH()

    state.RK, state.CKs = KDF_RK(state.RK, DH(state.DHs[0], state.DHr))


def ratchet_encrypt(state: DoubleRatchetState, plaintext):
    """
    Avanza la cadena de envío (Symmetric Ratchet) y cifra el mensaje.
    Devuelve un paquete listo para enviar por MQTT.
    """
    state.CKs, mk = KDF_CK(state.CKs)

    header = {"dh": serialize_public_key(state.DHs[1]), "pn": state.PN, "n": state.Ns}
    state.Ns += 1

    # Usa la cabecera codificada como Datos Asociados (AD) para el AEA
    ad = json.dumps(header, sort_keys=True).encode("utf-8")
    ciphertext = ENCRYPT(mk, plaintext, associated_data=ad)

    return {"header": header, "ciphertext": ciphertext.hex()}


def ratchet_decrypt(state: DoubleRatchetState, packet):
    """
    Procesa un paquete entrante: actualiza claves si hay cambio DH,
    avanza la cadena de recepción y descifra el texto.
    """
    header = packet["header"]
    ciphertext = bytes.fromhex(packet["ciphertext"])
    remote_dh_pub = deserialize_public_key(header["dh"])
    ad = json.dumps(header, sort_keys=True).encode("utf-8")

    # Si la clave pública en la cabecera es distinta a la que teníamos, se activa el DH Ratchet
    if state.DHr is None or remote_dh_pub.public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    ) != state.DHr.public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    ):
        dh_ratchet(state, remote_dh_pub)

    state.CKr, mk = KDF_CK(state.CKr)
    state.Nr += 1

    plaintext = DECRYPT(mk, ciphertext, ad)
    return plaintext