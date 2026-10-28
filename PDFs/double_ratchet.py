from funciones import DH, GENERATE_DH, KDF_RK, KDF_RK


class DoubleRatchetState:
    def __init__(self):
        self.DHs = None       # Par de claves DH propio (privada, pública)
        self.DHr = None       # Clave pública DH remota recibida
        self.RK = None        # Root Key actual
        self.CKs = None       # Sending Chain Key (Clave de la cadena de envío)
        self.CKr = None       # Receiving Chain Key (Clave de la cadena de recepción)
        self.Ns = 0           # Contador de mensajes enviados en la cadena actual
        self.Nr = 0           # Contador de mensajes recibidos en la cadena actual
        self.PN = 0           # Nº de mensajes enviados en la cadena previa
        self.MKSKIPPED = {}   # Diccionario de claves de mensajes omitidos: {(dh_pub, n): mk}

def init_alice(state, shared_rk, bob_dh_pub_key):
    """
    Inicializa el estado de Alice.
    Alice conoce la clave pública de Bob y realiza el primer paso DH para preparar su CKs.
    """
    state.DHr = GENERATE_DH()
    state.DHr = bob_dh_pub_key

    dh_out = DH(state.Dhs[0], state.DHr)
    state.RK, state.CKs = KDF_RK(shared_rk, dh_out)

    state.CKr = None # Se derivará cuando reciba la respuesta de Bob
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