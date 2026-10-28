import hmac
import os
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def GENERATE_DH():
    """Genera un nuevo par de claves Diffie-Hellman (X25519)."""
    private_key = x25519.X25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key

def DH(dh_pair, dh_pub):
    """Calcula el secreto compartido a partir de tu clave privada y la pública remota."""
    private_key = dh_pair
    shared_key = private_key.exchange(dh_pub)
    return shared_key

def KDF_RK(rk, dh_out):
    """
    Usa HKDF para derivar una nueva Root Key y la Chain Key inicial 
    de la cadena de envío/recepción.
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=64,
        salt=rk,
        info=b'DoubleRatchetRootChain',
    )
    derived_material = hkdf.derive(dh_out)
    new_rk = derived_material[:32]
    new_ck = derived_material[32:]
    return new_rk, new_ck

def KDF_CK(ck):
    """
    Usa HMAC para derivar la Message Key y la siguiente Chain Key.
    """
    
    # HMAC usando 0x01 para la Message Key
    h_mk = hmac.HMAC(ck, hashes.SHA256())
    h_mk.update(b"\x01")
    mk = h_mk.finalize()

    # HMAC usando 0x02 para la siguiente Chain Key
    h_ck = hmac.HMAC(ck, hashes.SHA256())
    h_ck.update(b"\x02")
    next_ck = h_ck.finalize()

    return next_ck, mk


def ENCRYPT(mk, plaintext, associated_data=b""):
    """Cifra el mensaje usando AES-GCM con clave de 128 bits"""
    # AES-GCM de 128 bits requiere una clave de 16 bytes. 
    # Truncamos los 32 bytes del HMAC a 16 bytes.
    aesgcm = AESGCM(mk[:16])
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)
    # Devolvemos el nonce concatenado al ciphertext para poder descifrar
    return nonce + ciphertext


def DECRYPT(mk, ciphertext_with_nonce, associated_data=b""):
    """Descifra el mensaje validando su integridad mediante AES-GCM."""
    aesgcm = AESGCM(mk[:16])
    nonce = ciphertext_with_nonce[:12]
    ciphertext = ciphertext_with_nonce[12:]
    plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data)

    return plaintext

    