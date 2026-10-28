import sys
import time
from funciones import GET_BOB_INITIAL_KEYPAIR
from double_ratchet import DoubleRatchetState, init_alice, init_bob, ratchet_encrypt, ratchet_decrypt
from mqtt_manager import MQTTManager

SHARED_ROOT_KEY = b"1234567890123456"

def main():
    print("=== MY WHATSAPP - DOUBLE RATCHET CHAT ===")
    user_name = input("Introduce tu identificador de canal (ej. alv): ").strip()
    role = input("¿Quieres iniciar como ALICE (A) o BOB (B)?: ").strip().upper()

    if role == "A":
        topic_in = f"{user_name}.out"
        topic_out = f"{user_name}.in"
    else:
        topic_in = f"{user_name}.in"
        topic_out = f"{user_name}.out"

    state = DoubleRatchetState()

    # Inicialización utilizando la clave fija de Bob
    if role == "A":
        _, bob_pub_init = GET_BOB_INITIAL_KEYPAIR()
        init_alice(state, SHARED_ROOT_KEY, bob_pub_init)
        print("[*] Estado inicializado como ALICE.")
    else:
        bob_pair = GET_BOB_INITIAL_KEYPAIR()
        init_bob(state, SHARED_ROOT_KEY, bob_pair)
        print("[*] Estado inicializado como BOB.")

    def on_message_received(packet: dict):
        try:
            plaintext_bytes = ratchet_decrypt(state, packet)
            print(f"\n[Mensaje Recibido]: {plaintext_bytes.decode('utf-8')}")
            print("> ", end="", flush=True)
        except Exception as e:
            print(f"\n[!] Error al descifrar mensaje: {e}")

    mqtt_net = MQTTManager(topic_in=topic_in, topic_out=topic_out, on_message_callback=on_message_received)
    mqtt_net.start()

    time.sleep(1)
    print("\nEscribe un mensaje y pulsa ENTER para enviar (o 'exit' para salir):\n")

    try:
        while True:
            text = input("> ").strip()
            if text.lower() == "exit":
                break
            if not text:
                continue
            
            packet = ratchet_encrypt(state, text.encode('utf-8'))
            mqtt_net.send_packet(packet)
            
    except KeyboardInterrupt:
        pass
    finally:
        mqtt_net.stop()
        print("\nSesión finalizada.")

if __name__ == "__main__":
    main()