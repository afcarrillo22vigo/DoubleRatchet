import json
import paho.mqtt.client as mqtt

BROKER_DEFAULT = "51.94.164.150"
PORT_DEFAULT = 1883
USER_DEFAULT = "sinf"
PASS_DEFAULT = "sinf2026"

class MQTTManager:
    def __init__(self, topic_in, topic_out, on_message_callback, broker=BROKER_DEFAULT, port=PORT_DEFAULT):
        self.broker = broker
        self.port = port
        self.topic_in = topic_in
        self.topic_out = topic_out
        self.on_message_callback = on_message_callback

        self.client = mqtt.Client()
        self.client.username_pw_set(USER_DEFAULT, PASS_DEFAULT)
        self.client.on_connect = self._on_connect
        self.client.on_message = self._on_message

    def _on_connect(self, client, userdata, flags, rc):
        if rc == 0:
            # Suscripción al canal de entrada (ej. alv.in)
            client.subscribe(self.topic_in)
            print(f"[*] Conectado al broker MQTT. Escuchando en el canal: {self.topic_in}")
        else:
            print(f"[!] Error de conexión al broker. Código: {rc}")

    def _on_message(self, client, userdata, msg):
        try:
            payload_str = msg.payload.decode('utf-8')
            packet = json.loads(payload_str)
            self.on_message_callback(packet)
        except Exception as e:
            print(f"\n[!] Error procesando paquete recibido: {e}")

    def start(self):
        self.client.connect(self.broker, self.port, 60)
        self.client.loop_start()

    def send_packet(self, packet: dict):
        payload = json.dumps(packet)
        self.client.publish(self.topic_out, payload)

    def stop(self):
        self.client.loop_stop()
        self.client.disconnect()
        