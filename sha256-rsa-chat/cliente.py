import threading
import time
import requests

from crypto_utils import create_packet, read_packet

class Cliente:

    def __init__(
        self,
        name,
        private_key,
        public_keys,
        server_url="http://127.0.0.1:5000"
    ):
        self.name = name
        self.private_key = private_key
        self.public_keys = public_keys
        self.server_url = server_url

    def start_receiver(self, interval=1):
        #Inicializa a thread em segundo plano para escutar o servidor
        def receiver_loop():
            while True:
                try:
                    messages = self.fetch_messages()

                    for msg in messages:
                        if "error" in msg:
                            print(f"\n[FALHA] -> {msg['error']}")
                        else:
                            print(f"\n({msg['sender']}) {msg['message']}")

                except Exception as e:
                    print(f"\nFalha crítica na recepção: {e}")

                time.sleep(interval)

        threading.Thread(
            target=receiver_loop,
            daemon=True
        ).start()

    def fetch_messages(self):
        #Coleta os pacotes destinados a este cliente
        response = requests.get(
            f"{self.server_url}/messages/{self.name}"
        )
        packets = response.json()
        messages = []

        for packet in packets:
            sender = packet["sender"]
            try:
                plaintext = read_packet(
                    packet,
                    self.private_key,
                    self.public_keys[sender]
                )
                messages.append({
                    "sender": sender,
                    "message": plaintext
                })
            except Exception as e:
                messages.append({
                    "sender": sender,
                    "error": str(e)
                })

        return messages

    def send_message(self, receiver, message):
        #Monta o pacote seguro e despacha para a API
        receiver_pub = self.public_keys[receiver]

        packet = create_packet(
            message,
            self.name,
            self.private_key,
            receiver_pub
        )
        packet["receiver"] = receiver

        requests.post(
            f"{self.server_url}/send",
            json=packet
        )