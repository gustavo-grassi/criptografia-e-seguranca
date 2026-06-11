import rsa
from cliente import Cliente

chaves_rede = {
    "lucas": rsa.load_key("lucas_pub.key"),
    "julia": rsa.load_key("julia_pub.key")
}
minha_chave_privada = rsa.load_key("lucas_priv.key")

lucas = Cliente("lucas", minha_chave_privada, chaves_rede)
lucas.start_receiver()

while True:
    texto = input("Lucas: ")

    if texto.strip():
        lucas.send_message(
            "julia",
            texto
        )