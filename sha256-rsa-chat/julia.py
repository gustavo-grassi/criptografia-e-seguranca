import rsa
from cliente import Cliente

chave_privada_julia = rsa.load_key("julia_priv.key")

lista_chaves_pub = {
    "julia": rsa.load_key("julia_pub.key"),
    "lucas": rsa.load_key("lucas_pub.key")
}

julia = Cliente("julia", chave_privada_julia, lista_chaves_pub)
julia.start_receiver()

while True:
    texto_input = input("Julia: ")

    if texto_input.strip():
        julia.send_message(
            "lucas",
            texto_input
        )