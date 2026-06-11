import aespuro
import rsa
import os

def read_packet(packet, receiver_private_key, sender_public_key):
    #Extração dos componentes hexadecimais e numéricos do payload
    iv = bytes.fromhex(packet["iv"])
    ciphertext = bytes.fromhex(packet["ciphertext"])
    signature = int(packet["signature"])

    to_sign = iv + ciphertext

    #Validação da assinatura digital do remetente
    if not rsa.verify(to_sign, signature, sender_public_key):
        raise ValueError("A assinatura digital não confere ou o conteúdo foi alterado.")

    #Decifragem assimétrica da chave simétrica de sessão (AES)
    aes_key = rsa.decrypt_key(packet["encrypted_key"], receiver_private_key)
    aes = aespuro.AES(aes_key)

    #Decifragem simétrica e remoção do preenchimento PKCS#7
    padded = aespuro.aes_decrypt_cbc(ciphertext, aes, iv)
    plaintext = aespuro.pkcs7_unpad(padded)

    return plaintext.decode("utf-8")


def create_packet(plaintext, sender_name, sender_private_key, receiver_public_key):
    #Geração de material criptográfico aleatório (Chave de sessão e IV)
    aes_key = os.urandom(16)
    iv = os.urandom(16)

    aes = aespuro.AES(aes_key)

    #Cifragem simétrica dos dados textuais (CBC)
    padded = aespuro.pkcs7_pad(plaintext.encode("utf-8"))
    ciphertext = aespuro.aes_encrypt_cbc(padded, aes, iv)

    #Proteção da chave simétrica usando a chave pública do destinatário
    encrypted_key = rsa.encrypt_key(aes_key, receiver_public_key)

    #Geração de assinatura digital sobre o vetor e a cifra
    to_sign = iv + ciphertext
    signature = rsa.sign(to_sign, sender_private_key)

    return {
        "sender": sender_name,
        "encrypted_key": encrypted_key,
        "iv": iv.hex(),
        "ciphertext": ciphertext.hex(),
        "signature": str(signature)
    }