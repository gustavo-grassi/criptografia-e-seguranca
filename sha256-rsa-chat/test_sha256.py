import unittest
import hashlib
import hmac
# Importando as funções do seu arquivo sha256.py
from sha256 import sha256_hex, hmac_sha256, pbkdf2_sha256

class TestSHA256Manual(unittest.TestCase):

    def test_sha256_vazio(self):
        #Testa o hash de uma string vazia (Vetor de teste oficial NIST)
        esperado = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        resultado = sha256_hex(b"")
        self.assertEqual(resultado, esperado)

    def test_sha256_abc(self):
        #Testa o vetor clássico do NIST 'abc'
        esperado = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        resultado = sha256_hex(b"abc")
        self.assertEqual(resultado, esperado)

    def test_sha256_com_hashlib(self):
        #Compara strings de múltiplos tamanhos e limites de bloco com o hashlib oficial
        casos_de_teste = [
            b"Estruturas de dados e criptografia pura.",
            b"A" * 55,   # Limite crítico antes do padding de comprimento (56 bytes)
            b"B" * 64,   # Tamanho exato de um bloco SHA-256
            b"C" * 128,  # Múltiplos blocos cheios
            b"Uma string muito mais longa para garantir que o message schedule e a compressao em lote funcionem sem quebrar absolutamente nada durante a iteracao dos blocos de 64 bytes."
        ]
        
        for texto in casos_de_teste:
            with self.subTest(msg=f"Tamanho do texto: {len(texto)} bytes"):
                manual = sha256_hex(texto)
                oficial = hashlib.sha256(texto).hexdigest()
                self.assertEqual(manual, oficial)

    def test_hmac_sha256(self):
        #Valida a integridade do HMAC-SHA256 contra a biblioteca hmac padrão
        chave = b"chave_secreta_de_teste"
        mensagem = b"Pacote de dados confidenciais do cliente."
        
        manual = hmac_sha256(chave, mensagem).hex()
        oficial = hmac.new(chave, mensagem, hashlib.sha256).hexdigest()
        self.assertEqual(manual, oficial)

    def test_pbkdf2_sha256(self):
        #Valida a derivação de chave (PBKDF2) contra o algoritmo oficial do hashlib
        senha = b"senha_forte_123"
        sal = b"sal_aleatorio_99"
        iteracoes = 500
        tamanho_chave = 32

        manual = pbkdf2_sha256(senha, sal, iteracoes, tamanho_chave)
        oficial = hashlib.pbkdf2_hmac('sha256', senha, sal, iteracoes, tamanho_chave)
        self.assertEqual(manual, oficial)

if __name__ == "__main__":
    unittest.main()