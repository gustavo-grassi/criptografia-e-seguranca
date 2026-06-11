import os
import hashlib
import sha256

#MISTURA E ARITMÉTICA

def gf_mul(a, b):
    acumulador = 0
    for _ in range(8):
        if b & 1:
            acumulador ^= a
        bit_alto = a & 0x80
        a = (a << 1) & 0xFF
        if bit_alto:
            a ^= 0x1b
        b >>= 1
    return acumulador

def xtime(a):
    return ((a << 1) ^ 0x1b) & 0xff if (a & 0x80) else (a << 1) & 0xff

def multiplicative_inverse(byte):
    if byte == 0:
        return 0
    for valor in range(1, 256):
        if gf_mul(byte, valor) == 1:
            return valor   
    return 0

#MAPEAMENTO S-BOX E INV S-BOX

def affine_transform(byte):
    b = byte
    resultado = b ^ ((b << 1) | (b >> 7)) & 0xFF
    resultado ^= ((b << 2) | (b >> 6)) & 0xFF
    resultado ^= ((b << 3) | (b >> 5)) & 0xFF
    resultado ^= ((b << 4) | (b >> 4)) & 0xFF
    resultado ^= 0x63
    return resultado & 0xFF

s_box = []
for idx in range(256):
    inverso_num = multiplicative_inverse(idx)
    s_box.append(affine_transform(inverso_num))

inv_s_box = [0] * 256
for idx in range(256):
    inv_s_box[s_box[idx]] = idx

#KEY EXPANSION

Rcon = [0x01, 0x02, 0x04, 0x08, 0x10,
        0x20, 0x40, 0x80, 0x1B, 0x36,
        0x6C, 0xD8, 0xAB, 0x4D, 0x9A]

def sub_word(word):
    return [s_box[b] for b in word]

def rot_word(word):
    return word[1:] + word[:1]

def key_expansion(key):
    elementos_chave = list(key)
    Nk = len(key) // 4
    Nr = Nk + 6

    w = [elementos_chave[i:i+4] for i in range(0, 4*Nk, 4)]

    for i in range(Nk, 4*(Nr+1)):
        bloco_temporario = w[i-1].copy()

        if i % Nk == 0:
            bloco_temporario = rot_word(bloco_temporario)
            bloco_temporario = sub_word(bloco_temporario)
            bloco_temporario[0] ^= Rcon[(i // Nk) - 1]
        elif Nk > 6 and i % Nk == 4:
            bloco_temporario = sub_word(bloco_temporario)

        palavra_nova = [w[i-Nk][j] ^ bloco_temporario[j] for j in range(4)]
        w.append(palavra_nova)

    return w

#MANIPULAÇÃO DE MATRIZES E ESTADOS

def block_to_matrix(block):
    return [[block[row + 4*col] for col in range(4)] for row in range(4)]

def matrix_to_block(state):
    return bytes([state[row][col] for col in range(4) for row in range(4)])

def copy_state(state):
    return [linha.copy() for linha in state]

#ETAPAS DO AES (FORWARD TRACK)

def shift_rows(state):
    new_state = copy_state(state)
    for r in range(4):
        new_state[r] = new_state[r][r:] + new_state[r][:r]
    return new_state

def sub_bytes(state):
    new_state = copy_state(state)
    for r in range(4):
        for c in range(4):
            new_state[r][c] = s_box[new_state[r][c]]
    return new_state

def mix_single_column(col):
    a0, a1, a2, a3 = col
    b0 = xtime(a0) ^ (xtime(a1) ^ a1) ^ a2 ^ a3
    b1 = a0 ^ xtime(a1) ^ (xtime(a2) ^ a2) ^ a3
    b2 = a0 ^ a1 ^ xtime(a2) ^ (xtime(a3) ^ a3)
    b3 = (xtime(a0) ^ a0) ^ a1 ^ a2 ^ xtime(a3)
    return [b0, b1, b2, b3]

def mix_columns(state):
    new_state = copy_state(state)
    for c in range(4):
        coluna_atual = [state[r][c] for r in range(4)]
        coluna_misturada = mix_single_column(coluna_atual)
        for r in range(4):
            new_state[r][c] = coluna_misturada[r]
    return new_state

def add_round_key(state, round_key):
    new_state = copy_state(state)
    for r in range(4):
        for c in range(4):
            new_state[r][c] ^= round_key[r][c]
    return new_state

#ETAPAS DO AES (INVERSE TRACK)

def inv_shift_rows(state):
    new_state = copy_state(state)
    for r in range(4):
        new_state[r] = new_state[r][-r:] + new_state[r][:-r]
    return new_state

def inv_sub_bytes(state):
    new_state = copy_state(state)
    for r in range(4):
        for c in range(4):
            new_state[r][c] = inv_s_box[new_state[r][c]]
    return new_state

def inv_mix_single_column(col):
    a0, a1, a2, a3 = col
    return [
        gf_mul(a0, 14) ^ gf_mul(a1, 11) ^ gf_mul(a2, 13) ^ gf_mul(a3, 9),
        gf_mul(a0, 9) ^ gf_mul(a1, 14) ^ gf_mul(a2, 11) ^ gf_mul(a3, 13),
        gf_mul(a0, 13) ^ gf_mul(a1, 9) ^ gf_mul(a2, 14) ^ gf_mul(a3, 11),
        gf_mul(a0, 11) ^ gf_mul(a1, 13) ^ gf_mul(a2, 9) ^ gf_mul(a3, 14)
    ]

def inv_mix_columns(state):
    new_state = copy_state(state)
    for c in range(4):
        coluna_atual = [state[r][c] for r in range(4)]
        coluna_misturada = inv_mix_single_column(coluna_atual)
        for r in range(4):
            new_state[r][c] = coluna_misturada[r]
    return new_state

#ENVELOPE DA CLASSE AES

class AES:
    def __init__(self, key):
        self.key = key
        self.Nk = len(key) // 4
        self.Nr = self.Nk + 6
        self.w = key_expansion(key)

    def get_round_key(self, round_num):
        return [[self.w[4*round_num + c][r] for c in range(4)] for r in range(4)]
    
    def encrypt_block(self, block):
        state = block_to_matrix(block)
        state = add_round_key(state, self.get_round_key(0))

        for etapa in range(1, self.Nr):
            state = sub_bytes(state)
            state = shift_rows(state)
            state = mix_columns(state)
            state = add_round_key(state, self.get_round_key(etapa))
        
        state = sub_bytes(state)
        state = shift_rows(state)
        state = add_round_key(state, self.get_round_key(self.Nr))
        return matrix_to_block(state)
    
    def decrypt_block(self, block):
        state = block_to_matrix(block)
        state = add_round_key(state, self.get_round_key(self.Nr))

        for etapa in range(self.Nr - 1, 0, -1):
            state = inv_shift_rows(state)
            state = inv_sub_bytes(state)
            state = add_round_key(state, self.get_round_key(etapa))
            state = inv_mix_columns(state)

        state = inv_shift_rows(state)
        state = inv_sub_bytes(state)
        state = add_round_key(state, self.get_round_key(0))
        return matrix_to_block(state)

#MODO DE OPERAÇÃO CBC E AUXILIARES

def split_blocks(data, block_size=16):
    return [data[i:i+block_size] for i in range(0, len(data), block_size)]

def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

def aes_encrypt_cbc(plaintext, aes, iv):
    blocos = split_blocks(plaintext)
    blocos_cifrados = []
    bloco_anterior = iv

    for b in blocos:
        passo_xor = xor_bytes(b, bloco_anterior)
        cifrado = aes.encrypt_block(passo_xor)
        blocos_cifrados.append(cifrado)
        bloco_anterior = cifrado

    return b''.join(blocos_cifrados)

def aes_decrypt_cbc(ciphertext, aes, iv):
    blocos = split_blocks(ciphertext)
    blocos_decifrados = []
    bloco_anterior = iv

    for b in blocos:
        decifrado = aes.decrypt_block(b)
        original = xor_bytes(decifrado, bloco_anterior)
        blocos_decifrados.append(original)
        bloco_anterior = b

    return b''.join(blocos_decifrados)

#INFRAESTRUTURA DE PREPARAÇÃO E ARQUIVOS

def pkcs7_pad(data, block_size=16):
    tamanho_pad = block_size - (len(data) % block_size)
    preenchimento = bytes([tamanho_pad] * tamanho_pad)
    return data + preenchimento

def pkcs7_unpad(data):
    tamanho_pad = data[-1]
    if tamanho_pad < 1 or tamanho_pad > 16:
        raise ValueError("Estrutura de preenchimento inválida.")
    if data[-tamanho_pad:] != bytes([tamanho_pad] * tamanho_pad):
        raise ValueError("Preenchimento corrompido detectado.")
    return data[:-tamanho_pad]

def derive_key(password, salt, iterations=100000, dklen=16):
    return sha256.pbkdf2_sha256(
        password.encode(),
        salt,
        iterations,
        dklen
    )

def read_file(path):
    with open(path, "rb") as arquivo:
        return arquivo.read()
    
def write_file(path, data):
    with open(path, "wb") as arquivo:
        arquivo.write(data)

#ROTINAS DE TESTES E DEMONSTRAÇÃO

def encrypt_file(input_path, output_path, password):
    conteudo = read_file(input_path)
    salt = os.urandom(16)
    chave_derivada = derive_key(password, salt)
    vetor_iv = os.urandom(16)

    instancia_aes = AES(chave_derivada)
    dados_alinhados = pkcs7_pad(conteudo)
    criptograma = aes_encrypt_cbc(dados_alinhados, instancia_aes, vetor_iv)

    write_file(output_path, salt + vetor_iv + criptograma)

def decrypt_file(input_path, output_path, password):
    conteudo_cifrado = read_file(input_path)
    salt = conteudo_cifrado[:16]
    vetor_iv = conteudo_cifrado[16:32]
    criptograma = conteudo_cifrado[32:]

    chave_derivada = derive_key(password, salt)
    instancia_aes = AES(chave_derivada)

    dados_alinhados = aes_decrypt_cbc(criptograma, instancia_aes, vetor_iv)
    conteudo_limpo = pkcs7_unpad(dados_alinhados)

    write_file(output_path, conteudo_limpo)

def aes_test_roundtrip(key_size):
    senha_dummy = "credencial_secreta"
    mensagem = b'Validacao de fluxo de blocos AES'
    salt = os.urandom(16)
    chave_derivada = derive_key(senha_dummy, salt, dklen=key_size)
    vetor_iv = os.urandom(16)

    instancia_aes = AES(chave_derivada)
    dados_alinhados = pkcs7_pad(mensagem)

    criptograma = aes_encrypt_cbc(dados_alinhados, instancia_aes, vetor_iv)
    decifrado = aes_decrypt_cbc(criptograma, instancia_aes, vetor_iv)
    conteudo_limpo = pkcs7_unpad(decifrado)

    assert conteudo_limpo == mensagem, f'Falha operacional no AES-{key_size*8}'
    print(f'Ciclo completo AES-{key_size*8} funcional.')

def aes_testfile_roundtrip(input_path, dklen):
    senha_dummy = "credencial_secreta"
    conteudo_original = read_file(input_path)
    salt = os.urandom(16)
    chave_derivada = derive_key(senha_dummy, salt, dklen=dklen)
    vetor_iv = os.urandom(16)

    instancia_aes = AES(chave_derivada)
    dados_alinhados = pkcs7_pad(conteudo_original)
    criptograma = aes_encrypt_cbc(dados_alinhados, instancia_aes, vetor_iv)

    decifrado_alinhado = aes_decrypt_cbc(criptograma, instancia_aes, vetor_iv)
    conteudo_limpo = pkcs7_unpad(decifrado_alinhado)

    assert conteudo_limpo == conteudo_original, f'Falha no teste de arquivo AES-{dklen*8}'
    print(f'Teste de arquivo para AES-{dklen*8} validado.')

if __name__ == "__main__":
    print("="*60)
    print("DEMONSTRAÇÃO DE CRIPTOGRAFIA SIMÉTRICA MANUAL (AES)")
    print("="*60)
    
    # 1. Teste de bloco único padrão (Vetor de Teste Conhecido)
    chave_vetor = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    texto_claro = bytes.fromhex("00112233445566778899aabbccddeeff")

    motor_aes = AES(chave_vetor)
    bloco_cifrado = motor_aes.encrypt_block(texto_claro)
    print(f"Vetor de Teste - Bloco Cifrado: {bloco_cifrado.hex()}")
    print("-"*60)

    #Execução dos testes de rodada (Roundtrips)
    print("Iniciando testes de consistência de chaves:")
    aes_test_roundtrip(16)
    aes_test_roundtrip(24)
    aes_test_roundtrip(32)
    print("-"*60)

    #Teste em arquivos locais
    arquivo_de_teste = 'teste.txt'
    
    #Cria o arquivo dummy caso ele não exista na pasta para evitar FileNotFoundError
    if not os.path.exists(arquivo_de_teste):
        with open(arquivo_de_teste, 'w') as f:
            f.write("Conteudo de simulação academica para o algoritmo AES.")

    print(f"Executando testes estruturais com o arquivo '{arquivo_de_teste}':")
    aes_testfile_roundtrip(arquivo_de_teste, 16)
    aes_testfile_roundtrip(arquivo_de_teste, 24)
    aes_testfile_roundtrip(arquivo_de_teste, 32)
    print("-"*60)

    #Demonstração de fluxo real
    chave_usuario = "mudar_senha_123"
    arq_criptografado = "teste.enc"
    arq_restaurado = "teste_decrypt.txt"

    print("Aplicando criptografia baseada em arquivo:")
    encrypt_file(arquivo_de_teste, arq_criptografado, chave_usuario)
    print(f"Arquivo '{arquivo_de_teste}' encriptado com sucesso para '{arq_criptografado}'")

    decrypt_file(arq_criptografado, arq_restaurado, chave_usuario)
    print(f"Arquivo '{arq_criptografado}' decriptado com sucesso para '{arq_restaurado}'")
    
    print("\nProcesso finalizado com sucesso!")
    print("="*60)