import sha256

def validar_integridade(arq_entrada, arq_hash):
    #Compara o hash atual do arquivo com o valor armazenado previamente
    hash_atual = calcular_hash_do_arquivo(arq_entrada)

    with open(arq_hash, 'r') as f:
        hash_gravado = f.read().strip()

    return hash_atual == hash_gravado


def exportar_hash_para_arquivo(arq_entrada, arq_hash):
    #Gera a assinatura do arquivo e a persiste em um documento de texto
    hash_resultado = calcular_hash_do_arquivo(arq_entrada)

    with open(arq_hash, 'w') as f:
        f.write(hash_resultado)


def calcular_hash_do_arquivo(path_alvo):
    #Realiza a leitura binária do arquivo para extrair o hash SHA-256
    with open(path_alvo, 'rb') as f:
        conteudo_binario = f.read()
    
    return sha256.sha256_hex(conteudo_binario)


if __name__ == '__main__':
    #Cria o arquivo de verificação inicial
    exportar_hash_para_arquivo('teste.txt', 'teste.sha256')

    #Executa o teste de validação de integridade
    is_valido = validar_integridade('teste.txt', 'teste.sha256')

    if is_valido:
        print("SUCESSO: O arquivo está íntegro e autêntico!")
    else:
        print("ALERTA: O arquivo foi modificado ou corrompido!")