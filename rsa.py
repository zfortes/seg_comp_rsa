from random import getrandbits, randrange
from hashlib import sha3_512
from base64 import b64encode

config = dict()
config['BITS'] = 1024
config['MR_PROBABILITY'] = 20
config['e'] = 65537

#Miller-Rabin
def miller_rabin(a, s, d, n):
    a_to_power = pow(a, d, n)
    if a_to_power == 1:
        return True
    for i in range(s-1):
        if a_to_power == n - 1:
            return True
        a_to_power = (a_to_power * a_to_power) % n
    return a_to_power == n - 1

#Metodo utilizando a tecnica Miller-Rabin para verificar se o numero 'number' eh primo.
def is_prime(number):
    d = number - 1
    s = 0

    #Verifica se 'd' eh impar, se nao for executa um bitshift right e 's'
    while d % 2 == 0:
        d >>= 1
        s += 1

    #Repete o teste Miller-Rabin 'MR_PROBABILITY' vezes para probabilidade de 1-1/4**'MR_PROBABILITY' do numero 'number' ser primo
    for repeat in range(config['MR_PROBABILITY']):
        #Escolhe 'a' aleatoriamente dentro do range de 'number', exceto o numero 0
        a = 0
        while a == 0:
            a = randrange(number)

        #Se o teste falhar, eh numero composto
        if not miller_rabin(a, s, d, number):
            return False

    return True

#Metodo para gerar um numero primo aleatorio de n bits
def get_prime(nbits):
    while True:
        #Gera numero aleatorio 'number' com ate n bits.
        number = getrandbits(nbits)

        #Bitwise OR para aumentar a probabilidade do numero gerado 'number' ser primo
        #Seta o bit mais significativo para 1 garantindo n bits e numero alto.
        #Seta o bit menos significativo para 1 (impar), todo numero primo acima de 2 eh impar
        number |= 2**nbits | 1

        #Verifica se 'number' eh primo
        if is_prime(number):
            break
    return number

def gcd(e,t):
    if t == 0:
        return e
    else:
        return gcd(t,e%t)

def extend_euclid(a, b):
    if b == 0:
        return 1, 0, a
    else:
        x, y, q = extend_euclid(b, a % b)
        return y, x - (a // b) * y, q


def modinv(a, b):
    x, y, q = extend_euclid(a, b)
    if q != 1:
        return None
    else:
        return x % b

def generate_RSA_keys():
    #Numero primo 'p' de n bits
    p = get_prime(config['BITS']//2)

    #Numero primo 'q' de n bits diferente de 'p'
    while True:
        q = get_prime(config['BITS']//2)
        if q != p:
            break

    #RSA Modulus 'n'
    n = p * q

    t = ( p - 1 ) * ( q - 1 )

    for e in range(config['e'],t):
        if gcd(e,t)==1:
            break

    d = modinv(e, t)

    public_key = {'n' : n, 'e': e}
    private_key = {'n' : n, 'd': d}

    #print("Public Key: {}".format(public_key))
    #print("Private Key: {}\n".format(private_key))

    return (public_key, private_key)

def sign_message(mensagem, private_key):
    #Mensagem/informacao para ser assinada
    mensagem = b64encode(mensagem.encode())

    #Hash da mensagem de 512bits para caber na assinatura de 1024bits
    hash = int.from_bytes(sha3_512(mensagem).digest(), byteorder='big')

    #Assinatura com a chave privada
    assinatura = pow(hash, private_key['d'], private_key['n'])

    return (hash, assinatura)

def verify_signature(hash, assinatura, public_key):
    #Retorno da assinatura para o hash da mensagem original para posterior comparacao e validacao da assinatura
    hash_assinatura = pow(assinatura, public_key['e'], public_key['n'])

    if hash == hash_assinatura:
        return True
    return False

def main():

    #Gerar as chaves RSA publica e privada
    (public_key, private_key) = generate_RSA_keys()

    #Mensagem para assinar
    mensagem = "Mensagem secreta 1, 2, 3 !!!"

    #Assinar mensagem gerando o hash e a assinatura
    (hash, assinatura) = sign_message(mensagem, private_key)

    print("Mensagem para assinar: {}\n".format(mensagem))
    print("Hash da mensagem: {}\n".format(hex(hash)))
    print("Assinatura: {}\n".format(hex(assinatura)))
    print("Validade da assinatura: {}".format(verify_signature(hash, assinatura, public_key)))

if __name__ == '__main__':
    main()
