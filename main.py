from ecc import *

def main():

    # Test case
    plaintext = "William Aitken"

    # secret key, arbitrary here for repetition. Should be random integer
    # less than q, the order of p
    sk = 111

    # arbitrary value for encoding. See encoding function for more details
    encoding_base = 256

    # random value for encryption. Should be random in real implementation less
    # than q, the order of p
    k = 546

    # derive public ket from generator and secret key
    pk = keygen(g, sk, a, p)


    print("Encoded characters:")

    encoded_message = []
    for char in plaintext:
        try:
            point = encode(char, encoding_base, a, b, p)
        except ValueError as e:
            print(e)
        else:
            encoded_message.append(point)
            print(point)


    print("Encrypted character cipher pairs:")

    encrypted_message = []
    for point in encoded_message:
        try: 
            cipher_tuple = encrypt(pk, point, k, g, a, p)
        except ValueError as e:
            print(e)
        else:
            encrypted_message.append(cipher_tuple)
            print(cipher_tuple)


    print("Decrypted message:")

    decrypted_message = []
    for cipher_tuple in encrypted_message:
        try:
            point = decrypt(cipher_tuple, sk, a, p)
        except ValueError as e:
            print(e)
        else:
            decrypted_message.append(point)
            print(point)


    print("Decoded message:")

    decoded_message = ""
    for char in decrypted_message:
        decoded_message = decoded_message + decode(char, encoding_base) 
    print(decoded_message)
    

if __name__ == "__main__":
    main()
