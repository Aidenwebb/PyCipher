import os
import cipher

if __name__ == '__main__':
    salt = os.urandom(32)
    print("Your salt: {}".format(salt))

    password = input("Type password: ")
    print("Your password: {}".format(password))

    encrypter = cipher.Cipher(password, salt)
    print("Your encryption key: {}".format(encrypter.key))

    str = input("Type string to encrypt: ")
    print("Your unencrypted string: {}".format(str))

    encrypted = encrypter.encrypt_string(str)
    print("Your encrypted string: {}".format(encrypted))

    decrypted = encrypter.decrypt_string(encrypted)
    print("Your decrypted string: {}".format(decrypted))