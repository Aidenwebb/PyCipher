import base64

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet

class Cipher(object):

    def __init__(self, password, salt):
        """Provides encryption and decryption methods for strings and creates an encryption key from a password

        Args:
             password (str): password to be converted to a key
             salt (bytes): salt for password hashing

        TODO: - Figure out how to store bytecode of salt
            """
        self.salt = salt
        self.key = self.password_to_key(password)
        self.fernet = Fernet(self.key)

    def password_to_key(self, password):
        password = bytes(password, encoding='utf8')
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),
                         length=32,
                         salt=self.salt,
                         iterations=1000000,
                         backend=default_backend()
                         )
        kdf_derived = kdf.derive(password)
        return base64.urlsafe_b64encode(kdf_derived)

    def encrypt_string(self, string):
        """Encrypts a string

        Args:
            string (str): The string to be encrypted

        Returns:
            token (str): The encrypted string
        """
        str_as_bytestr = bytes(string, encoding='utf8')
        token = self.fernet.encrypt(str_as_bytestr).decode('utf8')
        return token

    def decrypt_string(self, token):
        """Decrypts a string

        Args:
            token (str): The string to be decrypted

        Returns:
            string (str): The decrypted string
            """
        token = bytes(token, encoding='utf8')
        token = self.fernet.decrypt(token).decode('utf8')
        return token
