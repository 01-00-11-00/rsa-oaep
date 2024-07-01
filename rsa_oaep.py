# ---------------------------- Libraries ------------------------------- #
from utils.calculator import Calculator
from Crypto.Util import number
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import hashlib
import os


# ---------------------------- RSA-OAEP ------------------------------- #

class RsaOaep:
    """
    This class implements the RSA-OAEP encryption scheme.
    """

    # Constructor
    def __init__(self, seed_length=8):
        """
        Initializes the RsaOaep class with a given seed length.
        :param seed_length: The length of the seed used in the OAEP padding scheme.
        """

        self.calculator = Calculator()
        self.hash_function = hashlib.sha256
        self.seed_length = seed_length

    # Methods

    @staticmethod
    def __size_in_bytes(num: int) -> int:
        """
        Returns the number of bytes required to represent an integer in binary.
        :param num: The integer.
        :return: The number of bytes.
        """

        return (num.bit_length() + 7) // 8 or 1

    @staticmethod
    def read_keys(file_path: str):
        """
        Reads a private key from a PEM file.
        :param file_path: The path to the PEM file.
        :return: The private key.
        """

        with open(file_path, "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
            )

            return private_key

    @staticmethod
    def __mgf1(seed: bytes, mask_length: int) -> bytes:
        """
        Implements the MGF1 (Mask Generation Function) used in the OAEP padding scheme.
        :param seed: The seed used to generate the mask.
        :param mask_length: The length of the mask to be generated.
        :return: The generated mask.
        """

        counter = 0
        output = b""

        while len(output) < mask_length:
            c = counter.to_bytes(4, byteorder="big")
            hash_value = hashlib.sha256(seed + c)

            output += hash_value.digest()
            counter += 1

        return output[:mask_length]

    def create_oaep(self, message: bytes, n: int, label=b"") -> bytes:
        """
        Implements the OAEP (Optimal Asymmetric Encryption Padding) scheme.
        :param message: The message to be padded.
        :param n: The RSA modulus.
        :param label: The optional label to be associated with the message.
        :return: The padded message.
        """

        k = self.__size_in_bytes(n)
        m_len = len(message)
        h_len = self.hash_function().digest_size
        ps_len = k - 2 - self.seed_length - h_len - m_len

        ps = b'\x00' * ps_len
        db = self.hash_function(label).digest() + ps + b'\x01' + message

        seed = os.urandom(self.seed_length)
        db_mask = self.__mgf1(seed, len(db))
        masked_db = bytes(a ^ b for a, b in zip(db, db_mask))

        seed_mask = self.__mgf1(masked_db, self.seed_length)
        masked_seed = bytes(a ^ b for a, b in zip(seed, seed_mask))

        return b'\x00' + masked_seed + masked_db

    def remove_oaep(self, encoded_message: bytes, n: int, label=b"") -> bytes:
        """
        Removes the OAEP padding from a given message.
        :param encoded_message: The padded message.
        :param n: The RSA modulus.
        :param label: The optional label associated with the message.
        :return: The original message.
        """

        if encoded_message[0] != 0:
            raise ValueError("The first byte of the encoded message must be 0")

        k = self.__size_in_bytes(n)
        h_len = self.hash_function().digest_size

        masked_seed = encoded_message[1:1 + self.seed_length]
        masked_db = encoded_message[1 + self.seed_length:]

        seed_mask = self.__mgf1(masked_db, self.seed_length)
        seed = bytes(a ^ b for a, b in zip(masked_seed, seed_mask))

        db_mask = self.__mgf1(seed, k - self.seed_length - 1)
        db = bytes(a ^ b for a, b in zip(masked_db, db_mask))

        expected_hash = self.hash_function(label).digest()
        delivered_hash = db[:h_len]

        if expected_hash != delivered_hash:
            raise ValueError("The hash values are not identical.")

        return db[db.index(b'\x01') + 1:]

    def encrypt(self, message: bytes, e: int, n: int, label=b"") -> bytes:
        """
        Encrypts a given message using the RSA-OAEP encryption scheme.
        :param message: The message to be encrypted.
        :param e: The RSA public exponent.
        :param n: The RSA modulus.
        :param label: The optional label to be associated with the message.
        :return: The encrypted message.
        """

        encoded_message = self.create_oaep(message, n, label=label)
        message_int = number.bytes_to_long(encoded_message)
        encrypted_int = self.calculator.montgomery_ladder(message_int, e, n)

        return number.long_to_bytes(encrypted_int)

    def decrypt(self, encrypted_message: bytes, d: int, n: int, label=b"") -> bytes:
        """
        Decrypts a given message using the RSA-OAEP encryption scheme.
        :param encrypted_message: The encrypted message.
        :param d: The RSA private exponent.
        :param n: The RSA modulus.
        :param label: The optional label associated with the message.
        :return: The decrypted message.
        """

        encrypted_int = number.bytes_to_long(encrypted_message)
        decrypted_int = self.calculator.montgomery_ladder(encrypted_int, d, n)
        encoded_message = number.long_to_bytes(decrypted_int, self.__size_in_bytes(n))
        message = self.remove_oaep(encoded_message, n, label=label)

        return message

    def decrypt_file(self, file_path: str, d: int, n: int, label=b"") -> bytes:
        """
        Decrypts a file using the RSA-OAEP encryption scheme.
        :param file_path: The path to the file to be decrypted.
        :param d: The RSA private exponent.
        :param n: The RSA modulus.
        :param label: The optional label associated with the message.
        :return: The decrypted message.
        """

        with open(file_path, "rb") as f:
            encrypted_message = f.read()

        return self.decrypt(encrypted_message, d, n, label=label)

    def encrypt_file(self, message: bytes, e: int, n: int, file_path="outputs/ciphertext.bin"):
        """
        Encrypts a message and writes the encrypted message to a file.
        :param message: The message to be encrypted.
        :param e: The RSA public exponent.
        :param n: The RSA modulus.
        :param file_path: The path to the file where the encrypted message will be written.
        """

        decrypted_message = self.encrypt(message, e, n)

        with open(file_path, "wb") as f:
            f.write(decrypted_message)
