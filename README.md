# RSA-OAEP Encryption

This Python project includes an `RSAOAEP` class that implements the RSA-OAEP encryption scheme. RSA-OAEP is a cryptographic algorithm used for encrypting and decrypting messages and files, providing high security with relatively short key lengths.

## Getting Started

### Dependencies

- Python 3.x
- cryptography
- hashlib
- pycryptodome

### Installing

Clone the repository using the following command:

```bash
git clone https://github.com/01-00-11-00/rsa-oaep.git
```

Install the required packages using the following command:

````bash
pip install cryptography hashlib pycryptodome
````

## Features
## Features

The `RSAOAEP` class includes the following methods:

- `encrypt(message: bytes, e: int, n: int) -> bytes`: This method takes a message, a public exponent, and a modulus as input, and returns the encrypted message. The encryption is done using the RSA-OAEP encryption scheme.

- `decrypt(encrypted_message: bytes, d: int, n: int) -> bytes`: This method takes an encrypted message, a private exponent, and a modulus as input, and returns the decrypted message. The decryption is done using the RSA-OAEP encryption scheme.

- `encrypt_file(message: bytes, e: int, n: int, file_path: str)`: This method takes a message, a public exponent, a modulus, and a file path as input. It encrypts the message using the RSA-OAEP encryption scheme and writes the encrypted message to the file at the given file path.

- `decrypt_file(file_path: str, d: int, n: int) -> bytes`: This method takes a file path, a private exponent, and a modulus as input. It reads the encrypted message from the file at the given file path, decrypts the message using the RSA-OAEP encryption scheme, and returns the decrypted message.


## Usage

To use the RSAOAEP class, import it into your Python script and create an instance of the class. You can then call the methods on the instance as needed.

```python
from rsa_oaep import RSAOAEP

rsa_oaep = RSAOAEP()
```

## Authors

01-00-11-00

ex. [@01-00-11-00](https://github.com/01-00-11-00)

## Version History

- 0.1
    - Initial Release