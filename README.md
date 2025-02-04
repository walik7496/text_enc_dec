# Text Encrypter and Decrypter

A Python-based GUI application for encrypting and decrypting text using multiple cryptographic algorithms: AES, DES, Blowfish, and CAST. The app is built with Tkinter for the interface and PyCryptodome for cryptographic operations.

## Features

- **Multiple Encryption Methods**: Supports AES, DES, Blowfish, and CAST algorithms.
- **User-Friendly Interface**: Simple Tkinter-based GUI with input fields for plain text, encryption key, and output fields for encrypted and decrypted text.
- **Key Validation**: Ensures DES key length is exactly 8 bytes to meet algorithm requirements.
- **Base64 Encoding**: Uses Base64 for encoding encrypted output, making it easy to copy and store.

## Prerequisites

- Python 3.x
- PyCryptodome library

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/walik7496/text_enc_dec.git
   cd text-encrypter-decrypter
   ```

2. Install the required library:
   ```bash
   pip install pycryptodome
   ```

## Usage

1. Run the application:
   ```bash
   python encrypter_decrypter.py
   ```

2. Enter the text you want to encrypt in the "Enter plain text" field.
3. Choose the encryption method from the dropdown menu.
4. Provide an encryption key:
   - **AES**: Key length should be 16, 24, or 32 bytes.
   - **DES**: Key must be exactly 8 bytes.
   - **Blowfish/CAST**: Key can vary but should be secure.
5. Click **Encrypt** to encrypt the text.
6. To decrypt, paste the encrypted text in the corresponding field, provide the same key, and click **Decrypt**.

## Example

- **Input Text**: `Hello, World!`
- **Key (AES)**: `1234567890123456`
- **Encrypted Text**: `U2FsdGVkX1+Yq4k7bQ7QGg==`
- **Decrypted Text**: `Hello, World!`

## Notes

- **Key Management**: Always remember the encryption key; without it, decryption is impossible.
- **Security Considerations**: ECB mode is used for simplicity but is not recommended for production due to vulnerabilities. Consider using CBC mode with IV for secure applications.

## License

This project is licensed under the MIT License.

## Acknowledgments

- [PyCryptodome](https://www.pycryptodome.org/)
- [Tkinter Documentation](https://docs.python.org/3/library/tkinter.html)

