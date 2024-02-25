import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
from Crypto.Cipher import AES, DES, Blowfish, CAST # pip3 install pycryptodome
import base64

# Function for AES text encryption
def encrypt_aes(plaintext, key):
    cipher = AES.new(key.encode(), AES.MODE_ECB)
    # Padding the text to the multiple of AES block size
    plaintext = plaintext + ' ' * (AES.block_size - len(plaintext) % AES.block_size)
    return base64.b64encode(cipher.encrypt(plaintext.encode())).decode()

# Function for AES text decryption
def decrypt_aes(encrypted_text, key):
    cipher = AES.new(key.encode(), AES.MODE_ECB)
    decrypted_text = cipher.decrypt(base64.b64decode(encrypted_text)).decode()
    return decrypted_text.rstrip()

# Function for DES text encryption
def encrypt_des(plaintext, key):
    # Check DES key length
    if len(key) != 8:
        messagebox.showerror("Error", "Incorrect DES key length (8 bytes)")
        return
    cipher = DES.new(key.encode(), DES.MODE_ECB)
    # Padding the text to the multiple of DES block size
    plaintext = plaintext + ' ' * (DES.block_size - len(plaintext) % DES.block_size)
    return base64.b64encode(cipher.encrypt(plaintext.encode())).decode()

# Function for DES text decryption
def decrypt_des(encrypted_text, key):
    # Check DES key length
    if len(key) != 8:
        messagebox.showerror("Error", "Incorrect DES key length (8 bytes)")
        return
    cipher = DES.new(key.encode(), DES.MODE_ECB)
    decrypted_text = cipher.decrypt(base64.b64decode(encrypted_text)).decode()
    return decrypted_text.rstrip()

# Function for Blowfish text encryption
def encrypt_blowfish(plaintext, key):
    cipher = Blowfish.new(key.encode(), Blowfish.MODE_ECB)
    # Padding the text to the multiple of Blowfish block size
    plaintext = plaintext + ' ' * (Blowfish.block_size - len(plaintext) % Blowfish.block_size)
    return base64.b64encode(cipher.encrypt(plaintext.encode())).decode()

# Function for Blowfish text decryption
def decrypt_blowfish(encrypted_text, key):
    cipher = Blowfish.new(key.encode(), Blowfish.MODE_ECB)
    decrypted_text = cipher.decrypt(base64.b64decode(encrypted_text)).decode()
    return decrypted_text.rstrip()

# Function for CAST text encryption
def encrypt_cast(plaintext, key):
    cipher = CAST.new(key.encode(), CAST.MODE_ECB)
    # Padding the text to the multiple of CAST block size
    plaintext = plaintext + ' ' * (CAST.block_size - len(plaintext) % CAST.block_size)
    return base64.b64encode(cipher.encrypt(plaintext.encode())).decode()

# Function for CAST text decryption
def decrypt_cast(encrypted_text, key):
    cipher = CAST.new(key.encode(), CAST.MODE_ECB)
    decrypted_text = cipher.decrypt(base64.b64decode(encrypted_text)).decode()
    return decrypted_text.rstrip()

# Creating a Tkinter window
root = tk.Tk()
root.title("Text Encrypter and Decrypter")

# Creating a frame for selecting encryption method
encryption_frame = ttk.Frame(root)
encryption_frame.grid(row=0, column=0, padx=10, pady=10)

# Creating a label and a combobox for selecting encryption method
encryption_label = ttk.Label(encryption_frame, text="Select encryption method:")
encryption_label.grid(row=0, column=0, padx=5, pady=5)

encryption_methods = ["AES", "DES", "Blowfish", "CAST"]
encryption_combobox = ttk.Combobox(encryption_frame, values=encryption_methods, state="readonly")
encryption_combobox.grid(row=0, column=1, padx=5, pady=5)
encryption_combobox.current(0)

# Entry for entering the text to be encrypted
plain_text_label = tk.Label(root, text="Enter plain text:")
plain_text_label.grid(row=1, column=0, padx=5, pady=5)
plain_text_entry = tk.Entry(root, width=50)
plain_text_entry.grid(row=1, column=1, padx=5, pady=5)

# Entry for entering the encryption key
key_label = tk.Label(root, text="Enter encryption key:")
key_label.grid(row=2, column=0, padx=5, pady=5)
key_entry = tk.Entry(root, width=50)
key_entry.grid(row=2, column=1, padx=5, pady=5)

# Entry for displaying the encrypted text
encrypted_text_label = tk.Label(root, text="Encrypted text:")
encrypted_text_label.grid(row=3, column=0, padx=5, pady=5)
encrypted_text_entry = tk.Entry(root, width=50)
encrypted_text_entry.grid(row=3, column=1, padx=5, pady=5)

# Entry for displaying the decrypted text
decrypted_text_label = tk.Label(root, text="Decrypted text:")
decrypted_text_label.grid(row=4, column=0, padx=5, pady=5)
decrypted_text_entry = tk.Entry(root, width=50)
decrypted_text_entry.grid(row=4, column=1, padx=5, pady=5)

# Function for handling encryption event
def encrypt_text():
    plaintext = plain_text_entry.get()
    key = key_entry.get()
    method = encryption_combobox.get()

    if method == "AES":
        encrypted_text = encrypt_aes(plaintext, key)
    elif method == "DES":
        encrypted_text = encrypt_des(plaintext, key)
    elif method == "Blowfish":
        encrypted_text = encrypt_blowfish(plaintext, key)
    elif method == "CAST":
        encrypted_text = encrypt_cast(plaintext, key)
    else:
        messagebox.showerror("Error", "Invalid encryption method selected.")
        return

    encrypted_text_entry.delete(0, tk.END)
    encrypted_text_entry.insert(tk.END, encrypted_text)

# Function for handling decryption event
def decrypt_text():
    encrypted_text = encrypted_text_entry.get()
    key = key_entry.get()
    method = encryption_combobox.get()

    if method == "AES":
        decrypted_text = decrypt_aes(encrypted_text, key)
    elif method == "DES":
        decrypted_text = decrypt_des(encrypted_text, key)
    elif method == "Blowfish":
        decrypted_text = decrypt_blowfish(encrypted_text, key)
    elif method == "CAST":
        decrypted_text = decrypt_cast(encrypted_text, key)
    else:
        messagebox.showerror("Error", "Invalid encryption method selected.")
        return

    decrypted_text_entry.delete(0, tk.END)
    decrypted_text_entry.insert(tk.END, decrypted_text)

# Buttons for encryption and decryption
encrypt_button = tk.Button(root, text="Encrypt", command=encrypt_text)
encrypt_button.grid(row=5, column=0, columnspan=2, padx=5, pady=5)
decrypt_button = tk.Button(root, text="Decrypt", command=decrypt_text)
decrypt_button.grid(row=6, column=0, columnspan=2, padx=5, pady=5)

# Running the main event loop
root.mainloop()
