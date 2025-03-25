import tkinter as tk
from tkinter import ttk
from cryptography.fernet import Fernet

def generate_key():
    """Generates a new encryption key."""
    key = Fernet.generate_key()
    return key

def encrypt_message(message, key):
    """Encrypts a message using the provided key."""
    f = Fernet(key)
    encrypted_message = f.encrypt(message.encode())
    return encrypted_message

def decrypt_message(encrypted_message, key):
    """Decrypts an encrypted message using the provided key."""
    try:
        f = Fernet(key)
        decrypted_message = f.decrypt(encrypted_message).decode()
        return decrypted_message
    except Exception as e:
        return f"Decryption Error: {e}"

def encrypt_button_click():
    """Handles the encryption button click event."""
    message = message_entry.get("1.0", tk.END).strip()
    key_str = key_entry.get().strip()

    if not message or not key_str:
        result_text.delete("1.0", tk.END)
        result_text.insert(tk.END, "Please enter a message and a key.")
        return

    try:
        key = key_str.encode()
        encrypted_message = encrypt_message(message, key)
        result_text.delete("1.0", tk.END)
        result_text.insert(tk.END, f"{encrypted_message.decode()}")
    except Exception as e:
        result_text.delete("1.0", tk.END)
        result_text.insert(tk.END, f"Encryption Error: {e}")

def decrypt_button_click():
    """Handles the decryption button click event."""
    encrypted_message_str = message_entry.get("1.0", tk.END).strip()
    key_str = key_entry.get().strip()

    if not encrypted_message_str or not key_str:
        result_text.delete("1.0", tk.END)
        result_text.insert(tk.END, "Please enter an encrypted message and a key.")
        return

    try:
        key = key_str.encode()
        encrypted_message = encrypted_message_str.encode()
        decrypted_message = decrypt_message(encrypted_message, key)
        result_text.delete("1.0", tk.END)
        result_text.insert(tk.END, f"{decrypted_message}")
    except Exception as e:
        result_text.delete("1.0", tk.END)
        result_text.insert(tk.END, f"Decryption Error: {e}")

def generate_key_button_click():
    """Generates a new key and displays it."""
    key = generate_key()
    key_entry.delete(0, tk.END)
    key_entry.insert(0, key.decode())

# GUI Setup
root = tk.Tk()
root.title("Encryption/Decryption App")

# Message Input
message_label = ttk.Label(root, text="Message:")
message_label.pack(pady=5)
message_entry = tk.Text(root, height=5, width=40)
message_entry.pack(pady=5)

# Key Input
key_label = ttk.Label(root, text="Key:")
key_label.pack(pady=5)
key_entry = ttk.Entry(root, width=40)
key_entry.pack(pady=5)

generate_key_button = ttk.Button(root, text="Generate Key", command=generate_key_button_click)
generate_key_button.pack(pady=5)

# Buttons
encrypt_button = ttk.Button(root, text="Encrypt", command=encrypt_button_click)
encrypt_button.pack(pady=5)

decrypt_button = ttk.Button(root, text="Decrypt", command=decrypt_button_click)
decrypt_button.pack(pady=5)

# Result Text Widget
result_text = tk.Text(root, height=5, width=40)
result_text.pack(pady=10)

root.mainloop()