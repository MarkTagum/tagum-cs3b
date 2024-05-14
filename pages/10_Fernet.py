import streamlit as st
from cryptography.fernet import Fernet

def generate_key():
  """Generates a random secret key for encryption/decryption."""
  key = Fernet.generate_key()
  return key.decode()  # Convert key to a string for easier handling

def encrypt_message(message, key):
  """Encrypts a message using the provided key."""
  fernet = Fernet(key.encode())
  encrypted_message = fernet.encrypt(message.encode())
  return encrypted_message.decode()

def decrypt_message(encrypted_message, key):
  """Decrypts an encrypted message using the provided key."""
  fernet = Fernet(key.encode())
  decrypted_message = fernet.decrypt(encrypted_message.encode())
  return decrypted_message.decode()

def main():
  # Option 1: Pre-generated key (store securely!)
  # Replace 'your_secret_key' with your actual key
  # key = 'your_secret_key'

  # Option 2: Generate key on first run (less secure)
  if 'secret_key' not in st.session_state:
    st.session_state['secret_key'] = generate_key()
    st.write("Secret key generated! Please store it securely and don't share it with anyone.")
  key = st.session_state['secret_key']

  # Text input for message
  message = st.text_input("Enter a message to encrypt/decrypt:")

  # Encryption/Decryption buttons
  if message:
    encrypt_button = st.button("Encrypt")
    decrypt_button = st.button("Decrypt")

    if encrypt_button:
      encrypted_message = encrypt_message(message, key)
      st.write("Encrypted message:", encrypted_message)
    elif decrypt_button:
      try:
        decrypted_message = decrypt_message(message, key)
        st.write("Decrypted message:", decrypted_message)
      except cryptography.fernet.InvalidToken:
        st.error("Invalid decryption key or message. Please check your input.")

if __name__ == '__main__':
  main()
