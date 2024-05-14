import streamlit as st

def pad(data, block_size):
  """Pads data with the same value as the number of padding bytes (CMS padding)."""
  padding_length = block_size - len(data) % block_size
  padding = bytes([padding_length] * padding_length)
  return data + padding

def unpad(data):
  """Removes padding from the data based on the last byte."""
  padding_length = data[-1]
  return data[:-padding_length]

def xor_encrypt_block(plaintext_block, key):
  """Encrypts a plaintext block using XOR with the key."""
  encrypted_block = b''
  for i in range(len(plaintext_block)):
    encrypted_block += bytes([plaintext_block[i] ^ key[i % len(key)]])
  return encrypted_block

def xor_decrypt_block(ciphertext_block, key):
  """Decrypts a ciphertext block using XOR with the key (same as encryption)."""
  return xor_encrypt_block(ciphertext_block, key)

def xor_encrypt(plaintext, key, block_size):
  """Encrypts plaintext using XOR with padding and block processing."""
  encrypted_data = b''
  padded_plaintext = pad(plaintext, block_size)
  for i in range(0, len(padded_plaintext), block_size):
    plaintext_block = padded_plaintext[i:i+block_size]
    encrypted_block = xor_encrypt_block(plaintext_block, key)
    encrypted_data += encrypted_block
  return encrypted_data

def xor_decrypt(ciphertext, key, block_size):
  """Decrypts ciphertext using XOR with block processing and unpadding."""
  decrypted_data = b''
  for i in range(0, len(ciphertext), block_size):
    ciphertext_block = ciphertext[i:i+block_size]
    decrypted_block = xor_decrypt_block(ciphertext_block, key)
    decrypted_data += decrypted_block
  return unpad(decrypted_data)

st.title("XOR Encryption/Decryption")

plaintext = st.text_area("Plaintext").encode()
key = st.text_area("Key").encode()
block_size = st.number_input("Block Size (8, 16, 32, 64, or 128):", min_value=8, max_value=128)

if block_size not in [8, 16, 32, 64, 128]:
  st.write("Block size must be one of 8, 16, 32, 64, or 128 bytes")
else:
  key = pad(key, block_size)

  # Encryption
  encrypted_data = xor_encrypt(plaintext, key, block_size)

  # Decryption
  decrypted_data = xor_decrypt(encrypted_data, key, block_size)

  st.write("Original Plaintext:", plaintext.decode())
  st.write("Key (hex):", key.hex())
  st.write("Encrypted Data (hex):", encrypted_data.hex())
  st.write("Decrypted Data:", decrypted_data.decode())
