import streamlit as st
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.exceptions import InvalidSignature

def generate_keypair(key_size=2048):
  """
  Generates an RSA keypair of the specified size (in bits).

  Args:
      key_size (int, optional): The size of the keypair in bits. Defaults to 2048.

  Returns:
      tuple: A tuple containing the private key (PEM format) and public key (PEM format).
  """
  # Generate private key
  private_key = rsa.generate_private_key(
      public_exponent=65537,
      key_size=key_size,
      backend=default_backend()
  )

  # Write private key to PEM format (**Don't display or download in production!**)
  private_pem = private_key.private_bytes(
      encoding=serialization.Encoding.PEM,
      format=serialization.PrivateFormat.PKCS8,
      encryption_algorithm=serialization.NoEncryption()
  )

  # Extract public key from private key
  public_key = private_key.public_key()

  # Write public key to PEM format
  public_pem = public_key.public_bytes(
      encoding=serialization.Encoding.PEM,
      format=serialization.PublicFormat.SubjectPublicKeyInfo
  )

  return private_pem.decode(), public_pem.decode()

def encrypt_message(message, public_key):
  """
  Encrypts a message using the provided public key.

  Args:
      message (str): The message to encrypt.
      public_key (str): The public key (PEM format).

  Returns:
      str: The encrypted message (PEM format).
  """
  # Load public key
  public_key = rsa.PublicKey.from_pem(public_key.encode())

  # Hash the message
  digest = hashes.Hash(hashes.SHA256(), backend=default_backend()).update(message.encode())
  hashed = digest.finalize()

  # Encrypt the hashed message using OAEP padding
  ciphertext = public_key.encrypt(
      hashed,
      padding.OAEP(
          mgf=padding.MGF1(algorithm=hashes.SHA256()),
          algorithm=hashes.SHA256(),
          label=None
      )
  )

  # Write ciphertext to PEM format
  return ciphertext.decode()

def decrypt_message(ciphertext, private_key):
  """
  Decrypts a message using the provided private key.

  Args:
      ciphertext (str): The encrypted message (PEM format).
      private_key (str): The private key (PEM format).

  Returns:
      str: The decrypted message.
  """
  # Load private key
  private_key = rsa.PrivateKey.from_pem(private_key.encode())

  try:
    # Decrypt the ciphertext using OAEP padding
    original_message = private_key.decrypt(
      ciphertext.encode(),
      padding.OAEP(
          mgf=padding.MGF1(algorithm=hashes.SHA256()),
          algorithm=hashes.SHA256(),
          label=None
      )
    )
  except InvalidSignature:
    return "Invalid signature: Decryption failed!"

  # Verify the hash of the decrypted message
  digest = hashes.Hash(hashes.SHA256(), backend=default_backend()).update(original_message)
  if digest.finalize() != hashed:
    return "Hash mismatch: Message integrity compromised!"

  return original_message.decode()

# Streamlit App
st.title("RSA Encryption/Decryption Demo")

mode_option = st.selectbox("Select Mode", ("Encrypt", "Decrypt"))

# Generate keypair on demand (**Don't store keys in app!**)
if st.button("Generate Keypair"):
  private_key, public_key = generate_keypair()
  st.write("**Warning:** Private key is displayed here for demonstration purposes only. In a real application, it should be kept secret!")
  st.text_area("Private Key", private_key, disabled=True)
  