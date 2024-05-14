import streamlit as st
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend


def generate_rsa_keypair():
  """Generates an RSA key pair (private and public keys).

  Returns:
      A tuple containing the private key (PEM-encoded) and public key (PEM-encoded).
  """
  try:
      # Attempt using default_backend
      private_key = rsa.generate_private_key(
          public_exponent=65537,
          key_size=2048,
          backend=default_backend()
      )
  except NameError:  # If default_backend not found, use system-wide backend
      print("WARNING: cryptography.hazmat.backends.default_backend not found, using system-wide backend.")
      private_key = rsa.generate_private_key(
          public_exponent=65537,
          key_size=2048
      )
  public_key = private_key.public_key()
  private_pem = private_key.private_bytes(
      encoding=serialization.Encoding.PEM,
      format=serialization.PrivateFormat.PKCS8,
      encryption_algorithm=serialization.NoEncryption()
  )
  public_pem = public_key.public_bytes(
      encoding=serialization.Encoding.PEM,
      format=serialization.PublicFormat.SubjectPublicKeyInfo
  )
  return private_pem, public_pem


def rsa_encrypt(public_pem, message):
  """Encrypts a message using an RSA public key.

  Args:
      public_pem: The PEM-encoded public key.
      message: The message to encrypt (bytes).

  Returns:
      The encrypted message (bytes).
  """
  public_key = serialization.load_pem_public_key(
      public_pem,
      backend=default_backend()
  )
  ciphertext = public_key.encrypt(
      message,
      padding.OAEP(
          mgf=padding.MGF1(algorithm=hashes.SHA256()),
          algorithm=hashes.SHA256(),
          label=None
      )
  )
  return ciphertext


def rsa_decrypt(private_pem, ciphertext):
  """Decrypts a message using an RSA private key.

  Args:
      private_pem: The PEM-encoded private key.
      ciphertext: The encrypted message (bytes).

  Returns:
      The decrypted message (bytes).
  """
  private_key = serialization.load_pem_private_key(
      private_pem,
      password=None,
      backend=default_backend()
  )
  original_message = private_key.decrypt(
      ciphertext,
      padding.OAEP(
          mgf=padding.MGF1(algorithm=hashes.SHA256()),
          algorithm=hashes.SHA256(),
          label=None
      )
  )
  return original_message.decode()  # Decode decrypted message to string


# Streamlit app
st.title("RSA Encryption/Decryption")

# Key generation (optional, pre-generated keys can be used)
generate_keypair = st.checkbox("Generate Key Pair", value=False)
if generate_keypair:
  if st.button("Generate Keys"):
    try:
      private_pem, public_pem = generate_rsa_keypair()
      st.success("Key pair generated!")
      st.write("**Download Private Key (Keep Secret):**", download_data=private_pem, file_name="private_key.pem")
      st.code(public_pem.decode())  # Display public key in code block
    except Exception as e:
      st.error(f"Error generating key pair: {e}")
else:
  # Input fields for pre-generated keys
  private_key_file = st.file_uploader("Upload Private Key (PEM)", type="pem")
  public_key_area = st.text_area("Public Key (PEM)", height=100)

  if private_key_file is not None and public_key_area:
    private_pem = private_key_file.read()