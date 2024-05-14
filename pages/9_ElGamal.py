import streamlit as st

import random
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat
from cryptography.exceptions import InvalidSignature

# Utility function for converting messages to integers (for ElGamal)
def message_to_integer(message):
  """Converts a message string to an integer for ElGamal encryption."""
  return int.from_bytes(message.encode(), 'big')

def integer_to_message(integer):
  """Converts an integer back to a message string for ElGamal decryption."""
  return integer.to_bytes((integer.bit_length() + 7) // 8, 'big').decode()

class ElGamal:
  """ElGamal encryption and decryption class."""

  def __init__(self, p, g, a):
    """
    Initializes the ElGamal class with public key parameters.

    Args:
      p: A large prime number (int).
      g: A generator element in the finite field (int).
      a: Bob's private key (int).
    """
    self.p = p
    self.g = g
    self.a = a

  def generate_keypair(self, q):
    """
    Generates a public/private key pair for Bob.

    Args:
      q: The order of the subgroup generated by g (int).

    Returns:
      A tuple containing the public key (p, g, h) and private key (a).
    """
    self.a = random.randint(1, q - 1)
    self.h = pow(self.g, self.a, self.p)
    return (self.p, self.g, self.h), self.a

  def encrypt(self, message, k):
    """
    Encrypts a message using ElGamal with a random key k.

    Args:
      message: The message to encrypt (str).
      k: A random element from the subgroup generated by g (int).

    Returns:
      A tuple containing the ciphertext (c1, c2).
    """
    message_int = message_to_integer(message)
    c1 = pow(self.g, k, self.p)
    c2 = message_int * pow(self.h, k, self.p) % self.p
    return c1, c2

  def decrypt(self, c1, c2):
    """
    Decrypts a ciphertext using ElGamal with the private key.

    Args:
      c1: The first part of the ciphertext (int).
      c2: The second part of the ciphertext (int).

    Returns:
      The decrypted message (str).
    """
    s = pow(c1, self.p - 1 - self.a, self.p) * c2 % self.p
    message_int = s
    return integer_to_message(message_int)

# Streamlit app logic
st.title("ElGamal Encryption/Decryption")

# Key generation (optional, pre-generated keys can be used)
generate_keypair = st.checkbox("Generate Key Pair", value=False)
if generate_keypair:
  p = st.number_input("Prime Number (p)", min_value=11)  # Small for demo, use larger primes in practice
  g = st.number_input("Generator Element (g)", min_value=2)
  q = st.number_input("Order of Subgroup (q)", min_value=10)
  if st.button("Generate Keys"):
    bob = ElGamal(p, g, None)
    public_key, private_key = bob.generate_keypair(q)
    st.success("Key pair generated!")
    st.write("Public Key:", public_key)
    st.write("**Private Key (Keep Secret):**", private_key)  # Emphasize secrecy
else:
  # Input fields for pre-generated keys
  public_key_p = st.number_input("Public Key - p", min_value=11)