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

# Example usage
p = 11  # Small prime number for demonstration (use larger primes in practice)
g = 2  # Generator element in the finite field
q = 10  # Order of the subgroup generated by g

# Bob generates keypair
bob = ElGamal(p, g, None)
public_key, private_key = bob.generate_keypair(q)
print("Bob's public key:", public_key)
print("Bob's private key:", private_key)  # Keep this secret

# Alice encrypts a message
message = "Secret message"
k = random.randint(1, q - 1)  # Random key for encryption
ciphertext = bob.encrypt(message, k)
print("Ciphertext:", ciphertext)

# Bob decrypts the message
decrypted_message = bob.decrypt(*ciphertext)
print("Decrypted message:", decrypted_message)