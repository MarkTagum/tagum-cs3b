
import random
import streamlit as st

def generate_key_pair(p, g):
  """Generates a public and private key pair for a user.

  Args:
      p: A large prime number (int).
      g: A primitive root modulo p (int).

  Returns:
      A tuple containing the private key (int) and public key (int).
  """
  private_key = random.randint(1, p - 1)
  public_key = pow(g, private_key, p)  # Calculate public key using modular exponentiation
  return private_key, public_key

def main():
  """Main function for Diffie-Hellman key exchange in Streamlit."""
  st.title("Diffie-Hellman Key Exchange")

  # Get prime number (p) and primitive root (g) from user input with validation
  try:
    p = int(st.text_input("Enter a large prime number (p):"))
    g = int(st.text_input("Enter a primitive root modulo p (g):"))
  except ValueError:
    st.error("Please enter valid integers for p and g.")
    return

  # Generate key pairs for Alice and Bob
  alice_private, alice_public = generate_key_pair(p, g)
  bob_private, bob_public = generate_key_pair(p, g)

  # Display key pairs for Alice and Bob
  st.write("Alice's Private Key:", alice_private)
  st.write("Alice's Public Key:", alice_public)
  st.write("Bob's Private Key:", bob_private)
  st.write("Bob's Public Key:", bob_public)

  # Calculate shared secrets
  alice_shared_secret = pow(bob_public, alice_private, p)
  bob_shared_secret = pow(alice_public, bob_private, p)

  # Display shared secrets
  st.write("Alice's Shared Secret:", alice_shared_secret)
  st.write("Bob's Shared Secret:", bob_shared_secret)

if __name__ == "__main__":
  main()