import streamlit as st
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
import hashlib
import base64
import random
import os

def homepage():
    """
    Displays the welcome message and application description on the homepage.
    """
    st.markdown("<h2>Welcome to Cryptography Toolkit</h2>", unsafe_allow_html=True)
    st.write("This toolkit provides various cryptographic techniques for encryption, decryption, and hashing.")
    st.write("")

    st.write("Please select a technique from the sidebar to get started.")


def main():
    """
    The main function that runs the entire application.
    """
    st.title("Applied Cryptography Application")

    # Description for each cryptographic algorithm
    descriptions = {
        "Caesar Cipher": "The Caesar Cipher is one of the simplest and most widely known encryption techniques. It is a substitution cipher where each letter in the plaintext is shifted a certain number of places down or up the alphabet.",
        "Fernet Symmetric Encryption": "Fernet is a symmetric encryption algorithm that uses a shared secret key to encrypt and decrypt data. It provides strong encryption and is easy to use.",
        "RSA Asymmetric Encryption": "RSA (Rivest-Shamir-Adleman) is an asymmetric encryption algorithm that uses a public-private key pair. It is widely used for secure communication and digital signatures.",
        "SHA-1 Hashing": "SHA-1 is a cryptographic hash function that produces a 160-bit (20-byte) hash value. It is commonly used for data integrity verification.",
        "SHA-256 Hashing": "SHA-256 is a cryptographic hash function that produces a 256-bit (32-byte) hash value. It is commonly used for data integrity verification.",
        "SHA-512 Hashing": "SHA-512 is a cryptographic hash function that produces a 512-bit (64-byte) hash value. It provides stronger security than SHA-256.",
        "MD5 Hashing": "MD5 is a widely used cryptographic hash function that produces a 128-bit (16-byte) hash value. It is commonly used for checksums and data integrity verification.",
        "Symmetric File Encryption": "Symmetric encryption technique to encrypt and decrypt files using Fernet."
    }

    # Streamlit UI setup
    crypto_options = [
        "Homepage",
        "Caesar Cipher",
        "Fernet Symmetric Encryption",
        "Symmetric File Encryption",
        "RSA Asymmetric Encryption",
        "SHA-1 Hashing",
        "SHA-256 Hashing",
        "SHA-512 Hashing",
        "MD5 Hashing",
        "Diffie Hellman"
    ]
    selected_crypto = st.sidebar.selectbox("Select Cryptographic Technique", crypto_options)

    if selected_crypto == "Homepage":
        homepage()
        return

    if selected_crypto in descriptions:
        st.sidebar.subheader(selected_crypto)
        st.sidebar.write(descriptions[selected_crypto])
    
    if selected_crypto in ["Caesar Cipher", "Fernet Symmetric Encryption", "RSA Asymmetric Encryption"]:
        text = st.text_area("Enter Text")
        if selected_crypto == "Caesar Cipher":
            shift_key = st.number_input("Shift Key (Caesar Cipher)", min_value=1, max_value=25, step=1, value=3)
        if selected_crypto == "Fernet Symmetric Encryption":
            key = st.text_input("Enter Encryption Key")
        elif selected_crypto == "RSA Asymmetric Encryption":
            key = st.text_area("Enter Public Key (Encryption) / Private Key (Decryption)")
        if_decrypt = st.checkbox("Decrypt")
    
    if selected_crypto in ["SHA-1 Hashing", "SHA-256 Hashing", "SHA-512 Hashing", "MD5 Hashing"]:
        text_or_file = st.radio("Hash Text or File?", ("Text", "File"))
        if text_or_file == "Text":
            text = st.text_area("Enter Text")
        else:
            file_uploaded = st.file_uploader("Upload a file")

    if selected_crypto == "Symmetric File Encryption":
        file_uploaded = st.file_uploader("Upload a file")
        key = st.text_input("Enter Encryption Key")
        if_decrypt = st.checkbox("Decrypt")

    if selected_crypto == "Diffie Hellman":
          # Get prime number (p) and primitive root (g) from user input with validation
        try:
            p = int(st.text_input("Enter a large prime number (p):"))
            g = int(st.text_input("Enter a primitive root modulo p (g):"))
        except ValueError:
            st.error("Please enter valid integers for p and g.")
            return

        # Validate prime number using a more reliable Miller-Rabin primality test
        if not is_prime(p):
            st.error("p must be a large prime number. Please try again.")
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
        st.write("Bob's Shared Secret (should match Alice's):", bob_shared_secret)

    if st.button("Submit"):
        processed_text = ""
        try:
            if selected_crypto == "Caesar Cipher":
                processed_text, _, _ = caesar_cipher(text, shift_key, if_decrypt)
            elif selected_crypto == "Fernet Symmetric Encryption":
                processed_text, _, _ = fernet_encrypt_decrypt(text, key, if_decrypt)
            elif selected_crypto == "RSA Asymmetric Encryption":
                processed_text, _, _ = rsa_encrypt_decrypt(text, key, if_decrypt)
            elif selected_crypto == "SHA-1 Hashing":
                if text_or_file == "Text":
                    processed_text = sha1_hash(text)
                else:
                    processed_text = hash_file(file_uploaded, "sha1")
            elif selected_crypto == "SHA-256 Hashing":
                if text_or_file == "Text":
                    processed_text = hash_text(text, "sha256")
                else:
                    processed_text = hash_file(file_uploaded, "sha256")
            elif selected_crypto == "SHA-512 Hashing":
                if text_or_file == "Text":
                    processed_text = hash_text(text, "sha512")
                else:
                    processed_text = hash_file(file_uploaded, "sha512")
            elif selected_crypto == "MD5 Hashing":
                if text_or_file == "Text":
                    processed_text = hash_text(text, "md5")
                else:
                    processed_text = hash_file(file_uploaded, "md5")

            elif selected_crypto == "Symmetric File Encryption":
                if file_uploaded is not None:
                    original_filename = file_uploaded.name
                    if if_decrypt:
                        decrypted_data, filename = fernet_file_decrypt(file_uploaded, key, original_filename)
                        if decrypted_data:
                            st.download_button("Download Decrypted File", decrypted_data, file_name=filename)
                    else:
                        encrypted_data, file_hash = fernet_file_encrypt(file_uploaded, key)
                        if encrypted_data:
                            st.write(f"Encrypted file hash: {file_hash}")
                            st.download_button("Download Encrypted File", encrypted_data, file_name="Decrypted_" + original_filename)
                else:
                    processed_text = "No file uploaded."

        except Exception as e:
            st.error(f"An error occurred: {str(e)}")
        else:
            st.write("Processed Text:", processed_text)

def caesar_cipher(text, shift_key, if_decrypt):
    """Encrypts or decrypts text using the Caesar Cipher."""
    result = ""
    for char in text:
        if 32 <= ord(char) <= 125:
            shift = shift_key if not if_decrypt else -shift_key
            new_ascii = ord(char) + shift
            while new_ascii > 125:
                new_ascii -= 94
            while new_ascii < 32:
                new_ascii += 94
            result += chr(new_ascii)
        else:
            result += char
    return result, None, None  # Caesar Cipher doesn't generate keys

def fernet_encrypt_decrypt(text, key, if_decrypt):
    """Encrypts or decrypts text using the Fernet symmetric encryption."""
    if not key:
        key = Fernet.generate_key()
        st.write("Generated Fernet Secret Key:", key.decode())
    fernet = Fernet(key.encode())
    if if_decrypt:
        return fernet.decrypt(text.encode()).decode(), None, None
    else:
        return fernet.encrypt(text.encode()).decode(), key, None

def rsa_encrypt_decrypt(text, key, if_decrypt):
    """Encrypts or decrypts text using RSA asymmetric encryption."""
    if not key:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = key.public_key()
        # Generate public key and display it
        public_key_pem = public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
        st.write("Generated RSA Public Key:")
        st.code(public_key_pem.decode())

        # Generate private key in PKCS#1 format and display it
        private_key_pem = key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.TraditionalOpenSSL, encryption_algorithm=serialization.NoEncryption())
        st.write("Generated RSA Secret Key:")
        st.code(private_key_pem.decode())
    if if_decrypt:
        try:
            private_key = serialization.load_pem_private_key(
                key.encode(),
                password=None,
                backend=default_backend()
            )
            decrypted_text = private_key.decrypt(
                base64.b64decode(text),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            ).decode()
            return decrypted_text, None, None
        except Exception as e:
            st.write("Error during decryption:", e)
            return "Decryption Error: " + str(e), None, None  # Return error message
    else:
        if isinstance(key, str):
            key = key.encode()
        public_key = serialization.load_pem_public_key(key)
        encrypted_text = public_key.encrypt(text.encode(), padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
        return base64.b64encode(encrypted_text).decode(), None, key

def hash_text(text, algorithm):
    """Hashes the text using the specified algorithm."""
    return hashlib.new(algorithm, text.encode()).hexdigest()


def sha1_hash(text):
    """Hashes the text using SHA-1."""
    return hashlib.sha1(text.encode()).hexdigest()


def hash_file(file, algorithm):
    """Computes the hash of a file using the specified algorithm."""
    hash_function = hashlib.new(algorithm)
    file.seek(0)  # Ensure we're at the start of the file
    while True:
        data = file.read(65536)
        if not data:
            break
        hash_function.update(data)
    file.seek(0)  # Reset file pointer to beginning after hashing
    return hash_function.hexdigest()
def fernet_file_encrypt(file_uploaded, key):
    """Encrypts a file using Fernet symmetric encryption."""
    if not key:
        raise ValueError("Please provide an encryption key.")
    fernet = Fernet(key.encode())
    file_data = file_uploaded.read()
    encrypted_data = fernet.encrypt(file_data)
    # Generate a random filename to avoid conflicts
    filename = f"encrypted_{random.randint(100000,999999)}"
    return encrypted_data, filename


def fernet_file_decrypt(file_uploaded, key, original_filename):
    """Decrypts a file using Fernet symmetric encryption."""
    if not key:
        raise ValueError("Please provide a decryption key.")
    fernet = Fernet(key.encode())
    try:
        decrypted_data = fernet.decrypt(file_uploaded.read())
    except fernet.InvalidKey:
        st.error("Invalid decryption key. Please check the key and try again.")
        return None, None
    return decrypted_data, original_filename  # Return original filename for download

def generate_key_pair(p, g):
  """Generates a public and private key pair for a user in Diffie-Hellman.

  Args:
      p: A large prime number (int).
      g: A primitive root modulo p (int).

  Returns:
      A tuple containing the private key (int) and public key (int).
  """

  if not is_prime(p):
      raise ValueError("p must be a large prime number.")

  private_key = random.randint(1, p - 1)
  public_key = pow(g, private_key, p)  # Calculate public key using modular exponentiation
  return private_key, public_key

def is_prime(num):
  """Performs a primality test on a number using the Miller-Rabin test.

  Args:
      num: The number to test for primality (int).

  Returns:
      True if the number is prime, False otherwise.
  """

  if num <= 1:
      return False
  elif num <= 3:
      return True
  elif num % 2 == 0 or num % 3 == 0:
      return False

  d = num - 1
  while d % 2 == 0:
      d //= 2

  for _ in range(5):  # Increase iterations for stronger primality testing
      a = random.randrange(2, num - 1)
      x = pow(a, d, num)
      if x == 1 or x == num - 1:
          continue
      while d != num - 1:
          x = pow(x, 2, num)
          d *= 2
          if x == num - 1:
              break
      else:
          return False
  return True

if __name__ == "__main__":
    main()

