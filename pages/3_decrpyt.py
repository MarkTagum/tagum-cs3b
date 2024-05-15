import streamlit as st
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
import hashlib
import base64
import os


def homepage():
    """Displays the welcome message and application description"""
    st.markdown("<h2>Welcome to Cryptography Toolkit</h2>", unsafe_allow_html=True)
    st.write("This toolkit provides various cryptographic techniques for encryption, decryption, and hashing.")
    st.write("")

    # Center-align the images
    st.markdown("<div style='text-align: center;'>", unsafe_allow_html=True)

    st.image('435792060_908559531280445_5041796525148081874_n.jpg', width=300, caption='Francis Arroyo')
    st.image('80ba58d9-8951-4f51-a6aa-6b0dd67acad5.jpg', width=300, caption='Ma Veronica Beltrano')
    st.image('36962e81-2167-4f1f-8aac-39ffc2d272e1.jpg', width=300, caption='Ma Antoinette Sisno')

    # Close the center-aligned container
    st.markdown("</div>", unsafe_allow_html=True)

    st.write("Please select a technique from the sidebar to get started.")


def main():
    """
    Sets up the Streamlit user interface and calls functions based on user selections
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
        "MD5 Hashing"
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
            shift_key = st.number_input("Shift Key (Caesar Cipher)", min_value=1, max_