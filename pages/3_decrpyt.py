import streamlit as st
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import (
    serialization,
    hashes,
    asymmetric,
    padding,
)
from cryptography.hazmat.backends import default_backend
import hashlib
import base64
import os

def homepage():
    """Displays the welcome message and introductory text."""
    st.markdown("<h2>Welcome to Cryptography Toolkit</h2>", unsafe_allow_html=True)
    st.write("This toolkit provides various cryptographic techniques for encryption, decryption, and hashing.")
    st.write("")

    # Add image placeholders if desired
    # st.image('path/to/image1.jpg', width=300, caption='...')
    # st.image('path/to/image2.jpg', width=300, caption='...')

def main():
    """The main function of the Streamlit app."""
    st.title("Applied Cryptography Application")

    # Cryptographic algorithm descriptions
    descriptions = {
        "Caesar Cipher": "...",
        "Fernet Symmetric Encryption": "...",
        "RSA Asymmetric Encryption": "...",
        "SHA-1 Hashing": "...",
        "SHA-256 Hashing": "...",
        "SHA-512 Hashing": "...",
        "MD5 Hashing": "...",
        "Symmetric File Encryption": "...",
    }

    # User interface elements and interactions
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
    ]
    selected_crypto = st.sidebar.selectbox("Select Cryptographic Technique", crypto_options)

    if selected_crypto == "Homepage":
        homepage()
        return

    if selected_crypto in descriptions:
        st.sidebar.subheader(selected_crypto)
        st.sidebar.write(descriptions[selected_crypto])

    # Implement logic for handling user input, encryption/decryption, hashing, and displaying results based on the selected option

    # Move the submit button to the sidebar
    if st.sidebar.button("Submit"):
        processed_text = ""
        try:
            if selected_crypto == "Caesar Cipher":
                text = st.text_area("Enter Text")
                shift_key = st.number_input("Shift Key (Caesar Cipher)", min_value=1, max_value=25, step=1, value=3)
                if_decrypt = st.checkbox("Decrypt")
                processed_text, error_message, original_shift_keys = caesar_cipher(text, shift_key, if_decrypt)

            # Add logic for other cryptographic techniques here

            if error_message:
                st.error(error_message)
            else:
                st.write("Processed Text:", processed_text)

        except Exception as e:
            st.error(f"An error occurred: {str(e)}")

if __name__ == "__main__":
    main()

def caesar_cipher(text, shift_keys, if_decrypt):
    """
    Encrypts or decrypts text using the Caesar Cipher with multiple shift keys.

    Args:
        text: The text to process (str).
        shift_keys: A list of integers representing shift values for each character (list).
        if_decrypt: Flag indicating encryption (False) or decryption (True) (bool).

    Returns:
        A tuple containing:
            - The encrypted or decrypted text (str).
            - (Optional) An error message if invalid shift keys are provided (str).
            - (Optional) A list of the original shift keys used (list of int).
    """

    result = ""
    error_message = None
    original_shift_keys = shift_keys.copy()  # Track original keys for potential error reporting

    if not shift_keys or not all(isinstance(key, int) for key in shift_keys):
        error_message = "Invalid input: Please enter comma-separated integers for shift keys."
    else:
        for i, char in enumerate(text):
            if 32 <= ord(char) <= 126:
                shift = shift_keys[i % len(shift_keys)] * (-1 if if_decrypt else 1)
                shifted_char = chr((ord(char) - 32 + shift) % 94 + 32)
                result += shifted_char
            else:
                result += char

    return result, error_message, original_shift_keys

# Streamlit App Structure (assuming integration into a larger app)
st.title("Caesar Cipher with Multiple Shift Keys")

text = st.text_area("Enter Text to Encrypt/Decrypt:")
shift_keys_str = st.text_input("Enter Shift Keys (comma-separated):")

try:
    shift_keys = list(map(int, shift_keys_str.split(",")))
except ValueError:
    shift_keys = []
    st.error("Invalid input: Please enter comma-separated integers for shift keys.")

if st.button("Process Text"):
    processed_text, error_message, original_shift_keys = caesar_cipher(text, shift_keys, False)

    if error_message:
        st.error(error_message)
    else:
        decrypted_text = caesar_cipher(processed_text, original_shift_keys, True)[0]  # Use original keys for decryption

        st.write("Original Text:", text)
        st.write("Shift Keys:", ", ".join(map(str, original_shift_keys)))
        st.write("Encrypted Text:", processed_text)
        st.write("Decrypted Text:", decrypted_text)