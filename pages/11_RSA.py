import streamlit as st
import cryptography
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
import base64

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