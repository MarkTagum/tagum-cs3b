import streamlit as st
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat

def generate_rsa_key_pair(public_exponent=65537):
    """Generates an RSA key pair with a specified public exponent."""
    private_key = rsa.generate_private_key(
        public_exponent=public_exponent,
        key_size=2048,  # Use a secure key size (at least 2048 bits)
        backend=default_backend()  # Use a secure backend
    )
    public_key = private_key.public_key()
    return private_key, public_key

def sign_message(message, private_key):
    """Signs a message using RSA with PKCS#1 v1.5 padding."""
    private_key = private_key.to_private_key(Encoding.PEM, PrivateFormat.PKCS8, encryption_algorithm=padding.NoEncryption())
    signer = private_key.sign(
        message,
        padding.PKCS1v15(algorithm=hashes.SHA256()),
        hashes.SHA256()
    )
    return signer.decode()  # Decode signature to a string for Streamlit display

def verify_signature(message, signature, public_key):
    """Verifies a signature using RSA with PKCS#1 v1.5 padding."""
    public_key = public_key.to_public_key(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    try:
        public_key.verify(
            signature.encode(),  # Encode signature for verification
            message,
            padding.PKCS1v15(algorithm=hashes.SHA256()),
            hashes.SHA256()
        )
        return "Signature is valid"
    except Exception as e:
        return f"Signature verification failed: {e}"

# Streamlit app logic
st.title("RSA Signing with Streamlit")

# Key generation (optional, can be pre-generated and stored securely)
if st.button("Generate RSA Key Pair"):
    private_key, public_key = generate_rsa_key_pair()
    st.write("Private key (PEM format):")
    st.text_area("Private Key", private_key.decode(), disabled=True)
    st.write("Public key (PEM format):")
    st.text_area("Public Key", public_key.decode(), disabled=True)

# Signing and verification
uploaded_private_key = st.file_uploader("Upload Private Key (PEM)", type="pem")
uploaded_public_key = st.file_uploader("Upload Public Key (PEM)", type="pem")
message = st.text_input("Enter message to sign:")

if uploaded_private_key is not None and message:
    private_key_pem = uploaded_private_key.read()
    signature = sign_message(message.encode(), private_key_pem)
    st.write("Signature:")
    st.text_area("Signature", signature)

if uploaded_public_key is not None and message and signature:
    public_key_pem = uploaded_public_key.read()
    verification_result = verify_signature(message.encode(), signature.encode(), public_key_pem)
    st.write("Signature Verification:")
    st.success(verification_result)