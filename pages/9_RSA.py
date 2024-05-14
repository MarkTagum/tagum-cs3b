import streamlit as st
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat
from cryptography.hazmat.backends import default_backend

def generate_rsa_key_pair(public_exponent=65537):
    """Generates an RSA key pair with a specified public exponent."""
    private_key = rsa.generate_private_key(
        public_exponent=public_exponent,
        key_size=2048,  # Use a secure key size (at least 2048 bits)
        backend=default_backend()  # Use a secure backend
    )
    public_key = private_key.public_key()
    return private_key, public_key

def sign_message(message, private_key_pem):
    """Signs a message using RSA with PKCS#1 v1.5 padding."""
    private_key = rsa.load_private_key(
        private_key_pem,
        password=None,  # No password for demonstration (not recommended in production)
        backend=default_backend()
    )
    private_key = private_key.to_private_key(Encoding.PEM, PrivateFormat.PKCS8, encryption_algorithm=padding.NoEncryption())
    signer = private_key.sign(
        message,
        padding.PKCS1v15(algorithm=hashes.SHA256()),
        hashes.SHA256()
    )
    return signer.decode()  # Decode signature to a string for Streamlit display

def verify_signature(message, signature, public_key_pem):
    """Verifies a signature using RSA with PKCS#1 v1.5 padding."""
    public_key = rsa.load_public_key(
        public_key_pem,
        backend=default_backend()
    )
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
    private_key_pem = private_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=padding.NoEncryption()
    )
    public_key_pem = public_key.public_bytes(
        encoding=Encoding.PEM,
        format=PublicFormat.SubjectPublicKeyInfo
    )
    st.write("Private key (PEM format):")
    st.text_area("Private Key", private_key_pem.decode(), disabled=True)
    st.write("Public key (PEM format):")
    st.text_area("Public Key", public_key_pem.decode(), disabled=True)

# Signing and verification
message = st.text_input("Enter message to sign:")
signature_area = st.text_area("Signature")

if private_key_pem := st.session_state.get("private_key_pem") and message:
    signature = sign_message(message.encode(), private_key_pem.encode())
    signature_area.value = signature

if public_key_pem := st.session_state.get("public_key_pem") and message and signature_area.value:
    verification_result = verify_signature(message.encode(), signature_area.value.encode(), public_key_pem.encode())
    st.write("Signature Verification:")
    st.success(verification_result)

# Store keys in session state for persistence across re-runs
if st.button("Save Keys"):
    st.session_state["private_key_pem"] = private_key_pem.decode()
    st.session_state["public_key_pem"] = public_key_pem.decode()
    st.success("Keys saved in session state")