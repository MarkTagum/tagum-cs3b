import streamlit as st
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.exceptions import InvalidSignature
from streamlit_downloader import download_button

# Your functions here...

st.title("RSA Encryption/Decryption Demo")

# Generate keypair on demand (Don't store keys in app!)
if st.button("Generate Keypair"):
    private_key, public_key = generate_keypair()
    st.write("**Warning:** Private key is displayed here for demonstration purposes only. In a real application, it should be kept secret!")
    st.text_area("Private Key", private_key, disabled=True)
    st.text_area("Public Key", public_key, disabled=True)

    # Download keypair
    st.markdown("### Download Keypair")
    st.download_button(
        label="Download Keypair",
        data=f"{private_key}\n---\n{public_key}",
        file_name="rsa_keypair.pem",
        mime="text/plain"
    )

# Upload keypair
uploaded_file = st.file_uploader("Upload Keypair", type="pem")
if uploaded_file:
    private_key, public_key = None, None
    key_pair_data = uploaded_file.read().decode()
    lines = key_pair_data.split("\n---")
    if len(lines) == 2:
        private_key, public_key = lines

    if private_key:
        st.text_area("Private Key", private_key, disabled=True)
    if public_key:
        st.text_area("Public Key", public_key, disabled=True)

mode_option = st.selectbox("Select Mode", ("Encrypt", "Decrypt"))

if mode_option == "Encrypt":
    message = st.text_input("Enter Message to Encrypt")
    public_key_input = st.text_area("Public Key", disabled=True)

    if public_key_input and message:
        encrypted_message = encrypt_message(message, public_key_input)
        st.text_area("Encrypted Message", encrypted_message, disabled=True)

elif mode_option == "Decrypt":
    ciphertext = st.text_input("Enter Ciphertext to Decrypt")
    private_key_input = st.text_area("Private Key", disabled=True)

    if private_key_input and ciphertext:
        decrypted_message = decrypt_message(ciphertext, private_key_input)
        st.text_area("Decrypted Message", decrypted_message, disabled=True)