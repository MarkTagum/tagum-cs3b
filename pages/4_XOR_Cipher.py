import streamlit as st
def xor_encrypt(plaintext, key):
    """Encrypts plaintext using XOR cipher with the given key, printing bits involved."""

    ciphertext = bytearray()
    for i in range(len(plaintext)):
        plaintext_byte = plaintext[i]
        key_byte = key[i % len(key)]
        cipher_byte = plaintext_byte ^ key_byte
        ciphertext.append(cipher_byte)
        st.write(f"Plaintext byte: {bin(plaintext_byte)[2:]:>08} = {chr(plaintext_byte)}")
        st.write(f"Key byte:       {bin(key_byte)[2:]:>08} = {chr(key_byte)}")
        st.write(f"XOR result:     {bin(cipher_byte)[2:]:>08} = {chr(cipher_byte)}")
        st.write("--------------------")
        
    return ciphertext

def xor_decrypt(ciphertext, key):
    """Decrypts ciphertext using XOR cipher with the given key."""
        
    return xor_encrypt(ciphertext, key)   # XOR decryption is the same as encryption


# Example usage:
plaintext = bytes(st.text_area("Plaintext:").encode())
key = bytes(st.text_area("Key:").encode())

if st.button("Encrypt!"):
    if len(plaintext) >= len(key):
        if plaintext != key:
            cipher = xor_encrypt(plaintext, key)
            st.write(f"Ciphertext:", "".join([f"{chr(byte_val)}" for byte_val in cipher]))
            
            decrypt = xor_decrypt(cipher, key)
            st.write(f"Decrypted:", "".join([f"{chr(byte_va)}" for byte_va in decrypt]))
        else:
            st.write("Plaintext should not be equal to the key")
    else:
        st.write("Plaintext length should be equal or greater than the length of key")



