import hashlib
import streamlit as st

def hash_text(text):
    """Hashes the provided text using MD5 and returns the hexadecimal digest."""
    text_bytes = text.encode()
    hasher = hashlib.md5()
    hasher.update(text_bytes)
    return hasher.hexdigest()

def try_decode_hash(hash_value):
    """Attempts to decode a hexadecimal hash value back to the original text.

    This function is for demonstration purposes only and may not always
    be successful depending on the hashing algorithm and potential collisions.

    Args:
        hash_value: The hexadecimal hash string to decode (str).

    Returns:
        The decoded text if successful, or None otherwise (str).
    """
    try:
        # Replace with a more sophisticated decoding attempt if needed
        return bytes.fromhex(hash_value).decode()
    except:
        return None

# Streamlit app logic
st.title("MD5 Hashing/Decoding Tool")

# Mode selection with switch button
mode = st.selectbox("Mode", ["Text to Hash", "Hash to Text"])

user_input = st.text_area("Enter Text/Hash:")

if st.button("Process"):
    if mode == "Text to Hash":
        if user_input:
            text_hash = hash_text(user_input)
            st.success("Text Hashed Successfully!")
            st.write("MD5 Hash of Text:", text_hash)
        else:
            st.warning("Please enter text to hash.")
    else:
        if user_input:
            decoded_text = try_decode_hash(user_input)
            if decoded_text:
                st.success("Hash Decoded Successfully (may not be accurate)!")
                st.write("Decoded Text:", decoded_text)
            else:
                st.warning("Failed to decode hash. Decoding may not always be possible.")
        else:
            st.warning("Please enter a hash to decode.")