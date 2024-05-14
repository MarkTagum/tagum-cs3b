import streamlit as st
import hashlib

def hash_text(text):
    """
    Hashes the text with character-level and overall hashing.

    Args:
        text: The text to hash (str).

    Returns:
        None (prints output to console).
    """
    seen_chars = set()
    for char in text:
        if char not in seen_chars:
            seen_chars.add(char)
            encoded_char = char.encode()
            if char.isspace():
                char_hash = hashlib.sha1(b"<space>").hexdigest().upper()
                st.write(f"{char_hash}")
            else:
                char_hash = hashlib.sha1(encoded_char).hexdigest().upper()
                st.write(f"{char_hash} {char}")
    final_hash = hashlib.sha1(text.encode()).hexdigest().upper()
    st.write(f"{final_hash} {text}")

def display_text(text):
    """
    Displays the provided text without any hashing.

    Args:
        text: The text to display (str).
    """
    st.write(text)

# Streamlit app logic
st.title("Text Hashing with Character-Level Analysis (or Display)")

# Mode selection with switch button
mode = st.selectbox("Mode", ["Text", "Hash"])

user_input = st.text_input("Enter Text:")

if st.button("Process"):
    if mode == "Hash":
        hash_text(user_input)
    else:
        display_text(user_input)