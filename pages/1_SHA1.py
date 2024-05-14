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

st.title("Text Hashing with Character-Level Analysis")
user_text = st.text_input("Enter Text to Hash:")

if st.button("Hash Text"):
  hash_text(user_text)