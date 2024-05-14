import hashlib
import streamlit as st

def hash_text(text):
  """Hashes the provided text using MD5 and returns the hexadecimal digest."""
  text_bytes = text.encode()
  hasher = hashlib.md5()
  hasher.update(text_bytes)
  return hasher.hexdigest()

st.title("MD5 Hashing Tool")

# Text input with label
text_input = st.text_area("Enter Text to Hash:")

# Hash button
if st.button("Hash"):
  if text_input:
    text_hash = hash_text(text_input)
    st.success("Text Hashed Successfully!")
    st.write("MD5 Hash of Text:", text_hash)
  else:
    st.warning("Please enter text to hash.")