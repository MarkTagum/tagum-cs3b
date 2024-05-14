import hashlib
import streamlit as st

def hash_text(text):
  """Hashes the provided text using MD5 and returns the hexadecimal digest."""
  text_bytes = text.encode()
  hasher = hashlib.md5()
  hasher.update(text_bytes)
  return hasher.hexdigest()

def hash_file(filepath):
  """Hashes the contents of a file using MD5 and returns the hexadecimal digest.

  Args:
    filepath: The path to the file to hash (str).

  Returns:
    A string containing the MD5 hash in hexadecimal format,
    or None if the file cannot be opened.
  """
  try:
    with open(filepath, 'rb') as f:
      data = f.read()
      hasher = hashlib.md5()
      hasher.update(data)
      return hasher.hexdigest()
  except FileNotFoundError:
    st.error(f"Error: File not found - {filepath}")
    return None

st.title("MD5 Hashing Tool")

# Text input with label
text_input = st.text_area("Enter Text to Hash:")

# File upload with label
uploaded_file = st.file_uploader("Choose a File to Hash:")

# Hash button
if st.button("Hash"):
  if text_input:
    text_hash = hash_text(text_input)
    st.success("Text Hashed Successfully!")
    st.write("MD5 Hash of Text:", text_hash)
  elif uploaded_file:
    file_hash = hash_file(uploaded_file.name)
    if file_hash:
      st.success("File Hashed Successfully!")
      st.write("MD5 Hash of File:", file_hash)
  else:
    st.warning("Please enter text or upload a file to hash.")