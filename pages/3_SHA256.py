import hashlib
import streamlit as st

def hash_file(file):
  """Hashes the contents of a uploaded file using SHA-256."""
  # Read the uploaded file in chunks
  hasher = hashlib.sha256()
  for chunk in file.chunks():
    hasher.update(chunk)
  return hasher.hexdigest()

def main():
  # Add a file uploader widget
  uploaded_file = st.file_uploader("Choose a file to hash:")

  if uploaded_file is not None:
    # Hash the uploaded file
    file_hash = hash_file(uploaded_file)
    st.write(f"File Hash (SHA-256): {file_hash}")

if __name__ == '__main__':
  main()