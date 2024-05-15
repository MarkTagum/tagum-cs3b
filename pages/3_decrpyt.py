import streamlit as st
import hashlib


def hash_text(text):
  """
  Hashes the text with character-level and overall hashing.

  Args:
      text: The text to hash (str).

  Returns:
      A dictionary containing character-level hashes and the final hash (dict).
  """
  seen_chars = set()
  char_hashes = {}
  for char in text:
    if char not in seen_chars:
      seen_chars.add(char)
      encoded_char = char.encode()
      if char.isspace():
        char_hash = hashlib.sha1(b"<space>").hexdigest().upper()
      else:
        char_hash = hashlib.sha1(encoded_char).hexdigest().upper()
      char_hashes[char] = char_hash
      st.write(f"{char_hash} {char}")
  final_hash = hashlib.sha1(text.encode()).hexdigest().upper()
  return {"char_hashes": char_hashes, "final_hash": final_hash}


def homepage():
  """Displays the homepage with design elements."""
  st.title("Applied Cryptography Application")

  # Hero section with image and call to action
  st.markdown("""
  <div style="display: flex; align-items: center; justify-content: center;">
    <img src="path/to/your/banner.jpg" alt="Cryptography Banner" style="width: 70%; height: auto;">
  </div>
  <div style="text-align: center;">
    <h2>Secure Your Data with Applied Cryptography</h2>
    <p>Encrypt, decrypt, and hash your data with ease using our user-friendly tools.</p>
    <button type="button" class="btn btn-primary">Get Started</button>
  </div>
  """, unsafe_allow_html=True)

  # Content section with explanations and visuals
  st.write("---")  # Horizontal separator

  st.subheader("What We Offer:")
  st.markdown("""
  <ul>
    <li>Encryption: Transform your data into a secure format for safe storage and transmission.</li>
    <li>Decryption: Recover your encrypted data back to its original form.</li>
    <li>Hashing: Generate a unique fingerprint of your data to verify its integrity.</li>
  </ul>
  """, unsafe_allow_html=True)

  # Add icons or GIFs for each technique (replace with your image paths)
  col1, col2, col3 = st.columns(3)
  with col1:
    st.image("path/to/encryption_icon.png", width=100)
    st.caption("Encryption")
  with col2:
    st.image("path/to/decryption_icon.png", width=100)
    st.caption("Decryption")
  with col3:
    st.image("path/to/hashing_icon.png", width=100)
    st.caption("Hashing")

  # Showcase user interface with screenshot or animation
  st.subheader("Easy to Use Interface:")
  st.write("Experience a seamless workflow with our intuitive design.")
  st.image("path/to/homepage_screenshot.png")  # Replace with your screenshot

  # Optionally, include a short explainer video
  # st.video("path/to/cryptography_ explainer.mp4")


def main():
  st.title("Applied Cryptography Application")

  # Descriptions for cryptographic algorithms (unchanged)
  descriptions = {
      # ... (existing descriptions)
  }

  # Streamlit UI setup
  crypto_options = [
      "Homepage",
      "Caesar Cipher",
      "Fernet Symmetric Encryption",
      "Symmetric File Encryption",
      "RSA Asymmetric Encryption",
      "SHA-1 Hashing",
      "SHA-256 Hashing",
      "SHA-512 Hashing",
      "MD5 Hashing",
  ]
  selected_crypto = st.sidebar.selectbox("Select Cryptographic Technique", crypto_options)

  if selected_crypto == "Homepage":
    homepage()
    return

  if selected_crypto in descriptions:
    st.sidebar.subheader(selected_crypto)
    st.sidebar.write(descriptions[selected_crypto])