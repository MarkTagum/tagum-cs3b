import streamlit as st

def encrypt_decrypt(text, shift_keys, ifdecrypt):
  """
  Encrypts or decrypts text using Caesar Cipher with multiple shift keys.

  Args:
      text: The text to process (str).
      shift_keys: A list of integers representing shift values for each character (list).
      ifdecrypt: Flag indicating encryption (False) or decryption (True) (bool).

  Returns:
      A string containing the encrypted or decrypted text.
  """
  result = ""
  for i, char in enumerate(text):
    if char.isascii() and 32 <= ord(char) <= 126:
      shift = shift_keys[i % len(shift_keys)] * (-1 if ifdecrypt else 1)
      shifted_char = chr((ord(char) - 32 + shift) % 94 + 32)
      result += shifted_char
    else:
      result += char
  return result

st.title("Caesar Cipher with Multiple Shift Keys")

# Input for text
text = st.text_area("Enter Text to Encrypt/Decrypt:")

# Input for shift keys (separated by spaces)
shift_keys_str = st.text_input("Enter Shift Keys (space-separated):")

# Convert shift keys string to a list of integers with error handling
try:
  shift_keys = list(map(int, shift_keys_str.split()))
except ValueError:
  shift_keys = []
  st.error("Invalid input: Please enter comma-separated integers for shift keys.")

# Separate buttons for encryption and decryption
if st.button("Encrypt Text"):
  # Check if any shift keys are provided
  if not shift_keys:
    st.error("Please enter valid shift keys.")
  else:
    # Encrypt the text
    encrypted_text = encrypt_decrypt(text, shift_keys, False)
    # Display encrypted text
    st.write("Encrypted Text:", encrypted_text)

if st.button("Decrypt Text"):
  # Check if any shift keys are provided
  if not shift_keys:
    st.error("Please enter valid shift keys.")
  else:
    # Decrypt the text
    decrypted_text = encrypt_decrypt(text, shift_keys, True)
    # Display decrypted text
    st.write("Decrypted Text:", decrypted_text)