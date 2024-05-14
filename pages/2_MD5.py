import hashlib

def hash_text(text):
  """Hashes the provided text using MD5 and returns the hexadecimal digest.

  Args:
      text: The text to hash (str).

  Returns:
      A string containing the MD5 hash in hexadecimal format.
  """
  text_bytes = text.encode()  # Convert text to bytes for hashing
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
    with open(filepath, 'rb') as f:  # Open in binary reading mode
      data = f.read()  # Read the entire file content
      hasher = hashlib.md5()
      hasher.update(data)
      return hasher.hexdigest()
  except FileNotFoundError:
    print(f"Error: File not found - {filepath}")
    return None

# Example usage for text hashing
text = "This is some text to hash with MD5."
text_hash = hash_text(text)
print(f"MD5 Hash of Text: {text_hash}")

# Example usage for file hashing (replace 'your_file.txt' with your actual file)
file_path = "your_file.txt"
file_hash = hash_file(file_path)
if file_hash:
  print(f"MD5 Hash of File ({file_path}): {file_hash}")