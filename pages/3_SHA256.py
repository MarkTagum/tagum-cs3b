import hashlib

def hash_file(filename):
  """Hashes the contents of a file using SHA-256."""
  # Open the file in binary mode
  with open(filename, "rb") as f:
    # Read the file contents in chunks
    data = f.read()
  # Hash the data using SHA-256
  hasher = hashlib.sha256(data)
  return hasher.hexdigest()

# Example usage
filename = "my_file.txt"
file_hash = hash_file(filename)
print(f"File hash: {file_hash}")