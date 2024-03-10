import streamlit as st

def encrypt_decrypt(text, shift_keys, ifdecrypt):
    """
    Encrypts a text using Caesar Cipher with a list of shift keys.
    Args:
        text: The text to encrypt.
        shift_keys: A list of integers representing the shift values for each character.
        ifdecrypt: flag if decrypt or encrypt
    Returns:
        A string containing the encrypted text if encrypt and plain text if decrypt
    """
    result = ""
    for i, char in enumerate(text):
        if char.isascii() and 32 <= ord(char) <= 126:
            if ifdecrypt:
                shift = shift_keys[i % len(shift_keys)] * -1
            else:
                shift = shift_keys[i % len(shift_keys)]
            shifted_char = chr((ord(char) - 32 + shift) % 94 + 32)
            result += shifted_char
        else:
            result += char
            
        st.write(i, char, shift_keys[i % len(shift_keys)], result[i])
        
    return result
    
def main():
    
    # Example usage
    text = bytes(st.text_area("Enter shift keys (space-separated):").encode())
    shift_keys = st.text_input("Enter numbers (comma-separated):")
    try:
        # Convert the input string to a list of integers
        selected_numbers = list(map(int, shift_keys.split(',')))
    except ValueError:
        # Handle the case where input is not a valid list of numbers
        selected_numbers = []
    
    encrypted_text = encrypt_decrypt(text, shift_keys, False)
    st.write("----------")
    decrypted_text = encrypt_decrypt(encrypted_text, shift_keys, True)
    st.write("----------")
    
    st.write("Text:", text)
    st.write("Shift keys:", " ".join(map(str, shift_keys)))
    
    st.write("Cipher:", encrypted_text)
    st.write("Decrypted text:", decrypted_text)
    
if __name__ == "__main__":
    main()