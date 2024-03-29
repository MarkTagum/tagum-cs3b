import streamlit as st
def is_prime(n):
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0 or n % 3 == 0:
        return False
    i = 5
    while i * i <= n:
        if n % i == 0 or n % (i + 2) == 0:
            return False
        i += 6
    return True
    
def gcd(a, b):
    while b:
        a, b = b, a % b
    return a
    
def power_mod(base, exponent, modulus):
    
    return pow(base, exponent, modulus)
    
def primitive_input(prompt):
    while True:
        user_input = input(prompt)
        try:
            n = int(user_input)
            if n > 1:
                return n
            else:
                st.write("Please enter a number greater then 1.")
        except ValueError:
            st.write("Please enter a valid integer")
    
def find_primitive_roots(q):
    primitive_roots = []
    for g in range(1, q):
        if gcd(g, q) == 1:
            is_primitive = True
            residues = set()
            for power in range(1, q):
                residue = power_mod(g, power, q)
                if residue in residues:
                    is_primitive = False
                    break
                residues.add(residue)
                if power == 1:
                    st.write(f"{g}^{power} mod {q} = {residue}|", end='')
                else:
                    st.write(f"{g}^{power} mod {q} = {residue}", end='')
                    if power == q - 1:
                        st.write(f" ==> {g} is primitive root of {q}|", end='')
                    else:
                        st.write("|", end='')
                     
            st.write()
            if is_primitive:
                primitive_roots.append(g)
    return primitive_roots
    
def check_primitive_root(q, g):
    if not is_prime(q):
        return False, []
        
    primitive_roots = find_primitive_roots(q)
    if g in primitive_roots:
        return True, primitive_roots
    else:
        return False, primitive_roots

# Example Usage:    
p = st.number_input("Primitive Number:", min_value=2, step=1)
g = st.number_input("Primitive Root:", min_value=1, step=1)

if st.button("Check Primitive Root"):
    is_primitive, primitive_roots = check_primitive_root(p, g)
    if is_prime(p):
        if is_primitive:
            st.success(f"{g} is primitive root: {is_primitive} {primitive_roots}")
        else:   
            st.error(f"{g} is NOT primitive root of {p} - List of Primitive roots: {primitive_roots}")

    else:
        st.error(f"{p} is not a prime number!!")
