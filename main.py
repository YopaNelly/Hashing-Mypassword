
import hashlib

password = 'mypassword123'
salt = 'somesalt'

# Convert the password and salt to bytes
password_bytes = password.encode('utf-8')
salt_bytes = salt.encode('utf-8')

# Combine the salt and password and hash them using SHA256
hashed_bytes = hashlib.sha256(salt_bytes + password_bytes).digest()

# Convert the hash bytes to a hexadecimal string
hashed_password = ''.join(['{:02x}'.format(b) for b in hashed_bytes])

print('Original password:', password)
print('Hashed password:', hashed_password)

