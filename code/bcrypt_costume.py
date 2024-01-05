import hashlib
import os
import base64
# def for hashing password with bcrypt method without using buildin bcrypt functions
def custom_bcrypt(password, salt_rounds=12):
    salt = os.urandom(16)  # 16 bytes
    if not (4 <= salt_rounds <= 31):
        raise ValueError("Salt rounds must be between 4 and 31 inclusive.")
    salt_rounds = 2**salt_rounds    
    # Hash the password 
    hash_password = hashlib.sha256(password.encode()).digest()
    for _ in range(salt_rounds):
        hash_password = hashlib.sha256(hash_password + salt).digest()   
    # Encode the salt and hashed 
    bcrypt_hash = b"$2b$" + base64.b64encode(salt + hash_password)   
    return bcrypt_hash.decode('utf-8')

password = "my_secure_password"
hash_password = custom_bcrypt(password)
# now we can store password in database or to se result like here print it
print("Hashed Password:", hash_password)
