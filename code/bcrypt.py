# requirement : pip install bcrypt
import bcrypt
# def for hashing password with bcrypt method
def hash_bcrypt(password):
    hash_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    return hash_password
# verify password
def verify_password(hashed, plain):
    return bcrypt.checkpw(plain.encode(), hashed)

password = "my_password"
hash_password = hash_bcrypt(password)
# now we can store password in database or to se result like here print it
print(hash_password)