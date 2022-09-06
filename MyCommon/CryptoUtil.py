import base64

from Crypto.Cipher import AES, DES
from Crypto import Random
from Crypto.Hash import SHA
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5 as PKCS1_cipher
from Crypto.Signature import PKCS1_v1_5 as PKCS1_signature
from Crypto.Cipher import ARC2

# 如果text不足16位的倍数就用空格补足为16位
def pad(s): return s + bytes([16 - len(s) % 16] * (16 - len(s) % 16))
def unpad(s): return s[0:(len(s) - s[-1])]

def rc2pad(s): return s + bytes([8 - len(s) % 8] * (8 - len(s) % 8))

# 加密函数
def aes_cbc_encrypt(key,iv,data):
    mode = AES.MODE_CBC
    cryptos = AES.new(key, mode, iv)
    cipher_text = cryptos.encrypt(pad(data))
    # 因为AES加密后的字符串不一定是ascii字符集的，输出保存可能存在问题，所以这里转为16进制字符串
    return cipher_text


# aes解密 解密后，去掉补足的空格用strip() 去掉
def aes_cbc_decrypt(key,iv,data):
    mode = AES.MODE_CBC
    cryptos = AES.new(key, mode, iv)
    plain_text = cryptos.decrypt(data)
    return unpad(plain_text)
# aes加密
def aes_ecb_encrypt(key,data):
    mode = AES.MODE_ECB
    cryptos = AES.new(key, mode)
    cipher_text = cryptos.encrypt(pad(data))
    # 因为AES加密后的字符串不一定是ascii字符集的，输出保存可能存在问题，所以这里转为16进制字符串
    return cipher_text

# 解密后，去掉补足的空格用strip() 去掉
def aes_ecb_decrypt(key,data):
    mode = AES.MODE_ECB
    cryptos = AES.new(key, mode)
    plain_text = cryptos.decrypt(data)
    return bytes.decode(plain_text).rstrip('\0')

def aes_gcm_encrypt(key,iv,nonce,data):
    if len(iv)<=0:
        cipher = AES.new(key, AES.MODE_GCM,nonce=nonce)
    else:
        cipher = AES.new(key, AES.MODE_GCM,iv, nonce=nonce)
    # cipher.update(nonce)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return ciphertext, tag

def aes_gcm_decrypt(key,iv,nonce,data,tag):
    if len(iv)<=0:
        cipher = AES.new(key, AES.MODE_GCM,nonce=nonce)
    else:
        cipher = AES.new(key, AES.MODE_GCM,iv, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(data, tag)
    return plaintext

# 加密函数
def des_cbc_encrypt(key,iv,data):
    mode = DES.MODE_CBC
    cryptos = DES.new(key, mode, iv)
    cipher_text = cryptos.encrypt(rc2pad(data))
    return cipher_text

def des_cbc_decrypt(key,iv,data):
    mode = DES.MODE_CBC
    cryptos = DES.new(key, mode, iv)
    plain_text = cryptos.decrypt(data)
    return unpad(plain_text)

def des_ecb_encrypt(key,data):
    mode = DES.MODE_ECB
    cryptos = DES.new(key, mode)
    cipher_text = cryptos.encrypt(pad(data))
    return cipher_text

# 解密后，去掉补足的空格用strip() 去掉
def des_ecb_decrypt(key,data):
    mode = DES.MODE_ECB
    cryptos = DES.new(key, mode)
    plain_text = cryptos.decrypt(data)
    return bytes.decode(plain_text).rstrip('\0')

def rc2_cbc_encrypt(key,iv,data):
    cryptos = ARC2.new(key, ARC2.MODE_CBC,iv)
    cipher_text = cryptos.encrypt(rc2pad(data))
    return cipher_text

def rc2_cbc_decrypt(key,iv,data):
    cryptos = ARC2.new(key, ARC2.MODE_CBC,iv)
    cipher_text = cryptos.decrypt(data)
    return cipher_text

def rc2_ebc_encrypt(key,data):
    iv = Random.new().read(ARC2.block_size)
    cryptos = ARC2.new(key, ARC2.MODE_ECB)
    cipher_text = cryptos.encrypt(rc2pad(data))
    return cipher_text

def rc2_ebc_decrypt(key,data):
    cryptos = ARC2.new(key, ARC2.MODE_ECB)
    cipher_text = cryptos.decrypt(data)
    return cipher_text
#生成密钥对
def generateKey():
    random_generator = Random.new().read
    rsa = RSA.generate(2048, random_generator)
    # 生成私钥
    private_key = rsa.export_key()
    # print(private_key.decode('utf-8'))
    # 生成公钥
    public_key = rsa.publickey().exportKey()
    # print(public_key.decode('utf-8'))
    return public_key, private_key

#rsa加密
def rsa_encrypt(pubkey,data):
    pub_key = RSA.importKey(str(pubkey))
    cipher = PKCS1_cipher.new(pub_key)
    rsa_text = base64.b64encode(cipher.encrypt(bytes(data.encode("utf8"))))
    # print(rsa_text.decode('utf-8'))
    return rsa_text

#rsa解密
def rsa_decrypt(prikey,data):
    pri_key = RSA.importKey(prikey)
    cipher = PKCS1_cipher.new(pri_key)
    back_text = cipher.decrypt(base64.b64decode(data), 0)
    # print(back_text.decode('utf-8'))
    return back_text
#rsa私钥签名
def rsa_pri_signature(prikey,data):
    pri_key = RSA.importKey(prikey)
    signer = PKCS1_signature.new(pri_key)
    digest = SHA.new()
    digest.update(data.encode("utf8"))
    sign = signer.sign(digest)
    signature = base64.b64encode(sign)
    # print(signature.decode('utf-8'))
    return signature
#rsa公钥签名
def rsa_pub_signature(pubkey,data,signature):
    pub_key = RSA.importKey(pubkey)
    verifier = PKCS1_signature.new(pub_key)
    digest = SHA.new()
    digest.update(data.encode("utf8"))
    return verifier.verify(digest, base64.b64decode(signature))

