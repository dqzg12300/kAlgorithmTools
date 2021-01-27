from Crypto.Cipher import AES
from binascii import b2a_hex, a2b_hex


# 如果text不足16位的倍数就用空格补足为16位
def pad(s): return s + bytes([16 - len(s) % 16] * (16 - len(s) % 16))
def unpad(s): return s[0:(len(s) - s[-1])]


# 加密函数
def cbc_encrypt(key,iv,data):
    mode = AES.MODE_CBC
    cryptos = AES.new(key, mode, iv)
    cipher_text = cryptos.encrypt(pad(data))
    # 因为AES加密后的字符串不一定是ascii字符集的，输出保存可能存在问题，所以这里转为16进制字符串
    return cipher_text


# 解密后，去掉补足的空格用strip() 去掉
def cbc_decrypt(key,iv,data):
    mode = AES.MODE_CBC
    cryptos = AES.new(key, mode, iv)
    plain_text = cryptos.decrypt(data)
    return unpad(plain_text)

def ecb_encrypt(key,data):
    mode = AES.MODE_ECB
    cryptos = AES.new(key, mode)
    cipher_text = cryptos.encrypt(pad(data))
    # 因为AES加密后的字符串不一定是ascii字符集的，输出保存可能存在问题，所以这里转为16进制字符串
    return cipher_text


# 解密后，去掉补足的空格用strip() 去掉
def ecb_decrypt(key,data):
    mode = AES.MODE_ECB
    cryptos = AES.new(key, mode)
    plain_text = cryptos.decrypt(data)
    return bytes.decode(plain_text).rstrip('\0')

def gcm_encrypt(key,iv,nonce,data):
    if len(iv)<=0:
        cipher = AES.new(key, AES.MODE_GCM,nonce=nonce)
    else:
        cipher = AES.new(key, AES.MODE_GCM,iv, nonce=nonce)
    # cipher.update(nonce)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return ciphertext, tag

def gcm_decrypt(key,iv,nonce,data,tag):
    if len(iv)<=0:
        cipher = AES.new(key, AES.MODE_GCM,nonce=nonce)
    else:
        cipher = AES.new(key, AES.MODE_GCM,iv, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(data, tag)
    return plaintext
