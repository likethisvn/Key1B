import binascii
from hashlib import sha256, sha512
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA512, RIPEMD160
import base58

# Datele furnizate
mkey_full_hex = "b9ce876f42188517c305e69a895a94c596919441d784dfd24e34c1e1e58cd84f330a08b7c3fae5076e4316d755374245a1897ee901b8542d0004428b"
ckey_hex = "82719c6505331295e15907f6983e7a1f0399893c2bf519256583a9644d24238ef64b1e6f22f6319b994ec7e1380b1c88"
pubkey_hex = "03e2112950635617079b77a9b16b1d73a1efa0b8b92398fdd6c1a4f1f21d3e196b"
passphrase = "123"  # Parola pentru decriptare
salt_hex = "a1897ee901b8542d"
iv_hex = "96919441d784dfd24e34c1e1e58cd84f"
iterations = 279179

# Convertește hex în bytes
mkey_full_bytes = binascii.unhexlify(mkey_full_hex)
ckey_bytes = binascii.unhexlify(ckey_hex)
pubkey_bytes = binascii.unhexlify(pubkey_hex)
salt = binascii.unhexlify(salt_hex)
iv = binascii.unhexlify(iv_hex)

# Verificăm lungimea datelor de intrare
print(f"Length of mkey_full_bytes: {len(mkey_full_bytes)}")
print(f"Length of ckey_bytes: {len(ckey_bytes)}")
print(f"Length of pubkey_bytes: {len(pubkey_bytes)}")

class Crypter_pycrypto(object):
    def SetKeyFromPassphrase(self, vKeyData, vSalt, nDerivIterations, nDerivationMethod):
        if nDerivationMethod != 0:
            return 0
        data = vKeyData + vSalt
        for _ in range(nDerivIterations):
            data = sha512(data).digest()
        self.SetKey(data[:32])
        self.SetIV(data[32:32+16])
        return len(data)

    def SetKey(self, key):
        self.chKey = key

    def SetIV(self, iv):
        self.chIV = iv[:16]

    def Decrypt(self, data):
        cipher = AES.new(self.chKey, AES.MODE_CBC, self.chIV)
        decrypted = cipher.decrypt(data)
        pad_len = decrypted[-1]
        if isinstance(pad_len, int) and pad_len > 0 and pad_len <= 16:
            decrypted = decrypted[:-pad_len]
        return decrypted

crypter = Crypter_pycrypto()

def derive_master_key(passphrase, salt, iterations):
    return PBKDF2(passphrase, salt, dkLen=32, count=iterations, hmac_hash_module=SHA512)

def aes_decrypt(key, iv, ciphertext):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(ciphertext)
    pad_len = decrypted[-1]
    if isinstance(pad_len, int) and pad_len > 0 and pad_len <= 16:
        decrypted = decrypted[:-pad_len]
    return decrypted

def pubkey_to_address(pubkey_bytes):
    sha256_pubkey = sha256(pubkey_bytes).digest()
    ripemd160_pubkey = RIPEMD160.new(sha256_pubkey).digest()
    hashed_pubkey = b'\x00' + ripemd160_pubkey
    checksum = sha256(sha256(hashed_pubkey).digest()).digest()[:4]
    address_bytes = hashed_pubkey + checksum
    address = base58.b58encode(address_bytes)
    return address

def private_key_to_wif(private_key_bytes, compressed=True):
    extended_key = b'\x80' + private_key_bytes
    if compressed:
        extended_key += b'\x01'
    first_sha256 = sha256(extended_key).digest()
    second_sha256 = sha256(first_sha256).digest()
    checksum = second_sha256[:4]
    wif_bytes = extended_key + checksum
    wif = base58.b58encode(wif_bytes)
    return wif

# Derivăm cheia master din parolă și salt
derived_key = derive_master_key(passphrase, salt, iterations)
print(f"Derived Key: {binascii.hexlify(derived_key).decode()}")

# Decriptăm cheia master folosind derived_key și iv
# Folosim toți cei 60 de bytes din mkey_full_bytes pentru decriptare
master_key_encrypted = mkey_full_bytes[:48]
master_key = aes_decrypt(derived_key, iv, master_key_encrypted)
print(f"Master Key: {binascii.hexlify(master_key).decode()}")

# Derivăm un IV pentru ckey din SHA256(public_key)
iv_ckey = sha256(pubkey_bytes).digest()[:16]
print(f"IV for ckey: {binascii.hexlify(iv_ckey).decode()}")

# Decriptează ckey folosind master_key și iv_ckey
decrypted_ckey = aes_decrypt(master_key, iv_ckey, ckey_bytes)
decrypted_ckey_hex = binascii.hexlify(decrypted_ckey).decode()
print(f"Decrypted ckey: {decrypted_ckey_hex}")

# Verificăm dacă cheia privată este validă
if len(decrypted_ckey) == 48:
    private_key_candidate = decrypted_ckey[-32:]
    private_key_candidate_hex = binascii.hexlify(private_key_candidate).decode()
    print(f"Candidate Private Key (last 32 bytes): {private_key_candidate_hex}")
    if len(private_key_candidate) != 32:
        raise ValueError("Extracted private key length is not 32 bytes")
    decrypted_ckey = private_key_candidate
elif len(decrypted_ckey) != 32:
    raise ValueError("Invalid private key length")

# Generăm adresa Bitcoin din cheia publică
address = pubkey_to_address(pubkey_bytes)

# Conversia cheii private în format WIF (cheie comprimată)
private_key_wif = private_key_to_wif(decrypted_ckey, compressed=True)

# Afișăm rezultatele
print("Decrypted ckey (Private Key Hex):", binascii.hexlify(decrypted_ckey).decode())
print("Bitcoin Address:", address)
print("Public Key:", pubkey_hex)
print("Private Key (WIF):", private_key_wif)
