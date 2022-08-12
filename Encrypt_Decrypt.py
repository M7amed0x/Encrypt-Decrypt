#!/usr/bin/python3
import hashlib
import os
os.system("clear")
#---------------------------------------------------------------------------------------------------------------------------------------#
# -------------------------------------------------------- This Tool Encrypt && Decrypt ----------------------------------------------- #
# -------------------------------------------------------- Types Hashes Supported ----------------------------------------------------- #
# --------------------- MD5,SHA1,SHA256,SHA384,SHA224,SHA512,SHA3_256,SHA3_224,SHA3_384,SHA3_512,SHAKE_128,SHAKE_256------------------- #
#---------------------------------------------------------------------------------------------------------------------------------------#
def banner():
    print ('\033[1;31m _   _       ___   _____   _   _         _____   __   _   _____   _____   __    __  _____   _____        _____   _____   _____   _____   __    __  _____   _____  ')
    print ('\033[1;31m| | | |     /   | /  ___/ | | | |       | ____| |  \ | | /  ___| |  _  \  \ \  / / |  _  \ |_   _|      |  _  \ | ____| /  ___| |  _  \  \ \  / / |  _  \ |_   _| ')
    print ('\033[1;31m| |_| |    / /| | | |___  | |_| |       | |__   |   \| | | |     | |_| |   \ \/ /  | |_| |   | |        | | | | | |__   | |     | |_| |   \ \/ /  | |_| |   | |   ')
    print ('\033[1;31m|  _  |   / / | | \___  \ |  _  |       |  __|  | |\   | | |     |  _  /    \  /   |  ___/   | |        | | | | |  __|  | |     |  _  /    \  /   |  ___/   | |   ')
    print ('\033[1;31m| | | |  / /  | |  ___| | | | | |       | |___  | | \  | | |___  | | \ \    / /    | |       | |        | |_| | | |___  | |___  | | \ \    / /    | |       | |   ')
    print ('\033[1;31m|_| |_| /_/   |_| /_____/ |_| |_|       |_____| |_|  \_| \_____| |_|  \_\  /_/     |_|       |_|        |_____/ |_____| \_____| |_|  \_\  /_/     |_|       |_|   ')
banner()
print ('\n')
Hash = input("[+] Encrypt ==> (1)\n\n[+] Decrypt ==> (2)\n\nSelect The Type Of Encryption:\n")
if Hash == "1":
    hash = input ("Enter Your Password Hash: \n")
    type_hash = input ("Enter Your Type Hash: ")
    if type_hash == "md5":
        hash = hashlib.md5(hash.encode('utf-8'))
        print ("HASH MD5 IS: ",hash.hexdigest())
        exit
    elif type_hash == "sha1":
        hash = hashlib.sha1(hash.encode('utf-8'))
        print ("HASH SHA1 Is: ",hash.hexdigest())
        exit
    elif type_hash == "sha256":
        hash = hashlib.sha256(hash.encode('utf-8'))
        print ("HASH SHA256 IS; ",hash.hexdigest())
        exit
    elif type_hash == "sha384":
        hash = hashlib.sha384(hash.encode('utf-8'))
        print ("HASH SHA384 IS: ",hash.hexdigest())
        exit
    elif type_hash == "sha224":
        hash = hashlib.sha224(hash.encode('utf-8'))
        print ("HASH SHA224 IS: ",hash.hexdigest())
        exit
    elif type_hash == "sha512":
        hash = hashlib.sha512(hash.encode('utf-8'))
        print ("HASH SHA512 IS: ",hash.hexdigest())
        exit
    elif type_hash == "sha3_256":
        hash = hashlib.sha3_256(hash.encode('utf-8'))
        print ("HASH SHA3_256 IS: ",hash.hexdigest())
        exit
    elif type_hash == "sha3_224":
        hash = hashlib.sha3_224(hash.encode('utf-8'))
        print ("HASH SHA3_224 IS: ",hash.hexdigest())
        exit
    elif type_hash == "sha3_384":
        hash = hashlib.sha3_384(hash.encode('utf-8'))
        print ("HASH SHA3_384 Is: ",hash.hexdigest())
        quit
    elif type_hash == "sha3_512":
        hash = hashlib.sha3_512(hash.encode('utf-8'))
        print ("HASH SHA3_512 IS: ",hash.hexdigest())
        quit
    elif type_hash == "shake_128":
        hash = hashlib.md5(hash.encode('utf-8'))
        print ("HASH SHAKE_128 IS: ",hash.hexdigest())
        exit
    elif type_hash == "shake_256":
        hash = hashlib.shake_256(hash.encode('utf-8'))
        print ("HASH SHAKE_256",hash.hexdigest())
        exit
    else:
        print ("Error Please Try Again")
if Hash == "2":
    Decrypt_Hash = input ("Enter Your Hash Decrypt: \n")
    pass_found = 0
    File_Wordlist = input("Enter File Wordlist :\n")
try:
    Pass_File = open(File_Wordlist, 'r')
except:
    print ("\nError Please Try Again")
    print (exit)
for word in Pass_File:
    enc_word = word.encode('utf-8')
    hash_word = hashlib.md5(enc_word.strip())
    digest = hash_word.hexdigest()
    if digest == Decrypt_Hash:
        print ("==> Type Hash MD5 ==>\n")
        print ("==> Password Found ==>: ",word)
        pass_found = 1
        break
if not pass_found:
    print ("Password Not Found")
elif hash:
    Decrypt_Hash = input ("Enter Your Hash Decrypt: ")
    pass_found = 0
    File_Wordlist = input("Enter File Wordlists :")
try:
    Pass_File = open(File_Wordlist, 'r')
except:
    print("\nError Please Try Again")
for word in Pass_File:
    enc_word = word.encode('utf-8')
    hash_word = hashlib.sha1(enc_word.strip())
    digest = hash_word.hexdigest()
    if digest == Decrypt_Hash:
        print ("==> Type Hash SHA1 ==>\n")
        print("==> Password Found ==>: ", word)
        pass_found = 1
        break
if not pass_found:
    print("Password Not Found", File_Wordlist, "file")
    print('\n')
elif hash:
    Decrypt_Hash = input ("Enter Your Hash Decrypt: ")
    pass_found = 0
    File_Wordlist = input("Enter File Wordlists :")
try:
    Pass_File = open(File_Wordlist, 'r')
except:
    print("\nError Please Try Again")
    exit
for word in Pass_File:
    enc_word = word.encode('utf-8')
    hash_word = hashlib.sha256(enc_word.strip())
    digest = hash_word.hexdigest()
    if digest == Decrypt_Hash:
        print ("==> Type Hash SHA256 ==>\n")
        print("==> Password Found ==>: ", word)
        pass_found = 1
        break
if not pass_found:
    print("Password Not Found", File_Wordlist, "file")
    print('\n')
    quit
elif hash:
    Decrypt_Hash = input ("Enter Your Hash Decrypt: ")
    pass_found = 0
    File_Wordlist = input("Enter File Wordlists :")
try:
    Pass_File = open(File_Wordlist, 'r')
except:
    print("\nError Please Try Again")
    exit
for word in Pass_File:
    enc_word = word.encode('utf-8')
    hash_word = hashlib.sha384(enc_word.strip())
    digest = hash_word.hexdigest()
    if digest == Decrypt_Hash:
        print ("==> Type Hash SHA384 ==>\n")
        print("==> Password Found ==>: ", word)
        pass_found = 1
        break
if not pass_found:
    print("Password Not Found", File_Wordlist, "file")
    print('\n')
    quit
elif hash:
    Decrypt_Hash = input ("Enter Your Hash Decrypt: ")
    pass_found = 0
    File_Wordlist = input("Enter File Wordlists :")
try:
    Pass_File = open(File_Wordlist, 'r')
except:
    print("\nError Please Try Again")
    exit
for word in Pass_File:
    enc_word = word.encode('utf-8')
    hash_word = hashlib.sha224(enc_word.strip())
    digest = hash_word.hexdigest()
    if digest == Decrypt_Hash:
        print ("==> Type Hash SHA224 ==>\n")
        print("==> Password Found ==>: ", word)
        pass_found = 1
        break
if not pass_found:
    print("Password Not Found", File_Wordlist, "file")
    print('\n')
    quit
elif hash:
    Decrypt_Hash = input ("Enter Your Hash Decrypt: ")
    pass_found = 0
    File_Wordlist = input("Enter File Wordlists :")
try:
    Pass_File = open(File_Wordlist, 'r')
except:
    print("\nError Please Try Again")
    exit
for word in Pass_File:
    enc_word = word.encode('utf-8')
    hash_word = hashlib.sha512(enc_word.strip())
    digest = hash_word.hexdigest()
    if digest == Decrypt_Hash:
        print ("==> Type Hash SHA512 ==>\n")
        print("==> Password Found ==>: ", word)
        pass_found = 1
        break
if not pass_found:
    print("Password Not Found", File_Wordlist, "file")
    print('\n')
    quit
elif hash:
    Decrypt_Hash = input ("Enter Your Hash Decrypt: ")
    pass_found = 0
    File_Wordlist = input("Enter File Wordlists :")
try:
    Pass_File = open(File_Wordlist, 'r')
except:
    print("\nError Please Try Again")
    exit
for word in Pass_File:
    enc_word = word.encode('utf-8')
    hash_word = hashlib.sha3_256(enc_word.strip())
    digest = hash_word.hexdigest()
    if digest == Decrypt_Hash:
        print ("==> Type Hash SHA3_265 ==>\n")
        print("==> Password Found ==>: ", word)
        pass_found = 1
        break
if not pass_found:
    print("Password Not Found", File_Wordlist, "file")
    print('\n')
    quit
elif hash:
    Decrypt_Hash = input ("Enter Your Hash Decrypt: ")
    pass_found = 0
    File_Wordlist = input("Enter File Wordlists :")
try:
    Pass_File = open(File_Wordlist, 'r')
except:
    print("\nError Please Try Again")
    exit()
for word in Pass_File:
    enc_word = word.encode('utf-8')
    hash_word = hashlib.sha3_224(enc_word.strip())
    digest = hash_word.hexdigest()
    if digest == Decrypt_Hash:
        print ("==> Type Hash SHA3_224 ==>\n")
        print("==> Password Found ==>: ", word)
        pass_found = 1
        break
if not pass_found:
    print("Password Not Found", File_Wordlist, "file")
    print('\n')
    quit
elif hash:
    Decrypt_Hash = input ("Enter Your Hash Decrypt: ")
    pass_found = 0
    File_Wordlist = input("Enter File Wordlists :")
try:
    Pass_File = open(File_Wordlist, 'r')
except:
    print("\nError Please Try Again")
    exit
for word in Pass_File:
    enc_word = word.encode('utf-8')
    hash_word = hashlib.sha3_384(enc_word.strip())
    digest = hash_word.hexdigest()
    if digest == Decrypt_Hash:
        print ("==> Type Hash SHA3_384 ==>\n")
        print("==> Password Found ==>: ", word)
        pass_found = 1
        break
if not pass_found:
    print("Password Not Found", File_Wordlist, "file")
    print('\n')
    quit
elif hash:
    Decrypt_Hash = input ("Enter Your Hash Decrypt: ")
    pass_found = 0
    File_Wordlist = input("Enter File Wordlists :")
try:
    Pass_File = open(File_Wordlist, 'r')
except:
    print("\nError Please Try Again")
    exit
for word in Pass_File:
    enc_word = word.encode('utf-8')
    hash_word = hashlib.sha3_512(enc_word.strip())
    digest = hash_word.hexdigest()
    if digest == Decrypt_Hash:
        print ("==> Type Hash SHA3_512 ==>\n")
        print("==> Password Found ==>: ", word)
        pass_found = 1
        break
if not pass_found:
    print("Password Not Found", File_Wordlist, "file")
    print('\n')
    quit
elif hash:
    Decrypt_Hash = input ("Enter Your Hash Decrypt: ")
    pass_found = 0
    File_Wordlist = input("Enter File Wordlists :")
try:
    Pass_File = open(File_Wordlist, 'r')
except:
    print("\nError Please Try Again")
    exit
for word in Pass_File:
    enc_word = word.encode('utf-8')
    hash_word = hashlib.shake_128(enc_word.strip())
    digest = hash_word.hexdigest()
    if digest == Decrypt_Hash:
        print ("==> Type Hash SHAKE_128 ==>\n")
        print("==> Password Found ==>: ", word)
        pass_found = 1
        break
if not pass_found:
    print("Password Not Found", File_Wordlist, "file")
    print('\n')
    quit
elif hash:
    Decrypt_Hash = input ("Enter Your Hash Decrypt: ")
    pass_found = 0
    File_Wordlist = input("Enter File Wordlists :")
try:
    Pass_File = open(File_Wordlist, 'r')
except:
    print("\nError Please Try Again")
    exit
for word in Pass_File:
    enc_word = word.encode('utf-8')
    hash_word = hashlib.shake_256(enc_word.strip())
    digest = hash_word.hexdigest()
    if digest == Decrypt_Hash:
        print ("==> Type Hash SHAKE_256 ==>\n")
        print("==> Password Found ==>: ", word)
        pass_found = 1
        break
if not pass_found:
    print("Password Not Found", File_Wordlist, "file")
    print('\n')
    exit()
else:
    print ("This Hash Not Supported")
    exit()
