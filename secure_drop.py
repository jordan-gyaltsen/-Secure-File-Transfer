import json
import pwinput
#TESTING
import sys
from os import urandom
from pickle import dump, load
from base64 import b64encode, b64decode
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
from Crypto.PublicKey import RSA

#TESTING
class EncryptedMessage:
    def __init__(self, enc_key, enc_data, tag, nonce, iv):
        self.enc_key = enc_key
        self. enc_data = enc_data
        self.tag = tag
        self.nonce = nonce
        self.iv = iv

contactDict = {}

def add():
    flag = 0
    fp = open("contacts.txt", "rb")
    if not fp.read():
        flag = 1
    fp.close()
    if flag == 0:
        with open("contacts.txt", 'rb') as fd:
            obj2 = load(fd)
        iv2 = b64decode(obj2.iv)

        with open("private.pem", 'r') as fd2:
            private_key = RSA.import_key(fd2.read()) 
        fd2.close()
        cipher_rsa = PKCS1_OAEP.new(private_key)
        decrypted_rsa_key = cipher_rsa.decrypt(obj2.enc_key)
            
        key = decrypted_rsa_key
        cipher = AES.new(key, AES.MODE_CBC, iv2)
        decipher_text = unpad(cipher.decrypt(obj2.enc_data), AES.block_size)
        decipher_text2 = str(decipher_text, 'utf-8')
        jsonContactDict = decipher_text2
        contactDict = json.loads(jsonContactDict)
    #fp = open("contacts.txt", "r")
    #jsonContactDict = fp.read()
    #contactDict = json.loads(jsonContactDict)
    #fp.close()
    else:
        contactDict = {}
    #fp = open("contacts.txt", "w") 
    contact_name = input("Enter Full Name: ")
    contact_email = input("Enter Email Address: ")
    contactDict[contact_name] = contact_email
    jsonContactDict = json.dumps(contactDict)

    #START OF IMPLEMENTING SECURITY
    data = bytes(jsonContactDict, 'utf-8')
    first_key = urandom(16)
    cipher = AES.new(first_key, AES.MODE_CBC)
    cipher_text = cipher.encrypt(pad(data, AES.block_size))
    iv = b64encode(cipher.iv).decode('utf-8')
    ct = b64encode(cipher_text).decode('utf-8')
    with open('receiver.pem', 'r') as fd:
        recipient_key = RSA.import_key(fd.read())
    fd.close()
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    encrypted_rsa_key = cipher_rsa.encrypt(first_key)
    enc_key = encrypted_rsa_key
    enc_data = cipher_text
    tag = urandom(16)
    nonce = urandom(16)
    obj1 = EncryptedMessage(enc_key, enc_data, tag, nonce, iv)
    with open("contacts.txt", "wb") as fd:
        dump(obj1, fd)
    
    
    #fp.write(jsonContactDict)
    #fp.close()
    print("Contact Added")


def list_contacts():
    with open("contacts.txt", 'rb') as fd:
            obj2 = load(fd)
    iv2 = b64decode(obj2.iv)

    with open("private.pem", 'r') as fd2:
        private_key = RSA.import_key(fd2.read()) 
    fd2.close()
    cipher_rsa = PKCS1_OAEP.new(private_key)
    decrypted_rsa_key = cipher_rsa.decrypt(obj2.enc_key)
        
    key = decrypted_rsa_key
    cipher = AES.new(key, AES.MODE_CBC, iv2)
    decipher_text = unpad(cipher.decrypt(obj2.enc_data), AES.block_size)
    decipher_text2 = str(decipher_text, 'utf-8')
    print(decipher_text2)

fp = open("users.txt", "r")
if not fp.read():
    fp.close()
    print("No users are registered with this client.")
    ans = input("Do you want to register a new user (y/n)? ")
    while ans != 'y' and ans != 'n':
        ans = input("Invalid input, try again: ")
    if ans == 'n':
        exit
    else:
        name = input("Enter Full Name: ")
        email = input("Enter Email Address: ")
        pswd = pwinput.pwinput(prompt = "Enter Password: ", mask = '*')
        pswd_check = pwinput.pwinput(prompt = "Re-enter Password: ", mask = '*')
        while pswd != pswd_check:
            print("Passwords do not match, try again: ")
            pswd = pwinput.pwinput(prompt = "Enter Password: ", mask = '*')
            pswd_check = pwinput.pwinput(prompt = "Re-enter Password: ", mask = '*')
        fp = open("users.txt", "w")
        userDict = {}
        userDict[email] = pswd
        jsonUserDict = json.dumps(userDict)
        fp.write(jsonUserDict)
        fp.close()
        
        print("Passwords Match.")
        print("User Registered.")
        print("Exiting SecureDrop.")
        exit

else:
    fp = open("users.txt", "r")
    jsonUserDict = fp.read();
    userDict = json.loads(jsonUserDict)
    
    email = input("Enter Email Address: ")
    pswd = pwinput.pwinput(prompt = "Enter Password: ", mask = '*')
    while pswd != userDict[email]:
        print("Email and Password Combination Invalid")
        print("\n")
        email = input("Enter Email Address: ")
        pswd = pwinput.pwinput(prompt = "Enter Password: ", mask = '*')
    print("Welcome to SecureDrop.")
    print("Type \"help\" For Commands.")

    ans = input()
    while ans != "exit":
        match ans:
            case "help":
                print("\"add\" -> Add a new contact")
                print("\"list\" -> List all online contacts")
                print("\"send\" -> Transfer file to contact")
                print("\"exit\" -> Exit SecureDrop")
            case "add":
                add()
            case "list":
                list_contacts()
            case "send":
                print("send")
        ans = input()
    print("Exiting SecureDrop.")
    exit
