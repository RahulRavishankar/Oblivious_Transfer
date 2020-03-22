from hashlib import sha256
from cryptography.fernet import Fernet
import base64
import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import random


class Alice:
    def __init__(self):
        self.a=-1
        self.A=-1
        self.messages=["Coupon1","Coupon2"]
        self.keys=["",""]     
        self.hashcodes=["",""]
    
    def choose_a(self):
        self.a=random.randint(1,10)     
    
    def get_a(self):
        return self.a

    def getA(self):
        return self.A

    def calculateHashcodes(self,B,g,b):            
        self.hashcodes[0]=sha256(str(pow(B,self.a)).encode()).hexdigest()               #This is not the actual key used for encryption 
        self.hashcodes[1]=sha256(str(pow(int((B/self.A)),self.a)).encode()).hexdigest()      

    def getHashCodes(self):
        return self.hashcodes

    def getKeys(self):
        return self.keys

    def getEncryptedMessages(self):
        #GENERATE KEYS
        salt1 =os.urandom(16)        
        kdf1 = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt1,
            iterations=1000,
            backend=default_backend()
        )
        self.keys[0]= base64.urlsafe_b64encode(kdf1.derive(self.messages[0].encode())) 

        salt2 =os.urandom(16)       
        kdf2 = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt2,
            iterations=1000,
            backend=default_backend()
        )
        self.keys[1]= base64.urlsafe_b64encode(kdf2.derive(self.messages[1].encode())) 

        #ENCRYPT MESSAGES
        f1=Fernet(self.keys[0])
        f2=Fernet(self.keys[1])
        return [f1.encrypt(self.messages[0].encode()),f2.encrypt(self.messages[1].encode())]
        
        def getKeys(self):
            return self.keys

        def getHashCodes(self):
            return self.hashcodes

class Bob:
    def __init__(self):
        self.b=-1
        self.c=-1
        self.B=-1
        self.hashcode=""
        self.decryptionKey=-1    

    def choose_b(self):
        self.b=random.randint(1,10)
    
    def choose_c(self):
        self.c=random.randint(0,1)
        
    def calulateB(self,A):
        if(self.c ==0):
            self.B=pow(g,self.b)
        
        elif(self.c==1):
            self.B=A*pow(g,self.b)
    
    def getB(self):
        return self.B

    def getc(self):
        return self.c


if __name__ == "__main__":
    alice=Alice()
    bob=Bob()
    g=7
    print("Value of g:",g)

    alice.choose_a()
    a=alice.get_a()
    alice.A=pow(g,a)
    print("Alice chose a=",a)
    print("Value of A=",alice.getA())

    bob.choose_b()
    print("Bob chose b=",bob.b)
    bob.choose_c()
    print("Bob  chose c=",bob.c)

    A=alice.getA()
    bob.calulateB(A)   
    print("Value of B=",bob.B) 
    bob.hashcode=sha256(str(pow(A,bob.b)).encode()).hexdigest()
    print("Decryption key present with Bob:",bob.hashcode)

    B=bob.getB()
    alice.calculateHashcodes(B,g,bob.b)

    hashcodes=alice.getHashCodes()
    print("Encryption keys present with Alice: "+str(hashcodes[0])+" and "+str(hashcodes[1]))
    keys=alice.getKeys()
    print("\nEncrypting Messages...........")
    EncryptedMessages=alice.getEncryptedMessages()
    print("Encrypted messages sent by Alice: "+str(EncryptedMessages[0])+" and "+str(EncryptedMessages[1]))
    
    print("\nDecrypting Messages...........")
    c=bob.getc()
    #comparing hashcodes present with Alice and Bob instead of the encrypted messages
    if(hashcodes[c]==bob.hashcode):      
        #decrypt message
        f=Fernet(keys[c])
        print("Message Received: "+f.decrypt(EncryptedMessages[c]).decode())
    else:
        print("Error Detected! Invalid message")

    

