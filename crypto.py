import string
import sys
import os
import tempfile
import struct
import uuid
import time
#import logging

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from watchdog.observers import Observer
from watchdog.events import LoggingEventHandler
from watchdog.events import FileSystemEventHandler
from watchdog.events import FileCreatedEvent
from watchdog.events import FileDeletedEvent
from watchdog.events import FileModifiedEvent

def calculate256(input, append=None):
    digest = hashes.Hash(hashes.SHA3_256())
    digest.update(input)
    if append != None:
        digest.update(append)

    return digest.finalize()#Returns bytes

def calculate128(input, append=None):
    digest = hashes.Hash(hashes.SHAKE128(16))
    digest.update(input)
    if append != None:
        digest.update(append)

    return digest.finalize()#Returns bytes

class MultiCipher:
    
    hmac = None
    ciphers = []
    encryptors = []
    decryptors = []
    
    def __init__(self, key, iv, ciphersuites=["AESCTR","ChaCha20"]):
        

        self.hmac = hashes.Hash(hashes.SHA3_256())
        self.hmac.update(calculate256(key, b"hmac-key"))

        for c in ciphersuites:#Select cipher suite and operation mode
            match c:
                case "ChaCha20":
                    k = calculate256(key, c.encode("ansi"))
                    nonce = calculate128(iv, (c + "nonce").encode("ansi"))
                    self.ciphers.append(Cipher(algorithms.ChaCha20(k, nonce), mode=None))
                case "AESCTR":
                    k = calculate256(key, c.encode("ansi"))
                    nonce = calculate128(iv, (c + "iv").encode("ansi"))
                    self.ciphers.append(Cipher(algorithms.AES(k), modes.CTR(nonce)))
                case "CamelliaCTR":
                    k = calculate256(key, c.encode("ansi"))
                    nonce = calculate128(iv, (c + "iv").encode("ansi"))
                    self.ciphers.append(Cipher(algorithms.Camellia(k), modes.CTR(nonce)))
                case _:
                    raise Exception("Unsupported cipher: " + c)
        
        for c in self.ciphers:
            self.encryptors.append(c.encryptor())
            self.decryptors.append(c.decryptor())
        

    def update(self, plaintext):
        ct = plaintext
        for e in self.encryptors:#Run all encryptors then mac
            ct = e.update(ct)

        self.hmac.update(ct)
        return ct
        
    def updateDecryptor(self,ct):
        self.hmac.update(ct) #Mac first
        pt = ct
        for d in self.decryptors: #Run all decryptors
            pt = d.update(pt)
        
        return pt

    def finalizeHMAC(self):
        return self.hmac.finalize()

    def verifyHMAC(self,signature):
        return self.hmac.finalize() == signature 
        



def encryptFile(input_file, out_file, key, nonce, fileBuf=4086):
    mc = MultiCipher(key,nonce,ciphersuites=["AESCTR"])
    out_file.write(bytes.fromhex('00')*32)

    while True:
        data = input_file.read(fileBuf)
        if not data:
            break #Reached end of file
        else:
            ct = mc.update(data)
            out_file.write(ct)

    print("Writing hmac tag")
    out_file.seek(0)
    out_file.write(mc.finalizeHMAC())

def decryptFile(input_file, out_file, key, nonce,fileBuf=4086):
    mc = MultiCipher(key,nonce,ciphersuites=["AESCTR"])

    tag = input_file.read(32)
    #print("Read tag from input file:")
    #print(tag)
    while True:
        data = input_file.read(fileBuf)
        if not data:
            break #End of file
        else:
            pt = mc.updateDecryptor(data)
            
        out_file.write(pt)

    print("HMAC verification: ")
    print(mc.verifyHMAC(tag))



def getFileObjSize(f):
    #f = open('chardet-1.0.1.tgz','rb')
    f.seek(0, os.SEEK_END)
    s = f.tell()
    f.seek(0)
    return s

class VaultEventHandler(FileSystemEventHandler):
    
    def __init__(self, filevault) -> None:
        
        super().__init__()
        #print("VaultEventHandler constructor called!")
        self.fv = filevault
        self.addedFiles = []

    def on_created(self, event):
        #print("File created event: " + event.src_path)
        #print("IsDir: " + str(event.is_directory))
        if not event.is_directory:
            print("Adding file to vault")
            #self.addedFiles.append(event.src_path)
            self.fv.addToVault(event.src_path,move=False)
        #print(event)

    def on_deleted(self, event):
        print("File deleted event: " + event.src_path)
        print("IsDir: " + str(event.is_directory))

    def on_modified(self, event):
        #if event.src_path in self.addedFiles:
        #    print("Adding file to vault")
        #    self.fv.addToVault(event.src_path,move=False)
        #    self.addedFiles.remove(event.src_path)
        #print("File modified event: " + event.src_path)
        #print("IsDir: " + str(event.is_directory))
        return

    def on_moved(self, event):
        print("File moved from: " + event.src_path + " to " + event.dest_path)
        print("IsDir: " + str(event.is_directory))
        #print(event)

class filevault:
    def __init__(self, password, salt, encryptedFile, ciphersuites=["ChaCha20"]):
        salt = salt.encode("utf-8")
        kdf = Scrypt(
            salt=salt,
            length=32,#256bit key
            n=2**20,
            r=8,
            p=1,
        )

        start = time.process_time()
        self.key = kdf.derive(password.encode("utf-8"))
        print("Key derivation took: " + str(time.process_time() - start) + "s")

        self.iv = hashes.Hash(hashes.SHA256())
        self.iv.update(salt)
        self.iv = self.iv.finalize()

        self.f = encryptedFile
        self.ciphersuites = ciphersuites

        self.c_enc = MultiCipher(self.key,self.iv,self.ciphersuites)


        kh = hashes.Hash(hashes.SHA256())
        kh.update(self.key)
        kh.update(self.iv)
        kh = kh.finalize()
        try:
            with open(self.f, "rb") as f:
                csize = getFileObjSize(f)
                if csize > 32:
                    print("Opening existing data file!")
                    if kh != f.read(32):
                        #print("Invalid key or iv!")
                        raise ValueError("Invalid key or iv!")
                    else:
                        print("Correct pass/salt!")
                    self.c_enc.update(b'\0' * (csize - 32))
                
        except FileNotFoundError:
            print("File does not yet exist, creating new")
            with open(self.f, "wb") as f:
                f.write(kh)

        
        self.event_handler = VaultEventHandler(self)
        self.observer = Observer()
        
        

    def addToVault(self, inputFile, move=False):
        path = None
        if isinstance(inputFile, str):
            print("Got filepath!")
            path = inputFile
            for i in range(10):
                try:
                    inputFile = open(inputFile, "rb")
                    break
                except:
                    print("Cannot read file, probably open by another process, retrying in " + str(i) + " sec")
                    time.sleep(i)


        with open(self.f,"ab") as f:
            #f.seek(32)
            #print("Writing data to: " + str(f.tell()))
            fsize = getFileObjSize(inputFile)
            if fsize == 0:
                print("Skipping empty file!")
                return

            print("Reading input file at:" + str(inputFile.tell()))

            print("Adding file of size: " + str(fsize))
            
            l = self.c_enc.update(struct.pack('Q',fsize))
            print("Writing encrypted length data to: " + str(f.tell()))
            print(l)
            f.write(l)#Append file size

            filename = os.path.basename(path).encode("utf-8")
            while len(filename)<100:
                filename += b'\0'

            f.write(self.c_enc.update(filename)) #100 bytes filename
            
            #out_file.write(bytes.fromhex('00')*32)

            while True:
                data = inputFile.read(1024*4)
                if not data:
                    break #Reached end of file
                else:
                    ct = self.c_enc.update(data)
                    f.write(ct)

        
        if path != None and move:
            inputFile.close()
            os.remove(path)
        elif path != None:
            inputFile.close()#Just close
        print("File added successfully")

    def openVault(self):
        
        self.c_enc = MultiCipher(self.key,self.iv,self.ciphersuites)#Reset encryptor

        with tempfile.TemporaryDirectory() as tmpdirname:
            print("Temp dir: " + tmpdirname)
            with open(self.f,"rb") as f:
                f.seek(32)

                print("Reading length data at: " + str(f.tell()))
                l = f.read(8)
                if not l:
                    print("No data in this vault yet!")
                    return False

                print("Read encrypted length data")
                print(l)
                readbyteslen = self.c_enc.updateDecryptor(l)
                print(readbyteslen)
                l = struct.unpack('Q',readbyteslen)[0]


                #Read filename
                filename = self.c_enc.updateDecryptor(f.read(100)).decode("utf-8").rstrip('\0')

                pt = b''
                while True:
                    print("Decrypting file of length: " + str(l))
                    
                    start = time.process_time()
                    data = f.read(l)
                    print("Data reading took: " + str(time.process_time() - start) + "s")
                    if not data:
                        break #End of data
                    else:
                        start = time.process_time()
                        pt = self.c_enc.updateDecryptor(data)
                        print("Decrypting took: " + str(time.process_time() - start) + "s")

                        with open(os.path.join(tmpdirname, filename), 'wb') as out_file:
                            out_file.write(pt)


                        newl = f.read(8)
                        if not newl:
                            break
                        else:
                            newl = self.c_enc.updateDecryptor(newl)
                            l = struct.unpack('Q',newl)[0]

                            #ext = self.c_enc.updateDecryptor(f.read(4)).decode("ansi")
                            #print("File extension: " + ext)
                            filename = self.c_enc.updateDecryptor(f.read(100)).decode("utf-8").rstrip('\0')

            print("Starting filesystem observer")
            def handler():
                print("Changes detected")
                return
            self.observer.schedule(self.event_handler, tmpdirname, recursive=True)
            self.observer.start()
            os.startfile(tmpdirname)
            input("Press Enter to close...")

            print("Waiting for observer to stop")
            self.observer.stop()
            self.observer.join()
                    
        return True
                

        #print("HMAC verification: ")
        #print(mc.verifyHMAC(tag))





"""nonce = b"Test1"#os.urandom(16)
key = b"Test2"#os.urandom(32)

encryptfilepath = sys.argv[2]
originalPath = sys.argv[1]
print("Encrypting: " + originalPath + " to " + encryptfilepath)
#Encrypt
with open(originalPath, "rb") as input_file, open(encryptfilepath, "wb") as out_file:
    encryptFile(input_file, out_file, key, nonce, fileBuf=408600)


#Decrypt
with open(encryptfilepath, "rb") as input_file, open(originalPath + ".decrypted", "wb") as out_file:
    decryptFile(input_file, out_file, key, nonce, fileBuf=408600)


"""

def verifyHMAC(key, input_file, fileBuf=4086):

    hmac = hashes.Hash(hashes.SHA3_256())
    hmac.update(calculate256(key, b"hmac-key"))

    tag_from_file = input_file.read(32)
    while True:
        data = input_file.read(fileBuf)
        if not data:
            break #Reached end of file
        else:
            hmac.update(data)

    return hmac.finalize() == tag_from_file

#print("HMAC verification")
#with open(encryptfilepath,"rb") as f:
#    print(verifyHMAC(key,f))

