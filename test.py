import os, random, struct
from Cryptodome.Cipher import AES

def encrypt_file(key, filename, chunk_size=64*1024):
    output_filename = filename + '.encrypted'
    iv = ''.join(chr(random.randint(0, 0xFF)) for i in range(16))
    encryptor = AES.new(key, AES.MODE_CBC, iv)
    filesize = os.path.getsize(filename)
    with open(filename, 'rb') as inputfile:
        with open(output_filename, 'wb') as outputfile:
            outputfile.write(struct.pack('<Q', filesize))
            outputfile.write(iv)
            while True:
                chunk = inputfile.read(chunk_size)
                if len(chunk) == 0:
                    break
                elif len(chunk) % 16 != 0:
                    chunk += ' ' * (16 - len(chunk) % 16)
                outputfile.write(encryptor.encrypt(chunk))
                
encrypt_file("123asd123asd123asd", 'Original.xlsx')