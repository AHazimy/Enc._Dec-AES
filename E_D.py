"""1. Ability to Encrypt and Decrypt Directory"""
"""DONE===>2. Ability to Encrypt and Decrypt Files"""

from PyQt5.QtCore import *
from PyQt5.QtGui import *
from PyQt5.QtWidgets import *
from hashlib import md5
from Cryptodome.Cipher import AES
from os import urandom
from MainWindow import Ui_MainWindow


class MainWindow(QMainWindow, Ui_MainWindow):
    def __init__(self, parent=None):
        super(MainWindow, self).__init__(parent)
        self.setupUi(self)
        self.btn_browse_source.clicked.connect(lambda: self.browse(self.lineEdit_source, "src"))
        self.btn_browse_destination.clicked.connect(lambda: self.browse(self.lineEdit_destination, "dest"))
        self.btn_run.clicked.connect(lambda: self.choose_enc_dec(self.lineEdit_password.text(), self.lineEdit_source.text(), self.lineEdit_destination.text()))
          
    def browse(self, line_edit, status):
        if status == "src":
            filename=QFileDialog.getOpenFileName(self, 'Open File', '', '')
            line_edit.setText(filename[0])
        elif status == "dest":
            filename=QFileDialog.getSaveFileName(self, 'Save File', '', '')
            line_edit.setText(filename[0])

    def encrypt(self, in_file, out_file, password, key_length=32):
        global bs
        global salt
        bs = AES.block_size #16 bytes
        salt = urandom(bs) #return a string of random bytes
        key, iv = self.derive_key_and_iv(password, salt, key_length, bs)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        out_file.write(salt)
        finished = False

        while not finished:
            chunk = in_file.read(1024 * bs) 
            if len(chunk) == 0 or len(chunk) % bs != 0:#final block/chunk is padded before encryption
                padding_length = (bs - len(chunk) % bs) or bs
                chunk += str.encode(padding_length * chr(padding_length))
                finished = True
            out_file.write(cipher.encrypt(chunk))

    def decrypt(self, in_file, out_file, password, key_length=32):
        global bs
        global salt
        bs = AES.block_size
        salt = in_file.read(bs)
        key, iv = self.derive_key_and_iv(password, salt, key_length, bs)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        next_chunk = ''
        finished = False
        while not finished:
            chunk, next_chunk = next_chunk, cipher.decrypt(in_file.read(1024 * bs))
            if len(next_chunk) == 0:
                padding_length = chunk[-1]
                chunk = chunk[:-padding_length]
                finished = True 
            out_file.write(bytes(x for x in chunk)) 

    def derive_key_and_iv(self, password, salt, key_length, iv_length): #derive key and IV from password and salt.
        d = d_i = b''
        while len(d) < key_length + iv_length:
            d_i = md5(d_i + str.encode(password) + salt).digest() #obtain the md5 hash value
            d += d_i
        return d[:key_length], d[key_length:key_length+iv_length]

     #shouldn't be something this simple
    def run_enc(self, password, src_path, dest_path):
        with open(src_path, 'rb') as in_file, open(dest_path, 'wb') as out_file:
            self.encrypt(in_file, out_file, password)

    def run_dec(self, password, src_path,dest_path):
        with open(src_path, 'rb') as in_file, open(dest_path, 'wb') as out_file:
            self.decrypt(in_file, out_file, password)
            
    def choose_enc_dec(self, password, src_path,dest_path):
        if self.rb_encrypt.isChecked():
            self.run_enc(password, src_path,dest_path)
        elif self.rb_decrypt.isChecked():
            self.run_dec(password, src_path,dest_path)
            
            
app=QApplication([])
window=MainWindow()
window.show()
app.exec()