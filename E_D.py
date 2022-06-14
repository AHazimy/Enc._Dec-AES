"""DONE===>1. Ability to Encrypt and Decrypt Directory"""
"""DONE===>2. Ability to Encrypt and Decrypt Files"""
"""DONE===>######### Big Bug ###########3. Fix The path or the name or the type for the decrypted files and folders"""
"""3. Should check if the password is correct, if not ===>QMessageBox"""
"""DONE===>4. Fix the design"""
"""5. Fix imported Libraries"""
"""DONE===>6. Merge compress_folder() with the main function of enc_dec"""
"""DONE===>7. Be careful about just one button to enc and dec, so if we clicked on this button the two functions will run, and thats a big mistake
            And the second reson is for sugregation of lineEdits, beacusei dont enter line edits of dec yet"""
"""8. Try gzip(tar.gz) or 'tar' library instead of zipfile"""

from PyQt5.QtCore import *
from PyQt5.QtGui import *
from PyQt5.QtWidgets import *
from hashlib import md5
from Cryptodome.Cipher import AES
from os import urandom, remove
import os
from MainWindow import Ui_MainWindow
import shutil
from zipfile import ZipFile
from os.path import basename
import zipfile
from pathlib import Path
from datetime import datetime as dt
from Cryptodome.Util.Padding import pad
# import gzip


class MainWindow(QMainWindow, Ui_MainWindow):
    def __init__(self, parent=None):
        super(MainWindow, self).__init__(parent)
        self.setupUi(self)
        self.btn_browse_source_file_enc.clicked.connect(lambda: self.browse(self.lineEdit_source, "file"))
        self.btn_browse_source_fldr_enc.clicked.connect(lambda: self.browse(self.lineEdit_source, "fldr"))
        self.btn_browse_source_dec.clicked.connect(lambda: self.browse(self.lineEdit_source_dec, "file"))
        self.btn_browse_destination.clicked.connect(lambda: self.browse(self.lineEdit_destination, "fldr"))
        self.btn_browse_destination_dec.clicked.connect(lambda: self.browse(self.lineEdit_destination_dec, "fldr"))
        
        self.btn_run_enc.clicked.connect(lambda: self.choose_enc_dec(self.lineEdit_password.text(), self.lineEdit_password_confirm.text(), self.lineEdit_source.text(), self.lineEdit_destination.text()))
        self.btn_run_dec.clicked.connect(lambda: self.choose_enc_dec(self.lineEdit_password_dec.text(), None, self.lineEdit_source_dec.text(), self.lineEdit_destination_dec.text()))
        # self.btn_test.clicked.connect(lambda: self.test(self.lineEdit_destination.text(), self.lineEdit_source.text()))
        
    def compress_folder(self, output, input):
        if self.rb_encrypt.isChecked():
            shutil.make_archive(output, 'zip', input)
        else:
            shutil.unpack_archive(input, output)

        
    def browse(self, line_edit, typ):
        if typ == 'fldr':
            dirName=QFileDialog.getExistingDirectory(None, 'Select a folder:', 'C:\\',QFileDialog.ShowDirsOnly)
            line_edit.setText(dirName)
        elif typ == 'file':
            filename=QFileDialog.getOpenFileName(self, 'Open File', '', '')
            line_edit.setText(filename[0])

        
        
    #My work is here      
    # def browse(self, line_edit, status, btn):
    #     if btn=='folder':
    #         condition_1=None
    #         condition_2=None
    #         condition_3=(self.tabWidget.currentIndex()==1)
    #     elif btn=='file':
    #         condition_1=(self.tabWidget.currentIndex()==1)
    #         condition_2=(self.tabWidget.currentIndex()==0)
    #         condition_3=None
    #     if status == "src":
    #         if (self.rb_file.isChecked() and self.tabWidget.currentIndex()==1) or (self.rb_folder.isChecked() and self.tabWidget.currentIndex()==1) or (self.rb_file.isChecked() and self.tabWidget.currentIndex()==0):
    #             filename=QFileDialog.getOpenFileName(self, 'Open File', '', '')
    #             line_edit.setText(filename[0])
    #         else:
    #             dirName=QFileDialog.getExistingDirectory(None, 'Select a folder:', 'C:\\',QFileDialog.ShowDirsOnly)
    #             line_edit.setText(dirName)
    #     elif status == "dest":
    #         # if (self.rb_file.isChecked() and self.tabWidget.currentIndex()==1) or (self.rb_folder.isChecked() and self.tabWidget.currentIndex()==1):
    #         filename=QFileDialog.getExistingDirectory(None, 'Select a folder:', 'C:\\',QFileDialog.ShowDirsOnly)
    #         line_edit.setText(filename)
    #         # else:
    #         #     filename=QFileDialog.getSaveFileName(self, 'Save File', '', '')
    #         #     line_edit.setText(filename[0])
                


    def encrypt(self, in_file, out_file, password, key_length=32):
        global bs
        global salt
        bs = AES.block_size #16 bytes
        salt = urandom(bs) 
        key, iv = self.derive_key_and_iv(password, salt, key_length, bs)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        out_file.write(salt)
        finished = False

        while not finished:
            chunk = in_file.read(1024 * bs) 
            if len(chunk) == 0 or len(chunk) % bs != 0:
                padding_length = (bs - len(chunk) % bs) or bs
                chunk += str.encode(padding_length * chr(padding_length))
                finished = True
            out_file.write(cipher.encrypt(pad(chunk, 16)))

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

    def derive_key_and_iv(self, password, salt, key_length, iv_length): 
        d = d_i = b''
        while len(d) < key_length + iv_length:
            d_i = md5(d_i + str.encode(password) + salt).digest()
            d += d_i
        return d[:key_length], d[key_length:key_length+iv_length]


    def run_enc(self, password, src_path, dest_path):
        with open(src_path, 'rb') as in_file, open(dest_path, 'wb') as out_file:
            self.encrypt(in_file, out_file, password)

    def run_dec(self, password, src_path,dest_path):
        with open(src_path, 'rb') as in_file, open(dest_path, 'wb') as out_file:
            self.decrypt(in_file, out_file, password)
            
    def confirm_pass(self, line_edit1, line_edit2):
        confirmed=None
        if md5(str.encode(line_edit1)).hexdigest() == md5(str.encode(line_edit2)).hexdigest():
            confirmed=True
        else:
            confirmed=False
        return confirmed 
       
    def choose_enc_dec(self, password, confirm_pass, src_path, dest_path):
        # if os.path.isfile(src_path):#self.rb_file.isChecked():
        #     #if self.rb_encrypt.isChecked():
            
        #     if self.tabWidget.currentIndex() == 0: 
        #         if self.confirm_pass(password, confirm_pass):
        #             with ZipFile("Temp/compressed.zip", "w") as newzip:
        #                 newzip.write(src_path,basename(src_path))
        #             self.run_enc(password, 'Temp/compressed.zip',dest_path+str("/"+src_path.split("/")[-1].split(".")[0]))
        #             remove("Temp/compressed.zip")
        #         else:
        #             QMessageBox.warning(self, "Attention", "Your passwords must be the same!")
                
        #     #elif self.rb_decrypt.isChecked():
        #     elif self.tabWidget.currentIndex() == 1:
        #         self.run_dec(password, src_path,'Temp/compressed.zip')
        #         with ZipFile('Temp/compressed.zip', 'r') as zip:
        #             content=zip.namelist()
        #             for to_unzip in content:
        #                 zip.extract(to_unzip, dest_path)
        #             print(content[0].split("/")[-1])
        #         remove("Temp/compressed.zip")
                
        # elif os.path.isdir(src_path):
        #     #I should to delete the encrypted folder after decrypting it
        #     #if i want
        #     # if self.rb_encrypt.isChecked():
        #     if self.tabWidget.currentIndex() == 0: 
        #         if self.confirm_pass(password, confirm_pass):
        #             #self.compress_folder('Temp/compressed', src_path)
        #             shutil.make_archive('Temp/compressed', 'zip',  src_path)
        #             # time.sleep(2)
        #             CHECK_FOLDER = os.path.isdir(dest_path+"\Encrypted")
        #             if not CHECK_FOLDER:
        #                 Path(dest_path+"\Encrypted").mkdir(parents=True, exist_ok=True)
        #                 self.run_enc(password, 'Temp\compressed.zip',dest_path+"\Encrypted\Encrypted_DATA")
        #             else:
        #                 QMessageBox.critical(self, "Warning", "Your directory has already contains 'Encrypted' folder!")
        #             # enc_folder_name=dest_path+str("/"+src_path.split("/")[-1])
        #             remove("Temp\compressed.zip")
        #         else:
        #             QMessageBox.warning(self, "Attention", "Your passwords must be the same!")
                
        #     else:
        #         self.run_dec(password, src_path,'Temp/compressed.zip')
        #         # with ZipFile('Temp/compressed.zip', 'r') as zip:
        #         #     content=zip.namelist()
        #             # zip.extractall(dest_path+str(content[0]))
        #         # self.compress_folder(dest_path+str(content[0]), 'Temp/compressed.zip')
        #         CHECK_FOLDER = os.path.isdir(dest_path+"\Decrypted")
        #         if not CHECK_FOLDER:
        #             Path(dest_path+"\Decrypted").mkdir(parents=True, exist_ok=True)
        #             with ZipFile('Temp/compressed.zip', 'r') as zip:
        #                 content=zip.namelist()
        #                 zip.extractall(dest_path+"\Decrypted")
        #         else:
        #             # Path(dest_path+"\Decrypted+").mkdir(parents=True, exist_ok=True)
        #             QMessageBox.critical(self, "Warning", "Your directory has already contains 'Decrypted' folder!")
        #         # Path(dest_path+"\Decrypted").mkdir(parents=True, exist_ok=True)
                
        #             # print(content[0].split("/")[-1])
        #         remove("Temp/compressed.zip")
                
                
        ######################################################  
        if self.tabWidget.currentIndex() == 0:     
            if os.path.isfile(src_path):#self.rb_file.isChecked():
            #if self.rb_encrypt.isChecked(): 
                if self.confirm_pass(password, confirm_pass):
                    with ZipFile("Temp/compressed.zip", "w") as newzip:
                        newzip.write(src_path,basename(src_path))
                    self.run_enc(password, 'Temp/compressed.zip',dest_path+str("/"+src_path.split("/")[-1].split(".")[0]))
                    remove("Temp/compressed.zip")
                else:
                    QMessageBox.warning(self, "Attention", "Your passwords must be the same!")
                
            elif os.path.isdir(src_path):
                print("yesy")    
                if self.confirm_pass(password, confirm_pass):
                    #self.compress_folder('Temp/compressed', src_path)
                    shutil.make_archive('Temp/compressed', 'zip',  src_path)
                    # time.sleep(2)
                    CHECK_FOLDER = os.path.isdir(dest_path+"\Encrypted")
                    if not CHECK_FOLDER:
                        Path(dest_path+"\Encrypted").mkdir(parents=True, exist_ok=True)
                        self.run_enc(password, 'Temp\compressed.zip',dest_path+"\Encrypted\Encrypted_DATA")
                    else:
                        QMessageBox.critical(self, "Warning", "Your directory has already contains 'Encrypted' folder!")
                    # enc_folder_name=dest_path+str("/"+src_path.split("/")[-1])
                    remove("Temp\compressed.zip")
                else:
                    QMessageBox.warning(self, "Attention", "Your passwords must be the same!")
                
            #elif self.rb_decrypt.isChecked():
        elif self.tabWidget.currentIndex() == 1:
            # self.run_dec(password, src_path,'Temp/compressed.zip')
            # with ZipFile('Temp/compressed.zip', 'r') as zip:
            #     content=zip.namelist()
            #     for to_unzip in content:
            #         zip.extract(to_unzip, dest_path)
            #     print(content[0].split("/")[-1])
            # remove("Temp/compressed.zip")
            print("Decrypting")
            self.run_dec(password, src_path,'Temp/compressed.zip')
            # shutil.unpack_archive('Temp/compressed.zip', dest_path)
            # with ZipFile('Temp/compressed.zip', 'r') as zip:
            #     content=zip.namelist()
                # zip.extractall(dest_path+str(content[0]))
            # self.compress_folder(dest_path+str(content[0]), 'Temp/compressed.zip')
            print("Checking")
            CHECK_FOLDER = os.path.isdir(dest_path+"\Decrypted")
            if not CHECK_FOLDER:
                Path(dest_path+"\Decrypted").mkdir(parents=True, exist_ok=True)
                with ZipFile('Temp/compressed.zip', 'r') as zip:
                    print("Unzipping")
                    content=zip.namelist()
                    zip.extractall(dest_path+"\Decrypted")
            else:
                # Path(dest_path+"\Decrypted+").mkdir(parents=True, exist_ok=True)
                QMessageBox.critical(self, "Warning", "Your directory has already contains 'Decrypted' folder!")
            # Path(dest_path+"\Decrypted").mkdir(parents=True, exist_ok=True)
            
                # print(content[0].split("/")[-1])
            remove("Temp/compressed.zip")
    
        #I should to delete the encrypted folder after decrypting it
        #if i want
        # if self.rb_encrypt.isChecked():
        # if self.tabWidget.currentIndex() == 0: 
            
            
        # else:
        #     self.run_dec(password, src_path,'Temp/compressed.zip')
        #     # with ZipFile('Temp/compressed.zip', 'r') as zip:
        #     #     content=zip.namelist()
        #         # zip.extractall(dest_path+str(content[0]))
        #     # self.compress_folder(dest_path+str(content[0]), 'Temp/compressed.zip')
        #     CHECK_FOLDER = os.path.isdir(dest_path+"\Decrypted")
        #     if not CHECK_FOLDER:
        #         Path(dest_path+"\Decrypted").mkdir(parents=True, exist_ok=True)
        #         with ZipFile('Temp/compressed.zip', 'r') as zip:
        #             content=zip.namelist()
        #             zip.extractall(dest_path+"\Decrypted")
        #     else:
        #         # Path(dest_path+"\Decrypted+").mkdir(parents=True, exist_ok=True)
        #         QMessageBox.critical(self, "Warning", "Your directory has already contains 'Decrypted' folder!")
        #     # Path(dest_path+"\Decrypted").mkdir(parents=True, exist_ok=True)
            
        #         # print(content[0].split("/")[-1])
        #     remove("Temp/compressed.zip")
                
app=QApplication([])
window=MainWindow()
window.show()
app.exec()