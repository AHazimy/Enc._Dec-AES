"""DONE===>1. Ability to Encrypt and Decrypt Directory"""
"""DONE===>2. Ability to Encrypt and Decrypt Files"""
"""######### Big Bug ###########3. Fix The path or the name or the type for the decrypted files and folders
If i can save it without full path in the zip file the problem will be solved"""

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


class MainWindow(QMainWindow, Ui_MainWindow):
    def __init__(self, parent=None):
        super(MainWindow, self).__init__(parent)
        self.setupUi(self)
        self.btn_browse_source.clicked.connect(lambda: self.browse(self.lineEdit_source, "src"))
        self.btn_browse_destination.clicked.connect(lambda: self.browse(self.lineEdit_destination, "dest"))
        self.btn_run.clicked.connect(lambda: self.choose_enc_dec(self.lineEdit_password.text(), self.lineEdit_source.text(), self.lineEdit_destination.text()))
        self.btn_test.clicked.connect(lambda: self.test(self.lineEdit_destination.text(), self.lineEdit_source.text()))
        
    def compress_folder(self, output, input):
        if self.rb_encrypt.isChecked():
            shutil.make_archive(output, 'zip', input)
            # def _walk(path: Path):
            #     all_files = []
            #     for x in path.iterdir():
            #         if x.is_dir():
            #             all_files.extend(_walk(x))
            #         else:
            #             all_files.append(x)
            #     return all_files


            # def zip_files(path: Path, archive_name: str):
            #     all_files = _walk(path)
            #     with zipfile.ZipFile(f'{archive_name}', 'w', zipfile.ZIP_DEFLATED) as zipf:
            #         for f in all_files:
            #             zipf.write(f)
            #         zipf.close()


            # zip_files(input, output)
        else:
            shutil.unpack_archive(input, output)

        
    #My work is here      
    def browse(self, line_edit, status):
        if status == "src":
            if (self.rb_file.isChecked() and self.tabWidget.currentIndex()==1) or (self.rb_folder.isChecked() and self.tabWidget.currentIndex()==1) or (self.rb_file.isChecked() and self.tabWidget.currentIndex()==0):
                filename=QFileDialog.getOpenFileName(self, 'Open File', '', '')
                line_edit.setText(filename[0])
            else:
                dirName=QFileDialog.getExistingDirectory(None, 'Select a folder:', 'C:\\',QFileDialog.ShowDirsOnly)
                line_edit.setText(dirName)
        elif status == "dest":
            # if (self.rb_file.isChecked() and self.tabWidget.currentIndex()==1) or (self.rb_folder.isChecked() and self.tabWidget.currentIndex()==1):
            filename=QFileDialog.getExistingDirectory(None, 'Select a folder:', 'C:\\',QFileDialog.ShowDirsOnly)
            line_edit.setText(filename)
            # else:
            #     filename=QFileDialog.getSaveFileName(self, 'Save File', '', '')
            #     line_edit.setText(filename[0])
                


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
            
    def choose_enc_dec(self, password, src_path,dest_path):
        if self.rb_file.isChecked():
            #if self.rb_encrypt.isChecked():
            
            if self.tabWidget.currentIndex() == 0: 
                with ZipFile("Temp/compressed.zip", "w") as newzip:
                    newzip.write(src_path,basename(src_path))
                self.run_enc(password, 'Temp/compressed.zip',dest_path+str("/"+src_path.split("/")[-1].split(".")[0]))
                remove("Temp/compressed.zip")
                
            #elif self.rb_decrypt.isChecked():
            elif self.tabWidget.currentIndex() == 1:
                self.run_dec(password, src_path,'Temp/compressed.zip')
                with ZipFile('Temp/compressed.zip', 'r') as zip:
                    content=zip.namelist()
                    zip.extractall(dest_path)
                    print(content[0].split("/")[-1])
                remove("Temp/compressed.zip")
                
        else:
            #I should to delete the encrypted folder after decrypting it
            #if i want
            # if self.rb_encrypt.isChecked():
            if self.tabWidget.currentIndex() == 0: 
                self.compress_folder('Temp/compressed', src_path)
                # time.sleep(2)
                Path(dest_path+"\Decr").mkdir(parents=True, exist_ok=True)
                enc_folder_name=dest_path+str("/"+src_path.split("/")[-1])
                self.run_enc(password, 'Temp\compressed.zip',dest_path+"\Decr\Enc")
                remove("Temp\compressed.zip")
                
                
            else:
                self.run_dec(password, src_path,'Temp/compressed.zip')
                with ZipFile('Temp/compressed.zip', 'r') as zip:
                    content=zip.namelist()
                    # zip.extractall(dest_path+str(content[0]))
                self.compress_folder(dest_path+str(content[0]), 'Temp/compressed.zip')
                remove("Temp/compressed.zip")
                
app=QApplication([])
window=MainWindow()
window.show()
app.exec()