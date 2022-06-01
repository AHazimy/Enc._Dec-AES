# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'MainWindow.ui'
#
# Created by: PyQt5 UI code generator 5.9.2
#
# WARNING! All changes made in this file will be lost!

from PyQt5 import QtCore, QtGui, QtWidgets

class Ui_MainWindow(object):
    def setupUi(self, MainWindow):
        MainWindow.setObjectName("MainWindow")
        MainWindow.resize(294, 324)
        self.centralwidget = QtWidgets.QWidget(MainWindow)
        self.centralwidget.setObjectName("centralwidget")
        self.lineEdit_source = QtWidgets.QLineEdit(self.centralwidget)
        self.lineEdit_source.setGeometry(QtCore.QRect(22, 30, 151, 20))
        self.lineEdit_source.setObjectName("lineEdit_source")
        self.lineEdit_destination = QtWidgets.QLineEdit(self.centralwidget)
        self.lineEdit_destination.setGeometry(QtCore.QRect(22, 100, 151, 20))
        self.lineEdit_destination.setObjectName("lineEdit_destination")
        self.btn_browse_source = QtWidgets.QPushButton(self.centralwidget)
        self.btn_browse_source.setGeometry(QtCore.QRect(190, 30, 75, 23))
        self.btn_browse_source.setObjectName("btn_browse_source")
        self.btn_browse_destination = QtWidgets.QPushButton(self.centralwidget)
        self.btn_browse_destination.setGeometry(QtCore.QRect(190, 100, 75, 23))
        self.btn_browse_destination.setObjectName("btn_browse_destination")
        self.btn_run = QtWidgets.QPushButton(self.centralwidget)
        self.btn_run.setGeometry(QtCore.QRect(20, 240, 241, 23))
        self.btn_run.setObjectName("btn_run")
        self.rb_encrypt = QtWidgets.QRadioButton(self.centralwidget)
        self.rb_encrypt.setGeometry(QtCore.QRect(30, 160, 82, 17))
        self.rb_encrypt.setObjectName("rb_encrypt")
        self.rb_decrypt = QtWidgets.QRadioButton(self.centralwidget)
        self.rb_decrypt.setGeometry(QtCore.QRect(190, 160, 82, 17))
        self.rb_decrypt.setObjectName("rb_decrypt")
        self.lineEdit_password = QtWidgets.QLineEdit(self.centralwidget)
        self.lineEdit_password.setGeometry(QtCore.QRect(20, 200, 241, 20))
        self.lineEdit_password.setObjectName("lineEdit_password")
        MainWindow.setCentralWidget(self.centralwidget)
        self.menubar = QtWidgets.QMenuBar(MainWindow)
        self.menubar.setGeometry(QtCore.QRect(0, 0, 294, 21))
        self.menubar.setObjectName("menubar")
        MainWindow.setMenuBar(self.menubar)
        self.statusbar = QtWidgets.QStatusBar(MainWindow)
        self.statusbar.setObjectName("statusbar")
        MainWindow.setStatusBar(self.statusbar)

        self.retranslateUi(MainWindow)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)

    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", "AES_files"))
        self.btn_browse_source.setText(_translate("MainWindow", "Browse"))
        self.btn_browse_destination.setText(_translate("MainWindow", "Browse"))
        self.btn_run.setText(_translate("MainWindow", "Run"))
        self.rb_encrypt.setText(_translate("MainWindow", "Encrypt"))
        self.rb_decrypt.setText(_translate("MainWindow", "Decrypt"))


if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    MainWindow = QtWidgets.QMainWindow()
    ui = Ui_MainWindow()
    ui.setupUi(MainWindow)
    MainWindow.show()
    sys.exit(app.exec_())

