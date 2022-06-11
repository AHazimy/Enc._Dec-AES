# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'MainWindow.ui'
#
# Created by: PyQt5 UI code generator 5.15.6
#
# WARNING: Any manual changes made to this file will be lost when pyuic5 is
# run again.  Do not edit this file unless you know what you are doing.


from PyQt5 import QtCore, QtGui, QtWidgets


class Ui_MainWindow(object):
    def setupUi(self, MainWindow):
        MainWindow.setObjectName("MainWindow")
        MainWindow.resize(374, 361)
        MainWindow.setToolButtonStyle(QtCore.Qt.ToolButtonIconOnly)
        self.centralwidget = QtWidgets.QWidget(MainWindow)
        self.centralwidget.setObjectName("centralwidget")
        self.gridLayout = QtWidgets.QGridLayout(self.centralwidget)
        self.gridLayout.setObjectName("gridLayout")
        self.verticalLayout = QtWidgets.QVBoxLayout()
        self.verticalLayout.setObjectName("verticalLayout")
        self.tabWidget = QtWidgets.QTabWidget(self.centralwidget)
        self.tabWidget.setStyleSheet("")
        self.tabWidget.setTabPosition(QtWidgets.QTabWidget.North)
        self.tabWidget.setTabShape(QtWidgets.QTabWidget.Rounded)
        self.tabWidget.setIconSize(QtCore.QSize(16, 16))
        self.tabWidget.setElideMode(QtCore.Qt.ElideNone)
        self.tabWidget.setDocumentMode(False)
        self.tabWidget.setTabsClosable(False)
        self.tabWidget.setMovable(False)
        self.tabWidget.setTabBarAutoHide(False)
        self.tabWidget.setObjectName("tabWidget")
        self.tab = QtWidgets.QWidget()
        self.tab.setObjectName("tab")
        self.lineEdit_password_confirm = QtWidgets.QLineEdit(self.tab)
        self.lineEdit_password_confirm.setGeometry(QtCore.QRect(20, 170, 241, 20))
        self.lineEdit_password_confirm.setEchoMode(QtWidgets.QLineEdit.Password)
        self.lineEdit_password_confirm.setObjectName("lineEdit_password_confirm")
        self.btn_browse_destination = QtWidgets.QPushButton(self.tab)
        self.btn_browse_destination.setGeometry(QtCore.QRect(220, 80, 91, 23))
        self.btn_browse_destination.setCursor(QtGui.QCursor(QtCore.Qt.PointingHandCursor))
        self.btn_browse_destination.setObjectName("btn_browse_destination")
        self.btn_browse_source_file_enc = QtWidgets.QPushButton(self.tab)
        self.btn_browse_source_file_enc.setGeometry(QtCore.QRect(220, 10, 91, 23))
        self.btn_browse_source_file_enc.setCursor(QtGui.QCursor(QtCore.Qt.PointingHandCursor))
        icon = QtGui.QIcon()
        icon.addPixmap(QtGui.QPixmap(":/newPrefix/img/file.png"), QtGui.QIcon.Normal, QtGui.QIcon.On)
        self.btn_browse_source_file_enc.setIcon(icon)
        self.btn_browse_source_file_enc.setCheckable(False)
        self.btn_browse_source_file_enc.setFlat(True)
        self.btn_browse_source_file_enc.setObjectName("btn_browse_source_file_enc")
        self.lineEdit_destination = QtWidgets.QLineEdit(self.tab)
        self.lineEdit_destination.setEnabled(False)
        self.lineEdit_destination.setGeometry(QtCore.QRect(22, 80, 151, 20))
        self.lineEdit_destination.setObjectName("lineEdit_destination")
        self.lineEdit_password = QtWidgets.QLineEdit(self.tab)
        self.lineEdit_password.setGeometry(QtCore.QRect(20, 140, 241, 20))
        self.lineEdit_password.setEchoMode(QtWidgets.QLineEdit.Password)
        self.lineEdit_password.setObjectName("lineEdit_password")
        self.lineEdit_source = QtWidgets.QLineEdit(self.tab)
        self.lineEdit_source.setEnabled(False)
        self.lineEdit_source.setGeometry(QtCore.QRect(22, 10, 151, 20))
        self.lineEdit_source.setObjectName("lineEdit_source")
        self.btn_browse_source_fldr_enc = QtWidgets.QPushButton(self.tab)
        self.btn_browse_source_fldr_enc.setGeometry(QtCore.QRect(220, 40, 91, 23))
        self.btn_browse_source_fldr_enc.setCursor(QtGui.QCursor(QtCore.Qt.PointingHandCursor))
        icon1 = QtGui.QIcon()
        icon1.addPixmap(QtGui.QPixmap(":/newPrefix/img/folder.png"), QtGui.QIcon.Normal, QtGui.QIcon.On)
        self.btn_browse_source_fldr_enc.setIcon(icon1)
        self.btn_browse_source_fldr_enc.setCheckable(False)
        self.btn_browse_source_fldr_enc.setFlat(True)
        self.btn_browse_source_fldr_enc.setObjectName("btn_browse_source_fldr_enc")
        icon2 = QtGui.QIcon()
        icon2.addPixmap(QtGui.QPixmap(":/newPrefix/img/kisspng-lock-computer-icons-clip-art-lock-5aca2fd1ceb269.0955582915231999538466.png"), QtGui.QIcon.Normal, QtGui.QIcon.On)
        self.tabWidget.addTab(self.tab, icon2, "")
        self.tab_2 = QtWidgets.QWidget()
        self.tab_2.setObjectName("tab_2")
        self.gridLayout_2 = QtWidgets.QGridLayout(self.tab_2)
        self.gridLayout_2.setObjectName("gridLayout_2")
        self.verticalLayout_2 = QtWidgets.QVBoxLayout()
        self.verticalLayout_2.setObjectName("verticalLayout_2")
        self.horizontalLayout = QtWidgets.QHBoxLayout()
        self.horizontalLayout.setObjectName("horizontalLayout")
        self.lineEdit_source_dec = QtWidgets.QLineEdit(self.tab_2)
        self.lineEdit_source_dec.setEnabled(False)
        self.lineEdit_source_dec.setObjectName("lineEdit_source_dec")
        self.horizontalLayout.addWidget(self.lineEdit_source_dec)
        self.btn_browse_source_dec = QtWidgets.QPushButton(self.tab_2)
        self.btn_browse_source_dec.setCursor(QtGui.QCursor(QtCore.Qt.PointingHandCursor))
        self.btn_browse_source_dec.setIcon(icon)
        self.btn_browse_source_dec.setCheckable(False)
        self.btn_browse_source_dec.setFlat(True)
        self.btn_browse_source_dec.setObjectName("btn_browse_source_dec")
        self.horizontalLayout.addWidget(self.btn_browse_source_dec)
        self.verticalLayout_2.addLayout(self.horizontalLayout)
        self.horizontalLayout_2 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_2.setObjectName("horizontalLayout_2")
        self.lineEdit_destination_dec = QtWidgets.QLineEdit(self.tab_2)
        self.lineEdit_destination_dec.setEnabled(False)
        self.lineEdit_destination_dec.setObjectName("lineEdit_destination_dec")
        self.horizontalLayout_2.addWidget(self.lineEdit_destination_dec)
        self.btn_browse_destination_dec = QtWidgets.QPushButton(self.tab_2)
        self.btn_browse_destination_dec.setCursor(QtGui.QCursor(QtCore.Qt.PointingHandCursor))
        self.btn_browse_destination_dec.setObjectName("btn_browse_destination_dec")
        self.horizontalLayout_2.addWidget(self.btn_browse_destination_dec)
        self.verticalLayout_2.addLayout(self.horizontalLayout_2)
        self.lineEdit_password_dec = QtWidgets.QLineEdit(self.tab_2)
        self.lineEdit_password_dec.setEchoMode(QtWidgets.QLineEdit.Password)
        self.lineEdit_password_dec.setObjectName("lineEdit_password_dec")
        self.verticalLayout_2.addWidget(self.lineEdit_password_dec)
        self.gridLayout_2.addLayout(self.verticalLayout_2, 0, 0, 1, 1)
        icon3 = QtGui.QIcon()
        icon3.addPixmap(QtGui.QPixmap(":/newPrefix/img/unlock-16.png"), QtGui.QIcon.Normal, QtGui.QIcon.On)
        self.tabWidget.addTab(self.tab_2, icon3, "")
        self.verticalLayout.addWidget(self.tabWidget)
        self.btn_run = QtWidgets.QPushButton(self.centralwidget)
        self.btn_run.setCursor(QtGui.QCursor(QtCore.Qt.PointingHandCursor))
        self.btn_run.setObjectName("btn_run")
        self.verticalLayout.addWidget(self.btn_run)
        self.gridLayout.addLayout(self.verticalLayout, 0, 0, 1, 1)
        MainWindow.setCentralWidget(self.centralwidget)
        self.menubar = QtWidgets.QMenuBar(MainWindow)
        self.menubar.setGeometry(QtCore.QRect(0, 0, 374, 21))
        self.menubar.setObjectName("menubar")
        MainWindow.setMenuBar(self.menubar)
        self.statusbar = QtWidgets.QStatusBar(MainWindow)
        self.statusbar.setObjectName("statusbar")
        MainWindow.setStatusBar(self.statusbar)

        self.retranslateUi(MainWindow)
        self.tabWidget.setCurrentIndex(0)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)

    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", "AES_files"))
        self.btn_browse_destination.setText(_translate("MainWindow", "Results"))
        self.btn_browse_source_file_enc.setText(_translate("MainWindow", "Add File"))
        self.btn_browse_source_fldr_enc.setText(_translate("MainWindow", "Add Folder"))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.tab), _translate("MainWindow", "Encryption"))
        self.btn_browse_source_dec.setText(_translate("MainWindow", "Add File"))
        self.btn_browse_destination_dec.setText(_translate("MainWindow", "Results"))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.tab_2), _translate("MainWindow", "Decryption"))
        self.btn_run.setText(_translate("MainWindow", "Run"))
import icons_rc


if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    MainWindow = QtWidgets.QMainWindow()
    ui = Ui_MainWindow()
    ui.setupUi(MainWindow)
    MainWindow.show()
    sys.exit(app.exec_())
