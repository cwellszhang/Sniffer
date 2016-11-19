# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file '/Users/zcw/Sniffer/main.ui'
#
# Created by: PyQt5 UI code generator 5.7
#
# WARNING! All changes made in this file will be lost!

from PyQt5 import QtCore, QtGui, QtWidgets

class Ui_snifferUI(object):
    def setupUi(self, snifferUI):
        snifferUI.setObjectName("snifferUI")
        snifferUI.resize(677, 695)
        self.label = QtWidgets.QLabel(snifferUI)
        self.label.setGeometry(QtCore.QRect(30, 20, 60, 16))
        self.label.setObjectName("label")
        self.listWidget = QtWidgets.QListWidget(snifferUI)
        self.listWidget.setGeometry(QtCore.QRect(20, 110, 481, 192))
        self.listWidget.setObjectName("listWidget")
        self.pushButton = QtWidgets.QPushButton(snifferUI)
        self.pushButton.setGeometry(QtCore.QRect(10, 60, 113, 32))
        self.pushButton.setObjectName("pushButton")
        self.pushButton_2 = QtWidgets.QPushButton(snifferUI)
        self.pushButton_2.setGeometry(QtCore.QRect(140, 60, 113, 32))
        self.pushButton_2.setObjectName("pushButton_2")
        self.pushButton_3 = QtWidgets.QPushButton(snifferUI)
        self.pushButton_3.setGeometry(QtCore.QRect(280, 60, 113, 32))
        self.pushButton_3.setObjectName("pushButton_3")
        self.pushButton_4 = QtWidgets.QPushButton(snifferUI)
        self.pushButton_4.setGeometry(QtCore.QRect(20, 340, 113, 32))
        self.pushButton_4.setObjectName("pushButton_4")
        self.pushButton_5 = QtWidgets.QPushButton(snifferUI)
        self.pushButton_5.setGeometry(QtCore.QRect(160, 340, 113, 32))
        self.pushButton_5.setObjectName("pushButton_5")
        self.pushButton_6 = QtWidgets.QPushButton(snifferUI)
        self.pushButton_6.setGeometry(QtCore.QRect(300, 340, 113, 32))
        self.pushButton_6.setObjectName("pushButton_6")
        self.pushButton_7 = QtWidgets.QPushButton(snifferUI)
        self.pushButton_7.setGeometry(QtCore.QRect(430, 340, 113, 32))
        self.pushButton_7.setObjectName("pushButton_7")
        self.pushButton_8 = QtWidgets.QPushButton(snifferUI)
        self.pushButton_8.setGeometry(QtCore.QRect(540, 630, 113, 32))
        self.pushButton_8.setObjectName("pushButton_8")
        self.textBrowser = QtWidgets.QTextBrowser(snifferUI)
        self.textBrowser.setGeometry(QtCore.QRect(20, 410, 481, 241))
        self.textBrowser.setObjectName("textBrowser")
        self.label_2 = QtWidgets.QLabel(snifferUI)
        self.label_2.setGeometry(QtCore.QRect(360, 380, 60, 16))
        self.label_2.setObjectName("label_2")
        self.label_3 = QtWidgets.QLabel(snifferUI)
        self.label_3.setGeometry(QtCore.QRect(430, 380, 60, 16))
        self.label_3.setObjectName("label_3")
        self.comboBox = QtWidgets.QComboBox(snifferUI)
        self.comboBox.setGeometry(QtCore.QRect(100, 20, 401, 21))
        self.comboBox.setObjectName("comboBox")
        self.actionMenubar = QtWidgets.QAction(snifferUI)
        self.actionMenubar.setObjectName("actionMenubar")

        self.retranslateUi(snifferUI)
        self.comboBox.activated['QString'].connect(snifferUI.combo_box_clicked)
        QtCore.QMetaObject.connectSlotsByName(snifferUI)

    def retranslateUi(self, snifferUI):
        _translate = QtCore.QCoreApplication.translate
        snifferUI.setWindowTitle(_translate("snifferUI", "Sniffer"))
        self.label.setText(_translate("snifferUI", "选择网卡："))
        self.pushButton.setText(_translate("snifferUI", "开始抓包"))
        self.pushButton_2.setText(_translate("snifferUI", "停止抓包"))
        self.pushButton_3.setText(_translate("snifferUI", "过滤包"))
        self.pushButton_4.setText(_translate("snifferUI", "搜索"))
        self.pushButton_5.setText(_translate("snifferUI", "查看日志"))
        self.pushButton_6.setText(_translate("snifferUI", "报文重组"))
        self.pushButton_7.setText(_translate("snifferUI", "保存TXT"))
        self.pushButton_8.setText(_translate("snifferUI", "退出"))
        self.label_2.setText(_translate("snifferUI", "网络流量："))
        self.label_3.setText(_translate("snifferUI", "0 Kb/s"))
        self.actionMenubar.setText(_translate("snifferUI", "menubar"))
    
    def combo_box_clicked(self):
        QtWidgets.QMessageBox.information(self.pushButton,"标题","这是第一个PyQt5 GUI程序")

if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    snifferUI = QtWidgets.QDialog()
    ui = Ui_snifferUI()
    ui.setupUi(snifferUI)
    snifferUI.show()
    sys.exit(app.exec_())

