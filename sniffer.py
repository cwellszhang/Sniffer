# -*- coding: utf-8 -*-

"""
Module implementing sniffer.
"""
from pcap import findalldevs
from PyQt5.QtCore import pyqtSlot

from PyQt5.QtWidgets import QDialog, QTableWidget, QTableWidgetItem

from Ui_main import Ui_snifferUI


class sniffer(QDialog, Ui_snifferUI):
    def __init__(self, parent=None):
        super(sniffer, self).__init__(parent)
        self.setupUi(self)
        
        super(sniffer, self).__init__(parent)
        self.setupUi(self)
        devs = findalldevs()
        for eth in devs:
            self.choose_eth.addItem(eth)
        
        self.package_info.setColumnWidth(4,250) 
        
        self.package_info.setRowCount(1)
        newItem = QTableWidgetItem("11：11") 
        self.package_info.setItem(0, 0, newItem)  
        self.package_info.insertRow(1)

        
          
    @pyqtSlot()
    def on_btn_begin_clicked(self):
        pass
    
    @pyqtSlot()
    def on_btn_stop_clicked(self):
        pass
    
    @pyqtSlot()
    def on_btn_filter_clicked(self):
        pass
    
    @pyqtSlot()
    def on_btn_search_clicked(self):
        pass
    
    @pyqtSlot()
    def on_btn_viewlog_clicked(self):
        pass
    
    @pyqtSlot()
    def on_btn_recover_clicked(self):
        pass
    
    @pyqtSlot()
    def on_btn_save_clicked(self):
        pass
    
    @pyqtSlot()
    def on_btn_exit_clicked(self):
        pass
    
    @pyqtSlot(int)
    def on_choose_eth_activated(self, p0):
        pass
    
    @pyqtSlot(int)
    def on_choose_eth_currentIndexChanged(self, p0):
        print self.choose_eth.currentText()
if __name__ == "__main__":
 import sys
 from PyQt5.QtWidgets import QApplication
 app = QApplication(sys.argv)
 dlg = sniffer()
 dlg.show()
 sys.exit(app.exec_())
