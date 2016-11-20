# -*- coding: utf-8 -*-

"""
Module implementing sniffer.
"""
from pcap import *
import dpkt, datetime
from util import *
import time
import threading, Queue
from PyQt5.QtCore import pyqtSlot

from PyQt5.QtWidgets import QDialog, QTableWidget, QTableWidgetItem

from Ui_main import Ui_snifferUI


class sniffer(QDialog, Ui_snifferUI): 
    btn_stop = True
    def __init__(self, parent=None):
        super(sniffer, self).__init__(parent)
        self.setupUi(self)
        global q
        q = Queue.Queue(30)
        
        super(sniffer, self).__init__(parent)
        self.setupUi(self)
        devs = findalldevs()
        for eth in devs:
            self.choose_eth.addItem(eth)
        
        self.package_info.setColumnWidth(4,250) 
   
    def get_btnStop(self):
         return self.btn_stop
    def set_btnStop(self, stop):
         self.btn_stop = stop
    def package_reader(self):
        a=pcap(self.choose_eth.currentText(), immediate=False)
        total_package={}
        package={}
        suspend=0
        while( self.get_btnStop() == False ):
             timestamp, buf = a.readpkts()[0]
             package['timestamp']=str(datetime.datetime.utcfromtimestamp(timestamp))
             eth = dpkt.ethernet.Ethernet(buf)
             package['protocol']= eth.data.__class__.__name__
             ip = eth.data
             if not isinstance(eth.data, dpkt.ip.IP):
               print 'Non IP Packet type not supported %s\n' % eth.data.__class__.__name__
               continue
             package['src_ip'] = inet_to_str(ip.src) 
             package['dst_ip'] = inet_to_str(ip.dst)
             package['ip_len'] =  ip.len
             package['ip_ttl'] =  ip.ttl
             package['ip_DF'] =  bool(ip.off & dpkt.ip.IP_DF)
             package['ip_MF'] =  bool(ip.off & dpkt.ip.IP_MF)
             package['ip_offset'] = ip.off & dpkt.ip.IP_OFFMASK
             q.put(package)
             suspend=suspend+1
             if suspend % 10 == 0:
                  print "子线程暂停"
                  time.sleep(5000)


    @pyqtSlot() 
    def on_btn_begin_clicked(self):
         self.set_btnStop(False)
         
         print '设置符号为:', self.btn_stop
         th =threading.Thread(target = self.package_reader)
         th.start()
         i=0
         while(self.get_btnStop()==False):
                package = q.get()
                #self.package_info.insertRow(i)
                #timeItem = QTableWidgetItem(package['timestamp']) 
                #srcItem = QTableWidgetItem(package['src_ip']) 
                #dstItem = QTableWidgetItem(package['dst_ip']) 
                #protocolItem = QTableWidgetItem(package['protocol']) 
                print package['timestamp']
                #self.package_info.setItem(i, 0, timeItem)  
                #self.package_info.setItem(i, 1, srcItem)  
                #self.package_info.setItem(i, 2, dstItem)  
                #self.package_info.setItem(i, 3, protocolItem)   
                i=i+1
                #time.sleep(3)

         #threading.Thread.join(th)
        
             
     
     
    @pyqtSlot()
    def on_btn_stop_clicked(self):
        self.set_btnStop(True)
        print '设置符号为:', self.btn_stop
        #th.stop()
    
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
