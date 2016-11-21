# -*- coding: utf-8 -*-

"""
Module implementing sniffer.
"""
from pcap import *
import dpkt, datetime
from util import *
import time, re
import threading, Queue
from PyQt5.QtCore import pyqtSlot

from PyQt5.QtWidgets import QDialog, QTableWidget, QTableWidgetItem

from Ui_main import Ui_snifferUI


class sniffer(QDialog, Ui_snifferUI): 
    btn_stop = True
    def __init__(self, parent=None):
        super(sniffer, self).__init__(parent)
        self.setupUi(self)
        #global q
        #q = Queue.Queue()
        
        super(sniffer, self).__init__(parent)
        self.setupUi(self)
        devs = findalldevs()
        for eth in devs:
            self.choose_eth.addItem(eth)
        
        self.package_info.setColumnWidth(5,500) 
        self.package_info.setColumnWidth(2,150) 
        self.package_info.setColumnWidth(1,150)
    
    def get_btnStop(self):
         return self.btn_stop
    def set_btnStop(self, stop):
         self.btn_stop = stop
    def deal_package(self,timestamp,pkg):
         package={}
         timestamp,buf = timestamp,pkg
         # print 'Timestamp: ', str(datetime.datetime.utcfromtimestamp(timestamp))
         timestamp = str(datetime.datetime.fromtimestamp(timestamp))
         # print timestamp
         r =r'\d{2}:\d{2}:\d{2}'
         stand_time =re.findall(r,timestamp)[0]
         timestamp = stand_time
         
         # Unpack the Ethernet frame (mac src/dst, ethertype)
         eth = dpkt.ethernet.Ethernet(buf)

         # Make sure the Ethernet data contains an IP packet


         # Now grab the data within the Ethernet frame (the IP packet)
         ip = eth.data
         
         package['timestamp']=timestamp
         package['len']=len(buf)
         if isinstance(eth.data, dpkt.ip.IP):
             package['ip_len'] =  ip.len
             package['ip_ttl'] =  ip.ttl
             package['ip_DF'] =  bool(ip.off & dpkt.ip.IP_DF)
             package['ip_MF'] =  bool(ip.off & dpkt.ip.IP_MF)
             package['ip_offset'] = ip.off & dpkt.ip.IP_OFFMASK
             package['src_ip'] = inet_to_str(ip.src)
             package['dst_ip'] = inet_to_str(ip.dst)
         elif isinstance(eth.data, dpkt.arp.ARP):
             package['src_ip']=mac_addr(eth.src)
             package['dst_ip']=mac_addr(eth.dst)
 
         else:
             package['src_ip'] = inet_to_str(eth.data.src)
             package['dst_ip'] = inet_to_str(eth.data.dst)   
         info={}  
   

         if isinstance(ip.data, dpkt.icmp.ICMP):
             icmp = ip.data
             package['protocol']='ICMP'
             package['src_ip'] = inet_to_str(ip.src)
             package['dst_ip'] = inet_to_str(ip.dst)
             #print 'Timestamp: ', str(datetime.datetime.utcfromtimestamp(timestamp))
             # print 'Ethernet Frame: ', mac_addr(eth.src), mac_addr(eth.dst), eth.type
             #print 'IP: %s -> %s  ' % (inet_to_str(ip.src), inet_to_str(ip.dst))
             #print 'ICMP: type:%d code:%d checksum:%d data: %s\n' % (icmp.type, icmp.code, icmp.sum, repr(icmp.data))
             info['type']=icmp.type
             info['code']=icmp.code
             info['checksum']=icmp.sum
             info['data']=icmp.data
             package['info']=info
    # deal with TCP packet
         elif isinstance(ip.data, dpkt.tcp.TCP):
             tcp = ip.data
             package['protocol']='TCP'
       
             
        # Pull out fragment information (flags and offset all packed into off field, so use bitmasks)
        # do_not_fragment = bool(ip.off & dpkt.ip.IP_DF)
        # more_fragments = bool(ip.off & dpkt.ip.IP_MF)
        # fragment_offset = ip.off & dpkt.ip.IP_OFFMASK

        # Print out the info
             #print 'Timestamp: ', str(datetime.datetime.utcfromtimestamp(timestamp))
             #print 'IP: %s -> %s ' % (inet_to_str(ip.src), inet_to_str(ip.dst))

        # print 'Ethernet Frame: ', mac_addr(eth.src), mac_addr(eth.dst), eth.type
        # print 'IP: %s -> %s   (len=%d ttl=%d DF=%d MF=%d offset=%d)' % \
        #       (inet_to_str(ip.src), inet_to_str(ip.dst), ip.len, ip.ttl, do_not_fragment, more_fragments, fragment_offset)
             #print 'TCP: sport:%d dport:%d seq:%d ack:%d flags:%d window:%d checksum:%d data: %s\n' % (tcp.sport, tcp.dport,tcp.seq,tcp.ack,tcp.flags,tcp.win,tcp.sum ,repr(tcp.data))
             info['sport']=tcp.sport
             info['dport']=tcp.dport
             info['seq']= tcp.seq
             info['ack']= tcp.ack
             info['flags']=tcp.flags
             info['window']=tcp.win
             info['checksum']=tcp.sum
             info['data']=tcp.data
             info['packet_type'] = []
             if  tcp.flags & dpkt.tcp.TH_SYN :
                    info['packet_type'].append("SYN")
             if tcp.flags & dpkt.tcp.TH_FIN:
                    info['packet_type'].append("FIN")
             if tcp.flags & dpkt.tcp.TH_RST:
                    info['packet_type'].append("RST")
             if tcp.flags & dpkt.tcp.TH_PUSH:
                    info['packet_type'].append("PSH")
             if tcp.flags & dpkt.tcp.TH_ACK:
                    info['packet_type'].append("ACK")
             if tcp.flags & dpkt.tcp.TH_URG:
                    info['packet_type'].append("URG")
             package['info']=info
  
         elif isinstance(ip.data, dpkt.udp.UDP):
             udp = ip.data
             package['protocol']='UDP'
         
             #print 'Timestamp: ', str(datetime.datetime.utcfromtimestamp(timestamp))
             #print 'IP: %s -> %s ' % (inet_to_str(ip.src), inet_to_str(ip.dst))
             #print 'UDP: sport:%d dport:%d ulen:%d checksum:%d data: %s\n' % (udp.sport, udp.dport,udp.ulen, udp.sum ,repr(udp.data))
             info['sport']=udp.sport
             info['dport']=udp.dport
             info['ulen']=udp.ulen
             info['checksum']=udp.sum
             package['info']=info
         elif isinstance(ip.data, dpkt.igmp.IGMP):
             igmp = ip.data
             package['protocol']='IGMP'
        
             #print 'Timestamp: ', str(datetime.datetime.utcfromtimestamp(timestamp))
             #print 'IP: %s -> %s  ' % (inet_to_str(ip.src), inet_to_str(ip.dst))
             #print 'IGMP: type:%d maxresp:%d checksum:%d group:%d data: %s\n' % (igmp.type, igmp.maxresp,igmp.sum, igmp.group ,repr(igmp.data))
             info['type']=igmp.type
             info['maxresp']=igmp.maxresp
             info['checksum'] =igmp.sum
             info['group']=igmp.group
             package['info']=info
         elif eth.data.__class__.__name__=="ARP" :
             arp = eth.data
             package['protocol']='ARP' 

             #print 'Ethernet Frame: ', mac_addr(eth.src), mac_addr(eth.dst), eth.type
             #print 'Timestamp: ', str(datetime.datetime.utcfromtimestamp(timestamp))
             #print 'IP: %s -> %s ' % (inet_to_str(ip.src), inet_to_str(ip.dst))
             #print 'ARP: hardware_type:%d protocol_type:%d hrd_addr_len:%d pro_addr_len:%d op_code:%d sha:%d spa:%d tha:%d tpa:%d\n' % (arp.hrd, arp.pro, arp.hln, arp.pln ,arp.op,arp.sha,arp.spa,arp.tha,arp.tpa)
             info['hrd_type']=arp.hrd        
             info['pro_type']=arp.pro
             info['mac_addr_len']=arp.hln
             info['pro_addr_len']=arp.pln
             info['op']=arp.op
             info['sha']=mac_addr(arp.sha)
             info['spa']=inet_to_str(arp.spa)
             info['tha']=mac_addr(arp.tha)
             info['tpa']=inet_to_str(arp.tpa)
             package['info']=info
         elif eth.data.__class__.__name__=="IP6":
             ip6 = eth.data
             package['protocol'] = 'IPv6'
             #print 'IP: %s -> %s  ' % (inet_to_str(ip.src), inet_to_str(ip.dst))
             #print "IPv6: ver:%d traffic_class:%d flow:%d payload_len:%d  next_hdr:%d hop_lim;%d src:%s dst:%s data:%x\n" %(ip6.v ,ip6.fc, ip6.flow, ip6.plen, ip6.nxt, ip6.hlim,inet_to_str(ip6.src),inet_to_str(ip6.dst),ip6.data)
 
             info['traffic_class']=ip6.fc
             info['flow']=ip6.flow 
             info['payload_len']=ip6.plen
             info['next_hdr']=ip6.nxt
             info['hop_lim']=ip6.hlim
             info['src']=inet_to_str(ip6.src)
             info['dst']=inet_to_str(ip6.dst)
             info['data']= ip6.data
             package['info']= info
         else:
             package['protocol']=eth.data.__class__.__name__

         if package['protocol']=='IP6':
             return
         i  = self.package_info.currentRow()+1
         self.package_info.insertRow(i)
         timeItem = QTableWidgetItem("  "+package['timestamp'])
        # timeItem.setTextAlignment(8)
         srcItem = QTableWidgetItem("  "+package['src_ip'])
         dstItem = QTableWidgetItem("  "+package['dst_ip'])
         protocolItem = QTableWidgetItem(" "+package['protocol'])
         lenItem = QTableWidgetItem("  "+str(package['len']))
         
         self.package_info.setItem(i, 0, timeItem)
         self.package_info.setItem(i, 1, srcItem)
         self.package_info.setItem(i, 2, dstItem)
         self.package_info.setItem(i, 3, protocolItem)
         self.package_info.setItem(i, 4, lenItem)

         if (package['protocol'])=='UDP':
             info=package['info']
             show=str(info['sport'])+' -> '+str(info['dport'])+'  len :'+str(info['ulen'])+'   sum : ' + str(info['checksum'])
             infoItem = QTableWidgetItem(show)
             self.package_info.setItem(i, 5, infoItem)

         elif (package['protocol'])=='TCP':
             info=package['info']
             show=str(info['sport'])+' -> '+str(info['dport']) + '  ['+','.join(info['packet_type'])+']  seq :'+str(info['seq'])+'   ack : ' + str(info['ack'])+\
                  ' window : '+ str(info['window'])
             infoItem = QTableWidgetItem(show)
             self.package_info.setItem(i, 5, infoItem)

         elif (package['protocol'])=='ICMP':
             info=package['info']
             show='type : '+str(info['type'])+ \
                  '  code : '+str(info['code']) + \
                  '  sum : '+str(info['checksum'])+ \
                  '    ttl :'+str(package['ip_ttl'])
             infoItem = QTableWidgetItem(show)
             self.package_info.setItem(i, 5, infoItem)
 
         elif (package['protocol'])=='IPv6':
             info=package['info']
             show='traffic_class :'+str(info['traffic_class'])+' flow :' + str(info['flow'])+\
                ' payload_length : '+str(info['payload_len']) + str(info['src']+'-->'+str(info['dst']))
             infoItem = QTableWidgetItem(show)
             self.package_info.setItem(i, 5, infoItem)

         elif (package['protocol'])=='ARP':
             info=package['info']
             show=str(info['spa'])+" --> "+str(info['tpa'])+\
                  '  hrd_type : '+str(info['hrd_type']) + \
                  ' protocol_type:' +str(info['pro_type']) + \
                  ' op_code : ' +str(info['op'])
            
             infoItem = QTableWidgetItem(show)
             self.package_info.setItem(i, 5, infoItem)
 
         
    def package_reader(self):
        while(self.get_btnStop()==False):
           pcap(self.choose_eth.currentText(), immediate=True).loop(3,self.deal_package)



             
    @pyqtSlot() 
    def on_btn_begin_clicked(self):
         self.set_btnStop(False)
         
         print '设置符号为:', self.btn_stop
         th =threading.Thread(target = self.package_reader)
         th.start()
        
         
        
             
     
     
    @pyqtSlot()
    def on_btn_stop_clicked(self):
        self.set_btnStop(True)
        print '设置符号为:', self.btn_stop
    
    
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
