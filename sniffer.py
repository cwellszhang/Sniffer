# -*- coding: utf-8 -*-
import sys
reload(sys)
sys.setdefaultencoding('utf-8')

"""
Module implementing sniffer.
"""
from pcap import *
import dpkt, datetime
from util import *
import time, re, json, codecs
import struct
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
        self.package_info.setColumnHidden(6,True)
        self.package_info.setColumnHidden(7,True)
       
    def get_btnStop(self):
         return self.btn_stop
    def set_btnStop(self, stop):
         self.btn_stop = stop
    def deal_package(self,timestamp,pkg):
        package={}
        info={} 
        timestamp,buf = timestamp,pkg
        timestamp = str(datetime.datetime.fromtimestamp(timestamp))
        r =r'\d{2}:\d{2}:\d{2}'
        stand_time =re.findall(r,timestamp)[0]
        timestamp = stand_time
   
        package['timestamp']=timestamp
        package['len']=len(buf)  
        org= dpkt.hexdump(str(buf), 10)
        package['buf']=org
        #print type(buf)
        eth = dpkt.ethernet.Ethernet(buf)
        #print type(eth)
      # Make sure the Ethernet data contains an IP packet

        if eth.data.__class__.__name__=="ARP" :
             arp = eth.data
             package['protocol']='ARP' 
             #ARP包解析
             info['hrd_type']=arp.hrd         #硬件类型    
             info['pro_type']=arp.pro         #协议类型
             info['mac_addr_len']=arp.hln     #MAC地址长度
             info['pro_addr_len']=arp.pln     #协议地址长度
             info['op']=arp.op                #操作码
             info['sha']=mac_addr(arp.sha)    #发送方MAC地址
             info['spa']=inet_to_str(arp.spa) #发送方IP地址
             info['tha']=mac_addr(arp.tha)    #接收方MAC地址
             info['tpa']=inet_to_str(arp.tpa) #接收方IP地址
             data = arp.data
             package['info']=info 
             timeItem = QTableWidgetItem("  "+package['timestamp'])
             srcItem = QTableWidgetItem("  "+info['sha'])
             dstItem = QTableWidgetItem("  "+info['tha'])
             protocolItem = QTableWidgetItem(" "+package['protocol'])
             lenItem = QTableWidgetItem("  "+str(package['len']))
             #i  = self.package_info.currentRow()+1
             i = self.package_info.rowCount()
             self.package_info.insertRow(i)

             self.package_info.setItem(i, 0, timeItem)
             self.package_info.setItem(i, 1, srcItem)
             self.package_info.setItem(i, 2, dstItem)
             self.package_info.setItem(i, 3, protocolItem)
             self.package_info.setItem(i, 4, lenItem)
             
             show=str(info['spa'])+" --> "+str(info['tpa'])+ \
                  ' protocol_type:' +str(info['pro_type']) + \
                  ' op_code : ' +str(info['op'])
             infoItem = QTableWidgetItem(show)
             self.package_info.setItem(i, 5, infoItem)

             saveItem = QTableWidgetItem( json.dumps(package) )
             self.package_info.setItem(i, 6, saveItem)
             dataItem = QTableWidgetItem( data )
             self.package_info.setItem(i, 7, dataItem)
             return "ARP"
        elif eth.data.__class__.__name__=="IP6":
             
    
             ip6 = eth.data
             print 'get 6' + str(ip6.nxt)
             package['ip_ver'] = 6
             #IP6包解析
             info['fc']= ip6.fc              #优先级
             info['flow']=ip6.flow           #流量标识 
             info['payload_len']=ip6.plen    #有效载荷长度
             info['next_hdr']=ip6.nxt        #下一包头
             info['hop_lim']=ip6.hlim        #条数限制
             info['src']=inet_to_str(ip6.src)#起始地址
             info['dst']=inet_to_str(ip6.dst)#目的地址
             #info['extend_4'] = ip6.data
             if ip6.nxt != 1 and ip6.nxt !=2 and ip6.nxt !=17 and ip6.nxt !=6:
                  print 'return '
                  return
             package['ipv6_info']= info
             print package
             #if isinstance(ip6.data, dpkt.icmp.ICMP):
             
             if ip6.nxt == 1:       
                   icmp = ip6.data
                   package['protocol']='ICMP'
                   info['type']=icmp.type       #类型
                   info['code']=icmp.code       #代码
                   info['checksum']=icmp.sum    #校验和
                   data=icmp.data
                   package['info']=info
       
             elif ip6.nxt == 6:
                    tcp = ip6.data
                   
                    package['protocol']='TCP'
                    info['sport']=tcp.sport    #源端口
                    info['dport']=tcp.dport    #目的端口
                    info['seq']= tcp.seq       #seq    
                    info['ack']= tcp.ack       #ack
                    info['flags']=tcp.flags    #标志位
                    info['window']=tcp.win     #窗口大小
                    info['checksum']=tcp.sum   #校验和
                    data=tcp.data#数据 
                    info['packet_type'] = []   #具体
                    if  tcp.flags & dpkt.tcp.TH_SYN :
                        info['packet_type'].append("SYN")  #SYN
                    if tcp.flags & dpkt.tcp.TH_FIN:
                        info['packet_type'].append("FIN")  #FIN
                    if tcp.flags & dpkt.tcp.TH_RST:
                        info['packet_type'].append("RST")  #RST
                    if tcp.flags & dpkt.tcp.TH_PUSH:
                        info['packet_type'].append("PSH")  #PSH
                    if tcp.flags & dpkt.tcp.TH_ACK:
                       info['packet_type'].append("ACK")   #ACK
                    if tcp.flags & dpkt.tcp.TH_URG:
                        info['packet_type'].append("URG")  #URG
                    package['info']=info         
             #elif  isinstance(ip6.data, dpkt.udp.UDP):
             elif ip6.nxt == 17: 
                   udp = ip6.data
                 
                   package['protocol']='UDP'       
                   info['sport']=udp.sport         #源端口
                   info['dport']=udp.dport         #目的端口
                   info['ulen']=udp.ulen           #长度
                   info['checksum']=udp.sum        #校验和
                   data= udp.data
                   package['info']=info  
                   print package   
             #elif isinstance(ip6.data, dpkt.igmp.IGMP):
             elif ip6.nxt == 2:
                   igmp = ip6.data
                   package['protocol']='IGMP'
                   info['type']=igmp.type           #类型
                   info['maxresp']=igmp.maxresp     #最大响应延迟
                   info['checksum'] =igmp.sum       #校验和
                   info['group']=igmp.group         #组地址
                   data = igmp.data
                   package['info']=info
          
             if package:   
                  #i  = self.package_info.currentRow()+1
                  i = self.package_info.rowCount()
                  self.package_info.insertRow(i)
                  timeItem = QTableWidgetItem("  "+package['timestamp'])
           
                  srcItem = QTableWidgetItem("  "+info['src'])
                  dstItem = QTableWidgetItem("  "+info['dst'])
                  protocolItem = QTableWidgetItem(" "+package['protocol'])
                  lenItem = QTableWidgetItem("  "+str(package['len']))
            
                  self.package_info.setItem(i, 0, timeItem)
                  self.package_info.setItem(i, 1, srcItem)
                  self.package_info.setItem(i, 2, dstItem)
                  self.package_info.setItem(i, 3, protocolItem)
                  self.package_info.setItem(i, 4, lenItem)
           #self.package_info.
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
                          '  sum : '+str(info['checksum'])
                       infoItem = QTableWidgetItem(show)
                       self.package_info.setItem(i, 5, infoItem)
                  print data
                  dataItem = QTableWidgetItem(data)
                  self.package_info.setItem(i, 7, dataItem)
                  saveItem = QTableWidgetItem(json.dumps(package))
                  self.package_info.setItem(i, 6, saveItem)

    
 
   
        else:
           ip = eth.data
           package['ip_ver']= 4                                #版本
           if isinstance(eth.data, dpkt.ip.IP):
             package['ip_hl'] = ip.hl                          #头长度
             package['ip_tos'] = ip.tos                        #服务类型   
             package['ip_len'] =  ip.len                       #总长度
             package['ip_id'] = ip.id                          #标识
             package['ip_DF']=bool(ip.off & dpkt.ip.IP_DF)     #DF标识位
             package['ip_MF']=bool(ip.off & dpkt.ip.IP_MF)     #MF标识位
             package['ip_offset']=ip.off & dpkt.ip.IP_OFFMASK  #分段偏移量
             package['ip_ttl'] =  ip.ttl                       #生存期
             package['ip_protocol'] = ip.p                     #协议类型
             package['ip_sum'] = ip.sum                        #头校验和
             package['src_ip']=inet_to_str(ip.src)             #源地址
             package['dst_ip']=inet_to_str(ip.dst)             #目的地址
                                                
           if isinstance(ip.data, dpkt.icmp.ICMP):
             icmp = ip.data
             package['protocol']='ICMP'
             #package['src_ip'] = inet_to_str(ip.src)
             #package['dst_ip'] = inet_to_str(ip.dst)
             info['type']=icmp.type       #类型
             info['code']=icmp.code       #代码
             info['checksum']=icmp.sum    #校验和
             data=icmp.data
             package['info']=info
  
           elif isinstance(ip.data, dpkt.tcp.TCP):
             tcp = ip.data
             package['protocol']='TCP'
      
             info['sport']=tcp.sport    #源端口
             info['dport']=tcp.dport    #目的端口
             info['seq']= tcp.seq       #seq
             info['ack']= tcp.ack       #ack
             info['flags']=tcp.flags    #标记
             info['window']=tcp.win     #窗口大小
             info['checksum']=tcp.sum   #校验和
             data= tcp.data#数据
             info['packet_type'] = []   #具体
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
            
                 info['sport']=udp.sport  #源端口
                 info['dport']=udp.dport  #目的端口
                 info['ulen']=udp.ulen    #长度
                 info['checksum']=udp.sum #校验和 
                 data=udp.data
                 package['info']=info
           elif isinstance(ip.data, dpkt.igmp.IGMP):
                 igmp = ip.data
                 package['protocol']='IGMP'        
                 info['type']=igmp.type       #类型
                 info['maxresp']=igmp.maxresp #最大响应延迟
                 info['checksum'] =igmp.sum   #校验和
                 info['group']=igmp.group     #组地址
                 data = igmp.data
                 package['info']=info
         
           else:
                 package['protocol']=eth.data.__class__.__name__
             
           if package:
               #i  = self.package_info.currentRow()+1
               i = self.package_info.rowCount()
               self.package_info.insertRow(i)
               timeItem = QTableWidgetItem("  "+package['timestamp'])

               srcItem = QTableWidgetItem("  "+package['src_ip'])
               dstItem = QTableWidgetItem("  "+package['dst_ip'])
               protocolItem = QTableWidgetItem(" "+package['protocol'])
               lenItem = QTableWidgetItem("  "+str(package['len']))
             
               self.package_info.setItem(i, 0, timeItem)
               self.package_info.setItem(i, 1, srcItem)
               self.package_info.setItem(i, 2, dstItem)
               self.package_info.setItem(i, 3, protocolItem)
               self.package_info.setItem(i, 4, lenItem)
               #self.package_info.
               if (package['protocol'])=='UDP':
                     info=package['info']
                     show =str(info['sport'])+ " ->" + str(info['dport']) + ' id:'+str(package['ip_id'])+' MF:'+str(package['ip_MF']) 
                     infoItem = QTableWidgetItem(show)
                     self.package_info.setItem(i, 5, infoItem)
        
               elif (package['protocol'])=='TCP':
                 info=package['info']
                 show=str(info['sport'])+' -> '+str(info['dport']) + '  ['+','.join(info['packet_type'])+']  id :'+str(package['ip_id'])+' MF:'+str(package['ip_MF'])+\
                      ' window : '+ str(info['window'])
                 infoItem = QTableWidgetItem(show)
                 self.package_info.setItem(i, 5, infoItem)
    
               elif (package['protocol'])=='ICMP':
                 info=package['info']
                 show='type : '+str(info['type'])+ \
                      '  code : '+str(info['code']) + \
                      '  sum : '+str(info['checksum'])+ \
                       ' offset: '+str(ip.offset)+ \
                      '    ttl :'+str(package['ip_ttl'])
                 infoItem = QTableWidgetItem(show)
                 self.package_info.setItem(i, 5, infoItem)

      
               saveItem = QTableWidgetItem(json.dumps(package))
               self.package_info.setItem(i, 6, saveItem)
               dataItem = QTableWidgetItem( str(data)  )
               self.package_info.setItem(i, 7, dataItem)

        
    def package_reader(self):
        while(self.get_btnStop()==False):
           get = pcap(self.choose_eth.currentText(), immediate=True).loop(1,self.deal_package)
           if get :
            print "callback finised!"+ get
       
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

    @pyqtSlot(int, int)
    def on_package_info_cellClicked(self, row, column):
      self.textEdit.clear()
      self.textBrowser_2.clear()
      if self.package_info.item(row, 6) != None:
        package = json.loads(self.package_info.item(row, 6).text())
        protocol = package['protocol']
        data = self.package_info.item(row, 7).text()
        print data

        if protocol != 'ARP': 
             ip_ver = package['ip_ver']
        if protocol == 'ARP' :
             info=package['info']
             buf = package['buf']
             self.textBrowser_2.append("<pre>"+ buf+"</pre>")
             self.textEdit.append("<h3>   协议：ARP" +"</h3>")
             self.textEdit.append("<pre> 硬件类型: "+ str(info['hrd_type'])+ "  协议类型:"+ str(info['pro_type'])+\
                   " MAC地址长度："+str(info['mac_addr_len'])+" 协议地址长度："+str(info['pro_addr_len'])+" 操作码："+str(info['op'])+"</pre>" )
             self.textEdit.append("<pre> 发送方MAC地址 "+info['sha'] +"  发送方IP地址 "+info['spa'] +"</pre>")
             self.textEdit.append("<pre> 接收方MAC地址 "+info['tha'] +"  接收方IP地址 "+info['tpa'] +"</pre>")
             self.textEdit_2.setPlainText(bytes(data))
        elif protocol =='UDP' :
             ip_ver = package['ip_ver']
             buf = package['buf']
             self.textBrowser_2.append("<pre>"+ buf+"</pre>")
             if ip_ver == 4 :
                   info=package['info']
                   # ipv4头部信息
                   self.textEdit.append("<h3> IP首部:       IP version 4 "+"</h3>")
                   self.textEdit.append("<pre> 头长度:" + str(package['ip_hl'])  + \
                                           " 服务类型："+str(package['ip_tos'])+" 总长度："+ str(package['ip_len'])+" 标识："+str(package['ip_id'])+ \
                                           " DF标志位:"+str(package['ip_DF'])+" MF标志位:"+str(package['ip_MF'])+" 分段偏移量:"+str(package['ip_offset'])+"</pre>" )
                   self.textEdit.append("<pre> 生存期:"+ str(package['ip_ttl'])+" 协议类型:" + str(package['ip_protocol'])+" 头部校验和:"+str(package['ip_sum'])+"</pre>" )
                   self.textEdit.append("<pre> 源地址: "+str(package['src_ip'])+" 目的地址: "+str(package['dst_ip'])+"</pre>")
                                                     
                   # UDP头部信息
                   self.textEdit.append("<h3> UDP首部：</h3>")
                   self.textEdit.append("<pre> 源端口: "+str(info['sport']) +"  目的端口："+str(info['dport'])+\
                                            " 包长度："+str(info['ulen']) + " 校验和："+str(info['checksum'])+"</pre>")  
                   #
                    
                   self.textEdit_2.setPlainText(bytes(data))
                   self.textEdit.append("<pre> 抓包时间："+package['timestamp']+"</pre>")
             elif ip_ver == 6 :
                   info=package['info']
                   # ipv6头部信息
                   self.textEdit.append("<h3> IP首部:       IP version 6 "+"</h3>")             
                   self.textEdit.append("<pre> 优先级:"+str(info['fc'])+" 流量标识: "+ str(info['flow'])+" 有效载荷长度:"+ str(info['payload_len'])+\
                                             " 下一包头："+str(info['next_hdr'])+" 跳数限制："+str(info['hop_lim'])+"</pre>" )
                   self.textEdit.append("<pre> 起始地址："+str(info['src']) +"</pre>")
                   self.textEdit.append("<pre> 目的地址："+str(info['dst'])+ "</pre>")
                   # UDP头部信息      
                   self.textEdit.append("<h3> UDP首部：</h3>")
                   self.textEdit.append("<pre> 源端口: "+str(info['sport']) +"  目的端口："+str(info['dport'])+\
                                            " 包长度："+str(info['ulen']) + " 校验和："+str(info['checksum'])+"</pre>")  
                   # 


                   self.textEdit_2.setPlainText(bytes(data))
                   self.textEdit.append("<pre> 抓包时间："+package['timestamp']+"</pre>")
        


        elif protocol=='TCP' :
                   buf = package['buf']
                   self.textBrowser_2.append("<pre>"+ buf+"</pre>")
                   info=package['info']
                   if ip_ver ==4:
                       self.textEdit.append("<h3> IP首部:       IP version 4 "+"</h3>")
                       self.textEdit.append("<pre> 头长度:" + str(package['ip_hl'])  + \
                                           " 服务类型："+str(package['ip_tos'])+" 总长度："+ str(package['ip_len'])+" 标识："+str(package['ip_id'])+ \
                                           " DF标志位:"+str(package['ip_DF'])+" MF标志位:"+str(package['ip_MF'])+" 分段偏移量:"+str(package['ip_offset'])+"</pre>" )
                       self.textEdit.append("<pre> 生存期:"+ str(package['ip_ttl'])+" 协议类型:" + str(package['ip_protocol'])+" 头部校验和:"+str(package['ip_sum'])+"</pre>" )
                       self.textEdit.append("<pre> 源地址: "+str(package['src_ip'])+" 目的地址: "+str(package['dst_ip'])+"</pre>")

                       self.textEdit.append("<h3> TCP协议:"+"</h3>")
                       self.textEdit.append("<pre> 源端口: "+str(info['sport']) +"  目的端口："+str(info['dport'])+\
                                            " seq："+str(info['seq']) + " ack："+str(info['ack'])+"</pre>")  

                       self.textEdit.append("<pre> 标记: "+str(info['flags']) +"  窗口大小："+str(info['window'])+\
                                            " 标记类型："+','.join(info['packet_type']) + " 校验和："+str(info['checksum'])+"</pre>")  

                       self.textEdit_2.setPlainText(bytes(data))
                   elif ip_ver == 6 :
                      
                       self.textEdit.append("<h3> IP首部:       IP version 6 "+"</h3>")             
                       self.textEdit.append("<pre> 优先级:"+str(info['fc'])+" 流量标识: "+ str(info['flow'])+" 有效载荷长度:"+ str(info['payload_len'])+\
                                                 " 下一包头："+str(info['next_hdr'])+" 跳数限制："+str(info['hop_lim'])+"</pre>" )
                       self.textEdit.append("<pre> 起始地址："+str(info['src']) +"</pre>")
                       self.textEdit.append("<pre> 目的地址："+str(info['dst'])+ "</pre>")
 
                       self.textEdit.append("<h3> TCP协议:"+"</h3>")
                       self.textEdit.append("<pre> 源端口: "+str(info['sport']) +"  目的端口："+str(info['dport'])+\
                                            " seq："+str(info['seq']) + " ack："+str(info['ack'])+"</pre>")  

                       self.textEdit.append("<pre> 标记: "+str(info['flags']) +"  窗口大小："+str(info['window'])+\
                                            " 标记类型："+','.join(info['packet_type']) + " 校验和："+str(info['checksum'])+"</pre>")  

                       self.textEdit_2.setPlainText(bytes(data))


                 
        elif protocol == 'ICMP' :
               buf = package['buf']
               self.textBrowser_2.append("<pre>"+ buf+"</pre>")
               ip_ver = package['ip_ver'] 
               info=package['info']
               if ip_ver == 4:
                   self.textEdit.append("<h3> IP首部:       IP version 4 "+"</h3>")
                   self.textEdit.append("<pre> 头长度:" + str(package['ip_hl'])  + \
                                           " 服务类型："+str(package['ip_tos'])+" 总长度："+ str(package['ip_len'])+" 标识："+str(package['ip_id'])+ \
                                           " DF标志位:"+str(package['ip_DF'])+" MF标志位:"+str(package['ip_MF'])+" 分段偏移量:"+str(package['ip_offset'])+"</pre>" )
                   self.textEdit.append("<pre> 生存期:"+ str(package['ip_ttl'])+" 协议类型:" + str(package['ip_protocol'])+" 头部校验和:"+str(package['ip_sum'])+"</pre>" )
                   self.textEdit.append("<pre> 源地址: "+str(package['src_ip'])+" 目的地址: "+str(package['dst_ip'])+"</pre>")
                   
                   self.textEdit.append("<h3>"+"ICMP协议:" +"</pre>") 
                   self.textEdit.append("<pre>"+" 类型: "+str(info['type'])+" 代码："+str(info['code'])+" 校验和： "+str(info['checksum'])+ "</pre>") 
                   self.textEdit_2.setPlainText(bytes(data))
               elif ip_ver == 6 :
                       self.textEdit.append("<h3> IP首部:       IP version 6 "+"</h3>")             
                       self.textEdit.append("<pre> 优先级:"+str(info['fc'])+" 流量标识: "+ str(info['flow'])+" 有效载荷长度:"+ str(info['payload_len'])+\
                                                 " 下一包头："+str(info['next_hdr'])+" 跳数限制："+str(info['hop_lim'])+"</pre>" )
                       self.textEdit.append("<pre> 起始地址："+str(info['src']) +"</pre>")
                       self.textEdit.append("<pre> 目的地址："+str(info['dst'])+ "</pre>")
 
                       self.textEdit.append("<h3> ICMP协议:"+"</h3>")
                       self.textEdit.append("<pre>"+" 类型: "+str(info['type'])+" 代码："+str(info['code'])+" 校验和： "+str(info['checksum'])+ "</pre>") 
                       self.textEdit_2.setPlainText(bytes(data))

                                                        
                           
        elif protocol =='IGMP' :
                   buf = package['buf']
                   self.textBrowser_2.append("<pre>"+ buf+"</pre>")
                   info=package['info']
                   if ip_ver ==4:
                       self.textEdit.append("<h3> IP首部:       IP version 4 "+"</h3>")
                       self.textEdit.append("<pre> 头长度:" + str(package['ip_hl'])  + \
                                           " 服务类型："+str(package['ip_tos'])+" 总长度："+ str(package['ip_len'])+" 标识："+str(package['ip_id'])+ \
                                           " DF标志位:"+str(package['ip_DF'])+" MF标志位:"+str(package['ip_MF'])+" 分段偏移量:"+str(package['ip_offset'])+"</pre>" )
                       self.textEdit.append("<pre> 生存期:"+ str(package['ip_ttl'])+" 协议类型:" + str(package['ip_protocol'])+" 头部校验和:"+str(package['ip_sum'])+"</pre>" )
                       self.textEdit.append("<pre> 源地址: "+str(package['src_ip'])+" 目的地址: "+str(package['dst_ip'])+"</pre>")
                       self.textEdit.append("<h3>"+"IGMP协议:" +"</pre>") 
                       self.textEdit.append("<pre>"+" 类型: "+str(info['type'])+" 最大响应延迟："+str(info['maxresp'])+" 校验和： "+str(info['checksum'])+" 组地址:"+str(info['group'])+ "</pre>") 
                       self.textEdit_2.setPlainText(bytes(data))
                   elif ip_ver == 6 :
                       self.textEdit.append("<h3> IP首部:       IP version 6 "+"</h3>")             
                       self.textEdit.append("<pre> 优先级:"+str(info['fc'])+" 流量标识: "+ str(info['flow'])+" 有效载荷长度:"+ str(info['payload_len'])+\
                                                 " 下一包头："+str(info['next_hdr'])+" 跳数限制："+str(info['hop_lim'])+"</pre>" )
                       self.textEdit.append("<pre> 起始地址："+str(info['src']) +"</pre>")
                       self.textEdit.append("<pre> 目的地址："+str(info['dst'])+ "</pre>")                       
                       self.textEdit.append("<h3>"+"IGMP协议:" +"</pre>") 
                       self.textEdit.append("<pre>"+" 类型: "+str(info['type'])+" 最大响应延迟："+str(info['maxresp'])+" 校验和： "+str(info['checksum'])+" 组地址:"+str(info['group'])+ "</pre>") 
                       self.textEdit_2.setPlainText(bytes(data))

        else:
             print "error" 
             print protocol
             
             
if __name__ == "__main__":
 import sys
 from PyQt5.QtWidgets import QApplication
 app = QApplication(sys.argv)
 dlg = sniffer()
 dlg.show()
 sys.exit(app.exec_())
