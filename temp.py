       elif eth.data.__class__.__name__=="IP6":
             pass
    '''
             ip6 = eth.data
             package['ip_ver'] = 6
             #IP6包解析
             info['flow']=ip6.flow           #流量标识 
             info['payload_len']=ip6.plen    #有效载荷长度
             info['next_hdr']=ip6.nxt        #下一包头
             info['hop_lim']=ip6.hlim        #条数限制
             info['src']=inet_to_str(ip6.src)#起始地址
             info['dst']=inet_to_str(ip6.dst)#目的地址
             info['extend_4'] = ip6.data
             print ip6.nxt
             package['ipv6_info']= info
             print package
             if info['dst']==None:
                 return
             if isinstance(ip6.data, dpkt.icmp.ICMP):
             if ip6.nxt == 1:       
                   icmp = ip6.data
                   package['protocol']='ICMP'
                   info['type']=icmp.type
                   info['code']=icmp.code
                   info['checksum']=icmp.sum
                   info['data']=icmp.data
                   package['info']=info
       
             elif ip6.nxt ==6:
                    tcp = ip6.data
                   
                    package['protocol']='TCP'
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
             #elif  isinstance(ip6.data, dpkt.udp.UDP):
             elif ip6.nxt == 17: 
                   udp = ip6.data
                   print str(info['extend_4'])
                   package['protocol']='UDP'       
                   info['sport']=udp.sport
                   info['dport']=udp.dport
                   info['ulen']=udp.ulen
                   info['checksum']=udp.sum
                   package['info']=info  
                   print package   
             #elif isinstance(ip6.data, dpkt.igmp.IGMP):
             elif ip6.nxt == 2:
                   igmp = ip6.data
                   package['protocol']='IGMP'
                   info['type']=igmp.type
                   info['maxresp']=igmp.maxresp
                   info['checksum'] =igmp.sum
                   info['group']=igmp.group
                   package['info']=info
             
             else:       
                   package = None
             if package:   
                  i  = self.package_info.currentRow()+1
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
        
                  #saveItem = QTableWidgetItem(str(package))
                  #self.package_info.setItem(i, 6, saveItem)

    '''
