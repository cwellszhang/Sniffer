# -*- coding: utf-8 -*-
#!/usr/bin/env python
import dpkt
import datetime
import socket
from sniffer import sniffer
def mac_addr(address):
    """Convert a MAC address to a readable/printable string
       Args:
           address (str): a MAC address in hex form (e.g. '\x01\x02\x03\x04\x05\x06')
       Returns:
           str: Printable/readable MAC address
    """
    return ':'.join('%02x' % ord(b) for b in address)
def inet_to_str(inet):
    """Convert inet object to a string
        Args:
            inet (inet struct): inet network address
        Returns:
            str: Printable/readable IP address
    """
    # First try ipv4 and then ipv6
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)

def deal_save(package,data):
    #Convert the  package to a readable format
        protocol = package['protocol']
        show = ''
        show=show+"抓包时间:"+package['timestamp']+"\n"
        if protocol != 'ARP':
             ip_ver = package['ip_ver']

        if protocol == 'ARP' :
             info=package['info']
             show =show+"协议:ARP    硬件类型:"+ str(info['hrd_type'])+" 协议类型:"+str(info['pro_type'])+"\n"
             show=show+"MAC地址长度："+str(info['mac_addr_len'])+" 协议地址长度:"+str(info['pro_addr_len'])+" 操作码："+str(info['op'])+"\n"
             show=show+"发送方MAC地址 "+info['sha'] +"  发送方IP地址 "+info['spa'] +" 接收方MAC地址 "+info['tha'] +"  接收方IP地址 "+info['tpa']+"\n"
             show=show+data+"\n"
        elif protocol =='UDP' :
             ip_ver = package['ip_ver']
             if ip_ver == 4 :
                   info=package['info']
                   # ipv4头部信息
                   show=show+"协议：UDP    IP首部:IP version 4 "+" 头长度:" + str(package['ip_hl'])+" 服务类型："+str(package['ip_tos'])+" 总长度："+ str(package['ip_len'])+" 标识："+str(package['ip_id'])+ \
                        " DF标志位:"+str(package['ip_DF'])+" MF标志位:"+str(package['ip_MF'])+" 分段偏移量:"+str(package['ip_offset'])+"\n"
                   show=show+"生存期:"+ str(package['ip_ttl'])+" 协议类型:" + str(package['ip_protocol'])+" 头部校验和:"+str(package['ip_sum'])+"\n"
                   show=show+"源地址: "+str(package['src_ip'])+" 目的地址: "+str(package['dst_ip'])+"\n"
                   # UDP头部信息
                   show=show+" UDP首部信息：源端口: "+str(info['sport']) +"  目的端口："+str(info['dport'])+" 包长度："+str(info['ulen']) + " 校验和："+str(info['checksum'])+"\n"
                   show =show+data+"\n"
             elif ip_ver == 6 :
                   info=package['info']
                   # ipv6头部信息
                   show=show+"协议：UDP    IP首部:IP version 6 "+"优先级:"+str(info['fc'])+" 流量标识: "+ str(info['flow'])+" 有效载荷长度:"+ str(info['payload_len'])+\
                                             " 下一包头："+str(info['next_hdr'])+" 跳数限制："+str(info['hop_lim'])+"\n"
                   show=show+"起始地址："+str(info['src'])+" 目的地址："+str(info['dst']) +"\n"
                   # UDP头部信息
                   show=show+"UDP首部："+"<pre> 源端口: "+str(info['sport']) +"  目的端口："+str(info['dport'])+\
                                            " 包长度："+str(info['ulen']) + " 校验和："+str(info['checksum'])+"\n"
                   show=show+(data)+"\n"
        elif protocol=='TCP' :
                   info=package['info']
                   if ip_ver ==4:
                      show=show+"协议:TCP   IP首部:IP version 4 "+" 头长度:" + str(package['ip_hl'])+" 服务类型："+str(package['ip_tos'])+" 总长度："+ str(package['ip_len'])+" 标识："+str(package['ip_id'])+ \
                        " DF标志位:"+str(package['ip_DF'])+" MF标志位:"+str(package['ip_MF'])+" 分段偏移量:"+str(package['ip_offset'])+"\n"
                      show=show+"生存期:"+ str(package['ip_ttl'])+" 协议类型:" + str(package['ip_protocol'])+" 头部校验和:"+str(package['ip_sum'])+"\n"
                      show=show+"源地址: "+str(package['src_ip'])+" 目的地址: "+str(package['dst_ip'])+"\n"
                      show=show+"TCP协议:"+" 源端口: "+str(info['sport']) +"  目的端口："+str(info['dport'])+\
                                            " seq："+str(info['seq']) + " ack："+str(info['ack'])+str(info['flags']) +"  窗口大小："+str(info['window'])+\
                                            " 标记类型："+','.join(info['packet_type']) + " 校验和："+str(info['checksum'])+"\n"
                      show=show+data+"\n"
                   elif ip_ver == 6 :

                       # ipv6头部信息
                          show=show+"协议:TCP   IP首部:IP version 6 "+"优先级:"+str(info['fc'])+" 流量标识: "+ str(info['flow'])+" 有效载荷长度:"+ str(info['payload_len'])+\
                                             " 下一包头："+str(info['next_hdr'])+" 跳数限制："+str(info['hop_lim'])+"\n"
                          show=show+"起始地址："+str(info['src'])+" 目的地址："+str(info['dst']) +"\n"

                          show=show+"TCP协议:"+" 源端口: "+str(info['sport']) +"  目的端口："+str(info['dport'])+\
                                            " seq："+str(info['seq']) + " ack："+str(info['ack'])+str(info['flags']) +"  窗口大小："+str(info['window'])+\
                                            " 标记类型："+','.join(info['packet_type']) + " 校验和："+str(info['checksum'])+"\n"
                          show=show+data+"\n"

        elif protocol == 'ICMP' :
               ip_ver = package['ip_ver']
               info=package['info']
               if ip_ver == 4:
                   show=show+"协议:ICMP   IP首部:IP version 4 "+" 头长度:" + str(package['ip_hl'])+" 服务类型："+str(package['ip_tos'])+" 总长度："+ str(package['ip_len'])+" 标识："+str(package['ip_id'])+ \
                        " DF标志位:"+str(package['ip_DF'])+" MF标志位:"+str(package['ip_MF'])+" 分段偏移量:"+str(package['ip_offset'])+"\n"
                   show=show+"生存期:"+ str(package['ip_ttl'])+" 协议类型:" + str(package['ip_protocol'])+" 头部校验和:"+str(package['ip_sum'])+"\n"
                   show=show+"源地址: "+str(package['src_ip'])+" 目的地址: "+str(package['dst_ip'])+"\n"

                   show=show+"ICMP协议:"+" 类型: "+str(info['type'])+" 代码："+str(info['code'])+" 校验和： "+str(info['checksum'])+"\n"
                   show=show+data+"\n"
               elif ip_ver == 6 :
                   # ipv6头部信息
                   show=show+"协议:ICMP  IP首部:IP version 6 "+"优先级:"+str(info['fc'])+" 流量标识: "+ str(info['flow'])+" 有效载荷长度:"+ str(info['payload_len'])+\
                                             " 下一包头："+str(info['next_hdr'])+" 跳数限制："+str(info['hop_lim'])+"\n"
                   show=show+"起始地址："+str(info['src'])+" 目的地址："+str(info['dst']) +"\n"

                   show=show+"ICMP协议:"+" 类型: "+str(info['type'])+" 代码："+str(info['code'])+" 校验和： "+str(info['checksum'])+"\n"
                   show=show+data+"\n"



        elif protocol =='IGMP' :
                   info=package['info']
                   if ip_ver ==4:
                         show=show+"协议：IGMP    IP首部:IP version 4 "+" 头长度:" + str(package['ip_hl'])+" 服务类型："+str(package['ip_tos'])+" 总长度："+ str(package['ip_len'])+" 标识："+str(package['ip_id'])+ \
                             " DF标志位:"+str(package['ip_DF'])+" MF标志位:"+str(package['ip_MF'])+" 分段偏移量:"+str(package['ip_offset'])+"\n"
                         show=show+"生存期:"+ str(package['ip_ttl'])+" 协议类型:" + str(package['ip_protocol'])+" 头部校验和:"+str(package['ip_sum'])+"\n"
                         show=show+"源地址: "+str(package['src_ip'])+" 目的地址: "+str(package['dst_ip'])+"\n"
                         show=show+"IGMP协议:" +" 类型: "+str(info['type'])+" 最大响应延迟："+str(info['maxresp'])+" 校验和： "+str(info['checksum'])+" 组地址:"+str(info['group'])+"\n"
                         show=show+data+"\n"
                   elif ip_ver == 6 :
                        # ipv6头部信息
                        show=show+"协议：IGMP    IP首部:IP version 6 "+"优先级:"+str(info['fc'])+" 流量标识: "+ str(info['flow'])+" 有效载荷长度:"+ str(info['payload_len'])+\
                                             " 下一包头："+str(info['next_hdr'])+" 跳数限制："+str(info['hop_lim'])+"\n"
                        show=show+"起始地址："+str(info['src'])+" 目的地址："+str(info['dst']) +"\n"
                        show=show+"IGMP协议:" +" 类型: "+str(info['type'])+" 最大响应延迟："+str(info['maxresp'])+" 校验和： "+str(info['checksum'])+" 组地址:"+str(info['group'])+"\n"
                        show=show+data+"\n"
        show=show+"\n"
        return show




