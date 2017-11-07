# Sniffer
python sniffer finished with QT5

安装说明
=========

1. 运行环境：
本程序采用LibPcap抓包库，使用python语言，在macOS系统完成编译，支持macos或linux系统。




2. 编译工具：Qt5.5.7、 Pycharm5、python2.7、python3.5、Eric6（可选）

  所需类库：pyqt5、pypcap，dpkt
 （pypcap抓包必须使用）
 
 
  所需依赖：
  
       pyqt5： 必须安装python3, qt5, sip
       pypcap：必须安装：python2
       注：python3仅仅提供pyqt5依赖库，其他地方没有使用，安装完以后需要确保默认python版本为2.7
  
  
  

3. 安装说明：

    * 在MAC OS平台下安装pyqt5：
        brew install pyqt5 
     会自动安装所需依赖（qt5\sip\python3）
           
    - 在LINUX下安装（不推荐），仅安装qt5比较费时，其他都差不多，只需按照2中列出的依赖关系进行安装,但我没有在纯linux下测试过，如果库安装兼容的话理论上是能运行的。

   （可选)手动安装Qt5:虽然brew提供了自动安装，但我搭环境的时候还是会出问题，手动安装不会出问题；
    如果发现无法使用的话建议到官网下载安装相应版本，最简安装即可。


    * 安装抓包库pypcap
         pip install pypcap


    * 安装包解析库dpkt
        pip install dpkt


    以上为所必需安装的库和一些比较麻烦的库的说明，安装完成即可进行测试
    * 提示：如果自动安装了python3，一定要切换回python2，否则无法运行
    
    



由于用到了python2、3以及qt5安装的一些动态图形库，使用打包软件时出现很多bug,网上有资料说python打包
程序存在兼容性问题，一些图形库的打包仍没有解决方案

所以项目的可执行文件不能脱离系统环境来运行，需要按上面步骤配置好环境以后运行pyc文件或者在终端启动。
 
功能说明：
===========   
  1. 网卡选择  
  2. 支持TCP、UDP、ICMP、ARP头的解析  
  3. 支持包过滤功能,包括端口过滤、源目的地址过滤、协议过滤  
  4. 支持批量数据包的本地保存  
  5. 其他功能包括IP分片重组、文件重组、指定字段查询。  
  
 
 
