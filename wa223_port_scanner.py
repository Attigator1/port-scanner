#! /usr/bin/python

import sys
import time
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *


exitvalue = 0
while exitvalue == 0:
    print ("Welcome to Will's Port Scanner! Select a function below (type in the number)\n")
    print ("1 - TCP Scan \n")
    print ("2 - UDP Scan \n")
    print ("3 - Traceroute \n")
    print ("4 - Exit Program \n")

    #menu input goe shere
    menu = input("Enter value: ")

    if menu == 1:
      print ("---TCP Scan--- \n")
      print ("Please list the hostnames you would like to test. Separate each hostname with a ';' with NO spaces. Here is an example: 12.122.127.89;137.89.57.18;www.google.com;0.0.0.0\n")
      TCPHinput = raw_input("->")
      TCPsplits = TCPHinput.split(";")
      TCPHostList = []
      #this splits the input and appends it into a list
      for TCPsplit in TCPsplits:
          TCPHostList.append(TCPsplit)
      #print len(TCPHostList)
      #print ("You will be testing " + len(TCPHostList) + " hosts!\n")
      for i in TCPHostList:
        #loop through hosts
        print ("\nSelected Hostname/IP: " + i + "\n")
        print ("For this IP, please list the ports you want to test. Same as last time, separate the host with a ';' with NO spaces. Here is an example: 88;89;144\n")
        TCPPortinput = raw_input("->")
        TCPPortsplits =  TCPPortinput.split(";")
        TCPPortList = []
        #This splits and appends the port inputs
        for sp in TCPPortsplits:
            TCPPortList.append(sp)
        #print ("You will be testing " + len(TCPPortList) + " ports!\n")
        for p in TCPPortList:
          print ("\nTesting port: " + p)
          #loops through the port list
          if (p.isdigit()):
            #do Scapy stuff here
            # add print function here

            dst_ip = i
            src_port = RandShort()
            #this changes the port # into a int
            dst_port = int(p)

            tcp_connect_scan_resp = sr1(IP(dst=dst_ip)/TCP(sport=src_port,dport=dst_port,flags="S"),timeout=10)
            if(str(type(tcp_connect_scan_resp))=="<type 'NoneType'>"):
                #no response result
                print ("Port:" + p + " Closed\n")
            elif(tcp_connect_scan_resp.haslayer(TCP)):
                #These check the different flags for the end result
                if(tcp_connect_scan_resp.getlayer(TCP).flags == 0x12):
                    send_rst = sr(IP(dst=dst_ip)/TCP(sport=src_port,dport=dst_port,flags="AR"),timeout=10)
                    print ("Port:" + p + " Open\n")
                elif (tcp_connect_scan_resp.getlayer(TCP).flags == 0x14):
                    print ("Port:" + p + " Closed\n")
          else:
            print ("Not a valid port value! Moving on to the next port in list")







    elif menu == 2:
      print ("---UDP Scan--- \n")
      #UDP Scanner--
      print ("Please list the hostnames you would like to test. Separate each hostname with a ';' with NO spaces. Here is an example: 12.122.127.89;137.89.57.18;www.google.com;0.0.0.0\n")
      UDPHinput = raw_input(">")
      UDPHsp = UDPHinput.split(";")
      UDPHostList = []
      #Splitting & appending lists
      for ups in UDPHsp:
          UDPHostList.append(ups)
      #print ("You will be testing " + len(UDPHostList) + " hosts!\n")
      for i in UDPHostList:
        print ("\nSelected Hostname/IP: " + i + "\n")
        print ("For this IP, please list the ports you want to test. Same as last time, separate the host with a ';' with NO spaces. Here is an example: 88;89;144\n")
        #going through the ports and ips
        UDPPortinput = raw_input(">")
        UDPPsp = UDPPortinput.split(";")
        UDPPortList = []
        #adding ports to lists
        for t in UDPPsp:
            UDPPortList.append(t)
        #print ("You will be testing " + len(UDPPortList) + " Ports!\n")
        for p in UDPPortList:
          print ("\nTesting port: " + p)
          if (p.isdigit()):
            #do Scapy stuff here
            # add print function here
            dst_ip = i
            src_port = RandShort()
            dst_port= int(p)



            #scapy functions and  results here
            pkt = sr1(IP(dst=dst_ip)/UDP(sport=src_port, dport=dst_port), timeout=2, verbose=0)
            if(str(type(pkt))=="<type 'NoneType'>"):
                print ("Port:" + p + " Closed")
            else:
    			if pkt.haslayer(ICMP):
    				print ("Port:" + p + " Closed\n")
    			elif pkt.haslayer(UDP):
    				print ("Port:" + p + " Open / filtered\n")
    			else:
    				print ("Port:" + p + " Unknown\n")
    				print(pkt.summary())



          else:
            print ("Not a valid port value! Moving on to the next port in list")

    elif menu == 3:
      print ("---Traceroute--- \n")
      #getting the ip input
      TInput = raw_input("Enter hostname or IP: ")
      #printing out results
      print(traceroute(TInput))




    elif menu == 4:
      print ("---Ending Program--- \n")
      print ("Goodbye!")
      #exit program
      sys.exit()

    else:
      print ("NOT A VAILD INPUT!! TRY AGAIN! \n")
      #input validation
