#! /usr/bin/python

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *


print ("Welcome to Will's Port Scanner! Select a function below (type in the number)\n")
print ("1 - TCP Scan \n")
print ("2 - UDP Scan \n")
print ("3 - Traceroute \n")
print ("4 - Exit Program \n")

menu = input("Enter value: ")

if menu == 1
  print ("---TCP Scan--- \n")
  print ("Please list the hostnames you would like to test. Separate each hostname with a ';' with NO spaces. Here is an example: 12.122.127.89;137.89.57.18;www.google.com;0.0.0.0\n")
  TCPHinput = input(">")
  TCPHostList = TCPHinput.split(";")
  print len(TCPHostList)
  for i in TCPHostList
    print (Selected Hostname/IP: " + TCPHostList[i] + "\n")
    print ("For this IP, please list the ports you want to test. Same as last time, separate the host with a ';' with NO spaces. Here is an example: 88;89;144\n")
    TCPPortinput = input(">")
    TCPPortList = TCPPortinput.split(";")
    for p in TCPPortList
      print ("Testing port: " + TCPPortList[p])
      if (TCPPortList[p].isdigit())
        #do Scapy stuff here
        # add print function here
      else
        print ("Not a valid port value! Moving on to the next port in list")







elif menu == 2
  print "---UDP Scan--- \n"
  print ("Please list the hostnames you would like to test. Separate each hostname with a ';' with NO spaces. Here is an example: 12.122.127.89;137.89.57.18;www.google.com;0.0.0.0\n")
  UDPHinput = input(">")
  UDPHostList = UDPHinput.split(";")
  print len(UDPHostList)
  for i in UDPHostList
    print (Selected Hostname/IP: " + UDPHostList[i] + "\n")
    print ("For this IP, please list the ports you want to test. Same as last time, separate the host with a ';' with NO spaces. Here is an example: 88;89;144\n")
    UDPPortinput = input(">")
    UDPPortList = UDPPortinput.split(";")
    for p in UDPPortList
      print ("Testing port: " + UDPPortList[p])
      if (UDPPortList[p].isdigit())
        #do Scapy stuff here
        # add print function here
      else
        print ("Not a valid port value! Moving on to the next port in list")

elif menu == 3
  print "---Traceroute--- \n"
  TInput = input("Enter hostname or IP: ")
  for i in range(1, 30):
    Tpkt = IP(dst=TInput, ttl=i) / UDP(dport=33434)
    reply = sr1(Tpkt, verbose=0)
    if reply is None:
      # fail
      break
    elif reply.type == 3:
      # we hit it
      print "Done!", reply.src
      break
    else:
      # keep going
      print "%d hops away: " % i , reply.src




elif menu == 4
  print "---Ending Program--- \n"
  print "Goodbye!"
  sys.exit()

else
  print "NOT A VAILD INPUT!! TRY AGAIN! \n"
