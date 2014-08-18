"""
Ping discovery and create host list
"""

import os, sys, platform, time
if platform.system() == 'Windows':
    import msvcrt
import xml.etree.ElementTree as ET
from datetime import datetime
from subprocess import *


opsys = platform.system()
ipaddresses = ''
hostlist = []
descname = ''
nmapdir = ''
clear = ''
tree = {}
root = []
files = []
proto = {}
opsys = platform.system()
hostlistfile = ''


def startup():
    """
    print at startup
    """
    global descname,clear

    if opsys == 'Windows':
        clear = 'cls'
        os.system(clear)
    elif opsys == 'Linux':
        clear = 'clear'
        os.system(clear)
    else:
        print 'OS not Windows or Linux, exiting...'
        exit
    
    print '\n\nVZP Discovery and Hostlist creation tool\n\n'
    print 'This program will take IP addresses or subnets'
    print 'from you and perform nmap discovery scans on '
    print 'them and give you a hostlist.txt file in: \n\n'
    print 'windows - c:\\assessment\\nmap\\'
    print 'linux - /opt/assessment/nmap/'
    print '\n\n\n'
    print 'To get started we need a descriptive name for the customer and assessment.'
    print '\nexample:  ZippyWidgets-InfoGather-Internal'
    print 'example:  ZippyWidgets-Pentest-Internal'
    print 'example:  ZippyWidgets-Pentest-External'
    print 'remember, it is your data and YOU have analyze this later....so help your future self out...\n\n'

    descname = raw_input('Descriptive Name:  ')
    

def createdirs():
    """
    check directories and make them if not there
    """

    global opsys, nmapdir
    if opsys == 'Windows':
        nmapdir = 'c:\\assessment\\nmap\\'
        if os.path.exists('c:\\assessment\\') == False:
            os.mkdir('c:\\assessment\\')
        if os.path.exists('c:\\assessment\\agents\\') == False:
            os.mkdir('c:\\assessment\\agents\\')
        if os.path.exists('c:\\assessment\\collection\\') == False:
            os.mkdir('c:\\assessment\\collection')
        if os.path.exists('c:\\assessment\\nmap\\') == False:
            os.mkdir('c:\\assessment\\nmap\\')
        if os.path.exists('c:\\assessment\\nessus\\') == False:
            os.mkdir('c:\\assessment\\nessus\\')
        if os.path.exists('c:\\assessment\\retina\\') == False:
            os.mkdir('c:\\assessment\\retina\\')
    elif opsys == 'Linux':
        nmapdir = '/opt/assessment/nmap/'
        if os.path.exists('/opt/assessment/') == False:
            os.mkdir('/opt/assessment/')
        if os.path.exists('/opt/assessment/agents') == False:
            os.mkdir('/opt/assessment/agents')
        if os.path.exists('/opt/assessment/collection') == False:
            os.mkdir('/opt/assessment/collection')
        if os.path.exists('/opt/assessment/nessus') == False:
            os.mkdir('/opt/assessment/nessus')
        if os.path.exists('/opt/assessment/nmap') == False:
            os.mkdir('/opt/assessment/nmap')
        if os.path.exists('/opt/assessment/retina') == False:
            os.mkdir('/opt/assessment/retina')
    

def getipaddresses():
    """
    Going to ask user for ip addresses to perform discovery on.
    enetered wtih cidr notation, ranges by -, and separated by commas.
    """
    global opsys,ipaddresses

    print '\n\nEnter IP addresses in ONE of several ways!\n'
    print 'CIDR:  192.168.0.0/24'
    print 'range: 192.168.0.1-10'
    print 'individual:  192.168.0.55'
    print 'or combined separated by spaces:  192.168.0/24 10.4.8.10-42 10.4.8.44-254 172.16.1.103\n\n'
    ipaddresses = raw_input('enter IPs here:  ')


def date_time_stamp():
    """
    Here we want to get the current date/time and format it for naming files
    """
    global opsys
    
    cal_date = ""
    cal_time = ""
    whole = ""
    zone = ""
    splittz = []
    
    whole = str(datetime.now()).split(" ")
    cal_date = whole[0]
    cal_date = cal_date.replace("-", ".")
    cal_time = whole[1].split(":")
    zone = time.strftime("%z")
    if opsys == 'Windows':
        splittz = zone.split(" ")
        zone = splittz[0][:1] + splittz[1][:1] + splittz[2][:1]
    else:
        zone = 'GMT' + zone[:-2]
    date = cal_date + "-" + cal_time[0] + cal_time[1] + zone
    return date

def discoveryscan():
    """
    Now we take the IPs input and do a quick ping discovery scan on them and create a hostlist from it
    """
    global opsys, ipaddresses, hostlist, descname, nmapdir, hostlistfile
    tempfile1 = ''
    tempfile2 = ''
    hostfile = ''
    line = ''
    nmapfile = ''
    args = []
    hostname = ''
    hostlist = []
    host = ''
    

    date = date_time_stamp()
    hostlistfile = nmapdir + 'Hostlist-' + descname + '-' + date + '.txt'

    """
    First do nmap ping scan with raw output to all formats
    """
    if opsys == 'Windows':
        date = date_time_stamp()
        tempfile1 = nmapdir + date + '-' + descname + '-PING-DISCOVERY'
        call('nmap.exe -sn -n --open -oA ' + tempfile1 + ' ' + ipaddresses)

        """
        Now we do a syn discovery scan with raw output to all formats
        """
        date = date_time_stamp()
        tempfile2 = nmapdir + date + '-' + descname + '-SYN-DISCOVERY'
        call('nmap.exe -PS21,22,23,25,80,111,135,139,389,443,445 -p1 -Pn -n --open -oA ' + tempfile2 + ' ' + ipaddresses)
        
        

        """
        Now read in the gnmap files and cut out the hosts and create a unique hostlist
        might switch to reading the xml later
        """
        nmapfile1 = open(tempfile1 + '.gnmap', 'r')
        nmapfile2 = open(tempfile2 + '.gnmap', 'r')
        hostfile = open(hostlistfile, 'w')
    else:
        date = date_time_stamp()
        tempfile1 = nmapdir + date + '-' + descname + '-PING-DISCOVERY'
        call('/usr/bin/nmap -sn -n --open -oA ' + tempfile1 + ' ' + ipaddresses, shell = True)

        """
        Now we do a syn discovery scan with raw output to all formats
        """
        date = date_time_stamp()
        tempfile2 = nmapdir + date + '-' + descname + '-SYN-DISCOVERY'
        call('/usr/bin/nmap -PS21,22,23,25,80,111,135,139,389,443,445 -p1 -Pn -n --open -oA ' + tempfile2 + ' ' + ipaddresses, shell = True)
        
        

        """
        Now read in the gnmap files and cut out the hosts and create a unique hostlist
        might switch to reading the xml later
        """
        nmapfile1 = open(tempfile1 + '.gnmap', 'r')
        nmapfile2 = open(tempfile2 + '.gnmap', 'r')
        hostfile = open(hostlistfile, 'w')
    
    for line in nmapfile1:
        if line.startswith('Host: '):
            args = line.split(' ')
            print args[1]
            hostlist.append(args[1])

    for line in nmapfile2:
        if line.startswith('Host: '):
            args = line.split(' ')
            print args[1]
            if args[1] in hostlist == False:
                hostlist.append(args[1])

    """
    Now write the hostlist to the file
    """
    for host in sorted(hostlist):
        hostfile.write(host + '\n')
        

    """
    Now close the files and finish
    """
    nmapfile1.close()
    nmapfile2.close()
    hostfile.close()
            
def hostnames():
    """
    This will use the nameserver specified to perform reverse lookup on the hostlist.txt
    """
    global opsys, hostlist, nmapdir, clear, descname
    nameserver = ''
    rawdata = ''
    date = date_time_stamp()
    hostsfile = open(nmapdir + 'hostnames-' + descname + '-' + date + '.txt', 'w')
    date = date_time_stamp()
    filename = nmapdir + date + '-' + descname + '-hostsnames'
    ip = ''

    os.system(clear)
    print '\n\nPerforming reverse lookups on IP hostlist we just collected.\n'
    if opsys == 'Windows':
        rawdata = Popen('nmap.exe -sL -iL ' + hostlistfile + ' -oA ' + filename, stdout=PIPE, stderr=PIPE)
        rawdata = rawdata.communicate()[0].split('\n')
    else:
        rawdata = Popen('nmap -sL -iL ' + hostlistfile + ' -oA ' + filename, stdout=PIPE, stderr=PIPE, shell = True)
        rawdata = rawdata.communicate()[0].split('\n')
    for line in rawdata:
        if line.startswith('Nmap scan report'):
            line = line.split(' ')
            if len(line) > 5:
                ip = line[5]
                ip = ip[1:-2]
                print line[4] + '\t' + ip
                hostsfile.write(line[4] + '\t' + ip + '\n')

    hostsfile.close()

def tcpscans():
    global opsys, hostlist, nmapdir, clear
    date = date_time_stamp()
    tempfile = nmapdir + date + '-' + descname + '-TCP-SYNSCAN'
    
    os.system(clear)
    print '\n\nPerforming TCP Syn Scans\n'
    if opsys == 'Windows':
        call('nmap.exe -Pn -n --open -sS --top-ports 10000 -A --max-hostgroup 10 --max-retries 3 --host-timeout 5m -iL ' + hostlistfile + ' -oA ' + tempfile)
    else:
        call('nmap -Pn -n --open -sS --top-ports 10000 -A --max-hostgroup 10 --max-retries 3 --host-timeout 5m -iL ' + hostlistfile + ' -oA ' + tempfile, shell = True)

def udpscans():
    global opsys, hostlist, nmapdir, clear
    date = date_time_stamp()
    tempfile = nmapdir + date + '-' + descname + '-UDP-SCAN'
    
    os.system(clear)
    print '\n\nPerforming UDP Syn Scans\n'
    if opsys == 'Windows':
        call('nmap.exe -Pn -n --open -sU --top-ports 30 -sV -sC --max-hostgroup 10 --max-retries 3 --host-timeout 2m -iL ' + hostlistfile + ' -oA ' + tempfile)
    else:
        call('nmap -Pn -n --open -sU --top-ports 30 -sV -sC --max-hostgroup 10 --max-retries 3 --host-timeout 2m -iL ' + hostlistfile + ' -oA ' + tempfile, shell = True)

def ipscans():
    global opsys, hostlist, nmapdir, clear
    date = date_time_stamp()
    tempfile = nmapdir + date + '-' + descname + '-IPPROTO-SCAN'
    
    os.system(clear)
    print '\n\nPerforming IPPROTO Syn Scans\n'
    if opsys == 'Windows':
        call('nmap.exe -Pn -n --open -sO --max-hostgroup 10 --max-retries 3 --host-timeout 2m -iL ' + hostlistfile + ' -oA ' + tempfile)
    else:
        call('nmap -Pn -n --open -sO --max-hostgroup 10 --max-retries 3 --host-timeout 2m -iL ' + hostlistfile + ' -oA ' + tempfile, shell = True)

def portreportprep():
    global files, opsys, nmapdir, tree, root
    f = {}
    x = ''

    if opsys == 'Windows':
        f = Popen('dir /b "' + nmapdir + '*.xml"', shell=True, stdout=PIPE)
        files = f.communicate()[0].split('\n')
    else:
        f = Popen('ls ' + nmapdir + ' |grep \.xml', shell=True, stdout=PIPE)
        files = f.communicate()[0].split('\n')

    for x in files:
       if x[-1:] == '\n':
           x = x[:-1]
       if x[-1:] == '\r':
           x = x[:-1]
       if len(x) > 4:
           try:
               tree = ET.parse(nmapdir + x)
               root = tree.getroot()
               parse()
           except:
               print 'Failed to parse: ' + nmapdir + x
    
def parse():
   """
   This is a bit weird.  We want to capture each tcp and udp port number
   we find listening, capture the service name (there may be multiple), capture
   the productname (there may be multiple), and capture the IP addresses for each port and service.
   So, 21 may be open on 10 systems, but some are using wuftp, some
   another ftp, some IIS.  In metasploit, I can list all the FTP IP addresses
   but  I can't get a complete protocol/service name list.  I can get all the
   listening services for a give host, but not all the ports from all the
   hosts with all the services at once. This is what we are going to try to
   do here.  proto['TCP']['##']['servicename']['productname'] = [ip list]
   """
   
   global proto, root

   protocol = ''
   port = ''
   servicename = ''
   productname = ''
   ipaddress = ''
   addresses = []

   #Now lets parse the xml and get the fields we need.
   #The parent element is 'host'.  subelements will be nested below
   #collected, tested for inclusion, and then added as needed.
   for host in root.findall('host'):
       addrobj = host.find('address')
       ipaddress = addrobj.get('addr')
       ipaddress = ''.join(ipaddress.split())
       ports = host.find('ports')
       if ports != None:
           for x in ports.findall('port'):
               protocol = x.get('protocol')
               if protocol in proto:
                   pass
               else:
                   proto[protocol] = {}


               port = int(x.get('portid'))
               if port in proto[protocol]:
                   pass
               else:
                   proto[protocol][port] = {}

               service = x.find('service')
               if service != None:
                   

                   if service.get('name') == None:
                       servicename = 'None'
                   else:
                       servicename = service.get('name')
                       
                   if servicename in proto[protocol][port]:
                       pass
                   else:
                       proto[protocol][port][servicename] = {}


                   if service.get('product') == None:
                       productname = 'None'
                   else:
                       productname = service.get('product')
                       
                   if productname in proto[protocol][port][servicename]:
                       pass
                   else:
                       proto[protocol][port][servicename][productname] = {}
               else:
                   servicename = 'None'
                   productname = 'None'
                   if servicename in proto[protocol][port]:
                       pass
                   else:
                       proto[protocol][port][servicename] = {}

                   if productname in proto[protocol][port][servicename]:
                       pass
                   else:
                       proto[protocol][port][servicename][productname] = {}

               
           
               if 'IP' in proto[protocol][port][servicename][productname]:
                   if ipaddress in proto[protocol][port][servicename][productname]['IP']:
                       pass
                   else:
                       proto[protocol][port][servicename][productname]['IP'].append(ipaddress)
               else:
                   proto[protocol][port][servicename][productname]['IP'] = []
                   proto[protocol][port][servicename][productname]['IP'].append(ipaddress)

def remove_duplicates():
   global proto
   servicename = ''
   productname = ''
   sp = {}
   s = {}
   p = {}
   popkey = []
   removeip = []
   

   for protocol in sorted(proto):
       for port in sorted(proto[protocol]):
           sp[port] = []
           s[port] = []
           p[port] = []
           for servicename in proto[protocol][port]:
               for productname in proto[protocol][port][servicename]:
                   if servicename != 'None' and productname != 'None':
                       sp[port].extend(proto[protocol][port][servicename][productname]['IP'])
                   elif servicename !='None' and productname == 'None':
                       s[port].extend(proto[protocol][port][servicename][productname]['IP'])
                   elif servicename == 'None' and productname != 'None':
                       p[port].extend(proto[protocol][port][servicename][productname]['IP'])

       
   
   for protocol in sorted(proto):
       for port in sorted(proto[protocol]):
           for servicename in proto[protocol][port]:
               for productname in proto[protocol][port][servicename]:
                   if servicename == 'None' and productname == 'None':
                       for ip in proto[protocol][port][servicename][productname]['IP']:
                           if ip in sp[port]:
                               removeip.append(ip)
                           if ip in s[port]:
                               removeip.append(ip)
                           if ip in p[port]:
                               removeip.append(ip)
                       for ip in removeip:
                           proto[protocol][port][servicename][productname]['IP'].remove(ip)
                       removeip = []
                   if servicename != 'None' and productname == 'None':
                       for ip in proto[protocol][port][servicename][productname]['IP']:
                           if ip in sp[port]:
                               removeip.append(ip)
                       for ip in removeip:
                           proto[protocol][port][servicename][productname]['IP'].remove(ip)
                       removeip = []
                   if servicename == 'None' and productname != 'None':
                       for ip in proto[protocol][port][servicename][productname]['IP']:
                           if ip in sp[port]:
                               removeip.append(ip)
                       for ip in removeip:
                           proto[protocol][port][servicename][productname]['IP'].remove(ip)
                       removeip = []
                           
                           
                       
   

   
def report():
   global proto, nmapdir

   report = ''
   date = date_time_stamp()
   repfile1 = nmapdir + 'nmap-IPPROTO-port-report-' + date + '.csv'
   repfile2 = nmapdir + 'nmap-TCP-port-report-' + date + '.csv'
   repfile3 = nmapdir + 'nmap-UDP-port-report-' + date + '.csv'
   writefile1 = open(repfile1, 'w')
   writefile2 = open(repfile2, 'w')
   writefile3 = open(repfile3, 'w')

   writefile1.write('IP/TCP/UDP,Port#,Service Name,Product Name,IP List\n')
   writefile2.write('IP/TCP/UDP,Port#,Service Name,Product Name,IP List\n')
   writefile3.write('IP/TCP/UDP,Port#,Service Name,Product Name,IP List\n')
   for protocol in sorted(proto):
       for port in sorted(proto[protocol]):
           for servicename in sorted(proto[protocol][port]):
               for productname in sorted(proto[protocol][port][servicename]):
                   if not proto[protocol][port][servicename][productname]['IP']:
                       pass
                   else:
                       addresses = ",".join(proto[protocol][port][servicename][productname]['IP'])
                       report = protocol + ',' + str(port) + ',' + servicename + ',' + productname + ',' + addresses + "\n"
                       #print report
                       if protocol == 'ip':
                           writefile1.write(report)
                       elif protocol == 'tcp':
                           writefile2.write(report)
                       else:
                           writefile3.write(report)
                    
   writefile1.close()
   writefile2.close()
   writefile2.close()

           
    


"""
Main Program
"""

startup()
createdirs()
getipaddresses()
discoveryscan()
hostnames()
tcpscans()
udpscans()
ipscans()
portreportprep()
remove_duplicates()
report()

            
