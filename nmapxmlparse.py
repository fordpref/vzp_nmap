"""
Program to parse nmap XML files in a directory to generate a site report by protocol
"""

"""
Import modules
"""

import xml.etree.ElementTree as ET
from subprocess import *
import sys, os


"""
Global Variables
"""
tree = {}
root = []
xmldir = ""
files = []
repfile = ""
writefile = ""
proto = {}



def evalargs():
    global xmldir, files, repfile
    f = {}
    if len(sys.argv) < 2 or len(sys.argv) < 3 or len(sys.argv) > 3:
        print "This script takes 2 command line arguments, path to the nmap directory and name of the report file.\n"
        xmldir = raw_input("What is the path to the nmap directory: ");
        repfile = raw_input("What is the name of the report file: ");
    else:
        xmldir = sys.argv[1]
        repfile = sys.argv[2] 
    f = Popen('dir /b ' + xmldir + '*.xml', shell=True, stdout=PIPE)
    files = f.communicate()[0].split('\n')

def loop_files():
    global tree, root, files
    x = ""

    for x in files:
        x = x[:-1]
        if len(x) > 4:
            tree = ET.parse(xmldir + x)
            root = tree.getroot()
            print x
            parse()


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
        ports = host.find('ports')
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


            if x.find('service') == True:
                service = x.find('service')

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

            
        
            print type(productname)
            if 'IP' in proto[protocol][port][servicename][productname]:
                if ipaddress in proto[protocol][port][servicename][productname]['IP'] == True:
                    continue
                else:
                    proto[protocol][port][servicename][productname]['IP'].append(ipaddress)
            else:
                proto[protocol][port][servicename][productname]['IP'] = []
                proto[protocol][port][servicename][productname]['IP'].append(ipaddress)
            
def check_rep_file():
    global writefile, xmldir, repfile
    if os.path.isfile(xmldir + repfile) == True:
        repfile = raw_input("Report File Exists, type another name: ");
        check_rep_file()
        pass
    else:
        writefile = open(xmldir + repfile, 'w')

    
def report():
    global proto, xmldir, repfile, writefile

    report = ""
    check_rep_file()    
    
    for protocol in sorted(proto):
        for port in sorted(proto[protocol]):
            for servicename in sorted(proto[protocol][port]):
                for productname in sorted(proto[protocol][port][servicename]):
                    addresses = ",".join(proto[protocol][port][servicename][productname]['IP'])
                    report = protocol + ',' + str(port) + ',' + servicename + ',' + productname + ',' + addresses + "\n"
                    print report
                    writefile.write(report)
    writefile.close()

        
"""
Begin main program
"""

evalargs()
loop_files()
report()

#print root
#print "NMAP: " + root.get('args')
#for host in root.findall('host'):
#    for addr in host.findall('address'):
        #addr = host.find('address').get('addr')
#        print "Host: " + str(addr.get('addr'))
