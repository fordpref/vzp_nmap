"""
Program to parse nmap XML files in a directory to generate a site report by protocol
"""

"""
Import modules
"""

import xml.etree.ElementTree as ET
from subprocess import *
import sys, os, platform


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
opsys = platform.system()
parseos = {}



def evalargs():
    global xmldir, files, repfile, opsys
    f = {}
    if len(sys.argv) < 2 or len(sys.argv) < 3 or len(sys.argv) > 3:
        print "This script takes 2 command line arguments, path to the nmap directory and name of the report file.\n"
        xmldir = get_check_path()
        repfile = get_check_rep()
    else:
        xmldir = sys.argv[1]
        if opsys == 'Windows':
            if xmldir[-1:] != '\\':
                xmldir += '\\'
        else:
            if xmldir[-1:] != '/':
                xmldir += '/'
        if os.path.exists(xmldir) == False:
            xmldir = get_check_path()
        repfile = sys.argv[2]
        if repfile[-4:] != '.csv':
            repfile += '.csv'
        if os.path.isfile(xmldir + repfile):
            repfile = get_check_rep()
 
    if opsys == 'Windows':
        f = Popen('dir /b "' + xmldir + '*.xml"', shell=True, stdout=PIPE)
        files = f.communicate()[0].split('\n')
    else:
        f = Popen('ls ' + xmldir + ' |grep \.xml', shell=True, stdout=PIPE)
        files = f.communicate()[0].split('\n')

def get_check_path():
    global opsys
    path = ''
    path = raw_input('The path to the xmlfiles is not valid, enter path: ')
    if opsys == 'Windows':
        if path[-1:] != '\\':
            path += '\\'
    else:
        if path[-1:] != '/':
            path += '/'
    if os.path.exists(path):
        return path
    else:
        path = get_check_path()
        return path
   

def get_check_rep():
    global xmldir
    outfile = ''
    outfile = raw_input('Name of report file: ')
    return outfile
       

def loop_files():
    global tree, root, files
    x = ""

    for x in files:
        if x[-1:] == '\n':
            x = x[:-1]
        if x[-1:] == '\r':
            x = x[:-1]
        if len(x) > 4:
            try:
                tree = ET.parse(xmldir + x)
                root = tree.getroot()
                parse()
            except:
                print 'Failed to parse: ' + xmldir + x


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

    global proto, root, parseos

    protocol = ''
    port = ''
    servicename = ''
    productname = ''
    ipaddress = ''
    addresses = []
    osobj = ''
    osmatch = ''
    tempos = ''


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
 
        try:
            osobj = host.find('os')
            osmatch = osobj.find('osmatch')
            tempos = osmatch.get('name')
            tempos = ' '.join(tempos.split(','))
            if len(tempos) > 45:
                tempos = tempos[0:45]
            ostype = ''
            osvendor = ''
            osfamily = ''
            
            if tempos in parseos:
                if ipaddress in parseos[tempos]['ipaddress'] == False:
                    parseos[tempos]['ipaddress'].append(ipaddress)
            else:
                parseos[tempos] = {}
                parseos[tempos]['type'] = ''
                parseos[tempos]['vendor'] = ''
                parseos[tempos]['osfamily'] = ''
                parseos[tempos]['ipaddress'] = []
                parseos[tempos]['ipaddress'].append(ipaddress)
                
            for x in osmatch.findall('osclass'):
                ostype = x.get('type')
                osvendor = x.get('vendor')
                osfamily = x.get('osfamily')
                
                if len(parseos[tempos]['type']) == 0:
                    parseos[tempos]['type'] = ostype
                elif ostype in parseos[tempos]['type']:
                    pass
                else:
                    parseos[tempos]['type'] = parseos[tempos]['type'] + ' or ' + ostype
                    
                if len(parseos[tempos]['vendor']) == 0:
                    parseos[tempos]['vendor'] = osvendor
                elif osvendor in parseos[tempos]['vendor']:
                    pass
                else:
                    parseos[tempos]['vendor'] = parseos[tempos]['vendor'] + ' or ' + osvendor
                    
                if len(parseos[tempos]['osfamily']) == 0:
                    parseos[tempos]['osfamily'] = osfamily
                elif osfamily in parseos[tempos]['osfamily']:
                    pass
                else:
                    parseos[tempos]['osfamily'] = parseos[tempos]['osfamily'] + ' or ' + osfamily
                    
        except:
            pass

           

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
    global proto, xmldir, parseos, repfile

    report = ""
    writefile1 = open('IP-' + repfile + '.csv', 'w')
    writefile2 = open('TCP-' + repfile + '.csv', 'w')
    writefile3 = open('UDP-' + repfile + '.csv', 'w')
    writefile4 = open('OS-' + repfile + '.csv', 'w')

    writefile1.write('IP,Port#,Service Name,Product Name,IP List\n')
    writefile2.write('TCP,Port#,Service Name,Product Name,IP List\n')
    writefile3.write('UDP,Port#,Service Name,Product Name,IP List\n')
    writefile4.write('OSName,type,vendor,family,IP List\n')
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
    for tempos in sorted(parseos):
        addresses = ','.join(parseos[tempos]['ipaddress'])
        report = tempos + ',' + parseos[tempos]['type'] + ',' + parseos[tempos]['vendor'] + ',' + parseos[tempos]['osfamily'] + ',' + addresses + '\n'
        writefile4.write(report) 
    writefile1.close()
    writefile2.close()
    writefile3.close()
    writefile4.close() 


       
"""
Begin main program
"""

evalargs()
loop_files()
remove_duplicates()
report()

#print root
#print "NMAP: " + root.get('args')
#for host in root.findall('host'):
#    for addr in host.findall('address'):
       #addr = host.find('address').get('addr')
#        print "Host: " + str(addr.get('addr'))
