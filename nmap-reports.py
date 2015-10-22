"""
Program to parse nmap XML files in a directory to generate a site report by protocol
"""

"""
Import modules
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
parseos = {}


def startup():
    """
    print at startup
    """
    global clear, nmapdir

    if opsys == 'Windows':
        clear = 'cls'
        os.system(clear)
    elif opsys == 'Linux':
        clear = 'clear'
        os.system(clear)
    else:
        print 'OS not Windows or Linux, exiting...'
        exit

    nmapdir = get_check_path()

    
def get_check_path():
    global opsys
    path = ''
    path = raw_input('Enter path to nmap xml files: ')
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

    global proto, root, parseos, hostlist

    protocol = ''
    port = ''
    servicename = ''
    productname = ''
    version = ''
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
        if (ipaddress in hostlist) == False:
            hostlist.append(ipaddress)
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


                    if service.get('version') == None:
                        version = 'None'
                    else:
                        version = service.get('version')
                    if version in proto[protocol][port][servicename][productname]:
                        pass
                    else:
                        proto[protocol][port][servicename][productname][version] = {}
                else:
                    servicename = 'None'
                    productname = 'None'
                    version = 'None'
                    if servicename in proto[protocol][port]:
                       pass
                    else:
                       proto[protocol][port][servicename] = {}

                    if productname in proto[protocol][port][servicename]:
                       pass
                    else:
                       proto[protocol][port][servicename][productname] = {}

                    if version in proto[protocol][port][servicename][productname]:
                       pass
                    else:
                       proto[protocol][port][servicename][productname][version] = {}

                if 'IP' in proto[protocol][port][servicename][productname][version]:
                    if ipaddress in proto[protocol][port][servicename][productname][version]['IP']:
                        pass
                    else:
                        proto[protocol][port][servicename][productname][version]['IP'].append(ipaddress)
                else:
                    proto[protocol][port][servicename][productname][version]['IP'] = []
                    proto[protocol][port][servicename][productname][version]['IP'].append(ipaddress)


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
                if ipaddress in parseos[tempos]['ipaddress']:
                    pass
                else:
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
    version = ''
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
                    for version in proto[protocol][port][servicename][productname]:
                        if servicename != 'None' and productname != 'None' and version != 'None':
                            sp[port].extend(proto[protocol][port][servicename][productname][version]['IP'])
                        elif servicename !='None' and productname == 'None':
                            s[port].extend(proto[protocol][port][servicename][productname][version]['IP'])
                        elif servicename == 'None' and productname != 'None':
                            p[port].extend(proto[protocol][port][servicename][productname][version]['IP'])

       

    for protocol in sorted(proto):
        for port in sorted(proto[protocol]):
            for servicename in proto[protocol][port]:
                for productname in proto[protocol][port][servicename]:
                    for version in proto[protocol][port][servicename][productname]:
                        if servicename == 'None' and productname == 'None' and version == 'None':
                            for ip in proto[protocol][port][servicename][productname][version]['IP']:
                                if ip in sp[port]:
                                    removeip.append(ip)
                                if ip in s[port]:
                                    removeip.append(ip)
                                if ip in p[port]:
                                    removeip.append(ip)
                            for ip in removeip:
                                proto[protocol][port][servicename][productname][version]['IP'].remove(ip)
                            removeip = []
                        if servicename != 'None' and productname == 'None' and version == 'None':
                            for ip in proto[protocol][port][servicename][productname][version]['IP']:
                                if ip in sp[port]:
                                    removeip.append(ip)
                            for ip in removeip:
                                proto[protocol][port][servicename][productname][version]['IP'].remove(ip)
                            removeip = []
                        if servicename == 'None' and productname != 'None' and version != 'None':
                            for ip in proto[protocol][port][servicename][productname][version]['IP']:
                                if ip in sp[port]:
                                    removeip.append(ip)
                            for ip in removeip:
                                proto[protocol][port][servicename][productname][version]['IP'].remove(ip)
                            removeip = []
   
def report():
    global proto, nmapdir, parseos, hostlist
 
    report = ''
    hostreport = {}
    hostosreport = {}
    date = date_time_stamp()
    repfile1 = nmapdir + 'nmap-IPPROTO-port-report-' + date + '.csv'
    repfile2 = nmapdir + 'nmap-TCP-port-report-' + date + '.csv'
    repfile3 = nmapdir + 'nmap-UDP-port-report-' + date + '.csv'
    repfile4 = nmapdir + 'os-report-' + date + '.csv'
    repfile5 = nmapdir + 'nmap-hostport-report-' + date + '.csv'
    writefile1 = open(repfile1, 'w')
    writefile2 = open(repfile2, 'w')
    writefile3 = open(repfile3, 'w')
    writefile4 = open(repfile4, 'w')
    writefile5 = open(repfile5, 'w')
 
    writefile1.write('IP,Port#,Service Name,Product Name,Version,IP List\n')
    writefile2.write('TCP,Port#,Service Name,Product Name,Version,IP List\n')
    writefile3.write('UDP,Port#,Service Name,Product Name,Version,IP List\n')
    writefile4.write('OSName,type,vendor,family,IP Addresses\n')
    for protocol in sorted(proto):
        for port in sorted(proto[protocol]):
            for servicename in sorted(proto[protocol][port]):
                for productname in sorted(proto[protocol][port][servicename]):
                    for version in sorted(proto[protocol][port][servicename][productname]):
                        if not proto[protocol][port][servicename][productname][version]['IP']:
                            pass
                        else:
                            for ip in proto[protocol][port][servicename][productname][version]['IP']:
                                if (ip in hostreport) == False:
                                    hostreport[ip] = []
                                    line = protocol + ',' + str(port) + ',' + servicename + ',' + productname + ',' + str(version) + '\n'
                                    hostreport[ip].append(line)
                                else:
                                    line = protocol + ',' + str(port) + ',' + servicename + ',' + productname + ',' + str(version) + '\n'
                                    hostreport[ip].append(line)
                            addresses = ",".join(proto[protocol][port][servicename][productname][version]['IP'])
                            report = protocol + ',' + str(port) + ',' + servicename + ',' + productname + ',' + str(version) + ',' + addresses + "\n"
                            #print report
                            if protocol == 'ip':
                                writefile1.write(report)
                            elif protocol == 'tcp':
                                writefile2.write(report)
                            else:
                                writefile3.write(report)
 
    for tempos in sorted(parseos):
        for ip in parseos[tempos]['ipaddress']:
            if (ip in hostosreport) == False:
                hostosreport[ip] = ''
                line = tempos + ',' + parseos[tempos]['type'] + ',' + parseos[tempos]['vendor'] + ',' + parseos[tempos]['osfamily'] + '\n'
                hostosreport[ip] = line            
        addresses = ','.join(parseos[tempos]['ipaddress'])
        report = tempos + ',' + parseos[tempos]['type'] + ',' + parseos[tempos]['vendor'] + ',' + parseos[tempos]['osfamily'] + ',' + addresses + '\n'
        writefile4.write(report) 
    writefile1.close()
    writefile2.close()
    writefile3.close()
    writefile4.close()
    for ip in hostlist:
        if (ip in hostreport) or (ip in hostosreport):
            writefile5.write('IP address,OS Name,OS Type,OS Vendor,OS Family\n')
            if (ip in hostosreport):
                report = ip + ',' + hostosreport[ip]
            else:
                report = ip + ',none,none,none,none\n'
            writefile5.write(report)
            writefile5.write('\n')
            writefile5.write(' ,proto,port,Service Name,Product Name,Version\n')
            if (ip in hostreport):
                for line in hostreport[ip]:
                    writefile5.write(' ,' + line)
            else:
                pass
            writefile5.write('\n\n\n')
    writefile5.close()
        
        

       
"""
Begin main program
"""
startup()
portreportprep()
remove_duplicates()
report()



#print root
#print "NMAP: " + root.get('args')
#for host in root.findall('host'):
#    for addr in host.findall('address'):
       #addr = host.find('address').get('addr')
#        print "Host: " + str(addr.get('addr'))
