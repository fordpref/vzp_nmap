"""
Generic nmap assessment program, outputs to all formats, parses the xml to create port reports in csv format.
"""

import os, sys, platform, time
if platform.system() == 'Windows':
    import msvcrt
import xml.etree.ElementTree as ET
from datetime import datetime
from subprocess import *


opsys = platform.system()
nmapdir = ''
custname = ''
assessname = ''
tree = {}
root = []
proto = {}
opsys = platform.system()
parseos = {}
args = sys.argv



def clear():
    global opsys
    if opsys == 'Windows':
        os.system('cls')
    elif opsys == 'Linux':
        os.system('clear')
    else:
        print 'OS not Windows or Linux, exiting...'
        exit   

def date_stamp():
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

def createdirs():
    """
    check directories and make them if not there
    """

    global opsys, nmapdir, assessname
    if opsys == 'Windows':
        nmapdir = 'c:\\assessment\\' + assessname+ '\\nmap\\'
        if os.path.exists('c:\\assessment\\') == False:
            os.mkdir('c:\\assessment\\')
        if os.path.exists('c:\\assessment\\' + assessname) == False:
            os.mkdir('c:\\assessment\\' + assessname)
        if os.path.exists('c:\\assessment\\' + assessname + '\\agents\\') == False:
            os.mkdir('c:\\assessment\\' + assessname + '\\agents\\')
        if os.path.exists('c:\\assessment\\' + assessname + '\\collection\\') == False:
            os.mkdir('c:\\assessment\\' + assessname + '\\collection')
        if os.path.exists('c:\\assessment\\' + assessname + '\\canvas\\') == False:
            os.mkdir('c:\\assessment\\' + assessname + '\\canvas')
        if os.path.exists('c:\\assessment\\' + assessname + '\\nmap\\') == False:
            os.mkdir('c:\\assessment\\' + assessname + '\\nmap\\')
        if os.path.exists('c:\\assessment\\' + assessname + '\\nessus\\') == False:
            os.mkdir('c:\\assessment\\' + assessname + '\\nessus\\')
        if os.path.exists('c:\\assessment\\' + assessname + '\\retina\\') == False:
            os.mkdir('c:\\assessment\\' + assessname + '\\retina\\')
        custfile = open('c:\\assessment\\custname.txt', 'w')
        custfile.write(assessname)
        custfile.close()
    elif opsys == 'Linux':
        nmapdir = '/opt/assessment/' + assessname + '/nmap/'
        if os.path.exists('/opt/assessment/') == False:
            os.mkdir('/opt/assessment/')
        if os.path.exists('/opt/assessment/' + assessname + '/') == False:
            os.mkdir('/opt/assessment/' + assessname + '/')
        if os.path.exists('/opt/assessment/' + assessname + '/agents') == False:
            os.mkdir('/opt/assessment/' + assessname + '/agents')
        if os.path.exists('/opt/assessment/' + assessname + '/collection') == False:
            os.mkdir('/opt/assessment/' + assessname + '/collection')
        if os.path.exists('/opt/assessment/' + assessname + '/canvas') == False:
            os.mkdir('/opt/assessment/' + assessname + '/canvas')
        if os.path.exists('/opt/assessment/' + assessname + '/nessus') == False:
            os.mkdir('/opt/assessment/' + assessname + '/nessus')
        if os.path.exists('/opt/assessment/' + assessname + '/nmap') == False:
            os.mkdir('/opt/assessment/' + assessname + '/nmap')
        if os.path.exists('/opt/assessment/' + assessname + '/retina') == False:
            os.mkdir('/opt/assessment/' + assessname + '/retina')
        custfile = open('/opt/assessment/custname.txt', 'w')
        custfile.write(assessname)
        custfile.close()


def dnsservers():
    global opsys
    dns = []
    lines = []
    x = ''

    if opsys == 'Windows':
        lines = Popen('ipconfig /all', stdout=PIPE, stderr=PIPE)
        lines = lines.communicate()[0].split('\n')
        for line in lines:
            if line.startswith('   DNS Servers'):
                x = line.split(': ')
                x = x[1]
                if 'a' in x or 'b' in x or 'c' in x or 'd' in x or 'e' in x or 'f' in x or '::' in x or '%' in x:
                    next
                dns.append(x[:-1])
                print x
    else:
        lines = open('/etc/resolv.conf', 'r')
        for line in lines:
            if line.startswith('nameserver'):
                x = line.split(' ')
                x = x[1]
                dns.append(x[:-1])

    return(dns)

def masterreport():
    global opsys, nmapdir, tree, root, assessname
    f = {}
    x = ''
    files = []
    tfiles = []

    if opsys == 'Windows':
        f = Popen('dir /b "' + nmapdir + '*.xml"', shell=True, stdout=PIPE)
        tfiles = f.communicate()[0].split('\n')
    else:
        f = Popen('ls ' + nmapdir + ' |grep \.xml', shell=True, stdout=PIPE)
        tfiles = f.communicate()[0].split('\n')

    for line in tfiles:
        if 'TCP' in line:
            files.append(nmapdir + line)
        elif 'UDP' in line:
            files.append(nmapdir + line)
        elif 'IPPROTO' in line:
            files.append(nmapdir + line)
    assessname = assessname + '-MASTER'
    portreportprep(files)
    report(files)

        
def usage():
    print '\n\n\nassessment scan useage:'
    print '\n\nassessmentscan [-c <customer name>] [-d [discovery ports][-t <top tcp ports>] [-u <top udp ports>] [-i][-R] -IP <IP addresses>'
    print 'input the IP addresses last, for everyone\'s sanity please\n'
    print '-c <customer name>               Customer Name to be used in file names'
    print '-d <ports to do discovery>       discovery scans (ping and syn discovery on specified ports)'
    print '                                 if no ports specified uses 21,22,23,25,53,80,111,135,139,389,443,445'
    print '-t <top tcp ports>               tcp syn scan with # of top ports, max = 65535'
    print '-u <top udp ports>               udp scan with # of top ports max = 65535'
    print '-i (ipproto scan)                IPPROTO scan won\'t take top ports, it will scan all 256'
    print '-R                               Master reports, scans all xml in the dir and gives overall reports, ignores other arguments'
    print '-IP <IP Addresses>               IP addresses/space you want to scan in nmap acceptable format'
    print '\n\nExamples:'
    print '\nNo arguments results in a questionnaire walk through\n'
    print 'This will create a testcustomer dir under [/opt/][c:\]assessment, discovery ping scan syn scan with'
    print 'defalt ports, a tcp syn scan with top 10000 ports, a udp scan with top 3 ports.'
    print 'assessmentscan -c testcustomer -d -t 10000 -u 3 -IP 172.19.3.1-10 172.19.4.0/24'
    print '\nThis assumes a customer dir already, does just a tcp syn scan on top ports'
    print 'assessmentscan -t 100 -IP 192.168.33-65'
    print '\nNot doing a discovery scan will result in scans being performed without pings, assumes all hosts up'
    print 'and may take a long time.'
    exit()


def parseargs():
    """
    take command line arguments for rescanning or custom scans
    """
    global custname, assessname, args, ipaddresses, nmapdir

    # local variables and flags
    files = []
    c = 0
    d = 0
    t = 0
    u = 0
    i = 0
    ip = 0
    R = 0
    
    if len(args) == 1:
        walkthrough()
    else:
        x = 1
        y = 1
        while x < len(args):
            if '--help' in args:
                usage()
            elif '-IP' in args == False and '-R' in args == False:
                print 'No IP addresses...please add IP addresses.'
                usage()
            elif args[x].startswith('-R'):
                R = 1
                x += 1
            elif args[x].startswith('-c') and c == 0:
                custname = args[x + 1]
                assessname = custname
                c = 1
                x += 2
                if opsys == 'Windows':
                    if os.path.exists('c:\\assessment\\' + assessname):
                        nmapdir = 'c:\\assessment\\' + assessname + '\\nmap\\'
                    else:
                        createdirs()
                if opsys == 'Linux':
                    if os.path.exists('/opt/assessment/' + assessname):
                        nmapdir = '/opt/assessment/' + custname + '/nmap/'
                    else:
                        createdirs()
            elif args[x].startswith('-d') and d == 0:
                d = 1
                sdports = args[x + 1]
                if sdports.startswith('-'):
                    sdports = '21,22,23,25,80,111,135,139,389,443,445'
                    x += 1
                else:
                    x += 2
                
            elif args[x].startswith('-t') and t == 0:
                t = 1
                tports = args[x + 1]
                if tports.startswith('-'):
                    tports = 10000
                    x += 1
                else:
                    tports = int(tports)
                    x += 2
                if tports > 65535:
                    print 'something went wrong with tcp command line'
                    usage()
            elif args[x].startswith('-u') and u == 0:
                u = 1
                uports = args[x + 1]
                if uports.startswith('-'):
                    uports = 3
                    x += 1
                else:
                    uports = int(uports)
                    x += 2
                if uports > 65535:
                    print 'something went wrong with udp command line'
                    usage()
                
            elif args[x] == ('-i') and i == 0:
                i = 1
                x += 1
            elif args[x] == ('-IP') and ip == 0:
                ipaddresses = args[x + 1]
                x += 2
                ip = 1
                if x < len(args):
                    while x < len(args):
                        ipaddresses += ' ' + args[x]
                        x += 1
            elif y > len(args):
                print "\nCommand line parameters did not parse correctly.\n"
                print "Try again.\n\n"
                usage()
            y += 1

        if c == 0:
            if opsys == 'Windows':
                if os.path.exists('c:\\assessment\\custname.txt'):
                    custfile = open('c:\\assessment\\custname.txt', 'r')
                    for line in custfile:
                        custname = line
                    assessname = custname
                    nmapdir = 'c:\\assessment\\' + custname + '\\nmap\\'
                else:
                    print '\n\nYou must specify a customer name (-c) to use command line switches\n'
                    print 'Or do a walkthrough first.'
                    usage()
            else:
                if os.path.exists('/opt/assessment/custname.txt'):
                    custfile = open('/opt/assessment/custname.txt', 'r')
                    for line in custfile:
                        custname = line
                    assessname = custname
                    nmapdir = '/opt/assessment/' + custname + '/nmap/'
                else:
                    print '\n\nYou must specify a customer name (-c) to use command line switches\n'
                    print 'Or do a walkthrough first.'
                    usage()
        if R == 1:
            masterreport()
            exit()
        if d == 1:
            pingfile = pingdiscovery(ipaddresses)
            synfile = syndiscovery(sdports,ipaddresses)
            ipaddresses = ' '.join((hostlist(pingfile, synfile)))
            hostnames(ipaddresses)
        if t == 1:
            tcpfile = tcpscans(tports,ipaddresses)
            files.append(tcpfile)
        if u == 1:
            udpfile = udpscans(uports,ipaddresses)
            files.append(udpfile)
        if i == 1:
            ipprotofile = ipproto(ipaddresses)
            files.append(ipprotofile)
        
        portreportprep(files)
        report(files)


def walkthrough():
    """
    print at startup
    """
    global custname,assessname
    files = []
    
    clear()
    print '\n\nWalkthrough selected, no arguments'
    print '\n\nAssessment startup, discovery, hostlist creation, and initial scans tool\n\n'
    print 'Host lists, scan outputs, and reports are in: \n\n'
    print 'windows - c:\\assessment\\<assessment name>\\nmap\\'
    print 'linux - /opt/assessment/<assessment name>/nmap/'
    print '\n\n\n'
    print 'To get started we need a name for the customer.'
    print 'Make it easy on yourself later and don\'t use spaces, make it descriptive.'
    print 'We\'ll save the name in the customname.txt file if you need to run more scans later.'

    custname = raw_input('Customer Name:  ')
    assessname = custname
    createdirs()
    x = 0
    while x == 0:
        tports = raw_input('\n\nHow many top TCP ports do you want to scan, max=65535 [10000]: ')
        if tports == '':
            tports = 10000
        try:
            tports = int(tports)
            if tports > 65535:
                usage()
            x = 1
        except:
            print '\nYou must supply an integer or hit enter to accept default of 10000'
            pass

    x = 0
    while x == 0:
        uports = raw_input('\nHow many top UDP ports do you want to scan, max=65535 [3]: ')
        if uports == '':
            uports = 3
        try:
            uports = int(uports)
            if uports > 65535:
                usage()
            x = 1
        except:
            print 'You must use an integer, or hit enter to accept default of 3'
            pass
    createdirs()
    print '\nWhat IP addresses do you want to scan?  Use nmap formatting.'
    print 'Individual IPs separated by spaces: 172.16.0.5 192.168.3.2 10.4.2.7'
    print 'Ranges:  172.16.10.16-32 192.168.2.55-67'
    print 'CIDR: 172.16.0.0/19 192.168.6.0/24 10.4.3.240/27'
    ipaddresses = raw_input('IPs: ')
    pingfile = pingdiscovery(ipaddresses)
    sports = '21,22,23,25,53,80,111,135,139,389,443,445'
    synfile = syndiscovery(sports,ipaddresses)
    ipaddresses = ' '.join((hostlist(pingfile,synfile)))
    hostnames(ipaddresses)
    tcpfile = tcpscans(tports,ipaddresses)
    files.append(tcpfile)
    udpfile = udpscans(uports,ipaddresses)
    files.append(udpfile)
    portreportprep(files)
    report(files)

    
def pingdiscovery(ipaddresses):
    global nmapdir, assesname
    date = date_stamp()
    pingdiscfile = nmapdir + date + '-' + assessname + '-PingScan'
    nmap = 'nmap -sn -n --open -oA ' + pingdiscfile + ' ' + ipaddresses

    clear()
    print 'Performing ping discovery scan on: ' + ipaddresses
    print nmap
    call(nmap, shell=True)
    
    return(pingdiscfile + '.gnmap')

def syndiscovery(sports,ipaddresses):
    global nmapdir, assessname, clear
    date = date_stamp()
    syndiscfile = nmapdir + date + '-' + assessname + '-SynScan'
    nmap = 'nmap --open -n -PS' + sports + ' -p' + sports + ' -oA ' + syndiscfile + ' ' + ipaddresses

    clear()
    print 'performing syn discovery scan on ' + ipaddresses
    print nmap
    call(nmap, shell=True)
    
    return(syndiscfile + '.gnmap')

def hostlist(pingdiscfile,syndiscfile):
    global nmapdir, assessname, clear
    date = date_stamp()
    hostfile = nmapdir + 'hostlist-' + assessname + '-' + date + '.txt'
    hosts = []
    p = open(pingdiscfile, 'r')
    s = open(syndiscfile, 'r')
    h = open(hostfile, 'w')

    clear()
    print 'Creating hostlist from Ping and Syn scan: '
    for line in p:
        if line.startswith('Host: '):
            args = line.split(' ')
            hosts.append(args[1])

    for line in s:
        if line.startswith('Host: '):
            args = line.split(' ')
            if args[1] in hosts == False:
                hosts.append(args[1])

    for line in sorted(hosts):
        h.write(line + '\n')

    p.close()
    s.close()
    h.close()
    hosts = sorted(hosts)
    return(hosts)

def hostnames(ipaddresses):
    """
    This will use the nameserver specified to perform reverse lookup on the hostlist.txt
    """
    global nmapdir, assessname
    nameserver = ''
    rawdata = ''
    date = date_stamp()
    nmapfile = nmapdir + date + '-' + assessname + '-hostnames'
    namefile = nmapdir + 'hostnames-' + assessname + '-' + date + '.txt'
    hfile = open(namefile, 'w')

    clear()
    s = dnsservers()
    print 'Performing reverse lookups on IP hostlist we just collected.\n'
    if (s[0] == '') == False:
        dns = raw_input('Enter IP of DNS Server or Press Enter to accept system DNS [' + s[0] + ']: ')
    else:
        dns = raw_input('Enter IP of DNS Server: ')

    if (dns == '') == False:
        pass
    elif (s[0] == '') == False:
        dns = s[0]
    else:
        return
    nmap = 'nmap -sL --dns-servers ' + dns + ' -oA ' + nmapfile + ' ' + ipaddresses
    rawdata = Popen(nmap, stdout=PIPE, stderr=PIPE, shell = True)
    rawdata = rawdata.communicate()[0].split('\n')
    for line in rawdata:
        if line.startswith('Nmap scan report'):
            line = line.split(' ')
            if opsys == 'Windows':
                if len(line) > 5:
                    ip = line[5]
                    ip = ip[1:-2]
                    hfile.write(line[4] + '\t' + ip + '\n')
            else:                
                if len(line) > 5:
                    ip = line[5]
                    ip = ip[1:-1]
                    hfile.write(line[4] + '\t' + ip + '\n')

    hfile.close()


def tcpscans(tports,ipaddresses):
    global assessname, nmapdir
    date = date_stamp()
    tcpfile = nmapdir + date + '-' + assessname + '-TCPSYNScan'
    nmap = 'nmap --open -v -Pn -n -sS -A --max-hostgroup 6 --host-timeout 5m --top-ports ' + str(tports) + ' -oA ' + tcpfile + ' ' + ipaddresses
    
    clear()
    print 'Performing TCP Syn scan: '
    print nmap
    call(nmap, shell=True)

    return(tcpfile + '.xml')

def udpscans(uports,ipaddresses):
    global assessname, nmapdir
    date = date_stamp()
    udpfile = nmapdir + date + '-' + assessname + '-UDPScan'
    nmap = 'nmap --open -v -Pn -n -sU -sC -sV --max-hostgroup 6 --host-timeout 5m --top-ports ' + str(uports) + ' -oA ' + udpfile + ' ' + ipaddresses

    clear()
    print 'Performing UDP Scan: '
    print nmap
    call(nmap, shell=True)

    return(udpfile + '.xml')

def ipproto(ipaddresses):
    global assessname, nmapdir
    date = date_stamp()
    ipprotofile = nmapdir + date + '-' + assessname + '-IPPROTOScan'
    nmap = 'nmap --open -v -Pn -n -sO --max-retries 10 --max-scan-delay 500ms --host-timeout 5m -oA ' + ipprotofile + ' ' + ipaddresses

    clear()
    print 'Performing IP Protocol Scan: '
    print nmap
    call(nmap, shell=True)

    return(ipprotofile + '.xml')

def portreportprep(files):
    global tree, root
    x = ''

    for x in files:
        try:
            tree = ET.parse(x)
            root = tree.getroot()
            parse()
        except:
            print 'Couldn\'t parse ' + x + 'probably interrupted or corrupted.'
    removeduplicates()

    
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

def removeduplicates():
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
   
def report(files):
    global proto, nmapdir, parseos, assessname
    report = ''
    date = date_stamp()
    tcpfile = ''
    udpfile = ''
    iprotofile = ''
    osfile = ''
    tfile = ''
    ufile = ''
    ifile = ''

    clear()
    print 'Writing report files...'
    for line in files:
        if 'TCP' in line:
            tcpfile = nmapdir + 'TCP-report-' + assessname + '-' + date + '.csv'
            tfile = open(tcpfile, 'w')
            tfile.write('TCP,Port#,Service Name,Product Name,Version,IP List\n')
            osfile = nmapdir + 'OS-report-' + assessname + '-' + date + '.csv'
            ofile = open(osfile, 'w')
            ofile.write('OSName,type,vendor,family,IP Addresses\n')
        if 'UDP' in line:
            udpfile = nmapdir + 'UDP-report-' + assessname + '-' + date + '.csv'
            ufile = open(udpfile, 'w')
            ufile.write('UDP,Port#,Service Name,Product Name,Version,IP List\n')
        if 'IPPROTO' in line:
            ipprotofile = nmapdir + 'IPPROTO-report-' + assessname + '-' + date + '.csv'
            ifile = open(ipprotofile, 'w')
            ifile.write('IP,Port#,Service Name,Product Name,Version,IP List\n')
            
    for protocol in sorted(proto):
        for port in sorted(proto[protocol]):
            for servicename in sorted(proto[protocol][port]):
                for productname in sorted(proto[protocol][port][servicename]):
                    for version in sorted(proto[protocol][port][servicename][productname]):
                        if not proto[protocol][port][servicename][productname][version]['IP']:
                            pass
                        else:
                            addresses = ",".join(proto[protocol][port][servicename][productname][version]['IP'])
                            report = protocol + ',' + str(port) + ',' + servicename + ',' + productname + ',' + str(version) + ',' + addresses + "\n"
                            if protocol == 'ip':
                                ifile.write(report)
                            elif protocol == 'tcp':
                                tfile.write(report)
                            else:
                                ufile.write(report)
 
    if (osfile == '') == False:
        for tempos in sorted(parseos):
            addresses = ','.join(parseos[tempos]['ipaddress'])
            report = tempos + ',' + parseos[tempos]['type'] + ',' + parseos[tempos]['vendor'] + ',' + parseos[tempos]['osfamily'] + ',' + addresses + '\n'
            ofile.write(report) 
    if (tfile == '') == False:
        tfile.close()
        ofile.close()
    if (ufile == '') == False:
        ufile.close()
    if (ifile == '') == False:
        ifile.close()

           
    
'''
Main program
'''


parseargs()
