"""
Parsing nmap XML
"""

import xml.etree.ElementTree as ET

tree = ET.parse('c:\\assessment\\test-parse.xml')
root = tree.getroot()
proto = {}
protocol = ''
port = ''
servicename = ''
productname = ''
ipaddress = ''
addresses = []

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
        

        if 'IP' in proto[protocol][port][servicename][productname]:
            if ipaddress in proto[protocol][port][servicename][productname]['IP'] == True:
                continue
            else:
                proto[protocol][port][servicename][productname]['IP'].append(ipaddress)
        else:
            proto[protocol][port][servicename][productname]['IP'] = []
            proto[protocol][port][servicename][productname]['IP'].append(ipaddress)
            
            

for protocol in sorted(proto):
    for port in sorted(proto[protocol]):
        for servicename in sorted(proto[protocol][port]):
            for productname in sorted(proto[protocol][port][servicename]):
                addresses = ",".join(proto[protocol][port][servicename][productname]['IP'])
                print protocol + ',' + str(port) + ',' + servicename + ',' + productname + ',' + addresses

