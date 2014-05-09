vzp_nmap
========

quick nmap xml parser to supplement db_nmap services -s/-p &lt;name/number>.  

What does this mean?  Well, I love the way metasploit lets me look at some data, but sometimes I want a full report, by port number of what services and products are listening with all the IP addresses it found that match them.

So, I wrote this nmap xml parser to do that.  it isn't done, but will print to the screen right now in the format:
<protocol>,<port#>,<service>,<product>,<iplist command separated>

example:
tcp,21,ftp,Brother/HP printer ftpd,172.16.0.50
tcp,22,ssh,None,172.16.0.51,172.16.0.52
tcp,22,ssh,OpenSSH,172.16.0.53,172.16.0.54,172.16.0.55,172.16.0.56,172.16.0.57,172.16.0.58
tcp,23,telnet,Brother/HP printer telnetd,172.16.0.50
