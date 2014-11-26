vzp_nmap
========

vzp_nmap is an effort to get some sanity to switches and
output when several people are working on a test together.
We were looking to have an easy way to input some parameters
and do some common scans quickly without a lot of typing errors.
We also wanted to make sure that the output was all importable
to metasploit and vulnerability scanners.

'assessmentscans' does this.  you run it straight up and it asks
you for a descriptive test name and then the ip addresses you want 
to scan separated by spaces.  It then does two discovery scans,
a ping discovery and a syn discovery.  It will create a combined
hostlist that is used to do the rest of the comprehensive scans
list SYN scan, UDP scan, IP Proto scan.  All the output is saved
with nmap's -oA output to save in all formats.  This ensures that 
all the results can be loaded into whatever you need.  Also, the 
program parses all the xml to create a port repot for IP, TCP, 
and UDP.  The port report is a csv file that lists the protocols
found in port order, the protocol name (according to nmap) and 
the product name (from sV and sC if nmap can find it), and then 
the IP addresses listening on each unique grouping.  This becomes
a great list to manually look through and try connections on.  Put
it in Excel or Spreadsheet of your choice and you can sort by 
the different headings as you wish.  I like to look through it while
waiting on other scans to run, and just try manual connections to
things, getting screen captures or just making notes of things to 
look deeper into later.

Usage Windows:
assessmentscans.exe
-or-
python assessmentscans.py

Usage Linux:
python assessmentscans.py

The program prompts you for the rest.


'nmap-report' parses all the xml in the directory you give it
to put together the port report csv files.  This is useful if you run
some custom nmap scans after the initial scans and you want to see
any new information in the port report file.

Usage Windows:
nmap-report.exe
-or-
python nmap-report.py

Usage Linux:
python nmap-report.py

