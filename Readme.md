==================================
	PORT SCANNER README
==================================

By Jameson Ricks

Usage: scanner.py [options]

Hostnames can be specified by putting domain names or IP addresses
separated by commas with no spaces (i.e., google.com,192.168.1.1,10.0.1.1).

Ports can be specified by putting numbers separated by commas, or port
ranges separated by commas (i.e., 1-100,443,8080).

Results can be saved by using the -w flag and specifying a filename. The
file will be saved in the present working directory in the current shell.

Arguments:
------------
-h <hostname(s)>
-host <hostname(s)>
-hosts <hostname(s)>
-p <port(s)>
-port <port(s)>
-ports <port(s)>
-w <output html filename>

--help -- Prints the help description.

Example: scanner.py -hosts 10.0.1.1, 192.168.0.100 -p 22,80,443,500-100 -w results.html

A traceroute can also be performed with -t, --traceroute, or --tracert and specifying
a hostname or IP address. 

Example: scanner.py --traceroute google.com
