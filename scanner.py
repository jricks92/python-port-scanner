#!/usr/bin/env python
from socket import *
from logging import getLogger, ERROR
getLogger("scapy.runtime").setLevel(ERROR)
from scapy.all import *
import sys, getopt, time, subprocess
from datetime import datetime

## Adapted from a tutorial located at http://null-byte.wonderhowto.com/how-to/build-stealth-port-scanner-with-scapy-and-python-0164779/ and this one http://null-byte.wonderhowto.com/how-to/sploit-make-python-port-scanner-0161074/
## traceroute stuff taken from https://blogs.oracle.com/ksplice/entry/learning_by_doing_writing_your
## CLI info taken from http://www.tutorialspoint.com/python/python_command_line_arguments.htm
## By Jameson Ricks


## Global Variabls
max_port = 65535
min_port = 1
# file_path = ""

# Clear screen
#subprocess.call('clear', shell=True)

def main(argv):
    print "\n[*] Python Port Scanner, by Jameson Ricks"

    # User specified sports
    user_ports = []

    # Ports to scan
    ports = []

    #Results
    host_results = {}

    # Hosts variable
    hosts = ['']

    wo_file = False

    try:
        opts, args = getopt.getopt(argv,"w:h:p:t",["help=","host=","host=","port=","ports=","traceroute=","tracert="])
    except getopt.GetoptError:
        help()
    for opt, arg in opts:
        if opt in ("--help"):
            help()
        elif opt in ("-w"):
            # Write html file
            wo_file = True
            file_path = arg
            print("Argument:" + arg)

            print("file path: %s" % file_path)

        elif opt in ("-h", "--host", "--hosts"):
            # Split comma separated hosts
            hosts = [x.strip() for x in arg.split(',')]
        elif opt in ("-p", "--port", "--ports"):
            # Split comma separated ports
            user_ports = [x.strip() for x in arg.split(',')]
    	elif opt in ("--traceroute", "-t", "--tracert"):
    	    traceroute(arg)
    	    #Exit so we don't get further into the program
    	    sys.exit(1)

    #Port ranges
    for p in user_ports:
        if "-" in p:
            port_ends = p.split("-")

            for i in range(int(port_ends[0]), int(port_ends[1]) + 1):
                ports.append(i)
                ##print "Found dash"
        else:
            # make sure to cast as int
            ports.append(int(p))

    #Sort ports array
    ports = sorted(ports)

    print '\nItems to Scan:'
    print '=================='
    print 'Host(s): ', hosts
    print 'Port(s): ', user_ports

#    print 'Port(s): ', ports

    t1 = datetime.now()

    print('\n[*] Port Scan Started at %s' % t1.strftime('%X'))

    ## Start Scans of host

    for host in hosts:

        results = {}

        #Resolve Host
        ip_addr = gethostbyname(host)

        ##print("\nScanning Host: %s" % host)
        host_up = checkhost(host)

        if host_up:

            for port in ports:
                # Check to make sure our port is within bounds
                if port <= max_port:

                    if port >= min_port:
                        # print("Scanning port %d" % port)
                        try:
                            response = scan_host(ip_addr,port)

                            if response == 0:
                                print("[*} Port %d: Open" % port)
                                results[port] = "Open"
                        except Exception, e:
                            print("Port %d: Closed" % port)
                            results[port] = "Closed"
                    else:
                        print "\n[!] Invalid Range of Ports!"
                        print "[!] Exiting..."
                        sys.exit(1)
                else:
                    print "\n[!] Invalid Range of Ports!"
                    print "[!] Exiting..."
                    sys.exit(1)

            # Save results to dictionary
            host_results[host] = results


    t2 = datetime.now()

    duration = t2-t1

    print("\n[*] Scan Finished at %s. Scan took %s." % (t2.strftime('%X'), duration))

    if wo_file:
        write_html(host_results, file_path, t1, t2)


## Scan Host with ports
def scan_host(host,port,r_code = 1):

    try:
        #print('Creating Socket')
        s = socket.socket(AF_INET,SOCK_STREAM)
        #print('Executing...')
        code = s.connect_ex((host,port))

        #print('Success.')
        ## If we get a 0, the port is open
        if code == 0:
           #print('Found Open Port')
           r_code = code
        s.close()
    except Exception, e:
        pass
        #print('Port not open')

    return r_code


## Ping target
def checkhost(ip):
    check_host = gethostbyname(ip)
    conf.verb = 0
    print ("\n[*] Pinging target...")
    response = os.system("ping -c 1 " + ip + " > /dev/null 2>&1")
    if response == 0:
        ##Commented out since I can't get scapy to work
	##ping = sr1(IP(dst = ip)/ICMP())
        if ip == check_host:
            print ("[*] %s is Up, Beginning Scan..." % ip)
        else:
            print ("[*] %s (%s) is Up, Beginning Scan..." % (ip,check_host))
        return True
    else:
        print "\n[!] Couldn't Resolve Target"
        print ("[!] Skipping %s" % ip)
        return False

## Traceroute
def traceroute(hostname):
    print "\n[!] Running traceroute!"
    print "Press Ctrl-C to cancel when no more hops are being made!\n"
    dst = gethostbyname(hostname)
    port = 33434
    max_hops = 30
    icmp = getprotobyname('icmp')
    udp = getprotobyname('udp')
    ttl = 1
    while True:
        # Keyboard interrupt
        try:
            rx = socket.socket(AF_INET, SOCK_RAW, icmp)
            tx = socket.socket(AF_INET, SOCK_DGRAM, udp)
            tx.setsockopt(SOL_IP, IP_TTL, ttl)
            rx.bind(("", port))
            tx.sendto("", (hostname, port))
            cur_addr = None
            cur_name = None
            try:
                _, cur_addr = rx.recvfrom(512)
                cur_addr = cur_addr[0]
                try:
                    cur_name = gethostbyaddr(cur_addr)[0]
                except error:
                    cur_name = cur_addr
            except error:
                pass
            finally:
                tx.close()
                rx.close()

            if cur_addr is not None:
                cur_host = "%s (%s)" % (cur_name, cur_addr)
            else:
                cur_host = "*"
            print "%d\t%s" % (ttl, cur_host)

            ttl += 1
            if cur_addr == dst or ttl > max_hops:
                break
        except KeyboardInterrupt:
            print "\n[*] User Requested Shutdown...\n"
            sys.exit(1)

## Prints the help
def help():
    print "=================================="
    print "\tPORT SCANNER README"
    print "=================================="
    print '\nUsage: scanner.py [options]'
    print '\nHostnames can be specified by putting domain names or IP addresses'
    print 'separated by commas with no spaces (i.e., google.com,192.168.1.1,10.0.1.1).\n'
    print 'Ports can be specified by putting numbers separated by commas, or port'
    print 'ranges separated by commas (i.e., 1-100,443,8080).\n'
    print 'Results can be saved by using the -w flag and specifying a filename. The'
    print 'file will be saved in the present working directory in the current shell.'
    print '\nArguments:'
    print '------------'
    print '''-h <hostname(s)>
-host <hostname(s)>
-hosts <hostname(s)>
-p <port(s)>
-port <port(s)>
-ports <port(s)>
-w <output html filename>'''
    print '\n--help -- Prints the help description.'
    print "\nExample: scanner.py -hosts 10.0.1.1, 192.168.0.100 -p 22,80,443,500-100 -w results.html"
    print "\nA traceroute can also be performed with -t, --traceroute, or --tracert and specifying"
    print "a hostname or IP address. \n\nExample: scanner.py --traceroute google.com\n"
    sys.exit(2)

def write_html(results, file_path, t1, t2):
    print ('\nWriting results to %s.' % file_path)

    if len(results) > 0:

        html = "<h1>Scan Results</h1>"
        html += "<p><i>Date: %s</i></p>" % t1.strftime("%b %d, %Y at %H:%M:%S")
        for host in results.keys():
            html += "<h3>%s</h3>" % host
            html += "<h5>Open Ports:</h5>"
            for port in results[host]:
                html += "Port %s: <span style='color:green;'>Open</span></p>" % port

            #Add break tag to space out hosts
            html += "<br>"

            ## Get scan duration
            duration = t2-t1

            html += "Scan took %s to complete." % duration

        # Write to file
        text_file = open(file_path, "w")
        text_file.write(html)
        text_file.close()

    else:
        print "\n[!] No Results to save!"

if __name__ == "__main__":
    main(sys.argv[1:])
