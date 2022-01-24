#!/usr/bin/python3
# -*- coding: utf-8 -*-

"""
    Create a DNS Proxy Server in Python3 with website blocking from config file.
    Source code coping from end answers https://stackoverflow.com/questions/64792845/create-a-dns-server-in-python3-with-website-blocking
    Change some value:
                        change reply.add_answer(". A 0.0.0.0") to reply.add_answer(*RR.fromZone("%s %s %s" %(qname,qtype,bl_address_answer)))
                        becose it is error
    Add:
                        internal_bind_IP, internal_bind_IP_port
                        Config files dns_proxy_server.cfg with sections 
                        [Default]
                        tcpEnabled = True               # TCP bind True or False
                        internal_bind_IP = 0.0.0.0      # internal bind ip address
                        internal_bind_IP_port = 53   # internal IP Port
                        externalDNS = 1.1.1.1           # external DNS server
                        externalDNSPort = 53            # External DNS server port
                        [Blacklist]
                        name ip_to_answer

                        If config file not found (not exist, or another OS sys error) use standart parameters
                        Check IP from config file. If the ip address is incorrect that assign 127.0.0.1
                        


    InterceptResolver - proxy requests to upstream server
                        (optionally intercepting)
"""

from __future__ import print_function

import binascii,copy,socket,struct,sys

from dnslib import DNSRecord,RR,QTYPE,RCODE,parse_time
from dnslib.server import DNSServer,DNSHandler,BaseResolver,DNSLogger
from dnslib.label import DNSLabel


##################################################################################################
# Custom DNSLogger class with variable verbose setting
class variableVerboseDNSLogger(DNSLogger):

    """
        The class provides a default set of logging functions for the various//
        stages of the request handled by a DNSServer instance which are
        enabled/disabled by flags in the 'log' class variable.

        To customise logging create an object which implements the DNSLogger
        interface and pass instance to DNSServer.

        The methods which the logger instance must implement are:

            log_recv          - Raw packet received
            log_send          - Raw packet sent
            log_request       - DNS Request
            log_reply         - DNS Response
            log_truncated     - Truncated
            log_error         - Decoding error
            log_data          - Dump full request/response
    """

    def __init__(self,log="",prefix=True,verbose=False,logToList=False):
        """
            Selectively enable log hooks depending on log argument
            (comma separated list of hooks to enable/disable)

            - If empty enable default log hooks
            - If entry starts with '+' (eg. +send,+recv) enable hook
            - If entry starts with '-' (eg. -data) disable hook
            - If entry doesn't start with +/- replace defaults

            Prefix argument enables/disables log prefix
        """
        log_methods = ['log_recv','log_send','log_request','log_reply','log_truncated','log_error','log_data']
        self.verbose = verbose
        self.logToList = logToList
        self.currentLog = []
        # default = ["request","reply","truncated","error"]
        default = ["error"]
        log = log.split(",") if log else []
        enabled = set([ s for s in log if s[0] not in '+-'] or default)
        [ enabled.add(l[1:]) for l in log if l.startswith('+') ]
        [ enabled.discard(l[1:]) for l in log if l.startswith('-') ]
        for l in log_methods:
            if l[4:] not in enabled:
                setattr(self,l,self.log_pass)
        self.prefix = prefix

    def log_pass(self,*args):
        pass 

    def log_prefix(self,handler):
        if self.prefix:
            return "%s [%s:%s] " % (time.strftime("%Y-%m-%d %X"),
                               handler.__class__.__name__,
                               handler.server.resolver.__class__.__name__)
        else:
            return ""

    def log_recv(self,handler,data):
        # print("Entire log_recv")
        # print("Recive packet from ip:[%s], port:[%d]" %(handler.client_address[0],handler.client_address[1]))
        log = "%sReceived: [%s:%d] (%s) <%d> : %s" % (
                    self.log_prefix(handler),
                    handler.client_address[0],
                    handler.client_address[1],
                    handler.protocol,
                    len(data),
                    binascii.hexlify(data))

        # self.verbose = True
        if self.verbose:   print(log)
        if self.logToList: self.currentLog.append(log)
        

    def log_send(self,handler,data):
        # print("Entire log_send")
        log = "%sSent: [%s:%d] (%s) <%d> : %s" % (
                    self.log_prefix(handler),
                    handler.client_address[0],
                    handler.client_address[1],
                    handler.protocol,
                    len(data),
                    binascii.hexlify(data))

        if self.verbose:   print(log)
        if self.logToList: self.currentLog.append(log)
        

    def log_request(self,handler,request):
        # print("Entire log_request")
        log = "%sRequest: [%s:%d] (%s) / '%s' (%s)" % (
                    self.log_prefix(handler),
                    handler.client_address[0],
                    handler.client_address[1],
                    handler.protocol,
                    request.q.qname,
                    QTYPE[request.q.qtype])
        if self.verbose:    print(log)
        if self.logToList:  self.currentLog.append(log)
        
        self.log_data(request)

    def log_reply(self,handler,reply):
        # print("Entire to log_reply")
        if reply.header.rcode == RCODE.NOERROR:
            log = "%sReply: [%s:%d] (%s) / '%s' (%s) / RRs: %s" % (
                    self.log_prefix(handler),
                    handler.client_address[0],
                    handler.client_address[1],
                    handler.protocol,
                    reply.q.qname,
                    QTYPE[reply.q.qtype],
                    ",".join([QTYPE[a.rtype] for a in reply.rr]))
        else:
            log = "%sReply: [%s:%d] (%s) / '%s' (%s) / %s" % (
                    self.log_prefix(handler),
                    handler.client_address[0],
                    handler.client_address[1],
                    handler.protocol,
                    reply.q.qname,
                    QTYPE[reply.q.qtype],
                    RCODE[reply.header.rcode])
        if self.verbose:   print(log)
        if self.logToList: self.currentLog.append(log)
        
        self.log_data(reply)

    def log_truncated(self,handler,reply):
        log = "%sTruncated Reply: [%s:%d] (%s) / '%s' (%s) / RRs: %s" % (
                    self.log_prefix(handler),
                    handler.client_address[0],
                    handler.client_address[1],
                    handler.protocol,
                    reply.q.qname,
                    QTYPE[reply.q.qtype],
                    ",".join([QTYPE[a.rtype] for a in reply.rr]))

        if self.verbose:   print(log)
        if self.logToList: self.currentLog.append(log)
        
        self.log_data(reply)

    def log_error(self,handler,e):
        log = "%sInvalid Request: [%s:%d] (%s) :: %s" % (
                    self.log_prefix(handler),
                    handler.client_address[0],
                    handler.client_address[1],
                    handler.protocol,
                    e)

        if self.verbose:   print(log)
        if self.logToList: self.currentLog.append(log)

    def log_data(self,dnsobj):
        print("\n",dnsobj.toZone("    "),"\n",sep="")
        self.dataLog = str("\n" + str(dnsobj.toZone("    ")) + "\n" + str(sep=""))


class InterceptResolver(BaseResolver):

    """
        Intercepting resolver
        Proxy requests to upstream server optionally intercepting requests
        matching local records
    """

    def __init__(self,address,port,ttl,intercept,skip,nxdomain,forward,all_qtypes,timeout):
        """
            address/port    - upstream server
            ttl             - default ttl for intercept records
            intercept       - list of wildcard RRs to respond to (zone format)
            skip            - list of wildcard labels to skip
            nxdomain        - list of wildcard labels to return NXDOMAIN
            forward         - list of wildcard labels to forward
            all_qtypes      - intercept all qtypes if qname matches.
            timeout         - timeout for upstream server(s)
        """
        self.address = address
        self.port = port
        self.ttl = parse_time(ttl)
        self.skip = skip
        self.nxdomain = nxdomain
        self.forward = []
        for i in forward:
            qname, _, upstream = i.partition(':')
            upstream_ip, _, upstream_port = upstream.partition(':')
            self.forward.append((qname, upstream_ip, int(upstream_port or '53')))
        self.all_qtypes = all_qtypes
        self.timeout = timeout
        self.zone = []
        for i in intercept:
            if i == '-':
                i = sys.stdin.read()
            for rr in RR.fromZone(i,ttl=self.ttl):
                self.zone.append((rr.rname,QTYPE[rr.rtype],rr))
##################################################################################################
    def get_name_from_bl_file(self,qname):
        self.qname = qname
        global blacklist_srv_cfg

        bl_status = False
        bl_answer = ''
        # Truncate qname - delete dot qname['google.com.'] -> qname['google.com]
        qname = str(qname)[:str(qname).__len__()-1]
        # Search query name in black list array with shortname
        for i in blacklist_srv_cfg:
            regex = re.compile(i)
            if i == ''.join(regex.findall(qname)): 
                bl_answer = blacklist_srv_cfg[i]
                bl_status = True
                break
        return bl_status, bl_answer
##################################################################################################
    def jls_extract_def(self):
        return print

    def resolve(self,request,handler):
        matched = False
        reply = request.reply()
        qname = request.q.qname
        qtype = QTYPE[request.q.qtype]
        ttl1 = reply.a.ttl
        # Check for NXDOMAIN
        print("QNAME label= " + str(qname) + "\n")
        
        # Send to to upstream
        upstream, upstream_port = self.address,self.port
        if not reply.rr:
            try:
                if handler.protocol == 'udp':
                    proxy_r = request.send(upstream,upstream_port,
                                    timeout=self.timeout)
                else:
                    proxy_r = request.send(upstream,upstream_port,
                                    tcp=True,timeout=self.timeout)
                reply = DNSRecord.parse(proxy_r)
                
                # Detects sites from blacklist file and query QTYPE is A or AAAA
                # if self.get_name_from_bl_file(str(qname)) and qtype in ['A','AAAA']: 
                qtype_transparent = ['CNAME','MX', 'TXT', 'NS', 'PTR', 'SOA', 'MD', 'MF', 'MB', 'MG', 'MR', 'WKS', 'HINFO', 'MINFO']
                bl_get_address = False
                bl_address_answer = ''
                bl_get_address, bl_address_answer = self.get_name_from_bl_file(str(qname))
                # if self.get_name_from_bl_file(str(qname)) and (qtype not in qtype_transparent): 
                if bl_get_address and (qtype not in qtype_transparent): 
                    # Returns generic IP address
                    print("Address from blacklist tables:",qname)
                    print("REPLY = " + str(reply))
                    reply = request.reply()
                    # qname1 = str(qname)[:str(qname).__len__()-1]
                    # Check request at IPv6 (AAAA) answer to ::1 (IPv4 is 127.0.0.1)
                    if qtype == 'AAAA': bl_address_answer = '::1'
                    reply.add_answer(*RR.fromZone("%s %d %s %s" %(str(qname),ttl1,qtype,bl_address_answer)))
                    print("REPLY = " + str(reply))
            except socket.timeout:
                reply.header.rcode = getattr(RCODE,'SERVFAIL')

        return reply
##################################################################################################
# Read config file
def read_cfg_file():
    def validip(ip): 
        return ip.count('.') == 3 and  all(0<=int(num)<256 for num in ip.rstrip().split('.'))
    global blacklist_srv_cfg
    global default_srv_cfg

    global tcpEnabled
    global internal_bind_IP
    global internal_bind_IP_port
    global externalDNS
    global externalDNSPort
    global file_cfg
    # config = configparser.ConfigParser(allow_no_value=True)
    config = configparser.ConfigParser(allow_no_value=False)
    config.sections()
    result_read_cfg = config.read(file_cfg)
    config.sections()
    try:
        if result_read_cfg != []:
            pass
        else:
            raise IOError
    except IOError: 
        print ("Could not read file:[%s]" %file_cfg)
        # When not existing cfg file we use standart options
        # init_default_setting()
    else:
            default_srv_cfg = config['Default']
            tcpEnabled = default_srv_cfg['tcpEnabled']
            internal_bind_IP = default_srv_cfg['internal_bind_IP']
            internal_bind_IP_port = int(default_srv_cfg['internal_bind_IP_port'])
            externalDNS = default_srv_cfg['externalDNS']
            externalDNSPort = int(default_srv_cfg['externalDNSPort'])
            blacklist_srv_cfg = config['Blacklist']
            
            for sites_bl in blacklist_srv_cfg: 
                # print("%s = %s" %(sites_bl,blacklist_srv_cfg[sites_bl]))
                # if validip(blacklist_srv_cfg[sites_bl]) != True: blacklist_srv_cfg[sites_bl] = '127.0.0.1'
                if blacklist_srv_cfg[sites_bl] == '' \
                    or blacklist_srv_cfg[sites_bl] == None: 
                        blacklist_srv_cfg[sites_bl] = '127.0.0.1'
                else:
                    if validip(blacklist_srv_cfg[sites_bl]) != True: 
                        blacklist_srv_cfg[sites_bl] = '127.0.0.1'
                print("%s = %s" %(sites_bl,blacklist_srv_cfg[sites_bl]))
                

##################################################################################################

if __name__ == '__main__':

    import argparse,sys,time,re
    import configparser
    from decimal import Decimal

    file_cfg = 'dns_proxy_server.cfg'

    tcpEnabled = True
    internal_bind_IP = "0.0.0.0"
    internal_bind_IP_port = 53
    externalDNS = "1.1.1.1"
    externalDNSPort = 53

    # Clear
    print(chr(27) + "[2J")

    blacklist_srv_cfg = []
    default_srv_cfg = []
    # Read config file
    read_cfg_file()

        
    # Most of these don't do anything so don't use them
    p = argparse.ArgumentParser(description="DNS Intercept Proxy, please ignore arguments and run it")
    p.add_argument("--intercept","-i",action="append",
                    metavar="<zone record>",
                    help="Intercept requests matching zone record (glob) ('-' for stdin)")
    p.add_argument("--skip","-s",action="append",
                    metavar="<label>",
                    help="Don't intercept matching label (glob)")
    p.add_argument("--nxdomain","-x",action="append",
                    metavar="<label>",
                    help="Return NXDOMAIN (glob)")
    p.add_argument("--forward","-f",action="append",
                   metavar="<label:dns server:port>",
                   help="forward requests matching label (glob) to dns server")
    p.add_argument("--ttl","-t",default="60s",
                    metavar="<ttl>",
                    help="Intercept TTL (default: 60s)")
    p.add_argument("--timeout","-o",type=float,default=5,
                    metavar="<timeout>",
                    help="Upstream timeout (default: 5s)")
    p.add_argument("--all-qtypes",action='store_true',default=False,
                   help="Return an empty response if qname matches, but qtype doesn't")
    # p.add_argument("--log",default="-request,-reply,truncated,error,-recv",
    p.add_argument("--log",default="truncated,error",
                    help="Log hooks to enable (default: +request,+reply,+truncated,+error,-recv,-send,-data)")
    p.add_argument("--log-prefix",action='store_true',default=True,
                    help="Log prefix (timestamp/handler/resolver) (default: False)")
    args = p.parse_args()

    #'args.dns,_,args.dns_port = args.upstream.partition(':')
    #args.dns_port = int(args.dns_port or 53)
    
    resolver = InterceptResolver(address = externalDNS,
                                 port = externalDNSPort,
                                 ttl = "60s",
                                 intercept = args.intercept or [],
                                 skip = args.skip or [],
                                 nxdomain = args.nxdomain or [],
                                 forward = args.forward or [],
                                 all_qtypes = args.all_qtypes,
                                 timeout = args.timeout)
    
    logger = variableVerboseDNSLogger(log = args.log,
                                      prefix = args.log_prefix,
                                      verbose = True,
                                      logToList = True)

    
    print("Starting Intercept Proxy (%s:%d -> %s:%d) [%s]" % (
                        internal_bind_IP or "*",internal_bind_IP_port,
                        externalDNS,externalDNSPort,
                        "UDP/TCP" if tcpEnabled else "UDP"))

    for rr in resolver.zone:
        print("    | ",rr[2].toZone(),sep="")
    if resolver.nxdomain:
        print("    NXDOMAIN:",", ".join(resolver.nxdomain))
    if resolver.skip:
        print("    Skipping:",", ".join(resolver.skip))
    if resolver.forward:
        print("    Forwarding:")
        for i in resolver.forward:
            print("    | ","%s:%s:%s" % i,sep="")

    DNSHandler.log = {
        #'log_recv',
        #'log_request',       # DNS Request
        #'log_reply',        # DNS Response
        #'log_truncated',    # Truncated
        #'log_error',        # Decoding error
        #'log_send',
    }

    
    udp_server = DNSServer(resolver,
                           port=internal_bind_IP_port,
                           address=internal_bind_IP,
                           logger=logger)

    udp_server.start_thread()

    if tcpEnabled:
        tcp_server = DNSServer(resolver,
                               port=internal_bind_IP_port,
                               address=internal_bind_IP,
                               tcp=True,
                               logger=logger)

        tcp_server.start_thread()

    while udp_server.isAlive():
        time.sleep(1)
        #print(DNSHandler.log)
        # print("LOG START")
        #print(logger.currentLog)
        logger.currentLog = []
        # print("LOG END")

