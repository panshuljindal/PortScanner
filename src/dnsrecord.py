import socket
import dns
import dns.resolver
import socket
from datetime import datetime
import json
import os

def dnsScan(remoteServer):
    def get_absolute_path(relative_path):
        dir = os.path.dirname(os.path.abspath(_file_))
        split_path = relative_path.split("/")
        absolute_path = os.path.join(dir, *split_path)
        return absolute_path
    
    td1 = datetime.now()

    # net1 = input("Enter a remote host to scan: ")
    print ("\n\n")
    print ("===============================================================")
    print ("Fetching DNS records for host: ", remoteServer)
    print ("===============================================================")
    print ("\n\n")

    # remoteServer = net1

    addrDict=[]

    # --------------to fetch IPv4 and IPv6 addresses ----------------------
    try:
        remoteServerIP4 = socket.gethostbyname(remoteServer)
        remoteServerIP6 = socket.getaddrinfo(remoteServer, None, socket.AF_INET6)
        # addrDict.append("IPv4 Address : "+str(remoteServerIP4)+"\n")
        # addrDict.append("IPv6 Address : "+str(remoteServerIP6[0][4][0])+"\n")
        print ("IPv4 Address : " , remoteServerIP4)
        print ("\n\n")
        print ("IPv6 Address : " , remoteServerIP6[0][4][0])
        print ("\n\n")
    except socket.gaierror:
        print ("Hostname could not be resolved. Exiting")
        print ("\n\n")
    except Exception:
        print ("Error during dns resolution")
        print ("\n\n")
    # ------------to fetch CNAME record: canonical name records----------------
    try:
        result = dns.resolver.query(remoteServer, 'CNAME')
        for cnameval in result:
            addrDict.append("CNAME target address: "+str(cnameval.target)+"\n")
            print ("CNAME target address: ", cnameval.target)
        print ("\n\n")
    # except dns.resolver.NoAnswer as Error:
    # print Error
    except Exception as Error:
        print ("CNAME target address:")
        print (Error)
    print ("\n\n")
    # ------------to fetch MX record: mail exchange records----------------
    try:
        result = dns.resolver.query(remoteServer, 'MX')
        print ("MX Record: ")
        for exdata in result:
            potty = exdata.exchange.text()
            addrDict.append(potty+"\n\n")
            print (exdata.exchange.text())
        print ("\n\n")
    except Exception as Error:
        print ("MX Record: ")
        print (Error)
        print ("\n\n")
    # ------------to fetch ANY record: any records----------------
    try:
        result = dns.resolver.query(remoteServer, 'ANY')
        print (result._dict_)
        addrDict.append(result._dict_+"\n\n")
        for attr in dir(result):
            addrDict.append(attr + "\n" + getattr(result, attr)+"\n\n")
            print (attr, getattr(result, attr))
        print ("\n\n")
    except Exception as Error:
        print (Error)
        print ("Because it would add complexity in the Answer object, \nand because ANY queries are usually not good things to do from a stub resolver; \nthe ANY query will just get anything that happens to be cached, \n not everything that may be associated with the name.")
        print ("\n\n")
    # ------------to fetch NAPTR record: name authority pointer records----------------
    try:
        result = dns.resolver.query(remoteServerIP4, 'NAPTR')
        
        print ("NAPTR record: ")
        for rdata in result:
            addrDict.append(rdata.to_text()+"\n\n")
            print (rdata.to_text())
        print ("\n\n")
    except Exception as Error:
        print ("NAPTR record: ")
        print (Error)
        print ("\n\n")
    # ------------to fetch NS record: name server records----------------
    try:
        result = dns.resolver.query(remoteServer, 'NS')
        # for attr in dir(result):
        # print attr, getattr(result, attr)
        print ("NS record: ")
        for rdataset in result:
            addrDict.append(rdataset.target+"\n\n")
            print (rdataset.target)
        print ("\n\n")
    #-----------------------------------------------------------------------------------------------------------------------------
    except Exception as Error:
        print ("NS record: ")
        print (Error)
        print ("\n\n")
    # ------------to fetch PTR record: pointer records----------------
    req = '.'.join(reversed(remoteServerIP4.split("."))) + ".in-addr.arpa"
    try:
        result = dns.resolver.query(req, 'PTR')
        print ("PTR record: ")
        addrDict.append("PTR record: \n")
        for rdata in result:
            addrDict.append(rdata.target)
            print (rdata.target)
        print ("\n\n")
    except Exception as Error:
        print ("PTR record: ")
        print (Error)
        print ("\n\n")
    # ------------to fetch SOA record: start of authority records----------------
    try:
        result = dns.resolver.query(remoteServer, 'SOA')
        print ("SOA record: ")
        addrDict.append("SOA record: \n")
        for rdata in result:
            addrDict.append("Serial: "+ rdata.serial + "\n")
            print ('Serial: ', rdata.serial)
            addrDict.append("Tech: "+ rdata.rname + "\n")
            print ('Tech: ', rdata.rname)
            addrDict.append("Refresh: "+ rdata.refresh + "\n")
            print ('Refresh: ', rdata.refresh)
            addrDict.append("Retry: "+ rdata.retry + "\n")
            print ('Retry: ', rdata.retry)
            addrDict.append("Expire: "+ rdata.expire + "\n")
            print ('Expire: ', rdata.expire)
            addrDict.append("Minimum: "+ rdata.minimum + "\n")
            print ('Minimum: ', rdata.minimum)
            addrDict.append("mname: "+ rdata.mname + "\n")
            print ('mname: ', rdata.mname)
            print ("\n")
        print ("\n\n")
    except Exception as Error:
        print ("SOA record: ")
        print (Error)
        print ("\n\n")
    # ------------to fetch SRV record: service records----------------
    try:
        result = dns.resolver.query('_xmpp-client._tcp.'+remoteServer, 'SRV')
        print ("SRV record: ")
        addrDict.append("SRV record: \n")
        for srv in result:
            addrDict.append("weight: "+ srv.weight + "\n")
            print ("weight: ", srv.weight)
            addrDict.append("host: "+ str(srv.target).rstrip('.') + "\n")
            print ("host: ", str(srv.target).rstrip('.'))
            addrDict.append("priority: "+ srv.priority + "\n")
            print ("priority: ", srv.priority)
            addrDict.append("port: "+ srv.port + "\n")
            print ("port: ", srv.port)
            print ('\n')
        print ("\n\n")
    except Exception as Error:
        print ("SRV record: ")
        print (Error)
        print ("\n\n")
    # ------------to fetch TXT record: text records----------------
    try:
        result = dns.resolver.query(remoteServer, 'TXT')
        print ("TXT record: ")
        addrDict.append("TXT record: \n")
        for rdata in result:
            for txt_string in rdata.strings:
                addrDict.append(txt_string)
                print (" TXT: ", txt_string)
            print ("\n\n")
    except Exception as Error:
        print ("TXT record: ")
        print (Error)
        print ("\n\n")
    
    td2 = datetime.now()
    total = td2-td1
    # Printing the information to screen
    dictionary={total:addrDict}
    return dictionary