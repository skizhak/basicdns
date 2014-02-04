#######
# Original code sample taken from dnspython mail archive.
# credits to Luca Dionisi wherever is its due
#######
import dns
import dns.name, dns.query, dns.resolver
import dns.message, dns.rrset
import socket
import re

def requestHandler(address, message):
    resp = None
    try:
        message_id = ord(message[0]) * 256 + ord(message[1])
        print 'msg id = ' + str(message_id)
        if message_id in serving_ids:
            # the request is already taken, drop this message
            print 'I am already serving this request.'
            return
        serving_ids.append(message_id)
        try:
            msg = dns.message.from_wire(message)
            try:
                op = msg.opcode()
                if op == 0:
                    # standard and inverse query
                    qs = msg.question
                    if len(qs) > 0:
                        q = qs[0]
                        print 'request is ' + str(q)
                        if q.rdtype == dns.rdatatype.A:
                            resp = std_qry(msg)
                        elif q.rdtype == dns.rdatatype.CNAME:
                            print 'CNAME query'
                            resp = std_qry(msg)
                        else:
                            # not implemented
                            resp = self.make_response(qry=msg, RCODE=4)   # RCODE =  4    Not Implemented
                else:
                    # not implemented
                    resp = self.make_response(qry=msg, RCODE=4)   # RCODE =  4    Not Implemented

            except Exception, e:
                print 'got ' + repr(e)
                resp = self.make_response(qry=msg, RCODE=2)   # RCODE =  2    Server Error
                print 'resp = ' + repr(resp.to_wire())

        except Exception, e:
            print 'got ' + repr(e)
            resp = self.make_response(id=message_id, RCODE=1)   # RCODE =  1    Format Error
            print 'resp = ' + repr(resp.to_wire())

    except Exception, e:
        # message was crap, not even the ID
        print 'got ' + repr(e)

    if resp:
        s.sendto(resp.to_wire(), address)
        serving_ids.remove(message_id)


def std_qry(msg):
    qs = msg.question
    print str(len(qs)) + ' questions.'

    answers = []
    nxdomain = False
    for q in qs:
        qname = q.name.to_text()[:-1]
        print 'q name = ' + qname
        domain = qname.lower()
        if domain in dns_records.keys():
            print 'Found record'
            resp = make_response(qry=msg)
            if dns_records[domain]['type'] == 'A':
                rrset = dns.rrset.from_text(q.name, 1000,
                                            dns.rdataclass.IN, dns.rdatatype.A,
                                            dns_records[domain]['value'])
                resp.answer.append(rrset)
                
            elif dns_records[domain]['type'] == 'CNAME':
                print 'This is a CNAME record '
                value = dns_records[domain]['value']+'.'
                rrset = dns.rrset.from_text(q.name, 1000,
                                            dns.rdataclass.IN, dns.rdatatype.CNAME,
                                            value)
                
                resp.answer.append(rrset)

                # resolve the cname and append the results as the question
                # was rdatatype.A

                cname = dns.name.from_text(dns_records[domain]['value'])
                query = dns.message.make_query(cname, dns.rdatatype.A)
                response = dns.query.udp(query, def_ns)
                for rrset in response.answer:
                    resp.answer.append(rrset)

            else:
                return make_response(qry=msg, RCODE=3)
                    
            return resp
        else:
            #return make_response(qry=msg, RCODE=2)   # RCODE =  3    Name Error
            resp = make_response(qry=msg)

            # resolve the cname and append the results as the question
            # was rdatatype.A
            query = dns.message.make_query(domain, dns.rdatatype.A)
            response = dns.query.udp(query, def_ns)
            for rrset in response.answer:
                resp.answer.append(rrset)
                #print rrset
            
            return resp




def make_response(qry=None, id=None, RCODE=0):
    if qry is None and id is None:
        raise Exception, 'bad use of make_response'
    if qry is None:
        resp = dns.message.Message(id)
        # QR = 1
        resp.flags |= dns.flags.QR
        if RCODE != 1:
            raise Exception, 'bad use of make_response'
    else:
        resp = dns.message.make_response(qry)
    resp.flags |= dns.flags.AA
    resp.flags |= dns.flags.RA
    resp.set_rcode(RCODE)
    return resp

def parse_record_file(file):
    records = {}
    with open(file, 'r') as fobj:
        for line in fobj :
            if line.rstrip() and '#' not in line[0]:
                entry = re.findall(r"[\w\.\-]+",line)
                key = entry[0].lower()
                records[key] = {}
                records[key]['type'] = entry[1]
                records[key]['value'] = entry[2]
        
    return records

dns_rec_file = 'dns_records'
dns_records = parse_record_file(dns_rec_file)

def_ns = dns.resolver.get_default_resolver().nameservers[0]

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('', 53))
print 'binded to UDP port 53.'
serving_ids = []

while True:
    print 'waiting requests.'
    message, address = s.recvfrom(1024)
    print 'serving a request.'
    requestHandler(address, message)
