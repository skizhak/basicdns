#
# @author: sarin kizhakkepurayil
#
# some of the dns message parsing code sample is taken from 
# dnspython mail archive.credits to Luca Dionisi wherever is its due
#

import os
import sys
import socket
from curses.ascii import ctrl
import signal
import time
import threading
from multiprocessing import Process, Queue
from multiprocessing.reduction import reduce_handle, rebuild_handle
import logging, logging.handlers
import re
import dns
import dns.name, dns.query, dns.resolver
import dns.message, dns.rrset


log = logging.getLogger(__name__)

def setup_log(log_path, log_level):
    log_handler = logging.handlers.RotatingFileHandler(log_path,
                                                        maxBytes=1024*1024,
                                                        backupCount=2)
    format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    formatter = logging.Formatter(format)

    log_handler.setFormatter(formatter)
    main_logger = logging.getLogger('')
    main_logger.setLevel(log_level)
    main_logger.addHandler(log_handler)

def parse_conf_lines(line):
    record = {}
    if line.rstrip() and '#' not in line[0]:
        entry = re.findall(r"[\w\.\-]+",line)
        key = entry[0].lower()
        record[key] = {}
        record[key]['type'] = entry[1]
        record[key]['value'] = entry[2]
    return record

def parse_record_file(file):
    records = {}
    with open(file, 'r') as fobj:
        for line in fobj :
            record = parse_conf_lines(line)
            records.update(record)
    return records

def follow_record_file(file):
    log.debug(file)
    file.seek(0,2)
    while True:
        line = file.readline()
        log.debug("checking.. %s" %line)
        if not line:
            time.sleep(10)
            continue
        yield line

def watch_record_file_updates(file_name, new_dns_records):
    global dns_records
    file = open(file_name, 'r')
    log.debug(file)
    conf_lines = follow_record_file(file)
    log.debug(conf_lines)
    for line in conf_lines:
        record = parse_conf_lines(line)
        new_dns_records.update(record)
    dns_records = new_dns_records
    log.debug(new_dns_records)

class WatchUpdateThread(threading.Thread):
    """docstring for WatchUpdate"""
    def __init__(self, file_name, dns_records):
        threading.Thread.__init__(self)
        self.file_name = file_name
        self.dns_records = dns_records
        self.daemon = True

    def run(self):
        watch_record_file_updates(self.file_name, self.dns_records)
        

dns_rec_file = 'dns_records'
dns_records = parse_record_file(dns_rec_file)
watch_record_file_thread = WatchUpdateThread(dns_rec_file, dns_records)
watch_record_file_thread.start()

def_ns = dns.resolver.get_default_resolver().nameservers[0]

def make_response(query=None, id=None, RCODE=0):
    if query is None and id is None:
        raise Exception, 'bad use of make_response'
    if query is None:
        resp = dns.message.Message(id)
        # QR = 1
        resp.flags |= dns.flags.QR
        if RCODE != 1:
            raise Exception, 'bad use of make_response'
    else:
        resp = dns.message.make_response(query)
    resp.flags |= dns.flags.AA
    resp.flags |= dns.flags.RA
    resp.set_rcode(RCODE)
    return resp

def resolve_query(message):
    qs = message.question
    print str(len(qs)) + ' questions.'

    answers = []
    nxdomain = False
    for q in qs:
        qname = q.name.to_text()[:-1]
        print 'q name = ' + qname
        domain = qname.lower()
        if domain in dns_records.keys():
            print 'Found record'
            resp = make_response(query=message)
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
                return make_response(query=message, RCODE=3)
                    
            return resp
        else:
            #return make_response(qry=message, RCODE=2)   # RCODE =  3    Name Error
            resp = make_response(query=message)

            # resolve the cname and append the results as the question
            # was rdatatype.A
            query = dns.message.make_query(domain, dns.rdatatype.A)
            response = dns.query.udp(query, def_ns)
            for rrset in response.answer:
                resp.answer.append(rrset)
                #print rrset
            
            return resp

def resolve_message(message):
    resp = None
    try:
        message_id = ord(message[0]) * 256 + ord(message[1])
        print 'msg id = ' + str(message_id)

        '''
        #implement list of procesing message_ids

        if message_id in serving_ids:
            # the request is already taken, drop this message
            print 'I am already serving this request.'
            return
        serving_ids.append(message_id)
        '''
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
                            resp = resolve_query(msg)
                        elif q.rdtype == dns.rdatatype.CNAME:
                            print 'CNAME query'
                            resp = resolve_query(msg)
                        else:
                            # not implemented
                            resp = self.make_response(query=msg, RCODE=4)   # RCODE =  4    Not Implemented
                else:
                    # not implemented
                    resp = self.make_response(query=msg, RCODE=4)   # RCODE =  4    Not Implemented

            except Exception, e:
                print 'got ' + repr(e)
                resp = self.make_response(query=msg, RCODE=2)   # RCODE =  2    Server Error
                print 'resp = ' + repr(resp.to_wire())

        except Exception, e:
            print 'got ' + repr(e)
            resp = self.make_response(id=message_id, RCODE=1)   # RCODE =  1    Format Error
            print 'resp = ' + repr(resp.to_wire())

    except Exception, e:
        # message was crap, not even the ID
        print 'got ' + repr(e)

    if resp:
        return resp.to_wire()

class SocketHandler(object):
    """docstring for SocketHandler"""
    def __init__(self, message_q):
        self.message_q = message_q

    def start_message_handler(self):
        [data, address] = self.message_q.get()
        log.debug(data)
        resp = resolve_message(data)

        #sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        #sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        self.answer_q.put([resp, address])
        
        #sock.sendto(resp, address)

    def echo_connection(self):
        while True:
            request = connection.recv(1024)
            if 'end' in request:
                break
            elif request:
                connection.send(request)
        connection.send(ctrl(']'))
        connection.close()

class DnsWorker(Process, SocketHandler):
    """docstring for DnsWorker"""
    def __init__(self, message_q, answer_q, log_dir, log_level, group=None, target=None, name=None, args=(), kwargs={}):
        self.message_q = message_q
        self.answer_q = answer_q
        self.log_dir = log_dir
        self.log_level = log_level

        Process.__init__(self, group, target, name, args, kwargs)
        SocketHandler.__init__(self, message_q)

    def run(self):
        log_path = os.path.join(self.log_dir, '%s.log' %self.name)
        setup_log(log_path, self.log_level)
        while True:
            self.start_message_handler()

class DnsServer:
    def __init__(self, addr, port=53, procs=4, log_dir=os.path.dirname(__file__),
                log_level=logging.DEBUG):
        self.addr = addr
        self.port = port
        self.procs = procs
        self.proc_pool = {}
        self.log_dir = log_dir
        self.log_level = log_level
        self.message_q = Queue(self.procs)
        self.answer_q = Queue(self.procs)

    def stop_server(self):
        for proc_name, proc in self.proc_pool.iteritems():
            if proc.is_alive():
                proc.terminate()

    def stop_gracefully(self, signum, frame):
        self.stop_server()

    def start_worker_process(self):
        for i in range(self.procs):
            proc = DnsWorker(self.message_q, self.answer_q, self.log_dir, self.log_level, name='DnsWorker-%d' %i) 
            self.proc_pool[proc.name] = proc
            proc.start()

    def run_forever(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.addr, self.port))

        signal.signal(signal.SIGINT, self.stop_gracefully)

        self.start_worker_process()

        try:
            while True:
                data, address = sock.recvfrom(1024)
                self.message_q.put([data, address])
                [resp, address] = self.answer_q.get()
                sock.sendto(resp, address)

        except socket.error:
            self.stop_server()
        finally:
            sock.close()

if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    server = DnsServer('localhost', 53)
    server.run_forever()
