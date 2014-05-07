#!/usr/bin/env python
# -*- coding: utf-8 -*-
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
from multiprocessing import Process, Queue, Manager
from multiprocessing.sharedctypes import Array
from multiprocessing.reduction import reduce_handle, rebuild_handle
from ctypes import Structure
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

def record(Structure):
    _fields_ = [('name', c_char_p),
                ('type', c_char_p),
                ('value', c_char_p)]

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

class WatchUpdateThread(threading.Thread):
    """docstring for WatchUpdate"""
    def __init__(self, file_name, records):
        threading.Thread.__init__(self)
        self.file_name = file_name
        self.records = records
        self.daemon = True

    def follow_record_file(self, file):
        file.seek(0,2)
        while True:
            line = file.readline()
            log.debug("checking.. %s" %line)
            if not line:
                time.sleep(10)
                continue
            yield line

    def run(self):
        file = open(self.file_name, 'r')
        conf_lines = self.follow_record_file(file)
        dns_records = self.records[0]
        for line in conf_lines:
            record = parse_conf_lines(line)
            dns_records.update(record)
            log.debug(dns_records)
            time.sleep(5)
        #dns_records = curr_dns_records
        self.records[0] = dns_records
        records = self.records
        time.sleep(3)
        

class MessageHandler(object):
    """docstring for MessageHandler"""
    def __init__(self, message_q, answer_q, records):
        self.message_q = message_q
        self.answer_q = answer_q
        self.records = records
        self.dns_records = self.records[0]
        self.records_keys = self.dns_records.keys()
        
    def start_message_handler(self):
        [data, address] = self.message_q.get()
        resp = self.resolve_message(data)
        self.answer_q.put([resp, address])

    def make_response(self, query=None, id=None, RCODE=0):
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

    def resolve_query(self, message):
        qs = message.question
        log.debug(str(len(qs)) + ' questions.')

        answers = []
        nxdomain = False
        for q in qs:
            qname = q.name.to_text()[:-1]
            log.debug('q name = ' + qname)
            domain = qname.lower()
            if domain in self.records_keys:
                log.debug('Found record')
                resp = self.make_response(query=message)
                if self.dns_records[domain]['type'] == 'A':
                    rrset = dns.rrset.from_text(q.name, 1000,
                                                dns.rdataclass.IN, dns.rdatatype.A,
                                                self.dns_records[domain]['value'])
                    resp.answer.append(rrset)
                    
                elif self.dns_records[domain]['type'] == 'CNAME':
                    log.debug('This is a CNAME record ')
                    rrset = dns.rrset.from_text(q.name, 1000,
                                                dns.rdataclass.IN, dns.rdatatype.CNAME,
                                                self.dns_records[domain]['value']+'.')
                    
                    resp.answer.append(rrset)

                    # resolve the cname and append the results as the question
                    # was rdatatype.A
                    cname = dns.name.from_text(self.dns_records[domain]['value'])
                    query = dns.message.make_query(cname, dns.rdatatype.A)
                    response = dns.query.udp(query, def_ns)
                    for rrset in response.answer:
                        resp.answer.append(rrset)

                else:
                    return self.make_response(query=message, RCODE=3)
                        
                return resp
            else:
                resp = self.make_response(query=message)

                # resolve the cname and append the results as the question
                # was rdatatype.A
                query = dns.message.make_query(domain, dns.rdatatype.A)
                response = dns.query.udp(query, def_ns)
                for rrset in response.answer:
                    resp.answer.append(rrset)

                return resp

    def resolve_message(self, message):
        resp = None
        try:
            message_id = ord(message[0]) * 256 + ord(message[1])
            log.debug('msg id = ' + str(message_id))

            try:
                msg = dns.message.from_wire(message)
                try:
                    op = msg.opcode()
                    if op == 0:
                        # standard and inverse query
                        qs = msg.question
                        if len(qs) > 0:
                            q = qs[0]
                            log.debug('request is ' + str(q))
                            if q.rdtype == dns.rdatatype.A:
                                resp = self.resolve_query(msg)
                            elif q.rdtype == dns.rdatatype.CNAME:
                                log.debug('CNAME query')
                                resp = self.resolve_query(msg)
                            else:
                                # not implemented
                                resp = self.make_response(query=msg, RCODE=4)   # RCODE =  4    Not Implemented
                    else:
                        # not implemented
                        resp = self.make_response(query=msg, RCODE=4)   # RCODE =  4    Not Implemented

                except Exception, e:
                    log.debug('got ' + repr(e))
                    resp = self.make_response(query=msg, RCODE=2)   # RCODE =  2    Server Error
                    log.debug('resp = ' + repr(resp.to_wire()))

            except Exception, e:
                log.debug('got ' + repr(e))
                resp = self.make_response(id=message_id, RCODE=1)   # RCODE =  1    Format Error
                log.debug('resp = ' + repr(resp.to_wire()))

        except Exception, e:
            # message was crap, not even the ID
            log.debug('got ' + repr(e))

        if resp:
            log.debug('response for message_id: ' + str(message_id) + ' - ' + str([rrset.to_text() for rrset in resp.answer]))
            return resp.to_wire()
        
class DnsWorker(Process, MessageHandler):
    """docstring for DnsWorker"""
    def __init__(self, message_q, answer_q, records, log_dir, log_level, 
                    group=None, target=None, name=None, args=(), kwargs={}):
        self.message_q = message_q
        self.answer_q = answer_q
        self.records = records
        self.log_dir = log_dir
        self.log_level = log_level

        Process.__init__(self, group, target, name, args, kwargs)
        MessageHandler.__init__(self, message_q, answer_q, records)

    def run(self):
        log_path = os.path.join(self.log_dir, '%s.log' %self.name)
        setup_log(log_path, self.log_level)
        while True:
            self.start_message_handler()

class DnsServer:
    def __init__(self, addr, port=53, procs=4, log_dir=os.path.dirname(__file__),
                log_level=logging.DEBUG, record_file='conf/dns_records'):
        self.addr = addr
        self.port = port
        self.procs = procs
        self.proc_pool = {}
        self.log_dir = log_dir
        self.log_level = log_level
        self.record_file = record_file
        self.message_q = Queue(self.procs)
        self.answer_q = Queue(self.procs)

        records_dict = parse_record_file(self.record_file)
        self.records = Manager().list()
        self.records.append(records_dict)

        watch_record_file_thread = WatchUpdateThread(self.record_file, self.records)
        watch_record_file_thread.start()


    def stop_server(self):
        for proc_name, proc in self.proc_pool.iteritems():
            if proc.is_alive():
                proc.terminate()

    def stop_gracefully(self, signum, frame):
        self.stop_server()

    def start_worker_process(self):
        for i in range(self.procs):
            proc = DnsWorker(self.message_q, self.answer_q, self.records, self.log_dir, 
                             self.log_level, name='DnsWorker-%d' %i) 
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
'''
dns_rec_file = 'dns_records'
dns_records = parse_record_file(dns_rec_file)
watch_record_file_thread = WatchUpdateThread(dns_rec_file)
watch_record_file_thread.start()

records = Manager.list()
records.append(dns_records)
'''

def_ns = dns.resolver.get_default_resolver().nameservers[0]

if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    server = DnsServer('localhost', 53)
    server.run_forever()
