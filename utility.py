import socket
import subprocess

from dnslib import DNSRecord, RR, QTYPE, AAAA

import config.guardconfig as guard_cfg


class Utility(object):
    @staticmethod
    def exec(cmd):
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = p.communicate()

        # Check whether or not already have traffic mapping
        return out.decode('utf-8'), err.decode('utf-8')

    @staticmethod
    def pre_routing(source, source_port, target, target_port):
        nat = ['PREROUTING', '-i', guard_cfg.guardConfig['ETHERNET'], '-p', 'udp', '--dport',
               guard_cfg.guardConfig['DNS_PORT'], '-j', 'REDIRECT', '--to-port',
               guard_cfg.guardConfig['GUARD_PORT']]

    @staticmethod
    def get_record(data):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM):
            # Connect to server and send data
            HOST, PORT = guard_cfg.guardConfig['NAME_SERVER'], guard_cfg.guardConfig['DNS_PORT']
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

            sock.sendto(data, (HOST, PORT))
            received = sock.recv(1024)
            record = DNSRecord.parse(received)
            return record

    @staticmethod
    def build_response(req, rr):
        a = req.reply()
        a.add_answer(rr)
        return a
