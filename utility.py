import random
import socket
import subprocess

from dnslib import DNSRecord

import config.guardconfig as guard_cfg


class Utility(object):
    @staticmethod
    def exec(cmd):
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = p.communicate()

        # Check whether or not already have traffic mapping
        return out.decode('utf-8'), err.decode('utf-8')

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

    @staticmethod
    def rand_record(response):
        length = len(response.rr)
        i = random.randint(0, length - 1)
        return response.rr[i]

    @staticmethod
    def get_ipv6(ipv4):
        numbers = list(map(int, ipv4.split('.')))
        return '2604:a880:400:d0::ac9:e001:{:02x}{:02x}:{:02x}{:02x}'.format(*numbers)
