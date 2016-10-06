import time

import sys

from nat_manager import NATManager
from utility import Utility
from dns_request_handler import DNSRequestHandler
from socketserver import ThreadingUDPServer
from threading import Thread
import config.guardconfig as cfg


class Guard(object):
    def __init__(self):
        self.natManager = NATManager()

        # Check whether or not already have traffic mapping
        if self.natManager.is_pre_routing_exist(cfg.guardConfig['ETHERNET'], cfg.guardConfig['DNS_PORT'],
                                                cfg.guardConfig['GUARD_PORT']):
            print('Redirecting DNS queries to Guard')
            self.natManager.intercept(cfg.guardConfig['ETHERNET'], cfg.guardConfig['DNS_PORT'],
                                      cfg.guardConfig['GUARD_PORT'])

    @staticmethod
    def run():
        print('Start monitoring DNS queries')
        s = ThreadingUDPServer(('', cfg.guardConfig['GUARD_PORT']), DNSRequestHandler)
        thread = Thread(target=s.serve_forever)
        thread.daemon = True
        thread.start()

        try:
            while True:
                time.sleep(1)
                sys.stderr.flush()
                sys.stdout.flush()

        except KeyboardInterrupt:
            pass
        finally:
            s.shutdown()
