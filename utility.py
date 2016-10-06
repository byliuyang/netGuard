import subprocess

from dnslib import DNSRecord, RR, QTYPE, A
import config.guardconfig as guard_cfg
from dns.resolver import Resolver, NoAnswer


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
    def get_record(domain):
        resolver = Resolver()
        resolver.nameservers = [guard_cfg.guardConfig['NAME_SERVER']]
        try:
            return resolver.query(domain)
        except KeyError as err:
            print(err)
        except NoAnswer as err:
            print(err)

    @staticmethod
    def get_response(domain, address, ttl):
        q = DNSRecord.question(domain)
        a = q.reply()
        a.add_answer(RR(domain, QTYPE.A, rdata=A(address), ttl=ttl))
        print(a)
        return a
