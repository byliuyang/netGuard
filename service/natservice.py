from threading import Timer

from config.natconfig import natconfig
from db.mapdb import domain_ip_mappings
from utility import Utility


class NATService(object):
    """
    iptables commands
    reference: https://www.digitalocean.com/community/tutorials/how-to-forward-ports-through-a-linux-gateway-with-iptables
    """

    # Check whether NAT map exists
    NAT_TABLE_CMD = ['iptables', '-t', 'nat']

    def __init__(self):
        self.connections = {}

    @staticmethod
    def is_pre_routing_exist(ethernet, source_port, target_port):
        cmd = NATService.NAT_TABLE_CMD + ['-C', 'PREROUTING', '-i', ethernet, '-p', 'udp', '--dport', str(source_port),
                                          '-j',
                                          'REDIRECT', '--to-port', str(target_port)]
        out, err = Utility.exec(cmd)
        return err == ''

    @staticmethod
    def intercept(ethernet, source_port, target_port):
        cmd = NATService.NAT_TABLE_CMD + ['-A', 'PREROUTING', '-i', ethernet, '-p', 'udp', '--dport', str(source_port),
                                          '-j',
                                          'REDIRECT', '--to-port', str(target_port)]
        Utility.exec(cmd)

    @staticmethod
    def revert_pre_routing(ethernet, source_port, target_port):
        cmd = NATService.NAT_TABLE_CMD + ['-D', 'PREROUTING', '-i', ethernet, '-p', 'udp', '--dport', str(source_port),
                                          '-j',
                                          'REDIRECT', '--to-port', str(target_port)]
        Utility.exec(cmd)

    def __map(self, protocol, domain, public_ip, client_ip, ttl):
        print()
        print("Adding rule")
        print(public_ip)

        for port in domain_ip_mappings[domain]:
            r = domain_ip_mappings[domain][port]

            accept_tcp_cmd = [protocol, '-A', 'FORWARD', '-i', natconfig['PUBLIC_INTERFACE'], '-o',
                              natconfig['PRIVATE_INTERFACE'], '-s', client_ip, '-p', 'tcp', '--syn',
                              '--dport', str(r[1]), '-m', 'conntrack', '--ctstate', 'NEW', '-j', 'ACCEPT']

            guard_to_server_cmd = [protocol, '-A', 'FORWARD', '-i', natconfig['PUBLIC_INTERFACE'], '-o',
                                   natconfig['PRIVATE_INTERFACE'], '-s', client_ip, '-m', 'conntrack',
                                   '--ctstate', 'ESTABLISHED,RELATED', '-j', 'ACCEPT']

            server_to_guard_cmd = [protocol, '-A', 'FORWARD', '-i', natconfig['PRIVATE_INTERFACE'], '-o',
                                   natconfig['PUBLIC_INTERFACE'], '-m', 'conntrack',
                                   '--ctstate', 'ESTABLISHED,RELATED', '-j', 'ACCEPT']

            drop_pack_cmd = [protocol, '-P', 'FORWARD DROP']

            port_to_server_dst_cmd = [protocol, '-t', 'nat', '-A', 'PREROUTING', '-i',
                                      natconfig['PUBLIC_INTERFACE'],
                                      '-s', client_ip, '-d', public_ip,
                                      '-p', 'tcp', '--dport', str(port), '-j', 'DNAT', '--to',
                                      '%s:%d' % (r[0], r[1])]

            port_to_server_src_cmd = [protocol, '-t', 'nat', '-A', 'POSTROUTING', '-o',
                                      natconfig['PRIVATE_INTERFACE'], '-p', 'tcp',
                                      '--dport', str(r[1]), '-d', r[0], '-j', 'SNAT', '--to-source',
                                      '%s:%d' % (natconfig['PRIVATE_IP'], port)]

            Utility.exec(guard_to_server_cmd)
            Utility.exec(server_to_guard_cmd)
            Utility.exec(drop_pack_cmd)
            Utility.exec(accept_tcp_cmd)
            Utility.exec(port_to_server_dst_cmd)
            Utility.exec(port_to_server_src_cmd)

            print(' '.join(guard_to_server_cmd))
            print(' '.join(server_to_guard_cmd))
            print(' '.join(drop_pack_cmd))
            print(' '.join(accept_tcp_cmd))
            print(' '.join(port_to_server_dst_cmd))
            print(' '.join(port_to_server_src_cmd))
            print()

            Timer(ttl, self.__revoke_rule, (protocol, port, r, public_ip, client_ip)).start()

    def __revoke_rule(self, protocol, port, r, public_ip, client_ip):
        print()
        print("Revoking rule")
        accept_tcp_cmd = [protocol, '-D', 'FORWARD', '-i', natconfig['PUBLIC_INTERFACE'], '-o',
                          natconfig['PRIVATE_INTERFACE'], '-s', client_ip, '-p', 'tcp', '--syn',
                          '--dport', str(r[1]), '-m', 'conntrack', '--ctstate', 'NEW', '-j', 'ACCEPT']

        guard_to_server_cmd = [protocol, '-D', 'FORWARD', '-i', natconfig['PUBLIC_INTERFACE'], '-o',
                               natconfig['PRIVATE_INTERFACE'], '-s', client_ip, '-m', 'conntrack',
                               '--ctstate', 'ESTABLISHED,RELATED', '-j', 'ACCEPT']

        server_to_guard_cmd = [protocol, '-D', 'FORWARD', '-i', natconfig['PRIVATE_INTERFACE'], '-o',
                               natconfig['PUBLIC_INTERFACE'], '-m', 'conntrack',
                               '--ctstate', 'ESTABLISHED,RELATED', '-j', 'ACCEPT']

        drop_pack_cmd = [protocol, '-P', 'FORWARD DROP']

        port_to_server_dst_cmd = [protocol, '-t', 'nat', '-D', 'PREROUTING', '-i',
                                  natconfig['PUBLIC_INTERFACE'],
                                  '-s', client_ip, '-d', public_ip,
                                  '-p', 'tcp', '--dport', str(port), '-j', 'DNAT', '--to',
                                  '%s:%d' % (r[0], r[1])]

        port_to_server_src_cmd = [protocol, '-t', 'nat', '-D', 'POSTROUTING', '-o',
                                  natconfig['PRIVATE_INTERFACE'], '-p', 'tcp',
                                  '--dport', str(r[1]), '-d', r[0], '-j', 'SNAT', '--to-source',
                                  '%s:%d' % (natconfig['PRIVATE_IP'], port)]

        Utility.exec(accept_tcp_cmd)
        Utility.exec(port_to_server_dst_cmd)
        Utility.exec(port_to_server_src_cmd)
        Utility.exec(guard_to_server_cmd)
        Utility.exec(server_to_guard_cmd)

        print(' '.join(accept_tcp_cmd))
        print(' '.join(port_to_server_dst_cmd))
        print(' '.join(port_to_server_src_cmd))
        print(' '.join(guard_to_server_cmd))
        print(' '.join(server_to_guard_cmd))

    def ipv4_map(self, domain, public_ip, client_ip, ttl):
        self.__map('iptables', domain, public_ip, client_ip, ttl)

    def ipv6_map(self, domain, public_ip, client_ip, ttl):
        self.__map('ip6tables', domain, public_ip, client_ip, ttl)


nat_service = NATService()
