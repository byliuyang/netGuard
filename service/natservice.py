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
        self.commands = []
        self.timers = []

    @staticmethod
    def is_pre_routing_exist(ethernet, source_port, target_port):
        cmd = NATService.NAT_TABLE_CMD + ['-C', 'PREROUTING', '-i', ethernet, '-p', 'udp', '--dport', str(source_port),
                                          '-j',
                                          'REDIRECT', '--to-port', str(target_port)]
        out, err = Utility.exec(cmd)

        cmd = ['ip6tables', '-t', 'nat', '-C', 'PREROUTING', '-i', ethernet, '-p', 'udp', '--dport', str(source_port),
               '-j',
               'REDIRECT', '--to-port', str(target_port)]
        out1, err1 = Utility.exec(cmd)
        return err == '' and err1 == ''

    @staticmethod
    def intercept(ethernet, source_port, target_port):
        cmd = NATService.NAT_TABLE_CMD + ['-A', 'PREROUTING', '-i', ethernet, '-p', 'udp', '--dport', str(source_port),
                                          '-j',
                                          'REDIRECT', '--to-port', str(target_port)]
        Utility.exec(cmd)

        cmd6 = ['ip6tables', '-t', 'nat', '-A', 'PREROUTING', '-i', ethernet, '-p', 'udp', '--dport', str(source_port),
                '-j', 'REDIRECT', '--to-port', str(target_port)]
        Utility.exec(cmd6)

    @staticmethod
    def revert_pre_routing(ethernet, source_port, target_port):
        cmd = NATService.NAT_TABLE_CMD + ['-D', 'PREROUTING', '-i', ethernet, '-p', 'udp', '--dport', str(source_port),
                                          '-j',
                                          'REDIRECT', '--to-port', str(target_port)]
        Utility.exec(cmd)

    def ipv4_map(self, domain, public_ip, client_ip, ttl):
        print()
        print("Adding rule ipv4")
        print(public_ip)

        for port in domain_ip_mappings[domain]:
            r = domain_ip_mappings[domain][port]

            accept_tcp_cmd = ['iptables', '-I', 'FORWARD', '-i', natconfig['PUBLIC_INTERFACE'], '-p', 'tcp',
                              '--syn', '-s', client_ip, '-d', r[0], '--dport', str(r[1]), '-j', 'ACCEPT']

            server_to_guard_cmd = ['iptables', '-A', 'FORWARD', '-i',
                                   natconfig['PRIVATE_INTERFACE'], '-o',
                                   natconfig['PUBLIC_INTERFACE'], '-s', r[0], '-d', client_ip,
                                   '-m', 'conntrack', '--ctstate', 'ESTABLISHED,RELATED', '-j', 'ACCEPT']

            port_to_server_dst_cmd = ['iptables', '-t', 'nat', '-A', 'PREROUTING', '-i',
                                      natconfig['PUBLIC_INTERFACE'],
                                      '-s', client_ip, '-d', public_ip,
                                      '-p', 'tcp', '--dport', str(port), '-j', 'DNAT', '--to',
                                      '%s:%d' % (r[0], r[1])]

            accept_port_forwarding = ['iptables', '-A', 'FORWARD', '-p', 'tcp', '-s', client_ip,
                                      '-d', r[0], '--dport', str(r[1]), '-j',
                                      'ACCEPT']

            port_to_server_src_cmd = ['iptables', '-t', 'nat', '-A', 'POSTROUTING', '-o',
                                      natconfig['PRIVATE_INTERFACE'], '-p', 'tcp',
                                      '--dport', str(r[1]), '-s', client_ip,
                                      '-d', r[0], '-j', 'SNAT', '--to-source',
                                      natconfig['PRIVATE_IP']]

            Utility.exec(accept_tcp_cmd)
            print(' '.join(accept_tcp_cmd))

            Utility.exec(server_to_guard_cmd)
            print(' '.join(server_to_guard_cmd))

            Utility.exec(port_to_server_dst_cmd)
            print(' '.join(port_to_server_dst_cmd))

            Utility.exec(port_to_server_src_cmd)
            print(' '.join(port_to_server_src_cmd))

            Utility.exec(accept_port_forwarding)
            print(' '.join(accept_port_forwarding))
            print()

            # Cache rules
            # Keep long-live connection
            self.commands.append(['iptables', '-D', 'FORWARD', '-i', natconfig['PUBLIC_INTERFACE'], '-p', 'tcp',
                                  '--syn', '-s', client_ip, '-d', r[0], '--dport', str(r[1]), '-j', 'ACCEPT'])

            self.commands.append(['iptables', '-D', 'FORWARD', '-i', natconfig['PRIVATE_INTERFACE'], '-o',
                                  natconfig['PUBLIC_INTERFACE'], '-s', r[0], '-d', client_ip,
                                  '-m', 'conntrack', '--ctstate', 'ESTABLISHED,RELATED', '-j', 'ACCEPT'])
            self.commands.append(['iptables', '-t', 'nat', '-D', 'PREROUTING', '-i', natconfig['PUBLIC_INTERFACE'],
                                  '-s', client_ip, '-d', public_ip, '-p', 'tcp', '--dport', str(port), '-j', 'DNAT',
                                  '--to', '%s:%d' % (r[0], r[1])])
            self.commands.append(
                ['iptables', '-D', 'FORWARD', '-p', 'tcp', '-s', client_ip, '-d', r[0], '--dport', str(r[1]), '-j',
                 'ACCEPT'])
            self.commands.append(
                ['iptables', '-t', 'nat', '-D', 'POSTROUTING', '-o', natconfig['PRIVATE_INTERFACE'], '-p', 'tcp',
                 '--dport', str(r[1]), '-s', client_ip, '-d', r[0], '-j', 'SNAT', '--to-source',
                 natconfig['PRIVATE_IP']])

            timer = Timer(ttl, self.revoke_rule_v4, (r, client_ip))
            self.timers.append(timer)
            timer.start()

    def revoke_rule_v4(self, r, client_ip):
        print()
        print("Revoking rule")

        # Stop accepting new connection
        reject_tcp_cmd = ['iptables', '-I', 'FORWARD', '-i', natconfig['PUBLIC_INTERFACE'], '-p', 'tcp',
                          '--syn', '-s', client_ip, '-d', r[0], '--dport', str(r[1]), '-j', 'REJECT']

        self.commands.append(['iptables', '-D', 'FORWARD', '-i', natconfig['PUBLIC_INTERFACE'], '-p', 'tcp',
                              '--syn', '-s', client_ip, '-d', r[0], '--dport', str(r[1]), '-j', 'REJECT'])

        Utility.exec(reject_tcp_cmd)
        print(' '.join(reject_tcp_cmd))
        print()

    def ipv6_map(self, domain, public_ip, client_ip, ttl):
        print()
        print("Adding rule ipv6")
        print(public_ip)

        for port in domain_ip_mappings[domain]:
            r = domain_ip_mappings[domain][port]

            accept_tcp_cmd = ['ip6tables', '-I', 'FORWARD', '-i', natconfig['PUBLIC_INTERFACE'], '-p', 'tcp',
                              '--syn', '-s', client_ip, '-d', r[0], '--dport',
                              str(r[1]), '-j', 'ACCEPT']

            server_to_guard_cmd = ['ip6tables', '-A', 'FORWARD', '-i',
                                   natconfig['PUBLIC_INTERFACE'], '-o',
                                   natconfig['PUBLIC_INTERFACE'], '-s', r[0], '-d',
                                   client_ip, '-m', 'conntrack', '--ctstate', 'ESTABLISHED,RELATED',
                                   '-j', 'ACCEPT']

            port_to_server_dst_cmd = ['ip6tables', '-t', 'nat', '-A', 'PREROUTING', '-i',
                                      natconfig['PUBLIC_INTERFACE'],
                                      '-s', client_ip, '-d', public_ip,
                                      '-p', 'tcp', '--dport', str(port), '-j', 'DNAT', '--to',
                                      '[%s]:%d' % (r[0], r[1])]

            accept_port_forwarding = ['ip6tables', '-A', 'FORWARD', '-p', 'tcp', '-s', client_ip,
                                      '-d', r[0], '--dport', str(r[1]), '-j',
                                      'ACCEPT']

            port_to_server_src_cmd = ['ip6tables', '-t', 'nat', '-A', 'POSTROUTING', '-o',
                                      natconfig['PUBLIC_INTERFACE'], '-p', 'tcp',
                                      '--dport', str(r[1]), '-s', client_ip,
                                      '-d', r[0], '-j', 'SNAT', '--to-source',
                                      public_ip]

            Utility.exec(accept_tcp_cmd)
            print(' '.join(accept_tcp_cmd))
            #
            Utility.exec(server_to_guard_cmd)
            print(' '.join(server_to_guard_cmd))
            #
            Utility.exec(port_to_server_dst_cmd)
            print(' '.join(port_to_server_dst_cmd))
            #
            Utility.exec(port_to_server_src_cmd)
            print(' '.join(port_to_server_src_cmd))
            #
            Utility.exec(accept_port_forwarding)
            print(' '.join(accept_port_forwarding))
            # print()

            # Cache rules
            # Keep long-live connection
            self.commands.append(['ip6tables', '-D', 'FORWARD', '-i', natconfig['PUBLIC_INTERFACE'], '-p', 'tcp',
                                  '--syn', '-s', client_ip, '-d', r[0], '--dport',
                                  str(r[1]), '-j', 'ACCEPT'])

            self.commands.append(['ip6tables', '-D', 'FORWARD', '-i',
                                  natconfig['PUBLIC_INTERFACE'], '-o',
                                  natconfig['PUBLIC_INTERFACE'], '-s', r[0], '-d',
                                  client_ip, '-m', 'conntrack', '--ctstate', 'ESTABLISHED,RELATED',
                                  '-j', 'ACCEPT'])

            self.commands.append(['ip6tables', '-t', 'nat', '-D', 'PREROUTING', '-i',
                                  natconfig['PUBLIC_INTERFACE'],
                                  '-s', client_ip, '-d', public_ip,
                                  '-p', 'tcp', '--dport', str(port), '-j', 'DNAT', '--to',
                                  '[%s]:%d' % (r[0], r[1])])

            self.commands.append(['ip6tables', '-D', 'FORWARD', '-p', 'tcp', '-s', client_ip,
                                  '-d', r[0], '--dport', str(r[1]), '-j',
                                  'ACCEPT'])

            self.commands.append(['ip6tables', '-t', 'nat', '-D', 'POSTROUTING', '-o',
                                  natconfig['PUBLIC_INTERFACE'], '-p', 'tcp',
                                  '--dport', str(r[1]), '-s', client_ip,
                                  '-d', r[0], '-j', 'SNAT', '--to-source',
                                  public_ip])

            timer = Timer(ttl, self.revoke_rule_v6, (r, client_ip))
            self.timers.append(timer)
            timer.start()

    def revoke_rule_v6(self, r, client_ip):
        print()
        print("Revoking rule")

        # Stop accepting new connection
        reject_tcp_cmd = ['ip6tables', '-I', 'FORWARD', '-i', natconfig['PUBLIC_INTERFACE'], '-p', 'tcp',
                          '--syn', '-s', client_ip, '-d', r[0], '--dport',
                          str(r[1]), '-j', 'REJECT']

        self.commands.append(['ip6tables', '-D', 'FORWARD', '-i', natconfig['PUBLIC_INTERFACE'], '-p', 'tcp',
                              '--syn', '-s', client_ip, '-d', r[0], '--dport',
                              str(r[1]), '-j', 'REJECT'])

        Utility.exec(reject_tcp_cmd)
        print(' '.join(reject_tcp_cmd))
        print()


nat_service = NATService()
