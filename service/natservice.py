from utility import Utility


class NATService(object):
    """iptables commands"""
    # Check whether NAT map exists
    NAT_TABLE_CMD = ['iptables', '-t', 'nat']

    # NAT_TABLE_TRAFFIC_CMD = ['PREROUTING', '-i', guard_cfg.guardConfig['ETHERNET'], '-p', 'udp', '--dport',
    # guard_cfg.guardConfig['DNS_PORT'], '-j', 'REDIRECT', '--to-port',
    # guard_cfg.guardConfig['GUARD_PORT']]
    # STOP_INTERCEPTING_NAT_TRAFFIC_CMD = NAT_TABLE_CMD + ['-D'] + NAT_TABLE_TRAFFIC_CMD

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
