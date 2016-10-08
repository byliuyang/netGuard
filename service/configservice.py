import shutil

import config.guardconfig as cfg
from service.natservice import NATService


class ConfigService(object):
    @staticmethod
    def configure():
        natservice = NATService()
        # Check whether or not already have traffic mapping
        if not natservice.is_pre_routing_exist(cfg.guardConfig['ETHERNET'], cfg.guardConfig['DNS_PORT'],
                                               cfg.guardConfig['GUARD_PORT']):
            print('Redirecting DNS queries to Guard')
            natservice.intercept(cfg.guardConfig['ETHERNET'], cfg.guardConfig['DNS_PORT'],
                                 cfg.guardConfig['GUARD_PORT'])

        # Refresh zone files
        for zonefile in cfg.dnsConfig['ZONE_FILES']:
            src = 'config/zones/%s' % (zonefile)
            dst = '%s/%s' % (cfg.dnsConfig['ZONE_LOCATION'], zonefile)
            shutil.copyfile(src, dst)

    @staticmethod
    def revert():
        print('Revert DNS queries redirection')
        natservice = NATService()
        natservice.revert_pre_routing(cfg.guardConfig['ETHERNET'], cfg.guardConfig['DNS_PORT'],
                                      cfg.guardConfig['GUARD_PORT'])
