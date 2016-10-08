import shutil

import config.guardconfig as cfg
from service.natservice import nat_service
from utility import Utility


class ConfigService(object):
    @staticmethod
    def configure():
        # Check whether or not already have traffic mapping
        if not nat_service.is_pre_routing_exist(cfg.guardConfig['ETHERNET'], cfg.guardConfig['DNS_PORT'],
                                                cfg.guardConfig['GUARD_PORT']):
            print('Redirecting DNS queries to Guard')
            nat_service.intercept(cfg.guardConfig['ETHERNET'], cfg.guardConfig['DNS_PORT'],
                                  cfg.guardConfig['GUARD_PORT'])

        # Refresh zone files
        for zonefile in cfg.dnsConfig['ZONE_FILES']:
            src = 'config/zones/%s' % (zonefile)
            dst = '%s/%s' % (cfg.dnsConfig['ZONE_LOCATION'], zonefile)
            shutil.copyfile(src, dst)

        # Reload DNS zone files
        Utility.exec(['service', 'bind9', 'reload'])

    @staticmethod
    def revert():
        print('Revert DNS queries redirection')
        nat_service.revert_pre_routing(cfg.guardConfig['ETHERNET'], cfg.guardConfig['DNS_PORT'],
                                       cfg.guardConfig['GUARD_PORT'])
