from datetime import datetime


class LogService(object):
    def __init__(self):
        self.f = open('log/dns/access.log', 'a')

    def log_dns_access(self, client, tag, message):
        time = datetime.now()
        self.f.write('%s  %s  %-16s  %s\n' % (time, client, tag, message))

    def end(self):
        self.f.close()
