from socketserver import BaseRequestHandler

from dnslib import DNSRecord

from service.logservice import LogService
from utility import Utility


class DNSRequestHandler(BaseRequestHandler):
    def handle(self):
        # Get DNS request bytes
        data = self.request[0]
        # Parse bytes into request
        request = DNSRecord.parse(data)

        logService = LogService()

        print()
        print('Incoming query from %s' % self.client_address[0])
        # Get Record label list, ["b'cs4404'", "b'com'"]
        label = request.questions[0].qname.label
        # Decode bytes into string and reassemble the domain name
        domain = '.'.join([s.decode() for s in label])
        logService.log_dns_access(self.client_address[0], "Incoming query", "Permitted")
        # query DNS server for response
        response = Utility.get_record(data)
        # print(answer)
        logService.log_dns_access(self.client_address[0], "Resolving", domain)

        answer = response.get_a()

        address = answer.rdata.toZone()
        logService.log_dns_access(self.client_address[0], "Response", address)
        response = Utility.build_response(request, answer)
        print(response)
        response.header.id = request.header.id
        pack = response.pack()

        self.request[1].sendto(pack, self.client_address)

        logService.end()
