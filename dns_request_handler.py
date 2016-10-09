from socketserver import BaseRequestHandler

from dnslib import DNSRecord, QTYPE

from service.logservice import log_service
from service.natservice import nat_service
from utility import Utility


class DNSRequestHandler(BaseRequestHandler):
    def handle(self):
        # Get DNS request bytes
        data = self.request[0]
        # Parse bytes into request
        request = DNSRecord.parse(data)

        print()
        print('Incoming query from %s' % self.client_address[0])
        # Get Record label list
        label = request.questions[0].qname.label
        # Decode bytes into string and reassemble the domain name
        domain = '.'.join([s.decode() for s in label])
        log_service.log_dns_access(self.client_address[0], "Incoming query", "Permitted")
        # query DNS server for response
        response = Utility.get_record(data)
        log_service.log_dns_access(self.client_address[0], "Resolving", domain)

        # Get a random record
        answer = Utility.rand_record(response)

        address = answer.rdata.toZone()
        log_service.log_dns_access(self.client_address[0], "Response", address)

        # Add NAT map
        if answer.rtype == QTYPE.A:
            nat_service.ipv4_map(domain, address, self.client_address[0], answer.ttl)
        elif answer.rtype == QTYPE.AAAA:
            nat_service.ipv6_map(domain, address, self.client_address[0], answer.ttl)

        # Build response
        response = Utility.build_response(request, answer)
        print(response)
        response.header.id = request.header.id
        pack = response.pack()
        self.request[1].sendto(pack, self.client_address)
