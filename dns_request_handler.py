from socketserver import BaseRequestHandler
from dnslib import DNSRecord

from utility import Utility


class DNSRequestHandler(BaseRequestHandler):
    def handle(self):
        # Get DNS request bytes
        data = self.request[0]
        # Parse bytes into request
        record = DNSRecord.parse(data)

        print()
        print('Incoming query:')
        # Get Record label list, ["b'cs4404'", "b'com'"]
        label = record.questions[0].qname.label
        # Decode bytes into string and reassemble the domain name
        domain = '.'.join([s.decode() for s in label])
        # query DNS server for answer
        answer = Utility.get_record(domain)

        # Get the TTL
        ttl = answer.rrset.ttl

        address = answer.response.answer[0].items[0].to_text()
        response = Utility.get_response(domain, address, ttl)
        response.header.id = record.header.id
        pack = response.pack()

        self.request[1].sendto(pack, self.client_address)
