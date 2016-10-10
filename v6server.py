import socket
from socketserver import ThreadingUDPServer


class V6Server(ThreadingUDPServer):
    address_family = socket.AF_INET6
