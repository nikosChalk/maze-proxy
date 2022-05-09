
from __future__ import annotations
from pwnlib.util.fiddling import hexdump
from struct import pack,unpack
from enum import Enum
import logging
import socket
import os

from abc import ABC, abstractmethod
from typing import Any, Optional, Tuple

FORMAT = '%(asctime)-15s %(levelname)-7s %(message)s'
LOGLEVEL = os.environ.get('LOGLEVEL', 'INFO').upper()
CUSTOM_LOGGING_LVL=99
logging.addLevelName(CUSTOM_LOGGING_LVL, "CUSTOM_LOGGING")
logging.basicConfig(format=FORMAT, level=LOGLEVEL)
LOGGER = logging.getLogger()
BUFFER_SIZE = 1024


class Handler(ABC):
    """
    The Handler interface declares a method for building the chain of handlers.
    It also declares a method for executing a request.
    """

    @abstractmethod
    def add_next(self, handler: Handler) -> Handler:
        pass

    @abstractmethod
    def handle(self, packet: Any, direction: UDPProxy.PacketDirection) -> bytes:
        pass

class AbstractHandler(Handler):
    """
    The default chaining behavior can be implemented inside a base handler
    class.
    """

    def __init__(self):
        super().__init__()
        self._next_handler: Handler = None

    def add_next(self, handler: Handler) -> Handler:
        self._next_handler = handler

        # Returning a handler from here will let us link handlers in a
        # convenient way like this:
        # monkey.add_next(squirrel).add_next(dog)
        return handler

    @abstractmethod
    def handle(self, packet: Any, direction: UDPProxy.PacketDirection) -> bytes:
        if self._next_handler:
            return self._next_handler.handle(packet, direction)
        else:
            return packet


class LogHandler(AbstractHandler):
    def handle(self, packet: Any, direction: UDPProxy.PacketDirection) -> bytes:
        if direction == UDPProxy.PacketDirection.CLIENT_TO_SERVER:
            log_prefix = "client --> server: "
        elif direction == UDPProxy.PacketDirection.SERVER_TO_CLIENT:
            log_prefix = "server --> client: "
        
        log_msg = log_prefix + hexdump(packet[:24], width=24, groupsize=8, total=False)[10:]
        if len(log_msg) > 24:
            log_msg += ' ...'
        else:
            log_msg += ' '*(24-len(packet)+4)
        log_msg += ' (Len %03d)' % len(packet)
        LOGGER.info(log_msg)

        return super().handle(packet, direction)

class UDPProxy:
    PacketAction = Enum('PacketAction', 'FORWARD DROP')
    PacketDirection = Enum('PacketDirection', 'CLIENT_TO_SERVER SERVER_TO_CLIENT')

    @staticmethod
    def parse_endpoint(ip, resolve=False):
        """Parse IP string and return (ip, port) tuple.
        
        Arguments:
        ip -- IP address:port string. I.e.: '127.0.0.1:8000'.
        """
        ip, port = ip.split(':')
        if resolve:
            ip = socket.gethostbyname(ip)
        return (ip, int(port))

    def __init__(self, src, dst, handler=None):
        """Run UDP proxy.
        
        Arguments:
        src -- Source IP address and port string. I.e.: '127.0.0.1:8000'
        dst -- Destination IP address and port. I.e.: '127.0.0.1:8888'
        """
        self._src_endpoint = src
        self._dst_endpoint = dst
        self._handler = LogHandler()
        if handler:
            self._handler.add_next(handler)


    def run(self):
        LOGGER.debug('Starting UDP proxy...')
        LOGGER.debug('Src: {}'.format(self._src_endpoint))
        LOGGER.debug('Dst: {}'.format(self._dst_endpoint))
        
        proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        proxy_socket.bind(UDPProxy.parse_endpoint(self._src_endpoint))
        
        client_address = None
        server_address = UDPProxy.parse_endpoint(self._dst_endpoint, True)
        LOGGER.debug(' [*] {}'.format(server_address[0]))
        
        LOGGER.debug('Looping proxy (press Ctrl-Break to stop)...')
        while True:
            data, address = proxy_socket.recvfrom(BUFFER_SIZE)
            
            if client_address == None:
                client_address = address
                LOGGER.info("Client {} connected!".format(client_address))

            if address == client_address:
                fwd_address = server_address
                direction = UDPProxy.PacketDirection.CLIENT_TO_SERVER
            elif address == server_address:
                fwd_address = client_address
                direction = UDPProxy.PacketDirection.SERVER_TO_CLIENT
            else:
                LOGGER.error('Unknown address: {}'.format(str(address)))
                assert(False)

            data = self._handler.handle(data, direction)
            if data:
                proxy_socket.sendto(data, fwd_address)



