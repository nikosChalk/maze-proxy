
from __future__ import annotations
from pwnlib.util.fiddling import hexdump
from struct import pack,unpack
from enum import Enum
import threading
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
    def handle(self, packet: Any, direction: UDPProxy.PacketDirection, *args, **kwargs) -> bytes:
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
    def handle(self, packet: Any, direction: UDPProxy.PacketDirection, *args, **kwargs) -> bytes:
        if self._next_handler:
            return self._next_handler.handle(packet, direction, *args, **kwargs)
        else:
            return packet

class NoopHandler(AbstractHandler):
    def handle(self, packet: Any, direction: UDPProxy.PacketDirection, *args, **kwargs) -> bytes:
        return super().handle(packet, direction, *args, **kwargs)

class LogHandler(AbstractHandler):

    def __init__(self, cond_cb=None):
        super().__init__()
        self._cond_cb = cond_cb

    def handle(self, packet: Any, direction: UDPProxy.PacketDirection, *args, **kwargs) -> bytes:
        if not self._cond_cb or self._cond_cb(packet, direction, *args, **kwargs):
            if direction == UDPProxy.PacketDirection.CLIENT_TO_SERVER:
                log_prefix = "client --> server: "
            elif direction == UDPProxy.PacketDirection.SERVER_TO_CLIENT:
                log_prefix = "server --> client: "
            
            log_msg = log_prefix + hexdump(packet[:24], width=24, groupsize=8, total=False)[10:]
            if len(packet) > 24:
                log_msg += ' ...'
            else:
                log_msg += ' '*(24-len(packet)+4)
            log_msg += ' (Len %03d)' % len(packet)
            LOGGER.info(log_msg)

        return super().handle(packet, direction, *args, **kwargs)

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

    class DataFwdHandler(AbstractHandler):
        def __init__(self, proxy):
            super().__init__()
            self._proxy = proxy
            self._lock = threading.Lock()   #FIXME temporary solution. Proxy should have a multi-threaded packet FIFO queue instead

        def handle(self, packet, direction, *args, **kwargs) -> bytes:
            if packet:
                with self._lock:
                    self._proxy._proxy_socket.sendto(packet, self._proxy._get_fwd_addr(direction))
            return None # data consumed

    def __init__(self, src, dst):
        """Run UDP proxy.
        
        Arguments:
        src -- Source IP address and port string. I.e.: '127.0.0.1:8000'
        dst -- Destination IP address and port. I.e.: '127.0.0.1:8888'
        """
        LOGGER.debug("Creating Proxy")
        LOGGER.debug(' [*] Src: {}'.format(src))
        LOGGER.debug(' [*] Dst: {}'.format(dst))

        self._client_address = None
        self._server_address = UDPProxy.parse_endpoint(dst, True)
        LOGGER.debug('   [*] {}'.format(self._server_address[0]))

        self._proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._proxy_socket.bind(UDPProxy.parse_endpoint(src))
        
        # Always last
        self._data_fwd_handler = self.DataFwdHandler(self)

        # first handler
        self._first_handler = self._data_fwd_handler

        # One handler before the DataFwdHandler()
        self._prelast_handler  = None
    
    def append_handler(self, handler):
        if self._first_handler == self._data_fwd_handler:
            assert(self._prelast_handler == None)
            handler.add_next(self._data_fwd_handler)
            self._first_handler = handler
        else:
            handler.add_next(self._data_fwd_handler)
            self._prelast_handler.add_next(handler)
        
        self._prelast_handler = handler
        return self

    def _get_fwd_addr(self, direction):
        if direction == UDPProxy.PacketDirection.CLIENT_TO_SERVER:
            return self._server_address
        elif direction == UDPProxy.PacketDirection.SERVER_TO_CLIENT:
            return self._client_address
        else:
            assert(False)

    def inject_packet(self, packet, direction):
        assert(len(packet) > 0)
        self._first_handler.handle(packet, direction)

    def run(self):
        LOGGER.debug('Starting UDP proxy...')
        LOGGER.debug('Looping proxy (press Ctrl-Break to stop)...')

        while True:
            data, address = self._proxy_socket.recvfrom(BUFFER_SIZE)
            
            if self._client_address == None:
                self._client_address = address
                LOGGER.info("Client {} connected!".format(self._client_address))

            if address == self._client_address:
                direction = UDPProxy.PacketDirection.CLIENT_TO_SERVER
            elif address == self._server_address:
                direction = UDPProxy.PacketDirection.SERVER_TO_CLIENT
            else:
                LOGGER.error('Unknown address: {}'.format(str(address)))
                assert(False)

            self._first_handler.handle(data, direction)


