
from __future__ import annotations
from pwnlib.util.fiddling import hexdump
from enum import Enum
import queue
import logging
import socket
import select
import os

from abc import ABC, abstractmethod
from typing import Any, Optional, Tuple

FORMAT = '%(asctime)-15s %(levelname)-7s %(message)s'
LOGLEVEL = os.environ.get('LOGLEVEL', 'INFO').upper()
logging.basicConfig(format=FORMAT, level=LOGLEVEL)
LOGGER = logging.getLogger()


class Handler(ABC):
    """
    The Handler interface declares a method for building the chain of handlers.
    It also declares a method for executing a request.
    (Similar to chain of responsibility pattern)
    """

    @abstractmethod
    def add_next(self, handler: Handler) -> Handler:
        """Sets the next handler to be invoked

        Returns:
            Handler: The passed handler
        """
        pass

    @abstractmethod
    def handle(self, packet: bytes, direction: UDPProxy.PacketDirection, *args, **kwargs) -> bytes:
        """Handles the given packet by reading and/or modifying it.

        Args:
            packet (bytes): The packet to handle
            direction (UDPProxy.PacketDirection): The direction that the packer is travelling towards to.

        Returns:
            bytes: The modified packet
        """
        pass

class AbstractHandler(Handler):
    """
    The default chaining behavior is implemented here. It is to forward the packet to the next handler
    """

    def __init__(self):
        super().__init__()
        self._next_handler: Handler = None

    def add_next(self, handler: Handler) -> Handler:
        self._next_handler = handler

        # Returning a handler from here will let us link handlers in a convenient way like this:
        # monkey.add_next(squirrel).add_next(dog)
        return handler

    @abstractmethod
    def handle(self, packet: bytes, direction: UDPProxy.PacketDirection, *args, **kwargs) -> bytes:
        if self._next_handler:
            return self._next_handler.handle(packet, direction, *args, **kwargs)
        else:
            return packet

class NoopHandler(AbstractHandler):
    """Handler that is a no-op on the packet"""
    def handle(self, packet: bytes, direction: UDPProxy.PacketDirection, *args, **kwargs) -> bytes:
        return super().handle(packet, direction, *args, **kwargs)

class LogShortHexHandler(AbstractHandler):
    """
    Logs the packet if a condition is satisfied.
    For the packet, its directions, its first 24 bytes in hexdump format, and its length are logged.
    """

    def __init__(self, cond_cb=None):
        """
        Args:
            cond_cb (lambda packet, direction, *args, **kwargs : bool, optional): A callable that gets passed
            the parameters of the handle() to determine if the packet will be logged or not.
            Default value allows the packet to be always logged.
        """
        super().__init__()
        self._cond_cb = cond_cb

    def handle(self, packet, direction, *args, **kwargs):
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
    """
    An implementation of a simple, yet flexible UDP proxy.
    It currently supports 1-to-1 client-server connections, as UDP is not connection-oriented.
    """

    PacketAction = Enum('PacketAction', 'FORWARD DROP')
    PacketDirection = Enum('PacketDirection', 'CLIENT_TO_SERVER SERVER_TO_CLIENT')
    BUFFER_SIZE = 1024

    @staticmethod
    def parse_endpoint(ip:str, resolve=False) -> Tuple[str, int]:
        """Parses IP string and returns (ip, port) tuple.

        Args:
            ip (str): "address:port" string. I.e.: '127.0.0.1:8000'.
            resolve (bool, optional): If the given ip should be treated as a hostname and has
            to be resolved first. Defaults to False.

        Returns:
            Tuple[str, int]: (ip, port)
        """
        ip, port = ip.strip().split(':')
        if resolve:
            ip = socket.gethostbyname(ip)
        return (ip, int(port))

    class DataFwdHandler(AbstractHandler):
        """Handler that sends the packet to its destination via a socket"""
        def __init__(self, proxy: UDPProxy):
            super().__init__()
            self._proxy = proxy

        def handle(self, packet, direction, *args, **kwargs):
            self._proxy._proxy_socket.sendto(packet, self._proxy._get_fwd_addr(direction))
            return packet # We must always be last in chain

    def __init__(self, src:str, dst:str):
        """Creates the UDP proxy.
        The proxy is not listening for packets until run() is invoked.
        
        Arguments:
        src -- Source IP address and port string. I.e.: '127.0.0.1:8000'
        dst -- Destination IP address and port. I.e.: '127.0.0.1:8888'
        """
        LOGGER.debug("Creating Proxy")
        LOGGER.debug(' [*] Src: {}'.format(src))
        LOGGER.debug(' [*] Dst: {}'.format(dst))

        # (ip, port) tuples
        self._client_address = None
        self._server_address = UDPProxy.parse_endpoint(dst, True)
        LOGGER.debug('   [*] {}'.format(self._server_address[0]))

        self._proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._proxy_socket.bind(UDPProxy.parse_endpoint(src))

        # queue for injected packets
        self._injection_queue = queue.SimpleQueue()
        
        # Always last
        self._data_fwd_handler = self.DataFwdHandler(self)

        # first handler
        self._first_handler = self._data_fwd_handler

        # One handler before the DataFwdHandler()
        self._prelast_handler  = None
    
    def append_handler(self, handler: AbstractHandler) -> UDPProxy:
        """Appends the given handler at the end of the processing queue

        Returns:
            UDPProxy: self. So that you can chain multiple invocations. 
            e.g.: proxy.append_handler(foo).append_handler(bar) 
            This results in the processing order: input --> foo --> bar --> send to destination
        """
        if self._first_handler == self._data_fwd_handler:
            assert(self._prelast_handler == None)
            handler.add_next(self._data_fwd_handler)
            self._first_handler = handler
        else:
            handler.add_next(self._data_fwd_handler)
            self._prelast_handler.add_next(handler)
        
        self._prelast_handler = handler
        return self

    def _get_fwd_addr(self, direction: UDPProxy.PacketDirection) -> Tuple[str, int]:
        if direction == UDPProxy.PacketDirection.CLIENT_TO_SERVER:
            return self._server_address
        elif direction == UDPProxy.PacketDirection.SERVER_TO_CLIENT:
            return self._client_address
        else:
            assert(False)

    def inject_packet(self, packet: bytes, direction: UDPProxy.PacketDirection) -> None:
        """Injects the given packet into the communication between client and server.
        The packet will be processed normally by the handler chain.
        Useful if you want to inject spoofed packets.

        Args:
            packet (bytes): The packet to inject
            direction (UDPProxy.PacketDirection): The direction that the packet will travel to
        """
        assert(len(packet) > 0)
        self._injection_queue.put((packet, direction))

    def run(self) -> None:
        """Starts the proxy and listens for incoming packets. This method never returns."""

        LOGGER.debug('Starting UDP proxy...')
        LOGGER.debug('Looping proxy (press Ctrl-Break to stop)...')

        def handle_incoming_data():
            data, address = self._proxy_socket.recvfrom(self.BUFFER_SIZE)
            
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

        def handle_injected_packet():
            data, direction = self._injection_queue.get_nowait()  # since we are the sole consumer, it should not raise
            self._first_handler.handle(data, direction)

        while True:
            # wait for data
            rlist, _, _ = select.select([self._proxy_socket], [], [], 0.100) # timeout is in seconds
            if len(rlist) > 0 :
                handle_incoming_data()
            if not self._injection_queue.empty():
                handle_injected_packet()


