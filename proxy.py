

from pwnlib.util.fiddling import hexdump
from struct import pack,unpack
from enum import Enum
import threading
import logging
import select
import socket
import copy
import os
import time

import maze

FORMAT = '%(asctime)-15s %(levelname)-7s %(message)s'
LOGLEVEL = os.environ.get('LOGLEVEL', 'INFO').upper()
CUSTOM_LOGGING_LVL=99
logging.addLevelName(CUSTOM_LOGGING_LVL, "CUSTOM_LOGGING")
logging.basicConfig(format=FORMAT, level=LOGLEVEL)
LOGGER = logging.getLogger()
BUFFER_SIZE = 1024

class UDPProxy:
    PacketAction = Enum('PacketAction', 'FORWARD DROP')
    PacketDirection = Enum('PacketDirection', 'CLIENT_TO_SERVER SERVER_TO_CLIENT')

    def __init__(self, src, dst):
        """Run UDP proxy.
        
        Arguments:
        src -- Source IP address and port string. I.e.: '127.0.0.1:8000'
        dst -- Destination IP address and port. I.e.: '127.0.0.1:8888'
        """
        self._src_endpoint = src
        self._dst_endpoint = dst

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
    
    @staticmethod
    def pretty_hexdump(data, indent_level=0):
        s = hexdump(data, groupsize=8, width=24)
        if indent_level > 0:
            lines = s.split('\n')
            lines = [' '*indent_level + l for l in lines]
            s = '\n'.join(lines)
        return s

    def pre_process(self, raw_data, direction, *args, **kwargs):
        if direction == UDPProxy.PacketDirection.CLIENT_TO_SERVER:
            log_prefix = "client --> server: "
        elif direction == UDPProxy.PacketDirection.SERVER_TO_CLIENT:
            log_prefix = "server --> client: "
        
        log_msg = log_prefix + hexdump(raw_data[:24], width=24, groupsize=8, total=False)[10:]
        if len(log_msg) > 24:
            log_msg += ' ...'
        else:
            log_msg += ' '*(24-len(raw_data)+4)
        log_msg += ' (Len %03d)' % len(raw_data)
        LOGGER.info(log_msg)

        return raw_data
    
    def handle_data_from_client(self, raw_data, *args, **kwargs):
        return raw_data, UDPProxy.PacketAction.FORWARD
    
    def handle_data_from_server(self, raw_data, *args, **kwargs):
        return raw_data, UDPProxy.PacketAction.FORWARD
    
    def post_process(self, raw_data, direction, *args, **kwargs):
        return raw_data

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
                log_prefix = "client --> server: "
                fwd_address = server_address
                direction = UDPProxy.PacketDirection.CLIENT_TO_SERVER
            elif address == server_address:
                log_prefix = "server --> client: "
                fwd_address = client_address
                direction = UDPProxy.PacketDirection.SERVER_TO_CLIENT
            else:
                LOGGER.error('Unknown address: {}'.format(str(address)))
                assert(False)

            data = self.pre_process(data, direction)

            if direction == UDPProxy.PacketDirection.CLIENT_TO_SERVER:
                data, action = self.handle_data_from_client(data)
            elif direction == UDPProxy.PacketDirection.SERVER_TO_CLIENT:
                data, action = self.handle_data_from_server(data)
            else:
                assert(False)

            if action == UDPProxy.PacketAction.FORWARD:
                data = self.post_process(data, direction)
                proxy_socket.sendto(data, fwd_address)


class MazeProxy(UDPProxy):

    def __init__(self, src, dst):
        super().__init__(src, dst)
        self.last_Position_client = None

    def handle_data_from_client(self, raw_data, *args, **kwargs):
        modified_data = raw_data
        return modified_data, UDPProxy.PacketAction.FORWARD

    def handle_data_from_server(self, raw_data, *args, **kwargs):
        modified_data = raw_data
        return modified_data, UDPProxy.PacketAction.FORWARD


if __name__ == "__main__":
    maze.run_tests() # run the tests

    proxy = MazeProxy('0.0.0.0:1337', 'original.game.liveoverflo:1337')
    proxy.run()
