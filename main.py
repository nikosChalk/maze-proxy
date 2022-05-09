

from __future__ import annotations
from typing import Any, Optional, Tuple
from pwnlib.tubes import listen
import threading
import logging
import socket
import copy
import os
import proxy
import maze

LOGGER=proxy.LOGGER

class CipherSuiteHandlers:
    class DecryptionHandler(proxy.AbstractHandler):
        def __init__(self, outer):
            super().__init__()
            self._outer = outer

        def handle(self, packet, direction, *args, **kwargs) -> bytes:
            plaintext_packet = maze.decrypt_data(packet)
            self._outer._current_key = (packet[0], packet[1])
            return super().handle(plaintext_packet, direction, *args, **kwargs)

    class EncryptionHandler(proxy.AbstractHandler):
        def __init__(self, outer):
            super().__init__()
            self._outer = outer
        
        def handle(self, packet, direction, *args, **kwargs) -> bytes:
            ciphertext_packet = maze.encrypt_data(packet, *self._outer._current_key)
            return super().handle(ciphertext_packet, direction, *args, **kwargs)
    
    def __init__(self):
        self._current_key = (None, None) # rand1, rand2
        self.decryptionHandler = self.DecryptionHandler(self)
        self.encryptionHandler = self.EncryptionHandler(self)


class MazeParsingHandler(proxy.AbstractHandler):
    class_mapping = {
        proxy.UDPProxy.PacketDirection.CLIENT_TO_SERVER: {
            ord('<')    :   maze.HeartBeat_client,
            ord('P')    :   maze.Position_client
        },
        proxy.UDPProxy.PacketDirection.SERVER_TO_CLIENT: {
            ord('<')    :   maze.HeartBeat_server,
            ord('T')    :   maze.Teleport_server
        }
    }

    def handle(self, packet, direction, *args, **kwargs) -> bytes:
        parsed = None
        control_byte = packet[0]
        packet_cls = MazeParsingHandler.class_mapping[direction].get(control_byte, None)
        if packet_cls:
            parsed = packet_cls(packet)

        return super().handle(packet, direction, parsed=parsed, *args, **kwargs)

class MazeDispatchHandler(proxy.AbstractHandler):
    def HeartBeat_client_dispatcher(self, heartbeat):
        pass
    def Position_client_dispatcher(self, position):
        pass
    def HeartBeat_server_dispatcher(self, heartbeat):
        pass
    def Teleport_server_dispatcher(self, teleport):
        pass

    def __init__(self):
        super().__init__()
        self.dispatcher = {
            maze.HeartBeat_client   :   self.HeartBeat_client_dispatcher,
            maze.Position_client    :   self.Position_client_dispatcher,
            maze.HeartBeat_server   :   self.HeartBeat_server_dispatcher,
            maze.Teleport_server    :   self.Teleport_server_dispatcher
        }

    def handle(self, packet, direction, *args, **kwargs) -> bytes:
        parsed = kwargs['parsed']
        if parsed:
            self.dispatcher[parsed.__class__](parsed)
        else:
            LOGGER.warn("Unknown packet with control byte %02x" % (packet[0]))
        return super().handle(packet, direction, *args, **kwargs)


class ParsedLogHandler(proxy.AbstractHandler):
    def __init__(self, blacklist=[]):
        super().__init__()
        self._blacklist = blacklist

    def handle(self, packet, direction, *args, **kwargs) -> bytes:
        parsed=kwargs['parsed']
        if parsed and (parsed.__class__ not in self._blacklist):
            LOGGER.log(logging.INFO, "  " + str(parsed), )
        return super().handle(packet, direction, *args, **kwargs)


class MyMazeDispatchHandler(MazeDispatchHandler):
    
    def __init__(self):
        super().__init__()
        self._last_Position_client = None
        self._lock = threading.Lock()

    def Position_client_dispatcher(self, position):
        with self._lock:
            self._last_Position_client = position

    def get_last_Position_client(self):
        with self._lock:
            res = copy.deepcopy(self._last_Position_client)
        return res

class MazeProxy(proxy.UDPProxy):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        blacklist = [maze.HeartBeat_client, maze.HeartBeat_server]
        def log_condition_cb(packet, direction, *args, **kwargs):
            parsed = kwargs['parsed']
            if not parsed:
                return True
            return parsed.__class__ not in blacklist

        cipherSuiteHandlers = CipherSuiteHandlers()
        self._myMazeDispatchHandler = MyMazeDispatchHandler()
        self.append_handler(cipherSuiteHandlers.decryptionHandler) \
            .append_handler(MazeParsingHandler()) \
            .append_handler(proxy.LogHandler(log_condition_cb)) \
            .append_handler(ParsedLogHandler(blacklist)) \
            .append_handler(self._myMazeDispatchHandler) \
            .append_handler(cipherSuiteHandlers.encryptionHandler)

    def run(self):
        injector_thread = threading.Thread(target=self.command_injector)
        injector_thread.start()
        super().run()
        injector_thread.join()

    def command_injector(self):
        def wait_for_client():
            l = listen.listen(12345, '127.0.0.1', 'ipv4')
            l.wait_for_connection()
            return l
        
        def read_command(l):
            try:
                return l.recvline().decode('ascii').strip()
            except EOFError as err:
                return None
        
        last_plaintext_packet = None
        last_direction = None
        rand1, rand2 = (0xC0, 0xFE) #COFE!
        def dispatch_cmd(cmd):
            nonlocal last_plaintext_packet, last_direction, rand1, rand2

            plaintext_packet, direction = (None, None)
            if cmd == "r": # repeat
                plaintext_packet = last_plaintext_packet
                direction = last_direction
            elif cmd.startswith("reltp"):    # reltp X Y Z 
                x, y, z = [float(x) for x in cmd.split()[1:]]
                last_pos = self._myMazeDispatchHandler.get_last_Position_client()
                plaintext_packet = maze.Teleport_server.construct(
                    1, 
                    last_pos.positionX + x,
                    last_pos.positionY + y,
                    last_pos.positionZ + z
                ).serialize()
                direction = proxy.UDPProxy.PacketDirection.SERVER_TO_CLIENT
            elif cmd.startswith("tp"):    # tp X Y Z 
                x, y, z = [float(x) for x in cmd.split()[1:]]
                plaintext_packet = maze.Teleport_server.construct(
                    1, x, y, z
                ).serialize()
                direction = proxy.UDPProxy.PacketDirection.SERVER_TO_CLIENT
            else:
                LOGGER.warning("[injector] Unknown command: " + cmd)
            
            if plaintext_packet:
                assert(direction)
                encrypted_packet = maze.encrypt_data(plaintext_packet, rand1, rand2)
                self.inject_packet(encrypted_packet, direction)
                last_plaintext_packet = plaintext_packet
                last_direction = direction

        while True:
            l = wait_for_client()
            while True:
                cmd = read_command(l)
                if cmd == None: # client disconnected
                    break
                dispatch_cmd(cmd)



if __name__ == "__main__":
    os.environ["PYTHONUNBUFFERED"] = "1"
    maze.run_tests() # run the tests

    maze_proxy = MazeProxy('0.0.0.0:1337', 'original.game.liveoverflo:1337')
    maze_proxy.run()
    exit(0)
