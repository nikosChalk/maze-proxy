

from __future__ import annotations
from typing import Any, Optional, Tuple
import logging
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
    def HeartBeat_client_dispatcher(self, parsed):
        pass
    def Position_client_dispatcher(self, parsed):
        pass
    def HeartBeat_server_dispatcher(self, parsed):
        pass
    def Teleport_server_dispatcher(self, parsed):
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
    def handle(self, packet, direction, *args, **kwargs) -> bytes:
        parsed=kwargs['parsed']
        if parsed:
            LOGGER.log(logging.INFO, str(parsed), )
        return super().handle(packet, direction, *args, **kwargs)


class MazeProxy(proxy.UDPProxy):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        cipherSuiteHandlers = CipherSuiteHandlers()
        logHandler          = proxy.LogHandler()
        mazeParsingHandler  = MazeParsingHandler()
        mazeDispatchHandler = MazeDispatchHandler()

        self.append_handler(cipherSuiteHandlers.decryptionHandler) \
            .append_handler(logHandler) \
            .append_handler(mazeParsingHandler) \
            .append_handler(ParsedLogHandler()) \
            .append_handler(mazeDispatchHandler) \
            .append_handler(cipherSuiteHandlers.encryptionHandler)

        self._last_Position_client = None
        self._current_key = (None, None)


if __name__ == "__main__":
    maze.run_tests() # run the tests

    proxy = MazeProxy('0.0.0.0:1337', 'original.game.liveoverflo:1337')
    proxy.run()
