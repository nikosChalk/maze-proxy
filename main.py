

from __future__ import annotations
from typing import Any, Optional, Tuple
import proxy
import maze

LOGGER=proxy.LOGGER

class MazeProxy(proxy.UDPProxy):

    class DecryptionHandler(proxy.AbstractHandler):
        def __init__(self, proxy):
            super().__init__()
            self._proxy = proxy

        def handle(self, packet, direction) -> bytes:
            plaintext_packet = maze.decrypt_data(packet)
            self._proxy._current_key = (packet[0], packet[1])

            return super().handle(plaintext_packet, direction)

    class EncryptionHandler(proxy.AbstractHandler):
        def __init__(self, proxy):
            super().__init__()
            self._proxy = proxy
        
        def handle(self, packet, direction) -> bytes:
            ciphertext_packet = maze.encrypt_data(packet, *self._proxy._current_key)

            return super().handle(ciphertext_packet, direction)

    def __init__(self, *args, **kwargs):
        decryptionHandler = self.DecryptionHandler(self)
        encryptionHandler = self.EncryptionHandler(self)

        decryptionHandler.add_next(encryptionHandler)
        super().__init__(handler=decryptionHandler, *args, **kwargs)
        self._last_Position_client = None
        self._current_key = (None, None)


if __name__ == "__main__":
    maze.run_tests() # run the tests

    proxy = MazeProxy('0.0.0.0:1337', 'original.game.liveoverflo:1337')
    proxy.run()
