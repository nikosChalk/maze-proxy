

import logging
import proxy

LOGGER = logging.getLogger()

class CapitalizationHandler(proxy.AbstractHandler):
    def handle(self, packet, direction, *args, **kwargs):
        new_packet = bytearray(packet)
        for i in range(len(packet)):
            b = packet[i]
            if bytes([b]).isalpha():
                new_packet[i] = ord(chr(b).upper())

        return super().handle(new_packet, direction, *args, **kwargs)

class MyProxy(proxy.UDPProxy):
    """A simple UDP proxy that changes all lowercase characters to uppercase"""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # Log all packets that do no start with a null byte
        def log_condition_cb(packet, direction, *args, **kwargs):
            return packet[0] != 0x00

        self.append_handler(proxy.LogShortHexHandler(log_condition_cb, print_direction=True)) \
            .append_handler(CapitalizationHandler()) \
            .append_handler(proxy.LogShortHexHandler(log_condition_cb, print_direction=False))

if __name__ == "__main__":
    proxy = MyProxy('0.0.0.0:1337', 'original.game.liveoverflo:1337')
    proxy.run()
