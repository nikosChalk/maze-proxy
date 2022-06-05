

from __future__ import annotations
from typing import Any, Optional, Tuple
from pwnlib.tubes import listen
import threading
import logging
import socket
import time
import copy
import os
import proxy
import maze

LOGGER = logging.getLogger()

class CipherSuiteHandlers:
    class DecryptionHandler(proxy.AbstractHandler):
        def __init__(self, outer):
            super().__init__()
            self._outer = outer

        def handle(self, packet, direction, *args, **kwargs):
            plaintext_packet = maze.decrypt_data(packet)
            self._outer._current_key = (packet[0], packet[1])
            return super().handle(plaintext_packet, direction, *args, **kwargs)

    class EncryptionHandler(proxy.AbstractHandler):
        def __init__(self, outer):
            super().__init__()
            self._outer = outer
        
        def handle(self, packet, direction, *args, **kwargs):
            ciphertext_packet = maze.encrypt_data(packet, *self._outer._current_key)
            return super().handle(ciphertext_packet, direction, *args, **kwargs)
    
    def __init__(self):
        self._current_key = (None, None) # rand1, rand2
        self.decryptionHandler = self.DecryptionHandler(self)
        self.encryptionHandler = self.EncryptionHandler(self)


class MazeParsingHandler(proxy.AbstractHandler):
    class_mapping = {
        proxy.UDPProxy.PacketDirection.CLIENT_TO_SERVER: {
            ord('L')    :   maze.Login_client,
            ord('<')    :   maze.HeartBeat_client,
            ord('E')    :   maze.Emoji_client,
            ord('P')    :   maze.Position_client
        },
        proxy.UDPProxy.PacketDirection.SERVER_TO_CLIENT: {
            ord('L')    :   maze.LoginConfirm_server,
            ord('<')    :   maze.HeartBeat_server,
            ord('E')    :   maze.Emoji_server,
            ord('T')    :   maze.Teleport_server,
            ord('C')    :   maze.Flag_server,
            ord('D')    :   maze.Death_server,
            ord(' ')    :   maze.Respawn_server
        }
    }

    def handle(self, packet, direction, *args, **kwargs):
        parsed = None
        control_byte = packet[0]
        packet_cls = MazeParsingHandler.class_mapping[direction].get(control_byte, None)
        if packet_cls:
            parsed = packet_cls(packet)

        return super().handle(packet, direction, parsed=parsed, *args, **kwargs)

class MazeDispatchHandler(proxy.AbstractHandler):
    #TODO: add more
    def Login_client_dispatcher(self, login):
        with self._lock:
            self.usersecret = login.usersecret
            self.username   = login.username

    def HeartBeat_client_dispatcher(self, heartbeat):
        with self._lock:
            self.time = heartbeat.time

    def Emoji_client_dispatcher(self, emoji):
        pass
    def Position_client_dispatcher(self, position):
        pass



    def LoginConfirm_server_dispatcher(self, loginConfirm):
        with self._lock:
            self.uid = loginConfirm.uid

    def HeartBeat_server_dispatcher(self, heartbeat):
        with self._lock:
            if self.start_server_time is None:
                self.start_server_time = heartbeat.servertime
            self.server_time = (heartbeat.servertime - self.start_server_time) / 100.0

    def Emoji_server_dispatcher(self, emoji):
        pass
    def Teleport_server_dispatcher(self, teleport):
        pass
    def Flag_server_dispatcher(self, flag):
        pass
    def Death_server_dispatcher(self, death):
        pass
    def Respawn_server_dispatcher(self, respawn):
        pass

    def __init__(self):
        super().__init__()
        self.start_server_time = None
        self.dispatcher = {
            maze.Login_client       :   self.Login_client_dispatcher,
            maze.HeartBeat_client   :   self.HeartBeat_client_dispatcher,
            maze.Emoji_client       :   self.Emoji_client_dispatcher,
            maze.Position_client    :   self.Position_client_dispatcher,

            maze.LoginConfirm_server:   self.LoginConfirm_server_dispatcher,
            maze.HeartBeat_server   :   self.HeartBeat_server_dispatcher,
            maze.Emoji_server       :   self.Emoji_server_dispatcher,
            maze.Teleport_server    :   self.Teleport_server_dispatcher,
            maze.Flag_server        :   self.Flag_server_dispatcher,
            maze.Death_server       :   self.Death_server_dispatcher,
            maze.Respawn_server     :   self.Respawn_server_dispatcher,
        }
        self._lock = threading.Lock()

    def handle(self, packet, direction, *args, **kwargs):
        parsed = kwargs['parsed']
        if parsed:
            self.dispatcher[parsed.__class__](parsed)
        else:
            LOGGER.warning("Unknown packet with control byte %02x" % (packet[0]))
        return super().handle(packet, direction, *args, **kwargs)


class ParsedLogHandler(proxy.AbstractHandler):
    def __init__(self, blacklist=[]):
        super().__init__()
        self._blacklist = blacklist

    def handle(self, packet, direction, *args, **kwargs):
        parsed=kwargs['parsed']
        if parsed and (parsed.__class__ not in self._blacklist):
            LOGGER.log(logging.INFO, "  " + str(parsed), )
        return super().handle(packet, direction, *args, **kwargs)


class MyMazeDispatchHandler(MazeDispatchHandler):
    
    def __init__(self):
        super().__init__()
        self._last_Position_client = None

    def Position_client_dispatcher(self, position):
        #TODO: this should be done only based on our secret
        with self._lock:
            self._last_Position_client = position

    def get_last_Position_client(self):
        with self._lock:
            res = copy.deepcopy(self._last_Position_client)
        return res

class MazeProxy(proxy.UDPProxy):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        blacklist = [maze.HeartBeat_client, maze.HeartBeat_server] # filter out heartbeats from logs
        def log_condition_cb(packet, direction, *args, **kwargs):
            parsed = kwargs['parsed']
            if not parsed:  # log all unknown packets
                return True
            return parsed.__class__ not in blacklist

        cipherSuiteHandlers = CipherSuiteHandlers()
        self._myMazeDispatchHandler = MyMazeDispatchHandler()
        self.append_handler(cipherSuiteHandlers.decryptionHandler) \
            .append_handler(MazeParsingHandler()) \
            .append_handler(proxy.LogShortHexHandler(log_condition_cb)) \
            .append_handler(ParsedLogHandler(blacklist)) \
            .append_handler(self._myMazeDispatchHandler) \
            .append_handler(cipherSuiteHandlers.encryptionHandler)

    def run(self):
        injector_thread = threading.Thread(target=self.command_injector)
        injector_thread.start()
        super().run()
        injector_thread.join()

    def command_injector(self):
        usersecret = None
        def wait_for_client():
            l = listen.listen(12345, '127.0.0.1', 'ipv4')
            l.wait_for_connection()
            return l
        
        def read_command(l):
            try:
                return l.recvline().decode('ascii').strip()
            except EOFError as err:
                return None
        
        def dispatch_cmd(cmd):
            nonlocal usersecret

            rand1, rand2 = (0xC0, 0xFE) #COFE!
            if usersecret is None:
                with self._myMazeDispatchHandler._lock:
                    usersecret = self._myMazeDispatchHandler.usersecret
            
            plaintext_packet, direction = (None, None)
            if cmd.startswith("reltp"):    # reltp X Y Z 
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
            elif cmd.startswith("emojis exp"): # emojis explore
                for emoji_id in range (0,256):
                    time.sleep(3.5)
                    emoji = maze.Emoji_client.construct(usersecret, emoji_id)
                    encrypted_packet = maze.encrypt_data(emoji.serialize(), 0xC0, 0xFE)
                    self.inject_packet(encrypted_packet, direction = proxy.UDPProxy.PacketDirection.CLIENT_TO_SERVER)
            elif cmd.startswith("emoji"):   # emoji <id>
                emoji_id = int(cmd.split()[1:][0])
                if emoji_id < 0 or emoji_id > 255:
                    LOGGER.warning("[injector] Emoji out of range for command: " + cmd)
                    return False
                plaintext_packet = maze.Emoji_client.construct(usersecret, emoji_id).serialize()
                direction = proxy.UDPProxy.PacketDirection.CLIENT_TO_SERVER
            else:
                LOGGER.warning("[injector] Unknown command: " + cmd)
                return False
            
            if plaintext_packet:
                assert(direction)
                encrypted_packet = maze.encrypt_data(plaintext_packet, rand1, rand2)
                self.inject_packet(encrypted_packet, direction)
            return True

        last_cmd = None
        while True:
            l = wait_for_client()
            
            while True:
                cmd = read_command(l)
                if cmd == None: # client disconnected
                    break
                elif cmd == "r": # repeat
                    if last_cmd == None:
                        continue
                    cmd = last_cmd
                try:
                    success = dispatch_cmd(cmd)
                    if success:
                        last_cmd = cmd
                except Exception as ex: # gracefully handle malformed commands
                    LOGGER.warning("[injector] Exception: " + str(ex))


if __name__ == "__main__":
    os.environ["PYTHONUNBUFFERED"] = "1"
    maze.run_tests() # run the tests

    maze_proxy = MazeProxy('0.0.0.0:1337', 'original.game.liveoverflo:1337')
    maze_proxy.run()
    exit(0)
