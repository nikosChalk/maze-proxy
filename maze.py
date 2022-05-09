
from struct import pack,unpack
from abc import ABC, abstractmethod


def encrypt_data(data, rand1, rand2):
    '''data - bytes'''
    assert(rand1 & 0xff == rand1)
    assert(rand2 & 0xff == rand2)
    pktToSend = [None for _ in range(len(data)+2)]
    pktToSend[0] = rand1 # rand(1,0xff)
    pktToSend[1] = rand2 # rand(1,0xff)

    for i in range(len(data)):
        pktToSend[i+2] = data[i] ^ (rand1 & 0xFF)

        # both decryptions work correctly here
        # from the disassembly
        # rax = ( (pktToSend[1] + (rand1 & 0xff)) * 0x80808081) & 0xFFFFFFFFFFFFFFFF
        # rax = rax >> 0x27
        # rax = 0xFFFFFFFF ^ rax # rax = ~eax (32bit)
        # rand1 = (rand1 - rax) & 0xFFFFFFFF

        # from Ghidra's decompiler
        rand1 = pktToSend[1] + (rand1 & 0xff)
        rand1 = rand1 + (rand1 // 0xff)
    return bytes(pktToSend)

def decrypt_data(data):
    '''data - bytes'''
    decryptedPkt = [None for _ in range(len(data) - 2)]
    rand1 = data[0]
    rand2 = data[1]

    for i in range(len(decryptedPkt)):
        decryptedPkt[i] = (rand1 & 0xFF) ^ data[i+2]
        rand1 = (rand1 & 0xff) + rand2
        rand1 = rand1 + (rand1 // 0xff)
    return bytes(decryptedPkt)


class MazePacket(ABC):
    pass

class HeartBeat_client(MazePacket):
    '''
        [0]     : '<'
        [1]     : '3'
        [02:10] : Partial user secret == SHA256(<secret on login>)[0:8]. The full hash is 32 bytes
    '''
    def __init__(self, data):
        '''usersecret - Partial user secret. 8 bytes'''
        self.usersecret = data[2:10]
        #FIXME: time

    def __str__(self):
        return "[{}] usersecret={}".format(type(self).__name__, self.usersecret.hex())

class Position_client(MazePacket):
    '''
        [0]     : 'P'
        [1:9]   : usersecret[0:8]
        [9:17]  : some kind of servermanager->time transformation
        [17:21] : (__this->fields).position.fields.x * 10000.0
        [21:25] : (__this->fields).position.fields.y * 10000.0
        [25:29] : (__this->fields).position.fields.z * 10000.0
        [29:33] : (__this->fields).eulerAngles.fields.x * 10000.0
        [33:37] : (__this->fields).eulerAngles.fields.y * 10000.0
        [37:41] : (__this->fields).eulerAngles.fields.z * 10000.0
        [41]    : (__this->fields).trigger;
        [42]    : (uint8_t) (__this->fields).groundedblend;
        [43]    : ??
        [44]    : (uint8_t) (__this->fields).notgroundedblend;
        [45]    : (uint8_t) isFalling?                          # 0x00 if not falling. 0xFF if falling

        servermanager->trigger : uint8_t. See the ServerManager$$setTriggerXXX functions
            * grounded      = trigger & (1 << 0);
            * notGrounded   = trigger & (1 << 1);
            * attack1       = trigger & (1 << 2);
            * attack2       = trigger & (1 << 3);
            * groundedWall  = trigger & (1 << 4);
            * death         = trigger & (1 << 5);
    '''
    def __init__(self, data):
        assert(data[0] == ord('P'))
        self.data = data
        self.usersecret = data[1:9]
        # position is stored as float in ServerManager, but it transmits it as (int)(position * 10000.0)
        self.positionX = unpack("<i", data[17:21])[0] / 10000.0
        self.positionY = unpack("<i", data[21:25])[0] / 10000.0
        self.positionZ = unpack("<i", data[25:29])[0] / 10000.0

        self.eulerAnglesX = unpack("<i", data[29:33])[0] / 10000.0
        self.eulerAnglesY = unpack("<i", data[33:37])[0] / 10000.0
        self.eulerAnglesZ = unpack("<i", data[37:41])[0] / 10000.0

        self.trigger = data[41]

    def __str__(self):
        return "[{}] usersecret={} (x,y,z)=({:3.3f}, {:3.2f}, {:3.2f}) euler=({:3.2f}, {:3.2f}, {:3.2f})".format(
            type(self).__name__, self.usersecret.hex(),
            self.positionX, self.positionY, self.positionZ,
            self.eulerAnglesX, self.eulerAnglesY, self.eulerAnglesZ
        )
    
    def serialize(self):
        bs  = b'P'
        bs += self.usersecret
        bs += self.data[9:17]
        bs += pack("<i", int(self.positionX * 10000.0)) 
        bs += pack("<i", int(self.positionY * 10000.0))
        bs += pack("<i", int(self.positionZ * 10000.0))
        bs += pack("<i", int(self.eulerAnglesX * 10000.0))
        bs += pack("<i", int(self.eulerAnglesY * 10000.0)) 
        bs += pack("<i", int(self.eulerAnglesZ * 10000.0))
        bs += bytes([self.trigger])
        bs += self.data[42:]

        #fixme#
        # bs[45] = 
        #####
        return bs

class Teleport_server(MazePacket):
    '''
    [0]     : 'T'
    [1]     : (__this->fields).teleport_instant
    [2:6]   : x         # (__this->fields).teleport_player_x = x / 10000.0
    [6:10]  : y         # (__this->fields).teleport_player_y = y / 10000.0
    [10:14] : z         # (__this->fields).teleport_player_z = z / 10000.0
    '''
    def __init__(self, data):
        assert(data[0] == ord('T'))
        self.data = data
        self.teleport_instant = data[1]
        self.teleport_player_x = unpack("<i", data[2:6])[0] / 10000.0
        self.teleport_player_y = unpack("<i", data[6:10])[0] / 10000.0
        self.teleport_player_z = unpack("<i", data[10:14])[0] / 10000.0
    
    def __str__(self):
        return "[{}] tele={} (x,y,z)=({:3.2f}, {:3.2f}, {:3.2f})".format(
            type(self).__name__, self.teleport_instant,
            self.teleport_player_x, self.teleport_player_y, self.teleport_player_z
        )
    
    def serialize(self):
        bs  = b'T'
        bs += bytes([self.teleport_instant])
        bs += pack("<i", int(self.teleport_player_x * 10000.0))
        bs += pack("<i", int(self.teleport_player_y * 10000.0))
        bs += pack("<i", int(self.teleport_player_z * 10000.0))
        return bs

class HeartBeat_server(MazePacket):
    '''
        [0]     : <cmd byte> == 0x3c
        [1]     : '3'
        [02:10] : int64 # to compute RTT (ping)
        [10:18] : int64 # servermanager->start_server_time or smth
    '''
    def __init__(self, data):
        #FIXME:
        pass

    def __str__(self):
        return "[{}]".format(type(self).__name__)


def run_tests():
    groundtruth_hex_stream = "9901a5a921f31d85f7aca07d800da7a6a7a8a9aa" # sample heartbeat packet from wireshark

    print("Encryption test:")
    plaintext = b'<3' + bytes.fromhex("BA6F801B680C01DF")
    expected_ciphertext = bytes.fromhex(groundtruth_hex_stream)
    ciphertext = encrypt_data(plaintext, expected_ciphertext[0], expected_ciphertext[1])
    print("Expected: " + expected_ciphertext.hex())
    print("Output  : " + ciphertext.hex())
    print()

    print("Decryption test:")
    ciphertext = bytes.fromhex(groundtruth_hex_stream)
    expected_plaintext = b'<3' + bytes.fromhex("BA6F801B680C01DF")
    plaintext = decrypt_data(ciphertext)
    
    print("Expected: " + expected_plaintext.hex())
    print("Output  : " + plaintext.hex())
    print()

if __name__ == "__main__":
    run_tests()