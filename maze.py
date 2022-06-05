
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


MAPPED_EMOJIS = {   # Emojis that are mapped to keys
    '1': 0x17,  # KeyCode '1'
    '2': 0x16,  # KeyCode '2'
    '3': 0x04,  # KeyCode '3'
    '4': 0x12,  # KeyCode '4'
    '5': 0x0c,  # KeyCode '5'
    '6': 0x0a,  # KeyCode '6'
    '7': 0x14,  # KeyCode '7'
    '8': 0x0e,  # KeyCode '8'
    '9': 0x03,  # KeyCode '9'
    '0': 0x08   # KeyCode '0'
}
ALL_EMOJIS = list(range(1,25))  # emoji 13 is a flag

class MazePacket(ABC):
    #TODO: add @classmethod construct() method. See factory pattern
    pass

# usersecret = SHA256(<secret on login screen>)[0:8]


class Login_client(MazePacket):
    '''
        Packet is always 42 bytes long
        [0]     : 'L'
        [01:09] : (__this->fields).usersecret
        [9]     : (__this->fields).username.m_stringLength
        [10:10+username_length] : (__this->fields).username
        [10+username_length:42] : garbage
    '''

    def __init__(self, data):
        assert(data[0] == ord('L'))
        assert(len(data) == 42)
        self.usersecret = data[1:9]
        username_len = data[9]
        self.username = data[10:10+username_len].decode('ascii')

    def __str__(self):
        return "[{}] usersecret={} username={}".format(type(self).__name__, self.usersecret.hex(), self.username)


class HeartBeat_client(MazePacket):
    '''
        [0]     : '<'
        [1]     : '3'
        [02:10] : (__this->fields).usersecret
        [10:18] : (__this->fields).time * 10000.0
    '''
    def __init__(self, data):
        assert(data[:2] == b'<3')
        self.usersecret = data[2:10]
        self.time = unpack("<q", data[10:18])[0] / 10000.0

    def __str__(self):
        return "[{}] usersecret={} time={:.3f}secs".format(type(self).__name__, self.usersecret.hex(), self.time)

class Emoji_client(MazePacket):
    '''
        [0]     : 'E'
        [01:09] : (__this->fields).usersecret
        [9]     : emoji
    '''
    def __init__(self, data):
        assert(data[0] == ord('E'))
        assert(len(data) == 10)
        self.usersecret = data[1:9]
        self.emoji = data[9]

    def __str__(self):
        return "[{}] usersecret={} emoji={}".format(type(self).__name__, self.usersecret.hex(), self.emoji)
    
    @classmethod
    def construct(cls, usersecret, emoji):
        obj = cls(b'E'*10)  # doesn't matter. FIXME:
        obj.usersecret = usersecret
        obj.emoji = emoji
        return obj

    def serialize(self):
        bs  = b'E'
        bs += self.usersecret
        bs += bytes([self.emoji])
        return bs

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
    

class LoginConfirm_server(MazePacket):
    '''
        [0]     : 'L'
        [1:5]   : (__this->fields).uid
        [5:7]   : (__this->fields).unlocks
        [7]     : version   # Gets compared with (__this->fields).version
    '''

    def __init__(self, data):
        assert(data[0] == ord('L'))
        self.uid = unpack("<I", data[1:5])[0]
        self.unlocks = unpack("<H", data[5:7])[0]
        self.version = data[7]

    def __str__(self):
        return "[{}] uid={} unlocks=0x{:04x} version=0x{:x}".format(
            type(self).__name__, self.uid, self.unlocks, self.version
        )


class HeartBeat_server(MazePacket):
    '''
        [0]     : '<'
        [1]     : '3'
        [02:10] : client_time # to compute RTT (ping).
            The client_time is the time present in the last received HeartBeat_client packet
            (__this->fields).heartbeat_roundtrip = (__this->fields).time - (client_time / 10000.0)
        [10:18] : server_time
            Initializes (__this->fields).start_server_time on the first packet received
            Subsequent values are used to calculate (__this->fields).server_time
            100ticks of this counter correspond to 1 second.
            server_time / 100 == how long the server has been running in seconds
    '''
    def __init__(self, data):
        assert(data[:2] == b'<3')
        self.client_time = unpack("<q", data[2:10])[0] / 10000.0
        self.servertime = unpack("<q", data[10:18])[0]

    def __str__(self):
        return "[{}] client_time={:.3f}secs servertime={:.2f}secs".format(type(self).__name__, self.client_time, (self.servertime / 100))

class Emoji_server(MazePacket):
    '''
        [0]     : 'E'
        [01:05] : uid           # Same as the uid field in the LoginConfirm_server packet
        [05:09] : servertime    # Same as the ((servertime field) / 100)) in the last HeartBeat_server packet
        [9]     : emoji         # Same as the emoji field in the corresponding Emoji_client packet
    '''
    def __init__(self, data):
        assert(data[0] == ord('E'))
        self.uid = unpack("<I", data[1:5])[0]
        self.servertime = unpack("<I", data[5:9])[0]
        self.emoji = data[9]

    def __str__(self):
        return "[{}] uid={} servertime={}secs emoji={}".format(type(self).__name__, self.uid, self.servertime, self.emoji)

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
    
    @classmethod
    def construct(cls, teleport_instant, teleport_player_x, teleport_player_y, teleport_player_z):
        obj = cls(b'T'*50)  # doesn't matter. FIXME:
        obj.teleport_instant  = teleport_instant
        obj.teleport_player_x = teleport_player_x
        obj.teleport_player_y = teleport_player_y
        obj.teleport_player_z = teleport_player_z
        obj.data = obj.serialize()
        return obj

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

class Flag_server(MazePacket):
    '''
        [0]     : 'C'
        [1:3]   : 'SCG
        Remaining data is a null-terminated flag.
    '''
    def __init__(self, data):
        assert(data[:4] == b'CSCG')
        self.flag = data.decode('ascii')

    def __str__(self):
        return "[{}] flag={}".format(type(self).__name__, self.flag)

class Death_server(MazePacket):
    def __init__(self, data):
        assert(data[0] == ord('D'))

    def __str__(self):
        return "[{}] You died".format(type(self).__name__)

class Respawn_server(MazePacket):
    def __init__(self, data):
        assert(data[0] == ord(' '))
        self.msg = data.decode('ascii')

    def __str__(self):
        return "[{}] Player respawned: {}".format(type(self).__name__, self.msg)

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