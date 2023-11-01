import enum
from ctypes import Structure, addressof, c_uint8, c_uint16, c_uint32, memmove, sizeof

import crcmod
from scapy.compat import binascii

# cap packets and parse protocol
# common cap sniff data
# packets check and summary
# return bool filter functions


class pduType(enum.Enum):
    MCPA = 1
    MCPC = 3


pduTypeTable = {1: "MCPA", 3: "MCPC"}


class cmdFlag(enum.Enum):
    NONE = 0x0
    REPORT = 0x01
    GET = 0x02
    SET = 0x03
    CHANGE_UPGRADE_TYPE = 0x10
    SWITCH_SW = 0x11


cmdFlagTable = {
    0x0: "NONE",
    0x01: "REPORT",
    0x02: "GET",
    0x03: "SET",
    0x10: "CHANGE_UPGRADE_TYPE",
    0x11: "SWITCH_SW",
}


class replayFlag(enum.Enum):
    OK = 0x00
    EXEC_COND = 0x01
    CMD_ERR = 0x02
    LENGTH_ERR = 0x03
    CRC_ERR = 0x04
    MCP_TYPE_ERR = 0x05
    CMD = 0xFF


replayFlagTable = {
    0x00: "DEVICE REPLAY",
    0x01: "EXEC_COND",
    0x02: "CMD_ERR",
    0x03: "LENGTH_ERR",
    0x04: "CRC_ERR",
    0x05: "MCP_TYPE_ERR",
    0xFF: "OMC REQUEST",
}


class vpIneractFlag(enum.Enum):
    EXEC_OK = 0x0
    DEV_BUSY = 0x01
    NORMAL_CMD = 0x80


vpIneractFlagTable = {0x0: "EXEC_OK", 0x01: "DEV_BUSY", 0x80: "NORMAL_CMD"}


class ispIndexTable(enum.Enum):
    REPORT_TYPE = 0x0141
    PARA_LIST = 0x9


class reportType(enum.Enum):
    ALARM_REPORT = 1
    OPEN_REPORT = 2
    CHECK_REPORT = 3
    FAULT_REPAIR_REPORT = 4
    CONFIG_REPORT = 5
    LOGIN_REPORT = 6
    HEART_REPORT = 7
    UPDATE_SW_REPORT = 8
    PS_LOGIN_FAILED_REPORT = 9
    BATCH_END_REPORT = 10
    REBOOT_ABNORMAL = 11


reportFlagTable = {
    1: "ALARM_REPORT",
    2: "OPEN_REPORT",
    3: "CHECK_REPORT",
    4: "FAULT_REPAIR_REPORT",
    5: "CONFIG_REPORT",
    6: "LOGIN_REPORT",
    7: "HEART_REPORT",
    8: "UPDATE_SW_REPORT",
    9: "PS_LOGIN_FAILED_REPORT",
    10: "BATCH_END_REPORT",
    11: "REBOOT_ABNORMAL",
}


class IspCommonField(Structure):
    _pack_ = 1
    _fields_ = [
        ("start", c_uint8),
        ("ap_layer", c_uint8),
        ("vp_layer", c_uint8),
        ("station_numbers", c_uint32),
        ("device_numbers", c_uint8),
        ("packets_numbers", c_uint16),
        ("vp_layer_interact", c_uint8),
        ("mcp_layer", c_uint8),
        ("cmd", c_uint8),
        ("response", c_uint8),
    ]


class mcpa_tag(Structure):
    _pack_ = 1
    _fields_ = [("len", c_uint8), ("tag", c_uint16)]
    value: bytes


class mcpc_tag(Structure):
    _pack_ = 1
    _fields_ = [("len", c_uint8), ("tag", c_uint32)]
    value: bytes


class mcpa_idx(Structure):
    _pack_ = 1
    _fields_ = [("tag", c_uint16)]


class mcpc_idx(Structure):
    _pack_ = 1
    _fields_ = [("tag", c_uint32)]


class IspEndField(Structure):
    _pack_ = 1
    _fields_ = [("crc", c_uint16), ("end", c_uint8)]


# crc code calu
# isp protocol framework
# only for text parse protocol


class IspProtocolForLog(Structure):
    __IspCommonField__ = IspCommonField()
    __IspCommonFieldLen__ = sizeof(__IspCommonField__)
    __IspEndField__ = IspEndField()
    __IspEndFieldLen__ = sizeof(__IspEndField__)
    __crc16__ = 0x0
    __crcFlag__ = False
    __pdu_type: pduType

    def deserdes(self, msg: bytes):
        msg = msg.lower()
        esc_msg = self.__escape_recv_packets(msg)
        esc_msg = "7e" + esc_msg + "7e"
        esc_msg = esc_msg.encode()

        memmove(
            addressof(self.__IspCommonField__),
            binascii.unhexlify(esc_msg),
            self.__IspCommonFieldLen__,
        )

        ta = 8
        if self.__IspCommonField__.mcp_layer == 3:
            self.__pdu_type = pduType.MCPC
            ta = 8
        elif self.__IspCommonField__.mcp_layer == 1:
            self.__pdu_type = pduType.MCPA
            ta = 4

        start = self.__IspCommonFieldLen__ * 2
        end = -6
        self.__pduList__ = []
        pdu_part = esc_msg[start:end]
        __len = len(pdu_part)
        _start = 0
        _pdu: bytes

        while __len > 0:
            if self.__pdu_type == pduType.MCPA:
                _tmp = mcpa_tag()
                _pdu = pdu_part[_start : _start + 2]
                memmove(
                    addressof(_tmp),
                    binascii.unhexlify(pdu_part[_start : _start + ta]),
                    3,
                )
                _tmp.value = pdu_part[
                    _start + ta + 2 : _start + ta + 2 + int(_pdu, 16) * 2 - ta - 2
                ]
                self.__pduList__.append(_tmp)
                __len = __len - int(_pdu, 16) * 2
                _start = _start + int(_pdu, 16) * 2
            elif self.__pdu_type == pduType.MCPC:
                _tmp = mcpc_tag()
                _pdu = pdu_part[_start : _start + 2]
                memmove(
                    addressof(_tmp),
                    binascii.unhexlify(pdu_part[_start : _start + ta]),
                    5,
                )
                _tmp.value = pdu_part[
                    _start + ta + 2 : _start + ta + 2 + int(_pdu, 16) * 2 - ta - 2
                ]
                self.__pduList__.append(_tmp)
                __len = __len - int(_pdu, 16) * 2
                _start = _start + int(_pdu, 16) * 2
            else:
                break

        # Payload pdu part
        # end of payload data caluication
        memmove(
            addressof(self.__IspEndField__),
            binascii.unhexlify(esc_msg[-6:]),
            self.__IspEndFieldLen__,
        )
        self.__crc16__ = self.__crc16(binascii.unhexlify(esc_msg[2:-6]))
        if self.__IspEndField__.crc != self.__crc16__:
            print("ISP crc code parse error.drop this packets ... ...")
            return False
        else:
            return True

    def __crc16(self, code: bytes):
        return crcmod.mkCrcFun(0x11021, rev=False, initCrc=0, xorOut=0x0)(code)

    def __escape_recv_packets(self, msg: bytes):
        if msg[0:2] != b"7e" or msg[-2:] != b"7e":
            print("escape packets error")
        return msg[2:-2].decode().replace("5e5d", "5e").replace("5e7d", "7e")

    def payload(self):
        return self.__pduList__

    def crc16(self):
        return self.__crc16__

    def payloadShow(self):
        start = 0
        _tag = mcpc_idx()
        i = 0
        if self.PduType() == pduType.MCPA:
            _tag = mcpa_idx()
        elif self.PduType() == pduType.MCPC:
            _tag = mcpc_idx()

        for it in self.payload():
            if it.tag == 0x9:
                print("PARA LIST:")
                _len = len(it.value)
                while _len > 0:
                    memmove(
                        addressof(_tag),
                        it.value[start : start + self.pduTagLen()],
                        self.pduTagLen(),
                    )
                    print("%08x " % _tag.tag, end="")
                    if (i + 1) % 4 == 0:
                        print()
                    i += 1
                    start = start + self.pduTagLen()
                    _len = _len - self.pduTagLen()
                print()
            elif it.tag == 0x0141:
                print("0x141: %s" % reportFlagTable[binascii.unhexlify(it.value)[0]])
            else:
                print("%08x=" % it.tag + f"{it.value}")

    def PduType(self):
        return self.__pdu_type

    def show(self):
        print("start: %02x" % self.__IspCommonField__.start)
        print("ap_layer:%02x" % self.__IspCommonField__.ap_layer)
        print("vp_layer:%02x" % self.__IspCommonField__.vp_layer)
        print("station_numbers:%08x" % self.__IspCommonField__.station_numbers)
        print("device_numbers:%02x" % self.__IspCommonField__.device_numbers)
        print("packets_numbers:%04x" % self.__IspCommonField__.packets_numbers)
        print(
            "vp_layer_interact:%02x %s"
            % (
                self.__IspCommonField__.vp_layer_interact,
                vpIneractFlagTable[self.__IspCommonField__.vp_layer_interact],
            )
        )
        print(
            "mcp_layer:%02x %s"
            % (
                self.__IspCommonField__.mcp_layer,
                pduTypeTable[self.__IspCommonField__.mcp_layer],
            )
        )
        print(
            "cmd:%02x %s"
            % (self.__IspCommonField__.cmd, cmdFlagTable[self.__IspCommonField__.cmd])
        )
        print(
            "response:%02x %s"
            % (
                self.__IspCommonField__.response,
                replayFlagTable[self.__IspCommonField__.response],
            )
        )
        self.payloadShow()
        print("crc:%04x" % self.__IspEndField__.crc)
        print("end:%02x" % self.__IspEndField__.end)


def mcpa_idx_packets(id: int) -> bytes:
    return bytes([id >> 8, id & 0xFF])


def mcpc_idx_packets(id: int) -> bytes:
    return bytes([id >> 24, (id >> 16) & 0xFF, (id >> 8) & 0xFF, (id & 0xFF)])


def getParaListTextBuffer():
    # buf = b"7E03010100000000160000030200FF090000000503BF050000C0050000C1050000C2050000C3050000C4050000C5050000C6050000C7050000C8050000C9050000CA050000CB050000CD050000CE050000CF050000D2050000D3050000D70500000120000002200000062000000920000001210000022100000621000009210000022200000322000006220000072200000A2200000B2200000C2200000D2200000E2200000F22000001230000022300000323000011230000122300001323000021230000222300002323000031230000322300003323000051230000522300005323000061230000622300006323000002250000042500000A2500000326000004260000052600001326000092A47E"
    # buf = b"7e03010000000000020000010200d90900010102000300040005000600070008000a000b001000110012001300140015001600170018001900200021002200230024003000310032003300490075005c005d005e5d005f00010102011001110112011301140115012001300131013301340136013701380139014101420143014401500151015201530172010102020204020502080209020f02100211022002210222022302240225022802010302030403050308030903100311030f032003210322032303240325032803a204530454047308a005a105a205a3057c08b005b105b205b305c0056d1b7e"
    buf = b"7E030100000000004C80800301FF064101000007FEDB7E"
    hdr = IspProtocolForLog()
    hdr.deserdes(buf)
    hdr.show()


def getParaListTextBufferV2(buf: bytes):
    hdr = IspProtocolForLog()
    hdr.deserdes(buf)
    hdr.show()


class IspProtocol(Structure):
    __IspCommonField__ = IspCommonField()
    __IspCommonFieldLen__ = sizeof(__IspCommonField__)
    __IspEndField__ = IspEndField()
    __IspEndFieldLen__ = sizeof(__IspEndField__)
    __crc16__ = 0x0
    __crcFlag__ = False
    __pdu_type: pduType
    __pduTagLen__: int
    __error__: str = ""
    __packets__: bytes
    __devNumber__ = 0
    __stationNumber__ = 0
    __deserdesOK__ = False

    def deserdes(self, msg: bytes) -> bool:
        if msg[0] != 0x7E or msg[-1] != 0x7E:
            self.__error__ += "start Flag and end Flag error\n"
            return False
        esc_msg = self.__escape_recv_packets(msg)
        esc_msg = b"\x7e" + esc_msg + b"\x7e"
        memmove(
            addressof(self.__IspCommonField__),
            esc_msg,
            self.__IspCommonFieldLen__,
        )
        ta = 4
        if self.__IspCommonField__.mcp_layer == 3:
            self.__pdu_type = pduType.MCPC
            ta = 4
        elif self.__IspCommonField__.mcp_layer == 1:
            self.__pdu_type = pduType.MCPA
            ta = 2
        self.__pduTagLen__ = ta
        start = self.__IspCommonFieldLen__
        end = -3
        self.__pduList__ = []
        pdu_part = esc_msg[start:end]
        __len = len(pdu_part)
        _start = 0
        _pdu = 0

        while __len > 0:
            if self.__pdu_type == pduType.MCPA:
                _tmp = mcpa_tag()
                _pdu = pdu_part[_start]
                memmove(
                    addressof(_tmp),
                    pdu_part[_start : _start + ta],
                    sizeof(mcpa_tag),
                )
                _tmp.value = pdu_part[_start + ta + 1 : _start + ta + 1 + _pdu - ta - 1]
                self.__pduList__.append(_tmp)
                __len = __len - _pdu
                _start = _start + _pdu
            elif self.__pdu_type == pduType.MCPC:
                _tmp = mcpc_tag()
                _pdu = pdu_part[_start]
                memmove(
                    addressof(_tmp),
                    pdu_part[_start : _start + ta],
                    sizeof(mcpc_tag),
                )
                _tmp.value = pdu_part[_start + ta + 1 : _start + ta + 1 + _pdu - ta - 1]
                self.__pduList__.append(_tmp)
                __len = __len - _pdu
                _start = _start + _pdu
            else:
                self.__error__ += "mcp type error\n"
                return False

        # Payload pdu part
        # end of payload data caluication
        memmove(
            addressof(self.__IspEndField__),
            esc_msg[-3:],
            self.__IspEndFieldLen__,
        )

        self.__crc16__ = self.__crc16(esc_msg[1:-3])
        if self.__IspEndField__.crc != self.__crc16__:
            self.__error__ += (
                "crc code parse error... please drop this packets ... ...\n"
            )
            return False
        else:
            self.__deserdesOK__ = True
            return True

    def __crc16(self, code: bytes):
        return crcmod.mkCrcFun(0x11021, rev=False, initCrc=0, xorOut=0x0)(code)

    def __escape_recv_packets(self, msg: bytes):
        return msg[1:-1].replace(b"\x5e\x5d", b"\x5e").replace(b"\x5e\x7d", b"\x7e")

    def __escape_send_packets(self, msg: bytes):
        if msg[0] != 0x7E or msg[-1] != 0x7E:
            self.__error__ += "escape packets error"
        return msg[1:-1].replace(b"\x5e", b"\x5e\x5d").replace(b"\x7e", b"\x5e\x7d")

    def Packets(self, packets: bytes) -> bytes:
        if packets[0] != 0x7E or packets[-1] != 0x7E:
            self.__error__ += "Packets head err and tail err"
            return b"\x00"
        crc = self.__crc16(packets[1:-3])
        return self.__escape_send_packets(
            packets.replace(packets[-3:-1], bytes([crc >> 8, crc & 0xFF]))
        )

    def setDevNumber(self, num: int):
        self.__devNumber__ = num

    def setStationNumber(self, num: int):
        self.__stationNumber__ = num

    def PduType(self):
        return self.__pdu_type

    def pduTagLen(self):
        return self.__pduTagLen__

    def payload(self):
        return self.__pduList__

    def crc16(self):
        return self.__crc16__

    def error(self) -> tuple:
        return True, self.__error__

    def payloadShow(self):
        if not self.__deserdesOK__:
            self.__error__ += "deserdes Failed\n"
            return
        start = 0
        _tag = mcpc_tag()
        i = 0
        if self.PduType() == pduType.MCPA:
            _tag = mcpa_idx()
        elif self.PduType() == pduType.MCPC:
            _tag = mcpc_idx()

        for it in self.payload():
            if it.tag == 0x9:
                print("PARA LIST:")
                _len = len(it.value)
                while _len > 0:
                    memmove(
                        addressof(_tag),
                        it.value[start : start + self.pduTagLen()],
                        self.pduTagLen(),
                    )
                    print("%08x " % _tag.tag, end="")
                    if (i + 1) % 4 == 0:
                        print()
                    i += 1
                    start = start + self.pduTagLen()
                    _len = _len - self.pduTagLen()
                print()
            elif it.tag == 0x0141:
                print("%s" % reportFlagTable[it.value[0]])
            else:
                print("%08x=" % it.tag + f"{it.value}")

    def show(self):
        if not self.__deserdesOK__:
            self.__error__ += "deserdes Failed\n"
            return
        print("start: %02x" % self.__IspCommonField__.start)
        print("ap_layer:%02x" % self.__IspCommonField__.ap_layer)
        print("vp_layer:%02x" % self.__IspCommonField__.vp_layer)
        print("station_numbers:%08x" % self.__IspCommonField__.station_numbers)
        print("device_numbers:%02x" % self.__IspCommonField__.device_numbers)
        print("packets_numbers:%04x" % self.__IspCommonField__.packets_numbers)
        print(
            "vp_layer_interact:%02x %s"
            % (
                self.__IspCommonField__.vp_layer_interact,
                vpIneractFlagTable[self.__IspCommonField__.vp_layer_interact],
            )
        )
        print(
            "mcp_layer:%02x %s"
            % (
                self.__IspCommonField__.mcp_layer,
                pduTypeTable[self.__IspCommonField__.mcp_layer],
            )
        )
        print(
            "cmd:%02x %s"
            % (self.__IspCommonField__.cmd, cmdFlagTable[self.__IspCommonField__.cmd])
        )
        print(
            "response:%02x %s"
            % (
                self.__IspCommonField__.response,
                replayFlagTable[self.__IspCommonField__.response],
            )
        )
        self.payloadShow()
        print("crc:%04x" % self.__IspEndField__.crc)
        print("end:%02x" % self.__IspEndField__.end)


# paraList command
def getParaListHexbuffer():
    buf = b"\x7E\x03\x01\x01\x00\x00\x00\x00\x16\x00\x00\x03\x02\x00\xFF\x09\x00\x00\x00\x05\x03\xBF\x05\x00\x00\xC0\x05\x00\x00\xC1\x05\x00\x00\xC2\x05\x00\x00\xC3\x05\x00\x00\xC4\x05\x00\x00\xC5\x05\x00\x00\xC6\x05\x00\x00\xC7\x05\x00\x00\xC8\x05\x00\x00\xC9\x05\x00\x00\xCA\x05\x00\x00\xCB\x05\x00\x00\xCD\x05\x00\x00\xCE\x05\x00\x00\xCF\x05\x00\x00\xD2\x05\x00\x00\xD3\x05\x00\x00\xD7\x05\x00\x00\x01\x20\x00\x00\x02\x20\x00\x00\x06\x20\x00\x00\x09\x20\x00\x00\x01\x21\x00\x00\x02\x21\x00\x00\x06\x21\x00\x00\x09\x21\x00\x00\x02\x22\x00\x00\x03\x22\x00\x00\x06\x22\x00\x00\x07\x22\x00\x00\x0A\x22\x00\x00\x0B\x22\x00\x00\x0C\x22\x00\x00\x0D\x22\x00\x00\x0E\x22\x00\x00\x0F\x22\x00\x00\x01\x23\x00\x00\x02\x23\x00\x00\x03\x23\x00\x00\x11\x23\x00\x00\x12\x23\x00\x00\x13\x23\x00\x00\x21\x23\x00\x00\x22\x23\x00\x00\x23\x23\x00\x00\x31\x23\x00\x00\x32\x23\x00\x00\x33\x23\x00\x00\x51\x23\x00\x00\x52\x23\x00\x00\x53\x23\x00\x00\x61\x23\x00\x00\x62\x23\x00\x00\x63\x23\x00\x00\x02\x25\x00\x00\x04\x25\x00\x00\x0A\x25\x00\x00\x03\x26\x00\x00\x04\x26\x00\x00\x05\x26\x00\x00\x13\x26\x00\x00\x92\xA4\x7E"
    buf = b"\x7e\x03\x01\x00\x00\x00\x00\x00\x02\x00\x00\x01\x02\x00\xd9\x09\x00\x01\x01\x02\x00\x03\x00\x04\x00\x05\x00\x06\x00\x07\x00\x08\x00\x0a\x00\x0b\x00\x10\x00\x11\x00\x12\x00\x13\x00\x14\x00\x15\x00\x16\x00\x17\x00\x18\x00\x19\x00\x20\x00\x21\x00\x22\x00\x23\x00\x24\x00\x30\x00\x31\x00\x32\x00\x33\x00\x49\x00\x75\x00\x5c\x00\x5d\x00\x5e\x5d\x00\x5f\x00\x01\x01\x02\x01\x10\x01\x11\x01\x12\x01\x13\x01\x14\x01\x15\x01\x20\x01\x30\x01\x31\x01\x33\x01\x34\x01\x36\x01\x37\x01\x38\x01\x39\x01\x41\x01\x42\x01\x43\x01\x44\x01\x50\x01\x51\x01\x52\x01\x53\x01\x72\x01\x01\x02\x02\x02\x04\x02\x05\x02\x08\x02\x09\x02\x0f\x02\x10\x02\x11\x02\x20\x02\x21\x02\x22\x02\x23\x02\x24\x02\x25\x02\x28\x02\x01\x03\x02\x03\x04\x03\x05\x03\x08\x03\x09\x03\x10\x03\x11\x03\x0f\x03\x20\x03\x21\x03\x22\x03\x23\x03\x24\x03\x25\x03\x28\x03\xa2\x04\x53\x04\x54\x04\x73\x08\xa0\x05\xa1\x05\xa2\x05\xa3\x05\x7c\x08\xb0\x05\xb1\x05\xb2\x05\xb3\x05\xc0\x05\x6d\x1b\x7e"
    hdr = IspProtocol()
    hdr.deserdes(buf)
    hdr.show()
    st, err = hdr.error()
    if st is False:
        print(err)


def parseISP(pkts: bytes):
    hdr = IspProtocol()
    hdr.deserdes(pkts)
    hdr.show()
    st, err = hdr.error()
    print(err)


def getParaListTextBufferV3(buf: str):
    getParaListTextBufferV2(buf.encode())


if __name__ == "__main__":
    getParaListTextBufferV3("7E030100000000000180800301FF064101000007B7137E")
