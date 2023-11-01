import socketserver
import logging
import socket
from enum import Enum


class NetWorkTransType(Enum):
    TCP = 0x1
    UDP = 0x2


class NetWorkWorkType(Enum):
    CLIENT = 0x1
    SERVER = 0x2


class NetWorkCFG:
    ip: str
    port: int
    transType: NetWorkTransType
    workType: NetWorkWorkType

    def __init__(
        self, ip: str, port: int, transType: NetWorkTransType, workType: NetWorkWorkType
    ):
        self.ip = ip
        self.port = port
        self.transType = transType
        self.workType = workType


class NetWorkHandle(socketserver.BaseRequestHandler):
    __heartbeat_en__ = False
    __readwrite_en__ = False
    __alarm_en__ = False

    __call_heartbeat__ = None
    __call_readwrite__ = None
    __call_alarm__ = None

    __trans_flag__: NetWorkTransType

    __login_en__ = False
    __call_login__ = None

    def setTransFlag(self, flag: NetWorkTransType):
        self.__trans_flag__ = flag

    def handle(self) -> None:
        conn = self.request
        recvDATA = b"\x00"
        sendDATA = b"\x00"
        status = False
        try:
            if self.__trans_flag__ == NetWorkTransType.TCP:
                recvDATA = conn.recv(4096)
            elif self.__trans_flag__ == NetWorkTransType.UDP:
                recvDATA, _ = conn[0].recvfrom(4096)
            while True:
                if self.__login_en__ and self.__call_login__ is not None:
                    status, sendDATA = self.__call_login__(recvDATA)
                    if status is True:
                        break
                if self.__heartbeat_en__ and self.__call_heartbeat__ is not None:
                    # positivate recv heartbeat
                    status, sendDATA = self.__call_heartbeat__(recvDATA)
                if self.__alarm_en__ and self.__call_alarm__ is not None:
                    status, sendDATA = self.__call_alarm__(recvDATA)
                if self.__readwrite_en__ and self.__call_readwrite__ is not None:
                    status, sendDATA = self.__call_readwrite__(recvDATA)
                break

            if self.__trans_flag__ == NetWorkTransType.TCP:
                conn.sendall(sendDATA)
            elif self.__trans_flag__ == NetWorkTransType.UDP:
                conn[0].sendto(sendDATA, conn[1])

        except (
            ConnectionResetError,
            ConnectionRefusedError,
            ConnectionAbortedError,
            ConnectionError,
        ) as err:
            if self.__trans_flag__ == NetWorkTransType.TCP:
                logging.error("%s:%s" % (self.client_address[0], err.strerror))
                conn.close()
            elif self.__trans_flag__ == NetWorkTransType.UDP:
                logging.error("%s:%s" % conn[1], err.strerror)
                conn[0].close()

    # enable alarm thread
    def alarmEnable(self, enable: bool):
        self.__alarm_en__ = enable

    # enable readwrite thread
    def readwriteEnable(self, enable: bool):
        self.__readwrite_en__ = enable

    # enable hearbeat thread
    def hearbeatEnable(self, enable: bool):
        self.__heartbeat_en__ = enable

    def set_callHeartBeat(self, func):
        self.__call_heartbeat__ = func

    def set_callReadWrite(self, func):
        self.__call_readwrite__ = func

    def set_callAlarm(self, func):
        self.__call_alarm__ = func

    def set_callLogin(self, func):
        self.__call_login__ = func

    def loginEnable(self, enable: bool):
        self.__login_en__ = enable


class NetWork:
    __heartbeat_en__ = False
    __readwrite_en__ = False
    __alarm_en__ = False
    __config__: NetWorkCFG
    __call_heartbeat__ = None
    __call_readwrite__ = None
    __call_alarm__ = None
    __handle__ = None
    __server__ = None
    __login_en__ = False
    __call_login__ = False

    def __init__(self, config: NetWorkCFG):
        self.__config__ = config

    def overrideNETWORK_CFG(self, config: NetWorkCFG):
        self.__config__ = config

    def set_callHeartBeat(self, func):
        self.__call_heartbeat__ = func

    def set_callReadWrite(self, func):
        self.__call_readwrite__ = func

    def set_callAlarm(self, func):
        self.__call_alarm__ = func

    def set_callLogin(self, func):
        self.__call_login__ = func

    def loginEnable(self, enable: bool):
        self.__login_en__ = enable

    # enable alarm thread
    def alarmEnable(self, enable: bool):
        self.__alarm_en__ = enable

    # enable readwrite thread
    def readwriteEnable(self, enable: bool):
        self.__readwrite_en__ = enable

    # enable hearbeat thread
    def hearbeatEnable(self, enable: bool):
        self.__heartbeat_en__ = enable

    def setHandle(self, handle):
        self.__handle__ = handle

    def GETtransType(self):
        return self.__config__.transType

    def GETworkType(self):
        return self.__config__.workType

    # TODO: client work will add
    def start(self):
        if self.__handle__ is None:
            return
        if self.__config__.transType == NetWorkTransType.TCP:
            if self.__config__.workType == NetWorkWorkType.SERVER:
                self.__server__ = socketserver.ThreadingTCPServer(
                    (self.__config__.ip, self.__config__.port), self.__handle__
                )
            elif self.__config__.workType == NetWorkWorkType.CLIENT:
                pass
        elif self.__config__.transType == NetWorkTransType.UDP:
            if self.__config__.workType == NetWorkWorkType.SERVER:
                self.__server__ = socketserver.ThreadingUDPServer(
                    (self.__config__.ip, self.__config__.port), self.__handle__
                )
            elif self.__config__.workType == NetWorkWorkType.CLIENT:
                pass
        if self.__server__ is not None:
            self.__server__.serve_forever()
