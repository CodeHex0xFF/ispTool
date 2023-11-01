import socket
import socketserver
import threading
from enum import Enum

from loguru import logger as logging


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
    def handle(self) -> None:
        conn = self.request
        recvDATA = b"\x00"
        sendDATA = b"\x00"
        status = False
        logging.info("NetWorkHandle Start ... ...")
        try:
            while True:
                if self.server.common.__trans_flag__ == NetWorkTransType.TCP:
                    recvDATA = conn.recv(4096)
                elif self.server.common.__trans_flag__ == NetWorkTransType.UDP:
                    recvDATA, _ = conn[0].recvfrom(4096)

                while True:
                    if (
                        self.server.common.__login_en__
                        and self.server.common.__call_login__ is not None
                    ):
                        status, sendDATA = self.server.common.__call_login__(recvDATA)
                        if status is True:
                            break
                    if (
                        self.server.common.__heartbeat_en__
                        and self.server.common.__call_heartbeat__ is not None
                    ):
                        # positivate recv heartbeat
                        status, sendDATA = self.server.common.__call_heartbeat__(
                            recvDATA
                        )
                    if (
                        self.server.common.__alarm_en__
                        and self.server.common.__call_alarm__ is not None
                    ):
                        status, sendDATA = self.server.common.__call_alarm__(recvDATA)
                    if (
                        self.server.common.__readwrite_en__
                        and self.server.common.__call_readwrite__ is not None
                    ):
                        status, sendDATA = self.server.common.__call_readwrite__(
                            recvDATA
                        )
                    break

                if self.server.common.__trans_flag__ == NetWorkTransType.TCP:
                    if status is False:
                        logging.info(f"start sendDATA {sendDATA}")
                        conn.sendall(sendDATA)
                elif self.server.common.__trans_flag__ == NetWorkTransType.UDP:
                    if status is False:
                        logging.info(f"start sendDATA {sendDATA}")
                        conn[0].sendto(sendDATA, conn[1])

        except (
            ConnectionResetError,
            ConnectionRefusedError,
            ConnectionAbortedError,
            ConnectionError,
            BrokenPipeError,
        ) as err:
            if self.server.common.__trans_flag__ == NetWorkTransType.TCP:
                logging.error("%s:%s" % (self.client_address[0], err.strerror))
                conn.close()
            elif self.server.common.__trans_flag__ == NetWorkTransType.UDP:
                logging.error("%s:%s" % conn[1], err.strerror)
                conn[0].close()


class NetWorkCommon:
    __heartbeat_en__ = False
    __readwrite_en__ = False
    __alarm_en__ = False
    __call_heartbeat__ = None
    __call_readwrite__ = None
    __call_alarm__ = None
    __server__ = None
    __login_en__ = False
    __call_login__ = False
    __trans_flag__: NetWorkTransType

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


class TcpServer(socketserver.TCPServer):
    def __init__(
        self,
        server_address,
        RequestHandlerClass,
        bind_and_activate,
        common: NetWorkCommon,
    ) -> None:
        self.common = common
        super().__init__(server_address, RequestHandlerClass, bind_and_activate)


class UdpServer(socketserver.UDPServer):
    def __init__(
        self,
        server_address,
        RequestHandlerClass,
        bind_and_activate,
        common: NetWorkCommon,
    ) -> None:
        self.common = common
        super().__init__(server_address, RequestHandlerClass, bind_and_activate)


class TcpServerThread(socketserver.ThreadingMixIn, TcpServer):
    pass


class UdpServerThread(socketserver.ThreadingMixIn, UdpServer):
    pass


class NetWork:
    __config__: NetWorkCFG
    __handle__ = None
    __common__: NetWorkCommon

    def __init__(self, config: NetWorkCFG, common: NetWorkCommon):
        self.__config__ = config
        self.__common__ = common
        self.__common__.__trans_flag__ = config.transType

    def overrideNetWork_COMMON(self, config: NetWorkCommon):
        self.__common__ = config

    def overrideNETWORK_CFG(self, config: NetWorkCFG):
        self.__config__ = config

    def GETtransType(self):
        return self.__config__.transType

    def GETworkType(self):
        return self.__config__.workType

    def setHandle(self, handle):
        self.__handle__ = handle

    # TODO: client work will add
    def start(self):
        logging.info("NetWork Setup ... ...")
        if self.__handle__ is None:
            logging.error(
                "server handle functions not register,please register handle functions "
            )
            return
        if self.__config__.transType == NetWorkTransType.TCP:
            if self.__config__.workType == NetWorkWorkType.SERVER:
                logging.info("start TCP server")
                self.__server__ = TcpServerThread(
                    (self.__config__.ip, self.__config__.port),
                    self.__handle__,
                    True,
                    self.__common__,
                )
            elif self.__config__.workType == NetWorkWorkType.CLIENT:
                pass
        elif self.__config__.transType == NetWorkTransType.UDP:
            logging.info("start UDP server")
            if self.__config__.workType == NetWorkWorkType.SERVER:
                self.__server__ = UdpServerThread(
                    (self.__config__.ip, self.__config__.port),
                    self.__handle__,
                    True,
                    self.__common__,
                )
            elif self.__config__.workType == NetWorkWorkType.CLIENT:
                pass
        if self.__server__ is not None:
            self.__server__.serve_forever()


def one(data) -> tuple[bool, bytes]:
    return False, "hello".encode()


def two(data) -> tuple[bool, bytes]:
    return False, "world".encode()


def set_common(cfg: NetWorkCommon):
    cfg.set_callHeartBeat(two)


# NOTE: example
if __name__ == "__main__":
    commonCfg = NetWorkCommon()
    instanceNetwork = NetWork(
        NetWorkCFG("127.0.0.1", 40000, NetWorkTransType.TCP, NetWorkWorkType.SERVER),
        commonCfg,
    )
    threading.Timer(3, set_common, (commonCfg,)).start()
    commonCfg.set_callHeartBeat(one)
    commonCfg.hearbeatEnable(True)
    instanceNetwork.setHandle(NetWorkHandle)
    instanceNetwork.start()
