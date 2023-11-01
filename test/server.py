import socketserver


class TcpServerHandle(socketserver.BaseRequestHandler):
    def handle(self):
        conn = self.request
        conn.sendall("good?".encode())
        Flag = True
        while Flag:
            print("%s" % self.server.info)
            data = conn.recv(1024)
            if data == "exit":
                Flag = False
            elif data == "0":
                conn.sendall("verygood?".encode())
            else:
                conn.sendall("goodgood?".encode())

    def overrideHandle(self):
        pass


class TcpServer(socketserver.TCPServer):
    info = "Hello TcpServer"
    pass


class TcpServerThread(socketserver.ThreadingMixIn, TcpServer):
    pass


if __name__ == "__main__":
    server = TcpServerThread(("127.0.0.1", 40000), TcpServerHandle)
    server.serve_forever()
