import socketserver


class MyServer(socketserver.BaseRequestHandler):
    def handle(self):
        conn = self.request
        conn.sendall("good?".encode())
        Flag = True
        while Flag:
            data = conn.recv(1024)
            if data == "exit":
                Flag = False
            elif data == "0":
                conn.sendall("verygood?".encode())
            else:
                conn.sendall("goodgood?".encode())


if __name__ == "__main__":
    server = socketserver.ThreadingTCPServer(("127.0.0.1", 40000), MyServer)
    server.serve_forever()
