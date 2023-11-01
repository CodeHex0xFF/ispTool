# coding=utf-8
"""
client
"""
from socket import *

sk = socket()

sk.connect(("127.0.0.1", 9977))
while 1:
    sk.settimeout(50)

    print("sending...now....")
    s = input("输入：")
    sk.send(s.encode())
    if s == "bye":
        break

    print(sk.recv(1024).decode())

sk.close()
