# coding=utf-8
"""
client
"""
from socket import *

sk = socket()

sk.connect(("127.0.0.1", 40000))
while 1:
    sk.settimeout(50)

    print("sending...now....")
    s = input("输入：")
    sk.send(s.encode())
    if s == "bye":
        break

    print(f"{sk.recv(4096)}")

sk.close()
