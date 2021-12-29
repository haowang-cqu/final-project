#!/bin/python
import argparse
import socket
from typing import List


def tcp_connect_test(host: str, port: int) -> bool:
    """TCP连接测试，如果连接成功建立连接则返回True
    """
    try:
        # 10s没有连接则判定为端口关闭
        socket.setdefaulttimeout(10)
        tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcp_socket.connect((host, port))
        success = True
        tcp_socket.close()
    except socket.error:
        success = False
    return success


def main():
    parser = argparse.ArgumentParser("a simple port scanner")
    parser.add_argument("--host", help="target host, should be IPv4 or hostname", required=True, type=str)
    parser.add_argument("--port", help="target ports, separated by a space", nargs="+", required=True, type=int)
    args = parser.parse_args()
    host = socket.gethostbyname(args.host)
    port = args.port
    for p in port:
        if tcp_connect_test(host, p):
            print(f"[+] {p}/tcp open")
        else:
            print(f"[-] {p}/tcp closed")


if __name__ == "__main__":
    main()
    # e.g. python .\port-scan.py --host baidu.com --port 80 443 9999