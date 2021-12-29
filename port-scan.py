#!/bin/python
import argparse
from os import error
import socket
from typing import List


def tcp_connect_test(host: str, port: int) -> bool:
    """TCP连接测试，如果连接成功建立连接则返回True
    """
    try:
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
    parser.add_argument("--timeout", help="timeout(s)", required=False, type=int, default=10)
    args = parser.parse_args()
    host = args.host
    port = args.port
    timeout = args.timeout
    # 指定timeout时间内没有连接则判定为端口关闭
    socket.setdefaulttimeout(timeout)
    # 尝试域名解析
    try:
        host = socket.gethostbyname(host)
    except:
        print(f"Error: Cannot resolve '{args.host}': Unknown host")
        return
    print(f"Scan results for: {host}")
    # 端口扫描
    for p in port:
        if tcp_connect_test(host, p):
            print(f"[+] {p:>5}/tcp \topen")
        else:
            print(f"[-] {p:>5}/tcp \tclosed")


if __name__ == "__main__":
    main()
    # e.g.
    # python .\port-scan.py --host baidu.com --port 80 443 9999 --timeout 3
    # Scan results for: 220.181.38.251
    # [+]    80/tcp   open
    # [+]   443/tcp   open
    # [-]  9999/tcp   closed
