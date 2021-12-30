import socket

host = "127.0.0.1"
port = 23333
buffer_size = 1024

if __name__ == "__main__":
    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conn.connect((host, port))
    conn.send(b"0123456", 0)
    print(conn.recv(buffer_size, 0))
    conn.send(b"111111111111111111111111111111111111", 0)
    print(conn.recv(buffer_size, 0))
    conn.close()
