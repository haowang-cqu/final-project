import socket
import os

host = "127.0.0.1"
port = 23333
buffer_size = 102400


def login(conn: socket.socket) -> bool:
    """验证低级别权限
    """
    low_password = input("请输入低级别权限密码: ").strip().encode("utf-8")
    conn.send(b"0" + low_password, 0)
    is_success = conn.recv(buffer_size, 0)
    if is_success.decode("utf-8") != "success":
        print("验证失败")
        return False
    print("验证成功")
    return True


def command_handler(conn: socket.socket, command: str) -> None:
    action = command.split(" ", 1)[0]

    # 验证高级别权限
    if action == "admin":
        password = input("请输入高级别权限密码: ").strip().encode("utf-8")
        key = input("请输入加密密钥: ").strip().encode("utf-8")
        if len(key) < 8:
            key += b"0" * (8 - len(key))
        if len(password) < 8:
            password += b"0" * (8 - len(password))
        conn.send(b"1" + key[:8] + password[:8], 0)
        is_success = conn.recv(buffer_size, 0)
        if is_success.decode("utf-8") != "success":
            print("验证失败")
        else:
            print("验证成功，您已获得高级别权限")

    if action == "echo":
        message = command.split(" ", 1)[1]
        conn.send(b"e" + message.encode("utf-8"), 0)
        message = conn.recv(buffer_size, 0)
        print(message.decode("utf-8"))

    if action == "run":
        message = command.split(" ", 1)[1]
        conn.send(b"r" + message.encode("utf-8"), 0)
        message = conn.recv(buffer_size, 0)
        if message.decode("utf-8") == "success":
            print("成功")
        else:
            print("失败")

    if action == "upload":
        path = command.split(" ", 1)[1]
        if not os.path.isfile(path):
            print("文件不存在")
            return
        with open(path, "rb") as f:
            content = f.read()
        name = os.path.basename(path).encode("utf-8")
        message = b"f" + name + b"\r\n" + content
        if len(message) > buffer_size:
            print("文件太大")
            return
        conn.send(message, 0)
        message = conn.recv(buffer_size, 0)
        if message.decode("utf-8") == "success":
            print("成功")
        else:
            print("失败")


def client():
    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conn.connect((host, port))
    if not login(conn):
        return
    while True:
        print("> ", end="")
        command = input().strip()
        if len(command) > 0:
            if command == "exit":
                conn.close()
                return
            command_handler(conn, command)


if __name__ == "__main__":
    client()
