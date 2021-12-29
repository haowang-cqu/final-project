/**
 * 服务端
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#pragma comment(lib, "ws2_32.lib")

#define HOST "127.0.0.1"
#define PORT 23333
#define MAX_CLIENT 1024
#define BUFFER_SIZE 1024
#define USER_TOKEN "123456" // 低级别权限密码
#define ADMIN_TOKEN "654321" // 高级别权限密码

SOCKET clientSocket[MAX_CLIENT];

/**
 * 获取一个可用的客户端ID
 */
int getClientId()
{
    for (int i = 0; i < MAX_CLIENT; i++)
    {
        if (clientSocket[i] == NULL)
            return i;
    }
    return -1;
}

/**
 * 客户端登录
 * -1 失败
 *  0 低级别权限
 *  1 高级别权限
 */
int login(int id)
{
    char buf[BUFFER_SIZE] = {0};
    int len = recv(clientSocket[id], buf, BUFFER_SIZE, NULL);
    if (len > 0)
    {
        printf("recv[%d]: %s\n", len, buf);
        // 低级别权限登录
        if (buf[0] == '0' && strcmp(buf + 1, USER_TOKEN) == 0)
        {
            return 0;
        }
        // 高级别权限登录
        if (buf[0] == '1' && strcmp(buf + 1, ADMIN_TOKEN) == 0)
        {
            return 1;
        }
    }
    return -1;
}

/**
 * 和客户端交互的线程函数
 */
DWORD proc(LPVOID lpThreadParameter)
{
    int id = (int)lpThreadParameter;
    printf("client [%d] connected\n", id);
    int role = login(id);
    // 验证失败直接关闭连接
    if (role == -1)
    {
        printf("client [%d] verification failed\n", id);
        closesocket(clientSocket[id]);
        clientSocket[id] = NULL;
    }
    printf("the role of client [%d] is %d\n", id, role);
    char buf[BUFFER_SIZE];
    int len;
    while (1)
    {
        memset(buf, 0, BUFFER_SIZE);
        len = recv(clientSocket[id], buf, BUFFER_SIZE, NULL);
        printf("receive %d bytes from client [%d]\n", len, id);
        if (len > 0)
        {
            send(clientSocket[id], buf, len, NULL);
        }
        else
        {
            printf("client [%d] disconnected\n", id);
            closesocket(clientSocket[id]);
            clientSocket[id] = NULL;
            break;
        }
    }
    return 0;
}

/**
 * 监听客户端连接并创建通信线程
 */
void server()
{
    char *busyMsg = "Server is busy!\n";
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
    SOCKET serverSocket = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    // 服务端绑定IP和端口
    SOCKADDR_IN serverAddr = {0};
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.S_un.S_addr = inet_addr(HOST);
    serverAddr.sin_port = htons(PORT);
    bind(serverSocket, (SOCKADDR *)&serverAddr, sizeof serverAddr);
    // 监听客户端的连接请求
    listen(serverSocket, 20);
    SOCKADDR clientAddr = {0};
    int size = sizeof clientAddr;
    while (1)
    {
        SOCKET temp = accept(serverSocket, (SOCKADDR *)&clientAddr, &size);
        int id = getClientId();
        // 当连接数超过上限时直接把连接关闭
        if (id == -1)
        {
            send(temp, busyMsg, strlen(busyMsg) + sizeof(char), NULL);
            closesocket(temp);
            continue;
        }
        // 创建和客户端通信的子线程
        clientSocket[id] = temp;
        CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)proc, (LPVOID)id, NULL, NULL);
    }
}

int main(int argc, char **argv)
{
    server();
    return 0;
}