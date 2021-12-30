/**
 * �����
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include "des.h"
#pragma comment(lib, "ws2_32.lib")

#define HOST "127.0.0.1"
#define PORT 23333
#define MAX_CLIENT 1024
#define BUFFER_SIZE 1024
#define LOW_PASSWORD "123456" // �ͼ���Ȩ������

typedef struct
{
    SOCKET socket;
    int admin;
} Client;

Client clients[MAX_CLIENT];

/**
 * �ͻ��˵�¼
 */
int login(int id)
{
    char buf[BUFFER_SIZE] = {0};
    int len = recv(clients[id].socket, buf, BUFFER_SIZE, 0);
    if (len > 0 && buf[0] == '0' && strcmp(buf + 1, LOW_PASSWORD) == 0)
    {
        send(clients[id].socket, "success", 7, 0);
        clients[id].admin = 0; // ӵ����ͨ�û�Ȩ��
        return 1;
    }
    send(clients[id].socket, "failed", 6, 0);
    return 0;
}

int adminLogin(char *command, int len)
{
    Block key, password;
    if (len != 16)
        return 0;
    for (int i = 0; i < 8; i++)
    {
        key.c[i] = command[i];
        password.c[i] = command[8 + i];
    }
    uint64_t cipher = des(password.l, key.l, e);
    return cipher == 0x8e4fc7f03aa3a291;
}

/**
 * �ļ��ϴ�
 */
int fileUpload(const char *buf, int len)
{
    char fileName[1024] = {0};
    int i;
    // �����ļ���
    for (i = 0; i < len - 1; i++)
    {
        if (buf[i] == '\r' && buf[i + 1] == '\n')
            break;
        else
            fileName[i] = buf[i];
    }
    // �ļ�����Ϊ0
    if (len - (i + 2) < 1)
        return 0;
    FILE *fp = fopen(fileName, "wb");
    fwrite(buf + i + 2, sizeof(char), len - (i + 2), fp);
    fclose(fp);
    return 1;
}

/**
 * ִ������
 */
int runCommand(char *command)
{
    STARTUPINFO si = {sizeof(si)};
    PROCESS_INFORMATION pi;
    if (!CreateProcessA(NULL, command, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi))
    {
        return 0;
    }
    return 1;
}

/**
 * �ͻ��������
 */
void commandHandler(int id, char *command, int len)
{
    switch (command[0])
    {
    // ��֤�߼���Ȩ��
    case '1':
        if (clients[id].admin >= 0 && adminLogin(command + 1, len - 1))
        {
            clients[id].admin = 1;
            send(clients[id].socket, "success", 7, 0);
        }
        else
        {
            send(clients[id].socket, "failed", 6, 0);
        }
        break;
    // echo
    case 'e':
        if (clients[id].admin >= 0)
        {
            send(clients[id].socket, command + 1, len - 1, 0);
        }
        else
        {
            send(clients[id].socket, "failed", 6, 0);
        }
        break;
    // ִ������
    case 'r':
        if (clients[id].admin >= 0 && runCommand(command + 1))
        {
            send(clients[id].socket, "success", 7, 0);
        }
        else
        {
            send(clients[id].socket, "failed", 6, 0);
        }
        break;
    // �ļ��ϴ�
    case 'f':
        if (clients[id].admin >= 1 && fileUpload(command + 1, len - 1))
        {
            send(clients[id].socket, "success", 7, 0);
        }
        else
        {
            send(clients[id].socket, "failed", 6, 0);
        }
        break;
    default:
        send(clients[id].socket, "failed", 6, 0);
        break;
    }
}

/**
 * �Ϳͻ��˽������̺߳���
 */
DWORD proc(LPVOID lpThreadParameter)
{
    int id = (int)lpThreadParameter;
    printf("[INFO] client:%d connected\n", id);
    // �ͻ��˵�¼��֤
    if (!login(id))
    {
        printf("[WARN] client:%d verification failed\n", id);
        closesocket(clients[id].socket);
        clients[id].socket = INVALID_SOCKET;
        return 0;
    }
    else
    {
        printf("[INFO] client:%d login successfully\n", id);
    }
    // �ͻ��������ȡ
    char buf[BUFFER_SIZE];
    int len;
    while (1)
    {
        memset(buf, 0, BUFFER_SIZE);
        len = recv(clients[id].socket, buf, BUFFER_SIZE, 0);
        printf("[INFO] client:%d receive %d bytes\n", id, len);
        if (len > 0)
        {
            commandHandler(id, buf, len);
        }
        else
        {
            printf("[INFO] client:%d disconnected\n", id);
            closesocket(clients[id].socket);
            clients[id].socket = INVALID_SOCKET;
            break;
        }
    }
    return 0;
}

/**
 * �����ͻ������Ӳ�����ͨ���߳�
 */
void server()
{
    char *busyMsg = "Server is busy!\n";
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
    SOCKET serverSocket = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    // ����˰�IP�Ͷ˿�
    SOCKADDR_IN serverAddr = {0};
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.S_un.S_addr = inet_addr(HOST);
    serverAddr.sin_port = htons(PORT);
    bind(serverSocket, (SOCKADDR *)&serverAddr, sizeof serverAddr);
    // ��ʼ���ͻ�������
    for (int i = 0; i < MAX_CLIENT; i++)
    {
        clients[i].socket = INVALID_SOCKET;
        clients[i].admin = -1;
    }
    // �����ͻ��˵���������
    printf("[INFO] listening on address %s port %d\n", HOST, PORT);
    listen(serverSocket, 20);
    SOCKADDR clientAddr = {0};
    int size = sizeof clientAddr;
    while (1)
    {
        SOCKET temp = accept(serverSocket, (SOCKADDR *)&clientAddr, &size);
        int id = -1;
        // ��ȡһ�����õ�ID
        for (int i = 0; i < MAX_CLIENT; i++)
        {
            if (clients[i].socket == INVALID_SOCKET)
            {
                id = i;
                break;
            }
        }
        // ����������������ʱֱ�Ӱ����ӹر�
        if (id == -1)
        {
            printf("[WARN] Server is busy connecting\n");
            send(temp, "busy", 4, 0);
            closesocket(temp);
            continue;
        }
        // �����Ϳͻ���ͨ�ŵ����߳�
        clients[id].socket = temp;
        CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)proc, (LPVOID)id, 0, NULL);
    }
}

int main(int argc, char **argv)
{
    server();
    return 0;
}