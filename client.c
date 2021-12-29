/**
 * 客户端
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#pragma comment(lib, "ws2_32.lib")
#define HOST "127.0.0.1"
#define PORT 23333
#define BUFFER_SIZE 1024

int splitByDelim(char des[MAXBYTE][MAXBYTE], char msg[MAXBYTE], const char *delim)
{
    char *result = NULL;
    int cmdNum = 0;
    result = strtok(msg, delim);
    while (result != NULL)
    {
        strcpy(des[cmdNum], result);
        result = strtok(NULL, delim);
        cmdNum++;
    }
    return cmdNum;
}

void client(char *token)
{
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
    SOCKET sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    SOCKADDR_IN sockAddr = {0};
    sockAddr.sin_family = PF_INET;
    sockAddr.sin_addr.s_addr = inet_addr(HOST);
    sockAddr.sin_port = htons(PORT);
    connect(sock, (SOCKADDR *)&sockAddr, sizeof(SOCKADDR));
    // 登录
    send(sock, token, strlen(token), 0);
    char *buf[BUFFER_SIZE] = {0};
    recv(sock, buf, BUFFER_SIZE, 0);
    // 登录失败
    if (strcmp(buf, "success") != 0)
    {
        closesocket(sock);
        WSACleanup();
        fprintf(stderr, "[ERROR] wrong password!\n");
        return;
    }
    while (1)
    {
        printf(">> ");
        memset(buf, 0, BUFFER_SIZE);
        if (fgets(buf, BUFFER_SIZE, stdin))
        {
            send(sock, buf, strlen(buf), 0);
        }
        memset(buf, 0, BUFFER_SIZE);
        recv(sock, buf, BUFFER_SIZE, 0);
        printf("%s\n", buf);
    }
    closesocket(sock);
    WSACleanup();
}

int getToken(char *buf, char *argv[])
{
    if (strcmp(argv[1], "-u") == 0)
    {
        buf[0] = '0';
        strcpy(buf + 1, argv[2]);
        return 0;
    }
    else if (strcmp(argv[1], "-r") == 0)
    {
        buf[0] = '1';
        strcpy(buf + 1, argv[2]);
        return 0;
    }
    return -1;
}

int main(int argc, char **argv)
{
    if (argc != 3)
    {
        fprintf(stderr, "Usage: client -u/-r [password]\n");
        return -1;
    }
    char buf[BUFFER_SIZE];
    if (getToken(buf, argv) != 0)
    {
        fprintf(stderr, "Usage: client -u/-r [password]\n");
        return -1;
    }
    client(buf);
    return 0;
}