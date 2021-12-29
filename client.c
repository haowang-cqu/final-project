/**
 * 客户端
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#pragma comment(lib, "ws2_32.lib")

int main(int argc, char **argv)
{
    //初始化DLL
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
    //创建套接字
    SOCKET sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    //向服务器发起请求
    struct sockaddr_in sockAddr;
    memset(&sockAddr, 0, sizeof(sockAddr)); //每个字节都用0填充
    sockAddr.sin_family = PF_INET;
    sockAddr.sin_addr.s_addr = inet_addr("127.0.0.1");
    sockAddr.sin_port = htons(1234);
    connect(sock, (SOCKADDR *)&sockAddr, sizeof(SOCKADDR));
    //接收服务器传回的数据
    char szBuffer[MAXBYTE] = {0};
    recv(sock, szBuffer, MAXBYTE, NULL);
    //输出接收到的数据
    printf("Message form server: %s\n", szBuffer);
    //关闭套接字
    closesocket(sock);
    //终止使用 DLL
    WSACleanup();
    system("pause");
    return 0;
}