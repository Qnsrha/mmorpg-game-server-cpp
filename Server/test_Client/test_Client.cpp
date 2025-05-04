#include <winsock2.h>
#include <ws2tcpip.h>
#include <iostream>

#pragma comment(lib, "ws2_32.lib")

#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 9000
#define BUFFER_SIZE 512

int main()
{
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);

    SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET)
    {
        std::cerr << "Socket creation failed\n";
        return 1;
    }

    sockaddr_in serverAddr = {};
    serverAddr.sin_family = AF_INET;
    inet_pton(AF_INET, SERVER_IP, &serverAddr.sin_addr);
    serverAddr.sin_port = htons(SERVER_PORT);

    if (connect(sock, (SOCKADDR*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR)
    {
        std::cerr << "Connection failed\n";
        closesocket(sock);
        return 1;
    }

    std::cout << "[*] Connected to server\n";

    // ===== 패킷 생성 =====
    const char* msg = "Hello IOCP!";
    int msgLen = (int)strlen(msg);

    char packet[BUFFER_SIZE] = {};
    uint16_t totalLen = 4 + msgLen;     // length(2) + opcode(2) + data
    uint16_t opcode = 1;                // OP_ECHO

    memcpy(packet, &totalLen, 2);       // length
    memcpy(packet + 2, &opcode, 2);     // opcode
    memcpy(packet + 4, msg, msgLen);    // data

    send(sock, packet, totalLen, 0);

    // ===== 응답 수신 =====
    char recvBuf[BUFFER_SIZE] = {};
    int recvLen = recv(sock, recvBuf, BUFFER_SIZE, 0);

    if (recvLen > 0)
    {
        uint16_t rlen, rop;
        memcpy(&rlen, recvBuf, 2);
        memcpy(&rop, recvBuf + 2, 2);
        std::string recvMsg(recvBuf + 4, rlen - 4);

        std::cout << "[Recv] opcode=" << rop << ", msg=" << recvMsg << "\n";
    }

    closesocket(sock);
    WSACleanup();
    return 0;
}
