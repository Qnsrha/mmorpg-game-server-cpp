#include <winsock2.h>
#include <windows.h>
#include <process.h>
#include <iostream>
#include <unordered_map>
#include <queue>
#include <mutex>

#pragma comment(lib, "ws2_32.lib")

#define PORT 9000
#define WORKER_COUNT 4
#define BUFFER_SIZE 512

enum OPCODE : uint16_t
{
    OP_ECHO = 1,
    OP_HELLO = 2
};

struct Packet
{
    uint16_t length;
    uint16_t opcode;
    char data[BUFFER_SIZE - 4]; // 총 크기는 512
};

struct OverlappedIO
{
    OVERLAPPED overlapped;
    WSABUF wsaBuf;
    char buffer[BUFFER_SIZE];
    enum { RECV, SEND } type;
};

class Session
{
public:
    SOCKET socket;
    std::mutex mutex;
    bool sending = false;
    std::queue<std::string> sendQueue;

    Session(SOCKET s) : socket(s) {}

    void QueueSend(const std::string& msg)
    {
        std::lock_guard<std::mutex> lock(mutex);
        sendQueue.push(msg);

        if (!sending)
        {
            sending = true;
            DoSend();
        }
    }

    void DoSend()
    {
        if (sendQueue.empty())
        {
            sending = false;
            return;
        }

        OverlappedIO* sendIO = new OverlappedIO;
        ZeroMemory(&sendIO->overlapped, sizeof(OVERLAPPED));
        sendIO->type = OverlappedIO::SEND;

        const std::string& msg = sendQueue.front();
        memcpy(sendIO->buffer, msg.c_str(), msg.size());

        sendIO->wsaBuf.buf = sendIO->buffer;
        sendIO->wsaBuf.len = (ULONG)msg.size();

        DWORD bytesSent = 0;
        int ret = WSASend(socket, &sendIO->wsaBuf, 1, &bytesSent, 0, &sendIO->overlapped, nullptr);

        if (ret == SOCKET_ERROR && WSAGetLastError() != WSA_IO_PENDING)
        {
            delete sendIO;
        }
    }

    void OnSendComplete()
    {
        std::lock_guard<std::mutex> lock(mutex);
        if (!sendQueue.empty())
            sendQueue.pop();

        DoSend();
    }
};

class SessionManager
{
private:
    std::unordered_map<SOCKET, Session*> sessions;
    std::mutex lock;

public:
    void Add(Session* session)
    {
        std::lock_guard<std::mutex> guard(lock);
        sessions[session->socket] = session;
    }

    void Remove(SOCKET socket)
    {
        std::lock_guard<std::mutex> guard(lock);
        sessions.erase(socket);
    }

    Session* Get(SOCKET socket)
    {
        std::lock_guard<std::mutex> guard(lock);
        auto it = sessions.find(socket);
        return (it != sessions.end()) ? it->second : nullptr;
    }
};

HANDLE g_hIOCP;
SessionManager g_sessionManager;

void Disconnect(Session* session)
{
    if (!session) return;

    std::cout << "[!] Client disconnected: " << session->socket << "\n";
    closesocket(session->socket);
    g_sessionManager.Remove(session->socket);
    delete session;
}

void ProcessPacket(Session* session, const Packet* packet)
{
    if (packet->opcode == OP_ECHO)
    {
        std::string msg(packet->data, packet->length - 4);
        std::cout << "[Echo] " << msg << "\n";
        session->QueueSend(std::string((char*)packet, packet->length));
    }
    else if (packet->opcode == OP_HELLO)
    {
        std::cout << "[Hello] Packet received\n";
    }
}

unsigned int __stdcall WorkerThread(void* lpParam)
{
    DWORD bytesTransferred;
    ULONG_PTR completionKey;
    LPOVERLAPPED lpOverlapped;

    while (true)
    {
        BOOL result = GetQueuedCompletionStatus(
            g_hIOCP,
            &bytesTransferred,
            &completionKey,
            &lpOverlapped,
            INFINITE);

        Session* session = reinterpret_cast<Session*>(completionKey);
        OverlappedIO* ioData = reinterpret_cast<OverlappedIO*>(lpOverlapped);

        if (!result || bytesTransferred == 0)
        {
            Disconnect(session);
            if (ioData) delete ioData;
            continue;
        }

        if (ioData->type == OverlappedIO::RECV)
        {
            Packet* packet = reinterpret_cast<Packet*>(ioData->buffer);
            ProcessPacket(session, packet);

            ZeroMemory(&ioData->overlapped, sizeof(OVERLAPPED));
            ioData->type = OverlappedIO::RECV;
            DWORD flags = 0;
            DWORD recvBytes = 0;

            WSARecv(session->socket, &ioData->wsaBuf, 1, &recvBytes, &flags, &ioData->overlapped, nullptr);
        }
        else if (ioData->type == OverlappedIO::SEND)
        {
            session->OnSendComplete();
            delete ioData;
        }
    }

    return 0;
}

void AcceptClient(SOCKET listenSocket)
{
    SOCKET clientSocket = accept(listenSocket, nullptr, nullptr);
    if (clientSocket == INVALID_SOCKET)
        return;

    std::cout << "[+] Client connected: " << clientSocket << "\n";

    Session* session = new Session(clientSocket);
    g_sessionManager.Add(session);

    CreateIoCompletionPort((HANDLE)clientSocket, g_hIOCP, (ULONG_PTR)session, 0);

    OverlappedIO* recvIO = new OverlappedIO;
    ZeroMemory(&recvIO->overlapped, sizeof(OVERLAPPED));
    recvIO->type = OverlappedIO::RECV;
    recvIO->wsaBuf.buf = recvIO->buffer;
    recvIO->wsaBuf.len = BUFFER_SIZE;

    DWORD flags = 0;
    DWORD recvBytes = 0;
    WSARecv(clientSocket, &recvIO->wsaBuf, 1, &recvBytes, &flags, &recvIO->overlapped, nullptr);
}

int main()
{
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);

    SOCKET listenSocket = WSASocket(AF_INET, SOCK_STREAM, 0, nullptr, 0, WSA_FLAG_OVERLAPPED);

    sockaddr_in serverAddr = {};
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = htonl(INADDR_ANY);
    serverAddr.sin_port = htons(PORT);

    bind(listenSocket, (SOCKADDR*)&serverAddr, sizeof(serverAddr));
    listen(listenSocket, SOMAXCONN);

    g_hIOCP = CreateIoCompletionPort(INVALID_HANDLE_VALUE, nullptr, 0, 0);

    for (int i = 0; i < WORKER_COUNT; ++i)
    {
        _beginthreadex(nullptr, 0, WorkerThread, nullptr, 0, nullptr);
    }

    std::cout << "[*] Server running on port " << PORT << "\n";

    while (true)
    {
        AcceptClient(listenSocket);
    }

    closesocket(listenSocket);
    WSACleanup();
    return 0;
}
