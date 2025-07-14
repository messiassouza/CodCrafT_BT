#include "pch.h"
 


#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <windivert.h>
#include <stdio.h>
#include <thread>
#include <vector>
#include <atomic>
#include <string>
#include <fstream>
#include <windows.h>
#include <ctime>
#include <map>
#include <sstream>
#include <io.h>
#include <fcntl.h>
#include <iomanip>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

#define LOGIN_SERVER_PORT 2106
#define GAME_SERVER_PORT 7777
#define MAX_PACKET_SIZE 65535
#define TCP_PORT "12345"
#define PING_INTERVAL 5000

struct Connection {
    DWORD pid;
    UINT32 localAddr;
    UINT16 localPort;
};

struct PacketInfo {
    unsigned char opcode;
    bool isInbound;
    UINT packetSize;
};

struct PacketCaptureState {
    std::atomic<bool> running = false;
    std::vector<PacketInfo> capturedPackets;
    std::atomic<unsigned long> packetSequence = 0;
    std::atomic<int> opcodeCount = 0;
    std::wofstream logFile;
    bool debugMode = true;
    std::map<unsigned char, std::wstring> opcodeFunctions;
    std::thread socketThread;
    SOCKET serverSocket = INVALID_SOCKET;
    SOCKET clientSocket = INVALID_SOCKET;
    std::vector<std::thread*> captureThreads;
    std::vector<HANDLE> divertHandles;
    std::vector<UINT16> activePorts;

    PacketCaptureState() : logFile(L"packets.log", std::ios::app) {
        if (logFile.tellp() == 0) {
            logFile << L"\xFEFF";
        }
        opcodeFunctions = {
            {0x00, L"ProtocolVersion"},
            {0x07, L"Init"},
            {0x0D, L"RequestAuthLogin"},
            {0x03, L"LoginOk"},
            {0x01, L"LoginFail"},
            {0xB3, L"ServerList"},
            {0x2B, L"PlayOk"},
            {0x1B, L"MoveBackwardToLocation"},
            {0x18, L"TargetSelected"},
            {0x1F, L"TargetUnselected"},
            {0x1A, L"NpcInfo"},
            {0x32, L"ItemList"},
            {0x7A, L"StatusUpdate"},
            {0x09, L"KeepAlive"},
            {0x27, L"StopMove"},
            {0x43, L"JoinPartyRequest"},
            {0x51, L"SkillList"},
            {0x3F, L"ActionUse"},
            {0x22, L"MagicSkillUse"},
            // Add more opcodes as needed for Interlude
        };
    }

    ~PacketCaptureState() {
        StopCapture();
    }

    void ClearLogFile() {
        logFile.close();
        logFile.open(L"packets.log", std::ios::out | std::ios::trunc);
        logFile << L"\xFEFF";
        logFile << L"Log limpo em " << std::time(nullptr) << L"\n";
        logFile.flush();
    }

    void StopCapture() {
        running = false;
        if (clientSocket != INVALID_SOCKET) {
            closesocket(clientSocket);
            clientSocket = INVALID_SOCKET;
        }
        if (serverSocket != INVALID_SOCKET) {
            closesocket(serverSocket);
            serverSocket = INVALID_SOCKET;
        }
        if (socketThread.joinable()) {
            socketThread.join();
        }
        for (auto* thread : captureThreads) {
            if (thread) {
                thread->join();
                delete thread;
            }
        }
        captureThreads.clear();
        for (auto handle : divertHandles) {
            WinDivertClose(handle);
        }
        divertHandles.clear();
        activePorts.clear();
        logFile << L"Captura parada.\n";
        logFile.flush();
    }
};

PacketCaptureState g_CaptureState;
DWORD g_pid = 0;

void LoadOpcodeFunctions(const std::wstring& filename, std::map<unsigned char, std::wstring>& functions) {
    std::wifstream file(filename);
    if (file.is_open()) {
        std::wstring line;
        while (std::getline(file, line)) {
            std::wistringstream iss(line);
            std::wstring hexOpcodeStr, function;
            if (std::getline(iss, hexOpcodeStr, L' ') && std::getline(iss, function)) {
                unsigned char opcode;
                std::wstringstream ss(hexOpcodeStr);
                unsigned int temp;
                ss >> std::hex >> temp;
                if (ss.fail() || temp > 0xFF) continue;
                opcode = static_cast<unsigned char>(temp);
                functions[opcode] = function;
            }
        }
        file.close();
        g_CaptureState.logFile << L"Tabela de opcodes carregada de " << filename << L"\n";
    }
    else {
        g_CaptureState.logFile << L"Aviso: Arquivo " << filename << L" não encontrado. Usando mapeamentos padrão.\n";
    }
    g_CaptureState.logFile.flush();
}

std::vector<Connection> GetConnectionsByProcess() {
    std::vector<Connection> connections;
    MIB_TCPTABLE_OWNER_PID* tcpTable = nullptr;
    DWORD size = 0;

    DWORD result = GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    if (result != NO_ERROR && result != ERROR_INSUFFICIENT_BUFFER) {
        g_CaptureState.logFile << L"Erro ao obter tamanho da tabela TCP: " << result << L"\n";
        g_CaptureState.logFile.flush();
        return connections;
    }
    tcpTable = (MIB_TCPTABLE_OWNER_PID*)malloc(size);
    if (!tcpTable) {
        g_CaptureState.logFile << L"Erro de alocação de memória para tabela TCP\n";
        g_CaptureState.logFile.flush();
        return connections;
    }
    if (GetExtendedTcpTable(tcpTable, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
        for (DWORD i = 0; i < tcpTable->dwNumEntries; i++) {
            MIB_TCPROW_OWNER_PID* row = &tcpTable->table[i];
            if (row->dwOwningPid == g_pid) {
                Connection conn = { row->dwOwningPid, row->dwLocalAddr, ntohs((UINT16)row->dwLocalPort) };
                connections.push_back(conn);
                g_CaptureState.logFile << L"Conexão encontrada para PID=" << conn.pid << L", Porta local=" << conn.localPort << L"\n";
            }
        }
    }
    else {
        g_CaptureState.logFile << L"Erro ao obter tabela TCP: " << GetLastError() << L"\n";
    }
    free(tcpTable);
    g_CaptureState.logFile << L"Conexões verificadas para PID " << g_pid << L", encontradas: " << connections.size() << L"\n";
    g_CaptureState.logFile.flush();
    return connections;
}

void CapturePackets(HANDLE divertHandle, UINT16 localPort) {
    char buffer[MAX_PACKET_SIZE];
    UINT bufferLen;
    WINDIVERT_ADDRESS addr;

    g_CaptureState.logFile << L"Capturando pacotes na porta local " << localPort << L" (entrada e saída)...\n";
    g_CaptureState.logFile.flush();

    while (g_CaptureState.running) {
        if (WinDivertRecv(divertHandle, buffer, sizeof(buffer), &bufferLen, &addr)) {
            const char* direction = addr.Outbound ? "Saída" : "Entrada";
            bool isInbound = !addr.Outbound;
            unsigned long seq = g_CaptureState.packetSequence++;

            time_t now = time(nullptr);
            char timeStr[32];
            ctime_s(timeStr, sizeof(timeStr), &now);
            timeStr[strlen(timeStr) - 1] = '\0';

            WINDIVERT_IPHDR* ipHdr = nullptr;
            WINDIVERT_TCPHDR* tcpHdr = nullptr;
            PVOID data = nullptr;
            UINT dataLen = 0;
            if (!WinDivertHelperParsePacket(buffer, bufferLen, &ipHdr, nullptr, nullptr, nullptr, nullptr, &tcpHdr, nullptr, &data, &dataLen, nullptr, nullptr)) {
                g_CaptureState.logFile << L"[" << seq << L"][" << timeStr << L"] Erro ao parsear pacote\n";
                g_CaptureState.logFile.flush();
                WinDivertSend(divertHandle, buffer, bufferLen, nullptr, &addr);
                continue;
            }

            char srcIp[16], dstIp[16];
            inet_ntop(AF_INET, &ipHdr->SrcAddr, srcIp, sizeof(srcIp));
            inet_ntop(AF_INET, &ipHdr->DstAddr, dstIp, sizeof(dstIp));
            UINT16 srcPort = ntohs(tcpHdr->SrcPort);
            UINT16 dstPort = ntohs(tcpHdr->DstPort);

            unsigned char opcode = dataLen > 0 ? ((unsigned char*)data)[0] : 0;

            const char* serverType = (dstPort == LOGIN_SERVER_PORT || srcPort == LOGIN_SERVER_PORT) ? "Login" : (dstPort == GAME_SERVER_PORT || srcPort == GAME_SERVER_PORT) ? "Game" : "Desconhecido";

            g_CaptureState.opcodeCount++;

            std::wstringstream logMsg;
            logMsg << L"[" << seq << L"][" << timeStr << L"] Pacote capturado (" << std::wstring(direction, direction + strlen(direction)) << L", tamanho: " << bufferLen << L" bytes, payload: " << dataLen << L" bytes, servidor: " << std::wstring(serverType, serverType + strlen(serverType)) << L")\n";
            logMsg << L"Opcode: 0x" << std::hex << (int)opcode << L" Fonte: " << std::wstring(srcIp, srcIp + strlen(srcIp)) << L":" << srcPort << L" Destino: " << std::wstring(dstIp, dstIp + strlen(dstIp)) << L":" << dstPort << L"\n";

            auto it = g_CaptureState.opcodeFunctions.find(opcode);
            if (it != g_CaptureState.opcodeFunctions.end()) {
                logMsg << L"Descrição: " << it->second << L"\n";
            }
            else {
                logMsg << L"Opcode desconhecido\n";
            }

            if (g_CaptureState.debugMode && dataLen > 0) {
                logMsg << L"Payload inicial: ";
                for (unsigned int i = 0; i < (dataLen < 16 ? dataLen : 16); i++) {
                    logMsg << std::hex << std::setw(2) << std::setfill(L'0') << (int)((unsigned char*)data)[i] << L" ";
                }
                logMsg << L"\n";
            }

            g_CaptureState.logFile << logMsg.str();
            g_CaptureState.logFile.flush();

            // Send to C# via TCP
            if (g_CaptureState.clientSocket != INVALID_SOCKET) {
                std::string narrowLog = std::string(logMsg.str().begin(), logMsg.str().end());
                send(g_CaptureState.clientSocket, narrowLog.c_str(), narrowLog.size(), 0);
            }

            WinDivertSend(divertHandle, buffer, bufferLen, nullptr, &addr);
        }
        else {
            DWORD error = GetLastError();
            if (error == ERROR_OPERATION_ABORTED) break;
            if (error != ERROR_IO_PENDING) {
                g_CaptureState.logFile << L"Erro no WinDivertRecv: " << error << L"\n";
                g_CaptureState.logFile.flush();
            }
            Sleep(100);
        }
    }
}

void SocketServer() {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        g_CaptureState.logFile << L"Erro ao inicializar Winsock: " << WSAGetLastError() << L"\n";
        g_CaptureState.logFile.flush();
        return;
    }

    g_CaptureState.serverSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (g_CaptureState.serverSocket == INVALID_SOCKET) {
        g_CaptureState.logFile << L"Erro ao criar socket: " << WSAGetLastError() << L"\n";
        g_CaptureState.logFile.flush();
        WSACleanup();
        return;
    }

    sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    inet_pton(AF_INET, "127.0.0.1", &serverAddr.sin_addr);
    serverAddr.sin_port = htons(atoi(TCP_PORT));
    if (bind(g_CaptureState.serverSocket, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        g_CaptureState.logFile << L"Erro ao vincular socket: " << WSAGetLastError() << L"\n";
        g_CaptureState.logFile.flush();
        closesocket(g_CaptureState.serverSocket);
        WSACleanup();
        return;
    }

    if (listen(g_CaptureState.serverSocket, SOMAXCONN) == SOCKET_ERROR) {
        g_CaptureState.logFile << L"Erro ao ouvir socket: " << WSAGetLastError() << L"\n";
        g_CaptureState.logFile.flush();
        closesocket(g_CaptureState.serverSocket);
        WSACleanup();
        return;
    }

    g_CaptureState.clientSocket = accept(g_CaptureState.serverSocket, nullptr, nullptr);
    if (g_CaptureState.clientSocket == INVALID_SOCKET) {
        g_CaptureState.logFile << L"Erro ao aceitar conexão: " << WSAGetLastError() << L"\n";
        g_CaptureState.logFile.flush();
        closesocket(g_CaptureState.serverSocket);
        WSACleanup();
        return;
    }

    u_long mode = 1;
    ioctlsocket(g_CaptureState.clientSocket, FIONBIO, &mode);

    char buffer[256];
    while (g_CaptureState.running) {
        time_t now = time(nullptr);
        char timeStr[32];
        ctime_s(timeStr, sizeof(timeStr), &now);
        timeStr[strlen(timeStr) - 1] = '\0';
        std::string pingMessage = std::string("Ping: ") + timeStr + "\n";
        send(g_CaptureState.clientSocket, pingMessage.c_str(), pingMessage.size(), 0);

        int received = recv(g_CaptureState.clientSocket, buffer, sizeof(buffer) - 1, 0);
        if (received > 0) {
            buffer[received] = '\0';
            g_CaptureState.logFile << L"Pong recebido: " << std::wstring(buffer, buffer + strlen(buffer)) << L"\n";
        }
        else if (received == SOCKET_ERROR) {
            int error = WSAGetLastError();
            if (error != WSAEWOULDBLOCK) {
                g_CaptureState.logFile << L"Erro ao receber pong: " << error << L"\n";
                g_CaptureState.logFile.flush();
                break;
            }
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(PING_INTERVAL));
    }
}

extern "C" {
    __declspec(dllexport) char* StartCapture() {
        if (g_CaptureState.running) return _strdup("Erro: Captura já em execução");
        if (g_pid == 0) return _strdup("Erro: PID não definido");
        g_CaptureState.running = true;
        LoadOpcodeFunctions(L"opcodes.txt", g_CaptureState.opcodeFunctions);
        g_CaptureState.socketThread = std::thread(SocketServer);
        g_CaptureState.captureThreads.push_back(new std::thread([]() {
            while (g_CaptureState.running) {
                auto connections = GetConnectionsByProcess();
                for (const auto& conn : connections) {
                    if (std::find(g_CaptureState.activePorts.begin(), g_CaptureState.activePorts.end(), conn.localPort) == g_CaptureState.activePorts.end()) {
                        char filter[256];
                        snprintf(filter, sizeof(filter), "tcp and (tcp.SrcPort = %u or tcp.DstPort = %u)", conn.localPort, conn.localPort);
                        HANDLE divertHandle = WinDivertOpen(filter, WINDIVERT_LAYER_NETWORK, 0, 0);
                        if (divertHandle == INVALID_HANDLE_VALUE) {
                            g_CaptureState.logFile << L"Erro ao abrir WinDivert para porta " << conn.localPort << L": " << GetLastError() << L"\n";
                            g_CaptureState.logFile.flush();
                            continue;
                        }
                        g_CaptureState.divertHandles.push_back(divertHandle);
                        g_CaptureState.activePorts.push_back(conn.localPort);
                        g_CaptureState.captureThreads.push_back(new std::thread(CapturePackets, divertHandle, conn.localPort));
                    }
                }
                Sleep(5000);
            }
            }));
        return _strdup("DLL respondendo");
    }

    __declspec(dllexport) void FreeString(char* str) {
        if (str) free(str);
    }

    __declspec(dllexport) BOOL StopCapture() {
        g_CaptureState.StopCapture();
        return TRUE;
    }

    __declspec(dllexport) void SetPID(DWORD pid) {
        g_pid = pid;
    }
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        g_CaptureState.logFile << L"DLL carregada.\n";
        g_CaptureState.logFile.flush();
        break;
    case DLL_THREAD_ATTACH:
        // No action
        break;
    case DLL_THREAD_DETACH:
        // No action
        break;
    case DLL_PROCESS_DETACH:
        g_CaptureState.StopCapture();
        g_CaptureState.logFile << L"DLL descarregada.\n";
        g_CaptureState.logFile.flush();
        g_CaptureState.logFile.close();
        break;
    }
    return TRUE;
}