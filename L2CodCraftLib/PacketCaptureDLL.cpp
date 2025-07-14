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
#include <nlohmann/json.hpp>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

using json = nlohmann::json;

#define MAX_PACKET_SIZE 65535

// Estrutura para configurações do servidor
struct ServerConfig {
    std::string loginIp;
    UINT16 loginPort;
    std::string gameIp;
    UINT16 gamePort;
};

// Estrutura para conexão
struct Connection {
    DWORD pid;
    UINT32 localAddr;
    UINT16 localPort;
};

// Estrutura para informações do pacote (simplificada para C#)
struct PacketInfo {
    unsigned char opcode;
    bool isInbound;
    UINT packetSize;
    UINT32 sequence;
    char timestamp[32];
    char sourceIp[16];
    UINT16 sourcePort;
    char destIp[16];
    UINT16 destPort;
    char serverType[16];
    wchar_t description[256];
};

// Callback para notificar C# sobre novos pacotes
typedef void (*PacketCallback)(const PacketInfo* packet);

// Estado global da captura
struct PacketCaptureState {
    std::atomic<bool> running = false;
    std::vector<std::thread*> captureThreads;
    std::vector<HANDLE> divertHandles;
    std::vector<UINT16> activePorts;
    std::atomic<unsigned long> packetSequence = 0;
    std::wofstream logFile;
    std::map<unsigned char, std::wstring> opcodeFunctions;
    PacketCallback callback = nullptr;

    PacketCaptureState() : logFile(L"packets.log", std::ios::app) {
        if (logFile.tellp() == 0) {
            logFile << L"\xFEFF";
        }
        opcodeFunctions = {
            {0x09, L"Sincronização / Keep-alive"},
            {0x07, L"Sincronização / Atualização de status"},
            {0x0D, L"Sincronização / Confirmação de ação"},
            {0x1B, L"Movimento (Mover para localização)"},
            // ... outros opcodes ...
        };
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
        for (auto thread : captureThreads) {
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
    }

    ~PacketCaptureState() {
        StopCapture();
        logFile.close();
    }
};

PacketCaptureState g_CaptureState;
ServerConfig g_ServerConfig;

// Carrega configurações do JSON
bool LoadServerConfig(const std::wstring& filename) {
    std::ifstream file(filename);
    if (!file.is_open()) {
        g_CaptureState.logFile << L"Erro: Não foi possível abrir " << filename << L"\n";
        g_CaptureState.logFile.flush();
        return false;
    }

    try {
        json j;
        file >> j;
        g_ServerConfig.loginIp = j["login_server"]["ip"].get<std::string>();
        g_ServerConfig.loginPort = j["login_server"]["port"].get<UINT16>();
        g_ServerConfig.gameIp = j["game_server"]["ip"].get<std::string>();
        g_ServerConfig.gamePort = j["game_server"]["port"].get<UINT16>();
        g_CaptureState.logFile << L"Configurações carregadas: Login=" << std::wstring(g_ServerConfig.loginIp.begin(), g_ServerConfig.loginIp.end()) << L":" << g_ServerConfig.loginPort
            << L", Game=" << std::wstring(g_ServerConfig.gameIp.begin(), g_ServerConfig.gameIp.end()) << L":" << g_ServerConfig.gamePort << L"\n";
        g_CaptureState.logFile.flush();
        return true;
    }
    catch (const json::exception& e) {
        g_CaptureState.logFile << L"Erro ao parsear JSON: " << e.what() << L"\n";
        g_CaptureState.logFile.flush();
        return false;
    }
}

// Obtém conexões por processo
std::vector<Connection> GetConnectionsByProcess(const char* processName) {
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
            char exePath[MAX_PATH];
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, row->dwOwningPid);
            if (hProcess) {
                DWORD pathSize = MAX_PATH;
                if (QueryFullProcessImageNameA(hProcess, 0, exePath, &pathSize)) {
                    if (strstr(exePath, processName)) {
                        Connection conn = { row->dwOwningPid, row->dwLocalAddr, ntohs((UINT16)row->dwLocalPort) };
                        connections.push_back(conn);
                        g_CaptureState.logFile << L"Conexão encontrada: PID=" << conn.pid << L", Porta local=" << conn.localPort << L"\n";
                    }
                }
                CloseHandle(hProcess);
            }
        }
    }
    free(tcpTable);
    g_CaptureState.logFile << L"Conexões verificadas, encontradas: " << connections.size() << L"\n";
    g_CaptureState.logFile.flush();
    return connections;
}

// Captura de pacotes
void CapturePackets(HANDLE divertHandle, UINT16 localPort) {
    char buffer[MAX_PACKET_SIZE];
    UINT bufferLen;
    WINDIVERT_ADDRESS addr;

    g_CaptureState.logFile << L"Capturando pacotes na porta local " << localPort << L" (entrada e saída)...\n";
    g_CaptureState.logFile.flush();

    while (g_CaptureState.running) {
        if (WinDivertRecv(divertHandle, buffer, sizeof(buffer), &bufferLen, &addr)) {
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

            PacketInfo packet = {};
            packet.sequence = seq;
            strncpy_s(packet.timestamp, timeStr, sizeof(packet.timestamp));
            inet_ntop(AF_INET, &ipHdr->SrcAddr, packet.sourceIp, sizeof(packet.sourceIp));
            inet_ntop(AF_INET, &ipHdr->DstAddr, packet.destIp, sizeof(packet.destIp));
            packet.sourcePort = ntohs(tcpHdr->SrcPort);
            packet.destPort = ntohs(tcpHdr->DstPort);
            packet.packetSize = bufferLen;

            if (dataLen < 1) {
                g_CaptureState.logFile << L"[" << seq << L"][" << timeStr << L"] Pacote vazio (handshake TCP, tamanho: " << bufferLen << L" bytes)\n";
                g_CaptureState.logFile.flush();
                WinDivertSend(divertHandle, buffer, bufferLen, nullptr, &addr);
                continue;
            }

            packet.opcode = ((unsigned char*)data)[0];
            packet.isInbound = isInbound;
            strncpy_s(packet.serverType,
                (packet.destPort == g_ServerConfig.loginPort || packet.sourcePort == g_ServerConfig.loginPort) ? "Login" :
                (packet.destPort == g_ServerConfig.gamePort || packet.sourcePort == g_ServerConfig.gamePort) ? "Game" : "Desconhecido",
                sizeof(packet.serverType));

            auto it = g_CaptureState.opcodeFunctions.find(packet.opcode);
            if (it != g_CaptureState.opcodeFunctions.end()) {
                wcsncpy_s(packet.description, it->second.c_str(), sizeof(packet.description) / sizeof(wchar_t));
            }
            else {
                swprintf_s(packet.description, L"Opcode desconhecido: 0x%02X", packet.opcode);
            }

            // Notifica C# via callback
            if (g_CaptureState.callback) {
                g_CaptureState.callback(&packet);
            }

            g_CaptureState.logFile << L"[" << seq << L"][" << timeStr << L"] Opcode: 0x" << std::hex << (int)packet.opcode << L" (" << packet.description << L")\n";
            g_CaptureState.logFile.flush();

            WinDivertSend(divertHandle, buffer, bufferLen, nullptr, &addr);
        }
        else {
            DWORD error = GetLastError();
            if (error == ERROR_OPERATION_ABORTED) {
                g_CaptureState.logFile << L"WinDivertRecv abortado (handle fechado), saindo...\n";
                g_CaptureState.logFile.flush();
                break;
            }
            if (error != ERROR_IO_PENDING) {
                g_CaptureState.logFile << L"Erro no WinDivertRecv: " << error << L"\n";
                g_CaptureState.logFile.flush();
                Sleep(100);
            }
        }
    }
}

// Monitoramento de conexões
void MonitorConnections() {
    const char* processName = "L2.exe";
    while (g_CaptureState.running) {
        if (GetAsyncKeyState(VK_F12) & 0x8000) {
            g_CaptureState.ClearLogFile();
            g_CaptureState.logFile << L"Arquivo de log limpo.\n";
            g_CaptureState.logFile.flush();
            Sleep(200);
        }

        auto connections = GetConnectionsByProcess(processName);
        if (!connections.empty()) {
            bool portChanged = false;
            for (const auto& conn : connections) {
                if (std::find(g_CaptureState.activePorts.begin(), g_CaptureState.activePorts.end(), conn.localPort) == g_CaptureState.activePorts.end()) {
                    portChanged = true;
                    break;
                }
            }

            if (portChanged) {
                g_CaptureState.packetSequence = 0;
                g_CaptureState.logFile << L"Instâncias encontradas:\n";
                for (const auto& conn : connections) {
                    g_CaptureState.logFile << L"PID: " << conn.pid << L", Porta local=" << conn.localPort << L"\n";
                    g_CaptureState.logFile.flush();

                    if (std::find(g_CaptureState.activePorts.begin(), g_CaptureState.activePorts.end(), conn.localPort) == g_CaptureState.activePorts.end()) {
                        char filter[256];
                        snprintf(filter, sizeof(filter),
                            "tcp and (tcp.SrcPort = %u or tcp.DstPort = %u)",
                            conn.localPort, conn.localPort);

                        HANDLE divertHandle = WinDivertOpen(filter, WINDIVERT_LAYER_NETWORK, 0, 0);
                        if (divertHandle == INVALID_HANDLE_VALUE) {
                            g_CaptureState.logFile << L"Erro ao abrir WinDivert para porta " << conn.localPort << L": " << GetLastError() << L"\n";
                            g_CaptureState.logFile.flush();
                            continue;
                        }

                        g_CaptureState.logFile << L"WinDivert aberto com sucesso para porta " << conn.localPort << L"\n";
                        g_CaptureState.logFile.flush();

                        g_CaptureState.divertHandles.push_back(divertHandle);
                        g_CaptureState.activePorts.push_back(conn.localPort);
                        g_CaptureState.captureThreads.push_back(new std::thread(CapturePackets, divertHandle, conn.localPort));
                    }
                }
            }
        }
        else if (!g_CaptureState.divertHandles.empty()) {
            g_CaptureState.StopCapture();
            g_CaptureState.logFile << L"Nenhuma instância do L2.exe encontrada. Aguardando...\n";
            g_CaptureState.logFile.flush();
        }
        Sleep(5000);
    }
}

// Funções exportadas
extern "C" {
    __declspec(dllexport) BOOL StartCapture(PacketCallback callback) {
        if (g_CaptureState.running) {
            g_CaptureState.logFile << L"Captura já está em execução.\n";
            g_CaptureState.logFile.flush();
            return FALSE;
        }

        WSADATA wsaData;
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
            g_CaptureState.logFile << L"Erro ao inicializar Winsock: " << WSAGetLastError() << L"\n";
            g_CaptureState.logFile.flush();
            return FALSE;
        }

        if (!LoadServerConfig(L"settings.json")) {
            g_CaptureState.logFile << L"Falha ao carregar configurações do servidor.\n";
            g_CaptureState.logFile.flush();
            WSACleanup();
            return FALSE;
        }

        g_CaptureState.callback = callback;
        g_CaptureState.running = true;
        std::thread(MonitorConnections).detach();

        g_CaptureState.logFile << L"Captura iniciada.\n";
        g_CaptureState.logFile.flush();
        return TRUE;
    }

    __declspec(dllexport) BOOL StopCapture() {
        if (!g_CaptureState.running) {
            g_CaptureState.logFile << L"Captura já está parada.\n";
            g_CaptureState.logFile.flush();
            return FALSE;
        }

        g_CaptureState.StopCapture();
        WSACleanup();

        g_CaptureState.logFile << L"Captura parada.\n";
        g_CaptureState.logFile.flush();
        return TRUE;
    }
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        g_CaptureState.logFile << L"DLL carregada.\n";
        g_CaptureState.logFile.flush();
        break;
    case DLL_PROCESS_DETACH:
        g_CaptureState.StopCapture();
        g_CaptureState.logFile << L"DLL descarregada.\n";
        g_CaptureState.logFile.flush();
        break;
    }
    return TRUE;
}