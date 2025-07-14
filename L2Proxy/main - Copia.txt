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
#include <iomanip> // Adicionado para std::setw e std::setfill

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

#define LOGIN_SERVER_PORT 2106
#define GAME_SERVER_PORT 7778
#define MAX_PACKET_SIZE 65535

struct Connection {
    DWORD pid;
    UINT32 localAddr;
    UINT16 localPort;
};

struct BlowfishKey {
    unsigned char key[16];
    bool valid;
};

struct PacketInfo {
    unsigned char opcode;
    bool isInbound; // true = servidor -> cliente, false = cliente -> servidor
    UINT packetSize;
};

struct PacketCaptureState {
    std::atomic<bool> running = true;
    std::vector<PacketInfo> capturedPackets;
    std::atomic<unsigned long> packetSequence = 0;
    std::atomic<int> opcodeCount = 0; // Membro da estrutura, não global
    BlowfishKey blowfishKey = { {0}, false };
    std::wofstream logFile; // Usa wofstream para Unicode
    bool debugMode = true;
    std::map<unsigned char, std::wstring> opcodeFunctions;
    UINT32 lastTargetId = 0;
    time_t lastAttackTime = 0;
    INT32 playerX = 0, playerY = 0, playerZ = 0;

    PacketCaptureState() : logFile(L"packets.log", std::ios::app) {
        // Escreve BOM UTF-8 se o arquivo for novo
        if (logFile.tellp() == 0) {
            logFile << L"\xFEFF";
        }
        // Inicializa tabela de opcodes
        opcodeFunctions = {
            {0x09, L"Sincronização / Keep-alive"},
            {0x07, L"Sincronização / Atualização de status"},
            {0x0D, L"Sincronização / Confirmação de ação"},
            {0x1B, L"Movimento (Mover para localização)"},
            {0x19, L"Movimento (Atualizar posição)"},
            {0x27, L"Movimento (Parar de mover)"},
            {0x6F, L"Ataque ao NPC"},
            {0x12, L"Ação pós-ataque ou confirmação"},
            {0x22, L"RequestMove"},
            {0x7A, L"StatusUpdate"},
            {0x1A, L"NpcInfo"},
            {0x32, L"ItemList"},
            {0x03, L"LoginOk"},
            {0x01, L"LoginFail"},
            {0xB3, L"ServerList"},
            {0x2B, L"PlayOk"},
            {0x1C, L"RequestCharacterSelect"},
            {0x15, L"Configuração de Estado"},
            {0x43, L"Interação Inicial"},
            {0x51, L"Comando de Combate"},
            {0x23, L"Movimento Inicial"},
            {0x13, L"Atualização Secundária"},
            {0x1F, L"Seleção de Alvo"},
            {0x18, L"Seleção de NPC"}, // Ajustado para seleção
            {0x3F, L"Interação Complexa"}
        };
    }

    void ClearLogFile() {
        logFile.close();
        logFile.open(L"packets.log", std::ios::out | std::ios::trunc);
        logFile << L"\xFEFF"; // Reinsere BOM UTF-8
        logFile << L"Log limpo em " << std::time(nullptr) << L"\n";
        logFile.flush();
    }
};

PacketCaptureState g_CaptureState;

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
                if (ss.fail() || temp > 0xFF) {
                    g_CaptureState.logFile << L"Erro ao parsear opcode: " << hexOpcodeStr << L"\n";
                    continue;
                }
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
    else {
        g_CaptureState.logFile << L"Erro ao obter tabela TCP: " << GetLastError() << L"\n";
    }
    free(tcpTable);
    g_CaptureState.logFile << L"Conexões verificadas, encontradas: " << connections.size() << L"\n";
    g_CaptureState.logFile.flush();
    return connections;
}

bool SendAttackPacket(HANDLE divertHandle, WINDIVERT_ADDRESS* addr, UINT32 targetId, UINT16 localPort, time_t currentTime) {
    if (currentTime - g_CaptureState.lastAttackTime < 2) {
        return false;
    }

    unsigned char attackPacket[] = {
        0x6F, 0x00, // Opcode
        0x00, 0x00, 0x00, 0x00, // ID do NPC
        0x60, 0x6B, 0x6C, 0xD8, 0xB2, 0x0D, 0x1C, 0x1B, 0x0F, 0x42,
        0xAB, 0xCF, 0xE7, 0x4B, 0xD2, 0x21, 0x51, 0xFE, 0x2B, 0x11,
        0x37, 0x82, 0x93, 0x94, 0x81, 0xA8, 0x3B, 0x3A, 0x9B, 0xF7,
        0xC6, 0x51, 0x20, 0xEB, 0x44, 0x69, 0x02, 0x7E, 0xD3, 0x26,
        0x94, 0xDB, 0x12, 0x18, 0x21, 0x7B, 0xEF, 0xC5, 0x3D, 0x1B,
        0xCB, 0x02, 0xBE, 0x60, 0x38, 0xDD, 0x57, 0x91, 0x74, 0x9E,
        0xF1, 0x3E, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    UINT attackPacketLen = 111 + 40;

    memcpy(attackPacket + 2, &targetId, sizeof(targetId));

    char fullPacket[MAX_PACKET_SIZE];
    memcpy(fullPacket + 40, attackPacket, 111);
    WINDIVERT_IPHDR* ipHdr = (WINDIVERT_IPHDR*)fullPacket;
    WINDIVERT_TCPHDR* tcpHdr = (WINDIVERT_TCPHDR*)(fullPacket + sizeof(WINDIVERT_IPHDR));

    ipHdr->Version = 4;
    ipHdr->HdrLength = 5;
    ipHdr->Length = htons((USHORT)(sizeof(WINDIVERT_IPHDR) + sizeof(WINDIVERT_TCPHDR) + 111));
    ipHdr->TTL = 128;
    ipHdr->Protocol = IPPROTO_TCP;
    inet_pton(AF_INET, "10.0.0.184", &ipHdr->SrcAddr);
    inet_pton(AF_INET, "162.19.106.176", &ipHdr->DstAddr);

    tcpHdr->SrcPort = htons(localPort);
    tcpHdr->DstPort = htons(GAME_SERVER_PORT);
    tcpHdr->SeqNum = htonl(0x12345678);
    tcpHdr->AckNum = htonl(0);
    tcpHdr->HdrLength = 5;
    tcpHdr->Psh = 1;
    tcpHdr->Ack = 1;

    WinDivertHelperCalcChecksums(fullPacket, attackPacketLen, nullptr, 0);

    WINDIVERT_ADDRESS sendAddr = *addr;
    sendAddr.Outbound = TRUE;

    if (!WinDivertSend(divertHandle, fullPacket, attackPacketLen, nullptr, &sendAddr)) {
        g_CaptureState.logFile << L"Erro ao enviar pacote de ataque: " << GetLastError() << L"\n";
        g_CaptureState.logFile.flush();
        return false;
    }

    g_CaptureState.lastAttackTime = currentTime;
    g_CaptureState.logFile << L"Pacote de ataque (0x6F) enviado para NPC ID: " << targetId << L"\n";
    g_CaptureState.logFile.flush();
    return true;
}

void CapturePackets(HANDLE divertHandle, UINT16 localPort) {
    char buffer[MAX_PACKET_SIZE];
    UINT bufferLen;
    WINDIVERT_ADDRESS addr;

    wprintf(L"Capturando pacotes na porta local %u (entrada e saída)...\n", localPort);
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
                wprintf(L"[%lu][%s] Erro ao parsear pacote\n", seq, timeStr);
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

            wprintf(L"[%lu][%s] Pacote: %S:%u -> %S:%u\n", seq, timeStr, srcIp, srcPort, dstIp, dstPort);
            g_CaptureState.logFile << L"[" << seq << L"][" << timeStr << L"] Pacote: " << std::wstring(srcIp, srcIp + strlen(srcIp)) << L":" << srcPort << L" -> " << std::wstring(dstIp, dstIp + strlen(dstIp)) << L":" << dstPort << L"\n";
            g_CaptureState.logFile.flush();

            if (dataLen < 1) {
                wprintf(L"[%lu][%s] Pacote vazio (handshake TCP, tamanho: %u bytes)\n", seq, timeStr, bufferLen);
                g_CaptureState.logFile << L"[" << seq << L"][" << timeStr << L"] Pacote vazio (handshake TCP, tamanho: " << bufferLen << L" bytes)\n";
                g_CaptureState.logFile.flush();
                WinDivertSend(divertHandle, buffer, bufferLen, nullptr, &addr);
                continue;
            }

            const char* serverType = (dstPort == LOGIN_SERVER_PORT || srcPort == LOGIN_SERVER_PORT) ? "Login" :
                (dstPort == GAME_SERVER_PORT || srcPort == GAME_SERVER_PORT) ? "Game" : "Desconhecido";

            unsigned char opcode = ((unsigned char*)data)[0];
            g_CaptureState.opcodeCount++;

            wprintf(L"[%lu][%s] Pacote capturado (%S, tamanho: %u bytes, payload: %u bytes, servidor: %S)\n", seq, timeStr, direction, bufferLen, dataLen, serverType);
            g_CaptureState.logFile << L"[" << seq << L"][" << timeStr << L"] Pacote capturado (" << std::wstring(direction, direction + strlen(direction)) << L", tamanho: " << bufferLen << L" bytes, payload: " << dataLen << L" bytes, servidor: " << std::wstring(serverType, serverType + strlen(serverType)) << L")\n";

            auto it = g_CaptureState.opcodeFunctions.find(opcode);
            if (it != g_CaptureState.opcodeFunctions.end()) {
                wprintf(L"[%lu][%s] Opcode: 0x%02X (%S, %S): %s\n", seq, timeStr, opcode, direction, serverType, it->second.c_str());
                g_CaptureState.logFile << L"[" << seq << L"][" << timeStr << L"] Opcode: 0x" << std::hex << (int)opcode << L" (" << std::wstring(direction, direction + strlen(direction)) << L", " << std::wstring(serverType, serverType + strlen(serverType)) << L"): " << it->second << L"\n";
            }
            else {
                wprintf(L"[%lu][%s] Opcode desconhecido: 0x%02X (%S, %S)\n", seq, timeStr, opcode, direction, serverType);
                g_CaptureState.logFile << L"[" << seq << L"][" << timeStr << L"] Opcode desconhecido: 0x" << std::hex << (int)opcode << L" (" << std::wstring(direction, direction + strlen(direction)) << L", " << std::wstring(serverType, serverType + strlen(serverType)) << L")\n";
                if (g_CaptureState.debugMode && dataLen > 0) {
                    g_CaptureState.logFile << L"[" << seq << L"][" << timeStr << L"] Payload inicial: ";
                    for (unsigned int i = 0; i < (dataLen < 16 ? dataLen : 16); i++) {
                        g_CaptureState.logFile << std::hex << std::setw(2) << std::setfill(L'0') << (int)((unsigned char*)data)[i] << L" ";
                    }
                    g_CaptureState.logFile << L"\n";
                }
            }

            PacketInfo packet = { opcode, isInbound, bufferLen };
            g_CaptureState.capturedPackets.push_back(packet);

            // Detecta seleção de NPC (0x18 ou 0x1F) e envia ataque
            if (strcmp(serverType, "Game") == 0 && (opcode == 0x18 || opcode == 0x1F) && !isInbound && dataLen >= 7) {
                UINT32 targetId = *(UINT32*)((unsigned char*)data + 2);
                g_CaptureState.lastTargetId = targetId;
                wprintf(L"[%lu][%s] NPC selecionado, ID: %u\n", seq, timeStr, targetId);
                g_CaptureState.logFile << L"[" << seq << L"][" << timeStr << L"] NPC selecionado, ID: " << targetId << L"\n";
                if (g_CaptureState.debugMode && dataLen > 0) {
                    g_CaptureState.logFile << L"[" << seq << L"][" << timeStr << L"] Payload completo: ";
                    for (unsigned int i = 0; i < dataLen; i++) {
                        g_CaptureState.logFile << std::hex << std::setw(2) << std::setfill(L'0') << (int)((unsigned char*)data)[i] << L" ";
                    }
                    g_CaptureState.logFile << L"\n";
                }
                g_CaptureState.logFile.flush();

                SendAttackPacket(divertHandle, &addr, targetId, localPort, now);
            }

            // Atualiza coordenadas do jogador a partir de 0x1B
            if (strcmp(serverType, "Game") == 0 && opcode == 0x1B && !isInbound && dataLen >= 18) {
                g_CaptureState.playerX = *(INT32*)((unsigned char*)data + 6); // Ajustado offset
                g_CaptureState.playerY = *(INT32*)((unsigned char*)data + 10);
                g_CaptureState.playerZ = *(INT32*)((unsigned char*)data + 14);
                wprintf(L"[%lu][%s] Coordenadas atualizadas: X=%d, Y=%d, Z=%d\n", seq, timeStr, g_CaptureState.playerX, g_CaptureState.playerY, g_CaptureState.playerZ);
                g_CaptureState.logFile << L"[" << seq << L"][" << timeStr << L"] Coordenadas atualizadas: X=" << g_CaptureState.playerX << L", Y=" << g_CaptureState.playerY << L", Z=" << g_CaptureState.playerZ << L"\n";
                g_CaptureState.logFile.flush();
            }

            if (strcmp(serverType, "Login") == 0) {
                if (opcode == 0x07 && isInbound) {
                    wprintf(L"[%lu][%s] Init detectado (tamanho: %u bytes)\n", seq, timeStr, bufferLen);
                    g_CaptureState.logFile << L"[" << seq << L"][" << timeStr << L"] Init detectado (tamanho: " << bufferLen << L" bytes)\n";
                    if (dataLen >= 56) {
                        int blowfishOffset = dataLen - 16;
                        memcpy(g_CaptureState.blowfishKey.key, (unsigned char*)data + blowfishOffset, 16);
                        g_CaptureState.blowfishKey.valid = true;
                        wprintf(L"[%lu][%s] Chave Blowfish: ", seq, timeStr);
                        std::wstringstream keyStr;
                        for (int i = 0; i < 16; i++) {
                            wprintf(L"%02X ", g_CaptureState.blowfishKey.key[i]);
                            keyStr << std::hex << std::setw(2) << std::setfill(L'0') << (int)g_CaptureState.blowfishKey.key[i] << L" ";
                        }
                        wprintf(L"\n");
                        g_CaptureState.logFile << L"[" << seq << L"][" << timeStr << L"] Chave Blowfish: " << keyStr.str() << L"\n";
                        g_CaptureState.logFile.flush();
                    }
                }
                else if (opcode == 0x09 && !isInbound) {
                    wprintf(L"[%lu][%s] RequestServerList detectado (tamanho: %u bytes)\n", seq, timeStr, bufferLen);
                    g_CaptureState.logFile << L"[" << seq << L"][" << timeStr << L"] RequestServerList detectado (tamanho: " << bufferLen << L" bytes)\n";
                    g_CaptureState.logFile.flush();
                }
                else if (opcode == 0x0D && !isInbound) {
                    wprintf(L"[%lu][%s] RequestAuthLogin detectado (tamanho: %u bytes)\n", seq, timeStr, bufferLen);
                    g_CaptureState.logFile << L"[" << seq << L"][" << timeStr << L"] RequestAuthLogin detectado (tamanho: " << bufferLen << L" bytes)\n";
                    if (dataLen >= 31) {
                        char username[16] = { 0 };
                        memcpy(username, (unsigned char*)data + 18, 14);
                        wprintf(L"[%lu][%s] Username (+18): %S\n", seq, timeStr, username);
                        g_CaptureState.logFile << L"[" << seq << L"][" << timeStr << L"] Username (+18): " << std::wstring(username, username + strlen(username)) << L"\n";
                        if (username[0] == '\0' || strstr(username, "messiasgama") == nullptr) {
                            memcpy(username, (unsigned char*)data + 16, 14);
                            wprintf(L"[%lu][%s] Username (+16): %S\n", seq, timeStr, username);
                            g_CaptureState.logFile << L"[" << seq << L"][" << timeStr << L"] Username (+16): " << std::wstring(username, username + strlen(username)) << L"\n";
                        }
                        if (username[0] == '\0' || strstr(username, "messiasgama") == nullptr) {
                            memcpy(username, (unsigned char*)data + 14, 14);
                            wprintf(L"[%lu][%s] Username (+14): %S\n", seq, timeStr, username);
                            g_CaptureState.logFile << L"[" << seq << L"][" << timeStr << L"] Username (+14): " << std::wstring(username, username + strlen(username)) << L"\n";
                        }
                        if (username[0] == '\0' || strstr(username, "messiasgama") == nullptr) {
                            memcpy(username, (unsigned char*)data + 12, 14);
                            wprintf(L"[%lu][%s] Username (+12): %S\n", seq, timeStr, username);
                            g_CaptureState.logFile << L"[" << seq << L"][" << timeStr << L"] Username (+12): " << std::wstring(username, username + strlen(username)) << L"\n";
                        }
                    }
                    if (g_CaptureState.debugMode && dataLen > 0) {
                        g_CaptureState.logFile << L"[" << seq << L"][" << timeStr << L"] Full Payload: ";
                        for (unsigned int i = 0; i < dataLen; i++) {
                            g_CaptureState.logFile << std::hex << std::setw(2) << std::setfill(L'0') << (int)((unsigned char*)data)[i] << L" ";
                        }
                        g_CaptureState.logFile << L"\n";
                    }
                    g_CaptureState.logFile.flush();
                }
                else if (opcode == 0x03 && isInbound) {
                    wprintf(L"[%lu][%s] LoginOk detectado\n", seq, timeStr);
                    g_CaptureState.logFile << L"[" << seq << L"][" << timeStr << L"] LoginOk detectado\n";
                    if (dataLen >= 10) {
                        int sessionId1 = *(int*)((unsigned char*)data + 2);
                        int sessionId2 = *(int*)((unsigned char*)data + 6);
                        wprintf(L"[%lu][%s] Session IDs: %d, %d\n", seq, timeStr, sessionId1, sessionId2);
                        g_CaptureState.logFile << L"[" << seq << L"][" << timeStr << L"] Session IDs: " << sessionId1 << L", " << sessionId2 << L"\n";
                    }
                    g_CaptureState.logFile.flush();
                }
                else if (opcode == 0x01 && isInbound) {
                    wprintf(L"[%lu][%s] LoginFail detectado\n", seq, timeStr);
                    g_CaptureState.logFile << L"[" << seq << L"][" << timeStr << L"] LoginFail detectado\n";
                    if (dataLen >= 3) {
                        int reason = *(unsigned char*)((unsigned char*)data + 2);
                        wprintf(L"[%lu][%s] Motivo: %d\n", seq, timeStr, reason);
                        g_CaptureState.logFile << L"[" << seq << L"][" << timeStr << L"] Motivo: " << reason << L"\n";
                    }
                    g_CaptureState.logFile.flush();
                }
                else if (opcode == 0xB3 && isInbound) {
                    wprintf(L"[%lu][%s] ServerList detectado (tamanho: %u bytes)\n", seq, timeStr, bufferLen);
                    g_CaptureState.logFile << L"[" << seq << L"][" << timeStr << L"] ServerList detectado (tamanho: " << bufferLen << L" bytes)\n";
                    if (dataLen >= 20) {
                        int numServers = *(unsigned char*)((unsigned char*)data + 4);
                        int offset = 6;
                        for (int i = 0; i < numServers && offset + 6 < dataLen; i++) {
                            char serverIp[16] = { 0 };
                            UINT16 serverPort = *(UINT16*)((unsigned char*)data + offset + 4);
                            inet_ntop(AF_INET, (unsigned char*)data + offset, serverIp, sizeof(serverIp));
                            wprintf(L"[%lu][%s] Game Server %d: %S:%u\n", seq, timeStr, i + 1, serverIp, ntohs(serverPort));
                            g_CaptureState.logFile << L"[" << seq << L"][" << timeStr << L"] Game Server " << i + 1 << L": " << std::wstring(serverIp, serverIp + strlen(serverIp)) << L":" << ntohs(serverPort) << L"\n";
                            offset += 10;
                        }
                    }
                    if (g_CaptureState.debugMode && dataLen > 0) {
                        g_CaptureState.logFile << L"[" << seq << L"][" << timeStr << L"] Full Payload: ";
                        for (unsigned int i = 0; i < (dataLen < 64 ? dataLen : 64); i++) {
                            g_CaptureState.logFile << std::hex << std::setw(2) << std::setfill(L'0') << (int)((unsigned char*)data)[i] << L" ";
                        }
                        g_CaptureState.logFile << L"\n";
                    }
                    g_CaptureState.logFile.flush();
                }
                else if (opcode == 0x2B && isInbound) {
                    wprintf(L"[%lu][%s] PlayOk detectado (tamanho: %u bytes)\n", seq, timeStr, bufferLen);
                    g_CaptureState.logFile << L"[" << seq << L"][" << timeStr << L"] PlayOk detectado (tamanho: " << bufferLen << L" bytes)\n";
                    if (g_CaptureState.debugMode && dataLen > 0) {
                        g_CaptureState.logFile << L"[" << seq << L"][" << timeStr << L"] Full Payload: ";
                        for (unsigned int i = 0; i < (dataLen < 64 ? dataLen : 64); i++) {
                            g_CaptureState.logFile << std::hex << std::setw(2) << std::setfill(L'0') << (int)((unsigned char*)data)[i] << L" ";
                        }
                        g_CaptureState.logFile << L"\n";
                    }
                    g_CaptureState.logFile.flush();
                }
                else if (opcode == 0x1B && !isInbound) {
                    wprintf(L"[%lu][%s] RequestServerLogin detectado (tamanho: %u bytes)\n", seq, timeStr, bufferLen);
                    g_CaptureState.logFile << L"[" << seq << L"][" << timeStr << L"] RequestServerLogin detectado (tamanho: " << bufferLen << L" bytes)\n";
                    if (g_CaptureState.debugMode && dataLen > 0) {
                        g_CaptureState.logFile << L"[" << seq << L"][" << timeStr << L"] Full Payload: ";
                        for (unsigned int i = 0; i < dataLen; i++) {
                            g_CaptureState.logFile << std::hex << std::setw(2) << std::setfill(L'0') << (int)((unsigned char*)data)[i] << L" ";
                        }
                        g_CaptureState.logFile << L"\n";
                    }
                    g_CaptureState.logFile.flush();
                }
                else if (opcode == 0x1C && !isInbound) {
                    wprintf(L"[%lu][%s] RequestCharacterSelect detectado (tamanho: %u bytes)\n", seq, timeStr, bufferLen);
                    g_CaptureState.logFile << L"[" << seq << L"][" << timeStr << L"] RequestCharacterSelect detectado (tamanho: " << bufferLen << L" bytes)\n";
                    if (g_CaptureState.debugMode && dataLen > 0) {
                        g_CaptureState.logFile << L"[" << seq << L"][" << timeStr << L"] Full Payload: ";
                        for (unsigned int i = 0; i < dataLen; i++) {
                            g_CaptureState.logFile << std::hex << std::setw(2) << std::setfill(L'0') << (int)((unsigned char*)data)[i] << L" ";
                        }
                        g_CaptureState.logFile << L"\n";
                    }
                    g_CaptureState.logFile.flush();
                }
            }
            else if (strcmp(serverType, "Game") == 0) {
                if (opcode == 0x22 && !isInbound) {
                    wprintf(L"[%lu][%s] RequestMove detectado (tamanho: %u bytes)\n", seq, timeStr, bufferLen);
                    g_CaptureState.logFile << L"[" << seq << L"][" << timeStr << L"] RequestMove detectado (tamanho: " << bufferLen << L" bytes)\n";
                    if (dataLen >= 22) {
                        int x = *(int*)((unsigned char*)data + 14);
                        int y = *(int*)((unsigned char*)data + 18);
                        wprintf(L"[%lu][%s] Coordenadas: X=%d, Y=%d\n", seq, timeStr, x, y);
                        g_CaptureState.logFile << L"[" << seq << L"][" << timeStr << L"] Coordenadas: X=" << x << L", Y=" << y << L"\n";
                        g_CaptureState.logFile.flush();
                    }
                    if (g_CaptureState.debugMode && dataLen > 0) {
                        g_CaptureState.logFile << L"[" << seq << L"][" << timeStr << L"] Full Payload: ";
                        for (unsigned int i = 0; i < dataLen; i++) {
                            g_CaptureState.logFile << std::hex << std::setw(2) << std::setfill(L'0') << (int)((unsigned char*)data)[i] << L" ";
                        }
                        g_CaptureState.logFile << L"\n";
                    }
                }
                else if (opcode == 0x7A && isInbound) {
                    wprintf(L"[%lu][%s] StatusUpdate detectado (tamanho: %u bytes)\n", seq, timeStr, bufferLen);
                    g_CaptureState.logFile << L"[" << seq << L"][" << timeStr << L"] StatusUpdate detectado (tamanho: " << bufferLen << L" bytes)\n";
                    if (dataLen >= 14) {
                        int hp = *(int*)((unsigned char*)data + 6);
                        int mp = *(int*)((unsigned char*)data + 10);
                        wprintf(L"[%lu][%s] HP: %d, MP: %d\n", seq, timeStr, hp, mp);
                        g_CaptureState.logFile << L"[" << seq << L"][" << timeStr << L"] HP: " << hp << L", MP: " << mp << L"\n";
                        g_CaptureState.logFile.flush();
                    }
                    if (g_CaptureState.debugMode && dataLen > 0) {
                        g_CaptureState.logFile << L"[" << seq << L"][" << timeStr << L"] Full Payload: ";
                        for (unsigned int i = 0; i < (dataLen < 64 ? dataLen : 64); i++) {
                            g_CaptureState.logFile << std::hex << std::setw(2) << std::setfill(L'0') << (int)((unsigned char*)data)[i] << L" ";
                        }
                        g_CaptureState.logFile << L"\n";
                    }
                }
                else if (opcode == 0x1A && isInbound) {
                    wprintf(L"[%lu][%s] NpcInfo detectado (tamanho: %u bytes)\n", seq, timeStr, bufferLen);
                    g_CaptureState.logFile << L"[" << seq << L"][" << timeStr << L"] NpcInfo detectado (tamanho: " << bufferLen << L" bytes)\n";
                    if (dataLen >= 14) {
                        int npcId = *(int*)((unsigned char*)data + 12);
                        wprintf(L"[%lu][%s] NPC ID: %d\n", seq, timeStr, npcId);
                        g_CaptureState.logFile << L"[" << seq << L"][" << timeStr << L"] NPC ID: " << npcId << L"\n";
                        g_CaptureState.logFile.flush();
                    }
                    if (g_CaptureState.debugMode && dataLen > 0) {
                        g_CaptureState.logFile << L"[" << seq << L"][" << timeStr << L"] Full Payload: ";
                        for (unsigned int i = 0; i < (dataLen < 64 ? dataLen : 64); i++) {
                            g_CaptureState.logFile << std::hex << std::setw(2) << std::setfill(L'0') << (int)((unsigned char*)data)[i] << L" ";
                        }
                        g_CaptureState.logFile << L"\n";
                    }
                }
                else if (opcode == 0x32 && isInbound) {
                    wprintf(L"[%lu][%s] ItemList detectado (tamanho: %u bytes)\n", seq, timeStr, bufferLen);
                    g_CaptureState.logFile << L"[" << seq << L"][" << timeStr << L"] ItemList detectado (tamanho: " << bufferLen << L" bytes)\n";
                    if (dataLen >= 8) {
                        int itemId = *(int*)((unsigned char*)data + 6);
                        wprintf(L"[%lu][%s] Item ID: %d\n", seq, timeStr, itemId);
                        g_CaptureState.logFile << L"[" << seq << L"][" << timeStr << L"] Item ID: " << itemId << L"\n";
                        g_CaptureState.logFile.flush();
                    }
                    if (g_CaptureState.debugMode && dataLen > 0) {
                        g_CaptureState.logFile << L"[" << seq << L"][" << timeStr << L"] Full Payload: ";
                        for (unsigned int i = 0; i < (dataLen < 64 ? dataLen : 64); i++) {
                            g_CaptureState.logFile << std::hex << std::setw(2) << std::setfill(L'0') << (int)((unsigned char*)data)[i] << L" ";
                        }
                        g_CaptureState.logFile << L"\n";
                    }
                }
            }
            else {
                wprintf(L"[%lu][%s] Pacote desconhecido (porta: %u, tamanho: %u bytes)\n", seq, timeStr, dstPort, bufferLen);
                g_CaptureState.logFile << L"[" << seq << L"][" << timeStr << L"] Pacote desconhecido (porta: " << dstPort << L", tamanho: " << bufferLen << L" bytes)\n";
                g_CaptureState.logFile.flush();
            }

            if (!WinDivertSend(divertHandle, buffer, bufferLen, nullptr, &addr)) {
                wprintf(L"[%lu][%s] Erro ao reinjetar pacote: %lu\n", seq, timeStr, GetLastError());
                g_CaptureState.logFile << L"[" << seq << L"][" << timeStr << L"] Erro ao reinjetar pacote: " << GetLastError() << L"\n";
                g_CaptureState.logFile.flush();
            }
        }
        else {
            DWORD error = GetLastError();
            if (error == ERROR_OPERATION_ABORTED) {
                wprintf(L"WinDivertRecv abortado (handle fechado), saindo...\n");
                g_CaptureState.logFile << L"WinDivertRecv abortado (handle fechado), saindo...\n";
                g_CaptureState.logFile.flush();
                break;
            }
            if (error != ERROR_IO_PENDING) {
                wprintf(L"Erro no WinDivertRecv: %lu\n", error);
                g_CaptureState.logFile << L"Erro no WinDivertRecv: " << error << L"\n";
                g_CaptureState.logFile.flush();
                Sleep(100);
            }
        }
    }
}

int main() {
    // Configura console para Unicode
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
    _setmode(_fileno(stdout), _O_U16TEXT);
    _setmode(_fileno(stderr), _O_U16TEXT);

    // Opcional: Limpar log ao iniciar
    // g_CaptureState.ClearLogFile();

    wprintf(L"Iniciando programa de captura de pacotes...\n");
    g_CaptureState.logFile << L"Iniciando programa de captura de pacotes...\n";
    g_CaptureState.logFile.flush();

    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        wprintf(L"Erro ao inicializar Winsock: %d\n", WSAGetLastError());
        g_CaptureState.logFile << L"Erro ao inicializar Winsock: " << WSAGetLastError() << L"\n";
        g_CaptureState.logFile.flush();
        g_CaptureState.logFile.close();
        return 1;
    }

    // Carrega mapeamentos de opcodes de arquivo opcional
    LoadOpcodeFunctions(L"opcodes.txt", g_CaptureState.opcodeFunctions);

    const char* processName = "L2.exe";
    std::vector<std::thread*> captureThreads;
    std::vector<HANDLE> divertHandles;
    std::vector<UINT16> activePorts;

    while (g_CaptureState.running) {
        // Verifica tecla F12 para limpar o log
        if (GetAsyncKeyState(VK_F12) & 0x8000) {
            g_CaptureState.ClearLogFile();
            wprintf(L"Arquivo de log limpo.\n");
            Sleep(200);
        }

        auto connections = GetConnectionsByProcess(processName);
        if (!connections.empty()) {
            bool portChanged = false;
            for (const auto& conn : connections) {
                if (std::find(activePorts.begin(), activePorts.end(), conn.localPort) == activePorts.end()) {
                    portChanged = true;
                    break;
                }
            }

            if (portChanged) {
                g_CaptureState.packetSequence = 0;
                wprintf(L"Instâncias encontradas:\n");
                g_CaptureState.logFile << L"Instâncias encontradas:\n";
                for (const auto& conn : connections) {
                    wprintf(L"PID: %lu, Porta local: %u\n", conn.pid, conn.localPort);
                    g_CaptureState.logFile << L"PID: " << conn.pid << L", Porta local=" << conn.localPort << L"\n";
                    g_CaptureState.logFile.flush();

                    if (std::find(activePorts.begin(), activePorts.end(), conn.localPort) == activePorts.end()) {
                        char filter[256];
                        snprintf(filter, sizeof(filter),
                            "tcp and (tcp.SrcPort = %u or tcp.DstPort = %u)",
                            conn.localPort, conn.localPort);

                        HANDLE divertHandle = WinDivertOpen(filter, WINDIVERT_LAYER_NETWORK, 0, 0);
                        if (divertHandle == INVALID_HANDLE_VALUE) {
                            DWORD error = GetLastError();
                            wprintf(L"Erro ao abrir WinDivert para porta %u: %lu\n", conn.localPort, error);
                            g_CaptureState.logFile << L"Erro ao abrir WinDivert para porta " << conn.localPort << L": " << error << L"\n";
                            g_CaptureState.logFile.flush();
                            continue;
                        }

                        wprintf(L"WinDivert aberto com sucesso para porta %u\n", conn.localPort);
                        g_CaptureState.logFile << L"WinDivert aberto com sucesso para porta " << conn.localPort << L"\n";
                        g_CaptureState.logFile.flush();

                        divertHandles.push_back(divertHandle);
                        activePorts.push_back(conn.localPort);
                        captureThreads.push_back(new std::thread(CapturePackets, divertHandle, conn.localPort));
                    }
                }
            }
        }
        else {
            if (!divertHandles.empty()) {
                g_CaptureState.running = false;
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
                g_CaptureState.running = true;
                wprintf(L"Nenhuma instância do L2.exe encontrada. Aguardando...\n");
                g_CaptureState.logFile << L"Nenhuma instância do L2.exe encontrada. Aguardando...\n";
                g_CaptureState.logFile.flush();
            }
            else {
                wprintf(L"Nenhuma conexão do L2.exe detectada. Aguardando...\n");
                g_CaptureState.logFile << L"Nenhuma conexão do L2.exe detectada. Aguardando...\n";
                g_CaptureState.logFile.flush();
            }
        }
        Sleep(5000);
    }

    g_CaptureState.running = false;
    for (auto thread : captureThreads) {
        if (thread) {
            thread->join();
            delete thread;
        }
    }
    for (auto handle : divertHandles) {
        WinDivertClose(handle);
    }
    g_CaptureState.logFile << L"Programa encerrado.\n";
    g_CaptureState.logFile.flush();
    g_CaptureState.logFile.close();
    WSACleanup();
    return 0;
}