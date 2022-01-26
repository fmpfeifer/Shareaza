#pragma once

#define TYPE_UDP 0
#define TYPE_TCP 1

void LogReceivedPackage(IN_ADDR* addr, WORD port, WORD type);
void LogReceivedPackage(SOCKADDR_IN* addr, WORD type);
bool SaveSearchesNow();
void SetShareazaSpyOutputFolder(const char* folder);
std::string GetShareazaSpyOutputFolder();
