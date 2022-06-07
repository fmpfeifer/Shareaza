#pragma once

#define TYPE_UDP 0
#define TYPE_TCP 1

void LogReceivedPackage(const IN_ADDR* addr, WORD port, WORD type);
void LogReceivedPackage(const SOCKADDR_IN* addr, WORD type);
void LogDebugMessage(const char* message);
void LogDebugMessage(const char* msg, const IN_ADDR* addr, WORD port);
void LogDebugMessage(const char* message, const SOCKADDR_IN* addr);
void LogDebugMessage(const char* m1, const char* m2);
void LogDebugMessage(const char* m1, long m2);
bool SaveSearchesNow();
void SetShareazaSpyOutputFolder(const char* folder);
std::string GetShareazaSpyOutputFolder();
