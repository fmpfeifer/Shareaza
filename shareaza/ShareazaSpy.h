#pragma once

#define SHAREAZA_SPY_OUTPUT_FOLDER "C:\\ShareazaSpyTemp"

void LogReceivedPackage(SOCKADDR_IN* addr);
bool SaveSearchesNow(const char* fileName);
