#include "ShareazaSpy.h"

#include <ctime>
#include <fstream>
#include <sstream>
#include <boost/compute/detail/lru_cache.hpp>


//////////////////////////////////////////////////////////////////////
// Log received UDP packages info
#define MAX_LOG_PER_FILE 100000
static bool openFile = true;
std::ofstream logFile;
CCriticalSection cslock;
static long logCount = 0;

// cache recent logged lines to avoid duplicating same lines in log file
boost::compute::detail::lru_cache<std::string, int> logCache(512);

void LogReceivedPackage(SOCKADDR_IN* addr)
{
	CSingleLock lock(&cslock, TRUE);

	// create new file if MAX_LOG_PER_FILE lines is reached
	if (logCount >= MAX_LOG_PER_FILE) {
		openFile = true;
		logFile.close();
		logCount = 0;
	}

	// get current time
	time_t now;
	time(&now);

	if (openFile)
	{
		// open new log file
		char timeFileNameBuff[30];
		strftime(timeFileNameBuff, sizeof(timeFileNameBuff), "%Y-%m-%dT-%H-%M-%SZ", gmtime(&now));

		std::stringstream ssFileName;
		ssFileName << SHAREAZA_SPY_OUTPUT_FOLDER << "\\logs\\log_" << timeFileNameBuff << ".txt";
		std::string filename = ssFileName.str();

		logFile.open(filename, std::ios::out);
		openFile = false;
	}

	// get data for log line
	char timeLogBuff[30];
	strftime(timeLogBuff, sizeof(timeLogBuff), "%Y-%m-%dT%H:%M:%SZ", gmtime(&now));

	char ipBuff[INET6_ADDRSTRLEN];
	const char* rval = inet_ntop(addr->sin_family, &addr->sin_addr, ipBuff, sizeof(ipBuff));
	if (rval == NULL) {
		return;
	}


	std::string ip(ipBuff);
	if (ip == "0.0.0.0" || ip == "::") {
		return;
	}

	std::stringstream ssLogLine;
	ssLogLine << timeLogBuff << ";" << ip << ":" << ntohs(addr->sin_port);
	std::string logline = ssLogLine.str();

	// do not log if already logged
	if (logCache.contains(logline)) {
		return;
	}

	// log line and inser in cache
	logFile << logline << std::endl;
	logCount++;
	logCache.insert(logline, 0);
}