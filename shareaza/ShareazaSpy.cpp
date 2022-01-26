#include "StdAfx.h"
#include "ShareazaSpy.h"
#include "Shareaza.h"
#include "QuerySearch.h"
#include "QueryHit.h"
#include "WndMain.h"
#include "WndSearch.h"

#include <ctime>
#include <fstream>
#include <sstream>
#include <cstdio>
#include <sys/types.h>
#include <sys/stat.h>
#include <direct.h>
#include <boost/compute/detail/lru_cache.hpp>


#define SHAREAZA_SPY_OUTPUT_FOLDER "C:\\ShareazaSpyTemp"

// Where to save data
static std::string shareazaSpyOutputFolder = SHAREAZA_SPY_OUTPUT_FOLDER;
static bool outputFolderSet = false;


//////////////////////////////////////////////////////////////////////
// Log received UDP packages info
#define MAX_LOG_PER_FILE 100000
static bool openFile = true;
std::ofstream logFile;
CCriticalSection cslock;
static long logCount = 0;

// cache recent logged lines to avoid duplicating same lines in log file
boost::compute::detail::lru_cache<std::string, int> logCache(1024);

bool dirExists(const char* path) {
	struct stat info;

	if (stat(path, &info) != 0)
		return false;
	else if (info.st_mode & S_IFDIR)
		return true;
	return false;
}

void createFolderIfDoesntExist(const char* path) {
	if (!dirExists((path))) {
		_mkdir(path);
	}
}

void createFolders() {
	std::string logsDir = shareazaSpyOutputFolder + "\\logs";
	std::string searchesDir = shareazaSpyOutputFolder + "\\Searches";
	createFolderIfDoesntExist(shareazaSpyOutputFolder.c_str());
	createFolderIfDoesntExist(logsDir.c_str());
	createFolderIfDoesntExist(searchesDir.c_str());
}

void LogReceivedPackage(IN_ADDR* addr, WORD port, WORD type) {
	SOCKADDR_IN saddr_in;
	saddr_in.sin_addr = *addr;
	saddr_in.sin_family = AF_INET;
	saddr_in.sin_port = port;
	LogReceivedPackage(&saddr_in, type);
}

void LogReceivedPackage(SOCKADDR_IN* addr, WORD type)
{
	CSingleLock lock(&cslock, TRUE);
	if (!outputFolderSet) {
		return;
	}

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
		ssFileName << shareazaSpyOutputFolder << "\\logs\\log_" << timeFileNameBuff << ".txt";
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
	ssLogLine << timeLogBuff << ";" << ip << ":" << ntohs(addr->sin_port) << ";" << (type == TYPE_UDP ? "UDP" : "TCP");
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

bool SaveSearchesNow() {
	CString strFile(GetShareazaSpyOutputFolder().c_str());
	strFile += _T("\\Searches\\");
	
	// get current time
	time_t now;
	time(&now);

	// get date for file name
	char timeFileNameBuff[30];
	strftime(timeFileNameBuff, sizeof(timeFileNameBuff), "%Y-%m-%dT-%H-%M-%SZ", gmtime(&now));
	
	strFile += _T("Searches-");
	strFile += timeFileNameBuff;
	strFile += _T(".dat");

	CString tmpFile(GetShareazaSpyOutputFolder().c_str());
	tmpFile += _T("\\Searches\\searchessave.tmp");

	CFile pFile;

	if (!pFile.Open(tmpFile, CFile::modeWrite | CFile::modeCreate | CFile::shareExclusive | CFile::osSequentialScan))
	{
		theApp.Message(MSG_ERROR, _T("Failed to save search windows: %s"), (LPCTSTR)tmpFile);
		return FALSE;
	}
	CMainWnd* pMainWnd = static_cast< CMainWnd* >(theApp.m_pMainWnd);

	try
	{
		CArchive ar(&pFile, CArchive::store, 262144);	// 256 KB buffer
		try
		{
			DWORD nTotal = 0;
			for (POSITION pos = pMainWnd->m_pWindows.GetIterator(); pos; )
			{
				CSearchWnd* pWnd = (CSearchWnd*)pMainWnd->m_pWindows.GetNext(pos);
				if (pWnd->IsKindOf(RUNTIME_CLASS(CSearchWnd)) &&
					pWnd->GetLastSearch())
				{
					++nTotal;
				}
			}

			for (POSITION pos = pMainWnd->m_pWindows.GetIterator(); pos; )
			{
				CSearchWnd* pWnd = (CSearchWnd*)pMainWnd->m_pWindows.GetNext(pos);
				if (pWnd->IsKindOf(RUNTIME_CLASS(CSearchWnd)) &&
					pWnd->GetLastSearch())
				{
					ar.WriteCount(1);
					pWnd->Serialize(ar);
				}
			}
			ar.WriteCount(0);
			ar.Close();
		}
		catch (CException* pException)
		{
			ar.Abort();
			pFile.Abort();
			pException->Delete();
			theApp.Message(MSG_ERROR, _T("Failed to save search windows: %s"), (LPCTSTR)tmpFile);
			return FALSE;
		}
		pFile.Close();
	}
	catch (CException* pException)
	{
		pFile.Abort();
		pException->Delete();
		theApp.Message(MSG_ERROR, _T("Failed to save search windows: %s"), (LPCTSTR)tmpFile);
		return FALSE;
	}

	std::rename(CT2A(tmpFile).m_psz, CT2A(strFile).m_psz);

	return TRUE;
}

void SetShareazaSpyOutputFolder(const char* folder) {
	CSingleLock lock(&cslock, TRUE);
	shareazaSpyOutputFolder = folder;
	createFolders();
	outputFolderSet = true;
}

std::string GetShareazaSpyOutputFolder() {
	return shareazaSpyOutputFolder;
}
