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

bool SaveSearchesNow(const char* fileName) {
	CString strFile = _T(SHAREAZA_SPY_OUTPUT_FOLDER);
	strFile += _T("\\");
	strFile += fileName;

	CFile pFile;

	if (!pFile.Open(strFile, CFile::modeWrite | CFile::modeCreate | CFile::shareExclusive | CFile::osSequentialScan))
	{
		theApp.Message(MSG_ERROR, _T("Failed to save search windows: %s"), (LPCTSTR)strFile);
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
			theApp.Message(MSG_ERROR, _T("Failed to save search windows: %s"), (LPCTSTR)strFile);
			return FALSE;
		}
		pFile.Close();
	}
	catch (CException* pException)
	{
		pFile.Abort();
		pException->Delete();
		theApp.Message(MSG_ERROR, _T("Failed to save search windows: %s"), (LPCTSTR)strFile);
		return FALSE;
	}
	return TRUE;
}