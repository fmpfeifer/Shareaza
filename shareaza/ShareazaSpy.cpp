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
#include <iomanip>
#include <sys/types.h>
#include <sys/stat.h>
#include <direct.h>
#include <boost/compute/detail/lru_cache.hpp>


#define SHAREAZA_SPY_OUTPUT_FOLDER "C:\\ShareazaSpyTemp"

// #define LOG_DEBUG_ENABLED 1

// Where to save data
static std::string shareazaSpyOutputFolder = SHAREAZA_SPY_OUTPUT_FOLDER;
static bool outputFolderSet = false;


//////////////////////////////////////////////////////////////////////
// Log received UDP packages info
constexpr unsigned int MAX_LOG_PER_FILE = 100000;
constexpr unsigned int MAX_LOG_HITS_PER_FILE = 1000;
static bool shouldOpenFile = true;
static bool openDebugFile = true;
static bool shouldOpenHitsFile = true;
std::ofstream logFile;
std::ofstream logDebugFile;
std::ofstream logHitsFile;
CCriticalSection cslock;
static long logCount = 0;
static long logHitsCount = 0;

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

void LogReceivedPackage(const IN_ADDR* addr, WORD port, WORD type) {
	#if 0
	SOCKADDR_IN saddr_in;
	saddr_in.sin_addr = *addr;
	saddr_in.sin_family = AF_INET;
	saddr_in.sin_port = port;
	LogReceivedPackage(&saddr_in, type);
	#endif
}

void LogReceivedPackage(const SOCKADDR_IN* addr, WORD type)
{
	#if 0
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
	const char* rval = inet_ntop(addr->sin_family, (void*) &addr->sin_addr, ipBuff, sizeof(ipBuff));
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
	#endif
}

void LogDebugMessage(std::string* message);

void LogDebugMessage(const char* m1, const char* m2)
{
#ifdef LOG_DEBUG_ENABLED
	std::stringstream ss;
	ss << m1;
	if (m2 != NULL) {
		ss << m2;
	}
	LogDebugMessage(&ss.str());
#endif
}

void LogDebugMessage(const char* m1, long m2) {
#ifdef LOG_DEBUG_ENABLED
	std::stringstream ss;
	ss << m1 << m2;
	LogDebugMessage(&ss.str());
#endif
}

void LogDebugMessage(const char* message, const SOCKADDR_IN* addr) {
#ifdef LOG_DEBUG_ENABLED
	char ipBuff[INET6_ADDRSTRLEN];
	const char* rval = inet_ntop(addr->sin_family, (void*) &addr->sin_addr, ipBuff, sizeof(ipBuff));
	if (rval == NULL) {
		return;
	}


	std::string ip(ipBuff);
	if (ip == "0.0.0.0" || ip == "::") {
		return;
	}

	std::stringstream ssLogLine;
	ssLogLine << message << ip << ":" << ntohs(addr->sin_port);
	LogDebugMessage(&ssLogLine.str());
#endif
}

void LogDebugMessage(const char* msg, const IN_ADDR* addr, WORD port) {
#ifdef LOG_DEBUG_ENABLED
	SOCKADDR_IN saddr_in;
	saddr_in.sin_addr = *addr;
	saddr_in.sin_family = AF_INET;
	saddr_in.sin_port = port;
	LogDebugMessage(msg, &saddr_in);
#endif
}

void LogDebugMessage(const char* message) {
#ifdef LOG_DEBUG_ENABLED
	LogDebugMessage(message, (const char*) NULL);
#endif
}

void LogDebugMessage(std::string* message)
{
#ifdef LOG_DEBUG_ENABLED
	CSingleLock lock(&cslock, TRUE);
	if (!outputFolderSet) {
		return;
	}
	// get current time
	time_t now;
	time(&now);

	if (openDebugFile)
	{
		// open new log file
		char timeFileNameBuff[30];
		strftime(timeFileNameBuff, sizeof(timeFileNameBuff), "%Y-%m-%dT-%H-%M-%SZ", gmtime(&now));

		std::stringstream ssFileName;
		ssFileName << shareazaSpyOutputFolder << "\\logs\\debug_log_" << timeFileNameBuff << ".txt";
		std::string filename = ssFileName.str();

		logDebugFile.open(filename, std::ios::out);
		openDebugFile = false;
	}

	// get data for log line
	char timeLogBuff[30];
	strftime(timeLogBuff, sizeof(timeLogBuff), "%Y-%m-%dT%H:%M:%SZ", gmtime(&now));

	std::stringstream ssLogLine;
	ssLogLine << timeLogBuff << ";" << *message;
	std::string logline = ssLogLine.str();

	// log line and inser in cache
	logDebugFile << logline << std::endl;
#endif
}

bool SaveSearchesNow() {
	#if 0
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
	#endif
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

static constexpr char _HEX_ALPHA_DICT[] = "0123456789ABCDEF";
static constexpr char* BASE64_DICT = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

std::string hexify(const unsigned char* buff, size_t buf_size)
{
    std::stringstream ss;
    for(int pos = 0; pos < buf_size; pos ++)
    {
        ss << std::setfill('0') << std::setw(2) << std::right << std::hex << (int)buff[pos];
    }
    return ss.str();
}




static std::string base64_encode(const std::string& in) {

	std::string out;

	int val = 0, valb = -6;
	for (const u_char c : in) {
		val = (val << 8) + c;
		valb += 8;
		while (valb >= 0) {
			out.push_back(BASE64_DICT[(val >> valb) & 0x3F]);
			valb -= 6;
		}
	}
	if (valb > -6) out.push_back(BASE64_DICT[((val << 8) >> (valb + 8)) & 0x3F]);
	while (out.size() % 4) out.push_back('=');
	return out;
}

static std::string base64_encode(const CString& in) {
	std::string in_str = CW2A(in.GetString(), CP_UTF8);
	return base64_encode(in_str);
}

void LogQueryHit(const CQueryHit* pHit) {
	// get current time
	time_t now;
	time(&now);

	// get data for log line
	char timeLogBuff[30];
	memset(timeLogBuff, 0, sizeof(timeLogBuff));
	strftime(timeLogBuff, sizeof(timeLogBuff), "%Y-%m-%dT%H:%M:%SZ", gmtime(&now));

	std::string guid = hexify(&pHit->m_oClientID[0], 16);

	char ipBuff[INET6_ADDRSTRLEN];
	memset(ipBuff, 0, sizeof(ipBuff));
	const char* rval = inet_ntop(AF_INET, (void*) &pHit->m_pAddress, ipBuff, sizeof(ipBuff));
	if (rval == NULL) {
		return;
	}

	std::string ip(ipBuff);
	if (ip == "0.0.0.0" || ip == "::") {
		return;
	}

	memset(ipBuff, 0, sizeof(ipBuff));
	const char* rval2 = inet_ntop(AF_INET, (void*)&pHit->m_pRealAddress, ipBuff, sizeof(ipBuff));
	if (rval2 == NULL) {
		return;
	}

	std::string realIp(ipBuff);
	if (realIp == "0.0.0.0" || realIp == "::") {
		return;
	}

	std::string sha1 = hexify(&pHit->m_oSHA1[0], 20);

	std::string ed2k = hexify(&pHit->m_oED2K[0], 16);

	std::string protoId;

	switch (pHit->m_nProtocol) {
	case PROTOCOL_G1:
		protoId = "G1";
		break;
	case PROTOCOL_G2:
		protoId = "G2";
		break;
	case PROTOCOL_ED2K:
		protoId = "ED2K";
		break;
	case PROTOCOL_DC:
		protoId = "DC++";
		break;
	case PROTOCOL_BT:
		protoId = "BT";
		break;
	default:
		protoId = "UNKNOWN";

	}

	// timestamp, GUID, IP, REAL_IP, PORT, REAL_PORT, PROTOCOL, 
	// FILESIZE, nick_b64, vendor, clientSoftware_b64, SHA1, ED2K, partial, filename_b64
	// proto_id

	const bool isDirect = ip == realIp;

	double partial = -1;
	if (pHit->m_nSize > 0) {
		partial = (pHit->m_nPartial * 100.0) / pHit->m_nSize;
	}


	std::stringstream ssLogLine;
	ssLogLine << &timeLogBuff[0] << ";" << guid << ";" << ip << ";" << realIp << ";";
	ssLogLine << pHit->m_nPort << ";" << pHit->m_nRealPort << ";";
	ssLogLine << (pHit->m_bUDP ? "UDP" : "TCP") << ";" << pHit->m_nSize << ";" << base64_encode(pHit->m_sNick.GetString()) << ";" << CW2A(pHit->m_pVendor->m_sCode.GetString()) << ";;";
	ssLogLine << sha1 << ";" << ed2k  << ";" << std::fixed << std::setprecision(2) << partial << ";" << base64_encode(pHit->m_sName.GetString()) << ";" << protoId << ";" << (isDirect ? "Y" : "N");
	const std::string logline = ssLogLine.str();

	// log line
	logHitsFile << logline << std::endl;
	logHitsFile.flush();
	logHitsCount++;
}

inline bool file_exists(const std::string& filename) {
	std::ifstream f(filename.c_str());
	return f.good();
}

void open_log_file_if_needed() {
	if (shouldOpenHitsFile)
	{
		// get current time
		time_t now;
		time(&now);

		std::stringstream ssLoggingFileName;
		ssLoggingFileName << shareazaSpyOutputFolder << "\\logs\\c_shareaza_hits.txt";
		std::string loggingFileName = ssLoggingFileName.str();

		if (file_exists(loggingFileName)) {
			char timeFileNameBuff[30];
			strftime(timeFileNameBuff, sizeof(timeFileNameBuff), "%Y-%m-%dT-%H-%M-%SZ", gmtime(&now));

			std::stringstream ssFileName;
			ssFileName << shareazaSpyOutputFolder << "\\logs\\shareaza_hits_" << timeFileNameBuff << ".txt";
			std::string filename = ssFileName.str();

			std::rename(loggingFileName.c_str(), filename.c_str());
		}
		// open new log file


		logHitsFile.open(loggingFileName, std::ios::out | std::ios::app);
		shouldOpenHitsFile = false;
	}
}

void LogQueryHits(const CQueryHit* pHits) {
	CSingleLock lock(&cslock, TRUE);
	if (!outputFolderSet || !pHits) {
		return;
	}

	// create new file if MAX_LOG_HITS_PER_FILE lines is reached
	if (logHitsCount >= MAX_LOG_HITS_PER_FILE) {
		shouldOpenHitsFile = true;
		logHitsFile.close();
		logHitsCount = 0;
	}

	open_log_file_if_needed();

	for (const CQueryHit* pHit = pHits; pHit != NULL; pHit = pHit->m_pNext) {
		LogQueryHit(pHit);
	}

	
}