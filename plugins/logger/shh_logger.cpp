#pragma once

#include <osquery/registry/registry_factory.h>

#include "shh_logger.h"

#include <time.h>
#include <stdarg.h>
#include <tchar.h>
#include <windows.h>
#include <string>
#include <io.h>
#include <fcntl.h>

#define LOG_FILE L"C:\\logs\\shh-logger.txt"


namespace osquery {

	REGISTER(SHHLoggerPlugin, "logger", "shh_logger");

	void WriteToLog(wchar_t* szFileName, const wchar_t* szMessage)
	{
		int ilen = 0;
		int iFileHandle;

		time_t currtime;
		struct tm* tm_tmp;
		TCHAR szBuff[50] = _T("");
		TCHAR szTemp[50] = _T("");

		if (szFileName == NULL || szMessage == NULL)
		{
			return;
		}

		if (_taccess(szFileName, 0) != 0)
		{
			iFileHandle = _topen(szFileName,
				O_BINARY | O_RDWR | O_CREAT,
				S_IWRITE | S_IREAD);
			if (iFileHandle == -1)
			{
				return;
			}
		}
		else
		{
			iFileHandle = _topen(szFileName, O_BINARY | O_RDWR);
			if (iFileHandle == -1)
			{
				return;
			}
		}

		lseek(iFileHandle, 0L, SEEK_END);

		ilen = _tcslen(szMessage) * 2;

		TCHAR tmp[2] = { '\r', '\n' };
		write(iFileHandle, szMessage, ilen);
		write(iFileHandle, tmp, 4);

		close(iFileHandle);
	}

	SHHLoggerPlugin::SHHLoggerPlugin() {
		WriteToLog(LOG_FILE, L"SHHLoggerPlugin() called");
	}

	SHHLoggerPlugin::~SHHLoggerPlugin() {

		DWORD dwError;
		PVOID pReserved;

		WriteToLog(LOG_FILE, L"~SHHLoggerPlugin() called");

		if (TRUE == m_bInitSuccessful) {
            WriteToLog(LOG_FILE, L"SHHLoggerPlugin Unloading SHH");

			if (NULL != m_pfn_ShhCommDeinit) {
				m_pfn_ShhCommDeinit(&dwError, pReserved);
			}

			if (NULL != m_hShhcommLib) {
                FreeLibrary(m_hShhcommLib);
                m_hShhcommLib = NULL;
            }
		}
	}

	// Initialize the logger plugin after osquery has begun.
	void SHHLoggerPlugin::init(const std::string& name,
           const std::vector<StatusLogLine>& log) {

		BOOL boRet;
		DWORD dwRet;
		DWORD dwError;
		void* vReserved;
		wchar_t* pwszTemp = NULL;
		std::wstring wszModuleName = L"";
		wchar_t wszModuleFileName[MAX_PATH];

		WriteToLog(LOG_FILE, L"SHHLoggerPlugin::init called");

		if (FALSE == m_bInitSuccessful) {
            WriteToLog(LOG_FILE, L"SHHLoggerPlugin::init Loading SHH");

            dwRet = GetModuleFileName(NULL, wszModuleFileName, MAX_PATH);
            if (0 == dwRet) {
            WriteToLog(LOG_FILE, L"GetModuleFileName failed");
            return;
            }

            pwszTemp = wcsrchr(wszModuleFileName, L'\\');
            if (NULL == pwszTemp) {
            WriteToLog(LOG_FILE, L"wcsrchr failed");
            return;
            }

            *pwszTemp = L'\0';
            wszModuleName = wszModuleFileName;
            wszModuleName += L'\\';
            wszModuleName += L"shhcomm.dll";

            m_hShhcommLib = LoadLibraryEx(wszModuleName.c_str(),
                                        NULL,
                                        LOAD_WITH_ALTERED_SEARCH_PATH
										);
            if (NULL == m_hShhcommLib) {
            WriteToLog(LOG_FILE, L"LoadLibraryEx failed");
            return;
            }

            m_pfn_ShhCommInit = (PFN_SHHCOMM_INIT)GetProcAddress(
                m_hShhcommLib, "ShhCommInit");
            m_pfn_ShhCommDeinit = (PFN_SHHCOMM_DEINIT)GetProcAddress(
                m_hShhcommLib, "ShhCommDeinit");
            m_pfn_SendOsqueryResult =
                (PFN_SENDOSQUERYRESULT)GetProcAddress(
                    m_hShhcommLib, "SendOsqueryResult");

            if (NULL == m_pfn_ShhCommInit ||
                NULL == m_pfn_ShhCommDeinit ||
                NULL == m_pfn_SendOsqueryResult) {
            FreeLibrary(m_hShhcommLib);

            WriteToLog(LOG_FILE, L"GetProcAddress failed");
            return;
            }

            boRet = m_pfn_ShhCommInit(&dwError, vReserved);
            if (FALSE == boRet) {
            FreeLibrary(m_hShhcommLib);

            WriteToLog(LOG_FILE, L"m_pfn_ShhCommInit failed");
            return;
            }

            m_bInitSuccessful = TRUE;
		}
	}

	//Log results
	Status SHHLoggerPlugin::logString(const std::string& s) {

		std::wstring widestr = std::wstring(s.begin(), s.end());
          WriteToLog(LOG_FILE, widestr.c_str());

		  if (TRUE == m_bInitSuccessful) {
            m_pfn_SendOsqueryResult(s.c_str());
          }

		  return Status(0, "OK");
	}

} // namespace osquery