#pragma once

#include <osquery/core/plugins/logger.h>

namespace osquery {

//
//	ShhCommInit.
//
typedef BOOLEAN(__stdcall* PFN_SHHCOMM_INIT)(DWORD* pdwError, void* pvReserved);

//
//	ShhCommDeinit.
//
typedef BOOLEAN(__stdcall* PFN_SHHCOMM_DEINIT)(DWORD* pdwError, void* pvReserved);

//
// SendOsqueryResult
//
typedef BOOLEAN(__stdcall* PFN_SENDOSQUERYRESULT)(const char* pcszData);


class SHHLoggerPlugin : public LoggerPlugin {
	public:
	SHHLoggerPlugin();
	~SHHLoggerPlugin();

	// Initialize the logger plugin after osquery has begun.
	void init(const std::string& name,
        const std::vector<StatusLogLine>& log) override;

	// Log results
	Status logString(const std::string& s) override;

	private:
	BOOLEAN m_bInitSuccessful = FALSE;

    HMODULE m_hShhcommLib = NULL;

	PFN_SHHCOMM_INIT m_pfn_ShhCommInit = NULL;
    PFN_SHHCOMM_DEINIT m_pfn_ShhCommDeinit = NULL;
    PFN_SENDOSQUERYRESULT m_pfn_SendOsqueryResult = NULL;
};
}