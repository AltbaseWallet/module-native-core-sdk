#pragma once

#ifdef _WIN32
#ifdef ALTBASE_PRIVACY_CORE_EXPORTS
#define ALTBASE_PRIVACY_API extern "C" __declspec(dllexport)
#else
#define ALTBASE_PRIVACY_API extern "C" __declspec(dllimport)
#endif
#define ALTBASE_PRIVACY_CALL __cdecl
#else
#define ALTBASE_PRIVACY_API extern "C"
#define ALTBASE_PRIVACY_CALL
#endif

ALTBASE_PRIVACY_API char* ALTBASE_PRIVACY_CALL altbase_privacy_request(const char* request);
ALTBASE_PRIVACY_API void ALTBASE_PRIVACY_CALL altbase_privacy_free(char* value);
