#pragma once

#ifdef _WIN32
#ifdef ALTBASE_ZANO_CORE_EXPORTS
#define ALTBASE_ZANO_API extern "C" __declspec(dllexport)
#else
#define ALTBASE_ZANO_API extern "C" __declspec(dllimport)
#endif
#define ALTBASE_ZANO_CALL __cdecl
#else
#define ALTBASE_ZANO_API extern "C" __attribute__((visibility("default")))
#define ALTBASE_ZANO_CALL
#endif

ALTBASE_ZANO_API char* ALTBASE_ZANO_CALL altbase_zano_request(const char* request);
ALTBASE_ZANO_API void ALTBASE_ZANO_CALL altbase_zano_free(char* value);
