#pragma once

#ifdef _WIN32
#ifdef ALTBASE_NET_CORE_EXPORTS
#define ALTBASE_NET_API extern "C" __declspec(dllexport)
#else
#define ALTBASE_NET_API extern "C" __declspec(dllimport)
#endif
#define ALTBASE_NET_CALL __cdecl
#else
#define ALTBASE_NET_API extern "C" __attribute__((visibility("default")))
#define ALTBASE_NET_CALL
#endif

ALTBASE_NET_API char* ALTBASE_NET_CALL altbase_net_request(const char* request);
ALTBASE_NET_API void ALTBASE_NET_CALL altbase_net_free(char* value);
