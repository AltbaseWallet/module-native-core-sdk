#pragma once

#ifdef _WIN32
#ifdef ALTBASE_EPIC_WALLET_EXPORTS
#define ALTBASE_EPIC_WALLET_API extern "C" __declspec(dllexport)
#else
#define ALTBASE_EPIC_WALLET_API extern "C" __declspec(dllimport)
#endif
#define ALTBASE_EPIC_WALLET_CALL __cdecl
#else
#define ALTBASE_EPIC_WALLET_API extern "C"
#define ALTBASE_EPIC_WALLET_CALL
#endif

ALTBASE_EPIC_WALLET_API char* ALTBASE_EPIC_WALLET_CALL altbase_epic_wallet_request(const char* request);
ALTBASE_EPIC_WALLET_API void ALTBASE_EPIC_WALLET_CALL altbase_epic_wallet_free(char* value);
