#pragma once

#ifdef _WIN32
#ifdef ALTBASE_ZANO_WALLET_EXPORTS
#define ALTBASE_ZANO_WALLET_API extern "C" __declspec(dllexport)
#else
#define ALTBASE_ZANO_WALLET_API extern "C" __declspec(dllimport)
#endif
#define ALTBASE_ZANO_WALLET_CALL __cdecl
#else
#define ALTBASE_ZANO_WALLET_API extern "C"
#define ALTBASE_ZANO_WALLET_CALL
#endif

ALTBASE_ZANO_WALLET_API char* ALTBASE_ZANO_WALLET_CALL altbase_zano_wallet_request(const char* request);
ALTBASE_ZANO_WALLET_API void ALTBASE_ZANO_WALLET_CALL altbase_zano_wallet_free(char* value);
