#pragma once

#ifdef _WIN32
#ifdef ALTBASE_WALLET_VAULT_EXPORTS
#define ALTBASE_VAULT_API extern "C" __declspec(dllexport)
#else
#define ALTBASE_VAULT_API extern "C" __declspec(dllimport)
#endif
#define ALTBASE_VAULT_CALL __cdecl
#else
#define ALTBASE_VAULT_API extern "C"
#define ALTBASE_VAULT_CALL
#endif

ALTBASE_VAULT_API char* ALTBASE_VAULT_CALL altbase_wallet_vault_request(const char* request);
ALTBASE_VAULT_API void ALTBASE_VAULT_CALL altbase_wallet_vault_free(char* value);
