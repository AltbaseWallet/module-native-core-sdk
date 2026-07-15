#pragma once

#ifdef _WIN32
#define ALTBASE_UTXO_SERVICE_IMPORT extern "C" __declspec(dllimport)
#define ALTBASE_UTXO_SERVICE_IMPORT_CALL __cdecl
#else
#define ALTBASE_UTXO_SERVICE_IMPORT extern "C"
#define ALTBASE_UTXO_SERVICE_IMPORT_CALL
#endif

ALTBASE_UTXO_SERVICE_IMPORT char* ALTBASE_UTXO_SERVICE_IMPORT_CALL altbase_utxo_address_request(const char* request);
ALTBASE_UTXO_SERVICE_IMPORT void ALTBASE_UTXO_SERVICE_IMPORT_CALL altbase_utxo_address_free(char* value);
ALTBASE_UTXO_SERVICE_IMPORT char* ALTBASE_UTXO_SERVICE_IMPORT_CALL altbase_utxo_derivation_request(const char* request);
ALTBASE_UTXO_SERVICE_IMPORT void ALTBASE_UTXO_SERVICE_IMPORT_CALL altbase_utxo_derivation_free(char* value);
ALTBASE_UTXO_SERVICE_IMPORT char* ALTBASE_UTXO_SERVICE_IMPORT_CALL altbase_utxo_signer_request(const char* request);
ALTBASE_UTXO_SERVICE_IMPORT void ALTBASE_UTXO_SERVICE_IMPORT_CALL altbase_utxo_signer_free(char* value);
ALTBASE_UTXO_SERVICE_IMPORT char* ALTBASE_UTXO_SERVICE_IMPORT_CALL altbase_utxo_planner_request(const char* request);
ALTBASE_UTXO_SERVICE_IMPORT void ALTBASE_UTXO_SERVICE_IMPORT_CALL altbase_utxo_planner_free(char* value);
