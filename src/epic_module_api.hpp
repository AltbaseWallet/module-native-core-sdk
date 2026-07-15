#pragma once

#ifdef _WIN32
#define ALTBASE_EPIC_API extern "C" __declspec(dllimport)
#define ALTBASE_EPIC_CALL __cdecl
#else
#define ALTBASE_EPIC_API extern "C"
#define ALTBASE_EPIC_CALL
#endif

ALTBASE_EPIC_API char* ALTBASE_EPIC_CALL altbase_epic_state_request(const char* request);
ALTBASE_EPIC_API void ALTBASE_EPIC_CALL altbase_epic_state_free(char* value);
ALTBASE_EPIC_API char* ALTBASE_EPIC_CALL altbase_epic_sender_request(const char* request);
ALTBASE_EPIC_API void ALTBASE_EPIC_CALL altbase_epic_sender_free(char* value);
