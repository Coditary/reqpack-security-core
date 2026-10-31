#pragma once

#include <cstddef>

#ifdef __cplusplus
extern "C" {
#endif

// Return codes: 0 success, 1 error (message in *out_json), 2 panic, -1 invalid args
int rqp_cyclonedx_emit_json(const char* input_json, char** out_json);
int rqp_cyclonedx_parse_inventory_json(const char* cyclonedx_json, char** out_json);
void rqp_cyclonedx_free(char* buffer);

#ifdef __cplusplus
}
#endif
