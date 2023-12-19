#ifndef OSH_NOISE_PROTOCOL_NAME_H_
#define OSH_NOISE_PROTOCOL_NAME_H_

#include "constants.h"
#include <stdbool.h>

bool noise_parse_protocol_name(struct noise_protocol_name *parsed,
    const char *protocol_name);

#endif
