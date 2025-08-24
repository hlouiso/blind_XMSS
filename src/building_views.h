#ifndef BUILDING_H
#define BUILDING_H

#include "shared.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

a building_views(unsigned char digest[32], unsigned char shares[3][INPUT_LEN], unsigned char *randomness[3],
                 View views[3], unsigned char public_key[8192], bool *error);

#endif // BUILDING_H