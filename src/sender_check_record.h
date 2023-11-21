#include <resolv.h>
#include <string.h>
#include <errno.h>

#include "sender_check.h"
#include "maildrop.h"
#include "global.h"

#define EDNS0_MAXPACKET 4096
