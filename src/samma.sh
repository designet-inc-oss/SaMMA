#!/bin/sh

export LD_LIBRARY_PATH=/usr/local/samma/lib
export LD_PRELOAD=/usr/local/samma/lib/preloadable_libiconv.so
export CHARSET_ALIAS="Shift_JIS=CP932:EUC-JP=EUC-JP-MS:ISO-2022-JP=ISO-2022-JP-MS"

/usr/bin/samma > /dev/null 2>&1
