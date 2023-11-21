#!/bin/bash

LIBDGMAIL_PATH=$1
LIBDGSTR_PATH=$2

echo -n -e '#include <stdio.h>\n#include <libdgmail.h>\n\nint\nmain(void)\n{\n    unsigned char str[]="test <test@localhost.localdomain>";\n\n    get_addrpart_notranslate(str);\n    return 0;\n}\n' > check_get_addrpart_notrans.c

gcc check_get_addrpart_notrans.c ${LIBDGMAIL_PATH}/libdgmail.so ${LIBDGSTR_PATH}/libdgstr.so  -o result >/dev/null 2>&1
ret=$?
rm -f check_get_addrpart_notrans.c
if [ $ret -ne 0 ]
then
    exit 1
fi

./result >/dev/null 2>&1
rm -f result
ret=$?
if [ $ret -ne 0 ]
then
    exit 2
fi

exit 0
