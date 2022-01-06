#! /bin/bash

#web help http://astyle.sourceforge.net/astyle.html#_Usage

options="-R -A1 -c -s4 -S -N -Y -p -k3 -W3 -H -xL -xC80 -U -n -j -xV -w -z2 -i"

astyle $options "os/*.c,*.h" --exclude=os/android --exclude=os/rtos --exclude=os/rt-thread --exclude=os/windows
astyle $options "nic/*.c,*.h" --exclude=nic/utility/protothreads
