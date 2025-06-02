#!/bin/bash
#
# This script checks for TODO keywords in code.

directories=(core bridge-circuit-host circuits-lib risc0-circuits)
is_found=0

for directory in ${directories[@]}
do
    echo Looking TODOs in $directory...

    grep -Rnwi $directory -e 'TODO'

    # If something was found, TODOs are not present and script must fail.
    if [ $? -eq 0 ]
    then
        is_found=1
    fi
done

if [ $is_found -eq 1 ]
then
    exit 1
fi
