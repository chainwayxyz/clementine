#!/bin/bash
#
# This file isn't a strict requirement for preparing database. One can take this
# as a reference.

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

# Disconnect all other users from the database
psql -c "REVOKE CONNECT ON DATABASE $USER FROM PUBLIC;"
psql -c "SELECT pg_terminate_backend(pg_stat_activity.pid)
                              FROM pg_stat_activity
                              WHERE pg_stat_activity.datname = '$USER'
                                AND pid <> pg_backend_pid();"

dropdb $USER
dropuser $USER
createuser $USER
createdb -O $USER $USER

# Apply schema for the user named $USER who owns database named $USER.
cat $SCRIPT_DIR/test_schema.sql | psql -U $USER $USER
