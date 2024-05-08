#!/bin/bash
#
# This file isn't a strict requirement for preparing database. One can take this
# as a reference.

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

echo "Preparing database for $PGDATABASE"


dropdb $PGDATABASE
dropuser $PGDATABASE
createuser $PGDATABASE
createdb -O $PGDATABASE $PGDATABASE

# Apply schema for the user named $USER who owns database named $USER.
cat $SCRIPT_DIR/test_schema.sql $SCRIPT_DIR/schema.sql | psql -U $PGDATABASE $PGDATABASE
