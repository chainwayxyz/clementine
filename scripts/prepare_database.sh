#!/bin/bash
#
# This script isn't a strict requirement for preparing database. One can take
# this only as a reference.

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

echo "Preparing database for $PGDATABASE"

dropdb -U $PGUSER $PGDATABASE
createdb -U $PGUSER -O $PGUSER $PGDATABASE

cat $SCRIPT_DIR/schema.sql | psql -U $PGUSER $PGDATABASE
cat $SCRIPT_DIR/pgmq.sql | psql -U $PGUSER $PGDATABASE
