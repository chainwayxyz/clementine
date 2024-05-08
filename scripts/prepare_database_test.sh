#!/bin/bash
#
# This file isn't a strict requirement for preparing database. One can take this
# as a reference.

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )


echo "Preparing 5 database for $PGDATABASE, where we add db and user name is $PGDATABASE + str(i)"

dropdb -U $PGUSER $PGDATABASE
createdb -U $PGUSER -O $PGUSER $PGDATABASE
cat $SCRIPT_DIR/schema.sql | psql -U $PGUSER $PGDATABASE

for i in {0..4}
do
    dropdb -U $PGUSER $PGDATABASE$i
    createdb -U $PGUSER -O $PGUSER $PGDATABASE$i
    cat $SCRIPT_DIR/schema.sql | psql -U $PGUSER $PGDATABASE$i
done
