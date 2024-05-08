#!/bin/bash
#
# This file isn't a strict requirement for preparing database. One can take this
# as a reference.

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )


echo "Preparing 5 database for $PGDATABASE, where we add db and user name is $PGDATABASE + str(i)"

dropdb $PGDATABASE
dropuser $PGDATABASE
createuser $PGDATABASE
createdb -O $PGDATABASE $PGDATABASE
cat $SCRIPT_DIR/test_schema.sql $SCRIPT_DIR/schema.sql | psql -U $PGDATABASE $PGDATABASE

for i in {0..4}
do
    dropdb $PGDATABASE$i
    dropuser $PGDATABASE$i
    createuser $PGDATABASE$i
    createdb -O $PGDATABASE$i $PGDATABASE$i
    cat $SCRIPT_DIR/test_schema.sql $SCRIPT_DIR/schema.sql | psql -U $PGDATABASE$i $PGDATABASE$i
done
