#!/bin/bash

# Get the list of tables
tables=$(psql -t -c "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'")

# Loop through each table and print all rows
for table in $tables; do
    echo "Rows for table '$table':"
    psql -c "SELECT * FROM $table" -P pager=off
    echo -e "\n-------------------------------------------------\n"
done