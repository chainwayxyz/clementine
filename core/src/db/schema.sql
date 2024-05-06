begin;

drop table test_table;
-- This table is for testing purposes.
create table test_table (
    test_column_string text,
    test_column_number int
);

commit;
