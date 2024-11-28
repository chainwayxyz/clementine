#!/usr/bin/python

import sys
import json

EXPECTED_LINE_COVER_PERCENTAGE = float(70.0)
EXPECTED_FUNCTION_COVER_PERCENTAGE = float(70.0)

json_file = sys.argv[1]
print("Reading JSON file", json_file)

contents = open(json_file, "r").read()
contents = json.loads(contents)

lines_covered = contents["data"][0]["totals"]["lines"]["percent"]
print("Lines are covered", lines_covered, "percent")

functions_covered = contents["data"][0]["totals"]["functions"]["percent"]
print("Functions are covered", functions_covered, "percent")

assert EXPECTED_LINE_COVER_PERCENTAGE <= float(lines_covered), "Low line coverage"
assert EXPECTED_FUNCTION_COVER_PERCENTAGE <= float(functions_covered), "Low function coverage"

print("Coverage is enough")
