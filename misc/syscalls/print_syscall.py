#!/usr/bin/env python3

import json
import sys
from collections import defaultdict

import tabulate

with open("parsed_syscalls.json") as file:
    parsed_json = json.load(file)

parsed_per_name = defaultdict(list)

for s in parsed_json:
    parsed_per_name[s['name']].append(s)



to_print = []
for line in parsed_per_name[sys.argv[1]]:
    args = [[x['name'], x['type'].replace(" __user", "")] for x in line['args']]
    src = line['defined_in']
    to_print.append([src] + [x for y in args for x in y])

print(tabulate.tabulate(to_print))
