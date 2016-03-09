#!/usr/bin/python2
import os
import re

regex = re.compile('^\[.*')

with open(os.environ['HOME'] + "/.ossipee/config.ini", "r") as config:
    for line in config:
        for section in regex.findall(line):
            print re.sub('[\[\]]', '', section)
