#!/bin/sh

find . -name \*py | etags --output TAGS
rpmquery --list python-neutronclient | grep py$ | etags -a --output TAGS -
