#!/usr/bin/python

import os
import json

def iparesolver():
    for text in open("/etc/resolv.conf","r"):
        words = text.split()
        if words[0] == "nameserver":
            return words[1] 

def ipa_install_command():
    iparealm="RDO.CLOUDLAB.FREEIPA.ORG"
    install_command = ["ipa-server-install","-U","-r", iparealm,
                       "-p", "FreeIPA4All",
                       "-a", "FreeIPA4All",
                       "--setup-dns", "--forwarder", iparesolver()]
    return install_command


print json.dumps({
    "command" : ipa_install_command()
})
