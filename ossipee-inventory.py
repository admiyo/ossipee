import argparse
import sys
import os_client_config


class ServerInventory(object):
    def do(self):
        nova =  os_client_config.make_client('compute', cloud='envvars')
        for server in nova.servers.list():
            print("[%s]" % server.name)
            print(server.networks['ctlplane'][0])
            print("[%s:vars]" % server.name)
            print("ipa_realm=AYOUNG.DELLT1700.TEST")
            if server.name == 'ipa':
                print("cloud_user=centos")
            else:
                print("cloud_user=heat-admin")
            print("ipa_server_password=FreeIPA4All")
            print("ipa_domain=ayoung.dellt1700.test")
            print("ipa_forwarder=192.168.122.1")
            print("ipa_admin_user_password=FreeIPA4All")
            print("ipa_nova_join=False")
            print("nameserver=192.168.52.4")
            print("")


def main():
    inv = ServerInventory()
    inv.do()

if __name__ == '__main__':
    main()
