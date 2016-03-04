import argparse
import sys

from keystoneclient import auth as ksc_auth
from keystoneclient import session as ksc_session
from novaclient import client as novaclient

def session_factory():
    parser = argparse.ArgumentParser(description="")
    ksc_session.Session.register_cli_options(parser)
    ksc_auth.register_argparse_arguments(parser,
                                         sys.argv,
                                         default='v3password')
    args = parser.parse_args()
    auth_plugin = ksc_auth.load_from_argparse_arguments(args)
    session = ksc_session.Session.load_from_cli_options(
        args,
        auth=auth_plugin)
    return session

class ServerInventory(object):
    def do(self):
        nova = novaclient.Client('2', session=session_factory())
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
