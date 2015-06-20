import argparse
import logging
import os
import sys
import time

from keystoneclient.v3 import client as keystoneclient
from neutronclient.neutron import client as neutronclient
from novaclient import client as novaclient
from novaclient import exceptions as nova_exceptions

from keystoneclient import session as ksc_session
from keystoneclient.auth.identity import v3
from keystoneclient.v3 import client as keystone_v3
import ansible.runner


user_data_template = """
#cloud-config
hostname: %(fqdn)s
fqdn:  %(fqdn)s
package_upgrade: true

"""


class Plan(object):
    name = os.environ.get('USER', 'rdo')
    domain_name = name
    router_name = name + '-router'
    network_name = name + '-net'
    subnet_name = name + '-subnet'
    cidr = "192.168.52.0/24"
    flavor = "m1.medium"
    image = "centos-7-cloud"
    key = name + "-pubkey"
    security_groups = ["default"]
    forwarder = "192.168.52.3"

status = dict()

class WorkInProgress(object):
    pass


class WorkItem(object):
    def _external_id(self):
        return self.neutron.list_networks(name='external')['networks'][0]['id']

    def _router_response(self):
        return self.neutron.list_routers(name=self.plan.router_name)

    def _networks_response(self):
        return self.neutron.list_networks(name=self.plan.network_name)

    def _subnet_response(self):
        return self.neutron.list_subnets(name=self.plan.subnet_name)

    def _subnet_id(self):
        return self._subnet_response()['subnets'][0]['id']

    def get_image_id(self, image_name):
        for image in self.nova.images.list():
            if image.name == image_name:
                return image.id

    def get_flavor_id(self, flavor_name):
        for flavor in self.nova.flavors.list():
            if flavor.name == flavor_name:
                return flavor.id

    def list_servers(self):
        return self.nova.servers.list(
            search_opts={"name": self.plan.domain_name + "$"})

    def get_server_by_name(self, name):

        servers = self.nova.servers.list(
            search_opts={"name": "^" + name + "$"})
        return servers[0]

    def __init__(self, session, plan):

        self.keystone = keystone_v3.Client(session=session)
        self.nova = novaclient.Client('2', session=session)
        self.neutron = neutronclient.Client('2.0', session=session)
        self.neutron.format = 'json'

        self.plan = plan

    def make_fqdn(self, name):
        return name + '.' + self.plan.domain_name


class Network(WorkItem):
    def _networks_response(self):
        return self.neutron.list_networks(name=self.plan.network_name)

    def create(self):
        network = self.neutron.create_network(
            {'network':
             {'name': self.plan.network_name,
              'admin_state_up': True}})
        status['network'] = network

    def display(self):
        print(self._networks_response())

    def teardown(self):
        for network in self._networks_response()['networks']:
            self.neutron.delete_network(network['id'])


class SubNet(WorkItem):

    def create(self):
        network = self._networks_response()['networks'][0]
        subnet = self.neutron.create_subnet(
            body={
                "subnets": [
                    {
                        "name": self.plan.subnet_name,
                        "cidr": self.plan.cidr,
                        "ip_version": 4,
                        "network_id": network['id']
                    }
                ]
            })
        status['subnet'] = subnet

    def display(self):
        print (self._subnet_response())

    def teardown(self):
        for subnet in self._subnet_response()['subnets']:
            self.neutron.delete_subnet(subnet['id'])


class Router(WorkItem):
    def create(self):
        router = self.neutron.create_router(
            body={'router': {
                'name': self.plan.router_name,
                'admin_state_up': True,
            }})['router']
        self.neutron.add_gateway_router(
            router['id'],
            {'network_id': self._external_id()})

    def display(self):
        print(self._router_response())

    def teardown(self):
        for router in self._router_response()['routers']:
            self.neutron.remove_gateway_router(router['id'])
            self.neutron.delete_router(router['id'])


class RouterInterface(WorkItem):
    def create(self):
        self.neutron.add_interface_router(
            self._router_response()['routers'][0]['id'],
            {"subnet_id": self._subnet_id()})

    def display(self):
        for router in self._router_response()['routers']:
            for subnet in self._subnet_response()['subnets']:
                try:
                    print("router %s on subnet %s" % (router['id'],
                                                      subnet['id']))
                except Exception:
                    pass

    def teardown(self):
        for router in self._router_response()['routers']:
            for subnet in self._subnet_response()['subnets']:
                try:
                    self.neutron.remove_interface_router(
                        router['id'], {"subnet_id": subnet['id']})
                except Exception:
                    pass


class FloatIP(WorkItem):
    def next_float_ip(self):
        ip_list = self.nova.floating_ips.list()
        for float in ip_list:
            if float.instance_id is None:
                return float
        return None

    def assign_next_ip(self, server):
        try:
            float = self.next_float_ip()
            print (" Assigning %s to host id %s" % (float.ip, server.id))
            server.add_floating_ip(float.ip)
        except nova_exceptions.BadRequest:
            print ("IP assign failed. Waiting 5 seconds to try again.")
            time.sleep(5)
            server.add_floating_ip(float.ip)

    def display_ip_for_server(self, server):
        for float in self.nova.floating_ips.list():
            if float.instance_id == server.id:
                print (float.ip)

    def remove_float_from_server(self, server):
        for float in self.nova.floating_ips.list():
            if float.instance_id == server.id:
                print ("Removing  %s from host id %s"
                       % (float.ip, server.id))
                server.remove_floating_ip(float)
                break

    def create(self):
        server = self.get_server_by_name(self.make_fqdn(self.host_name))
        self.assign_next_ip(server)

    def display(self):
        try:
            server = self.get_server_by_name(self.make_fqdn(self.host_name))
            self.display_ip_for_server(server)
        except IndexError:
            pass


    def teardown(self):
        server = self.get_server_by_name(self.make_fqdn(self.host_name))
        self.remove_float_from_server(server)


class IPAFloatIP(FloatIP):
    host_name = "ipa"

class RDOFloatIP(FloatIP):
    host_name = "rdo"



class NovaHost(WorkItem):
    def _host(self, name, user_data):

        nics = []
        for network in self._networks_response()['networks']:
            nics.append({'net-id': network['id']})

        response = self.nova.servers.create(
            self.fqdn(),
            self.get_image_id(self.plan.image),
            self.get_flavor_id(self.plan.flavor),
            security_groups=self.plan.security_groups,
            nics=nics,
            meta=None,
            files=None,
            reservation_id=None,
            min_count=1,
            max_count=1,
            userdata=user_data,
            key_name=self.plan.key,
            availability_zone=None,
            block_device_mapping=None,
            scheduler_hints=None,
            config_drive=None
        )
        return self.wait_for_creation(response.id)

    def wait_for_creation(self, host_id):
        found = False
        while not found:
            try:
                host = self.nova.servers.get(host_id)
                found = True
                print ("Host %s created" % host_id)
                return host
            except Exception as e:
                print (".")
                pass

    #  Over ride this to create a subset of the hosts
    def host_name_list(self):
        return self.plan.host_names

    def user_data(self):
        realm = self.plan.domain_name.upper()
        data = self.user_data_template() % {
            'hostname': self.host_name(),
            'fqdn': self.fqdn(),
            'realm': realm
        }
        return data

    def fqdn(self):
        return self.host_name() + '.' + self.plan.domain_name

    def host_list(self):
        for host in self.nova.servers.list(search_opts={"name": self.fqdn()}):
            yield host

    def create(self):
        host = self._host(self.host_name(), self.user_data())
        status [self.host_name()] = host

    def display(self):
        try:
            for server in self.host_list():
                print (server.name)
        except Exception:
            pass

    def teardown(self):
        for server in self.host_list():
            self.nova.servers.delete(server.id)


class IPAServer(NovaHost):

    def user_data_template(self):
        return user_data_template + """
packages:
 - ipa-client
 - ipa-server
 - bind-dyndb-ldap
runcmd:
 - [ rngd, -r, /dev/hwrng]
 - [ ipa-server-install, -r, %(realm)s, -n, %(hostname)s, -p,
     FreeIPA4All, -a, FreeIPA4All, -N, --hostname=%(fqdn)s,
     --setup-dns, --forwarder=192.168.52.3, -U]
"""

    def host_name(self):
        return "ipa"


class RDOServer(NovaHost):

    def user_data_template(self):

        resolve_data = """
manage-resolv-conf: true

resolv_conf:
  nameservers: ['192.168.52.2']
  searchdomains:
    - foo.example.com
    - bar.example.com
  domain: example.com
  options:
    rotate: true
    timeout: 1
"""
        return user_data_template +  """

runcmd:
 - [yum, install, -y, https://rdo.fedorapeople.org/openstack-juno/rdo-release-juno.rpm]

packages:
 - ipa-client
 - epel-release
 - openstack-packstack


"""
    def create(self):
        super(RDOServer,self).create()


    def host_name(self):
        return "rdo"


class WorkItemList(object):

    def __init__(self, work_item_classes, session, plan):

        self.work_items = []
        for item_class in work_item_classes:
            self.work_items.append(item_class(session, plan))

    def create(self):
        for item in self.work_items:
            print (item.__class__.__name__)
            item.create()

    def teardown(self):
        for item in reversed(self.work_items):
            print (item.__class__.__name__)

            try:
                item.teardown()
            except Exception:
                pass

    def display(self):
        for item in self.work_items:
            print (item.__class__.__name__)
            item.display()

class IPA(WorkItemList):
    def __init__(self, session, plan):
        super(IPA, self).__init__([IPAServer, IPAFloatIP], session, plan)


class RDO(WorkItemList):
    def __init__(self, session, plan):
        super(RDO, self).__init__([RDOServer, RDOFloatIP], session, plan)


_auth = None
_session = None


def get_auth():
    if _auth is None:
        OS_AUTH_URL = os.environ.get('OS_AUTH_URL')
        OS_USERNAME = os.environ.get('OS_USERNAME')
        OS_PASSWORD = os.environ.get('OS_PASSWORD')
        OS_USER_DOMAIN_NAME = os.environ.get('OS_USER_DOMAIN_NAME')
        OS_PROJECT_DOMAIN_NAME = os.environ.get('OS_PROJECT_DOMAIN_NAME')
        OS_PROJECT_NAME = os.environ.get('OS_PROJECT_NAME')

        if OS_AUTH_URL is None:
            print ("OS_AUTH_URL not set.  Aborting.")
            sys.exit(-1)

        auth = v3.Password(auth_url=OS_AUTH_URL,
                           username=OS_USERNAME,
                           user_domain_name=OS_USER_DOMAIN_NAME,
                           password=OS_PASSWORD,
                           project_name=OS_PROJECT_NAME,
                           project_domain_name=OS_PROJECT_DOMAIN_NAME)

    return auth


def create_session():
        session = ksc_session.Session(auth=get_auth())
        return session


def build_work_item_list(work_item_classes):
    plan = Plan()
    session = create_session()
    return WorkItemList(work_item_classes, session, plan)


worker = build_work_item_list([
    Router, Network, SubNet, RouterInterface,
    IPA,
    RDO,
])


workers = {
    "all": build_work_item_list([
        Router, Network, SubNet, RouterInterface,
        IPA,  RDO,]),
    "rdo": build_work_item_list([RDO]),
    "ipa": build_work_item_list([IPA]),
    "network": build_work_item_list([Router, Network, SubNet, RouterInterface]),
}


def get_args():
    parser = argparse.ArgumentParser(description='Display the state of the system.')
    parser.add_argument('worker', nargs='?', default="all",
                    help='Worker to execute, defaults to "all"')
    args = parser.parse_args()
    return args



def enable_logging():
    logging.basicConfig(level=logging.DEBUG)


def create(worker="all"):
    workers[worker].create()


def teardown(worker="all"):
    workers[worker].teardown()


def display(worker="all"):
    workers[worker].display()

def list():
    print(workers.keys())
