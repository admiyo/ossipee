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


class DTO(object):
    def params_to_properties(params):          
        keys = params().keys()
        keys.remove('self')
        for key in keys:
            setattr(self, key, params()[key])

class HostDTO(DTO):
    def _init__(self, name, image, key, security_groups, nics):
        self.params_to_properites(self, locals)


class Host(object):
    pass


class Plan(object):
    server_name='ipa.ayoung'
    router_name = 'rdo-router'
    network_name ='rdo-net'
    subnet_name ='rdo-subnet'
    cidr = "192.168.52.0/24"
    flavor = "m1.medium"
    image = "centos-7-x86_64"
    key= "ayoung-pubkey"
    security_groups = ["default"]
    
    
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


    def __init__(self, neutron, nova, plan):
        self.neutron = neutron
        self.nova = nova
        self.plan = plan

class Network(WorkItem):
    def _networks_response(self):
        return self.neutron.list_networks(name=self.plan.network_name)

    def create(self):
        self.neutron.create_network(
            {'network':
             {'name':self.plan.network_name,
              'admin_state_up': True}})

    def display(self):
        print(self._networks_response())

    def cleanup(self):
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

    def display(self):
        print (self._subnet_response())

    def cleanup(self):
        for subnet in self._subnet_response()['subnets']:
            self.neutron.delete_subnet(subnet['id'])


class Router(WorkItem):
    def create(self):
        router = self.neutron.create_router(
            body={'router': {
                'name' : self.plan.router_name,
                'admin_state_up': True,
            }})['router']
        self.neutron.add_gateway_router(
            router['id'],
            {'network_id': self._external_id()})

    def display(self):
        print(self._router_response())

    def cleanup(self):
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

    def cleanup(self):
        for router in self._router_response()['routers']:
            for subnet in self._subnet_response()['subnets']:
                try:
                    self.neutron.remove_interface_router(
                        router['id'], {"subnet_id": subnet['id']})
                except Exception:
                    pass

class FloatIP(WorkItem):

    def create(self):
        ip_list = self.nova.floating_ips.list()
        for float in ip_list:
            if float.instance_id == None:
                break
        for server in self.nova.servers.list():
            if server.name == self.plan.server_name:
                break
        print (" Assigning %s to host id %s" % (float.ip, server.id) )

        try:
            server.add_floating_ip(float.ip)
        except nova_exceptions.BadRequest:
            print ("IP assign failed. Waiting 5 seconds to try again.")
            time.sleep(5)
            server.add_floating_ip(float.ip)


    def display(self):
        for server in self.nova.servers.list():
            if server.name == "demo.cloudlab.freeipa.org":
                break

        for float in self.nova.floating_ips.list():
            if float.instance_id == server.id:
                print (float.ip)

    def cleanup(self):
        for server in self.nova.servers.list():
            if server.name == self.plan.server_name:
                break
        for float in self.nova.floating_ips.list():
            if float.instance_id == server.id:
                break

        print (" Removing  %s from host id %s" % (float.ip, server.id) )
        server.remove_floating_ip(float)




class NovaHost(WorkItem):

    def _host(self):
        host = Host()
        host.flavor = self.plan.flavor
        host.image = self.plan.image
        host.key= self.plan.key
        host.security_groups = self.plan.security_groups
        host.name= self.plan.server_name
        host.image_id = self.get_image_id(host.image)
        host.flavor_id = self.get_flavor_id(host.flavor)
        host.nics = []

        for network in self._networks_response()['networks']:
            host.nics.append({'net-id': network['id']})

        return host

    def wait_for_creation(self, host_id):
        found = False
        while not found:
            try:
                self.nova.servers.get(host_id)
                found = True
                print ("Host %s created" % host_id)
            except Exception as e:
                print (".")
                pass


    def create(self):

        self._host()
        host_entry = self._host()

        response = self.nova.servers.create(
            host_entry.name,
            host_entry.image_id,
            host_entry.flavor_id,
            security_groups = host_entry.security_groups,
            nics=host_entry.nics,
            meta = None,
            files = None,
            reservation_id = None,
            min_count = 1,
            max_count = 1,
            userdata = None,#host_entry.userdata,
            key_name = host_entry.key,
            availability_zone = None,
            block_device_mapping= None,
            scheduler_hints= None,
            config_drive= None
        )
        self.wait_for_creation(response.id)

    def display(self):
        for server in self.nova.servers.list():
            if server.name == self.plan.server_name:
                print (server)

    def cleanup(self):
        for server in self.nova.servers.list():
            if server.name == self.plan.server_name:
                self.nova.servers.delete(server.id)


class IPAServer(WorkItem):
    pass
    #ansible rdo -i ~/.ossipee/inventory.ini -u centos --sudo -m yum -a "name=ipa-server state=present"

_auth = None
_session = None

def get_auth():
    if _auth is None:

        OS_AUTH_URL = os.environ.get('OS_AUTH_URL')
        OS_USERNAME = os.environ.get('OS_USERNAME')
        OS_PASSWORD= os.environ.get('OS_PASSWORD')
        OS_USER_DOMAIN_NAME=os.environ.get('OS_USER_DOMAIN_NAME')
        OS_PROJECT_DOMAIN_NAME=os.environ.get('OS_PROJECT_DOMAIN_NAME')
        OS_PROJECT_NAME=os.environ.get('OS_PROJECT_NAME')

        if  OS_AUTH_URL is None:
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




class Worklist(object):
    def __init__(self):

        plan = Plan()
        session = create_session()
        keystone = keystone_v3.Client(session=session)
        nova = novaclient.Client('2', session=session)
        neutron = neutronclient.Client('2.0', session=session)

        neutron.format = 'json'
        work_item_classes = [
            Router, Network, SubNet, RouterInterface, NovaHost,
            FloatIP
        ]

        self.work_items = []

        for item_class in work_item_classes:
            self.work_items.append(item_class(neutron, nova, plan))

    def create(self):
        for item in self.work_items:
            item.create()

    def teardown(self):
        for item in reversed(self.work_items):
            try:
                item.cleanup()
            except Exception:
                pass

    def display(self):
        for item in self.work_items:
            item.display()

def enable_logging():
    logging.basicConfig(level=logging.DEBUG)


def create():
    Worklist().create()


def teardown():
    Worklist().teardown()

def display():
    wl = Worklist()
    wl.display()
