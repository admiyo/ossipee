import os

from keystoneclient.v3 import client as keystoneclient
from neutronclient.neutron import client as neutronclient
from novaclient import client as novaclient


from keystoneclient import session as ksc_session
from keystoneclient.auth.identity import v3
from keystoneclient.v3 import client as keystone_v3


router_name = 'rdo-router'
network_name ='rdo-net'
subnet_name ='rdo-subnet'


class WorkItem(object):
    def _external_id(self):
        return self.neutron.list_networks(name='external')['networks'][0]['id']

    def _router_response(self):
        return self.neutron.list_routers(name=router_name)

    def _networks_response(self):
        return self.neutron.list_networks(name=network_name)

    def _subnet_response(self):
        return self.neutron.list_subnets(name=subnet_name)

    def _subnet_id(self):
        return self._subnet_response()['subnets'][0]['id']


    def __init__(self, neutron):
        self.neutron = neutron

class Network(WorkItem):
    def _networks_response(self):
        return self.neutron.list_networks(name=network_name)

    def create(self):
        self.neutron.create_network(
            {'network':{'name': network_name, 'admin_state_up': True}})

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
                        "name": subnet_name,
                        "cidr": "192.168.52.0/24",
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
                'name' : router_name,
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
        print ("RouterInterface")

    def cleanup(self):
        for router in self._router_response()['routers']:
            for subnet in self._subnet_response()['subnets']:
                try:
                    self.neutron.remove_interface_router(
                        router['id'], {"subnet_id": subnet['id']})
                except Exception:
                    pass

#logging.basicConfig(level=logging.DEBUG)

def create_session():

        OS_AUTH_URL = os.environ.get('OS_AUTH_URL')
        OS_USERNAME = os.environ.get('OS_USERNAME')
        OS_PASSWORD= os.environ.get('OS_PASSWORD')
        OS_USER_DOMAIN_NAME=os.environ.get('OS_USER_DOMAIN_NAME')
        OS_PROJECT_DOMAIN_NAME=os.environ.get('OS_PROJECT_DOMAIN_NAME')
        OS_PROJECT_NAME=os.environ.get('OS_PROJECT_NAME')

        auth = v3.Password(auth_url=OS_AUTH_URL,
                           username=OS_USERNAME,
                           user_domain_name=OS_USER_DOMAIN_NAME,
                           password=OS_PASSWORD,
                           project_name=OS_PROJECT_NAME,
                           project_domain_name=OS_PROJECT_DOMAIN_NAME)

        session = ksc_session.Session(auth=auth)
        return session


class Worklist(object):
    def __init__(self):

        session = create_session()
        keystone = keystone_v3.Client(session=session)
        nova = novaclient.Client('2', session=session)
        neutron = neutronclient.Client('2.0', session=session)
        neutron.format = 'json'


        work_item_classes =[Router,Network,SubNet,RouterInterface]

        self.work_items = []

        for item_class in work_item_classes:
            self.work_items.append(item_class(neutron))


    def setup(self):
        for item in self.work_items:
            item.create()

    def teardown(self):
        for item in reversed(self.work_items):
            item.cleanup()

    def display(self):
        for item in self.work_items:
            item.display()


def setup():
    Worklist().setup()

def teardown():
    Worklist().teardown()

def display():
    wl = Worklist()
    wl.display()
