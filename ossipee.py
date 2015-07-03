#!/usr/bin/python

import argparse
import json
import logging
import os
import shlex
import subprocess
import sys
import time

import ConfigParser

from neutronclient.neutron import client as neutronclient
from novaclient import client as novaclient
from novaclient import exceptions as nova_exceptions

from keystoneclient import session as ksc_session
from keystoneclient.auth.identity import v3
from keystoneclient.v3 import client as keystone_v3


user_data_template = '''
#cloud-config
hostname: %(fqdn)s
fqdn:  %(fqdn)s
package_upgrade: true

'''


class Plan(object):
    def _default_config_options(self, config, outfile):
        config.add_section('scope')
        config.set('scope', 'name', self.username)
        config.set('scope', 'pubkey', self.key)
        config.set('scope', 'flavor',  'm1.medium')
        config.set('scope', 'image',  'centos-7-cloud')
        config.set('scope', 'forwarder',  '192.168.52.3')
        config.write(outfile)

    def __init__(self):
        self.config_dir = os.environ.get('HOME', '/tmp') + "/.ossipee"
        self.username = os.environ.get('USER', 'rdo')
        self.key = self.username + '-pubkey'
        if not os.path.exists(self.config_dir):
            os.makedirs(self.config_dir)

        self.config_file = self.config_dir + "/config.ini"

        if not os.path.exists(self.config_file):
            with open(self.config_file, 'w') as f:
                config = ConfigParser.RawConfigParser()
                self._default_config_options(config, f)
                logging.error("No config file %s. wrote default" %
                              self.config_file)
                exit(1)

        config = ConfigParser.ConfigParser()
        config.read(self.config_file)
        try:
            self.name = config.get("scope", "name")
            self.key = config.get("scope", "pubkey")
            self.flavor = config.get("scope", 'flavor')
            self.image = config.get("scope", 'image')
            self.forwarder = config.get("scope", 'forwarder')
            self.security_groups = ['default']

        except ConfigParser.NoSectionError:
            self._default_config_options(config, f)
            logging.error("No Scope Section in %s, wrote defaults" %
                          self.config_file)
            exit(1)

        name = self.name
        self.domain_name = name
        self.inventory_dir = self.config_dir + "/inventory/"
        self.inventory_file = self.inventory_dir + name + ".ini"
        self.variable_dir = self.config_dir + "/variables/"
        self.variable_file = self.variable_dir + name + ".ini"

        self.networks = {
            'public': {
                'router_name': name + '-public-router',
                'network_name': name + '-public-net',
                'subnet_name': name + '-public-subnet',
                'cidr': '192.168.52.0/24'},
            'private': {
                'router_name': name + '-private-router',
                'network_name': name + '-private-net',
                'subnet_name': name + '-private-subnet',
                'cidr': '192.168.178.0/24'},
        }
        self.hosts = {
            "ipa": {
                "ipa_forwarder": "192.168.52.3",
                "ipa_realm": name.upper(),
                "ipa_server_password": "FreeIPA4All",
                "ipa_admin_user_password": "FreeIPA4All"
            },
            "rdo": {
                "ipa_realm": name.upper(),
                "rdo_password": "FreeIPA4All",
                "ipa_admin_user_password": "FreeIPA4All"
            }
        }

    def make_fqdn(self, name):
        return name + '.' + self.domain_name


class Scorecard(object):
    def __init__(self, server_list, plan):
        self.plan = plan
        self.hosts = dict()
        for server in server_list:
            self.hosts[server.name] = dict()
            for net in server.addresses:
                for addr in server.addresses[net]:
                    if addr['OS-EXT-IPS:type'] == 'fixed':
                        self.hosts[server.name]['fixed'] = addr['addr']
                    if addr['OS-EXT-IPS:type'] == 'floating':
                        self.hosts[server.name]['floating'] = addr['addr']

    def ipa_resolver(self):
        return self.hosts[self.plan.make_fqdn('ipa')]['fixed']

    def display(self):
        logging.info('ipa resolver = ' + self.ipa_resolver())
        for host in self.hosts:
            logging.info(host)
            logging.info(self.hosts[host])


class WorkItem(object):
    def _external_id(self):
        return self.neutron.list_networks(name='external')['networks'][0]['id']

    def _router_response(self, which):
        return self.neutron.list_routers(
            name=self.plan.networks[which]['router_name'])

    def _networks_response(self, which):
        return self.neutron.list_networks(
            name=self.plan.networks[which]['network_name'])

    def _subnet_response(self, which):
        return self.neutron.list_subnets(
            name=self.plan.networks[which]['subnet_name'])

    def _subnet_id(self, which):
        return self._subnet_response(which)['subnets'][0]['id']

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
            search_opts={'name': self.plan.domain_name + '$'})

    def get_server_by_name(self, name):

        servers = self.nova.servers.list(
            search_opts={'name': '^' + name + '$'})
        return servers[0]

    def floating_ip_for_server(self, server):
        for float in self.nova.floating_ips.list():
            if float.instance_id == server.id:
                return (float.ip)

    def __init__(self, session, plan, name):
        self.name = name
        self.keystone = keystone_v3.Client(session=session)
        self.nova = novaclient.Client('2', session=session)
        self.neutron = neutronclient.Client('2.0', session=session)
        self.neutron.format = 'json'

        self.plan = plan

    def make_fqdn(self, name):
        return self.plan.make_fqdn(name)


class Network(WorkItem):

    def _networks_response(self):
        return self.neutron.list_networks(
            name=self.plan.networks[self.name]['network_name'])

    def create(self):
        network = self.neutron.create_network(
            {'network':
             {'name': self.plan.networks[self.name]['network_name'],
              'admin_state_up': True}})
        logging.info(network)

    def display(self):
        logging.info(self._networks_response())

    def teardown(self):
        for network in self._networks_response()['networks']:
            self.neutron.delete_network(network['id'])


class SubNet(WorkItem):
    def create(self):
        network = self._networks_response(self.name)['networks'][0]
        subnet = self.neutron.create_subnet(
            body={
                'subnets': [
                    {
                        'name': self.plan.networks[self.name]['subnet_name'],
                        'cidr': self.plan.networks[self.name]['cidr'],
                        'ip_version': 4,
                        'network_id': network['id']
                    }
                ]
            })
        logging.info(subnet)

    def display(self):
        logging.info(self._subnet_response(self.name))

    def teardown(self):
        for subnet in self._subnet_response(self.name)['subnets']:
            self.neutron.delete_subnet(subnet['id'])


class Router(WorkItem):

    def create(self):
        router = self.neutron.create_router(
            body={'router': {
                'name': self.plan.networks[self.name]['router_name'],
                'admin_state_up': True,
            }})['router']
        self.neutron.add_gateway_router(
            router['id'],
            {'network_id': self._external_id()})

    def display(self):
        logging.info(self._router_response(self.name))

    def teardown(self):
        for router in self._router_response(self.name)['routers']:
            self.neutron.remove_gateway_router(router['id'])
            self.neutron.delete_router(router['id'])


class RouterInterface(WorkItem):
    def create(self):
        self.neutron.add_interface_router(
            self._router_response(self.name)['routers'][0]['id'],
            {'subnet_id': self._subnet_id(self.name)})

    def display(self):
        for router in self._router_response(self.name)['routers']:
            try:
                print (self._subnet_response(self.name)['subnets'])
            except Exception:
                pass

    def teardown(self):
        for router in self._router_response(self.name)['routers']:
            for subnet in self._subnet_response(self.name)['subnets']:
                try:
                    self.neutron.remove_interface_router(
                        router['id'], {'subnet_id': subnet['id']})
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
            logging.info(' Assigning %s to host id %s' % (float.ip, server.id))
            server.add_floating_ip(float.ip)
        except nova_exceptions.BadRequest:
            logging.info('IP assign failed. Waiting 5 seconds to try again.')
            time.sleep(5)
            server.add_floating_ip(float.ip)
        return float.ip

    def display_ip_for_server(self, server):
        logging.info(self.floating_ip_for_server(server))

    def remove_float_from_server(self, server):
        for float in self.nova.floating_ips.list():
            if float.instance_id == server.id:
                logging.info('Removing  %s from host id %s'
                             % (float.ip, server.id))
                server.remove_floating_ip(float)
                break

    def reset_ssh(self, ip_address):
        subprocess.call(['ssh-keygen', '-R', ip_address])
        attempts = 5
        while(attempts):
            try:
                subprocess.check_call(
                    ['ssh',
                     '-o', 'StrictHostKeyChecking=no',
                     '-o', 'PasswordAuthentication=no',
                     '-l', 'centos', ip_address, 'hostname'])
                attempts = 0
            except subprocess.CalledProcessError:
                logging.info(
                    'ssh to server failed.' +
                    '  Waiting 5 seconds to retry %s.' % ip_address +
                    '  Attempts left = %d', attempts)
                attempts = attempts - 1
                time.sleep(5)

    def create(self):
        server = self.get_server_by_name(self.make_fqdn(self.name))
        ip_address = self.assign_next_ip(server)
        self.reset_ssh(ip_address)

    def display(self):
        try:
            server = self.get_server_by_name(self.make_fqdn(self.name))
            self.display_ip_for_server(server)
        except IndexError:
            pass

    def teardown(self):
        server = self.get_server_by_name(self.make_fqdn(self.name))
        self.remove_float_from_server(server)


class NovaServer(WorkItem):

    # Override this if the host needs more complex userdata
    def user_data_template(self):
        return user_data_template

    def _host(self, name, user_data):

        nics = []
        for net_name in ["public", "private"]:
            for network in self._networks_response(net_name)['networks']:
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
            min_cont=1,
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
                logging.info('Host %s created' % host_id)
                return host
            except Exception:
                logging.info('.')
                pass

    #  Over ride this to create a subset of the hosts
    def host_name_list(self):
        return self.plan.host_names

    def user_data(self):
        realm = self.plan.domain_name.upper()
        data = self.user_data_template() % {
            'hostname': self.name,
            'fqdn': self.fqdn(),
            'realm': realm,
            'domain': self.plan.domain_name
        }
        return data

    def fqdn(self):
        return self.name + '.' + self.plan.domain_name

    def host_list(self):
        for host in self.nova.servers.list(search_opts={'name': self.fqdn()}):
            yield host

    def create(self):
        host = self._host(self.name, self.user_data())
        logging.info(host)

    def display(self):
        try:
            for server in self.host_list():
                logging.info(server.name)
        except Exception:
            pass

    def teardown(self):
        for server in self.host_list():
            self.nova.servers.delete(server.id)


class IPAAddress(WorkItem):
    def display_static_address(self):
        scorecard = Scorecard(self.list_servers(), self.plan)
        scorecard.display()

    def display(self):
        self.display_static_address()


class FileWorkItem(WorkItem):

    def create(self):
        if not os.path.exists(self.directory):
            os.makedirs(self.directory)
        with open(self.file_name, 'w') as f:
            self.write_contents(f)

    def display(self):
        try:
            with open(self.file_name, 'r')as f:
                read_data = f.read()
                print(read_data)

        except IOError as ioerror:
            if not os.path.exists(self.directory):
                print("Inventory Directory %s does not exist" %
                      self.directory)
                return

            if not os.path.isdir(self.directory):
                print("%s exists but is not a directory" %
                      self.directory)
                return

            if not os.path.exists(self.file_name):
                print("Inventory File %s does not exist" %
                      self.file_name)
                return

            print("Error reading inventory file")
            print(ioerror)

    def teardown(self):
        if os.path.exists(self.file_name):
            os.remove(self.file_name)


class Inventory(FileWorkItem):

    def __init__(self, session, plan):
        super(Inventory, self).__init__(session, plan, 'inventory')
        self.directory = self.plan.inventory_dir
        self.file_name = self.plan.inventory_file

    def write_contents(self, f):

        for host, vars in self.plan.hosts.iteritems():
            try:
                server = self.get_server_by_name(self.make_fqdn(host))
                ip = self.floating_ip_for_server(server)
                f.write("[%s]\n" % host)
                f.write("%s\n\n" % ip)
                f.write("[%s:vars]\n" % host)
                for key, value in vars.iteritems():
                    f.write("%s=%s\n" % (key, value))
                f.write("\n")

            except IndexError:
                pass


class WorkItemList(object):

    def __init__(self, work_item_factories, session, plan):

        self.work_items = [factory(session, plan)
                           for factory in work_item_factories]

    def create(self):
        for item in self.work_items:
            logging.info(item.__class__.__name__)
            item.create()

    def teardown(self):
        for item in reversed(self.work_items):
            logging.info(item.__class__.__name__)

            try:
                item.teardown()
            except Exception:
                pass

    def display(self):
        for item in self.work_items:
            logging.info(item.__class__.__name__)
            item.display()


def IPAFloatIP(session, plan):
    return FloatIP(session, plan, 'ipa')


def RDOFloatIP(session, plan):
        return FloatIP(session, plan, 'rdo')


def IPAServer(session, plan):
    return NovaServer(session, plan, 'ipa')


def RDOServer(session, plan):
    return NovaServer(session, plan, 'rdo')


def IPA(session, plan):
    return WorkItemList([IPAServer, IPAFloatIP], session, plan)


def RDO(session, plan):
        return WorkItemList([RDOServer, RDOFloatIP], session, plan)


def PublicNetwork(session, plan):
    return Network(session, plan, 'public')


def PrivateNetwork(session, plan):
    return Network(session, plan, 'private')


def PublicSubNet(session, plan):
    return SubNet(session, plan, 'public')


def PrivateSubNet(session, plan):
    return SubNet(session, plan, 'private')


def PublicRouter(session, plan):
    return Router(session, plan, 'public')


def PublicRouterInterface(session, plan):
    return RouterInterface(session, plan, 'public')


def PublicNetworkList(session, plan):
    return WorkItemList(
        [PublicRouter, PublicNetwork, PublicSubNet, PublicRouterInterface],
        session, plan)


def PrivateNetworkList(session, plan):
    return WorkItemList(
        [PrivateNetwork, PrivateSubNet], session, plan)

components = dict()
_auth = None
_session = None


def _create_auth():
    OS_AUTH_URL = os.environ.get('OS_AUTH_URL')
    OS_USERNAME = os.environ.get('OS_USERNAME')
    OS_PASSWORD = os.environ.get('OS_PASSWORD')
    OS_USER_DOMAIN_NAME = os.environ.get('OS_USER_DOMAIN_NAME')
    OS_PROJECT_DOMAIN_NAME = os.environ.get('OS_PROJECT_DOMAIN_NAME')
    OS_PROJECT_NAME = os.environ.get('OS_PROJECT_NAME')

    if OS_AUTH_URL is None:
        logging.error('OS_AUTH_URL not set.  Aborting.')
        sys.exit(-1)

    auth = v3.Password(auth_url=OS_AUTH_URL,
                       username=OS_USERNAME,
                       user_domain_name=OS_USER_DOMAIN_NAME,
                       password=OS_PASSWORD,
                       project_name=OS_PROJECT_NAME,
                       project_domain_name=OS_PROJECT_DOMAIN_NAME)

    return auth


def get_auth():
    if components.get(v3.Auth) is None:
        components[v3.Auth] = _create_auth()
    return components[v3.Auth]


def create_session():
        session = ksc_session.Session(auth=get_auth())
        return session


def build_work_item_list(work_item_factories):
    plan = Plan()
    session = create_session()
    return WorkItemList(work_item_factories, session, plan)

worker = build_work_item_list([
    PublicNetwork,
    IPA,
    RDO
])


workers = {
    'all': build_work_item_list([
        PrivateNetworkList, PublicNetworkList,
        IPAServer,  RDOServer, IPAFloatIP, RDOFloatIP, Inventory]),
    'rdo': build_work_item_list([RDO]),
    'ipa': build_work_item_list([IPA]),
    'network': build_work_item_list([PrivateNetworkList, PublicNetworkList]),
    'inventory': build_work_item_list([Inventory])
}


def get_args():
    parser = argparse.ArgumentParser(
        description='Display the state of the system.')
    parser.add_argument('worker', nargs='?', default='all',
                        help='Worker to execute, defaults to "all"')
    args = parser.parse_args()
    return args


def enable_logging():
    logging.basicConfig(level=logging.DEBUG)


def create(worker='all'):
    workers[worker].create()


def teardown(worker='all'):
    workers[worker].teardown()


def display(worker='all'):
    workers[worker].display()


def list():
    logging.info(json.dumps(workers.keys()))


def main():
    args_file = sys.argv[1]
    args_data = file(args_file).read()
    arguments = shlex.split(args_data)
    worker = 'all'
    action = WorkItemList.display

    for arg in arguments:
        # ignore any arguments without an equals in it
        if '=' in arg:
            (key, value) = arg.split('=')
            if key == 'worker':
                worker = workers[value]
            if key == 'action':
                if value == 'create':
                    action = WorkItemList.create
                elif value == 'teardown':
                    action = WorkItemList.teardown
                elif value == 'display':
                    action = WorkItemList.display

    logging.basicConfig(level=logging.ERROR)

    action(worker)
    print json.dumps({
        'success': True,
        'args': args_data
    })

if __name__ == '__main__':
    main()
