#!/usr/bin/python

import argparse
import json
import logging
import os
import shlex
import six
import subprocess
import sys
import time

import ConfigParser

from keystoneclient import auth as ksc_auth
from keystoneclient import session as ksc_session
from keystoneclient.openstack.common.apiclient import exceptions
from keystoneclient.v3 import client as keystone_v3
from neutronclient.neutron import client as neutronclient
from novaclient import client as novaclient
from novaclient import exceptions as nova_exceptions


user_data_template = '''
#cloud-config
hostname: %(fqdn)s
fqdn:  %(fqdn)s

'''


class Configuration(object):

    config_dir = os.environ.get('HOME', '/tmp') + "/.ossipee"
    config_file = config_dir + "/config.ini"
    profile_file = config_dir + "/profiles.ini"

    default_profiles = {
        'centos7': {
            'cloud_user': 'centos',
            'image': 'centos-7-cloud',
            'flavor': 'm1.medium',
        },
        'rhel7': {
            'cloud_user': 'cloud-user',
            'image': 'rhel-guest-image-7.1-20150224.0',
            'flavor': 'm1.medium',
        },
        'os1rhel7': {
            'cloud_user': 'cloud-user',
            'image': '_OS1_rhel-guest-image-7.1-20150224.0.x86_64.qcow2',
            'flavor': 'm1.medium',
        },

        'rhel6': {
            'cloud_user': 'cloud-user',
            'image': 'rhel-6.6-latest',
            'flavor': 'm1.medium',
        },
        'f22': {
            'cloud_user': 'fedora',
            'image': 'Fedora 22 Cloud Image',
            'flavor': 'm1.medium',
        }
    }

    PROFILE_VARS = ['cloud_user', 'image', 'flavor']

    def _default_config_options(self):
        self.config.add_section(self.section)
        self.config.set(self.section, 'profile', self.profile)
        self.config.set(self.section, 'name', self.name)
        self.config.set(self.section, 'pubkey', self.key)
        self.config.set(self.section, 'forwarder',  self.forwarder)

        logging.warning("Writing new config section %s to %s",
                        self.section,
                        self.config_file)

        with open(self.config_file, 'w') as f:
            self.config.write(f)

    def _default_profile_options(self):
        for profile, details in six.iteritems(self.default_profiles):
            self.profiles.add_section(profile)
            for k, v in six.iteritems(details):
                self.profiles.set(profile, k, v)

        logging.warn("Wrote profiles file at %s" % self.profile_file)

        with open(self.profile_file, 'w') as f:
            self.profiles.write(f)

    def __init__(self, section):
        self.section = section
        self.config = ConfigParser.SafeConfigParser()
        self.profiles = ConfigParser.SafeConfigParser()

        if not os.path.exists(self.config_dir):
            os.makedirs(self.config_dir)

        if os.path.exists(self.profile_file):
            self.profiles.read(self.profile_file)
        else:
            self._default_profile_options()

        if not os.path.exists(self.config_file):
            self._default_config_options()
            logging.error("Config file created. Please edit this with the "
                          "appropriate options and then run again.")
            exit(1)

        self.config.read(self.config_file)

        if not self.config.has_section(self.section):
            self._default_config_options()

        self.security_groups = ['default']

    def get(self, name, default=None):
        try:
            return self.config.get(self.section, name)
        except ConfigParser.NoOptionError:
            logging.debug("Option %s not in config file, using default: %s",
                          name,
                          default)

            return default

    @property
    def profile(self):
        profile = self.get('profile', 'rhel7')

        if not self.profiles.has_section(profile):
            logging.error("Unknown profile type: %s. This is not in your "
                          "profiles file at %s", profile, self.profile_file)
            exit(1)

        missing = [v for v in self.PROFILE_VARS
                   if not self.profiles.has_option(profile, v)]

        if missing:
            logging.error("Missing parameters %s in profile %s definition in "
                          "%s. It must contain at least %s",
                          ", ".join(missing),
                          profile,
                          self.profile_file,
                          ", ".join(self.PROFILE_VARS))
            exit(1)

        return dict(self.profiles.items(profile))

    @property
    def name(self):
        return self.get('name', os.environ.get('USER', 'rdo'))

    @property
    def key(self):
        return self.get('pubkey', self.name + '-pubkey')

    @property
    def forwarder(self):
        return self.get('forwarder', '192.168.52.3')


class Plan(object):

    def __init__(self, configuration):
        self.configuration = configuration

        name = self.configuration.name
        self.name = self.configuration.name
        self.forwarder = self.configuration.forwarder
        self.security_groups = self.configuration.security_groups
        self.key = self.configuration.key
        self.profile = self.configuration.profile

        self.domain_name = name + '.test'
        self.inventory_dir = self.configuration.config_dir + '/inventory/'
        self.inventory_file = self.inventory_dir + name + '.ini'

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
        self.ipa_client_vars = self._get_client_vars()
        self.hosts = {}

    def _get_client_vars(self):
        return {
            'cloud_user': self.profile['cloud_user'],
            'ipa_forwarder': self.forwarder,
            'ipa_domain': self.domain_name,
            'ipa_realm': self.domain_name.upper(),
            'ipa_server_password': 'FreeIPA4All',
            'ipa_admin_user_password': 'FreeIPA4All'
        }

    def make_fqdn(self, name):
        return name + '.' + self.domain_name

    def add_host(self, name):
        if self.hosts.get(name):
            print ('host %s already exists.' % name)
            return
        self.hosts[name] = self._get_client_vars()


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

    def calculate_address_for_server(self, server):
        ip_address = None
        for _, address in server.addresses.iteritems():
            for interface in address:
                if interface.get('OS-EXT-IPS:type', '') == 'floating':
                    ip_address = interface.get('addr')
        return ip_address

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
        for net in self._networks_response()['networks']:
            if net['name'] == self.plan.networks[self.name]['network_name']:
                return

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
        for net in self._subnet_response(self.name)['subnets']:
            if net['name'] == self.plan.networks[self.name]['subnet_name']:
                return

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
        if len(self._router_response(self.name)['routers']) > 0:
            return

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
        subnet_id = self._subnet_id(self.name)
        if subnet_id is None:
            return
        router_id = self._router_response(self.name)['routers'][0]['id']
        if router_id is None:
            return
        try:
            self.neutron.add_interface_router(
                router_id,
                {'subnet_id': subnet_id})
        except exceptions.BadRequest:
            logging.warn('interface_router (probably) already exists')

    def display(self):
        for router in self._router_response(self.name)['routers']:
            try:
                print (self._subnet_response(self.name)['subnets'])
            except Exception:
                pass

    def teardown(self):
        try:
            for router in self._router_response(self.name)['routers']:
                for subnet in self._subnet_response(self.name)['subnets']:
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
        except AttributeError:
            # if floating IPs are auto assigned, there will
            # be none listed
            return None
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
        attempts = 5
        while(attempts):
            try:
                subprocess.check_call(
                    ['ssh',
                     '-o', 'StrictHostKeyChecking=no',
                     '-o', 'PasswordAuthentication=no',
                     '-l', self.plan.profile['cloud_user'],
                     ip_address, 'hostname'])
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
        for float in self.nova.floating_ips.list():
            if float.instance_id == server.id:
                return

        fqdn = self.make_fqdn(self.name)
        server = self.get_server_by_name(fqdn)
        ip_address = self.assign_next_ip(server)
        ip_address = self.calculate_address_for_server(server)
        attempts = 4
        while(ip_address is None and attempts):
            logging.info(
                'Getting IP address for sever failed.' +
                '  Waiting 5 seconds to retry.'
                '  Attempts left = %d', attempts)
            time.sleep(5)
            attempts -= 1
            server = self.get_server_by_name(self.make_fqdn(self.name))
            ip_address = self.calculate_address_for_server(server)

        subprocess.call(['ssh-keygen', '-R', fqdn])
        subprocess.call(['ssh-keygen', '-R', ip_address])
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
        if len(self.nova.servers.list(search_opts={'name': self.fqdn()})) > 0:
            return

        nics = []
        try:
            for net_name in ['public', 'private']:
                for network in self._networks_response(net_name)['networks']:
                    nics.append({'net-id': network['id']})
        except exceptions.EndpointNotFound:
            # HACK to get OS1 to work
            nics.append({'net-id': 'f975ca87-2bff-4230-b6ad-5d9ec93749e1'})

        response = self.nova.servers.create(
            self.fqdn(),
            self.get_image_id(self.plan.profile['image']),
            self.get_flavor_id(self.plan.profile['flavor']),
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

    def wait_for_destruction(self, host_id):
        attempts = 5
        while attempts > 0:
            try:
                host = self.nova.servers.get(host_id)
                attempts = attempts - 1
                logging.info(
                    'Teardown of host not completed. ' +
                    'Waiting 5 second to check again.' +
                    'Remaining attempts = %d' % attempts)
                time.sleep(5)
            except Exception:
                break

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


class HostsEntries(WorkItem):

    def __init__(self, session, plan):
        super(HostsEntries, self).__init__(session, plan, 'hosts')
        self.host_file = '/etc/hosts'

    def fetch_float_ip_from_server(self, server_name):
        server = self.get_server_by_name(self.make_fqdn(server_name))
        ip = self.floating_ip_for_server(server)
        return ip

    def create(self):
        self.teardown()
        for host in self.plan.hosts:
            ip = self.fetch_float_ip_from_server(host)
            command = "$ a %s %s.%s" % (ip, host, self.plan.domain_name)
            process = subprocess.Popen(
                ['sudo', 'sed', '-i', command, self.host_file],

                stdout=subprocess.PIPE)
            out, err = process.communicate()
        self.display()

    def display(self):
        process = subprocess.Popen(['sudo',
                                    'grep',
                                    '-e',
                                    "%s$" % self.plan.domain_name,
                                    self.host_file],
                                   stdout=subprocess.PIPE)
        out, err = process.communicate()
        print(out)

    def teardown(self):
        command = "/%s$/ d" % self.plan.domain_name

        process = subprocess.Popen(
            ['sudo', 'sed', '-i', command, self.host_file],
            stdout=subprocess.PIPE)
        out, err = process.communicate()
        self.display()


class AllServers(WorkItem):

    def __init__(self, session, plan):
        super(AllServers, self).__init__(session, plan, 'AllServers')
        self.servers = WorkItemList([], session, plan)
        self.servers.work_items = [NovaServer(session, plan, server_name)
                                   for server_name in plan.hosts]
        self.float_ips = WorkItemList([], session, plan)
        self.float_ips.work_items = [FloatIP(session, plan,  server_name)
                                     for server_name in plan.hosts]

    def create(self):
        self.servers.create()
        self.float_ips.create()

    def display(self):
        self.servers.display()
        self.float_ips.display()

    def teardown(self):
        for server in self.list_servers():
            self.nova.servers.delete(server.id)


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
                print('Directory %s does not exist' %
                      self.directory)
                return

            if not os.path.isdir(self.directory):
                print('%s exists but is not a directory' %
                      self.directory)
                return

            if not os.path.exists(self.file_name):
                print('File %s does not exist' %
                      self.file_name)
                return

            print('Error reading file')
            print(ioerror)

    def teardown(self):
        if os.path.exists(self.file_name):
            os.remove(self.file_name)


class Inventory(FileWorkItem):

    def __init__(self, session, plan):
        super(Inventory, self).__init__(session, plan, 'inventory')
        self.directory = self.plan.inventory_dir
        self.file_name = self.plan.inventory_file

    def _get_nameserver_address(self, ipa_server):
        # The nameserver should be the fixed IP on the public network.
        nameserver = None
        for _, address in ipa_server.addresses.iteritems():
            for interface in address:
                if interface.get('OS-EXT-IPS:type', '') == 'floating':
                    ip_address = interface.get('addr')
                    for interface in address:
                        if interface.get('OS-EXT-IPS:type', '') == 'fixed':
                            nameserver = interface['addr']
        return nameserver

    def write_contents(self, f):
        ipa_server = self.get_server_by_name(self.make_fqdn('ipa'))
        nameserver = self._get_nameserver_address(ipa_server)
        ipa_clients = []
        for host, vars in self.plan.hosts.iteritems():
            try:
                server = self.get_server_by_name(self.make_fqdn(host))
                ip = self.calculate_address_for_server(server)
                f.write('[%s]\n' % host)
                f.write('%s\n\n' % ip)
                f.write('[%s:vars]\n' % host)
                for key, value in vars.iteritems():
                    f.write('%s=%s\n' % (key, value))
                f.write('%s=%s\n' % ('nameserver',  nameserver))
                f.write('\n')

                if not host == 'ipa':
                    ipa_clients.append(ip)
            except IndexError:
                pass

        f.write('[ipa_clients]\n')
        for ip in ipa_clients:
            f.write('%s\n' % ip)

        f.write('[%ipa_clients:vars]\n')

        for key, value in self.plan.ipa_client_vars.iteritems():
            f.write('%s=%s\n' % (key, value))


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
            except exceptions.Conflict:
                logging.info(
                    'Teardown of work item failed. ' +
                    'Waiting 1 second to try again.')
                time.sleep(1)
                item.teardown()

    def display(self):
        for item in self.work_items:
            logging.info(item.__class__.__name__)
            item.display()


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


class AllNetworks(WorkItem):

    def __init__(self, session, plan):
        super(AllServers, self).__init__(session, plan, 'AllServers')
        self.public = PublicNetworkList(session, plan)
        self.private = PrivateNetworkList(session, plan)

    def create(self):
        self.servers.create()
        self.float_ips.create()

    def display(self):
        self.servers.display()
        self.float_ips.display()

    def teardown(self):
        for server in self.list_servers():
            self.nova.servers.delete(server.id)


def enable_logging():
    logging.basicConfig(level=logging.DEBUG)


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


class Application(object):

    description = ''

    def __init__(self, description=None):
        self._session = None
        self._args = None
        self._plan = None
        self._configuration = None

        if description:
            self.description = description

    @property
    def session(self):
        if not self._session:
            auth_plugin = ksc_auth.load_from_argparse_arguments(self.args)
            try:
                if not auth_plugin.auth_url:
                    logging.error('OS_AUTH_URL not set.  Aborting.')
                    sys.exit(-1)
            except AttributeError:
                pass

            self._session = ksc_session.Session.load_from_cli_options(
                self.args,
                auth=auth_plugin)

        return self._session

    def get_parser(self):
        parser = argparse.ArgumentParser(description=self.description)
        ksc_session.Session.register_cli_options(parser)
        ksc_auth.register_argparse_arguments(parser,
                                             sys.argv,
                                             default='v3password')
        parser.add_argument('-s', '--section',
                            dest='section',
                            default='scope')
        return parser

    @property
    def args(self):
        if not self._args:
            self._args = self.get_parser().parse_args()

        return self._args

    @property
    def configuration(self):
        if not self._configuration:
            self._configuration = Configuration(self.args.section)

        return self._configuration

    @property
    def plan(self):
        if not self._plan:
            self._plan = Plan(self.configuration)
            for host in ['ipa', 'openstack']:
                self._plan.add_host(host)

        return self._plan

    def build_work_item_list(self, items):
        return WorkItemList(items, self.session, self.plan)


class WorkerApplication(Application):

    description = 'Display the state of the system.'

    worker_class = {
        'all': [PrivateNetworkList, PublicNetworkList, AllServers, Inventory],
        'servers': [AllServers, Inventory],
        'controller': [
            lambda session, plan: NovaServer(session, plan, 'controller'),
            lambda session, plan: FloatIP(session, plan, 'controller'),
            Inventory
        ],
        'ipa': [
            lambda session, plan: NovaServer(session, plan, 'ipa'),
            lambda session, plan: FloatIP(session, plan, 'ipa'),
            Inventory
        ],
        'openstack': [
            lambda session, plan: NovaServer(session, plan, 'openstack'),
            lambda session, plan: FloatIP(session, plan, 'openstack'),
            Inventory
        ],
        'network': [PrivateNetworkList, PublicNetworkList],
        'inventory': [Inventory],
        'hosts_entries': [HostsEntries]
    }

    def get_parser(self):
        parser = super(WorkerApplication, self).get_parser()
        parser.add_argument('worker', nargs='?', default='all',
                            help='Worker to execute, defaults to "all"')
        return parser

    @property
    def worker(self):
        return self.args.worker

    def __getitem__(self, item):
        return self.build_work_item_list(self.worker_class[item])

    def __len__(self):
        return len(self.worker_class)

    def __iter__(self):
        return iter(self.worker_class)

    def create(self, *args, **kwargs):
        return self[self.worker].create(*args, **kwargs)

    def teardown(self, *args, **kwargs):
        return self[self.worker].teardown(*args, **kwargs)

    def display(self, *args, **kwargs):
        return self[self.worker].display(*args, **kwargs)


if __name__ == '__main__':
    main()

    def ipa_resolver(self):
        return self.hosts[self.plan.make_fqdn('ipa')]['fixed']

    def display(self):
        logging.info('ipa resolver = ' + self.ipa_resolver())
        for host in self.hosts:
            logging.info(host)
            logging.info(self.hosts[host])
