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
from neutronclient.common import exceptions as neutron_exceptions
from novaclient import client as novaclient
from novaclient import exceptions as nova_exceptions


user_data_template = '''
#cloud-config
hostname: %(fqdn)s
fqdn:  %(fqdn)s

'''

# TODO(ayoung): These should be in the config file
CLOUD_AUTH_URLS = {
    'http://controller.oslab.openstack.engineering.redhat.com:5000/v3':
    'oslab',
    'http://control.os1.phx2.redhat.com:5000/v3/': 'os1',
    'https://keystone.dream.io/v3': 'dreamcompute'
}


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
        self.config.set(self.section, 'forwarder',  self.forwarder)
        self.config.set(self.section, 'public_network', self.public_network)
        self.config.set(self.section, 'private_network', self.private_network)

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

        self.security_ports = {
            'openstack':{
                'tcp': [
                    22,  # SSH
                    80, 443,  # Horizon
                    5000, 35357,  # Keystone
                    9191, 9292,  # Glance
                    8773, 8774, 8775, 3333, 6080, 5800, 5900,  # Nova
                    8776,  # Cinder
            ]},
            'ipa': {
                'tcp':[
                    22,  # SSH
                    80, 443,  # HTTP
                    389, 686,  # LDAP
                    88, 464,  # Kerberos, kpasswd
                    53,  # DNS
                    123,  # NTP,
                ],
                'udp':[]
            }
        }

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

    @property
    def public_network(self):
        return self.config.getboolean(self.section, 'public_network')

    @property
    def private_network(self):
        return self.config.getboolean(self.section, 'private_network')


class Plan(object):

    def __init__(self, configuration, session):
        self.configuration = configuration

        name = self.configuration.name
        self.name = self.configuration.name
        self.forwarder = self.configuration.forwarder
        self.security_groups = []
        self.security_ports = {}

        for group, ports in self.configuration.security_ports.iteritems():
            sec_group = "%s-%s" % (name, group)
            self.security_groups.append(sec_group)
            self.security_ports[sec_group] = ports

        self.key = self.configuration.key
        self.profile = self.configuration.profile
        self.cloud = CLOUD_AUTH_URLS.get(session.auth.auth_url, 'unknown')

        self.domain_name = name + '.' + self.cloud + '.test'
        self.deployments_dir = self.configuration.config_dir + '/deployments'
        self.deployment_dir = (self.deployments_dir +
                               '/' + name + '.' + self.cloud)
        self.inventory_file = self.deployment_dir + '/inventory.ini'

        self.networks = dict()
        cidr_template = '192.168.%d.0/24'

        if configuration.public_network:
            self.networks['public'] = {
                'components': [Router, Network, SubNet, RouterInterface],
                'cidr': cidr_template % 52
            }
        if configuration.private_network:
            self.networks['private'] = {
                'components': [Network, SubNet],
                'cidr': cidr_template % 78
            }

        self.ipa_client_vars = self._get_client_vars()
        self.hosts = {}

    def _get_client_vars(self):
        return {
            'deployment_dir': self.deployment_dir,
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
        self.hosts[name]['security_group'] = "%s-%s" % (self.name, name)


class WorkItem(object):

    def _router_name(self):
        return self.plan.name + '-' + self.name + '-router'

    def _subnet_name(self):
        return self.plan.name + '-' + self.name + '-subnet'

    def build_network_name(self, key):
        return self.plan.name + '-' + key + '-net'

    def _network_name(self):
        return self.build_network_name(self.name)

    def _external_id(self):
        return self.neutron.list_networks(name='external')['networks'][0]['id']

    def _router_response(self, router_name):
        return self.neutron.list_routers(name=router_name)

    def _networks_response(self, network_name):
        return self.neutron.list_networks(name=network_name)

    def _subnet_response(self, subnet_name):
        return self.neutron.list_subnets(name=subnet_name)

    def _subnet_id(self, which):
        return self._subnet_response(self._subnet_name())['subnets'][0]['id']

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
        for _, address in server.addresses.iteritems():
            for interface in address:
                if interface.get('OS-EXT-IPS:type', '') == 'floating':
                    ip = interface['addr']
        return ip

    def calculate_address_for_server(self, server):
        ip_address = None
        for _, address in server.addresses.iteritems():
            for interface in address:
                if interface.get('OS-EXT-IPS:type', '') == 'floating':
                    ip_address = interface.get('addr')
        return ip_address

    def build_security_group_name(self, key):
        return "%s-%s" % (key, self.name)

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
        return self.neutron.list_networks(name=self._network_name())

    def create(self):
        for net in self._networks_response()['networks']:
            if net['name'] == self._network_name():
                return

        network = self.neutron.create_network(
            {'network':
             {'name': self._network_name(),
              'admin_state_up': True}})
        logging.info(network)

    def display(self):
        logging.info(self._networks_response())

    def teardown(self):
        for network in self._networks_response()['networks']:
            self.neutron.delete_network(network['id'])


class SubNet(WorkItem):

    def create(self):
        for net in self._subnet_response(self._subnet_name())['subnets']:
            if net['name'] == self._subnet_name():
                return

        network = self._networks_response(self._network_name())['networks'][0]
        subnet = self.neutron.create_subnet(
            body={
                'subnets': [
                    {
                        'name': self._subnet_name(),
                        'cidr': self.plan.networks[self.name]['cidr'],
                        'ip_version': 4,
                        'network_id': network['id']
                    }
                ]
            })
        logging.info(subnet)

    def display(self):
        logging.info(self._subnet_response(self._subnet_name()))

    def teardown(self):
        for subnet in self._subnet_response(self._subnet_name())['subnets']:
            attempts = 2
            while (attempts):
                try:
                    self.neutron.delete_subnet(subnet['id'])
                    attempts = 0
                except neutron_exceptions.Conflict:
                    logging.info(
                        'teardown of subnet failed.' +
                        '  Waiting 5 seconds to retry.' +
                        '  Attempts left = %d', attempts)
                    attempts = attempts - 1
                    time.sleep(5)
                except neutron_exceptions.NotFound:
                    pass


class Router(WorkItem):

    def create(self):

        if len(self._router_response(self._router_name())['routers']) > 0:
            return

        router = self.neutron.create_router(
            body={'router': {
                'name': self._router_name(),
                'admin_state_up': True,
            }})['router']
        self.neutron.add_gateway_router(
            router['id'],
            {'network_id': self._external_id()})

    def display(self):
        logging.info(self._router_response(self._router_name()))

    def teardown(self):
        for router in self._router_response(self._router_name())['routers']:
            self.neutron.remove_gateway_router(router['id'])
            self.neutron.delete_router(router['id'])


class RouterInterface(WorkItem):

    def create(self):
        subnet_id = self._subnet_id(self.name)
        if subnet_id is None:
            return
        router_response = self._router_response(
            self._router_name())
        router_id = router_response['routers'][0]['id']
        if router_id is None:
            return
        try:
            self.neutron.add_interface_router(
                router_id,
                {'subnet_id': subnet_id})
        except neutron_exceptions.BadRequest:
            logging.warn('interface_router (probably) already exists')
        except exceptions.BadRequest:
            logging.warn('interface_router (probably) already exists')

    def display(self):
        for router in self._router_response(self.name)['routers']:
            try:
                print (self._subnet_response(self._subnet_name())['subnets'])
            except Exception:
                pass

    def teardown(self):
        routers = self._router_response(self._router_name())['routers']
        for router in routers:
            for subnet in self._subnet_response(
                    self._subnet_name())['subnets']:
                attempts = 5
                while attempts:
                    attempts = attempts - 1
                    try:
                        self.neutron.remove_interface_router(
                            router['id'], {'subnet_id': subnet['id']})
                        attempts = 0
                    except neutron_exceptions.Conflict as e:
                        if attempts == 0:
                            raise e
                        logging.info(
                            'Teardown of interface_router failed.' +
                            '  Waiting 5 seconds to retry.'
                            '  Attempts left = %d', attempts)
                        time.sleep(5)


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

    def create(self):

        fqdn = self.make_fqdn(self.name)
        server = self.get_server_by_name(fqdn)
        for float in self.nova.floating_ips.list():
            if float.instance_id == server.id:
                return

        server = self.get_server_by_name(fqdn)
        ip_address = self.assign_next_ip(server)
        ip_address = self.calculate_address_for_server(server)
        attempts = 4
        while(ip_address is None and attempts):
            logging.info(
                'Getting IP address for server failed.' +
                '  Waiting 5 seconds to retry.'
                '  Attempts left = %d', attempts)
            time.sleep(5)
            attempts -= 1
            server = self.get_server_by_name(self.make_fqdn(self.name))
            ip_address = self.calculate_address_for_server(server)

        subprocess.call(['ssh-keygen', '-R', ip_address])
        self.reset_ssh(ip_address)

    def display(self):
        try:
            server = self.get_server_by_name(self.make_fqdn(self.name))
            self.display_ip_for_server(server)
        except IndexError:
            pass

    def teardown(self):
        try:
            server = self.get_server_by_name(self.make_fqdn(self.name))
            self.remove_float_from_server(server)
        except IndexError:
            pass


class SecurityGroup(WorkItem):

    def __init__(self, session, plan):
        super(SecurityGroup, self).__init__(session, plan, 'SecurityGroup')

    def create(self):
        missing_groups = list(self.plan.security_groups)
        for sec_group in self.nova.security_groups.list():
            if sec_group.name in self.plan.security_groups:
                missing_groups.remove(sec_group.name)

        for group_name in missing_groups:
            sec_group = self.nova.security_groups.create(
                name=group_name,
                description=group_name)
            security_ports = self.plan.security_ports[group_name]
            for protocol, ports in security_ports.iteritems():
                for port in ports:
                    self.nova.security_group_rules.create(
                        sec_group.id,
                        from_port=port,
                        ip_protocol=protocol,
                        to_port=port,
                        cidr='0.0.0.0/0')
        self.display()

    def display(self):
        for sec_group in self.nova.security_groups.list():
            if sec_group.name not in self.plan.security_groups:
                continue
            print ("group_id: %s" % sec_group.id)
            print ("group_name: %s" % sec_group.name)

            for rule in self.nova.security_groups.get(sec_group).rules:
                print (rule)

    def teardown(self):
        for sec_group in self.nova.security_groups.list():
            if sec_group.name in self.plan.security_groups:
                self.nova.security_groups.delete(sec_group)
        self.display()


class NovaServer(WorkItem):

    # Override this if the host needs more complex userdata
    def user_data_template(self):
        return user_data_template

    def _pubkey(self):
        return self.nova.keypairs.list()[0].id

    def _host(self, name, user_data):
        if len(self.nova.servers.list(search_opts={'name': self.fqdn()})) > 0:
            return

        nics = []
        for net_name in self.plan.networks.keys():
            for network in self._networks_response(
                    self.build_network_name(net_name))['networks']:
                nics.append({'net-id': network['id']})

        security_groups = [self.plan.hosts[name]['security_group']]
        response = self.nova.servers.create(
            self.fqdn(),
            self.get_image_id(self.plan.profile['image']),
            self.get_flavor_id(self.plan.profile['flavor']),
            security_groups=security_groups,
            nics=nics,
            meta=None,
            files=None,
            reservation_id=None,
            min_cont=1,
            max_count=1,
            userdata=user_data,
            key_name=self._pubkey(),
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


class HostsEntries(WorkItem):

    def __init__(self, session, plan):
        super(HostsEntries, self).__init__(session, plan, 'hosts')
        self.host_file = '/etc/hosts'

    def fetch_float_ip_from_server(self, server_name):
        server = self.get_server_by_name(self.make_fqdn(server_name))
        return self.floating_ip_for_server(server)

    def create(self):
        self.teardown()
        for host in self.plan.hosts:
            ip = self.fetch_float_ip_from_server(host)
            command = "$ a %s %s.%s" % (ip, host, self.plan.domain_name)
            process = subprocess.Popen(
                ['sudo', 'sed', '-i', command, self.host_file],

                stdout=subprocess.PIPE)
            out, err = process.communicate()

            fqdn = self.make_fqdn(host)
            subprocess.call(['ssh-keygen', '-R', fqdn])
            self.reset_ssh(fqdn)

        self.display()

    def display(self):
        process = subprocess.Popen(['grep',
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
        self.float_ips.teardown()
        for server in self.list_servers():
            try:
                self.nova.servers.delete(server.id)
            except nova_exceptions.NotFound:
                # Race condition.  If its gone, it is safe
                # to progress.
                pass
        for server in self.list_servers():
            self.wait_for_destruction(server.id)


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
        self.directory = self.plan.deployment_dir
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
                fqdn = self.make_fqdn(host)
                f.write('[%s]\n' % host)
                f.write('%s\n\n' % fqdn)
                f.write('[%s:vars]\n' % host)
                for key, value in vars.iteritems():
                    f.write('%s=%s\n' % (key, value))
                f.write('%s=%s\n' % ('nameserver',  nameserver))
                f.write('\n')

                if not host == 'ipa':
                    ipa_clients.append(fqdn)
            except IndexError:
                pass

        f.write('[ipa_clients]\n')
        for fqdn in ipa_clients:
            f.write('%s\n' % fqdn)

        f.write('[ipa_clients:vars]\n')

        for key, value in self.plan.ipa_client_vars.iteritems():
            f.write('%s=%s\n' % (key, value))


class Rippowam(WorkItem):

    def create(self):
        process = subprocess.call(
            ['ansible-playbook', '-i',
             self.plan.inventory_file,
             os.getenv('HOME') + '/devel/rippowam/site.yml'])

    def display(self):
        pass

    def teardown(self):
        pass


class WorkItemList(object):

    def __init__(self, work_items, session, plan, factories=True):
        if factories:
            self.work_items = [factory(session, plan)
                               for factory in work_items]
        else:
            self.work_items = work_items

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


def network_components(session, plan, name):
    work_items = [component(session, plan, name)
                  for component in plan.networks[name]['components']]
    return WorkItemList(work_items, session, plan, False)


def all_networks(session, plan):
    return WorkItemList([network_components(session, plan, network)
                         for network in plan.networks.keys()],
                        session, plan, False)


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
            self._plan = Plan(self.configuration, self.session)
            for host in ['ipa', 'openstack']:
                self._plan.add_host(host)

        return self._plan

    def build_work_item_list(self, items):
        return WorkItemList(items, self.session, self.plan)


class WorkerApplication(Application):

    description = 'Display the state of the system.'

    worker_class = {
        'all': [all_networks, SecurityGroup,
                AllServers, HostsEntries, Inventory],
        'servers': [AllServers, HostsEntries, Inventory],
        'controller': [
            lambda session, plan: NovaServer(session, plan, 'controller'),
            lambda session, plan: FloatIP(session, plan, 'controller'),
            HostsEntries,
            Inventory
        ],
        'ipa': [
            lambda session, plan: NovaServer(session, plan, 'ipa'),
            lambda session, plan: FloatIP(session, plan, 'ipa'),
            HostsEntries,
            Inventory
        ],
        'openstack': [
            lambda session, plan: NovaServer(session, plan, 'openstack'),
            lambda session, plan: FloatIP(session, plan, 'openstack'),
            HostsEntries,
            Inventory
        ],
        'network': [all_networks],
        'inventory': [Inventory],
        'rippowam': [
            lambda session, plan: Rippowam(session, plan, 'controller')
        ],
        'security_group': [SecurityGroup],
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
