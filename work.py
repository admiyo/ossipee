import logging
import os
import subprocess
import time

from neutronclient.neutron import client as neutronclient
from neutronclient.common import exceptions as neutron_exceptions

from keystoneclient.v3 import client as keystone_v3
from keystoneclient.openstack.common.apiclient import exceptions
from novaclient import client as novaclient
from novaclient import exceptions as nova_exceptions

import depend


def get_server_by_name(nova, name):
    servers = nova.servers.list(
        search_opts={'name': '^' + name + '$'})
    return servers[0]


def calculate_address_for_server(server):
    ip_address = None
    for _, address in server.addresses.iteritems():
        for interface in address:
            if interface.get('OS-EXT-IPS:type', '') == 'floating':
                ip_address = interface.get('addr')
    return ip_address


def _reset_openssh(cloud_user, ip_address):
    try:
        subprocess.check_call(
            ['ssh',
             '-o', 'StrictHostKeyChecking=no',
             '-o', 'PasswordAuthentication=no',
             '-l', cloud_user,
             ip_address, 'hostname'])
        return True
    except subprocess.CalledProcessError:
        return False


def reset_ssh(cloud_user, ip_address):
    attempts = 5
    while(attempts):
        if _reset_openssh(cloud_user, ip_address):
            attempts = 0
            return
        else:
            logging.info(
                'openssh to server failed.' +
                '  Waiting 5 seconds to retry %s.' % ip_address +
                '  Attempts left = %d', attempts)
            attempts = attempts - 1
            time.sleep(5)
    raise IOError("Cannot SSH to host")


def floating_ip_for_server(server):
    for _, address in server.addresses.iteritems():
        for interface in address:
            if interface.get('OS-EXT-IPS:type', '') == 'floating':
                ip = interface['addr']
    return ip


class Network(object):
    def __init__(self, neutron, network_name):
        self.neutron = neutron
        self._network_name = network_name

    def _networks_response(self):
        return self.neutron.list_networks(name=self._network_name)

    def create(self):
        for net in self._networks_response()['networks']:
            if net['name'] == self._network_name:
                return

        network = self.neutron.create_network(
            {'network':
             {'name': self._network_name,
              'admin_state_up': True}})
        logging.info(network)

    def display(self):
        logging.info(self._networks_response())

    def teardown(self):
        for network in self._networks_response()['networks']:
            self.neutron.delete_network(network['id'])


class SubNet(object):
    def __init__(self, neutron, name, network_name, cidr, subnet_name):

        self.neutron = neutron
        self.name = name
        self._network_name = network_name
        self.cidr = cidr
        self.subnet_name = subnet_name

    def create(self):
        for net in self.neutron.list_subnets(
                name=self.subnet_name)['subnets']:
            if net['name'] == self.subnet_name:
                return

        network = self.neutron.list_networks(
            name=self._network_name)['networks'][0]
        subnet = self.neutron.create_subnet(
            body={
                'subnets': [
                    {
                        'name': self.subnet_name,
                        'cidr': self.cidr,
                        'ip_version': 4,
                        'network_id': network['id']
                    }
                ]
            })
        logging.info(subnet)

    def display(self):
        logging.info(self.neutron.list_subnets(name=self.subnet_name))

    def teardown(self):
        for subnet in self.neutron.list_subnets(
                name=self.subnet_name)['subnets']:
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


class Router(object):
    def __init__(self, neutron,  name, router_name):

        self.name = name
        self.neutron = neutron
        self.router_name = router_name

    def _router_name(self):
        return self.router_name

    def _external_id(self):
        return self.neutron.list_networks(name='external')['networks'][0]['id']

    def create(self):
        _router_name = self.router_name
        if len(self.neutron.list_routers(name=_router_name)['routers']) > 0:
            return

        router = self.neutron.create_router(
            body={'router': {
                'name': _router_name,
                'admin_state_up': True,
            }})['router']
        self.neutron.add_gateway_router(
            router['id'],
            {'network_id': self._external_id()})

    def display(self):
        _router_name = self.router_name
        logging.info(self.neutron.list_routers(name=_router_name))

    def teardown(self):
        _router_name = self.router_name
        for router in self.neutron.list_routers(name=_router_name)['routers']:
            self.neutron.remove_gateway_router(router['id'])
            self.neutron.delete_router(router['id'])


class RouterInterface(object):

    def __init__(self, neutron, name, router_name, subnet_name):
        self.name = name
        self.neutron = neutron
        self.router_name = router_name
        self.subnet_name = subnet_name

    def create(self):
        subnet_id = self.neutron.list_subnets(
            name=self.subnet_name)['subnets'][0]['id']

        if subnet_id is None:
            return
        router_response = self.neutron.list_routers(
            name=self.router_name)
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
        for router in self.neutron.list_routers(name=self.name)['routers']:
            try:
                print (self.neutron.list_subnets(
                    name=self._subnet_name())['subnets'])
            except Exception:
                pass

    def teardown(self):
        routers = self.neutron.list_routers(
            name=self.router_name)['routers']
        for router in routers:
            for subnet in self.neutron.list_subnets(
                    name=self.subnet_name)['subnets']:
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


class FloatIP(object):
    def __init__(self, nova, fqdn, cloud_user):
        self.nova = nova
        self.fqdn = fqdn
        self.cloud_user = cloud_user

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
        logging.info(floating_ip_for_server(server))

    def remove_float_from_server(self, server):
        for float in self.nova.floating_ips.list():
            if float.instance_id == server.id:
                logging.info('Removing  %s from host id %s'
                             % (float.ip, server.id))
                server.remove_floating_ip(float)
                break

    def create(self):
        server = get_server_by_name(self.nova, self.fqdn)
        for float in self.nova.floating_ips.list():
            if float.instance_id == server.id:
                return

        ip_address = self.assign_next_ip(server)
        ip_address = calculate_address_for_server(server)
        attempts = 4
        while(ip_address is None and attempts):
            logging.info(
                'Getting IP address for server failed.' +
                '  Waiting 5 seconds to retry.'
                '  Attempts left = %d', attempts)
            time.sleep(5)
            attempts -= 1
            server = get_server_by_name(self.nova, self.fqdn)
            ip_address = calculate_address_for_server(server)

        subprocess.call(['ssh-keygen', '-R', ip_address])
        reset_ssh(self.cloud_user, ip_address)

    def display(self):
        try:
            server = get_server_by_name(self.nova, self.fqdn)
            self.display_ip_for_server(server)
        except IndexError:
            pass

    def teardown(self):
        try:
            server = get_server_by_name(self.nova, self.fqdn)
            self.remove_float_from_server(server)
        except IndexError:
            pass


class SecurityGroup(object):

    def __init__(self, nova, neutron, security_groups, security_ports):
        self.nova = nova
        self.neutron = neutron
        self.security_groups = security_groups
        self.security_ports = security_ports

    def create(self):
        missing_groups = list(self.security_groups)
        for sec_group in self.nova.security_groups.list():
            if sec_group.name in missing_groups:
                missing_groups.remove(sec_group.name)

        for group_name in missing_groups:
            sec_group = self.nova.security_groups.create(
                name=group_name,
                description=group_name)
            security_ports = self.security_ports[group_name]
            for protocol, ports in security_ports.iteritems():
                for port in ports:
                    try:
                        from_port, to_port = port
                    except TypeError:
                        from_port = to_port = port

                    self.nova.security_group_rules.create(
                        sec_group.id,
                        from_port=from_port,
                        ip_protocol=protocol,
                        to_port=to_port,
                        cidr='0.0.0.0/0')
        self.display()

    def display(self):
        for sec_group in self.nova.security_groups.list():
            if sec_group.name not in self.security_groups:
                continue
            print ("group_id: %s" % sec_group.id)
            print ("group_name: %s" % sec_group.name)

            for rule in self.nova.security_groups.get(sec_group).rules:
                print (rule)

    def teardown(self):
        for sec_group in self.nova.security_groups.list():
            if sec_group.name in self.security_groups:
                self.nova.security_groups.delete(sec_group)
        self.display()


class NovaServer(object):
    def __init__(self, nova, neutron, spec):
        self.name = spec.name
        self.nova = nova
        self.neutron = neutron
        self.spec = spec

    def get_flavor_id(self, flavor_name):
        for flavor in self.nova.flavors.list():
            if flavor.name == flavor_name:
                return flavor.id

    def get_image_id(self, image_name):
        for image in self.nova.images.list():
            if image.name == image_name:
                return image.id

    def _host(self):
        if len(self.nova.servers.list(
                search_opts={'name': self.spec.fqdn})) > 0:
            return
        image_id = self.get_image_id(self.spec.image_name)
        flavor_id = self.get_flavor_id(self.spec.flavor_name)
        nics = []
        for net_name in self.spec.network_names:
            for network in self.neutron.list_networks(
                    name=net_name)['networks']:
                nics.append({'net-id': network['id']})

        response = self.nova.servers.create(
            self.spec.fqdn,
            image_id,
            flavor_id,
            security_groups=self.spec.security_groups,
            nics=nics,
            meta=None,
            files=None,
            reservation_id=None,
            min_cont=1,
            max_count=1,
            userdata=self.spec.user_data,
            key_name=self.spec.keypair_name or self.nova.keypairs.list()[0].id,
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

    def host_list(self):
        for host in self.nova.servers.list(
                search_opts={'name': self.spec.fqdn}):
            yield host

    def create(self):
        host = self._host()
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


class HostsEntries(object):

    def __init__(self, resolver, nova, hosts, cloud_user, domain_name):
        self.nova = nova
        self.host_file = '/etc/hosts'
        self. hosts = hosts
        self.cloud_user = cloud_user
        self.domain_name = domain_name

    def fetch_float_ip_from_server(self, host):
        server = get_server_by_name(self.nova, host.fqdn)
        return floating_ip_for_server(server)

    def create(self):
        self.teardown()
        for host in self.hosts:
            ip = self.fetch_float_ip_from_server(host)
            command = "$ a %s %s.%s" % (ip, host.name, self.domain_name)
            process = subprocess.Popen(
                ['sudo', 'sed', '-i', command, self.host_file],
                stdout=subprocess.PIPE)
            out, err = process.communicate()
            fqdn = host.fqdn
            subprocess.call(['ssh-keygen', '-R', fqdn])
            reset_ssh(self.cloud_user, fqdn)
        self.display()

    def display(self):
        process = subprocess.Popen(['grep',
                                    '-e',
                                    "%s$" % self.domain_name,
                                    self.host_file],
                                   stdout=subprocess.PIPE)
        out, err = process.communicate()
        print(out)

    def teardown(self):
        command = "/%s$/ d" % self.domain_name

        process = subprocess.Popen(
            ['sudo', 'sed', '-i', command, self.host_file],
            stdout=subprocess.PIPE)
        out, err = process.communicate()
        self.display()


class AllServers(object):

    def __init__(self, nova, domain_name, servers, float_ips):
        self.nova = nova
        self.domain_name = domain_name
        self.servers = servers
        self.float_ips = float_ips

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

    def list_servers(self):
        return self.nova.servers.list(
            search_opts={'name': self.domain_name + '$'})

    def wait_for_destruction(self, host_id):
        attempts = 5
        while True:
            try:
                host = self.nova.servers.get(host_id)
                attempts = attempts - 1
                if attempts > 0:
                    logging.info(
                        'Teardown of host not completed. ' +
                        'Waiting 5 second to check again.' +
                        'Remaining attempts = %d' % attempts)
                    time.sleep(5)
                else:
                    logging.info('Teardown of host not completed.')
                    break
            except Exception:
                return


class FileWorkItem(object):

    def __init__(self, file_name):
        self.file_name = file_name

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

    def __init__(self, nova, inventory_file, directory, hosts, ipa_vars):
        super(Inventory, self).__init__(inventory_file)

        self.nova = nova
        self.directory = directory
        self.hosts = hosts
        self.ipa_vars = ipa_vars

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
        ipa_server = get_server_by_name(self.nova, self.hosts['ipa'].fqdn)
        nameserver = self._get_nameserver_address(ipa_server)
        ipa_clients = []
        for host, vars in self.hosts.iteritems():
            try:
                server = get_server_by_name(self.nova, vars.fqdn)
                ip = calculate_address_for_server(server)
                f.write('[%s]\n' % host)
                f.write('%s\n\n' % vars.fqdn)
                f.write('[%s:vars]\n' % host)
                for key, value in vars.client_vars.iteritems():
                    f.write('%s=%s\n' % (key, value))
                f.write('%s=%s\n' % ('nameserver',  nameserver))
                f.write('\n')

                if not host == 'ipa':
                    ipa_clients.append(vars.fqdn)
            except IndexError:
                pass

        f.write('[ipa_clients]\n')
        for fqdn in ipa_clients:
            f.write('%s\n' % fqdn)

        f.write('[ipa_clients:vars]\n')

        for key, value in self.ipa_vars.iteritems():
            f.write('%s=%s\n' % (key, value))


class AnsiblePlaybook(object):

    def __init__(self, inventory_file, ansible_playbook):
        self.inventory_file = inventory_file
        self.ansible_playbook = ansible_playbook

    def create(self):

        process = subprocess.call(
            ['ansible-playbook', '-i', self.inventory_file,
             self.ansible_playbook])

    def display(self):
        pass

    def teardown(self):
        pass
