#!/usr/bin/python

import argparse
import gi
import json
import logging
import re
import shlex
import six
import sys

gi.require_version('GnomeKeyring', '1.0')

from keystoneclient import auth as ksc_auth
from keystoneclient import session as ksc_session
from novaclient import client as novaclient
from neutronclient.neutron import client as neutronclient

import depend
import planning
import work


def network_factory(resolver, name):
    neutron = resolver.resolve(neutronclient.Client)
    plan = resolver.resolve(planning.Plan)
    network_name = plan.build_network_name(name)
    return work.Network(neutron, network_name)


def subnet_factory(resolver, name):
    neutron = resolver.resolve(neutronclient.Client)
    plan = resolver.resolve(planning.Plan)
    network_name = plan.build_network_name(name)
    cidr = plan.networks[name]['cidr']
    subnet_name = plan.subnet_name(name)
    return work.SubNet(neutron, name, network_name, cidr, subnet_name)


def network_components(resolver, name):
    plan = resolver.resolve(planning.Plan)
    networks = dict()
    if plan.public_network:
        networks['public'] = {
            'components': [work.Router,
                           work.Network,
                           work.SubNet,
                           work.RouterInterface],
        }
    if plan.private_network:
        networks['private'] = {
            'components': [work.Network, work.SubNet],
        }
    work_items = networks[name]['components']
    return depend.NamedComponentList(resolver, work_items, name)


# TODO: rename this a factory, and don't rebuild the networks dictionary above
# but rather register each network as a subclass
def all_networks_factory(resolver):
    plan = resolver.resolve(planning.Plan)
    return depend.WorkItemList([network_components(resolver, network)
                                for network in plan.networks.keys()],
                               resolver, False)


def enable_logging():
    logging.basicConfig(level=logging.DEBUG)


def router_factory(resolver, name):
    plan = resolver.resolve(planning.Plan)
    neutron = resolver.resolve(neutronclient.Client)
    router_name = plan.router_name(name)
    return work.Router(neutron,  name, router_name)


def router_interface_factory(resolver, name):
    plan = resolver.resolve(planning.Plan)
    name = name
    neutron = resolver.resolve(neutronclient.Client)
    router_name = plan.router_name(name)
    subnet_name = plan.subnet_name(name)
    return work.RouterInterface(neutron, name, router_name, subnet_name)


def neutron_client_factory(resolver):
    session = resolver.resolve(ksc_session.Session)
    neutron = neutronclient.Client('2.0', session=session)
    neutron.format = 'json'
    return neutron


def float_ip_factory(resolver, name):
    plan = resolver.resolve(planning.Plan)
    fqdn = plan.make_fqdn(name)
    cloud_user = plan.profile['cloud_user']
    nova = resolver.resolve(novaclient.Client)
    return work.FloatIP(nova, fqdn, cloud_user)


def nova_client_factory(resolver):
    session = resolver.resolve(ksc_session.Session)
    nova_client = novaclient.Client('2', session=session)
    return nova_client


def parser_factory(resolver):
    parser = argparse.ArgumentParser(description='')
    ksc_session.Session.register_cli_options(parser)
    ksc_auth.register_argparse_arguments(parser,
                                         sys.argv,
                                         default='v3password')
    parser.add_argument('-s', '--section',
                        dest='section',
                        default='scope')
    parser.add_argument('worker', nargs='?', default='all',
                        help='Worker to execute, defaults to "all"')

    return parser


def args_factory(resolver):
    parser = resolver.resolve(argparse.ArgumentParser)
    args = parser.parse_args()
    return args


def session_factory(resolver):
    parser = resolver.resolve(argparse.ArgumentParser)
    args = parser.parse_args()
    auth_plugin = ksc_auth.load_from_argparse_arguments(args)
    try:
        if not auth_plugin.auth_url:
            logging.error('OS_AUTH_URL not set.  Aborting.')
            sys.exit(-1)
    except AttributeError:
        pass

    session = ksc_session.Session.load_from_cli_options(
        args, auth=auth_plugin)

    return session


def plan_factory(resolver):
    parser = resolver.resolve(argparse.ArgumentParser)
    args = parser.parse_args()
    session = resolver.resolve(ksc_session.Session)
    plan = planning.Plan(args.section, session)
    for host in ['ipa', 'openstack', 'keycloak']:
        plan.add_host(host)
    return plan


def worker_factory(resolver):
    args = resolver.resolve("args")
    return args.worker


def security_group_factory(resolver):
    nova = resolver.resolve(novaclient.Client)
    neutron = resolver.resolve(neutronclient.Client)
    plan = resolver.resolve(planning.Plan)
    security_groups = []
    security_ports = {}
    for group, ports in plan.security_ports.iteritems():
        sec_group = "%s-%s" % (plan.name, group)
        security_groups.append(sec_group)
        security_ports[sec_group] = ports
    return work.SecurityGroup(nova, neutron, security_groups, security_ports)


def anisble_playbook_factory(resolver, name):
    plan = resolver.resolve(planning.Plan)
    return work.AnsiblePlaybook(plan.inventory_file, plan.ansible_playbook)


def hosts_entries_factory(resolver):
    nova = resolver.resolve(novaclient.Client)
    plan = resolver.resolve(planning.Plan)
    hosts = plan.hosts.values()
    cloud_user = plan.profile['cloud_user']
    domain_name = plan.domain_name
    return work.HostsEntries(resolver, nova, hosts, cloud_user, domain_name)


def inventory_factory(resolver):
    plan = resolver.resolve(planning.Plan)
    nova = resolver.resolve(novaclient.Client)
    directory = plan.deployment_dir
    hosts = plan.hosts
    ipa_vars = plan.ipa_client_vars
    inventory_file = plan.inventory_file
    return work.Inventory(nova, inventory_file, directory, hosts, ipa_vars)


def all_items_factory(resolver, name):
    all = [(depend.WorkItemList, 'networks'),
           work.SecurityGroup,
           work.AllServers,
           work.HostsEntries,
           work.Inventory]
    return depend.UnnamedComponentList(resolver, all)


def all_servers_factory(resolver):
    nova = resolver.resolve(novaclient.Client)
    plan = resolver.resolve(planning.Plan)
    domain_name = plan.domain_name
    servers = depend.WorkItemList(
        [resolver.resolve_named(work.NovaServer, server_name)
         for server_name in plan.hosts],
        resolver, False)
    float_ips = depend.WorkItemList(
        [resolver.resolve_named(work.FloatIP, server_name)
         for server_name in plan.hosts], resolver, False)

    return work.AllServers(nova, domain_name, servers, float_ips)


def host_worker_factory(resolver, name):
    work_items = [
        work.NovaServer,
        work.FloatIP,
        work.HostsEntries,
        work.Inventory
    ]
    return depend.NamedComponentList(resolver, work_items, name)


def nova_server_factory(resolver, name):
    nova = resolver.resolve(novaclient.Client)
    neutron = resolver.resolve(neutronclient.Client)
    plan = resolver.resolve(planning.Plan)
    spec = plan.hosts[name]
    return work.NovaServer(nova, neutron, spec)


class WorkerApplication(object):
    def __init__(self):
        resolver = depend.global_resolver
        item = resolver.resolve("worker")
        self.work_item_list = resolver.resolve(depend.WorkItemList, item)

    def create(self, *args, **kwargs):
        return self.work_item_list.create(*args, **kwargs)

    def teardown(self, *args, **kwargs):
        return self.work_item_list.teardown(*args, **kwargs)

    def display(self, *args, **kwargs):
        return self.work_item_list.display(*args, **kwargs)


# So, we can lie.  Since Python is not strictly typed,
# we do not need to return an actual instance of a class,
# but rather a component that conforms to the same
# interface as the class. In the case of WorkItemList,
# it must implement the methods create, tear_down, and display

depend.register_named(depend.WorkItemList, 'ipa',  host_worker_factory)
depend.register_named(depend.WorkItemList, 'controller',  host_worker_factory)
depend.register_named(depend.WorkItemList, 'openstack',  host_worker_factory)
depend.register_named(depend.WorkItemList, 'keycloak',  host_worker_factory)
depend.register_named(depend.WorkItemList, 'rippowam',
                      anisble_playbook_factory)
depend.register_named(depend.WorkItemList, 'ansible',
                      anisble_playbook_factory)
depend.register_named(depend.WorkItemList, 'all', all_items_factory)
depend.register_named(depend.WorkItemList, 'networks', all_networks_factory)
depend.register_named(depend.WorkItemList, 'security_group',
                      security_group_factory)
depend.register_named(depend.WorkItemList, 'inventory', inventory_factory)

depend.register_named(
    depend.WorkItemList,
    'servers',
    lambda resolver, name: depend.NamedComponentList(
        resolver, [work.AllServers, work.HostsEntries, work.Inventory], name))

depend.register_named(
    depend.WorkItemList,
    'public-network',
    lambda resolver, name: depend.NamedComponentList(
        resolver, [work.Router,
                   work.Network,
                   work.SubNet,
                   work.RouterInterface], 'public'))

depend.register_named(
    depend.WorkItemList,
    'private-network',
    lambda resolver, name: depend.NamedComponentList(
        resolver, [work.Network,
                   work.SubNet], 'private'))

depend.register(work.Network, network_factory)
depend.register(work.SubNet, subnet_factory)
depend.register(work.Router, router_factory)
depend.register(work.RouterInterface, router_interface_factory)
depend.register(work.SecurityGroup, security_group_factory)

depend.register(work.FloatIP, float_ip_factory)
depend.register(work.NovaServer, nova_server_factory)
depend.register(work.AllServers, all_servers_factory)

depend.register(work.HostsEntries, hosts_entries_factory)
depend.register(work.Inventory, inventory_factory)

depend.register(argparse.ArgumentParser, parser_factory)
depend.register(ksc_session.Session, session_factory)
depend.register(planning.Plan, plan_factory)
depend.register("args", args_factory)
depend.register("worker", worker_factory)
depend.register(novaclient.Client, nova_client_factory)
depend.register(neutronclient.Client, neutron_client_factory)


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
