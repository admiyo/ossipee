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

from glanceclient import client as glanceclient
from novaclient import client as novaclient
from neutronclient.neutron import client as neutronclient
import os_client_config


import depend
import planning
import work


def all_items_factory(resolver, name):
    all = [(depend.WorkItemList, 'networks'),
           work.SecurityGroup,
           work.AllServers,
           work.HostsEntries,
           work.Inventory]
    return depend.UnnamedComponentList(resolver, all)


def all_networks_factory(resolver, name=None):
    plan = resolver.resolve(planning.Plan)
    components = list()
    if plan.public_network:
        components.append((depend.WorkItemList, 'public-network'))
    if plan.private_network:
        components.append((depend.WorkItemList, 'private-network'))
    return depend.UnnamedComponentList(resolver, components)


def all_servers_factory(resolver, name=None):
    nova = resolver.resolve(novaclient.Client)
    plan = resolver.resolve(planning.Plan)
    domain_name = plan.domain_name
    servers = depend.WorkItemList(
        [resolver.resolve_named(work.Server, server_name)
         for server_name in plan.hosts],
        resolver, False)
    float_ips = depend.WorkItemList(
        [resolver.resolve_named(work.FloatIP, server_name)
         for server_name in plan.hosts], resolver, False)

    return work.AllServers(nova, domain_name, servers, float_ips)


def anisble_playbook_factory(resolver, name):
    plan = resolver.resolve(planning.Plan)
    return work.AnsiblePlaybook(plan.inventory_file, plan.ansible_playbook)


def args_factory(resolver):
    parser = resolver.resolve(argparse.ArgumentParser)
    args = parser.parse_args()
    return args


def float_ip_factory(resolver, name):
    plan = resolver.resolve(planning.Plan)
    fqdn = plan.make_fqdn(name)
    cloud_user = plan.profile['cloud_user']
    nova = resolver.resolve(novaclient.Client)
    neutron = resolver.resolve(neutronclient.Client)
    return work.FloatIP(nova, neutron, fqdn, cloud_user)


def hosts_entries_factory(resolver, name=None):
    nova = resolver.resolve(novaclient.Client)
    plan = resolver.resolve(planning.Plan)
    hosts = plan.hosts.values()
    cloud_user = plan.profile['cloud_user']
    domain_name = plan.domain_name
    return work.HostsEntries(resolver, nova, hosts, cloud_user, domain_name)


def host_worker_factory(resolver, name):
    work_items = [
        work.Server,
        work.FloatIP,
        work.HostsEntries,
        work.Inventory
    ]
    return depend.NamedComponentList(resolver, work_items, name)


def inventory_factory(resolver, name=None):
    plan = resolver.resolve(planning.Plan)
    nova = resolver.resolve(novaclient.Client)
    directory = plan.deployment_dir
    hosts = plan.hosts
    ipa_vars = plan.ipa_client_vars
    inventory_file = plan.inventory_file
    return work.Inventory(nova, inventory_file, directory, hosts, ipa_vars)


def network_factory(resolver, name):
    neutron = resolver.resolve(neutronclient.Client)
    plan = resolver.resolve(planning.Plan)
    network_name = plan.build_network_name(name)
    return work.Network(neutron, network_name)


def neutron_client_factory(resolver, name=None):
    neutron = os_client_config.make_client('network')
    neutron.format = 'json'
    return neutron


def nova_client_factory(resolver, name=None):
    nova_client = os_client_config.make_client('compute')
    return nova_client

def glance_client_factory(resolver, name=None):
    glance_client = os_client_config.make_client('image')
    return glance_client


# TODO: this needs to be named.  It is just a server, not *the* nova server
def nova_server_factory(resolver, name):
    nova = resolver.resolve(novaclient.Client)
    neutron = resolver.resolve(neutronclient.Client)
    glance = resolver.resolve(glanceclient.Client)
    plan = resolver.resolve(planning.Plan)
    spec = plan.hosts[name]
    return work.Server(nova, neutron, glance, spec)


def parser_factory(resolver, name=None):
    parser = argparse.ArgumentParser(description='')
    parser.add_argument('-s', '--section',
                        dest='section',
                        default='scope')
    parser.add_argument('worker', nargs='?', default='all',
                        help='Worker to execute, defaults to "all"')

    return parser


def plan_factory(resolver, name=None):
    auth_url=""
    parser = resolver.resolve(argparse.ArgumentParser)
    args = parser.parse_args()
    plan = planning.Plan(args.section, auth_url)
    return plan


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


def security_group_factory(resolver, name=None):
    nova = resolver.resolve(novaclient.Client)
    neutron = resolver.resolve(neutronclient.Client)
    plan = resolver.resolve(planning.Plan)
    security_groups = []
    security_ports = {}
    for group, ports in plan.security_ports.items():
        sec_group = "%s-%s" % (plan.name, group)
        security_groups.append(sec_group)
        security_ports[sec_group] = ports
    return work.SecurityGroup(nova, neutron, security_groups, security_ports)


def worker_factory(resolver, name=None):
    args = resolver.resolve("args")
    return args.worker


def subnet_factory(resolver, name):
    neutron = resolver.resolve(neutronclient.Client)
    plan = resolver.resolve(planning.Plan)
    network_name = plan.build_network_name(name)
    cidr = plan.networks[name]['cidr']
    subnet_name = plan.subnet_name(name)
    return work.SubNet(neutron, name, network_name, cidr, subnet_name)


def enable_logging():
    logging.basicConfig(level=logging.DEBUG)


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

    def list(self,  *args, **kwargs):
        def list_registered(clazz):
            worker_keys = []
            for proxy_key in depend.GLOBAL_SCOPE.proxy_map:
                try:
                    isinstance(depend.WorkItemList, proxy_key[0])
                except TypeError:
                    continue
                worker_keys.append(proxy_key[1])
            print(sorted(worker_keys))
                    
        list_registered(depend.WorkItemList)
    
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
depend.register(work.Server, nova_server_factory)
depend.register(work.AllServers, all_servers_factory)

depend.register(work.HostsEntries, hosts_entries_factory)
depend.register(work.Inventory, inventory_factory)

depend.register(argparse.ArgumentParser, parser_factory)
depend.register(planning.Plan, plan_factory)
depend.register("args", args_factory)
depend.register("worker", worker_factory)
depend.register(glanceclient.Client, glance_client_factory)
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
    print (json.dumps({
        'success': True,
        'args': args_data
    }))

if __name__ == '__main__':
    main()
