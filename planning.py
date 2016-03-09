import logging
import os

import ConfigParser


# TODO(ayoung): These should be in the config file
CLOUD_AUTH_URLS = {
    'http://controller.oslab.openstack.engineering.redhat.com:5000/v3':
    'oslab',
    'http://control.os1.phx2.redhat.com:5000/v3/': 'os1',
    'http://openstack.demorack.lab.eng.rdu.redhat.com:5000/v3': 'demorack',
    'https://keystone.dream.io/v3': 'dreamcompute'
}

user_data_template = '''
#cloud-config
hostname: %(fqdn)s
fqdn:  %(fqdn)s
write_files:
-   path: /etc/sudoers.d/999-ansible-requiretty
    permissions: 440
    content: |
        Defaults:%(cloud_user)s !requiretty
'''


class Plan(object):
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

    DEFAULT_PROFILE = 'rhel7'

    def _default_config_options(self):
        self.config.add_section(self.section)
        self.config.set(self.section, 'profile', self.DEFAULT_PROFILE)
        self.config.set(self.section, 'name', self.name)
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

    def __init__(self, section, session):
        self.section = section
        self.config = ConfigParser.SafeConfigParser()
        self.profiles = ConfigParser.SafeConfigParser()
        self.cloud = CLOUD_AUTH_URLS.get(session.auth.auth_url, 'unknown')

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

        global_rule = {
            'tcp': [
                (1, 65535)
            ],
            'udp': [
                (1, 65535)
            ],
            'icmp': [
                -1
            ]
        }

        self.security_ports = {
            'all-open': global_rule,
        }

        configuration = self
        name = self.name

        self.cloud = CLOUD_AUTH_URLS.get(session.auth.auth_url, 'unknown')
        self.deployments_dir = self.config_dir + '/deployments'
        self.deployment_dir = (self.deployments_dir +
                               '/' + name + '.' + self.cloud)
        self.inventory_file = self.deployment_dir + '/inventory.ini'

        self.networks = dict()

        cidr_template = '192.168.%d.0/24'
        if self.public_network:
            self.networks['public'] = {
                'cidr': cidr_template % 52
            }
        if self.private_network:
            self.networks['private'] = {
                'cidr': cidr_template % 78
            }

        self.ipa_client_vars = self._get_client_vars()
        self.hosts = {}

    def build_network_name(self,  key):
        return self.name + '-' + key + '-net'

    def get(self, name, default=None):
        try:
            return self.config.get(self.section, name)
        except ConfigParser.NoOptionError:
            logging.debug("Option %s not in config file, using default: %s",
                          name,
                          default)

            return default

    def getboolean(self, name, default=False):
        try:
            return self.config.getboolean(self.section, name)
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
        return self.get('pubkey', None)

    @property
    def domain_name(self):
        return self.get('domain_name',
                        self.name + '.' + self.cloud + '.test')

    @property
    def forwarder(self):
        return self.get('forwarder', '192.168.52.3')

    @property
    def public_network(self):
        return self.getboolean('public_network')

    @property
    def private_network(self):
        return self.getboolean('private_network')

    @property
    def ansible_playbook(self):
        return self.get('ansible_playbook',
                        os.getenv('HOME') + '/devel/rippowam/site.yml')

    def subnet_name(self, name):
        return self.name + '-' + name + '-subnet'

    def router_name(self, name):
        return self.name + '-' + name + '-router'

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
        def build_network_name(name, key):
            return name + '-' + key + '-net'

        if self.hosts.get(name):
            print ('host %s already exists.' % name)
            return

        host = HostSpec()
        host.name = name
        host.fqdn = self.make_fqdn(name)
        host.client_vars = self._get_client_vars()
        host.security_groups = ["%s-%s" % (self.name, 'all-open')]
        host.image_name = self.profile['image']
        host.flavor_name = self.profile['flavor']
        host.keypair_name = self.key
        host.user_data = self.user_data(name)
        host.network_names = [self.build_network_name(net_name)
                              for net_name in self.networks.keys()]
        self.hosts[name] = host

    # TODO:  Marshall a Python object to YAML
    def user_data(self, name):
        realm = self.domain_name.upper()
        data = user_data_template % {
            'hostname': name,
            'fqdn': self.make_fqdn(name),
            'realm': realm,
            'domain': self.domain_name,
            'cloud_user': self.profile['cloud_user']
        }
        return data


class HostSpec(object):
    pass
