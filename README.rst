=========
 Ossipee
=========


This project started as  OS-IPA, but it sounded too much like Ossipee_ ; One of
the twelve Algonquian tribes, and a Lake and Town in New Hampshire named for
them.

.. _Ossipee: https://en.wikipedia.org/wiki/Ossipee,_New_Hampshire

Ossipee is now a system for building a small cluster in an OpenStack
deployment.  It also serves to tear down and clean up the resources.

To get startes, source a V3 Keystone Resource file based on this template:


export OS_AUTH_URL=http://{{ keystone_hostname }}:5000/v3
export OS_USERNAME={{ username }}
export OS_PASSWORD={{ password }}
export OS_USER_DOMAIN_NAME={{ user_domain }}
export OS_PROJECT_DOMAIN_NAME={{ project_domain }}
export OS_PROJECT_NAME={{ project_name }}
export OS_IDENTITY_API_VERSION=3

Ossipee stores reads and stores local information in the directory

  $HOME/.ossipee

To get started, run

  ossipee-display

This will generate a blank config file in 

  $HOME/.ossipee/config.ini

A sample config file will look like this:


  [scope]
  profile = rhel7
  name = yourname
  pubkey = yourname-pubkey
  forwarder = 192.168.52.3


The $USER value will be used as the ``name`` which is used to link the
resources.

To do a complete run,

ossipee-create


This will use the OpenStack APIs to create the following resources:

two networks, named

  yourname-public-net
  yourname-private-net

two subnets named
 yourname-public-subnet
 yourname-private-subnet

The necessary router and interfaces to connect the ``yourname-public-net`` to
the external network.


two hosts named

  ipa.yourname.test
  openstack.yourname.test

An Ansible inventory file in ~/.ossipee/inventory/yourname.ini

This last is expected to be consumed by Rippowam_.

.. _Rippowam: https://github.com/jamielennox/rippowam


To tear down the install:

  ossipee-teardown

There are several targets.  To see them, run

  ossipee-list

For instance, to reset just the ipa server, you can run

  ossipee-redo ipa

A profile is the combination of computer Flavor and image that will be used
when creating the virtual machine. There are several profiles suported:

-    'centos7':
        - 'cloud_user': 'centos',
        - 'image': 'centos-7-cloud',
        - 'flavor': 'm1.medium',	
-    'rhel7':
        - 'cloud_user': 'cloud-user',
        - 'image': 'rhel-guest-image-7.1-20150224.0',
        - 'flavor': 'm1.medium',
-    'f22': 
        - 'cloud_user': 'fedora',
        - 'image': 'Fedora 22 Cloud Image',
        - 'flavor': 'm1.medium',

The image and flavor names must match.
