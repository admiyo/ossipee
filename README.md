Code to set up a Demo running on top of OpenStack

Right now, it just sets up Neutron, using the Python API.

source your keystone.rc file and then run

./ossipee-create

to set up the demo

./ossipee-display
to show the status of the components


./ossipee-teardown
to Tear down the demo


./ossipee-list

To list the workers.


To run jhust one worker say, to tear down ipa:

./ossipee-teardown ipa


USING Ansible

ansible localhost -i ~/.ossipee/inventory.ini -M . -m ossipee -a "action=teardown worker=network"

ansible-playbook -vvvv -i ~/.ossipee/inventory.ini -M $PWD playbooks/all.yml
