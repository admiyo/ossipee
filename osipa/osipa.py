import json
import requests
from requests_kerberos import HTTPKerberosAuth

from novaclient.v1_1 import client


"""
To delete a VM
VM_NAME=""$1

if [ -z $VM_NAME ]
then
        echo usage $0 ' <VM_NAME>'
        exit
fi

. ./keystone.rc

INSTANCE=`nova list | awk -v vm_name=$VM_NAME ' $4 == vm_name {print $2}'`
FLOATING_IP=`nova floating-ip-list | awk -v instance=$INSTANCE ' $4 == instance {print $2}'`

echo $FLOATING_IP

nova floating-ip-delete $FLOATING_IP
ipa host-del $VM_NAME --updatedns
nova delete $VM_NAME

"""

"""
To Create A VM

. ./keystone.rc
. ./vm_def.rc


OTP=`uuidgen -r | sed 's/-//g'`


numbered_vm_name(){
INDEX=`cat index.dat`
VM_NAME=$USER-$INDEX
echo $(( $INDEX + 1 )) > index.dat
echo $VM_NAME
}

get_first_floating_ip(){
    nova floating-ip-list | awk ' $4~/None/  {print $2 ; exit }' 
}

get_new_floating_ip(){
    nova floating-ip-create | awk '/None/ {print $2}'
}

make_user_data(){
cat << END_HEREDOC > $VM_NAME.dat
#!/bin/bash
echo $VM_NAME.$DOMAIN > /etc/hostname
hostname $VM_NAME.$DOMAIN
echo nameserver $NAMESERVER > /etc/resolv.conf
yum -y install freeipa-client
ipa-client-install -U -w $OTP
END_HEREDOC
}

wait_for_build(){
while [ `nova show $VM_NAME | awk ' $2~ /status/ { print $4 }'` = BUILD ]
do
        sleep 1
        echo -n .
done

echo
echo  adding floating IP address $FLOAT_IP to $VM_NAME
}

VM_NAME=`numbered_vm_name`
FLOAT_IP=`get_new_floating_ip`
#FLOAT_IP= `get_first_floating_ip`
make_user_data
"""

"""
"""

class KeystoneData():
    keys = ['OS_AUTH_URL', 'OS_PASSWORD', 'OS_USERNAME', 'OS_TENANT_NAME']
    
    def __init__(self):
        f = open('../keystone.rc', 'r')
        for line in f:
            k,v = line.split('=')
            if k in self.keys:
                setattr(self, k, v)
    

class VMDefinition():
    nameserver="10.16.16.143"
    key_name="ayoung-pubkey"
    image_id="94d1dbba-9e65-471e-97d0-eb7966982c12"
    flavor_id="3"
    secgroup="all"
    domain="openstack.freeipa.org"


class HostEntry:
    def __getitem__(self,key):
        return getattr(self, key)
    def __init__(self, vm_definition):
        self.name = 'ayoung-test'
        self.domain = vm_definition.domain
        self.nameserver= vm_definition.nameserver
        self.key_name=vm_definition.key_name
        self.image_id=vm_definition.image_id
        self.flavor_id=vm_definition.flavor_id
        self.security_groups=[vm_definition.secgroup]
        self.domain=vm_definition.domain
        
        self.fqdn = '%(name)s.%(domain)s' % self


class IPAConfig():
    host="https://ipa.openstack.freeipa.org"
    ca_cert = "/etc/pki/CA/certs/ipa.ca.cert"


class OpenStack():
        
    def __init__(self):
        kd = KeystoneData()
        self.nova_c = client.Client(kd.OS_USERNAME,
                                    kd.OS_PASSWORD,
                                    kd.OS_TENANT_NAME,
                                    auth_url= kd.OS_AUTH_URL,
                                    service_type="compute")
    def find_by_name(self,server_name):
        for s in self.nova_c.servers.list():
            if (s.name == server_name):
                return s.id
        return None
            
    def delete_vm(self,vm_name):
        vm_id = self.find_by_name(vm_name)
        
        for floating in self.nova_c.floating_ips.list():
            if floating.instance_id == vm_id:
                float_ip = floating.id;
                break

    def boot_vm(self, host_entry):
        print "nova boot --flavor=2 --image=13 testserver --meta description='Use for testing purposes' --meta creator=joecool"
        self.nova_c.servers.create(host_entry.name, 
                                   host_entry.image_id, 
                                   host_entry.flavor_id, 
                                   meta = None, 
                                   files = None, 
                                   reservation_id = None, 
                                   min_count = 1, 
                                   max_count = 1, 
                                   security_groups = host_entry.security_groups, 
                                   userdata = host_entry.userdata, 
                                   key_name = host_entry.key_name, 
                                   availability_zone = None, 
                                   block_device_mapping= None, 
                                   nics= None, 
                                   scheduler_hints= None, 
                                   config_drive= None)
        

    def get_new_floating_ip(self):
        next_ip = self.nova_c.floating_ips.create()
        return next_ip

    def list_stuff(self):
        self.delete_vm('ayoung-portal')
        print self.find_by_name('ayoung-portal')

class IPA():
    config = IPAConfig()
    host=config.host
    headers = {"referer" :"%s/ipa" % host,
                   "Content-Type": "application/json",
                   "Accept":"applicaton/json"}
    url = "%s/ipa/json" % host
    ca_cert = config.ca_cert

    def rpc_post(self, data):
        response = requests.post(self.url,
                     data = json.dumps(data),
                     headers = self.headers,
                     auth=HTTPKerberosAuth(),
                     verify=self.ca_cert)
        result_data = json.loads(response.content)
        #TDOD check error code
        if 'error' in result_data and result_data['error'] is not None:
            raise Exception(response.content)
        return result_data['result']['result']

    def user_find(self):
        data = {"method":"user_find","params":[[""],{}],"id":0}
        return self.rpc_post(data)

    def host_add(self, host_entry):
        data = {"method":"host_add",
                "params":[[host_entry.fqdn],
                          {"force": True,
                           "random": True}]}
        if hasattr(host_entry, 'ip'):
            data['params'][1]['ip'] = host_entry.ip
        response =  self.rpc_post(data)
        
        return response
    
    def host_del(self, host_entry):
        data = {"method":"host_del",
                "params":[[host_entry.fqdn],
                           {"updatedns":True}]}
        return self.rpc_post(data)




class Ossipee():

    userdata_template = """
#!/bin/bash
echo %s(fqdn)s > /etc/hostname
hostname $s(fqdn)
echo nameserver %(nameserver)s > /etc/resolv.conf
yum -y install freeipa-client
ipa-client-install -U -w %(otp)s
""" 

    
    ipa = IPA()
    os = OpenStack()
    vm_definition = VMDefinition()

    def next_host(self):
        
        host_entry = HostEntry(self.vm_definition)
        return host_entry

    def create_next_vm(self, host_entry):
        """
            Allocate a Floating IP address
            Generate an One Time Password (OTP)
            Create a Host entry in FreeIPA, using the IP Address.  
                Have it generate an OTP
            Generate a user-data script
            Boot the virtual machine
            wait until the machine is running
            Allocate the Floating IP address to the Virtual Machine
        
        """
        host_entry.ip = self.os.get_new_floating_ip().ip
        response = self.ipa.host_add(host_entry)
        host_entry.otp = response['randompassword']
        self.create_userdata(host_entry)
        result = self.os.boot_vm(host_entry)

    def delete_vm(self, host_entry):
        """
        nova floating-ip-delete $FLOATING_IP
        ipa host-del $VM_NAME --updatedns
        nova delete $VM_NAME
        """
        self.ipa.host_del(host_entry)
        pass

    def create_userdata(self, host_entry):
        host_entry.userdata = self.userdata_template % host_entry


def _main():
    ossipee = Ossipee()
    host_entry = ossipee.next_host()
    try:
        ossipee.create_next_vm(host_entry)
    finally:
        ossipee.delete_vm(host_entry)
    #for user in ossipee.ipa_client.user_find():
    #    print user['uid'][0]



if __name__ == '__main__':
    _main()