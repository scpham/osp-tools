#!/usr/bin/env python
# coding=utf-8
__author__ = "Scott Pham"
__version__ = "0.1"
__maintainer__ = "Scott Pham"
__email__ = "scpham@cisco.com"

import argparse
import json
import logging
import os
import threading
from copy import deepcopy
from time import sleep

import ansible.inventory
import ansible.runner
from neutronclient.v2_0 import client as neutron_client
from novaclient import client as nova_client
from prettytable import PrettyTable

# noinspection PyPep8Naming
from glanceclient import Client as glance_client
from keystoneclient.v2_0 import client as keystone_client

logging.basicConfig(date_fmt='%m-%d %H:%M')
LOG = logging.getLogger('InstanceInfo')


class NovaInstance(object):
    """NovaInstance."""

    def __init__(self, **args):
        """Init NovaInstance."""

        self._wait_interval = args.pop('wait_interval', 1)

        self._keystone = keystone_client.Client(**args)

        glance_endpoint = self._keystone.service_catalog.url_for(service_type='image', endpoint_type='internalURL')
        neutron_endpoint = self._keystone.service_catalog.url_for(service_type='network', endpoint_type='internalURL')
        nova_endpoint = self._keystone.service_catalog.url_for(service_type='compute', endpoint_type='internalURL')
        self._neutron = neutron_client.Client(endpoint_url=neutron_endpoint, token=self._keystone.auth_token)

        self._glance = glance_client('2', glance_endpoint, token=self._keystone.auth_token)
        self.debug = args.pop('debug')
        if self.debug:
            LOG.setLevel(logging.DEBUG)
        self.ovs_data = args.pop('ovs_data')
        self.dhcp_logs = args.pop('dhcp_logs')
        self.dhcp_ping_test = args.pop('dhcp_ping_test')
        self.capture_tcpdump = args.pop('capture_tcpdump')
        nova_args = deepcopy(args)
        self._nova = nova_client.Client('2', nova_args.pop('username'),
                                        nova_args.pop('password'),
                                        auth_token=self._keystone.auth_token,
                                        project_id=nova_args.pop('tenant_name'), **nova_args)

    def get_instance_neutron_port_list(self, instance_uuid):
        """Get Neutron Ports (neutron port-show)"""

        ports = self._neutron.list_ports(device_id=instance_uuid).get('ports', [])
        if self.debug:
            LOG.debug("Print Ports Data")
            self.data_dump(ports)
        return ports

    def get_neutron_routers(self, tenant_id):
        """Get List of Routers For Tenant"""

        routers = self._neutron.list_routers(tenant_id=tenant_id)
        if self.debug:
            LOG.debug("Routers Data Dump")
            self.data_dump(routers)
        return routers

    def get_router_associated_with_instance(self, routers, subnet_id):
        """Get Routers Associated with Instance"""

        filtered_routers = {}

        for router in routers['routers']:
            router_ports = self._neutron.list_ports(device_id=router['id'])
            if self.debug:
                LOG.debug("Router Ports Dump")
                self.data_dump(router_ports)

            for rp in router_ports['ports']:
                router_net_node = rp['binding:host_id']
                for fip in rp['fixed_ips']:
                    if fip['subnet_id'] == subnet_id:
                        filtered_routers[rp['device_id']] = {'network_node': router_net_node,
                                                             'ip_address': fip['ip_address']}
                        # return if router found
                        return filtered_routers

        return filtered_routers

    def get_instance_info(self, instance_uuid):
        """Get Nova Instance Info (nova show)"""

        instance_data = self._nova.servers.get(instance_uuid).to_dict()

        if self.debug:
            LOG.debug("Instance Data Dump")
            self.data_dump(instance_data)

        instance_keys = ['name', 'created', 'updated', 'status', 'image', 'tenant_id', 'OS-EXT-SRV-ATTR:host', 'flavor']

        instance = dict()
        for field_name in instance_keys:
            instance[field_name] = instance_data[field_name]
            if field_name == 'image' and 'id' in instance_data[field_name]:
                instance[field_name] = instance_data[field_name]['id']
            elif field_name == 'image':
                instance[field_name] = "Image Not Found"
            elif field_name == 'flavor':
                flavor_id = instance_data['flavor']['id']
                flavor = self._nova.flavors.get(flavor_id)
                instance[field_name] = flavor.name
        return instance_keys, instance

    def get_instance_floatingip(self, port_id):
        """Get Floating IP of Instance"""

        floating_ips = self._neutron.list_floatingips(port_id=port_id)['floatingips']

        if self.debug:
            LOG.debug("Floating IP Data Dump")
            self.data_dump(floating_ips)

        floating_ip = {}
        for fp in floating_ips:
            floating_ip[fp['id']] = fp['floating_ip_address']

        return floating_ip

    def get_network_vlan(self, network_id):
        """Get Network Vlan Segment"""

        net_show = self._neutron.show_network(network=network_id)

        return net_show['network']['provider:segmentation_id']

    def get_neutron_security_group_rules(self, security_group_id):
        """Get Neutron Security Group Rules"""

        group_rules = self._neutron.show_security_group(security_group=security_group_id)

        if self.debug:
            LOG.debug("Security Group [%s] Rules Dump" % security_group_id)
            self.data_dump(group_rules)

        rules = []
        rule_keys = ['direction', 'remote_ip_prefix', 'ethertype', 'protocol']
        is_pingable = False
        for rule in sorted(group_rules['security_group']['security_group_rules']):
            rule_tmp = []
            port_range = None
            if rule['port_range_min'] is not None and rule['port_range_max'] is not None:
                port_range = "%s - %s" % (rule['port_range_min'], rule['port_range_max'])
            for rule_key in rule_keys:
                rule_tmp.append("%s" % rule[rule_key])
            if port_range is not None:
                rule_tmp.append(port_range)
            rules.append(' '.join(rule_tmp))
            if 'ingress' in rule_tmp and '0.0.0.0/0' in rule_tmp and 'icmp' in rule_tmp:
                is_pingable = True

        return rules, is_pingable

    def get_dhcp_agent_ports(self, network_id, tenant_id):
        """Get DHCP Agent Neutron Ports"""

        dhcp_ports = self._neutron.list_ports(tenant_id=tenant_id, network_id=network_id, device_owner='network:dhcp')
        LOG.debug("DHCP Agent Port Dump")
        self.data_dump(dhcp_ports)

        agents_port = {}
        for port in dhcp_ports['ports']:
            hostname = port['binding:host_id'].split('.')[0]

            if hostname not in agents_port:
                agents_port[hostname] = {}

            agents_port[hostname]['ip_address'] = port['fixed_ips'][0]['ip_address']
            agents_port[hostname]['mac_address'] = port['mac_address']

        self.data_dump(agents_port)

        return agents_port

    def get_dhcp_agents(self, network_id):
        """Get DHCP Agents for Network ID"""

        agents = self._neutron.list_dhcp_agent_hosting_networks(network_id)

        if self.debug:
            LOG.debug("DHCP Agent Data Dump")
            self.data_dump(agents)

        agent_hosts = []
        for agent in agents['agents']:
            agent_hosts.append(agent['host'].split('.')[0])

        return agent_hosts

    def get_tenant_name(self, tenant_id):
        """Get Tenant Details"""

        tenant = self._keystone.tenants.get(tenant_id)
        return tenant.name

    def get_glance_image(self, image_id):
        """Get Glance Image Details"""
        image = {}
        try:
            image = self._glance.images.get(image_id)
        except:
            image['name'] = 'Image Not Found (Deleted)'

        return image['name']

    def print_instance_info(self, uuid):
        """Prints Instance Info"""

        instance_fields, instance = self.get_instance_info(uuid)

        instance_pt = PrettyTable(['Nova', 'Data'])
        instance_pt.align['Data'] = 'l'
        # Print Instance Data
        compute_node = ""
        for field in instance_fields:
            if field == 'OS-EXT-SRV-ATTR:host':
                compute_node = instance[field].split('.')[0]
                instance_pt.add_row(['Compute', compute_node])
            elif field == 'tenant_id':
                tenant_name = self.get_tenant_name(instance['tenant_id'])
                instance_pt.add_row(['Tenant ID', instance['tenant_id']])
                instance_pt.add_row(['Tenant Name', tenant_name])
            elif field == 'image':
                if instance[field] == "Image Not Found (Deleted)":
                    instance_pt.add_row(['Image', instance[field]])
                else:
                    image_name = self.get_glance_image(instance['image'])
                    instance_pt.add_row(['Image', "%s (%s)" % (instance[field], image_name)])
            else:
                instance_pt.add_row([field.title(), instance[field]])
        print instance_pt
        routers = self.get_neutron_routers(instance['tenant_id'])

        # Print Port Info
        ports = self.get_instance_neutron_port_list(instance_uuid=uuid)

        instance_data = {}
        for port in ports:
            neutron_pt = PrettyTable(['Interface', 'Data'])
            neutron_pt.align['Data'] = "l"
            ovs_port = port['id'][:11]
            instance_data['mac'] = port['mac_address']
            instance_data['ip_address'] = port['fixed_ips'][0]['ip_address']
            neutron_pt.add_row(['Network ID', port['network_id']])
            neutron_pt.add_row(['Subnet ID', port['fixed_ips'][0]['subnet_id']])
            neutron_pt.add_row(['IP Address', instance_data['ip_address']])
            neutron_pt.add_row(['MAC Address', instance_data['mac']])

            # Get Floating IP Info
            floating_ip = self.get_instance_floatingip(port['id'])
            for floating_ip_id in floating_ip.keys():
                neutron_pt.add_row(['Floating IP ID', floating_ip_id])
                neutron_pt.add_row(['Floating IP Address', floating_ip[floating_ip_id]])
            network_vlan = self.get_network_vlan(port['network_id'])
            neutron_pt.add_row(['Network VLAN', network_vlan])

            # Get DHCP Info
            dhcp_agents_line = []
            dhcp_agent_ports = self.get_dhcp_agent_ports(network_id=port['network_id'], tenant_id=instance['tenant_id'])
            for agent in dhcp_agent_ports.keys():
                dhcp_agents_line.append("%s (%s)" % (agent, dhcp_agent_ports[agent]['ip_address']))
            neutron_pt.add_row(['DHCP Agents', '\n'.join(dhcp_agents_line)])

            neutron_pt.add_row(['OVS Port', ovs_port])
            neutron_pt.add_row(['Neutron Port ID', port['id']])
            neutron_pt.add_row(['Neutron Port Status', port['status']])
            neutron_pt.add_row(['Admin Port State', port['admin_state_up']])

            # Get Router Info
            router = self.get_router_associated_with_instance(routers, port['fixed_ips'][0]['subnet_id'])
            router_ip = None
            for router_id in router.keys():
                router_ip = router[router_id]['ip_address']
                neutron_pt.add_row(['Router ID', router_id])
                neutron_pt.add_row(['Router Net Node', "%s (%s)" % (
                    router[router_id]['network_node'].split('.')[0], router_ip)])

            # Get Security Group Info
            is_pingable = False
            for security_group_id in port['security_groups']:
                rules, is_pingable = self.get_neutron_security_group_rules(security_group_id)
                neutron_pt.add_row(['Security Group ID', security_group_id])
                neutron_pt.add_row(['Security Group Rules', '\n'.join(rules)])
            print neutron_pt

            # Get OVS Flows and brctl and ip a
            if self.ovs_data:
                self.get_compute_ovs_data(compute_node, network_vlan, ovs_port)

            # Get DHCP Agent Logs for Mac
            if self.dhcp_logs and dhcp_agent_ports.keys():
                self.get_dhcp_logs(network_nodes=dhcp_agent_ports.keys(), mac=instance_data['mac'],
                                   network_id=port['network_id'])

            if self.dhcp_ping_test and dhcp_agent_ports.keys():
                self.get_dhcp_ping_test(network_node_ports=dhcp_agent_ports, network_id=port['network_id'],
                                        instance_ip=instance_data['ip_address'], router_ip=router_ip,
                                        is_pingable=is_pingable)
            if self.capture_tcpdump and dhcp_agent_ports.keys():
                self.run_tcpdump(net_nodes=dhcp_agent_ports, compute_node=compute_node, instance=instance_data,
                                 ovs_port=ovs_port, network_id=port['network_id'])

    @staticmethod
    def get_compute_ovs_data(compute_node, vlan, ovs_port):
        """Get Compute OVS Data From Compute Node"""
        command = "ovs-ofctl dump-flows br-int | grep -w %s; ovs-ofctl dump-flows br-ex | grep -w %s; ip a | grep %s; brctl show | grep %s ; ovs-vsctl --timeout=10 --format=json -- --columns=name,tag list Port" % (
            vlan, vlan, ovs_port, ovs_port)

        runner = ansible.runner.Runner(
            module_name='shell',
            module_args=command,
            pattern=compute_node,
        )

        results = runner.run()
        # for host in results['contacted']:

        # Print Error For Host
        for node in results['dark']:
            dark_table = PrettyTable(["Failed to Contact Host [%s] with error" % node])
            dark_table.align["Failed to Contact Host [%s] with error" % node] = "l"
            dark_table.add_row([results['dark'][node]['msg']])
            print dark_table

        # Print results from host

        for node in results['contacted']:

            stdout_lines = results['contacted'][node]['stdout'].split('\n')

            ovs_header = "OVS Flow Dump For VLAN %s on Compute: %s" % (vlan, compute_node)
            ovs_dump_flows = PrettyTable([ovs_header])
            ovs_dump_flows.align[ovs_header] = "l"
            ip_header = "ip a | grep %s on Compute Node: %s" % (ovs_port, compute_node)
            ip_a_table = PrettyTable([ip_header])
            ip_a_table.align[ip_header] = "l"
            brctl_header = "brctl show | grep %s on Compute Node: %s" % (ovs_port, compute_node)
            brctl_table = PrettyTable([brctl_header])
            brctl_table.align[brctl_header] = "r"
            port_json = {}
            for line in stdout_lines:
                if 'cookie' in line:
                    ovs_dump_flows.add_row([line])
                elif 'BROADCAST' in line:
                    ip_a_table.add_row([line])
                elif '{' in line:
                    port_json = json.loads(line)
                else:
                    brctl_table.add_row([line.replace('\t', ' ')])

            ovs_port_vlan = PrettyTable(["OVS Port", "OVS Internal VLAN"])
            for port in port_json['data']:
                if ovs_port in port[0]:
                    ovs_port_vlan.add_row([port[0], port[1]])
            print ovs_port_vlan
            print ovs_dump_flows
            print ip_a_table
            print brctl_table

    @staticmethod
    def get_dhcp_logs(network_nodes, mac, network_id):
        """Get DHCP Logs From Network Node"""

        dhcp_namespace = "qdhcp-%s" % network_id
        dhcp_agent_inventory = ansible.inventory.Inventory(network_nodes)
        dhcp_logs_command = "(echo '***** %s [ip a] ******';ip netns exec %s ip a); (echo '******************** DHCP LOGS *********************'; grep -w %s /var/log/messages | grep -v ansible-command | tail -5)" % (
            dhcp_namespace, dhcp_namespace, mac)

        runner = ansible.runner.Runner(
            module_name='shell',
            module_args=dhcp_logs_command,
            inventory=dhcp_agent_inventory,
        )

        result = runner.run()

        for agent in result['contacted']:
            dhcp_log = []
            for line in result['contacted'][agent]['stdout'].split('\n'):
                if line != "":
                    dhcp_log.append(line)

            dhcp_header = "DHCP Data on host [%s] for Mac Address: %s" % (agent, mac)
            dhcp_table = PrettyTable([dhcp_header])

            dhcp_table.align[dhcp_header] = "l"
            for log in dhcp_log:
                dhcp_table.add_row([log])
            print dhcp_table

    @staticmethod
    def get_dhcp_ping_test(network_node_ports, network_id, is_pingable, instance_ip, router_ip):
        """DHCP Ping Test Across Namespaces and Instance"""

        dhcp_namespace = "qdhcp-%s" % network_id

        ip_to_agent = {}
        dhcp_agent_ips = []
        # TODO: Do this within 1 loop
        for agent in network_node_ports.keys():
            ip_to_agent[network_node_ports[agent]['ip_address']] = agent
            dhcp_agent_ips.append(network_node_ports[agent]['ip_address'])

        net_node = None
        agent_ip = None
        for agent in network_node_ports.keys():
            ip = dhcp_agent_ips.pop()
            if network_node_ports[agent]['ip_address'] != ip:
                # net_node = ping from network node (source)
                # agent_ip = ping destination ip
                net_node = agent
                agent_ip = ip
                break

        dhcp_ping_test_command = "( echo '****** Ping Test Between Net Nodes inside namespace [%s (%s) -> %s (%s)] ******'; ip netns exec %s ping -c 1 %s )" \
                                 % (net_node, network_node_ports[net_node]['ip_address'],
                                    ip_to_agent[agent_ip], agent_ip, dhcp_namespace,
                                    agent_ip)

        if router_ip is not None:
            dhcp_ping_test_command = "%s; ( echo '****** Router Ping Test %s [%s -> ping -c 1 %s] ******'; ip netns exec %s ping -c 1 %s )" % (
                dhcp_ping_test_command, dhcp_namespace, net_node, router_ip, dhcp_namespace, router_ip)
            dhcp_ping_test_command = "%s; (echo '****** External Ping Test %s [%s -> ping -c 1 8.8.8.8] ******'; ip netns exec %s ping -c 1 8.8.8.8 )" % (
                dhcp_ping_test_command, dhcp_namespace, net_node, dhcp_namespace)

        if is_pingable:
            dhcp_ping_test_command = "%s; ( echo '***** Instance Ping Test %s [%s -> ping -c 1 %s] *****'; ip netns exec %s ping -c 1 %s )" % (
                dhcp_ping_test_command, dhcp_namespace, net_node, instance_ip, dhcp_namespace, instance_ip)
        else:
            pt = PrettyTable(["Instance Security Group Rules Prevents Instance Ping Test.. Skipping..."])
            print pt

        LOG.debug(dhcp_ping_test_command)

        runner = ansible.runner.Runner(
            module_name='shell',
            module_args=dhcp_ping_test_command,
            pattern=net_node
        )

        results = runner.run()

        data = {}
        for node in results['contacted']:
            header = ""
            for line in results['contacted'][node]['stdout'].split('\n'):
                if '****' in line:
                    header = line
                    data[header] = []
                    continue
                else:
                    data[header].append(line)

        for header in sorted(data.keys(), reverse=True):
            pp = PrettyTable([header])
            # if 'ip a' in header:
            pp.align[header] = "l"
            for line in data[header]:
                pp.add_row([line])
            print pp

    @staticmethod
    def data_dump(data):
        """Pretty Print JSON Data Structures"""
        LOG.debug(json.dumps(data, sort_keys=True, indent=4, separators=(',', ': ')))

    def run_tcpdump(self, net_nodes, compute_node, instance, ovs_port, network_id):
        """ Run TCPDUMP on compute nodes using threads and queues"""

        net_node = net_nodes.keys()[0]
        dhcp_namespace_mac = net_nodes[net_node]['mac_address']
        instance_mac = instance['mac']
        instance_ip = instance['ip_address']
        dhcp_namespace = "qdhcp-%s" % network_id

        # get_instance_cmd = "ovs-vsctl list-ports br-ex | grep ^eth || ovs-appctl bond/show bond1 | sed -e '/active slave mac:/!d' -e 's/.*active slave mac: .*\(\(eth.\)\).*/\1/'"

        # Tcpdump command for capturing compute ovs north bound
        get_ovs_northbound_interface_cmd = "interface=$(ovs-vsctl list-ports br-ex | grep ^eth || ovs-appctl bond/show bond1 | awk '/active slave mac/ {print $4}'|awk -F\( '{print $2}'|sed -e 's#)##g')"
        tcpdump_compute_ovs_interface_cmd = "%s; timeout 9 tcpdump -enni $interface '((ether src %s and ether dst %s and icmp))'" % (
            get_ovs_northbound_interface_cmd, dhcp_namespace_mac, instance_mac)

        # Tcpdump command for capturing network node ovs north bound
        tcpdump_network_ovs_interface_cmd = "%s; timeout 7 tcpdump -enni $interface '((ether src %s and ether dst %s and icmp))'" % (
            get_ovs_northbound_interface_cmd, dhcp_namespace_mac, instance_mac)

        # Tcpdump command for tap interface
        tcpdump_tap_interface_cmd = "timeout 13 tcpdump -enni tap%s '((ether src %s and ether dst %s and icmp))'" % (
            ovs_port, dhcp_namespace_mac, instance_mac)

        # Tcpdump command for qvo interface
        tcpdump_qvo_interface_cmd = "timeout 11 tcpdump -enni qvo%s '((ether src %s and ether dst %s and icmp))'" % (
            ovs_port, dhcp_namespace_mac, instance_mac)

        # Ping Command
        ping_instance_cmd = "ip netns exec %s ping -c 5 %s" % (dhcp_namespace, instance_ip)

        # Tcpdump thread for OVS Bridge Interface
        tcpdump_compute_ovs_thread = threading.Thread(name='Compute Node OVS Thread', target=self.get_tcpdump,
                                                      args=(compute_node, tcpdump_compute_ovs_interface_cmd,
                                                            'Compute Node OVS North Bound Interface TCPDUMP: [%s] tcpdump -enni {eth1,eth2} \'((ether src %s and ether dst %s and icmp))\'' % (
                                                                compute_node, dhcp_namespace_mac, instance_mac)))

        # Tcpdump thread for OVS Bridge Interface
        tcpdump_network_ovs_thread = threading.Thread(name='Network Node OVS Thread', target=self.get_tcpdump,
                                                      args=(net_node, tcpdump_network_ovs_interface_cmd,
                                                            'Network Node OVS North Bound Interface TCPDUMP: [%s] tcpdump -enni {eth1,eth2} \'((ether src %s and ether dst %s and icmp))\'' % (
                                                                net_node, dhcp_namespace_mac, instance_mac)))

        # Tcpdump Thread for Tap interface
        tcpdump_tap_interface_thread = threading.Thread(name="Tap Interface Thread", target=self.get_tcpdump,
                                                        args=(compute_node, tcpdump_tap_interface_cmd,
                                                              'TAP Interface TCPDUMP: [%s] %s' % (
                                                                  compute_node, tcpdump_tap_interface_cmd)))

        # Tcpdump thread for QVO Interface
        tcpdump_qvo_interface_thread = threading.Thread(name='QVO Interface Thread', target=self.get_tcpdump, args=(
            compute_node, tcpdump_qvo_interface_cmd,
            "QVO Interface TCPDUMP: [%s] %s" % (compute_node, tcpdump_qvo_interface_cmd)))

        # Ping Thread
        ping_cmd_thread = threading.Thread(name='Ping Command Thread', target=self.get_tcpdump,
                                           args=(net_node, ping_instance_cmd,
                                                 'Ping Test for Tcpdump: [%s] %s' % (net_node, ping_instance_cmd)))

        try:

            tcpdump_network_ovs_thread.start()
            tcpdump_compute_ovs_thread.start()

            tcpdump_tap_interface_thread.start()
            tcpdump_qvo_interface_thread.start()
            sleep(2)
            ping_cmd_thread.start()
        except (KeyboardInterrupt, SystemExit):
            print "Recieved shutdown signal"
            tcpdump_tap_interface_thread.join(0)
            tcpdump_compute_ovs_thread.join(0)
            tcpdump_network_ovs_thread.join(0)
            tcpdump_qvo_interface_thread.join(0)
            ping_cmd_thread.join(0)

    def get_tcpdump(self, host, command, header):
        """Perform TCPDUMP on Compute Node and Capture it's data"""

        runner = ansible.runner.Runner(
            module_name='shell',
            module_args=command,
            pattern=host,
        )

        results = runner.run()

        # Print Error For Host
        for node in results['dark']:
            dark_table = PrettyTable(["Failed to Contact Host [%s] with error" % node])
            dark_table.align["Failed to Contact Host [%s] with error" % node] = "l"
            dark_table.add_row([results['dark'][node]['msg']])
            print dark_table

        # Print Results of STDOUT
        for node in results['contacted']:
            lines = results['contacted'][node]['stdout'].split('\n')
            results_table = PrettyTable([header])
            # if 'Ping' in header:
            results_table.align[header] = "l"
            for i in lines:
                results_table.add_row([i])
            print results_table


if __name__ == '__main__':
    # ensure environment has necessary items to authenticate
    for key in ['OS_TENANT_NAME', 'OS_USERNAME', 'OS_PASSWORD',
                'OS_AUTH_URL']:
        if key not in os.environ.keys():
            exit(1)
    parser = argparse.ArgumentParser()
    parser.add_argument("uuid", help="instance uuid")
    parser.add_argument('-d', '--debug', dest='debug', action='store_true', help="Print Debug")
    parser.add_argument('-k', '--insecure', action='store_true',
                        default=False, help='allow connections to SSL sites '
                                            'without certs')
    parser.add_argument('--ovs-data', dest='ovs_data', action='store_true', help="Grab OVS data from compute node")
    parser.add_argument('--dhcp-logs', '--dhcp-data', '--logs', dest='dhcp_logs', action='store_true',
                        help="Grab DHCP Logs for Instance MAC")
    parser.add_argument('--dhcp-ping-test', '--ping-test', dest='dhcp_ping_test', action='store_true',
                        help="Performs Ping Test inside DHCP Namespace")
    parser.add_argument('--capture-tcpdump', dest='capture_tcpdump', action='store_true',
                        help="Runs TCP Dump on Compute node and captures it's output. This takes about 10 seconds to perform")

    args = parser.parse_args()
    os_args = dict(auth_url=os.environ.get('OS_AUTH_URL'),
                   username=os.environ.get('OS_USERNAME'),
                   tenant_name=os.environ.get('OS_TENANT_NAME'),
                   password=os.environ.get('OS_PASSWORD'),
                   endpoint_type=os.environ.get('OS_ENDPOINT_TYPE',
                                                'publicURL'),
                   insecure=args.insecure,
                   debug=args.debug,
                   ovs_data=args.ovs_data,
                   dhcp_logs=args.dhcp_logs,
                   dhcp_ping_test=args.dhcp_ping_test,
                   capture_tcpdump=args.capture_tcpdump)

    nova_instance = NovaInstance(**os_args)
    nova_instance.print_instance_info(args.uuid)
