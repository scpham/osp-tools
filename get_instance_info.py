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
from copy import deepcopy

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
        self._neutron = neutron_client.Client(**args)
        self._glance = glance_client('2', glance_endpoint, token=self._keystone.auth_token)
        self.debug = args.pop('debug')
        if self.debug:
            LOG.setLevel(logging.DEBUG)
        self.ovs_data = args.pop('ovs_data')
        self.dhcp_logs = args.pop('dhcp_logs')
        self.dhcp_ping_test = args.pop('dhcp_ping_test')
        nova_args = deepcopy(args)
        self._nova = nova_client.Client('2', nova_args.pop('username'),
                                        nova_args.pop('password'),
                                        nova_args.pop('tenant_name'), **nova_args)

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
            agents_port[port['binding:host_id'].split('.')[0]] = port['fixed_ips'][0]['ip_address']

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

        image = self._glance.images.get(image_id)
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
                if instance[field] == "Image Not Found":
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

        for port in ports:
            neutron_pt = PrettyTable(['Interface', 'Data'])
            neutron_pt.align['Data'] = "l"
            ovs_port = port['id'][:11]
            neutron_pt.add_row(['Network ID', port['network_id']])
            neutron_pt.add_row(['Subnet ID', port['fixed_ips'][0]['subnet_id']])
            neutron_pt.add_row(['IP Address', port['fixed_ips'][0]['ip_address']])
            neutron_pt.add_row(['MAC Address', port['mac_address']])

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
                dhcp_agents_line.append("%s (%s)" % (agent, dhcp_agent_ports[agent]))
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
                self.get_dhcp_logs(network_nodes=dhcp_agent_ports.keys(), mac=port['mac_address'],
                                   network_id=port['network_id'])

            if self.dhcp_ping_test and dhcp_agent_ports.keys():
                self.get_dhcp_ping_test(network_node_ports=dhcp_agent_ports, network_id=port['network_id'],
                                        instance_ip=port['fixed_ips'][0]['ip_address'], router_ip=router_ip,
                                        is_pingable=is_pingable)

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

        dhcp_agent_ips = network_node_ports.values()
        dhcp_namespace = "qdhcp-%s" % network_id

        ip_to_agent = {}
        # TODO: Do this within 1 loop
        for agent in network_node_ports.keys():
            ip_to_agent[network_node_ports[agent]] = agent

        net_node = None
        agent_ip = None
        for agent in network_node_ports.keys():
            ip = dhcp_agent_ips.pop()
            if network_node_ports[agent] != ip:
                net_node = agent
                agent_ip = ip
                break

        dhcp_ping_test_command = "( echo '****** Ping Test Between Net Nodes inside namespace [%s (%s) -> %s (%s)] ******'; ip netns exec %s ping -c 1 %s )" \
                                 % (net_node, network_node_ports[net_node],
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
    parser.add_argument('--dhcp-logs', '--dhcp-data', dest='dhcp_logs', action='store_true',
                        help="Grab DHCP Logs for Instance MAC")
    parser.add_argument('--dhcp-ping-test', '--ping-test', dest='dhcp_ping_test', action='store_true',
                        help="Performs Ping Test inside DHCP Namespace")

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
                   dhcp_ping_test=args.dhcp_ping_test)

    nova_instance = NovaInstance(**os_args)
    nova_instance.print_instance_info(args.uuid)

