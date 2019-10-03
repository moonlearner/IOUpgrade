from pexpect.popen_spawn import PopenSpawn
import pexpect
from datetime import datetime
import requests
import urllib3
urllib3.disable_warnings()
import multiprocessing
import itertools
import quantaskylake
from esxi import ESXi
import time
import ipaddress
import badtime
import glob
import os
import sys
from netmiko import ConnectHandler


def getNICInterfaces():
    interfacelist = []
    if 'win' in sys.platform:
        # Start route print
        session = PopenSpawn('route print')
        # Get output from session
        output = session.read(2000)
        # Convert to utf-8
        output = output.decode('utf-8')
        # Split by =====
        output = output.split('===========================================================================')
        if len(output) < 4:
            raise ValueError('Route print returned incorrect output.')
        # Get Interface Line and parse output
        for line in output:
            # Go to line with Interface List string
            if 'Interface List' in line:
                # Split everything by newline
                splitline = line.splitlines()
                # Remove lines without ...
                # https://stackoverflow.com/questions/3416401/removing-elements-from-a-list-containing-specific-characters
                splitline = [x for x in splitline if "..." in x]
                # Get NIC Number and append to interfacelist
                for nic in splitline:
                    # Get the index number from line
                    index = nic[:3].lstrip()
                    # Once list gets to loopback, break
                    if index is '1':
                        break
                    # Add index to list
                    interfacelist.append(nic[:3].lstrip())
    # Assuming everything else is linux
    else:
        session = pexpect.spawn('ls /sys/class/net')
        output = session.read(2000)
        output = output.decode('utf-8')
        output = output.split()
        for item in output:
            if 'lo' not in item:
                interfacelist.append(item)
    return interfacelist

def getIPv6Neighbors(interface = None):
    # Get Interfaces if interface is None, otherwise program Interface from input
    NICs = []
    if interface is None:
        NICs = getNICInterfaces()
    else:
        NICs.append(str(interface))
    # Send link-local ping to each NIC
    print('Discovering IPv6 devices on the following interfaces:')
    print(*NICs)
    # Set and start ping threads
    hosts = []
    if 'win' in sys.platform:
        for NIC in NICs:
            host = 'ff02::1%' + NIC
            hosts.append((host,))
        pool = multiprocessing.Pool(processes=10)
        pool.starmap(ping, hosts)
        pool.close()
        pool.join()
        # Get IPv6 Neighbors for each NIC
        IPv6Devices = []
        for NIC in NICs:
            print('Getting IPv6 Neighbors for NIC#' + NIC)
            # Get output from netsh command
            session = PopenSpawn('netsh interface ipv6 show neighbors ' + NIC)
            output = session.read(200000)
            # Split output by newlines
            splitline = output.splitlines()
            # Remove lines without ...
            # https://stackoverflow.com/questions/3416401/removing-elements-from-a-list-containing-specific-characters
            splitline = [x for x in splitline if b'fe80::' in x]
            # Create IPv6 Regular Expression
            for line in splitline:
                # Get IPv6 Device from line
                IPv6Device = line[:44].rstrip().decode("utf-8") + '%' + NIC
                print(IPv6Device)
                IPv6Devices.append(IPv6Device)
    # Assume everything else is linux platform
    else:
        IPv6Devices = []
        for NIC in NICs:
            session = pexpect.spawn('ping6 -c 2 ff02::1%' + str(NIC))
            session.wait()
            output = session.read(20000)
            output = output.decode('utf-8')
            output = output.splitlines()
            for line in output:
                if line.startswith("64 bytes from fe80:"):
                    IPv6Devices.append(line.split()[3][:-1] + '%' + str(NIC))
    return IPv6Devices

def ping(host):
    # For Windows, IPv6 neighbors can be discovered by sending a link-local packet across the whole L2 network.
    # Response time should be <1ms since the toolkit needs to physically be near the nodes.
    session = PopenSpawn('ping -w 1 -n 8 ' + host)
    output = session.read(2000)
    output = output.decode('utf-8')
    print(output)
    return output

def discoverNodes(IPv6nodes, usernames=['admin'], passwords=['cmb9.admin']):
    print('Starting Quanta Discovery against ' + str(len(IPv6nodes)) + ' IPv6 Devices')
    time.sleep(5)

    # Create all combinations of commands
    tuples = []
    for combination in itertools.product(IPv6nodes, usernames, passwords):
        tuples.append(combination)

    pool = multiprocessing.Pool(processes=30)
    results = pool.starmap(discoverNodeType, tuples)
    pool.close()
    pool.join()
    # https://stackoverflow.com/questions/16096754/remove-none-value-from-a-list-without-removing-the-0-value
    results = [x for x in results if x is not None]
    # Add forwarding ports for linux applications that do not support IPv6 Link-Local Addressing
    return results

def discoverNodeType(IPv6node, username, password):
    # Output the address, username and password
    temp = IPv6node + ' ' + username + ' ' + password
    print('Start  ' + temp)

    # Set the address
    # Also %25 has to be used for URLs instead of % due to URL Encoding rules.
    redfishapi = 'https://[' + IPv6node.replace('%','%25') + ']/redfish/v1/'
    # Have to remove the lin-local zone ID for correct curl command
    redfishheader = {
        'Content-Type': 'application/json',
        'User-Agent': 'curl/7.54.0',
        'Host': '[' + IPv6node.split('%')[0] + ']'
    }

    # Attempt to connect
    try:
        session = requests.get(redfishapi + 'Systems', auth=(username, password), verify=False,
                               headers=redfishheader, timeout=30)
    except:
        print('Finish ' + temp)
        return None
    # If Session is not good, return nothing
    if not session.ok:
        print('Finish ' + temp)
        return None

    try:
        # Attempt to decode JSON data
        j = session.json()
    except:
        # If return data isn't JSON, return nothing.
        return None
    print('Data   ' + IPv6node + ' ' + str(j))

    ''' Get first member '''
    # Attempt to get Members
    try:
        members = j['Members']
    except:
        return None

    # Loop through members and get first member
    for member in members:
        try:
            redfishapi = 'https://[' + IPv6node.replace('%','%25') + ']' + member['@odata.id']
            break
        except:
            # Return nothing if @odata.id key doesn't exist
            return None

    ''' Discover which type of node this is '''
    # Try to get first member details
    try:
        session = requests.get(redfishapi, auth=(username, password), verify=False,
                               headers=redfishheader, timeout=30)
    except:
        print('Finish ' + temp)
        return None
    # If Session is not good, return nothing
    if not session.ok:
        print('Finish ' + temp)
        return None

    # Attempt to decode JSON data
    try:
        j = session.json()
    except:
        # If return data isn't JSON, return nothing.
        print('Finish ' + temp)
        return None

    print('Data   ' + IPv6node + ' ' + str(j))

    # Attempt to get SKU Data
    try:
        SKU = j['SKU']
    except:
        print('Finish ' + temp)
        return None

    # Decode which node this is
    # If its a D52B Series, return Skylake Server
    if 'DS120' in SKU:
        print('Finish ' + temp)
        return quantaskylake.DS120(IPv6node, username, password)
    elif 'DS220' in SKU:
        print('Finish ' + temp)
        return quantaskylake.DS220(IPv6node, username, password)
    elif 'DS225' in SKU:
        print('Finish ' + temp)
        return quantaskylake.DS225(IPv6node, username, password)
    elif 'DS240' in SKU:
        print('Finish ' + temp)
        return quantaskylake.DS240(IPv6node, username, password)
    elif 'D52BV' in SKU:
        print('Finish ' + temp)
        return quantaskylake.D52BV(IPv6node, username, password)
    elif 'D52B' in SKU:
        print('Finish ' + temp)
        return quantaskylake.D52B(IPv6node, username, password)
    elif 'Q72D' in SKU:
        print('Finish ' + temp)
        return quantaskylake.Q72D(IPv6node, username, password)
    else:
        # If it doesn't match anything, return nothing
        print('Finish ' + temp)
        return None

def discoverSwitches(IPv6Addresses, usernames=['admin'], passwords=['Passw0rd!']):
    print('Starting Switch Discovery against ' + str(len(IPv6Addresses)) + ' IPv6 Devices')
    # Create all combinations of commands
    tuples = []
    for combination in itertools.product(IPv6Addresses, usernames, passwords):
        tuples.append(combination)
    pool = multiprocessing.Pool(processes=30)
    results = pool.starmap(discoverSwitchType, tuples)
    pool.close()
    pool.join()
    # https://stackoverflow.com/questions/16096754/remove-none-value-from-a-list-without-removing-the-0-value
    results = [x for x in results if x is not None]
    # Add forwarding ports for linux applications that do not support IPv6 Link-Local Addressing
    return results

def discoverSwitchType(IPv6Address, username, password):
    # Output the address, username and password
    temp = IPv6Address + ' ' + username + ' ' + password
    print('Start  ' + temp)

    # SSH Into Switch as generic SSH device
    try:
        net_connect = ConnectHandler(device_type='terminal_server', ip=IPv6Address, username=username, password=password, timeout=15)
    except:
        # If we failed to connect, return nothing
        print('Finish ' + temp)
        return None

    # Check for Cisco Nexus switches and Brocade FOS
    cmds = ["show version", "chassisshow"]
    for cmd in cmds:
        try:
            output = net_connect.send_command(cmd)
        except:
            output = ''
        # If Nexus 3048 is in output, return Nexus Object
        if 'Nexus 3048 Chassis' in output:
            print('Data   ' + IPv6Address + ' Found a Nexus3048 Switch')
            net_connect.disconnect()
            return cisconexus.Nexus3048(IPv6Address, username, password)
        # If the 9k YC switch is in the output, return 9k YC object.
        elif '93180YC-EX ' in output:
            print('Data   ' + IPv6Address + ' Found a Nexus93180YC-EX Switch')
            net_connect.disconnect()
            return cisconexus.Nexus93180YCEX(IPv6Address, username, password)
        # If the 9k LC switch is in the output, return 9k LC object.
        elif '93180LC-EX ' in output:
            print('Data   ' + IPv6Address + ' Found a Nexus93180LC-EX Switch')
            net_connect.disconnect()
            return cisconexus.Nexus93180LCEX(IPv6Address, username, password)
        # If the part number for a G620 is found, return G620 Object
        elif 'BROCAD0000G62' in output:
            print('Data   ' + IPv6Address + ' Found a G620 Switch')
            net_connect.disconnect()
            return brocadefc.G620(IPv6Address, username, password)

def discover(nodesnum = 0, usernames = ['admin'], passwords = ['cmb9.admin']):
    nodesnum = int(nodesnum)
    # Get the nodes
    print('I\'m going to use all your NIC interfaces to detect IPv6 devices.')
    if nodesnum > 0:
        input('Hit enter to continue!')

    while True:
        nodes = None
        # Get Any Nodes
        nodes = discoverNodes(getIPv6Neighbors(), usernames, passwords)

        print('\nGetting IPv4 Addresses via IPv6 Link-Local Addresses')
        for node in nodes:
            node.getIPv4Address()
        print(' ')

        # Nodesnum override I.E. Just return any discovered node
        if nodesnum < 1:
            return nodes

        # Let the user know about the detected nodes
        if len(nodes) < 1:
            input('Uffff.... I wasn\'t able to detect any nodes man. Sorry about that. Hit enter to try again.')
        elif len(nodes) != int(nodesnum):
            input('Uh oh, I have detected a ' + str(len(
                nodes)) + ' node(s) in the rack, instead of ' + str(nodesnum) + '.\nPlease make sure all the BMC connections are connected or disconnected on the same flat network. Hit enter to try again.')
        else:
            input('Perfect! I have detected ' + str(len(nodes)) + '!!! Hit enter to continue!')
            return nodes
'''
test = discoverType('fe80::aa1e:84ff:fea5:339b%enp0s8', 'admin', 'cmb9.admin')

test = discoverType('fe80::aa1e:84ff:fea5:32c9%13', 'admin', 'cmb9.admin')
print(test)

testfunc()

test = discoverSwitchType('fe80::a23d:6fff:fefe:2b40%13', 'admin', 'Passw0rd!')
print(test)
'''

def main():
    test = discoverSwitches(getIPv6Neighbors(), ['admin'], ['Passw0rd!'])
    print(test)

if __name__ == "__main__":
    count = 0
    main()
