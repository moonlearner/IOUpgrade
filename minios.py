import time
import re
from prettytable import PrettyTable
import collections
import json
import glob
import os
import subprocess


def getminiosiso():
    return "minios_20190409.iso"

def pcidiscoverwrapper(minios_instance):
    minios_instance.discoverPCIDevices()
    return minios_instance

class minios(object):
    def __init__(self, node):
        self.node = node
        self.pcidevices = None
        self.user = "ubuntu"
        self.password = "\n"
        self.hostname = "ubuntu"
        self.prompt = self.user + '@' + self.hostname + ':'
        self.attempts = 20
        self.loggedin = False
        self.PCITypes = ['VGA compatible controller', '3D controller', 'Ethernet', 'Fibre', 'Serial Attached SCSI', 'RAID', 'Non-Volatile memory controller']
        # PCI Devices in Dictionary Form
        self.PCIDevices = {}
        self.lshwdict = {}

        self.filename = ""

    def login(self):
        # Hit enter to find out if console is alive
        count = 0
        while count < self.attempts:
            self.node.SOLActivate()
            try:
                self.node.SOLSession.sendline('\n')
            except:
                pass
            try:
                result = self.node.SOLSession.expect(['login:', self.prompt], timeout=10)
            except Exception as e:
                print(self.node.host + ' Attempt#' + str(count) + ' MiniOS console isn\'t ready yet.')
                time.sleep(60)
                count += 1
                continue

            # If the login screen is turned on, attempt to login
            if result == 0:
                self.node.SOLSession.sendline(self.user)
                try:
                    prompt = self.node.SOLSession.expect(['Password:'], timeout=120)
                    if prompt == 0:
                        self.node.SOLSession.sendline(self.password)
                        break
                    else:
                        raise Exception(self.node.host + ' MiniOS Console Password response isn\'t their.')
                except:
                    continue
            elif result == 1:
                break


        # Check if console is logged in
        while not self.loggedin:
            self.node.SOLSession.sendline('\n')
            print("Jenny: I come to here")
            try:
                result = self.node.SOLSession.expect(['login:', self.prompt], timeout=120)
            except Exception as e:
                print(self.node.host + ' MiniOS console Login response isn\'t their. Retrying')
                continue
            if result == 1:
                print(self.node.host + ' MiniOS console is logged in.')
                self.loggedin = True
            else:
                raise Exception(self.node.host + ' MiniOS Login Credentials Incorrect')

    def logout(self):
        self.node.SOLActivate()
        self.node.SOLSession.sendline('exit')
        self.node.SOLDeactivate()
        self.loggedin = False

    def checklogin(self):
        if self.loggedin is not True:
            raise Exception(self.node.host + ' MiniOS console is not logged in')

    def rawcommand(self, cmd, wait=1):
        self.checklogin()
        # Activate the session
        self.node.SOLActivate()
        # Send the line
        self.node.SOLSession.sendline(cmd)
        time.sleep(wait)
        self.node.SOLDeactivate()
        return self.node.SOLSession.read(20000)

    def apprun(self, cmd, interval=1):
        self.checklogin()
        # Activate the session
        count = 0
        while count < self.attempts:
            count += 1
            if self.node.SOLActivate() is None:
                time.sleep(5)
                continue
            else:
                break

        # Send the line initial cmd
        self.node.SOLSession.sendline(cmd)
        count = 0
        while count < self.attempts:
            count += 1
            try:
                self.node.SOLSession.send('\n')
            except:
                continue
            try:
                self.node.SOLSession.expect([self.prompt], timeout=interval)
                break
            except:
                # print(count)
                continue
        output = self.node.SOLSession.before
        self.node.SOLDeactivate()
        # Trim the output to only include output of app
        try:
            #output = output.split(cmd + '\r\n')[1]
            output = output.split(cmd + '\r\n')[1]
        except:
            pass
        return output

    def apprun2(self, cmd):
        result = subprocess.getoutput(cmd)
        #print(result)
        try:
            #output = result.split(cmd + '\r\n')[1]
            result = result.split(cmd + '\r\n')[1]
        except:
            pass
        return result


    def getlshw(self):
        output = self.apprun('sudo lshw', 15)
        temp_dict = self.list2dictionary(output)
        self.lshwdict = temp_dict

    def list2dictionary(self, input):
        lines = input.splitlines()
        master_dict = {}
        header = ['','','','','','','']
        for line in lines:
            if '=======' in line:
                continue
            data = line.split(': ')
            leftspace = len(data[0]) - len(data[0].lstrip())
            if len(data) == 1:
                header[int(leftspace/4)] = data[0].lstrip().rstrip()
                if leftspace == 0:
                    master_dict.update({data[0].lstrip().rstrip() : None})
                continue

            if len(data) == 2:
                json_string = '{'
                for count in range(int(leftspace/4)):
                    json_string = json_string +  '"' + header[count] + '":{'
                json_string = json_string + '"' + data[0].lstrip().rstrip() + '":"' + data[1] + '"'
                for count in range(int(leftspace/4)):
                    json_string = json_string + "}"
                json_string = json_string + '}'
                temp_dict = json.loads(json_string)
                self.updatedict(master_dict, temp_dict)
        return master_dict

    # https://stackoverflow.com/questions/40648302/how-to-update-deeply-nested-dictionaries-of-an-unknown-state
    def updatedict(self, a, b):
        for key in b:
            if not key in a or type(a[key]) != dict or type(b[key]) != dict:
                a[key] = b[key]
            else:
                self.updatedict(a[key], b[key])

    def discoverPCIDevices(self):
        print(self.node.host + 'Jenny Discovering PCI Devices')
        cmdprep = 'sudo lspci -mm | grep --color=never '
        for pcitype in self.PCITypes:
            cmd = cmdprep + "\"" + pcitype + "\""
            print("Jenny add cmd print: ", cmd)
            continue_status = True
            while continue_status:
                try:
                    output = self.apprun(cmd)
                    output = output.splitlines()
                    continue_status = False
                except:
                    continue_status = True

            # Get list of available PCI Locations
            busdevlist = []
            for line in output:
                try:
                    busdevID = line.split()[0].split('.')[0]
                    busdevlist.append(busdevID)
                except:
                    pass

            # Remove duplicate entries
            busdevlist = list(set(busdevlist))

            # Get details about the device (only one, ignore function device)
            busdevdetails = []
            for item in busdevlist:
                for line in output:
                    if item in line:
                        busdevdetails.append(line)
                        break

            # Initialize the PCI Devices
            for line in busdevdetails:
                busdevID = line.split()[0].split('.')[0]
                if 'Ethernet' in line:
                    if 'Mellanox' in line:
                        print(self.node.host + ' Found a Mellanox Ethernet Card')
                        self.PCIDevices.update({busdevID: mellanoxNIC(self, busdevID)})
                    # For some reason, there is a dummy device within the Intel NICs that has DID 37cc. Ignoring it.
                    elif 'Intel' in line and '37cc' not in line:
                        print(self.node.host + ' Found a Intel Ethernet Card')
                        self.PCIDevices.update({busdevID: intelNIC(self, busdevID)})
                elif 'Fibre' in line:
                    if 'Emulex' in line:
                        print(self.node.host + ' Found a Emulex HBA')
                        # Jenny Modified on 9/19/2019
                        #self.PCIDevices.update({busdevID: emulexHBA(self, busdevID)})
                elif 'Serial Attached SCSI' in line:
                    if 'LSI' in line:
                        print(self.node.host + ' Found a LSI SAS Card')
                        self.PCIDevices.update({busdevID: LSISAS3Controller(self, busdevID)})
                elif 'RAID' in line:
                    if 'LSI' in line:
                        print(self.node.host + ' Found a LSI RAID Card')
                        self.PCIDevices.update({busdevID: AVAGORAIDController(self, busdevID)})
                elif 'VGA compatible controller' in line or '3D controller' in line:
                    if 'NVIDIA' in line:
                        print(self.node.host + ' Found a NVIDIA GPU')
                        self.PCIDevices.update({busdevID: NVIDIAGPUController(self, busdevID)})
                elif 'Non-Volatile memory controller' in line:
                    if 'Intel' in line:
                        print(self.node.host + ' Found a Intel NVMe Device')
                        self.PCIDevices.update({busdevID: IntelNVMeDevice(self, busdevID)})

        '''
        # Remove devices with the same Serial Number
        temp_PCIDevices = {}
        for key, value in self.PCIDevices.items():
            if "N/A" in value.serial:
                temp_PCIDevices.update({key:value})
                continue
            else:
                existed = False
                for tempkey, tempvalue in temp_PCIDevices.items():
                    if value.serial == tempvalue.serial:
                        existed = True
                if existed:
                    continue
                else:
                    temp_PCIDevices.update({key:value})
        self.PCIDevices = temp_PCIDevices
        '''
        return self.PCIDevices.keys()

    # Jenny Modified on 9/19/2019
    def discoverPCIDevices2(self):
        print(self.node.host + 'Jenny Discovering PCI Devices')
        cmdprep = 'sudo lspci -mm | grep --color=never '
        for pcitype in self.PCITypes:
            cmd = cmdprep + "\"" + pcitype + "\""
            print("Jenny add cmd print: ", cmd)
            output = self.apprun2(cmd)
            output = output.splitlines()

            # Get list of available PCI Locations
            busdevlist = []
            for line in output:
                try:
                    busdevID = line.split()[0].split('.')[0]
                    busdevlist.append(busdevID)
                except:
                    pass

            # Remove duplicate entries
            busdevlist = list(set(busdevlist))

            # Get details about the device (only one, ignore function device)
            busdevdetails = []
            for item in busdevlist:
                for line in output:
                    if item in line:
                        busdevdetails.append(line)
                        break

            # Initialize the PCI Devices
            for line in busdevdetails:
                busdevID = line.split()[0].split('.')[0]
                if 'Ethernet' in line:
                    if 'Mellanox' in line:
                        print(self.node.host + ' Found a Mellanox Ethernet Card')
                        self.PCIDevices.update({busdevID: mellanoxNIC(self, busdevID)})
                    # For some reason, there is a dummy device within the Intel NICs that has DID 37cc. Ignoring it.
                    elif 'Intel' in line and '37cc' not in line:
                        print(self.node.host + ' Found a Intel Ethernet Card')
                        self.PCIDevices.update({busdevID: intelNIC(self, busdevID)})
                elif 'Fibre' in line:
                    if 'Emulex' in line:
                        print(self.node.host + ' Found a Emulex HBA')
                        # Jenny Modified on 9/19/2019
                        self.PCIDevices.update({busdevID: emulexHBA(self, busdevID)})
                elif 'Serial Attached SCSI' in line:
                    if 'LSI' in line:
                        print(self.node.host + ' Found a LSI SAS Card')
                        # Jenny Modified on 9/19/2019
                        self.PCIDevices.update({busdevID: LSISAS3Controller(self, busdevID)})
                elif 'RAID' in line:
                    if 'LSI' in line:
                        print(self.node.host + ' Found a LSI RAID Card')
                        self.PCIDevices.update({busdevID: AVAGORAIDController(self, busdevID)})
                elif 'VGA compatible controller' in line or '3D controller' in line:
                    if 'NVIDIA' in line:
                        print(self.node.host + ' Found a NVIDIA GPU')
                        self.PCIDevices.update({busdevID: NVIDIAGPUController(self, busdevID)})
                elif 'Non-Volatile memory controller' in line:
                    if 'Intel' in line:
                        print(self.node.host + ' Found a Intel NVMe Device')
                        self.PCIDevices.update({busdevID: IntelNVMeDevice(self, busdevID)})

        '''
        # Remove devices with the same Serial Number
        temp_PCIDevices = {}
        for key, value in self.PCIDevices.items():
            if "N/A" in value.serial:
                temp_PCIDevices.update({key:value})
                continue
            else:
                existed = False
                for tempkey, tempvalue in temp_PCIDevices.items():
                    if value.serial == tempvalue.serial:
                        existed = True
                if existed:
                    continue
                else:
                    temp_PCIDevices.update({key:value})
        self.PCIDevices = temp_PCIDevices
        '''
        return self.PCIDevices.keys()


    def printPCIDevices(self):
        print(self.node.host + " Discovered the following PCI Devices:")
        t = PrettyTable(["PCI_Address", "Name", "Firmware", "Serial", "VID", "DVID", "SVID", "SSID"])
        t.sortby = "PCI_Address"
        for device, pciclass in self.PCIDevices.items():
            print(self.node.host + ' Discovered PCI Device: ' + device + ' ' + pciclass.name + ' v.' + pciclass.firmware)
            #print(pciclass)
            t.add_row([device, pciclass.name, pciclass.firmware, pciclass.serial, pciclass.VID, pciclass.DVID, pciclass.SVID, pciclass.SSID])
        print(t)
        return t

    def printPCIDevices2(self):
        print(self.node.host + " Discovered the following PCI Devices:")
        t = PrettyTable(["PCI_Address", "Name", "Firmware", "Serial", "VID", "DVID", "SVID", "SSID"])
        t.sortby = "PCI_Address"
        for device, pciclass in self.PCIDevices.items():
            if (pciclass.name.find("LSI_Quanta_Mezz") != -1):
                pciclass.name = pciclass.name.replace("LSI_Quanta_Mezz", "LSI_QS3216")

            print(
                self.node.host + ' Discovered PCI Device: ' + device + ' ' + pciclass.name + ' v.' + pciclass.firmware)
            # print(pciclass)
            t.add_row(
                [device, pciclass.name, pciclass.firmware, pciclass.serial, pciclass.VID, pciclass.DVID, pciclass.SVID,
                 pciclass.SSID])
        print(t)
        return self.PCIDevices


    def discoverNewestFile(self, filepath):
        print(self.node.host + ' Discovering Newest Firmware File ' + filepath)
        # Get the latest file ina folder
        #cmd = 'ls -tc ' + filepath + ' | head -1'
        # Jenny Modified on 9/30/2019
        #cmd = 'ls ' + filepath + ' | sort -r | head -n1'
        cmd = 'ls ' + filepath + ' | head -n1'
        print("The cmd is: " + cmd)
        # Jenny Modified on 9/19/2019
        #output = self.apprun(cmd)
        output = self.apprun2(cmd)
        #output = self.rawcommand(cmd)

        if (filepath.find("Intel") != -1):
            #output = output.split('\r\n')[1]
            output = output.split('\r\n')[0]

        #output = output.splitlines()
        #for Line in output:
        #   print(Line)
        #for root, dirs, files in os.walk(filepath):
        #   for filename in files:
        #       print(filename)
        return output


    def dancePCIDevices(self):
        for device, pciclass in sorted(self.PCIDevices.items()):
            if isinstance(pciclass, NIC):
                for MAC in pciclass.MACs:
                    print(self.node.host + ' Blinking ' + MAC + ' on ' + device + ' ' + pciclass.name)
                    pciclass.blinkLED(MAC, True)
                    time.sleep(5)
                    pciclass.blinkLED(MAC, False)
            elif isinstance(pciclass, emulexHBA):
                for WWN in pciclass.WWNs:
                    print(self.node.host + ' Blinking ' + WWN + ' on ' + device + ' ' + pciclass.name)
                    pciclass.blinkLED(WWN, True)
                    time.sleep(5)
                    pciclass.blinkLED(WWN, False)

    def sendpingstorm(self):
        for device, pciclass in self.PCIDevices.items():
            if isinstance(pciclass, NIC):
                print(self.node.host + ' Sending Ping Storm via ' + pciclass.name)
                pciclass.linklocalping6()

class pcidevice(object):
    def __init__(self, minios_instance, pciloc):
        self.minios = minios_instance
        self.busdevID = str(pciloc)
        self.classID = None
        # Vendor ID
        self.VID = None
        # Device ID
        self.DVID = None
        # Subsystem Vendor ID
        self.SVID = None
        # Subsystem ID
        self.SSID = None
        # Name of Device
        self.name = None
        # Firmware of PCI Device
        self.firmware = None
        # Serial number of PCI Device
        self.serial = "N/A"
        # Get the PCIIDs
        self.getPCIIDs()
        # Set the attempts
        self.attempts = int(5)

    def getPCIIDs(self):
        cmd = 'sudo lspci -nm | grep --color=never ' + self.busdevID
        #output = self.minios.apprun(cmd)
        # Jenny Modified on 9/19/2019
        output = self.minios.apprun2(cmd)
        output = output.splitlines()
        for line in output:
            # If the line of output has the real output and not the cmd input, extract details about PCI device
            if self.busdevID in line and cmd not in line:
                line = line.replace('"', '')
                line = line.split()
                temp = []
                for word in line:
                    if '-' not in word:
                        temp.append(word)
                self.classID = temp[1]
                self.VID = temp[2]
                self.DVID = temp[3]
                try:
                    self.SVID = temp[4]
                except:
                    pass
                try:
                    self.SSID = temp[5]
                except:
                    pass
                break

    def getName(self):
        print('This is a placeholder to populate NAME of card.')

    def getDetails(self):
        print('This is a placeholder to populate MAC/WWNS.')

    def blinkLED(self, port):
        print('This is a placeholder for blink function.')

    def flash(self, file):
        print('This is a placeholder for flashing function.')

class NIC(pcidevice):
    def __init__(self, minios_instance, pciloc):
        pcidevice.__init__(self, minios_instance, pciloc)
        self.MACs = []

    # Blink the LED based off the MAC
    def blinkLED(self, MAC, switch=True):
        # Make sure MAC has colins and is lower.case
        # https://stackoverflow.com/questions/9020843/how-to-convert-a-mac-number-to-mac-string
        MAC = ':'.join(format(s, '02x') for s in bytes.fromhex(MAC))
        # Get interfaces
        cmd = 'sudo ls /sys/class/net -1'
        # Jenny Modified on 9/19/2019
        #output = self.minios.apprun(cmd)
        output = self.minios.apprun2(cmd)
        output = output.splitlines()
        # Get MACs
        cmd = 'sudo cat /sys/class/net/*/address'
        output2 = self.minios.apprun(cmd)
        output2 = output2.splitlines()
        interface = None
        # Find interface based off MAC
        for interface_loop, MAC_loop in zip(output, output2):
            if MAC in MAC_loop:
                interface = interface_loop
        for line in output:
            if MAC in line:
                interface = line.split('Link')[0]
                break
        if interface is not None:
            if switch:
                cmd = 'sudo ethtool -p ' + interface + ' 600 &'
            else:
                cmd = 'sudo pkill -f ethtool'
            output = self.minios.apprun(cmd)
        else:
            print('This MAC doesn\'t exist.')
        return None

    def getinterfacenames(self, MACs=[]):
        # If MACs is empty, get MAC from cache
        if len(MACs) < 1:
            MACs = self.MACs

        temp_MACs = []
        for MAC in MACs:
             temp_MACs.append(':'.join(format(s, '02x') for s in bytes.fromhex(MAC)))

        # Get interfaces
        cmd = 'sudo ls /sys/class/net -1'
        # Jenny Modified on 9/19/2019
        #output = self.minios.apprun(cmd)
        output = self.minios.apprun2(cmd)
        output = output.splitlines()
        # Get MACs
        cmd = 'sudo cat /sys/class/net/*/address'
        # Jenny Modified on 9/19/2019
        #output2 = self.minios.apprun(cmd)
        output2 = self.minios.apprun2(cmd)
        output2 = output2.splitlines()
        temp_interfaces = []
        # Find interface based off MAC
        for interface_loop, MAC_loop in zip(output, output2):
            if MAC_loop in temp_MACs:
                temp_interfaces.append(interface_loop)

        return temp_interfaces

    def enable(self):
        interfaces = self.getinterfacenames()
        for interface in interfaces:
            cmd = "sudo ip link set " + interface + " up"
            # Jenny Modified on 9/19/2019
            #output = self.minios.apprun(cmd)
            output = self.minios.apprun2(cmd)

    def linklocalping6(self, address='ff02::1'):
        interfaces = self.getinterfacenames()
        for interface in interfaces:
            # Attempt to ping
            cmd = 'ping6 -c 2 '+ address +'%' + interface
            # Jenny Modified on 9/19/2019
            #output = self.minios.apprun(cmd)
            output = self.minios.apprun2(cmd)

class HBA(pcidevice):
    def __init__(self, minios_instance, pciloc):
        pcidevice.__init__(self, minios_instance, pciloc)
        self.WWNs = []

class SASController(pcidevice):
    def __init__(self, minios_instance, pciloc):
        pcidevice.__init__(self, minios_instance, pciloc)
        self.storagedevices = []

class GPUController(pcidevice):
    def __init__(self, minios_instance, pciloc):
        pcidevice.__init__(self, minios_instance, pciloc)

class NVMeDevice(pcidevice):
    def __init__(self, minios_instance, pciloc):
        pcidevice.__init__(self, minios_instance, pciloc)

class intelNIC(NIC):
    def __init__(self, minios_instance, pciloc):
        NIC.__init__(self, minios_instance, pciloc)
        self.bootutil64e = "sudo bootutil64e "
        self.nvmupdate64e = "sudo nvmupdate64e "
        self.nvmupdate64einventory = None
        count = 0
        while self.name is None or self.firmware is None:
            self.getDetails()
            if count > self.attempts:
                break
            else:
                count += 1
        if self.name is None:
            self.name = 'Unknown'
        if self.firmware is None:
            self.firmware = 'Unknown'
        # Enable Interface
        self.enable()

    def getDetails(self):
        # Run nvmupdate64e in Inventory Mode
        cmd = self.nvmupdate64e + '-i -l'
        # Jenny Modified on 9/19/2019
        #output = self.minios.apprun(cmd, 60)
        output = self.minios.apprun2(cmd)
        # nvmupdate64e outputs details very weirdly. Run the command in minios to find out for yourself
        output = output.splitlines()
        # Convert the HEX PCI Location to INTEGER PCI Location for nvmupdate64e
        location = str.format('{:02}',int(self.busdevID[:2], 16)) + ':' + str.format('{:02}',int(self.busdevID[-2:], 16))

        # Get PCI Location and Functions in nvmupdate64e userspace
        isentry = False
        pcifunctiontemp = None
        pcifunctiondictionarytemp = {}
        dictionarytemp = {}
        for line in output:
            # Only use the output from requested adapter
            if location in line and '[' in line:
                if pcifunctiontemp is not None:
                    pcifunctiondictionarytemp.update({pcifunctiontemp:dictionarytemp})
                pcifunctiontemp = line.split(': ')[0]
                dictionarytemp = {}
                # Add Device Name to Dictionary
                dictionarytemp.update({'Name':line.split(': ')[1].strip()})
                isentry = True
                continue
            # Ignore non-requested adapters
            elif location not in line and '[' in line:
                if pcifunctiontemp is not None:
                    pcifunctiondictionarytemp.update({pcifunctiontemp:dictionarytemp})
                isentry = False
                pcifunctiontemp = None
                dictionarytemp = {}
                continue
            # Add the keys to dictionary
            elif isentry is True:
                items = line.split(':')
                if len(items) < 2:
                    isentry = False
                    pcifunctiontemp = None
                    continue
                dictionarytemp.update({items[0].strip():items[1].strip()})

        # Add last dictionary if any
        if len(dictionarytemp.keys()) > 0:
            pcifunctiondictionarytemp.update({pcifunctiontemp: dictionarytemp})
        self.nvmupdate64einventory = pcifunctiondictionarytemp

        # Store the name of the Intel NIC
        for pcifunction in self.nvmupdate64einventory.keys():
            self.name = self.nvmupdate64einventory[pcifunction].get('Name').replace(' ', '_')
            self.firmware = self.nvmupdate64einventory[pcifunction].get('NVM Version',self.nvmupdate64einventory[pcifunction].get('EEPROM Version'))
            break

        # Store the MAC Addresses of the Intel NIC
        for pcifunction in self.nvmupdate64einventory.keys():
            self.MACs.append(self.nvmupdate64einventory[pcifunction].get('LAN MAC','000000000000'))

        return pcifunctiondictionarytemp

    def flash(self, file):
        # Clear Tmp Folder
        cmd = 'sudo rm -rf /tmp/*'
        # Jenny Modified on 9/19/2019
        #self.minios.apprun(cmd)
        self.minios.apprun2(cmd)
        if '.zip' in file:
            # Unzip file to /tmp
            print(self.minios.node.host + ' Unzipping ' + file)
            cmd = "sudo unzip \"" + file + "\" -d /tmp"
        else:
            # Extract File to /tmp
            print(self.minios.node.host + ' Extracting ' + file)
            cmd = 'sudo tar -xf \"' + file + '\" -C /tmp'
        # Jenny Modified on 9/19/2019
        #self.minios.apprun(cmd, 30)
        self.minios.apprun2(cmd)
        # 777 the tmp directory
        cmd = 'sudo chmod -R 777 /tmp'
        # Jenny Modified on 9/19/2019
        #self.minios.apprun(cmd)
        self.minios.apprun2(cmd)
        # Look for nvmeupdate64e file in /tmp directory
        cmd = 'find /tmp -name \"nvmupdate64e\"'
        # Jenny Modified on 9/19/2019
        #output = self.minios.apprun(cmd)
        output = self.minios.apprun2(cmd)
        output = output.splitlines()
        cmd = None
        for line in output:
            if 'nvmupdate64e' in line:
                cmd = 'sudo \"' + line.strip() + '\" -a \"' + line.strip('nvmupdate64e') + '\" -u -m ' + self.MACs[0] + ' -l -f'
                print(self.minios.node.host + ' Flashing ' + self.name)
                # Jenny Modified on 9/19/2019
                #output = self.minios.apprun(cmd, 60)
                output = self.minios.apprun2(cmd)
                if 'Reboot is required to complete the update process.' in output and 'Error' not in output:
                    print(self.minios.node.host + ' Successfully Flashed ' + self.name)
                    return True
        #print(self.minios.node.host + ' Failed to Flash ' + self.name + ' Debugging output: ' + output)
        print(self.minios.node.host + ' Failed to Flash ' + self.name + ' Debugging output: ')
        print(output)
        return False


class mellanoxNIC(NIC):
    def __init__(self, minios_instance, pciloc):
        NIC.__init__(self, minios_instance, pciloc)
        self.mlnxen = "sudo /etc/init.d/mlnx-en.d "
        self.mst = "sudo mst "
        self.flint = "sudo flint "
        self.mlxup = "sudo mlxup "
        self.mlxupdict = {}
        count = 0
        while self.name is None or self.firmware is None:
            self.getDetails()
            if count > self.attempts:
                break
            else:
                count += 1
        if self.name is None:
            self.name = 'Unknown'
        if self.firmware is None:
            self.firmware = 'Unknown'
        # Enable Interface
        self.enable()

    def loadDriver(self):
        # Check current status of driver
        cmd = self.mlnxen + 'status'
        # Jenny Modified on 9/19/2019
        #output = self.minios.apprun(cmd)
        output = self.minios.apprun2(cmd)
        '''
        if 'NIC Driver is not loaded' in output:
            # Start Drive if it's not loaded
            cmd = self.mlnxen + 'start & sleep 5'
            output = self.minios.apprun(cmd, 10)
            if 'Failed' in output:
                raise(ValueError(self.minios.node.host + ' Failed to load Mellanox Driver'))
        '''
        # Start Drive in any costs
        cmd = self.mlnxen + 'start & sleep 10'
        # Jenny Modified on 9/19/2019
        #output = self.minios.apprun(cmd, 30)
        output = self.minios.apprun2(cmd)
        if 'Failed' in output:
            raise (ValueError(self.minios.node.host + ' Failed to load Mellanox Driver'))
        return True

    def getDetails(self):
        # Try to load the driver
        try:
            self.loadDriver()
        except:
            print(self.minios.node.host + ' Failed to load Mellanox Driver')
            return None

        count = 0
        while count < 5:
            try:
                # Get the details about the Mellanox NICs
                cmd = self.mlxup + '--query --dev 0000:' + self.busdevID + '.0'
                # Jenny Modified on 9/19/2019
                #output = self.minios.apprun(cmd, 120)
                output = self.minios.apprun2(cmd)
                output = output.splitlines()
                dictionarytemp = {}
                # for line in output:
                for line in output:
                    line = line.split(': ')
                    if len(line) > 1:
                        dictionarytemp.update({line[0].strip():line[1].strip()})
                    else:
                        if '  FW  ' in line[0] or '  PXE  ' in line[0] or '  UEFI  ' in line[0]:
                            line = line[0].split()
                            if len(line) > 1:
                                dictionarytemp.update({line[0].strip():line[1].strip()})
                    # If a new device is found and if dictionarytemp has stuff, add it to the mlxupdict
                    if 'Device #' in line and len(dictionarytemp) > 0:
                        self.mlxupdict.update({dictionarytemp['PCI Device Name']:dictionarytemp})
                        dictionarytemp = {}

                # If there is anything in dictionarytemp, add it as well
                if len(dictionarytemp) > 0:
                    self.mlxupdict.update({dictionarytemp['PCI Device Name']: dictionarytemp})

                # Get the MAC Addresses
                for key, value in self.mlxupdict.items():
                    MAC = value['Base MAC']
                    # https://stackoverflow.com/questions/9020843/how-to-convert-a-mac-number-to-mac-string
                    MAC = ':'.join(format(s, '02x') for s in bytes.fromhex(MAC))[-17:]
                    # Get interfaces
                    cmd = 'sudo ls /sys/class/net -1'
                    # Jenny Modified on 9/19/2019
                    #output = self.minios.apprun(cmd)
                    output = self.minios.apprun2(cmd)
                    output = output.splitlines()
                    # Get MACs
                    cmd = 'sudo cat /sys/class/net/*/address'
                    # Jenny Modified on 9/19/2019
                    #output2 = self.minios.apprun(cmd)
                    output2 = self.minios.apprun2(cmd)
                    output2 = output2.splitlines()
                    interface = None
                    # Find interface based off MAC
                    for interface_loop, MAC_loop in zip(output, output2):
                        if MAC in MAC_loop:
                            interface = interface_loop
                    for line in output:
                        if MAC in line:
                            interface = line.split('Link')[0]
                            break
                    # Get the other MACs based off the main interface
                    for interface_loop, MAC_loop in zip(output, output2):
                        if interface[:-1] in interface_loop:
                            self.MACs.append(MAC_loop.replace(":","").strip())

                    # Get the name of the NIC
                    self.name = value.get('Part Number', None)

                    # Get the firmware of the NIC
                    self.firmware = value.get('FW', None)
                    count = 5
                    break
            except:
                count += 1

    def flash(self, file):
        # Clear Tmp Folder
        cmd = 'sudo rm -rf /tmp/*'
        # Jenny Modified on 9/19/2019
        #self.minios.apprun(cmd)
        self.minios.apprun2(cmd)
        # Unzip file to /tmp
        print(self.minios.node.host + ' Unzipping ' + file)
        cmd = "sudo unzip " + file + " -d /tmp"
        # Jenny Modified on 9/19/2019
        #self.minios.apprun(cmd, 120)
        self.minios.apprun2(cmd)
        # Look for bin file in /tmp directory
        cmd = 'sudo find /tmp -name \"*.bin\"'
        # Jenny Modified on 9/19/2019
        #output = self.minios.apprun(cmd)
        output = self.minios.apprun2(cmd)
        output = output.splitlines()
        output2 = ''
        for line in output:
            if '.bin' in line:
                cmd = self.mlxup + ' -d 0000:' + self.busdevID + '.0 -u -f -y -i ' + line.strip()
                print(self.minios.node.host + ' Flashing ' + self.name)
                # Jenny Modified on 9/19/2019
                #output2 = self.minios.apprun(cmd, 30)
                output2 = self.minios.apprun2(cmd)
                if 'Restart needed for updates to take effect.' in output2:
                    print(self.minios.node.host + ' Successfully Flashed ' + self.name)
                    return True
        print(self.minios.node.host + ' Failed to Flash ' + self.name + ' \nDebugging output: ' + output2)
        return False



class emulexHBA(HBA):
    def __init__(self, minios_instance, pciloc):
        HBA.__init__(self, minios_instance, pciloc)
        self.hbacmd = "sudo hbacmd "
        self.systool = "systool -c fc_host -v "
        self.elxflash = "sudo elxflash.sh "
        self.linlpcfg = "sudo linlpcfg.sh "
        #self.linlpcfg = "sudo linlpcfg "
        self.hbacmdlisthbadict = {}
        while self.name is None and self.firmware is None:
            self.getDetails()

    def getDetails(self):
        cmd_symbolic  = self.systool + '| grep symbolic_name'
        cmd_portwwn  = self.systool + '| grep port_name'
        output = self.minios.apprun2(cmd_symbolic)
        output = output.splitlines()
        dictionarytemp = {}
        # PCI Location in integers
        location = str(int(self.busdevID[:2],16))
        # Get the WWNs assocated to the card
        for line in output:
            lines = line.split(' = ')
            if len(lines) > 1:
                dictionarytemp.update({lines[0].strip():lines[1].strip()})
        for key, value in dictionarytemp.items():
            print("The key is: ", key)
            print("The value is: ", value)
            values = value.split(' ')
            self.name = 'Emulex_' + values[1]
            self.firmware = values[2]
            #break
        # Set WWNs to List
        output = self.minios.apprun2(cmd_portwwn)
        output = output.splitlines()
        dictionarytemp2 = {}
        # Get the WWNs assocated to the card
        for line in output:
            lines = line.split(' = ')
            if len(lines) > 1:
                dictionarytemp2.update({lines[0].strip():lines[1].strip()})
        for key, value in dictionarytemp2.items():
            print("The WWN key is: ", key)
            print("The WWN value is: ", value)
            self.WWN_key = value.upper()
            self.WWN_key = self.WWN_key[3:11] + ' ' + self.WWN_key[11:18]
            print(self.WWN_key)
            break

        return False
    '''
    def getDetails(self):
        cmd = self.hbacmd + 'listhba'
        # Jenny Modified on 9/19/2019
        #output = self.minios.apprun(cmd, 15)
        output = self.minios.apprun2(cmd)
        output = output.splitlines()
        dictionarytemp = {}
        # PCI Location in integers
        location = str(int(self.busdevID[:2],16))
        # Get the WWNs associated to the card
        for line in output:
            lines = line.split(' : ')
            if len(lines) > 1:
                dictionarytemp.update({lines[0].strip():lines[1].strip()})
            else:
                # If a blank line is found and location is in the dictionary temp, add dictionary to main listdict
                if '' is line and location in dictionarytemp.get('PCI Bus Number', '0'):
                    self.hbacmdlisthbadict.update({dictionarytemp.get('Port WWN'):dictionarytemp})
                    dictionarytemp = {}

        # Get more WWN details
        for WWN in self.hbacmdlisthbadict.keys():
            cmd = self.hbacmd + 'hbaattrib ' + WWN
            # Jenny Modified on 9/19/2019
            #output = self.minios.apprun(cmd)
            output = self.minios.apprun2(cmd)
            output = output.splitlines()
            for line in output:
                items = line.split(' : ')
                if len(items) > 1:
                    self.hbacmdlisthbadict[WWN].update({items[0].strip():items[1].strip()})

        # Set name and firmware details to class
        for WWN in self.hbacmdlisthbadict.keys():
            self.name = 'Emulex_' + self.hbacmdlisthbadict[WWN].get('Model')
            self.firmware =  self.hbacmdlisthbadict[WWN].get('FW Version')

        # Set WWNs to List
        self.WWNs = list(self.hbacmdlisthbadict)

        # Get the serial number
        for key, value in self.hbacmdlisthbadict.items():
            try:
                self.serial = value['Serial No.']
                break
            except:
                pass

        return None
        '''
    def flash(self, file):
        # Clear Tmp Folder
        cmd = 'sudo rm -rf /tmp/*'
        # Jenny Modified on 9/19/2019
        #self.minios.apprun(cmd)
        self.minios.apprun2(cmd)
        # Copy file to temp folder
        print(self.minios.node.host + ' Copying ' + file)
        cmd = "sudo cp " + file + " /tmp"
        # Jenny Modified on 9/19/2019
        #self.minios.apprun(cmd, 120)
        self.minios.apprun2(cmd)
        # Get HBA Number
        cmd = self.linlpcfg + 'listHBA'
        # Jenny Modified on 9/19/2019
        #output = self.minios.apprun(cmd)
        output = self.minios.apprun2(cmd)
        output = output.splitlines()
        print(output)
        # Get first WWN of HBA and format to meet linlpcfg standards
        #WWN_key = self.WWNs[0].replace(":","").upper()
        #WWN_key = WWN_key[:8] + ' '+ WWN_key[8:]
        adapternumber = None
        print("==================")
        print(self.WWN_key)
        print("==================")
        for line in output:
            print(line)
            if self.WWN_key in line:
                print("Catched line: ", line)
                adapternumber = line.split()[1].split(':')[0]
        if adapternumber is not None:
            print(self.minios.node.host + ' Flashing ' + self.name)
            cmd = self.linlpcfg + 'download n=' + adapternumber + ' i=/tmp/' + file.split('/')[-1]
            # Jenny Modified on 9/19/2019
            #output = self.minios.apprun(cmd, 30)
            output = self.minios.apprun2(cmd)
            if 'Command completed, NO Error' in output:
                print(self.minios.node.host + ' Successfully Flashed ' + self.name)
                return True
        #print(self.minios.node.host + ' Failed to Flash ' + self.name + ' \nDebugging output: ' + output)
        # Jenny Add 9/6/2019
        print("Failed to Flash Emulex Card")
        #print(output)

        return False

    def blinkLED(self, WWN, switch = True):
        cmdprep = self.hbacmd + ' SetBeacon ' + WWN
        if switch:
            cmd = cmdprep + ' 1'
        else:
            cmd = cmdprep + ' 0'
        # Jenny Modified on 9/19/2019
        #output = self.minios.apprun(cmd)
        output = self.minios.apprun2(cmd)
        return None

class AVAGORAIDController(SASController):
    def __init__(self, minios_instance, pciloc):
        SASController.__init__(self, minios_instance, pciloc)
        self.storagedevices = []
        self.storcli64e = "sudo storcli64 "
        self.CTL = ""
        self.detailsDict = {}
        self.controlleroutputcache = ""
        count = 0
        while self.name is None or self.firmware is None:
            self.getDetails()
            self.getControllerDict()
            if count > self.attempts:
                break
            else:
                count += 1
        if self.name is None:
            self.name = 'Unknown'
        if self.firmware is None:
            self.firmware = 'Unknown'

    def getDetails(self):
        # Remove the old driver
        cmd = "sudo rmmod megaraid_sas"
        # Jenny Modified on 9/19/2019
        #self.minios.apprun(cmd, 15)
        self.minios.apprun2(cmd)

        # Load new driver (Need to allow dynamic find for this driver)
        cmd = "sudo insmod /lib/modules/4.4.0-21-generic/weak-updates/megaraid_sas/megaraid_sas.ko.new"
        # Jenny Modified on 9/19/2019
        #self.minios.apprun(cmd, 15)
        self.minios.apprun2(cmd)

        # Get total number of controllers
        cmd = self.storcli64e + "show ctrlcount"
        # Jenny Modified on 9/19/2019
        #output = self.minios.apprun(cmd, 15)
        output = self.minios.apprun2(cmd)
        lines = output.splitlines()
        tempdict = {}
        for line in lines:
            splited = line.split("=")
            if len(splited) > 1:
                tempdict.update({splited[0].strip():splited[1].strip()})
        totalctl = int(tempdict.get("Controller Count", "0"))

        # Get ctl based of PCI location and store the details
        for ctltemp in range(totalctl):
            cmd = self.storcli64e + "/c" + str(ctltemp) + " show"
            # Jenny Modified on 9/19/2019
            #output = self.minios.apprun(cmd, 15)
            output = self.minios.apprun2(cmd)
            # Store Output in cache
            self.controlleroutputcache = output
            if self.busdevID in output:
                self.CTL = str(ctltemp)
                lines = output.splitlines()
                for line in lines:
                    splited = line.split("=")
                    if len(splited) > 1:
                        self.detailsDict.update({splited[0].strip(): splited[1].strip()})
                break

        if len(self.detailsDict) < 1:
            print(self.minios.node.host + ' Couldn\'t find CTL number for RAID Card ' + self.busdevID)
            return None

        # Attempt to store the name and the firmware
        self.name = self.detailsDict.get("Product Name", "").replace(" ", "_")
        self.firmware = self.detailsDict.get("FW Version", "")

        # Attempt to get the serial number
        try:
            self.serial = self.detailsDict['Serial Number']
        except:
            pass


        # print(output)

    def flash(self, file):
        # Clear Tmp Folder
        cmd = 'sudo rm -rf /tmp/*'
        # Jenny Modified on 9/19/2019
        #self.minios.apprun(cmd)
        self.minios.apprun2(cmd)
        # Unzip file to /tmp
        print(self.minios.node.host + ' Unzipping ' + file)
        cmd = "sudo unzip " + file + " -d /tmp"
        # Jenny Modified on 9/19/2019
        #self.minios.apprun(cmd, 120)
        self.minios.apprun2(cmd)
        # Find the files rom and bin files
        cmd = "sudo find /tmp -name *.rom"
        # Jenny Modified on 9/19/2019
        #output = self.minios.apprun(cmd)
        output = self.minios.apprun2(cmd)
        lines = output.splitlines()

        # Flash the ROM
        for line in lines:
            if ".rom" in line:
                print(self.minios.node.host + ' Flashing ' + self.name + ' with ' + line)
                cmd = self.storcli64e + "/c" + self.CTL + " download file= \"" + line + "\" noverchk"
                # Jenny Modified on 9/19/2019
                #output = self.minios.apprun(cmd, 120)
                output = self.minios.apprun2(cmd)
                if "Flash Completed" in output and "Status = Success" in output:
                    break
                else:
                    print(self.minios.node.host + ' Failed to Flash ' + self.name + ' \nDebugging output: ' + output)
                    return False
        print(self.minios.node.host + ' Successfully Flashed ' + self.name)
        return True

    def deleteConfig(self):
        cmd = self.storcli64e + "/c" + str(self.CTL) + " delete config force"
        # Jenny Modified on 9/19/2019
        #output = self.minios.apprun(cmd, 15)
        output = self.minios.apprun2(cmd)
        if 'successfully' in output:
            return True
        else:
            return False

    def deleteForeignConfig(self):
        cmd = self.storcli64e + "/c" + str(self.CTL) + "/fall delete"
        # Jenny Modified on 9/19/2019
        #output = self.minios.apprun(cmd, 15)
        output = self.minios.apprun2(cmd)
        if 'Successfully' in output or 'Success' in output:
            return True
        else:
            return False

    def getControllerDict(self, force=False):
        if force or len(self.controlleroutputcache) < 1:
            cmd = self.storcli64e + "/c" + str(self.CTL) + " show"
            # Jenny Modified on 9/19/2019
            #output = self.minios.apprun(cmd, 15)
            output = self.minios.apprun2(cmd)
        else:
            output = self.controlleroutputcache

        lines = output.splitlines()
        table_name = ""
        table_header_line = ""
        table_header = []
        lines_count = 0
        data_count = 0
        temp_dict = {}
        mastertemp_dict = {}
        for line in lines:
            # Get the table name
            if ' :' in line:
                table_name = line.split(':')[0].strip()
                self.detailsDict.pop(table_name, None)
            # Add 1 to line_count
            elif '--------' in line:
                lines_count += 1
                continue
            # When there is one line, it's header line. Get the header details
            elif lines_count == 1:
                table_header_line = line
                temp_table_header = line.split()
                table_header = []
                for line in temp_table_header:
                    table_header.append(line + " ")
            # Where there are two lines, it's where the valuable data is at. Decode the data to a dictionary
            elif lines_count == 2:
                # Get the detail based off the header index
                for index in range(len(table_header)):
                    # Get end indexes
                    try:
                        if 'Size' in table_header[index + 1]:
                            next_string_index = table_header_line.index(table_header[index]) + len(table_header[index])
                        else:
                            next_string_index = table_header_line.index(table_header[index + 1])
                    # If we can't get the last index, store rest of the data to last header
                    except:
                        next_string_index = len(line)

                    # Get start indexes
                    start_string_index = 0
                    if index > 0:
                        if 'Model' in table_header[index - 1]:
                            start_string_index = table_header_line.index(table_header[index])
                        else:
                            start_string_index = table_header_line.index(table_header[index - 1]) + len(table_header[index - 1])

                    data = line[start_string_index:next_string_index]

                    temp_dict.update({table_header[index]: data})

                # Strip whitespace all the content
                temptemp_dict = {}
                for key, value in temp_dict.items():
                    temptemp_dict.update({key.strip():value.strip()})
                temp_dict = temptemp_dict

                mastertemp_dict.update({data_count: temp_dict})
                temp_dict = {}
                data_count += 1
            elif lines_count > 2:
                self.detailsDict.update({table_name: mastertemp_dict})
                mastertemp_dict = {}
                table_header_line = ""
                table_header = []
                lines_count = 0
                data_count = 0

        # print(self.detailsDict)

    def getPhysicalDevicesList(self, force = False):
        if force:
            self.getControllerDict(force)

        list = []
        for key, value in self.detailsDict.get("PD LIST", {}).items():
            list.append(value)

        return list

    def getTotalRAIDSize(self, raidtype, drives = []):
        if "raid" in raidtype:
            raidtype = int(raidtype.replace("raid", ""))
        else:
            raidtype = int(raidtype)

        # Get drives if user didn't declare any drives
        if len(drives) < 1:
            for key, value in self.detailsDict.get("PD LIST", {}).items():
                drives.append(value)
        else:
            temp_drives = []
            for drive in drives:
                for key, value in self.detailsDict.get("PD LIST", {}).items():
                    if drive == value["EIF:slt"]:
                        temp_drives.append(value)
                        break

        # Double check if drives are the same model and size
        prev_model = None
        prev_size = None
        for drive in drives:
            drive_size = float(re.findall("\d+\.\d+", drive["Size"])[0])
            if prev_model is None:
                prev_model = drive["Model"]
                prev_size = drive_size
                continue

            if prev_model != drive["Model"] or drive_size != prev_size:
                print(self.minios.node.host + " Drives aren't the same. Cancelling RAID Creation")
                return "0 GB"

        # Get the total size
        size = 0
        size_type = None
        for drive in drives:
            drive_size = float(re.findall("\d+\.\d+", drive["Size"])[0])
            if size_type is None:
                size_type = drive["Size"].split()[1]
            size += drive_size

        if raidtype == 5 and len(drives) > 2:
            size = size / len(drives) * (len(drives) - 1)
        elif raidtype == 1:
            size = size / 2
        else:
            print(self.minios.node.host + " Only RAID1 and RAID5 are supported.")
            return "0 GB"

        size_string = "%.3f" % size + " " + size_type.strip()
        print(size_string)

        return size_string

    def setDriveStatus(self, status = "good", drives=[], force = True):
        if len(drives) < 1:
            for key, value in self.detailsDict.get("PD LIST",{}).items():
                drives.append(str(value["EID:Slt"]))

        if "good" in status:
            for drive in drives:
                EID, Slt = drive.split(":", 1)
                cmd = self.storcli64e + "/c" + str(self.CTL) + "/e" + EID + "/s" + Slt + " set good"
                if force:
                    cmd = cmd + " force"
                # print(cmd)
                # Jenny Modified on 9/19/2019
                #output = self.minios.apprun(cmd, 60)
                output = self.minios.apprun2(cmd)

    # This function is limited to R and NR settings for read ahead / no read ahead
    def setDriveCacheSettings(self, setting = "RWBD", virtualdisks = []):
        success = True
        for virtualdisks in virtualdisks:
            DG,VG = virtualdisks.split("/", 1)
            cmd = self.storcli64e + "/c" + str(self.CTL) + "/v" + VG + " "
            if "NRWBD" == setting:
                cmd = cmd + "set rdcache=NoRA"
            elif "RWBD" == setting:
                cmd = cmd + "set rdcache=RA"
            else:
                print(self.minios.node.host + " Invalid Cache Setting")
                continue
            # Jenny Modified on 9/19/2019
            #output = self.minios.apprun(cmd, 15)
            output = self.minios.apprun2(cmd, 15)
            if 'Success' not in output:
                success = False

        return success


    def createRAID(self, raidtype, names = [], sizes = [], cache_settings = [], drives = [], force = False):
        # Delete configuration if force is true
        if force:
            self.deleteConfig()
            self.setDriveStatus(status="good", force = True)
            self.deleteForeignConfig()
            time.sleep(10)

        cmd = self.storcli64e + "/c" + str(self.CTL) + " add vd "

        # Add Raid Spec
        if 'raid' not in raidtype:
            cmd = cmd + "type=raid" + str(raidtype) + " "
        else:
            cmd = cmd + "type=" + str(raidtype) + " "

        # Check if number of names and sizes are the same. Name is required for sizes.
        if len(names) != len(sizes):
            print(self.minios.node.host + " Can't create RAID Group. Incorrect number of Names and Sizes")
            return False

        # If the number of cache_settings is greater than 0, number of names and cache_settings must by the same:
        if len(cache_settings) > 0 and (len(names) != len(cache_settings)):
            print(self.minios.node.host + " Can't create RAID Group. Incorrect number of Names and Cache Settings")
            return False

        # Add Size Spec
        if len(sizes) > 0:
            cmd = cmd + "size="
            for size in sizes:
                cmd = cmd + str(size) + ","
            cmd = cmd[:-1] + " "

        # Add Name Spec
        if len(names) > 0:
            cmd = cmd + "name="
            for name in names:
                cmd = cmd + str(name) + ","
            cmd = cmd[:-1] + " "

        # Add Drive Spec
        cmd = cmd + "drives="
        if len(drives) > 0:
            for drive in drives:
                cmd = cmd + str(drive) + ","
            cmd = cmd[:-1] + " "
        else:
            for key, value in self.detailsDict.get("PD LIST",{}).items():
                try:
                    cmd = cmd + str(value["EID:Slt"]) + ","
                except:
                    pass
            cmd = cmd[:-1] + " "

        # Run the command
        print(self.minios.node.host + " Attempting to run the following command:" + cmd)
        # Jenny Modified on 9/19/2019
        #output = self.minios.apprun(cmd, 60)
        output = self.minios.apprun2(cmd)

        if "Add VD Succeeded" in output:
            print(self.minios.node.host + " Created RAID Group Successfully")

            # Update the dictionary for latest
            self.getControllerDict(force=True)

            # Set CacheSettings
            print(self.minios.node.host + " Setting Cache Settings")
            if len(cache_settings) > 0:
                for key, value, in self.detailsDict["VD LIST"].items():
                    self.setDriveCacheSettings(cache_settings[key], virtualdisks =[value["DG/VD"]])
                # Update the dictionary for latest
                self.getControllerDict(force=True)

            print(self.minios.node.host + " Created the following virtual disks")
            t = PrettyTable(["Name","RAID","Size","Cache_Settings"])
            for key, value, in self.detailsDict["VD LIST"].items():
                # print("RAID:" + value["TYPE"] + "\tName:" + value["Name"] + "\tSize:" + value["Size"] + "\tCache_Settings:" + value["Cache"])
                t.add_row([value["Name"], value["TYPE"], value["Size"], value["Cache"]])
            print(t)
            return True
        else:
            print(self.minios.node.host + " Failed to create RAID Group. Here is the output:\n" + output)
            return False


class LSISAS3Controller(SASController):
    def __init__(self, minios_instance, pciloc):
        SASController.__init__(self, minios_instance, pciloc)
        self.storagedevices = []
        self.storcli64e = "sudo storcli64 "
        self.CTL = ""
        self.sas3flash = "sudo sas3flash "
        self.detailsDict = {}
        while self.name is None or self.firmware is None:
            self.getDetails()

    def getDetails(self):
        # Get total number of controllers
        cmd = self.storcli64e + "show ctrlcount"
        # Jenny Modified on 9/19/2019
        #output = self.minios.apprun(cmd, 15)
        output = self.minios.apprun2(cmd)
        print("%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%")
        print(output)
        time.sleep(1)
        print("%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%")

        lines = output.splitlines()
        tempdict = {}
        for line in lines:
            splited = line.split("=")
            if len(splited) > 1:
                tempdict.update({splited[0].strip(): splited[1].strip()})
        totalctl = int(tempdict.get("Controller Count", "0"))

        # Get ctl based of PCI location and store the details
        for ctltemp in range(totalctl):
            cmd = self.storcli64e + "/c" + str(ctltemp) + " show"
            # Jenny Modified on 9/19/2019
            #output = self.minios.apprun(cmd, 15)
            output = self.minios.apprun2(cmd)
            if self.busdevID in output:
                self.CTL = str(ctltemp)
                lines = output.splitlines()
                for line in lines:
                    splited = line.split("=")
                    if len(splited) > 1:
                        self.detailsDict.update({splited[0].strip(): splited[1].strip()})
                break

        if len(self.detailsDict) < 1:
            print(self.minios.node.host + ' Couldn\'t find CTL number for SAS Card ' + self.busdevID)
            # Jenny Modified on 9/26/2019
            #return None
            #return True
 
        # Attempt to store the name and the firmware
        self.name = "LSI_" + self.detailsDict.get("Product Name", "").replace(" ", "_")
        # Jenny Add this code on 9/5/2019
        if (self.name.find("LSI_Quanta_Mezz") != -1):
            self.name = self.name.replace("LSI_Quanta_Mezz", "LSI_QS3216")
        self.firmware = self.detailsDict.get("FW Version", "")

        # Attempt to get the serial number
        try:
            self.serial = self.detailsDict['Serial Number']
        except:
            pass
        # print(output)

    def flash(self, file):
        # Clear Tmp Folder
        cmd = 'sudo rm -rf /tmp/*'
        # Jenny Modified on 9/19/2019
        #self.minios.apprun(cmd)
        self.minios.apprun2(cmd)
        # Unzip file to /tmp
        print(self.minios.node.host + ' Unzipping ' + file)
        cmd = "sudo unzip " + file + " -d /tmp"
        # Jenny Modified on 9/19/2019
        #self.minios.apprun(cmd, 120)
        self.minios.apprun2(cmd)
        # Find the files rom and bin files
        cmd = "sudo find /tmp -name *.bin -o -name *.rom"
        # Jenny Modified on 9/19/2019
        #output = self.minios.apprun(cmd)
        output = self.minios.apprun2(cmd)
        lines = output.splitlines()
        # Erase the flash
        cmd = self.sas3flash + "-c " + self.CTL + " -o -e 6"
        # Jenny Modified on 9/19/2019
        #output = self.minios.apprun(cmd, 120)
        output = self.minios.apprun2(cmd)
        # Flash the firmware
        for line in lines:
            if ".bin" in line:
                print(self.minios.node.host + ' Flashing ' + self.name + ' with ' + line)
                cmd = self.sas3flash + "-c " + self.CTL + " -o -f " + line
                # Jenny Modified on 9/19/2019
                #output = self.minios.apprun(cmd, 120)
                output = self.minios.apprun2(cmd)
                if "Firmware Flash Successful" in output:
                    break
                else:
                    print(self.minios.node.host + ' Failed to Flash ' + self.name + ' \nDebugging output: ' + output)
                    return False
        # Flash the BIOS
        for line in lines:
            if ".rom" in line:
                print(self.minios.node.host + ' Flashing ' + self.name + ' with ' + line)
                cmd = self.sas3flash + "-c " + self.CTL + " -o -b " + line
                # Jenny Modified on 9/19/2019
                #output = self.minios.apprun(cmd, 120)
                output = self.minios.apprun2(cmd)
                if "Flash BIOS Image Successful" in output:
                    continue
                else:
                    print(self.minios.node.host + ' Failed to Flash ' + self.name + ' \nDebugging output: ' + output)
                    return False
        print(self.minios.node.host + ' Successfully Flashed ' + self.name)
        return True

class NVIDIAGPUController(GPUController):
    def __init__(self, minios_instance, pciloc):
        GPUController.__init__(self, minios_instance, pciloc)
        self.nvidiasmi = "sudo nvidia-smi"
        self.detailsDict = {}
        self.getDetails()

    def loadDriver(self):
        modprobe = "sudo modprobe "
        # Disable open source nvidia linux driver
        # Jenny Modified on 9/19/2019
        #self.minios.apprun(modprobe + "-r nouveau")
        self.minios.apprun2(modprobe + "-r nouveau")
        # Enable nvidia driver
        # Jenny Modified on 9/19/2019
        #self.minios.apprun(modprobe + "nvidia")
        self.minios.apprun2(modprobe + "nvidia")

    def getDetails(self):
        self.loadDriver()
        cmd = self.nvidiasmi + " --query"
        # Jenny Modified on 9/19/2019
        #output = self.minios.apprun(cmd, interval=10)
        output = self.minios.apprun2(cmd)
        toolsDict = self.list2dictionary(output)
        for key, value in toolsDict.items():
            if self.busdevID.upper() in key:
                self.detailsDict = value
                break
        try:
            self.name = self.detailsDict["Product Name"].replace(" ", "_")
        except:
            self.name = "Unknown"

        try:
            self.firmware = self.detailsDict["VBIOS Version"]
        except:
            self.firmware = "Unknown"

        try:
            self.serial = self.detailsDict["Serial Number"]
        except:
            pass


    def list2dictionary(self, input):
        lines = input.splitlines()
        master_dict = {}
        header = ['','','','','','','']
        for line in lines:
            if '=======' in line:
                continue
            data = line.split(' : ')
            leftspace = len(data[0]) - len(data[0].lstrip())
            if len(data) == 1:
                header[int(leftspace/4)] = data[0].lstrip().rstrip()
                if leftspace == 0:
                    master_dict.update({data[0].lstrip().rstrip() : None})
                continue

            if len(data) == 2:
                json_string = '{'
                for count in range(int(leftspace/4)):
                    json_string = json_string +  '"' + header[count] + '":{'
                json_string = json_string + '"' + data[0].lstrip().rstrip() + '":"' + data[1] + '"'
                for count in range(int(leftspace/4)):
                    json_string = json_string + "}"
                json_string = json_string + '}'
                temp_dict = json.loads(json_string)
                self.updatedict(master_dict, temp_dict)
        return master_dict

    # https://stackoverflow.com/questions/40648302/how-to-update-deeply-nested-dictionaries-of-an-unknown-state
    def updatedict(self, a, b):
        for key in b:
            if not key in a or type(a[key]) != dict or type(b[key]) != dict:
                a[key] = b[key]
            else:
                self.updatedict(a[key], b[key])

class IntelNVMeDevice(NVMeDevice):
    def __init__(self, minios_instance, pciloc):
        NVMeDevice.__init__(self, minios_instance, pciloc)
        self.nvmeapp = "sudo nvme "
        self.ledctl = "sudo ledctl "
        self.lsblock = "sudo ls -l /sys/block | grep --color=never  " + str(pciloc) + ".0/nvme"
        self.detailsDict = {}

        count = 0
        while count < 5:
            if self.name is None:
                self.getDetails()
                count+=1
            else:
                break

    def getDetails(self):
        # Get the NVMe device name via lsblock
        # Jenny Modified on 9/19/2019
        #output = self.minios.apprun(self.lsblock, interval=10)
        output = self.minios.apprun2(self.lsblock)
        # Look for the nvme device
        lines = output.splitlines()
        for line in lines:
            try:
                device = '/dev/' + line.split('/')[-1]
                break
            except:
                device = ''
                continue
        # Get details about the nvme device
        cmd = self.nvmeapp + 'id-ctrl ' + device
        # Jenny Modified on 9/19/2019
        #self.detailsDict = self.list2dictionary(self.minios.apprun(cmd, interval=10))
        self.detailsDict = self.list2dictionary(self.minios.apprun2(cmd))
        # Store the name, firmware, and serial
        try:
            self.name = self.detailsDict['mn'].replace(' ', '_')
            self.firmware = self.detailsDict['fr']
            self.serial = self.detailsDict['sn']
        except:
            pass
        return self.detailsDict

    def list2dictionary(self, input):
        lines = input.splitlines()
        tempdict = {}
        for line in lines:
            try:
                key, value = line.split(' : ', 1)
                tempdict.update({key.rstrip(): value.rstrip()})
            except:
                pass
        return tempdict
'''
node = quantaskylake.D52B('fe80::aa1e:84ff:fea5:32c9%13', 'admin', 'cmb9.admin')
test = minios(node)
test.login()
test.discoverPCIDevices()
test.printPCIDevices()

raidtest = AVAGORAIDController(test, '5e:00')
raidtest.flash("/cdrom/firmware/AVAGO_MegaRAID_SAS_PCI_Express_ROMB-QS-3516B/QS-3516B-16i-R6-PD32-2G_FW-Online_5.040.00-1123.zip")


sastest = LSISAS3Controller(test, '5e:00')
sastest.flash("/cdrom/firmware/Quanta-QS3216/Qfw_1A14.zip")

node = quantaskylake.D52B('fe80::aa1e:84ff:fe73:ba49%13', 'admin', 'cmb9.admin')

test = minios(node)

test.login()

test.discoverPCIDevices()
test.printPCIDevices()
# test.dancePCIDevices()

# pcitest = intelNIC(test, '3d:00')
# pcitest.flash("/cdrom/firmware/Intel(R)_Ethrnet_Connection_X722_for_10GbE_SFP+/ON 10GbE X722-X527-DA4 SFP plus_FW-Online-Auto_Linux_0004.zip")



node = quantaskylake.D52B('fe80::aa1e:84ff:fe73:ba49%13', 'admin', 'cmb9.admin')


# node.deleteVMCLIapp()
node.setMiniOSDefaults()
node.poweroff()
time.sleep(60)
# node.createVMCLIapp()
# node.startVMCLIapp('minios2.iso')
node.poweron()

test = minios(node)

test.login()

test.discoverPCIDevices()
test.printPCIDevices()
test.dancePCIDevices()

pcitest = intelNIC(test, '1c:00')
pcitest.flash("/cdrom/firmware/Intel(R)_Ethernet_Network_Adapter_XXV710-2/XL710_NVMUpdatePackage_v6_01_Linux.tar.gz")

hbatest = emulexHBA(test, 'af:00')
hbatest.flash('/cdrom/firmware/Emulex_LPe31002-M6/lancerg6_A11.4.204.25.grp')

melltext = mellanoxNIC(test, '18:00')
melltext.flash('/cdrom/firmware/Mellanox-CX4121A/fw-ConnectX4Lx-rel-14_20_1010-MCX4121A-ACA_Ax-FlexBoot-3.5.210.bin.zip')

melltext = mellanoxNIC(test, '3b:00')
melltext.flash('/cdrom/firmware/Quanta_S5B_CX4Lx_25G_2P/3GS5BMA0000_MLX_25G_dual_port_14_20_1010_Online.zip')

pcitest = intelNIC(test, '3d:00')
pcitest.flash("/cdrom/firmware/Intel(R)_Ethernet_Connection_X722_for_10GbE_SFP+/ON 10GbE X722-X527-DA4 SFP plus_FW-Online-Auto_Linux_0004.zip")

hbatest = emulexHBA(test, 'af:00')
hbatest.getDetails()
hbatest.blinkLED(hbatest.WWNs[0])
# print(test)

pcitest = intelNIC(test, '1c:00')
pcitest.getDetails()
while True:
    print(pcitest.MACs[0] + ' On')
    pcitest.blinkLED(pcitest.MACs[0])
    time.sleep(5)
    print(pcitest.MACs[0] + ' Off')
    pcitest.blinkLED(pcitest.MACs[0], False)
    time.sleep(5)
    print(pcitest.MACs[1] + ' On')
    pcitest.blinkLED(pcitest.MACs[1])
    time.sleep(5)
    print(pcitest.MACs[1] + ' Off')
    pcitest.blinkLED(pcitest.MACs[1], False)
    time.sleep(5)
print(pcitest.SVID)
'''
