import pexpect
import requests
import sys
import logging
import badtime
import multiprocessing
import concurrent.futures
import quantaskylake
import json
import minios
import time
import os

class firmware(object):

    def __init__(self):
        self.firmwaredictionary = {
            ("D52B", "DS120", "DS220"): {
                "2017-09-08": {
                    "BMC": {"Version": "3.16.06", "File": "s5bxv3.16.06_rom.ima_enc"},
                    "BIOS": {"Version": "3A08.H2", "File": "3A08.BIN"},
                    "CPLD": {"Version": "REV10", "File": "S5B_MB_CPLD_REV10.jed"}
                },
                "2018-08-19": {
                    "BMC": {"Version": "3.74.06", "File": "s5bxv3.74.06_rom.ima_enc"},
                    "BIOS": {"Version": "3A10.H3", "File": "3A10.H3.BIN"},
                    "CPLD": {"Version": "REV10", "File": "S5B_MB_CPLD_REV10.jed"}
                },
                "2019-04-25": {
                    "BMC": {"Version": "3.74.06", "File": "s5bxv3.74.06_rom.ima_enc"},
                    "BIOS": {"Version": "3A10.H3", "File": "3A10.H3.BIN"},
                    "CPLD": {"Version": "REV10", "File": "S5B_MB_CPLD_REV10.jed"}
                }
            },
            ("D52BV", "DS225"): {
                "2018-07-30": {
                    "BMC": {"Version": "4.23.06", "File": "s5bxv4.23.06_rom.ima_enc"},
                    "BIOS": {"Version": "3A10.H8", "File": "3A10.H8.BIN_enc"},
                    "CPLD": {"Version": "REV10", "File": "S5B_MB_CPLD_REV10.jed_enc"}
                },
                "2018-08-19": {
                    "BMC": {"Version": "4.24.06", "File": "s5bxv4.23.06_rom.ima_enc"},
                    "BIOS": {"Version": "3A10.H8", "File": "3A10.H8.BIN_enc"},
                    "CPLD": {"Version": "REV10", "File": "S5B_MB_CPLD_REV10.jed_enc"}
                },
                "2018-08-20": {
                    "BMC": {"Version": "4.24.06", "File": "s5bxv4.24.06_rom.ima_enc"},
                    "BIOS": {"Version": "3A10.H8", "File": "3A10.H8.BIN_enc"},
                    "CPLD": {"Version": "REV10", "File": "S5B_MB_CPLD_REV10.jed_enc"}
                },
                "2018-10-18": {
                    "BMC": {"Version": "4.26.06", "File": "s5bxv4.26.06_rom.ima_enc"},
                    "BIOS": {"Version": "3A10.H8", "File": "3A10.H8.BIN_enc"},
                    "CPLD": {"Version": "REV10", "File": "S5B_MB_CPLD_REV10.jed_enc"}
                }
            },
            ("Q72D", "DS240"): {
                "2018-05-11": {
                    "BMC": {"Version": "3.88.06", "File": "s7dhxv3.88.06_rom.ima_enc"},
                    "BIOS": {"Version": "3A01.H3", "File": "3A01.H3.BIN"},
                },
                "2018-06-19": {
                    "BMC": {"Version": "4.22.06", "File": "s7dhxv4.22.06_rom.ima_enc"},
                    "BIOS": {"Version": "3A01.H3", "File": "3A01.H3.BIN_enc"},
                },
                "2018-07-13": {
                    "BMC": {"Version": "4.23.06", "File": "s7dhxv4.23.06_rom.ima_enc"},
                    "BIOS": {"Version": "3A02.H1", "File": "3A02.H1.BIN_enc"}
                },
                "2018-08-20": {
                    "BMC": {"Version": "4.23.06", "File": "s7dhxv4.23.06_rom.ima_enc"},
                    "BIOS": {"Version": "3A02.H2", "File": "3A02.H2.BIN_enc"}
                }
            },
            ("AVAGO_MegaRAID_SAS_9460-16i"): {
                "2017-12-17": {"Version": "5.040.00-1123", "File": "50.4.0-0919_9460-16i_SAS_MR_FW_IMAGE.zip"},
                "2018-05-31": {"Version": "5.060.00-1455", "File": "50.6.0-1375_9460-16i_SAS_MR_FW_IMAGE.zip"}
            },
            ("Quanta_S5B_CX4Lx_25G_2P"): {
                "2017-04-07": {"Version": "14.18.1000", "File": "3GS5BMA0000_MLX_25G_dual_port_14_18_1000_Online.zip"},
                "2018-02-03": {"Version": "14.20.1010", "File": "3GS5BMA0000_MLX_25G_dual_port_14_20_1010_Online.zip"}
            },
            ("MCX4121A-ACA_Ax"): {
                                     "2017-03-17": {"Version": "14.18.2000",
                                                    "File": "fw-ConnectX4Lx-rel-14_18_2000-MCX4121A-ACA_Ax-FlexBoot-3.5.110.bin.zip"},
                                     "2017-06-29": {"Version": "14.20.1010",
                                                    "File": "fw-ConnectX4Lx-rel-14_20_1010-MCX4121A-ACA_Ax-FlexBoot-3.5.210.bin.zip"},
                                     "2017-12-04": {"Version": "14.21.2010",
                                                    "File": "fw-ConnectX4Lx-rel-14_21_2010-MCX4121A-ACA_Ax-FlexBoot-3.5.305.bin.zip"},
                                     "2018-03-01": {"Version": "14.22.1002",
                                                    "File": "fw-ConnectX4Lx-rel-14_22_1002-MCX4121A-ACA_Ax-UEFI-14.15.19-FlexBoot-3.5.403.bin.zip"},
                                     "2018-07-12": {"Version": "14.23.1020",
                                                    "File": "fw-ConnectX4Lx-rel-14_23_1020-MCX4121A-ACA_Ax-UEFI-14.16.17-FlexBoot-3.5.504.bin.zip"},
                                     "2018-12-02": {"Version": "14.24.1000",
                                                    "File": "fw-ConnectX4Lx-rel-14_24_1000-MCX4121A-ACA_Ax-UEFI-14.17.11-FlexBoot-3.5.603.bin.zip"}
                                 },

        }

        self.vmwaredictionary = {
            "2019-04-25_UCPv20190425": {
                "ESXI_Version": "6.5U2/6.7U1",
                "ESXI_Build": "10390116/10302608",
                "Nodes": {
                    #"D52B": "2019-04-25",
                    "DS120": "2019-04-25",
                    "DS220": "2018-08-19",
                    #"D52BV": "2018-07-30",
                    #"DS225": "2018-07-30",
                    #"Q72D": "2018-08-20",
                    #"DS240": "2018-08-20"
                },
                "IOCards": {
                    "AVAGO_MegaRAID_SAS_9460-16i": "2017-12-17",
                    # "AVAGO_MegaRAID_SAS_PCI_Express_ROMB-QS-3516B": "2018-01-11",
                    # "Emulex_LPe31002-M6": "2018-02-06",
                    # "Emulex_LPe32002-M2": "2018-02-06",
                    # "Intel(R)_Ethernet_Connection_X722_for_10GbE_SFP+": "2018-02-23",
                    # "Intel(R)_Ethernet_Network_Adapter_XXV710-2": "2017-11-30",
                    # "LSI_SAS9305-16i": "2017-05-03",
                    # "LSI_QS3216": "2017-06-14",
                    "MCX4121A-ACA_Ax": "2018-07-12",
                    "Quanta_S5B_CX4Lx_25G_2P": "2018-02-03"
                }
            }
        }

        if 'linux' in sys.platform:
            self.path = '../../Firmware/COMPUTE/'
        else:
            self.path = '..\\..\\Firmware\\COMPUTE\\'

    def printfirmwareselection(self, name):
            print('Firmware Selection for ' + str(name) + ':')
            for device, data in self.firmwaredictionary.items():
                print(device)
                print(data)
                if name in device:
                    print(json.dumps(data, indent=4))
            return None

    def printesxiselection(self, inputdata=None):
        if inputdata is not None:
            for date, data in self.vmwaredictionary.items():
                if str(inputdata) in date:
                    for item, itemdata in data.items():
                        print("My item print:   ", item)
                        if 'Nodes' in item or 'IOCards' in item:
                            for node, nodedate in itemdata.items():
                                print(json.dumps(self.returnfirmwarefileJSON(node, nodedate), indent=4))
                        print("\n")
                    break
        else:
            for date, data in self.vmwaredictionary.items():
                print(date + ' : vSphere ESXi ' + data.get('ESXI_Version') + ' (' + data.get('ESXI_Build') + ')')

    def returnesxiselection(self, inputdata):
        for date, data in self.vmwaredictionary.items():
            if str(inputdata) in date:
                return data
        return {}

        # Returns the file details about the device in either date form or version form
        # Note: Nodes can only be used with date form. Can't force update incorrect BMC/BIOs combo
    def returnfirmwarefileJSON(self, name, inputdata):
        print("The name for node is: ", name)
        print("The inputdata for nodedate is: ", inputdata)
        print("============================================")
        for device, data in self.firmwaredictionary.items():
            print("This device is the ", device)
            print("This data is the  ", data)
            if name in device:
                for datesel, json in data.items():
                    if inputdata in datesel or inputdata in json.get("Version", ""):
                        return json
        #raise ValueError("Can't find JSON profile")
        raise ValueError("Can't find JSON profile for device ==== ", device, datesel)

    def returnfilepath(self, name):
        for root, dirs, files in os.walk(self.path):
            for file in files:
                if name in file:
                    return str(os.path.join(root, file))


    def spawn(self, command, **kwargs):
        if 'linux' in sys.platform:
            #session = PopenSpawn(command, **kwargs)
            #session = PopenSpawn(command)
            session = pexpect.spawn(command)
        else:
            #session = pexpect.spawn(command, **kwargs)
            #session = pexpect.spawn(command)
            print("Not support OS")
        return session

        # Start AMI Section
        # DO NOT USE THIS FOR OFFICIAL PURPOSES. ONLY CREATED FOR BMC 4.22.06 PURPOSES SINCE WE CAN'T LOG INTO REDFISH AT INITIAL BMC BOOTUP.
        # FORCE CHANGE PASSWORD TO SAME PASSWORD

    def poweroff(self):
        # session = PopenSpawn(self.IPMIPre + ' power off')
        session = self.spawn(self.IPMIPre + ' power off')
        output = session.read(2000)
        output = output.decode('utf-8')
        output = output.replace('\n', '')
        print(self.host + ' ' + output)

    def poweron(self):
        # session = PopenSpawn(self.IPMIPre + ' power on')
        session = self.spawn(self.IPMIPre + ' power on')
        output = session.read(2000)
        output = output.decode('utf-8')
        output = output.replace('\n', '')
        print(self.host + ' ' + output)

    def powersoft(self):
        # If node is on, press power button softly.
        if self.getPowerStatus():
            # session = PopenSpawn(self.IPMIPre + ' power soft')
            session = self.spawn(self.IPMIPre + ' power soft')
            output = session.read(2000)
            output = output.decode('utf-8')
            output = output.replace('\n', '')

    def forcePasswordChange(self):
        # Get QSESSIONID and X-CSRFTOKEN to log into AMI API
        header = {'Content-Type': 'application/x-www-form-urlencoded', 'User-Agent': 'curl/7.54.0',
                  'Host': '[' + self.host.split('%')[0] + ']'}
        url_prep = 'https://[' + self.host.replace('%', '%25') + ']/'
        session = requests.post(url=url_prep + 'api/session', data="username=admin&password=cmb9.admin", headers=header,
                                verify=False)
        if session.ok:
            try:
                j = session.json()
            except:
                print(self.host + ' ' + output)
                print(self.host + " Failed to Force Change Password")
                return False
            # print(j)
            CSRFToken = j["CSRFToken"]
            QSESSIONID = session.cookies["QSESSIONID"]
        else:
            print(self.host + " Failed to Force Change Password")
            return False

        # Update Header with QSESSIONID, X-CSRFTOKEN Details and new Content Type
        header.update({'Cookie': 'QSESSIONID=' + QSESSIONID})
        header.update({"X-CSRFTOKEN": CSRFToken})
        header.update({'Content-Type': 'application/json'})

        session = requests.post(url=url_prep + 'api/force_change_password',
                                data="{\"this_userid\":\"2\",\"password\":\"cmb9.admin\",\"confirm_password\":\"cmb9.admin\",\"password_size\":\"0\"}",
                                headers=header, verify=False)
        if session.ok:
            print(self.host + " Successfully Force Change Password")
        else:
            print(self.host + " Failed to Force Change Password")

        # Don't forget to log our of session
        session = requests.delete(url=url_prep + 'api/session', headers=header, verify=False)
        if session.ok:
            return True
        else:
            print(self.host + " Failed to Force Change Password")
            return False

    def createAPISession(self):
        # Get QSESSIONID and X-CSRFTOKEN to log into AMI API
        self.amiheader = {'Content-Type': 'application/x-www-form-urlencoded', 'User-Agent': 'curl/7.54.0',
                          'Host': '[' + self.host.split('%')[0] + ']'}
        url_prep = 'https://[' + self.host.replace('%', '%25') + ']/'
        session = requests.post(url=url_prep + 'api/session', data="username=admin&password=cmb9.admin",
                                headers=self.amiheader, verify=False)
        if session.ok:
            try:
                j = session.json()
            except:
                print(self.host + " Failed to log into AMI Session")
                return False
            # print(j)
            CSRFToken = j["CSRFToken"]
            QSESSIONID = session.cookies["QSESSIONID"]
        else:
            print(self.host + " Failed to log into AMI Session")
            return False

        # Update Header with QSESSIONID, X-CSRFTOKEN Details and new Content Type
        self.amiheader.update({'Cookie': 'QSESSIONID=' + QSESSIONID})
        self.amiheader.update({"X-CSRFTOKEN": CSRFToken})
        self.amiheader.update({'Content-Type': 'application/json'})

        self.amiloggedin = True

    def destroyAPISession(self):
        # Don't forget to log our of session
        url_prep = 'https://[' + self.host.replace('%', '%25') + ']/'
        session = requests.delete(url=url_prep + 'api/session', headers=self.amiheader, verify=False)
        if session.ok:
            self.amiloggedin = False
            return True
        else:
            print(self.host + " Failed to lot out of AMI session")
            return False

    def getVirtualMediaStatus(self):
        if self.amiloggedin:
            pass
        else:
            return {}
        url_prep = 'https://[' + self.host.replace('%', '%25') + ']/'
        session = requests.get(url=url_prep + 'api/settings/media/instance', headers=self.amiheader, verify=False)

        if session.ok:
            try:
                j = session.json()
            except:
                return {}

        return j

 # Each Redfish Update Requires just one PUT Call. Can't use multiple PUT Calls
    def setMiniOSDefaults(self):
        try:
            session = requests.put(self.redfishapi + 'Systems/Self/Bios/SD', auth=(self.username, self.password),\
                                   verify=False, headers=self.redfishheader,\
                                   # data='{"Attributes":{"FBO001":"LEGACY","FBO101":"CD/DVD","FBO102":"USB","FBO103":"Hard Disk","FBO104":"Network"}}')\
        
                                   data='{"Attributes":{"FBO001":"UEFI","FBO201":"CD/DVD","FBO202":"USB","FBO203":"Hard Disk","FBO204":"Network","CRCS005":"Enable","IIOS1FE":"Enable", "IPMI100":"Disabled"}}')
            if session.status_code == 200:
                print(self.host + ' ' + 'Successfully set MiniOS BIOS Settings')
            else:
                print(self.host + ' ' + 'Hooray Failed to set MiniOS BIOS Settings')

        except:
            pass
        #if session.status_code == 204:
        #    print(self.host + ' ' + 'Successfully set MiniOS BIOS Settings')
        #else:
        #    print(self.host + ' ' + 'Failed to set MiniOS BIOS Settings')


    def miniospcidiscoverwrapper(minios_instance):
        minios_instance.discoverPCIDeiveices()
        return minios_instance

    def pciflashing(minios_instance, firmware_class, firmware_selection):
        for pciloc, device in minios_instance.PCIDevices.items():
            date = firmware_selection.get("IOCards").get(device.name, None)
            if date is None:
                print(
                    minios_instance.node.host + "" + device.name + " isn\'t compatible wit this firmware selction or firmware doesn\]'t exit.")
                continue
            filejson = firmware_class.returnfirmwarefileJSON(device.name, date)
            # This path is relative to the MiniOS
            filepath = "/cdrom/firmware/" + device.name + "/" + filejson.get("File")
            print(minios_instance.node.host + ' Flashing ' + device.name + ' on ' + pciloc + ' with ' + filepath)
            device.flash(filepath)
        return minios_instance



def main():
    preserveconfig = True
    # Ask the user how many nodes that rack has
    #nodesnum = helper.askNodeQuantity()
    nodesnum = 10

    if preserveconfig is True:
        while True:
            # Ask for the username and password of BMC
            username = input('What is the username of the BMC? ')
            if username != 'admin':
                print(
                    "This toolkit only supports \"admin\" account for restoration. If another account is used, please manually create the account. Exiting.")
                return False

            password = input('What is the password of the BMC? ')

            print('You have entered ' + str(username) + ' and ' + str(password) + ' ')
            response = input('Is this correct? (Enter y for yes or n for no): ')
            if 'y' in response:
                print('Perfect! Let\'s move on.')
                break
            else:
                print('Re-asking questions.')




    # Get the existing nodes
    #if preserveconfig is True:
    #    # Discover with existing details
    #    nodes = autodiscover.discover(nodesnum, [username], [password])
    #else:
    #    # Discover with default details
    #    nodes = autodiscover.discover(nodesnum)

    nodes = [quantaskylake.DS120('10.76.38.85', 'admin', 'cmb9.admin')]
    #nodes = [quantaskylake.DS120('fe80::dac4:97ff:fe17:6e7c%ens160', 'admin', 'cmb9.admin')]
    #nodes = [quantaskylake.DS120('fe80::dac4:97ff:fe17:6e7c', 'admin', 'cmb9.admin')]

    #nodes = ['fe80::dac4:97ff:fe17:6e7c%ens160']
    #r = firmware('fe80::dac4:97ff:fe17:6e7c%ens160', 'admin', 'cmb9.admin')
    #r.printfirmwareselection("DS120")
    # Start the firmware object
    f = firmware()

    # Ask the user which vSphere version so we can flash the DS120/220 with appropriate firmware.
    while True:
        print('\nWhich appliance are you going to install? (Note: Entering UCP is the default option)\n')
        f.printesxiselection()
        date = input('Enter the date and/or version (if any): ')
        if len(f.returnesxiselection(date)) < 1:
            print('I couldn\'t find this selection. Please try again.')
        else:
            print('\nThis selection has the following firmwares:')
            f.printesxiselection(date)
            firmwareselection = f.returnesxiselection(date)
            break
'''
    # Start MiniOS Logic
    badtime.seperate()
    print("\nStarting PCI Device Firmware Flashing\n")

    print('Setting MiniOS BIOS Default')
    processes = []
    for node in nodes:
        processes.append(multiprocessing.Process(target=node.setMiniOSDefaults2()))
    # Start threads
    for process in processes:
        process.start()
        time.sleep(1)
    # Wait for threads
    for process in processes:
        process.join()

    #vmcli_nodes = copy.deepcopy(nodes)
    #vmcli_nodes = helper.massStartVMCLI(vmcli_nodes, minios.getminiosiso())

    print('Powering on the nodes to start MiniOS')
    processes = []
    for node in nodes:
        processes.append(multiprocessing.Process(target=node.poweron))
    # Start threads
    for process in processes:
        process.start()
        # Slowly power-on nodes to not overload circuit
        time.sleep(2)
    # Wait for threads
    for process in processes:
        process.join()

    print("\nCreating MiniOS Instances")
    minioses = []
    for node in nodes:
        minioses.append(minios.minios(node))

    print("\nAttempting to login into all MiniOS Instances")
    for minios_instance in minioses:
        minios_instance.login()

    time.sleep(30)

    print(" Jenny, I am here now")

    print("\nDiscovering All PCI Devices in all MiniOS Instances")
    temp_minioses = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=32) as executor:
        futures = [executor.submit(miniospcidiscoverwrapper, minios_instance) for minios_instance in minioses]
        for future in concurrent.futures.as_completed(futures):
            temp_minioses.append(future.result())
    minioses = temp_minioses

    for minios_instance in minioses:
        minios_instance.printPCIDevices()

    print("\nFlashing All PCI Devices in all MiniOS Instances")
    temp_minioses = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=32) as executor:
        futures = [executor.submit(pciflashing, minios_instance, firmware, firmwareselection) for minios_instance in
                   minioses]
        for future in concurrent.futures.as_completed(futures):
            try:
                temp_minioses.append(future.result())
            except:
                continue
    minioses = temp_minioses

    input("Hit enter to continue")

    # Power off the nodes
    for node in nodes:
        node.poweroff()

def miniospcidiscoverwrapper(minios_instance):
    minios_instance.discoverPCIDevices()
    return minios_instance

def pciflashing(minios_instance, firmware_class, firmware_selection):
    for pciloc, device in minios_instance.PCIDevices.items():
        date = firmware_selection.get("IOCards").get(device.name, None)
        if date is None:
            print(
                minios_instance.node.host + " " + device.name + " isn\'t compatible with this firmware selection or firmware doesn\'t exist.")
            continue
        filejson = firmware_class.returnfirmwarefileJSON(device.name, date)
        # This path is relative to the MiniOS
        filepath = "/cdrom/firmware/" + device.name + "/" + filejson.get("File")
        print(minios_instance.node.host + ' Flashing ' + device.name + ' on ' + pciloc + ' with ' + filepath)
        device.flash(filepath)
    return minios_instance
'''

if __name__ == '__main__':
    '''
    from argparse import ArgumentParser

    logging.basicConfig(format='%(asctime)s %(name)-5s %(levelname)-10s %(message)s')
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)

    parser = ArgumentParser()
    parser.add_argument('-h_list', type=str, nargs='*', dest='hostname', help='Hostname list for BMC')
    parser.add_argument('-u_list', type=str, nargs='*', dest='username', help='Username list for BMC')
    parser.add_argument('-p_list', type=str, nargs='*', dest='password', help='Password List for BMC')
    args = parser.parse_args()


    # nodes = [quantaskylake.DS120('fe80::dac4:97ff:fe1c:4e26%11', 'admin', 'cmb9.admin')]
    try:
        if isinstance(args.username, list) and isinstance(args.password, list):
            autodiscover = QuantaSkylake(args.hostname, args.username, args.password)
            print(autodiscover.firmware())
        else:
            parser.print_help()
    except Exception as ex:
        print('Exception| ', ex)
        '''
    main()
