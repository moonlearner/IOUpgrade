from pexpect.popen_spawn import PopenSpawn
import pexpect
from datetime import datetime
import requests
import json
import urllib3
import os
import subprocess
import time
urllib3.disable_warnings()
import sys
import re
import ipv6linklocalforwarding
import signal
import tempfile

class QuantaSkylake(object):
    def __init__(self, host, username, password):
        self.host = host

        # Some applications do not work via IPv6 Link Local. Adding ipv6linklocal instance
        self.hostforwardinstance = None

        self.username = username
        self.password = password
        #self.redfishapi2 = 'https://[' + host.replace('%','%25') + ']/redfish/v1/'
        self.redfishapi2 = 'https://' + host.replace('%', '%25') + '/redfish/v1/'
        self.redfishheader = {
                                'Content-Type': 'application/json',
                                'User-Agent': 'curl/7.54.0',
                                'Host': '[' + host.split('%')[0] + ']'
                            }
        self.redfishheader2 = {
            'Content-Type': 'application/json',
            'User-Agent': 'curl/7.54.0',
        }
        self.payload = json.dumps( {"Attributes":{
			"FBO001":"UEFI",
			"FBO201":"CD/DVD",
			"FBO202":"USB",
			"FBO203":"Hard Disk",
			"FBO204":"Network",
			"CRCS005":"Enable",
			"IIOS1FE":"Enable",
			"IPMI100":"Disabled"
			}
          })

        self.amiheader = {}
        self.amiloggedin = False
        self.cookie = None
        self.token = None
        self.BMCVersion = None
        self.BIOSVersion = None
        self.BIOSJSONCache = None
        self.ManagersJSONCache = None
        self.SystemsJSONCache = None
        self.IPMIPre = 'ipmitool -I lanplus -H ' + host + ' -U ' + username + ' -P ' + password + ' '
        self.ipv4Address = None
        self.ipv4Subnet = None
        self.ipv4Gateway = None
        self.ipv4Src = None
        self.mgmtMAC = None
        self.lastButtonTime = None
        self.SOLSession = None
        self.VMCLISession = None
        # Fill UP JSON Cache
        self.getJSONs()

    def spawn(self, command, **kwargs):
        if 'Linux' in sys.platform:
            session = pexpect.spawn(command, **kwargs)
        else:
            session = PopenSpawn(command, **kwargs)
        return  session

        # if 'win' in sys.platform:
        #     session = PopenSpawn(command, **kwargs)
        # else:
        #     session = pexpect.spawn(command, **kwargs)
        # return session

    def poweroff(self):
        # session = PopenSpawn(self.IPMIPre + ' power off')
        session = self.spawn(self.IPMIPre + ' power off')
        output = session.read(2000)
        output = output.decode('utf-8')
        output = output.replace('\n', '')
        print(self.host + ' ' + output)

    def poweron(self):
        # session = PopenSpawn(self.IPMIPre + ' power on')
        #session = self.spawn(self.IPMIPre + ' power on')
        session = self.spawn(self.IPMIPre + ' power on') # Jenny Changed on 8/5/2019
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
            print(self.host + ' ' + output)

    def idon(self):
        # session = PopenSpawn(self.IPMIPre + ' chassis identify force')
        session = self.spawn(self.IPMIPre + ' chassis identify force')
        output = session.read(2000)

    def idoff(self):
        # session = PopenSpawn(self.IPMIPre + ' chassis identify 0')
        session = self.spawn(self.IPMIPre + ' chassis identify 0')
        output = session.read(2000)

    def idblink(self):
        # session = PopenSpawn(self.IPMIPre + ' chassis identify 0')
        session = self.spawn(self.IPMIPre + ' chassis identify 240')
        output = session.read(2000)

    def resetBMC(self):
        session = self.spawn(self.IPMIPre + ' mc reset cold')
        output = session.read(2000)

    def updateUserPass(self, username, password):
        print(self.host + ' Setting username to ' + username + ' and password to ' + password)
        if username == 'admin':
            # session = PopenSpawn(self.IPMIPre + ' user set password 2 ' + password)
            session = self.spawn(self.IPMIPre + ' user set password 2 \"' + password + '\"')
        else:
            print(self.host + ' This tool kit does not support setting different usernames yet.')
            return False

        output = session.read(2000)
        output = output.decode('utf-8')
        print(self.host + ' ' + output)
        if 'successful' in output:
            self.username = username
            self.password = password
            self.IPMIPre = 'ipmitool -I lanplus -H ' + self.host + ' -U ' + self.username + ' -P \"' + self.password + '\" '
            return True
        else:
            return False

    # Get FRU Data
    def getFRU(self):
        cmd = self.IPMIPre + 'fru print'
        session = self.spawn(cmd)
        output = session.read(2000)
        lines = output.splitlines()
        print(output)
        test = self.readFRU(0)
        print(test)



    # Start AMI Section
    # DO NOT USE THIS FOR OFFICIAL PURPOSES. ONLY CREATED FOR BMC 4.22.06 PURPOSES SINCE WE CAN'T LOG INTO REDFISH AT INITIAL BMC BOOTUP.
    # FORCE CHANGE PASSWORD TO SAME PASSWORD
    def forcePasswordChange(self):
        # Get QSESSIONID and X-CSRFTOKEN to log into AMI API
        header = {'Content-Type': 'application/x-www-form-urlencoded', 'User-Agent': 'curl/7.54.0', 'Host': '[' + self.host.split('%')[0] + ']'}
        url_prep = 'https://[' + self.host.replace('%','%25') + ']/'
        session = requests.post(url = url_prep + 'api/session', data="username=admin&password=cmb9.admin", headers=header, verify=False)
        if session.ok:
            try:
                j = session.json()
            except:
                print(self.host + " Failed to Force Change Password")
                return False
            # print(j)
            CSRFToken = j["CSRFToken"]
            QSESSIONID = session.cookies["QSESSIONID"]
        else:
            print(self.host + " Failed to Force Change Password")
            return False

        # Update Header with QSESSIONID, X-CSRFTOKEN Details and new Content Type
        header.update({'Cookie':'QSESSIONID=' + QSESSIONID})
        header.update({"X-CSRFTOKEN": CSRFToken})
        header.update({'Content-Type': 'application/json'})

        session = requests.post(url = url_prep + 'api/force_change_password', data="{\"this_userid\":\"2\",\"password\":\"cmb9.admin\",\"confirm_password\":\"cmb9.admin\",\"password_size\":\"0\"}", headers=header, verify=False)
        if session.ok:
            print(self.host + " Successfully Force Change Password")
        else:
            print(self.host + " Failed to Force Change Password")

        # Don't forget to log our of session
        session = requests.delete(url = url_prep + 'api/session', headers=header, verify=False)
        if session.ok:
            return True
        else:
            print(self.host + " Failed to Force Change Password")
            return False

    def createAPISession(self):
        # Get QSESSIONID and X-CSRFTOKEN to log into AMI API
        self.amiheader = {'Content-Type': 'application/x-www-form-urlencoded', 'User-Agent': 'curl/7.54.0', 'Host': '[' + self.host.split('%')[0] + ']'}
        url_prep = 'https://[' + self.host.replace('%','%25') + ']/'
        session = requests.post(url = url_prep + 'api/session', data="username=admin&password=cmb9.admin", headers=self.amiheader, verify=False)
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
        self.amiheader.update({'Cookie':'QSESSIONID=' + QSESSIONID})
        self.amiheader.update({"X-CSRFTOKEN": CSRFToken})
        self.amiheader.update({'Content-Type': 'application/json'})

        self.amiloggedin = True

    def destroyAPISession(self):
        # Don't forget to log our of session
        url_prep = 'https://[' + self.host.replace('%', '%25') + ']/'
        session = requests.delete(url = url_prep + 'api/session', headers=self.amiheader, verify=False)
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



    # End AMI Section #

    def setHDDBoot(self):
        try:
            session = requests.put(self.redfishapi2 + 'Systems/Self/Bios/SD', auth=(self.username, self.password),
                                   verify=False, headers=self.redfishheader,
                                   data='{"Attributes":{"FBO201":"Hard Disk","FBO202":"USB","FBO203":"CD/DVD","FBO204":"Network"}}')
        except:
            pass
        if session.status_code == 204:
            print(self.host + ' ' + ' Successfully set HDD First Boot order')
        else:
            print(self.host + ' ' + ' Failed to set HDD First Boot order')

    def setCDROMBoot(self):
        try:
            session = requests.put(self.redfishapi2 + 'Systems/Self/Bios/SD', auth=(self.username, self.password),
                                   verify=False, headers=self.redfishheader,
                                   data='{"Attributes":{"FBO201":"CD/DVD","FBO202":"USB","FBO203":"Hard Disk","FBO204":"Network"}}')
        except:
            pass
        if session.status_code == 204:
            print(self.host + ' ' + ' Successfully set CD/DVD First Boot order')
        else:
            print(self.host + ' ' + ' Failed to set CD/DVD First Boot order')

    def setIIOS1FE(self, value):
        # For more details about IIOS1FE, go to https://(BMC IP)/redfish/v1/Registries/BiosAttributeRegistry0.0.0.0.json
        if value is True:
            self.setBIOSAttribute('IIOS1FE', 'Enable')
        else:
            self.setBIOSAttribute('IIOS1FE', 'Disable')

    def setCRCS005(self, value):
        # For more details about CRCS005, go to https://(BMC IP)/redfish/v1/Registries/BiosAttributeRegistry0.0.0.0.json
        if value is True:
            self.setBIOSAttribute('CRCS005', 'Enable')
        else:
            self.setBIOSAttribute('CRCS005', 'Disable')

    # Repairs rebooting issue when OS takes too long to boot
    def setSMI(self, value=False):
        if value is True:
            session = self.spawn(self.IPMIPre + ' raw 0x36 0x1c 0x4c 0x1c 0x00 0x01 0x01')
            output = session.read(2000)
            print(self.host + ' Enabling S')
        else:
            session = self.spawn(self.IPMIPre + ' raw 0x36 0x1c 0x4c 0x1c 0x00 0x01 0x00')
            output = session.read(2000)
            print(self.host + ' Disabling SMI Timer')

    # Each Redfish Update Requires just one PUT Call. Can't use multiple PUT Calls
    def setUCPCIDefaults(self):
        try:
            session = requests.put(self.redfishapi2 + 'Systems/Self/Bios/SD', auth=(self.username, self.password),
                                   verify=False, headers=self.redfishheader,
                                   data='{"Attributes":{"FBO001":"UEFI","FBO201":"CD/DVD","FBO202":"USB","FBO203":"Hard Disk","FBO204":"Network","CRCS005":"Enable","IIOS1FE":"Enable", "IPMI100":"Disabled"}}')
        except:
            pass
        if session.status_code == 204:
            print(self.host + ' ' + 'Successfully set UCP CI/HC/RS BIOS Settings')
        else:
            print(self.host + ' ' + 'Failed to set UCP CI/HC/RS BIOS Settings')

    # Each Redfish Update Requires just one PUT Call. Can't use multiple PUT Calls
    def setMiniOSDefaults(self):
        try:
            session = requests.put(self.redfishapi2 + 'Systems/Self/Bios/SD', auth=(self.username, self.password),
                                   verify=False, headers=self.redfishheader,
                                   # data='{"Attributes":{"FBO001":"LEGACY","FBO101":"CD/DVD","FBO102":"USB","FBO103":"Hard Disk","FBO104":"Network"}}')
                                   data='{"Attributes":{"FBO001":"UEFI","FBO201":"CD/DVD","FBO202":"USB","FBO203":"Hard Disk","FBO204":"Network","CRCS005":"Enable","IIOS1FE":"Enable", "IPMI100":"Disabled"}}')
        except:
            pass
        if session.status_code == 204:
            print(self.host + ' ' + 'Successfully set MiniOS BIOS Settings')
        else:
            print(self.host + ' ' + 'Failed to set MiniOS BIOS Settings')


    def setMiniOSDefaults2(self):
        try:
            session = requests.put(self.redfishapi22 + 'Systems/Self/Bios/SD', auth=(self.username, self.password),
                                   verify=False, headers=self.redfishheader2,
                                   data=self.payload)
            print(self.redfishapi22)
            print(self.username)
            print(self.password)
            print(self.payload)
            print(session.status_code)
            if session.status_code == 204:
                print(self.host + ' ' + 'In quantaskylake: Successfully set MiniOS BIOS Settings')
            else:
                print(self.host + ' ' + 'In quantaskylake: Failed to set MiniOS BIOS Settings')
        except:
            print("Error Out")
            pass


    # This technically doesn't work if used in a loop.
    def setBIOSAttribute(self, key, value):
        try:
            session = requests.put(self.redfishapi2 + 'Systems/Self/Bios/SD', auth=(self.username, self.password),
                                   verify=False, headers=self.redfishheader,
                                   data='{"Attributes":{"' + str(key) + '":"' + str(value) + '"}}')
        except:
            pass
        if session.status_code == 204:
            print(self.host + ' ' + ' Successfully set key ' + str(key) + ' with value ' + str(value) +'.')
        else:
            print(self.host + ' ' + ' Failed to set key ' + str(key) + ' with value ' + str(value) +'.')

    @staticmethod
    def validate(host, username, password):
        temp = host + ' ' + username + ' ' + password
        print('Start  ' + temp)
        #redfishapi2 = 'https://[' + host + ']/redfish/v1/'
        # Jenny Modified
        redfishapi2 = 'https://' + host + '/redfish/v1/'
        redfishheader = {
            'Content-Type': 'application/json',
            'User-Agent': 'curl/7.54.0',
            'Host': '[' + host.split('%')[0] + ']'
        }
        # Attempt to connect
        try:
            session = requests.get(redfishapi2 + 'Systems/Self', auth=(username, password), verify=False,
                                   headers=redfishheader, timeout=30)
        except:
            print('Finish ' + temp)
            return None
        print('Finish ' + temp)
        # If redfish responded, we are good.
        if session.ok:
            try:
                j = session.json()
            except:
                return None
            print(j)
            try:
                SKU = j['SKU']
            except:
                return None
            if ('D52B' in SKU) or ('DS120' in SKU) or ('DS220' in SKU):
                return QuantaSkylake(host, username, password)
            else:
                return None
        else:
            return None

    def getJSONs(self):
        self.getManagersJSON()
        self.getSystemsJSON()

    def getSystemsJSON(self):
        # Get Redfish Systems/Self Details
        session = requests.get(self.redfishapi2 + 'Systems/Self', auth=(self.username, self.password), verify=False, headers=self.redfishheader)
        try:
            # Decode JSON to Dictionary
            j = session.json()
            # Store it
            self.SystemsJSONCache = j
            return j
        except:
            return {}

    def getManagersJSON(self):
        session = requests.get(self.redfishapi2 + 'Managers/Self', auth=(self.username, self.password), verify=False, headers=self.redfishheader)
        # Decode JSON to Dictionary
        j = session.json()
        # Store it
        self.ManagersJSONCache = j
        return j

    def getRegistriesJSON(self):
        session = requests.get(self.redfishapi2 + 'Registries/Self', auth=(self.username, self.password), verify=False, headers=self.redfishheader)
        # Decode JSON to Dictionary
        j = session.json()
        return j

    def getBIOSVersion(self):
        try:
            self.BIOSVersion = self.SystemsJSONCache['BiosVersion']
        except:
            raise ValueError('BIOs from server has\'t turned on yet. Please turn on server.')
        return self.BIOSVersion

    def getBIOSJSON(self):
        session = requests.get(self.redfishapi2 + 'Systems/Self/Bios', auth=(self.username, self.password), verify=False, headers=self.redfishheader)
        try:
            j = session.json()
        except:
            return {'error':'error'}
        self.BIOSJSONCache = j
        return j

    def restoreBIOSJSON(self, json):
        inputdata = str(json)
        inputdata = inputdata.replace('\'','\"')
        inputdata = inputdata.replace('False', 'false')
        inputdata = inputdata.replace('True', 'true')
        try:
            session = requests.put(self.redfishapi2 + 'Systems/Self/Bios/SD', auth=(self.username, self.password),
                                   verify=False, headers=self.redfishheader,
                                   data=inputdata)
        except:
            pass
        if session.status_code == 204:
            print(self.host + ' ' + 'Successfully set BIOS Settings')
        else:
            print(self.host + ' ' + 'Failed to set BIOS Settings. Redfish API said ' + str(session.content))

    def restoreBIOSJSONtest(self, json):
        for key, value in json['Attributes'].items():
            # print(key + ' ' + str(value))
            self.setBIOSAttribute(key, value)

    def getBIOSJSONRegistries(self):
        # Get BIOS Registries
        session = requests.get(self.redfishapi2 + 'Registries/BiosAttributeRegistry0.0.0.0.json', auth=(self.username, self.password), verify=False, headers=self.redfishheader)
        j = session.json()
        return j

    def getBMCVersion(self):
        try:
            self.BMCVersion = self.ManagersJSONCache['FirmwareVersion']
        except:
            raise ValueError('BMC Version isn\'t in the output. This shouldn\'t happen. Did you run get JSONS yet? :(')
        return self.BMCVersion

    def getJSON(self, inputurl):
        if self.redfishapi2 in inputurl:
            url = str(inputurl)
        else:
            url = self.redfishapi2 + str(inputurl)
        session = requests.get(url, auth=(self.username, self.password), verify=False,
                               headers=self.redfishheader)
        try:
            j = session.json()
        except:
            return {'error': 'error'}
        self.BIOSJSONCache = j
        return j

    def getIPv4Address(self):
        # Ask ipmitool to go to node and print out LAN details
        # session = PopenSpawn(self.IPMIPre + 'lan print')
        session = self.spawn(self.IPMIPre + 'lan print')
        output = session.read(2000)
        output = output.decode('utf-8')
        output = output.splitlines()
        for line in output:
            if 'IP Address    ' in line:
                ipv4 = line.split(': ')[1]
                self.ipv4Address = ipv4
            elif 'Subnet Mask    ' in line:
                subnet = line.split(': ')[1]
                self.ipv4Subnet = subnet
            elif 'Default Gateway IP ' in line:
                gateway = line.split(': ')[1]
                self.ipv4Gateway = gateway
            elif 'IP Address Source ' in line:
                source = line.split(': ')[1]
                self.ipv4Src = source
            elif 'MAC Address  ' in line:
                mgmtMAC = line.split(': ')[1].replace(":", "").lower()
                self.mgmtMAC = mgmtMAC

        try:
            print(self.host + ' ' + str(self.__class__.__name__) + ' Address: ' + ipv4 + ' Subnet: ' + subnet + ' Gateway: ' + gateway)
            return self.ipv4Address
        except:
            print(self.host + ' This host has a failing IPMI interface. Please do not continue and reflash this system.')
            return None

    def setIPv4Address(self, IPv4Address = None, subnet = None, gateway = None):
        print(self.host + ' Setting IPv4 LAN Parameters')
        # Ask ipmitool to set DHCP Mode if IPv4Address is None. Otherwise, set to Static
        if IPv4Address is None:
            # session = PopenSpawn(self.IPMIPre + ' lan set 1 ipsrc dhcp')
            session = self.spawn(self.IPMIPre + ' lan set 1 ipsrc dhcp')
            output = session.read(2000)
            output = output.decode('utf-8')
            output = output.replace('\n', '')
            print(self.host + ' Setting IP Source to DHCP')
            self.ipv4Address = None
            return True
        else:
            # session = PopenSpawn(self.IPMIPre + ' lan set 1 ipsrc static')
            session = self.spawn(self.IPMIPre + ' lan set 1 ipsrc static')
            output = session.read(2000)
            output = output.decode('utf-8')
            output = output.replace('\n', '')
            print(self.host + ' Setting IP Source to Static')
            time.sleep(15)

        if subnet is None:
            raise ValueError('Subnet cannot be blank.')

        # Wait for interface to come back
        time.sleep(10)

        if IPv4Address is not None and subnet is not None:
            # session = PopenSpawn(self.IPMIPre + ' lan set 1 netmask ' + str(subnet), timeout=120)
            session = self.spawn(self.IPMIPre + ' lan set 1 netmask ' + str(subnet), timeout=120)
            output = session.read(2000)
            output = output.decode('utf-8')
            output = output.replace('\n', '')
            print(self.host + ' ' + output)
            # session = PopenSpawn(self.IPMIPre + ' lan set 1 ipaddr ' + str(IPv4Address), timeout=120)
            session = self.spawn(self.IPMIPre + ' lan set 1 ipaddr ' + str(IPv4Address), timeout=120)
            output = session.read(2000)
            output = output.decode('utf-8')
            output = output.replace('\n', '')
            print(self.host + ' ' + output)

        if gateway is not None:
            # session = PopenSpawn(self.IPMIPre + ' lan set 1 defgw ipaddr ' + str(gateway), timeout=120)
            session = self.spawn(self.IPMIPre + ' lan set 1 defgw ipaddr ' + str(gateway), timeout=120)
            output = session.read(2000)
            output = output.decode('utf-8')
            output = output.replace('\n', '')
            print(self.host + ' ' + output)

        return True

    def setIPv4SubnetAddress(self, subnet = None, gateway = None):
        print(self.host + ' Setting IPv4 LAN Parameters')

        if subnet is None:
            raise ValueError('Subnet cannot be blank.')

        if subnet is not None:
            # session = PopenSpawn(self.IPMIPre + ' lan set 1 netmask ' + str(subnet), timeout=120)
            session = self.spawn(self.IPMIPre + ' lan set 1 netmask ' + str(subnet), timeout=120)
            output = session.read(2000)
            output = output.decode('utf-8')
            output = output.replace('\n', '')
            print(self.host + ' ' + output)

        if gateway is not None:
            # session = PopenSpawn(self.IPMIPre + ' lan set 1 defgw ipaddr ' + str(gateway), timeout=120)
            session = self.spawn(self.IPMIPre + ' lan set 1 defgw ipaddr ' + str(gateway), timeout=120)
            output = session.read(2000)
            output = output.decode('utf-8')
            output = output.replace('\n', '')
            print(self.host + ' ' + output)

        return True



    def getPowerStatus(self):
        # session = PopenSpawn(self.IPMIPre + ' power status')
        session = self.spawn(self.IPMIPre + ' power status')
        output = session.read(2000)
        output = output.decode('utf-8')
        output = output.replace('\n', '')
        print(self.host + ' ' + output)
        if 'off' in output:
            return False
        else:
            return True

    def setTime(self):
        # session = PopenSpawn(self.IPMIPre + ' sel time set "' + datetime.now().strftime("%m/%d/%Y %H:%M:%S") + '"')
        session = self.spawn(self.IPMIPre + ' sel time set "' + datetime.now().strftime("%m/%d/%Y %H:%M:%S") + '"')
        output = session.read(2000)
        output = output.decode('utf-8').rstrip()
        print(self.host + ' ' + output)

    def getTime(self):
        # session = PopenSpawn(self.IPMIPre + ' sel time get')
        session = self.spawn(self.IPMIPre + ' sel time get')
        output = session.read(2000)
        output = output.decode('utf-8').lstrip().rstrip()
        print(self.host + ' ' + output)
        return datetime.strptime(output, '%m/%d/%Y %H:%M:%S')

    def clearSEL(self):
        # session = PopenSpawn(self.IPMIPre + ' sel clear')
        session = self.spawn(self.IPMIPre + ' sel clear')
        output = session.read(200000)
        output = output.decode('utf-8').rstrip()
        print(self.host + ' ' + output)

    def rawIPMI(self,input):
        session = self.spawn(self.IPMIPre + ' raw ' + input)
        output = session.read(2000)
        output = output.decode('utf-8').rstrip()
        return output

    def readFRU(self, fruID):
        fruID = str(fruID)
        file, path = tempfile.mkstemp()
        session = self.spawn(self.IPMIPre + ' fru read ' + fruID + ' ' + path)
        output = session.read(2000)
        output = output.decode('utf-8').rstrip()
        content = ''
        try:
            with os.fdopen(file, 'rb') as tmp:
                content = tmp.read()
        finally:
            os.remove(path)
        return content

    def writeFRU(self, fruID, fruData):
        fruID = str(fruID)

    @staticmethod
    def getLastButtonTime(node):
        session = PopenSpawn(node.IPMIPre + ' sel list', timeout=60)
        output = session.read(200000)
        output = output.decode('utf-8')
        # print(output)
        output = output.splitlines()
        buttons = []
        for line in output:
            if "Button #" in line:
                # Only get the date and time
                buttons.append(datetime.strptime(line[7:28], '%m/%d/%Y | %H:%M:%S'))
        if buttons.__len__() > 0:
            node.lastButtonTime = buttons[-1]
        else:
            node.lastButtonTime = datetime.strptime('1/1/1970 | 00:00:00', '%m/%d/%Y | %H:%M:%S')
        return node

    def deleteVMCLIapp(self):
        self.stopVMCLIapp()
        # session = PopenSpawn('sc delete VMCLI_' + self.host, timeout=60)
        session = self.spawn('sc delete VMCLI_' + self.host, timeout=60)
        output = session.read(2000)
        output = output.decode('utf-8')
        # print(self.host + ' ' + output)

    # Needs help
    def createVMCLIapp(self):
        if 'win' in sys.platform:
            '''
            cwd = os.getcwd()
            session = PopenSpawn('sc create VMCLI_' + self.host + ' binPath= "' + cwd + '\\VMCLI.exe', timeout=60)
            # session = self.spawn()
            output = session.read(2000)
            output = output.decode('utf-8')
            # print(self.host + ' ' + output)
            '''
            print('VMCLI Service creation isn\'t required for Windows environments.')
        else:
            print('VMCLI Service creation isn\'t required for Linux environments.')

    def stopVMCLIapp(self):
        if self.VMCLISession is not None:
            self.VMCLISession.kill(signal.CTRL_C_EVENT)
        self.VMCLISession = None

    def startVMCLIapp(self, isofile):
        self.createAPISession()
        self.stopVMCLIapp()
        print(self.host + ' Starting VMCLI Service with ' + isofile)
        time.sleep(1)
        if 'win' in sys.platform:
            cwd = os.getcwd()
            # cmd = 'sc start VMCLI_' + self.host + ' -r [' + self.host + ']:443 -u ' + self.username + ' -p ' + self.password + ' -c "' + cwd + '\\' + isofile + '"'
            cmd = "VMCLI.exe -r [" + self.host + "]:443 -u " + self.username + " -p " + self.password + " -c " + cwd + "/" + isofile
            cmd = cmd.replace("\\","/")
            count = 0
            while count < 10:
                try:
                    # output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
                    # print(self.host + ' ' + output)
                    session = PopenSpawn(cmd, timeout=30, encoding = 'utf-8', searchwindowsize=100)
                    self.VMCLISession = session
                    session.expect('Starting CD redirection', timeout=30)
                except:
                    pass
                time.sleep(30)
                if self.statusVMCLIapp():
                    break
                else:
                    print(self.host + " VMCLI Failed to start. Attempt #" + str(count))
                    session.kill(signal.CTRL_C_EVENT)
                    count += 1
        else:
            self.startTunnel(['443','5120'])
            cmd = 'VMCLIEXE -r [' + self.host.split('%')[0].split('fe80')[1] + ']:443 -u ' + self.username + ' -p ' + self.password + ' -c ' + isofile
            session = self.spawn(cmd, encoding = 'utf-8')
            try:
                session.expect('CD redirection in progress')
                self.VMCLISession = session
                time.sleep(1)
                print(self.host + ' ' + ' CD redirection in progress')
            except:
                print(self.host + 'VMCLI Failed to start')

        if not self.statusVMCLIapp():
            print(self.host + ' VMCLI Failed to start')
        else:
            print(self.host + ' CD redirection in progress')
        self.destroyAPISession()
    # Needs help
    def statusVMCLIapp(self):
        # Check #1
        if self.VMCLISession is None:
            return False
        else:
            if not self.VMCLISession.closed:
                index = self.VMCLISession.expect(['Stopping all the redirections', 'Error', 'Ejected', pexpect.EOF, pexpect.TIMEOUT])
                if index < 4:
                    self.stopVMCLIapp()
                    return False
                # else:
                #     return True
            else:
                return False

        # Check #2
        cdrom_status = False
        if self.amiloggedin:
            j = self.getVirtualMediaStatus()
            try:
                # Set True if the AMI API says CD redirection is active
                cdrom_status = bool(int(j['cd_active_sessions'])%2)
            except:
                pass

        return cdrom_status




    def SOLActivate(self):
        count = 0
        while count < 5:
            count += 1
            #self.SOLDeactivate()
            try:
                # session = PopenSpawn(self.IPMIPre + 'sol activate', encoding='utf-8')
                session = self.spawn(self.IPMIPre + 'sol activate', encoding='utf-8')
            except Exception as e:
                continue

            # Pexpect will wait for these two outputs.
            result = session.expect(['[SOL Session operational.  Use ~? for help]','Info: SOL payload already active on another session'])

            # If the output is SOL Session Operational, return the session. Otherwise, return nothing.
            if result == 0:
                self.SOLSession = session
                return session
            else:
                continue
        return None

    def SOLDeactivate(self):
        # session = PopenSpawn(self.IPMIPre + 'sol deactivate')
        session = self.spawn(self.IPMIPre + 'sol deactivate')
        try:
            output = session.read(2000)
        except:
            pass
        # output = output.decode('utf-8')
        # print(self.host + ' ' + output)

    def ipmicmdraw(self, input):
        # session = PopenSpawn(self.IPMIPre + ' ' + str(input))
        session = self.spawn(self.IPMIPre + ' ' + str(input))
        output = session.read(2000)
        output = output.decode('utf-8')
        print(self.host + ' ' + self.IPMIPre + ' ' + str(input) + '\n' + output)

    def startTunnel(self, port):
        self.hostforwardinstance = ipv6linklocalforwarding.forwarding(self.host.split('%')[0].split('fe80')[1], port, self.host, port)
        self.hostforwardinstance.start()

    def stopTunnel(self):
        if self.hostforwardinstance is not None:
            self.hostforwardinstance.stop()

    def bmcFlash(self, file):
        if 'win' in sys.platform:
            cmd = 'Yafuflash2 -nw -vyes -fb -host ' + self.host + ' -u ' + self.username + ' -p ' + self.password + ' ' + file
        else:
            # Yafuflash2 doesn't support IPv6 Link-Local Address. Adding Tunnel
            self.startTunnel(['623'])
            cmd = 'Yafuflash2 -nw -vyes -fb -host ' + self.host.split('%')[0].split('fe80')[1] + ' -u ' + self.username + ' -p ' + self.password + ' ' + file
        # session = PopenSpawn(cmd, maxread=20000)
        session = self.spawn(cmd, maxread=20000)

        filename = re.sub('[%:]', '.', self.host.split('%')[0])
        if 'win' in sys.platform:
            fout = open('temp\\' + filename + '_BMCFLASH.txt',"wb")
        else:
            fout = open('temp/' + filename + '_BMCFLASH.txt', "wb")
        fout.write(str.encode(cmd))
        session.logfile = fout

        print(self.host + ' Running: ' + cmd)
        returnCode = 0
        timetowait = 240
        try:
            session.expect('Uploading Firmware Image : 0', timeout=600)
            print(self.host + ' Uploading BMC Image')
        except:
            print(self.host + ' Failed to upload BMC image')
            timetowait = 10
            returnCode = returnCode + 1

        try:
            session.expect('Flashing \[boot\] Module', timeout=timetowait)
            print(self.host + ' Flashing [boot] Module')
        except:
            print(self.host + ' Failed to flash boot module')
            timetowait = 10
            returnCode = returnCode + 2

        try:
            session.expect('Flashing \[conf\] Module', timeout=timetowait)
            print(self.host + ' Flashing [conf] Module')
        except:
            print(self.host + ' Failed to flash [conf] Module')
            timetowait = 10
            returnCode = returnCode + 4

        try:
            session.expect('Flashing \[bkupconf\] Module', timeout=timetowait)
            print(self.host + ' Flashing [bkupconf] Module')
        except:
            print(self.host + ' Failed to flash [bkupconf] Module')
            timetowait = 10
            returnCode = returnCode + 8

        try:
            session.expect('Flashing \[root\] Module', timeout=timetowait)
            print(self.host + ' Flashing [root] Module')
        except:
            print(self.host + ' Failed to flash [root] Module')
            timetowait = 10
            returnCode = returnCode + 16

        try:
            session.expect('Flashing \[osimage\] Module', timeout=timetowait)
            print(self.host + ' Flashing [osimage] Module')
        except:
            print(self.host + ' Failed to flash [osimage] Module')
            timetowait = 10
            returnCode = returnCode + 32

        try:
            session.expect('Flashing \[www\] Module', timeout=timetowait)
            print(self.host + ' Flashing [www] Module')
        except:
            print(self.host + ' failed to flash [www] Module')
            timetowait = 10
            returnCode = returnCode + 64

        try:
            session.expect('Flashing \[ast2500e\] Module', timeout=timetowait)
            print(self.host + ' Flashing [ast2500e] Module')
        except:
            print(self.host + ' Failed tp flash [ast2500e] Module')
            timetowait = 10
            returnCode = returnCode + 128

        try:
            session.expect('Resetting the firmware', timeout=timetowait)
            print(self.host + ' Resetting Firmware')
        except:
            print(self.host + ' Failed to reset Firmware. Please wait for yafuflash to exit cleanly.')
            timetowait = 10
            returnCode = returnCode + 256

        # Wait for Yafuflash to exit
        session.wait()

        if returnCode < 1:
            print(self.host + ' Successfully flashed BMC')
        else:
            print(self.host + ' Failed to flash BMC')
        fout.close()
        self.stopTunnel()

        return returnCode

    def biosFlash(self, file):
        if 'win' in sys.platform:
            cmd = 'Yafuflash2 -nw -vyes -fb -host ' + self.host + ' -u ' + self.username + ' -p ' + self.password + ' -d 2 ' + file
        else:
            # Yafuflash2 doesn't support IPv6 Link-Local Address. Adding Tunnel
            self.startTunnel(['623'])
            cmd = 'Yafuflash2 -nw -vyes -fb -host ' + self.host.split('%')[0].split('fe80')[1] + ' -u ' + self.username + ' -p ' + self.password + ' -d 2 ' + file
        # session = PopenSpawn(cmd, maxread=2000)
        session = self.spawn(cmd, maxread=2000)

        filename = re.sub('[%:]', '.', self.host.split('%')[0])
        if 'win' in sys.platform:
            fout = open('temp\\' + filename +'_BIOSFLASH.txt',"wb")
        else:
            fout = open('temp/' + filename + '_BIOSFLASH.txt', "wb")
        fout.write(str.encode(cmd))
        session.logfile = fout

        print(self.host + ' Running: ' + cmd)
        returnCode = 0
        timetowait = 240
        try:
            session.expect('Beginning BIOS Update', timeout=600)
            print(self.host + ' Uploading BIOS Image')
        except:
            print(self.host + ' Failed to upload BIOS image')
            timetowait = 10
            returnCode = returnCode + 1

        try:
            session.expect('Flashing  Firmware Image :', timeout=timetowait)
            print(self.host + ' Flashing BIOS Image')
        except:
            print(self.host + ' Failed to flash BIOS image')
            timetowait = 10
            returnCode = returnCode + 2

        try:
            session.expect('Verifying Firmware Image :', timeout=timetowait)
            print(self.host + ' Verifying BIOS Image')
            session.expect('done', timeout=timetowait)
        except:
            print(self.host + ' Failed to verify BIOS image. Please wait for yafuflash to exit cleanly.')
            timetowait = 10
            returnCode = returnCode + 4

        # Wait for Yafuflash to exit
        session.wait()

        if returnCode < 1:
            print(self.host + ' Successfully flashed BIOS')
        else:
            print(self.host + ' Failed to flash BIOS')
        fout.close()
        self.stopTunnel()
        return returnCode

    def cmcFlash(self, file):
        print(self.host + ' doesn\'t support CMC flashing.')

    def cpldFlash(self, file):
        if 'win' in sys.platform:
            cmd = 'Yafuflash2 -nw -vyes -fb -host ' + self.host + ' -u ' + self.username + ' -p ' + self.password + ' -d 4 ' + file
        else:
            # Yafuflash2 doesn't support IPv6 Link-Local Address. Adding Tunnel
            self.startTunnel(['623'])
            cmd = 'Yafuflash2 -nw -vyes -fb -host ' + self.host.split('%')[0].split('fe80')[1] + ' -u ' + self.username + ' -p ' + self.password + ' -d 4 ' + file
        # session = PopenSpawn(cmd, maxread=2000)
        session = self.spawn(cmd, maxread=2000)

        filename = re.sub('[%:]', '.', self.host.split('%')[0])
        if 'win' in sys.platform:
            fout = open('temp\\' + filename + '_CPLDFLASH.txt', "wb")
        else:
            fout = open('temp/' + filename + '_CPLDFLASH.txt', "wb")
        fout.write(str.encode(cmd))
        session.logfile = fout

        print(self.host + ' Running: ' + cmd)
        returnCode = 0
        timetowait = 240
        try:
            session.expect('Beginning CPLD Update', timeout=600)
            print(self.host + ' Uploading CPLD Image')
        except:
            print(self.host + ' Failed to upload CPLD image')
            timetowait = 10
            returnCode = returnCode + 1

        try:
            session.expect('Flashing  Firmware Image :', timeout=timetowait)
            print(self.host + ' Flashing CPLD Image')
        except:
            print(self.host + ' Failed to flash CPLD image')
            timetowait = 10
            returnCode = returnCode + 2

        try:
            session.expect('Verifying Firmware Image :', timeout=timetowait)
            print(self.host + ' Verifying CPLD Image')
            session.expect('done', timeout=timetowait)
        except:
            print(self.host + ' Failed to verify CPLD image. Please wait for yafuflash to exit cleanly.')
            timetowait = 10
            returnCode = returnCode + 4
        # Wait for Yafuflash to exit
        session.wait()

        if returnCode < 1:
            print(self.host + ' Successfully flashed CPLD')
        else:
            print(self.host + ' Failed to flash CPLD')
        fout.close()
        self.stopTunnel()
        return returnCode


class D52B(QuantaSkylake):
    def __init__(self, host, username, password):
        QuantaSkylake.__init__(self, host, username, password)
        self.OCPpciloc = 'af:00'
        self.model = "D52B"
        self.Usize = 1

class DS120(D52B):
    def __init__(self, host, username, password):
        D52B.__init__(self, host, username, password)
        self.model = "DS120"
        self.Usize = 1

class DS220(D52B):
    def __init__(self, host, username, password):
        D52B.__init__(self, host, username, password)
        self.model = "DS220"
        self.Usize = 2

class D52BV(QuantaSkylake):
    def __init__(self, host, username, password):
        QuantaSkylake.__init__(self, host, username, password)
        self.model = "D52BV"
        self.Usize = 1

class DS225(D52BV):
    def __init__(self, host, username, password):
        D52B.__init__(self, host, username, password)
        self.model = "DS225"
        self.Usize = 2

class Q72D(QuantaSkylake):
    def __init__(self, host, username, password):
        QuantaSkylake.__init__(self, host, username, password)
        self.model = "Q72D"
        self.Usize = 2

    # CMC Flashing only applies to the Q72D Nodes
    def cmcFlash(self, file):
        if 'win' in sys.platform:
            cmd = 'Yafuflash2 -nw -vyes -fb -host ' + self.host + ' -u ' + self.username + ' -p ' + self.password + ' -d 0x20 ' + file
        else:
            # Yafuflash2 doesn't support IPv6 Link-Local Address. Adding Tunnel
            self.startTunnel(['623'])
            cmd = 'Yafuflash2 -nw -vyes -fb -host ' + self.host.split('%')[0].split('fe80')[1] + ' -u ' + self.username + ' -p ' + self.password + ' -d 0x20 ' + file
        # session = PopenSpawn(cmd, maxread=2000)
        session = self.spawn(cmd, maxread=2000)

        filename = re.sub('[%:]', '.', self.host.split('%')[0])
        if 'win' in sys.platform:
            fout = open('temp\\' + filename +'_CMCFLASH.txt',"wb")
        else:
            fout = open('temp/' + filename + '_CMCFLASH.txt', "wb")
        fout.write(str.encode(cmd))
        session.logfile = fout

        print(self.host + ' Running: ' + cmd)
        returnCode = 0
        timetowait = 240
        try:
            session.expect('Beginning BIC Update', timeout=600)
            print(self.host + ' Uploading CMC Image')
        except:
            print(self.host + ' Failed to upload CMC image')
            timetowait = 10
            returnCode = returnCode + 1

        try:
            session.expect('Flashing  Firmware Image :', timeout=timetowait)
            print(self.host + ' Flashing CMC Image')
        except:
            print(self.host + ' Failed to flash CMC image')
            timetowait = 10
            returnCode = returnCode + 2

        try:
            session.expect('Verifying Firmware Image :', timeout=timetowait)
            print(self.host + ' Verifying CMC Image')
            session.expect('done', timeout=timetowait)
        except:
            print(self.host + ' Failed to verify CMC image. Please wait for yafuflash to exit cleanly.')
            timetowait = 10
            returnCode = returnCode + 4
        # Wait for Yafuflash to exit
        session.wait()

        if returnCode < 1:
            print(self.host + ' Successfully flashed CMC')
        else:
            print(self.host + ' Failed to flash CMC')
        fout.close()
        self.stopTunnel()
        return returnCode

    # DOESN'T SUPPORT "ipmitool sel time set" COMMAND!!! UGHHHH!!!!!! Using Redfish Instead
    def setTime(self):
        nowtime = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
        timezone = '+00:00'
        senddata = '{"DateTime": "' + nowtime + timezone + '", "DateTimeLocalOffset": "' + timezone + '"}'
        try:
            session = requests.patch(self.redfishapi2 + 'Managers/Self/LogServices/SEL', auth=(self.username, self.password),
                                   verify=False, headers=self.redfishheader,
                                   data=senddata)
        except:
            pass
        if session.status_code == 204:
            print(self.host + ' ' + nowtime)
        else:
            print(self.host + ' Failed to set time.')

class DS240(Q72D):
    def __init__(self, host, username, password):
        Q72D.__init__(self, host, username, password)
        self.model = "DS240"
        self.Usize = 2
