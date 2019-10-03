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
            ("AVAGO_MegaRAID_SAS_9460-16i"): {
                "2017-12-17": {"Version": "5.040.00-1123", "File": "50.4.0-0919_9460-16i_SAS_MR_FW_IMAGE.zip"},
                "2018-05-31": {"Version": "5.060.00-1455", "File": "50.6.0-1375_9460-16i_SAS_MR_FW_IMAGE.zip"}
            }
        }

        self.vmwaredictionary = {
            "2019-04-25_UCPv20190425": {
                "ESXI_Version": "6.5U2/6.7U1",
                "ESXI_Build": "10390116/10302608",
                "Nodes": {
                    "D52B": "2019-04-25",
                    "DS120": "2018-08-19",
                    "DS220": "2018-08-19",
                    "D52BV": "2018-07-30",
                    "DS225": "2018-07-30",
                    "Q72D": "2018-08-20",
                    "DS240": "2018-08-20"
                },
                "IOCards": {
                    "AVAGO_MegaRAID_SAS_9460-16i": "2017-12-17",
                    "AVAGO_MegaRAID_SAS_PCI_Express_ROMB-QS-3516B": "2018-01-11",
                    "Emulex_LPe31002-M6": "2018-02-06",
                    "Emulex_LPe32002-M2": "2018-02-06",
                    "Intel(R)_Ethernet_Connection_X722_for_10GbE_SFP+": "2018-02-23",
                    "Intel(R)_Ethernet_Network_Adapter_XXV710-2": "2017-11-30",
                    "LSI_SAS9305-16i": "2017-05-03",
                    "LSI_QS3216": "2017-06-14",
                    "MCX4121A-ACA_Ax": "2018-07-12",
                    "Quanta_S5B_CX4Lx_25G_2P": "2018-02-03"
                }
            },
            "2017-09-08_UCPv20170908": {
                "ESXI_Version": "###6.5U2/6.7U1",
                "ESXI_Build": "###10390116/10302608",
                "Nodes": {
                    "D52B": "2019-04-25",
                    "DS120": "2018-08-19",
                    "DS220": "2018-08-19",
                    "D52BV": "2018-07-30",
                    "DS225": "2018-07-30",
                    "Q72D": "###2018-08-20",
                    "DS240": "###2018-08-20"
                },
                "IOCards": {
                    "AVAGO_MegaRAID_SAS_9460-16i": "###2017-12-17",
                    "AVAGO_MegaRAID_SAS_PCI_Express_ROMB-QS-3516B": "2018-01-11",
                    "Emulex_LPe31002-M6": "2018-02-06",
                    "Emulex_LPe32002-M2": "2018-02-06",
                    "Intel(R)_Ethernet_Connection_X722_for_10GbE_SFP+": "2018-02-23",
                    "Intel(R)_Ethernet_Network_Adapter_XXV710-2": "2017-11-30",
                    "LSI_SAS9305-16i": "2017-05-03",
                    "LSI_QS3216": "2017-06-14",
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
                print("The date: ", date)
                print("The data: ", data)

                if str(inputdata) in date:
                    print(inputdata)
                    for item, itemdata in data.items():
                        if 'Nodes' in item or 'IOCards' in item:
                            for node, nodedate in itemdata.items():
                                print("Jenny node: ", node)
                                print("Jenny nodedate: ", nodedate)
                                print(json.dumps(self.returnfirmwarefileJSON(node, nodedate), indent=4))

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
        print("This pass value for name: ", name)
        print("This pass value for inputdata: ", inputdata)
        for device, data in self.firmwaredictionary.items():
            print("This device is the ", device)
            print("This data is the  ", data)
            print("=======================================")
            if name in device:
                for datesel, json in data.items():
                    print("This datesel is the: ", datesel)
                    print("This json is the: ", json)
                    if inputdata in datesel or inputdata in json.get("Version", ""):
                        return json
        raise ValueError("Can't find JSON profile")

def main():

    f = firmware()

    # Ask the user which vSphere version so we can flash the DS120/220 with appropriate firmware.
    #while True:
    print('\nWhich appliance are you going to install? (Note: Entering UCP is the default option)\n')
    f.printesxiselection()
    date = input('Enter the date and/or version (if any): ')
    if len(f.returnesxiselection(date)) < 1:
        print('I couldn\'t find this selection. Please try again.')
    else:
        print('\nThis selection has the following firmwares:')
        f.printesxiselection(date)
        #firmwareselection = f.returnesxiselection(date)
        #break

if __name__ == '__main__':
    main()
