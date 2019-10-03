import quantaskylake
import minios
from prettytable import PrettyTable
import os


node = quantaskylake.D52B('10.76.38.52', 'admin', 'cmb9.admin')
test = minios.minios(node)
#tset = minios(node) # if this is used, there is an error that module is not callable
test.login()
test.discoverPCIDevices()
founddevices = test.printPCIDevices()

'''
#print("=================Starting to Upgrade==========================")
#pcitest = minios.intelNIC(test, '3d:00')
#pcitest.flash("/cdrom/firmware/Intel(R)_Ethrnet_Connection_X722_for_10GbE_SFP+/ON 10GbE X722-X527-DA4 SFP plus_FW-Online-Auto_Linux_0004.zip")
#pcitest.flash("/cdrom/firmware/Intel(R)_Ethernet_Connection_X722_for_10GbE_SFP+/2018_WW46_LBG_X722_NUP_UEFI_v0006.zip")

#melltext = minios.mellanoxNIC(test, '3d:00')
# melltext.flash('/cdrom/firmware/Quanta_S5B_CX4Lx_25G_2P/3GS5BMA0000_MLX_25G_dual_port_14_20_1010_Online.zip')
#melltext.flash('/cdrom/firmware/Intel(R)_Ethernet_Connection_X722_for_10GbE_SFP+/2018_WW46_LBG_X722_NUP_UEFI_v0006.zip')

founddevices = test.printPCIDevices2()

print(node.host + " Discovered the following PCI Devices:")
t = PrettyTable(["PCI_Address", "Name", "Firmware", "Serial", "VID", "DVID", "SVID", "SSID"])
t.sortby = "PCI_Address"
for device2, pciclass2 in founddevices.items():
    print(node.host + ' In Loop --- Discovered PCI Device: ' + device2 + ' ' + pciclass2.name + ' v.' + pciclass2.firmware)
    # This path is relative to the MiniOS
    for ch in ['(', ')']:
        if ch in pciclass2.name:
            pciclass2.name = pciclass2.name.replace(ch, "\\"+ch)
            #pciclass2.name = pciclass2.name.replace(ch, "" + ch)
    filepath = "/cdrom/firmware/" + pciclass2.name + "/"

    if (filepath.find("LSI_Quanta_Mezz")  != -1):
        filepath = filepath.replace("LSI_Quanta_Mezz", "LSI_QS3216")
    elif (filepath.find("X722_for_10GBASE-T")  != -1):
        filepath = filepath.replace("X722_for_10GBASE-T", "X722_for_10GbE_SFP+")

    filename = test.discoverNewestFile(filepath)
    print("=======filename: ", filename)

    # Add Codes for flash device:
    # Initialize the PCI Devices
    line = filepath
    fullfilepath = filepath + filename
    fullfilepath = fullfilepath.rstrip()    # strip out all tailing whitespace
    print("This line has the value = ", line)
    if 'Ethernet' in line or 'Quanta' in line or 'MCX' in line:
        if 'Mellanox' in line or 'Quanta' in line or 'MCX' in line:
            print(node.host + ' ******Found a Mellanox Ethernet Card******', device2)
            print("The fullfilepath ===", fullfilepath)
            melltext = minios.mellanoxNIC(test, device2)
            melltext.flash(fullfilepath)
            #melltext.flash('/cdrom/firmware/Quanta_S5B_CX4Lx_25G_2P/3GS5BMA0000_MLX_25G_dual_port_14_20_1010_Online.zip')

        # For some reason, there is a dummy device within the Intel NICs that has DID 37cc. Ignoring it.
        elif 'Intel' in line and '37cc' not in line:
            print(node.host + ' ******Found a Intel Ethernet Card***** ', device2)
            pcitest = minios.intelNIC(test, device2)
            #fullfilepath = line + 'ON 10GbE X722-X527-DA4 SFP plus_FW-Online-Auto_Linux_0004.zip'
            print("This full file path is ", fullfilepath)
            fullfilepath = fullfilepath.replace("\\", "")
            pcitest.flash(fullfilepath)

            #pcitest.flash("/cdrom/firmware/Intel(R)_Ethrnet_Connection_X722_for_10GbE_SFP+/ON 10GbE X722-X527-DA4 SFP plus_FW-Online-Auto_Linux_0004.zip")

    elif 'Fibre' in line or 'Emulex' in line:
        if 'Emulex' in line:
            print(node.host + ' Found a Emulex HBA')
            emulextest = minios.emulexHBA(test, device2)
            #emulextest.flash('/cdrom/firmware/Emulex_LPe31002-M6/lancerg6_A11.4.204.25.grp')
            emulextest.flash(fullfilepath)
    elif 'Serial Attached SCSI' in line or 'LSI' in line:
        if 'LSI' in line:
            print(node.host + ' ******Found a LSI SAS Card******', device2)
            print("The fullfilepath ===", fullfilepath)
            sastest = minios.LSISAS3Controller(test, device2)
            sastest.flash(fullfilepath)
            #sastest = LSISAS3Controller(test, '5e:00')
            #sastest.flash("/cdrom/firmware/Quanta-QS3216/Qfw_1A14.zip")

    elif 'RAID' in line:
        if 'LSI' in line:
            print(node.host + ' Found a LSI RAID Card')
            #self.PCIDevices.update({busdevID: AVAGORAIDController(self, busdevID)})
    elif 'VGA compatible controller' in line or '3D controller' in line:
        if 'NVIDIA' in line:
            print(node.host + ' Found a NVIDIA GPU')
            #self.PCIDevices.update({busdevID: NVIDIAGPUController(self, busdevID)})
    elif 'Non-Volatile memory controller' in line:
        if 'Intel' in line:
            print(node.host + ' Found a Intel NVMe Device')
            #self.PCIDevices.update({busdevID: IntelNVMeDevice(self, busdevID)})

    t.add_row(
            [device2, pciclass2.name, pciclass2.firmware, pciclass2.serial, pciclass2.VID, pciclass2.DVID, pciclass2.SVID,
             pciclass2.SSID])
#print(t)


#print("=================Starting to Upgrade==========================")
emulextest = minios.emulexHBA(test,'86:00')
emulextest.flash('/cdrom/firmware/Emulex_LPe31002-M6/lancerg6_A11.4.204.25.grp')


melltext = minios.mellanoxNIC(test, '3b:00')
melltext.flash('/cdrom/firmware/Quanta_S5B_CX4Lx_25G_2P/3GS5BMA0000_MLX_25G_dual_port_14_20_1010_Online.zip')

pcitest = minios.intelNIC(test, '3d:00')
pcitest.flash("/cdrom/firmware/Intel(R)_Ethrnet_Connection_X722_for_10GbE_SFP+/ON 10GbE X722-X527-DA4 SFP plus_FW-Online-Auto_Linux_0004.zip")



raidtest = AVAGORAIDController(test, '5e:00')
raidtest.flash("/cdrom/firmware/AVAGO_MegaRAID_SAS_PCI_Express_ROMB-QS-3516B/QS-3516B-16i-R6-PD32-2G_FW-Online_5.040.00-1123.zip")


class AVAGORAIDController(SASController):
class emulexHBA(HBA):

sastest = LSISAS3Controller(test, '5e:00')
sastest.flash("/cdrom/firmware/Quanta-QS3216/Qfw_1A14.zip")

node = quantaskylake.D52B('fe80::aa1e:84ff:fe73:ba49%13', 'admin', 'cmb9.admin')

test = minios(node)

test.login()

test.discoverPCIDevices()
test.printPCIDevices()
# test.dancePCIDevices()

#pcitest = intelNIC(test, '3d:00')
# pcitest.flash("/cdrom/firmware/Intel(R)_Ethrnet_Connection_X722_for_10GbE_SFP+/ON 10GbE X722-X527-DA4 SFP plus_FW-Online-Auto_Linux_0004.zip")



node = quantaskylake.D52B('fe80::aa1e:84ff:fe73:ba49%13', 'admin', 'cmb9.admin')


# node.deleteVMCLIapp()
test.discoverPCIDevices()
test.printPCIDevices()
#node.setMiniOSDefaults()
node.poweroff()
time.sleep(60)
# node.createVMCLIapp()
# node.startVMCLIapp('minios2.iso')
#node.poweron()

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
