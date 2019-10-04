dictionarytemp = {}
line = "Emulex LPe31002-M6 FV12.0.193.13 DV12.0.0.10. HN:ubuntu2. OS:Linux" 
lines = line.split(' ')
print(lines)
print(len(lines))
if len(lines) > 1:
#    dictionarytemp.update({lines[0].strip():lines[1].strip()})
#for keys,values in dictionarytemp.items():
#    print(keys)
#    print(values)
    for x in range(len(lines)):
        print(lines[x])

 # Get the serial number
        for key, value in self.hbacmdlisthbadict.items():
            try:
                self.serial = value['Serial No.']
                break
            except:
                pass

        return None
