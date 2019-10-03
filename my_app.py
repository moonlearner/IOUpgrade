
import os
import subprocess
print(" I love shanghai")
cmd = ["lspci -mm |  grep --color=never"]
#cmd = ['lspci','-mm', '| grep --color=never']
#cmd = ['ls', '-l']
#proc = subprocess.run(cmd, stdout=subprocess.PIPE)
#tmp = proc.stdout.decode('utf-8')
output = subprocess.getoutput("lspci -mm | grep --color=never Ethernet")
#try:
#    output = output.split(cmd + '\r\n')[1]
#except:
#    pass
print(output)


