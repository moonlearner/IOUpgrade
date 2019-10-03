import pexpect
import sys
import time

class forwarding(object):
    def __init__(self, localhost, localports, remotehost, remoteports):
        self.remotehost = str(remotehost)
        self.remoteports = remoteports
        self.localhost = str(localhost)
        self.localports = localports
        self.sshclient = 'localhost'
        self.sshsession = None

        self.username = 'ucpadmin'
        self.password = 'Hitachi1'

    def start(self):
        if 'win' in sys.platform:
            raise(ValueError('This isn\'t for Windows.'))
        else:
            cmdstart = 'sudo ssh '
            for localport, remoteport in zip(self.localports, self.remoteports):
                print(self.remotehost + ' Starting Port Forwarding \'[' + self.localhost + ']:' + str(localport) + ':[' + self.remotehost + ']:' + str(remoteport) + '\'')
                cmdstart += '-L [' + self.localhost + ']:' + str(localport) + ':[' + self.remotehost + ']:' + str(remoteport) + ' '
            cmd = cmdstart + ' ' + self.username + '@' + self.sshclient
            # Add IPv6 Localhost IP for IPv6 Tunnel
            temp = pexpect.spawn('sudo ifconfig lo inet6 add ' + self.localhost + '/128')
            temp.wait()
            time.sleep(1)
            # print(self.remotehost + ' sudo ssh -L [' + self.localhost + ']:' + self.localport + ':[' + self.remotehost + ']:' + self.remoteport + ' ' + self.username + '@' + self.sshclient)
            self.sshsession = pexpect.spawn(cmd, encoding='utf-8')
            self.sshsession.expect(self.username + '@' + self.sshclient + '\'s password:')
            self.sshsession.sendline(self.password)
            time.sleep(1)

    def stop(self):
        print(self.remotehost + ' Stopping Port Forward')
        self.sshsession.close()
        # Remove IPv6 Localhost IP for IPv6 Tunnel
        temp = pexpect.spawn('sudo ifconfig lo inet6 del ' + self.localhost + '/128')
        temp.wait()

'''
test = forwarding('::aa1e:84ff:fe73:ba85', ['443', '5120'], 'fe80::aa1e:84ff:fe73:ba85%enp0s8', ['443', '5120'])
test.start()
test.stop()
'''