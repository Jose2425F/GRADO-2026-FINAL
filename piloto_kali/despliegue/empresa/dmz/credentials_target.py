"""Servicios sintéticos: SSH sin privilegios y FTP sin escritura."""
import os
import subprocess
from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer

password = os.environ['LAB_TARGET_PASSWORD']
subprocess.run(['chpasswd'], input=f'labuser:{password}\n', text=True, check=True)
subprocess.run(['ssh-keygen', '-A'], check=True)
subprocess.Popen(['/usr/sbin/sshd', '-D', '-e', '-o', 'PasswordAuthentication=yes',
                  '-o', 'PermitRootLogin=no', '-o', 'AllowUsers=labuser',
                  '-o', 'AllowTcpForwarding=no', '-o', 'X11Forwarding=no',
                  '-o', 'MaxAuthTries=2'])
authorizer = DummyAuthorizer()
authorizer.add_user('labuser', password, '/srv/ftp', perm='elr')
handler = FTPHandler
handler.authorizer = authorizer
handler.banner = 'pyftpdlib 2.2.0 FTP (laboratorio autorizado)'
FTPServer(('0.0.0.0', 21), handler).serve_forever()
