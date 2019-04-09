#!/bin/bash
#description            :This script will setup the server auto tunnel.
#author                 :Robin Lennox
#==============================================================================

username=$1
sshkey=$(echo $2 | base64 --decode)
clientDesc="${@:3}"

# Create the drop box user account
useradd -m -r -s /bin/bash ${username} -c "${clientDesc}" > /dev/null

# Setup drop box ssh keys
mkdir /home/${username}/.ssh > /dev/null
#touch /home/${username}/.ssh/authorized_keys
echo no-pty,no-X11-forwarding ${sshkey} >> /home/${username}/.ssh/authorized_keys
chown -R ${username} /home/${username} > /dev/null
echo "Match User ${username}
    PasswordAuthentication no" >> /etc/ssh/sshd_config

# Enable root login over SSH using a password
#sed -Ei 's/^PermitRootLogin without-password/PermitRootLogin yes/' /etc/ssh/sshd_config > /dev/null

# Start the SSH service
update-rc.d ssh enable > /dev/null
service ssh restart > /dev/null

#sudo ssh -R 9000:localhost:22 ${username}@139.59.228.224 -i /home/${username}/.ssh/id_rsa