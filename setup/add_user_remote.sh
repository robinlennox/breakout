#!/bin/bash
#title          :add_user_remote.sh
#description    :Adds a client's SSH public key to the callback server to allow reverse tunnels.
#author         :Robin Lennox
#==============================================================================

username=$1
sshkey=$(echo $2 | base64 --decode)
privkey=$(echo $3 | base64 --decode)
clientDesc="${@:4}"

# Create the drop box user account
useradd -m -r -s /bin/bash ${username} -c "${clientDesc}" > /dev/null

# Setup drop box ssh keys
mkdir /home/${username}/.ssh > /dev/null
#touch /home/${username}/.ssh/authorized_keys
echo no-pty,no-X11-forwarding ${sshkey} >> /home/${username}/.ssh/authorized_keys
echo "${privkey}" > /home/${username}/.ssh/id_rsa
echo "${sshkey}" > /home/${username}/.ssh/id_rsa.pub

chmod 700 /home/${username}/.ssh
chmod 600 /home/${username}/.ssh/id_rsa
chmod 644 /home/${username}/.ssh/id_rsa.pub
chown -R ${username} /home/${username} > /dev/null

echo "Match User ${username}
    PasswordAuthentication no" >> /etc/ssh/sshd_config

# Enable root login over SSH using a password
#sed -Ei 's/^PermitRootLogin without-password/PermitRootLogin yes/' /etc/ssh/sshd_config > /dev/null

# Start the SSH service
update-rc.d ssh enable > /dev/null
service ssh restart > /dev/null

#sudo ssh -R 9000:localhost:22 ${username}@139.59.228.224 -i /home/${username}/.ssh/id_rsa