**NOTE**: OSSEC uses ports UDP:1514 and TCP:1515. Ensure that firewall rules for agent nodes allow outbound trafic on these ports.

### Supported operating systems:
- Debian 7 (wheezy)
- Debian 8 (jessie)
- Ubuntu 12.04 (precise)
- Ubuntu 14.04 (trysty)
- Centos 5
- Centos 6
- Centos 7
- Red Hat Enterprise Linux 5
- Red Hat Enterprise Linux 6
- Red Hat Enterprise Linux 7
- Amazon Linux 2015.03
- Amazon Linux 2015.09

### Get installer
```
wget --no-check-certificate https://raw.githubusercontent.com/cloudaware/public-utilities/master/ossec-installer/ossec-installer.bash
```
**NOTE**: if you have not 'wget' on your server you can install it by the next commands:
```
apt-get install wget    # For Debian and Ubuntu
yum install wget        # For CentOS, Red Hat and Amazon Linux
```

### Change installer mode
```
chmod +x ./ossec-installer.bash
```

### Install OSSEC Agent
- with server hostname definition:
```
./ossec-installer.bash --server-hostname=ossec.example.com
```
- with server IP definition:
```
./ossec-installer.bash --server-ip=1.2.3.4
```
- with server hostname and node name definition:
```
./ossec-installer.bash --server-hostname=ossec.example.com --node-name=foo
```
- with server IP and node name definition:
```
./ossec-installer.bash --server-ip=1.2.3.4 --node-name=bar
```
- with Docker support:
```
./ossec-installer.bash --docker
```
**NOTE**: default node name is $HOSTNAME or $INSTANCE_ID on AWS
- Ninja mode :)
```
./ossec-installer.bash --help
```
