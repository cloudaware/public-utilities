### Get installer
```
wget --no-check-certificate https://raw.githubusercontent.com/cloudaware/public-utilities/master/ossec-installer/ossec-installer.bash
```

### Change installer mode
```
chmod +x ./ossec-installer.bash
```

### Install OSSEC Agent
- with server hostname definition:
```
./ossec-installer.bash --server-hostname ossec.example.com
```
- with server IP definition:
```
./ossec-installer.bash --server-ip 1.2.3.4
```
- with server hostname and node name definition:
```
./ossec-installer.bash --server-hostname ossec.example.com --node-name=foo
```
- with server IP and node name definition:
```
./ossec-installer.bash --server-ip 1.2.3.4 --node-name=bar
```
**NOTE**: default node name is $HOSTNAME or $INSTANCE_ID on AWS
- Ninja mode :)
```
./ossec-installer.bash --help
```
