#!/bin/bash

sed -i '/ec2_network_interfaces_macs/d' /tmp/$1.json
sed -i 's/^[ \t]*//' /tmp/$1.json
sed -i 's/ansible_ec2/ec2/' /tmp/$1.json
