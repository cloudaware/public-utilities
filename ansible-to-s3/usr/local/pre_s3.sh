#!/bin/bash

python -m json.tool $1 > /tmp/temp_file
cp /tmp/temp_file $1; rm -f /tmp/temp_file
sed -i 's/^[ \t]*//' $1
sed -i '/ec2_network_interfaces_macs/d' $1
sed -i '/ssh_host_key/d' $1
sed -i '/ansible_ssh_pass/d' $1
sed -i 's/ansible_ec2/ec2/g' $1
