#!/bin/bash

sensu_server="localhost"
api_port="4567"
api_user="user"
api_pass="password"
s3_bucket="some-bucket"
s3_bucket_prefix=""

curl -s -X GET http://$api_user:$api_pass@$sensu_server:$api_port/clients | jq -r '.[].name' > /tmp/clients_list.json

for i in `cat /tmp/clients_list.json`
do
stat=`curl -s http://$api_user:$api_pass@$sensu_server:$api_port/events/$i| jq -r '.[0].check.status'`
if [[ $stat != null ]]; then
status="\"status\": $stat,"
else
status="\"status\": 0,"
fi
curl -s -X GET http://$api_user:$api_pass@$sensu_server:$api_port/clients/$i | jq -r '.' > /tmp/$i
sed -i "0,/^{.*/a\  $status" /tmp/$i
name=`grep 'instance_id' /tmp/$i | tr -d \" | tr -d \, |awk '{print $2}'`
if [[ -n $name ]]; then
mv /tmp/$i /tmp/$name.json
else
name=`grep 'address' /tmp/$i | tr -d \" | tr -d \, |awk '{print $2}' `
mv /tmp/$i /tmp/$name.json
fi
if [[ -n $s3_bucket_prefix ]]; then
s3cmd put /tmp/$name.json s3://$s3_bucket/$s3_bucket_prefix/
else
s3cmd sync /tmp/$name.json s3://$s3_bucket/
fi
done
