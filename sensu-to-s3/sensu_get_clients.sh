#!/bin/bash

sensu_server="localhost"
api_port="4567"
api_user="user"
api_pass="password"
s3_bucket="some-bucket"
s3_bucket_prefix=""

curl -X GET http://$api_user:$api_pass@$sensu_server:$api_port/clients -o /tmp/clients_list.json

if [[ -n $s3_bucket_prefix ]]; then
s3cmd put /tmp/clients_list.json s3://$s3_bucket/$s3_bucket_prefix/
else
s3cmd sync /tmp/clients_list.json s3://$s3_bucket/
fi
