### Installation sensu-to-s3
- You need to have **'s3cmd'** installed and configured on a server:
```sh
# apt-get install s3cmd
or
# yum install s3cmd
```
```sh
# s3cmd --configure
```

- edit the following variables below for your needs in the file **'sensu_get_clients.sh'**
 - 'sensu_server' - IP address or DNS name of sensu server;
 - 'api_port' - Sensu API port;
 - 'api_user' - User name to access sensu API;
 - 'api_pass' - Password to sensu API;
 - 's3_bucket' - S3 bucket name;
 - 's3_bucket_prefix' - The prefix value in Amazon S3 bucket. You can leave it blank.


- Put the file **'sensu_get_clients.sh'** into **'/usr/local/sbin'** directory.
- Copy file **'get_clients'** into your **'etc/cron.d'** directory.
