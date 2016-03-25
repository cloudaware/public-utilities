### Ansible facts to S3 bucket
- Requirements:
 - boto
 - python >= 2.6
 - AWS EC2 External Inventory Script

- Create a ~/.boto file with these contents:
```sh
[Credentials]
aws_access_key_id = YOURACCESSKEY
aws_secret_access_key = YOURSECRETKEY
```

- Put playbook file 'facts_to_s3.yaml' to your '/etc/ansible' directory.
In this file you need to specify your hosts, for example we use servers with Name tags 'ansible_server'
```sh
 - hosts: tag_Name_ansible_server
```
Also you should to specify your bucket name.
```sh
    local_action: s3 bucket=some-bucket
```

- Copy 'pre_s3.py' script to your '/usr/local' directory and make it executable.

- Put 'ansible_to_s3' file to the '/etc/cron.d' directory.
Note: You should to change user from which run cron job in the file '/etc/cron.d/ansible_to_s3', we use 'root' user for example.
