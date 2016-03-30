### Ansible facts to S3 bucket
- Requirements:
 - python >= 2.6
 - python-boto
 - AWS EC2 External Inventory Script

- How to install and configure AWS EC2 External Inventory Script you can find at the following link: http://docs.ansible.com/ansible/intro_dynamic_inventory.html#example-aws-ec2-external-inventory-script
- You should to create a '~/.boto' file with these contents in the home directory of the user under which you will run a playbook:
```sh
[Credentials]
aws_access_key_id = YOUR_ACCESS_KEY
aws_secret_access_key = YOUR_SECRET_KEY
```

- Put playbook file 'facts_to_s3.yml' to your '/etc/ansible' directory.
In this file you need to specify your hosts, for example we use servers with Name tags 'ansible_server'
```sh
    - hosts: tag_Name_ansible_server
```
Also you should to specify your bucket name.
```sh
    local_action: s3 bucket=some-bucket
```

- Copy 'pre_s3.py' script to your '/usr/local' directory and make it executable.
```
    chmod +x /usr/local/pre_s3.py
```
- To run playbook periodically you should put 'ansible_to_s3' file to the '/etc/cron.d' directory.
Note: You should to change user from which run cron job in the '/etc/cron.d/ansible_to_s3' file, we use 'root' user for example.
