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

- Put the 'facts_to_s3.yml' file to your '/etc/ansible' directory.
In this file you need to specify your hosts, for example we use servers with Name tags 'ansible_server'
```sh
    - hosts: tag_Name_ansible_server
```
Also you should to specify 'cron_user' and 's3_bucket' variables in this file.
```sh
    cron_user: root
    s3_bucket: some-bucket
```
cron_user will be used in your cron job for periodically update your facts on s3 bucket. Also your s3 bucket should contain 'ansible-facts' directory. Please note that 'cron_user' should have access to '.boto' file with credentials to your s3 bucket.

- After that you will be able to run your playbook by the following command
```
ansible-playbook facts_to_s3.yml
```
