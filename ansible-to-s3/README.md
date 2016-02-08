### Ansible facts to S3 bucket
- Requirements:
 - boto
 - python >= 2.6

- Create a ~/.boto file with these contents:
```sh
[Credentials]
aws_access_key_id = YOURACCESSKEY
aws_secret_access_key = YOURSECRETKEY
```

- Put 'pre_s3.sh' file to the '/usr/local' directory and make it file executable.
```sh
# chmod +x /usr/local/pre_s3.sh
```

- Put playbook file 'facts_to_s3.yaml' to your '/etc/ansible' directory.
