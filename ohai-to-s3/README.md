ohai-to-s3
========

* Install the aws-sdk gem first:
```
gem install aws-sdk
```

* Clone the public-utilities repo to your server:
```
git clone https://github.com/cloudaware/public-utilities.git
```

* Copy the files to their respective locations and make the script executable:
```
cp -a public-utilities/ohai-to-s3/etc/cron.d/ohai2s3 /etc/cron.d/ohai2s3
cp -a public-utilities/ohai-to-s3/usr/sbin/ohai2s3.rb /usr/sbin/ohai2s3.rb
chmod +x /usr/sbin/ohai2s3.rb
```

* Edit the script to use your AWS key, secret key and bucket information:
```
@aws_key="" #This is the AWS Key
@aws_secret="" #This is the AWS Secret Key
@aws_bucket="" #This is the bucket where to load the ohai facts in json format
```

* Deploy the ohai-plugins cookbook using the next commands:
```
mkdir /var/chef/cookbooks
mv public-utilities/ohai-to-s3/cookbook/ohai-plugins /var/chef/cookbooks
knife cookbook upload ohai-plugins
```

* Create the ohai-plugin role:
```
export EDITOR=vi #any other editor can be selected, like nano for instance
knife role create ohai-plugin
```
Once in the editor, replace everything with the next content and save:
```
{
  "name": "ohai-plugin",
  "description": "",
  "json_class": "Chef::Role",
  "default_attributes": {},
  "override_attributes": {},
  "chef_type": "role",
  "run_list": [ "ohai-plugins" ],
  "env_run_lists": {

  }
}
```
* Add the role to the nodes that you need or to all nodes using your web interface or using the next command:
```
knife node run_list add $NODE_NAME 'role[ohai-plugin]' #Where $NODE_NAME is the name of the actual node
```
To add the role to all of the nodes you can run:
```
for node in `knife node list`;do knife node run_list add $node 'role[ohai-plugin]';done;
```
