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
