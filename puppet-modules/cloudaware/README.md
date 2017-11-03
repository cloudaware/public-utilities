## facts2ca

### Install by Puppet

1. Put Puppet module `cloudaware` to the `/etc/puppetlabs/code/environments/production/modules/`.
2. Add new class `cloudaware::facts2ca` in the Puppet Dashboard.
3. Attach `cloudaware::facts2ca` class to the Puppet server node.
4. Add required variable `facts2ca_s3_bucket` to the Puppet server node with value like `S3_BUCKET/[SOME/PATH]`.

Optional variables:
```
facts2ca_s3_region
  S3 bucket region. Default: 'us-east-1'

facts2ca_access_key, facts2ca_secret_key
  Access credentials for IAM user. By default module uses the EC2 IAM Role.
```

### Uninstall

1. Disable Puppet module `cloudaware` for Puppet master.
2. Remove cronjob file:
    ```
    rm /etc/cron.d/facts2ca
    ```
3. Remove `facts2ca` application and configuration files:
    ```
    rm /opt/puppetlabs/mcollective/plugins/mcollective/application/facts2ca.rb
    rm /etc/puppetlabs/mcollective/facts2ca.yaml
    ```
4. Uninstall Rubygem `aws-sdk`:
    ```
    /opt/puppetlabs/puppet/bin/gem uninstall aws-sdk -v 2.0.33
    ```
