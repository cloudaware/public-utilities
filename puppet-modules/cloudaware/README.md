facts2ca
---

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
