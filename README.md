# public-utilities
Some public utilities.

### Installation mysql-backups-to-s3
- you need to have **'s3cmd'** installed and configured on a server:
```sh
# apt-get install s3cmd
or
# yum install s3cmd
```
```sh
# s3cmd --configure
```

- copy the following files below to a proper place, e.g. ~/bin
 - mysql_maint.sh
 - mysql_backup.sh
 - mysql_credentials_file

- edit the variables **'MYSQL_USER'** and **'MYSQL_PASS'** in the file **'mysql_credentials_file'** (these credentials with proper access must be on all mysql servers that you want to take backups from)
- edit the following variables below for your needs in the file **'mysql_backup.sh'**
 - 'BACKUP_DIR' - local folder on the server with enough space;
 - 'S3_BUCKET' - existing S3 bucket in your AWS account
 - 'S3CMD_CONF' - config file of 's3cmd' util with your AWS credentials
 - 'MYSQL_MAINT' - path to the script 'mysql_maint.sh'
 - 'MYSQL_CREDENTIALS_FILE' - path to the file 'mysql_credentials_file'
- edit the following variables below for your needs in the file **'mysql_backup.sh'**
 - DELETE_CURRENT_BACKUPS_OLDER_THAN="1 month ago"
 - DELETE_DAILY___BACKUPS_OLDER_THAN="6 months ago"
 - DELETE_WEEKLY__BACKUPS_OLDER_THAN="1 year ago"
 - DELETE_MONTHLY_BACKUPS_OLDER_THAN="3 years ago"
- add mysql servers into the file **'mysql_backup.sh'** to be backed up:
```sh
BACKUP_HOST_NAME="MYSQL1"
MYSQL_HOST="MYSQL1.sample.com"
backup
#
BACKUP_HOST_NAME="MYSQL2"
MYSQL_HOST="MYSQL2.sample.com"
backup
```
- configure a cron job on the server to run the script **'mysql_backup.sh'**
