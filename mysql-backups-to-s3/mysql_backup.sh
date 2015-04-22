#!/bin/sh

PREF=~/bin
PATH=/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin:$PREF

[ -s $0.pid ] && [ -n "$(ps `cat $0.pid` | grep "$0")" ] && exit 1
pidof -x $0 > $0.pid

# Backup folder
# /!\ Don't add a trailing slash
BACKUP_DIR="/mnt/mysql_backups"
S3_BUCKET="s3://mysql-backups"
S3CMD_CONF="~/.s3cfg"
MYSQL_MAINT="~/bin/mysql_maint.sh"
MYSQL_CREDENTIALS_FILE="~/bin/mysql_credentials_file"

DELETE_CURRENT_BACKUPS_OLDER_THAN="1 month ago"
DELETE_DAILY___BACKUPS_OLDER_THAN="6 months ago"
DELETE_WEEKLY__BACKUPS_OLDER_THAN="1 year ago"
DELETE_MONTHLY_BACKUPS_OLDER_THAN="3 years ago"

MYSQL_BACKUPS_S3="/tmp/MYSQL_backups_S3.tmp"

# Backup folders names
CURRENT_FOLDER='01_current'
DAILY_FOLDER='02_daily'
WEEKLY_FOLDER='03_weekly'
MONTHLY_FOLDER='04_monthly'

backup() {
    sleep 2
    nice -n 15 $MYSQL_MAINT -b -H "$MYSQL_HOST" -P "$MYSQL_PORT" -u "$MYSQL_USER" -p "$MYSQL_PASS" -d "$BACKUP_DIR" -n "$BACKUP_HOST_NAME" &
}

# Server name
# The backups will go to ${BACKUP_DIR}/${BACKUP_HOST_NAME}/<db-name>
# defaults to $DB_HOST

MYSQL_USER=""
MYSQL_PASS=""
MYSQL_PORT="3306"

test -f $MYSQL_CREDENTIALS_FILE && . $MYSQL_CREDENTIALS_FILE

if [ "$MYSQL_USER" = "" -o "$MYSQL_PASS" = "" ]; then
    echo "Please specify MySQL credentials. Exiting..."
    rm -f $0.pid
    exit 1
fi

##################################################################################################

BACKUP_HOST_NAME="MYSQL1"
MYSQL_HOST="MYSQL1.sample.com"
backup

BACKUP_HOST_NAME="MYSQL2"
MYSQL_HOST="MYSQL2.sample.com"
backup

##################################################################################################

# Wait until mysql_maint works
sleep 3
while [ -n "`ls -1 /tmp/mysql_maint-*.pid 2> /dev/null`" ]; do
    sleep 3
done

#ulimit -n 100000

getvariable() {
    echo $1 | sed 's/\/$//'
}

S3_BUCKET=`getvariable $S3_BUCKET`
LOCAL_DIR=`getvariable $BACKUP_DIR`
DESTINATION="$S3_BUCKET/$(echo $LOCAL_DIR | awk -F/ '{print $NF}')"

echo ""
find $LOCAL_DIR/ -type f -name "*.sql.bz2" > $MYSQL_BACKUPS_S3
for BACKUP_FOLDER in $CURRENT_FOLDER $DAILY_FOLDER $WEEKLY_FOLDER $MONTHLY_FOLDER; do
    [ "$BACKUP_FOLDER" = "$CURRENT_FOLDER" ] && PERIOD_OF_ROTATION="$DELETE_CURRENT_BACKUPS_OLDER_THAN"
    [ "$BACKUP_FOLDER" = "$DAILY_FOLDER" ]   && PERIOD_OF_ROTATION="$DELETE_DAILY___BACKUPS_OLDER_THAN"
    [ "$BACKUP_FOLDER" = "$WEEKLY_FOLDER" ]  && PERIOD_OF_ROTATION="$DELETE_WEEKLY__BACKUPS_OLDER_THAN"
    [ "$BACKUP_FOLDER" = "$MONTHLY_FOLDER" ] && PERIOD_OF_ROTATION="$DELETE_MONTHLY_BACKUPS_OLDER_THAN"
    ROTATION_DATE=`date -d "$PERIOD_OF_ROTATION" +%Y.%m.%d`
    DATES_LOCAL=`grep "$BACKUP_FOLDER" $MYSQL_BACKUPS_S3 | sed 's|^'$LOCAL_DIR'\/.*\/'$BACKUP_FOLDER'\/.*\_\(....\-..\-..\).*\.sql\.bz2$|\1|' | sort | uniq`
    for DATE_LOCAL in $DATES_LOCAL; do
	if [ `echo $DATE_LOCAL | tr -d ".|-" | awk '{print substr($0,length-7)}'` -lt `echo $ROTATION_DATE | tr -d ".|-"` ]; then
	    echo ""
	    echo "----- Deleting old backups from the folder \"$BACKUP_FOLDER\" for the date \"$DATE_LOCAL\", PERIOD_OF_ROTATION=\"$PERIOD_OF_ROTATION\""
	    DELETE_BACKUPS=`grep "$BACKUP_FOLDER" $MYSQL_BACKUPS_S3 | grep $DATE_LOCAL`
	    for BACKUP in $DELETE_BACKUPS; do
		rm -vf $BACKUP
	    done
	fi
    done
done

# Deleting empty folders
find $LOCAL_DIR/ -type d -empty -delete

# Syncing backups to S3 and deleting the local backup dir.
echo ""
echo "----- Start synchronizing $LOCAL_DIR at `date`"
s3cmd -c $S3CMD_CONF --skip-existing sync $LOCAL_DIR/ $DESTINATION/ && \
rm -rf $LOCAL_DIR
echo "===== Stop  synchronizing $LOCAL_DIR at `date`"
echo ""

# Deleting old S3 backups
s3cmd -c $S3CMD_CONF -r ls $DESTINATION/ | awk '/sql\.bz2$/ {print $4}' > $MYSQL_BACKUPS_S3
for BACKUP_FOLDER in $CURRENT_FOLDER $DAILY_FOLDER $WEEKLY_FOLDER $MONTHLY_FOLDER; do
    [ "$BACKUP_FOLDER" = "$CURRENT_FOLDER" ] && PERIOD_OF_ROTATION="$DELETE_CURRENT_BACKUPS_OLDER_THAN"
    [ "$BACKUP_FOLDER" = "$DAILY_FOLDER" ]   && PERIOD_OF_ROTATION="$DELETE_DAILY___BACKUPS_OLDER_THAN"
    [ "$BACKUP_FOLDER" = "$WEEKLY_FOLDER" ]  && PERIOD_OF_ROTATION="$DELETE_WEEKLY__BACKUPS_OLDER_THAN"
    [ "$BACKUP_FOLDER" = "$MONTHLY_FOLDER" ] && PERIOD_OF_ROTATION="$DELETE_MONTHLY_BACKUPS_OLDER_THAN"
    ROTATION_DATE=`date -d "$PERIOD_OF_ROTATION" +%Y.%m.%d`
    DATES_S3=`grep "$BACKUP_FOLDER" $MYSQL_BACKUPS_S3 | sed 's|^'$DESTINATION'\/.*\/'$BACKUP_FOLDER'\/.*\_\(....\-..\-..\).*\.sql\.bz2$|\1|' | sort | uniq`
    for DATE_S3 in $DATES_S3; do
	if [ `echo $DATE_S3 | tr -d ".|-" | awk '{print substr($0,length-7)}'` -lt `echo $ROTATION_DATE | tr -d ".|-"` ]; then
	    echo ""
	    echo "----- Deleting old S3 backups from the folder \"$BACKUP_FOLDER\" for the date \"$DATE_S3\", PERIOD_OF_ROTATION=\"$PERIOD_OF_ROTATION\""
	    DELETE_BACKUPS=`grep "$BACKUP_FOLDER" $MYSQL_BACKUPS_S3 | grep $DATE_S3`
	    for BACKUP in $DELETE_BACKUPS; do
		s3cmd -c $S3CMD_CONF del $BACKUP
	    done
	fi
    done
done

rm -f $MYSQL_BACKUPS_S3
rm -f $0.pid
exit 0
