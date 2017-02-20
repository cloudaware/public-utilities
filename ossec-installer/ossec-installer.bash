#!/usr/bin/env bash
#
# Description: OSSEC Agent automatic installation script
# Author: Sergey Zhuga <szhuga@gigware.com>
#

function show_help {
    echo "Usage: $( basename $0 ) [options]"
    echo 'Options:'
    echo '  --server-ip=IP_ADDRESS      Set server IP address'
    echo '  --server-hostname=HOSTNAME  Set server IP address'
    echo '  --node-name=NODE_NAME       Set node name. Default value: $HOSTNAME or $INSTANCE_ID on AWS'
    echo '  --docker                    Add Docker support'
    echo '  --sudo                      Use sudo command'
    echo '  --help                      Show this message'
}

function echo_error {
    RED='\033[0;31m'; NORMAL='\033[0m'
    echo -e "[${RED}ERROR${NORMAL}]: ${@}" >&2
    kill -INT $$
}

function echo_info {
    GREEN='\033[0;32m'; NORMAL='\033[0m'
    echo -e "[${GREEN}INFO${NORMAL}]: ${@}"
}

function echo_unsupported {
    echo_error 'This OS name or version is unsupported'
}

function get_os_name {
    if [ -f /etc/redhat-release ]; then
        NAME=()
        NAME+=$( rpm -qi centos-release &>/dev/null && echo 'centos' )
        NAME+=$( rpm -qi redhat-release &>/dev/null && echo 'redhat' )
        NAME+=$( rpm -qi redhat-release-server &>/dev/null && echo 'redhat' )
        if [ "${NAME}" != '' ]; then
            echo $NAME
        else
            echo_unsupported
        fi
    elif [ -f /etc/os-release ]; then
        grep -e "^ID=" /etc/os-release | awk -F '=' '{print $2}' | sed s/\"//g
    else
        echo_unsupported
    fi
}

function get_os_version {
    if [ -f /etc/redhat-release ]; then
        VERSION=()
        VERSION+=$( rpm -qi centos-release | grep Version | awk '{print $3}' | grep -oP '^\d+' )
        VERSION+=$( rpm -qi redhat-release | grep Version | awk '{print $3}' | grep -oP '^\d+' )
        VERSION+=$( rpm -qi redhat-release-server | grep Version | awk '{print $3}' | grep -oP '^\d+' )
        case $VERSION in
        5|6|7)
            echo $VERSION
            ;;
        *)
            echo_unsupported
            ;;
        esac
    elif [ -f /etc/os-release ]; then
        grep -e "^VERSION_ID=" /etc/os-release | awk -F '=' '{print $2}' | sed s/\"//g
    else
        echo_unsupported
    fi
}

function get_os_codename {
    case $OS_NAME in
    debian)
        case $OS_VERSION in
        7)
            echo 'wheezy'
            ;;
        8)
            echo 'jessie'
            ;;
        *)
            echo_unsupported
            ;;
        esac
        ;;
    ubuntu)
        case $OS_VERSION in
        12.04)
            echo 'precise'
            ;;
        14.04)
            echo 'trusty'
            ;;
        16.04)
            echo 'xenial'
            ;;
        *)
            echo_unsupported
            ;;
        esac
        ;;
    *)
        echo_unsupported
        ;;
    esac
}

function create_apt_repo {
    URL="http://ossec.wazuh.com/repos/apt/${OS_NAME}"
    COMPONENT='main'

    echo_info 'Create APT repo'
    $SUDO bash -c "echo \"deb ${URL} ${OS_CODENAME} ${COMPONENT}\" > /etc/apt/sources.list.d/ossec-${OS_CODENAME}.list"
}

function add_apt_key {
    URL='http://ossec.wazuh.com/repos/apt/conf/ossec-key.gpg.key'

    echo_info 'Add APT key'
    $SUDO bash -c "apt-key adv --fetch-keys $URL"
}

function create_yum_repo {
    echo_info 'Create YUM repo'
    REPO_FILENAME="/etc/yum.repos.d/ossec-${OS_NAME}.repo"
    $SUDO bash -c "cat > $REPO_FILENAME << EOF
[atomic]
name = CentOS / Red Hat Enterprise Linux \\\$releasever - atomicrocketturtle.com
mirrorlist = http://updates.atomicorp.com/channels/mirrorlist/atomic/centos-${OS_VERSION}-\\\$basearch
enabled = 1
priority = 1
protect = 0
gpgkey = file:///etc/pki/rpm-gpg/RPM-GPG-KEY.art.txt
         file:///etc/pki/rpm-gpg/RPM-GPG-KEY.atomicorp.txt
gpgcheck = 0
EOF"
}

function check_wget {
    if [ -z $( whereis -b wget | awk '{print $2}' ) ]; then
        echo_info "Install 'wget'"
        case $OS_NAME in
        debian|ubuntu)
            $SUDO bash -c "apt-get -y install wget"
            ;;
        centos|redhat)
            $SUDO bash -c "yum -y install wget"
            ;;
        esac
    fi
}

function add_yum_key {
    check_wget

    URL='https://www.atomicorp.com/'
    KEYS=(
        'RPM-GPG-KEY.atomicorp.txt'
        'RPM-GPG-KEY.art.txt'
    )

    echo_info 'Add YUM key'
    for KEY in ${KEYS[@]}; do
        $SUDO bash -c "wget \"${URL}/${KEY}\" -O \"/etc/pki/rpm-gpg/${KEY}\""
        $SUDO bash -c "rpm --import \"/etc/pki/rpm-gpg/${KEY}\""
    done
}

function add_docker_support {
    CONFIG='/var/ossec/etc/ossec.conf'

    check_wget

    echo_info 'Install Ruby'
    case $OS_NAME in
    debian|ubuntu)
        $SUDO bash -c "DEBIAN_FRONTEND='noninteractive' apt-get -y install ruby"
        ;;
    centos|redhat)
        $SUDO bash -c "yum -y install ruby"
        ;;
    esac

    echo_info "Get OSSEC Docker plugin"
    OSSEC_DOCKER_PLUGIN_URL='https://raw.githubusercontent.com/cloudaware/public-utilities/master/ossec-installer/files/ossec-docker-logs.rb'
    OSSEC_DOCKER_PLUGIN='/var/ossec/bin/ossec-docker-logs.rb'
    $SUDO bash -c "wget $OSSEC_DOCKER_PLUGIN_URL -O $OSSEC_DOCKER_PLUGIN"
    $SUDO bash -c "chmod +x $OSSEC_DOCKER_PLUGIN"

    echo_info "Update crontab"
    $SUDO bash -c "echo '* * * * * root /var/ossec/bin/ossec-docker-logs.rb' > /etc/cron.d/ossec-docker-logs"

    echo_info "Add Docker monitor"
    if [ -z "$($SUDO bash -c 'grep ossec-docker-logs /var/ossec/etc/ossec.conf')" ]; then
        $SUDO bash -c "sed -i \"/<\/ossec_config>/i <localfile>\" $CONFIG"
        $SUDO bash -c "sed -i \"/<\/ossec_config>/i <log_format>syslog<\/log_format>\" $CONFIG"
        $SUDO bash -c "sed -i \"/<\/ossec_config>/i <location>\/var\/log\/ossec-docker-logs.log<\/location>\" $CONFIG"
        $SUDO bash -c "sed -i \"/<\/ossec_config>/i <\/localfile>\" $CONFIG"
    fi
}

function set_server_address {
    ADDRESS_TYPE=$1
    CONFIG='/var/ossec/etc/ossec.conf'

    $SUDO bash -c "sed -i \"/<client>/,/<\/client>/d\" $CONFIG"
    $SUDO bash -c "sed -i \"/<ossec_config>/a </client>\" $CONFIG"
    case $ADDRESS_TYPE in
    ip)
        echo_info "Set server IP to '${SERVER_IP}'"
        $SUDO bash -c "sed -i \"/<ossec_config>/a <server-ip>${SERVER_IP}</server-ip>\" $CONFIG"
        ;;
    hostname)
        echo_info "Set server hostname to '${SERVER_HOSTNAME}'"
        $SUDO bash -c "sed -i \"/<ossec_config>/a <server-hostname>${SERVER_HOSTNAME}</server-hostname>\" $CONFIG"
        ;;
    esac
    $SUDO bash -c "sed -i \"/<ossec_config>/a <client>\" $CONFIG"
}

function register_on_server {
    SERVER=$1

    if [ -n "${NODE_NAME}" ]; then
        NODE=$NODE_NAME
    else
        check_wget

        INSTANCE_ID=$( wget -q -O - http://169.254.169.254/latest/meta-data/instance-id )
        if [ -n "${INSTANCE_ID}" ]; then
            NODE=$INSTANCE_ID
        else
            NODE=$( hostname )
        fi
    fi

    echo_info "Register node '$NODE' at server '${SERVER}'"
    $SUDO bash -c "/var/ossec/bin/agent-auth -m $SERVER -A $NODE"
}

function restart_service {
    echo_info 'Restart OSSEC Agent'
    case $OS_NAME in
    debian|ubuntu)
        $SUDO bash -c "/etc/init.d/ossec restart"
        ;;
    centos|redhat)
        $SUDO bash -c "/etc/init.d/ossec-hids restart"
        ;;
    esac
}

for OPT in ${@}; do
    case $OPT in
    --server-ip=*)
        SERVER_IP=${OPT#*=}
        shift
        ;;
    --server-hostname=*)
        SERVER_HOSTNAME=${OPT#*=}
        shift
        ;;
    --node-name=*)
        NODE_NAME=${OPT#*=}
        shift
        ;;
    --docker)
        DOCKER='true'
        shift
        ;;
    --sudo)
        SUDO='sudo'
        shift
        ;;
    --help)
        show_help
        exit
        ;;
    *)
        echo_error "Unknown option '${OPT}'"
        ;;
    esac
done

OS_NAME=$( get_os_name )
echo_info "OS name is '${OS_NAME}'"

OS_VERSION=$( get_os_version )
echo_info "OS version is '${OS_VERSION}'"

if [ "${OS_NAME}" == 'amzn' ]; then
    echo_info 'Amazon Linux is working good with CentOS 6 repos'
    OS_NAME='centos'
    OS_VERSION='6'
fi

case $OS_NAME in
debian|ubuntu)
    OS_CODENAME=$( get_os_codename )
    echo_info "OS code name is '${OS_CODENAME}'"

    create_apt_repo

    add_apt_key

    echo_info 'Update APT cache'
    $SUDO bash -c "apt-get update"

    echo_info 'Install OSSEC agent'
    $SUDO bash -c "DEBIAN_FRONTEND='noninteractive' apt-get -y install ossec-hids-agent"
    ;;
centos|redhat)
    create_yum_repo

    add_yum_key

    $SUDO bash -c "yum -y install ossec-hids-client 2>/dev/null"
    ;;
*)
    echo_unsupported
    ;;
esac

if [ -n "${DOCKER}" ]; then
    add_docker_support
fi

if [ -n "${SERVER_HOSTNAME}" ]; then
    set_server_address hostname
    register_on_server $SERVER_HOSTNAME
    restart_service
elif [ -n "${SERVER_IP}" ]; then
    set_server_address ip
    register_on_server $SERVER_IP
    restart_service
fi

echo_info 'Complete'
