#!/bin/bash

#system message
#Instruction Set
machine=""
#What system
release=""
#System version number
systemVersion=""
redhat_version=""
debian_package_manager=""
redhat_package_manager=""
#Physical memory size
mem=""
#Physical memory + swap size before running the script
mem_total=""
#Whether swap is enabled before running the script
using_swap=""
#Is there any script to start swap now?
using_swap_now=0

#Installation Information
nginx_version="nginx-1.19.6"
openssl_version="openssl-openssl-3.0.0-alpha11"
nginx_prefix="/usr/local/nginx"
nginx_config="${nginx_prefix}/conf.d/xray.conf"
nginx_service="/etc/systemd/system/nginx.service"
nginx_is_installed=""

php_version="php-8.0.1"
php_prefix="/usr/local/php"
php_service="/etc/systemd/system/php-fpm.service"
php_is_installed=""

cloudreve_version="3.2.1"
cloudreve_prefix="/usr/local/cloudreve"
cloudreve_service="/etc/systemd/system/cloudreve.service"
cloudreve_is_installed=""

nextcloud_url="https://download.nextcloud.com/server/prereleases/nextcloud-21.0.0beta8.zip"

xray_config="/usr/local/etc/xray/config.json"
xray_is_installed=""

temp_dir="/temp_install_update_xray_tls_web"

is_installed=""

update=""

#Configuration Information
#Domain name list Two lists are used to distinguish www.main domain name
unset domain_list
unset true_domain_list
unset domain_config_list
#Domain name disguise list, corresponding domain name list
unset pretend_list

#Xray-TCP-TLS protocol used, 0 means disabled, 1 means VLESS
protocol_1=""
#Xray-WS-TLS protocol used, 0 means disabled, 1 means VLESS, 2 means VMess
protocol_2=""
path=""
xid_1=""
xid_2=""


#Functional function:
#Define a few colors
purple() #Keel purple
{
     echo -e "\\033[35;1m${*}\\033[0m"
}
tyblue() #天依蓝
{
     echo -e "\\033[36;1m${*}\\033[0m"
}
green() #水鸭青
{
     echo -e "\\033[32;1m${*}\\033[0m"
}
yellow() #Duck feces yellow
{
     echo -e "\\033[33;1m${*}\\033[0m"
}
red() #Aunt Red
{
     echo -e "\\033[31;1m${*}\\033[0m"
}
#Check basic commands
check_base_command()
{
    local i
    local temp_command_list=('bash''true''false''exit''echo''test''free''sort''sed''awk''grep''cut''cd''rm''cp' ' mv''head''tail''uname''tr''md5sum''tar''cat''find''type''command''kill''pkill''wc''ls''mktemp')
    for i in ${!temp_command_list[@]}
    do
        if! command -V "${temp_command_list[$i]}"> /dev/null; then
            red "command\"${temp_command_list[$i]}\"not found"
            red "Not a standard Linux system"
            exit 1
        fi
    done
}
check_sudo()
{
    if [ "$SUDO_GID" ] && [ "$SUDO_COMMAND" ] && [ "$SUDO_USER" ] && [ "$SUDO_UID" ]; then
        if [ "$SUDO_USER" = "root" ] && [ "$SUDO_UID" = "0" ]; then
            #it's root using sudo, no matter it's using sudo or not, just fine
            return 0
        fi
        if [ -n "$SUDO_COMMAND" ]; then
            #it's a normal user doing "sudo su", or `sudo -i` or `sudo -s`, or `sudo su acmeuser1`
            echo "$SUDO_COMMAND" | grep -- "/bin/su\$" >/dev/null 2>&1 || echo "$SUDO_COMMAND" | grep -- "/bin/su " >/dev/null 2>&1 || grep "^$SUDO_COMMAND\$" /etc/shells >/dev/null 2>&1
            return $?
        fi
        #otherwise
        return 1
    fi
    return 0
}
#Version comparison function
version_ge()
{
    test "$(echo -e "$1\\n$2" | sort -rV | head -n 1)" == "$1"
}
#Install a single important dependency
check_important_dependence_installed()
{
    if [$release == "ubuntu"] || [$release == "other-debian" ]; then
        if dpkg -s "$1"> /dev/null 2>&1; then
            apt-mark manual "$1"
        elif! $debian_package_manager -y --no-install-recommends install "$1"; then
            $debian_package_manager update
            if! $debian_package_manager -y --no-install-recommends install "$1"; then
                red "Important component\"$1\"installation failed!!!"
                yellow "Press Enter to continue or Ctrl+c to exit"
                read -s
            fi
        fi
    else
        if rpm -q "$2"> /dev/null 2>&1; then
            if ["$redhat_package_manager" == "dnf" ]; then
                dnf mark install "$2"
            else
                yumdb set reason user "$2"
            fi
        elif! $redhat_package_manager -y install "$2"; then
            red "Important component\"$2\"installation failed!!!"
            yellow "Press Enter to continue or Ctrl+c to exit"
            read -s
        fi
    fi
}
#Installation dependencies
install_dependence()
{
    if [$release == "ubuntu"] || [$release == "other-debian" ]; then
        if! $debian_package_manager -y --no-install-recommends install "$@"; then
            $debian_package_manager update
            if! $debian_package_manager -y --no-install-recommends install "$@"; then
                yellow "Dependency installation failed!!!"
                green "Welcome to a bug report (https://github.com/kirin10000/Xray-script/issues), thank you for your support"
                yellow "Press Enter to continue or Ctrl+c to exit"
                read -s
            fi
        fi
    else
        if $redhat_package_manager --help | grep -q "\\-\\-enablerepo="; then
            local temp_redhat_install="$redhat_package_manager -y --enablerepo="
        else
            local temp_redhat_install="$redhat_package_manager -y --enablerepo "
        fi
        if! $redhat_package_manager -y install "$@"; then
            if ["$release" == "centos"] && version_ge "$systemVersion" 8 && $temp_redhat_install"epel,PowerTools" install "$@";then
                return 0
            fi
            if $temp_redhat_install'*' install "$@"; then
                return 0
            fi
            yellow "Dependency installation failed!!!"
            green "Welcome to a bug report (https://github.com/kirin10000/Xray-script/issues), thank you for your support"
            yellow "Press Enter to continue or Ctrl+c to exit"
            read -s
        fi
    fi
}
#Enter working directory
enter_temp_dir()
{
    rm -rf "$temp_dir"
    mkdir "$temp_dir"
    cd "$temp_dir"
}
#Check if php is required
check_need_php()
{
    [$is_installed -eq 0] && return 1
    local i
    for i in ${!pretend_list[@]}
    do
        ["${pretend_list[$i]}" == "2"] && return 0
    done
    return 1
}
#Check if cloudreve is needed
check_need_cloudreve()
{
     [$is_installed -eq 0] && return 1
     local i
     for i in ${!pretend_list[@]}
     do
         ["${pretend_list[$i]}" == "1"] && return 0
     done
     return 1
}
#Check for Nginx updates
check_nginx_update()
{
     local nginx_version_now
     local openssl_version_now
     nginx_version_now="nginx-$(${nginx_prefix}/sbin/nginx -V 2>&1 | grep "^nginx version:" | cut -d / -f 2)"
     openssl_version_now="openssl-openssl-$(${nginx_prefix}/sbin/nginx -V 2>&1 | grep "^built with OpenSSL" | awk'{print $4}')"
     if ["$nginx_version_now" == "$nginx_version"] && ["$openssl_version_now" == "$openssl_version" ]; then
         return 1
     else
         return 0
     fi
}
#Check php update
check_php_update()
{
    local php_version_now
    php_version_now="php-$(${php_prefix}/bin/php -v | head -n 1 | awk '{print $2}')"
    [ "$php_version_now" == "$php_version" ] && return 1
    return 0
}
swap_on()
{
    if [ $using_swap_now -ne 0 ]; then
         red "An error occurred when opening swap"
         green "Welcome to a bug report (https://github.com/kirin10000/Xray-script/issues), thank you for your support"
         yellow "Press Enter to continue or Ctrl+c to exit"
         read -s
     fi
     if [$mem_total -lt $1 ]; then
         tyblue "Insufficient memory of $1M, automatically apply for swap..."
        if dd if=/dev/zero of=${temp_dir}/swap bs=1M count=$(($1-mem)); then
            chmod 0600 ${temp_dir}/swap
            mkswap ${temp_dir}/swap
            swapoff -a
            swapon ${temp_dir}/swap
            using_swap_now=1
        else
            rm -rf ${temp_dir}/swap
             red "Failed to open swap!"
             yellow "Maybe the machine's memory and hard disk space are insufficient"
             green "Welcome to a bug report (https://github.com/kirin10000/Xray-script/issues), thank you for your support"
             yellow "Press Enter to continue or Ctrl+c to exit"
             read -s
        fi
    fi
}
swap_off()
{
    if [ $using_swap_now -eq 1 ]; then
        tyblue "正在恢复swap。。。"
        swapoff -a
        [ $using_swap -ne 0 ] && swapon -a
        using_swap_now=0
    fi
}
#Enable/disable php cloudreve
turn_on_off_php()
{
    if check_need_php; then
        systemctl --now enable php-fpm
    else
        systemctl --now disable php-fpm
    fi
}
turn_on_off_cloudreve()
{
    if check_need_cloudreve; then
        systemctl --now enable cloudreve
    else
        systemctl --now disable cloudreve
    fi
}
let_change_cloudreve_domain()
{
    tyblue "----------- Please open \"https://${domain_list[$1]}\"Modify Cloudreve site information ---------"
     tyblue "1. Login account"
     tyblue "2. Picture in the upper right corner -> Management Panel"
     tyblue "3. Parameter settings on the left -> site information"
     tyblue "4. Change the site URL to \"https://${domain_list[$1]}\" -> pull down and click save"
     sleep 15s
     echo -e "\\n\\n"
     tyblue "Press Enter twice to continue..."
     read -s
     read -s
}
init_cloudreve()
{
    local temp
     temp="$(timeout 5s $cloudreve_prefix/cloudreve | grep "Initial administrator password:" | awk'{print $4}')"
     sleep 1s
     systemctl --now enable cloudreve
     tyblue "-------- Please open \"https://${domain_list[$1]}\" to initialize Cloudreve -------"
     tyblue "1. Login account"
     purple "Initial administrator account: admin@cloudreve.org"
     purple "$temp"
     tyblue "2. Picture in the upper right corner -> Management Panel"
     tyblue "3. At this time a dialog box will pop up \"Confirm Site URL Settings\" Select \"Change\""
     tyblue "4. Parameter settings on the left -> Registration and login -> New user registration is not allowed -> drop down and click save"
     sleep 15s
     echo -e "\\n\\n"
     tyblue "Press Enter twice to continue..."
     read -s
     read -s
}
ask_if()
{
    local choice=""
    while [ "$choice" != "y" ] && [ "$choice" != "n" ]
    do
        tyblue "$1"
        read choice
    done
    [ $choice == y ] && return 0
    return 1
}
#Uninstall function
remove_xray()
{
    if ! bash <(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh) remove --purge; then
        systemctl --now disable xray
        rm -rf /usr/local/bin/xray
        rm -rf /usr/local/etc/xray
        rm -rf /etc/systemd/system/xray.service
        rm -rf /etc/systemd/system/xray@.service
        rm -rf /var/log/xray
        systemctl daemon-reload
    fi
}
remove_nginx()
{
    systemctl --now disable nginx
    rm -rf $nginx_service
    systemctl daemon-reload
    rm -rf ${nginx_prefix}
    nginx_is_installed=0
}
remove_php()
{
    systemctl --now disable php-fpm
    rm -rf $php_service
    systemctl daemon-reload
    rm -rf ${php_prefix}
    php_is_installed=0
}
remove_cloudreve()
{
    systemctl --now disable cloudreve
    rm -rf $cloudreve_service
    systemctl daemon-reload
    rm -rf ${cloudreve_prefix}
    cloudreve_is_installed=0
}
#Backup domain name disguise website
backup_domains_web()
{
    local i
    mkdir "${temp_dir}/domain_backup"
    for i in ${!true_domain_list[@]}
    do
        if [ "$1" == "cp" ]; then
            cp -rf ${nginx_prefix}/html/${true_domain_list[$i]} "${temp_dir}/domain_backup" 2>/dev/null
        else
            mv ${nginx_prefix}/html/${true_domain_list[$i]} "${temp_dir}/domain_backup" 2>/dev/null
        fi
    done
}
#Get configuration information
get_config_info()
{
    [ $is_installed -eq 0 ] && return
    if [ $(grep -c '"clients"' $xray_config) -eq 2 ] || [ $(grep -Ec '"(vmess|vless)"' $xray_config) -eq 1 ]; then
        protocol_1=1
        xid_1=$(grep '"id"' $xray_config | head -n 1 | cut -d : -f 2)
        xid_1=${xid_1#*'"'}
        xid_1=${xid_1%'"'*}
    else
        protocol_1=0
        xid_1=""
    fi
    if [ $(grep -Ec '"(vmess|vless)"' $xray_config) -eq 2 ]; then
        grep -q '"vmess"' $xray_config && protocol_2=2 || protocol_2=1
        path=$(grep '"path"' $xray_config | head -n 1 | cut -d : -f 2)
        path=${path#*'"'}
        path=${path%'"'*}
        xid_2=$(grep '"id"' $xray_config | tail -n 1 | cut -d : -f 2)
        xid_2=${xid_2#*'"'}
        xid_2=${xid_2%'"'*}
    else
        protocol_2=0
        path=""
        xid_2=""
    fi
    unset domain_list
    unset true_domain_list
    unset domain_config_list
    unset pretend_list
    domain_list=($(grep "^#domain_list=" $nginx_config | cut -d = -f 2))
    true_domain_list=($(grep "^#true_domain_list=" $nginx_config | cut -d = -f 2))
    domain_config_list=($(grep "^#domain_config_list=" $nginx_config | cut -d = -f 2))
    pretend_list=($(grep "^#pretend_list=" $nginx_config | cut -d = -f 2))
}
#Delete all domains
remove_all_domains()
{
    systemctl stop xray
    systemctl stop nginx
    systemctl --now disable php-fpm
    systemctl --now disable cloudreve
    local i
    for i in ${!true_domain_list[@]}
    do
        rm -rf ${nginx_prefix}/html/${true_domain_list[$i]}
    done
    rm -rf "${nginx_prefix}/certs"
    mkdir "${nginx_prefix}/certs"
    $HOME/.acme.sh/acme.sh --uninstall
    rm -rf $HOME/.acme.sh
    curl https://get.acme.sh | sh
    $HOME/.acme.sh/acme.sh --upgrade --auto-upgrade
    unset domain_list
    unset true_domain_list
    unset domain_config_list
    unset pretend_list
}

check_base_command
if [ "$EUID" != "0" ]; then
red "Please run this script as the root user!!!"
    exit 1
fi
if ! check_sudo; then
red "--------------------------- sudo is detected in use ---------------- -----------"
     yellow "acme.sh does not support sudo, please use root user to run this script"
     tyblue "For details, please see: https://github.com/acmesh-official/acme.sh/wiki/sudo"
     exit 1
fi
if [[! -f'/etc/os-release' ]]; then
     red "The system version is too old, Xray official script does not support"
     exit 1
fi
if [[ -f /.dockerenv ]] || grep -q'docker\|lxc' /proc/1/cgroup && [[ "$(type -P systemctl)" ]]; then
     true
elif [[ -d /run/systemd/system ]] || grep -q systemd <(ls -l /sbin/init); then
     true
else
     red "Only systems that use systemd are supported!"
     exit 1
fi
if [[! -d /dev/shm ]]; then
     red "/dev/shm does not exist, unsupported system"
     exit 1
fi
if [[ "$(type -P apt)" ]]; then
     if [[ "$(type -P dnf)" ]] || [[ "$(type -P yum)" ]]; then
         red "Apt and yum/dnf exist at the same time"
         red "Unsupported system!"
        exit 1
    fi
    release="other-debian"
    debian_package_manager="apt"
    redhat_package_manager="true"
elif [[ "$(type -P dnf)" ]]; then
    release="other-redhat"
    redhat_package_manager="dnf"
    debian_package_manager="true"
elif [[ "$(type -P yum)" ]]; then
    release="other-redhat"
    redhat_package_manager="yum"
    debian_package_manager="true"
else
    red "No apt yum dnf commands exist" 
    red "Unsupported system"
    exit 1
fi
[ -e $nginx_config ] && nginx_is_installed=1 || nginx_is_installed=0
[ -e ${php_prefix}/php-fpm.service.default ] && php_is_installed=1 || php_is_installed=0
[ -e ${cloudreve_prefix}/cloudreve.db ] && cloudreve_is_installed=1 || cloudreve_is_installed=0
[ -e /usr/local/bin/xray ] && xray_is_installed=1 || xray_is_installed=0
([ $xray_is_installed -eq 1 ] && [ $nginx_is_installed -eq 1 ]) && is_installed=1 || is_installed=0
case "$(uname -m)" in
    'amd64' | 'x86_64')
        machine='amd64'
        ;;
    'armv5tel' | 'armv6l' | 'armv7' | 'armv7l')
        machine='arm'
        ;;
    'armv8' | 'aarch64')
        machine='arm64'
        ;;
    *)
        machine=''
        ;;
esac

mem="$(free -m | sed -n 2p | awk '{print $2}')"
mem_total="$(($(free -m | sed -n 2p | awk '{print $2}')+$(free -m | tail -n 1 | awk '{print $2}')))"
[[ "$(free -b | tail -n 1 | awk '{print $2}')" -ne "0" ]] && using_swap=1 || using_swap=0
if [ $is_installed -eq 1 ] && ! grep -q "domain_list=" $nginx_config; then
     red "The script has been updated for an incompatible downward compatibility"
     yellow "Please select \"Reinstall\" to upgrade"
     sleep 3s
fi

#Get system version information
get_system_info()
{
    local temp_release
    temp_release="$(lsb_release -i -s | tr "[:upper:]" "[:lower:]")"
    if [[ "$temp_release" =~ ubuntu ]]; then
        release="ubuntu"
    elif [[ "$temp_release" =~ centos ]]; then
        release="centos"
    elif [[ "$temp_release" =~ fedora ]]; then
        release="fedora"
    fi
    systemVersion="$(lsb_release -r -s)"
    if [ $release == "fedora" ]; then
        if version_ge "$systemVersion" 30; then
            redhat_version=8
        elif version_ge "$systemVersion" 19; then
            redhat_version=7
        elif version_ge "$systemVersion" 12; then
            redhat_version=6
        else
            redhat_version=5
        fi
    else
        redhat_version="$systemVersion"
    fi
}

#Check if port 80 and port 443 are occupied
check_port()
{
     green "Checking port occupancy..."
     local xray_status=0
     local nginx_status=0
     systemctl -q is-active xray && xray_status=1 && systemctl stop xray
     systemctl -q is-active nginx && nginx_status=1 && systemctl stop nginx
     ([ $xray_status -eq 1] || [$nginx_status -eq 1 ]) && sleep 2s
     local check_list=('80' '443')
     local i
     for i in ${!check_list[@]}
     do
         if netstat -tuln | awk'{print $4}' | awk -F:'{print $NF}' | grep -E "^[0-9]+$" | grep -wq "${check_list[$i] }"; then
             red "${check_list[$i]} port is occupied!"
             yellow "Please use lsof -i:${check_list[$i]} command to check"
             exit 1
         fi
     done
     [$xray_status -eq 1] && systemctl start xray
     [$nginx_status -eq 1] && systemctl start nginx
}

#Check whether Nginx has been installed via apt/dnf/yum
check_nginx_installed_system()
{
     if [[! -f /usr/lib/systemd/system/nginx.service ]] && [[! -f /lib/systemd/system/nginx.service ]]; then
         return 0
     fi
     red "------------ It is detected that Nginx is installed and will conflict with this script------------"
     yellow "If you don't remember that Nginx was installed before, it may have been installed using another one-click script"
     yellow "It is recommended to use a clean system to run this script"
     echo
     ! ask_if "Try uninstalling? (y/n)" && exit 0
     $debian_package_manager -y purge nginx
     $redhat_package_manager -y remove nginx
     if [[! -f /usr/lib/systemd/system/nginx.service ]] && [[! -f /lib/systemd/system/nginx.service ]]; then
         return 0
     fi
     red "Uninstallation failed!"
     yellow "Please try to change the system, it is recommended to use the latest version of Ubuntu system"
     green "Welcome to a bug report (https://github.com/kirin10000/Xray-script/issues), thank you for your support"
     exit 1
}

#Check SELinux
check_SELinux()
{
     turn_off_selinux()
     {
         check_important_dependence_installed selinux-utils libselinux-utils
         setenforce 0
         sed -i's/^[ \t]*SELINUX[ \t]*=[ \t]*enforcing[ \t]*$/SELINUX=disabled/g' /etc/sysconfig/selinux
         $redhat_package_manager -y remove libselinux-utils
         $debian_package_manager -y purge selinux-utils
     }
     if getenforce 2>/dev/null | grep -wqi Enforcing || grep -Eq'^['$'\t]*SELINUX['$'\t]*=['$'\t]*enforcing['$ '\t]*$' /etc/sysconfig/selinux 2>/dev/null; then
         yellow "SELinux has been detected, the script may not run properly"
         if ask_if "Try to close SELinux? (y/n)"; then
             turn_off_selinux
         else
             exit 0
         fi
     fi
}

#配置sshd
check_ssh_timeout()
{
if grep -q "#This file has been edited by Xray-TLS-Web-setup-script" /etc/ssh/sshd_config; then
        return 0
    fi
    echo -e "\\n\\n\\n"
    tyblue "------------------------------------------"
    tyblue "Installation may take a long time (5-40 minutes)"
    tyblue "It will be troublesome if you disconnect halfway"
    tyblue "Setting the ssh connection timeout will effectively reduce the possibility of disconnection"
    echo
    ! ask_if "Whether to set the ssh connection timeout time? (y/n)" && return 0
    sed -i'/^[ \t]*ClientAliveInterval[ \t]/d' /etc/ssh/sshd_config
    sed -i'/^[ \t]*ClientAliveCountMax[ \t]/d' /etc/ssh/sshd_config
    echo >> /etc/ssh/sshd_config
    echo "ClientAliveInterval 30" >> /etc/ssh/sshd_config
    echo "ClientAliveCountMax 60" >> /etc/ssh/sshd_config
    echo "#This file has been edited by Xray-TLS-Web-setup-script" >> /etc/ssh/sshd_config
    systemctl restart sshd
    green "----------------------Configuration complete----------------------"
    tyblue "Please re-connect to ssh (ie re-login to the server) and run this script again"
    yellow "Press Enter to exit..."
    read -s
    exit 0
}

#Delete firewall and Alibaba Cloud Shield
uninstall_firewall()
{
     green "The firewall is being deleted..."
    ufw disable
    $debian_package_manager -y purge firewalld
    $debian_package_manager -y purge ufw
    systemctl stop firewalld
    systemctl disable firewalld
    $redhat_package_manager -y remove firewalld
    green "Alibaba Cloud Shield and Tencent Cloud Shield are being deleted (only valid for Alibaba Cloud and Tencent Cloud servers)..."
#Alibaba Cloud
    if [ $release == "ubuntu" ] || [ $release == "other-debian" ]; then
        systemctl stop CmsGoAgent
        systemctl disable CmsGoAgent
        rm -rf /usr/local/cloudmonitor
        rm -rf /etc/systemd/system/CmsGoAgent.service
        systemctl daemon-reload
    else
        systemctl stop cloudmonitor
        /etc/rc.d/init.d/cloudmonitor remove
        rm -rf /usr/local/cloudmonitor
        systemctl daemon-reload
    fi

    systemctl stop aliyun
    systemctl disable aliyun
    rm -rf /etc/systemd/system/aliyun.service
    systemctl daemon-reload
    $debian_package_manager -y purge aliyun-assist
    $redhat_package_manager -y remove aliyun_assist
    rm -rf /usr/local/share/aliyun-assist
    rm -rf /usr/sbin/aliyun_installer
    rm -rf /usr/sbin/aliyun-service
    rm -rf /usr/sbin/aliyun-service.backup

    pkill -9 AliYunDun
    pkill -9 AliHids
    /etc/init.d/aegis uninstall
    rm -rf /usr/local/aegis
    rm -rf /etc/init.d/aegis
    rm -rf /etc/rc2.d/S80aegis
    rm -rf /etc/rc3.d/S80aegis
    rm -rf /etc/rc4.d/S80aegis
    rm -rf /etc/rc5.d/S80aegis
# Tencent Cloud Shield
    /usr/local/qcloud/stargate/admin/uninstall.sh
    /usr/local/qcloud/YunJing/uninst.sh
    /usr/local/qcloud/monitor/barad/admin/uninstall.sh
    systemctl daemon-reload
    systemctl stop YDService
    systemctl disable YDService
    rm -rf /lib/systemd/system/YDService.service
    systemctl daemon-reload
    sed -i 's#/usr/local/qcloud#rcvtevyy4f5d#g' /etc/rc.local
    sed -i '/rcvtevyy4f5d/d' /etc/rc.local
    rm -rf $(find /etc/udev/rules.d -iname "*qcloud*" 2>/dev/null)
    pkill -9 YDService
    pkill -9 YDLive
    pkill -9 sgagent
    pkill -9 tat_agent
    pkill -9 /usr/local/qcloud
    pkill -9 barad_agent
    rm -rf /usr/local/qcloud
    rm -rf /usr/local/yd.socket.client
    rm -rf /usr/local/yd.socket.server
    mkdir /usr/local/qcloud
    mkdir /usr/local/qcloud/action
    mkdir /usr/local/qcloud/action/login_banner.sh
    mkdir /usr/local/qcloud/action/action.sh
    if [[ "$(type -P uname)" ]] && uname -a | grep solaris >/dev/null; then
        crontab -l | sed "/qcloud/d" | crontab --
    else
        crontab -l | sed "/qcloud/d" | crontab -
    fi
}

#Upgrade system components
doupdate()
{
    updateSystem()
    {
        if ! [[ "$(type -P do-release-upgrade)" ]]; then
            if ! $debian_package_manager -y --no-install-recommends install ubuntu-release-upgrader-core; then
                $debian_package_manager update
                if ! $debian_package_manager -y --no-install-recommends install ubuntu-release-upgrader-core; then
                    red "Script error!"
                     yellow "Press Enter to continue or Ctrl+c to exit"
                     read -s
                fi
            fi
        fi
        echo -e "\\n\\n\\n"
        tyblue "------------------Please choose to upgrade the system version--------------------"
        tyblue "1. The latest beta version (now 21.04) (2020.11)"
        tyblue "2. The latest release (now 20.10) (2020.11)"
        tyblue "3. The latest LTS version (now 20.04) (2020.11)"
        tyblue "-------------------------Release note--------------------- ----"
        tyblue "beta version: the beta version"
        tyblue "release version: stable version"
        tyblue "LTS version: long-term support version, can be understood as super stable version"
        tyblue "-------------------------Cautions--------------------- ----"
        yellow "1. Encountered a question/dialog box during the upgrade process, if you don’t understand, select yes/y/the first option"
        yellow "2. After the upgrade system is completed, it will restart. After restarting, please run this script again to complete the remaining installation"
        yellow "3. It may take 15 minutes or more to upgrade the system"
        yellow "4. Sometimes it is not possible to update to the selected version at one time, it may have to be updated multiple times"
        yellow "5. The following configuration may restore the system default configuration after upgrading the system:"
        yellow "ssh port ssh timeout time bbr acceleration (return to closed state)"
        tyblue "------------------------------------------------ ----------"
        green "Your current system version is "$systemVersion""
        tyblue "------------------------------------------------ ----------"
        echo
        choice=""
        while ["$choice" != "1"] && ["$choice" != "2"] && ["$choice" != "3"]
        do
            read -p "Your choice is:" choice
        done
        if! [[ "$(grep -i'^['$'\t]*port '/etc/ssh/sshd_config | awk'{print $2}')" =~ ^("22"|)$ ]] ; then
            red "Detected that the ssh port number has been modified"
            red "After upgrading the system, the ssh port number may be restored to the default value (22)"
            yellow "Press Enter to continue..."
            read -s
        fi
        local i
        for ((i=0;i<2;i++))
        do
            sed -i '/^[ \t]*Prompt[ \t]*=/d' /etc/update-manager/release-upgrades
            echo 'Prompt=normal' >> /etc/update-manager/release-upgrades
            case "$choice" in
                1)
                    do-release-upgrade -d
                    do-release-upgrade -d
                    sed -i 's/Prompt=normal/Prompt=lts/' /etc/update-manager/release-upgrades
                    do-release-upgrade -d
                    do-release-upgrade -d
                    sed -i 's/Prompt=lts/Prompt=normal/' /etc/update-manager/release-upgrades
                    do-release-upgrade
                    do-release-upgrade
                    sed -i 's/Prompt=normal/Prompt=lts/' /etc/update-manager/release-upgrades
                    do-release-upgrade
                    do-release-upgrade
                    ;;
                2)
                    do-release-upgrade
                    do-release-upgrade
                    ;;
                3)
                    sed -i 's/Prompt=normal/Prompt=lts/' /etc/update-manager/release-upgrades
                    do-release-upgrade
                    do-release-upgrade
                    ;;
            esac
            if ! version_ge "$systemVersion" 20.04; then
                sed -i 's/Prompt=lts/Prompt=normal/' /etc/update-manager/release-upgrades
                do-release-upgrade
                do-release-upgrade
            fi
            $debian_package_manager update
            $debian_package_manager -y --auto-remove --purge full-upgrade
        done
    }
    while ((1))
    do
        echo -e "\\n\\n\\n"
         tyblue "-----------------------Do you want to update the system components?-------------------- ---"
         green "1. Update the installed software and upgrade the system (for Ubuntu only)"
         green "2. Only update installed software"
         red "3. Do not update"
         if ["$release" == "ubuntu"] && ((mem<400)); then
             red "Detected that the memory is too small, upgrading the system may result in failure to boot, please choose carefully"
         fi
         echo
         choice=""
         while ["$choice" != "1"] && ["$choice" != "2"] && ["$choice" != "3"]
         do
             read -p "Your choice is:" choice
         done
         if ["$release" == "ubuntu"] || [$choice -ne 1 ]; then
             break
         fi
         echo
         yellow "The update system only supports Ubuntu!"
        sleep 3s
    done
    if [ $choice -eq 1 ]; then
        updateSystem
        $debian_package_manager -y --purge autoremove
        $debian_package_manager clean
    elif [ $choice -eq 2 ]; then
        tyblue "-----------------------The update will start soon---------------------- -"
         yellow "If you encounter a question/dialog box during the update process, if you don’t understand, select yes/y/the first option"
         yellow "Press Enter to continue..."
         read -s
        $redhat_package_manager -y autoremove
        $redhat_package_manager -y update
        $debian_package_manager update
        $debian_package_manager -y --auto-remove --purge full-upgrade
        $debian_package_manager -y --purge autoremove
        $debian_package_manager clean
        $redhat_package_manager -y autoremove
        $redhat_package_manager clean all
    fi
}

#Install bbr
install_bbr()
{
     #Output: latest_kernel_version and your_kernel_version
     get_kernel_info()
     {
         green "Getting the latest version of the kernel version number... (Skip automatically if it is not obtained within 60 seconds)"
        your_kernel_version="$(uname -r | cut -d - -f 1)"
        while [ ${your_kernel_version##*.} -eq 0 ]
        do
            your_kernel_version=${your_kernel_version%.*}
        done
        if ! timeout 60 wget -O "temp_kernel_version" "https://kernel.ubuntu.com/~kernel-ppa/mainline/"; then
            latest_kernel_version="error"
            return 1
        fi
        local kernel_list=()
        local kernel_list_temp
        kernel_list_temp=($(awk -F'\"v' '/v[0-9]/{print $2}' "temp_kernel_version" | cut -d '"' -f1 | cut -d '/' -f1 | sort -rV))
        if [ ${#kernel_list_temp[@]} -le 1 ]; then
            latest_kernel_version="error"
            return 1
        fi
        local i2=0
        local i3
        local kernel_rc=""
        local kernel_list_temp2
        while ((i2<${#kernel_list_temp[@]}))
        do
            if [[ "${kernel_list_temp[$i2]}" =~ -rc(0|[1-9][0-9]*)$ ]] && [ "$kernel_rc" == "" ]; then
                kernel_list_temp2=("${kernel_list_temp[$i2]}")
                kernel_rc="${kernel_list_temp[$i2]%-*}"
                ((i2++))
            elif [[ "${kernel_list_temp[$i2]}" =~ -rc(0|[1-9][0-9]*)$ ]] && [ "${kernel_list_temp[$i2]%-*}" == "$kernel_rc" ]; then
                kernel_list_temp2+=("${kernel_list_temp[$i2]}")
                ((i2++))
            elif [[ "${kernel_list_temp[$i2]}" =~ -rc(0|[1-9][0-9]*)$ ]] && [ "${kernel_list_temp[$i2]%-*}" != "$kernel_rc" ]; then
                for((i3=0;i3<${#kernel_list_temp2[@]};i3++))
                do
                    kernel_list+=("${kernel_list_temp2[$i3]}")
                done
                kernel_rc=""
            elif [ -z "$kernel_rc" ] || version_ge "${kernel_list_temp[$i2]}" "$kernel_rc"; then
                kernel_list+=("${kernel_list_temp[$i2]}")
                ((i2++))
            else
                for((i3=0;i3<${#kernel_list_temp2[@]};i3++))
                do
                    kernel_list+=("${kernel_list_temp2[$i3]}")
                done
                kernel_rc=""
            fi
        done
        if [ -n "$kernel_rc" ]; then
            for((i3=0;i3<${#kernel_list_temp2[@]};i3++))
            do
                kernel_list+=("${kernel_list_temp2[$i3]}")
            done
        fi
        latest_kernel_version="${kernel_list[0]}"
        if [ $release == "ubuntu" ] || [ $release == "other-debian" ]; then
            local rc_version
            rc_version="$(uname -r | cut -d - -f 2)"
            if [[ $rc_version =~ rc ]]; then
                rc_version="${rc_version##*'rc'}"
                your_kernel_version="${your_kernel_version}-rc${rc_version}"
            fi
            uname -r | grep -q xanmod && your_kernel_version="${your_kernel_version}-xanmod"
        else
            latest_kernel_version="${latest_kernel_version%%-*}"
        fi
    }
#Unload redundant kernel
    remove_other_kernel()
    {
        if [$release == "ubuntu"] || [$release == "other-debian" ]; then
            local kernel_list_image
            kernel_list_image=($(dpkg --list | awk'{print $2}' | grep'^linux-image'))
            local kernel_list_modules
            kernel_list_modules=($(dpkg --list | awk'{print $2}' | grep'^linux-modules'))
            local kernel_now
            kernel_now="$(uname -r)"
            local ok_install=0
            for ((i=${#kernel_list_image[@]}-1;i>=0;i--))
            do
                if [[ "${kernel_list_image[$i]}" =~ "$kernel_now" ]]; then
                    unset'kernel_list_image[$i]'
                    ((ok_install++))
                fi
            done
            if [$ok_install -lt 1 ]; then
                red "The kernel in use was not found, it may have been uninstalled, please restart first"
                yellow "Press Enter to continue..."
                read -s
                return 1
            fi
            for ((i=${#kernel_list_modules[@]}-1;i>=0;i--))
            do
                if [[ "${kernel_list_modules[$i]}" =~ "$kernel_now" ]]; then
                    unset'kernel_list_modules[$i]'
                fi
            done
            if [${#kernel_list_modules[@]} -eq 0] && [${#kernel_list_image[@]} -eq 0 ]; then
                yellow "No kernel to uninstall"
                return 0
            fi
            $debian_package_manager -y purge "${kernel_list_image[@]}" "${kernel_list_modules[@]}"
            apt-mark manual "^grub"
        else
            local kernel_list
            kernel_list=($(rpm -qa |grep '^kernel-[0-9]\|^kernel-ml-[0-9]'))
            local kernel_list_devel
            kernel_list_devel=($(rpm -qa | grep '^kernel-devel\|^kernel-ml-devel'))
            if version_ge "$redhat_version" 8; then
                local kernel_list_modules
                kernel_list_modules=($(rpm -qa |grep '^kernel-modules\|^kernel-ml-modules'))
                local kernel_list_core
                kernel_list_core=($(rpm -qa | grep '^kernel-core\|^kernel-ml-core'))
            fi
            local kernel_now
            kernel_now="$(uname -r)"
            local ok_install=0
            for ((i=${#kernel_list[@]}-1;i>=0;i--))
            do
                if [[ "${kernel_list[$i]}" =~ "$kernel_now" ]]; then
                    unset 'kernel_list[$i]'
                    ((ok_install++))
                fi
            done
            if [ $ok_install -lt 1 ]; then
red "The kernel in use was not found, it may have been uninstalled, please restart first"
                yellow "Press Enter to continue..."
                read -s
                return 1
            fi
            for ((i=${#kernel_list_devel[@]}-1;i>=0;i--))
            do
                if [[ "${kernel_list_devel[$i]}" =~ "$kernel_now" ]]; then
                    unset'kernel_list_devel[$i]'
                fi
            done
            if version_ge "$redhat_version" 8; then
                ok_install=0
                for ((i=${#kernel_list_modules[@]}-1;i>=0;i--))
                do
                    if [[ "${kernel_list_modules[$i]}" =~ "$kernel_now" ]]; then
                        unset'kernel_list_modules[$i]'
                        ((ok_install++))
                    fi
                done
                if [$ok_install -lt 1 ]; then
                    red "The kernel in use was not found, it may have been uninstalled, please restart first"
                    yellow "Press Enter to continue..."
                    read -s
                    return 1
                fi
                ok_install=0
                for ((i=${#kernel_list_core[@]}-1;i>=0;i--))
                do
                    if [[ "${kernel_list_core[$i]}" =~ "$kernel_now" ]]; then
                        unset'kernel_list_core[$i]'
                        ((ok_install++))
                    fi
                done
                if [$ok_install -lt 1 ]; then
                    red "The kernel in use was not found, it may have been uninstalled, please restart first"
                    yellow "Press Enter to continue..."
                    read -s
                    return 1
                fi
            fi
            if ([ ${#kernel_list[@]} -eq 0] && [${#kernel_list_devel[@]} -eq 0 ]) && (! version_ge "$redhat_version" 8 || ([ ${#kernel_list_modules[@] } -eq 0] && [${#kernel_list_core[@]} -eq 0 ])); then
                yellow "No kernel to uninstall"
                return 0
            fi
            if version_ge "$redhat_version" 8; then
                $redhat_package_manager -y remove "${kernel_list[@]}" "${kernel_list_modules[@]}" "${kernel_list_core[@]}" "${kernel_list_devel[@]}"
            else
                $redhat_package_manager -y remove "${kernel_list[@]}" "${kernel_list_devel[@]}"
            fi
        fi
        green "-------------------Uninstallation complete-------------------"
    }
    change_qdisc()
    {
        local list=('fq' 'fq_pie' 'cake' 'fq_codel')
        tyblue "---------------Please select the queue algorithm you want to use---------------"
         green "1.fq"
         green "2.fq_pie"
         tyblue "3.cake"
         tyblue "4.fq_codel"
         choice=""
         while [[! "$choice" =~ ^([1-9][0-9]*)$ ]] || ((choice>4))
         do
             read -p "Your choice is:" choice
        done
        local qdisc="${list[$((choice-1))]}"
        local default_qdisc
        default_qdisc="$(sysctl net.core.default_qdisc | cut -d = -f 2 | awk '{print $1}')"
        sed -i '/^[ \t]*net.core.default_qdisc[ \t]*=/d' /etc/sysctl.conf
        echo "net.core.default_qdisc = $qdisc" >> /etc/sysctl.conf
        sysctl -p
        sleep 1s
        if [ "$(sysctl net.core.default_qdisc | cut -d = -f 2 | awk '{print $1}')" == "$qdisc" ]; then
            green "Successful replacement!"
         else
             red "Replacement failed, not supported by the kernel"
            sed -i '/^[ \t]*net.core.default_qdisc[ \t]*=/d' /etc/sysctl.conf
            echo "net.core.default_qdisc = $default_qdisc" >> /etc/sysctl.conf
            return 1
        fi
    }
    local your_kernel_version
    local latest_kernel_version
    get_kernel_info
    if ! grep -q "#This file has been edited by Xray-TLS-Web-setup-script" /etc/sysctl.conf; then
        echo >> /etc/sysctl.conf
        echo "#This file has been edited by Xray-TLS-Web-setup-script" >> /etc/sysctl.conf
    fi
    while ((1))
    do
        echo -e "\\n\\n\\n"
        tyblue "------------------Please select the bbr version you want to use------------------"
        green "1. Upgrade the latest version of the kernel and enable bbr (recommended)"
        green "2. Install xanmod kernel and enable bbr (recommended)"
        if version_ge $your_kernel_version 4.9; then
            tyblue "3. Enable bbr"
        else
            tyblue "3. Upgrade the kernel to enable bbr"
        fi
        tyblue "4. Install a third-party kernel and enable bbr2"
        tyblue "5. Install a third-party kernel and enable bbrplus/bbr magic revision/violent bbr magic revision/ruise"
        tyblue "6. Uninstall redundant kernel"
        tyblue "7. Change the queue algorithm"
        tyblue "0. Exit bbr installation"
        tyblue "------------------Instructions on installing bbr acceleration------------------"
        green "bbr congestion algorithm can greatly increase network speed, it is recommended to enable"
        yellow "Replacement of third-party kernels may cause system instability and even failure to boot"
        yellow "You need to restart to replace/upgrade the kernel. After restarting, please run this script again to complete the remaining installation"
        tyblue "------------------------------------------------ ---------"
        tyblue "Current kernel version: ${your_kernel_version}"
        tyblue "Latest kernel version: ${latest_kernel_version}"
        tyblue "Does the current kernel support bbr:"
        if version_ge $your_kernel_version 4.9; then
            green "yes"
        else
            red "No, need to upgrade the kernel"
        fi
        tyblue "Current congestion control algorithm:"
        local tcp_congestion_control
        tcp_congestion_control=$(sysctl net.ipv4.tcp_congestion_control | cut -d = -f 2 | awk '{print $1}')
        if [[ "$tcp_congestion_control" =~ bbr|nanqinlang|tsunami ]]; then
            if [ $tcp_congestion_control == nanqinlang ]; then
                tcp_congestion_control="${tcp_congestion_control} \\033[35m(暴力bbr魔改版)"
            elif [ $tcp_congestion_control == tsunami ]; then
                tcp_congestion_control="${tcp_congestion_control} \\033[35m(bbr魔改版)"
            fi
            green  "       ${tcp_congestion_control}"
        else
        tyblue "${tcp_congestion_control} \\033[31m (bbr is not enabled)"
         fi
         tyblue "Current queue algorithm:"
        green "       $(sysctl net.core.default_qdisc | cut -d = -f 2 | awk '{print $1}')"
        echo
        local choice=""
        while [[ ! "$choice" =~ ^(0|[1-9][0-9]*)$ ]] || ((choice>7))
        do
            read -p "Your choice is:" choice
        done
        if [ $choice -eq 1 ]; then
            if ! ([ "$(sysctl net.ipv4.tcp_congestion_control | cut -d = -f 2 | awk '{print $1}')" == "bbr" ] && [ "$(grep '^[ '$'\t]*net.ipv4.tcp_congestion_control[ '$'\t]*=' "/etc/sysctl.conf" | tail -n 1 | cut -d = -f 2 | awk '{print $1}')" == "bbr" ] && [ "$(sysctl net.core.default_qdisc | cut -d = -f 2 | awk '{print $1}')" == "$(grep '^[ '$'\t]*net.core.default_qdisc[ '$'\t]*=' "/etc/sysctl.conf" | tail -n 1 | cut -d = -f 2 | awk '{print $1}')" ]); then
                sed -i '/^[ \t]*net.core.default_qdisc[ \t]*=/d' /etc/sysctl.conf
                sed -i '/^[ \t]*net.ipv4.tcp_congestion_control[ \t]*=/d' /etc/sysctl.conf
                echo 'net.core.default_qdisc = fq' >> /etc/sysctl.conf
                echo 'net.ipv4.tcp_congestion_control = bbr' >> /etc/sysctl.conf
                sysctl -p
            fi
            if ! wget -O update-kernel.sh https://github.com/kirin10000/update-kernel/raw/master/update-kernel.sh; then
                 red "Failed to get the kernel upgrade script"
                 yellow "Press Enter to continue or Ctrl+c to terminate"
                read -s
            fi
            chmod +x update-kernel.sh
            ./update-kernel.sh
            if [ "$(sysctl net.ipv4.tcp_congestion_control | cut -d = -f 2 | awk '{print $1}')" == "bbr" ] && [ "$(sysctl net.core.default_qdisc | cut -d = -f 2 | awk '{print $1}')" == "$(grep '^[ '$'\t]*net.core.default_qdisc[ '$'\t]*=' "/etc/sysctl.conf" | tail -n 1 | cut -d = -f 2 | awk '{print $1}')" ]; then
                green "--------------------bbr is installed--------------------"
            else
                 red "Failed to open bbr"
                 red "If you just installed the kernel, please reboot first"
                 red "If restarting still does not work, please try option 3"
            fi
        elif [ $choice -eq 2 ]; then
            if ! ([ "$(sysctl net.ipv4.tcp_congestion_control | cut -d = -f 2 | awk '{print $1}')" == "bbr" ] && [ "$(grep '^[ '$'\t]*net.ipv4.tcp_congestion_control[ '$'\t]*=' "/etc/sysctl.conf" | tail -n 1 | cut -d = -f 2 | awk '{print $1}')" == "bbr" ] && [ "$(sysctl net.core.default_qdisc | cut -d = -f 2 | awk '{print $1}')" == "$(grep '^[ '$'\t]*net.core.default_qdisc[ '$'\t]*=' "/etc/sysctl.conf" | tail -n 1 | cut -d = -f 2 | awk '{print $1}')" ]); then
                sed -i '/^[ \t]*net.core.default_qdisc[ \t]*=/d' /etc/sysctl.conf
                sed -i '/^[ \t]*net.ipv4.tcp_congestion_control[ \t]*=/d' /etc/sysctl.conf
                echo 'net.core.default_qdisc = fq' >> /etc/sysctl.conf
                echo 'net.ipv4.tcp_congestion_control = bbr' >> /etc/sysctl.conf
                sysctl -p
            fi
            if ! wget -O xanmod-install.sh https://github.com/kirin10000/xanmod-install/raw/main/xanmod-install.sh; then
                 red "Failed to get the xanmod kernel installation script"
                 yellow "Press Enter to continue or Ctrl+c to terminate"
                read -s
            fi
            chmod +x xanmod-install.sh
            ./xanmod-install.sh
            if [ "$(sysctl net.ipv4.tcp_congestion_control | cut -d = -f 2 | awk '{print $1}')" == "bbr" ] && [ "$(sysctl net.core.default_qdisc | cut -d = -f 2 | awk '{print $1}')" == "$(grep '^[ '$'\t]*net.core.default_qdisc[ '$'\t]*=' "/etc/sysctl.conf" | tail -n 1 | cut -d = -f 2 | awk '{print $1}')" ]; then
                green "--------------------bbr is installed--------------------"
             else
                 red "Failed to open bbr"
                 red "If you just installed the kernel, please reboot first"
                 red "If restarting still does not work, please try option 3"
            fi
        elif [ $choice -eq 3 ]; then
            if [ "$(sysctl net.ipv4.tcp_congestion_control | cut -d = -f 2 | awk '{print $1}')" == "bbr" ] && [ "$(grep '^[ '$'\t]*net.ipv4.tcp_congestion_control[ '$'\t]*=' "/etc/sysctl.conf" | tail -n 1 | cut -d = -f 2 | awk '{print $1}')" == "bbr" ] && [ "$(sysctl net.core.default_qdisc | cut -d = -f 2 | awk '{print $1}')" == "$(grep '^[ '$'\t]*net.core.default_qdisc[ '$'\t]*=' "/etc/sysctl.conf" | tail -n 1 | cut -d = -f 2 | awk '{print $1}')" ]; then
                green "--------------------bbr is installed--------------------"
            else
                sed -i '/^[ \t]*net.core.default_qdisc[ \t]*=/d' /etc/sysctl.conf
                sed -i '/^[ \t]*net.ipv4.tcp_congestion_control[ \t]*=/d' /etc/sysctl.conf
                echo 'net.core.default_qdisc = fq' >> /etc/sysctl.conf
                echo 'net.ipv4.tcp_congestion_control = bbr' >> /etc/sysctl.conf
                sysctl -p
                sleep 1s
                if [ "$(sysctl net.ipv4.tcp_congestion_control | cut -d = -f 2 | awk '{print $1}')" == "bbr" ] && [ "$(sysctl net.core.default_qdisc | cut -d = -f 2 | awk '{print $1}')" == "fq" ]; then
                    green "--------------------bbr已安装--------------------"
                else
                    if ! wget -O bbr.sh https://github.com/teddysun/across/raw/master/bbr.sh; then
                        red "Failed to get bbr script"
                        yellow "Press Enter to continue or Ctrl+c to terminate"
                        read -s
                    fi
                    chmod +x bbr.sh
                    ./bbr.sh
                fi
            fi
        elif [$choice -eq 4 ]; then
            tyblue "--------------------bbr2 acceleration will be installed soon, the server will restart after the installation is complete---------------- ----"
            tyblue "After restarting, please select this option again to complete the remaining part of bbr2 installation (open bbr and ECN)"
            yellow "Press Enter to continue..."
            read -s
            local temp_bbr2
            if [$release == "ubuntu"] || [$release == "other-debian" ]; then
                local temp_bbr2="https://github.com/yeyingorg/bbr2.sh/raw/master/bbr2.sh"
            else
                local temp_bbr2="https://github.com/jackjieYYY/bbr2/raw/master/bbr2.sh"
            fi
            if! wget -O bbr2.sh $temp_bbr2; then
                red "Failed to get bbr2 script"
                yellow "Press Enter to continue or Ctrl+c to terminate"
                read -s
            fi
            chmod +x bbr2.sh
            ./bbr2.sh
        elif [$choice -eq 5 ]; then
            if! wget -O tcp.sh "https://raw.githubusercontent.com/chiakge/Linux-NetSpeed/master/tcp.sh"; then
                red "Failed to get script"
                yellow "Press Enter to continue or Ctrl+c to terminate"
                read -s
            fi
            chmod +x tcp.sh
            ./tcp.sh
        elif [$choice -eq 6 ]; then
            tyblue "This operation will unload the remaining kernels except the kernel currently in use"
            tyblue "The kernel you are using is: $(uname -r)"
            ask_if "Do you want to continue? (y/n)" && remove_other_kernel
        elif [ $choice -eq 7 ]; then
            change_qdisc
        else
            break
        fi
        sleep 3s
    done
}

#读取xray_protocol配置
readProtocolConfig()
{
    echo -e "\\n\\n\\n"
    tyblue "---------------------请选择Xray要使用协议---------------------"
    tyblue " 1. (VLESS-TCP+XTLS) + (VMess-WebSocket+TLS) + Web"
    green  "    适合有时使用CDN，且CDN不可信任(如国内CDN)"
    tyblue " 2. (VLESS-TCP+XTLS) + (VLESS-WebSocket+TLS) + Web"
    green  "    适合有时使用CDN，且CDN可信任"
    tyblue " 3. VLESS-TCP+XTLS+Web"
    green  "    适合完全不用CDN"
    tyblue " 4. VMess-WebSocket+TLS+Web"
    green  "    适合一直使用CDN，且CDN不可信任(如国内CDN)"
    tyblue " 5. VLESS-WebSocket+TLS+Web"
    green  "    适合一直使用CDN，且CDN可信任"
    echo
    yellow " 注："
    yellow "   1.各协议理论速度对比：github.com/badO1a5A90/v2ray-doc/blob/main/Xray_test_v1.1.1.md"
    yellow "   2.XTLS完全兼容TLS"
    yellow "   3.WebSocket协议支持CDN，TCP不支持"
    yellow "   4.VLESS协议用于CDN，CDN可以看见传输的明文"
    yellow "   5.若不知CDN为何物，请选3"
    echo
    local mode=""
    while [[ "$mode" != "1" && "$mode" != "2" && "$mode" != "3" && "$mode" != "4" && "$mode" != "5" ]]
    do
        read -p "您的选择是：" mode
    done
    if [ $mode -eq 1 ]; then
        protocol_1=1
        protocol_2=2
    elif [ $mode -eq 2 ]; then
        protocol_1=1
        protocol_2=1
    elif [ $mode -eq 3 ]; then
        protocol_1=1
        protocol_2=0
    elif [ $mode -eq 4 ]; then
        protocol_1=0
        protocol_2=2
    elif [ $mode -eq 5 ]; then
        protocol_1=0
        protocol_2=1
    fi
}

#Read camouflage type output pretend
readPretend()
{
    local queren=0
    while [$queren -ne 1]
    do
        echo -e "\\n\\n\\n"
        tyblue "------------------------------Please select the website page you want to disguise----------- -------------------"
        tyblue "1. Cloudreve \\033[32m(recommended)"
        purple "Personal Network Disk"
        tyblue "2. Nextcloud \\033[32m(recommended)"
        purple "Personal network disk, need to install php"
        tyblue "3. 403 pages"
        purple "Simulate website backend"
        tyblue "4. Custom static website"
        purple "It is not recommended for Xiaobai to choose, the default is the Nextcloud login interface, it is strongly recommended to replace it by yourself"
        tyblue "5. Custom reverse proxy webpage \033[31m(not recommended)"
        echo
        green "Memory <128MB is recommended to choose 403 pages"
        green "128MB<=Memory<1G It is recommended to choose Cloudreve"
        green "Memory>=1G It is recommended to choose Nextcloud or Cloudreve"
        echo
        yellow "For detailed instructions on choosing a camouflage website, please see: https://github.com/kirin10000/Xray-script# camouflage website instructions"
        echo
        pretend=""
        while [[ "$pretend" != "1" && "$pretend" != "2" && "$pretend" != "3" && "$pretend" != "4" && "$pretend" != " 5" ]]
        do
            read -p "Your choice is:" pretend
        done
        queren=1
        if [$pretend -eq 1 ]; then
            if [-z "$machine" ]; then
                red "Your VPS command set does not support Cloudreve!"
                sleep 3s
                queren=0
            fi
        elif [$pretend -eq 2 ]; then
            if ([ $release == "centos"] || [$release == "fedora"] || [$release == "other-redhat" ]) &&! version_ge "$redhat_version" 8; then
                red "Does not support installing php on Red Hat-based systems with Red Hat version <8"
                yellow "For example: CentOS<8 Fedora<30 version"
                sleep 3s
                queren=0
            elif [$php_is_installed -eq 0 ]; then
                tyblue "Installing Nextcloud requires installing php"
                yellow "Compiling && installing php may take an additional 15-60 minutes"
                yellow "php will occupy a certain amount of system resources, and it is not recommended for machines with less than 512M memory"
                ! ask_if "Are you sure to choose? (y/n)" && queren=0
            fi
        elif [$pretend -eq 5 ]; then
            yellow "Enter the reverse proxy URL in the format: \"https://v.qq.com\""
            pretend=""
            while [-z "$pretend"]
            do
                read -p "Please enter the reverse proxy URL:" pretend
            done
        fi
    done
}
readDomain()
{
    check_domain()
    {
        if [ -z "$1" ]; then
            return 1
        elif [ "${1%%.*}" == "www" ]; then
        red "Do not bring www in front of the domain name!"
            return 1
        else
            return 0
        fi
    }
local domain
    local domain_config=""
    local pretend
    echo -e "\\n\\n\\n"
    tyblue "--------------------Please select the domain name resolution situation--------------------"
    tyblue "1. The main domain name and www. main domain name are resolved to this server \\033[32m(recommended)"
    green "For example: 123.com and www.123.com are resolved to this server"
    tyblue "2. Only a specific domain name resolves to this server"
    green "For example, one of 123.com or www.123.com or xxx.123.com resolves to this server"
    echo
    while ["$domain_config" != "1"] && ["$domain_config" != "2"]
    do
        read -p "Your choice is:" domain_config
    done
    local queren=0
    while [$queren -ne 1]
    do
        domain=""
        echo
        if [$domain_config -eq 1 ]; then
            tyblue'---------Please enter the main domain name (without "www.", "http://" or "https://" in front)---------'
            while! check_domain "$domain"
            do
                read -p "Please enter the domain name:" domain
            done
        else
            tyblue'-------Please enter the domain name resolved to this server (without "http://" or "https://" in front)-------'
            while [-z "$domain"]
            do
                read -p "Please enter the domain name:" domain
            done
        fi
        echo
        ask_if "The domain name you entered is \"$domain\", are you sure? (y/n)" && queren=1
    done
    readPretend
    true_domain_list+=("$domain")
    [ $domain_config -eq 1 ] && domain_list+=("www.$domain") || domain_list+=("$domain")
    domain_config_list+=("$domain_config")
    pretend_list+=("$pretend")
}

#Installation dependencies
install_base_dependence()
{
    if [ $release == "centos" ] || [ $release == "fedora" ] || [ $release == "other-redhat" ]; then
        install_dependence net-tools redhat-lsb-core ca-certificates wget unzip curl openssl crontabs gcc gcc-c++ make
    else
        install_dependence net-tools lsb-release ca-certificates wget unzip curl openssl cron gcc g++ make
    fi
}
install_nginx_dependence()
{
    if [ $release == "centos" ] || [ $release == "fedora" ] || [ $release == "other-redhat" ]; then
        install_dependence perl-IPC-Cmd perl-Getopt-Long perl-Data-Dumper pcre-devel zlib-devel libxml2-devel libxslt-devel gd-devel geoip-devel perl-ExtUtils-Embed gperftools-devel libatomic_ops-devel perl-devel
    else
        install_dependence libpcre3-dev zlib1g-dev libxml2-dev libxslt1-dev libgd-dev libgeoip-dev libgoogle-perftools-dev libatomic-ops-dev libperl-dev
    fi
}
install_php_dependence()
{
    if [ $release == "centos" ] || [ $release == "fedora" ] || [ $release == "other-redhat" ]; then
        install_dependence pkgconf-pkg-config libxml2-devel sqlite-devel systemd-devel libacl-devel openssl-devel krb5-devel pcre2-devel zlib-devel bzip2-devel libcurl-devel gdbm-devel libdb-devel tokyocabinet-devel lmdb-devel enchant-devel libffi-devel libpng-devel gd-devel libwebp-devel libjpeg-turbo-devel libXpm-devel freetype-devel gmp-devel libc-client-devel libicu-devel openldap-devel oniguruma-devel unixODBC-devel freetds-devel libpq-devel aspell-devel libedit-devel net-snmp-devel libsodium-devel libargon2-devel libtidy-devel libxslt-devel libzip-devel autoconf git ImageMagick-devel
    else
        install_dependence pkg-config libxml2-dev libsqlite3-dev libsystemd-dev libacl1-dev libapparmor-dev libssl-dev libkrb5-dev libpcre2-dev zlib1g-dev libbz2-dev libcurl4-openssl-dev libqdbm-dev libdb-dev libtokyocabinet-dev liblmdb-dev libenchant-dev libffi-dev libpng-dev libgd-dev libwebp-dev libjpeg-dev libxpm-dev libfreetype6-dev libgmp-dev libc-client2007e-dev libicu-dev libldap2-dev libsasl2-dev libonig-dev unixodbc-dev freetds-dev libpq-dev libpspell-dev libedit-dev libmm-dev libsnmp-dev libsodium-dev libargon2-dev libtidy-dev libxslt1-dev libzip-dev autoconf git libmagickwand-dev
    fi
}

#Compile &&install php
compile_php()
{
    green "php is being compiled..."
    if ! wget -O "${php_version}.tar.xz" "https://www.php.net/distributions/${php_version}.tar.xz"; then
        red "Failed to get php"
        yellow "Press Enter to continue or Ctrl+c to terminate"
        read -s
    fi
    tar -xJf "${php_version}.tar.xz"
    cd "${php_version}"
    sed -i 's#db$THIS_VERSION/db_185.h include/db$THIS_VERSION/db_185.h include/db/db_185.h#& include/db_185.h#' configure
    if [ $release == "ubuntu" ] || [ $release == "other-debian" ]; then
        sed -i 's#if test -f $THIS_PREFIX/$PHP_LIBDIR/lib$LIB\.a || test -f $THIS_PREFIX/$PHP_LIBDIR/lib$LIB\.$SHLIB_SUFFIX_NAME#& || true#' configure
        sed -i 's#if test ! -r "$PDO_FREETDS_INSTALLATION_DIR/$PHP_LIBDIR/libsybdb\.a" && test ! -r "$PDO_FREETDS_INSTALLATION_DIR/$PHP_LIBDIR/libsybdb\.so"#& \&\& false#' configure
        ./configure --prefix=${php_prefix} --enable-embed=shared --enable-fpm --with-fpm-user=www-data --with-fpm-group=www-data --with-fpm-systemd --with-fpm-acl --with-fpm-apparmor --disable-phpdbg --with-layout=GNU --with-openssl --with-kerberos --with-external-pcre --with-pcre-jit --with-zlib --enable-bcmath --with-bz2 --enable-calendar --with-curl --enable-dba --with-qdbm --with-db4 --with-db1 --with-tcadb --with-lmdb --with-enchant --enable-exif --with-ffi --enable-ftp --enable-gd --with-external-gd --with-webp --with-jpeg --with-xpm --with-freetype --enable-gd-jis-conv --with-gettext --with-gmp --with-mhash --with-imap --with-imap-ssl --enable-intl --with-ldap --with-ldap-sasl --enable-mbstring --with-mysqli --with-mysql-sock --with-unixODBC --enable-pcntl --with-pdo-dblib --with-pdo-mysql --with-zlib-dir --with-pdo-odbc=unixODBC,/usr --with-pdo-pgsql --with-pgsql --with-pspell --with-libedit --with-mm --enable-shmop --with-snmp --enable-soap --enable-sockets --with-sodium --with-password-argon2 --enable-sysvmsg --enable-sysvsem --enable-sysvshm --with-tidy --with-xsl --with-zip --enable-mysqlnd --with-pear CPPFLAGS="-g0 -O3" CFLAGS="-g0 -O3" CXXFLAGS="-g0 -O3"
    else
        ./configure --prefix=${php_prefix} --with-libdir=lib64 --enable-embed=shared --enable-fpm --with-fpm-user=www-data --with-fpm-group=www-data --with-fpm-systemd --with-fpm-acl --disable-phpdbg --with-layout=GNU --with-openssl --with-kerberos --with-external-pcre --with-pcre-jit --with-zlib --enable-bcmath --with-bz2 --enable-calendar --with-curl --enable-dba --with-gdbm --with-db4 --with-db1 --with-tcadb --with-lmdb --with-enchant --enable-exif --with-ffi --enable-ftp --enable-gd --with-external-gd --with-webp --with-jpeg --with-xpm --with-freetype --enable-gd-jis-conv --with-gettext --with-gmp --with-mhash --with-imap --with-imap-ssl --enable-intl --with-ldap --with-ldap-sasl --enable-mbstring --with-mysqli --with-mysql-sock --with-unixODBC --enable-pcntl --with-pdo-dblib --with-pdo-mysql --with-zlib-dir --with-pdo-odbc=unixODBC,/usr --with-pdo-pgsql --with-pgsql --with-pspell --with-libedit --enable-shmop --with-snmp --enable-soap --enable-sockets --with-sodium --with-password-argon2 --enable-sysvmsg --enable-sysvsem --enable-sysvshm --with-tidy --with-xsl --with-zip --enable-mysqlnd --with-pear CPPFLAGS="-g0 -O3" CFLAGS="-g0 -O3" CXXFLAGS="-g0 -O3"
    fi
    swap_on 1800
    if ! make; then
        swap_off
        red "php compilation failed!"
        green "Welcome to a bug report (https://github.com/kirin10000/Xray-script/issues), thank you for your support"
        yellow "Before the bug is fixed, it is recommended to use the latest version of Ubuntu system"
        exit 1
    fi
    swap_off
    cd ..
}
install_php_part1()
{
    green "php is being installed..."
    cd "${php_version}"
    make install
    cp sapi/fpm/php-fpm.service ${php_prefix}/php-fpm.service.default
    cd ..
    php_is_installed=1
}
instal_php_imagick()
{
    if ! git clone https://github.com/Imagick/imagick; then
        yellow "Failed to obtain php-imagick source code"
        yellow "Press Enter to continue or Ctrl+c to terminate"
        read -s
    fi
    cd imagick
    ${php_prefix}/bin/phpize
    ./configure --with-php-config=${php_prefix}/bin/php-config CFLAGS="-g0 -O3"
    swap_on 380
    if ! make; then
        swap_off
        yellow "php-imagick compilation failed"
        green "Welcome to a bug report (https://github.com/kirin10000/Xray-script/issues), thank you for your support"
        yellow "Before the bug is fixed, it is recommended to use the latest version of Ubuntu system"
        yellow "Press Enter to continue or Ctrl+c to terminate"
        read -s
    else
        swap_off
    fi
    mv modules/imagick.so "$(${php_prefix}/bin/php -i | grep "^extension_dir" | awk '{print $3}')"
    cd ..
}
install_php_part2()
{
    useradd -r -s /bin/bash www-data
    cp ${php_prefix}/etc/php-fpm.conf.default ${php_prefix}/etc/php-fpm.conf
    cp ${php_prefix}/etc/php-fpm.d/www.conf.default ${php_prefix}/etc/php-fpm.d/www.conf
    sed -i '/^[ \t]*listen[ \t]*=/d' ${php_prefix}/etc/php-fpm.d/www.conf
    echo "listen = /dev/shm/php-fpm_unixsocket/php.sock" >> ${php_prefix}/etc/php-fpm.d/www.conf
    sed -i '/^[ \t]*env\[PATH\][ \t]*=/d' ${php_prefix}/etc/php-fpm.d/www.conf
    echo "env[PATH] = $PATH" >> ${php_prefix}/etc/php-fpm.d/www.conf
    instal_php_imagick
cat > ${php_prefix}/etc/php.ini << EOF
[PHP]
memory_limit=-1
upload_max_filesize=-1
extension=imagick.so
zend_extension=opcache.so
opcache.enable=1
EOF
    install -m 644 "${php_prefix}/php-fpm.service.default" $php_service
cat >> $php_service <<EOF

[Service]
ProtectSystem=false
ExecStartPre=/bin/rm -rf /dev/shm/php-fpm_unixsocket
ExecStartPre=/bin/mkdir /dev/shm/php-fpm_unixsocket
ExecStartPre=/bin/chmod 711 /dev/shm/php-fpm_unixsocket
ExecStopPost=/bin/rm -rf /dev/shm/php-fpm_unixsocket
EOF
    systemctl daemon-reload
}

#Compile & install nginx
compile_nginx()
{
    green "正在编译Nginx。。。。"
    if ! wget -O ${nginx_version}.tar.gz https://nginx.org/download/${nginx_version}.tar.gz; then
        red "Failed to obtain nginx"
        yellow "Press Enter to continue or Ctrl+c to terminate"
        read -s
    fi
    tar -zxf ${nginx_version}.tar.gz
    if ! wget -O ${openssl_version}.tar.gz https://github.com/openssl/openssl/archive/${openssl_version#*-}.tar.gz; then
         red "Failed to obtain openssl"
         yellow "Press Enter to continue or Ctrl+c to terminate"
        read -s
    fi
    tar -zxf ${openssl_version}.tar.gz
    cd ${nginx_version}
    sed -i "s/OPTIMIZE[ \\t]*=>[ \\t]*'-O'/OPTIMIZE          => '-O3'/g" src/http/modules/perl/Makefile.PL
    ./configure --prefix=/usr/local/nginx --with-openssl=../$openssl_version --with-mail=dynamic --with-mail_ssl_module --with-stream=dynamic --with-stream_ssl_module --with-stream_realip_module --with-stream_geoip_module=dynamic --with-stream_ssl_preread_module --with-http_ssl_module --with-http_v2_module --with-http_realip_module --with-http_addition_module --with-http_xslt_module=dynamic --with-http_image_filter_module=dynamic --with-http_geoip_module=dynamic --with-http_sub_module --with-http_dav_module --with-http_flv_module --with-http_mp4_module --with-http_gunzip_module --with-http_gzip_static_module --with-http_auth_request_module --with-http_random_index_module --with-http_secure_link_module --with-http_degradation_module --with-http_slice_module --with-http_stub_status_module --with-http_perl_module=dynamic --with-pcre --with-libatomic --with-compat --with-cpp_test_module --with-google_perftools_module --with-file-aio --with-threads --with-poll_module --with-select_module --with-cc-opt="-Wno-error -g0 -O3"
    swap_on 480
    if ! make; then
    swap_off
     red "Nginx compilation failed!"
     green "Welcome to a bug report (https://github.com/kirin10000/Xray-script/issues), thank you for your support"
     yellow "Before the bug is fixed, it is recommended to use the latest version of Ubuntu system"
     exit 1
    fi
    swap_off
    cd ..
}
config_service_nginx()
{
    rm -rf $nginx_service
cat > $nginx_service << EOF
[Unit]
Description=The NGINX HTTP and reverse proxy server
After=syslog.target network-online.target remote-fs.target nss-lookup.target
Wants=network-online.target

[Service]
Type=forking
User=root
ExecStartPre=/bin/rm -rf /dev/shm/nginx_unixsocket
ExecStartPre=/bin/mkdir /dev/shm/nginx_unixsocket
ExecStartPre=/bin/chmod 711 /dev/shm/nginx_unixsocket
ExecStartPre=/bin/rm -rf /dev/shm/nginx_tcmalloc
ExecStartPre=/bin/mkdir /dev/shm/nginx_tcmalloc
ExecStartPre=/bin/chmod 0777 /dev/shm/nginx_tcmalloc
ExecStart=${nginx_prefix}/sbin/nginx
ExecStop=${nginx_prefix}/sbin/nginx -s stop
ExecStopPost=/bin/rm -rf /dev/shm/nginx_tcmalloc
ExecStopPost=/bin/rm -rf /dev/shm/nginx_unixsocket
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF
    chmod 644 $nginx_service
    systemctl daemon-reload
}
install_nginx_part1()
{
green "Nginx is being installed..."
    cd ${nginx_version}
    make install
    cd ..
}
install_nginx_part2()
{
    mkdir ${nginx_prefix}/conf.d
    touch $nginx_config
    mkdir ${nginx_prefix}/certs
    mkdir ${nginx_prefix}/html/issue_certs
cat > ${nginx_prefix}/conf/issue_certs.conf << EOF
events {
    worker_connections  1024;
}
http {
    server {
        listen [::]:80 ipv6only=off;
        root ${nginx_prefix}/html/issue_certs;
    }
}
EOF
cat > ${nginx_prefix}/conf.d/nextcloud.conf <<EOF
    client_max_body_size 0;
    fastcgi_buffers 64 4K;
    gzip on;
    gzip_vary on;
    gzip_comp_level 4;
    gzip_min_length 256;
    gzip_proxied expired no-cache no-store private no_last_modified no_etag auth;
    gzip_types application/atom+xml application/javascript application/json application/ld+json application/manifest+json application/rss+xml application/vnd.geo+json application/vnd.ms-fontobject application/x-font-ttf application/x-web-app-manifest+json application/xhtml+xml application/xml font/opentype image/bmp image/svg+xml image/x-icon text/cache-manifest text/css text/plain text/vcard text/vnd.rim.location.xloc text/vtt text/x-component text/x-cross-domain-policy;
    add_header Referrer-Policy                      "no-referrer"   always;
    add_header X-Content-Type-Options               "nosniff"       always;
    add_header X-Download-Options                   "noopen"        always;
    add_header X-Frame-Options                      "SAMEORIGIN"    always;
    add_header X-Permitted-Cross-Domain-Policies    "none"          always;
    add_header X-Robots-Tag                         "none"          always;
    add_header X-XSS-Protection                     "1; mode=block" always;
    fastcgi_hide_header X-Powered-By;
    index index.php index.html /index.php\$request_uri;
    location = / {
        if ( \$http_user_agent ~ ^DavClnt ) {
            return 302 https://\$host/remote.php/webdav/\$is_args\$args;
        }
    }
    location = /robots.txt {
        allow all;
        log_not_found off;
        access_log off;
    }
    location ^~ /.well-known {
        rewrite ^/\\.well-known/host-meta\\.json  /public.php?service=host-meta-json  last;
        rewrite ^/\\.well-known/host-meta        /public.php?service=host-meta       last;
        rewrite ^/\\.well-known/webfinger        /public.php?service=webfinger       last;
        rewrite ^/\\.well-known/nodeinfo         /public.php?service=nodeinfo        last;
        location = /.well-known/carddav     { return 301 https://\$host/remote.php/dav/; }
        location = /.well-known/caldav      { return 301 https://\$host/remote.php/dav/; }
        try_files \$uri \$uri/ =404;
    }
    location ~ ^/(?:build|tests|config|lib|3rdparty|templates|data)(?:$|/)  { return 404; }
    location ~ ^/(?:\\.|autotest|occ|issue|indie|db_|console)              { return 404; }
    location ~ \\.php(?:$|/) {
        try_files \$fastcgi_script_name =404;
        include fastcgi.conf;
        fastcgi_param REMOTE_ADDR 127.0.0.1;
        fastcgi_param SERVER_PORT 443;
        fastcgi_split_path_info ^(.+?\\.php)(/.*)$;
        fastcgi_param PATH_INFO \$fastcgi_path_info;
        fastcgi_param HTTPS on;
        fastcgi_param modHeadersAvailable true;
        fastcgi_param front_controller_active true;
        fastcgi_pass unix:/dev/shm/php-fpm_unixsocket/php.sock;
        fastcgi_intercept_errors on;
        fastcgi_request_buffering off;
    }
    location ~ \\.(?:css|js|svg|gif)$ {
        try_files \$uri /index.php\$request_uri;
        expires 6M;
        access_log off;
    }
    location ~ \\.woff2?$ {
        try_files \$uri /index.php\$request_uri;
        expires 7d;
        access_log off;
    }
    location / {
        try_files \$uri \$uri/ /index.php\$request_uri;
    }
EOF
    config_service_nginx
    systemctl enable nginx
    nginx_is_installed=1
}

#Install/Update Xray
install_update_xray()
{
     green "Installing/updating Xray..."
     if! bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install -u root --without-geodata &&! bash- c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install -u root --without-geodata; then
         red "Failed to install/update Xray"
         yellow "Press Enter to continue or Ctrl+c to terminate"
         read -s
         return 1
     fi
}

#Get certificate Parameters: domain name location
get_cert()
{
    mv $xray_config ${xray_config}.bak
    mv ${nginx_prefix}/conf/nginx.conf ${nginx_prefix}/conf/nginx.conf.bak2
    cp ${nginx_prefix}/conf/nginx.conf.default ${nginx_prefix}/conf/nginx.conf
    echo "{}" > $xray_config
    local temp=""
    [ ${domain_config_list[$1]} -eq 1 ] && temp="-d ${domain_list[$1]}"
    if ! $HOME/.acme.sh/acme.sh --issue -d ${true_domain_list[$1]} $temp -w ${nginx_prefix}/html/issue_certs -k ec-256 -ak ec-256 --pre-hook "mv ${nginx_prefix}/conf/nginx.conf ${nginx_prefix}/conf/nginx.conf.bak && cp ${nginx_prefix}/conf/issue_certs.conf ${nginx_prefix}/conf/nginx.conf && sleep 2s && systemctl restart nginx" --post-hook "mv ${nginx_prefix}/conf/nginx.conf.bak ${nginx_prefix}/conf/nginx.conf && sleep 2s && systemctl restart nginx" --ocsp; then
        $HOME/.acme.sh/acme.sh --issue -d ${true_domain_list[$1]} $temp -w ${nginx_prefix}/html/issue_certs -k ec-256 -ak ec-256 --pre-hook "mv ${nginx_prefix}/conf/nginx.conf ${nginx_prefix}/conf/nginx.conf.bak && cp ${nginx_prefix}/conf/issue_certs.conf ${nginx_prefix}/conf/nginx.conf && sleep 2s && systemctl restart nginx" --post-hook "mv ${nginx_prefix}/conf/nginx.conf.bak ${nginx_prefix}/conf/nginx.conf && sleep 2s && systemctl restart nginx" --ocsp --debug
    fi
    if ! $HOME/.acme.sh/acme.sh --installcert -d ${true_domain_list[$1]} --key-file ${nginx_prefix}/certs/${true_domain_list[$1]}.key --fullchain-file ${nginx_prefix}/certs/${true_domain_list[$1]}.cer --reloadcmd "sleep 2s && systemctl restart xray" --ecc; then
        $HOME/.acme.sh/acme.sh --remove --domain ${true_domain_list[$1]} --ecc
        rm -rf $HOME/.acme.sh/${true_domain_list[$1]}_ecc
        rm -rf "${nginx_prefix}/certs/${true_domain_list[$1]}.key" "${nginx_prefix}/certs/${true_domain_list[$1]}.cer"
        mv ${xray_config}.bak $xray_config
        mv ${nginx_prefix}/conf/nginx.conf.bak2 ${nginx_prefix}/conf/nginx.conf
        return 1
    fi
    mv ${xray_config}.bak $xray_config
    mv ${nginx_prefix}/conf/nginx.conf.bak2 ${nginx_prefix}/conf/nginx.conf
    return 0
}
get_all_certs()
{
local i
     for ((i=0;i<${#domain_list[@]};i++))
     do
         if! get_cert "$i"; then
             red "Domain name\"${true_domain_list[$i]}\"Certificate application failed!"
             yellow "Please check:"
             yellow "1. Is the domain name resolved correctly"
             yellow "2. Is port 80 of the vps firewall open?"
             yellow "And after installing/resetting the domain name, use the script main menu \"reset domain name\" option to repair"
             yellow "Press Enter to continue..."
             read -s
         fi
     done
}

#Configure nginx
config_nginx_init()
{
cat > ${nginx_prefix}/conf/nginx.conf <<EOF

user  root root;
worker_processes  auto;

#error_log  logs/error.log;
#error_log  logs/error.log  notice;
#error_log  logs/error.log  info;

#pid        logs/nginx.pid;
google_perftools_profiles /dev/shm/nginx_tcmalloc/tcmalloc;

events {
    worker_connections  1024;
}


http {
    include       mime.types;
    default_type  application/octet-stream;

    #log_format  main  '\$remote_addr - \$remote_user [\$time_local] "\$request" '
    #                  '\$status \$body_bytes_sent "\$http_referer" '
    #                  '"\$http_user_agent" "\$http_x_forwarded_for"';

    #access_log  logs/access.log  main;

    sendfile        on;
    #tcp_nopush     on;

    #keepalive_timeout  0;
    keepalive_timeout  65;

    #gzip  on;

    include       $nginx_config;
    #server {
        #listen       80;
        #server_name  localhost;

        #charset koi8-r;

        #access_log  logs/host.access.log  main;

        #location / {
        #    root   html;
        #    index  index.html index.htm;
        #}

        #error_page  404              /404.html;

        # redirect server error pages to the static page /50x.html
        #
        #error_page   500 502 503 504  /50x.html;
        #location = /50x.html {
        #    root   html;
        #}

        # proxy the PHP scripts to Apache listening on 127.0.0.1:80
        #
        #location ~ \\.php\$ {
        #    proxy_pass   http://127.0.0.1;
        #}

        # pass the PHP scripts to FastCGI server listening on 127.0.0.1:9000
        #
        #location ~ \\.php\$ {
        #    root           html;
        #    fastcgi_pass   127.0.0.1:9000;
        #    fastcgi_index  index.php;
        #    fastcgi_param  SCRIPT_FILENAME  /scripts\$fastcgi_script_name;
        #    include        fastcgi_params;
        #}

        # deny access to .htaccess files, if Apache's document root
        # concurs with nginx's one
        #
        #location ~ /\\.ht {
        #    deny  all;
        #}
    #}


    # another virtual host using mix of IP-, name-, and port-based configuration
    #
    #server {
    #    listen       8000;
    #    listen       somename:8080;
    #    server_name  somename  alias  another.alias;

    #    location / {
    #        root   html;
    #        index  index.html index.htm;
    #    }
    #}


    # HTTPS server
    #
    #server {
    #    listen       443 ssl;
    #    server_name  localhost;

    #    ssl_certificate      cert.pem;
    #    ssl_certificate_key  cert.key;

    #    ssl_session_cache    shared:SSL:1m;
    #    ssl_session_timeout  5m;

    #    ssl_ciphers  HIGH:!aNULL:!MD5;
    #    ssl_prefer_server_ciphers  on;

    #    location / {
    #        root   html;
    #        index  index.html index.htm;
    #    }
    #}

}
EOF
}
config_nginx()
{
    config_nginx_init
    local i
cat > $nginx_config<<EOF
server {
    listen 80 reuseport default_server;
    listen [::]:80 reuseport default_server;
    return 301 https://${domain_list[0]};
}
server {
    listen 80;
    listen [::]:80;
    server_name ${domain_list[@]};
    return 301 https://\$host\$request_uri;
}
EOF
    local temp_domain_list2=()
    for i in ${!domain_config_list[@]}
    do
        [ ${domain_config_list[$i]} -eq 1 ] && temp_domain_list2+=("${true_domain_list[$i]}")
    done
    if [ ${#temp_domain_list2[@]} -ne 0 ]; then
cat >> $nginx_config<<EOF
server {
    listen 80;
    listen [::]:80;
    listen unix:/dev/shm/nginx_unixsocket/default.sock;
    listen unix:/dev/shm/nginx_unixsocket/h2.sock http2;
    server_name ${temp_domain_list2[@]};
    return 301 https://www.\$host\$request_uri;
}
EOF
    fi
cat >> $nginx_config<<EOF
server {
    listen unix:/dev/shm/nginx_unixsocket/default.sock default_server;
    listen unix:/dev/shm/nginx_unixsocket/h2.sock http2 default_server;
    return 301 https://${domain_list[0]};
}
EOF
    for ((i=0;i<${#domain_list[@]};i++))
    do
cat >> $nginx_config<<EOF
server {
    listen unix:/dev/shm/nginx_unixsocket/default.sock;
    listen unix:/dev/shm/nginx_unixsocket/h2.sock http2;
    server_name ${domain_list[$i]};
    add_header Strict-Transport-Security "max-age=63072000; includeSubdomains; preload" always;
EOF
        if [ "${pretend_list[$i]}" == "1" ]; then
cat >> $nginx_config<<EOF
    location / {
        proxy_set_header X-Forwarded-For 127.0.0.1;
        proxy_set_header Host \$http_host;
        proxy_redirect off;
        proxy_pass http://unix:/dev/shm/cloudreve_unixsocket/cloudreve.sock;
        client_max_body_size 0;
    }
EOF
        elif [ "${pretend_list[$i]}" == "2" ]; then
            echo "    root ${nginx_prefix}/html/${true_domain_list[$i]};" >> $nginx_config
            echo "    include ${nginx_prefix}/conf.d/nextcloud.conf;" >> $nginx_config
        elif [ "${pretend_list[$i]}" == "3" ]; then
            echo "    return 403;" >> $nginx_config
        elif [ "${pretend_list[$i]}" == "4" ]; then
            echo "    root ${nginx_prefix}/html/${true_domain_list[$i]};" >> $nginx_config
        else
cat >> $nginx_config<<EOF
    location / {
        proxy_pass ${pretend_list[$i]};
        proxy_set_header referer "${pretend_list[$i]}";
    }
EOF
        fi
        echo "}" >> $nginx_config
    done
cat >> $nginx_config << EOF
#-----------------Do not modify the following content----------------
#domain_list=${domain_list[@]}
#true_domain_list=${true_domain_list[@]}
#domain_config_list=${domain_config_list[@]}
#pretend_list=${pretend_list[@]}
EOF
}

#Configuration xray
config_xray()
{
    local i
    local temp_domain
cat > $xray_config <<EOF
{
    "log": {
        "loglevel": "none"
    },
    "inbounds": [
        {
            "port": 443,
            "protocol": "vless",
            "settings": {
EOF
    if [ $protocol_1 -eq 1 ]; then
cat >> $xray_config <<EOF
                "clients": [
                    {
                        "id": "$xid_1",
                        "flow": "xtls-rprx-direct"
                    }
                ],
EOF
    fi
    echo '                "decryption": "none",' >> $xray_config
    echo '                "fallbacks": [' >> $xray_config
    if [ $protocol_2 -ne 0 ]; then
cat >> $xray_config <<EOF
                    {
                        "path": "$path",
                        "dest": "@/dev/shm/xray/ws.sock"
                    },
EOF
    fi
cat >> $xray_config <<EOF
                    {
                        "alpn": "h2",
                        "dest": "/dev/shm/nginx_unixsocket/h2.sock"
                    },
                    {
                        "dest": "/dev/shm/nginx_unixsocket/default.sock"
                    }
                ]
            },
            "streamSettings": {
                "network": "tcp",
                "security": "xtls",
                "xtlsSettings": {
                    "alpn": [
                        "h2",
                        "http/1.1"
                    ],
                    "minVersion": "1.2",
                    "cipherSuites": "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
                    "certificates": [
EOF
    for ((i=0;i<${#true_domain_list[@]};i++))
    do
cat >> $xray_config <<EOF
                        {
                            "certificateFile": "${nginx_prefix}/certs/${true_domain_list[$i]}.cer",
                            "keyFile": "${nginx_prefix}/certs/${true_domain_list[$i]}.key",
                            "ocspStapling": 3600
EOF
        ((i==${#true_domain_list[@]}-1)) && echo "                        }" >> $xray_config || echo "                        }," >> $xray_config
    done
cat >> $xray_config <<EOF
                    ]
                }
            }
EOF
    if [ $protocol_2 -ne 0 ]; then
        echo '        },' >> $xray_config
        echo '        {' >> $xray_config
        echo '            "listen": "@/dev/shm/xray/ws.sock",' >> $xray_config
        if [ $protocol_2 -eq 2 ]; then
            echo '            "protocol": "vmess",' >> $xray_config
        else
            echo '            "protocol": "vless",' >> $xray_config
        fi
        echo '            "settings": {' >> $xray_config
        echo '                "clients": [' >> $xray_config
        echo '                    {' >> $xray_config
        echo "                        \"id\": \"$xid_2\"" >> $xray_config
        echo '                    }' >> $xray_config
        if [ $protocol_2 -eq 2 ]; then
            echo '                ]' >> $xray_config
        else
            echo '                ],' >> $xray_config
            echo '                "decryption": "none"' >> $xray_config
        fi
cat >> $xray_config <<EOF
            },
            "streamSettings": {
                "network": "ws",
                "wsSettings": {
                    "path": "$path"
                }
            }
EOF
    fi
cat >> $xray_config <<EOF
        }
    ],
    "outbounds": [
        {
            "protocol": "freedom"
        }
    ]
}
EOF
}

#Download the nextcloud template for disguising parameters: the position of the domain name in the list
init_web()
{
     if! ([ "${pretend_list[$1]}" == "2"] || ["${pretend_list[$1]}" == "4" ]); then
         return 0
     fi
     local url
     [${pretend_list[$1]} -eq 2] && url="${nextcloud_url}" || url="https://github.com/kirin10000/Xray-script/raw/main/Website-Template.zip"
     local info
     [${pretend_list[$1]} -eq 2] && info="Nextcloud" || info="Website template"
     if! wget -O "${nginx_prefix}/html/Website.zip" "$url"; then
         red "Failed to obtain ${info}"
         yellow "Press Enter to continue or Ctrl+c to terminate"
        read -s
    fi
    rm -rf "${nginx_prefix}/html/${true_domain_list[$1]}"
    if [ ${pretend_list[$1]} -eq 4 ]; then
        mkdir "${nginx_prefix}/html/${true_domain_list[$1]}"
        unzip -q -d "${nginx_prefix}/html/${true_domain_list[$1]}" "${nginx_prefix}/html/Website.zip"
    else
        unzip -q -d "${nginx_prefix}/html" "${nginx_prefix}/html/Website.zip"
        mv "${nginx_prefix}/html/nextcloud" "${nginx_prefix}/html/${true_domain_list[$1]}"
        chown -R www-data:www-data "${nginx_prefix}/html/${true_domain_list[$1]}"
    fi
    rm -rf "${nginx_prefix}/html/Website.zip"
}
init_all_webs()
{
    local i
    for ((i=0;i<${#domain_list[@]};i++))
    do
        init_web "$i"
    done
}

#Install/Update Cloudreve
update_cloudreve()
{
if! wget -O cloudreve.tar.gz "https://github.com/cloudreve/Cloudreve/releases/download/${cloudreve_version}/cloudreve_${cloudreve_version}_linux_${machine}.tar.gz"; then
         red "Failed to obtain Cloudreve!!"
         yellow "Press Enter to continue or Ctrl+c to terminate"
        read -s
    fi
    tar -zxf cloudreve.tar.gz
    local temp_cloudreve_status=0
    systemctl -q is-active cloudreve && temp_cloudreve_status=1
    systemctl stop cloudreve
    cp cloudreve $cloudreve_prefix
cat > $cloudreve_prefix/conf.ini << EOF
[System]
Mode = master
Debug = false
[UnixSocket]
Listen = /dev/shm/cloudreve_unixsocket/cloudreve.sock
EOF
    rm -rf $cloudreve_service
cat > $cloudreve_service << EOF
[Unit]
Description=Cloudreve
Documentation=https://docs.cloudreve.org
After=network.target
After=mysqld.service
Wants=network.target

[Service]
WorkingDirectory=$cloudreve_prefix
ExecStartPre=/bin/rm -rf /dev/shm/cloudreve_unixsocket
ExecStartPre=/bin/mkdir /dev/shm/cloudreve_unixsocket
ExecStartPre=/bin/chmod 711 /dev/shm/cloudreve_unixsocket
ExecStart=$cloudreve_prefix/cloudreve
ExecStopPost=/bin/rm -rf /dev/shm/cloudreve_unixsocket
Restart=on-abnormal
RestartSec=5s
KillMode=mixed

StandardOutput=null
StandardError=syslog

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    [ $temp_cloudreve_status -eq 1 ] && systemctl start cloudreve
}
install_init_cloudreve()
{
    remove_cloudreve
    mkdir -p $cloudreve_prefix
    update_cloudreve
    init_cloudreve "$1"
    cloudreve_is_installed=1
}

#Initial nextcloud parameter 1: The position of the domain name in the list
let_init_nextcloud()
{
     echo -e "\\n\\n"
     yellow "Please open now\"https://${domain_list[$1]}\" to initialize Nextcloud:"
     tyblue "1. Customize the user name and password of the administrator"
     tyblue "2. Choose SQLite for database type"
     tyblue "3. It is recommended not to check \"Install recommended applications\", because you can install it again after you enter"
     sleep 15s
     echo -e "\\n\\n"
     tyblue "Press Enter twice to continue..."
     read -s
     read -s
     echo
}

print_share_link()
{
if [$protocol_1 -eq 1 ]; then
        local ip=""
        while [-z "$ip"]
        do
            read -p "Please enter your VPS IP:" ip
        done
    fi
    echo
    tyblue "Share link:"
    if [$protocol_1 -eq 1 ]; then
        green "VLESS-TCP+XTLS\\033[35m(do not take CDN)\\033[32m:"
        yellow "Linux/Android/Router:"
        for i in ${!domain_list[@]}
        do
            tyblue "vless://${xid_1}@${ip}:443?security=xtls&sni=${domain_list[$i]}&flow=xtls-rprx-splice"
        done
        yellow "Other:"
        for i in ${!domain_list[@]}
        do
            tyblue "vless://${xid_1}@${ip}:443?security=xtls&sni=${domain_list[$i]}&flow=xtls-rprx-direct"
        done
    fi
    if [$protocol_2 -eq 1 ]; then
        green "VLESS-WebSocket+TLS\\033[35m (If there is a CDN, take the CDN, otherwise connect directly)\\033[32m:"
        for i in ${!domain_list[@]}
        do
            tyblue "vless://${xid_2}@${domain_list[$i]}:443?type=ws&security=tls&path=%2F${path#/}"
        done
    elif [$protocol_2 -eq 2 ]; then
        green "VMess-WebSocket+TLS\\033[35m (If there is a CDN, take the CDN, otherwise connect directly)\\033[32m:"
        for i in ${!domain_list[@]}
        do
            tyblue "vmess://${xid_2}@${domain_list[$i]}:443?type=ws&security=tls&path=%2F${path#/}"
        done
    fi
}
print_config_info()
{

Echo -e"\\n\\n\\n" if [$protocol_1 -ne 0]; then tyblue"---------------------- Xray-TCP+XTLS+Web (bù zǒu CDN) ---------------------" tyblue" fúwùqì lèixíng :VLESS" tyblue" address(dìzhǐ) : Fúwùqì ip" purple" (Qv2ray: Zhǔjī)" tyblue" port(duānkǒu) :443" Tyblue" id(yònghù ID/UUID) :${Xid_1}" tyblue" flow(liú kòng) : Shǐyòng XTLS:Linux/ānzhuō/lùyóuqì:Xtls-rprx-splice\\033[32m(tuījiàn)\\033[36m huò xtls-rprx-direct" tyblue" qítā:Xtls-rprx-direct" tyblue" shǐyòng TLS : Kōng" tyblue" encryption(jiāmì) :None" tyblue" ---Transport/StreamSettings(dǐcéng chuánshū fāngshì/liú shèzhì)---" tyblue" network(chuánshū xiéyì) :Tcp" purple" (Shadowrocket: Chuánshū fāngshì:None)" tyblue" type(wèizhuāng lèixíng) :None" purple" (Qv2ray: Xiéyì shèzhì-lèixíng)" tyblue" security(chuánshū céng jiāmì) :Xtls\\033[32m(tuījiàn)\\033[36m huò tls\\033[35m(cǐ xuǎnxiàng jiāng juédìng shì shǐyòng XTLS háishì TLS)" purple" (V2RayN(G): Dǐcéng chuánshū ānquán;Qv2ray:TLS shèzhì-ānquán lèixíng)" if [${#domain_list[@]} -eq 1]; then tyblue" serverName :${Domain_list[*]}" else tyblue" serverName :${Domain_list[*]}\\033[35m(rèn xuǎn qí yī)" fi purple" (V2RayN(G): Wèizhuāng yùmíng;Qv2ray:TLS shèzhì-fúwùqì dìzhǐ;Shadowrocket:Peer míngchēng)" tyblue" allowInsecure :False" purple" (Qv2ray: Yǔnxǔ bù ānquán de zhèngshū (bù dǎ gōu);Shadowrocket: Yǔnxǔ bù ānquán (guānbì))" tyblue" ------------------------qítā-----------------------" tyblue" Mux(duō lù fù yòng) : Shǐyòng XTLS bìxū guānbì; bù shǐyòng XTLS yě jiànyì guānbì" tyblue" socks rù zhàn de Sniffing(liúliàng tàncè): Jiànyì kāiqǐ" purple" (Qv2ray: Shǒu xuǎnxiàng-rù zhàn shèzhì-SOCKS shèzhì-xiù tàn)" tyblue"------------------------------------------------------------------------" fi if [$protocol_2 -ne 0]; then echo tyblue"------------ Xray-WebSocket+TLS+Web (yǒu CDN zé zǒu CDN, fǒuzé zhí lián) -----------" if [$protocol_2 -eq 1]; then tyblue" fúwùqì lèixíng :VLESS" else tyblue" fúwùqì lèixíng :VMess" fi if [${#domain_list[@]} -eq 1]; then tyblue" address(dìzhǐ) :${Domain_list[*]}" else tyblue" address(dìzhǐ) :${Domain_list[*]}\\033[35m(rèn xuǎn qí yī)" fi purple" (Qv2ray: Zhǔjī)" tyblue" port(duānkǒu) :443" Tyblue" id(yònghù ID/UUID) :${Xid_2}" if [$protocol_2 -eq 1]; then tyblue" flow(liú kòng) : Kōng" tyblue" encryption(jiāmì) :None" else tyblue" alterId(éwài ID) :0" Tyblue" security(jiāmì fāngshì) : Shǐyòng CDN, tuījiàn auto; bù shǐyòng CDN, tuījiàn none" purple" (Qv2ray: Ānquán xuǎnxiàng;Shadowrocket: Suànfǎ)" fi tyblue" ---Transport/StreamSettings(dǐcéng chuánshū fāngshì/liú shèzhì)---" tyblue" network(chuánshū xiéyì) :Ws" purple" (Shadowrocket: Chuánshū fāngshì:Websocket)" tyblue" path(lùjìng) :${Path}" tyblue" Host : Kōng" purple" (V2RayN(G): Wèizhuāng yùmíng;Qv2ray: Xiéyì shèzhì-qǐngqiú tóu)" tyblue" security(chuánshū céng jiāmì) :Tls" purple" (V2RayN(G): Dǐcéng chuánshū ānquán;Qv2ray:TLS shèzhì-ānquán lèixíng)" tyblue" serverName(yànzhèng fúwù duān zhèngshū yùmíng): Kōng" purple" (V2RayN(G): Wèizhuāng yùmíng;Qv2ray:TLS shèzhì-fúwùqì dìzhǐ;Shadowrocket:Peer míngchēng)" tyblue" allowInsecure :False" purple" (Qv2ray: Yǔnxǔ bù ānquán de zhèngshū (bù dǎ gōu);Shadowrocket: Yǔnxǔ bù ānquán (guānbì))" tyblue" ------------------------qítā-----------------------" tyblue" Mux(duō lù fù yòng) : Jiànyì guānbì" tyblue" socks rù zhàn de Sniffing(liúliàng tàncè): Jiànyì kāiqǐ" purple" (Qv2ray: Shǒu xuǎnxiàng-rù zhàn shèzhì-SOCKS shèzhì-xiù tàn)" tyblue"------------------------------------------------------------------------" fi echo ask_if"shìfǒu shēngchéng fèn xiǎng liànjiē?(Y/n)" && print_share_link echo green " mùqián zhīchí zhīchí XTLS de túxíng huà kèhù duān:" Green " Windows :Qv2ray v2.7.0-Pre1+ V2RayN v3.26+" Green " Android :V2RayNG v1.4.8+" Green " Linux/MacOS:Qv2ray v2.7.0-Pre1+" green " IOS :Shadowrocket v2.1.67+" Echo yellow" ruò shǐyòng VMess, qǐng jǐnkuài jiāng kèhù duān gēngxīn zhì Xray huò V2Ray v4.28.0+ Yǐ qǐyòng VMessAEAD" yellow" ruò shǐyòng VLESS, qǐng quèbǎo kèhù duān wèi Xray huò V2Ray v4.30.0+" Yellow" ruò shǐyòng XTLS, qǐng quèbǎo kèhù duān wèi Xray huò V2Ray v4.31.0 Zhì v4.32.1" Yellow" ruò shǐyòng xtls-rprx-splice, qǐng quèbǎo kèhù duān wèi Xray v1.1.0+" Echo tyblue" jiǎoběn zuìhòu gēngxīn shíjiān:2020.01.18" Echo red " cǐ jiǎoběn jǐn gōng jiāoliú xuéxí shǐyòng, qǐng wù shǐyòng cǐ jiǎoběn háng wéifǎ zhī shì. Wǎngluò fēifǎ wài zhī dì, xíng fēifǎ zhī shì, bì jiāng jiēshòu fǎlǜ zhìcái!!!!" Tyblue" 2020.11"
Show more
4436 / 5000
Translation results
echo -e "\\n\\n\\n"
    if [$protocol_1 -ne 0 ]; then
        tyblue "---------------------- Xray-TCP+XTLS+Web (not CDN) -------------- -------"
        tyblue "Server Type: VLESS"
        tyblue "address (address): server ip"
        purple "(Qv2ray: host)"
        tyblue "port (port): 443"
        tyblue "id(User ID/UUID): ${xid_1}"
        tyblue "flow (flow control): use XTLS: Linux/Android/router: xtls-rprx-splice\\033[32m(recommended)\\033[36m or xtls-rprx-direct"
        tyblue "Other: xtls-rprx-direct"
        tyblue "Use TLS: empty"
        tyblue "encryption (encryption): none"
        tyblue "---Transport/StreamSettings (underlying transmission mode/stream settings)---"
        tyblue "network (transmission protocol): tcp"
        purple "(Shadowrocket: transmission method: none)"
        tyblue "type (camouflage type): none"
        purple "(Qv2ray: protocol setting-type)"
        tyblue "security (transport layer encryption): xtls\\033[32m(recommended)\\033[36m or tls\\033[35m (this option will determine whether to use XTLS or TLS)"
        purple "(V2RayN(G): underlying transmission security; Qv2ray: TLS setting-security type)"
        if [${#domain_list[@]} -eq 1 ]; then
            tyblue "serverName: ${domain_list[*]}"
        else
            tyblue "serverName: ${domain_list[*]} \\033[35m (choose one)"
        fi
        purple "(V2RayN(G): camouflage domain name; Qv2ray: TLS setting-server address; Shadowrocket: Peer name)"
        tyblue "allowInsecure: false"
        purple "(Qv2ray: Allow insecure certificates (not tick); Shadowrocket: Allow insecure (closed))"
        tyblue "------------------------other----------------------- "
        tyblue "Mux (multiplexing): It must be closed when using XTLS; it is recommended to close when not using XTLS"
        tyblue "Sniffing of socks inbound (traffic detection): It is recommended to enable"
        purple "(Qv2ray: Preferences-Inbound Settings-SOCKS Settings-Sniffing)"
        tyblue "------------------------------------------------ ------------------------"
    fi
    if [$protocol_2 -ne 0 ]; then
        echo
        tyblue "------------ Xray-WebSocket+TLS+Web (If there is a CDN, take the CDN, otherwise directly connect) -----------"
        if [$protocol_2 -eq 1 ]; then
            tyblue "Server Type: VLESS"
        else
            tyblue "Server Type: VMess"
        fi
        if [${#domain_list[@]} -eq 1 ]; then
            tyblue "address (address): ${domain_list[*]}"
        else
            tyblue "address (address): ${domain_list[*]} \\033[35m (choose one)"
        fi
        purple "(Qv2ray: host)"
        tyblue "port (port): 443"
        tyblue "id(User ID/UUID): ${xid_2}"
        if [$protocol_2 -eq 1 ]; then
            tyblue "flow (flow control): empty"
            tyblue "encryption (encryption): none"
        else
            tyblue "alterId(additional ID): 0"
            tyblue "security (encryption method): use CDN, recommend auto; do not use CDN, recommend none"
            purple "(Qv2ray: security option; Shadowrocket: algorithm)"
        fi
        tyblue "---Transport/StreamSettings (underlying transmission mode/stream settings)---"
        tyblue "network (transmission protocol): ws"
        purple "(Shadowrocket: transmission method: websocket)"
        tyblue "path (path): ${path}"
        tyblue "Host: empty"
        purple "(V2RayN(G): camouflage domain name; Qv2ray: protocol setting-request header)"
        tyblue "security (transport layer encryption): tls"
        purple "(V2RayN(G): underlying transmission security; Qv2ray: TLS setting-security type)"
        tyblue "serverName (verification server certificate domain name): empty"
        purple "(V2RayN(G): camouflage domain name; Qv2ray: TLS setting-server address; Shadowrocket: Peer name)"
        tyblue "allowInsecure: false"
        purple "(Qv2ray: Allow insecure certificates (not tick); Shadowrocket: Allow insecure (closed))"
        tyblue "------------------------other----------------------- "
        tyblue "Mux (Multiplex): It is recommended to close"
        tyblue "Sniffing for socks inbound (traffic detection): It is recommended to enable"
        purple "(Qv2ray: Preferences-Inbound Settings-SOCKS Settings-Sniffing)"
        tyblue "------------------------------------------------ ------------------------"
    fi
    echo
    ask_if "Do you want to generate a share link? (y/n)" && print_share_link
    echo
    green "Currently supports graphical clients that support XTLS:"
    green "Windows: Qv2ray v2.7.0-pre1+ V2RayN v3.26+"
    green "Android ：V2RayNG v1.4.8+"
    green "Linux/MacOS: Qv2ray v2.7.0-pre1+"
    green "IOS ：Shadowrocket v2.1.67+"
    echo
    yellow "If you use VMess, please update the client to Xray or V2Ray v4.28.0+ as soon as possible to enable VMessAEAD"
    yellow "If you use VLESS, please make sure the client is Xray or V2Ray v4.30.0+"
    yellow "If you use XTLS, please make sure the client is Xray or V2Ray v4.31.0 to v4.32.1"
    yellow "If you use xtls-rprx-splice, please make sure the client is Xray v1.1.0+"
    echo
    tyblue "script Last updated: 2020.01.18"
    echo
    red "This script is for communication and learning purposes only, please do not use this script to commit illegal things. If you commit illegal things outside the illegal network, you will be subject to legal sanctions!!!!"
    tyblue "2020.11" 
}

install_update_xray_tls_web()
{
    check_nginx_installed_system
    check_SELinux
    check_important_dependence_installed net-tools net-tools
    check_port
    check_important_dependence_installed lsb-release redhat-lsb-core
    get_system_info
    check_important_dependence_installed ca-certificates ca-certificates
    check_important_dependence_installed wget wget
    check_ssh_timeout
    uninstall_firewall
    doupdate
    enter_temp_dir
    install_bbr
    $debian_package_manager -y -f install

#Read information
    if [$update -eq 0 ]; then
        readProtocolConfig
        readDomain
        path="/$(head -c 8 /dev/urandom | md5sum | head -c 7)"
        xid_1="$(cat /proc/sys/kernel/random/uuid)"
        xid_2="$(cat /proc/sys/kernel/random/uuid)"
    else
        get_config_info
    fi

    local choice

    local install_php
    if [$update -eq 0 ]; then
        ["${pretend_list[0]}" == "2"] && install_php=1 || install_php=0
    else
        install_php=$php_is_installed
    fi
    local use_existed_php=0
    if [$install_php -eq 1 ]; then
        if [$update -eq 1 ]; then
            if check_php_update; then
                ! ask_if "A new version of PHP is detected, do you want to update? (y/n)" && use_existed_php=1
            else
                green "php is already the latest version, do not update"
                use_existed_php=1
            fi
        elif [$php_is_installed -eq 1 ]; then
            tyblue "---------------Detected that php already exists--------------"
            tyblue "1. Use existing php"
            tyblue "2. Uninstall existing php and recompile and install"
            echo
            choice=""
            while ["$choice" != "1"] && ["$choice" != "2"]
            do
                read -p "Your choice is:" choice
            done
            [$choice -eq 1] && use_existed_php=1
        fi
    fi

    local use_existed_nginx=0
    if [$update -eq 1 ]; then
        if check_nginx_update; then
            ! ask_if "A new version of Nginx is detected, do you want to update it? (y/n)" && use_existed_nginx=1
        else
            green "Nginx is already the latest version, do not update"
            use_existed_nginx=1
        fi
    elif [$nginx_is_installed -eq 1 ]; then
        tyblue "---------------Nginx detected already exists---------------"
        tyblue "1. Use existing Nginx"
        tyblue "2. Uninstall the existing Nginx and recompile and install"
        echo
        choice=""
        while ["$choice" != "1"] && ["$choice" != "2"]
        do
            read -p "Your choice is:" choice
        done
        [$choice -eq 1] && use_existed_nginx=1
    fi
    #This parameter is only valid when [$update -eq 0]
    local temp_remove_cloudreve=1
    if [$update -eq 0] && ["${pretend_list[0]}" == "1"] && [$cloudreve_is_installed -eq 1 ]; then
        tyblue "----------------- Cloudreve already exists -----------------"
        tyblue "1. Use existing Cloudreve"
        tyblue "2. Uninstall and reinstall"
        echo
        red "Warning: Uninstalling Cloudreve will delete all files and user information in the network disk"
        choice=""
        while ["$choice" != "1"] && ["$choice" != "2"]
        do
            read -p "Your choice is:" choice
        done
        [$choice -eq 1] && temp_remove_cloudreve=0
    fi

    green "Installing dependencies..."
    install_base_dependence
    install_nginx_dependence
    [$install_php -eq 1] && install_php_dependence
    $debian_package_manager clean
    $redhat_package_manager clean all

    #Compile &&install php
    if [$install_php -eq 1 ]; then
        if [$use_existed_php -eq 0 ]; then
            compile_php
            remove_php
            install_php_part1
        else
            systemctl --now disable php-fpm
        fi
        install_php_part2
        [$update -eq 1] && turn_on_off_php
    fi

    #Compile&&Install Nginx
    if [$use_existed_nginx -eq 0 ]; then
        compile_nginx
        [$update -eq 1] && backup_domains_web
        remove_nginx
        install_nginx_part1
    else
        systemctl --now disable nginx
        rm -rf ${nginx_prefix}/conf.d
        rm -rf ${nginx_prefix}/certs
        rm -rf ${nginx_prefix}/html/issue_certs
        rm -rf ${nginx_prefix}/conf/issue_certs.conf
        cp ${nginx_prefix}/conf/nginx.conf.default ${nginx_prefix}/conf/nginx.conf
    fi
    install_nginx_part2
    [$update -eq 1] && [$use_existed_nginx -eq 0] && mv "${temp_dir}/domain_backup/"* ${nginx_prefix}/html 2>/dev/null

    #Install Xray
    remove_xray
    install_update_xray

    green "Getting a certificate..."
    if [$update -eq 0 ]; then
        [-e $HOME/.acme.sh/acme.sh] && $HOME/.acme.sh/acme.sh --uninstall
        rm -rf $HOME/.acme.sh
        curl https://get.acme.sh | sh
    fi
    $HOME/.acme.sh/acme.sh --upgrade --auto-upgrade
    get_all_certs

    #Configure Nginx and Xray
    config_nginx
    config_xray
    [$update -eq 0] && init_all_webs
    sleep 2s
    systemctl restart xray nginx
    if [$update -eq 0 ]; then
        if ["${pretend_list[0]}" == "2" ]; then
            systemctl --now enable php-fpm
            let_init_nextcloud "0"
        else
            systemctl --now disable php-fpm
        fi
        if ["${pretend_list[0]}" == "1" ]; then
            if [$temp_remove_cloudreve -eq 1 ]; then
                install_init_cloudreve "0"
            else
                systemctl --now enable cloudreve
                update_cloudreve
                let_change_cloudreve_domain "0"
            fi
        else
            systemctl --now disable cloudreve
        fi
        green "-------------------installation complete-------------------"
        print_config_info
    else
        [$cloudreve_is_installed -eq 1] && update_cloudreve
        turn_on_off_cloudreve
        green "-------------------Update complete-------------------"
    fi
    cd /
    rm -rf "$temp_dir"
} 

#Functional function
check_script_update()
{
    if [[ -z "${BASH_SOURCE[0]}" ]]; then
        red "Script is not a file, cannot check for updates"
        exit 1
    fi
    ["$(md5sum "${BASH_SOURCE[0]}" | awk'{print $1}')" == "$(md5sum <(wget -O-"https://github.com/kirin10000/Xray-script /raw/main/Xray-TLS+Web-setup.sh") | awk'{print $1}')"] && return 1 || return 0
}
update_script()
{
    if [[ -z "${BASH_SOURCE[0]}" ]]; then
        red "The script is not a file and cannot be updated"
        return 1
    fi
    rm -rf "${BASH_SOURCE[0]}"
    if! wget -O "${BASH_SOURCE[0]}" "https://github.com/kirin10000/Xray-script/raw/main/Xray-TLS+Web-setup.sh" &&! wget -O "$ {BASH_SOURCE[0]}" "https://github.com/kirin10000/Xray-script/raw/main/Xray-TLS+Web-setup.sh"; then
        red "Failed to update script!"
        yellow "Press Enter to continue or Ctrl+c to abort"
        read -s
    fi
}
full_install_php()
{
    install_base_dependence
    install_php_dependence
    enter_temp_dir
    compile_php
    remove_php
    install_php_part1
    install_php_part2
    cd /
    rm -rf "$temp_dir"
}
#Install/check for updates/update php
install_check_update_update_php()
{
    check_script_update && red "The script can be upgraded, please update the script first" && return 1
    if [$php_is_installed -eq 1 ]; then
        if check_php_update; then
            green "php has a new version"
            ! ask_if "Update? (y/n)" && return 0
        else
            green "php is the latest version"
            return 0
        fi
    fi
    local php_status=0
    systemctl -q is-active php-fpm && php_status=1
    full_install_php
    turn_on_off_php
    if [$php_status -eq 1 ]; then
        systemctl start php-fpm
    else
        systemctl stop php-fpm
    fi
    green "Update complete!"
}
check_update_update_nginx()
{
check_script_update && red "The script can be upgraded, please update the script first" && return 1
     if check_nginx_update; then
         green "Nginx has a new version"
         ! ask_if "Update? (y/n)" && return 0
     else
         green "Nginx is the latest version"
         return 0
    fi
    local nginx_status=0
    local xray_status=0
    systemctl -q is-active nginx && nginx_status=1
    systemctl -q is-active xray && xray_status=1
    install_base_dependence
    install_nginx_dependence
    enter_temp_dir
    compile_nginx
    backup_domains_web
    remove_nginx
    install_nginx_part1
    install_nginx_part2
    config_nginx
    mv "${temp_dir}/domain_backup/"* ${nginx_prefix}/html 2>/dev/null
    get_all_certs
    if [ $nginx_status -eq 1 ]; then
        systemctl restart nginx
    else
        systemctl stop nginx
    fi
    if [ $xray_status -eq 1 ]; then
        systemctl restart xray
    else
        systemctl stop xray
    fi
    cd /
    rm -rf "$temp_dir"
green "Update complete!"
}
full_install_init_cloudreve()
{
    enter_temp_dir
    install_init_cloudreve "$1"
    cd /
    rm -rf "$temp_dir"
}
reinit_domain()
{
yellow "Resetting the domain name will delete all existing domain names (including domain name certificates, fake websites, etc.)"
     ! ask_if "Do you want to continue? (y/n)" && return 0
     readDomain
     ["${pretend_list[-1]}" == "2"] && [$php_is_installed -eq 0] && full_install_php
     green "Resetting the domain name..."
    local temp_domain="${domain_list[-1]}"
    local temp_true_domain="${true_domain_list[-1]}"
    local temp_domain_config="${domain_config_list[-1]}"
    local temp_pretend="${pretend_list[-1]}"
    unset 'domain_list[-1]'
    unset 'true_domain_list[-1]'
    unset 'domain_config_list[-1]'
    unset 'pretend_list[-1]'
    remove_all_domains
    domain_list+=("$temp_domain")
    domain_config_list+=("$temp_domain_config")
    true_domain_list+=("$temp_true_domain")
    pretend_list+=("$temp_pretend")
    get_all_certs
    config_nginx
    config_xray
    init_all_webs
    sleep 2s
    systemctl restart xray nginx
    if [ "${pretend_list[0]}" == "2" ]; then
        systemctl --now enable php-fpm
        let_init_nextcloud "0"
    elif [ "${pretend_list[0]}" == "1" ]; then
        if [ $cloudreve_is_installed -eq 0 ]; then
            full_install_init_cloudreve "0"
        else
            systemctl --now enable cloudreve
            let_change_cloudreve_domain "0"
        fi
    fi
green "Domain reset complete!!"
    print_config_info
}
add_domain()
{
    local need_cloudreve=0
    check_need_cloudreve && need_cloudreve=1
    readDomain
    if ["${pretend_list[-1]}" == "1"] && [$need_cloudreve -eq 1 ]; then
        yellow "Cloudreve can only be used for one domain name!!!"
        tyblue "Nextcloud can be used for multiple domains"
        return 1
    fi
    ["${pretend_list[-1]}" == "2"] && [$php_is_installed -eq 0] && full_install_php
    if! get_cert "-1"; then
        sleep 2s
        systemctl restart xray nginx
        red "Failed to apply for certificate!!!"
        red "Failed to add domain name"
        return 1
    fi
    init_web "-1"
    config_nginx
    config_xray
    sleep 2s
    systemctl restart xray nginx
    turn_on_off_php
    ["${pretend_list[-1]}" == "2"] && let_init_nextcloud "-1"
    if ["${pretend_list[-1]}" == "1" ]; then
        if [$cloudreve_is_installed -eq 0 ]; then
            full_install_init_cloudreve "-1"
        else
            systemctl --now enable cloudreve
            let_change_cloudreve_domain "-1"
        fi
    fi
    green "The domain name is added!!"
    print_config_info
}
delete_domain()
{
    if [${#domain_list[@]} -le 1 ]; then
        red "Only one domain name"
        return 1
    fi
    local i
    tyblue "-----------------------Please select the domain name to be deleted------------------- ----"
    for i in ${!domain_list[@]}
    do
        if [${domain_config_list[$i]} -eq 1 ]; then
            tyblue "$((i+1)). ${domain_list[$i]} ${true_domain_list[$i]}"
        else
            tyblue "$((i+1)). ${domain_list[$i]}"
        fi
    done
    yellow "0. Do not delete"
    local delete=""
    while! [[ "$delete" =~ ^([1-9][0-9]*|0)$ ]] || [$delete -gt ${#domain_list[@]}]
    do
        read -p "Your choice is:" delete
    done
    [ $delete -eq 0 ] && return 0
    ((delete--))
    $HOME/.acme.sh/acme.sh --remove --domain ${true_domain_list[$delete]} --ecc
    rm -rf $HOME/.acme.sh/${true_domain_list[$delete]}_ecc
    rm -rf "${nginx_prefix}/certs/${true_domain_list[$delete]}.key" "${nginx_prefix}/certs/${true_domain_list[$delete]}.cer"
    rm -rf ${nginx_prefix}/html/${true_domain_list[$delete]}
    unset 'domain_list[$delete]'
    unset 'true_domain_list[$delete]'
    unset 'domain_config_list[$delete]'
    unset 'pretend_list[$delete]'
    domain_list=("${domain_list[@]}")
    true_domain_list=("${true_domain_list[@]}")
    domain_config_list=("${domain_config_list[@]}")
    pretend_list=("${pretend_list[@]}")
    config_nginx
    config_xray
    systemctl restart xray nginx
    turn_on_off_php
    turn_on_off_cloudreve
green "Domain deletion is complete!!"
    print_config_info
}
reinit_cloudreve()
{
    ! check_need_cloudreve && red "Cloudreve does not currently bind a domain name" && return 1
    red "Resetting Cloudreve will delete all Cloudreve network disk files and account information, which is equivalent to reinstalling"
    tyblue "Forgot the administrator password, you can use this option to recover"
    ! ask_if "Are you sure you want to continue? (y/n)" && return 0
    local i
    for i in ${!pretend_list[@]}
    do
        ["${pretend_list[$i]}" == "1"] && break
    done
    systemctl stop cloudreve
    sleep 1s
    shopt -s extglob
    temp="rm -rf $cloudreve_prefix/!(cloudreve|conf.ini)"
    $temp
    init_cloudreve "$i"
    green "Reset complete!"
}
change_pretend()
{
    local change=""
    if [${#domain_list[@]} -eq 1 ]; then
        change=0
    else
        local i
        tyblue "-----------------------Please select the domain name to modify the disguise type----------------- ------"
        for i in ${!domain_list[@]}
        do
            if [${domain_config_list[$i]} -eq 1 ]; then
                tyblue "$((i+1)). ${domain_list[$i]} ${true_domain_list[$i]}"
            else
                tyblue "$((i+1)). ${domain_list[$i]}"
            fi
        done
        yellow "0. Do not modify"
        while! [[ "$change" =~ ^([1-9][0-9]*|0)$ ]] || [$change -gt ${#domain_list[@]}]
        do
            read -p "Your choice is:" change
        done
        [$change -eq 0] && return 0
        ((change--))
    fi
    local pretend
    readPretend
    if ["${pretend_list[$change]}" == "$pretend" ]; then
        yellow "The disguise type has not changed"
        return 1
    fi
    local need_cloudreve=0
    check_need_cloudreve && need_cloudreve=1
    pretend_list[$change]="$pretend"
    if ["$pretend" == "1"] && [$need_cloudreve -eq 1 ]; then
        yellow "Cloudreve can only be used for one domain name!!!"
        tyblue "Nextcloud can be used for multiple domains"
        return 1
    fi
    [ "$pretend" == "2" ] && [ $php_is_installed -eq 0 ] && full_install_php
    init_web "$change"
    config_nginx
    systemctl restart nginx
    turn_on_off_php
    [ "$pretend" == "2" ] && let_init_nextcloud "$change"
    if [ "$pretend" == "1" ]; then
        if [ $cloudreve_is_installed -eq 0 ]; then
            full_install_init_cloudreve "$change"
        else
            systemctl --now enable cloudreve
            let_change_cloudreve_domain "$change"
        fi
    else
        turn_on_off_cloudreve
    fi
green "Modification is complete!"
}
change_xray_id()
{
    local flag=""
    if [$protocol_1 -ne 0] && [$protocol_2 -ne 0 ]; then
        tyblue "-------------Please enter the id you want to modify-------------"
        tyblue "1. Xray-TCP+XTLS id"
        tyblue "2. Xray-WebSocket+TLS id"
        echo
        while ["$flag" != "1"] && ["$flag" != "2"]
        do
            read -p "Your choice is:" flag
        done
    elif [$protocol_1 -ne 0 ]; then
        flag=1
    else
        flag=2
    fi
    local xid="xid_$flag"
    tyblue "Your current id is: ${!xid}"
    ! ask_if "Do you want to continue? (y/n)" && return 0
    xid=""
    while [-z "$xid"]
    do
        tyblue "-------------Please enter a new id-------------"
        read xid
    done
    [$flag -eq 1] && xid_1="$xid" || xid_2="$xid"
    config_xray
    systemctl -q is-active xray && systemctl restart xray
    green "Successful replacement!!!"
    print_config_info
}
change_xray_path()
{
    if [$protocol_2 -eq 0 ]; then
        red "Xray-TCP+XTLS+Web mode has no path!!"
        return 1
    fi
    tyblue "Your current path is: $path"
    ! ask_if "Do you want to continue? (y/n)" && return 0
    path=""
    while [-z "$path"]
    do
        tyblue "---------------Please enter a new path (with \"/\")---------------"
        read path
    done
    config_xray
    systemctl -q is-active xray && systemctl restart xray
    green "Successful replacement!!!"
    print_config_info
}
change_xray_protocol()
{
    local protocol_1_old=$protocol_1
    local protocol_2_old=$protocol_2
    readProtocolConfig
    if [$protocol_1_old -eq $protocol_1] && [$protocol_2_old -eq $protocol_2 ]; then
        red "Transmission protocol has not been changed"
        return 1
    fi
    [$protocol_1_old -eq 0] && [$protocol_1 -ne 0] && xid_1=$(cat /proc/sys/kernel/random/uuid)
    if [$protocol_2_old -eq 0] && [$protocol_2 -ne 0 ]; then
        path="/$(head -c 8 /dev/urandom | md5sum | head -c 7)"
        xid_2=$(cat /proc/sys/kernel/random/uuid)
    fi
    config_xray
    systemctl -q is-active xray && systemctl restart xray
    green "Successful replacement!!!"
    print_config_info
}
simplify_system()
{
    if systemctl -q is-active xray || systemctl -q is-active nginx || systemctl -q is-active php-fpm; then
        yellow "Please stop Xray-TLS+Web first"
        return 1
    fi
    yellow "Warning: If there are other programs running on the server, they may be deleted by mistake"
    tyblue "It is recommended to use this function in a pure system"
    ! ask_if "Do you want to continue? (y/n)" && return 0
    if [$release == "centos"] || [$release == "fedora"] || [$release == "other-redhat" ]; then
        $redhat_package_manager -y remove openssl "perl*"
    else
        local temp_remove_list=('openssl' 'snapd' 'kdump-tools' 'flex' 'make' 'automake' '^cloud-init' 'pkg-config' '^gcc-[1-9][0-9]*$' 'libffi-dev' '^cpp-[1-9][0-9]*$' 'curl' '^python' '^libpython' 'dbus' 'cron' 'at' 'open-iscsi' 'rsyslog' 'anacron' 'acpid')
        if ! $debian_package_manager -y --autoremove purge "${temp_remove_list[@]}"; then
            $debian_package_manager -y -f install
            for i in ${!temp_remove_list[@]}
            do
                $debian_package_manager -y --autoremove purge "${temp_remove_list[$i]}"
            done
            $debian_package_manager -y -f install
        fi
        [ $release == "ubuntu" ] && check_important_dependence_installed netplan.io
    fi
    check_important_dependence_installed openssh-server openssh-server
    [ $nginx_is_installed -eq 1 ] && install_nginx_dependence
    [ $php_is_installed -eq 1 ] && install_php_dependence
    [ $is_installed -eq 1 ] && install_base_dependence
green "Complete streamlined"
}
repair_tuige()
{
    yellow "Try to fix the backspace key abnormal problem, please don't fix the backspace key normal"
    ! ask_if "Do you want to continue? (y/n)" && return 0
    if stty -a | grep -q'erase = ^?'; then
        stty erase'^H'
    elif stty -a | grep -q'erase = ^H'; then
        stty erase'^?'
    fi
    green "Repair complete!!"
}
change_dns()
{
    red "Attention!!"
    red "1. Some cloud service providers (such as Alibaba Cloud) use a local server as the source of the package, and need to change the source after modifying the dns!!!"
    red "If you don't understand, please modify the dns after the installation is complete, and do not reinstall after the modification"
    red "2. The original dns may be restored after the Ubuntu system restarts"
    tyblue "This operation will modify the dns server to 1.1.1.1 and 1.0.0.1 (cloudflare public dns)"
    ! ask_if "Do you want to continue? (y/n)" && return 0
    if! grep -q "#This file has been edited by Xray-TLS-Web-setup-script" /etc/resolv.conf; then
        sed -i's/^[ \t]*nameserver[ \t][ \t]*/#&/' /etc/resolv.conf
        {
            echo
            echo'nameserver 1.1.1.1'
            echo'nameserver 1.0.0.1'
            echo'#This file has been edited by Xray-TLS-Web-setup-script'
        } >> /etc/resolv.conf
    fi
    green "Modification is complete!!!"
}
#Start Menu
start_menu()
{
local xray_status
    [$xray_is_installed -eq 1] && xray_status="\\033[32m installed" || xray_status="\\033[31m not installed"
    systemctl -q is-active xray && xray_status+=" \\033[32m is running" || xray_status+=" \\033[31m is not running"
    local nginx_status
    [$nginx_is_installed -eq 1] && nginx_status="\\033[32m installed" || nginx_status="\\033[31m not installed"
    systemctl -q is-active nginx && nginx_status+=" \\033[32m is running" || nginx_status+=" \\033[31m is not running"
    local php_status
    [$php_is_installed -eq 1] && php_status="\\033[32m installed" || php_status="\\033[31m not installed"
    systemctl -q is-active php-fpm && php_status+=" \\033[32m is running" || php_status+=" \\033[31m is not running"
    local cloudreve_status
    [$cloudreve_is_installed -eq 1] && cloudreve_status="\\033[32m installed" || cloudreve_status="\\033[31m not installed"
    systemctl -q is-active cloudreve && cloudreve_status+=" \\033[32m is running" || cloudreve_status+=" \\033[31m is not running"
    tyblue "---------------------- Xray-TLS(1.3)+Web build/management script-------------- -------"
    echo
    tyblue "Xray: ${xray_status}"
    echo
    tyblue "Nginx: ${nginx_status}"
    echo
    tyblue "php: ${php_status}"
    echo
    tyblue "Cloudreve: ${cloudreve_status}"
    echo
    tyblue "Official website: https://github.com/kirin10000/Xray-script"
    echo
    tyblue "----------------------------------Notes------------ ----------------------"
    yellow "1. This script needs a domain name that resolves to this server"
    tyblue "2. This script takes a long time to install. For detailed reasons, see:"
    tyblue "https://github.com/kirin10000/Xray-script#Installation time description"
    green "3. It is recommended to use a pure system (VPS console-reset system)"
    green "4. The latest version of Ubuntu is recommended"
    tyblue "------------------------------------------------ ----------------------------"
    echo
    echo
    tyblue "-----------install/update/uninstall-----------"
    if [ $is_installed -eq 0 ]; then
    green "1. Install Xray-TLS+Web"
    else
        green "1. Reinstall Xray-TLS+Web"
    fi
    purple "Process: [Update system components]->[install bbr]->[install php]->install Nginx->install Xray->apply for certificate->configuration file->[install/configure Cloudreve]"
    green "2. Update Xray-TLS+Web"
    purple "Process: update script->[update system components]->[update bbr]->[update php]->[update Nginx]->update Xray->update certificate->update configuration file->[update Cloudreve] "
    tyblue "3. Check for updates/update scripts"
    tyblue "4. Update system components"
    tyblue "5. Install/check for updates/update bbr"
    purple "includes: bbr2/bbrplus/bbr magic revision/violent bbr magic revision/sharp speed"
    tyblue "6. Install/check for updates/update php"
    tyblue "7. Check for updates/update Nginx"
    tyblue "8. Update Cloudreve"
    tyblue "9. Update Xray"
    red "10. Uninstall Xray-TLS+Web"
    red "11. Uninstall php"
    red "12. Uninstall Cloudreve"
    echo
    tyblue "--------------start/stop-------------"
    tyblue "13. Start/Restart Xray-TLS+Web"
    tyblue "14. Stop Xray-TLS+Web"
    echo
    tyblue "----------------Management----------------"
    tyblue "15. View configuration information"
    tyblue "16. Reset domain name"
    purple "will delete all domain name configuration, the domain name was entered incorrectly during the installation process, causing Xray to fail to start, you can use this option to fix"
    tyblue "17. Add domain name"
    tyblue "18. Delete domain name"
    tyblue "19. Modify the type of fake website"
    tyblue "20. Reinitialize Cloudreve"
    purple "All files and account information of Cloudreve will be deleted. If the administrator password is forgotten, use this option to recover"
    tyblue "21. Modify id (user ID/UUID)"
    tyblue "22. Modify path (path)"
    tyblue "23. Modify Xray transmission protocol (TCP/WebSocket)"
    echo
    tyblue "----------------Other----------------"
    tyblue "24. Streamline the system"
    purple "Remove unnecessary system components"
    tyblue "25. Try to fix the problem that the backspace key cannot be used"
    purple "Some ssh tools (such as Xshell) may have such problems"
    tyblue "26. Modify dns"
    yellow "0. Exit script"
    echo
    echo
    local choice=""
    while [[ ! "$choice" =~ ^(0|[1-9][0-9]*)$ ]] || ((choice>26))
    do
        read -p "Your choice is:" choice
    done
    if (( choice==2 || (7<=choice&&choice<=9) || choice==13 || (15<=choice&&choice<=23) )) && [ $is_installed -eq 0 ]; then
        red "Please install Xray-TLS+Web first!!!"
        return 1
    fi
    if (( 16<=choice&&choice<=20 )) && ! (systemctl -q is-active nginx && systemctl -q is-active xray); then
        red "Please start Xray-TLS+Web first!!!"
        return 1
    fi
    (( 4<=choice&&choice<=6 || choice==24 )) && check_important_dependence_installed lsb-release redhat-lsb-core
    if (( choice==3 || choice==5 || choice==6 || choice==10 )); then
        check_important_dependence_installed ca-certificates ca-certificates
        if [ $choice -eq 10 ]; then
            check_important_dependence_installed curl curl
        else
            check_important_dependence_installed wget wget
        fi
    fi
    (( (4<=choice&&choice<=7) || choice==16 || choice==17 || choice==19 || choice==24 )) && get_system_info
    (( choice==6 || choice==7 || (11<=choice&&choice<=13) || (15<=choice&&choice<=23) )) && get_config_info
    if [ $choice -eq 1 ]; then
        install_update_xray_tls_web
    elif [ $choice -eq 2 ]; then
        update_script && bash "${BASH_SOURCE[0]}" --update
    elif [ $choice -eq 3 ]; then
        if check_script_update; then
            green "The script can be upgraded!"
            ask_if "Do you want to upgrade the script? (y/n)" && update_script && green "Script update completed"
        else
            green "The script is already the latest version"
        fi
    elif [ $choice -eq 4 ]; then
        doupdate
    elif [ $choice -eq 5 ]; then
        enter_temp_dir
        install_bbr
        $debian_package_manager -y -f install
        rm -rf "$temp_dir"
    elif [ $choice -eq 6 ]; then
        install_check_update_update_php
    elif [ $choice -eq 7 ]; then
        check_update_update_nginx
    elif [ $choice -eq 8 ]; then
        if [ $cloudreve_is_installed -eq 0 ]; then
            red   "Please install Cloudreve first!"
            tyblue "Select Cloudreve in Modify Disguise Website Type/Reset Domain Name/Add Domain Name"
            return 1
        fi
        update_cloudreve
        green "Cloudreve update complete!"
    elif [ $choice -eq 9 ]; then
        install_update_xray
        green "Xray update complete!"
    elif [ $choice -eq 10 ]; then
        ! ask_if "Are you sure you want to delete? (y/n)" && return 0
        remove_xray
        remove_nginx
        remove_php
        remove_cloudreve
        $HOME/.acme.sh/acme.sh --uninstall
        rm -rf $HOME/.acme.sh
        green "Deletion complete!"
    elif [ $choice -eq 11 ]; then
        [ $is_installed -eq 1 ] && check_need_php && red "A domain name is using php" && return 1
        ! ask_if "Are you sure you want to delete php? (y/n)" && return 0
        remove_php && green "Deletion complete!"
    elif [ $choice -eq 12 ]; then
        [ $is_installed -eq 1 ] && check_need_cloudreve && red "A domain is using Cloudreve" && return 1
        ! ask_if "Are you sure you want to delete cloudreve? (y/n)" && return 0
        remove_cloudreve && green "Deletion complete!"
    elif [ $choice -eq 13 ]; then
        systemctl restart xray nginx
        turn_on_off_php
        turn_on_off_cloudreve
        sleep 1s
        if ! systemctl -q is-active xray; then
            red "Xray failed to start!!"
        elif ! systemctl -q is-active nginx; then
            red "Nginx failed to start!!"
        elif check_need_php && ! systemctl -q is-active php-fpm; then
            red "php failed to start!!!"
        elif check_need_cloudreve && ! systemctl -q is-active cloudreve; then
            red "Cloudreve failed to start!!"
        else
            green "Restart/start successfully!!!"
        fi
    elif [ $choice -eq 14 ]; then
        systemctl stop xray nginx
        [ $php_is_installed -eq 1 ] && systemctl stop php-fpm
        [ $cloudreve_is_installed -eq 1 ] && systemctl stop cloudreve
        green "stopped!"
    elif [ $choice -eq 15 ]; then
        print_config_info
    elif [ $choice -eq 16 ]; then
        reinit_domain
    elif [ $choice -eq 17 ]; then
        add_domain
    elif [ $choice -eq 18 ]; then
        delete_domain
    elif [ $choice -eq 19 ]; then
        change_pretend
    elif [ $choice -eq 20 ]; then
        reinit_cloudreve
    elif [ $choice -eq 21 ]; then
        change_xray_id
    elif [ $choice -eq 22 ]; then
        change_xray_path
    elif [ $choice -eq 23 ]; then
        change_xray_protocol
    elif [ $choice -eq 24 ]; then
        simplify_system
    elif [ $choice -eq 25 ]; then
        repair_tuige
    elif [ $choice -eq 26 ]; then
        change_dns
    fi
}

if [ "$1" == "--update" ]; then
    update=1
    install_update_xray_tls_web
else
    update=0
    start_menu
fi
