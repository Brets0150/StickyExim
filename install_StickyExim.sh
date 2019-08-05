#!/usr/bin/env bash
## Author: Bret.S
## Creation: 06/27/19
## Last Update: 07/17/19
## Built For Debian 9 OS
## Purpose: Install the Exim service that is vulnerable, patch it while maintaining the version number, log and report attackers.
## Usage: ./install_StickyExim.sh "<DomainNameUsedForHoneyPot>" "<ExternalEmailAddressToSendTestEmailTo>"
##
## Notes: This was built for Debain 9.
##
## Change Log:
##           - 6/24/19 -  Main code done. Version 1.0 done and working.
##           - 8/5/19  -  Hostname update bug, fixed.
##
##
## START Declare Variables ##
#
# Set the domain name for the server.
str_this_scripts_name="${0}"
str_hp_domain_name="${1}"
str_testing_email_to_send_to="${2}"
str_starting_hostname="$(hostname)"
str_full_domain_name="${str_starting_hostname}.${str_hp_domain_name}"
str_scripts_current_working_dir="${PWD}/"
str_honey_harvester_script_name="honey_harvester_exim_cve-2019-10149.sh"
str_script_arguments="<DomainNameUsedForHoneyPot> <ExternalEmailAddressToSendTestEmailTo>"
str_script_arguments_example='"definitelynotahoneypot.com" "me@myreal-email.com"'
str_exim_config_dir="/etc/exim4/"
str_exim_config_file_and_location="${str_exim_config_dir}exim4.conf"
str_cert_state="Washington"
str_cert_country_2letter_code="US"
str_exim_log_dir="/var/log/exim4"
str_exim_main_log_file="${str_exim_log_dir}/mainlog"
str_exim_reject_log_file="${str_exim_log_dir}/rejectlog"
str_packages_to_install='whois wget coreutils apt-utils git net-tools apt-transport-https ca-certificates curl software-properties-common gnupg2 apt-utils openssl'
#
## END Declare Variables ##
##
## Start of Functions Code ##
##

function fun_check_data_passed() {
    # Get data given to this function
    declare str_data_to_check="${1}"

    # Check if the variable is empty. If yes, stop script.
    if [ -z ${str_data_to_check} ]; then
        echo "Not all data given..."
        echo "Command Line Usage: ${str_this_scripts_name} ${str_script_arguments}"
        echo "Command Line Usage: ${str_this_scripts_name} ${str_script_arguments_example}"
        exit 1
    fi
}

function fun_send_test_email() {
    # Get email address given to this function
    declare str_who_to_send_email_to="${1}"
    declare str_exim_main_log_file="${2}"

    # Send test message with servers details.
    /usr/sbin/exim4 ${str_who_to_send_email_to} <<EOF
From: "Test Email Setup" <script_test@$(hostname -d)>
To: "StickyExim Admin" <${str_who_to_send_email_to}>
Reply-To: script_test@$(hostname -d)
Subject: Test on $(date)
Content-Type: text/plain; charset=utf-8

Hello,
  Checking in from IP: $(hostname -I), FQDN: $(hostname -f)
EOF
    # Confirm the email send successfully.
    sleep 5
    exigrep "${str_who_to_send_email_to}" "${str_exim_main_log_file}"
}

function fun_add_to_config_after_string_match() {
    # Get Data Passed to function
    local str_file_name_and_path="${1}"
    local str_line_to_match="${2}"
    local str_new_line_to_add_after_match="${3}"

    # Get the current line the number of the line we want to replace.
    declare -i int_current_line_number=0
    int_current_line_number=$(cat "${str_file_name_and_path}"|grep -n "${str_line_to_match}"|head -n1|cut -f 1 -d :)

    # Confirm line number not empty or less than 1.
    if [[ ${int_current_line_number} < 1 ]] || [[ ${int_current_line_number} == "" ]]; then
        # Existing line not found in config file. Trying to add it to the end of the file. (50/50 if it works. lol)
        echo "Error: Config Line to replace not found. Not Found: ${str_line_to_match}."
        exit 1
    else
        # Old line to replace was found. Change the old line out with the new one.
        head -n${int_current_line_number} "${str_file_name_and_path}" > "${str_file_name_and_path}.tmp"
        echo "${str_new_line_to_add_after_match}" >> "${str_file_name_and_path}.tmp"
        tail -n +$(expr ${int_current_line_number} + 1) "${str_file_name_and_path}" >> "${str_file_name_and_path}.tmp"
    fi

    # Replace the current file with the new file built.
    mv "${str_file_name_and_path}.tmp" "${str_file_name_and_path}"
}

#
##
## END Functions Code ##
##
# START Test to check for all needed Data ##
##

# Confirm all data needed was passed from the command line(or where ever).
fun_check_data_passed ${str_hp_domain_name}
fun_check_data_passed ${str_testing_email_to_send_to}

#
##
# END Test to check for all needed Data ##
##
## Start of Code ##
##
#

# Update the systems file to match the domain name and IPs.
cat /etc/hosts | grep -v "${str_starting_hostname}" >/etc/hosts
echo "$(ip a | grep "inet " | grep -v "127.\|172." | awk -F" " '{print $2}' | awk -F/ '{print $1}') ${str_full_domain_name} ${str_starting_hostname}" >>/etc/hosts
echo "${str_full_domain_name}" > /etc/hostname
hostnamectl set-hostname "${str_full_domain_name}"

# Use OpenDNS Servers.
echo "nameserver 208.67.222.222" > /etc/resolv.conf ; echo "nameserver 208.67.220.220" >> /etc/resolv.conf

# Update and install needed packages
wget -O /etc/apt/trusted.gpg.d/php.gpg https://packages.sury.org/php/apt.gpg
apt-get -y update ; apt-get -y dist-upgrade
apt-get install -y ${str_packages_to_install}
apt-get -y autoremove

# Make SSL Cert
mkdir ${str_exim_config_dir}/ssl -p
openssl req -nodes -x509 -newkey rsa:2048 -keyout ${str_exim_config_dir}/ssl/${str_full_domain_name}.key -out ${str_exim_config_dir}/ssl/${str_full_domain_name}.crt -days 365 -subj "/C=${str_cert_country_2letter_code}/ST=${str_cert_state}/L=${str_cert_state}/O=${str_hp_domain_name}/OU=IT Department/CN=${str_full_domain_name}"


# Check is Exim is already installed. If yes remove it.
if [ ! -z "$(apt list | grep exim4)" ]; then
    apt-get remove --purge -y exim4*
    apt-get -y autoremove
fi

# Download and install the Exim 4.89-2 Version that is vulnerable.
wget http://security-cdn.debian.org/debian-security/pool/updates/main/e/exim4/exim4-config_4.89-2+deb9u4_all.deb -O ./exim-config.deb;
wget http://security-cdn.debian.org/debian-security/pool/updates/main/e/exim4/exim4-base_4.89-2+deb9u4_amd64.deb -O ./exim-base.deb;
wget http://security-cdn.debian.org/debian-security/pool/updates/main/e/exim4/exim4-daemon-heavy_4.89-2+deb9u4_amd64.deb -O ./exim-heavy.deb;
wget http://security-cdn.debian.org/debian-security/pool/updates/main/e/exim4/exim4_4.89-2+deb9u4_all.deb -O ./exim.deb;

# Install the downloaded packages
dpkg --force-all -i ./exim*.deb

# Fix any install issues.
apt-get --fix-broken install -y

# Remove duplicate Exim config files
rm -rf "${str_exim_config_dir}conf.d/*"

# Create a new config file from Template file.
cat "${str_exim_config_dir}exim4.conf.template" > "${str_exim_config_file_and_location}"

# Remove all comment and empty lines from the file.
#str_exim_config_file="$(cat "${str_exim_config_file_and_location}" | grep -v "#" | sed '/^$/d')"
#echo "${str_exim_config_file}" > "${str_exim_config_file_and_location}"

# Add configs to Exim conf file

sed -i "s/domainlist local_domains = MAIN_LOCAL_DOMAINS/domainlist local_domains = @ : ${str_hp_domain_name}/g" "${str_exim_config_file_and_location}"
sed -i "s/primary_hostname = MAIN_HARDCODE_PRIMARY_HOSTNAME/primary_hostname = ${str_starting_hostname}.${str_hp_domain_name}/g" "${str_exim_config_file_and_location}"
sed -i "s/qualify_domain = ETC_MAILNAME/qualify_domain = ${str_starting_hostname}.${str_hp_domain_name}/g" "${str_exim_config_file_and_location}"
sed -i "s/# need to be deliverable remotely./DCconfig_internet = ''/g" "${str_exim_config_file_and_location}"
sed -i "s/tls_advertise_hosts = MAIN_TLS_ADVERTISE_HOSTS/tls_advertise_hosts = */g" "${str_exim_config_file_and_location}"
sed -i "s/tls_certificate = MAIN_TLS_CERTIFICATE/tls_certificate = \/etc\/exim4\/ssl\/${str_starting_hostname}.${str_hp_domain_name}.crt/g" "${str_exim_config_file_and_location}"
sed -i "s/tls_privatekey = MAIN_TLS_PRIVATEKEY/tls_privatekey = \/etc\/exim4\/ssl\/${str_starting_hostname}.${str_hp_domain_name}.key/g" "${str_exim_config_file_and_location}"

# declare Config to catch exploit attempts
str_exim_exploit_catch_config='
###################################################
#### START - Patch Exim Exploit CVE-2019-10149 ####
###################################################
  deny
    message = Restricted characters in address
    domains = +local_domains
    local_parts = ^[.] : ^.*[@%!/|] : ^.*\N\${run{\N.*}}

  deny
    message = Restricted characters in address
    domains = !+local_domains
    local_parts = ^[./|] : ^.*[@%!] : ^.*/\\.\\./ : ^.*\N\${run{\N.*}}
###################################################
##### END - Patch Exim Exploit CVE-2019-10149 #####
###################################################
'

# Add the config to catch exploit attempts to config file.
fun_add_to_config_after_string_match "${str_exim_config_file_and_location}" 'acl_check_rcpt:' "${str_exim_exploit_catch_config}"

# Turn on TLS.
fun_add_to_config_after_string_match "${str_exim_config_file_and_location}" 'tls_advertise_hosts = *'

# Add the port TLS transport should run on.
fun_add_to_config_after_string_match "${str_exim_config_file_and_location}" 'tls_privatekey = ' 'tls_on_connect_ports = 465'

# Add the port to run Exim on.
fun_add_to_config_after_string_match "${str_exim_config_file_and_location}"\
                                             'listen on all all interfaces?'\
                                             "local_interfaces = <; [$(hostname -I|tr -d ' ')]:465; [$(hostname -I|tr -d ' ')]:587; [$(hostname -I|tr -d ' ')]:25; [$(hostname -I|tr -d ' ')]:2525"

# Turn on TLS support.
fun_add_to_config_after_string_match "${str_exim_config_file_and_location}"\
                                           '# TLS/SSL configuration for exim'\
                                            'MAIN_TLS_ENABLE = ""'

# Set the proper permission.
chmod 0644 "${str_exim_config_file_and_location}"

# Restart Exim to apply new config.
service exim4 stop ; service exim4 start  #  TO DO, confirm that thing works

# Install cronjob to run the Honey_Harvester scripts every 15 minutes.
crontab -l | { cat; echo "*/15 * * * * ${str_scripts_current_working_dir}${str_honey_harvester_script_name}";echo ""; } | crontab -

# Send test email to StickyExim Admin email.
fun_send_test_email "${str_testing_email_to_send_to}" "${str_exim_main_log_file}"

# Add a helpful alias commands to bash.bashrc config
echo "alias clear-exim-mail-q='exim -bp | exiqgrep -i | xargs exim -Mrm'" >> /etc/bash.bashrc
echo "alias ll='ls -lah --color=auto'" >> /etc/bash.bashrc

# Remove Exim install packages
rm -f ./*.deb

echo ""
echo "StickyHoney Install complete. Please check your email for confirmation email at ${str_testing_email_to_send_to}."
echo "Make sure you check the variables in the top of the ${str_honey_harvester_script_name} script and matches your set up."
echo ''
#
##
## END of Code ##
#
exit 0