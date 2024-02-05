#!/bin/bash

### INIT ###
if [[ -e "/home/sailpoint/config.yaml" ]]; then
  # Set global vars whose data come from config.yaml
  ORGNAME=$(grep -oP '(?<=org: ).*' /home/sailpoint/config.yaml)
  ORGNAME="${ORGNAME//$'\r'/}" #remove return characters
  PODNAME=$(grep -oP '(?<=pod: ).*' /home/sailpoint/config.yaml)
  PODNAME="${PODNAME//$'\r'/}" #remove return characters
else
  echo "*** Config file not found. Please install config.yaml or ensure ***"
  echo "*** this is run only on a SailPoint VA.                         ***"
  echo "*** Execution stopped; no log file created or changes made.     ***"
  exit 1
fi


### GLOBAL VARIABLES ###
VERSION="v2.1"
DATE=$(date -u +"%b_%d_%y-%H_%M")
DIVIDER="================================================================================"
IPADDR=$(networkctl status | grep Address | sed 's/Address: //' | grep -E -o '[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}')
LOGFILE=/home/sailpoint/stuntlog-$ORGNAME-$IPADDR.txt
ZIPFILE=/home/sailpoint/logs.$ORGNAME-$PODNAME-$(hostname)-$IPADDR-$DATE.zip # POD-ORG-CLUSTER_ID-VA_ID.zip 
LISTOFLOGS="/home/sailpoint/log/*.log"
RUNNING_FLATCAR_VERSION="$(cat /etc/os-release | grep -oP 'VERSION=\K[^<]*')"
FLATCAR_RELEASES_URL="https://www.flatcar.org/releases"
FLATCAR_CURRENT_VER=''
is_canal_enabled_bool=false # Assume canal disabled until proven otherwise
CERT_DIRECTORY="/home/sailpoint/certificates"
ADD_REBOOT_MESSAGE=false # Assume we don't require a reboot

# colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
REDBOLDUL='\033[31;1;4m'
RESETCOLOR='\033[0m'

# for test pass/warn/fail and summary
total_tests=0
passes=0
failures=0
warnings=0
declare -A test_categories
summary=""
output_document_summary="$summary"

# for error handling
error_message=""

# for curl test
total_seconds_to_test=180
seconds_between_tests=4

### FUNCTIONS ###

help () {
  # Display help
  echo "Stunt version: $VERSION"
  echo "The stunt script collects information about the current state of your"
  echo "VA, and places that data into a stuntlog text file in your home directory."
  echo "Collecting this helps SailPoint Support Engineers troubleshoot your system."
  echo
  echo "Syntax: ./stunt.sh [-h] [-t,p,o,f,l|L|u|c|r]"
  echo "Options:"
  echo "h   Print this help info then exit"
  echo "t   Add traceroute test to SQS"
  echo "p   Add ping test"
  echo "o   Add openssl cert test"
  echo "f   Add automatic fixup steps"
  echo "l/L Add collection of log files and archive them along with stuntlog file."
  echo "u   Only perform forced update (this will make system changes) then exit"
  echo "c   Only perform a curl test that connects to SQS and S3, one test every four seconds for three minutes then exit"
  echo "r   Only reset your <id>.json file. ***Do not run this flag unless instructed to do so by support***"
}

# Get cmd line args
while getopts ":htpuflLocer" option; do
  case $option in
    h) #display help
      help
      exit;;
    t)
      do_traceroute=true;;
    p)
      do_ping=true;;
    u)
      do_update=true;;
    f)
      do_fixup=true;;
    l)
      gather_logs=true;;
    L)
      gather_logs=true;;
    o)
      check_openssl_cert=true;;
    c)
      curl_test=true;;
    r)
      reset_id_json=true;;
    \?) 
      echo "Invalid argument on command line. Please review help below:"
      help
      exit;;
    esac
done

# args:
# $1 == stdout description
intro() {
  set -f #Disable globbing
  echo "$DIVIDER" >> "$LOGFILE"
  echo "$1"
  echo "$1" >> "$LOGFILE"
  echo "$DIVIDER" >> "$LOGFILE"
  set +f
}

outro() {
  set -f
  echo >> "$LOGFILE"
  echo
  set +f
}

expect() {
  set -f
  echo "********************************************************************************" >> "$LOGFILE"
  echo "*** Expect $1" >> "$LOGFILE"
  echo "********************************************************************************" >> "$LOGFILE"
  set +f
}

endscript() {
  echo "$DIVIDER"
  intro "$(date -u) - END TESTS for $ORGNAME on $PODNAME "
  echo >&2 "*** Tests completed on $(date -u) ***"
  echo "$DIVIDER"
}

get_keyPassphrase_length() {
  cat /home/sailpoint/config.yaml | grep "::::" | sed "s/keyPassphrase: '//g" | sed "s/'$//gm" | wc -m # Will return 0 if unencrypted
}

get_num_jobs() {
  echo $(find "/opt/sailpoint/share/jobs" -maxdepth 1 -type f | wc -l)
}

add_test_result() {
  local category="$1"
  local test_name="$2"
  local test_result="$3"
  local test_output="$4"

  if [[ -z "${test_categories[$category]}" ]]; then
    test_categories["$category"]="$test_name: $test_result -- Test output: $test_output"
  else
    test_categories["$category"]="${test_categories["$category"]},$test_name: $test_result -- Test output: $test_output"
  fi
}

# CS0237804
# example: 
# perform_test test_name test_command pass_comparison_operator pass_expected_condition fail_comparison_operator fail_expected_condition test_category
# e.g.: perform_test "Does 1 = 1?" "if [[ 1 == 1 ]]; then echo true; fi" "==" "true" "==" "false" "<null>" "system"
perform_test() {
  local test_name="$1"
  local test_command="$2"
  local pass_comparison_operator="$3"
  local pass_expected_condition="$4"
  local fail_comparison_operator="$5"
  local fail_expected_condition="$6"
  local test_category="$7"
  
  output=$(eval "$test_command")

  if [ "$pass_comparison_operator" = "==" ] && [ "$output" = "$pass_expected_condition" ]; then
    echo -e "Test - PASS: $test_name" >> "$LOGFILE"
    echo -e "Test -$GREEN PASS$RESETCOLOR: $test_name"
    ((passes++))
    add_test_result "$test_category" "$test_name" "pass" "$output"
  elif [ "$fail_comparison_operator" = "==" ] && [ "$output" = "$fail_expected_condition" ]; then
    echo -e "Test - FAIL: $test_name" >> "$LOGFILE"
    echo -e "Test -$RED FAIL$RESETCOLOR: $test_name"
    ((failures++))
    add_test_result "$test_category" "$test_name" "fail" "$output"
  elif [ "$pass_comparison_operator" != "==" ] && [ "$output" "$pass_comparison_operator" "$pass_expected_condition" ]; then
    echo -e "Test - PASS: $test_name" >> "$LOGFILE"
    echo -e "Test -$GREEN PASS$RESETCOLOR: $test_name"
    ((passes++))
    add_test_result "$test_category" "$test_name" "pass" "$output"
  elif [ "$fail_comparison_operator" != "==" ] && [ "$output" "$fail_comparison_operator" "$fail_expected_condition" ]; then
    echo -e "Test - FAIL: $test_name" >> "$LOGFILE"
    echo -e "Test -$RED FAIL$RESETCOLOR: $test_name"
    ((failures++))
    add_test_result "$test_category" "$test_name" "fail" "$output"
  else
    echo -e "Test - WARNING: $test_name" >> "$LOGFILE"
    echo -e "Test -$YELLOW WARNING$RESETCOLOR: $test_name"
    ((warnings++))
    add_test_result "$test_category" "$test_name" "warn" "$output"
  fi
}

output_all_tests_by_category() {
  for category in "${!test_categories[@]}"; do
    echo "Category: $category"
    tests="${test_categories[$category]}"
    IFS=',' read -ra test_results <<< "$tests"
    
    for test_result in "${test_results[@]}"; do
      echo "  $test_result"
    done
  done
}

# Handle exceptions
handle_interrupts() {
  intro "Script interrupted by ctrl+c. Exiting."
  echo "The stuntlog file at $LOGFILE is incomplete due to the above exception."
  endscript
  exit 0
}

handle_error() {
  error_message="$1"
  intro "Script encountered an error with the following command: ${BASH_COMMAND}."
  echo "The stuntlog file at $LOGFILE contains an error due to the exception. Continuing... "
  echo -e "Test $test_name: WARNING" >> "$LOGFILE"
  echo -e "Test $test_name: $YELLOW WARNING $RESETCOLOR"
  add_test_result "script" "Error handler" "warn" "$1"
  ((warnings++))
  outro
}

trap handle_interrupts SIGINT
trap 'handle_error "$BASH_COMMAND"' ERR

# CS0237900
# Test if IP address is public, returns 0 if private, 1 if public.
is_ip_private_bool() {
  local private_ranges=(
    "10.0.0.0/8"
    "172.16.0.0/12"
    "192.168.0.0/16"
  )

  IFS='.' read -r -a ip_parts <<< "$IPADDR"
  local ip_number=$(( (${ip_parts[0]} << 24) + (${ip_parts[1]} << 16) + (${ip_parts[2]} << 8) + ${ip_parts[3]} ))

  for range in "${private_ranges[@]}"; do
    IFS='/' read -r -a range_parts <<< "$range"
    local network_address="${range_parts[0]}"
    local subnet_mask="${range_parts[1]}"

    IFS='.' read -r -a range_parts <<< "$network_address"
    local range_number=$(( (${range_parts[0]} << 24) + (${range_parts[1]} << 16) + (${range_parts[2]} << 8) + ${range_parts[3]} ))
    local mask=$(( 0xFFFFFFFF << (32 - $subnet_mask) ))

    if (( ($ip_number & $mask) == ($range_number & $mask) )); then
      echo 0
      return
    fi
  done

  echo 1
}

cert_tester() {
  failed_certs=()
  starting_failures=$failures

  # Check if the directory exists
  if [ ! -d "$CERT_DIRECTORY" ]; then
    echo "Directory $CERT_DIRECTORY does not exist."
    intro "ERROR: $CERT_DIRECTORY was not found; skipping test."
    add_test_result "configuration" "Does $CERT_DIRECTORY exist?" "warn" "$CERT_DIRECTORY not found"
    ((warnings++))
    return
  fi

  # Loop through each certificate file in the directory
  for cert_file in "$CERT_DIRECTORY"/*; do
    if [ -f "$cert_file" ]; then
      # Check if the file is in PEM format using the 'openssl' command
      if openssl x509 -in "$cert_file" -noout -text &>/dev/null; then
        # Certificate is valid (in PEM format)
        add_test_result "certificates" "Cert test: $cert_file" "pass" ""
        ((passes++))
      else
        # Certificate is not in PEM format
        add_test_result "certificates" "Cert test: $cert_file" "fail" ""
        failed_certs+=("$(basename "$cert_file")")
        ((failures++))
      fi
    else
      echo "Skipped: $cert_file (Unknown file type)"
      add_test_result "certificates" "Cert test: $cert_file" "warn" ""
      failed_certs+=("$(basename "$cert_file")")
      ((warnings++))
    fi
  done

  if [[ $failures > $starting_failures ]]; then
    echo "Failed or skipped certificates:"
    for cert_name in "${failed_certs[@]}"; do
      echo "- $cert_name"
    done
  fi
}

# Gives integer expression expected
canalenv_exists_bool() {
  if [[ -e /home/sailpoint/canal.env ]]; then
    echo 0
  else
    if [[ "$do_fixup" == true ]]; then
      echo "Creating canal.env"
      touch /home/sailpoint/canal.env
    else
      echo -e "$YELLOW ACTION: $RESETCOLOR File does not exist, but the option for automatic fixup "
      echo -e "is not enabled. Rerun STUNT with -f to create the canal.env file"
    fi
    echo 1
  fi
}

# CS0268465
canal_log_contains_FNF_string() {
  if [[ $(cat /home/sailpoint/canal-hc.log | grep "No such file or directory" | wc -l) -lt 1 ]]; then
    echo 0
  else
    if [[ "$do_fixup" == true ]]; then
      echo "Creating canal-hc.log"
      touch /home/sailpoint/log/canal-hc.log
    else
      echo -e "$YELLOW ACTION: $RESETCOLOR 'No such file or directory' error found in canal-hc.log,"
      echo -e "but the option for automatic fixup is not enabled. Rerun STUNT with -f to create the canal-hc.log file"
    fi
    echo 1
  fi
}

canal-hc_log_exists_bool() {
  if [[ -e /home/sailpoint/log/canal-hc.log ]]; then
    echo 0
  else
    if [[ "$do_fixup" == true ]]; then
      echo "Creating canal-hc.log"
      touch /home/sailpoint/log/canal-hc.log
    else
      echo -e "$YELLOW ACTION: $RESETCOLOR File does not exist, but the option for automatic fixup"
      echo -e "is not enabled. Rerun STUNT with -f to create the canal-hc.log file"
    fi
    echo 1
  fi
}

ntp_sync_bool() {
  if timedatectl show --property=NTPSynchronized --value | grep -q '^yes$'; then
    echo 0
  else
    echo 1
  fi
}

get_charon_network_test_line() {
  grep -a 'Networking check' /home/sailpoint/log/charon.log | tail -1 
}

#CS0254079
detect_old_os_version() {
  #look in $RUNNING_FLATCAR_VERSION for major version 2345 or lower
  major_version=$( echo "$RUNNING_FLATCAR_VERSION" | awk -F'.' '{ print $1}' )
  if [[ $major_version -le 2345 ]]; then
    echo "Major version is $major_version, and requires update."
    if [[ "$do_fixup" == true ]]; then
      update_old_os
      echo 1
    else
      echo -e "$YELLOW ACTION: $RESETCOLOR File does not exist, but the option for automatic fixup"
      echo -e "is not enabled. Rerun STUNT with -f to create the canal-hc.log file"
      echo 1
    fi
  else # major version greater than 2345
    echo 0
  fi
}

# CS0268451
get_flatcar_current_version() {
  if html=$(curl -s "$FLATCAR_RELEASES_URL" 2>/dev/null); then
    FLATCAR_CURRENT_VER=$(echo "$html" | grep -oP '<span class="version">\K[^<]*' | head -n 1)
  else
    echo "Error: unable to fetch HTML content from $url"
  fi
}

### END FUNCTIONS ###


### START STDOUT OUTPUT ###

echo $DIVIDER
echo "STUNT -- Support Team UNified Test -- ${VERSION}"
echo $DIVIDER
echo "*** This script tests network connectivity, gathers log/system data,"
echo "*** performs recommended setup steps from the SailPoint VA documents which"
echo "*** when skipped will cause network connectivity problems, and creates a"
echo "*** log file at '$LOGFILE'."
echo "*** No warranty is expressed or implied for this tool by SailPoint."
echo 


if test -f "$LOGFILE"; then
  echo "*** Found an old log file. Renaming..." &&
  mv $LOGFILE $LOGFILE.$DATE.old
else
  touch $LOGFILE
fi

# Start the tests by placing a header in the logfile
echo $DIVIDER
echo "$(date -u) - STARTING TESTS for $ORGNAME on $PODNAME"
echo $DIVIDER
echo "$(date -u) - START TESTS for $ORGNAME on $PODNAME on stunt.sh $VERSION " >> "$LOGFILE"
echo $DIVIDER >> "$LOGFILE"
echo "<SUMMARY_BLOCK>" >> "$LOGFILE"
outro

# Do update
if [ "$do_update" == "true" ]; then
  intro "Performing forced update - this process resets the machine-id and the update service. *REBOOTS ARE REQUIRED WHEN SUCCESSFUL*"
  sudo rm -f /etc/machine-id  >> "$LOGFILE" 2>&1
  sudo systemd-machine-id-setup  >> "$LOGFILE" 2>&1
  if [ echo "$RUNNING_FLATCAR_VERSION" | awk -F'.' '{print $1}' -lt 3374 ]; then #CS0268437
    sudo systemctl restart update-engine  >> "$LOGFILE" 2>&1
  fi
  sudo update_engine_client -reset_status && sudo update_engine_client -update >> "$LOGFILE" 2>&1
  # TODO - If this detects "NO_UPDATE_AVAILABLE", we should remove the machine id again, set it up again, and do the double-update (last line)
  # TODO - if this detects "UPDATE_STATUS_REPORTING_ERROR_EVENT", then do:
  # sudo journalctl --no-pager -u update-engine -e >> "$LOGFILE" 2>&1
  outro
  endscript
  echo "EXITING"
  exit 0
fi

# Do alternating curl test
if [ "$curl_test" == "true" ]; then
  intro "Curl test starting"
  echo "Performing alternating curl test against S3 and SQS. This will run for $total_seconds_to_test seconds,"
  echo "and then quit automatically. Use ctrl+c to stop early."
  runme=true;
  run_sqs=true;
  now=$(date +%s) #time in seconds since epoch
  future=$(($now + $total_seconds_to_test))
  while $runme; do
    if [ "$run_sqs" == true ]; then
      echo $(date -u +"%b_%d_%y-%H:%M:%S") >> "$LOGFILE"
      echo "Testing connection to SQS: "
      echo "Testing connection to SQS: " >> "$LOGFILE"
      expect "a 404 error."
      curl -i --connect-timeout $seconds_between_tests "https://sqs.us-east-1.amazonaws.com" >> "$LOGFILE"
      echo
      echo >> "$LOGFILE"
      run_sqs=false;
      sleep 4;
    else
      echo $(date -u +"%b_%d_%y-%H:%M:%S") >> "$LOGFILE"
      echo "Testing connection to S3: "
      echo "Testing connection to S3: " >> "$LOGFILE"
      expect "a 403 error."
      curl -i --connect-timeout $seconds_between_tests "https://sppcbu-va-images.s3.amazonaws.com" >> "$LOGFILE" 
      echo
      echo >> "$LOGFILE"
      run_sqs=true;
      sleep 4;
    fi
    if [[ $(date +%s) -ge $future ]]; then
      echo "$total_seconds_to_test seconds have elapsed. Quitting..."
      outro
      runme=false;
    fi
  done
  endscript
  exit 0
fi
  
# Reset <id>.json file - only use when moving a VA to a new cluster due to error "OpenSSL::PKey::RSAError: Neither PUB key nor PRIV key: bad decrypt" in charon.log
if [[ "$reset_id_json" == "true" ]]; then
  intro "Resetting the <id>.json file at /opt/sailpoint/share/chef/data_bags/aws_credentials/"
  id_json_filepath="/opt/sailpoint/share/chef/data_bags/aws_credentials"
  id_json_filename=$(ls $id_json_filepath)
  original_md5=$(md5sum $id_json_filepath/$id_json_filename)
  ellipsis=("." ".." "...")
  ellipsis_index=0
  expect "the file at $id_json_filepath/$id_json_filename to be deleted and a new copy generated."
  while true; do
    read -p "Type 'Y' to confirm file delete for $id_json_filepath/$id_json_filename: " response
    case $response in
      [Y])
        echo "User accepted delete for $id_json_filepath/$id_json_filename by pressing Y" >> "$LOGFILE"
        echo "Accepted delete. Continuing..."
        sudo systemctl stop charon va_agent &&
        sudo rm -f $id_json_filepath/$id_json_filename
        if [ -f $id_json_filepath/$id_json_filename ]; then
          echo "File still exists. Delete failed. Exiting" >> "$LOGFILE"
          echo "File still exists. Delete failed. Exiting"
          exit 1
        else
          echo "File deleted successfully." >> "$LOGFILE"
          echo "File deleted successfully. Please create a new VA record in your cluster, and copy the new"
          echo "config.yaml onto this VA instance. I will wait to continue until you tell me this is complete by"
          read -p "pressing Y again: " new_response
          case $new_response in
            [Y])
              echo "User stated 2nd step in reset complete (new config.yaml in place) by pressing Y" >> "$LOGFILE"
              echo "Continuing..."
              sudo systemctl start va_agent
              while [ ! "$(find "$id_json_filepath" -maxdepth 1 -type f -name "*.json")" ]; do
                echo -n "Waiting for .json file to be generated${ellipsis[ellipsis_index]}"
                ellipsis_index=$(( (ellipsis_index + 1) % ${#ellipsis[@]} ))
                sleep 1
                echo -ne "\r"
              done
              new_file=$(find "$id_json_filepath" -maxdepth 1 -type f -name "*.json")
              echo "File generated @ $new_file!" >> "$LOGFILE"
              echo "File generated @ $new_file!"
              echo "Restarting services"
              sudo systemctl start charon >> "$LOGFILE" 
              sudo systemctl restart falcon >> "$LOGFILE" 
              sudo systemctl restart canal >> "$LOGFILE" 
              sudo systemctl restart ccg >> "$LOGFILE" 
              sudo systemctl restart otel_agent >> "$LOGFILE" 
              ;;
            *)
              "Invalid input - exiting."
              exit 1
              ;;
          esac
        fi
        echo "Steps complete. Please test the VA connection in the new cluster."
        exit 0
        break
        ;;
      *) #anything else
        echo "Invalid input - exiting."
        exit 1
        ;;
      esac
  done
  endscript
fi


update_old_os() {
  intro "Retrieving Flatcar Linux certificate, and starting OS update. This will reboot the VA when complete."
  echo "This will reboot the VA when complete."
  curl -sS https://stable.release.flatcar-linux.net/ >/dev/null
  sudo rm /etc/ssl/certs/DST_Root_CA_X3.pem
  sudo update-ca-certificates
  curl -sS https://stable.release.flatcar-linux.net/ >/dev/null
  sudo update_engine_client -update && echo "\nCompleted STUNT process." >> "$LOGFILE"
  ADD_REBOOT_MESSAGE=true
}

# detect Canal in config.yaml
if [[ $(cat /home/sailpoint/config.yaml | grep "tunnelTraffic: true" | wc -l) -gt 0 ]]; then
  is_canal_enabled_bool=true
  intro "NOTE: CANAL CONFIG DETECTED"
fi

# Execute tests

intro "Retrieving list of files in home directory with ls -alh"
ls -alh /home/sailpoint/ >> "$LOGFILE"
outro

intro "Retrieving current working directory path with pwd"
expect "this to be /home/sailpoint/ but not a requirement"
pwd >> "$LOGFILE"
outro

key_passphrase_length=$(get_keyPassphrase_length)
expect "keyPassphrase length to be greater than 0 characters"
perform_test "Is keyPassphrase length more than 0 characters?" "get_keyPassphrase_length" -gt 0 -lt 1 "configuration"
outro
expect "keyPassphrase length to be less than than 60 characters"
perform_test "Is keyPassphrase length less than 60 characters?" "get_keyPassphrase_length" -lt 60 -gt 59 "configuration"
outro
echo -e "Current keyPassphrase length: $key_passphrase_length chars" >> "$LOGFILE"
if [[ $key_passphrase_length -lt 1 ]]; then
  cat /home/sailpoint/config.yaml | sed "s/keyPassphrase: .*/keyPassphrase: <REMAINS UNENECRYPTED>/g" | sed "s/apiKey: .*/apiKey: <redacted>/g" >> "$LOGFILE"
else
  cat /home/sailpoint/config.yaml | sed "s/keyPassphrase: ':::.*/keyPassphrase: <redacted>/g" | sed "s/apiKey: .*/apiKey: <redacted>/g" >> "$LOGFILE"
fi

expect "a passing test against the IP $IPADDR. If public, VA is much less likely to be able to communicate with an internal DNS"
perform_test "Is IP address ($IPADDR) private?" "is_ip_private_bool $IPADDR" -eq 0 -eq 1 "networking"
outro

expect "a passing test; string match uname command output for 'flatcar'"
perform_test "Does Kernel version name report flatcar?" "uname -a | grep flatcar | wc -m" -gt 6 -eq 0 "system"
outro

# CS0239311 
ntp_result=$(ntp_sync_bool)
perform_test "Does timedatectl show NTP time is synced?" "ntp_sync_bool" -eq 0 -ne 0 "configuration"
if [[ $ntp_result != 0 ]]; then
  echo -e "     $YELLOW ACTION: $RESETCOLOR Test for NTP sync failed. To configure NTP, see the following link: "
  echo -e "     https://documentation.sailpoint.com/saas/help/va/requirements_va.html#connecting-the-va-to-a-local-ntp-server"
  echo "ACTION: Test for NTP sync failed. To configure NTP, see the following link: " >> "$LOGFILE"
  echo "https://documentation.sailpoint.com/saas/help/va/requirements_va.html#connecting-the-va-to-a-local-ntp-server" >> "$LOGFILE"
fi
outro

intro "Retrieving OS Uptime"
expect "this VA to have been restarted recently if it is having issues."
uptime >> "$LOGFILE"
outro 

intro "Retrieving environment variables"
env >> "$LOGFILE"
outro

intro "Retrieving OpenJDK version from ccg"
expect "this version of java to be 11.0.14 or higher and not 1.8.x"
grep -a openjdk /home/sailpoint/log/worker.log | tail -1 >> "$LOGFILE"
grep -a "openjdk version" /home/sailpoint/log/ccg-start.log | tail -1 >> "$LOGFILE"
#TODO also look in ccg-start.log for "openjdk version "11.0.19" 2023-04-18" or "OpenJDK Runtime Environment (build 11.0.19+7-post-Ubuntu-0ubuntu120.04.1)"
outro

if test -f /etc/profile.env; then
  intro "Retrieving profile.env"
  expect "the file to exist. If proxy is a concern, have customer confirm settings."
  cat /etc/profile.env >> "$LOGFILE" 2>&1
  outro
fi

if test -f /etc/systemd/system.conf.d/10-default-env.conf; then
  intro "Retrieving 10-default-env.conf"
  expect "the file to exist. If proxy is a concern, have customer confirm settings."
  cat /etc/systemd/system.conf.d/10-default-env.conf >> "$LOGFILE" 2>&1
  outro
fi

intro "Retrieving docker.env"
expect "proxy references in docker.env. Remove references to proxy if proxying is a concern."
cat /home/sailpoint/docker.env >> "$LOGFILE"
outro

if test -f /etc/systemd/network/static.network; then
  intro "Retrieving the static.network file"
  expect "individual DNS entries to be on separate lines beginning with 'DNS'."
  expect "the IP address to include CIDR notation."
  cat /etc/systemd/network/static.network >> "$LOGFILE"
  outro
fi

intro "Retrieving the resolv.conf file"
expect "DNS entries to match those in static.network, if it exists."
cat /etc/resolv.conf >> "$LOGFILE"
outro

if test -f /home/sailpoint/proxy.yaml; then
  intro "Retrieving the proxy config"
  cat /home/sailpoint/proxy.yaml >> "$LOGFILE"
  outro
fi

expect "Version is the same as stable channel's most recent: https://www.flatcar.org/releases#stable-release"
perform_test "Is current OS version the same as the one pulled from the Flatcar site?" "get_flatcar_current_version" "==" "$FLATCAR_CURRENT_VER" "!=" "$FLATCAR_CURRENT_VER" "system"
echo "Current OS version on this system: $RUNNING_FLATCAR_VERSION" >> "$LOGFILE"
echo "Current stable OS version on Flatcar site: $FLATCAR_CURRENT_VER" >> "$LOGFILE"
outro

intro "Retrieving CPU information"
expect "the number of CPU(s) to be >= 2 CPUs. This is from AWS m4.large specs."
lscpu >> "$LOGFILE"
outro

intro "Retrieving total RAM"
expect "the RAM to be >= 16Gi (approx 16GB). This is from AWS m4.large specs."
free -h >> "$LOGFILE"
outro

intro "Network list for all adapters"
expect "one of two adapters to exist: ens160 or eth0. If canal is enabled, tun0 should be in this list as well."
if [[ "$is_canal_enabled_bool" == true ]]; then
  expect "that tun0 exists and is routable."
fi
networkctl list >> "$LOGFILE"
outro

intro "Network information for main adapter"
expect "information from resolv.conf/static.network/etc. to match up with what you find for the main adapter"
if [[ $(networkctl list | grep ens160) == *"ens160"* ]]; then
  networkctl status ens160 >> "$LOGFILE" 2>&1
else
  networkctl status eth0 >> "$LOGFILE" 2>&1
fi
outro

if [[ "$is_canal_enabled_bool" == true ]]; then
  expect "tun0 adapter to be in a 'routable (configuring)' state, and to show the online state as 'online'."
  networkctl status tun0 >> "$LOGFILE" 2>&1
fi

intro "Retrieving networking check in charon.log"
expect "all endpoints to have 'PASS' after their name"
perform_test "Post charon networking test, do all endpoints include PASS?" "get_charon_network_test_line | grep ERROR | wc -l" -eq 0 -ne 0 "networking"
get_charon_network_test_line >> "$LOGFILE"
outro

intro "Testing direct connection to regional Secure Tunnel servers"
expect "tests below to pass for every IP. On failure(s), ask if DPI (Deep Packet Inspection) or any variation is decrypting traffic from the VAs" 
if [[ $PODNAME == *"useast1"* ||  $PODNAME == *"cook"* || $PODNAME == *"fiji"* || $PODNAME == *"uswest2"* || $PODNAME == *"cacentral1"* ]]; then
  # us-east-1 PODNAMEs contain: useast1 cook fiji uswest2 cacentral1
  echo "Using us-east-1 endpoints: " >> "$LOGFILE"
  echo "Using us-east-1 endpoints: "
  perform_test "Canal Server Connection Test to IP: 52.206.130.59" "echo -e '\x00\x0e\x38\xa3\xcf\xa4\x6b\x74\xf3\x12\x8a\x00\x00\x00\x00\x00' | ncat 52.206.130.59 443 | cat -v | tr -d '[:space:]' | grep -e @^Z@ | wc -m" -gt 10 -eq 0 "networking" 
  outro
  perform_test "Canal Server Connection Test to IP: 52.206.133.183" "echo -e '\x00\x0e\x38\xa3\xcf\xa4\x6b\x74\xf3\x12\x8a\x00\x00\x00\x00\x00' | ncat 52.206.133.183 443 | cat -v | tr -d '[:space:]' | grep -e @^Z@ | wc -m" -gt 10 -eq 0 "networking" 
  outro
  perform_test "Canal Server Connection Test to IP: 52.206.132.240" "echo -e '\x00\x0e\x38\xa3\xcf\xa4\x6b\x74\xf3\x12\x8a\x00\x00\x00\x00\x00' | ncat 52.206.132.240 443 | cat -v | tr -d '[:space:]' | grep -e @^Z@ | wc -m" -gt 10 -eq 0 "networking" 
  outro
elif [[ $PODNAME == *"eucentral1"* ]]; then
  # eu-central-1 PODNAMEs contain: eucentral1 
  echo "Using eu-central-1 endpoints: " >> "$LOGFILE"
  echo "Using eu-central-1 endpoints: "
  perform_test "Canal Server Connection Test to IP: 35.157.132.22" "echo -e '\x00\x0e\x38\xa3\xcf\xa4\x6b\x74\xf3\x12\x8a\x00\x00\x00\x00\x00' | ncat 35.157.132.22 443 | cat -v | tr -d '[:space:]' | grep -e @^Z@ | wc -m" -gt 10 -eq 0 "networking" 
  outro
  perform_test "Canal Server Connection Test to IP: 35.157.185.79" "echo -e '\x00\x0e\x38\xa3\xcf\xa4\x6b\x74\xf3\x12\x8a\x00\x00\x00\x00\x00' | ncat 35.157.185.79 443 | cat -v | tr -d '[:space:]' | grep -e @^Z@ | wc -m" -gt 10 -eq 0 "networking" 
  outro
  perform_test "Canal Server Connection Test to IP: 35.157.251.228" "echo -e '\x00\x0e\x38\xa3\xcf\xa4\x6b\x74\xf3\x12\x8a\x00\x00\x00\x00\x00' | ncat 35.157.251.228 443 | cat -v | tr -d '[:space:]' | grep -e @^Z@ | wc -m" -gt 10 -eq 0 "networking" 
  outro
elif [[ $PODNAME == *"euwest2"* ]]; then
  #eu-west-2 PODNAMEs contain: euwest2
  echo "Using eu-west-2 endpoints: " >> "$LOGFILE"
  echo "Using eu-west-2 endpoints: "
  perform_test "Canal Server Connection Test to IP: 18.130.210.174" "echo -e '\x00\x0e\x38\xa3\xcf\xa4\x6b\x74\xf3\x12\x8a\x00\x00\x00\x00\x00' | ncat 18.130.210.174 443 | cat -v | tr -d '[:space:]' | grep -e @^Z@ | wc -m" -gt 10 -eq 0 "networking"  
  outro
  perform_test "Canal Server Connection Test to IP: 18.130.148.201" "echo -e '\x00\x0e\x38\xa3\xcf\xa4\x6b\x74\xf3\x12\x8a\x00\x00\x00\x00\x00' | ncat 18.130.148.201 443 | cat -v | tr -d '[:space:]' | grep -e @^Z@ | wc -m" -gt 10 -eq 0 "networking" 
  outro
  perform_test "Canal Server Connection Test to IP: 35.178.220.78" "echo -e '\x00\x0e\x38\xa3\xcf\xa4\x6b\x74\xf3\x12\x8a\x00\x00\x00\x00\x00' | ncat 35.178.220.78 443 | cat -v | tr -d '[:space:]' | grep -e @^Z@ | wc -m" -gt 10 -eq 0 "networking" 
  outro
elif [[ $PODNAME == *"apsoutheast2"* ]]; then
  #apac PODNAMEs contain: apsoutheast2
  echo "Using ap-southeast-2 endpoints: " >> "$LOGFILE"
  echo "Using ap-southeast-2 endpoints: "
  perform_test "Canal Server Connection Test to IP: 52.65.42.92" "echo -e '\x00\x0e\x38\xa3\xcf\xa4\x6b\x74\xf3\x12\x8a\x00\x00\x00\x00\x00' | ncat 52.65.42.92 443 | cat -v | tr -d '[:space:]' | grep -e @^Z@ | wc -m" -gt 10 -eq 0 "networking"  
  outro
  perform_test "Canal Server Connection Test to IP: 13.55.78.212" "echo -e '\x00\x0e\x38\xa3\xcf\xa4\x6b\x74\xf3\x12\x8a\x00\x00\x00\x00\x00' | ncat 13.55.78.212 443 | cat -v | tr -d '[:space:]' | grep -e @^Z@ | wc -m" -gt 10 -eq 0 "networking" 
  outro
  perform_test "Canal Server Connection Test to IP: 3.24.127.50" "echo -e '\x00\x0e\x38\xa3\xcf\xa4\x6b\x74\xf3\x12\x8a\x00\x00\x00\x00\x00' | ncat 3.24.127.50 443 | cat -v | tr -d '[:space:]' | grep -e @^Z@ | wc -m" -gt 10 -eq 0 "networking" 
  outro
else
  echo "Unable to find appropriate canal server test with PODNAME: $PODNAME" >> "$LOGFILE"
  outro
fi

intro "Retrieving contents of /home/sailpoint/hosts.yaml"
expect "hosts.yaml information to be fed into /etc/hosts"
cat /home/sailpoint/hosts.yaml >> "$LOGFILE"
outro

intro "Retrieving contents of /etc/hosts from host"
expect "entries to match the /etc/hosts from ccg in the next section."
cat /etc/hosts >> "$LOGFILE"
outro

intro "Retrieving contents of /etc/hosts from ccg container."
sudo docker exec ccg cat /etc/hosts >> "$LOGFILE" 2>&1
outro

intro "Retrieving contents of /opt/sailpoint/ccg/lib/custom from ccg container"
expect "JDBC driver jar files. Make sure they are populating here if required."
sudo docker exec ccg ls -l /opt/sailpoint/ccg/lib/custom >> "$LOGFILE" 2>&1
outro

if [[ "$do_fixup" == true ]]; then
  intro "This step disables esx_dhcp_bump"
  expect "any output stating this was removed/disabled. If there is, be sure to do a sudo reboot."
  sudo systemctl disable esx_dhcp_bump >> "$LOGFILE" 2>&1
  outro
fi

intro "Retrieving list of all SSL certs in $CERT_DIRECTORY"
ls -alh $CERT_DIRECTORY >> "$LOGFILE" 2>&1
outro

if [[ "$check_openssl_cert" == true ]]; then
  intro "Test all custom certificates in $CERT_DIRECTORY against openssl"
  cert_tester
  outro
fi

if [[ "$do_fixup" == true ]]; then
  intro "This step updates all SSL certificates in /etc/ssl/certs"
  expect "this section to be blank; we only catch errors here."
  sudo /usr/sbin/update-ca-certificates > /dev/null 2>> "$LOGFILE" # stdout to /dev/null, catch only errors
  outro
fi

intro "Retrieving list of all SSL certs in /etc/ssl/certs"
expect "updated date for most certs to be today's date due to the script above (update-ca-certificates)."
ls -alh /etc/ssl/certs >> "$LOGFILE" 2>&1
outro

intro "External connectivity: Connection test for SQS (https://sqs.us-east-1.amazonaws.com)"
expect "no self-signed certificates, and a verbose response, and a result of 404."
curl -i -vv --connect-timeout 10 "https://sqs.us-east-1.amazonaws.com" >> "$LOGFILE" 2>&1
expect "a 404"
perform_test "Curl test to SQS" "curl -i --connect-timeout 10 \"https://sqs.us-east-1.amazonaws.com\" 2>&1 | grep \"404 Not Found\" | wc -l" -gt 0 -eq 0 "networking"
outro

intro "External connectivity: Connection test for https://$ORGNAME.identitynow.com"
expect "a result of 302 - may fail to complete if this is a vanity org."
curl -i --connect-timeout 10 "https://$ORGNAME.identitynow.com" >> "$LOGFILE" 2>&1
expect "a 302"
perform_test "Curl test to IdentityNow org" "curl -i \"https://$ORGNAME.identitynow.com\" 2>&1 | grep \"HTTP/2 302\" | wc -l" -gt 0 -eq 0 "networking"
outro

intro "External connectivity: Connection test for https://$ORGNAME.api.identitynow.com"
expect "a result of 404 - may fail to complete if this is a vanity org."
curl -i --connect-timeout 10 "https://$ORGNAME.api.identitynow.com" >> "$LOGFILE" 2>&1
expect "a 404"
perform_test "Curl test to the tenant API" "curl -i --connect-timeout 10 \"https://$ORGNAME.api.identitynow.com\" 2>&1 | grep \"404\" | wc -l" -gt 0 -eq 0 "networking"
outro

intro "External connectivity: Connection test for https://$PODNAME.accessiq.sailpoint.com"
expect "a result of 302"
curl -i --connect-timeout 10 "https://$PODNAME.accessiq.sailpoint.com" >> "$LOGFILE" 2>&1
expect "a 302"
perform_test "Curl test to IdentityNow pod" "curl -i \"https://$PODNAME.accessiq.sailpoint.com\" 2>&1 | grep \"HTTP/2 302\" | wc -l" -gt 0 -eq 0 "networking"
outro

intro "External connectivity: Connection test for DynamoDB (https://dynamodb.us-east-1.amazonaws.com)"
expect "a result of 200"
curl -i --connect-timeout 10 "https://dynamodb.us-east-1.amazonaws.com" >> "$LOGFILE" 2>&1
expect "a 200"
perform_test "Curl test to DynamoDB" "curl -i \"https://dynamodb.us-east-1.amazonaws.com\" 2>&1 | grep \"HTTP/1.1 200 OK\" | wc -l" -gt 0 -eq 0 "networking"
outro

intro "Checking active ports using netstat."
sudo netstat -pan -A inet,inet6 | grep -v ESTABLISHED >> "$LOGFILE" 2>&1
outro 

intro "Display tcp statistics"
expect "the number of failed connection attempts to be less than 100. If more, consider a packet capture."
sudo netstat -st >> "$LOGFILE" 2>&1
outro

intro "Using the ss utility to list open ports"
ss -plno -A tcp,udp,sctp >> "$LOGFILE"
outro

if [ "$do_ping" = true ]; then
  intro "Pinging IdentityNow tenant"
  ping -c 5 -W 2 $ORGNAME.identitynow.com >> "$LOGFILE"
  outro
fi

if [ "$do_traceroute" = true ]; then
  intro "Collecting traceroute to SQS... (this may take a moment; please be patient)"
  traceroute sqs.us-east-1.amazonaws.com >> "$LOGFILE"
  outro
fi

intro "Retrieving additional routing information from ip route show"
ip route show >> "$LOGFILE"
outro

# Only gather log snippets if we're not getting all logs via -l switch
if [[ "$gather_logs" != true ]]; then
  intro "Retrieving ccg.log errors - latest 30 errors"
  expect "recent datestamps. Some logs might be old and no longer pertinent. Expect no errors for keystore.jks which usually signifies a keyPassphrase issue."
  cat /home/sailpoint/log/ccg.log | grep stacktrace | tail -n30 >> "$LOGFILE" 2>&1
  outro
fi

expect "the CCG image to be updated: it should be less than 3 weeks old."
sudo docker images | sort >> "$LOGFILE"
outro

expect "the following four (4) processes to be running: ccg, va_agent, charon, and va."
perform_test "Is ccg running?" "sudo docker ps | grep ccg | wc -l" -eq 1 -lt 1 "system"
outro
perform_test "Is va_agent running?" "sudo docker ps | grep va_agent | wc -l" -eq 1 -lt 1 "system"
outro
perform_test "Is charon running?" "sudo docker ps | grep charon | wc -l" -eq 1 -lt 1 "system"
outro
perform_test "Is va (fluent) running?" "sudo docker ps | grep 'va:current' | wc -l" -eq 1 -lt 1 "system"
outro
if [[ "$is_canal_enabled_bool" == true ]]; then
  expect "an additional service to be running when Secure Tunnel is enabled: canal"
  perform_test "Is canal running?" "sudo docker ps | grep canal | wc -l" -eq 1 -lt 1 "system"
  outro
fi

intro "Retrieving systemd service configuration file: charon"
expect "the file to exist, and contains a valid docker ECR address compared to the docker images list above."
cat /etc/systemd/system/charon.service >> "$LOGFILE"
outro

intro "Retrieving systemd service configuration file: ccg"
expect "the file to exist, and contains a valid docker ECR address compared to the docker images list above."
cat /etc/systemd/system/ccg.service >> "$LOGFILE"
outro

intro "Retrieving systemd service configuration file: va_agent"
expect "the file to exist, and contains a valid docker ECR address compared to the docker images list above."
cat /etc/systemd/system/va_agent.service >> "$LOGFILE"
outro

intro "Retrieving systemd service configuration file: fluent"
expect "the file to exist, and contains a valid docker ECR address compared to the docker images list above."
cat /etc/systemd/system/fluent.service >> "$LOGFILE"
outro

intro "Retrieving systemd service configuration file: relay"
expect "the file to exist, and contains a valid docker ECR address compared to the docker images list above."
cat /etc/systemd/system/relay.service >> "$LOGFILE"
outro

intro "Retrieving systemd service configuration file: toolbox"
expect "the file to exist, and contains a valid docker ECR address compared to the docker images list above."
cat /etc/systemd/system/toolbox.service >> "$LOGFILE"
outro

if [[ "$is_canal_enabled_bool" == true ]]; then
  intro "Retrieving systemd service configuration file: canal"
  expect "the file to exist, and contains a valid docker ECR address compared to the docker images list above."
  cat /etc/systemd/system/canal.service >> "$LOGFILE"
  outro
fi

if test -f /etc/systemd/system/esx_dhcp_bump.service; then
  intro "Retrieving systemd service configuration file: esx_dhcp_bump"
  cat /etc/systemd/system/esx_dhcp_bump.service >> "$LOGFILE"
  outro
fi

intro "Retrieving partition table info"
expect "total disk space under \"SIZE\". Should be ~128GB or more."
expect "one sda<#> to be TYPE 'part' and RO '0'. This means the PARTition is writable."
lsblk -o NAME,SIZE,FSSIZE,FSAVAIL,FSUSE%,MOUNTPOINT,TYPE,RO >> "$LOGFILE"
outro

intro "Retrieving disk usage stats"
expect "sda9/nvme0n1p9 to be less than 15% full. More likely means a debug setting was enabled long-term."
df -h >> "$LOGFILE"
outro

intro "Retrieving disk usage paths"
expect "most files to be less than 1GB. Log files can be significantly larger, but shouldn't exceed 1GB each."
du -h /home/sailpoint/ >> "$LOGFILE"
outro

intro "Retrieving list of large files"
expect "most files to be less than 1MB. Log files can be significantly larger, but shouldn't exceed 1GB each."
find /home/sailpoint/ -xdev -type f -size +100M -print | xargs ls -lh | sort -k5,5 -h -r >> "$LOGFILE"
outro

#TODO: Sometimes awk pattern /sda9|nvme0n1p9/ won't match. Need some error-checking on the local 'output' variable which stores the result of evaluating the 'test_command' variable.
perform_test "Are more than 100 inodes available on the main partition at sda9 or nvme0n1p9?" '(df -i | awk "/sda9|nvme0n1p9/ {print \$4}" | tail -n1)' -gt 100 -lt 100 "system" 
outro 

intro "Retrieving number and list of pending jobs." 
num_pending_jobs=$(ls /opt/sailpoint/workflow/jobs/ | wc -l)
echo "$num_pending_jobs pending jobs in the directory." >> "$LOGFILE"
ls -al /opt/sailpoint/workflow/jobs >> "$LOGFILE"
outro

expect "this to have fewer than 20 completed jobs. If lots of jobs are > 1 week old, run: sudo rm -rf /opt/sailpoint/share/jobs/* && sudo reboot"
perform_test "Does /opt/sailpoint/share/jobs have fewer than 20 jobs?" "get_num_jobs" -lt 20 -gt 19 "system"
outro

if [[ "$is_canal_enabled_bool" == true ]]; then
  echo "$DIVIDER"
  intro "*** The following tests and data gathering are only run if Secure Tunnel config has been enabled"
  echo
  intro "Retrieving the canal config file @/opt/sailpoint/share/canal/client.conf"
  cat /opt/sailpoint/share/canal/client.conf >> "$LOGFILE"
  outro

  expect "the canal.env file to exist if canal is configured"
  perform_test "canal.env existence check" "canalenv_exists_bool" -eq 0 -eq 1 "system"
  outro

  expect "the canal-hc.log file to exist if canal is configured"
  perform_test "canal-hc.log existence check" "canal-hc_log_exists_bool" -eq 0 -eq 1 "system"
  outro

  intro "Checking ccg.log for successful canal setup"
  expect "this to contain something like 'Job SERVICE_SETUP fluent/ccg/relay/canal has FINISHED - result: SUCCESS'"
  perform_test "Check charon.log for canal setup success message" 'grep -e "SUCCESS" -e "canal" /home/sailpoint/log/charon.log | tail -n1' "==" "Job SERVICE_SETUP fluent/ccg/relay/canal has FINISHED - result: SUCCESS" "==" "" "configuration" 
  outro

  intro "Retrieving last 50 lines of canal service journal logs"
  sudo journalctl --no-pager -n50 -u canal >> "$LOGFILE" 
  outro

  intro "Retrieving last 50 lines of update-service journal logs"
  sudo journalctl --no-pager -n50 -u update-engine >> "$LOGFILE" 
  outro
  
  echo "*** Completed gathering extra data from Canal config."
  echo "$DIVIDER"
  echo 
fi

intro "Retrieving last 50 lines of kernel journal logs"
sudo journalctl --no-pager -n50 -k >> "$LOGFILE"
outro

intro "Retrieving last 50 lines of network journal logs"
sudo journalctl --no-pager -n50 -u systemd-networkd >> "$LOGFILE"
outro

intro "Retrieving last 50 lines of ccg journal logs"
sudo journalctl --no-pager -n50 -u ccg >> "$LOGFILE"
outro

intro "Retrieving last 50 lines of va_agent journal logs"
sudo journalctl --no-pager -n50 -u va_agent >> "$LOGFILE"
outro

intro "Retrieving last 50 lines of otel_agent journal logs"
sudo journalctl --no-pager -n50 -u otel_agent >> "$LOGFILE"
outro

endscript

if [ "$gather_logs" = true ]; then
  # Get list of files in log directory just in case we need more than these specific files
  intro "Gathering all log files and zipping."
  echo
  echo "*** NOTE: This file might be large depending on the life of your VA. ***"
  echo
  zip -r $ZIPFILE $LOGFILE $LISTOFLOGS
  echo "Zipped to $ZIPFILE"
  echo "Zipped to $ZIPFILE" >> $LOGFILE
  outro
fi

all_test_results=$(output_all_tests_by_category)

echo $DIVIDER
echo "Testing summary"
echo $DIVIDER
echo -e "Tests passed:                           $GREEN $passes $RESETCOLOR"
echo -e "Tests failed:                           $RED $failures $RESETCOLOR"
echo -e "Test warnings:                          $YELLOW $warnings $RESETCOLOR"
echo 
echo $DIVIDER

summary="Testing summary \n
Tests passed:   $passes \n
Tests failed:    $failures \n
Test warnings:  $warnings \n

All tests sorted by category: \n
$all_test_results \n"

echo "$summary" > /tmp/summary_temp.txt
awk -v var="$(cat /tmp/summary_temp.txt)" '{gsub(/<SUMMARY_BLOCK>/, var)}1' $LOGFILE > temp && mv temp $LOGFILE
rm /tmp/summary_temp.txt

if [ "$gather_logs" = true ]; then
  echo
  echo "*** RETRIEVE THE ZIPPED FILE WITHOUT RENAMING:"
  echo "*** ${ZIPFILE} "
  echo "*** AND UPLOAD TO YOUR CASE."
  echo
  echo "We recommend use of the scp tool from a Linux/Mac/PuTTY shell to retrieve the zip file from"
  echo "this server. Use the line created for you below at your local machine's terminal:"
  echo -e $CYAN
  echo -e "scp sailpoint@$IPADDR:$ZIPFILE ./ $RESETCOLOR"
else
  echo
  echo "*** RETRIEVE THE FILE WITHOUT RENAMING:"
  echo "*** ${LOGFILE} "
  echo "*** AND UPLOAD TO YOUR CASE."
  echo
  echo "We recommend use of the scp tool from a Linux/Mac/PuTTY shell to retrieve the zip file from"
  echo "this server. Use the line created for you below at your local machine's terminal:"
  echo -e $CYAN
  echo -e "scp sailpoint@$IPADDR:$LOGFILE ./ $RESETCOLOR"
fi

if [ "$ADD_REBOOT_MESSAGE" == true ]; then
  echo -e "$YELLOW$DIVIDER $REDBOLDUL"
  echo -e "REBOOT IS REQUIRED; PLEASE RUN 'sudo reboot' NOW $RESETCOLOR"
  echo -e "$YELLOW$DIVIDER $RESETCOLOR"
fi
