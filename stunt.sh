#!/bin/bash

VERSION="v1.4"
DATE=$(date -u +"%b_%d_%y-%H_%M")
DIVIDER="================================================================================"

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
RESETCOLOR='\033[0m'

if [[ -e "/home/sailpoint/config.yaml" ]]; then
  orgname=$(grep -oP '(?<=org: ).*' /home/sailpoint/config.yaml)
  orgname="${orgname//$'\r'/}" #remove return characters
  podname=$(grep -oP '(?<=pod: ).*' /home/sailpoint/config.yaml)
  podname="${podname//$'\r'/}" #remove return characters
  ipaddr=$(networkctl status | grep Address | sed 's/Address: //' | grep -E -o '[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}')
  LOGFILE=/home/sailpoint/stuntlog-$orgname-$ipaddr.txt
  ZIPFILE=/home/sailpoint/logs.$orgname-$podname-$(hostname)-$ipaddr-$DATE.tar.gz # POD-ORG-CLUSTER_ID-VA_ID.tar.gz 
  encrypted_keyPassphrase_length=$(cat /home/sailpoint/config.yaml | grep "::::" | wc -m) # This will be 0 if unencrypted
  LISTOFLOGS="/home/sailpoint/log/*.log"
  total_seconds_to_test=180
  seconds_between_tests=4
  error_message=""
else
  echo "*** Config file not found. Please run this only on a SailPoint VA."
  echo "*** Execution stopped; no log file created or changes made. ***"
  endscript
  exit 1
fi


help () {
  # Display help
  echo "Stunt version: $VERSION"
  echo "The stunt script collects information about the current state of your"
  echo "VA, and places that data into a stuntlog text file in your home directory."
  echo "Collecting this helps SailPoint Support Engineers troubleshoot your system."
  echo
  echo "Syntax: ./stunt.sh [-h] [-t,p,o,l|L|u|c]"
  echo "Options:"
  echo "h   Print this help info and exit"
  echo "t   Add traceroute test to SQS"
  echo "p   Add ping test"
  echo "o   Add openssl cert test"
  echo "l/L Add collection of log files and tar.gzip them with stuntlog file."
  echo "u   Only perform forced update (this will make system changes)"
  echo "c   Only perform a curl test that connects to SQS and S3, one test every four seconds for three minutes."
}

# Get cmd line args
while getopts ":htpulLoc" option; do
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
    l)
      gather_logs=true;;
    L)
      gather_logs=true;;
    o)
      check_openssl_cert=true;;
    c)
      curl_test=true;;
    \?) 
      echo "Invalid argument on command line. Please review help below:"
      help
      exit;;
    esac
done

echo $DIVIDER
echo "STUNT -- Support Team UNified Test -- ${VERSION}"
echo $DIVIDER
echo "*** This script tests network connectivity, gathers log/system data,"
echo "*** performs recommended setup steps from the SailPoint VA documents which"
echo "*** when skipped will cause network connectivity problems, and creates a"
echo "*** log file at '$LOGFILE'."
echo "*** No warranty is expressed or implied for this tool by SailPoint."
echo 

# Global vars for functions
is_canal_enabled=false

# Functions

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
  intro "$(date -u) - END TESTS for $orgname on $podname "
  echo >&2 "*** Tests completed on $(date -u) ***"
}

# args:
# $1 == IP address for canal server on SailPoint side (past the gateway)

#Handle exceptions
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
  outro
}

trap handle_interrupts SIGINT
trap 'handle_error "$BASH_COMMAND"' ERR

canalServerConnectionTest() {
  initStringOutput=$(echo -e "\x00\x0e\x38\xa3\xcf\xa4\x6b\x74\xf3\x12\x8a\x00\x00\x00\x00\x00" | ncat $1 443 | cat -v )
  initStringOutput=$(echo "$initStringOutput" | tr -d '[:space:]')
  if [[ $initStringOutput == *"^@^Z"* ]]; then
    echo -e "Testing $1: PASS" >> "$LOGFILE"
    echo -e "Testing $1: $GREEN PASS $RESETCOLOR"
  else
    echo -e "Testing $1: FAIL" >> "$LOGFILE"
    echo -e "Testing $1: $RED FAIL $RESETCOLOR"
  fi
  echo >> "$LOGFILE"
}

if test -f "$LOGFILE"; then
  echo "*** Found an old log file. Renaming..." &&
  mv $LOGFILE $LOGFILE.$DATE.old
fi

touch $LOGFILE
# Start the tests by placing a header in the logfile
echo $DIVIDER
echo "$(date -u) - STARTING TESTS for $orgname on $podname"
echo $DIVIDER
echo "$(date -u) - START TESTS for $orgname on $podname on stunt.sh $VERSION " >> "$LOGFILE"
outro

# Start update
if [ "$do_update" = true ]; then
  intro "Performing forced update - this process resets the machine-id and the update service. *REBOOTS ARE REQUIRED WHEN SUCCESSFUL*"
  sudo rm -f /etc/machine-id  >> "$LOGFILE" 2>&1
  sudo systemd-machine-id-setup  >> "$LOGFILE" 2>&1
  sudo systemctl restart update-engine  >> "$LOGFILE" 2>&1
  sudo update_engine_client -update >> "$LOGFILE" 2>&1
  outro
  endscript
  echo "EXITING"
  exit 0
fi

if [ "$curl_test" == "true" ]; then
  intro "Curl test starting"
  echo "Performing alternating curl test against S3 and SQS. This will run for $total_seconds_to_test seconds,"
  echo "and then quit automatically. Use ctrl+c to stop early."
  runme=true;
  run_sqs=true;
  now=$(date +%s) #time in seconds since epoch
  future=$(($now + $total_seconds_to_test))
  while $runme; do
    if [ "$run_sqs" == "true" ]; then
      echo $(date -u +"%b_%d_%y-%H:%M:%S") >> "$LOGFILE"
      echo "Testing connection to SQS: "
      echo "Testing connection to SQS: " >> "$LOGFILE"
      curl -i --connect-timeout $seconds_between_tests "https://sqs.us-east-1.amazonaws.com" >> "$LOGFILE"
      echo
      echo >> "$LOGFILE"
      run_sqs=false;
      sleep 4;
    else
      echo $(date -u +"%b_%d_%y-%H:%M:%S") >> "$LOGFILE"
      echo "Testing connection to S3: "
      echo "Testing connection to S3: " >> "$LOGFILE"
      curl -i --connect-timeout $seconds_between_tests "https://sppcbu-va-images.s3.amazonaws.com" >> "$LOGFILE" 
      echo
      echo >> "$LOGFILE"
      run_sqs=true;
      sleep 4;
    fi
    if [[ $(date +%s) -ge $future ]]; then
      echo "$total_seconds_to_test seconds have elapsed. Quitting..."
      outro
      endscript
      runme=false;
    fi
  done
  endscript
  exit 0
fi

# detect Canal in config.yaml
if [[ $(cat /home/sailpoint/config.yaml) == *"tunnelTraffic: true"* ]]; then
  is_canal_enabled=true
  intro "NOTE: CANAL CONFIG DETECTED"
fi

# Execute tests

intro "Getting list of files in home directory with ls -alh"
ls -alh /home/sailpoint/ >> "$LOGFILE"
outro

intro "Getting current working directory path with pwd"
expect "this to be /home/sailpoint/ but not a requirement"
pwd >> "$LOGFILE"
outro

intro "Getting config.yaml"
if [ $encrypted_keyPassphrase_length -gt 0 ]; then
  expect "the keyPassphrase encryption test to pass."
  echo -e "Testing keyPassphrase encryption: PASS" >> "$LOGFILE"
  echo -e "Testing keyPassphrase encryption: $GREEN PASS$RESETCOLOR"
  cat /home/sailpoint/config.yaml | sed "s/keyPassphrase: ':::.*/keyPassphrase: <redacted>/g" | sed "s/apiKey: .*/apiKey: <redacted>/g" >> "$LOGFILE"
else # This assumes keyPassphrase is UNENCRYPTED
  expect "problems connecting to tenant as the keyPassphrase is unencrypted. Confirm with customer via screenshare."
  echo -e "Testing keyPassphrase encryption: WARNING" >> "$LOGFILE"
  echo -e "Testing keyPassphrase encryption: $YELLOW WARNING$RESETCOLOR"
  cat /home/sailpoint/config.yaml | sed "s/keyPassphrase: .*/keyPassphrase: <REMAINS UNENECRYPTED>/g" | sed "s/apiKey: .*/apiKey: <redacted>/g" >> "$LOGFILE"
fi
key_length=$(cat /home/sailpoint/config.yaml | grep "::::" | sed "s/keyPassphrase: '//g" | sed "s/'$//gm" | wc -m)
if [[ $key_length -gt 60 ]]; then
  expect "timeouts connecting to sources when the encrypted keyPassphrase length is > 60 characters. Current length: $key_length chars"
  echo -e "Testing keyPassphrase length: FAIL" >> "$LOGFILE"
  echo -e "Testing keyPassphrase length: $RED FAIL$RESETCOLOR"
else
  echo >> "$LOGFILE"
  expect "keyPassphrase length test to pass."
  echo -e "Testing keyPassphrase length: PASS" >> "$LOGFILE"
  echo -e "Testing keyPassphrase length: $GREEN PASS$RESETCOLOR"
fi
echo -e "Curren keyPassphrase length: $key_length chars" >> "$LOGFILE"
outro

intro "Getting OS version"
expect "this section to contain 'Flatcar' and not 'CoreOS'."
uname -a >> "$LOGFILE"
outro

intro "Checking OS Uptime"
expect "this VA to have been restarted recently if it is having issues."
uptime >> "$LOGFILE"
outro 

intro "Getting environment variables"
env >> "$LOGFILE"
outro

intro "Getting OpenJDK version from ccg"
expect "this version of java to be 11.0.14 or higher and not 1.8.x"
grep -a openjdk /home/sailpoint/log/worker.log | tail -1 >> "$LOGFILE"
outro

if test -f /etc/profile.env; then
  intro "Getting profile.env"
  expect "the file to exist. If proxy is a concern, have customer confirm settings."
  cat /etc/profile.env >> "$LOGFILE" 2>&1
  outro
fi

if test -f /etc/systemd/system.conf.d/10-default-env.conf; then
  intro "Getting 10-default-env.conf"
  expect "the file to exist. If proxy is a concern, have customer confirm settings."
  cat /etc/systemd/system.conf.d/10-default-env.conf >> "$LOGFILE" 2>&1
  outro
fi

intro "Getting docker.env"
expect "proxy references in docker.env. Remove references to proxy if proxying is a concern."
cat /home/sailpoint/docker.env >> "$LOGFILE"
outro

if test -f /etc/systemd/network/static.network; then
  intro "Getting the static.network file"
  expect "individual DNS entries to be on separate lines beginning with 'DNS'."
  expect "the IP address to include CIDR notation."
  cat /etc/systemd/network/static.network >> "$LOGFILE"
  outro
fi

intro "Getting the resolv.conf file"
expect "DNS entries to match those in static.network, if it exists."
cat /etc/resolv.conf >> "$LOGFILE"
outro

if test -f /home/sailpoint/proxy.yaml; then
  intro "Getting the proxy config"
  cat /home/sailpoint/proxy.yaml >> "$LOGFILE"
  outro
fi

intro "Getting /etc/os-release info"
expect "'NAME=Flatcar Container Linux by Kinvolk'. Check that version is semi-recent: https://www.flatcar.org/releases#stable-release"
cat /etc/os-release >> "$LOGFILE"
outro

intro "Getting CPU information"
expect "the number of CPU(s) to be >= 2 CPUs. This is from AWS m4.large specs."
lscpu >> "$LOGFILE"
outro

intro "Getting total RAM"
expect "the RAM to be >= 16Gi (approx 16GB). This is from AWS m4.large specs."
free -h >> "$LOGFILE"
outro

intro "Network list for all adapters"
expect "one of two adapters to exist: ens160 or eth0."
if [ "$is_canal_enabled" = true ]; then
  expect "that tun0 exists and is routable."
fi
networkctl list >> "$LOGFILE"
outro

intro "Network information for main adapter"
expect "information from resolv.conf/static.network/etc. to match up with what you find for the main adapter"
if [[ $(networkctl list | grep ens160) == *"ens160"* ]]; then
  networkctl status ens160 >> "$LOGFILE" 2>&1
else
  networkctl status eth0 >> "$LOGFILE" 2>&1 #works as a catchall if nothing exists
fi
outro

if [ $is_canal_enabled ]; then
  expect "tun0 adapter to be in a 'routable' state, and to show the online state as 'online'."
  networkctl status tun0 >> "$LOGFILE" 2>&1
fi

intro "Getting networking check in charon.log"
expect "all services to say PASS after their name"
grep -a "Networking check" /home/sailpoint/log/charon.log | tail -1 >> "$LOGFILE"
outro

intro "Testing direct connection to regional Secure Tunnel servers"
expect "tests below to pass for every IP"
 
if [[ $podname == *"useast1"* ||  $podname == *"cook"* || $podname == *"fiji"* || $podname == *"uswest2"* || $podname == *"cacentral1"* ]]; then
  # us-east-1 podnames contain: useast1 cook fiji uswest2 cacentral1
  echo "Using us-east-1 endpoints: " >> "$LOGFILE"
  echo "Using us-east-1 endpoints: "
  canalServerConnectionTest 52.206.130.59
  canalServerConnectionTest 52.206.133.183
  canalServerConnectionTest 52.206.132.240
elif [[ $podname == *"eucentral1"* ]]; then
  # eu-central-1 podnames contain: eucentral1 
  echo "Using eu-central-1 endpoints: " >> "$LOGFILE"
  echo "Using eu-central-1 endpoints: "
  canalServerConnectionTest 35.157.132.22
  canalServerConnectionTest 35.157.185.79
  canalServerConnectionTest 35.157.251.228
elif [[ $podname == *"euwest2"* ]]; then
  #eu-west-2 podnames contain: euwest2
  echo "Using eu-west-2 endpoints: " >> "$LOGFILE"
  echo "Using eu-west-2 endpoints: "
  canalServerConnectionTest 18.130.210.174
  canalServerConnectionTest 18.130.148.201
  canalServerConnectionTest 35.178.220.78
elif [[ $podname == *"apsoutheast2"* ]]; then
  #apac podnames contain: apsoutheast2
  echo "Using ap-southeast-2 endpoints: " >> "$LOGFILE"
  echo "Using ap-southeast-2 endpoints: "
  canalServerConnectionTest 52.65.42.92
  canalServerConnectionTest 13.55.78.212
  canalServerConnectionTest 3.24.127.50
else
  echo "Unable to find appropriate canal server test with podname: $podname" >> "$LOGFILE"
fi
outro

if [[ "$check_openssl_cert" == true ]]; then
  intro "Checking openssl cert chain with connection to sqs (this may take a moment; please be patient)"
  expect "no self-signed certificates - these can cause all sources to disconnect, and some/all charon tests above to fail."
  openssl s_client -connect sqs.us-east-1.amazonaws.com:443 >> "$LOGFILE" 2>&1
  outro

  #intro "Check custom certs against openssl"
  ### TODO ###
  #outro
fi

intro "Getting contents of /etc/hosts from host"
expect "entries to match the /etc/hosts from ccg in the next section."
cat /etc/hosts >> "$LOGFILE"
outro

intro "Getting contents of /etc/hosts from ccg container."
sudo docker exec ccg cat /etc/hosts >> "$LOGFILE" 2>&1
outro

intro "Getting contents of /opt/sailpoint/ccg/lib/custom from ccg container"
expect "JDBC driver jar files. Make sure they are populating here if required."
sudo docker exec ccg ls -l /opt/sailpoint/ccg/lib/custom >> "$LOGFILE" 2>&1
outro

intro "This step disables esx_dhcp_bump"
expect "any output stating this was removed/disabled. If there is, be sure to do a sudo reboot."
sudo systemctl disable esx_dhcp_bump >> "$LOGFILE" 2>&1
outro

intro "Get list of all SSL certs in /home/sailpoint/certificates"
ls -alh /home/sailpoint/certificates >> "$LOGFILE" 2>&1
outro

intro "This step updates all of the SSL certificates"
expect "this section to be blank; we only catch errors here."
sudo /usr/sbin/update-ca-certificates > /dev/null 2>> "$LOGFILE" # stdout to /dev/null, catch only errors
outro

intro "Get list of all SSL certs in /etc/ssl/certs"
expect "updated date for most certs to be today's date due to the script above (update-ca-certificates)."
ls -alh /etc/ssl/certs >> "$LOGFILE" 2>&1
outro

intro "External connectivity: Connection test for SQS (https://sqs.us-east-1.amazonaws.com)"
expect "a verbose response, and a result of 404."
curl -i -vv --connect-timeout 10 "https://sqs.us-east-1.amazonaws.com" >> "$LOGFILE" 2>&1
outro

intro "External connectivity: Connection test for https://$orgname.identitynow.com"
expect "a result of 302 - may fail to complete if this is a vanity org."
curl -i --connect-timeout 10 "https://$orgname.identitynow.com" >> "$LOGFILE" 2>&1
outro

intro "External connectivity: Connection test for https://$orgname.api.identitynow.com"
expect "a result of 404 - may fail to complete if this is a vanity org."
curl -i --connect-timeout 10 "https://$orgname.api.identitynow.com" >> "$LOGFILE" 2>&1
outro

intro "External connectivity: Connection test for https://$podname.accessiq.sailpoint.com"
expect "a result of 302"
curl -i --connect-timeout 10 "https://$podname.accessiq.sailpoint.com" >> "$LOGFILE" 2>&1
outro

intro "External connectivity: Connection test for DynamoDB (https://dynamodb.us-east-1.amazonaws.com)."
expect "a result of 200"
curl -i --connect-timeout 10 "https://dynamodb.us-east-1.amazonaws.com" >> "$LOGFILE" 2>&1
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
  ping -c 5 -W 2 $orgname.identitynow.com >> "$LOGFILE"
  outro
fi

if [ "$do_traceroute" = true ]; then
  intro "Collecting traceroute to SQS... (this may take a moment; please be patient)"
  traceroute sqs.us-east-1.amazonaws.com >> "$LOGFILE"
  outro
fi

intro "Getting additional routing information from ip route show"
ip route show >> "$LOGFILE"
outro

# Only gather log snippets if we're not getting all logs via -l switch
if [[ "$gather_logs" != true ]]; then
  intro "Getting ccg.log errors - latest 30 errors"
  expect "recent datestamps. Some logs might be old and no longer pertinent. Expect no errors for keystore.jks which usually signifies a keyPassphrase issue."
  cat /home/sailpoint/log/ccg.log | grep stacktrace | tail -n30 >> "$LOGFILE" 2>&1
  outro
fi

intro "Getting docker images"
expect "the CCG image to be updated: it should be less than 3 weeks old."
sudo docker images >> "$LOGFILE"
outro

intro "Getting docker processes"
expect "the following four (4) processes to be running: ccg, va_agent, charon, and va."
sudo docker ps >> "$LOGFILE"
outro

intro "Getting systemd service configuration file: charon"
expect "the file to exist, and contains a valid docker ECR address compared to the docker images list above."
cat /etc/systemd/system/charon.service >> "$LOGFILE"
outro

intro "Getting systemd service configuration file: ccg"
expect "the file to exist, and contains a valid docker ECR address compared to the docker images list above."
cat /etc/systemd/system/ccg.service >> "$LOGFILE"
outro

intro "Getting systemd service configuration file: va_agent"
expect "the file to exist, and contains a valid docker ECR address compared to the docker images list above."
cat /etc/systemd/system/va_agent.service >> "$LOGFILE"
outro

intro "Getting systemd service configuration file: fluent"
expect "the file to exist, and contains a valid docker ECR address compared to the docker images list above."
cat /etc/systemd/system/fluent.service >> "$LOGFILE"
outro

intro "Getting systemd service configuration file: relay"
expect "the file to exist, and contains a valid docker ECR address compared to the docker images list above."
cat /etc/systemd/system/relay.service >> "$LOGFILE"
outro

intro "Getting systemd service configuration file: toolbox"
expect "the file to exist, and contains a valid docker ECR address compared to the docker images list above."
cat /etc/systemd/system/toolbox.service >> "$LOGFILE"
outro

if [ "$is_canal_enabled" = true ]; then
  intro "Getting systemd service configuration file: canal"
  expect "the file to exist, and contains a valid docker ECR address compared to the docker images list above."
  cat /etc/systemd/system/canal.service >> "$LOGFILE"
  outro
fi

if test -f /etc/systemd/system/esx_dhcp_bump.service; then
  intro "Getting systemd service configuration file: esx_dhcp_bump"
  cat /etc/systemd/system/esx_dhcp_bump.service >> "$LOGFILE"
  outro
fi

intro "Getting partition table info"
expect "total disk space under \"SIZE\". Should be ~128GB or more."
expect "one sda<#> to be TYPE 'part' and RO '0'. This means the PARTition is writable."
lsblk -o NAME,SIZE,FSSIZE,FSAVAIL,FSUSE%,MOUNTPOINT,TYPE,RO >> "$LOGFILE"
outro

intro "Getting disk usage stats"
df -h >> "$LOGFILE"
outro

intro "Getting disk usage paths"
expect "sda9 to be less than 15% full. More likely means a debug setting was enabled long-term."
du -h /home/sailpoint/ >> "$LOGFILE"
outro

intro "Getting list of large files"
expect "most files to be less than 1MB. Log files can be significantly larger, but shouldn't exceed 1GB each."
find /home/sailpoint/ -xdev -type f -size +100M -print | xargs ls -lh | sort -k5,5 -h -r >> "$LOGFILE"
outro

intro "Getting jobs list"
expect "this to be (almost) empty. If lots of jobs are > 1 week old, run: sudo rm -rf /opt/sailpoint/share/jobs/* && sudo reboot"
ls -l /opt/sailpoint/share/jobs/ >> "$LOGFILE"
outro

if [ "$is_canal_enabled" = true ]; then
  intro "*** The following tests and data gathering are only run if Secure Tunnel config has been enabled"
  echo
  intro "Getting the canal config file @/opt/sailpoint/share/canal/client.conf"
  cat /opt/sailpoint/share/canal/client.conf >> "$LOGFILE"
  outro

  intro "Checking ccg.log for successful canal setup"
  expect "this to contain something like 'Job SERVICE_SETUP fluent/ccg/relay/canal has FINISHED - result: SUCCESS'"
  grep -e "SUCCESS" -e "canal" /home/sailpoint/log/charon.log | tail -n1 >> "$LOGFILE"
  outro

  intro "Getting last 50 lines of canal service journal logs"
  sudo journalctl --no-pager -n50 -u canal >> "$LOGFILE" 
  outro
  
  echo "*** Completed gathering extra data from Canal config."
  echo 
fi

intro "Getting last 50 lines of kernel journal logs"
sudo journalctl --no-pager -n50 -k >> "$LOGFILE"
outro

intro "Getting last 50 lines of network journal logs"
sudo journalctl --no-pager -n50 -u systemd-networkd >> "$LOGFILE"
outro

intro "Getting last 50 lines of ccg journal logs"
sudo journalctl --no-pager -n50 -u ccg >> "$LOGFILE"
outro

intro "Getting last 50 lines of va_agent journal logs"
sudo journalctl --no-pager -n50 -u va_agent >> "$LOGFILE"
outro

intro "Getting last 50 lines of otel_agent journal logs"
sudo journalctl --no-pager -n50 -u otel_agent >> "$LOGFILE"
outro

endscript

if [ "$gather_logs" = true ]; then
  # Get list of files in log directory just in case we need more than these specific files
  intro "Gathering all log files and zipping."
  echo
  echo "*** NOTE: This file might be large depending on the life of your VA. ***"
  echo
  tar -czvf $ZIPFILE $LOGFILE $LISTOFLOGS
  echo "Zipped to $ZIPFILE"
  echo "Zipped to $ZIPFILE" >> $LOGFILE
  outro
fi

echo $DIVIDER
if [ "$gather_logs" = true ]; then
  echo
  echo "*** RETRIEVE THE ZIPPED FILE WITHOUT RENAMING:"
  echo "*** ${ZIPFILE} "
  echo "*** AND UPLOAD TO YOUR CASE."
  echo
  echo "We recommend use of the scp tool from a Linux/Mac/PuTTY shell to retrieve the tar.gz file from"
  echo "this server. Use the line created for you below at your local machine's terminal:"
  echo
  echo "scp sailpoint@$ipaddr:$ZIPFILE ./"
else
  echo
  echo "*** RETRIEVE THE FILE WITHOUT RENAMING:"
  echo "*** ${LOGFILE} "
  echo "*** AND UPLOAD TO YOUR CASE."
  echo
  echo "We recommend use of the scp tool from a Linux/Mac/PuTTY shell to retrieve the tar.gz file from"
  echo "this server. Use the line created for you below at your local machine's terminal:"
  echo
  echo "scp sailpoint@$ipaddr:$LOGFILE ./"
fi
