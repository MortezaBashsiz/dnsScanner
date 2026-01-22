#!/bin/bash  -
#===============================================================================
#
#          FILE: dnsScanner.sh
#
#         USAGE: ./dnsScanner.sh [Argumets]
#
#   DESCRIPTION: Scan subnets to find dns servers
#
#       OPTIONS: -h, --help
#  REQUIREMENTS: getopt, jq, git, tput, bc, curl, parallel (version > 20220515), shuf
#        AUTHOR: Morteza Bashsiz (mb), morteza.bashsiz@gmail.com
#  ORGANIZATION: Linux
#       CREATED: 19/01/2026 15:36:57 PM
#      CONTRIBUTORS: MortezaBashsiz 
#===============================================================================

export TOP_PID=$$

# Function fncLongIntToStr
# converts IP in long integer format to a string 
fncLongIntToStr() {
    local IFS=. num quad ip e
    num=$1
    for e in 3 2 1
    do
        (( quad = 256 ** e))
        (( ip[3-e] = num / quad ))
        (( num = num % quad ))
    done
    ip[3]=$num
    echo "${ip[*]}"
}
# End of Function fncLongIntToStr

# Function fncIpToLongInt
# converts IP to long integer 
fncIpToLongInt() {
    local IFS=. ip num e
    # shellcheck disable=SC2206
    ip=($1)
    for e in 3 2 1
    do
        (( num += ip[3-e] * 256 ** e ))
    done
    (( num += ip[3] ))
    echo $num
}
# End of Function fncIpToLongInt

# Function fncSubnetToIP
# converts subnet to IP list
fncSubnetToIP() {
  # shellcheck disable=SC2206
  local network=(${1//\// })
  # shellcheck disable=SC2206
  local iparr=(${network[0]//./ })
  local mask=32
  [[ $((${#network[@]})) -gt 1 ]] && mask=${network[1]}

  local maskarr
  # shellcheck disable=SC2206
  if [[ ${mask} = '\.' ]]; then  # already mask format like 255.255.255.0
    maskarr=(${mask//./ })
  else                           # assume CIDR like /24, convert to mask
    if [[ $((mask)) -lt 8 ]]; then
      maskarr=($((256-2**(8-mask))) 0 0 0)
    elif  [[ $((mask)) -lt 16 ]]; then
      maskarr=(255 $((256-2**(16-mask))) 0 0)
    elif  [[ $((mask)) -lt 24 ]]; then
      maskarr=(255 255 $((256-2**(24-mask))) 0)
    elif [[ $((mask)) -lt 32 ]]; then
      maskarr=(255 255 255 $((256-2**(32-mask))))
    elif [[ ${mask} == 32 ]]; then
      maskarr=(255 255 255 255)
    fi
  fi

  # correct wrong subnet masks (e.g. 240.192.255.0 to 255.255.255.0)
  [[ ${maskarr[2]} == 255 ]] && maskarr[1]=255
  [[ ${maskarr[1]} == 255 ]] && maskarr[0]=255

  # generate list of ip addresses
  if [[ "$randomNumber" != "NULL" ]]
  then
    local bytes=(0 0 0 0)
    for i in $(seq 0 $((255-maskarr[0]))); do
      bytes[0]="$(( i+(iparr[0] & maskarr[0]) ))"
      for j in $(seq 0 $((255-maskarr[1]))); do
        bytes[1]="$(( j+(iparr[1] & maskarr[1]) ))"
        for k in $(seq 0 $((255-maskarr[2]))); do
          bytes[2]="$(( k+(iparr[2] & maskarr[2]) ))"
          for l in $(seq 1 $((255-maskarr[3]))); do
            bytes[3]="$(( l+(iparr[3] & maskarr[3]) ))"
            ipList+=("$(printf "%d.%d.%d.%d" "${bytes[@]}")")
          done
        done
      done
    done
    # Choose random IP addresses from generated IP list
    mapfile -t ipList < <(shuf -e "${ipList[@]}")
    mapfile -t ipList < <(shuf -e "${ipList[@]:0:$randomNumber}")
    for i in "${ipList[@]}"; do 
      echo "$i"
    done
  elif [[ "$randomNumber" == "NULL" ]]
  then
    local bytes=(0 0 0 0)
    for i in $(seq 0 $((255-maskarr[0]))); do
      bytes[0]="$(( i+(iparr[0] & maskarr[0]) ))"
      for j in $(seq 0 $((255-maskarr[1]))); do
        bytes[1]="$(( j+(iparr[1] & maskarr[1]) ))"
        for k in $(seq 0 $((255-maskarr[2]))); do
          bytes[2]="$(( k+(iparr[2] & maskarr[2]) ))"
          for l in $(seq 1 $((255-maskarr[3]))); do
            bytes[3]="$(( l+(iparr[3] & maskarr[3]) ))"
            printf "%d.%d.%d.%d\n" "${bytes[@]}"
          done
        done
      done
    done
  fi
}
# End of Function fncSubnetToIP

# Function fncShowProgress
# Progress bar maker function (based on https://www.baeldung.com/linux/command-line-progress-bar)
function fncShowProgress {
  barCharDone="="
  barCharTodo=" "
  barSplitter='>'
  barPercentageScale=2
  current="$1"
  total="$2"

  barSize="$(($(tput cols)-70))" # 70 cols for description characters

  # calculate the progress in percentage 
  percent=$(bc <<< "scale=$barPercentageScale; 100 * $current / $total" )
  # The number of done and todo characters
  done=$(bc <<< "scale=0; $barSize * $percent / 100" )
  todo=$(bc <<< "scale=0; $barSize - $done")
  # build the done and todo sub-bars
  doneSubBar=$(printf "%${done}s" | tr " " "${barCharDone}")
  todoSubBar=$(printf "%${todo}s" | tr " " "${barCharTodo} - 1") # 1 for barSplitter
  spacesSubBar=$(printf "%${todo}s" | tr " " " ")

  # output the bar
  progressBar="| Progress bar of main IPs: [${doneSubBar}${barSplitter}${todoSubBar}] ${percent}%${spacesSubBar}" # Some end space for pretty formatting
}
# End of Function showProgress

# Function fncCheckIPList
# Check Subnet
function fncCheckIPList {
  local ipList resultFile domain dnsTypeLocal randomSubdomainFlagLocal queryDomain randLabel
  ipList="${1}"
  resultFile="${3}"
  domain="${4}"
  dnsTypeLocal="${5:-TXT}"
  randomSubdomainFlagLocal="${6:-0}"

  # set proper command for linux
  if command -v timeout >/dev/null 2>&1; 
  then
      timeoutCommand="timeout"
  else
    # set proper command for mac
    if command -v gtimeout >/dev/null 2>&1; 
    then
        timeoutCommand="gtimeout"
    else
        echo >&2 "I require 'timeout' command but it's not installed. Please install 'timeout' or an alternative command like 'gtimeout' and try again."
        exit 1
    fi
  fi
  for ip in ${ipList}
    do
      queryDomain="$domain"
      if [[ "$randomSubdomainFlagLocal" == "1" ]]; then
        # generate a random label to avoid DNS caching; use /dev/urandom when available, fall back to $RANDOM
        if command -v tr >/dev/null 2>&1; then
          randLabel=$(tr -dc 'a-z0-9' </dev/urandom 2>/dev/null | head -c 8)
        fi
        if [[ -z "$randLabel" ]]; then
          randLabel="${RANDOM}${RANDOM}"
        fi
        queryDomain="${randLabel}.${domain}"
      fi
      result=$("$timeoutCommand" 1 dig +short @"$ip" "$queryDomain" "$dnsTypeLocal" 2>&1)
      # check if result is non-empty and doesn't contain error messages
      if [[ -n "$result" ]] && [[ ! "$result" =~ "no servers could be reached" ]] && [[ ! "$result" =~ "communications error" ]]; then
        echo -e "$ip"
        echo -e "$ip" >> "$resultFile"
      fi
  done
}
# End of Function fncCheckIPList
export -f fncCheckIPList

# Function fncCheckDpnd
# Check for dipendencies
function fncCheckDpnd {
  command -v jq >/dev/null 2>&1 || { echo >&2 "I require 'jq' but it's not installed. Please install it and try again."; kill -s 1 "$TOP_PID"; }
  command -v parallel >/dev/null 2>&1 || { echo >&2 "I require 'parallel' but it's not installed. Please install it and try again."; kill -s 1 "$TOP_PID"; }
  command -v bc >/dev/null 2>&1 || { echo >&2 "I require 'bc' but it's not installed. Please install it and try again."; kill -s 1 "$TOP_PID"; }
  command -v timeout >/dev/null 2>&1 || { echo >&2 "I require 'timeout' but it's not installed. Please install it and try again."; kill -s 1 "$TOP_PID"; }
}
# End of Function fncCheckDpnd

# Function fncCreateDir
# creates needed directory
function fncCreateDir {
  local dirPath
  dirPath="${1}"
  if [ ! -d "$dirPath" ]; then
    mkdir -p "$dirPath"
  fi
}
# End of Function fncCreateDir

# Function fncMainCFFindSubnet
# main Function for Subnet
function fncMainCFFindSubnet {
  local threads progressBar resultFile subnetsFile breakedSubnets network netmask 
  threads="${1}"
  progressBar="${2}"
  resultFile="${3}"
  subnetsFile="${4}"
  local dnsTypeLocal="${5:-TXT}"
  local randomSubdomainFlagLocal="${6:-0}"

  if [[ "$subnetsFile" == "NULL" ]] 
  then
    echo "Specify subnet file"
    exit 0
  else
    echo "Reading subnets from file $subnetsFile"
    dnsSubnetList=$(cat "$subnetsFile")
  fi
  
  ipListLength="0"
  for subNet in ${dnsSubnetList}
  do
    breakedSubnets=
    maxSubnet=24
    network=${subNet%/*}
    netmask=${subNet#*/}
    if [[ ${netmask} -ge ${maxSubnet} ]]
    then
      breakedSubnets="${breakedSubnets} ${network}/${netmask}"
    else
      for i in $(seq 0 $(( $(( 2 ** (maxSubnet - netmask) )) - 1 )) )
      do
        breakedSubnets="${breakedSubnets} $( fncLongIntToStr $(( $( fncIpToLongInt "${network}" ) + $(( 2 ** ( 32 - maxSubnet ) * i )) )) )/${maxSubnet}"
      done
    fi
    breakedSubnets=$(echo "${breakedSubnets}"|tr ' ' '\n')
    for breakedSubnet in ${breakedSubnets}
    do
      ipListLength=$(( ipListLength+1 ))
    done
  done

  passedIpsCount=0
  for subNet in ${dnsSubnetList}
  do
    breakedSubnets=
    maxSubnet=24
    network=${subNet%/*}
    netmask=${subNet#*/}
    if [[ ${netmask} -ge ${maxSubnet} ]]
    then
      breakedSubnets="${breakedSubnets} ${network}/${netmask}"
    else
      for i in $(seq 0 $(( $(( 2 ** (maxSubnet - netmask) )) - 1 )) )
      do
        breakedSubnets="${breakedSubnets} $( fncLongIntToStr $(( $( fncIpToLongInt "${network}" ) + $(( 2 ** ( 32 - maxSubnet ) * i )) )) )/${maxSubnet}"
      done
    fi
    breakedSubnets=$(echo "${breakedSubnets}"|tr ' ' '\n')
    for breakedSubnet in ${breakedSubnets}
    do
      fncShowProgress "$passedIpsCount" "$ipListLength"
      ipList=$(fncSubnetToIP "$breakedSubnet")
      tput cuu1; tput ed # rewrites Parallel's bar
      #echo -e "${RED}$progressBar${NC}"
      parallel --ll --bar -j "$threads" fncCheckIPList ::: "$ipList" ::: "$progressBar" ::: "$resultFile" ::: "$domain" ::: "$dnsTypeLocal" ::: "$randomSubdomainFlagLocal"
      killall v2ray > /dev/null 2>&1
      passedIpsCount=$(( passedIpsCount+1 ))
    done
  done
  sort -n -k1 -t, "$resultFile" -o "$resultFile"
}
# End of Function fncMainCFFindSubnet

clientConfigFile="NULL"
subnetIPFile="NULL"

# Function fncUsage
# usage function
function fncUsage {
  echo -e "Usage: dnsScanner
    [ -p|--thread <int> ]
    [ -f|--file <string> ]
    [ -d|--domain <string> ]
    [ -t|--type <string> ]
    [ -r|--random-subdomain ]
    [ -h|--help ]\n
  DNS type examples: A, AAAA, NS, TXT, MX (default: TXT)
  -r, --random-subdomain : prepend a random label to the domain (e.g. <random>.example.com) to avoid DNS caching when you have a wildcard rule\n"
  exit 2
}
# End of Function fncUsage

threads="4"
dnsType="TXT"
randomSubdomainFlag="0"

parsedArguments=$(getopt -a -n dnsScanner -o p:f:d:t:hr --long thread:,file:,domain:,type:,help,random-subdomain -- "$@")

eval set -- "$parsedArguments"
while :
do
  case "$1" in
    -p|--thread) threads="$2" ; shift 2 ;;
    -f|--file) subnetIPFile="$2" ; shift 2 ;;
    -d|--domain) domain="$2" ; shift 2 ;;
    -t|--type) dnsType="$2" ; shift 2 ;;
    -r|--random-subdomain) randomSubdomainFlag="1" ; shift ;;
    -h|--help) fncUsage ;;
    --) shift; break ;;
    *) echo "Unexpected option: $1 is not acceptable"
    fncUsage ;;
  esac
done

validArguments=$?
if [ "$validArguments" != "0" ]; then
  echo "error validate"
  exit 2
fi

if [[ "$subnetIPFile" != "NULL" ]]
then
  if ! [[ -f "$subnetIPFile" ]]
  then
    echo "file does not exists: $subnetIPFile"
    exit 1
  fi
fi

now=$(date +"%Y%m%d-%H%M%S")
scriptDir=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
resultDir="$scriptDir/result"
resultFile="$resultDir/$now.txt"

progressBar=""
randomNumber="NULL"
export GREEN='\033[0;32m'
export BLUE='\033[0;34m'
export RED='\033[0;31m'
export ORANGE='\033[0;33m'
export YELLOW='\033[1;33m'
export NC='\033[0m'

fncCreateDir "${resultDir}"
echo "" > "$resultFile"

fncMainCFFindSubnet "$threads" "$progressBar" "$resultFile" "$subnetIPFile" "$dnsType" "$randomSubdomainFlag"
