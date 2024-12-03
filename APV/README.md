# APV
```    ___    ____ _    __
   /   |  / __ \ |  / /
  / /| | / /_/ / | / /
 / ___ |/ ____/| |/ /
/_/  |_/_/     |___/


Welcome to APV! Starting up...

usage: apv.py [-h] -d DOMAIN -u USERNAME -p PASSWORD

options:
  -h, --help            show this help message and exit
  -d DOMAIN, --domain DOMAIN
                        Domain to target
  -u USERNAME, --username USERNAME
                        Username to use
  -p PASSWORD, --password PASSWORD
                        Password to use
  -i IPADDRESS, --ipaddress IPADDRESS
                        IP address to use
  -per, --permission    Running APV-Permission
  -ser, --service       Running APV-Service
  -op [OUTPUT_PERMISSION], --output_permission [OUTPUT_PERMISSION]
                        Specify the output APV_Permission file
  -os [OUTPUT_SERVICE], --output_service [OUTPUT_SERVICE]
                        Specify the output APV_Permission file
```

## Install 
```git clone``` this repository
```
git clone https://github.com/dotienduc113/APV
```
Requirement: Using Python3 and install all required dependencies
```commandline
pip install -r requirements.txt
```

## Basic Command
1. Running both APV-Permission and APV-Service
```apv.py -d [DOMAIN] -u [USERNAME] -p [PASSWORD] -i [IPADDRESS]```
2. Running APV Permission
```apv.py -d [DOMAIN] -u [USERNAME] -p [PASSWORD] -per -op [OUTPUT_PERMISSION]```
3. Running APV Service
```apv.py -d [DOMAIN] -u [USERNAME] -p [PASSWORD] -i [IPADDRESS] -ser -os [OUTPUT_SERVICE]```