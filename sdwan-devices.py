#!/usr/bin/env python3

# This script get's a list of ISR 1100 routers from vManage to perform the following check
# Is port G0/1/0 active and is G0/1/03 admin down? if G0/1/3 is not admin downt then the provisioning ports need shutting down for this site

# This library hides sensitive input and replaces it with another character; default *
from pwinput import pwinput


# SSH library
from netmiko import ConnectHandler

# Cisco SDK for Catlayst SDWAN
from catalystwan.session import create_manager_session
from catalystwan.utils.alarm_status import Severity
from catalystwan.utils.personality import Personality
from catalystwan.utils.dashboard import HealthColor
from catalystwan.exceptions import (
    DefaultPasswordError,
    ManagerHTTPError,
    ManagerReadyTimeout,
    ManagerRequestException,
    SessionNotCreatedError,
    TenantSubdomainNotFound,
)


# Standard libraries
from pprint import pprint
import urllib3
import sys

username = input("Enter your vManage username: ")
password = pwinput("Enter your vManage password: ")

ciscouser = input("\nEnter your ISE username: ")
ciscopass = pwinput("Enter your ISE password: ")

proceed = input("\nNOTE: Ensure you have an active VPN connection for management before proceeding [ENTER]:")


base_url = "https://vmanage-171203704.sdwan.cisco.com/"

# Disable insecure wanring due to self signed cert on SDWAN manager
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

print(f"\nConnecting to vManage...\n")

# Create SDWAN Manager session
try:
    session = create_manager_session(url=base_url, username=username, password=password)
except ManagerHTTPError as error:
    # Error processing
    print(error.response.status_code)
    print(error.info.code)
    print(error.info.message)
    print(error.info.details)

# Get devices and filter on EDGES, then loop through and pick out the 1100s used for NGN (1127 and 1161)

print("\fChecking devices...\n\n")

devices = session.api.devices.get()
routers = devices.filter(personality=Personality.EDGE)

change_required = []

for router in routers:
    if "1127" in router.uuid or "1161" in router.uuid:
        if "UNREACHABLE" in router.reachability: continue
        systemip = router.id
        hostname = router.hostname
        serial = router.uuid.split("-")[-1]
        print(f"{systemip:<20}{hostname:<35}{'Connecting...'}")
        try:
            ssh_connect = ConnectHandler(host=systemip, username=ciscouser, password=ciscopass, device_type="cisco_ios")
      
        # Some error
        except Exception as e:
            print(f"An error occurred: {str(e)}")
            continue
    

        interface_status = ssh_connect.send_command("show interface status",use_textfsm=True)
        #print(f'{interface_status[0]["port"]} {interface_status[0]["status"]}')
        #print(f'{interface_status[4]["port"]} {interface_status[3]["status"]}')
        if interface_status[0]["status"] == "connected":
            if interface_status[4]["status"] != "disabled":
                print(f"{serial:<55}{'Needs ports disabling'}")
                change_required.append(serial)
        ssh_connect.disconnect()
    
# Close the vManage session

print("\nClosing the vManage session")

session.close()

# Print device serials requiring change

change_required = set(change_required)

if not change_required:
    print("No changes required!")
    sys.exit()

print("\nThe following serial numbers need the provision ports disabling:\n\n")
for serial in change_required:
    print(serial)