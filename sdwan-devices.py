#!/usr/bin/env python3

# This script get's a list of ISR 1100 routers from vManage to perform the following check
# Is port G0/1/0 active and is G0/1/0/4 admin down? if G0/1/4 is not admin downt then the provisioning ports need shutting down for this site

# This library hides sensitive input and replaces it with another character; default *
from pwinput import pwinput


# SSH library
from netmiko import ConnectHandler,NetmikoTimeoutException

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
import logging

def qosreport(routers):

    logging.basicConfig(filename="netmiko.log", level=logging.DEBUG)
    logger = logging.getLogger("netmiko")
    
    shaperdict = {}
    shaperdict["hostname"] = []
    shaperdict["postcode"] = []
    shaperdict["ip"] = []
    shaperdict["shaperate"] = []
    shaperdict["downstream"] = []
    shaperdict["live"] = []

    total_devices = 0

    try:
        n2r1_ssh_connect = ConnectHandler(host="172.31.232.9", username=ciscouser, password=ciscopass, device_type="cisco_ios")
	# Some error
    except Exception as e:
        print(f"An error occurred: {str(e)}")

    for router in routers:
        reachable=str(router.reachability)
        systemip = router.id
        hostname = router.hostname

        total_devices = total_devices + 1
        
        if "UNREACHABLE" in reachable:
            print(f"{systemip:<20}{hostname:<35}{'Device offline - Skipping'}")
            continue

        print(f"{systemip:<20}{hostname:<35}{'Connecting...'}")
        
        try:
            ssh_connect = ConnectHandler(host=systemip, username=ciscouser, password=ciscopass, device_type="cisco_ios")
		# Some error
        except Exception as e:
            print(f"An error occurred: {str(e)}")
            continue
        
        # check if router is "live" - only works for 1100 series

        if "1127" in router.uuid or "1161" in router.uuid or "1117" in router.uuid:
            interface_status = ssh_connect.send_command("show interface status",use_textfsm=True)
            if interface_status[0]["status"] == "connected" or interface_status[1]["status"] =="connected":
                shaperdict["live"].append("Live")
            else:
                shaperdict["live"].append("Not Live")
        else:
            shaperdict["live"].append("na")
        
        # Get downstream bandwith
        # Log into a headend and get the bandwidth from there as it is requested by the spoke
        # for this we need the WAN IP

        # get WAN IP
        ceftext = ssh_connect.send_command("sh ip cef 0.0.0.0/0 | inc nexthop",use_textfsm=False)
        wanif = (ceftext.split(" ")[-1])
        protocoltext = ssh_connect.send_command("sh prot "+wanif+" | inc Internet address",use_textfsm=False)
        protocoltext = protocoltext.split("/")[0]
        wanip = protocoltext.split(" ")[-1]
        # we do not want to check tloc interface as the private IP wont exist on the hub and when we check the other router for this site the shaper will be checked then
        if "192.168.12" in wanip:
            wanif = (ceftext.split(" ")[-5].split())[0]
            protocoltext = ssh_connect.send_command("sh prot "+wanif+" | inc Internet address",use_textfsm=False)
            protocoltext = protocoltext.split("/")[0]
            wanip = protocoltext.split(" ")[-1]

        # connect to a hub and read the downstream bandwidth that was requested
        hubqostext = n2r1_ssh_connect.send_command("sh platform software sdwan qos target | inc " + wanip,use_textfsm=False)
        # remove trailing spaces
        hubqostext=hubqostext.strip()
        
        if len(hubqostext) == 0:
            shaperdict["downstream"].append("---")
        else:    
            downrate = int(int(hubqostext.split(" ")[-1])/1000)
            shaperdict["downstream"].append(str(downrate))
        
        shapertext = ssh_connect.send_command("sh policy-map int output | inc target shape rate",use_textfsm=False)
        if len(shapertext) == 0:
			# no shaper
            shaperdict["hostname"].append(hostname)
            try:
                postcode = hostname.split("-")[3]
            except IndexError:
                postcode = "unknown"
            shaperdict["postcode"].append(postcode)
            shaperdict["ip"].append(systemip)
            shaperdict["shaperate"].append("---")
            continue

        shaperate = int(shapertext.split("target shape rate ")[1])
        shaperate = int(shaperate/1000000)
        #if shaperate > 100: continue

        # shaperate is 100Mb or less so collect additional info
        # print(f"{shaperate}Mb")
        shaperdict["hostname"].append(hostname)
        postcode = hostname.split("-")[3]
        shaperdict["postcode"].append(postcode)
        shaperdict["ip"].append(systemip)
        shaperdict["shaperate"].append(shaperate)

        
        # get downstream bandwidth - this caused frequent timeout failures
        # netmiko.exceptions.ReadTimeout: 
        # Pattern not detected: 'SC\\-3\\-0124\\-SE78EX\\-R1\\#' in output. (checked log and it was there)
        #
        #try:
        #    downstreamtext = ssh_connect.send_command("sh sdwan run | inc downst",read_timeout=30,use_textfsm=False)
        #except NetmikoTimeoutException:
        #    shaperdict["downstream"].append("timeout")
        #   continue
        


    print(f"\nTotal devices (including unreacahble): {total_devices}")        

    print("\nThe following shapers are deployed:\n\n")

    print(f'{"ip":<20}{"hostname":<35}{"postcode":<10}{"up":<5}{"down":<5}{"live"}\n')

    for index in range(len(shaperdict["hostname"])):
        print(f'{shaperdict["ip"][index]:<20}{shaperdict["hostname"][index]:<35}{shaperdict["postcode"][index]:<10}{shaperdict["shaperate"][index]:<5}{shaperdict["downstream"][index]:<5}{shaperdict["live"][index]}')

            

def disableportscheck(routers):
    
    change_required = []
    total_devices = 0

    print("\fChecking devices to see if ports need disabling...\n\n")

    for router in routers:
        if "1127" in router.uuid or "1161" in router.uuid:
            reachable=str(router.reachability)
            systemip = router.id
            hostname = router.hostname
            serial = router.uuid.split("-")[-1]
            total_devices = total_devices + 1
            if "UNREACHABLE" in reachable:
                print(f"{systemip:<20}{hostname:<35}{'Device offline - Skipping'}")
                continue
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

    # Print device serials requiring change

    change_required = set(change_required)

    print(f"\nTotal devices 1127 and 1161 only (including unreacahble): {total_devices}") 

    if not change_required:
        print("No changes required!")

    if change_required:
        print("\nThe following serial numbers need the provision ports disabling:\n\n")
        for serial in change_required:
            print(serial)

username = input("Enter your vManage username: ")
password = pwinput("Enter your vManage password: ")

ciscouser = input("\nEnter your ISE username: ")
ciscopass = pwinput("Enter your ISE password: ")

proceed = input("\nNOTE: Ensure you have an active VPN connection for management before proceeding [ENTER]: ")


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

devices = session.api.devices.get()
routers = devices.filter(personality=Personality.EDGE)

while True:
    print("\n\nUtility for interacting with devices in vManage")
    print("-----------------------------------------------\n")
    print("[1] Check for provisoning ports that should be disabled")
    print("[2] List shapers and downstream bandwidth for all routers")
    print("[3] Exit this utility")
    try:
        choice = int(input("\n Please select an option and press [ENTER]: "))
    except ValueError:
        print("\nPick something :)\n\n\n")
        continue

    print("\n")

    if choice == 1:
        disableportscheck(routers)
    
    if choice ==2:
        qosreport(routers)

    if choice == 3:
    # Close the vManage session

        print("Closing the vManage session")
        session.close()
        sys.exit()