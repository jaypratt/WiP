#!/usr/bin/python3
# -*- coding: utf-8 -*-

''' Pull Device information from JamfPro into a csv

We access the Jamf Pro API endpoint:
* computers-inventory

After identifying the variables that we want to collect, we will assign them variables that we will use throughout
the rest of the script. Once they are all assigned, we will run an "if statement" to see which ones are running a 
version that is no longer supported, in this current case, Catalina and before. You can change the os version later
on to adjust for future EoL devices. You will need to look at Mac's website to research if the device model can support
any more updates, and if not, it is then considered EoL.

API Documentation
* https://developer.jamf.com/jamf-pro/reference/get_v1-computers-inventory
* https://usu.jamfcloud.com/api/doc/#/

'''

__file__ = "JamfEOL.py"
__authors__ = ["Austin Pratt"]
__date__ = "2023-04-12"
__depricated__ = "False"
__maintainer__ = "Austin Pratt"
__status__ = "Working"
__version__ = "1.0"

# TODO: 
# export to said file (use += to append to a python variable?)
# pray it works

# Standard Python libraries
import base64
import ssl
import datetime
import logging
import json
import csv

# Third party Python libraries
import requests

# Custom libraries
from modules.secrets import SECRETS

########################
# FUNCTIONS
########################

def jamf_get_computers():

    logging.debug("entered function: jamf_get_computers")

    # Process through each page of computers (pagination)
    total_consumed = 0
    current_page = 0
    page_size = 100
    stop_paging = False

    # Update the headers to include the token
    headers_update = {'Authorization': token_string}
    headers.update(headers_update)

    while not stop_paging:

        # Build the endpoint URL
        url = '{0}/api/v1/computers-inventory?page-size={1}&page={2}&section=GENERAL&section=HARDWARE&section=SECURITY&section=OPERATING_SYSTEM&section=USER_AND_LOCATION'.format(baseUrl,page_size,current_page)
        logging.debug('url: %s', url)

        # Get the response
        response = requests.get(url, headers=headers)
        results = response.json()

        # Count up the computer objects in the results
        total_computers = results["totalCount"]

        clients_raw = results['results']
        
        for computer in clients_raw:

            # asset_id
            try:
                asset_id = str(computer['id']) 
            except KeyError:
                asset_id = "" 

            # UDID
            try:
                udid = str(computer['udid']) 
            except KeyError:
                udid = ""

            #################
            # General Section
            #################

            # Host name
            try:
                name = str(computer['general']['name']) 
            except KeyError:
                name = ""

            # Last IP Address
            try:
                lastIpAddress = str(computer['general']['lastIpAddress']) 
            except KeyError:
                lastIpAddress = ""

             # Last Reported IP Address
            try:
                lastReportedIp = str(computer['general']['lastReportedIp']) 
            except KeyError:
                lastReportedIp = ""

            # jamf agent version
            try:
                jamfBinaryVersion = str(computer['general']['jamfBinaryVersion']) 
            except KeyError:
                jamfBinaryVersion = ""

            # type (OS) - The API propertie is "platform" but to keep things
            # consistant with the MDM table, we rename to "type"
            try:
                type = str(computer['general']['type']) 
            except KeyError:
                type = ""

            # assetTag
            try:
                assetTag = str(computer['general']['assetTag']) 
            except KeyError:
                assetTag = ""

            # If the device is remote managed or not - True/False
            try:
                managed = str(computer['general']['remoteManagement']['managed']) 
            except KeyError:
                managed = ""

            # If the device is supervised or not - True/False
            # Supervised means it went through the device enrollment program rather than web enrolment.
            try:
                supervised = str(computer['general']['supervised']) 
            except KeyError:
                supervised = ""

            # If the device is MDM capable or not - True/False
            try:
                mdmCapable = str(computer['general']['mdmCapable']['capable']) 
            except KeyError:
                mdmCapable = ""

            # reportDate - Last time the inventory was updated (default daily)
            try:
                reportDate = datetime.datetime.strftime(datetime.datetime.strptime(computer['general']['reportDate'], iso), mysqliso)
            except (KeyError):
                reportDate = ""
            except (ValueError):
                reportDate = datetime.datetime.strftime(datetime.datetime.strptime(computer['general']['reportDate'], iso2), mysqliso)

            # Last time agent checked in
            try:
                lastContactTime = datetime.datetime.strftime(datetime.datetime.strptime(computer['general']['lastContactTime'], iso), mysqliso)
            except (KeyError, TypeError):
                lastContactTime = ""
            except (ValueError):
                lastContactTime = datetime.datetime.strftime(datetime.datetime.strptime(computer['general']['lastContactTime'], iso2), mysqliso)

            # MDM profile expiration
            try:
                mdmProfileExpiration = datetime.datetime.strftime(datetime.datetime.strptime(computer['general']['mdmProfileExpiration'], iso), mysqliso)
            except (KeyError):
                mdmProfileExpiration = ""
            except (ValueError):
                mdmProfileExpiration = datetime.datetime.strftime(datetime.datetime.strptime(computer['general']['mdmProfileExpiration'], iso2), mysqliso)

            # site
            try:
                site = str(computer['general']['site']['name']) 
            except (KeyError):
                site = ""

            # User approved MDM
            try:
                userApprovedMdm = str(computer['general']['userApprovedMdm']) 
            except (KeyError):
                userApprovedMdm = ""

            ##################
            # Hardware Section
            ##################

            # Serial Number
            try:
                serialNumber = str(computer['hardware']['serialNumber']) 
            except KeyError:
                serialNumber = ""

            # Model
            try:
                model = str(computer['hardware']['model']) 
            except KeyError:
                model = ""

            # macAddress
            try:
                macAddress = str(computer['hardware']['macAddress']) 
            except KeyError:
                macAddress = ""

            ##################
            # Security Section
            ##################

            # sipStatus
            try:
                sipStatus = str(computer['security']['sipStatus']) 
            except KeyError:
                sipStatus = ""
            
            # Gatekeeper Status
            try:
                gatekeeperStatus = str(computer['security']['gatekeeperStatus']) 
            except KeyError:
                gatekeeperStatus = ""

            # xProtect Version
            try:
                xprotectVersion = str(computer['security']['xprotectVersion']) 
            except KeyError:
                xprotectVersion = ""

            # Auto login Disabled
            try:
                autoLoginDisabled = str(computer['security']['autoLoginDisabled']) 
            except KeyError:
                autoLoginDisabled = ""

            # Remote Desktop Enabled
            try:
                remoteDesktopEnabled = str(computer['security']['remoteDesktopEnabled']) 
            except KeyError:
                remoteDesktopEnabled = ""

            # Activation Lock Enabled
            try:
                activationLockEnabled = str(computer['security']['activationLockEnabled']) 
            except KeyError:
                activationLockEnabled = ""

            # Recovery Lock Enabled
            try:
                recoveryLockEnabled = str(computer['security']['recoveryLockEnabled']) 
            except KeyError:
                recoveryLockEnabled = ""

            # Firewall Enabled
            try:
                firewallEnabled = str(computer['security']['firewallEnabled']) 
            except KeyError:
                firewallEnabled = ""

            # Secure Boot Level
            try:
                secureBootLevel = str(computer['security']['secureBootLevel']) 
            except KeyError:
                secureBootLevel = ""

            # External BootLevel
            try:
                externalBootLevel = str(computer['security']['externalBootLevel']) 
            except KeyError:
                externalBootLevel = ""

            # Bootstrap Token Allowed
            try:
                bootstrapTokenAllowed = str(computer['security']['bootstrapTokenAllowed']) 
            except KeyError:
                bootstrapTokenAllowed = ""

            ##################
            # Operating System
            ##################

            # osVersion
            try:
                osVersion = str(computer['operatingSystem']['version']) 
            except KeyError:
                osVersion = ""

            # fileVault2Status
            try:
                fileVault2Status = str(computer['operatingSystem']['fileVault2Status']) 
            except KeyError:
                fileVault2Status = ""

            ###################
            # User and Location
            ###################

            # Real Name
            try:
                realname = str(computer['userAndLocation']['realname']) 
            except KeyError:
                realname = ""

            logging.debug('Will attempt to append computer: %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s', asset_id, udid, name, lastIpAddress, lastReportedIp, jamfBinaryVersion, type, assetTag, managed, supervised, mdmCapable, reportDate, lastContactTime, mdmProfileExpiration, userApprovedMdm, serialNumber, model, macAddress, sipStatus, gatekeeperStatus, xprotectVersion, autoLoginDisabled, remoteDesktopEnabled, activationLockEnabled, recoveryLockEnabled, firewallEnabled, secureBootLevel, externalBootLevel, bootstrapTokenAllowed, fileVault2Status, realname)

            # some of the Admin computers may not want to share the OS version with JAMF and this will mess with the code, 
            # so we have a "None" case for these.
            if  (osVersion) == "None":
                with open(today+'.csv', 'a') as csvfile:
                    filewriter.writerow([name, realname, macAddress, lastIpAddress, site, osVersion, model, lastContactTime, jamfBinaryVersion])
                

                logging.info('Successfully PRINTed: "%s": %s.', name, osVersion)
            
            #######################
            # Change Version Here
            #######################
            # osVersion 10 means anything Catalina and before. To alter this in the future, change the "10" below to the appropriate EOL Operating System
            # This script is pulling more information than is being used in case it is wanted in the future. to adjust this, add the variable from above to
            # the filewriter command above and below these comments, as well as at the end where we define the csv.
            elif int(osVersion[0:2]) <= 10:
                with open(today+'.csv', 'a') as csvfile:
                    filewriter.writerow([name, realname, macAddress, lastIpAddress, site, osVersion, model, lastContactTime, jamfBinaryVersion])
                

                logging.info('Successfully PRINTed: "%s": %s.', name, osVersion)
            else:
                pass


        # Increase the page value and stop processing when on the last page
        current_page += 1
        logging.debug('current_page: %s', current_page)
        
        total_consumed += len(clients_raw)
        logging.info('total_consumed (total computers pulled from Jamf into the DB): %s', total_consumed)

        stop_paging = (total_computers == total_consumed)
        logging.debug('stop_paging: %s', stop_paging)

        # Close function jamf_get_computers


########################
# Global Variables
########################

# Valid log levels include:
# INFO
# WARNING
# ERROR
# CRITICAL
# DEBUG

# Logging options
log_File = './JamfProDataExport.log'
#log_File = 'JamfProDataExport.log'
logging.basicConfig(format='%(asctime)s %(levelname)s %(message)s', datefmt='%Y-%m-%d %H:%M:%S', filename=log_File, level=logging.INFO, filemode='w')

# Define the URL that we will use throughout this script
# And pull in the credentials from the secrets.json file
if 'jamfpro' in SECRETS:
    
    # Build the base URL that will be passed into the API calls
    baseUrl = 'https://{0}'.format(SECRETS['jamfpro']['host'])
    logging.debug('baseUrl: %s', baseUrl)

    # Credentials used to request the Token
    user = '{0}'.format(SECRETS['jamfpro']['user'])
    password = '{0}'.format(SECRETS['jamfpro']['password'])

    # generate authorization headers
    headers = {
        'Accept': 'application/json',
    }

    # Retreive the API token
    url = '{0}/api/v1/auth/token'.format(baseUrl)
    request = requests.post(url, headers=headers, auth=(user, password))
    response = request.json()
    token = response['token']
    token_string = "Bearer " + token


#Time formats used to make the datetime variables easier to read

# Define the format of the date that JamfPro presents via the API
# Some dates are formated with a %f, others are not - we need to accomodate both
iso = '%Y-%m-%dT%H:%M:%S.%fZ'
iso2 = '%Y-%m-%dT%H:%M:%SZ'

# We will take the date format from JamfPro's API and convert it to a
# format that we can then insert into MySQL
mysqliso = '%Y-%m-%d %H:%M:%S'

# File Export Set-Up
# File name with today's date and time in 24h clock format e.g. 2023-04-12_14:47
ymdhm = '%Y-%m-%d_%H:%M'
today = datetime.datetime.strftime(datetime.datetime.today(), ymdhm)

########################
# ACTION!
########################

with open(today+'.csv', 'w') as csvfile:
    filewriter = csv.writer(csvfile, delimiter=',', lineterminator='\n',)
    filewriter.writerow(['name', ' realname', ' macAddress', ' lastIpAddress', ' site', ' osVersion', ' model', ' lastContactTime', ' jamfBinaryVersion'])
    jamf_get_computers()
csvfile.close()
