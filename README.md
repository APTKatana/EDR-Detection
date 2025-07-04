A stealthy PowerShell script to detect EDE/Av and SIEM Agent
CAN Detect : 
    EDRs: CrowdStrike Falcon , Windows Defender , SentinalOne , Carbon Black , Sophos , Cortex XDR , Symantec , Trend Micro Apexone
    SIEMs: Splunk , Elastic , NXLog , Wazuh  
    AVs: McAfee , Kaspersky , ESET , Avast , Bitdefender , ZoneAlarm

    This script leverages various Living Off The Land (LOTL) techniques and built-in Windows
    binaries to identify running security software and agents without relying on external
    tools or unusual system calls that might trigger alerts.

    As defenders deploy sophisticated EDRs and SIEM logging, understanding the security
    stack of a target system becomes crucial for red teams, penetration testers, and
    even blue teams for verifying deployment. This script aims to provide insights into
    the presence of such agents by:

    1.  *Process Analysis:* Identifying running processes with names or paths characteristic
        of EDR/SIEM agents.

    2.  *Service Enumeration:* Listing services that belong to known security vendors.

    3.  *Driver Inspection:* Checking loaded kernel drivers for security products.

    4.  *Registry Key Queries:* Looking for specific registry entries created by security software.

    5.  *Filesystem & Directory Checks:* Scanning common installation paths and program files
        for agent footprints.

    6.  *WMI Queries:* Using Windows Management Instrumentation to discover installed software
        and system configurations relevant to security solutions.

    7.  *Network Connection Analysis:* Identifying network connections to known EDR/SIEM
        cloud services or on-premise collectors.

    The script is designed to be as "quiet" as possible, focusing on techniques commonly
    used by legitimate system administrators, thereby reducing the likelihood of detection
    by behavioral analysis engines.






    Disclaimer: This script is for educational and authorized testing purposes only.
    Use in production environments or for unauthorized activities is strictly prohibited.
