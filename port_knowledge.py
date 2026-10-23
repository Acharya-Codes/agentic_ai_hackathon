PORT_HINTS = {
    21: "FTP: unencrypted file transfer, a legacy and insecure protocol",
    23: "Telnet: unencrypted remote login, a legacy protocol heavily targeted by IoT botnets",
    69: "TFTP: file transfer with no authentication, legacy and insecure",
    139: "NetBIOS/SMB file sharing: normal on Windows but risky on untrusted networks",
    445: "SMB file sharing: normal on Windows but risky on untrusted networks",
    1900: "UPnP/SSDP device discovery: often abused to expose devices",
    2323: "Alternate Telnet port: unencrypted remote login, scanned for by IoT botnets such as Mirai",
    3389: "Remote Desktop (RDP): powerful remote access, a frequent attack target",
    5555: "Android Debug Bridge: gives full device control if exposed",
    5900: "VNC remote screen control: often weakly protected",
    7547: "TR-069 router management: a known botnet target",
    57621: "Spotify local network discovery: normal behaviour for the Spotify app",
}


def hint_for(port):
    return PORT_HINTS.get(port, "")