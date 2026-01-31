export const CATEGORIES = {
  awareness: {
    name: "Situational Awareness",
    icon: "🔍",
    description: "System info, user context, OS details"
  },
  enumeration: {
    name: "Enumeration",
    icon: "📋",
    description: "Users, groups, shares, services"
  },
  network: {
    name: "Network Discovery",
    icon: "🌐",
    description: "Network config, connections, shares"
  },
  credentials: {
    name: "Credential Hunting",
    icon: "🔐",
    description: "Password files, credentials, keys"
  },
  privesc: {
    name: "Privilege Escalation",
    icon: "⬆️",
    description: "SUID, sudo, weak permissions"
  },
  persistence: {
    name: "Persistence",
    icon: "💾",
    description: "Autoruns, services, cron jobs"
  },
  lateral: {
    name: "Lateral Movement",
    icon: "↔️",
    description: "Pass-the-hash, sessions, shares"
  },
  defevade: {
    name: "Defense Evasion",
    icon: "🛡️",
    description: "AV bypass, log cleanup, obfuscation"
  },
  exfiltration: {
    name: "Data Exfiltration",
    icon: "📤",
    description: "File transfer, encoding, covert channels"
  }
};

export const SUBCATEGORIES = {
  windows: ["cmd", "powershell", "wmi", "registry"],
  linux: ["bash"]
};

export const SUBCATEGORY_LABELS = {
  cmd: "CMD",
  powershell: "PowerShell",
  wmi: "WMI",
  registry: "Registry",
  bash: "Bash"
};
