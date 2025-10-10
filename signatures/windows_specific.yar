/*
    Windows Antivirus - Windows Specific Signatures
    Windows-specific malware and threat detection
*/

rule Windows_Registry_Persistence
{
    meta:
        description = "Detects registry persistence mechanisms"
        author = "Windows Antivirus Team"
        version = "1.0"
        threat_type = "trojan"
        severity = "high"
        tags = "persistence,registry,autostart"

    strings:
        $reg1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" nocase
        $reg2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce" nocase
        $reg3 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" nocase
        $reg4 = "SYSTEM\\CurrentControlSet\\Services" nocase
        $api1 = "RegSetValueEx" nocase
        $api2 = "RegCreateKeyEx" nocase
        $api3 = "RegOpenKeyEx" nocase

    condition:
        any of ($reg*) and any of ($api*)
}

rule Windows_Service_Installation
{
    meta:
        description = "Detects malicious service installation"
        author = "Ramusa"
        version = "1.0"
        threat_type = "trojan"
        severity = "medium"
        tags = "service,installation,persistence"

    strings:
        $api1 = "CreateService" nocase
        $api2 = "OpenSCManager" nocase
        $api3 = "StartService" nocase
        $api4 = "ControlService" nocase
        $service1 = "SERVICE_AUTO_START" nocase
        $service2 = "SERVICE_DEMAND_START" nocase
        $service3 = "SERVICE_WIN32_OWN_PROCESS" nocase

    condition:
        2 of ($api*) and any of ($service*)
}

rule Windows_DLL_Injection
{
    meta:
        description = "Detects DLL injection techniques"
        author = "Windows Antivirus Team"
        version = "1.0"
        threat_type = "trojan"
        severity = "high"
        tags = "injection,dll,process"

    strings:
        $api1 = "LoadLibrary" nocase
        $api2 = "GetProcAddress" nocase
        $api3 = "VirtualAllocEx" nocase
        $api4 = "WriteProcessMemory" nocase
        $api5 = "CreateRemoteThread" nocase
        $api6 = "SetWindowsHookEx" nocase
        $technique1 = "DLL injection" nocase
        $technique2 = "process hollowing" nocase

    condition:
        3 of ($api*) and any of ($technique*)
}

rule Windows_UAC_Bypass
{
    meta:
        description = "Detects UAC bypass attempts"
        author = "Windows Antivirus Team"
        version = "1.0"
        threat_type = "trojan"
        severity = "high"
        tags = "uac,bypass,privilege"

    strings:
        $uac1 = "eventvwr.exe" nocase
        $uac2 = "fodhelper.exe" nocase
        $uac3 = "computerdefaults.exe" nocase
        $uac4 = "sdclt.exe" nocase
        $reg1 = "ms-settings\\shell\\open\\command" nocase
        $reg2 = "exefile\\shell\\runas\\command" nocase
        $bypass1 = "UAC bypass" nocase
        $bypass2 = "privilege escalation" nocase

    condition:
        any of ($uac*) and any of ($reg*) and any of ($bypass*)
}

rule Windows_Credential_Theft
{
    meta:
        description = "Detects credential theft mechanisms"
        author = "Windows Antivirus Team"
        version = "1.0"
        threat_type = "spyware"
        severity = "critical"
        tags = "credentials,theft,password"

    strings:
        $file1 = "SAM" nocase
        $file2 = "SYSTEM" nocase
        $file3 = "SECURITY" nocase
        $file4 = "ntds.dit" nocase
        $tool1 = "mimikatz" nocase
        $tool2 = "pwdump" nocase
        $tool3 = "fgdump" nocase
        $api1 = "LsaEnumerateLogonSessions" nocase
        $api2 = "SamConnect" nocase

    condition:
        2 of ($file*) and (any of ($tool*) or any of ($api*))
}

rule Windows_Ransomware_Behavior
{
    meta:
        description = "Detects ransomware behavior patterns"
        author = "Windows Antivirus Team"
        version = "1.0"
        threat_type = "ransomware"
        severity = "critical"
        tags = "ransomware,encryption,behavior"

    strings:
        $crypto1 = "CryptEncrypt" nocase
        $crypto2 = "CryptGenKey" nocase
        $crypto3 = "CryptAcquireContext" nocase
        $file1 = "FindFirstFile" nocase
        $file2 = "FindNextFile" nocase
        $file3 = "CreateFile" nocase
        $ransom1 = "ransom" nocase
        $ransom2 = "decrypt" nocase
        $ransom3 = "bitcoin" nocase
        $ransom4 = "payment" nocase

    condition:
        2 of ($crypto*) and 2 of ($file*) and any of ($ransom*)
}

rule Windows_Process_Hollowing
{
    meta:
        description = "Detects process hollowing technique"
        author = "Windows Antivirus Team"
        version = "1.0"
        threat_type = "trojan"
        severity = "high"
        tags = "hollowing,injection,stealth"

    strings:
        $api1 = "CreateProcess" nocase
        $api2 = "VirtualAllocEx" nocase
        $api3 = "WriteProcessMemory" nocase
        $api4 = "SetThreadContext" nocase
        $api5 = "ResumeThread" nocase
        $api6 = "NtUnmapViewOfSection" nocase
        $flag1 = "CREATE_SUSPENDED" nocase

    condition:
        4 of ($api*) and $flag1
}

rule Windows_Anti_Analysis
{
    meta:
        description = "Detects anti-analysis and evasion techniques"
        author = "Windows Antivirus Team"
        version = "1.0"
        threat_type = "suspicious"
        severity = "medium"
        tags = "evasion,analysis,detection"

    strings:
        $vm1 = "VMware" nocase
        $vm2 = "VirtualBox" nocase
        $vm3 = "QEMU" nocase
        $vm4 = "Xen" nocase
        $debug1 = "IsDebuggerPresent" nocase
        $debug2 = "CheckRemoteDebuggerPresent" nocase
        $debug3 = "OutputDebugString" nocase
        $sleep1 = "Sleep" nocase
        $sleep2 = "WaitForSingleObject" nocase

    condition:
        any of ($vm*) and any of ($debug*) and any of ($sleep*)
}

rule Windows_Fileless_Malware
{
    meta:
        description = "Detects fileless malware techniques"
        author = "Windows Antivirus Team"
        version = "1.0"
        threat_type = "trojan"
        severity = "high"
        tags = "fileless,memory,powershell"

    strings:
        $ps1 = "powershell.exe" nocase
        $ps2 = "PowerShell" nocase
        $cmd1 = "-EncodedCommand" nocase
        $cmd2 = "-WindowStyle Hidden" nocase
        $cmd3 = "-ExecutionPolicy Bypass" nocase
        $mem1 = "Invoke-Expression" nocase
        $mem2 = "IEX" nocase
        $mem3 = "DownloadString" nocase
        $mem4 = "Reflection.Assembly" nocase

    condition:
        any of ($ps*) and any of ($cmd*) and any of ($mem*)
}