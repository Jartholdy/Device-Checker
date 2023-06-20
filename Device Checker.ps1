#set Window Title
$host.ui.RawUI.WindowTitle = "Device Checker v2.3.1 (01 Jun 2023) for Foxway A/S by Johny Bartholdy Jensen"
$host.ui.RawUI.BackgroundColor = "Black";
$host.ui.RawUI.ForegroundColor = "White";
slmgr -ato
devmgmt.msc

#page header
function p.header {
    Clear-Host
    write-Host " " -NoNewline;Write-Host "filler                                                                    " -f DarkMagenta -b DarkMagenta
    write-Host " " -NoNewline;Write-Host "                                Foxway A/S                                " -f White -b DarkMagenta
    write-Host " " -NoNewline;Write-Host "                              Device Checker                              " -f White -b DarkMagenta
    write-Host " " -NoNewline;Write-Host "filler                                                                    " -f DarkMagenta -b DarkMagenta 
}

#page footer
function p.footer {
    write-Host " " -NoNewline;Write-Host "filler                                                                    " -f DarkGray -b DarkGray
    write-Host " " -NoNewline;Write-Host "   U. Updater    O. OKInject   M. MAR    C. Change PK     Q. Quick menu   " -f White -b DarkGray
    write-Host " " -NoNewline;Write-Host "   S. Shutdown   R. Reboot     B. BIOS   V. Boot option   Any. Exit       " -f White -b DarkGray
    write-Host " " -NoNewline;Write-Host "filler                                                                    " -f DarkGray -b DarkGray
}

#Product Description and Part Number
function PN {
    Get-CimInstance win32_computersystem | select-object Manufacturer, model, systemfamily, SystemSKUNumber | ForEach-Object {
        if ($_.Manufacturer -match "HP"){
            "  PD: " + $_.model
            "  PN: " + $_.SystemSKUNumber
        } elseif ($_.Manufacturer -match "Lenovo") {    
            "  PD: " + $_.systemfamily
            "  PN: " + $_.model
        } elseif ($_.Manufacturer -match "Dell") {    
            "  PD: " + $_.model
            "  PN: " + $_.model
        } else {    
            "  PD: " + $_.systemfamily
            "  PN: " + $_.model
        }
    }
}

#Serial Number
function SN {
    Get-CimInstance win32_bios | select-object SerialNumber | ForEach-Object {
        "  SN: " + $_.SerialNumber
    }
}

#Operation System Edition
function OS {
    $OS_ProductName = Get-CimInstance win32_operatingsystem | Select-Object caption | foreach-object {
        if ($_.caption -match 'Microsoft') {
            $OS_ProductName = ($_.caption).substring(10)
            $OS_ProductName
        } else {
            $OS_ProductName = $_.caption
            $OS_ProductName
        }
    }
    $OS_DisplayVersion = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").DisplayVersion
    if (!$OS_DisplayVersion) {
        $OS_DisplayVersion = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").ReleaseId
    }
    "  OS: " + ($OS_ProductName) + " (" + ($OS_DisplayVersion) + ")"
}

#Product Key
function PK {
    $SoftwareLicensingService = (Get-CimInstance -ClassName SoftwareLicensingService)
    if ($SoftwareLicensingService.OA3xOriginalProductKey) {
        Get-CimInstance -ClassName SoftwareLicensingService | Select-Object OA3xOriginalProductKeyDescription | ForEach-Object {
            $PKD = Get-CimInstance -ClassName SoftwareLicensingService | Select-Object OA3xOriginalProductKeyDescription
            if($_.OA3xOriginalProductKeyDescription -contains '[4.0] Core OEM:DM') {$PKD = "Windows 10 Home"}
            if($_.OA3xOriginalProductKeyDescription -contains '[4.0] Professional OEM:DM') {$PKD = "Windows 10 Pro"}
            if($_.OA3xOriginalProductKeyDescription -contains '[4.0] ProfessionalWorkstation OEM:DM') {$PKD = "Windows 10 Pro for Workstations"}
            if($_.OA3xOriginalProductKeyDescription -contains '[4.0] IoTEnterprise OEM:DM') {$PKD = "Windows 10 IoT Enterprise"}
            if($_.OA3xOriginalProductKeyDescription -contains '[4.0] ProfessionalEducation OEM:DM') {$PKD = "Windows 10 Pro Education"}
            if($_.OA3xOriginalProductKeyDescription -contains '') {$PKD = "No Product Key found"}
            "  PK: " + $PKD
        }
    } else {
        "  PK: No Product Key found"
    }
}

#Operation System Language(s)
function LA {
    $OSInfo = Get-CimInstance -ClassName Win32_OperatingSystem
    $lang = $OSInfo.MUILanguages.substring(3)
    if ($lang.count -eq 2) {
        if($lang -contains 'US' -and $lang -contains 'GB') {}
        elseif($lang -contains 'US') {$lang = $lang -ne "US"}
        elseif($lang -contains 'GB') {$lang = $lang -ne "GB"}
    }
    if(($lang -contains 'ES') -and ($lang -contains 'MX') -and (($lang -contains 'GB') -or ($lang -contains 'US'))) {$langmatch = "ES"}
    if(($lang -contains 'DE') -and ($lang -contains 'FR') -and ($lang -contains 'IT') -and ($lang -contains 'NL') -and (($lang -contains 'GB') -or ($lang -contains 'US'))) {$langmatch = "MH"}
    if(($lang -contains 'DK') -and ($lang -contains 'SE') -and ($lang -contains 'NO') -and ($lang -contains 'FI') -and (($lang -contains 'GB') -or ($lang -contains 'US'))) {$langmatch = "MX"}
    if(($lang -contains 'DK') -and ($lang -contains 'SE') -and ($lang -contains 'NO') -and ($lang -contains 'FI') -and ($lang -contains 'DE') -and ($lang -contains 'FR') -and ($lang -contains 'IT') -and ($lang -contains 'NL') -and (($lang -contains 'GB') -or ($lang -contains 'US'))) {$langmatch = "EU"}
    #test for match
    if($langmatch){$lang = $langmatch}
    #output
    $LA = "  LA: " + $lang
    $LA
}

#AutoPilot
function AP {
    if (test-path "HKLM:\SOFTWARE\Microsoft\Provisioning\AutopilotPolicyCache") {
        $AzurePolicy = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Provisioning\AutopilotPolicyCache" -Name ProfileAvailable).ProfileAvailable

        if ($AzurePolicy -ne "1") {
            write-Host "  AutoPilot  : " -NoNewline
            write-Host "Nej" -f green
        } else {
            write-Host "  AutoPilot  : " -NoNewline
            write-Host "Ja! " -NoNewline -f red
            if (test-path "HKLM:\software\microsoft\provisioning\Diagnostics\Autopilot") {
                $TenantDomain = (Get-ItemProperty "HKLM:\software\microsoft\provisioning\Diagnostics\Autopilot").CloudAssignedTenantDomain
                write-Host "($TenantDomain)" -f white
            }
        }
    } else {
        write-Host "  AutoPilot  : " -NoNewline
        write-Host "Nej" -f green
    }
}

#CompuTrace
function CT {
    $CT_Found = 0
    $CT_SYSTEM32_Path = "C:\Windows\System32"
    $CT_SYSTEM32_1 = test-path (Join-Path $CT_SYSTEM32_Path rpcnet.exe)
    $CT_SYSTEM32_2 = test-path (Join-Path $CT_SYSTEM32_Path rpcnetp.exe)
    $CT_SYSTEM32_3 = test-path (Join-Path $CT_SYSTEM32_Path wceprv.exe)
    $CT_SYSTEM32_4 = test-path (Join-Path $CT_SYSTEM32_Path identprv.exe)
    $CT_SYSTEM32_5 = test-path (Join-Path $CT_SYSTEM32_Path Upgrd.exe)
    $CT_SYSTEM32_6 = test-path (Join-Path $CT_SYSTEM32_Path autochk.exe.bak)
    $CT_REGISTRY_Path = "HKLM:\SYSTEM\CurrentControlSet\Services"
    $CT_REGISTRY_1 = test-path (Join-Path $CT_REGISTRY_Path rpcnet)
    $CT_REGISTRY_2 = test-path (Join-Path $CT_REGISTRY_Path rpcnetp)
    if (($CT_SYSTEM32_1) -or ($CT_SYSTEM32_2) -or ($CT_SYSTEM32_3) -or ($CT_SYSTEM32_4) -or ($CT_SYSTEM32_5) -or ($CT_SYSTEM32_6) -or ($CT_REGISTRY_1) -or ($CT_REGISTRY_2)) {
        $CT_Found = 1
    }
    if(-not (get-process "rpcnet", "rpcnetp" -ea SilentlyContinue) -eq $Null){
        $CT_Found = 1
    }
    if ($CT_Found -gt 0) {
        Write-host "  CompuTrace : " -n
        Write-host "JA!" -f red
    } else {
        Write-host "  CompuTrace : " -n
        Write-host "Nej" -f green
    }
}

# Asset Tag
function AT {
    $AT_SMBios = (Get-CimInstance  -Class Win32_SystemEnclosure).SMBiosAssetTag
    if (
        ($AT_SMBios) -and
        ($AT_SMBios -ne " ") -and
        ($AT_SMBios -notmatch "   ") -and
        ($AT_SMBios -ne "NO Asset Tag") -and
        ($AT_SMBios -notmatch "ýýý") -and
        ($AT_SMBios -notmatch "ý ý ý") -and
        ($AT_SMBios -notmatch "ÿÿÿ") -and
        ($AT_SMBios -notmatch "ÿ ÿ ÿ") -and
        ($AT_SMBios -ne (Get-CimInstance win32_bios | select-object SerialNumber | ForEach-Object {$_.SerialNumber})) -and
        ($AT_SMBios -ne "No Asset Information")
    ) {
        write-Host "  Asset Tag  : " -NoNewline
        write-Host "Ja! " -NoNewline -f red
        write-Host "($AT_SMBios)" -f white
    } else {
        write-Host "  Asset Tag  : " -NoNewline
        write-Host "Nej" -f green
    }
}

# Bitlocker
function BL {
    if (Get-Command 'Get-BitlockerVolume' -errorAction SilentlyContinue) {
        $Bitlocker = (Get-BitlockerVolume -MountPoint "C:")
        If ($Bitlocker.protectionstatus -like "off") {    
            Write-Host "  BitLocker  : " -NoNewline
            Write-host "Nej" -f green
        } else {
            Write-Host "  BitLocker  : " -NoNewline
            Write-host "Ja!" -f red
        }
    } else {
        Write-Host "  BitLocker  : " -NoNewline
        Write-host "Unsupported" -F Yellow
    }
}

# Bios Password
Function BIOS_PW {
    $BIOS_PW_LENOVO = Get-CIMInstance -Namespace root\wmi -Class Lenovo_BiosPasswordSettings -EA SilentlyContinue
    if ($BIOS_PW_LENOVO){
        write-Host "  BIOS PW    : " -N
        $passwordState = ($BIOS_PW_LENOVO).PasswordState
        switch ($passwordState) {
            0 { write-Host "Nej" -F green }
            2 { write-Host "Supervisor password set" -F Red }
            3 { write-Host "Power on and supervisor passwords set" -F Red }
            4 { write-Host "Hard drive password(s) set" -F Red }
            5 { write-Host "Power on and hard drive passwords set" -F Red }
            6 { write-Host "Supervisor and hard drive passwords set" -F Red }
            7 { write-Host "Supervisor, power on, and hard drive passwords set" -F Red }
        }
    } else {
        write-Host "  BIOS PW    : " -N
        write-Host "Unsupported" -F Yellow
    }
}

#Processor
function CPU {
    Get-CimInstance -ClassName Win32_processor | Select-Object DeviceID, name | ForEach-Object {
        "  CPU: " + $_.name
    }
}

#RAM
function RAM {
    $RAM_total = Get-CimInstance -ClassName CIM_PhysicalMemory | Measure-Object -Property capacity -Sum | ForEach-Object {
        ($_.sum / 1GB)
    }
    $RAM_slot = Get-CimInstance -ClassName CIM_PhysicalMemory | Select-Object capacity,formfactor | Where-Object { ($_.formfactor -like "8") -or ($_.formfactor -like "12") } | ForEach-Object {
        "" + [math]::Truncate($_.capacity) / 1GB + "GB"
    }
    $RAM_onboard_total = Get-CimInstance -ClassName CIM_PhysicalMemory | Select-Object capacity,formfactor | Where-Object { ($_.formfactor -notlike "8") -and ($_.formfactor -notlike "12") } | Measure-Object -Property capacity -Sum | ForEach-Object {
        ($_.sum / 1GB)
    }
    ForEach-Object {
        Write-Host "  RAM: " -n
        Write-Host "$RAM_total" -n
        Write-Host "GB (" -n
        Write-Host "$RAM_slot" -n
        if($RAM_onboard_total) {
            if($RAM_slot) {
                Write-Host " + " -n
            }
            Write-Host "$RAM_onboard_total" -n
            Write-Host "GB onboard" -n
        }
        Write-Host ")"
    }
}

#Resolution
function RES {
    $RES_H = Get-CimInstance -Class Win32_VideoController | Select-Object CurrentHorizontalResolution | ForEach-Object {$_.CurrentHorizontalResolution}
    $RES_V = Get-CimInstance -Class Win32_VideoController | Select-Object CurrentVerticalResolution | ForEach-Object {$_.CurrentVerticalResolution}
    $RES_R = Get-CimInstance -Class Win32_VideoController | Select-Object CurrentRefreshRate | ForEach-Object {$_.CurrentRefreshRate}
    Write-Host "  RES: " -n
    Write-Host "$RES_H".Trim() -n
    Write-Host "x" -n
    Write-Host "$RES_V".Trim() -n
    Write-Host "@" -n
    Write-Host "$RES_R".Trim() -n
    Write-Host "hz"
}

#Graphics
function GPU {
    Get-CimInstance -ClassName CIM_VideoController | Select-Object Description | ForEach-Object {
        "  GPU: " + $_.Description
    }
}

#DC_DISK
function DC_DISK {
    Get-PhysicalDisk | Select-Object MediaType, Bustype, Size, FriendlyName, HealthStatus | ForEach-Object {
        if ($_.HealthStatus -eq "healthy") {$diskhe = "Green"} else {$diskhe = "Red"}
        write-host "  " -n
        write-host $_.MediaType -n
        write-host "/" -n
        write-host $_.BusType -n
        write-host ": " -n
        write-host ([math]::round($_.size/1000000000,0)) -n
        write-host "GB (" -n
        write-host $_.HealthStatus -n -f $diskhe
        write-host ") (" -n
        write-host $_.FriendlyName -n
        write-host ")"
    }
}

#LAN
function LAN {
    Get-NetAdapter | Where-Object Name -match "Ethernet" | Where-Object Status -eq "Up" | Select-Object LinkSpeed,InterfaceDescription | ForEach-Object {
        "  LAN: " + $_.LinkSpeed + " - " + $_.InterfaceDescription
    }
}

#WIFI
function WIFI {
    $WIFI = Get-NetAdapter -Physical | Where-Object { $_.MediaType -like "*802.11*" }
    if ($WIFI) {
        $signal = netsh wlan show network
        #$signal_network1 = "There are [0-9] networks currently visible."
        #$signal_network2 = "There are [0-9][0-9] networks currently visible."
        #$signal_network3 = "SSID [0-9]"
        $signal_network4 = "SSID"
        $signal_powered = "The wireless local area network interface is powered down and doesn't support the requested operation."   
        write-Host "  WIFI: Ja - Signal: " -NoNewline     
        if ($signal -match $signal_network4) {
            write-Host "Ja" -f green
        } elseif ($signal -match $signal_powered) {
            write-Host "Powered off" -f yellow
        } else {
            write-Host "Nej" -f red
        }

    } else {
        write-Host "  WIFI: Nej"
    }
}

#WWAN
function WWAN {
    $WWAN = Get-NetAdapter -Physical | Where-Object { $_.MediaType -like "*Wireless WAN*" }
    if ($WWAN) {
        write-Host "  WWAN: Ja"
    } else {
        write-Host "  WWAN: Nej"
    }
}

#Battery
function BAT {
    $Battery_CT = (Get-CimInstance -ClassName Win32_SystemEnclosure).ChassisTypes
    if (($Battery_CT -ne "3") -and ($Battery_CT -ne "4") -and ($Battery_CT -ne "6") -and ($Battery_CT -ne "7") -and ($Battery_CT -ne "13") -and ($Battery_CT -ne "16") -and ($Battery_CT -ne "24") -and ($Battery_CT -ne "34") -and ($Battery_CT -ne "35")) {
        $BatteryCount = @(Get-CimInstance -ClassName Win32_Battery).Count
        if ($BatteryCount -gt 0) {
            #---------- Battery Procent and Charging Status
            $BatteryEstimated = Get-CimInstance -ClassName Win32_Battery | Select-Object -Property DeviceID, BatteryStatus, EstimatedChargeRemaining | ForEach-Object {
                $FriendlyBatteryStatus = switch ($_.BatteryStatus) { 
                    1 {'Battery Power'}
                    2 {'AC Power'}
                    3 {'Fully Charged'}
                    4 {'Low'}
                    5 {'Critical'}
                    6 {'Charging'}
                    7 {'Charging and High'}
                    8 {'Charging and Low'}
                    9 {'Charging and Critical'}
                    10 {'Undefined'}
                    11 {'Partially Charged'}
                    default {"$value"}
                }
                "  BAT: " + $_.EstimatedChargeRemaining + "% (" + $FriendlyBatteryStatus + ")"
            }
            #---------- Creation of Battery Report
            $BatteryPath = "c:\batteryreport.xml"
            & powercfg /batteryreport /XML /OUTPUT $BatteryPath | Out-Null
            Start-Sleep -Seconds 2        
            $BatteryTestPath = Test-Path $BatteryPath
            if ($BatteryTestPath -eq $true) {
                [xml]$Report = Get-Content $BatteryPath
                <#$BatteryStatus = #>
                $Report.BatteryReport.Batteries | Out-Null | ForEach-Object {
                    [PSCustomObject]@{
                        DesignCapacity     = $_.Battery.DesignCapacity
                        FullChargeCapacity = $_.Battery.FullChargeCapacity
                    }
                }
                $BatteryDesignCap = $Report.BatteryReport.Batteries.Battery.DesignCapacity
                $BatteryChargeCap = $Report.BatteryReport.Batteries.Battery.FullChargeCapacity    
                $BatteryHealth = for ($i = 0; $i -lt $BatteryDesignCap.Length; $i++) {
                    "" + [math]::Round((100 / $BatteryDesignCap[$i]) * $BatteryChargeCap[$i]) + "%"
                }
                #---------- Output with Battery Report
                if ($BatteryCount -lt 1) {
                    "  BAT: No Battery"
                } elseif ($BatteryCount -gt 1) {
                    for ($i = 0; $i -lt $BatteryCount; $i++){
                        "" + ($BatteryEstimated[$i]) + " - Health: " + ($BatteryHealth[$i])
                    }
                } else {
                    for ($i = 0; $i -lt $BatteryCount; $i++) {
                        "" + ($BatteryEstimated) + " - Health: " + ($BatteryHealth[$i])
                    }        
                }
                Start-Sleep -Seconds 3
                Remove-Item $BatteryPath
                } else {
                #---------- Output without Battery Report
                if ($BatteryCount -lt 1) {
                    write-Host "  BAT: " -N
                    write-Host "NO BATTERY" -f Red
                } elseif ($BatteryCount -gt 1) {
                    for ($i = 0; $i -lt $BatteryCount; $i++) {
                        "" + ($BatteryEstimated[$i]) + " - Health: Unknown"
                    }
                } else {
                    for ($i = 0; $i -lt $BatteryCount; $i++) {
                        "" + ($BatteryEstimated) + " - Health: Unknown"
                    }        
                }
            }
        } else {
            write-Host "  BAT: " -N
            write-Host "NO BATTERY" -f Red
        }
    }
}

#Output her
p.header
""
PN
SN
""
OS
PK
LA
""
AP
AT
BIOS_PW
BL
CT
""
CPU
RAM
DC_DISK
RES
GPU
""
LAN
WIFI
WWAN
""
BAT
""
p.footer

for () {
    $selection = Read-Host "`n  Select option"
    switch ($selection) {
        's'    {shutdown -s -t 0}
        'r'    {shutdown -r -t 0}
        'b'    {shutdown -r -f -fw -t 0;shutdown -r -f -fw -t 0}
        'v'    {shutdown -r -o -t 0}
        'au'   {$RootPath = (Split-Path $PSScriptRoot);Start-Process "$RootPath\AutoPilot\AutoPilot.bat"}
        'as1'  {$RootPath = (Split-Path $PSScriptRoot);Start-Process "$RootPath\Asset tag\Asset tag - Notebook.bat"}
        'as2'  {$RootPath = (Split-Path $PSScriptRoot);Start-Process "$RootPath\Asset tag\Asset tag - Desktop.bat"}
        'dev'  {devmgmt.msc}
        'sl'   {slmgr -ato}
        'u'    {$RootPath = (Split-Path $PSScriptRoot);Start-Process "$RootPath\Auto Driver Updater\Auto Driver Updater.bat"}
        'o'    {$RootPath = (Split-Path $PSScriptRoot);Start-Process "$RootPath\Original Product Key Injector\Original Product Key Injector.bat"}
        'q'    {$RootPath = (Split-Path $PSScriptRoot);Start-Process "$RootPath\Quick Menu\Quick Menu.bat"}
        'c'    {Start-Process ms-settings:activation;Start-Process changepk}
        'm'    {$RootPath = (Split-Path $PSScriptRoot);Start-Process "$RootPath\SMART\SMART.bat"}
        Default{exit}
    }
}