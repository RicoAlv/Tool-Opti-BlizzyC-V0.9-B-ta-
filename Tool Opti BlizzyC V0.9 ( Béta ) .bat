@echo off
cd /d "%~dp0"
chcp 65001 >nul 2>&1
mode con lines=30 cols=136
setlocal enabledelayedexpansion
title Optimisation By BlizzyC
call :Colors

REM Check for Administrator Privileges
whoami /groups | findstr /i /c:"S-1-16-12288" >nul 2>&1 || (echo %BRIGHT_BLACK% Pour continuer, exécutez cet outil en tant que en %DARK_RED% administrateur%DARK_WHITE%. && pause && exit)

REM Main Menu
:Main-Menu
cls
echo.
echo.                                              %BRIGHT_BLACK% Tool Opti BlizzyC V0.09 ( Béta ) Twitter @c_bliizzy%WHITE%
echo  %BRIGHT_BLUE%1%BRIGHT_WHITE%: Optimisation 
echo  %BRIGHT_BLUE%2%BRIGHT_WHITE%: Information
echo  %BRIGHT_RED%E%BRIGHT_WHITE%: Leave
echo.
set "choice="
set /p choice=%DARK_WHITE%Choisissez une option pour continuer: !BRIGHT_BLUE!
if not defined choice goto :Main-Menu
call :Menu_[%choice%] 2>nul || (echo %BRIGHT_BLACK%Choix non valide, veuillez réessayer.%DARK_WHITE% & pause)
goto :Main-Menu

REM Option 1: Optimisation By BlizzyC
:Menu_[1] Run Optimisation By BlizzyC

REM Services
set services_auto=AudioEndpointBuilder Audiosrv BITS BFE BluetoothUserService_dc2a4 BrokerInfrastructure Browser BthAvctpSvc BthHFSrv CaptureService_dc2a4 CDPUserSvc_dc2a4 COMSysApp CoreMessagingRegistrar CredentialEnrollmentManagerUserSvc_dc2a4 CryptSvc DPS Dhcp Dnscache DoSvc DsmSvc DusmSvc EapHost EventLog EventSystem FrameServer GraphicsPerfSvc HvHost IKEEXT LanmanServer LanmanWorkstation LicenseManager MMCSS MpsSvc NaturalAuthentication NgcCtnrSvc NgcSvc NlaSvc OneSyncSvc_dc2a4 ProfSvc Power PrintWorkflowUserSvc_dc2a4 RasAuto RasMan RemoteRegistry RpcEptMapper RpcLocator RpcSs SamSs Schedule SecurityHealthService SENS ShellHWDetection Spooler SSDPSRV SysMain TabletInputService Themes UsoSvc VGAuthService VMTools VSS WebClient WdiServiceHost WinDefend WlanSvc WpnUserService_dc2a4 XblAuthManager XboxNetApiSvc bthserv gpsvc iphlpsvc mpssvc nsi p2psvc perceptionsimulation sppsvc svsvc tzautoupdate vds webthreatdefusersvc_dc2a4 wscsvc
set services_disabled=AJRouter AppVClient DiagTrack DialogBlockingService DistributedLinkTrackingService EdgeUpdate edgeupdatem embeddedmode hidserv shpamsvc spectrum ssh-agent uhssvc wercplsupport webthreatdefsvc wuauserv
set services_autodelay=BITS DoSvc WSearch wscsvc

echo !BRIGHT_WHITE!Ajustement des paramètres service...
echo !BRIGHT_WHITE!Définition de tous les services en mode manuel: 
for /f "tokens=1,2" %%a in ('sc query state^= all ^| find "SERVICE_NAME:"') do (
    echo !DARK_YELLOW!Configuration %%b to start manually...
    sc config "%%b" start= demand
    echo Successfully set %%b to Manual
)

echo !BRIGHT_WHITE!Définition des services importants sur automatique: 
for %%s in (%services_auto%) do (
    echo !DARK_BLUE!Configuration %%s pour démarrer automatiquement...
    sc config "%%s" start= auto
    echo Successfully set %%s to Automatic
)

echo !BRIGHT_WHITE!Setting AutomaticDelayedStart Services: 
for %%s in (%services_autodelay%) do (
    echo !DARK_GREEN!Configuration %%s to start automatically with delay...
    sc config "%%s" start= delayed-auto
    echo Successfully set %%s to AutomaticDelayedStart
)

echo !BRIGHT_WHITE!Setting Disabled Services: 
for %%s in (%services_disabled%) do (
    echo !DARK_RED!Disabling %%s...
    sc config "%%s" start= disabled
    echo Successfully set %%s to Disabled
)
echo !BRIGHT_WHITE!Tous les paramètres de service ont été ajustés avec succès.

REM Désactiver les tâches planifiées
echo !BRIGHT_WHITE!Désactiver les tâches planifiées
schtasks /change /tn "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /disable
schtasks /change /tn "Microsoft\Windows\Application Experience\ProgramDataUpdater" /disable
schtasks /change /tn "Microsoft\Windows\Autochk\Proxy" /disable
schtasks /change /tn "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /disable
schtasks /change /tn "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /disable
schtasks /change /tn "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" /disable
schtasks /change /tn "Microsoft\Windows\Feedback\Siuf\DmClient" /disable
schtasks /change /tn "Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload" /disable
schtasks /change /tn "Microsoft\Windows\Windows Error Reporting\QueueReporting" /disable
schtasks /change /tn "Microsoft\Windows\Application Experience\MareBackup" /disable
schtasks /change /tn "Microsoft\Windows\Application Experience\StartupAppTask" /disable
schtasks /change /tn "Microsoft\Windows\Application Experience\PcaPatchDbTask" /disable
schtasks /change /tn "Microsoft\Windows\Maps\MapsUpdateTask" /disable

REM Désactiver la télémétrie via le registre
echo !BRIGHT_WHITE!Désactiver la télémétrie via le registre
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v AllowTelemetry /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v AllowTelemetry /t REG_DWORD /d "0" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v ContentDeliveryAllowed /t REG_DWORD /d "0" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v OemPreInstalledAppsEnabled /t REG_DWORD /d "0" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v PreInstalledAppsEnabled /t REG_DWORD /d "0" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v PreInstalledAppsEverEnabled /t REG_DWORD /d "0" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SilentInstalledAppsEnabled /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-338387Enabled /t REG_DWORD /d "0" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-338388Enabled /t REG_DWORD /d "0" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-338389Enabled /t REG_DWORD /d "0" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-353698Enabled /t REG_DWORD /d "0" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SystemPaneSuggestionsEnabled /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsConsumerFeatures /t REG_DWORD /d "1" /f
reg add "HKCU\SOFTWARE\Microsoft\Siuf\Rules" /v "NumberOfSIUFInPeriod" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v DoNotShowFeedbackNotifications /t REG_DWORD /d "1" /f
reg add "HKCU\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v DisableTailoredExperiencesWithDiagnosticData /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" /v DisabledByGroupPolicy /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting" /v Disabled /t REG_DWORD /d "1" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Remote Assistance" /v fAllowToGetHelp /t REG_DWORD /d "0" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" /v EnthusiastMode /t REG_DWORD /d "1" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ShowTaskViewButton /t REG_DWORD /d "0" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" /v PeopleBand /t REG_DWORD /d "0" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v LaunchTo /t REG_DWORD /d "1" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v LongPathsEnabled /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" /v SearchOrderConfig /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v SystemResponsiveness /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v NetworkThrottlingIndex /t REG_DWORD /d "4294967295" /f
reg add "HKCU\Control Panel\Desktop" /v MenuShowDelay /t REG_DWORD /d "1" /f
reg add "HKCU\Control Panel\Desktop" /v AutoEndTasks /t REG_DWORD /d "1" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v ClearPageFileAtShutdown /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\ControlSet001\Services\Ndu" /v Start /t REG_DWORD /d "2" /f
reg add "HKCU\Control Panel\Mouse" /v MouseHoverTime /t REG_SZ /d "400" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v IRPStackSize /t REG_DWORD /d "30" /f
reg add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds" /v EnableFeeds /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Feeds" /v ShellFeedsTaskbarViewMode /t REG_DWORD /d "2" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v HideSCAMeetNow /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v GPU Priority /t REG_DWORD /d "8" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v Priority /t REG_DWORD /d "6" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v Scheduling Category /t REG_SZ /d "High" /f

REM Modification de la politique du menu de démarrage en mode hérité...
echo !BRIGHT_WHITE!Modification de la politique du menu de démarrage en mode hérité...
bcdedit /set {current} bootmenupolicy Legacy
echo !BRIGHT_WHITE!La politique du menu de démarrage a été modifiée avec succès en mode hérité.

REM Vérifiez la version de Windows avant d'exécuter des commandes supplémentaires...
echo !BRIGHT_WHITE!Vérifiez la version de Windows avant d'exécuter des commandes supplémentaires...
ver | find "Version 10.0." > nul
if errorlevel 1 goto :eof

REM Modifier les paramètres du Gestionnaire des tâches pour les versions Windows antérieures à 22557
echo !BRIGHT_WHITE!Modifier les paramètres du Gestionnaire des tâches pour les versions Windows antérieures à 22557...
set taskmgr=""
for /f "tokens=2 delims= " %%v in ('reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\TaskManager" /v Preferences ^| find Preferences') do set taskmgr=%%v
if %taskmgr% lss 22557 (
    start "" /min taskmgr.exe
    :loop
    ping -n 1 127.0.0.1 > nul
    reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\TaskManager" /v Preferences > nul 2>&1
    if %errorlevel% equ 0 (
        taskkill /f /im taskmgr.exe
        reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\TaskManager" /v Preferences /t REG_BINARY /d 0 /f
    ) else (
        goto loop
    )
)

REM Group svchost.exe processus
echo !BRIGHT_WHITE!Group svchost.exe processus...
for /f "tokens=1,2,*" %%a in ('wmic memorychip get capacity ^| find /i " " ^| find "."') do set ram=%%c
reg add "HKLM\SYSTEM\CurrentControlSet\Control" /v SvcHostSplitThresholdInKB /t REG_DWORD /d %ram% /f

REM Supprimez AutoLogger-Diagtrack-Listener.etl et refusez les autorisations
echo !BRIGHT_WHITE!Supprimez AutoLogger-Diagtrack-Listener.etl et refusez les autorisations...
set "autoLoggerDir=%PROGRAMDATA%\Microsoft\Diagnosis\ETLLogs\AutoLogger"
if exist "%autoLoggerDir%\AutoLogger-Diagtrack-Listener.etl" (
    del "%autoLoggerDir%\AutoLogger-Diagtrack-Listener.etl"
)
icacls "%autoLoggerDir%" /deny SYSTEM:(OI)(CI)F
:continue

REM Désactiver la détection Wi-Fi
echo !BRIGHT_WHITE!Désactiver la détection Wi-Fi
reg add "HKLM\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" /v Value /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" /v Value /t REG_DWORD /d 0 /f

REM Désactiver le flux d'activité
echo !BRIGHT_WHITE!Désactiver le flux d'activité
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v EnableActivityFeed /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v PublishUserActivities /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v UploadUserActivities /t REG_DWORD /d 0 /f

REM Supprimer les fichiers temporaires
echo !BRIGHT_WHITE!Supprimer les fichiers temporaires
rd /s /q C:\Windows\Temp
rd /s /q %TEMP%
rd /s /q C:\Windows\Prefetch
del /q /s /f "%LocalAppData%\Microsoft\Windows\INetCache\*.*" > nul
rd /s /q %LocalAppData%\Microsoft\Windows\INetCache
rd /s /q %SystemDrive%\$Recycle.Bin
net stop wuauserv
rd /s /q C:\Windows\SoftwareDistribution
net start wuauserv
for /F "tokens=*" %%G in ('wevtutil el') do (wevtutil cl "%%G")
rd /s /q C:\ProgramData\Microsoft\Windows\WER\ReportQueue
rd /s /q C:\ProgramData\Microsoft\Windows\WER\ReportArchive
rd /s /q C:\Windows.old
rd /s /q %LocalAppData%\DirectX Shader Cache
del /f /s /q /a %LocalAppData%\Microsoft\Windows\Explorer\thumbcache_*.db

REM Refuser l'accès à la localisation
echo !BRIGHT_WHITE!Refuser l'accès à la localisation
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" /v Value /t REG_SZ /d "Deny" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" /v SensorPermissionState /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration" /v Status /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\Maps" /v AutoUpdateEnabled /t REG_DWORD /d 0 /f

REM Arrêter les services de groupe résidentiel
echo !BRIGHT_WHITE!Arrêter les services de groupe résidentiel
net stop "HomeGroupListener"
net stop "HomeGroupProvider"
sc config HomeGroupListener start= demand
sc config HomeGroupProvider start= demand
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\HomeGroup" /v DisableHomeGroup /t REG_DWORD /d 1 /f

REM Désactiver le sens de stockage
echo !BRIGHT_WHITE!Désactiver le sens de stockage
reg delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" /f

REM Désactiver la mise en veille prolongée
echo !BRIGHT_WHITE!Désactiver la mise en veille prolongée
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v HibernateEnabled /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" /v ShowHibernateOption /t REG_DWORD /d 0 /f
powercfg.exe /hibernate off

REM Désactiver GameDVR
echo !BRIGHT_WHITE!Désactiver GameDVR
reg add "HKCU\System\GameConfigStore" /v GameDVR_FSEBehavior /t REG_DWORD /d 2 /f
reg add "HKCU\System\GameConfigStore" /v GameDVR_Enabled /t REG_DWORD /d 0 /f
reg add "HKCU\System\GameConfigStore" /v GameDVR_DXGIHonorFSEWindowsCompatible /t REG_DWORD /d 1 /f
reg add "HKCU\System\GameConfigStore" /v GameDVR_HonorUserFSEBehaviorMode /t REG_DWORD /d 1 /f
reg add "HKCU\System\GameConfigStore" /v GameDVR_EFSEFeatureFlags /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\GameDVR" /v AllowGameDVR /t REG_DWORD /d 0 /f

REM Désactiver Telemetry
echo !BRIGHT_WHITE!Désactiver Telemetry...
reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection" /v AllowTelemetry /t REG_DWORD /d 0 /f

REM Désactiver Compatibility Telemetry
echo !BRIGHT_WHITE!Désactiver Compatibility Telemetry...
reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection" /v AllowTelemetry /t REG_DWORD /d 0 /f

REM Désactivere Advertising ID
echo !BRIGHT_WHITE!Désactiver Advertising ID...
reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\AdvertisingInfo" /v Enabled /t REG_DWORD /d 0 /f

REM Désactiver Wi-Fi Sense
echo !BRIGHT_WHITE!Désactiver Wi-Fi Sense...
reg add "HKLM\\Software\\Microsoft\\PolicyManager\\default\\WiFi\\AllowWiFiHotSpotReporting" /v Value /t REG_DWORD /d 0 /f
reg add "HKLM\\Software\\Microsoft\\PolicyManager\\default\\WiFi\\AllowAutoConnectToWiFiSenseHotspots" /v Value /t REG_DWORD /d 0 /f

REM Désactiver Diagnostic Data
echo !BRIGHT_WHITE!Désactiver Diagnostic Data...
reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection" /v MaxTelemetryAllowed /t REG_DWORD /d 0 /f

REM Désactiver Handwriting Data Sharing
echo !BRIGHT_WHITE!Désactiver Handwriting Data Sharing...
reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\HandwritingErrorReports" /v PreventHandwritingErrorReports /t REG_DWORD /d 1 /f

REM Désactiver Windows Hello Biometrics
echo !BRIGHT_WHITE!Désactiver Windows Hello Biometrics...
reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Biometrics" /v Enabled /t REG_DWORD /d 0 /f

REM Désactiver Timeline Function
echo !BRIGHT_WHITE!Désactiver Timeline Function...
reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\System" /v EnableActivityFeed /t REG_DWORD /d 0 /f

REM Désactiver Location Tracking
echo !BRIGHT_WHITE!Désactiver Location Tracking...
reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\LocationAndSensors" /v DisableLocation /t REG_DWORD /d 1 /f

REM Désactiver Feedback Notifications
echo !BRIGHT_WHITE!Désactiver Feedback Notifications...
reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection" /v DoNotShowFeedbackNotifications /t REG_DWORD /d 1 /f

REM Désactiver Windows Tips
echo !BRIGHT_WHITE!Désactiver Windows Tips...
reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\CloudContent" /v DisableSoftLanding /t REG_DWORD /d 1 /f

REM Désactiver Lock Screen Ads
echo !BRIGHT_WHITE!Désactiver Lock Screen Ads...
reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Personalization" /v NoLockScreenCamera /t REG_DWORD /d 1 /f

REM Désactiver Automatic Installation of Apps
echo !BRIGHT_WHITE!Désactiver Automatic Installation of Apps...
reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\CloudContent" /v DisableWindowsConsumerFeatures /t REG_DWORD /d 1 /f

REM Désactiver Start Menu App Suggestions
echo !BRIGHT_WHITE!Désactiver Start Menu App Suggestions...
reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\ContentDeliveryManager" /v SystemPaneSuggestionsEnabled /t REG_DWORD /d 0 /f

REM Désactiver Setting App Ads
echo !BRIGHT_WHITE!Désactiver Setting App Ads...
reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\ContentDeliveryManager" /v SubscribedContent-338393Enabled /t REG_DWORD /d 0 /f

REM Désactiver Customer Experience Improvement Program
echo !BRIGHT_WHITE!Désactiver Customer Experience Improvement Program...
reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\SQMClient\\Windows" /v CEIPEnable /t REG_DWORD /d 0 /f

REM Désactiver Help Experience Program
echo !BRIGHT_WHITE!Désactiver Help Experience Program...
reg add "HKLM\\SOFTWARE\\Policies\\Assist" /v NoImplicitFeedback /t REG_DWORD /d 1 /f

REM Désactiver Experimental Features
echo !BRIGHT_WHITE!Désactiver Experimental Features...
reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\FlightSettings" /v UserPreferredRedirectStage /t REG_DWORD /d 0 /f

REM Désactiver Inventory Collector
echo !BRIGHT_WHITE!Désactiver Inventory Collector...
reg add "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\DataCollection" /v AllowTelemetry /t REG_DWORD /d 0 /f

REM Désactiver Get More Out of Windows
echo !BRIGHT_WHITE!Désactiver Get More Out of Windows...
reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\ContentDeliveryManager" /v SubscribedContent-353698Enabled /t REG_DWORD /d 0 /f

cls
echo Êtes-vous sûr de vouloir désactiver les atténuations du système ? 
echo Cela peut améliorer les performances mais augmente également les risques de sécurité.
echo.
echo !BRIGHT_GREEN!Positif : amélioration des performances du système.
echo !BRIGHT_RED!Négatif : vulnérabilité accrue aux menaces de sécurité.!BRIGHT_WHITE!
echo.
echo Veuillez saisir !BRIGHT_MAGENTA!Oui !BRIGHT_WHITE!pour continuer ou toute autre touche pour abandonner.
set /p UserInput="Entrez votre choix: "
if /I "%UserInput%"=="Oui" (
    echo !BRIGHT_WHITE!Désactivation des atténuations...
    call :DisableMitigations
    echo !BRIGHT_WHITE!Les atténuations ont été désactivées.
) else (
    echo !BRIGHT_RED!Opération annulée.
)
pause
exit

:DisableMitigations
    powershell -Command "& {ForEach($v in (Get-Command -Name 'Set-ProcessMitigation').Parameters['Disable'].Attributes.ValidValues){Set-ProcessMitigation -System -Disable $v.ToString() -ErrorAction SilentlyContinue}}"
    powershell -Command "& {Remove-Item -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\*' -Recurse -ErrorAction SilentlyContinue}"
    call :UpdateRegistry
    goto :eof

:UpdateRegistry
    reg add "HKLM\SOFTWARE\Policies\Microsoft\FVE" /v "DisableExternalDMAUnderLock" /t REG_DWORD /d "0" /f
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" /v "EnableVirtualizationBasedSecurity" /t REG_DWORD /d "0" /f
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" /v "HVCIMATRequired" /t REG_DWORD /d "0" /f
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "DisableExceptionChainValidation" /t REG_DWORD /d "1" /f
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "KernelSEHOPEnabled" /t REG_DWORD /d "0" /f
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "EnableCfg" /t REG_DWORD /d "0" /f
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" /v "ProtectionMode" /t REG_DWORD /d "0" /f
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettings" /t REG_DWORD /d "1" /f
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverride" /t REG_DWORD /d "3" /f
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverrideMask" /t REG_DWORD /d "3" /f
pause

cls
echo !BRIGHT_WHITE!Tous les ajustements ont été appliqués avec succès ! Pour que les modifications prennent effet, veuillez redémarrer votre ordinateur.
echo Press !BRIGHT_MAGENTA!ENTER !BRIGHT_WHITE!pour revenir au menu principal.
pause >nul
cls
goto :Main-Menu

REM Option 2: Information
:Menu_[2] Information
cls
echo.
echo %BRIGHT_BLUE%Bienvenue dans Tool Opti BlizzyC V0.9 - Votre optimiseur de performances ultime !
echo.
echo %WHITE%Tool Opti BlizzyC V0.9 est un outil méticuleusement conçu, dans le seul but d'élever votre expérience Windows vers de nouveaux sommets.
echo %WHITE%Pour ce faire, il ajuste avec précision divers paramètres du système et optimise les paramètres de votre système pour offrir des performances optimales et une sécurité robuste.
echo.
echo %DARK_RED%Avertissement : nous nous efforçons de garantir la plus haute qualité et fiabilité. Cependant, l'utilisation de cet outil est à votre propre discrétion.
echo %DARK_RED%Nous vous recommandons fortement de conserver une sauvegarde de votre système pour des raisons de sécurité.
echo.
echo %BRIGHT_BLUE%Rester connecté:
echo %WHITE%Pour des mises à jour, des informations et bien plus encore, suivez-nous sur Twitter : @c_bliizzy
echo.
pause
goto :Main-Menu

REM Option E: Exit
:Menu_[E] Exit
exit

REM Colors
:Colors
set "DARK_BLACK=[30m"
set "DARK_RED=[31m"
set "DARK_GREEN=[32m"
set "DARK_YELLOW=[33m"
set "DARK_BLUE=[34m"
set "DARK_MAGENTA=[35m"
set "DARK_CYAN=[36m"
set "DARK_WHITE=[37m"
set "BRIGHT_BLACK=[90m"
set "BRIGHT_RED=[91m"
set "BRIGHT_GREEN=[92m"
set "BRIGHT_YELLOW=[93m"
set "BRIGHT_BLUE=[94m"
set "BRIGHT_MAGENTA=[95m"
set "BRIGHT_CYAN=[96m"
set "BRIGHT_WHITE=[97m"
set "WHITE=[97m"
exit /b
:EOF
