; Dumplyzer NSIS template based on Tauri 2.11.5 installer.nsi.
; Default INSTDIR for perMachine is $PROGRAMFILES64\${PRODUCTNAME}
; (Program Files on the Windows system drive). User data stays in
; %LOCALAPPDATA%\Dumplyzer and is never mixed with the install tree.
; Kernel PDBs/ISF are not copied into INSTDIR. After install, the app
; stores a per-build file under %LOCALAPPDATA%\Dumplyzer\symbols when
; the user agrees (Download & Continue) or browses to a local file.
Unicode true
ManifestDPIAware true
; Add in `dpiAwareness` `PerMonitorV2` to manifest for Windows 10 1607+ (note this should not affect lower versions since they should be able to ignore this and pick up `dpiAware` `true` set by `ManifestDPIAware true`)
; Currently undocumented on NSIS's website but is in the Docs folder of source tree, see
; https://github.com/kichik/nsis/blob/5fc0b87b819a9eec006df4967d08e522ddd651c9/Docs/src/attributes.but#L286-L300
; https://github.com/tauri-apps/tauri/pull/10106
ManifestDPIAwareness PerMonitorV2

!if "{{compression}}" == "none"
 SetCompress off
!else
 ; Set the compression algorithm. We default to LZMA.
 SetCompressor /SOLID "{{compression}}"
!endif

; Keep above !include to stay ahead of any plugin command
; see https://github.com/tauri-apps/tauri/pull/15422#discussion_r3289239624
{{#if signed_plugins_path}}
!addplugindir "{{signed_plugins_path}}"
{{/if}}

!include MUI2.nsh
!include FileFunc.nsh
!include x64.nsh
!include WordFunc.nsh
!include "utils.nsh"
!include "FileAssociation.nsh"
!include "Win\COM.nsh"
!include "Win\Propkey.nsh"
!include "StrFunc.nsh"
${StrCase}
${StrLoc}

{{#if installer_hooks}}
!include "{{installer_hooks}}"
{{/if}}

!define WEBVIEW2APPGUID "{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}"

!define MANUFACTURER "{{manufacturer}}"
!define PRODUCTNAME "{{product_name}}"
!define VERSION "{{version}}"
!define VERSIONWITHBUILD "{{version_with_build}}"
!define HOMEPAGE "{{homepage}}"
!define INSTALLMODE "{{install_mode}}"
!define LICENSE "{{license}}"
!define INSTALLERICON "{{installer_icon}}"
!define SIDEBARIMAGE "{{sidebar_image}}"
!define HEADERIMAGE "{{header_image}}"
!define UNINSTALLERICON "{{uninstaller_icon}}"
!define UNINSTALLERHEADERIMAGE "{{uninstaller_header_image}}"
!define MAINBINARYNAME "{{main_binary_name}}"
!define MAINBINARYSRCPATH "{{main_binary_path}}"
!define BUNDLEID "{{bundle_id}}"
!define COPYRIGHT "{{copyright}}"
!define OUTFILE "{{out_file}}"
!define ARCH "{{arch}}"
!define ADDITIONALPLUGINSPATH "{{additional_plugins_path}}"
!define ALLOWDOWNGRADES "{{allow_downgrades}}"
!define DISPLAYLANGUAGESELECTOR "{{display_language_selector}}"
!define INSTALLWEBVIEW2MODE "{{install_webview2_mode}}"
!define WEBVIEW2INSTALLERARGS "{{webview2_installer_args}}"
!define WEBVIEW2BOOTSTRAPPERPATH "{{webview2_bootstrapper_path}}"
!define WEBVIEW2INSTALLERPATH "{{webview2_installer_path}}"
!define MINIMUMWEBVIEW2VERSION "{{minimum_webview2_version}}"
!define UNINSTKEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCTNAME}"
!define MANUKEY "Software\${MANUFACTURER}"
!define MANUPRODUCTKEY "${MANUKEY}\${PRODUCTNAME}"
!define UNINSTALLERSIGNCOMMAND "{{uninstaller_sign_cmd}}"
!define ESTIMATEDSIZE "{{estimated_size}}"
!define STARTMENUFOLDER "{{start_menu_folder}}"

Var PassiveMode
Var UpdateMode
Var NoShortcutMode
Var WixMode
Var OldMainBinaryName
Var InstalledVersion
Var VersionCmp
Var PreviousInstallDir
Var NeedRemovePrevious
Var RemovePreviousDone
Var RemoveStatusLabel
Var RemoveProgress
Var RemoveTreeStarted
Var RemoveTargetDir
Var RemoveWipeUserData
Var RemoveKeepUninstaller
Var UninstallTreeRemoved
Var DeleteAppDataCheckbox
Var DeleteAppDataCheckboxState
Var RemovePollCount

Name "${PRODUCTNAME}"
BrandingText "${COPYRIGHT}"
OutFile "${OUTFILE}"

; We don't actually use this value as default install path,
; it's just for nsis to append the product name folder in the directory selector
; https://nsis.sourceforge.io/Reference/InstallDir
!define PLACEHOLDER_INSTALL_DIR "placeholder\${PRODUCTNAME}"
InstallDir "${PLACEHOLDER_INSTALL_DIR}"

VIProductVersion "${VERSIONWITHBUILD}"
VIAddVersionKey "ProductName" "${PRODUCTNAME}"
VIAddVersionKey "FileDescription" "${PRODUCTNAME}"
VIAddVersionKey "LegalCopyright" "${COPYRIGHT}"
VIAddVersionKey "FileVersion" "${VERSION}"
VIAddVersionKey "ProductVersion" "${VERSION}"

# additional plugins
!addplugindir "${ADDITIONALPLUGINSPATH}"

; Uninstaller signing command
!if "${UNINSTALLERSIGNCOMMAND}" != ""
 !uninstfinalize '${UNINSTALLERSIGNCOMMAND}'
!endif

; Handle install mode, `perUser`, `perMachine` or `both`
!if "${INSTALLMODE}" == "perMachine"
 RequestExecutionLevel admin
!endif

!if "${INSTALLMODE}" == "currentUser"
 RequestExecutionLevel user
!endif

!if "${INSTALLMODE}" == "both"
 !define MULTIUSER_MUI
 !define MULTIUSER_INSTALLMODE_INSTDIR "${PRODUCTNAME}"
 !define MULTIUSER_INSTALLMODE_COMMANDLINE
 !if "${ARCH}" == "x64"
 !define MULTIUSER_USE_PROGRAMFILES64
 !else if "${ARCH}" == "arm64"
 !define MULTIUSER_USE_PROGRAMFILES64
 !endif
 !define MULTIUSER_INSTALLMODE_DEFAULT_REGISTRY_KEY "${UNINSTKEY}"
 !define MULTIUSER_INSTALLMODE_DEFAULT_REGISTRY_VALUENAME "CurrentUser"
 !define MULTIUSER_INSTALLMODEPAGE_SHOWUSERNAME
 !define MULTIUSER_INSTALLMODE_FUNCTION RestorePreviousInstallLocation
 !define MULTIUSER_EXECUTIONLEVEL Highest
 !include MultiUser.nsh
!endif

; Installer icon
!if "${INSTALLERICON}" != ""
 !define MUI_ICON "${INSTALLERICON}"
!endif

; Installer sidebar image
!if "${SIDEBARIMAGE}" != ""
 !define MUI_WELCOMEFINISHPAGE_BITMAP "${SIDEBARIMAGE}"
!endif

; Enable header images for installer and uninstaller pages when either image is configured.
!if "${HEADERIMAGE}" != ""
 !define MUI_HEADERIMAGE
!else if "${UNINSTALLERHEADERIMAGE}" != ""
 !define MUI_HEADERIMAGE
!endif

; Installer header image
!if "${HEADERIMAGE}" != ""
 !define MUI_HEADERIMAGE_BITMAP "${HEADERIMAGE}"
!endif

; Uninstaller header image
!if "${UNINSTALLERHEADERIMAGE}" != ""
 !define MUI_HEADERIMAGE_UNBITMAP "${UNINSTALLERHEADERIMAGE}"
!endif

; Uninstaller icon
!if "${UNINSTALLERICON}" != ""
 !define MUI_UNICON "${UNINSTALLERICON}"
!endif

; Define registry key to store installer language
!define MUI_LANGDLL_REGISTRY_ROOT "HKCU"
!define MUI_LANGDLL_REGISTRY_KEY "${MANUPRODUCTKEY}"
!define MUI_LANGDLL_REGISTRY_VALUENAME "Installer Language"

; Installer pages, must be ordered as they appear
; 1. Welcome Page
!define MUI_PAGE_CUSTOMFUNCTION_PRE SkipIfPassive
!insertmacro MUI_PAGE_WELCOME

; 2. License Page (if defined)
!if "${LICENSE}" != ""
 !define MUI_PAGE_CUSTOMFUNCTION_PRE SkipIfPassive
 !insertmacro MUI_PAGE_LICENSE "${LICENSE}"
!endif

; 3. Install mode (if it is set to `both`)
!if "${INSTALLMODE}" == "both"
 !define MUI_PAGE_CUSTOMFUNCTION_PRE SkipIfPassive
 !insertmacro MULTIUSER_PAGE_INSTALLMODE
!endif

; 4. Custom page to ask user if he wants to reinstall/uninstall
; only if a previous installation was detected
Var ReinstallPageCheck
Page custom PageReinstall PageLeaveReinstall
; HideWindow made Setup vanish for several seconds. Exec of powershell.exe
; also flashes a console even with -WindowStyle Hidden. Delete with cmd.exe
; created via CreateProcess(CREATE_NO_WINDOW) and poll progress from a timer.
Page custom PageRemovePrevious PageRemovePreviousLeave
Function PageReinstall
 ; Uninstall previous WiX installation if exists.
 ;
 ; A WiX installer stores the installation info in registry
 ; using a UUID and so we have to loop through all keys under
 ; `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`
 ; and check if `DisplayName` and `Publisher` keys match ${PRODUCTNAME} and ${MANUFACTURER}
 ;
 ; This has a potential issue that there maybe another installation that matches
 ; our ${PRODUCTNAME} and ${MANUFACTURER} but wasn't installed by our WiX installer,
 ; however, this should be fine since the user will have to confirm the uninstallation
 ; and they can chose to abort it if doesn't make sense.
 StrCpy $0 0
 wix_loop:
 EnumRegKey $1 HKLM "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" $0
 StrCmp $1 "" wix_loop_done ; Exit loop if there is no more keys to loop on
 IntOp $0 $0 + 1
 ReadRegStr $R0 HKLM "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\$1" "DisplayName"
 ReadRegStr $R1 HKLM "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\$1" "Publisher"
 StrCmp "$R0$R1" "${PRODUCTNAME}${MANUFACTURER}" 0 wix_loop
 ReadRegStr $R0 HKLM "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\$1" "UninstallString"
 ${StrCase} $R1 $R0 "L"
 ${StrLoc} $R0 $R1 "msiexec" ">"
 StrCmp $R0 0 0 wix_loop_done
 StrCpy $WixMode 1
 StrCpy $R6 "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\$1"
 Goto compare_version
 wix_loop_done:

 ; Check if there is an existing installation, if not, abort the reinstall page
 ReadRegStr $R0 SHCTX "${UNINSTKEY}" ""
 ReadRegStr $R1 SHCTX "${UNINSTKEY}" "UninstallString"
 ${IfThen} "$R0$R1" == "" ${|} Abort ${|}

 ; Compare this installer version with the existing installation
 ; and modify the messages presented to the user accordingly
 compare_version:
 StrCpy $R4 "$(older)"
 ${If} $WixMode = 1
 ReadRegStr $R8 HKLM "$R6" "DisplayVersion"
 ${Else}
 ReadRegStr $R8 SHCTX "${UNINSTKEY}" "DisplayVersion"
 ${EndIf}
 ${If} $R8 == ""
 StrCpy $InstalledVersion "unknown"
 ${Else}
 StrCpy $InstalledVersion $R8
 ${EndIf}

 nsis_tauri_utils::SemverCompare "${VERSION}" $R8
 Pop $VersionCmp
 ; Reinstalling the same version
 ${If} $VersionCmp = 0
 StrCpy $R1 "$(alreadyInstalledLong)"
 StrCpy $R2 "$(addOrReinstall)"
 StrCpy $R3 "$(uninstallApp)"
 !insertmacro MUI_HEADER_TEXT "$(alreadyInstalled)" "$(chooseMaintenanceOption)"
 ; Upgrading: previous build must be removed. Overlay upgrades leave a mixed
 ; Program Files tree (locked python312.dll, stale engine).
 ${ElseIf} $VersionCmp = 1
 StrCpy $R1 "Dumplyzer $InstalledVersion is already installed.$\r$\nSetup will uninstall version $InstalledVersion before installing version ${VERSION}.$\r$\nYour Dumplyzer data will be preserved.$\r$\n$\r$\nClick Next to uninstall and continue, or Cancel to exit Setup."
 StrCpy $R2 ""
 StrCpy $R3 ""
 !insertmacro MUI_HEADER_TEXT "Previous version installed" "Uninstall required"
 ; Downgrading
 ${ElseIf} $VersionCmp = -1
 StrCpy $R1 "$(newerVersionInstalled)"
 StrCpy $R2 "$(uninstallBeforeInstalling)"
 !if "${ALLOWDOWNGRADES}" == "true"
 StrCpy $R3 "$(dontUninstall)"
 !else
 StrCpy $R3 "$(dontUninstallDowngrade)"
 !endif
 !insertmacro MUI_HEADER_TEXT "$(alreadyInstalled)" "$(choowHowToInstall)"
 ${Else}
 Abort
 ${EndIf}

 ; Skip showing the page if passive
 ;
 ; Note that we don't call this earlier at the begining
 ; of this function because we need to populate some variables
 ; related to current installed version if detected and whether
 ; we are downgrading or not.
 ${If} $PassiveMode = 1
 Call PageLeaveReinstall
 ${Else}
 nsDialogs::Create 1018
 Pop $R4
 ${IfThen} $(^RTL) = 1 ${|} nsDialogs::SetRTL $(^RTL) ${|}

 ${If} $R2 == ""
 ${NSD_CreateLabel} 0 0 100% 56u $R1
 Pop $R1
 ${Else}
 ${NSD_CreateLabel} 0 0 100% 28u $R1
 Pop $R1

 ${NSD_CreateRadioButton} 0u 40u 100% 10u $R2
 Pop $R2
 ${NSD_OnClick} $R2 PageReinstallUpdateSelection

 ${If} $R3 != ""
 ${NSD_CreateRadioButton} 0u 56u 100% 10u $R3
 Pop $R3
 ; Disable this radio button if downgrading and downgrades are disabled
 !if "${ALLOWDOWNGRADES}" == "false"
 ${IfThen} $VersionCmp = -1 ${|} EnableWindow $R3 0 ${|}
 !endif
 ${NSD_OnClick} $R3 PageReinstallUpdateSelection
 ${EndIf}

 ${If} $ReinstallPageCheck <> 2
 SendMessage $R2 ${BM_SETCHECK} ${BST_CHECKED} 0
 ${ElseIf} $R3 != ""
 SendMessage $R3 ${BM_SETCHECK} ${BST_CHECKED} 0
 ${Else}
 SendMessage $R2 ${BM_SETCHECK} ${BST_CHECKED} 0
 ${EndIf}

 ${NSD_SetFocus} $R2
 ${EndIf}
 nsDialogs::Show
 ${EndIf}
FunctionEnd
Function PageReinstallUpdateSelection
 ${NSD_GetState} $R2 $R1
 ${If} $R1 == ${BST_CHECKED}
 StrCpy $ReinstallPageCheck 1
 ${Else}
 StrCpy $ReinstallPageCheck 2
 ${EndIf}
FunctionEnd
Function PageLeaveReinstall
 ${If} $PassiveMode <> 1
 ${AndIf} $VersionCmp <> 1
 ${NSD_GetState} $R2 $R1
 ${EndIf}

 ; If migrating from Wix, always uninstall
 ${If} $WixMode = 1
 Goto reinst_uninstall
 ${EndIf}

 ; $VersionCmp: same(0) / this installer is newer(1) / this installer is older(-1)
 ; $R1 radio state: 1 = first choice, 0 = second choice
 ;
 ; A newer installer never overlays Program Files. Next on that page is
 ; confirmation to uninstall the previous version, then continue setup.
 ${If} $VersionCmp = 1
 Goto reinst_uninstall
 ${EndIf}

 ; In-app updater (/UPDATE) replacing the same version: copy over files.
 ${If} $UpdateMode = 1
 Goto reinst_done
 ${EndIf}

 ${If} $VersionCmp = 0 ; Same version, proceed
 ${If} $R1 = 1 ; User chose to add/reinstall
 Goto reinst_done
 ${Else} ; User chose to uninstall
 Goto reinst_uninstall
 ${EndIf}
 ${ElseIf} $VersionCmp = -1 ; Downgrading
 ${If} $R1 = 1 ; User chose to uninstall
 Goto reinst_uninstall
 ${Else}
 Goto reinst_done ; User chose NOT to uninstall
 ${EndIf}
 ${EndIf}

 reinst_uninstall:
 StrCpy $NeedRemovePrevious 1
 Goto reinst_done
 reinst_done:
FunctionEnd

; ExecWait on uninstall.exe / rmdir freezes the wizard: NSIS is single-threaded
; and the bundled CPython tree is thousands of files. Delete from hidden cmd.exe
; (CREATE_NO_WINDOW) and pump a determinate progress bar from a nsDialogs timer.
!if "${ARCH}" == "x86"
 !define DUMPLYZER_STARTUPINFO_CB 68
 !define DUMPLYZER_PROCESSINFO_CB 16
!else
 !define DUMPLYZER_STARTUPINFO_CB 104
 !define DUMPLYZER_PROCESSINFO_CB 24
!endif
!define CREATE_NO_WINDOW 0x08000000

!macro WriteRemoveInstallTreeScript UN
Function ${UN}WriteRemoveInstallTreeScript
 InitPluginsDir
 FileOpen $0 "$PLUGINSDIR\remove-install-tree.cmd" w
 FileWrite $0 "@echo off$\r$\n"
 FileWrite $0 "setlocal$\r$\n"
 FileWrite $0 "set $\"ROOT=%~1$\"$\r$\n"
 FileWrite $0 "set $\"STATUS=%~2$\"$\r$\n"
 FileWrite $0 "set $\"WIPE=%~3$\"$\r$\n"
 FileWrite $0 "set $\"KEEPUN=%~4$\"$\r$\n"
 FileWrite $0 "call :S 2 $\"Stopping Dumplyzer...$\"$\r$\n"
 FileWrite $0 "taskkill /F /IM dumplyzer.exe /T >nul 2>&1$\r$\n"
 FileWrite $0 "ping -n 2 127.0.0.1 >nul$\r$\n"
 FileWrite $0 "call :S 5 $\"Preparing to remove files...$\"$\r$\n"
 FileWrite $0 "call :D $\"%ROOT%\resources\runtime\Lib\site-packages\volatility3$\" 20$\r$\n"
 FileWrite $0 "call :D $\"%ROOT%\resources\runtime\Lib\site-packages$\" 35$\r$\n"
 FileWrite $0 "call :D $\"%ROOT%\resources\runtime\Lib$\" 45$\r$\n"
 FileWrite $0 "call :D $\"%ROOT%\resources\runtime$\" 55$\r$\n"
 FileWrite $0 "call :D $\"%ROOT%\resources\tools$\" 65$\r$\n"
 FileWrite $0 "call :D $\"%ROOT%\resources$\" 75$\r$\n"
 FileWrite $0 "if $\"%KEEPUN%$\"==$\"1$\" ($\r$\n"
 FileWrite $0 "call :S 85 $\"Removing application files...$\"$\r$\n"
 FileWrite $0 "for /d %%D in ($\"%ROOT%\*$\") do rmdir /S /Q $\"%%D$\" >nul 2>&1$\r$\n"
 FileWrite $0 "for %%F in ($\"%ROOT%\*$\") do if /I not $\"%%~nxF$\"==$\"uninstall.exe$\" del /F /Q $\"%%F$\" >nul 2>&1$\r$\n"
 FileWrite $0 ") else ($\r$\n"
 FileWrite $0 "call :S 90 $\"Removing application files...$\"$\r$\n"
 FileWrite $0 "rmdir /S /Q $\"%ROOT%$\" >nul 2>&1$\r$\n"
 FileWrite $0 ")$\r$\n"
 FileWrite $0 "if $\"%WIPE%$\"==$\"1$\" ($\r$\n"
 FileWrite $0 "call :S 95 $\"Removing application data...$\"$\r$\n"
 FileWrite $0 "rmdir /S /Q $\"%LOCALAPPDATA%\Dumplyzer$\" >nul 2>&1$\r$\n"
 FileWrite $0 "rmdir /S /Q $\"%APPDATA%\${BUNDLEID}$\" >nul 2>&1$\r$\n"
 FileWrite $0 "rmdir /S /Q $\"%LOCALAPPDATA%\${BUNDLEID}$\" >nul 2>&1$\r$\n"
 FileWrite $0 ")$\r$\n"
 FileWrite $0 "call :S 100 $\"done$\"$\r$\n"
 FileWrite $0 "echo done>$\"%STATUS%\remove-done.txt$\"$\r$\n"
 FileWrite $0 "exit /B 0$\r$\n"
 FileWrite $0 ":S$\r$\n"
 FileWrite $0 "echo %~1>$\"%STATUS%\remove-percent.txt$\"$\r$\n"
 FileWrite $0 "echo %~2>$\"%STATUS%\remove-text.txt$\"$\r$\n"
 FileWrite $0 "goto :eof$\r$\n"
 FileWrite $0 ":D$\r$\n"
 FileWrite $0 "if exist $\"%~1$\" ($\r$\n"
 FileWrite $0 "call :S %~2 $\"Removing %~nx1$\"$\r$\n"
 FileWrite $0 "rmdir /S /Q $\"%~1$\" >nul 2>&1$\r$\n"
 FileWrite $0 "if exist $\"%~1$\" del /F /Q $\"%~1$\" >nul 2>&1$\r$\n"
 FileWrite $0 ")$\r$\n"
 FileWrite $0 "goto :eof$\r$\n"
 FileClose $0
FunctionEnd
!macroend
!insertmacro WriteRemoveInstallTreeScript ""
!insertmacro WriteRemoveInstallTreeScript "un."

!macro ExecHiddenCommand UN
Function ${UN}ExecHiddenCommand
 ; $9 = command line. CREATE_NO_WINDOW avoids a console flash (Exec cannot).
 System::Alloc ${DUMPLYZER_STARTUPINFO_CB}
 Pop $1
 System::Call "*$1(i ${DUMPLYZER_STARTUPINFO_CB})"
 System::Alloc ${DUMPLYZER_PROCESSINFO_CB}
 Pop $2
 StrCpy $8 "$SYSDIR\cmd.exe"
 System::Call "kernel32::CreateProcessW(t r8, t r9, n, n, i 0, i ${CREATE_NO_WINDOW}, n, n, p r1, p r2) i .r3"
 ${If} $3 = 0
 nsExec::ExecToLog `$9`
 ${EndIf}
 ${If} $2 != ""
 System::Call "*$2(p .r4, p .r5)"
 ${If} $4 != 0
 ${AndIf} $4 != ""
 System::Call "kernel32::CloseHandle(p r4)"
 ${EndIf}
 ${If} $5 != 0
 ${AndIf} $5 != ""
 System::Call "kernel32::CloseHandle(p r5)"
 ${EndIf}
 ${EndIf}
 System::Free $1
 System::Free $2
FunctionEnd
!macroend
!insertmacro ExecHiddenCommand ""
!insertmacro ExecHiddenCommand "un."

!macro StartRemoveInstallTree UN
Function ${UN}StartRemoveInstallTree
 ${If} $RemoveTreeStarted = 1
 Return
 ${EndIf}
 Call ${UN}WriteRemoveInstallTreeScript
 Delete "$PLUGINSDIR\remove-done.txt"
 Delete "$PLUGINSDIR\remove-percent.txt"
 Delete "$PLUGINSDIR\remove-text.txt"
 StrCpy $RemovePollCount 0
 StrCpy $9 '"$SYSDIR\cmd.exe" /C call "$PLUGINSDIR\remove-install-tree.cmd" "$RemoveTargetDir" "$PLUGINSDIR" $RemoveWipeUserData $RemoveKeepUninstaller'
 Call ${UN}ExecHiddenCommand
 StrCpy $RemoveTreeStarted 1
FunctionEnd
!macroend
!insertmacro StartRemoveInstallTree ""
!insertmacro StartRemoveInstallTree "un."

!macro RemoveInstallTreeBlocking UN
Function ${UN}RemoveInstallTreeBlocking
 Call ${UN}WriteRemoveInstallTreeScript
 Delete "$PLUGINSDIR\remove-done.txt"
 Delete "$PLUGINSDIR\remove-percent.txt"
 Delete "$PLUGINSDIR\remove-text.txt"
 nsExec::ExecToLog '"$SYSDIR\cmd.exe" /C call "$PLUGINSDIR\remove-install-tree.cmd" "$RemoveTargetDir" "$PLUGINSDIR" $RemoveWipeUserData $RemoveKeepUninstaller'
 ${IfThen} ${Errors} ${|} StrCpy $0 2 ${|}
FunctionEnd
!macroend
!insertmacro RemoveInstallTreeBlocking ""
!insertmacro RemoveInstallTreeBlocking "un."

!macro PollRemoveInstallTree UN
Function ${UN}PollRemoveInstallTree
 StrCpy $0 0
 IntOp $RemovePollCount $RemovePollCount + 1
 ${If} ${FileExists} "$PLUGINSDIR\remove-done.txt"
 StrCpy $0 1
 ${If} $RemoveProgress != ""
 SendMessage $RemoveProgress 0x402 100 0
 ${EndIf}
 Return
 ${EndIf}
 ${If} $RemovePollCount > 25
 ${AndIfNot} ${FileExists} "$PLUGINSDIR\remove-percent.txt"
 StrCpy $0 2
 Return
 ${EndIf}
 ${If} $RemovePollCount > 3600
 StrCpy $0 2
 Return
 ${EndIf}
 ${If} ${FileExists} "$PLUGINSDIR\remove-percent.txt"
 ClearErrors
 FileOpen $1 "$PLUGINSDIR\remove-percent.txt" r
 FileRead $1 $2
 FileClose $1
 StrCpy $3 $2 1 -1
 ${If} $3 == "$\r"
 StrCpy $2 $2 -1
 ${EndIf}
 ${If} $RemoveProgress != ""
 SendMessage $RemoveProgress 0x402 $2 0
 ${EndIf}
 ${EndIf}
 ${If} ${FileExists} "$PLUGINSDIR\remove-text.txt"
 ClearErrors
 FileOpen $1 "$PLUGINSDIR\remove-text.txt" r
 FileRead $1 $2
 FileClose $1
 StrCpy $3 $2 1 -1
 ${If} $3 == "$\r"
 StrCpy $2 $2 -1
 ${EndIf}
 ${If} $2 == "done"
 StrCpy $2 "Finishing..."
 ${EndIf}
 ${If} $RemoveStatusLabel != ""
 ${NSD_SetText} $RemoveStatusLabel $2
 ${EndIf}
 ${EndIf}
FunctionEnd
!macroend
!insertmacro PollRemoveInstallTree ""
!insertmacro PollRemoveInstallTree "un."

!macro SetWizardButtonsEnabled UN
Function ${UN}SetWizardButtonsEnabled
 GetDlgItem $1 $HWNDPARENT 1
 EnableWindow $1 $0
 GetDlgItem $1 $HWNDPARENT 2
 EnableWindow $1 $0
 GetDlgItem $1 $HWNDPARENT 3
 EnableWindow $1 $0
FunctionEnd
!macroend
!insertmacro SetWizardButtonsEnabled ""
!insertmacro SetWizardButtonsEnabled "un."

!macro ShowRemoveProgressPage UN
Function ${UN}ShowRemoveProgressPage
 nsDialogs::Create 1018
 Pop $R4
 ${IfThen} $(^RTL) = 1 ${|} nsDialogs::SetRTL $(^RTL) ${|}
 ${NSD_CreateLabel} 0 0 100% 12u $R8
 Pop $R1
 ${NSD_CreateProgressBar} 0 18u 100% 12u
 Pop $RemoveProgress
 SendMessage $RemoveProgress 0x406 0 100
 SendMessage $RemoveProgress 0x402 0 0
 ${NSD_CreateLabel} 0 36u 100% 28u "Preparing..."
 Pop $RemoveStatusLabel
 StrCpy $0 0
 Call ${UN}SetWizardButtonsEnabled
 Call ${UN}StartRemoveInstallTree
 ${NSD_CreateTimer} ${UN}RemoveTreeTick 200
 nsDialogs::Show
FunctionEnd
!macroend
!insertmacro ShowRemoveProgressPage ""
!insertmacro ShowRemoveProgressPage "un."

Function PreparePreviousInstallDir
 ReadRegStr $PreviousInstallDir SHCTX "${MANUPRODUCTKEY}" ""
 ${If} $PreviousInstallDir == ""
 ReadRegStr $PreviousInstallDir SHCTX "${UNINSTKEY}" "InstallLocation"
 ${EndIf}
 StrCpy $R7 $PreviousInstallDir 1
 ${If} $R7 == '"'
 StrLen $R7 $PreviousInstallDir
 IntOp $R7 $R7 - 2
 StrCpy $PreviousInstallDir $PreviousInstallDir $R7 1
 ${EndIf}
 ${If} $PreviousInstallDir == ""
 StrCpy $PreviousInstallDir $INSTDIR
 ${EndIf}
 ${If} $PreviousInstallDir != ""
 StrCpy $INSTDIR $PreviousInstallDir
 ${EndIf}
FunctionEnd

Function FinishRemoveInstallTree
 ${If} ${FileExists} "$RemoveTargetDir\${MAINBINARYNAME}.exe"
 ${AndIf} ${FileExists} "$RemoveTargetDir\uninstall.exe"
 StrCpy $R9 " /S"
 ${IfThen} $UpdateMode = 1 ${|} StrCpy $R9 "$R9 /UPDATE" ${|}
 ${IfThen} $PassiveMode = 1 ${|} StrCpy $R9 "$R9 /P" ${|}
 ExecWait '"$RemoveTargetDir\uninstall.exe"$R9 _?=$RemoveTargetDir' $0
 ${EndIf}
 ${If} ${FileExists} "$RemoveTargetDir\${MAINBINARYNAME}.exe"
 nsExec::ExecToLog '"$SYSDIR\cmd.exe" /C if exist "$RemoveTargetDir" rmdir /S /Q "$RemoveTargetDir"'
 RMDir /r /REBOOTOK "$RemoveTargetDir"
 ${EndIf}
FunctionEnd

Function un.FinishRemoveInstallTree
 ; Keep uninstall.exe on disk until this uninstall wizard completes. Windows
 ; Settings re-checks UninstallString; deleting it here makes the file "not found".
 nsExec::ExecToLog '"$SYSDIR\cmd.exe" /C if exist "$RemoveTargetDir\resources" rmdir /S /Q "$RemoveTargetDir\resources"'
FunctionEnd

Function UninstallPreviousInstall
 ClearErrors
 ${If} $WixMode = 1
 HideWindow
 ReadRegStr $R1 HKLM "$R6" "UninstallString"
 ExecWait '$R1' $0
 BringToFront
 ${IfThen} ${Errors} ${|} StrCpy $0 2 ${|}
 Return
 ${EndIf}

 Call PreparePreviousInstallDir
 StrCpy $RemoveTargetDir $PreviousInstallDir
 StrCpy $RemoveWipeUserData 0
 StrCpy $RemoveKeepUninstaller 0
 StrCpy $RemoveTreeStarted 0
 Call RemoveInstallTreeBlocking
 Call FinishRemoveInstallTree
 ${IfThen} ${Errors} ${|} StrCpy $0 2 ${|}
FunctionEnd

Function PreviousInstallStillPresent
 ${If} ${FileExists} "$PreviousInstallDir\${MAINBINARYNAME}.exe"
 ${OrIf} ${FileExists} "$INSTDIR\${MAINBINARYNAME}.exe"
 ${OrIf} ${FileExists} "$RemoveTargetDir\${MAINBINARYNAME}.exe"
 StrCpy $0 1
 ${Else}
 StrCpy $0 0
 ${EndIf}
FunctionEnd

Function un.InstallTreeStillPresent
 ${If} ${FileExists} "$RemoveTargetDir\${MAINBINARYNAME}.exe"
 ${OrIf} ${FileExists} "$INSTDIR\${MAINBINARYNAME}.exe"
 StrCpy $0 1
 ${Else}
 StrCpy $0 0
 ${EndIf}
FunctionEnd

Function AbortIfPreviousUninstallFailed
 ${If} $WixMode = 1
 ${AndIf} $0 <> 0
 ${If} $0 = 1602
 Abort
 ${EndIf}
 MessageBox MB_ICONEXCLAMATION "$(unableToUninstall)"
 Abort
 ${EndIf}

 Call PreviousInstallStillPresent
 ${If} $0 = 1
 MessageBox MB_ICONEXCLAMATION "Could not remove the previous Dumplyzer install.$\r$\n$\r$\nClose Dumplyzer if it is running, then click Next to try again."
 Abort
 ${EndIf}
FunctionEnd

Function PageRemovePrevious
 ${If} $NeedRemovePrevious != 1
 ${OrIf} $RemovePreviousDone = 1
 Abort
 ${EndIf}

 ${If} ${Silent}
 ${OrIf} $PassiveMode = 1
 ${OrIf} $WixMode = 1
 Call UninstallPreviousInstall
 Call AbortIfPreviousUninstallFailed
 StrCpy $RemovePreviousDone 1
 Abort
 ${EndIf}

 Call PreparePreviousInstallDir
 StrCpy $RemoveTargetDir $PreviousInstallDir
 StrCpy $RemoveWipeUserData 0
 StrCpy $RemoveKeepUninstaller 0
 StrCpy $RemoveTreeStarted 0
 !insertmacro MUI_HEADER_TEXT "Removing previous version" "Please wait"
 StrCpy $R8 "Uninstalling Dumplyzer $InstalledVersion..."
 Call ShowRemoveProgressPage
FunctionEnd

Function RemoveTreeTick
 Call PollRemoveInstallTree
 ${If} $0 = 2
 ${NSD_KillTimer} RemoveTreeTick
 StrCpy $RemoveTreeStarted 0
 StrCpy $0 1
 Call SetWizardButtonsEnabled
 MessageBox MB_ICONEXCLAMATION "Could not remove the previous Dumplyzer install.$\r$\n$\r$\nClose Dumplyzer if it is running, then click Next to try again."
 Return
 ${EndIf}
 ${If} $0 != 1
 Return
 ${EndIf}
 ${NSD_KillTimer} RemoveTreeTick
 Call FinishRemoveInstallTree
 Call PreviousInstallStillPresent
 ${If} $0 = 1
 StrCpy $RemoveTreeStarted 0
 StrCpy $0 1
 Call SetWizardButtonsEnabled
 MessageBox MB_ICONEXCLAMATION "Could not remove the previous Dumplyzer install.$\r$\n$\r$\nClose Dumplyzer if it is running, then click Next to try again."
 Return
 ${EndIf}

 StrCpy $RemovePreviousDone 1
 ${NSD_SetText} $RemoveStatusLabel "Previous version removed."
 SendMessage $RemoveProgress 0x402 100 0
 Sleep 300
 GetDlgItem $1 $HWNDPARENT 1
 EnableWindow $1 1
 SendMessage $HWNDPARENT 0x0111 1 $1
FunctionEnd

Function PageRemovePreviousLeave
 ${If} $RemovePreviousDone = 1
 Return
 ${EndIf}
 ${If} $RemoveTreeStarted = 1
 Abort
 ${EndIf}
 Call UninstallPreviousInstall
 Call AbortIfPreviousUninstallFailed
 StrCpy $RemovePreviousDone 1
FunctionEnd

Function un.PageRemoving
 ${If} ${Silent}
 ${OrIf} $PassiveMode = 1
 Abort
 ${EndIf}

 StrCpy $RemoveTargetDir $INSTDIR
 ${If} $DeleteAppDataCheckboxState = 1
 ${AndIf} $UpdateMode <> 1
 StrCpy $RemoveWipeUserData 1
 ${Else}
 StrCpy $RemoveWipeUserData 0
 ${EndIf}
 StrCpy $RemoveKeepUninstaller 1
 StrCpy $RemoveTreeStarted 0
 !insertmacro MUI_HEADER_TEXT "Uninstalling Dumplyzer" "Please wait"
 StrCpy $R8 "Uninstalling Dumplyzer..."
 Call un.ShowRemoveProgressPage
FunctionEnd

Function un.RemoveTreeTick
 Call un.PollRemoveInstallTree
 ${If} $0 = 2
 ${NSD_KillTimer} un.RemoveTreeTick
 StrCpy $RemoveTreeStarted 0
 StrCpy $0 1
 Call un.SetWizardButtonsEnabled
 MessageBox MB_ICONEXCLAMATION "Could not remove Dumplyzer.$\r$\n$\r$\nClose Dumplyzer if it is running, then click Next to try again."
 Return
 ${EndIf}
 ${If} $0 != 1
 Return
 ${EndIf}
 ${NSD_KillTimer} un.RemoveTreeTick
 Call un.FinishRemoveInstallTree
 Call un.InstallTreeStillPresent
 ${If} $0 = 1
 StrCpy $RemoveTreeStarted 0
 StrCpy $0 1
 Call un.SetWizardButtonsEnabled
 MessageBox MB_ICONEXCLAMATION "Could not remove Dumplyzer.$\r$\n$\r$\nClose Dumplyzer if it is running, then click Next to try again."
 Return
 ${EndIf}

 StrCpy $UninstallTreeRemoved 1
 ${NSD_SetText} $RemoveStatusLabel "Application files removed."
 SendMessage $RemoveProgress 0x402 100 0
 Sleep 300
 GetDlgItem $1 $HWNDPARENT 1
 EnableWindow $1 1
 SendMessage $HWNDPARENT 0x0111 1 $1
FunctionEnd

Function un.PageRemovingLeave
 ${If} $UninstallTreeRemoved = 1
 Return
 ${EndIf}
 ${If} $RemoveTreeStarted = 1
 Abort
 ${EndIf}
FunctionEnd

; 5. Choose install directory page
!define MUI_PAGE_CUSTOMFUNCTION_PRE SkipIfPassive
!insertmacro MUI_PAGE_DIRECTORY

; 6. Start menu shortcut page
Var AppStartMenuFolder
!if "${STARTMENUFOLDER}" != ""
 !define MUI_PAGE_CUSTOMFUNCTION_PRE SkipIfPassive
 !define MUI_STARTMENUPAGE_DEFAULTFOLDER "${STARTMENUFOLDER}"
!else
 !define MUI_PAGE_CUSTOMFUNCTION_PRE Skip
!endif
!insertmacro MUI_PAGE_STARTMENU Application $AppStartMenuFolder

; 7. Installation page
!insertmacro MUI_PAGE_INSTFILES

; 8. Finish page
;
; Don't auto jump to finish page after installation page,
; because the installation page has useful info that can be used debug any issues with the installer.
!define MUI_FINISHPAGE_NOAUTOCLOSE
; Use show readme button in the finish page as a button create a desktop shortcut
!define MUI_FINISHPAGE_SHOWREADME
!define MUI_FINISHPAGE_SHOWREADME_TEXT "$(createDesktop)"
!define MUI_FINISHPAGE_SHOWREADME_FUNCTION CreateOrUpdateDesktopShortcut
; Show run app after installation.
!define MUI_FINISHPAGE_RUN
!define MUI_FINISHPAGE_RUN_FUNCTION RunMainBinary
!define MUI_PAGE_CUSTOMFUNCTION_PRE SkipIfPassive
!insertmacro MUI_PAGE_FINISH

Function RunMainBinary
 nsis_tauri_utils::RunAsUser "$INSTDIR\${MAINBINARYNAME}.exe" ""
FunctionEnd

; Uninstaller Pages
; 1. Confirm uninstall page
!define /ifndef WS_EX_LAYOUTRTL 0x00400000
!define MUI_PAGE_CUSTOMFUNCTION_SHOW un.ConfirmShow
Function un.ConfirmShow ; Add add a `Delete app data` check box
 ; $1 inner dialog HWND
 ; $2 window DPI
 ; $3 style
 ; $4 x
 ; $5 y
 ; $6 width
 ; $7 height
 FindWindow $1 "#32770" "" $HWNDPARENT ; Find inner dialog
 System::Call "user32::GetDpiForWindow(p r1) i .r2"
 ${If} $(^RTL) = 1
 StrCpy $3 "${__NSD_CheckBox_EXSTYLE} | ${WS_EX_LAYOUTRTL}"
 IntOp $4 50 * $2
 ${Else}
 StrCpy $3 "${__NSD_CheckBox_EXSTYLE}"
 IntOp $4 0 * $2
 ${EndIf}
 IntOp $5 100 * $2
 IntOp $6 400 * $2
 IntOp $7 25 * $2
 IntOp $4 $4 / 96
 IntOp $5 $5 / 96
 IntOp $6 $6 / 96
 IntOp $7 $7 / 96
 System::Call 'user32::CreateWindowEx(i r3, w "${__NSD_CheckBox_CLASS}", w "$(deleteAppData)", i ${__NSD_CheckBox_STYLE}, i r4, i r5, i r6, i r7, p r1, i0, i0, i0) i .s'
 Pop $DeleteAppDataCheckbox
 SendMessage $HWNDPARENT ${WM_GETFONT} 0 0 $1
 SendMessage $DeleteAppDataCheckbox ${WM_SETFONT} $1 1
FunctionEnd
!define MUI_PAGE_CUSTOMFUNCTION_LEAVE un.ConfirmLeave
Function un.ConfirmLeave
 SendMessage $DeleteAppDataCheckbox ${BM_GETCHECK} 0 0 $DeleteAppDataCheckboxState
FunctionEnd
!define MUI_PAGE_CUSTOMFUNCTION_PRE un.SkipIfPassive
!insertmacro MUI_UNPAGE_CONFIRM

; 1b. Keep a determinate progress bar visible while the Python runtime
; tree is deleted. A single rmdir on INSTFILES froze this page.
UninstPage custom un.PageRemoving un.PageRemovingLeave

; 2. Uninstalling Page
!insertmacro MUI_UNPAGE_INSTFILES

;Languages
{{#each languages}}
!insertmacro MUI_LANGUAGE "{{this}}"
{{/each}}
!insertmacro MUI_RESERVEFILE_LANGDLL
{{#each language_files}}
 !include "{{this}}"
{{/each}}

Function .onInit
 StrCpy $VersionCmp 0
 StrCpy $InstalledVersion ""
 StrCpy $PreviousInstallDir ""
 StrCpy $NeedRemovePrevious 0
 StrCpy $RemovePreviousDone 0
 StrCpy $RemoveTreeStarted 0
 StrCpy $RemoveWipeUserData 0
 StrCpy $RemoveKeepUninstaller 0
 StrCpy $UninstallTreeRemoved 0
 ${GetOptions} $CMDLINE "/P" $PassiveMode
 ${IfNot} ${Errors}
 StrCpy $PassiveMode 1
 ${EndIf}

 ${GetOptions} $CMDLINE "/NS" $NoShortcutMode
 ${IfNot} ${Errors}
 StrCpy $NoShortcutMode 1
 ${EndIf}

 ${GetOptions} $CMDLINE "/UPDATE" $UpdateMode
 ${IfNot} ${Errors}
 StrCpy $UpdateMode 1
 ${EndIf}

 !if "${DISPLAYLANGUAGESELECTOR}" == "true"
 !insertmacro MUI_LANGDLL_DISPLAY
 !endif

 !insertmacro SetContext

 ${If} $INSTDIR == "${PLACEHOLDER_INSTALL_DIR}"
 ; Set default install location
 !if "${INSTALLMODE}" == "perMachine"
 ${If} ${RunningX64}
 !if "${ARCH}" == "x64"
 StrCpy $INSTDIR "$PROGRAMFILES64\${PRODUCTNAME}"
 !else if "${ARCH}" == "arm64"
 StrCpy $INSTDIR "$PROGRAMFILES64\${PRODUCTNAME}"
 !else
 StrCpy $INSTDIR "$PROGRAMFILES\${PRODUCTNAME}"
 !endif
 ${Else}
 StrCpy $INSTDIR "$PROGRAMFILES\${PRODUCTNAME}"
 ${EndIf}
 !else if "${INSTALLMODE}" == "currentUser"
 StrCpy $INSTDIR "$LOCALAPPDATA\Programs\${PRODUCTNAME}"
 !endif

 Call RestorePreviousInstallLocation
 ${EndIf}

 !if "${INSTALLMODE}" == "both"
 !insertmacro MULTIUSER_INIT
 !endif
FunctionEnd

Section EarlyChecks
 ; Abort silent installer if downgrades is disabled
 !if "${ALLOWDOWNGRADES}" == "false"
 ${If} ${Silent}
 ; If downgrading
 ${If} $VersionCmp = -1
 System::Call 'kernel32::AttachConsole(i -1)i.r0'
 ${If} $0 <> 0
 System::Call 'kernel32::GetStdHandle(i -11)i.r0'
 System::call 'kernel32::SetConsoleTextAttribute(i r0, i 0x0004)' ; set red color
 FileWrite $0 "$(silentDowngrades)"
 ${EndIf}
 Abort
 ${EndIf}
 ${EndIf}
 !endif

SectionEnd

Section WebView2
 ; Check if Webview2 is already installed and skip this section
 ${If} ${RunningX64}
 ReadRegStr $4 HKLM "SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\${WEBVIEW2APPGUID}" "pv"
 ${Else}
 ReadRegStr $4 HKLM "SOFTWARE\Microsoft\EdgeUpdate\Clients\${WEBVIEW2APPGUID}" "pv"
 ${EndIf}
 ${If} $4 == ""
 ReadRegStr $4 HKCU "SOFTWARE\Microsoft\EdgeUpdate\Clients\${WEBVIEW2APPGUID}" "pv"
 ${EndIf}

 ${If} $4 == ""
 ; WebView2 is required. Ask before downloading so cancel/close does not
 ; leave this installer sitting on InstFiles as if it were frozen.
 ${If} $UpdateMode <> 1
 ${IfNot} ${Silent}
 ${AndIf} $PassiveMode <> 1
 MessageBox MB_YESNO|MB_ICONQUESTION "Microsoft Edge WebView2 Runtime is required to run Dumplyzer.$\r$\n$\r$\nYes = download and install it now (Internet required).$\r$\nNo = install WebView2 yourself, then run this installer again.$\r$\n$\r$\nIf you cancel or close the WebView2 download, this installer will exit." IDYES prepare_webview2
 MessageBox MB_OK|MB_ICONINFORMATION "Install the Microsoft Edge WebView2 Runtime, then run Dumplyzer setup again."
 SetErrorLevel 1602
 Quit
 ${EndIf}

 prepare_webview2:
 !if "${INSTALLWEBVIEW2MODE}" == "downloadBootstrapper"
 Delete "$TEMP\MicrosoftEdgeWebview2Setup.exe"
 DetailPrint "$(webview2Downloading)"
 NSISdl::download "https://go.microsoft.com/fwlink/p/?LinkId=2124703" "$TEMP\MicrosoftEdgeWebview2Setup.exe"
 Pop $0
 ${If} $0 == "success"
 DetailPrint "$(webview2DownloadSuccess)"
 ${Else}
 DetailPrint "$(webview2DownloadError)"
 Goto webview2_cancelled
 ${EndIf}
 StrCpy $6 "$TEMP\MicrosoftEdgeWebview2Setup.exe"
 Goto install_webview2
 !endif

 !if "${INSTALLWEBVIEW2MODE}" == "embedBootstrapper"
 Delete "$TEMP\MicrosoftEdgeWebview2Setup.exe"
 File "/oname=$TEMP\MicrosoftEdgeWebview2Setup.exe" "${WEBVIEW2BOOTSTRAPPERPATH}"
 DetailPrint "$(installingWebview2)"
 StrCpy $6 "$TEMP\MicrosoftEdgeWebview2Setup.exe"
 Goto install_webview2
 !endif

 !if "${INSTALLWEBVIEW2MODE}" == "offlineInstaller"
 Delete "$TEMP\MicrosoftEdgeWebView2RuntimeInstaller.exe"
 File "/oname=$TEMP\MicrosoftEdgeWebView2RuntimeInstaller.exe" "${WEBVIEW2INSTALLERPATH}"
 DetailPrint "$(installingWebview2)"
 StrCpy $6 "$TEMP\MicrosoftEdgeWebView2RuntimeInstaller.exe"
 Goto install_webview2
 !endif

 Goto webview2_done

 install_webview2:
 DetailPrint "$(installingWebview2)"
 ; Quote $6. Unquoted ExecWait lets CreateProcess split the Temp path, so the
 ; bootstrapper can hang on `/silent /` instead of installing.
 ; Do not pass /silent: the Evergreen bootstrapper must show its own UI while
 ; it downloads the runtime (~150 MB). Silent mode looks frozen on machines
 ; that do not already have WebView2.
 ExecWait '"$6" ${WEBVIEW2INSTALLERARGS} /install' $1
 ; 0 = success. 3010 = success, reboot required.
 ${If} $1 = 0
 ${OrIf} $1 = 3010
 DetailPrint "$(webview2InstallSuccess)"
 Goto webview2_done
 ${EndIf}
 webview2_cancelled:
 DetailPrint "$(webview2InstallError)"
 ${IfNot} ${Silent}
 MessageBox MB_OK|MB_ICONEXCLAMATION "WebView2 is required. The download was cancelled or failed, so Dumplyzer setup will exit.$\r$\n$\r$\nInstall WebView2, then run this installer again."
 ${EndIf}
 StrCmp $1 "" 0 +2
 StrCpy $1 1602
 SetErrorLevel $1
 Quit
 webview2_done:
 ${EndIf}
 ${Else}
 !if "${MINIMUMWEBVIEW2VERSION}" != ""
 ${VersionCompare} "${MINIMUMWEBVIEW2VERSION}" "$4" $R0
 ${If} $R0 = 1
 update_webview:
 DetailPrint "$(installingWebview2)"
 ${If} ${RunningX64}
 ReadRegStr $R1 HKLM "SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate" "path"
 ${Else}
 ReadRegStr $R1 HKLM "SOFTWARE\Microsoft\EdgeUpdate" "path"
 ${EndIf}
 ${If} $R1 == ""
 ReadRegStr $R1 HKCU "SOFTWARE\Microsoft\EdgeUpdate" "path"
 ${EndIf}
 ${If} $R1 != ""
 ; Chromium updater docs: https://source.chromium.org/chromium/chromium/src/+/main:docs/updater/user_manual.md
 ; Modified from "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft EdgeWebView\ModifyPath"
 ExecWait `"$R1" /install appguid=${WEBVIEW2APPGUID}&needsadmin=true` $1
 ${If} $1 = 0
 DetailPrint "$(webview2InstallSuccess)"
 ${Else}
 MessageBox MB_ICONEXCLAMATION|MB_ABORTRETRYIGNORE "$(webview2InstallError)" IDIGNORE ignore IDRETRY update_webview
 Quit
 ignore:
 ${EndIf}
 ${EndIf}
 ${EndIf}
 !endif
 ${EndIf}
SectionEnd

; Upgrade/reinstall cannot overwrite runtime DLLs while Dumplyzer or its
; bundled python.exe still has them mapped (e.g. _bz2.pyd). Only touch
; dumplyzer.exe and this install's runtime python, never a system Python.
; Inline PowerShell -Command with { } is truncated by NSIS and raises
; ParserError MissingEndCurlyBrace. Write a .ps1 then invoke it with -File.
; Only dumplyzer.exe and this install's runtime python.exe, never system Python.
!macro StopDumplyzerRuntime
 nsExec::Exec 'taskkill /F /IM dumplyzer.exe /T'
 InitPluginsDir
 FileOpen $0 "$PLUGINSDIR\stop-dumplyzer-runtime.ps1" w
 FileWrite $0 "param([string]$$InstallRoot)$\r$\n"
 FileWrite $0 "if ([string]::IsNullOrWhiteSpace($$InstallRoot)) { exit 0 }$\r$\n"
 FileWrite $0 "$$exe = [System.IO.Path]::GetFullPath((Join-Path $$InstallRoot 'dumplyzer.exe'))$\r$\n"
 FileWrite $0 "$$py = [System.IO.Path]::GetFullPath((Join-Path $$InstallRoot 'resources\runtime\python.exe'))$\r$\n"
 FileWrite $0 "Get-Process -ErrorAction SilentlyContinue | Where-Object { $$_.Path -and (($$_.Path -ieq $$exe) -or ($$_.Path -ieq $$py)) } | Stop-Process -Force -ErrorAction SilentlyContinue$\r$\n"
 FileClose $0
 nsExec::ExecToLog '"$SYSDIR\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File "$PLUGINSDIR\stop-dumplyzer-runtime.ps1" "$INSTDIR"'
 Sleep 200
!macroend

Function StopDumplyzerRuntime
 !insertmacro StopDumplyzerRuntime
FunctionEnd

Function un.StopDumplyzerRuntime
 !insertmacro StopDumplyzerRuntime
FunctionEnd

Section Install
 SetOutPath $INSTDIR

 !ifmacrodef NSIS_HOOK_PREINSTALL
 !insertmacro NSIS_HOOK_PREINSTALL
 !endif

 !insertmacro CheckIfAppIsRunning "${MAINBINARYNAME}.exe" "${PRODUCTNAME}"
 Call StopDumplyzerRuntime

 ; Copy main executable
 File "${MAINBINARYSRCPATH}"

 ; Copy resources
 {{#each resources_dirs}}
 CreateDirectory "$INSTDIR\\{{this}}"
 {{/each}}
 {{#each resources}}
 File /a "/oname={{this.[1]}}" "{{no-escape @key}}"
 {{/each}}

 ; Copy external binaries
 {{#each binaries}}
 File /a "/oname={{this}}" "{{no-escape @key}}"
 {{/each}}

 ; Create file associations
 {{#each file_associations as |association| ~}}
 {{#each association.ext as |ext| ~}}
 !insertmacro APP_ASSOCIATE "{{ext}}" "{{or association.name ext}}" "{{association-description association.description ext}}" "$INSTDIR\${MAINBINARYNAME}.exe,0" "Open with ${PRODUCTNAME}" "$INSTDIR\${MAINBINARYNAME}.exe $\"%1$\""
 {{/each}}
 {{/each}}

 ; Register deep links
 {{#each deep_link_protocols as |protocol| ~}}
 WriteRegStr SHCTX "Software\Classes\\{{protocol}}" "URL Protocol" ""
 WriteRegStr SHCTX "Software\Classes\\{{protocol}}" "" "URL:${BUNDLEID} protocol"
 WriteRegStr SHCTX "Software\Classes\\{{protocol}}\DefaultIcon" "" "$\"$INSTDIR\${MAINBINARYNAME}.exe$\",0"
 WriteRegStr SHCTX "Software\Classes\\{{protocol}}\shell\open\command" "" "$\"$INSTDIR\${MAINBINARYNAME}.exe$\" $\"%1$\""
 {{/each}}

 ; Create uninstaller
 WriteUninstaller "$INSTDIR\uninstall.exe"

 ; Save $INSTDIR in registry for future installations
 WriteRegStr SHCTX "${MANUPRODUCTKEY}" "" $INSTDIR

 !if "${INSTALLMODE}" == "both"
 ; Save install mode to be selected by default for the next installation such as updating
 ; or when uninstalling
 WriteRegStr SHCTX "${UNINSTKEY}" $MultiUser.InstallMode 1
 !endif

 ; Remove old main binary if it doesn't match new main binary name
 ReadRegStr $OldMainBinaryName SHCTX "${UNINSTKEY}" "MainBinaryName"
 ${If} $OldMainBinaryName != ""
 ${AndIf} $OldMainBinaryName != "${MAINBINARYNAME}.exe"
 Delete "$INSTDIR\$OldMainBinaryName"
 ${EndIf}

 ; Save current MAINBINARYNAME for future updates
 WriteRegStr SHCTX "${UNINSTKEY}" "MainBinaryName" "${MAINBINARYNAME}.exe"

 ; Registry information for add/remove programs
 WriteRegStr SHCTX "${UNINSTKEY}" "DisplayName" "${PRODUCTNAME}"
 WriteRegStr SHCTX "${UNINSTKEY}" "DisplayIcon" "$\"$INSTDIR\${MAINBINARYNAME}.exe$\""
 WriteRegStr SHCTX "${UNINSTKEY}" "DisplayVersion" "${VERSION}"
 WriteRegStr SHCTX "${UNINSTKEY}" "Publisher" "${MANUFACTURER}"
 WriteRegStr SHCTX "${UNINSTKEY}" "InstallLocation" "$\"$INSTDIR$\""
 WriteRegStr SHCTX "${UNINSTKEY}" "UninstallString" "$\"$INSTDIR\uninstall.exe$\""
 WriteRegStr SHCTX "${UNINSTKEY}" "QuietUninstallString" "$\"$INSTDIR\uninstall.exe$\" /S"
 WriteRegDWORD SHCTX "${UNINSTKEY}" "NoModify" "1"
 WriteRegDWORD SHCTX "${UNINSTKEY}" "NoRepair" "1"

 ${GetSize} "$INSTDIR" "/M=uninstall.exe /S=0K /G=0" $0 $1 $2
 IntOp $0 $0 + ${ESTIMATEDSIZE}
 IntFmt $0 "0x%08X" $0
 WriteRegDWORD SHCTX "${UNINSTKEY}" "EstimatedSize" "$0"

 !if "${HOMEPAGE}" != ""
 WriteRegStr SHCTX "${UNINSTKEY}" "URLInfoAbout" "${HOMEPAGE}"
 WriteRegStr SHCTX "${UNINSTKEY}" "URLUpdateInfo" "${HOMEPAGE}"
 WriteRegStr SHCTX "${UNINSTKEY}" "HelpLink" "${HOMEPAGE}"
 !endif

 ; Create start menu shortcut
 !insertmacro MUI_STARTMENU_WRITE_BEGIN Application
 Call CreateOrUpdateStartMenuShortcut
 !insertmacro MUI_STARTMENU_WRITE_END

 ; Create desktop shortcut for silent and passive installers
 ; because finish page will be skipped
 ${If} $PassiveMode = 1
 ${OrIf} ${Silent}
 Call CreateOrUpdateDesktopShortcut
 ${EndIf}

 !ifmacrodef NSIS_HOOK_POSTINSTALL
 !insertmacro NSIS_HOOK_POSTINSTALL
 !endif

 ; Auto close this page for passive mode
 ${If} $PassiveMode = 1
 SetAutoClose true
 ${EndIf}
SectionEnd

Function .onInstSuccess
 ; Check for `/R` flag only in silent and passive installers because
 ; GUI installer has a toggle for the user to (re)start the app
 ${If} $PassiveMode = 1
 ${OrIf} ${Silent}
 ${GetOptions} $CMDLINE "/R" $R0
 ${IfNot} ${Errors}
 ${GetOptions} $CMDLINE "/ARGS" $R0
 nsis_tauri_utils::RunAsUser "$INSTDIR\${MAINBINARYNAME}.exe" "$R0"
 ${EndIf}
 ${EndIf}
FunctionEnd

Function un.onInit
 !insertmacro SetContext

 !if "${INSTALLMODE}" == "both"
 !insertmacro MULTIUSER_UNINIT
 !endif

 !insertmacro MUI_UNGETLANGUAGE

 StrCpy $RemoveTreeStarted 0
 StrCpy $UninstallTreeRemoved 0
 StrCpy $RemoveTargetDir ""
 StrCpy $RemoveWipeUserData 0
 StrCpy $RemoveKeepUninstaller 1
 StrCpy $DeleteAppDataCheckboxState 0

 ${GetOptions} $CMDLINE "/P" $PassiveMode
 ${IfNot} ${Errors}
 StrCpy $PassiveMode 1
 ${EndIf}

 ${GetOptions} $CMDLINE "/UPDATE" $UpdateMode
 ${IfNot} ${Errors}
 StrCpy $UpdateMode 1
 ${EndIf}
FunctionEnd

Section Uninstall

 !ifmacrodef NSIS_HOOK_PREUNINSTALL
 !insertmacro NSIS_HOOK_PREUNINSTALL
 !endif

 Call un.StopDumplyzerRuntime
 !insertmacro CheckIfAppIsRunning "${MAINBINARYNAME}.exe" "${PRODUCTNAME}"

 ; Delete app associations
 {{#each file_associations as |association| ~}}
 {{#each association.ext as |ext| ~}}
 !insertmacro APP_UNASSOCIATE "{{ext}}" "{{or association.name ext}}"
 {{/each}}
 {{/each}}

 ; Delete deep links
 {{#each deep_link_protocols as |protocol| ~}}
 ReadRegStr $R7 SHCTX "Software\Classes\\{{protocol}}\shell\open\command" ""
 ${If} $R7 == "$\"$INSTDIR\${MAINBINARYNAME}.exe$\" $\"%1$\""
 DeleteRegKey SHCTX "Software\Classes\\{{protocol}}"
 ${EndIf}
 {{/each}}

 ; Bundled CPython + Volatility is thousands of files. Per-file Delete
 ; (Tauri's default) spends minutes redrawing "Delete file:" in the UI.
 ; Interactive uninstall already deleted the tree on un.PageRemoving.
 ${If} $UninstallTreeRemoved != 1
 StrCpy $RemoveTargetDir $INSTDIR
 ${If} $DeleteAppDataCheckboxState = 1
 ${AndIf} $UpdateMode <> 1
 StrCpy $RemoveWipeUserData 1
 ${Else}
 StrCpy $RemoveWipeUserData 0
 ${EndIf}
 StrCpy $RemoveKeepUninstaller 1
 SetDetailsPrint textonly
 DetailPrint "Removing application files..."
 Call un.RemoveInstallTreeBlocking
 StrCpy $UninstallTreeRemoved 1
 ${EndIf}
 nsExec::ExecToLog '"$SYSDIR\cmd.exe" /C if exist "$INSTDIR" rmdir /S /Q "$INSTDIR"'
 RMDir /r /REBOOTOK "$INSTDIR"
 SetDetailsPrint both

 ; Remove shortcuts if not updating
 ${If} $UpdateMode <> 1
 !insertmacro DeleteAppUserModelId

 ; Remove start menu shortcut
 !insertmacro MUI_STARTMENU_GETFOLDER Application $AppStartMenuFolder
 !insertmacro IsShortcutTarget "$SMPROGRAMS\$AppStartMenuFolder\${PRODUCTNAME}.lnk" "$INSTDIR\${MAINBINARYNAME}.exe"
 Pop $0
 ${If} $0 = 1
 !insertmacro UnpinShortcut "$SMPROGRAMS\$AppStartMenuFolder\${PRODUCTNAME}.lnk"
 Delete "$SMPROGRAMS\$AppStartMenuFolder\${PRODUCTNAME}.lnk"
 RMDir "$SMPROGRAMS\$AppStartMenuFolder"
 ${EndIf}
 !insertmacro IsShortcutTarget "$SMPROGRAMS\${PRODUCTNAME}.lnk" "$INSTDIR\${MAINBINARYNAME}.exe"
 Pop $0
 ${If} $0 = 1
 !insertmacro UnpinShortcut "$SMPROGRAMS\${PRODUCTNAME}.lnk"
 Delete "$SMPROGRAMS\${PRODUCTNAME}.lnk"
 ${EndIf}

 ; Remove desktop shortcuts
 !insertmacro IsShortcutTarget "$DESKTOP\${PRODUCTNAME}.lnk" "$INSTDIR\${MAINBINARYNAME}.exe"
 Pop $0
 ${If} $0 = 1
 !insertmacro UnpinShortcut "$DESKTOP\${PRODUCTNAME}.lnk"
 Delete "$DESKTOP\${PRODUCTNAME}.lnk"
 ${EndIf}
 ${EndIf}

 ; Remove registry information for add/remove programs
 !if "${INSTALLMODE}" == "both"
 DeleteRegKey SHCTX "${UNINSTKEY}"
 !else if "${INSTALLMODE}" == "perMachine"
 DeleteRegKey HKLM "${UNINSTKEY}"
 !else
 DeleteRegKey HKCU "${UNINSTKEY}"
 !endif

 ; Removes the Autostart entry for ${PRODUCTNAME} from the HKCU Run key if it exists.
 ; This ensures the program does not launch automatically after uninstallation if it exists.
 ; If it doesn't exist, it does nothing.
 ; We do this when not updating (to preserve the registry value on updates)
 ${If} $UpdateMode <> 1
 DeleteRegValue HKCU "Software\Microsoft\Windows\CurrentVersion\Run" "${PRODUCTNAME}"
 ${EndIf}

 ; Delete app data if the checkbox is selected
 ; and if not updating
 ${If} $DeleteAppDataCheckboxState = 1
 ${AndIf} $UpdateMode <> 1
 ; Clear the install location $INSTDIR from registry
 DeleteRegKey SHCTX "${MANUPRODUCTKEY}"
 DeleteRegKey /ifempty SHCTX "${MANUKEY}"

 ; Clear the install language from registry
 DeleteRegValue HKCU "${MANUPRODUCTKEY}" "Installer Language"
 DeleteRegKey /ifempty HKCU "${MANUPRODUCTKEY}"
 DeleteRegKey /ifempty HKCU "${MANUKEY}"

 SetShellVarContext current
 SetDetailsPrint textonly
 DetailPrint "Removing application data..."
 nsExec::ExecToLog '"$SYSDIR\cmd.exe" /C if exist "$LOCALAPPDATA\Dumplyzer" rmdir /S /Q "$LOCALAPPDATA\Dumplyzer"'
 RmDir /r "$LOCALAPPDATA\Dumplyzer"
 nsExec::ExecToLog '"$SYSDIR\cmd.exe" /C if exist "$APPDATA\${BUNDLEID}" rmdir /S /Q "$APPDATA\${BUNDLEID}"'
 nsExec::ExecToLog '"$SYSDIR\cmd.exe" /C if exist "$LOCALAPPDATA\${BUNDLEID}" rmdir /S /Q "$LOCALAPPDATA\${BUNDLEID}"'
 RmDir /r "$APPDATA\${BUNDLEID}"
 RmDir /r "$LOCALAPPDATA\${BUNDLEID}"
 SetDetailsPrint both
 ${EndIf}

 !ifmacrodef NSIS_HOOK_POSTUNINSTALL
 !insertmacro NSIS_HOOK_POSTUNINSTALL
 !endif

 ; Auto close if passive mode or updating
 ${If} $PassiveMode = 1
 ${OrIf} $UpdateMode = 1
 SetAutoClose true
 ${EndIf}
SectionEnd

Function RestorePreviousInstallLocation
 ReadRegStr $4 SHCTX "${MANUPRODUCTKEY}" ""
 StrCmp $4 "" +2 0
 StrCpy $INSTDIR $4
FunctionEnd

Function Skip
 Abort
FunctionEnd

Function SkipIfPassive
 ${IfThen} $PassiveMode = 1 ${|} Abort ${|}
FunctionEnd
Function un.SkipIfPassive
 ${IfThen} $PassiveMode = 1 ${|} Abort ${|}
FunctionEnd

Function CreateOrUpdateStartMenuShortcut
 ; We used to use product name as MAINBINARYNAME
 ; migrate old shortcuts to target the new MAINBINARYNAME
 StrCpy $R0 0

 !insertmacro IsShortcutTarget "$SMPROGRAMS\$AppStartMenuFolder\${PRODUCTNAME}.lnk" "$INSTDIR\$OldMainBinaryName"
 Pop $0
 ${If} $0 = 1
 !insertmacro SetShortcutTarget "$SMPROGRAMS\$AppStartMenuFolder\${PRODUCTNAME}.lnk" "$INSTDIR\${MAINBINARYNAME}.exe"
 StrCpy $R0 1
 ${EndIf}

 !insertmacro IsShortcutTarget "$SMPROGRAMS\${PRODUCTNAME}.lnk" "$INSTDIR\$OldMainBinaryName"
 Pop $0
 ${If} $0 = 1
 !insertmacro SetShortcutTarget "$SMPROGRAMS\${PRODUCTNAME}.lnk" "$INSTDIR\${MAINBINARYNAME}.exe"
 StrCpy $R0 1
 ${EndIf}

 ${If} $R0 = 1
 Return
 ${EndIf}

 ; Skip creating shortcut if in update mode or no shortcut mode
 ; but always create if migrating from wix
 ${If} $WixMode = 0
 ${If} $UpdateMode = 1
 ${OrIf} $NoShortcutMode = 1
 Return
 ${EndIf}
 ${EndIf}

 !if "${STARTMENUFOLDER}" != ""
 CreateDirectory "$SMPROGRAMS\$AppStartMenuFolder"
 CreateShortcut "$SMPROGRAMS\$AppStartMenuFolder\${PRODUCTNAME}.lnk" "$INSTDIR\${MAINBINARYNAME}.exe"
 !insertmacro SetLnkAppUserModelId "$SMPROGRAMS\$AppStartMenuFolder\${PRODUCTNAME}.lnk"
 !else
 CreateShortcut "$SMPROGRAMS\${PRODUCTNAME}.lnk" "$INSTDIR\${MAINBINARYNAME}.exe"
 !insertmacro SetLnkAppUserModelId "$SMPROGRAMS\${PRODUCTNAME}.lnk"
 !endif
FunctionEnd

Function CreateOrUpdateDesktopShortcut
 ; We used to use product name as MAINBINARYNAME
 ; migrate old shortcuts to target the new MAINBINARYNAME
 !insertmacro IsShortcutTarget "$DESKTOP\${PRODUCTNAME}.lnk" "$INSTDIR\$OldMainBinaryName"
 Pop $0
 ${If} $0 = 1
 !insertmacro SetShortcutTarget "$DESKTOP\${PRODUCTNAME}.lnk" "$INSTDIR\${MAINBINARYNAME}.exe"
 Return
 ${EndIf}

 ; Skip creating shortcut if in update mode or no shortcut mode
 ; but always create if migrating from wix
 ${If} $WixMode = 0
 ${If} $UpdateMode = 1
 ${OrIf} $NoShortcutMode = 1
 Return
 ${EndIf}
 ${EndIf}

 CreateShortcut "$DESKTOP\${PRODUCTNAME}.lnk" "$INSTDIR\${MAINBINARYNAME}.exe"
 !insertmacro SetLnkAppUserModelId "$DESKTOP\${PRODUCTNAME}.lnk"
FunctionEnd
