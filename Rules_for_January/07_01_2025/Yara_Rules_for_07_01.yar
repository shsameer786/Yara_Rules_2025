/*
   YARA Rule Set
   Author: Sameer P Sheik
   Date: 2025-01-07
   Identifier: evidences
   Reference: https://datalake.abuse.ch/malware-bazaar/daily/
*/

/* Rule Set ----------------------------------------------------------------- */

rule sig_00ef07ba411691ce7cc5d4eb5066a4f231f42be450f735a5bd635bb5136fd7cc {
   meta:
      description = "evidences - file 00ef07ba411691ce7cc5d4eb5066a4f231f42be450f735a5bd635bb5136fd7cc.rar"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-07"
      hash1 = "00ef07ba411691ce7cc5d4eb5066a4f231f42be450f735a5bd635bb5136fd7cc"
   strings:
      $s1 = "DHL 8350232025-2.exe" fullword ascii
      $s2 = "dfimosu" fullword ascii
      $s3 = "WUSOMKIG" fullword ascii
      $s4 = "YIrcR$" fullword ascii
      $s5 = "Xmonopr" fullword ascii
      $s6 = "TSV:k -P|" fullword ascii
      $s7 = ")S139- }" fullword ascii
      $s8 = "vh)+ 6A<I" fullword ascii
      $s9 = "Ms15&'v14" fullword ascii
      $s10 = "cyvgew" fullword ascii
      $s11 = "t=H- 8M" fullword ascii
      $s12 = "tugjaf" fullword ascii
      $s13 = "H+ :fp" fullword ascii
      $s14 = "\\A2%h;" fullword ascii
      $s15 = "mknlmHh`i" fullword ascii
      $s16 = "#SCKw\"_" fullword ascii
      $s17 = "AkMMp@~t?d" fullword ascii
      $s18 = "wWWUwWW" fullword ascii
      $s19 = "GYhb#]@^%u" fullword ascii
      $s20 = "GPuTD\"WW`Eg" fullword ascii
   condition:
      uint16(0) == 0x6152 and filesize < 3000KB and
      8 of them
}

rule sig_153b7fdc3db3b4bfb6cbe37338c7c3c1393755c0b67c896149538ca6f8032839 {
   meta:
      description = "evidences - file 153b7fdc3db3b4bfb6cbe37338c7c3c1393755c0b67c896149538ca6f8032839.ps1"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-07"
      hash1 = "153b7fdc3db3b4bfb6cbe37338c7c3c1393755c0b67c896149538ca6f8032839"
   strings:
      $s1 = "[System.Text.Encoding]::ascii.(([system.String]::new(@((2009-(5734-3796)),(109181/(-833+1914)),(-4465+(4667-(594862/(33333023/(6" ascii
      $s2 = "q/CEk+FrbGA05K7mLTB8JusobxWbPYxGtzIze2+S9RZXyuH15yl5eoMop+XR3MShL8aqNwD5xGZfFea06aegn0EH6ynm9zH4sLot2QMsDllA7OFCoZaqv7OCJ/xkfPZ0" ascii
      $s3 = "Gd+yj6LWtJZnLCoJ9n+U6P6FtpOBaK0HAg27PHdODg8X6rcUd55xvwxQjjXZT0XiT+FOQD6E5eL2uwuMALnFJQ7qrIkgoQALy5ggSgZ8Z43hx56JHx2RLJ4+153AxvhS" ascii
      $s4 = "CU+OhzRXtCJeywH38u/8qfQRBruQ7z9xgDMjj8e+I/BH/uZZ3OgwhzjOsSCQlEzF3tn1wIwuCnq73qplv07omFNktDOHRZQTVULzEyEiLuX029jvUVnPwDaFwpOR9zpD" ascii
      $s5 = "8715+(10517-1701)),(750295/(7997-262)),(906335/8315)) -join ''))($mjsh8zr12yi4g6x, ([IO.Compression.CompressionMode]::Decompress" ascii
      $s6 = "00000001830000000000000176\".Substring(($_ * ([math]::Pow(2, 2 + 2))), ([math]::Pow(2, 2 + 2))) - 73)}))(($_ * (7307-(35188185/4" ascii
      $s7 = "ath]::Pow(2, 2 + 2))) - 13)}))($anedisesatenoralinisbeantionaresaronenon, ([CHar[]]@((2525-2447),(32+79),(-9924+(89734062/8943))" ascii
      $s8 = "$xqizhfkvr=$executioncontext;$reatananisinerisaninatonbetionenesarin = ([Char[]]@((-2653+(-517+3223)),(184600/3550),(576327/(665" ascii
      $s9 = "ubstring(($_ * ([math]::Pow(2, 2 + 1))), ([math]::Pow(2, 2 + 1))) - 28)}))(($_ * (1712/(370+(2075-1589)))), (-6322+(3895584/616)" ascii
      $s10 = "yaPcy+B/GiwIlTap2Yh04vcCC2UikuIvLpr2jEfeyEMa2vnbJnVcif3UeNGYTx+BBlb4ZYCaTt5fZ74389mn0nf+oIcK5xn1f1iJ9IMPB9mj0kJt3OQz4BHA5c68U/O0" ascii
      $s11 = "+XxpZyhEgqmmc7Ir0VsP6bPGj1Myy/FfR+238IbIzf5lEdt94qw1nkD9mtky7cEtX55GqEgFZF4B3PKxN22/KrI46Lc62hYJVuQFbwBGeCVJ3cE4tJezYOu7K/2q+Z4Z" ascii
      $s12 = "53qnd/rRS83z6+Hr/nOXD8Ppu10BNcCyFFMAUqFh7uWXxazx/HB3N/OhSwSZTohZQH7Bcvup8aEjyW/I7H0qrfkXG3apH/U3TDw7wJrJAGFxPr4LPdtnWr2dcxShYDli" ascii
      $s13 = "7LGNgo9Gse08CJwTt5RNkBo4JnEgXO7/F3lr1OosIwVhl0TPfBJUr1ihCf07IIp5bORuKTg0uFMSt9MMWSl4JqoAv8ivobdzE4kSwG0JiGGNnWwo/loqOPqInGQnzNEj" ascii
      $s14 = "YB0airi0qvgM3+NSN9yp/1v6kL5qo+nnNrAQrT9deOvGMz/HyLCE/lti8NgFRgzNvt1zCmw7uP5ONuQD9s2vZzadewkL1MjwuaGwh9MbHOdao4hFY66cGfZM2C29P/sv" ascii
      $s15 = "9VbtcjNUNTjcdFlYugRm2TxxQmO4427EBHFgcSck4yO+ddTrUJfy2YlUW1+GtE4XP084aiHTZ3VQBYIg2LgtEDZfkPgmVriCy49whQcUZhBIoAzGDaL45XULkC74hNzi" ascii
      $s16 = "sEY0GHFLw0CDDFH4wcnISWCWijl2e8N8tD6VE0ACyr4mieO90LV61KTerlBkxVnZ9RMXK+ehwuWyNizGLfmEpp80HvdkO7zvw+vLENe8dIiVfzkw901YSFl28jpYClzw" ascii
      $s17 = "U5tYRkhuccNnZcV6N15fBWalOdloUoJzCWoIMUu0BiH7NEFCSUpTIsMAoiF6f8RTTZqzU6Euf1mfJ7BgQ3g9MO78cGiuauQg4vJutOX7aUODVQUgwrM7Muzhi1GzBiXi" ascii
      $s18 = "hqyysgeAagqGgQnXnb2CXrR7uyScGw1Xr4lLm747NA6H8GqPHb6tyPbtG4kvwQLLqmfCNeXrJ+R1HjN7SiFZxBazsvwSthbHk096gBlOKRrTR+ZuMGovT8XNcROtcOFi" ascii
      $s19 = "9E9qJvQ24gXGOP06Yn5RlQUEWzwt6PwRGEjGnnrTg7LmzG7c4ozoAOSfX8dC/tGJkSgnG3RdH/d+5PcBKbghyKv169cMXCyFHRRUXmOcElCyHXD1NiAWfNOwul7dTody" ascii
      $s20 = "lu8FBd12i/B8v/9Lqg+uXW0Q4A1V+nsoZLJRx0ALGPZfwrQPPwybbQFie5ARB5wZI2+0IZ35FQwy9Xhqjj2qxVeINwQEN6sR/Pb33j38zXbsUtJFxrVI8cQoTZ+Dhv/Y" ascii
   condition:
      uint16(0) == 0x7824 and filesize < 60KB and
      8 of them
}

rule c1ee79c33aac2e4228b9fa27067eb82e6708248af833d282d53d455c25e2b8d7 {
   meta:
      description = "evidences - file c1ee79c33aac2e4228b9fa27067eb82e6708248af833d282d53d455c25e2b8d7.ps1"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-07"
      hash1 = "c1ee79c33aac2e4228b9fa27067eb82e6708248af833d282d53d455c25e2b8d7"
   strings:
      $x1 = "[Scripts] \\BINx64\\notmyfaultc.exe - force a memory dump: https://learn.microsoft.com/es-es/sysinternals/downloads/notmyfault i" ascii
      $x2 = "$Command = \"Start-Process -WindowStyle Minimized -FilePath `\"procdump.exe`\" -ArgumentList `\"-ma -e -AcceptEula $($Proc.ID) $" ascii
      $x3 = "$Command = \"Start-Process -WindowStyle Minimized -FilePath `\"procdump.exe`\" -ArgumentList `\"-ma -e -AcceptEula $($Proc.ID) $" ascii
      $x4 = "try {$ETWSessionList| Out-String | out-file $outFile; $TotProvCnt=$($ETWSessionListCount -5); \"`n $(Get-Date -format `\"yyyyMMd" ascii
      $x5 = "$Proccess = Start-Process -FilePath $TraceObject.CommandName -ArgumentList $TraceObject.AutoLogger.AutoLoggerStartOption -Redire" ascii
      $x6 = "[Scripts] \\BINx64\\notmyfaultc.exe - force a memory dump: https://learn.microsoft.com/es-es/sysinternals/downloads/notmyfault i" ascii
      $x7 = "to execute this command: wevtutil.exe export-log \"Microsoft-Windows-CAPI2/Operational\" \"c:\\Capi2_Oper.evtx\" /overwrite:true" ascii
      $x8 = "LogError \"TTD.exe does not support `'-TTDOptions -injectMode`'! Please remove `'-TTDOptions -injectMode`' from the TSS command " ascii
      $x9 = "[Commands]  -ProcDump <PID[]|ProcessName.exe[]|ServiceName[]> - capture user dump(s) of single item or comma separated list of i" ascii
      $x10 = "[Commands]  -ProcDump <PID[]|ProcessName.exe[]|ServiceName[]> - capture user dump(s) of single item or comma separated list of i" ascii
      $x11 = "$proc = FwExecWMIQuery -Namespace \"root\\cimv2\" -Query \"select Name, CreationDate, ProcessId, ParentProcessId, SessionId, Wor" ascii
      $x12 = "# Xperf  - to detect Xperf: logman.exe query -ets \"NT Kernel Logger\" (before #546), we now use the existence of temporary log " ascii
      $x13 = "# Xperf  - to detect Xperf: logman.exe query -ets \"NT Kernel Logger\" (before #546), we now use the existence of temporary log " ascii
      $x14 = "\"Get-ItemProperty `'HKLM:System\\CurrentControlSet\\Control\\CrashControl`' | Out-File -Append $BasicLogFolder\\_Reg_Dump.txt\"" ascii
      $x15 = "[Commands]  -TTDE <PID[]|ProcessName.exe[]|ServiceName[]> - start Time Travel Debugging (TTD.exe) (TTT/iDNA) with default= `'-in" ascii
      $x16 = "$Command = \"Remove-ItemProperty -Path `\"HKLM:\\System\\CurrentControlSet\\Control\\Session Manager\\Memory Management`\" -Name" ascii
      $x17 = "LogWarn \"Procdump on lsass may fail with Access Denied, see https://mikesblogs.net/access-denied-when-running-procdump/ + https" ascii
      $x18 = "$Proccess = Start-Process -FilePath $TraceObject.CommandName -ArgumentList $TraceObject.Startoption -RedirectStandardOutput $env" ascii
      $x19 = "LogError \"TTD.exe does not support `'-TTDOptions -injectMode`'! Please remove `'-TTDOptions -injectMode`' from the TSS command " ascii
      $x20 = "LogInfoFile ('[' + $TraceObject.Name + '] Running Stop-Command: ' + $TraceObject.CommandName + ' ' + $TraceObject.AutoLogger.Aut" ascii
   condition:
      uint16(0) == 0x233c and filesize < 3000KB and
      1 of ($x*)
}

rule de56f2adb28159654d43754aed8f485a3f4808d759103434882f3e9290bfb8dd {
   meta:
      description = "evidences - file de56f2adb28159654d43754aed8f485a3f4808d759103434882f3e9290bfb8dd.ps1"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-07"
      hash1 = "de56f2adb28159654d43754aed8f485a3f4808d759103434882f3e9290bfb8dd"
   strings:
      $s1 = "[System.Text.Encoding]::ascii.(([system.String]::new(@((4551-(-5540+10020)),(-7193+(36119888/(5049-97))),(513880/(5819-1389)),(-" ascii
      $s2 = "7r3F6qPC/5FjR2SVcXaDR6VYsfCtCMx83e+TGkvBAEu/hpzMy7USfYaRPNTqZPiMqHSvtrKuVlQ+EP93OuS8OFKkP6EYEx3oOqkAUsx6i/o9+lvfznmt6WzEs/mjtDGB" ascii
      $s3 = "6NMcRCeuQdhtx2Xoacz063XeoJc3P17irYVUK5wY/G9fTp+Rtellhb8ParW+0BxofjYElankNdS333KAeg2LbtAUG4ByufRm2KKdg9Kf4IPJgLyyD8fCW3N4L17O15th" ascii
      $s4 = "kQ3uAV28NyU/+VWzXwTJSazEQWAJeF6h7A2sBI3R5FZt2dVGczfzOfDFAkEThSEFWMBnwVt/HZtoxH2ttNBh8srCzN2hd0YYqVk/COCpK6irdDDXGno5PMa9cHqxAU1g" ascii
      $s5 = "t9//wP071hS/9JGRGJVvGgWfUrj+bNDUq8TVfR798jckwAtezuAUTH/GctN9KSzS7rzpNr8KdALMRJO0PGWqVEwVwyTXxQ+JhwdE3r39gcGgYCLyjRW91rzBo3Q9oD3X" ascii
      $s6 = "acCcS3kjvnd6z4J6LqgoeKkWhUAAW5u39/KXWN2juvu1UwmoFt1rknXsWhH/4gz1wwrxtsaKBlNXBqgfS8+nYYVpcT+h7prdrOPU6G+y5J+fYjHNsmaE3wISBWx4axsY" ascii
      $s7 = "h]::Pow(2, 1 + 2))), ([math]::Pow(2, 1 + 2))) - 17)}))($null, $true)" fullword ascii
      $s8 = "Pow(2, 2 + 1))), ([math]::Pow(2, 2 + 1))) - 26)}))(($_ * (1240/(3159520/5096))), (7843-(12711-4870))))});$inreatalenaralesisatal" ascii
      $s9 = "j7cDhqB16gp3zSpyFzaVIWvEGu1AP5HxOW8dz9fGkpSxaw5c0FLkg+0SQHKxtxBVNOTLNbADgGHH5uRHWiIJrKt9H0TjlyffDLZtS7teCAJ0pOTc6hFNbz2btt87nI7o" ascii
      $s10 = "([math]::Pow(2, 2 + 2))) - 70)});$aleratererenenatistionanes = (-JoIN (@((490245/(36728355/3671)),(14504/(7522-7226)),(1797-1742" ascii
      $s11 = "$gwrxbc=$executioncontext;$altionenaresistionbeisined = -join (0..54 | ForEach-Object {[char]([int]\"000000000000012300000000000" ascii
      $s12 = "w(2, 2 + 1))) - 63)})).(([chAR[]]@((705669/(13224-(5692905/1733))),(909606/9006),(791352/6822),(5984-(12829-6929)),(5869-5748),(" ascii
      $s13 = "yEZmamZ+THM6SBcCl6UEcDtcNKMloxpA+wl+71qbO8YEQ0nRBtuBCpNP12EEL0UsTFByejJePk46qJlvWGFFuZE1zhVDz8U1He9bhs1ApNhWpX9DdUBlYSVEDTxTQv1H" ascii
      $s14 = "HXMHgLyxnnalDRDyDxo6xZRZQNt+NLj1AvDGYY66ldtJ0AibNW+YIWy9Q9CmVq0HYCTIEUJZ7TMfUi5eRlw+7byD7H2r0AIEr1hQmNhpp25Hg2aSTJKimeBBvT955KSN" ascii
      $s15 = "6IF94zCFkxVF0RHet3h4iEYKx8IyonZuFhFr9CRfvVtXZTSvdKAEEgiFU9iPH4wEzNVrBPtozALWjnxbp8XW+p9x03rGdvtwa2K8xD3+gx2oCGBPpA3q5+hYzvazNEWA" ascii
      $s16 = "jn3zFuGwK1Fu7UqhgjQ4PKVh3ffmfjgBe73kmphvdLYo887R33bs8tLs4+8TdTheCu1/0Uw7PBofvT/SyiWL5UHQcPuWG2CrJs/5x/RTBsQq7CrCqX0f1NluwuXuwj1b" ascii
      $s17 = "5gchVI5zZb17XQsIJkXSjEHeqapZ8wCDmBmD0fl2Eyn3LVMhvdqdULoIYtXyoZfv3z7yEk4aKj44rlsCDh56Fjp6LhrSsmH+Ygpe/P0EQHc7rFIdUFxiekoO4u8Lq527" ascii
      $s18 = "5lztGhAvVCME8x8bHDN449kHj78oC3bIQnYNQSlpIUkhb5rOZWROKjr0Gky4qMKGTIk07F7Fuig2Hh58gk5GAlATWfHAkfpzWBnwkFDEN2NDlTrLEatjQfQ+1oP30g3N" ascii
      $s19 = "Pqb9kyxQOYRQ6qVmB/ltK8r6PuXuMLCqG51nmq7dqZjjPJ8AsL8pIgGgiwWGxHLF7Ne8Iviv3JQGLnP26VxKRi3+EEFjOnNVm0pDkiHOgRGHeLGtGGCLn8hFyNsjZmQI" ascii
      $s20 = "X3GoYJkKc/BaVVv1HXxhNWh++sDQdViwrQ86o0j5Ch9hMOqklzamMkGvn/zBvag8gZuMUtuEqfjU7QLtkCJNbtoQ05kKHskl2Wo4x+T3tHX0rfJaMoesZhW9bevaqiWU" ascii
   condition:
      uint16(0) == 0x6724 and filesize < 60KB and
      8 of them
}

rule sig_27a7ba032f7d6cf787454c2fd036c95d13be9fb489b26fd9050659aa23498dd6 {
   meta:
      description = "evidences - file 27a7ba032f7d6cf787454c2fd036c95d13be9fb489b26fd9050659aa23498dd6.exe"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-07"
      hash1 = "27a7ba032f7d6cf787454c2fd036c95d13be9fb489b26fd9050659aa23498dd6"
   strings:
      $s1 = "System.Security.Permissions.SecurityPermissionAttribute, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934" ascii
      $s2 = "VCRUNTIME140_1.dll" fullword ascii
      $s3 = "https://tzpdld.com/update/download" fullword wide
      $s4 = "DotNet.getCorRtHost_byVersion" fullword ascii
      $s5 = "https://tzpdld.com/update/auth" fullword wide
      $s6 = "Session.GetKey" fullword ascii
      $s7 = "?A0xeb4f7d22.??__E?InitializedPerProcess@CurrentDomain@<CrtImplementationDetails>@@$$Q2W4Progress@2@A@@YMXXZ" fullword ascii
      $s8 = "__m2mep@?GetKey@Session@@$$FSAHPEAU_CLIENT_DATA@@@Z" fullword ascii
      $s9 = "?A0xeb4f7d22.?InitializedPerProcess$initializer$@CurrentDomain@<CrtImplementationDetails>@@$$Q2P6MXXZEA" fullword ascii
      $s10 = "        <requestedExecutionLevel level='asInvoker' uiAccess='false' />" fullword ascii
      $s11 = "DotNet.bruteforce_CLRhost" fullword ascii
      $s12 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0" fullword wide
      $s13 = "??_C@_0BF@OOFKKNEJ@?$FL?$CB?$FN?5Download?5error?$CB?6@" fullword ascii
      $s14 = "[!] Download error!" fullword ascii
      $s15 = "GetAppHash" fullword ascii
      $s16 = "DotNet.getDefaultDomain" fullword ascii
      $s17 = "GetInstallHash" fullword ascii
      $s18 = "Tools.get_client" fullword ascii
      $s19 = "NetworkRequest.GetData" fullword ascii
      $s20 = "Tools.get_clientdata" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      8 of them
}

rule sig_6a3222ecabe6739e9016073da83d46d2b8e2bd59b1ac200c3285fde3287e3ea8 {
   meta:
      description = "evidences - file 6a3222ecabe6739e9016073da83d46d2b8e2bd59b1ac200c3285fde3287e3ea8.exe"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-07"
      hash1 = "6a3222ecabe6739e9016073da83d46d2b8e2bd59b1ac200c3285fde3287e3ea8"
   strings:
      $s1 = "lSystem.Resources.ResourceReader, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.R" ascii
      $s2 = "TEST.exe" fullword wide
      $s3 = "TestResource/Launcher_Start.exe" fullword wide
      $s4 = " version.txt" fullword wide
      $s5 = "webClient_DownloadFileCompleted" fullword ascii
      $s6 = "        <requestedExecutionLevel level=\"requireAdministrator\" uiAccess=\"false\" />" fullword ascii
      $s7 = "D:\\Documents\\Project\\" fullword ascii
      $s8 = "\\updater\\Test.AionClassic.Pro\\obj\\x64\\Release\\TEST.pdb" fullword ascii
      $s9 = ".NET Framework 4.8" fullword ascii
      $s10 = "webClient_DownloadProgressChanged" fullword ascii
      $s11 = ".NETFramework,Version=v4.8" fullword ascii
      $s12 = "Release.zip" fullword wide
      $s13 = "https://test.aionclassic.pro/launcher/updater/version.txt" fullword wide
      $s14 = "TestResource/version.ini" fullword wide
      $s15 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">" fullword ascii
      $s16 = "Update.Properties.Resources.resources" fullword ascii
      $s17 = "Update.Form1.resources" fullword ascii
      $s18 = "Update.Properties" fullword ascii
      $s19 = "Update.Properties.Resources" fullword wide
      $s20 = "17.0.0.0" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 500KB and
      8 of them
}

rule sig_8f5469d96f148afd08a0f693684f9bb0195a5291eb2437214c01465b463acbf8 {
   meta:
      description = "evidences - file 8f5469d96f148afd08a0f693684f9bb0195a5291eb2437214c01465b463acbf8.exe"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-07"
      hash1 = "476f526d9f5f3010094e5a977c6a24558ddb12f9c02c5577bf47f8ed92d07bac"
   strings:
      $s1 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3" ascii
      $s2 = "DriverUninstall.exe" fullword wide
      $s3 = "D:\\Workspace\\Driver\\DriverUninstall\\Release\\DriverUninstall.pdb" fullword ascii
      $s4 = "curity><requestedPrivileges><requestedExecutionLevel level=\"requireAdministrator\" uiAccess=\"false\"></requestedExecutionLevel" ascii
      $s5 = "\\sprdvcom.sys" fullword wide
      $s6 = "\\rdavcom.sys" fullword wide
      $s7 = "\\sprdport.sys" fullword wide
      $s8 = "\\sprd_rdavcom.sys" fullword wide
      $s9 = "\\sprd_wvcom.sys" fullword wide
      $s10 = "\\sprdvcomIOT.sys" fullword wide
      $s11 = "\\usbcommsprdserial.sys" fullword wide
      $s12 = "ings:dpiAware xmlns:ms_windowsSettings=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\" xmlns=\"http://schemas.microsof" ascii
      $s13 = ".\\uninstall.log" fullword ascii
      $s14 = "\\sprdvmdm.sys" fullword wide
      $s15 = "\\sprdmux.sys" fullword wide
      $s16 = "\\sprdbus.sys" fullword wide
      $s17 = "\\sprdmodem.sys" fullword wide
      $s18 = "\\sprd_acm.sys" fullword wide
      $s19 = "\\sprd_enum.sys" fullword wide
      $s20 = "\\sprd_wvmdm.sys" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      8 of them
}

rule cbdfe04b8f754e5e6150936ee604f0a478b79c6d0466ee155775ead575adea90 {
   meta:
      description = "evidences - file cbdfe04b8f754e5e6150936ee604f0a478b79c6d0466ee155775ead575adea90.exe"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-07"
      hash1 = "cbdfe04b8f754e5e6150936ee604f0a478b79c6d0466ee155775ead575adea90"
   strings:
      $s1 = "Updater.exe" fullword wide
      $s2 = "!http://ocsp.globalsign.com/rootr30;" fullword ascii
      $s3 = "-http://ocsp.globalsign.com/codesigningrootr450F" fullword ascii
      $s4 = "0http://crl.globalsign.com/codesigningrootr45.crl0U" fullword ascii
      $s5 = "4http://crl3.digicert.com/DigiCertAssuredIDRootCA.crl0" fullword ascii
      $s6 = "2http://crl3.digicert.com/DigiCertTrustedRootG4.crl0 " fullword ascii
      $s7 = "/http://secure.globalsign.com/cacert/root-r3.crt06" fullword ascii
      $s8 = "%http://crl.globalsign.com/root-r3.crl0G" fullword ascii
      $s9 = "7http://cacerts.digicert.com/DigiCertAssuredIDRootCA.crt0E" fullword ascii
      $s10 = "5http://cacerts.digicert.com/DigiCertTrustedRootG4.crt0C" fullword ascii
      $s11 = ":http://secure.globalsign.com/cacert/codesigningrootr45.crt0A" fullword ascii
      $s12 = "\\ZipThisApp.exe" fullword wide
      $s13 = "\\zipthisUserId.txt" fullword wide
      $s14 = "http://ocsp.digicert.com0X" fullword ascii
      $s15 = "ZXZlbnRfbmFtZQ==" fullword wide /* base64 encoded string 'event_name' */
      $s16 = "ZmV0Y2hlcl9sb2c=" fullword wide /* base64 encoded string 'fetcher_log' */
      $s17 = "dXNlcl9pZA==" fullword wide /* base64 encoded string 'user_id' */
      $s18 = "dXBkYXRlcl9lcnJvcg==" fullword wide /* base64 encoded string 'updater_error' */
      $s19 = "3http://ocsp.globalsign.com/gsgccr45evcodesignca20200U" fullword ascii
      $s20 = "6http://crl.globalsign.com/gsgccr45evcodesignca2020.crl0$" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 60KB and
      8 of them
}

rule sig_94694e56c6d22a0115a3dc615597f5e24a5f844fb5a250a4b71f673cfc2d0d02 {
   meta:
      description = "evidences - file 94694e56c6d22a0115a3dc615597f5e24a5f844fb5a250a4b71f673cfc2d0d02.apk"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-07"
      hash1 = "94694e56c6d22a0115a3dc615597f5e24a5f844fb5a250a4b71f673cfc2d0d02"
   strings:
      $s1 = "$$res/drawable/design_password_eye.xml" fullword ascii
      $s2 = "res/drawable/design_password_eye.xml" fullword ascii
      $s3 = "%%res/layout/test_toolbar_elevation.xml" fullword ascii
      $s4 = "META-INF/androidx.lifecycle_lifecycle-process.version3" fullword ascii
      $s5 = "META-INF/androidx.lifecycle_lifecycle-process.versionPK" fullword ascii
      $s6 = "com.mem.installdropsession" fullword wide
      $s7 = "org/apache/commons/codec/language/bm/sep_rules_portuguese.txt" fullword ascii
      $s8 = "res/layout-land/mtrl_picker_header_dialog.xml" fullword ascii
      $s9 = "res/layout/mtrl_picker_header_dialog.xml" fullword ascii
      $s10 = "res/drawable/design_password_eye.xmlPK" fullword ascii
      $s11 = "--res/layout-land/mtrl_picker_header_dialog.xml" fullword ascii
      $s12 = "org/apache/commons/codec/language/bm/gen_rules_portuguese.txt" fullword ascii
      $s13 = "((res/layout/mtrl_picker_header_dialog.xml" fullword ascii
      $s14 = "*http://schemas.android.com/apk/res/android" fullword wide
      $s15 = "com.qualcomm.qti.tetherservice" fullword ascii
      $s16 = "44res/animator/m3_btn_elevated_btn_state_list_anim.xml" fullword ascii
      $s17 = "44res/animator/mtrl_btn_unelevated_state_list_anim.xml" fullword ascii
      $s18 = "--com.qualcomm.qti.auth.securesampleauthservice" fullword ascii
      $s19 = "res/color/m3_elevated_chip_background_color.xml" fullword ascii
      $s20 = "res/animator/m3_btn_elevated_btn_state_list_anim.xml" fullword ascii
   condition:
      uint16(0) == 0x4b50 and filesize < 14000KB and
      8 of them
}

rule fde931224d2e558e67ac8c9c0c1d0aac4f7562622a67870d6c3024bdeb851676 {
   meta:
      description = "evidences - file fde931224d2e558e67ac8c9c0c1d0aac4f7562622a67870d6c3024bdeb851676.apk"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-07"
      hash1 = "fde931224d2e558e67ac8c9c0c1d0aac4f7562622a67870d6c3024bdeb851676"
   strings:
      $s1 = "META-INF/androidx.lifecycle_lifecycle-process.version3" fullword ascii
      $s2 = "META-INF/androidx.lifecycle_lifecycle-process.versionPK" fullword ascii
      $s3 = "org/apache/commons/codec/language/bm/sep_rules_portuguese.txt" fullword ascii
      $s4 = "org/apache/commons/codec/language/bm/gen_rules_portuguese.txt" fullword ascii
      $s5 = "*http://schemas.android.com/apk/res/android" fullword wide
      $s6 = "android.permission.DUMP" fullword wide
      $s7 = "Nandroidx.work.impl.background.systemalarm.ConstraintProxy$BatteryChargingProxy" fullword wide
      $s8 = "Landroidx.work.impl.background.systemalarm.ConstraintProxy$BatteryNotLowProxy" fullword wide
      $s9 = "Kandroidx.work.impl.background.systemalarm.ConstraintProxy$NetworkStateProxy" fullword wide
      $s10 = "Landroidx.work.impl.background.systemalarm.ConstraintProxy$StorageNotLowProxy" fullword wide
      $s11 = "Gandroidx.work.impl.background.systemalarm.ConstraintProxyUpdateReceiver" fullword wide
      $s12 = "8androidx.work.impl.background.systemjob.SystemJobService" fullword wide
      $s13 = "5androidx.work.impl.foreground.SystemForegroundService" fullword wide
      $s14 = ".com.android.launcher2.permission.READ_SETTINGS" fullword wide
      $s15 = ".com.android.launcher3.permission.READ_SETTINGS" fullword wide
      $s16 = "com.qualcomm.qti.tetherservice" fullword ascii
      $s17 = "--com.qualcomm.qti.auth.securesampleauthservice" fullword ascii
      $s18 = "res/color/m3_elevated_chip_background_color.xml" fullword ascii
      $s19 = "//res/color/m3_elevated_chip_background_color.xml" fullword ascii
      $s20 = "META-INF/androidx.loader_loader.version3" fullword ascii
   condition:
      uint16(0) == 0x4b50 and filesize < 11000KB and
      8 of them
}

rule sig_2eb065b1232323c7342347e2d57a7894da0ee9a24c2525fdc2dbfbac28731028 {
   meta:
      description = "evidences - file 2eb065b1232323c7342347e2d57a7894da0ee9a24c2525fdc2dbfbac28731028.msi"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-07"
      hash1 = "2eb065b1232323c7342347e2d57a7894da0ee9a24c2525fdc2dbfbac28731028"
   strings:
      $x1 = "NameTableTypeColumnValue_ValidationNPropertyId_SummaryInformationDescriptionSetCategoryKeyColumnMaxValueNullableKeyTableMinValue" ascii
      $x2 = "oned files.LanguageList of decimal language Ids, comma-separated if more than one.Integer containing bit flags representing file" ascii
      $x3 = "4C4}INSTALLFOLDERl4dZhengJiaLe8964ProgramFilesFoldergujfn150|Windows NTTARGETDIR.SourceDirSetupfile.datValidateProductIDProcessC" ascii
      $x4 = "on.AdminUISequenceAdvtExecuteSequenceBinaryUnique key identifying the binary data.DataThe unformatted binary data.ComponentPrima" ascii
      $s5 = "ReachFramework.resources.dll" fullword wide
      $s6 = "get_loader_name_from_dll" fullword ascii
      $s7 = "Update.dll" fullword ascii
      $s8 = "f columnAdminExecuteSequenceActionName of action to invoke, either in the engine or the handler DLL.ConditionOptional expression" ascii
      $s9 = "ry key used to identify a particular component record.ComponentIdGuidA string GUID unique to this component, version, and langua" ascii
      $s10 = "ack cabinet order.InstallExecuteSequenceInstallUISequenceMediaDiskIdPrimary key, integer to determine sort order for table.LastS" ascii
      $s11 = "alizeInstallAdminPackageInstallFilesInstallFinalizeExecuteActionPublishFeaturesPublishProduct_{125CBCBA-000D-4311-82CD-4ABABCD73" ascii
      $s12 = "qgethostname" fullword ascii
      $s13 = "process_config_directive" fullword ascii
      $s14 = "get_loader_name" fullword ascii
      $s15 = "ode.TargetFormattedExcecution parameter, depends on the type of custom actionExtendedTypeA numeric custom action type that exten" ascii
      $s16 = "ags.SourceCustomSourceThe table reference of the source of the code.TargetFormattedExcecution parameter, depends on the type of " ascii
      $s17 = "dActionData.SequenceNumber that determines the sort order in which the actions are to be executed.  Leave blank to suppress acti" ascii
      $s18 = ", Name of table to which data must linkColumn to which foreign key connectsText;Formatted;Template;Condition;Guid;Path;Version;L" ascii
      $s19 = "qregexec" fullword ascii
      $s20 = "ature attributesFeatureComponentsFeature_Foreign key into Feature table.Component_Foreign key into Component table.FilePrimary k" ascii
   condition:
      uint16(0) == 0xcfd0 and filesize < 25000KB and
      1 of ($x*) and 4 of them
}

rule sig_4d598a25fe154e10edcbaaac7361049e5e1c93a4c4e00a942964c8ae98e0d11a {
   meta:
      description = "evidences - file 4d598a25fe154e10edcbaaac7361049e5e1c93a4c4e00a942964c8ae98e0d11a.msi"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-07"
      hash1 = "4d598a25fe154e10edcbaaac7361049e5e1c93a4c4e00a942964c8ae98e0d11a"
   strings:
      $x1 = "NameTableTypeColumnValue_ValidationNPropertyId_SummaryInformationDescriptionSetCategoryKeyColumnMaxValueNullableKeyTableMinValue" ascii
      $x2 = "oned files.LanguageList of decimal language Ids, comma-separated if more than one.Integer containing bit flags representing file" ascii
      $x3 = "4C4}INSTALLFOLDERl4dZhengJiaLe8964ProgramFilesFoldergujfn150|Windows NTTARGETDIR.SourceDirSetupfile.datValidateProductIDProcessC" ascii
      $x4 = "on.AdminUISequenceAdvtExecuteSequenceBinaryUnique key identifying the binary data.DataThe unformatted binary data.ComponentPrima" ascii
      $s5 = "ReachFramework.resources.dll" fullword wide
      $s6 = "get_loader_name_from_dll" fullword ascii
      $s7 = "Update.dll" fullword ascii
      $s8 = "f columnAdminExecuteSequenceActionName of action to invoke, either in the engine or the handler DLL.ConditionOptional expression" ascii
      $s9 = "ry key used to identify a particular component record.ComponentIdGuidA string GUID unique to this component, version, and langua" ascii
      $s10 = "ack cabinet order.InstallExecuteSequenceInstallUISequenceMediaDiskIdPrimary key, integer to determine sort order for table.LastS" ascii
      $s11 = "alizeInstallAdminPackageInstallFilesInstallFinalizeExecuteActionPublishFeaturesPublishProduct_{125CBCBA-000D-4311-82CD-4ABABCD73" ascii
      $s12 = "qgethostname" fullword ascii
      $s13 = "process_config_directive" fullword ascii
      $s14 = "get_loader_name" fullword ascii
      $s15 = "ode.TargetFormattedExcecution parameter, depends on the type of custom actionExtendedTypeA numeric custom action type that exten" ascii
      $s16 = "ags.SourceCustomSourceThe table reference of the source of the code.TargetFormattedExcecution parameter, depends on the type of " ascii
      $s17 = "dActionData.SequenceNumber that determines the sort order in which the actions are to be executed.  Leave blank to suppress acti" ascii
      $s18 = ", Name of table to which data must linkColumn to which foreign key connectsText;Formatted;Template;Condition;Guid;Path;Version;L" ascii
      $s19 = "qregexec" fullword ascii
      $s20 = "ature attributesFeatureComponentsFeature_Foreign key into Feature table.Component_Foreign key into Component table.FilePrimary k" ascii
   condition:
      uint16(0) == 0xcfd0 and filesize < 25000KB and
      1 of ($x*) and 4 of them
}

rule sig_9c8f45131281ea291dba4a21af7bd94183039b89209a1da23b9c336f00bcc6fe {
   meta:
      description = "evidences - file 9c8f45131281ea291dba4a21af7bd94183039b89209a1da23b9c336f00bcc6fe.msi"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-07"
      hash1 = "9c8f45131281ea291dba4a21af7bd94183039b89209a1da23b9c336f00bcc6fe"
   strings:
      $x1 = "NameTableTypeColumnValue_ValidationNPropertyId_SummaryInformationDescriptionSetCategoryKeyColumnMaxValueNullableKeyTableMinValue" ascii
      $x2 = "oned files.LanguageList of decimal language Ids, comma-separated if more than one.Integer containing bit flags representing file" ascii
      $x3 = "4C4}INSTALLFOLDERl4dZhengJiaLe8964ProgramFilesFoldergujfn150|Windows NTTARGETDIR.SourceDirSetupfile.datValidateProductIDProcessC" ascii
      $x4 = "on.AdminUISequenceAdvtExecuteSequenceBinaryUnique key identifying the binary data.DataThe unformatted binary data.ComponentPrima" ascii
      $s5 = "ReachFramework.resources.dll" fullword wide
      $s6 = "get_loader_name_from_dll" fullword ascii
      $s7 = "Update.dll" fullword ascii
      $s8 = "f columnAdminExecuteSequenceActionName of action to invoke, either in the engine or the handler DLL.ConditionOptional expression" ascii
      $s9 = "ry key used to identify a particular component record.ComponentIdGuidA string GUID unique to this component, version, and langua" ascii
      $s10 = "ack cabinet order.InstallExecuteSequenceInstallUISequenceMediaDiskIdPrimary key, integer to determine sort order for table.LastS" ascii
      $s11 = "alizeInstallAdminPackageInstallFilesInstallFinalizeExecuteActionPublishFeaturesPublishProduct_{125CBCBA-000D-4311-82CD-4ABABCD73" ascii
      $s12 = "qgethostname" fullword ascii
      $s13 = "process_config_directive" fullword ascii
      $s14 = "get_loader_name" fullword ascii
      $s15 = "ode.TargetFormattedExcecution parameter, depends on the type of custom actionExtendedTypeA numeric custom action type that exten" ascii
      $s16 = "ags.SourceCustomSourceThe table reference of the source of the code.TargetFormattedExcecution parameter, depends on the type of " ascii
      $s17 = "dActionData.SequenceNumber that determines the sort order in which the actions are to be executed.  Leave blank to suppress acti" ascii
      $s18 = ", Name of table to which data must linkColumn to which foreign key connectsText;Formatted;Template;Condition;Guid;Path;Version;L" ascii
      $s19 = "qregexec" fullword ascii
      $s20 = "ature attributesFeatureComponentsFeature_Foreign key into Feature table.Component_Foreign key into Component table.FilePrimary k" ascii
   condition:
      uint16(0) == 0xcfd0 and filesize < 25000KB and
      1 of ($x*) and 4 of them
}

rule def2fe31fadaedb011d5e637a272e649405ce748dcfb1ab90cdc7d32237e8859 {
   meta:
      description = "evidences - file def2fe31fadaedb011d5e637a272e649405ce748dcfb1ab90cdc7d32237e8859.msi"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-07"
      hash1 = "def2fe31fadaedb011d5e637a272e649405ce748dcfb1ab90cdc7d32237e8859"
   strings:
      $x1 = "NameTableTypeColumnValue_ValidationNPropertyId_SummaryInformationDescriptionSetCategoryKeyColumnMaxValueNullableKeyTableMinValue" ascii
      $x2 = "oned files.LanguageList of decimal language Ids, comma-separated if more than one.Integer containing bit flags representing file" ascii
      $x3 = "4C4}INSTALLFOLDERl4dZhengJiaLe8964ProgramFilesFoldergujfn150|Windows NTTARGETDIR.SourceDirSetupfile.datValidateProductIDProcessC" ascii
      $x4 = "on.AdminUISequenceAdvtExecuteSequenceBinaryUnique key identifying the binary data.DataThe unformatted binary data.ComponentPrima" ascii
      $s5 = "ReachFramework.resources.dll" fullword wide
      $s6 = "get_loader_name_from_dll" fullword ascii
      $s7 = "Update.dll" fullword ascii
      $s8 = "f columnAdminExecuteSequenceActionName of action to invoke, either in the engine or the handler DLL.ConditionOptional expression" ascii
      $s9 = "ry key used to identify a particular component record.ComponentIdGuidA string GUID unique to this component, version, and langua" ascii
      $s10 = "ack cabinet order.InstallExecuteSequenceInstallUISequenceMediaDiskIdPrimary key, integer to determine sort order for table.LastS" ascii
      $s11 = "alizeInstallAdminPackageInstallFilesInstallFinalizeExecuteActionPublishFeaturesPublishProduct_{125CBCBA-000D-4311-82CD-4ABABCD73" ascii
      $s12 = "qgethostname" fullword ascii
      $s13 = "process_config_directive" fullword ascii
      $s14 = "get_loader_name" fullword ascii
      $s15 = "ode.TargetFormattedExcecution parameter, depends on the type of custom actionExtendedTypeA numeric custom action type that exten" ascii
      $s16 = "ags.SourceCustomSourceThe table reference of the source of the code.TargetFormattedExcecution parameter, depends on the type of " ascii
      $s17 = "dActionData.SequenceNumber that determines the sort order in which the actions are to be executed.  Leave blank to suppress acti" ascii
      $s18 = ", Name of table to which data must linkColumn to which foreign key connectsText;Formatted;Template;Condition;Guid;Path;Version;L" ascii
      $s19 = "qregexec" fullword ascii
      $s20 = "ature attributesFeatureComponentsFeature_Foreign key into Feature table.Component_Foreign key into Component table.FilePrimary k" ascii
   condition:
      uint16(0) == 0xcfd0 and filesize < 26000KB and
      1 of ($x*) and 4 of them
}

rule sig_36c48cccbb350187491e4a513ebc05d5d8550c88f5b57ee8de0ea1914ea2af28 {
   meta:
      description = "evidences - file 36c48cccbb350187491e4a513ebc05d5d8550c88f5b57ee8de0ea1914ea2af28.zip"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-07"
      hash1 = "36c48cccbb350187491e4a513ebc05d5d8550c88f5b57ee8de0ea1914ea2af28"
   strings:
      $s1 = "FACTURAMAIL.htmlPK" fullword ascii
      $s2 = "FACTURAMAIL.html" fullword ascii
      $s3 = "?CJN|K" fullword ascii
      $s4 = "64$YJ[" fullword ascii
      $s5 = "wnN*)!" fullword ascii
      $s6 = "fh*SSuA" fullword ascii
      $s7 = "'2\"S\\e" fullword ascii
   condition:
      uint16(0) == 0x4b50 and filesize < 7KB and
      all of them
}

rule sig_4c56d42d6eb7bce78e43e0328df9596b38fdbbb21f750ce30437a2d6a043b1ab {
   meta:
      description = "evidences - file 4c56d42d6eb7bce78e43e0328df9596b38fdbbb21f750ce30437a2d6a043b1ab.sh"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-07"
      hash1 = "4c56d42d6eb7bce78e43e0328df9596b38fdbbb21f750ce30437a2d6a043b1ab"
   strings:
      $s1 = "#!/bin/bash" fullword ascii
      $s2 = "# EICAR test string" fullword ascii
      $s3 = "echo \"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*\"" fullword ascii
   condition:
      uint16(0) == 0x2123 and filesize < 1KB and
      all of them
}

rule sig_8192b877a210281568cb059c8b597d4442e852607131651d89584992ea3f1010 {
   meta:
      description = "evidences - file 8192b877a210281568cb059c8b597d4442e852607131651d89584992ea3f1010.unknown"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-07"
      hash1 = "8192b877a210281568cb059c8b597d4442e852607131651d89584992ea3f1010"
   strings:
      $s1 = "WQQIvXT" fullword ascii
      $s2 = "ITThm:6" fullword ascii
      $s3 = "eKCX!HL" fullword ascii
      $s4 = "kZ;!EGPKBQ*" fullword ascii
      $s5 = "jYlVC!b" fullword ascii
      $s6 = "mBUC1m(P@m" fullword ascii
      $s7 = "FjVbibZ" fullword ascii
      $s8 = ".cpI&}T" fullword ascii
      $s9 = "CfzV$zt" fullword ascii
      $s10 = "QueV<*R,N" fullword ascii
      $s11 = "kZcR8&{" fullword ascii
      $s12 = "eZRSl\\v" fullword ascii
      $s13 = "deIA%Od" fullword ascii
      $s14 = "JkTlE$f" fullword ascii
      $s15 = "VXhC\\S" fullword ascii
      $s16 = "I)V.Sbg" fullword ascii
      $s17 = "idXM[_r" fullword ascii
      $s18 = "UKIJBsh" fullword ascii
      $s19 = ";CBVRddi" fullword ascii
      $s20 = "gMijiXB?" fullword ascii
   condition:
      uint16(0) == 0xd8ff and filesize < 600KB and
      8 of them
}

rule sig_83112fc8a354c0a8b2693c09e31247e8d10acd98f0544e9bbb4ad741896d1a70 {
   meta:
      description = "evidences - file 83112fc8a354c0a8b2693c09e31247e8d10acd98f0544e9bbb4ad741896d1a70.rar"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-07"
      hash1 = "83112fc8a354c0a8b2693c09e31247e8d10acd98f0544e9bbb4ad741896d1a70"
   strings:
      $s1 = "PO-000172483 pdf.exe" fullword ascii
      $s2 = "6|\"#'-9`" fullword ascii /* hex encoded string 'i' */
      $s3 = "fgddllmmee(" fullword ascii
      $s4 = "-pU:\\O" fullword ascii
      $s5 = "q1T.Vwx" fullword ascii
      $s6 = "tJ:\\(C#" fullword ascii
      $s7 = "\\ -$@A" fullword ascii
      $s8 = "Zaqrook" fullword ascii
      $s9 = "*38- ^" fullword ascii
      $s10 = "\\pkEa|Y|" fullword ascii
      $s11 = "# n5HF" fullword ascii
      $s12 = "sWDqXqm0" fullword ascii
      $s13 = "aZ%}<- " fullword ascii
      $s14 = " -?J}(2" fullword ascii
      $s15 = ")NBsC, `" fullword ascii
      $s16 = "Mofu//T" fullword ascii
      $s17 = "NjkH<DI" fullword ascii
      $s18 = "9>8tXNK>`:" fullword ascii
      $s19 = "KfvQ(ML," fullword ascii
      $s20 = "QTfQ9I\\" fullword ascii
   condition:
      uint16(0) == 0x6152 and filesize < 2000KB and
      8 of them
}

rule sig_9e3bb3e18cd84227fd2a52ae89837d866e402b92652d81264f805821c5611e14 {
   meta:
      description = "evidences - file 9e3bb3e18cd84227fd2a52ae89837d866e402b92652d81264f805821c5611e14.unknown"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-07"
      hash1 = "9e3bb3e18cd84227fd2a52ae89837d866e402b92652d81264f805821c5611e14"
   strings:
      $s1 = "AMWTIPFileHashDBDownloader - y" fullword ascii
      $s2 = "HSBFSTStore - generateHashCode - move to util - y" fullword ascii
      $s3 = " - move to utl" fullword ascii
      $s4 = "0_1_md5.shsb - 141 MB" fullword ascii
      $s5 = "HSBFSTIndexMap -  y" fullword ascii
      $s6 = "HSBFST - y" fullword ascii
      $s7 = "FSTWrapper - TO DO" fullword ascii
      $s8 = "total signatures count in fst - 2442366" fullword ascii
      $s9 = "0_1_md5.hsb - 2447378" fullword ascii
      $s10 = "7316370007246b2cd83a2210a0b1d1c1:203824:osx.malware.agent-7679997-0:73" fullword ascii
      $s11 = "check with this hash" fullword ascii
      $s12 = "3797880822420460763:257200:osx.malware.agent-7680198-0:73" fullword ascii
      $s13 = "3110884603881437933:203824:osx.malware.agent-7679997-0:73" fullword ascii
      $s14 = "classpath - y" fullword ascii
      $s15 = "HASHIndexer" fullword ascii
      $s16 = "b4bdf8c7a87e30abaa22452bb2c37278:44544:win.trojan.loony-17" fullword ascii
      $s17 = "d9afd878542adc48da21f5ee394fbeaf:24576:win.trojan.vb-103" fullword ascii
      $s18 = "b1b5e6514fc3642f72fb654a9438e034:40448:win.trojan.dialer-286" fullword ascii
      $s19 = "b4bdf8c7a87e30abaa22452bb2c37278" ascii
      $s20 = "FSTUtil" fullword ascii
   condition:
      uint16(0) == 0x3939 and filesize < 2KB and
      8 of them
}

rule de285b9f73391d5476dbe764acdd14be8a95df42d16a26df8e7299c785d0e234 {
   meta:
      description = "evidences - file de285b9f73391d5476dbe764acdd14be8a95df42d16a26df8e7299c785d0e234.html"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-07"
      hash1 = "de285b9f73391d5476dbe764acdd14be8a95df42d16a26df8e7299c785d0e234"
   strings:
      $s1 = "<head><meta http-equiv=\"Content-Type\" content=\"text/html; charset=UTF-8\" /><link rel=\"stylesheet\" type=\"text/css\" href=" ascii
      $s2 = "<script type=\"text/javascript\" src=\"https://s.uicdn.com/3c-cdn/mail/client/wicket/resource/static-res/---/js/head-vEr-643ABA7" ascii
      $s3 = "<script type=\"text/javascript\" src=\"https://s.uicdn.com/3c-cdn/mail/client/wicket/resource/static-res/---/js/head-vEr-643ABA7" ascii
      $s4 = "<script type=\"text/javascript\" src=\"https://s.uicdn.com/3c-cdn/mail/client/wicket/resource/static-res/---/js/behavior-vEr-EC7" ascii
      $s5 = "<script type=\"text/javascript\" src=\"https://s.uicdn.com/3c-cdn/mail/client/wicket/resource/static-res/---/js/core-vEr-87B19EB" ascii
      $s6 = "<script type=\"text/javascript\" src=\"https://s.uicdn.com/3c-cdn/mail/client/wicket/resource/static-res/en/js/language-vEr-DBA7" ascii
      $s7 = "<script type=\"text/javascript\" src=\"https://s.uicdn.com/3c-cdn/mail/client/wicket/resource/static-res/---/js/jqueryui-vEr-DCE" ascii
      $s8 = "<script type=\"text/javascript\" src=\"https://s.uicdn.com/3c-cdn/mail/client/wicket/resource/static-res/---/js/external-vEr-C40" ascii
      $s9 = "<script type=\"text/javascript\" src=\"https://s.uicdn.com/3c-cdn/mail/client/wicket/resource/org.apache.wicket.ajax.AbstractDef" ascii
      $s10 = "<script type=\"text/javascript\" id=\"phx-namespace\">var phx = { vars : {\"blankUrl\":\"https://deref-mail.com/mail/client/blan" ascii
      $s11 = "<script type=\"text/javascript\" src=\"https://s.uicdn.com/3c-cdn/mail/client/wicket/resource/static-res/---/js/jqueryui-vEr-DCE" ascii
      $s12 = "<script type=\"text/javascript\" src=\"https://s.uicdn.com/3c-cdn/mail/client/wicket/resource/static-res/---/js/external-vEr-C40" ascii
      $s13 = "<script type=\"text/javascript\" src=\"https://s.uicdn.com/3c-cdn/mail/client/wicket/resource/static-res/en/js/language-vEr-DBA7" ascii
      $s14 = "<script type=\"text/javascript\" src=\"https://s.uicdn.com/3c-cdn/mail/client/wicket/resource/org.apache.wicket.ajax.AbstractDef" ascii
      $s15 = "<script type=\"text/javascript\" src=\"https://s.uicdn.com/3c-cdn/mail/client/wicket/resource/static-res/---/js/core-vEr-87B19EB" ascii
      $s16 = "<script type=\"text/javascript\" id=\"phx-namespace\">var phx = { vars : {\"blankUrl\":\"https://deref-mail.com/mail/client/blan" ascii
      $s17 = "<script type=\"text/javascript\" src=\"https://s.uicdn.com/3c-cdn/mail/client/wicket/resource/static-res/---/js/behavior-vEr-EC7" ascii
      $s18 = "If you use a screenreader we recommend that you use the following page: <a href=\"https://m.mail.com\">https://m.mail.com</a>" fullword ascii
      $s19 = "<script type=\"text/javascript\" src=\"//s.uicdn.com/nav-cdn/navigator-common/iac/client/5.2.0/iac.client-5.2.0.min.js\"></scrip" ascii
      $s20 = "<link rel=\"stylesheet\" type=\"text/css\" href=\"https://s.uicdn.com/3c-cdn/mail/client/wicket/resource/static-res/---/unified/" ascii
   condition:
      uint16(0) == 0x0a0d and filesize < 20KB and
      8 of them
}

/* Super Rules ------------------------------------------------------------- */

rule _2eb065b1232323c7342347e2d57a7894da0ee9a24c2525fdc2dbfbac28731028_4d598a25fe154e10edcbaaac7361049e5e1c93a4c4e00a942964c8ae98_0 {
   meta:
      description = "evidences - from files 2eb065b1232323c7342347e2d57a7894da0ee9a24c2525fdc2dbfbac28731028.msi, 4d598a25fe154e10edcbaaac7361049e5e1c93a4c4e00a942964c8ae98e0d11a.msi, 9c8f45131281ea291dba4a21af7bd94183039b89209a1da23b9c336f00bcc6fe.msi, def2fe31fadaedb011d5e637a272e649405ce748dcfb1ab90cdc7d32237e8859.msi"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-07"
      hash1 = "2eb065b1232323c7342347e2d57a7894da0ee9a24c2525fdc2dbfbac28731028"
      hash2 = "4d598a25fe154e10edcbaaac7361049e5e1c93a4c4e00a942964c8ae98e0d11a"
      hash3 = "9c8f45131281ea291dba4a21af7bd94183039b89209a1da23b9c336f00bcc6fe"
      hash4 = "def2fe31fadaedb011d5e637a272e649405ce748dcfb1ab90cdc7d32237e8859"
   strings:
      $x1 = "NameTableTypeColumnValue_ValidationNPropertyId_SummaryInformationDescriptionSetCategoryKeyColumnMaxValueNullableKeyTableMinValue" ascii
      $x2 = "4C4}INSTALLFOLDERl4dZhengJiaLe8964ProgramFilesFoldergujfn150|Windows NTTARGETDIR.SourceDirSetupfile.datValidateProductIDProcessC" ascii
      $x3 = "on.AdminUISequenceAdvtExecuteSequenceBinaryUnique key identifying the binary data.DataThe unformatted binary data.ComponentPrima" ascii
      $s4 = "ReachFramework.resources.dll" fullword wide
      $s5 = "get_loader_name_from_dll" fullword ascii
      $s6 = "Update.dll" fullword ascii
      $s7 = "f columnAdminExecuteSequenceActionName of action to invoke, either in the engine or the handler DLL.ConditionOptional expression" ascii
      $s8 = "ry key used to identify a particular component record.ComponentIdGuidA string GUID unique to this component, version, and langua" ascii
      $s9 = "ack cabinet order.InstallExecuteSequenceInstallUISequenceMediaDiskIdPrimary key, integer to determine sort order for table.LastS" ascii
      $s10 = "alizeInstallAdminPackageInstallFilesInstallFinalizeExecuteActionPublishFeaturesPublishProduct_{125CBCBA-000D-4311-82CD-4ABABCD73" ascii
      $s11 = "qgethostname" fullword ascii
      $s12 = "process_config_directive" fullword ascii
      $s13 = "get_loader_name" fullword ascii
      $s14 = "ode.TargetFormattedExcecution parameter, depends on the type of custom actionExtendedTypeA numeric custom action type that exten" ascii
      $s15 = "ags.SourceCustomSourceThe table reference of the source of the code.TargetFormattedExcecution parameter, depends on the type of " ascii
      $s16 = "dActionData.SequenceNumber that determines the sort order in which the actions are to be executed.  Leave blank to suppress acti" ascii
      $s17 = ", Name of table to which data must linkColumn to which foreign key connectsText;Formatted;Template;Condition;Guid;Path;Version;L" ascii
      $s18 = "qregexec" fullword ascii
      $s19 = "ature attributesFeatureComponentsFeature_Foreign key into Feature table.Component_Foreign key into Component table.FilePrimary k" ascii
      $s20 = ".TitleShort text identifying a visible feature item.Longer descriptive text describing a visible feature item.DisplayNumeric sor" ascii
   condition:
      ( uint16(0) == 0xcfd0 and filesize < 26000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _94694e56c6d22a0115a3dc615597f5e24a5f844fb5a250a4b71f673cfc2d0d02_fde931224d2e558e67ac8c9c0c1d0aac4f7562622a67870d6c3024bdeb_1 {
   meta:
      description = "evidences - from files 94694e56c6d22a0115a3dc615597f5e24a5f844fb5a250a4b71f673cfc2d0d02.apk, fde931224d2e558e67ac8c9c0c1d0aac4f7562622a67870d6c3024bdeb851676.apk"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-07"
      hash1 = "94694e56c6d22a0115a3dc615597f5e24a5f844fb5a250a4b71f673cfc2d0d02"
      hash2 = "fde931224d2e558e67ac8c9c0c1d0aac4f7562622a67870d6c3024bdeb851676"
   strings:
      $s1 = "META-INF/androidx.lifecycle_lifecycle-process.version3" fullword ascii
      $s2 = "META-INF/androidx.lifecycle_lifecycle-process.versionPK" fullword ascii
      $s3 = "org/apache/commons/codec/language/bm/sep_rules_portuguese.txt" fullword ascii
      $s4 = "org/apache/commons/codec/language/bm/gen_rules_portuguese.txt" fullword ascii
      $s5 = "*http://schemas.android.com/apk/res/android" fullword wide
      $s6 = "com.qualcomm.qti.tetherservice" fullword ascii
      $s7 = "--com.qualcomm.qti.auth.securesampleauthservice" fullword ascii
      $s8 = "res/color/m3_elevated_chip_background_color.xml" fullword ascii
      $s9 = "//res/color/m3_elevated_chip_background_color.xml" fullword ascii
      $s10 = "META-INF/androidx.loader_loader.version3" fullword ascii
      $s11 = "META-INF/androidx.loader_loader.versionPK" fullword ascii
      $s12 = "**com.qualcomm.qti.auth.secureextauthservice" fullword ascii
      $s13 = "00com.qualcomm.qti.auth.sampleauthenticatorservice" fullword ascii
      $s14 = ".androidx.lifecycle.ProcessLifecycleInitializer" fullword wide
      $s15 = "org/apache/commons/codec/language/bm/sep_rules_french.txt" fullword ascii
      $s16 = "org/apache/commons/codec/language/bm/gen_rules_polish.txt" fullword ascii
      $s17 = "org/apache/commons/codec/language/bm/sep_rules_italian.txt}S" fullword ascii
      $s18 = "org/apache/commons/codec/language/bm/gen_approx_polish.txt}R]" fullword ascii
      $s19 = "org/apache/commons/codec/language/bm/gen_rules_greek.txt" fullword ascii
      $s20 = "org/apache/commons/codec/language/bm/ash_rules_polish.txt" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and filesize < 14000KB and ( 8 of them )
      ) or ( all of them )
}

rule _4d598a25fe154e10edcbaaac7361049e5e1c93a4c4e00a942964c8ae98e0d11a_9c8f45131281ea291dba4a21af7bd94183039b89209a1da23b9c336f00_2 {
   meta:
      description = "evidences - from files 4d598a25fe154e10edcbaaac7361049e5e1c93a4c4e00a942964c8ae98e0d11a.msi, 9c8f45131281ea291dba4a21af7bd94183039b89209a1da23b9c336f00bcc6fe.msi"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-07"
      hash1 = "4d598a25fe154e10edcbaaac7361049e5e1c93a4c4e00a942964c8ae98e0d11a"
      hash2 = "9c8f45131281ea291dba4a21af7bd94183039b89209a1da23b9c336f00bcc6fe"
   strings:
      $x1 = "oned files.LanguageList of decimal language Ids, comma-separated if more than one.Integer containing bit flags representing file" ascii
      $s2 = "roductCode{82F43C44-8548-4543-BADD-5A21DFF718DA}ProductLanguage1033ProductNameProductVersion1.2.4.9UpgradeCodel not be installed" ascii
      $s3 = "RGKeY^{.E" fullword ascii
      $s4 = "sPY\"i." fullword ascii
      $s5 = "J+ 3wL" fullword ascii
      $s6 = "EfC%t%" fullword ascii
      $s7 = " -%{^te(o;" fullword ascii
      $s8 = "7kP- qH" fullword ascii
      $s9 = " 1,* `" fullword ascii
      $s10 = "# 2U7yHd" fullword ascii
      $s11 = "xTZgiN5" fullword ascii
      $s12 = "fhqguf" fullword ascii
      $s13 = "Ao -.-" fullword ascii
      $s14 = "6%Nfc%" fullword ascii
      $s15 = "K+ IsH4" fullword ascii
      $s16 = "[I7-N -<rn" fullword ascii
      $s17 = "WaxbcB%" fullword ascii
      $s18 = "dotQ@00hx" fullword ascii
      $s19 = "sS.bne" fullword ascii
      $s20 = "Knwyd~>#|)j" fullword ascii
   condition:
      ( uint16(0) == 0xcfd0 and filesize < 25000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _27a7ba032f7d6cf787454c2fd036c95d13be9fb489b26fd9050659aa23498dd6_cbdfe04b8f754e5e6150936ee604f0a478b79c6d0466ee155775ead575_3 {
   meta:
      description = "evidences - from files 27a7ba032f7d6cf787454c2fd036c95d13be9fb489b26fd9050659aa23498dd6.exe, cbdfe04b8f754e5e6150936ee604f0a478b79c6d0466ee155775ead575adea90.exe"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-07"
      hash1 = "27a7ba032f7d6cf787454c2fd036c95d13be9fb489b26fd9050659aa23498dd6"
      hash2 = "cbdfe04b8f754e5e6150936ee604f0a478b79c6d0466ee155775ead575adea90"
   strings:
      $s1 = ".NET Framework 4.6" fullword ascii
      $s2 = "Updater" fullword ascii /* Goodware String - occured 17 times */
      $s3 = "Encoding" fullword ascii /* Goodware String - occured 809 times */
      $s4 = "Updater.dll" fullword ascii /* Goodware String - occured 1 times */
      $s5 = "System" fullword ascii /* Goodware String - occured 2567 times */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 300KB and ( all of them )
      ) or ( all of them )
}
