rule PUP_InstallRex_AntiFWb : hardened
{
	meta:
		description = "Malware InstallRex / AntiFW"
		author = "Florian Roth"
		date = "2015-05-13"
		hash = "bb5607cd2ee51f039f60e32cf7edc4e21a2d95cd"
		score = 65

	strings:
		$s4 = {45 72 72 6f 72 20 25 75 20 77 68 69 6c 65 20 6c 6f 61 64 69 6e 67 20 54 53 55 2e 44 4c 4c 20 25 6c 73}
		$s7 = {47 65 74 4d 6f 64 75 6c 65 46 69 6c 65 4e 61 6d 65 28 29 20 66 61 69 6c 65 64 20 3d 3e 20 25 75}
		$s8 = {54 00 53 00 55 00 4c 00 6f 00 61 00 64 00 65 00 72 00 2e 00 65 00 78 00 65 00}
		$s15 = {5c 00 53 00 74 00 72 00 69 00 6e 00 67 00 46 00 69 00 6c 00 65 00 49 00 6e 00 66 00 6f 00 5c 00 25 00 30 00 34 00 78 00 25 00 30 00 34 00 78 00 5c 00 41 00 72 00 67 00 75 00 6d 00 65 00 6e 00 74 00 73 00}
		$s17 = {54 00 73 00 75 00 25 00 30 00 38 00 6c 00 58 00 2e 00 64 00 6c 00 6c 00}

	condition:
		uint16( 0 ) == 0x5a4d and all of them
}

rule LightFTP_fftp_x86_64 : hardened
{
	meta:
		description = "Detects a light FTP server"
		author = "Florian Roth"
		reference = "https://github.com/hfiref0x/LightFTP"
		date = "2015-05-14"
		hash1 = "989525f85abef05581ccab673e81df3f5d50be36"
		hash2 = "5884aeca33429830b39eba6d3ddb00680037faf4"
		score = 50

	strings:
		$s1 = {66 00 66 00 74 00 70 00 2e 00 63 00 66 00 67 00}
		$s2 = {32 32 30 20 4c 69 67 68 74 46 54 50 20 73 65 72 76 65 72 20 76 31 2e 30 20 72 65 61 64 79}
		$s3 = {2a 00 46 00 54 00 50 00 20 00 74 00 68 00 72 00 65 00 61 00 64 00 20 00 65 00 78 00 69 00 74 00 2a 00}
		$s4 = {50 41 53 53 2d 3e 6c 6f 67 6f 6e 20 73 75 63 63 65 73 73 66 75 6c}
		$s5 = {32 35 30 20 52 65 71 75 65 73 74 65 64 20 66 69 6c 65 20 61 63 74 69 6f 6e 20 6f 6b 61 79 2c 20 63 6f 6d 70 6c 65 74 65 64 2e}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 250KB and 4 of them
}

rule LightFTP_Config : hardened
{
	meta:
		description = "Detects a light FTP server - config file"
		author = "Florian Roth"
		reference = "https://github.com/hfiref0x/LightFTP"
		date = "2015-05-14"
		hash = "ce9821213538d39775af4a48550eefa3908323c5"

	strings:
		$s2 = {6d 00 61 00 78 00 75 00 73 00 65 00 72 00 73 00 3d 00}
		$s6 = {5b 00 66 00 74 00 70 00 63 00 6f 00 6e 00 66 00 69 00 67 00 5d 00}
		$s8 = {61 00 63 00 63 00 73 00 3d 00 72 00 65 00 61 00 64 00 6f 00 6e 00 6c 00 79 00}
		$s9 = {5b 00 61 00 6e 00 6f 00 6e 00 79 00 6d 00 6f 00 75 00 73 00 5d 00}
		$s10 = {61 00 63 00 63 00 73 00 3d 00}
		$s11 = {70 00 73 00 77 00 64 00 3d 00}

	condition:
		uint16( 0 ) == 0xfeff and filesize < 1KB and all of them
}

rule CrowdStrike_CSA_240838_01 : daolpu stealer hardened
{
	meta:
		copyright = "(c) 2024 CrowdStrike Inc."
		description = "C++ stealer delivered via Word documents with macros impersonating CS"
		reports = "CSA-240838"
		version = "202407221342"
		last_modified = "2024-07-22"
		malware_family = "Daolpu"
		score = 75
		reference = "https://www.crowdstrike.com/blog/fake-recovery-manual-used-to-deliver-unidentified-stealer/"

	strings:
		$ = {43 3a 5c 57 69 6e 64 6f 77 73 5c 54 65 6d 70 5c 72 65 73 75 6c 74 2e 74 78 74}
		$ = {44 3a 5c 63 2b 2b 5c 4d 61 6c 5f 43 6f 6f 6b 69 65 5f 78 36 34 5c 78 36 34 5c 52 65 6c 65 61 73 65 5c 6d 73 63 6f 72 73 76 63 2e 70 64 62}

	condition:
		all of them
}

rule ZXProxy : hardened limited
{
	meta:
		author = "ThreatConnect Intelligence Research Team"

	strings:
		$C = {((5c 43 6f 6e 74 72 6f 6c 5c 7a 78 70 6c 75 67) | (5c 00 43 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 5c 00 7a 00 78 00 70 00 6c 00 75 00 67 00))}
		$h = {((68 74 74 70 3a 2f 2f 77 77 77 2e 66 61 63 65 62 6f 6f 6b 2e 63 6f 6d 2f 63 6f 6d 6d 65 6e 74 2f 75 70 64 61 74 65 2e 65 78 65) | (68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 77 00 77 00 77 00 2e 00 66 00 61 00 63 00 65 00 62 00 6f 00 6f 00 6b 00 2e 00 63 00 6f 00 6d 00 2f 00 63 00 6f 00 6d 00 6d 00 65 00 6e 00 74 00 2f 00 75 00 70 00 64 00 61 00 74 00 65 00 2e 00 65 00 78 00 65 00))}
		$S = {((53 68 61 72 65 64 20 61 20 73 68 65 6c 6c 20 74 6f 20 25 73 3a 25 73 20 53 75 63 63 65 73 73 66 75 6c 6c 79) | (53 00 68 00 61 00 72 00 65 00 64 00 20 00 61 00 20 00 73 00 68 00 65 00 6c 00 6c 00 20 00 74 00 6f 00 20 00 25 00 73 00 3a 00 25 00 73 00 20 00 53 00 75 00 63 00 63 00 65 00 73 00 73 00 66 00 75 00 6c 00 6c 00 79 00))}

	condition:
		any of them
}

rule OrcaRAT : hardened
{
	meta:
		Author = "PwC Cyber Threat Operations"
		Date = "2014/10/20"
		Description = "Strings inside"
		Reference = "http://pwc.blogs.com/cyber_security_updates/2014/10/orcarat-a-whale-of-a-tale.html"

	strings:
		$MZ = {4d 5a}
		$apptype1 = {61 70 70 6c 69 63 61 74 69 6f 6e 2f 78 2d 6d 73 2d 61 70 70 6c 69 63 61 74 69 6f 6e}
		$apptype2 = {61 70 70 6c 69 63 61 74 69 6f 6e 2f 78 2d 6d 73 2d 78 62 61 70}
		$apptype3 = {61 70 70 6c 69 63 61 74 69 6f 6e 2f 76 6e 64 2e 6d 73 2d 78 70 73 64 6f 63 75 6d 65 6e 74}
		$apptype4 = {61 70 70 6c 69 63 61 74 69 6f 6e 2f 78 61 6d 6c 2b 78 6d 6c}
		$apptype5 = {61 70 70 6c 69 63 61 74 69 6f 6e 2f 78 2d 73 68 6f 63 6b 77 61 76 65 2d 66 6c 61 73 68}
		$apptype6 = {69 6d 61 67 65 2f 70 6a 70 65 67}
		$err1 = {53 65 74 20 72 65 74 75 72 6e 20 74 69 6d 65 20 65 72 72 6f 72 20 3d 20 20 20 25 64 21}
		$err2 = {53 65 74 20 72 65 74 75 72 6e 20 74 69 6d 65 20 20 20 73 75 63 63 65 73 73 21}
		$err3 = {51 75 69 74 20 73 75 63 63 65 73 73 21}

	condition:
		$MZ at 0 and filesize < 500KB and ( all of ( $apptype* ) and 1 of ( $err* ) )
}

rule SpyGate_v2_9 : hardened
{
	meta:
		date = "2014/09"
		maltype = "Spygate v2.9 Remote Access Trojan"
		filetype = "exe"
		reference = "https://blogs.mcafee.com/mcafee-labs/middle-east-developer-spygate-struts-stuff-online"

	strings:
		$1 = {73 00 68 00 75 00 74 00 64 00 6f 00 77 00 6e 00 63 00 6f 00 6d 00 70 00 75 00 74 00 65 00 72 00}
		$2 = {73 00 68 00 75 00 74 00 64 00 6f 00 77 00 6e 00 20 00 2d 00 72 00 20 00 2d 00 74 00 20 00 30 00 30 00}
		$3 = {62 00 6c 00 6f 00 63 00 6b 00 6d 00 6f 00 75 00 73 00 65 00 61 00 6e 00 64 00 6b 00 65 00 79 00 62 00 6f 00 61 00 72 00 64 00}
		$4 = {50 72 6f 63 65 73 73 48 61 63 6b 65 72}
		$5 = {46 00 69 00 6c 00 65 00 4d 00 61 00 6e 00 61 00 67 00 65 00 72 00 53 00 70 00 6c 00 69 00 74 00}

	condition:
		all of them
}

rule ice_ix_12xy : banker hardened
{
	meta:
		author = "Jean-Philippe Teissier / @Jipe_"
		description = "ICE-IX 1.2.x.y trojan banker"
		date = "2013-01-12"
		filetype = "memory"
		version = "1.0"

	strings:
		$regexp1 = /bn1=.{32}&sk1=[0-9a-zA-Z]{32}/
		$a = {62 6e 31 3d}
		$b = {26 73 6b 31 3d}
		$c = {6d 61 72 69 6f}
		$d = {46 49 58 4d 45}
		$e = {52 46 42 20 30 30 33 2e 30 30 33}
		$ggurl = {68 74 74 70 3a 2f 2f 77 77 77 2e 67 6f 6f 67 6c 65 2e 63 6f 6d 2f 77 65 62 68 70}

	condition:
		$regexp1 or ( $a and $b ) or all of ( $c , $d , $e , $ggurl )
}

rule qadars : banker hardened
{
	meta:
		author = "Jean-Philippe Teissier / @Jipe_"
		description = "Qadars - Mobile part. Maybe Perkele."
		version = "1.0"
		filetype = "memory"
		ref1 = "http://www.lexsi-leblog.fr/cert/qadars-nouveau-malware-bancaire-composant-mobile.html"

	strings:
		$cmd1 = {6d 3f 44}
		$cmd2 = {6d 3f 53}
		$cmd3 = {41 4c 4c}
		$cmd4 = {46 49 4c 54 45 52}
		$cmd5 = {4e 4f 4e 45}
		$cmd6 = {4b 49 4c 4c}
		$cmd7 = {43 41 4e 43 45 4c}
		$cmd8 = {53 4d 53}
		$cmd9 = {44 49 56 45 52 54}
		$cmd10 = {4d 45 53 53}
		$nofilter = {6e 6f 66 69 6c 74 65 72 31 31 31 31 31 31 31}
		$botherderphonenumber1 = {2b 33 38 30 36 37 38 34 30 39 32 31 30}

	condition:
		all of ( $cmd* ) or $nofilter or any of ( $botherderphonenumber* )
}

rule shylock : banker hardened
{
	meta:
		author = "Jean-Philippe Teissier / @Jipe_"
		description = "Shylock Banker"
		date = "2013-12-12"
		version = "1.0"
		ref1 = "http://iocbucket.com/iocs/1b4660d57928df5ca843c21df0b2adb117026cba"
		ref2 = "http://www.trusteer.com/blog/merchant-fraud-returns-%E2%80%93-shylock-polymorphic-financial-malware-infections-rise"
		ref3 = "https://www.csis.dk/en/csis/blog/3811/"

	strings:
		$process1 = {4d 41 53 54 45 52}
		$process2 = {5f 53 48 55 54 44 4f 57 4e}
		$process3 = {45 56 54 5f 56 4e 43}
		$process4 = {45 56 54 5f 42 41 43 4b}
		$process5 = {45 56 54 5f 56 4e 43}
		$process6 = {49 45 5f 48 6f 6f 6b 3a 3a 47 65 74 52 65 71 75 65 73 74 49 6e 66 6f}
		$process7 = {46 46 5f 48 6f 6f 6b 3a 3a 67 65 74 52 65 71 75 65 73 74 49 6e 66 6f}
		$process8 = {45 58 5f 48 6f 6f 6b 3a 3a 43 72 65 61 74 65 50 72 6f 63 65 73 73}
		$process9 = {68 69 6a 61 63 6b 64 6c 6c 2e 64 6c 6c}
		$process10 = {4d 54 58 5f}
		$process11 = {46 46 3a 3a 50 52 5f 57 72 69 74 65 48 6f 6f 6b 20 65 6e 74 72 79}
		$process12 = {46 46 3a 3a 50 52 5f 57 72 69 74 65 48 6f 6f 6b 20 65 78 69 74}
		$process13 = {48 69 6a 61 63 6b 50 72 6f 63 65 73 73 41 74 74 61 63 68 3a 3a 2a 2a 2a 20 4d 41 53 54 45 52 20 2a 2a 2a 20 4d 41 53 54 45 52 20 2a 2a 2a 20 4d 41 53 54 45 52 20 2a 2a 2a 20 25 73 20 50 49 44 3d 25 75}
		$process14 = {48 69 6a 61 63 6b 50 72 6f 63 65 73 73 41 74 74 61 63 68 3a 3a 65 6e 74 72 79}
		$process15 = {46 46 3a 3a 42 45 46 4f 52 45 20 49 4e 4a 45 43 54}
		$process16 = {46 46 3a 3a 41 46 54 45 52 20 49 4e 4a 45 43 54}
		$process17 = {49 45 3a 3a 41 46 54 45 52 20 49 4e 4a 45 43 54}
		$process18 = {49 45 3a 3a 42 45 46 4f 52 45 20 49 4e 4a 45 43 54}
		$process19 = {2a 2a 2a 20 56 4e 43 20 2a 2a 2a 20 56 4e 43 20 2a 2a 2a 20 56 4e 43 20 2a 2a 2a 20 56 4e 43 20 2a 2a 2a 20 56 4e 43 20 2a 2a 2a 20 56 4e 43 20 2a 2a 2a 20 56 4e 43 20 2a 2a 2a 20 56 4e 43 20 2a 2a 2a 20 56 4e 43 20 2a 2a 2a 20 56 4e 43 20 2a 2a 2a 20 25 73}
		$process20 = {2a 2a 2a 20 4c 4f 47 20 49 4e 4a 45 43 54 53 20 2a 2a 2a 20 25 73}
		$process21 = {2a 2a 2a 20 69 6e 6a 65 63 74 20 74 6f 20 70 72 6f 63 65 73 73 20 25 73 20 6e 6f 74 20 61 6c 6c 6f 77 65 64}
		$process22 = {2a 2a 2a 20 42 61 63 6b 53 6f 63 6b 73 20 2a 2a 2a 20 42 61 63 6b 53 6f 63 6b 73 20 2a 2a 2a 20 42 61 63 6b 53 6f 63 6b 73 20 2a 2a 2a 20 42 61 63 6b 53 6f 63 6b 73 20 2a 2a 2a 20 42 61 63 6b 53 6f 63 6b 73 20 2a 2a 2a 20 42 61 63 6b 53 6f 63 6b 73 20 2a 2a 2a 20 42 61 63 6b 53 6f 63 6b 73 20 2a 2a 2a 20 25 73}
		$process23 = {2e 3f 41 56 46 46 5f 48 6f 6f 6b 40 40}
		$process24 = {2e 3f 41 56 49 45 5f 48 6f 6f 6b 40 40}
		$process25 = {49 6e 6a 65 63 74 3a 3a 49 6e 6a 65 63 74 44 6c 6c 46 72 6f 6d 4d 65 6d 6f 72 79}
		$process26 = {42 61 64 53 6f 63 6b 73 2e 64 6c 6c}
		$domain1 = {65 78 74 65 6e 73 61 64 76 2e 63 63}
		$domain2 = {74 6f 70 62 65 61 74 2e 63 63}
		$domain3 = {62 72 61 69 6e 73 70 68 65 72 65 2e 63 63}
		$domain4 = {63 6f 6d 6d 6f 6e 77 6f 72 6c 64 6d 65 2e 63 63}
		$domain5 = {67 69 67 61 63 61 74 2e 63 63}
		$domain6 = {6e 77 2d 73 65 72 76 2e 63 63}
		$domain7 = {70 61 72 61 67 75 61 2d 61 6e 61 6c 79 73 74 2e 63 63}

	condition:
		3 of ( $process* ) or any of ( $domain* )
}

rule memory_shylock : hardened
{
	meta:
		author = "https://github.com/jackcr/"

	strings:
		$a = /pipe\\[A-F0-9]{32}/
		$b = /id=[A-F0-9]{32}/
		$c = /MASTER_[A-F0-9]{32}/
		$d = {2a 2a 2a 4c 6f 61 64 20 69 6e 6a 65 63 74 73 20 62 79 20 50 49 50 45 20 28 25 73 29}
		$e = {2a 2a 2a 4c 6f 61 64 20 69 6e 6a 65 63 74 73 20 75 72 6c 3d 25 73 20 28 25 73 29}
		$f = {2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 20 50 69 6e 67 20 4f 6b 20 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a}
		$g = {2a 2a 2a 20 4c 4f 47 20 49 4e 4a 45 43 54 53 20 2a 2a 2a 20 25 73}

	condition:
		any of them
}

rule potential_banker : refined hardened
{
	meta:
		author = "Jean-Philippe Teissier / @Jipe_"
		description = "SpyEye X.Y memory"
		date = "2012-05-23"
		version = "1.0"
		filetype = "memory"

	strings:
		$spyeye = {53 70 79 45 79 65}
		$a = {25 42 4f 54 4e 41 4d 45 25}
		$b = {67 6c 6f 62 70 6c 75 67 69 6e 73}
		$c = {64 61 74 61 5f 69 6e 6a 65 63 74}
		$d = {64 61 74 61 5f 62 65 66 6f 72 65}
		$e = {64 61 74 61 5f 61 66 74 65 72}
		$f = {64 61 74 61 5f 65 6e 64}
		$g = {62 6f 74 5f 76 65 72 73 69 6f 6e}
		$h = {62 6f 74 5f 67 75 69 64}
		$i = {54 61 6b 65 42 6f 74 47 75 69 64}
		$j = {54 61 6b 65 47 61 74 65 54 6f 43 6f 6c 6c 65 63 74 6f 72}
		$k = {5b 45 52 52 4f 52 5d 20 3a 20 4f 6d 66 67 21 20 50 72 6f 63 65 73 73 20 69 73 20 73 74 69 6c 6c 20 61 63 74 69 76 65 3f 20 4c 65 74 73 20 6b 69 6c 6c 20 74 68 61 74 20 6d 61 7a 61 66 61 6b 61 21}
		$l = {5b 45 52 52 4f 52 5d 20 3a 20 55 70 64 61 74 65 20 69 73 20 6e 6f 74 20 73 75 63 63 65 73 73 66 75 6c 6c 20 66 6f 72 20 73 6f 6d 65 20 72 65 61 73 6f 6e}
		$m = {5b 45 52 52 4f 52 5d 20 3a 20 64 77 45 72 72 20 3d 3d 20 25 75}
		$n = {47 52 41 42 42 45 44 20 44 41 54 41}

	condition:
		$spyeye or ( 2 of ( $a , $b , $c , $d , $e , $f , $g , $h , $i , $j , $k , $l , $m , $n ) )
}

rule spyeye_plugins : banker refined hardened
{
	meta:
		author = "Jean-Philippe Teissier / @Jipe_"
		description = "SpyEye X.Y Plugins memory"
		date = "2012-05-23"
		version = "1.0"
		filetype = "memory"

	strings:
		$a = {77 65 62 66 61 6b 65 73 2e 64 6c 6c}
		$c = {63 6f 6c 6c 65 63 74 6f 72 73 2e 74 78 74}
		$d = {77 65 62 69 6e 6a 65 63 74 73 2e 74 78 74}
		$e = {73 63 72 65 65 6e 73 68 6f 74 73 2e 74 78 74}
		$f = {62 69 6c 6c 69 6e 67 68 61 6d 6d 65 72 2e 64 6c 6c}
		$g = {62 6c 6f 63 6b 2e 64 6c 6c}
		$h = {62 75 67 72 65 70 6f 72 74 2e 64 6c 6c}
		$i = {63 63 67 72 61 62 62 65 72 2e 64 6c 6c}
		$j = {63 6f 6e 6e 65 63 74 6f 72 32 2e 64 6c 6c}
		$k = {63 72 65 64 69 74 67 72 61 62 2e 64 6c 6c}
		$l = {63 75 73 74 6f 6d 63 6f 6e 6e 65 63 74 6f 72 2e 64 6c 6c}
		$m = {66 66 63 65 72 74 67 72 61 62 62 65 72 2e 64 6c 6c}
		$n = {66 74 70 62 63 2e 64 6c 6c}
		$o = {72 64 70 2e 64 6c 6c}
		$p = {72 74 5f 32 5f 34 2e 64 6c 6c}
		$r = {73 70 79 53 70 72 65 61 64 2e 64 6c 6c}
		$s = {77 32 63 68 65 6b 34 5f 34 2e 64 6c 6c}
		$t = {77 32 63 68 65 6b 34 5f 36 2e 64 6c 6c}

	condition:
		any of them
}

rule Invoke_mimikittenz : hardened
{
	meta:
		description = "Detects Mimikittenz - file Invoke-mimikittenz.ps1"
		author = "Florian Roth"
		reference = "https://github.com/putterpanda/mimikittenz"
		date = "2016-07-19"
		score = 90
		hash1 = "14e2f70470396a18c27debb419a4f4063c2ad5b6976f429d47f55e31066a5e6a"

	strings:
		$x1 = {5b 6d 69 6d 69 6b 69 74 74 65 6e 7a 2e 4d 65 6d 50 72 6f 63 49 6e 73 70 65 63 74 6f 72 5d}
		$s1 = {50 52 4f 43 45 53 53 5f 41 4c 4c 5f 41 43 43 45 53 53 20 3d 20 50 52 4f 43 45 53 53 5f 54 45 52 4d 49 4e 41 54 45 20 7c 20 50 52 4f 43 45 53 53 5f 43 52 45 41 54 45 5f 54 48 52 45 41 44 20 7c 20 50 52 4f 43 45 53 53 5f 53 45 54 5f 53 45 53 53 49 4f 4e 49 44 20 7c 20 50 52 4f 43 45 53 53 5f 56 4d 5f 4f 50 45 52 41 54 49 4f 4e 20 7c}
		$s2 = {49 6e 74 50 74 72 20 70 72 6f 63 65 73 73 48 61 6e 64 6c 65 20 3d 20 4d 49 6e 74 65 72 6f 70 2e 4f 70 65 6e 50 72 6f 63 65 73 73 28 4d 49 6e 74 65 72 6f 70 2e 50 52 4f 43 45 53 53 5f 57 4d 5f 52 45 41 44 20 7c 20 4d 49 6e 74 65 72 6f 70 2e 50 52 4f 43 45 53 53 5f 51 55 45 52 59 5f 49 4e 46 4f 52 4d 41 54 49 4f 4e 2c 20 66 61 6c 73 65 2c 20 70 72 6f 63 65 73 73 2e 49 64 29 3b}
		$s3 = {26 65 6d 61 69 6c 3d 2e 7b 31 2c 34 38 7d 26 63 72 65 61 74 65 3d 2e 7b 31 2c 32 7d 26 70 61 73 73 77 6f 72 64 3d 2e 7b 31 2c 32 32 7d 26 6d 65 74 61 64 61 74 61 31 3d}
		$s4 = {5b 44 6c 6c 49 6d 70 6f 72 74 28 22 6b 65 72 6e 65 6c 33 32 2e 64 6c 6c 22 2c 20 53 65 74 4c 61 73 74 45 72 72 6f 72 20 3d 20 74 72 75 65 29 5d}

	condition:
		( uint16( 0 ) == 0x7566 and filesize < 60KB and 2 of them ) or $x1
}

