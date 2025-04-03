rule TSCookie : hardened
{
	meta:
		description = "detect TSCookie in memory"
		author = "JPCERT/CC Incident Response Group"
		rule_usage = "memory scan"
		reference = "https://blogs.jpcert.or.jp/en/2018/03/malware-tscooki-7aa0.html"
		hash1 = "6d2f5675630d0dae65a796ac624fb90f42f35fbe5dec2ec8f4adce5ebfaabf75"

	strings:
		$v1 = {4d 00 6f 00 7a 00 69 00 6c 00 6c 00 61 00 2f 00 34 00 2e 00 30 00 20 00 28 00 63 00 6f 00 6d 00 70 00 61 00 74 00 69 00 62 00 6c 00 65 00 3b 00 20 00 4d 00 53 00 49 00 45 00 20 00 38 00 2e 00 30 00 3b 00 20 00 57 00 69 00 6e 00 33 00 32 00 29 00}
		$b1 = { 68 D4 08 00 00 }

	condition:
		all of them
}

rule TSC_Loader : hardened
{
	meta:
		description = "detect TSCookie Loader in memory"
		author = "JPCERT/CC Incident Response Group"
		rule_usage = "memory scan"
		reference = "internal research"

	strings:
		$v1 = {4d 00 6f 00 7a 00 69 00 6c 00 6c 00 61 00 2f 00 34 00 2e 00 30 00 20 00 28 00 63 00 6f 00 6d 00 70 00 61 00 74 00 69 00 62 00 6c 00 65 00 3b 00 20 00 4d 00 53 00 49 00 45 00 20 00 38 00 2e 00 30 00 3b 00 20 00 57 00 69 00 6e 00 33 00 32 00 29 00}
		$b1 = { 68 78 0B 00 00 }

	condition:
		all of them
}

rule CobaltStrike : hardened
{
	meta:
		description = "detect CobaltStrike Beacon in memory"
		author = "JPCERT/CC Incident Response Group"
		rule_usage = "memory scan"
		reference = "https://blogs.jpcert.or.jp/en/2018/08/volatility-plugin-for-detecting-cobalt-strike-beacon.html"
		hash1 = "154db8746a9d0244146648006cc94f120390587e02677b97f044c25870d512c3"
		hash2 = "f9b93c92ed50743cd004532ab379e3135197b6fb5341322975f4d7a98a0fcde7"

	strings:
		$v1 = { 73 70 72 6E 67 00 }
		$v2 = { 69 69 69 69 69 69 69 69 }

	condition:
		all of them
}

rule RedLeaves : hardened
{
	meta:
		description = "detect RedLeaves in memory"
		author = "JPCERT/CC Incident Response Group"
		rule_usage = "memory block scan"
		reference = "https://blogs.jpcert.or.jp/en/2017/05/volatility-plugin-for-detecting-redleaves-malware.html"
		hash1 = "5262cb9791df50fafcb2fbd5f93226050b51efe400c2924eecba97b7ce437481"

	strings:
		$v1 = {72 65 64 5f 61 75 74 75 6d 6e 61 6c 5f 6c 65 61 76 65 73 5f 64 6c 6c 6d 61 69 6e 2e 64 6c 6c}
		$b1 = { FF FF 90 00 }

	condition:
		$v1 and $b1 at 0
}

rule Himawari : hardened
{
	meta:
		description = "detect Himawari(a variant of RedLeaves) in memory"
		author = "JPCERT/CC Incident Response Group"
		rule_usage = "memory scan"
		reference = "https://www.jpcert.or.jp/present/2018/JSAC2018_01_nakatsuru.pdf"
		hash1 = "3938436ab73dcd10c495354546265d5498013a6d17d9c4f842507be26ea8fafb"

	strings:
		$h1 = {68 69 6d 61 77 61 72 69 41}
		$h2 = {68 69 6d 61 77 61 72 69 42}
		$h3 = {48 69 6d 61 77 61 72 69 44 65 6d 6f}

	condition:
		all of them
}

rule Lavender : hardened
{
	meta:
		description = "detect Lavender(a variant of RedLeaves) in memory"
		author = "JPCERT/CC Incident Response Group"
		rule_usage = "memory scan"
		reference = "internal research"
		hash1 = "db7c1534dede15be08e651784d3a5d2ae41963d192b0f8776701b4b72240c38d"

	strings:
		$a1 = { C7 ?? ?? 4C 41 56 45 }
		$a2 = { C7 ?? ?? 4E 44 45 52 }

	condition:
		all of them
}

rule Armadill : hardened
{
	meta:
		description = "detect Armadill(a variant of RedLeaves) in memory"
		author = "JPCERT/CC Incident Response Group"
		rule_usage = "memory scan"
		reference = "internal research"

	strings:
		$a1 = { C7 ?? ?? 41 72 6D 61 }
		$a2 = { C7 ?? ?? 64 69 6C 6C }

	condition:
		all of them
}

rule zark20rk : hardened
{
	meta:
		description = "detect zark20rk(a variant of RedLeaves) in memory"
		author = "JPCERT/CC Incident Response Group"
		rule_usage = "memory scan"
		reference = "internal research"
		hash1 = "d95ad7bbc15fdd112594584d92f0bff2c348f48c748c07930a2c4cc6502cd4b0"

	strings:
		$a1 = { C7 ?? ?? 7A 61 72 6B }
		$a2 = { C7 ?? ?? 32 30 72 6B }

	condition:
		all of them
}

rule Ursnif : hardened limited
{
	meta:
		description = "detect Ursnif(a.k.a. Dreambot, Gozi, ISFB) in memory"
		author = "JPCERT/CC Incident Response Group"
		rule_usage = "memory scan"
		reference = "internal research"
		hash1 = "0207c06879fb4a2ddaffecc3a6713f2605cbdd90fc238da9845e88ff6aef3f85"
		hash2 = "ff2aa9bd3b9b3525bae0832d1e2b7c6dfb988dc7add310088609872ad9a7e714"
		hash3 = "1eca399763808be89d2e58e1b5e242324d60e16c0f3b5012b0070499ab482510"
		score = 50

	strings:
		$a1 = {73 6f 66 74 3d 25 75 26 76 65 72 73 69 6f 6e 3d 25 75 26 75 73 65 72 3d 25 30 38 78 25 30 38 78 25 30 38 78 25 30 38 78 26 73 65 72 76 65 72 3d 25 75 26 69 64 3d 25 75 26 63 72 63 3d 25 78}
		$b1 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 63 6c 69 65 6e 74 2e 64 6c 6c (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$c1 = {76 65 72 73 69 6f 6e 3d 25 75}
		$c2 = {75 73 65 72 3d 25 30 38 78 25 30 38 78 25 30 38 78 25 30 38 78}
		$c3 = {73 65 72 76 65 72 3d 25 75}
		$c4 = {69 64 3d 25 75}
		$c5 = {63 72 63 3d 25 75}
		$c6 = {67 75 69 64 3d 25 30 38 78 25 30 38 78 25 30 38 78 25 30 38 78}
		$c7 = {6e 61 6d 65 3d 25 73}
		$c8 = {73 6f 66 74 3d 25 75}
		$d1 = {25 73 3a 2f 2f 25 73 25 73}
		$d2 = {50 52 49 20 2a 20 48 54 54 50 2f 32 2e 30}
		$e1 = { A1 ?? ?? ?? 00 35 E7 F7 8A 40 50 }
		$e2 = { 56 56 56 6A 06 5? FF ?? ?? ?? ?? 00 }
		$f1 = { 56 57 BE ?? ?? ?? ?? 8D ?? ?? A5 A5 A5 }
		$f2 = { 35 8F E3 B7 3F }
		$f3 = { 35 0A 60 2E 51 }

	condition:
		$a1 or ( $b1 and 3 of ( $c* ) ) or ( 5 of ( $c* ) ) or ( $b1 and all of ( $d* ) ) or all of ( $e* ) or all of ( $f* )
}

rule Datper : hardened
{
	meta:
		description = "detect Datper in memory"
		author = "JPCERT/CC Incident Response Group"
		rule_usage = "memory scan"
		reference = "https://blogs.jpcert.or.jp/en/2017/08/detecting-datper-malware-from-proxy-logs.html"

	strings:
		$a1 = { E8 03 00 00 }
		$b1 = {7c 7c 7c}
		$c1 = {43 6f 6e 74 65 6e 74 2d 54 79 70 65 3a 20 61 70 70 6c 69 63 61 74 69 6f 6e 2f 78 2d 77 77 77 2d 66 6f 72 6d 2d 75 72 6c 65 6e 63 6f 64 65 64}
		$push7530h64 = { C7 C1 30 75 00 00 }
		$push7530h = { 68 30 75 00 00 }

	condition:
		$a1 and $b1 and $c1 and ( $push7530h64 or $push7530h )
}

rule PlugX : hardened
{
	meta:
		description = "detect PlugX in memory"
		author = "JPCERT/CC Incident Response Group"
		rule_usage = "memory scan"
		reference = "internal research"

	strings:
		$v1 = { 47 55 4c 50 00 00 00 00 }
		$v2a = { 68 40 25 00 00 }
		$v2c = { 68 58 2D 00 00 }
		$v2b = { 68 a0 02 00 00 }
		$v2d = { 68 a4 36 00 00 }
		$v2e = { 8D 46 10 68 }
		$v2f = { 68 24 0D 00 00 }
		$v2g = { 68 a0 02 00 00 }
		$v2h = { 68 e4 0a 00 00 }
		$enc1 = { C1 E? 03 C1 E? 07 2B ?? }
		$enc2 = { 32 5? ?? 81 E? ?? ?? 00 00 2A 5? ?? 89 ?? ?? 32 ?? 2A ?? 32 5? ?? 2A 5? ?? 32 }
		$enc3 = { B? 33 33 33 33 }
		$enc4 = { B? 44 44 44 44 }

	condition:
		$v1 at 0 or ( $v2a and $v2b and $enc1 ) or ( $v2c and $v2b and $enc1 ) or ( $v2d and $v2b and $enc2 ) or ( $v2d and $v2e and $enc2 ) or ( $v2f and $v2g and $enc3 and $enc4 ) or ( $v2h and $v2g and $enc3 and $enc4 )
}

rule Ramnit : hardened
{
	meta:
		description = "detect Ramnit"
		author = "nazywam"
		module = "ramnit"
		reference = "https://www.cert.pl/en/news/single/ramnit-in-depth-analysis/"

	strings:
		$guid = {7b 25 30 38 58 2d 25 30 34 58 2d 25 30 34 58 2d 25 30 34 58 2d 25 30 38 58 25 30 34 58 7d}
		$md5_magic_1 = {31 35 42 6e 39 39 67 54}
		$md5_magic_2 = {31 45 34 68 4e 79 31 4f}
		$init_dga = { C7 ?? ?? ?? ?? ?? FF FF FF FF FF ?? ?? ?? ?? ?? FF ?? ?? ?? ?? ?? FF ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 0B C0 75 ?? }
		$xor_secret = { 8A ?? ?? 32 ?? 88 ?? 4? 4? E2 ?? }
		$init_function = { FF 35 [4] 68 [4] 68 [2] 00 00 68 [4] E8 [4] FF 35 [4] 68 [4] 68 [2] 00 00 68 [4] E8 [4] FF 35 [4] 68 [4] 68 [2] 00 00 68 [4] E8 [4] FF 35 [4] 68 [4] 68 [2] 00 00 68 [4] E8 }
		$dga_rand_int = { B9 1D F3 01 00 F7 F1 8B C8 B8 A7 41 00 00 }
		$cookies = {63 6f 6f 6b 69 65 73 34 2e 64 61 74}
		$s3 = {70 64 61 74 65 73 44 69 73 61 62 6c 65 4e 6f 74 69 66 79}
		$get_domains = { a3 [4] a1 [4] 80 3? 00 75 ?? c7 05 [4] ff ff ff ff ff 35 [4] ff 35 [4] ff 35 [4] e8 }
		$add_tld = { 55 8B EC  83 ?? ?? 57 C7 ?? ?? 00 00 00 00 B? ?? ?? ?? ?? 8B ?? ?? 3B ?? ?? 75 ?? 8B ?? }
		$get_port = { 90 68 [4] 68 [4] FF 35 [4] FF 35 [4] E8 [4] 83 }

	condition:
		$init_dga and $init_function and 2 of ( $guid , $md5_magic_* , $cookies , $s3 ) and any of ( $get_port , $add_tld , $dga_rand_int , $get_domains , $xor_secret )
}

rule Hawkeye : hardened
{
	meta:
		description = "detect HawkEye in memory"
		author = "JPCERT/CC Incident Response Group"
		rule_usage = "memory scan"
		reference = "internal research"
		score = 70

	strings:
		$hawkstr1 = {48 00 61 00 77 00 6b 00 45 00 79 00 65 00 20 00 4b 00 65 00 79 00 6c 00 6f 00 67 00 67 00 65 00 72 00}
		$hawkstr2 = {44 00 65 00 61 00 72 00 20 00 48 00 61 00 77 00 6b 00 45 00 79 00 65 00 20 00 43 00 75 00 73 00 74 00 6f 00 6d 00 65 00 72 00 73 00 21 00}
		$hawkstr3 = {48 00 61 00 77 00 6b 00 45 00 79 00 65 00 20 00 4c 00 6f 00 67 00 67 00 65 00 72 00 20 00 44 00 65 00 74 00 61 00 69 00 6c 00 73 00 3a 00}

	condition:
		all of them
}

rule Bebloh : hardened
{
	meta:
		description = "detect Bebloh(a.k.a. URLZone) in memory"
		author = "JPCERT/CC Incident Response Group"
		rule_usage = "memory scan"
		reference = "internal research"

	strings:
		$crc32f = { b8 EE 56 0b ca }
		$dga = {71 77 65 72 74 79 75 69 6f 70 61 73 64 66 67 68 6a 6b 6c 7a 78 63 76 62 6e 6d 31 32 33 39 34 35 36 37 38}
		$post1 = {26 76 63 6d 64 3d}
		$post2 = {3f 74 76 65 72 3d}

	condition:
		all of them
}

rule xxmm : hardened
{
	meta:
		description = "detect xxmm in memory"
		author = "JPCERT/CC Incident Response Group"
		rule_usage = "memory scan"
		reference = "internal research"

	strings:
		$v1 = {73 65 74 75 70 50 61 72 61 6d 65 74 65 72 3a}
		$v2 = {6c 6f 61 64 65 72 50 61 72 61 6d 65 74 65 72 3a}
		$v3 = {70 61 72 61 6d 65 74 65 72 3a}

	condition:
		all of them
}

rule Azorult : hardened
{
	meta:
		description = "detect Azorult in memory"
		author = "JPCERT/CC Incident Response Group"
		rule_usage = "memory scan"
		reference = "internal research"
		score = 60

	strings:
		$v1 = {4d 6f 7a 69 6c 6c 61 2f 34 2e 30 20 28 63 6f 6d 70 61 74 69 62 6c 65 3b 20 4d 53 49 45 20 36 2e 30 62 3b 20 57 69 6e 64 6f 77 73 20 4e 54 20 35 2e 31 29}
		$v2 = {68 74 74 70 3a 2f 2f 69 70 2d 61 70 69 2e 63 6f 6d 2f 6a 73 6f 6e}
		$v3 = { c6 07 1e c6 47 01 15 c6 47 02 34 }

	condition:
		all of them
}

rule PoisonIvy : hardened
{
	meta:
		description = "detect PoisonIvy in memory"
		author = "JPCERT/CC Incident Response Group"
		rule_usage = "memory scan"
		reference = "internal research"

	strings:
		$a1 = { 0E 89 02 44 }
		$b1 = { AD D1 34 41 }
		$c1 = { 66 35 20 83 66 81 F3 B8 ED }

	condition:
		all of them
}

rule netwire : hardened
{
	meta:
		description = "detect netwire in memory"
		author = "JPCERT/CC Incident Response Group"
		rule_usage = "memory scan"
		reference = "internal research"

	strings:
		$v1 = {48 6f 73 74 49 64 2d 25 52 61 6e 64 25}
		$v2 = {6d 6f 7a 73 71 6c 69 74 65 33}
		$v3 = {5b 53 63 72 6f 6c 6c 20 4c 6f 63 6b 5d}
		$v4 = {47 65 74 52 61 77 49 6e 70 75 74 44 61 74 61}
		$ping = {70 69 6e 67 20 31 39 32 2e 30 2e 32 2e 32}
		$log = {5b 4c 6f 67 20 53 74 61 72 74 65 64 5d 20 2d 20 5b 25 2e 32 64 2f 25 2e 32 64 2f 25 64 20 25 2e 32 64 3a 25 2e 32 64 3a 25 2e 32 64 5d}

	condition:
		($v1 ) or ( $v2 and $v3 and $v4 ) or ( $ping and $log )
}

rule Nanocore : hardened
{
	meta:
		description = "detect Nanocore in memory"
		author = "JPCERT/CC Incident Response Group"
		rule_usage = "memory scan"
		reference = "internal research"

	strings:
		$v1 = {4e 61 6e 6f 43 6f 72 65 20 43 6c 69 65 6e 74}
		$v2 = {50 6c 75 67 69 6e 43 6f 6d 6d 61 6e 64}
		$v3 = {43 6f 6d 6d 61 6e 64 54 79 70 65}

	condition:
		all of them
}

rule Noderat : hardened
{
	meta:
		description = "detect Noderat in memory"
		author = "JPCERT/CC Incident Response Group"
		rule_usage = "memory scan"
		reference = "https://blogs.jpcert.or.jp/ja/2019/02/tick-activity.html"

	strings:
		$config = {2f 63 6f 6e 66 69 67 2f 61 70 70 2e 6a 73 6f 6e}
		$key = {2f 63 6f 6e 66 69 67 2f 2e 72 65 67 65 64 69 74 4b 65 79 2e 72 63}
		$message = {75 6e 69 6e 73 74 61 6c 6c 20 65 72 72 6f 72 20 77 68 65 6e 20 72 65 61 64 46 69 6c 65 53 79 6e 63 3a 20}

	condition:
		all of them
}

rule Trickbot : hardened
{
	meta:
		description = "detect TrickBot in memory"
		author = "JPCERT/CC Incident Response Group"
		rule_usage = "memory scan"
		hash1 = "2153be5c6f73f4816d90809febf4122a7b065cbfddaa4e2bf5935277341af34c"

	strings:
		$tagm1 = {3c 00 6d 00 63 00 63 00 6f 00 6e 00 66 00 3e 00 3c 00 76 00 65 00 72 00 3e 00}
		$tagm2 = {3c 00 2f 00 61 00 75 00 74 00 6f 00 72 00 75 00 6e 00 3e 00 3c 00 2f 00 6d 00 63 00 63 00 6f 00 6e 00 66 00 3e 00}
		$tagc1 = {3c 00 6d 00 6f 00 64 00 75 00 6c 00 65 00 63 00 6f 00 6e 00 66 00 69 00 67 00 3e 00 3c 00 61 00 75 00 74 00 6f 00 73 00 74 00 61 00 72 00 74 00 3e 00}
		$tagc2 = {3c 00 2f 00 61 00 75 00 74 00 6f 00 63 00 6f 00 6e 00 66 00 3e 00 3c 00 2f 00 6d 00 6f 00 64 00 75 00 6c 00 65 00 63 00 6f 00 6e 00 66 00 69 00 67 00 3e 00}
		$tagi1 = {3c 00 69 00 67 00 72 00 6f 00 75 00 70 00 3e 00 3c 00 64 00 69 00 6e 00 6a 00 3e 00}
		$tagi2 = {3c 00 2f 00 64 00 69 00 6e 00 6a 00 3e 00 3c 00 2f 00 69 00 67 00 72 00 6f 00 75 00 70 00 3e 00}
		$tags1 = {3c 00 73 00 65 00 72 00 76 00 63 00 6f 00 6e 00 66 00 3e 00 3c 00 65 00 78 00 70 00 69 00 72 00 3e 00}
		$tags2 = {3c 00 2f 00 70 00 6c 00 75 00 67 00 69 00 6e 00 73 00 3e 00 3c 00 2f 00 73 00 65 00 72 00 76 00 63 00 6f 00 6e 00 66 00 3e 00}
		$tagl1 = {3c 00 73 00 6c 00 69 00 73 00 74 00 3e 00 3c 00 73 00 69 00 6e 00 6a 00 3e 00}
		$tagl2 = {3c 00 2f 00 73 00 69 00 6e 00 6a 00 3e 00 3c 00 2f 00 73 00 6c 00 69 00 73 00 74 00 3e 00}

	condition:
		all of ( $tagm* ) or all of ( $tagc* ) or all of ( $tagi* ) or all of ( $tags* ) or all of ( $tagl* )
}

rule Quasar : hardened
{
	meta:
		description = "detect Quasar RAT in memory"
		author = "JPCERT/CC Incident Response Group"
		rule_usage = "memory scan"
		score = 60
		hash1 = "390c1530ff62d8f4eddff0ac13bc264cbf4183e7e3d6accf8f721ffc5250e724"

	strings:
		$quasarstr1 = {43 00 6c 00 69 00 65 00 6e 00 74 00 2e 00 65 00 78 00 65 00}
		$quasarstr2 = {28 00 7b 00 30 00 7d 00 3a 00 7b 00 31 00 7d 00 3a 00 7b 00 32 00 7d 00 29 00}
		$class = { 52 00 65 00 73 00 6F 00 75 00 72 00 63 00 65 00 73 00 00 17 69 00 6E 00 66 00 6F 00 72 00 6D 00 61 00 74 00 69 00 6F 00 6E 00 00 80 }

	condition:
		all of them
}

