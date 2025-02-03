rule Mirai_Generic_Arch : MALW hardened
{
	meta:
		description = "Mirai Botnet TR-069 Worm - Generic Architecture"
		author = "Felipe Molina / @felmoltor"
		date = "2016-12-04"
		version = "1.0"
		ref1 = "http://www.theregister.co.uk/2016/11/28/router_flaw_exploited_in_massive_attack/"
		ref2 = "https://isc.sans.edu/forums/diary/Port+7547+SOAP+Remote+Code+Execution+Attack+Against+DSL+Modems/21759"
		ref3 = "https://krebsonsecurity.com/2016/11/new-mirai-worm-knocks-900k-germans-offline/"

	strings:
		$miname = {4d 79 6e 61 6d 65 2d 2d 69 73 3a}
		$iptables1 = {62 75 73 79 62 6f 78 20 69 70 74 61 62 6c 65 73 20 2d 41 20 49 4e 50 55 54 20 2d 70 20 74 63 70 20 2d 2d 64 65 73 74 69 6e 61 74 69 6f 6e 2d 70 6f 72 74 20 37 35 34 37 20 2d 6a 20 44 52 4f 50}
		$iptables2 = {62 75 73 79 62 6f 78 20 69 70 74 61 62 6c 65 73 20 2d 41 20 49 4e 50 55 54 20 2d 70 20 74 63 70 20 2d 2d 64 65 73 74 69 6e 61 74 69 6f 6e 2d 70 6f 72 74 20 35 35 35 35 20 2d 6a 20 44 52 4f 50}
		$procnet = {2f 70 72 6f 63 2f 6e 65 74 2f 74 63 70}

	condition:
		$miname and $iptables1 and $iptables2 and $procnet
}

import "hash"

rule Mirai_MIPS_LSB : MALW hardened
{
	meta:
		description = "Mirai Botnet TR-069 Worm - MIPS LSB"
		author = "Felipe Molina / @felmoltor"
		date = "2016-12-04"
		version = "1.0"
		MD5 = "bf650d39eb603d92973052ca80a4fdda"
		SHA1 = "03ecd3b49aa19589599c64e4e7a51206a592b4ef"
		ref1 = "http://www.theregister.co.uk/2016/11/28/router_flaw_exploited_in_massive_attack/"
		ref2 = "https://isc.sans.edu/forums/diary/Port+7547+SOAP+Remote+Code+Execution+Attack+Against+DSL+Modems/21759"
		ref3 = "https://krebsonsecurity.com/2016/11/new-mirai-worm-knocks-900k-germans-offline/"

	strings:
		$miname = {4d 79 6e 61 6d 65 2d 2d 69 73 3a}
		$iptables1 = {62 75 73 79 62 6f 78 20 69 70 74 61 62 6c 65 73 20 2d 41 20 49 4e 50 55 54 20 2d 70 20 74 63 70 20 2d 2d 64 65 73 74 69 6e 61 74 69 6f 6e 2d 70 6f 72 74 20 37 35 34 37 20 2d 6a 20 44 52 4f 50}
		$iptables2 = {62 75 73 79 62 6f 78 20 69 70 74 61 62 6c 65 73 20 2d 41 20 49 4e 50 55 54 20 2d 70 20 74 63 70 20 2d 2d 64 65 73 74 69 6e 61 74 69 6f 6e 2d 70 6f 72 74 20 35 35 35 35 20 2d 6a 20 44 52 4f 50}
		$procnet = {2f 70 72 6f 63 2f 6e 65 74 2f 74 63 70}

	condition:
		$miname and $iptables1 and $iptables2 and $procnet and hash.sha1 ( 0 , filesize ) == "03ecd3b49aa19589599c64e4e7a51206a592b4ef"
}

import "hash"

rule Mirai_MIPS_MSB : MALW hardened
{
	meta:
		description = "Mirai Botnet TR-069 Worm - MIPS MSB"
		author = "Felipe Molina / @felmoltor"
		date = "2016-12-04"
		version = "1.0"
		MD5 = "0eb51d584712485300ad8e8126773941"
		SHA1 = "18bce2f0107b5fab1b0b7c453e2a6b6505200cbd"
		ref1 = "http://www.theregister.co.uk/2016/11/28/router_flaw_exploited_in_massive_attack/"
		ref2 = "https://isc.sans.edu/forums/diary/Port+7547+SOAP+Remote+Code+Execution+Attack+Against+DSL+Modems/21759"
		ref3 = "https://krebsonsecurity.com/2016/11/new-mirai-worm-knocks-900k-germans-offline/"

	strings:
		$miname = {4d 79 6e 61 6d 65 2d 2d 69 73 3a}
		$iptables1 = {62 75 73 79 62 6f 78 20 69 70 74 61 62 6c 65 73 20 2d 41 20 49 4e 50 55 54 20 2d 70 20 74 63 70 20 2d 2d 64 65 73 74 69 6e 61 74 69 6f 6e 2d 70 6f 72 74 20 37 35 34 37 20 2d 6a 20 44 52 4f 50}
		$iptables2 = {62 75 73 79 62 6f 78 20 69 70 74 61 62 6c 65 73 20 2d 41 20 49 4e 50 55 54 20 2d 70 20 74 63 70 20 2d 2d 64 65 73 74 69 6e 61 74 69 6f 6e 2d 70 6f 72 74 20 35 35 35 35 20 2d 6a 20 44 52 4f 50}
		$procnet = {2f 70 72 6f 63 2f 6e 65 74 2f 74 63 70}

	condition:
		$miname and $iptables1 and $iptables2 and $procnet and hash.sha1 ( 0 , filesize ) == "18bce2f0107b5fab1b0b7c453e2a6b6505200cbd"
}

import "hash"

rule Mirai_ARM_LSB : MALW hardened
{
	meta:
		description = "Mirai Botnet TR-069 Worm - ARM LSB"
		author = "Felipe Molina / @felmoltor"
		date = "2016-12-04"
		version = "1.0"
		MD5 = "eba670256b816e2d11f107f629d08494"
		SHA1 = "8a25dee4ea7d61692b2b95bd047269543aaf0c81"
		ref1 = "http://www.theregister.co.uk/2016/11/28/router_flaw_exploited_in_massive_attack/"
		ref2 = "https://isc.sans.edu/forums/diary/Port+7547+SOAP+Remote+Code+Execution+Attack+Against+DSL+Modems/21759"
		ref3 = "https://krebsonsecurity.com/2016/11/new-mirai-worm-knocks-900k-germans-offline/"

	strings:
		$miname = {4d 79 6e 61 6d 65 2d 2d 69 73 3a}
		$iptables1 = {62 75 73 79 62 6f 78 20 69 70 74 61 62 6c 65 73 20 2d 41 20 49 4e 50 55 54 20 2d 70 20 74 63 70 20 2d 2d 64 65 73 74 69 6e 61 74 69 6f 6e 2d 70 6f 72 74 20 37 35 34 37 20 2d 6a 20 44 52 4f 50}
		$iptables2 = {62 75 73 79 62 6f 78 20 69 70 74 61 62 6c 65 73 20 2d 41 20 49 4e 50 55 54 20 2d 70 20 74 63 70 20 2d 2d 64 65 73 74 69 6e 61 74 69 6f 6e 2d 70 6f 72 74 20 35 35 35 35 20 2d 6a 20 44 52 4f 50}
		$procnet = {2f 70 72 6f 63 2f 6e 65 74 2f 74 63 70}

	condition:
		$miname and $iptables1 and $iptables2 and $procnet and hash.sha1 ( 0 , filesize ) == "8a25dee4ea7d61692b2b95bd047269543aaf0c81"
}

import "hash"

rule Mirai_Renesas_SH : MALW hardened
{
	meta:
		description = "Mirai Botnet TR-069 Worm - Renesas SH LSB"
		author = "Felipe Molina / @felmoltor"
		date = "2016-12-04"
		version = "1.0"
		MD5 = "863dcf82883c885b0686dce747dcf502"
		SHA1 = "bdc86295fad70480f0c6edcc37981e3cf11d838c"
		ref1 = "http://www.theregister.co.uk/2016/11/28/router_flaw_exploited_in_massive_attack/"
		ref2 = "https://isc.sans.edu/forums/diary/Port+7547+SOAP+Remote+Code+Execution+Attack+Against+DSL+Modems/21759"
		ref3 = "https://krebsonsecurity.com/2016/11/new-mirai-worm-knocks-900k-germans-offline/"

	strings:
		$miname = {4d 79 6e 61 6d 65 2d 2d 69 73 3a}
		$iptables1 = {62 75 73 79 62 6f 78 20 69 70 74 61 62 6c 65 73 20 2d 41 20 49 4e 50 55 54 20 2d 70 20 74 63 70 20 2d 2d 64 65 73 74 69 6e 61 74 69 6f 6e 2d 70 6f 72 74 20 37 35 34 37 20 2d 6a 20 44 52 4f 50}
		$iptables2 = {62 75 73 79 62 6f 78 20 69 70 74 61 62 6c 65 73 20 2d 41 20 49 4e 50 55 54 20 2d 70 20 74 63 70 20 2d 2d 64 65 73 74 69 6e 61 74 69 6f 6e 2d 70 6f 72 74 20 35 35 35 35 20 2d 6a 20 44 52 4f 50}
		$procnet = {2f 70 72 6f 63 2f 6e 65 74 2f 74 63 70}

	condition:
		$miname and $iptables1 and $iptables2 and $procnet and hash.sha1 ( 0 , filesize ) == "bdc86295fad70480f0c6edcc37981e3cf11d838c"
}

import "hash"

rule Mirai_PPC_Cisco : MALW hardened
{
	meta:
		description = "Mirai Botnet TR-069 Worm - PowerPC or Cisco 4500"
		author = "Felipe Molina / @felmoltor"
		date = "2016-12-04"
		version = "1.0"
		MD5 = "dbd92b08cbff8455ff76c453ff704dc6"
		SHA1 = "6933d555a008a07b859a55cddb704441915adf68"
		ref1 = "http://www.theregister.co.uk/2016/11/28/router_flaw_exploited_in_massive_attack/"
		ref2 = "https://isc.sans.edu/forums/diary/Port+7547+SOAP+Remote+Code+Execution+Attack+Against+DSL+Modems/21759"
		ref3 = "https://krebsonsecurity.com/2016/11/new-mirai-worm-knocks-900k-germans-offline/"

	strings:
		$miname = {4d 79 6e 61 6d 65 2d 2d 69 73 3a}
		$iptables1 = {62 75 73 79 62 6f 78 20 69 70 74 61 62 6c 65 73 20 2d 41 20 49 4e 50 55 54 20 2d 70 20 74 63 70 20 2d 2d 64 65 73 74 69 6e 61 74 69 6f 6e 2d 70 6f 72 74 20 37 35 34 37 20 2d 6a 20 44 52 4f 50}
		$iptables2 = {62 75 73 79 62 6f 78 20 69 70 74 61 62 6c 65 73 20 2d 41 20 49 4e 50 55 54 20 2d 70 20 74 63 70 20 2d 2d 64 65 73 74 69 6e 61 74 69 6f 6e 2d 70 6f 72 74 20 35 35 35 35 20 2d 6a 20 44 52 4f 50}
		$procnet = {2f 70 72 6f 63 2f 6e 65 74 2f 74 63 70}

	condition:
		($miname and $iptables1 and $iptables2 and $procnet ) and hash.sha1 ( 0 , filesize ) == "6933d555a008a07b859a55cddb704441915adf68"
}

import "hash"

rule Mirai_SPARC_MSB : MALW hardened
{
	meta:
		description = "Mirai Botnet TR-069 Worm - SPARC MSB"
		author = "Felipe Molina / @felmoltor"
		date = "2016-12-04"
		version = "1.0"
		MD5 = "05891dbabc42a36f33c30535f0931555"
		SHA1 = "3d770480b6410cba39e19b3a2ff3bec774cabe47"
		ref1 = "http://www.theregister.co.uk/2016/11/28/router_flaw_exploited_in_massive_attack/"
		ref2 = "https://isc.sans.edu/forums/diary/Port+7547+SOAP+Remote+Code+Execution+Attack+Against+DSL+Modems/21759"
		ref3 = "https://krebsonsecurity.com/2016/11/new-mirai-worm-knocks-900k-germans-offline/"

	strings:
		$miname = {4d 79 6e 61 6d 65 2d 2d 69 73 3a}
		$iptables1 = {62 75 73 79 62 6f 78 20 69 70 74 61 62 6c 65 73 20 2d 41 20 49 4e 50 55 54 20 2d 70 20 74 63 70 20 2d 2d 64 65 73 74 69 6e 61 74 69 6f 6e 2d 70 6f 72 74 20 37 35 34 37 20 2d 6a 20 44 52 4f 50}
		$iptables2 = {62 75 73 79 62 6f 78 20 69 70 74 61 62 6c 65 73 20 2d 41 20 49 4e 50 55 54 20 2d 70 20 74 63 70 20 2d 2d 64 65 73 74 69 6e 61 74 69 6f 6e 2d 70 6f 72 74 20 35 35 35 35 20 2d 6a 20 44 52 4f 50}
		$procnet = {2f 70 72 6f 63 2f 6e 65 74 2f 74 63 70}

	condition:
		($miname and $iptables1 and $iptables2 and $procnet ) and hash.sha1 ( 0 , filesize ) == "3d770480b6410cba39e19b3a2ff3bec774cabe47"
}

rule Mirai_1 : MALW hardened
{
	meta:
		description = "Mirai Variant 1"
		author = "Joan Soriano / @joanbtl"
		date = "2017-04-16"
		version = "1.0"
		MD5 = "655c3cf460489a7d032c37cd5b84a3a8"
		SHA1 = "4dd3803956bc31c8c7c504734bddec47a1b57d58"

	strings:
		$dir1 = {2f 64 65 76 2f 77 61 74 63 68 64 6f 67}
		$dir2 = {2f 64 65 76 2f 6d 69 73 63 2f 77 61 74 63 68 64 6f 67}
		$pass1 = {50 4d 4d 56}
		$pass2 = {46 47 44 43 57 4e 56}
		$pass3 = {4f 4d 56 4a 47 50}

	condition:
		$dir1 and $pass1 and $pass2 and not $pass3 and not $dir2
}

rule Mirai_2 : MALW hardened
{
	meta:
		description = "Mirai Variant 2"
		author = "Joan Soriano / @joanbtl"
		date = "2017-04-16"
		version = "1.0"
		MD5 = "0e5bda9d39b03ce79ab8d421b90c0067"
		SHA1 = "96f42a9fad2923281d21eca7ecdd3161d2b61655"

	strings:
		$dir1 = {2f 64 65 76 2f 77 61 74 63 68 64 6f 67}
		$dir2 = {2f 64 65 76 2f 6d 69 73 63 2f 77 61 74 63 68 64 6f 67}
		$s1 = {50 4d 4d 56}
		$s2 = {5a 4f 4a 46 4b 52 41}
		$s3 = {46 47 44 43 57 4e 56}
		$s4 = {4f 4d 56 4a 47 50}

	condition:
		uint32be( 0x0 ) == 0x7f454c46 and $dir1 and $dir2 and $s1 and $s2 and $s3 and not $s4
}

rule Mirai_3 : MALW hardened
{
	meta:
		description = "Mirai Variant 3"
		author = "Joan Soriano / @joanbtl"
		date = "2017-04-16"
		version = "1.0"
		MD5 = "bb22b1c921ad8fa358d985ff1e51a5b8"
		SHA1 = "432ef83c7692e304c621924bc961d95c4aea0c00"

	strings:
		$dir1 = {2f 64 65 76 2f 77 61 74 63 68 64 6f 67}
		$dir2 = {2f 64 65 76 2f 6d 69 73 63 2f 77 61 74 63 68 64 6f 67}
		$s1 = {50 4d 4d 56}
		$s2 = {5a 4f 4a 46 4b 52 41}
		$s3 = {46 47 44 43 57 4e 56}
		$s4 = {4f 4d 56 4a 47 50}
		$ssl = {73 73 6c 33 5f 63 74 72 6c}

	condition:
		$dir1 and $dir2 and $s1 and $s2 and $s3 and $s4 and not $ssl
}

rule Mirai_4 : MALW hardened
{
	meta:
		description = "Mirai Variant 4"
		author = "Joan Soriano / @joanbtl"
		date = "2017-04-16"
		version = "1.0"
		MD5 = "f832ef7a4fcd252463adddfa14db43fb"
		SHA1 = "4455d237aadaf28aafce57097144beac92e55110"

	strings:
		$s1 = {32 31 30 37 36 35}
		$s2 = {71 6c 6c 77}
		$s3 = {3b 3b 3b 3b 3b 3b}

	condition:
		$s1 and $s2 and $s3
}

rule Mirai_Dwnl : MALW hardened
{
	meta:
		description = "Mirai Downloader"
		author = "Joan Soriano / @joanbtl"
		date = "2017-04-16"
		version = "1.0"
		MD5 = "85784b54dee0b7c16c57e3a3a01db7e6"
		SHA1 = "6f6c625ef730beefbc23c7f362af329426607dee"

	strings:
		$s1 = {47 45 54 20 2f 6d 69 72 61 69 2f}
		$s2 = {64 76 72 48 65 6c 70 65 72}

	condition:
		$s1 and $s2
}

rule Mirai_5 : MALW hardened
{
	meta:
		description = "Mirai Variant 5"
		author = "Joan Soriano / @joanbtl"
		date = "2017-04-16"
		version = "1.0"
		MD5 = "7e17c34cddcaeb6755c457b99a8dfe32"
		SHA1 = "b63271672d6a044704836d542d92b98e2316ad24"

	strings:
		$dir1 = {2f 64 65 76 2f 77 61 74 63 68 64 6f 67}
		$dir2 = {2f 64 65 76 2f 6d 69 73 63 2f 77 61 74 63 68 64 6f 67}
		$s1 = {50 4d 4d 56}
		$s2 = {5a 4f 4a 46 4b 52 41}
		$s3 = {46 47 44 43 57 4e 56}
		$s4 = {4f 4d 56 4a 47 50}
		$ssl = {73 73 6c 33 5f 63 74 72 6c}

	condition:
		$dir1 and $dir2 and $s1 and $s2 and $s3 and $s4 and $ssl
}

