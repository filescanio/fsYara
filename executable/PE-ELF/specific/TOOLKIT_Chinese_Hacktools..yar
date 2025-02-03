rule mswin_check_lm_group : hardened
{
	meta:
		description = "Chinese Hacktool Set - file mswin_check_lm_group.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "115d87d7e7a3d08802a9e5fd6cd08e2ec633c367"

	strings:
		$s1 = {56 61 6c 69 64 5f 47 6c 6f 62 61 6c 5f 47 72 6f 75 70 73 3a 20 63 68 65 63 6b 69 6e 67 20 67 72 6f 75 70 20 6d 65 6d 62 65 72 73 68 69 70 20 6f 66 20 27 25 73 5c 25 73 27 2e}
		$s2 = {55 73 61 67 65 3a 20 25 73 20 5b 2d 44 20 64 6f 6d 61 69 6e 5d 5b 2d 47 5d 5b 2d 50 5d 5b 2d 63 5d 5b 2d 64 5d 5b 2d 68 5d}
		$s3 = {2d 44 20 20 20 20 64 65 66 61 75 6c 74 20 75 73 65 72 20 44 6f 6d 61 69 6e}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 380KB and all of them
}

rule WAF_Bypass : hardened
{
	meta:
		description = "Chinese Hacktool Set - file WAF-Bypass.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "860a9d7aac2ce3a40ac54a4a0bd442c6b945fa4e"

	strings:
		$s1 = {45 00 6d 00 61 00 69 00 6c 00 3a 00 20 00 62 00 6c 00 61 00 63 00 6b 00 73 00 70 00 6c 00 69 00 74 00 6e 00 40 00 67 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00}
		$s2 = {55 00 73 00 65 00 72 00 2d 00 41 00 67 00 65 00 6e 00 74 00 3a 00}
		$s3 = {53 65 6e 64 20 46 61 69 6c 65 64 2e 69 6e 20 52 65 6d 6f 74 65 54 68 72 65 61 64}
		$s4 = {77 00 77 00 77 00 2e 00 65 00 78 00 61 00 6d 00 70 00 6c 00 65 00 2e 00 63 00 6f 00 6d 00}
		$s5 = {47 65 74 20 44 6f 6d 61 69 6e 3a 25 73 20 49 50 20 46 61 69 6c 65 64 2e}
		$s6 = {43 6f 6e 6e 65 63 74 20 54 6f 20 53 65 72 76 65 72 20 46 61 69 6c 65 64 2e}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 7992KB and 5 of them
}

rule Guilin_veterans_cookie_spoofing_tool : hardened
{
	meta:
		description = "Chinese Hacktool Set - file Guilin veterans cookie spoofing tool.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "06b1969bc35b2ee8d66f7ce8a2120d3016a00bb1"

	strings:
		$s0 = {6b 65 72 6e 65 6c 33 32 2e 64 6c 6c 5e 47}
		$s1 = {5c 2e 53 75 73 22 42}
		$s4 = {75 35 36 4c 6f 61 64 33}
		$s11 = {4f 20 4d 59 54 4d 50 28 69 4d 29 20 56 41 4c 55 45 53 20 28}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 1387KB and all of them
}

rule MarathonTool : hardened
{
	meta:
		description = "Chinese Hacktool Set - file MarathonTool.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "084a27cd3404554cc799d0e689f65880e10b59e3"

	strings:
		$s0 = {4d 61 72 61 74 68 6f 6e 54 6f 6f 6c}
		$s17 = {2f 42 6c 69 6e 64 20 53 51 4c 20 69 6e 6a 65 63 74 69 6f 6e 20 74 6f 6f 6c 20 62 61 73 65 64 20 69 6e 20 68 65 61 76 79 20 71 75 65 72 69 65 73}
		$s18 = {53 00 45 00 4c 00 45 00 43 00 54 00 20 00 55 00 4e 00 49 00 43 00 4f 00 44 00 45 00 28 00 53 00 55 00 42 00 53 00 54 00 52 00 49 00 4e 00 47 00 28 00 28 00 73 00 79 00 73 00 74 00 65 00 6d 00 5f 00 75 00 73 00 65 00 72 00 29 00 2c 00 7b 00 30 00 7d 00 2c 00 31 00 29 00 29 00}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 1040KB and all of them
}

rule PLUGIN_TracKid : hardened
{
	meta:
		description = "Chinese Hacktool Set - file TracKid.dll"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "a114181b334e850d4b33e9be2794f5bb0eb59a09"

	strings:
		$s0 = {45 2d 6d 61 69 6c 3a 20 63 72 61 63 6b 65 72 5f 70 72 69 6e 63 65 40 31 36 33 2e 63 6f 6d}
		$s1 = {2e 5c 54 72 61 63 4b 69 64 20 4c 6f 67 5c 25 73 2e 74 78 74}
		$s2 = {43 6f 64 65 64 20 62 79 20 70 72 69 6e 63 65}
		$s3 = {54 72 61 63 4b 69 64 2e 64 6c 6c}
		$s4 = {2e 5c 54 72 61 63 4b 69 64 20 4c 6f 67}
		$s5 = {25 30 38 78 20 2d 2d 20 25 73}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 200KB and 3 of them
}

rule Pc_pc2015 : hardened
{
	meta:
		description = "Chinese Hacktool Set - file pc2015.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "de4f098611ac9eece91b079050b2d0b23afe0bcb"

	strings:
		$s0 = {5c 73 76 63 68 6f 73 74 2e 65 78 65}
		$s1 = {4c 4f 4e 5c 4f 44 5c 4f 2d 5c 4f 29 5c 4f 25 5c 4f 21 5c 4f 3d 5c 4f 39 5c 4f 35 5c 4f 31 5c 4f}
		$s8 = {25 73 25 30 38 78 2e 30 30 31}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 309KB and all of them
}

rule sekurlsa : hardened
{
	meta:
		description = "Chinese Hacktool Set - file sekurlsa.dll"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "6acecd18fc7da1c5eb0d04e848aae9ce59d2b1b5"

	strings:
		$s1 = {42 00 69 00 65 00 6e 00 76 00 65 00 6e 00 75 00 65 00 20 00 64 00 61 00 6e 00 73 00 20 00 75 00 6e 00 20 00 70 00 72 00 6f 00 63 00 65 00 73 00 73 00 75 00 73 00 20 00 64 00 69 00 73 00 74 00 61 00 6e 00 74 00}
		$s2 = {46 00 6f 00 72 00 6d 00 61 00 74 00 20 00 64 00 27 00 61 00 70 00 70 00 65 00 6c 00 20 00 69 00 6e 00 76 00 61 00 6c 00 69 00 64 00 65 00 20 00 3a 00 20 00 61 00 64 00 64 00 4c 00 6f 00 67 00 6f 00 6e 00 53 00 65 00 73 00 73 00 69 00 6f 00 6e 00 20 00 5b 00 69 00 64 00 53 00 65 00 63 00 41 00 70 00 70 00 48 00 69 00 67 00 68 00 5d 00 20 00 69 00 64 00 53 00 65 00 63 00 41 00 70 00 70 00 4c 00 6f 00 77 00 20 00 55 00 74 00 69 00 6c 00 69 00 73 00 61 00 74 00 65 00 75 00 72 00}
		$s3 = {53 00 45 00 43 00 55 00 52 00 49 00 54 00 59 00 5c 00 50 00 6f 00 6c 00 69 00 63 00 79 00 5c 00 53 00 65 00 63 00 72 00 65 00 74 00 73 00}
		$s4 = {49 00 6e 00 6a 00 65 00 63 00 74 00 69 00 6f 00 6e 00 20 00 64 00 65 00 20 00 64 00 6f 00 6e 00 6e 00}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 1150KB and all of them
}

rule mysqlfast : hardened
{
	meta:
		description = "Chinese Hacktool Set - file mysqlfast.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "32b60350390fe7024af7b4b8fbf50f13306c546f"

	strings:
		$s2 = {49 6e 76 61 6c 69 64 20 70 61 73 73 77 6f 72 64 20 68 61 73 68 3a 20 25 73}
		$s3 = {2d 3d 20 4d 79 53 71 6c 20 48 61 73 68 20 43 72 61 63 6b 65 72 20 3d 2d 20}
		$s4 = {55 73 61 67 65 3a 20 25 73 20 68 61 73 68}
		$s5 = {48 61 73 68 3a 20 25 30 38 6c 78 25 30 38 6c 78}
		$s6 = {46 6f 75 6e 64 20 70 61 73 73 3a 20}
		$s7 = {50 61 73 73 20 6e 6f 74 20 66 6f 75 6e 64}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 900KB and 4 of them
}

rule DTools2_02_DTools : hardened
{
	meta:
		description = "Chinese Hacktool Set - file DTools.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "9f99771427120d09ec7afa3b21a1cb9ed720af12"

	strings:
		$s0 = {6b 65 72 6e 65 6c 33 32 2e 64 6c 6c}
		$s1 = {54 00 53 00 45 00 54 00 50 00 41 00 53 00 53 00 57 00 4f 00 52 00 44 00 46 00 4f 00 52 00 4d 00}
		$s2 = {54 00 47 00 45 00 54 00 4e 00 54 00 55 00 53 00 45 00 52 00 4e 00 41 00 4d 00 45 00 46 00 4f 00 52 00 4d 00}
		$s3 = {54 00 50 00 4f 00 52 00 54 00 46 00 4f 00 52 00 4d 00}
		$s4 = {53 68 65 6c 6c 46 6f 6c 64}
		$s5 = {44 65 66 61 75 6c 74 50 48 6f 74 4c 69 67 68}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 2000KB and all of them
}

rule dll_PacketX : hardened
{
	meta:
		description = "Chinese Hacktool Set - file PacketX.dll - ActiveX wrapper for WinPcap packet capture library"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		score = 50
		hash = "3f0908e0a38512d2a4fb05a824aa0f6cf3ba3b71"

	strings:
		$s9 = {5b 00 46 00 61 00 69 00 6c 00 65 00 64 00 20 00 74 00 6f 00 20 00 6c 00 6f 00 61 00 64 00 20 00 77 00 69 00 6e 00 70 00 63 00 61 00 70 00 20 00 70 00 61 00 63 00 6b 00 65 00 74 00 2e 00 64 00 6c 00 6c 00 2e 00}
		$s10 = {50 00 61 00 63 00 6b 00 65 00 74 00 58 00 20 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 1920KB and all of them
}

rule SqlDbx_zhs : hardened
{
	meta:
		description = "Chinese Hacktool Set - file SqlDbx_zhs.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "e34228345498a48d7f529dbdffcd919da2dea414"

	strings:
		$s0 = {53 2e 66 61 69 6c 65 64 5f 6c 6f 67 69 6e 73 20 22 46 61 69 6c 65 64 20 4c 6f 67 69 6e 20 41 74 74 65 6d 70 74 73 22 2c 20}
		$s7 = {53 45 4c 45 43 54 20 52 4f 4c 45 2c 20 50 41 53 53 57 4f 52 44 5f 52 45 51 55 49 52 45 44 20 46 52 4f 4d 20 53 59 53 2e 44 42 41 5f 52 4f 4c 45 53 20 4f 52 44 45 52 20 42 59 20 52 4f 4c 45}
		$s8 = {53 45 4c 45 43 54 20 73 70 69 64 20 27 53 50 49 44 27 2c 20 73 74 61 74 75 73 20 27 53 74 61 74 75 73 27 2c 20 64 62 5f 6e 61 6d 65 20 28 64 62 69 64 29 20 27 44 61 74 61 62 61 73 65 27 2c 20 6c 6f 67 69 6e 61 6d 65 20 27 4c 6f 67 69 6e 27}
		$s9 = {62 63 70 2e 65 78 65 20 3c 3a 73 63 68 65 6d 61 3a 3e 2e 3c 3a 74 61 62 6c 65 3a 3e 20 6f 75 74 20 22 3c 3a 66 69 6c 65 3a 3e 22 20 2d 6e 20 2d 53 20 3c 3a 73 65 72 76 65 72 3a 3e 20 2d 55 20 3c 3a 75 73 65 72 3a 3e 20 2d 50 20 3c 3a}
		$s11 = {4c 2e 6c 6f 67 69 6e 5f 70 6f 6c 69 63 79 5f 6e 61 6d 65 20 41 53 20 22 4c 6f 67 69 6e 20 50 6f 6c 69 63 79 22 2c 20}
		$s12 = {6d 61 69 6c 74 6f 3a 73 75 70 70 6f 72 74 40 73 71 6c 64 62 78 2e 63 6f 6d}
		$s15 = {53 2e 6c 61 73 74 5f 6c 6f 67 69 6e 5f 74 69 6d 65 20 22 4c 61 73 74 20 4c 6f 67 69 6e 22 2c 20}

	condition:
		uint16( 0 ) == 0x5a4d and 4 of them
}

rule ms10048_x86 : hardened
{
	meta:
		description = "Chinese Hacktool Set - file ms10048-x86.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "e57b453966e4827e2effa4e153f2923e7d058702"

	strings:
		$s1 = {5b 20 5d 20 52 65 73 6f 6c 76 69 6e 67 20 50 73 4c 6f 6f 6b 75 70 50 72 6f 63 65 73 73 42 79 50 72 6f 63 65 73 73 49 64}
		$s2 = {54 68 65 20 74 61 72 67 65 74 20 69 73 20 6d 6f 73 74 20 6c 69 6b 65 6c 79 20 70 61 74 63 68 65 64 2e}
		$s3 = {44 6f 6a 69 62 69 72 6f 6e 20 62 79 20 52 6f 6e 61 6c 64 20 48 75 69 7a 65 72 2c 20 28 63 29 20 6d 61 73 74 65 72 40 68 34 63 6b 65 72 2e 75 73 20 2e}
		$s4 = {5b 20 5d 20 43 72 65 61 74 69 6e 67 20 65 76 69 6c 20 77 69 6e 64 6f 77}
		$s5 = {25 73 48 41 4e 44 4c 45 46 5f 49 4e 44 45 53 54 52 4f 59}
		$s6 = {5b 2b 5d 20 53 65 74 20 74 6f 20 25 64 20 65 78 70 6c 6f 69 74 20 68 61 6c 66 20 73 75 63 63 65 65 64 65 64}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 100KB and 4 of them
}

rule Dos_ch : hardened
{
	meta:
		description = "Chinese Hacktool Set - file ch.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "60bbb87b08af840f21536b313a76646e7c1f0ea7"

	strings:
		$s0 = {2f 43 68 75 72 72 61 73 6b 69 74 6f 2f 2d 2d 3e 55 73 61 67 65 3a 20 43 68 75 72 72 61 73 6b 69 74 6f 2e 65 78 65 20 22 63 6f 6d 6d 61 6e 64 22 20}
		$s4 = {66 75 63 6b 2c 63 61 6e 27 74 20 66 69 6e 64 20 57 4d 49 20 70 72 6f 63 65 73 73 20 50 49 44 2e}
		$s5 = {2f 43 68 75 72 72 61 73 6b 69 74 6f 2f 2d 2d 3e 46 6f 75 6e 64 20 74 6f 6b 65 6e 20 25 73 20}
		$s8 = {77 6d 69 70 72 76 73 65 2e 65 78 65}
		$s10 = {53 45 4c 45 43 54 20 2a 20 46 52 4f 4d 20 49 49 73 57 65 62 49 6e 66 6f}
		$s17 = {57 69 6e 53 74 61 30 5c 44 65 66 61 75 6c 74}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 260KB and 3 of them
}

rule DUBrute_DUBrute : hardened
{
	meta:
		description = "Chinese Hacktool Set - file DUBrute.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "8aaae91791bf782c92b97c6e1b0f78fb2a9f3e65"

	strings:
		$s1 = {49 50 20 2d 20 25 64 3b 20 4c 6f 67 69 6e 20 2d 20 25 64 3b 20 50 61 73 73 77 6f 72 64 20 2d 20 25 64 3b 20 43 6f 6d 62 69 6e 61 74 69 6f 6e 20 2d 20 25 64}
		$s2 = {49 50 20 2d 20 30 3b 20 4c 6f 67 69 6e 20 2d 20 30 3b 20 50 61 73 73 77 6f 72 64 20 2d 20 30 3b 20 43 6f 6d 62 69 6e 61 74 69 6f 6e 20 2d 20 30}
		$s3 = {43 72 65 61 74 65 20 25 64 20 49 50 40 4c 6f 67 69 6e 6c 3b 50 61 73 73 77 6f 72 64}
		$s4 = {55 42 72 75 74 65 2e 63 6f 6d}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 1020KB and all of them
}

rule CookieTools : hardened
{
	meta:
		description = "Chinese Hacktool Set - file CookieTools.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "b6a3727fe3d214f4fb03aa43fb2bc6fadc42c8be"

	strings:
		$s0 = {68 74 74 70 3a 2f 2f 32 31 30 2e 37 33 2e 36 34 2e 38 38 2f 64 6f 6f 72 77 61 79 2f 63 67 69 2d 62 69 6e 2f 67 65 74 63 6c 69 65 6e 74 69 70 2e 61 73 70 3f 49 50 3d}
		$s2 = {4e 00 6f 00 20 00 64 00 61 00 74 00 61 00 20 00 74 00 6f 00 20 00 72 00 65 00 61 00 64 00 2e 00 24 00 43 00 61 00 6e 00 20 00 6e 00 6f 00 74 00 20 00 62 00 69 00 6e 00 64 00 20 00 69 00 6e 00 20 00 70 00 6f 00 72 00 74 00 20 00 72 00 61 00 6e 00 67 00 65 00 20 00 28 00 25 00 64 00 20 00 2d 00 20 00 25 00 64 00 29 00}
		$s3 = {43 00 6f 00 6e 00 6e 00 65 00 63 00 74 00 69 00 6f 00 6e 00 20 00 43 00 6c 00 6f 00 73 00 65 00 64 00 20 00 47 00 72 00 61 00 63 00 65 00 66 00 75 00 6c 00 6c 00 79 00 2e 00 3b 00 43 00 6f 00 75 00 6c 00 64 00 20 00 6e 00 6f 00 74 00 20 00 62 00 69 00 6e 00 64 00 20 00 73 00 6f 00 63 00 6b 00 65 00 74 00 2e 00 20 00 41 00 64 00 64 00 72 00 65 00 73 00 73 00 20 00 61 00 6e 00 64 00 20 00 70 00 6f 00 72 00 74 00 20 00 61 00 72 00 65 00 20 00 61 00 6c 00 72 00 65 00 61 00 64 00}
		$s8 = {4f 6e 47 65 74 50 61 73 73 77 6f 72 64 50}
		$s12 = {68 74 74 70 3a 2f 2f 77 77 77 2e 63 68 69 6e 65 73 65 68 61 63 6b 2e 6f 72 67 2f}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 5000KB and 2 of them
}

rule update_PcInit : hardened
{
	meta:
		description = "Chinese Hacktool Set - file PcInit.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "a6facc4453f8cd81b8c18b3b3004fa4d8e2f5344"

	strings:
		$s1 = {5c 73 76 63 68 6f 73 74 2e 65 78 65}
		$s2 = {25 73 25 30 38 78 2e 30 30 31}
		$s3 = {47 6c 6f 62 61 6c 5c 70 73 25 30 38 78}
		$s4 = {64 72 69 76 65 72 73 5c}
		$s5 = {53 74 72 53 74 72 41}
		$s6 = {53 74 72 54 6f 49 6e 74 41}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 50KB and all of them
}

rule dat_NaslLib : hardened
{
	meta:
		description = "Chinese Hacktool Set - file NaslLib.dll"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "fb0d4263118faaeed2d68e12fab24c59953e862d"

	strings:
		$s1 = {6e 65 73 73 75 73 5f 67 65 74 5f 73 6f 63 6b 65 74 5f 66 72 6f 6d 5f 63 6f 6e 6e 65 63 74 69 6f 6e 3a 20 66 64 20 3c 25 64 3e 20 69 73 20 63 6c 6f 73 65 64}
		$s2 = {5b 2a 5d 20 22 25 73 22 20 63 6f 6d 70 6c 65 74 65 64 2c 20 25 64 2f 25 64 2f 25 64 2f 25 64 3a 25 64 3a 25 64 20 2d 20 25 64 2f 25 64 2f 25 64 2f 25 64 3a 25 64 3a 25 64}
		$s3 = {41 20 46 73 53 6e 69 66 66 65 72 20 62 61 63 6b 64 6f 6f 72 20 73 65 65 6d 73 20 74 6f 20 62 65 20 72 75 6e 6e 69 6e 67 20 6f 6e 20 74 68 69 73 20 70 6f 72 74 25 73}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 1360KB and all of them
}

rule Dos_1 : hardened
{
	meta:
		description = "Chinese Hacktool Set - file 1.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "b554f0687a12ec3a137f321cc15e052ff219f28c"

	strings:
		$s1 = {2f 63 68 75 72 72 61 73 63 6f 2f 2d 2d 3e 55 73 61 67 65 3a 20 43 68 75 72 72 61 73 63 6f 2e 65 78 65 20 22 63 6f 6d 6d 61 6e 64 20 74 6f 20 72 75 6e 22}
		$s2 = {2f 63 68 75 72 72 61 73 63 6f 2f 2d 2d 3e 44 6f 6e 65 2c 20 63 6f 6d 6d 61 6e 64 20 73 68 6f 75 6c 64 20 68 61 76 65 20 72 61 6e 20 61 73 20 53 59 53 54 45 4d 21}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 1000KB and all of them
}

rule OtherTools_servu : hardened
{
	meta:
		description = "Chinese Hacktool Set - file svu.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "5c64e6879a9746a0d65226706e0edc7a"

	strings:
		$s0 = {4d 5a 4b 45 52 4e 45 4c 33 32 2e 44 4c 4c}
		$s1 = {55 70 61 63 6b 42 79 44 77 69 6e 67 40}
		$s2 = {47 65 74 50 72 6f 63 41 64 64 72 65 73 73}
		$s3 = {57 72 69 74 65 46 69 6c 65}

	condition:
		$s0 at 0 and filesize < 50KB and all of them
}

rule ustrrefadd : hardened
{
	meta:
		description = "Chinese Hacktool Set - file ustrrefadd.dll"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "b371b122460951e74094f3db3016264c9c8a0cfa"

	strings:
		$s0 = {45 2d 4d 61 69 6c 20 20 3a 20 61 64 6d 69 6e 40 6c 75 6f 63 6f 6e 67 2e 63 6f 6d}
		$s1 = {48 6f 6d 65 70 61 67 65 3a 20 68 74 74 70 3a 2f 2f 77 77 77 2e 6c 75 6f 63 6f 6e 67 2e 63 6f 6d}
		$s2 = {3a 20 25 64 20 20 2d 20 20}
		$s3 = {75 73 74 72 72 65 66 66 69 78 2e 64 6c 6c}
		$s5 = {55 6c 74 72 61 20 53 74 72 69 6e 67 20 52 65 66 65 72 65 6e 63 65 20 70 6c 75 67 69 6e 20 76 25 64 2e 25 30 32 64}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 320KB and all of them
}

rule XScanLib : hardened
{
	meta:
		description = "Chinese Hacktool Set - file XScanLib.dll"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "c5cb4f75cf241f5a9aea324783193433a42a13b0"

	strings:
		$s4 = {58 53 63 61 6e 4c 69 62 2e 64 6c 6c}
		$s6 = {50 6f 72 74 73 2f 25 73 2f 25 64}
		$s8 = {44 45 46 41 55 4c 54 2d 54 43 50 2d 50 4f 52 54}
		$s9 = {50 6c 75 67 43 68 65 63 6b 54 63 70 50 6f 72 74}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 360KB and all of them
}

rule IDTools_For_WinXP_IdtTool : hardened
{
	meta:
		description = "Chinese Hacktool Set - file IdtTool.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "ebab6e4cb7ea82c8dc1fe4154e040e241f4672c6"

	strings:
		$s2 = {49 64 74 54 6f 6f 6c 2e 73 79 73}
		$s4 = {49 00 64 00 74 00 20 00 54 00 6f 00 6f 00 6c 00 20 00 62 00 59 00 20 00 74 00 4d 00 64 00 5b 00 43 00 73 00 50 00 5d 00}
		$s6 = {5c 5c 2e 5c 73 6c 49 64 74 54 6f 6f 6c}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 25KB and all of them
}

rule GoodToolset_ms11046 : hardened
{
	meta:
		description = "Chinese Hacktool Set - file ms11046.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "f8414a374011fd239a6c6d9c6ca5851cd8936409"

	strings:
		$s1 = {5b 2a 5d 20 54 6f 6b 65 6e 20 73 79 73 74 65 6d 20 63 6f 6d 6d 61 6e 64}
		$s2 = {5b 2a 5d 20 63 6f 6d 6d 61 6e 64 20 61 64 64 20 75 73 65 72 20 39 30 73 65 63 20 39 30 73 65 63}
		$s3 = {5b 2a 5d 20 41 64 64 20 74 6f 20 41 64 6d 69 6e 69 73 74 72 61 74 6f 72 73 20 73 75 63 63 65 73 73}
		$s4 = {5b 2a 5d 20 55 73 65 72 20 68 61 73 20 62 65 65 6e 20 73 75 63 63 65 73 73 66 75 6c 6c 79 20 61 64 64 65 64}
		$s5 = {50 72 6f 67 72 61 6d 3a 20 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 840KB and 2 of them
}

rule Cmdshell32 : hardened
{
	meta:
		description = "Chinese Hacktool Set - file Cmdshell32.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "3c41116d20e06dcb179e7346901c1c11cd81c596"

	strings:
		$s1 = {63 00 6d 00 64 00 73 00 68 00 65 00 6c 00 6c 00 2e 00 65 00 78 00 65 00}
		$s2 = {63 6d 64 73 68 65 6c 6c}
		$s3 = {5b 00 52 00 6f 00 6f 00 74 00 40 00 43 00 6d 00 64 00 53 00 68 00 65 00 6c 00 6c 00 20 00 7e 00 5d 00 23 00}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 62KB and all of them
}

rule Sniffer_analyzer_SSClone_1210_full_version : hardened
{
	meta:
		description = "Chinese Hacktool Set - file Sniffer analyzer SSClone 1210 full version.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "6882125babb60bd0a7b2f1943a40b965b7a03d4e"

	strings:
		$s0 = {68 74 74 70 3a 2f 2f 77 77 77 2e 76 69 70 38 30 30 30 30 2e 63 6f 6d 2f 68 6f 74 2f 69 6e 64 65 78 2e 68 74 6d 6c}
		$s1 = {47 65 74 43 6f 6e 6e 65 63 74 53 74 72 69 6e 67}
		$s2 = {43 6e 43 65 72 54 2e 53 61 66 65 2e 53 53 43 6c 6f 6e 65 2e 64 6c 6c}
		$s3 = {28 2a 2e 4a 50 47 3b 2a 2e 42 4d 50 3b 2a 2e 47 49 46 3b 2a 2e 49 43 4f 3b 2a 2e 43 55 52 29 7c 2a 2e 4a 50 47 3b 2a 2e 42 4d 50 3b 2a 2e 47 49 46 3b 2a 2e 49 43 4f 3b 2a 2e 43 55 52 7c 4a 50 47}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 3580KB and all of them
}

rule x64_klock : hardened
{
	meta:
		description = "Chinese Hacktool Set - file klock.dll"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "44825e848bc3abdb6f31d0a49725bb6f498e9ccc"

	strings:
		$s1 = {42 00 69 00 65 00 6e 00 76 00 65 00 6e 00 75 00 65 00 20 00 64 00 61 00 6e 00 73 00 20 00 75 00 6e 00 20 00 70 00 72 00 6f 00 63 00 65 00 73 00 73 00 75 00 73 00 20 00 64 00 69 00 73 00 74 00 61 00 6e 00 74 00}
		$s2 = {6b 6c 6f 63 6b 2e 64 6c 6c}
		$s3 = {45 00 72 00 72 00 65 00 75 00 72 00 20 00 3a 00 20 00 6c 00 65 00 20 00 62 00 75 00 72 00 65 00 61 00 75 00 20 00 63 00 6f 00 75 00 72 00 61 00 6e 00 74 00 20 00 28 00}
		$s4 = {6b 00 6c 00 6f 00 63 00 6b 00 20 00 64 00 65 00 20 00 6d 00 69 00 6d 00 69 00 6b 00 61 00 74 00 7a 00 20 00 70 00 6f 00 75 00 72 00 20 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 907KB and all of them
}

rule Dos_Down32 : hardened
{
	meta:
		description = "Chinese Hacktool Set - file Down32.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "0365738acd728021b0ea2967c867f1014fd7dd75"

	strings:
		$s2 = {43 00 3a 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 54 00 65 00 6d 00 70 00 5c 00 43 00 6d 00 64 00 2e 00 74 00 78 00 74 00}
		$s6 = {64 00 6f 00 77 00 6e 00 2e 00 65 00 78 00 65 00}
		$s15 = {67 65 74 5f 46 6f 72 6d 31}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 137KB and all of them
}

rule MarathonTool_2 : hardened
{
	meta:
		description = "Chinese Hacktool Set - file MarathonTool.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "75b5d25cdaa6a035981e5a33198fef0117c27c9c"

	strings:
		$s3 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 6c 00 6f 00 63 00 61 00 6c 00 68 00 6f 00 73 00 74 00 2f 00 72 00 65 00 74 00 6f 00 6d 00 79 00 73 00 71 00 6c 00 2f 00 70 00 69 00 73 00 74 00 61 00 2e 00 61 00 73 00 70 00 78 00 3f 00 69 00 64 00 5f 00 70 00 69 00 73 00 74 00 61 00 3d 00 31 00}
		$s6 = {53 00 45 00 4c 00 45 00 43 00 54 00 20 00 41 00 53 00 43 00 49 00 49 00 28 00 53 00 55 00 42 00 53 00 54 00 52 00 28 00 75 00 73 00 65 00 72 00 6e 00 61 00 6d 00 65 00 2c 00 7b 00 30 00 7d 00 2c 00 31 00 29 00 29 00 20 00 46 00 52 00 4f 00 4d 00 20 00 55 00 53 00 45 00 52 00 5f 00 55 00 53 00 45 00 52 00 53 00}
		$s17 = {2f 42 6c 69 6e 64 20 53 51 4c 20 69 6e 6a 65 63 74 69 6f 6e 20 74 6f 6f 6c 20 62 61 73 65 64 20 69 6e 20 68 65 61 76 79 20 71 75 65 72 69 65 73}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 1000KB and all of them
}

rule Tools_termsrv : hardened
{
	meta:
		description = "Chinese Hacktool Set - file termsrv.dll"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "294a693d252f8f4c85ad92ee8c618cebd94ef247"

	strings:
		$s1 = {49 76 5c 53 6d 53 73 57 69 6e 53 74 61 74 69 6f 6e 41 70 69 50 6f 72 74}
		$s2 = {20 00 54 00 53 00 49 00 6e 00 74 00 65 00 72 00 6e 00 65 00 74 00 55 00 73 00 65 00 72 00 20 00}
		$s3 = {4b 76 49 6e 74 65 72 6c 6f 63 6b 65 64 43 6f 6d 70 61 72 65 45 78 63 68 61 6e 67 65}
		$s4 = {20 00 57 00 49 00 4e 00 53 00 2f 00 44 00 4e 00 53 00 20 00}
		$s5 = {77 00 69 00 6e 00 65 00 72 00 72 00 6f 00 72 00 3d 00 25 00 31 00}
		$s6 = {54 00 65 00 72 00 6d 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 20 00}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 1150KB and all of them
}

rule scanms_scanms : hardened
{
	meta:
		description = "Chinese Hacktool Set - file scanms.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "47787dee6ddea2cb44ff27b6a5fd729273cea51a"

	strings:
		$s1 = {2d 2d 2d 20 53 63 61 6e 4d 73 20 54 6f 6f 6c 20 2d 2d 2d 20 28 63 29 20 32 30 30 33 20 49 6e 74 65 72 6e 65 74 20 53 65 63 75 72 69 74 79 20 53 79 73 74 65 6d 73 20 2d 2d 2d}
		$s2 = {53 63 61 6e 73 20 66 6f 72 20 73 79 73 74 65 6d 73 20 76 75 6c 6e 65 72 61 62 6c 65 20 74 6f 20 4d 53 30 33 2d 30 32 36 20 76 75 6c 6e}
		$s3 = {4d 6f 72 65 20 61 63 63 75 72 61 74 65 20 66 6f 72 20 57 69 6e 58 50 2f 57 69 6e 32 6b 2c 20 6c 65 73 73 20 61 63 63 75 72 61 74 65 20 66 6f 72 20 57 69 6e 4e 54}
		$s4 = {61 64 64 65 64 20 25 64 2e 25 64 2e 25 64 2e 25 64 2d 25 64 2e 25 64 2e 25 64 2e 25 64}
		$s5 = {49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 20 31 2e 30}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 300KB and 3 of them
}

rule CN_Tools_PcShare : hardened
{
	meta:
		description = "Chinese Hacktool Set - file PcShare.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "ee7ba9784fae413d644cdf5a093bd93b73537652"

	strings:
		$s0 = {74 00 69 00 74 00 6c 00 65 00 3d 00 25 00 73 00 25 00 73 00 2d 00 25 00 73 00 3b 00 69 00 64 00 3d 00 25 00 73 00 3b 00 68 00 77 00 6e 00 64 00 3d 00 25 00 64 00 3b 00 6d 00 61 00 69 00 6e 00 68 00 77 00 6e 00 64 00 3d 00 25 00 64 00 3b 00 6d 00 61 00 69 00 6e 00 70 00 72 00 6f 00 63 00 65 00 73 00 73 00 3d 00 25 00 64 00 3b 00 63 00 6d 00 64 00 3d 00 25 00 64 00 3b 00}
		$s1 = {4d 00 6f 00 7a 00 69 00 6c 00 6c 00 61 00 2f 00 34 00 2e 00 30 00 20 00 28 00 63 00 6f 00 6d 00 70 00 61 00 74 00 69 00 62 00 6c 00 65 00 3b 00 20 00 4d 00 53 00 49 00 45 00 20 00 36 00 2e 00 30 00 3b 00 20 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 4e 00 54 00 20 00 35 00 2e 00 30 00 3b 00 20 00 2e 00 4e 00 45 00 54 00 20 00 43 00 4c 00 52 00 20 00 31 00 2e 00 31 00 2e 00 34 00 33 00 32 00 32 00 29 00}
		$s2 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 77 00 77 00 77 00 2e 00 70 00 63 00 73 00 68 00 61 00 72 00 65 00 73 00 2e 00 63 00 6e 00 2f 00 70 00 63 00 73 00 68 00 61 00 72 00 65 00 32 00 30 00 30 00 2f 00 6c 00 6f 00 73 00 74 00 70 00 61 00 73 00 73 00 2e 00 61 00 73 00 70 00}
		$s5 = {70 00 6f 00 72 00 74 00 3d 00 25 00 73 00 3b 00 6e 00 61 00 6d 00 65 00 3d 00 25 00 73 00 3b 00 70 00 61 00 73 00 73 00 3d 00 25 00 73 00 3b 00}
		$s16 = {25 00 73 00 5c 00 69 00 6e 00 69 00 5c 00 2a 00 2e 00 64 00 61 00 74 00}
		$s17 = {70 00 63 00 69 00 6e 00 69 00 74 00 2e 00 65 00 78 00 65 00}
		$s18 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 77 00 77 00 77 00 2e 00 70 00 63 00 73 00 68 00 61 00 72 00 65 00 2e 00 63 00 6e 00}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 6000KB and 3 of them
}

rule pw_inspector : hardened
{
	meta:
		description = "Chinese Hacktool Set - file pw-inspector.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "4f8e3e101098fc3da65ed06117b3cb73c0a66215"

	strings:
		$s1 = {2d 6d 20 4d 49 4e 4c 45 4e 20 20 6d 69 6e 69 6d 75 6d 20 6c 65 6e 67 74 68 20 6f 66 20 61 20 76 61 6c 69 64 20 70 61 73 73 77 6f 72 64}
		$s2 = {68 74 74 70 3a 2f 2f 77 77 77 2e 74 68 63 2e 6f 72 67}
		$s3 = {55 73 65 20 66 6f 72 20 68 61 63 6b 69 6e 67 3a 20 74 72 69 6d 20 79 6f 75 72 20 64 69 63 74 69 6f 6e 61 72 79 20 66 69 6c 65 20 74 6f 20 74 68 65 20 70 77 20 72 65 71 75 69 72 65 6d 65 6e 74 73 20 6f 66 20 74 68 65 20 74 61 72 67 65 74 2e}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 460KB and all of them
}

rule Dll_LoadEx : hardened
{
	meta:
		description = "Chinese Hacktool Set - file Dll_LoadEx.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "213d9d0afb22fe723ff570cf69ff8cdb33ada150"

	strings:
		$s0 = {57 00 69 00 4e 00 72 00 4f 00 4f 00 74 00 40 00 31 00 32 00 36 00 2e 00 63 00 6f 00 6d 00}
		$s1 = {44 00 6c 00 6c 00 5f 00 4c 00 6f 00 61 00 64 00 45 00 78 00 2e 00 45 00 58 00 45 00}
		$s3 = {59 6f 75 20 41 6c 72 65 61 64 79 20 4c 6f 61 64 65 64 20 54 68 69 73 20 44 4c 4c 20 21 20 3a 28}
		$s10 = {44 00 6c 00 6c 00 5f 00 4c 00 6f 00 61 00 64 00 45 00 78 00 20 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 20 00}
		$s17 = {43 61 6e 27 74 20 4c 6f 61 64 20 54 68 69 73 20 44 6c 6c 20 21 20 3a 28}
		$s18 = {57 00 69 00 4e 00 72 00 4f 00 4f 00 74 00}
		$s20 = {20 00 44 00 6c 00 6c 00 5f 00 4c 00 6f 00 61 00 64 00 45 00 78 00 28 00 26 00 41 00 29 00 2e 00 2e 00 2e 00}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 120KB and 3 of them
}

rule dat_report : hardened
{
	meta:
		description = "Chinese Hacktool Set - file report.dll"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "4582a7c1d499bb96dad8e9b227e9d5de9becdfc2"

	strings:
		$s1 = {3c 61 20 68 72 65 66 3d 22 68 74 74 70 3a 2f 2f 77 77 77 2e 78 66 6f 63 75 73 2e 6e 65 74 22 3e 58 2d 53 63 61 6e 3c 2f 61 3e}
		$s2 = {52 45 50 4f 52 54 2d 41 4e 41 4c 59 53 49 53 2d 4f 46 2d 48 4f 53 54}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 480KB and all of them
}

rule Dos_iis7 : hardened
{
	meta:
		description = "Chinese Hacktool Set - file iis7.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "0a173c5ece2fd4ac8ecf9510e48e95f43ab68978"

	strings:
		$s0 = {5c 5c 6c 6f 63 61 6c 68 6f 73 74}
		$s1 = {69 69 73 2e 72 75 6e}
		$s3 = {3e 43 6f 75 6c 64 20 6e 6f 74 20 63 6f 6e 6e 65 63 74 6f 20 25 73}
		$s5 = {57 48 4f 41 4d 49}
		$s13 = {57 69 6e 53 74 61 30 5c 44 65 66 61 75 6c 74}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 140KB and all of them
}

rule SwitchSniffer : hardened
{
	meta:
		description = "Chinese Hacktool Set - file SwitchSniffer.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "1e7507162154f67dff4417f1f5d18b4ade5cf0cd"

	strings:
		$s0 = {4e 00 65 00 78 00 74 00 53 00 65 00 63 00 75 00 72 00 69 00 74 00 79 00 2e 00 4e 00 45 00 54 00}
		$s2 = {53 00 77 00 69 00 74 00 63 00 68 00 53 00 6e 00 69 00 66 00 66 00 65 00 72 00 20 00 53 00 65 00 74 00 75 00 70 00}

	condition:
		uint16( 0 ) == 0x5a4d and all of them
}

rule dbexpora : hardened
{
	meta:
		description = "Chinese Hacktool Set - file dbexpora.dll"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "b55b007ef091b2f33f7042814614564625a8c79f"

	strings:
		$s0 = {53 45 4c 45 43 54 20 41 2e 55 53 45 52 20 46 52 4f 4d 20 53 59 53 2e 55 53 45 52 5f 55 53 45 52 53 20 41 20}
		$s12 = {4f 43 49 20 38 20 2d 20 4f 43 49 44 65 73 63 72 69 70 74 6f 72 46 72 65 65}
		$s13 = {4f 52 41 43 6f 6d 6d 61 6e 64 20 2a}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 835KB and all of them
}

rule SQLCracker : hardened
{
	meta:
		description = "Chinese Hacktool Set - file SQLCracker.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "1aa5755da1a9b050c4c49fc5c58fa133b8380410"

	strings:
		$s0 = {6d 73 76 62 76 6d 36 30 2e 64 6c 6c}
		$s1 = {5f 43 49 63 6f 73}
		$s2 = {6b 65 72 6e 65 6c 33 32 2e 64 6c 6c}
		$s3 = {63 4b 6d 68 56}
		$s4 = {30 00 38 00 30 00 34 00 30 00 34 00 42 00 30 00}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 125KB and all of them
}

rule FreeVersion_debug : hardened
{
	meta:
		description = "Chinese Hacktool Set - file debug.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "d11e6c6f675b3be86e37e50184dadf0081506a89"

	strings:
		$s0 = {63 3a 5c 44 6f 63 75 6d 65 6e 74 73 20 61 6e 64 20 53 65 74 74 69 6e 67 73 5c 41 64 6d 69 6e 69 73 74 72 61 74 6f 72 5c}
		$s1 = {47 6f 74 20 57 4d 49 20 70 72 6f 63 65 73 73 20 50 69 64 3a 20 25 64}
		$s2 = {54 68 69 73 20 65 78 70 6c 6f 69 74 20 77 69 6c 6c 20 65 78 65 63 75 74 65}
		$s6 = {46 6f 75 6e 64 20 74 6f 6b 65 6e 20 25 73 20}
		$s7 = {52 75 6e 6e 69 6e 67 20 72 65 76 65 72 73 65 20 73 68 65 6c 6c}
		$s10 = {77 6d 69 70 72 76 73 65 2e 65 78 65}
		$s12 = {53 45 4c 45 43 54 20 2a 20 46 52 4f 4d 20 49 49 73 57 65 62 49 6e 66 6f}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 820KB and 3 of them
}

rule Dos_look : hardened
{
	meta:
		description = "Chinese Hacktool Set - file look.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "e1a37f31170e812185cf00a838835ee59b8f64ba"

	strings:
		$s1 = {3c 64 65 73 63 72 69 70 74 69 6f 6e 3e 43 48 4b 65 6e 20 51 51 3a 34 31 39 30 31 32 39 38 3c 2f 64 65 73 63 72 69 70 74 69 6f 6e 3e}
		$s2 = {76 65 72 73 69 6f 6e 3d 22 39 2e 39 2e 39 2e 39 22}
		$s3 = {6e 61 6d 65 3d 22 43 48 2e 4b 65 6e 2e 54 6f 6f 6c 22}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 40KB and all of them
}

rule NtGodMode : hardened
{
	meta:
		description = "Chinese Hacktool Set - file NtGodMode.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "8baac735e37523d28fdb6e736d03c67274f7db77"

	strings:
		$s0 = {74 6f 20 48 4f 53 54 21}
		$s1 = {53 53 2e 45 58 45}
		$s5 = {6c 73 74 72 6c 65 6e 30}
		$s6 = {56 69 72 74 75 61 6c}
		$s19 = {52 74 6c 55 6e 77}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 45KB and all of them
}

rule Dos_NC : hardened
{
	meta:
		description = "Chinese Hacktool Set - file NC.EXE"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "57f0839433234285cc9df96198a6ca58248a4707"

	strings:
		$s1 = {6e 63 20 2d 6c 20 2d 70 20 70 6f 72 74 20 5b 6f 70 74 69 6f 6e 73 5d 20 5b 68 6f 73 74 6e 61 6d 65 5d 20 5b 70 6f 72 74 5d}
		$s2 = {69 6e 76 61 6c 69 64 20 63 6f 6e 6e 65 63 74 69 6f 6e 20 74 6f 20 5b 25 73 5d 20 66 72 6f 6d 20 25 73 20 5b 25 73 5d 20 25 64}
		$s3 = {70 6f 73 74 2d 72 63 76 20 67 65 74 73 6f 63 6b 6e 61 6d 65 20 66 61 69 6c 65 64}
		$s4 = {46 61 69 6c 65 64 20 74 6f 20 65 78 65 63 75 74 65 20 73 68 65 6c 6c 2c 20 65 72 72 6f 72 20 3d 20 25 73}
		$s5 = {55 44 50 20 6c 69 73 74 65 6e 20 6e 65 65 64 73 20 2d 70 20 61 72 67}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 290KB and all of them
}

rule WebCrack4_RouterPasswordCracking : hardened
{
	meta:
		description = "Chinese Hacktool Set - file WebCrack4-RouterPasswordCracking.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "00c68d1b1aa655dfd5bb693c13cdda9dbd34c638"

	strings:
		$s0 = {68 74 74 70 3a 2f 2f 77 77 77 2e 73 69 74 65 2e 63 6f 6d 2f 74 65 73 74 2e 64 6c 6c 3f 75 73 65 72 3d 25 55 53 45 52 4e 41 4d 45 26 70 61 73 73 3d 25 50 41 53 53 57 4f 52 44}
		$s1 = {55 73 65 72 6e 61 6d 65 3a 20 22 25 73 22 2c 20 50 61 73 73 77 6f 72 64 3a 20 22 25 73 22 2c 20 52 65 6d 61 72 6b 73 3a 20 22 25 73 22}
		$s14 = {75 73 65 72 3a 22 25 73 22 20 70 61 73 73 3a 20 22 25 73 22 20 72 65 73 75 6c 74 3d 22 25 73 22}
		$s16 = {4d 6f 7a 69 6c 6c 61 2f 34 2e 30 20 28 63 6f 6d 70 61 74 69 62 6c 65 3b 20 4d 53 49 45 20 34 2e 30 31 3b 20 57 69 6e 64 6f 77 73 20 4e 54 29}
		$s20 = {4c 00 69 00 73 00 74 00 20 00 63 00 6f 00 75 00 6e 00 74 00 20 00 6f 00 75 00 74 00 20 00 6f 00 66 00 20 00 62 00 6f 00 75 00 6e 00 64 00 73 00 20 00 28 00 25 00 64 00 29 00 2b 00 4f 00 70 00 65 00 72 00 61 00 74 00 69 00 6f 00 6e 00 20 00 6e 00 6f 00 74 00 20 00 61 00 6c 00 6c 00 6f 00 77 00 65 00 64 00 20 00 6f 00 6e 00 20 00 73 00 6f 00 72 00 74 00 65 00 64 00 20 00 73 00 74 00 72 00 69 00 6e 00 67 00 20 00 6c 00 69 00 73 00 74 00 25 00 53 00 74 00 72 00 69 00 6e 00 67 00}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 5000KB and 2 of them
}

rule HScan_v1_20_oncrpc : hardened
{
	meta:
		description = "Chinese Hacktool Set - file oncrpc.dll"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "e8f047eed8d4f6d2f5dbaffdd0e6e4a09c5298a2"

	strings:
		$s1 = {63 6c 6e 74 5f 72 61 77 2e 63 20 2d 20 46 61 74 61 6c 20 68 65 61 64 65 72 20 73 65 72 69 61 6c 69 7a 61 74 69 6f 6e 20 65 72 72 6f 72 2e}
		$s2 = {73 76 63 74 63 70 5f 2e 63 20 2d 20 63 61 6e 6e 6f 74 20 67 65 74 73 6f 63 6b 6e 61 6d 65 20 6f 72 20 6c 69 73 74 65 6e}
		$s3 = {74 6f 6f 20 6d 61 6e 79 20 63 6f 6e 6e 65 63 74 69 6f 6e 73 20 28 25 64 29 2c 20 63 6f 6d 70 69 6c 61 74 69 6f 6e 20 63 6f 6e 73 74 61 6e 74 20 46 44 5f 53 45 54 53 49 5a 45 20 77 61 73 20 6f 6e 6c 79 20 25 64}
		$s4 = {73 76 63 5f 72 75 6e 3a 20 2d 20 73 65 6c 65 63 74 20 66 61 69 6c 65 64}
		$s5 = {40 28 23 29 62 69 6e 64 72 65 73 76 70 6f 72 74 2e 63}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 340KB and 4 of them
}

rule hscan_gui : hardened
{
	meta:
		description = "Chinese Hacktool Set - file hscan-gui.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "1885f0b7be87f51c304b39bc04b9423539825c69"

	strings:
		$s0 = {48 00 73 00 63 00 61 00 6e 00 2e 00 45 00 58 00 45 00}
		$s1 = {52 65 73 74 54 6f 6f 6c 2e 45 58 45}
		$s3 = {48 00 73 00 63 00 61 00 6e 00 20 00 41 00 70 00 70 00 6c 00 69 00 63 00 61 00 74 00 69 00 6f 00 6e 00 20 00}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 550KB and all of them
}

rule S_MultiFunction_Scanners_s : hardened
{
	meta:
		description = "Chinese Hacktool Set - file s.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "79b60ffa1c0f73b3c47e72118e0f600fcd86b355"

	strings:
		$s0 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 74 65 6d 70 5c 70 6f 6a 69 65 2e 65 78 65 20 2f 6c 3d}
		$s1 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 74 65 6d 70 5c 73 2e 65 78 65}
		$s2 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 74 65 6d 70 5c 73 2e 65 78 65 20 74 63 70 20}
		$s3 = {65 78 70 6c 6f 72 65 72 2e 65 78 65 20 68 74 74 70 3a 2f 2f 77 77 77 2e 68 61 63 6b 64 6f 73 2e 63 6f 6d}
		$s4 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 74 65 6d 70 5c 70 6f 6a 69 65 2e 65 78 65}
		$s5 = {46 61 69 6c 65 64 20 74 6f 20 72 65 61 64 20 66 69 6c 65 20 6f 72 20 69 6e 76 61 6c 69 64 20 64 61 74 61 20 69 6e 20 66 69 6c 65 21}
		$s6 = {77 77 77 2e 68 61 63 6b 64 6f 73 2e 63 6f 6d}
		$s7 = {57 54 4e 45 20 2f 20 4d 41 44 45 20 42 59 20 45 20 43 4f 4d 50 49 4c 45 52 20 2d 20 57 55 54 41 4f 20}
		$s11 = {54 68 65 20 69 6e 74 65 72 66 61 63 65 20 6f 66 20 6b 65 72 6e 65 6c 20 6c 69 62 72 61 72 79 20 69 73 20 69 6e 76 61 6c 69 64 21}
		$s12 = {65 76 65 6e 74 76 77 72}
		$s13 = {46 61 69 6c 65 64 20 74 6f 20 64 65 63 6f 6d 70 72 65 73 73 20 64 61 74 61 21}
		$s14 = {4e 4f 54 45 50 41 44 2e 45 58 45 20 72 65 73 75 6c 74 2e 74 78 74}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 8000KB and 4 of them
}

rule Dos_GetPass : hardened
{
	meta:
		description = "Chinese Hacktool Set - file GetPass.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "d18d952b24110b83abd17e042f9deee679de6a1a"

	strings:
		$s0 = {47 65 74 4c 6f 67 6f 6e 53}
		$s3 = {2f 73 68 6f 77 74 68 72 65 61 64 2e 70 68 70 3f 74 3d 31 35 36 36 34 33}
		$s8 = {54 6f 20 52 75 6e 20 41 73 20 41 64 6d 69 6e 69 73 74}
		$s18 = {45 6e 61 62 6c 65 44 65 62 75 67 50 72 69 76 69 6c 65 67}
		$s19 = {73 65 64 65 62 75 67 6e 61 6d 65 56 61 6c 75 65}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 890KB and all of them
}

rule update_PcMain : hardened
{
	meta:
		description = "Chinese Hacktool Set - file PcMain.dll"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "aa68323aaec0269b0f7e697e69cce4d00a949caa"

	strings:
		$s0 = {55 73 65 72 2d 41 67 65 6e 74 3a 20 4d 6f 7a 69 6c 6c 61 2f 34 2e 30 20 28 63 6f 6d 70 61 74 69 62 6c 65 3b 20 4d 53 49 45 20 37 2e 30 3b 20 57 69 6e 64 6f 77 73 20 4e 54 20 35 2e 32 3b 20 2e 4e 45 54 20 43 4c 52 20 31 2e 31 2e 34 33 32 32}
		$s1 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 53 76 63 48 6f 73 74}
		$s2 = {53 4f 46 54 57 41 52 45 5c 43 6c 61 73 73 65 73 5c 48 54 54 50 5c 73 68 65 6c 6c 5c 6f 70 65 6e 5c 63 6f 6d 6d 61 6e 64}
		$s3 = {5c 73 76 63 68 6f 73 74 2e 65 78 65 20 2d 6b 20}
		$s4 = {53 59 53 54 45 4d 5c 43 6f 6e 74 72 6f 6c 53 65 74 30 30 31 5c 53 65 72 76 69 63 65 73 5c 25 73}
		$s9 = {47 6c 6f 62 61 6c 5c 25 73 2d 6b 65 79 2d 65 76 65 6e 74}
		$s10 = {25 64 25 64 2e 65 78 65}
		$s14 = {25 64 2e 65 78 65}
		$s15 = {47 6c 6f 62 61 6c 5c 25 73 2d 6b 65 79 2d 6d 65 74 75 78}
		$s18 = {47 45 54 20 2f 20 48 54 54 50 2f 31 2e 31}
		$s19 = {5c 53 65 72 76 69 63 65 73 5c}
		$s20 = {71 79 30 30 31 69 64 3d 25 64 3b 71 79 30 30 31 67 75 69 64 3d 25 73}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 500KB and 4 of them
}

rule Dos_sys : hardened
{
	meta:
		description = "Chinese Hacktool Set - file sys.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "b5837047443f8bc62284a0045982aaae8bab6f18"

	strings:
		$s0 = {27 53 65 44 65 62 75 67 50 72 69 76 69 6c 65 67 65 4f 70 65 6e 20}
		$s6 = {41 75 74 68 6f 72 3a 20 43 79 67 30 37 2a 32}
		$s12 = {66 72 6f 6d 20 67 6f 6c 64 73 37 6e 5b 4c 41 47 5d 27 4a}
		$s14 = {44 41 4d 41 47 45}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 150KB and all of them
}

rule dat_xpf : hardened
{
	meta:
		description = "Chinese Hacktool Set - file xpf.sys"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "761125ab594f8dc996da4ce8ce50deba49c81846"

	strings:
		$s1 = {55 6e 48 6f 6f 6b 20 49 6f 47 65 74 44 65 76 69 63 65 4f 62 6a 65 63 74 50 6f 69 6e 74 65 72 20 6f 6b 21}
		$s2 = {5c 00 44 00 65 00 76 00 69 00 63 00 65 00 5c 00 58 00 53 00 63 00 61 00 6e 00 50 00 46 00}
		$s3 = {5c 00 44 00 6f 00 73 00 44 00 65 00 76 00 69 00 63 00 65 00 73 00 5c 00 58 00 53 00 63 00 61 00 6e 00 50 00 46 00}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 25KB and all of them
}

rule Project1 : hardened
{
	meta:
		description = "Chinese Hacktool Set - file Project1.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "d1a5e3b646a16a7fcccf03759bd0f96480111c96"

	strings:
		$s1 = {45 58 45 43 20 6d 61 73 74 65 72 2e 64 62 6f 2e 73 70 5f 61 64 64 65 78 74 65 6e 64 65 64 70 72 6f 63 20 27 78 70 5f 63 6d 64 73 68 65 6c 6c 27 2c 27 78 70 6c 6f 67 37 30 2e 64 6c 6c 27}
		$s2 = {50 61 73 73 77 6f 72 64 2e 74 78 74}
		$s3 = {4c 6f 67 69 6e 50 72 6f 6d 70 74}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 5000KB and all of them
}

rule Arp_EMP_v1_0 : hardened
{
	meta:
		description = "Chinese Hacktool Set - file Arp EMP v1.0.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "ae4954c142ad1552a2abaef5636c7ef68fdd99ee"

	strings:
		$s0 = {41 00 72 00 70 00 20 00 45 00 4d 00 50 00 20 00 76 00 31 00 2e 00 30 00 2e 00 65 00 78 00 65 00}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 800KB and all of them
}

rule CN_Tools_MyUPnP : hardened
{
	meta:
		description = "Chinese Hacktool Set - file MyUPnP.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "15b6fca7e42cd2800ba82c739552e7ffee967000"

	strings:
		$s1 = {3c 64 65 73 63 72 69 70 74 69 6f 6e 3e 42 59 54 45 4c 49 4e 4b 45 52 2e 43 4f 4d 3c 2f 64 65 73 63 72 69 70 74 69 6f 6e 3e}
		$s2 = {6d 79 75 70 6e 70 2e 65 78 65}
		$s3 = {4c 4f 41 44 45 52 20 45 52 52 4f 52}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 1500KB and all of them
}

rule CN_Tools_Shiell : hardened
{
	meta:
		description = "Chinese Hacktool Set - file Shiell.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "b432d80c37abe354d344b949c8730929d8f9817a"

	strings:
		$s1 = {43 3a 5c 55 73 65 72 73 5c 54 6f 6e 67 5c 44 6f 63 75 6d 65 6e 74 73 5c 56 69 73 75 61 6c 20 53 74 75 64 69 6f 20 32 30 31 32 5c 50 72 6f 6a 65 63 74 73 5c 53 68 69 66 74 20 73 68 65 6c 6c}
		$s2 = {43 00 3a 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 53 00 68 00 69 00 65 00 6c 00 6c 00 2e 00 65 00 78 00 65 00}
		$s3 = {53 00 68 00 69 00 66 00 74 00 20 00 73 00 68 00 65 00 6c 00 6c 00 2e 00 65 00 78 00 65 00}
		$s4 = {22 00 20 00 2f 00 76 00 20 00 64 00 65 00 62 00 75 00 67 00 67 00 65 00 72 00 20 00 2f 00 74 00 20 00 52 00 45 00 47 00 5f 00 53 00 5a 00 20 00 2f 00 64 00 20 00 22 00}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 1500KB and 2 of them
}

rule cndcom_cndcom : hardened
{
	meta:
		description = "Chinese Hacktool Set - file cndcom.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "08bbe6312342b28b43201125bd8c518531de8082"

	strings:
		$s1 = {2d 20 52 65 77 72 69 74 74 65 6e 20 62 79 20 48 44 4d 20 6c 61 73 74 20 3c 68 64 6d 20 5b 61 74 5d 20 6d 65 74 61 73 70 6c 6f 69 74 2e 63 6f 6d 3e}
		$s2 = {2d 20 55 73 61 67 65 3a 20 25 73 20 3c 54 61 72 67 65 74 20 49 44 3e 20 3c 54 61 72 67 65 74 20 49 50 3e}
		$s3 = {2d 20 52 65 6d 6f 74 65 20 44 43 4f 4d 20 52 50 43 20 42 75 66 66 65 72 20 4f 76 65 72 66 6c 6f 77 20 45 78 70 6c 6f 69 74}
		$s4 = {2d 20 57 61 72 6e 69 6e 67 3a 54 68 69 73 20 43 6f 64 65 20 69 73 20 6d 6f 72 65 20 6c 69 6b 65 20 61 20 64 6f 73 20 74 6f 6f 6c 21 28 4d 6f 64 69 66 79 20 62 79 20 70 69 6e 67 6b 65 72 29}
		$s5 = {57 69 6e 64 6f 77 73 20 4e 54 20 53 50 36 20 28 43 68 69 6e 65 73 65 29}
		$s6 = {2d 20 4f 72 69 67 69 6e 61 6c 20 63 6f 64 65 20 62 79 20 46 6c 61 73 68 53 6b 79 20 61 6e 64 20 42 65 6e 6a 75 72 72 79}
		$s7 = {5c 00 43 00 24 00 5c 00 31 00 32 00 33 00 34 00 35 00 36 00 31 00 31 00 31 00 31 00 31 00 31 00 31 00 31 00 31 00 31 00 31 00 31 00 31 00 31 00 31 00 2e 00 64 00 6f 00 63 00}
		$s8 = {73 68 65 6c 6c 33 61 6c 6c 2e 63}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 100KB and 2 of them
}

rule IsDebug_V1_4 : hardened
{
	meta:
		description = "Chinese Hacktool Set - file IsDebug V1.4.dll"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "ca32474c358b4402421ece1cb31714fbb088b69a"

	strings:
		$s0 = {49 73 44 65 62 75 67 2e 64 6c 6c}
		$s1 = {53 00 56 00 20 00 44 00 75 00 6d 00 70 00 65 00 72 00 20 00 56 00 31 00 2e 00 30 00}
		$s2 = {28 49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 20 62 79 74 65 20 50 61 74 63 68 65 72 29}
		$s8 = {45 72 72 6f 72 20 57 72 69 74 65 4d 65 6d 6f 72 79 20 66 61 69 6c 65 64}
		$s9 = {49 73 44 65 62 75 67 50 72 65 73 65 6e 74}
		$s10 = {69 64 62 5f 41 75 74 6f 6c 6f 61 64}
		$s11 = {42 69 6e 20 46 69 6c 65 73}
		$s12 = {4d 41 53 4d 33 32 20 76 65 72 73 69 6f 6e}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 30KB and all of them
}

rule HTTPSCANNER : hardened
{
	meta:
		description = "Chinese Hacktool Set - file HTTPSCANNER.EXE"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "ae2929346944c1ea3411a4562e9d5e2f765d088a"

	strings:
		$s1 = {48 00 74 00 74 00 70 00 53 00 63 00 61 00 6e 00 6e 00 65 00 72 00 2e 00 65 00 78 00 65 00}
		$s2 = {48 00 74 00 74 00 70 00 53 00 63 00 61 00 6e 00 6e 00 65 00 72 00}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 3500KB and all of them
}

rule HScan_v1_20_PipeCmd : hardened
{
	meta:
		description = "Chinese Hacktool Set - file PipeCmd.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "64403ce63b28b544646a30da3be2f395788542d6"

	strings:
		$s1 = {25 53 79 73 74 65 6d 52 6f 6f 74 25 5c 73 79 73 74 65 6d 33 32 5c 50 69 70 65 43 6d 64 53 72 76 2e 65 78 65}
		$s2 = {50 00 69 00 70 00 65 00 43 00 6d 00 64 00 2e 00 65 00 78 00 65 00}
		$s3 = {50 6c 65 61 73 65 20 55 73 65 20 4e 54 43 6d 64 2e 65 78 65 20 52 75 6e 20 54 68 69 73 20 50 72 6f 67 72 61 6d 2e}
		$s4 = {25 73 5c 70 69 70 65 5c 25 73 25 73 25 64}
		$s5 = {5c 5c 2e 5c 70 69 70 65 5c 25 73 25 73 25 64}
		$s6 = {25 73 5c 41 44 4d 49 4e 24 5c 53 79 73 74 65 6d 33 32 5c 25 73 25 73}
		$s7 = {54 68 69 73 20 69 73 20 61 20 73 65 72 76 69 63 65 20 65 78 65 63 75 74 61 62 6c 65 21 20 43 6f 75 6c 64 6e 27 74 20 73 74 61 72 74 20 64 69 72 65 63 74 6c 79 2e}
		$s8 = {43 6f 6e 6e 65 63 74 69 6e 67 20 74 6f 20 52 65 6d 6f 74 65 20 53 65 72 76 65 72 20 2e 2e 2e 46 61 69 6c 65 64}
		$s9 = {50 00 49 00 50 00 45 00 43 00 4d 00 44 00 53 00 52 00 56 00}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 200KB and 4 of them
}

rule Dos_fp : hardened
{
	meta:
		description = "Chinese Hacktool Set - file fp.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "41d57d356098ff55fe0e1f0bcaa9317df5a2a45c"

	strings:
		$s1 = {66 70 69 70 65 20 2d 6c 20 35 33 20 2d 73 20 35 33 20 2d 72 20 38 30 20 31 39 32 2e 31 36 38 2e 31 2e 31 30 31}
		$s2 = {46 00 50 00 69 00 70 00 65 00 2e 00 65 00 78 00 65 00}
		$s3 = {68 74 74 70 3a 2f 2f 77 77 77 2e 66 6f 75 6e 64 73 74 6f 6e 65 2e 63 6f 6d}
		$s4 = {25 73 20 25 73 20 70 6f 72 74 20 25 64 2e 20 41 64 64 72 65 73 73 20 69 73 20 61 6c 72 65 61 64 79 20 69 6e 20 75 73 65}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 65KB and all of them
}

rule Dos_netstat : hardened
{
	meta:
		description = "Chinese Hacktool Set - file netstat.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "d0444b7bd936b5fc490b865a604e97c22d97e598"

	strings:
		$s0 = {77 30 33 61 32 34 30 39 2e 64 6c 6c}
		$s1 = {52 00 65 00 74 00 72 00 61 00 6e 00 73 00 6d 00 69 00 73 00 73 00 69 00 6f 00 6e 00 20 00 54 00 69 00 6d 00 65 00 6f 00 75 00 74 00 20 00 41 00 6c 00 67 00 6f 00 72 00 69 00 74 00 68 00 6d 00 20 00 20 00 20 00 20 00 3d 00 20 00 75 00 6e 00 6b 00 6e 00 6f 00 77 00 6e 00 20 00 28 00 25 00 31 00 21 00 75 00 21 00 29 00}
		$s2 = {41 00 64 00 6d 00 69 00 6e 00 69 00 73 00 74 00 72 00 61 00 74 00 69 00 76 00 65 00 20 00 53 00 74 00 61 00 74 00 75 00 73 00 20 00 20 00 3d 00 20 00 25 00 31 00 21 00 75 00 21 00}
		$s3 = {50 00 61 00 63 00 6b 00 65 00 74 00 20 00 54 00 6f 00 6f 00 20 00 42 00 69 00 67 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 25 00 31 00 21 00 2d 00 31 00 30 00 75 00 21 00 20 00 20 00 25 00 32 00 21 00 2d 00 31 00 30 00 75 00 21 00}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 150KB and all of them
}

rule CN_Tools_xsniff : hardened
{
	meta:
		description = "Chinese Hacktool Set - file xsniff.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "d61d7329ac74f66245a92c4505a327c85875c577"

	strings:
		$s0 = {78 73 69 66 66 2e 65 78 65 20 2d 70 61 73 73 20 2d 68 69 64 65 20 2d 6c 6f 67 20 70 61 73 73 2e 6c 6f 67}
		$s1 = {48 4f 53 54 3a 20 25 73 20 55 53 45 52 3a 20 25 73 2c 20 50 41 53 53 3a 20 25 73}
		$s2 = {78 73 69 66 66 2e 65 78 65 20 2d 74 63 70 20 2d 75 64 70 20 2d 61 73 63 20 2d 61 64 64 72 20 31 39 32 2e 31 36 38 2e 31 2e 31}
		$s10 = {43 6f 64 65 20 62 79 20 67 6c 61 63 69 65 72 20 3c 67 6c 61 63 69 65 72 40 78 66 6f 63 75 73 2e 6f 72 67 3e}
		$s11 = {25 2d 35 73 25 73 2d 3e 25 73 20 42 79 74 65 73 3d 25 64 20 54 54 4c 3d 25 64 20 54 79 70 65 3a 20 25 64 2c 25 64 20 49 44 3d 25 64 20 53 45 51 3d 25 64}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 220KB and 2 of them
}

rule MSSqlPass : hardened
{
	meta:
		description = "Chinese Hacktool Set - file MSSqlPass.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "172b4e31ed15d1275ac07f3acbf499daf9a055d7"

	strings:
		$s0 = {52 00 65 00 76 00 65 00 61 00 6c 00 73 00 20 00 74 00 68 00 65 00 20 00 70 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 73 00 20 00 73 00 74 00 6f 00 72 00 65 00 64 00 20 00 69 00 6e 00 20 00 74 00 68 00 65 00 20 00 52 00 65 00 67 00 69 00 73 00 74 00 72 00 79 00 20 00 62 00 79 00 20 00 45 00 6e 00 74 00 65 00 72 00 70 00 72 00 69 00 73 00 65 00 20 00 4d 00 61 00 6e 00 61 00 67 00 65 00 72 00 20 00 6f 00 66 00 20 00 53 00 51 00 4c 00 20 00 53 00 65 00 72 00 76 00 65 00 72 00}
		$s1 = {65 00 6d 00 70 00 76 00 2e 00 65 00 78 00 65 00}
		$s2 = {45 00 6e 00 74 00 65 00 72 00 70 00 72 00 69 00 73 00 65 00 20 00 4d 00 61 00 6e 00 61 00 67 00 65 00 72 00 20 00 50 00 61 00 73 00 73 00 56 00 69 00 65 00 77 00}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 120KB and all of them
}

rule WSockExpert : hardened
{
	meta:
		description = "Chinese Hacktool Set - file WSockExpert.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "2962bf7b0883ceda5e14b8dad86742f95b50f7bf"

	strings:
		$s1 = {4f 70 65 6e 50 72 6f 63 65 73 73 43 6d 64 45 78 65 63 75 74 65 21}
		$s2 = {68 74 74 70 3a 2f 2f 77 77 77 2e 68 61 63 6b 70 2e 63 6f 6d}
		$s3 = {27 00 25 00 73 00 27 00 20 00 69 00 73 00 20 00 6e 00 6f 00 74 00 20 00 61 00 20 00 76 00 61 00 6c 00 69 00 64 00 20 00 74 00 69 00 6d 00 65 00 21 00 27 00 25 00 73 00 27 00 20 00 69 00 73 00 20 00 6e 00 6f 00 74 00 20 00 61 00 20 00 76 00 61 00 6c 00 69 00 64 00 20 00 64 00 61 00 74 00 65 00 20 00 61 00 6e 00 64 00 20 00 74 00 69 00 6d 00 65 00}
		$s4 = {53 61 76 65 53 65 6c 65 63 74 65 64 46 69 6c 74 65 72 43 6d 64 45 78 65 63 75 74 65}
		$s5 = {50 61 73 73 77 6f 72 64 43 68 61 72 40}
		$s6 = {57 53 6f 63 6b 48 6f 6f 6b 2e 44 4c 4c}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 2500KB and 4 of them
}

rule Ms_Viru_racle : hardened
{
	meta:
		description = "Chinese Hacktool Set - file racle.dll"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "13116078fff5c87b56179c5438f008caf6c98ecb"

	strings:
		$s0 = {50 73 49 6e 69 74 69 61 6c 53 79 73 74 65 6d 50 72 6f 63 65 73 73 20 40 25 70}
		$s1 = {50 73 4c 6f 6f 6b 75 70 50 72 6f 63 65 73 73 42 79 50 72 6f 63 65 73 73 49 64 28 25 75 29 20 46 61 69 6c 65 64}
		$s2 = {50 73 4c 6f 6f 6b 75 70 50 72 6f 63 65 73 73 42 79 50 72 6f 63 65 73 73 49 64 28 25 75 29 20 3d 3e 20 25 70}
		$s3 = {46 69 72 73 74 53 74 61 67 65 28 29 20 4c 6f 61 64 65 64 2c 20 43 75 72 72 65 6e 74 54 68 72 65 61 64 20 40 25 70 20 53 74 61 63 6b 20 25 70 20 2d 20 25 70}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 210KB and all of them
}

rule lamescan3 : hardened
{
	meta:
		description = "Chinese Hacktool Set - file lamescan3.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "3130eefb79650dab2e323328b905e4d5d3a1d2f0"

	strings:
		$s1 = {64 69 63 5c 6c 6f 67 69 6e 6c 69 73 74 2e 74 78 74}
		$s2 = {52 61 64 6d 69 6e 2e 65 78 65}
		$s3 = {6c 61 6d 65 73 63 61 6e 33 2e 70 64 66 21}
		$s4 = {64 69 63 5c 70 61 73 73 6c 69 73 74 2e 74 78 74}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 3740KB and all of them
}

rule CN_Tools_pc : hardened
{
	meta:
		description = "Chinese Hacktool Set - file pc.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "5cf8caba170ec461c44394f4058669d225a94285"

	strings:
		$s0 = {5c 73 76 63 68 6f 73 74 2e 65 78 65}
		$s2 = {25 73 25 30 38 78 2e 30 30 31}
		$s3 = {51 79 30 30 31 53 65 72 76 69 63 65}
		$s4 = {2f 2e 4d 49 4b 59}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 300KB and all of them
}

rule Dos_Down64 : hardened
{
	meta:
		description = "Chinese Hacktool Set - file Down64.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "43e455e43b49b953e17a5b885ffdcdf8b6b23226"

	strings:
		$s1 = {43 00 3a 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 54 00 65 00 6d 00 70 00 5c 00 44 00 6f 00 77 00 6e 00 2e 00 74 00 78 00 74 00}
		$s2 = {43 00 3a 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 54 00 65 00 6d 00 70 00 5c 00 43 00 6d 00 64 00 2e 00 74 00 78 00 74 00}
		$s3 = {43 00 3a 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 54 00 65 00 6d 00 70 00 5c 00}
		$s4 = {50 72 6f 63 65 73 73 58 45 6c 65 6d 65 6e 74}
		$s8 = {64 00 6f 00 77 00 6e 00 2e 00 65 00 78 00 65 00}
		$s20 = {73 65 74 5f 54 69 6d 65 72 31}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 150KB and all of them
}

rule epathobj_exp32 : hardened
{
	meta:
		description = "Chinese Hacktool Set - file epathobj_exp32.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "ed86ff44bddcfdd630ade8ced39b4559316195ba"

	strings:
		$s0 = {57 61 74 63 68 64 6f 67 20 74 68 72 65 61 64 20 25 64 20 77 61 69 74 69 6e 67 20 6f 6e 20 4d 75 74 65 78}
		$s1 = {45 78 70 6c 6f 69 74 20 6f 6b 20 72 75 6e 20 63 6f 6d 6d 61 6e 64}
		$s2 = {5c 65 70 61 74 68 6f 62 6a 5f 65 78 70 5c 52 65 6c 65 61 73 65 5c 65 70 61 74 68 6f 62 6a 5f 65 78 70 2e 70 64 62}
		$s3 = {41 6c 6c 6c 6f 63 61 74 65 64 20 75 73 65 72 73 70 61 63 65 20 50 41 54 48 52 45 43 4f 52 44 20 28 29 20 25 70}
		$s4 = {4d 75 74 65 78 20 6f 62 6a 65 63 74 20 64 69 64 20 6e 6f 74 20 74 69 6d 65 6f 75 74 2c 20 6c 69 73 74 20 6e 6f 74 20 70 61 74 63 68 65 64}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 270KB and all of them
}

rule Tools_unknown : hardened
{
	meta:
		description = "Chinese Hacktool Set - file unknown.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "4be8270c4faa1827177e2310a00af2d5bcd2a59f"

	strings:
		$s1 = {4e 00 6f 00 20 00 64 00 61 00 74 00 61 00 20 00 74 00 6f 00 20 00 72 00 65 00 61 00 64 00 2e 00 24 00 43 00 61 00 6e 00 20 00 6e 00 6f 00 74 00 20 00 62 00 69 00 6e 00 64 00 20 00 69 00 6e 00 20 00 70 00 6f 00 72 00 74 00 20 00 72 00 61 00 6e 00 67 00 65 00 20 00 28 00 25 00 64 00 20 00 2d 00 20 00 25 00 64 00 29 00}
		$s2 = {47 45 54 20 2f 6f 6b 2e 61 73 70 3f 69 64 3d 31 5f 5f 73 71 6c 5f 5f 20 48 54 54 50 2f 31 2e 31}
		$s3 = {4d 6f 7a 69 6c 6c 61 2f 34 2e 30 20 28 63 6f 6d 70 61 74 69 62 6c 65 3b 20 4d 53 49 45 20 36 2e 30 3b 20 57 69 6e 64 6f 77 73 20 4e 54 20 35 2e 30 29}
		$s4 = {46 00 61 00 69 00 6c 00 65 00 64 00 20 00 74 00 6f 00 20 00 63 00 6c 00 65 00 61 00 72 00 20 00 74 00 61 00 62 00 20 00 63 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 20 00 46 00 61 00 69 00 6c 00 65 00 64 00 20 00 74 00 6f 00 20 00 64 00 65 00 6c 00 65 00 74 00 65 00 20 00 74 00 61 00 62 00 20 00 61 00 74 00 20 00 69 00 6e 00 64 00 65 00 78 00 20 00 25 00 64 00 22 00 46 00 61 00 69 00 6c 00 65 00 64 00 20 00 74 00 6f 00 20 00 72 00 65 00 74 00 72 00 69 00 65 00 76 00 65 00}
		$s5 = {48 6f 73 74 3a 20 31 32 37 2e 30 2e 30 2e 31}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 2500KB and 4 of them
}

rule PLUGIN_AJunk : hardened
{
	meta:
		description = "Chinese Hacktool Set - file AJunk.dll"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "eb430fcfe6d13b14ff6baa4b3f59817c0facec00"

	strings:
		$s1 = {41 4a 75 6e 6b 2e 64 6c 6c}
		$s2 = {41 00 4a 00 75 00 6e 00 6b 00 2e 00 44 00 4c 00 4c 00}
		$s3 = {41 00 4a 00 75 00 6e 00 6b 00 20 00 44 00 79 00 6e 00 61 00 6d 00 69 00 63 00 20 00 4c 00 69 00 6e 00 6b 00 20 00 4c 00 69 00 62 00 72 00 61 00 72 00 79 00}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 560KB and all of them
}

rule IISPutScanner : hardened
{
	meta:
		description = "Chinese Hacktool Set - file IISPutScanner.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "9869c70d6a9ec2312c749aa17d4da362fa6e2592"

	strings:
		$s2 = {4b 45 52 4e 45 4c 33 32 2e 44 4c 4c}
		$s3 = {41 44 56 41 50 49 33 32 2e 44 4c 4c}
		$s4 = {56 45 52 53 49 4f 4e 2e 44 4c 4c}
		$s5 = {57 53 4f 43 4b 33 32 2e 44 4c 4c}
		$s6 = {43 4f 4d 43 54 4c 33 32 2e 44 4c 4c}
		$s7 = {47 44 49 33 32 2e 44 4c 4c}
		$s8 = {53 48 45 4c 4c 33 32 2e 44 4c 4c}
		$s9 = {55 53 45 52 33 32 2e 44 4c 4c}
		$s10 = {4f 4c 45 41 55 54 33 32 2e 44 4c 4c}
		$s11 = {4c 6f 61 64 4c 69 62 72 61 72 79 41}
		$s12 = {47 65 74 50 72 6f 63 41 64 64 72 65 73 73}
		$s13 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74}
		$s14 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63}
		$s15 = {56 69 72 74 75 61 6c 46 72 65 65}
		$s16 = {45 78 69 74 50 72 6f 63 65 73 73}
		$s17 = {52 65 67 43 6c 6f 73 65 4b 65 79}
		$s18 = {47 65 74 46 69 6c 65 56 65 72 73 69 6f 6e 49 6e 66 6f 41}
		$s19 = {49 6d 61 67 65 4c 69 73 74 5f 41 64 64}
		$s20 = {42 69 74 42 6c 74}
		$s21 = {53 68 65 6c 6c 45 78 65 63 75 74 65 41}
		$s22 = {41 63 74 69 76 61 74 65 4b 65 79 62 6f 61 72 64 4c 61 79 6f 75 74}
		$s23 = {42 00 42 00 41 00 42 00 4f 00 52 00 54 00}
		$s25 = {42 00 42 00 43 00 41 00 4e 00 43 00 45 00 4c 00}
		$s26 = {42 00 42 00 43 00 4c 00 4f 00 53 00 45 00}
		$s27 = {42 00 42 00 48 00 45 00 4c 00 50 00}
		$s28 = {42 00 42 00 49 00 47 00 4e 00 4f 00 52 00 45 00}
		$s29 = {50 00 52 00 45 00 56 00 49 00 45 00 57 00 47 00 4c 00 59 00 50 00 48 00}
		$s30 = {44 00 4c 00 47 00 54 00 45 00 4d 00 50 00 4c 00 41 00 54 00 45 00}
		$s31 = {54 00 41 00 42 00 4f 00 55 00 54 00 42 00 4f 00 58 00}
		$s32 = {54 00 46 00 4f 00 52 00 4d 00 31 00}
		$s33 = {4d 00 41 00 49 00 4e 00 49 00 43 00 4f 00 4e 00}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 500KB and filesize > 350KB and all of them
}

rule IDTools_For_WinXP_IdtTool_2 : hardened
{
	meta:
		description = "Chinese Hacktool Set - file IdtTool.sys"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "07feb31dd21d6f97614118b8a0adf231f8541a67"

	strings:
		$s0 = {5c 00 44 00 65 00 76 00 69 00 63 00 65 00 5c 00 64 00 65 00 76 00 49 00 64 00 74 00 54 00 6f 00 6f 00 6c 00}
		$s1 = {49 6f 44 65 6c 65 74 65 53 79 6d 62 6f 6c 69 63 4c 69 6e 6b}
		$s3 = {49 6f 44 65 6c 65 74 65 44 65 76 69 63 65}
		$s6 = {49 6f 43 72 65 61 74 65 53 79 6d 62 6f 6c 69 63 4c 69 6e 6b}
		$s7 = {49 6f 43 72 65 61 74 65 44 65 76 69 63 65}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 7KB and all of them
}

rule hkmjjiis6 : hardened
{
	meta:
		description = "Chinese Hacktool Set - file hkmjjiis6.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "4cbc6344c6712fa819683a4bd7b53f78ea4047d7"

	strings:
		$s1 = {63 6f 6d 73 70 65 63}
		$s2 = {75 73 65 72 33 32 2e 64 6c 6c 79}
		$s3 = {72 75 6e 74 69 6d 65 20 65 72 72 6f 72}
		$s4 = {57 69 6e 53 74 61 30 5c 44 65 66 61 75}
		$s5 = {41 70 70 49 44 46 6c 61 67 73}
		$s6 = {47 65 74 4c 61 67}
		$s7 = {2a 20 46 52 4f 4d 20 49 49 73 57 65 62 49 6e 66 6f}
		$s8 = {77 6d 69 70 72 76 73 65 2e 65 78 65}
		$s9 = {4c 6f 6f 6b 75 70 41 63 63}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 70KB and all of them
}

rule Dos_lcx : hardened
{
	meta:
		description = "Chinese Hacktool Set - file lcx.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "b6ad5dd13592160d9f052bb47b0d6a87b80a406d"

	strings:
		$s0 = {63 3a 5c 55 73 65 72 73 5c 63 61 72 65 66 75 6c 5f 73 6e 6f 77 5c}
		$s1 = {44 65 73 6b 74 6f 70 5c 48 74 72 61 6e 5c 52 65 6c 65 61 73 65 5c 48 74 72 61 6e 2e 70 64 62}
		$s3 = {5b 53 45 52 56 45 52 5d 63 6f 6e 6e 65 63 74 69 6f 6e 20 74 6f 20 25 73 3a 25 64 20 65 72 72 6f 72}
		$s4 = {2d 74 72 61 6e 20 20 3c 43 6f 6e 6e 65 63 74 50 6f 72 74 3e 20 3c 54 72 61 6e 73 6d 69 74 48 6f 73 74 3e 20 3c 54 72 61 6e 73 6d 69 74 50 6f 72 74 3e}
		$s6 = {3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 20 43 6f 64 65 20 62 79 20 6c 69 6f 6e 20 26 20 62 6b 62 6c 6c 2c 20 57 65 6c 63 6f 6d 65 20 74 6f 20 5b 75 72 6c 5d 68 74 74 70 3a 2f 2f 77 77 77 2e 63 6e 68 6f 6e 6b 65 72 2e 63 6f 6d 5b 2f 75 72 6c 5d 20}
		$s7 = {5b 2d 5d 20 54 68 65 72 65 20 69 73 20 61 20 65 72 72 6f 72 2e 2e 2e 43 72 65 61 74 65 20 61 20 6e 65 77 20 63 6f 6e 6e 65 63 74 69 6f 6e 2e}
		$s8 = {5b 2b 5d 20 41 63 63 65 70 74 20 61 20 43 6c 69 65 6e 74 20 6f 6e 20 70 6f 72 74 20 25 64 20 66 72 6f 6d 20 25 73}
		$s11 = {2d 73 6c 61 76 65 20 20 3c 43 6f 6e 6e 65 63 74 48 6f 73 74 3e 20 3c 43 6f 6e 6e 65 63 74 50 6f 72 74 3e 20 3c 54 72 61 6e 73 6d 69 74 48 6f 73 74 3e 20 3c 54 72 61 6e 73 6d 69 74 50 6f 72 74 3e}
		$s13 = {5b 2b 5d 20 4d 61 6b 65 20 61 20 43 6f 6e 6e 65 63 74 69 6f 6e 20 74 6f 20 25 73 3a 25 64 2e 2e 2e 2e}
		$s16 = {2d 6c 69 73 74 65 6e 20 3c 43 6f 6e 6e 65 63 74 50 6f 72 74 3e 20 3c 54 72 61 6e 73 6d 69 74 50 6f 72 74 3e}
		$s17 = {5b 2b 5d 20 57 61 69 74 69 6e 67 20 61 6e 6f 74 68 65 72 20 43 6c 69 65 6e 74 20 6f 6e 20 70 6f 72 74 3a 25 64 2e 2e 2e 2e}
		$s18 = {5b 2b 5d 20 41 63 63 65 70 74 20 61 20 43 6c 69 65 6e 74 20 6f 6e 20 70 6f 72 74 20 25 64 20 66 72 6f 6d 20 25 73 20 2e 2e 2e 2e 2e 2e}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 100KB and 2 of them
}

rule x_way2_5_X_way : hardened
{
	meta:
		description = "Chinese Hacktool Set - file X-way.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "8ba8530fbda3e8342e8d4feabbf98c66a322dac6"

	strings:
		$s0 = {54 00 54 00 46 00 54 00 50 00 53 00 45 00 52 00 56 00 45 00 52 00 46 00 52 00 4d 00}
		$s1 = {54 00 50 00 4f 00 52 00 54 00 53 00 43 00 41 00 4e 00 53 00 45 00 54 00 46 00 52 00 4d 00}
		$s2 = {54 00 49 00 49 00 53 00 53 00 48 00 45 00 4c 00 4c 00 46 00 52 00 4d 00}
		$s3 = {54 00 41 00 44 00 56 00 53 00 43 00 41 00 4e 00 53 00 45 00 54 00 46 00 52 00 4d 00}
		$s4 = {6e 74 77 64 62 6c 69 62 2e 64 6c 6c}
		$s5 = {54 00 53 00 4e 00 49 00 46 00 46 00 45 00 52 00 46 00 52 00 4d 00}
		$s6 = {54 00 43 00 52 00 41 00 43 00 4b 00 53 00 45 00 54 00 46 00 52 00 4d 00}
		$s7 = {54 00 43 00 52 00 41 00 43 00 4b 00 46 00 52 00 4d 00}
		$s8 = {64 62 6e 65 78 74 72 6f 77}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 1000KB and 5 of them
}

rule tools_Sqlcmd : hardened
{
	meta:
		description = "Chinese Hacktool Set - file Sqlcmd.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "99d56476e539750c599f76391d717c51c4955a33"

	strings:
		$s0 = {5b 55 73 61 67 65 5d 3a 20 20 25 73 20 3c 48 6f 73 74 4e 61 6d 65 7c 49 50 3e 20 3c 55 73 65 72 4e 61 6d 65 3e 20 3c 50 61 73 73 77 6f 72 64 3e}
		$s1 = {3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 42 79 20 75 68 68 75 68 79 28 46 65 62 20 31 38 2c 32 30 30 33 29 20 2d 20 68 74 74 70 3a 2f 2f 77 77 77 2e 63 6e 68 6f 6e 6b 65 72 2e 6e 65 74 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d}
		$s4 = {43 6f 6f 6c 21 20 43 6f 6e 6e 65 63 74 65 64 20 74 6f 20 53 51 4c 20 73 65 72 76 65 72 20 6f 6e 20 25 73 20 73 75 63 63 65 73 73 66 75 6c 6c 79 21}
		$s5 = {45 58 45 43 20 6d 61 73 74 65 72 2e 2e 78 70 5f 63 6d 64 73 68 65 6c 6c 20 22 25 73 22}
		$s6 = {3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 53 71 6c 63 6d 64 20 76 30 2e 32 31 20 46 6f 72 20 48 53 63 61 6e 20 76 31 2e 32 30 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d}
		$s10 = {45 72 72 6f 72 2c 65 78 69 74 21}
		$s11 = {53 71 6c 63 6d 64 3e}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 40KB and 3 of them
}

rule Sword1_5 : hardened
{
	meta:
		description = "Chinese Hacktool Set - file Sword1.5.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "96ee5c98e982aa8ed92cb4cedb85c7fda873740f"

	strings:
		$s3 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 77 00 77 00 77 00 2e 00 69 00 70 00 31 00 33 00 38 00 2e 00 63 00 6f 00 6d 00 2f 00 69 00 70 00 32 00 63 00 69 00 74 00 79 00 2e 00 61 00 73 00 70 00}
		$s4 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 77 00 77 00 77 00 2e 00 6d 00 64 00 35 00 64 00 65 00 63 00 72 00 79 00 70 00 74 00 65 00 72 00 2e 00 63 00 6f 00 2e 00 75 00 6b 00 2f 00 66 00 65 00 65 00 64 00 2f 00 61 00 70 00 69 00 2e 00 61 00 73 00 70 00 78 00 3f 00}
		$s6 = {4c 00 69 00 73 00 74 00 42 00 6f 00 78 00 5f 00 43 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00}
		$s13 = {6d 00 64 00 3d 00 37 00 66 00 65 00 66 00 36 00 31 00 37 00 31 00 34 00 36 00 39 00 65 00 38 00 30 00 64 00 33 00 32 00 63 00 30 00 35 00 35 00 39 00 66 00 38 00 38 00 62 00 33 00 37 00 37 00 32 00 34 00 35 00 26 00 73 00 75 00 62 00 6d 00 69 00 74 00 3d 00 4d 00 44 00 35 00 2b 00 43 00 72 00 61 00 63 00 6b 00}
		$s18 = {5c 00 53 00 65 00 74 00 2e 00 69 00 6e 00 69 00}
		$s19 = {4f 00 70 00 65 00 6e 00 46 00 69 00 6c 00 65 00 44 00 69 00 61 00 6c 00 6f 00 67 00 31 00}
		$s20 = {20 00 28 00 2a 00 2e 00 74 00 78 00 74 00 29 00 7c 00 2a 00 2e 00 74 00 78 00 74 00}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 400KB and 4 of them
}

rule Tools_scan : hardened
{
	meta:
		description = "Chinese Hacktool Set - file scan.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "c580a0cc41997e840d2c0f83962e7f8b636a5a13"

	strings:
		$s2 = {53 00 68 00 61 00 6e 00 6c 00 75 00 20 00 53 00 74 00 75 00 64 00 69 00 6f 00}
		$s3 = {5f 41 75 74 6f 41 74 74 61 63 6b 4d 61 69 6e}
		$s4 = {5f 66 72 6d 49 70 54 6f 41 64 64 72}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 3000KB and all of them
}

rule Dos_c : hardened
{
	meta:
		description = "Chinese Hacktool Set - file c.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "3deb6bd52fdac6d5a3e9a91c585d67820ab4df78"

	strings:
		$s0 = {21 57 69 6e 33 32 20 2e 45 58 45 2e}
		$s1 = {2e 4d 50 52 45 53 53 31}
		$s2 = {2e 4d 50 52 45 53 53 32}
		$s3 = {58 4f 4c 45 48 4c 50 2e 64 6c 6c}
		$s4 = {3c 2f 62 6f 64 79 3e 3c 2f 68 74 6d 6c 3e}
		$s8 = {44 74 63 47 65 74 54 72 61 6e 73 61 63 74 69 6f 6e 4d 61 6e 61 67 65 72 45 78 41}
		$s9 = {47 65 74 55 73 65 72 4e 61 6d 65 41}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 100KB and all of them
}

rule arpsniffer : hardened
{
	meta:
		description = "Chinese Hacktool Set - file arpsniffer.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "7d8753f56fc48413fc68102cff34b6583cb0066c"

	strings:
		$s1 = {53 48 45 4c 4c}
		$s2 = {50 61 63 6b 65 74 53 65 6e 64 50 61 63 6b 65 74}
		$s3 = {41 72 70 53 6e 69 66 66}
		$s4 = {70 63 61 70 5f 6c 6f 6f 70}
		$s5 = {70 61 63 6b 65 74 2e 64 6c 6c}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 120KB and all of them
}

rule pw_inspector_2 : hardened
{
	meta:
		description = "Chinese Hacktool Set - file pw-inspector.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "e0a1117ee4a29bb4cf43e3a80fb9eaa63bb377bf"

	strings:
		$s1 = {55 73 65 20 66 6f 72 20 68 61 63 6b 69 6e 67 3a 20 74 72 69 6d 20 79 6f 75 72 20 64 69 63 74 69 6f 6e 61 72 79 20 66 69 6c 65 20 74 6f 20 74 68 65 20 70 77 20 72 65 71 75 69 72 65 6d 65 6e 74 73 20 6f 66 20 74 68 65 20 74 61 72 67 65 74 2e}
		$s2 = {53 79 6e 74 61 78 3a 20 25 73 20 5b 2d 69 20 46 49 4c 45 5d 20 5b 2d 6f 20 46 49 4c 45 5d 20 5b 2d 6d 20 4d 49 4e 4c 45 4e 5d 20 5b 2d 4d 20 4d 41 58 4c 45 4e 5d 20 5b 2d 63 20 4d 49 4e 53 45 54 53 5d 20 2d 6c 20 2d 75 20 2d 6e 20 2d 70 20}
		$s3 = {50 57 2d 49 6e 73 70 65 63 74 6f 72}
		$s4 = {69 3a 6f 3a 6d 3a 4d 3a 63 3a 6c 75 6e 70 73}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 100KB and 2 of them
}

rule datPcShare : hardened
{
	meta:
		description = "Chinese Hacktool Set - file datPcShare.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "87acb649ab0d33c62e27ea83241caa43144fc1c4"

	strings:
		$s1 = {50 00 63 00 53 00 68 00 61 00 72 00 65 00 2e 00 45 00 58 00 45 00}
		$s2 = {4d 5a 4b 45 52 4e 45 4c 33 32 2e 44 4c 4c}
		$s3 = {50 00 63 00 53 00 68 00 61 00 72 00 65 00}
		$s4 = {51 00 51 00 3a 00 34 00 35 00 36 00 34 00 34 00 30 00 35 00}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 500KB and all of them
}

rule Tools_xport : hardened
{
	meta:
		description = "Chinese Hacktool Set - file xport.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "9584de562e7f8185f721e94ee3cceac60db26dda"

	strings:
		$s1 = {4d 61 74 63 68 20 6f 70 65 72 61 74 65 20 73 79 73 74 65 6d 20 66 61 69 6c 65 64 2c 20 30 78 25 30 30 30 30 34 58 3a 25 75 3a 25 64 28 57 69 6e 64 6f 77 3a 54 54 4c 3a 44 46 29}
		$s2 = {45 78 61 6d 70 6c 65 3a 20 78 70 6f 72 74 20 77 77 77 2e 78 78 78 2e 63 6f 6d 20 38 30 20 2d 6d 20 73 79 6e}
		$s3 = {25 73 20 2d 20 63 6f 6d 6d 61 6e 64 20 6c 69 6e 65 20 70 6f 72 74 20 73 63 61 6e 6e 65 72}
		$s4 = {78 70 6f 72 74 20 31 39 32 2e 31 36 38 2e 31 2e 31 20 31 2d 31 30 32 34 20 2d 74 20 32 30 30 20 2d 76}
		$s5 = {55 73 61 67 65 3a 20 78 70 6f 72 74 20 3c 48 6f 73 74 3e 20 3c 50 6f 72 74 73 20 53 63 6f 70 65 3e 20 5b 4f 70 74 69 6f 6e 73 5d}
		$s6 = {2e 5c 70 6f 72 74 2e 69 6e 69}
		$s7 = {50 6f 72 74 20 73 63 61 6e 20 63 6f 6d 70 6c 65 74 65 2c 20 74 6f 74 61 6c 20 25 64 20 70 6f 72 74 2c 20 25 64 20 70 6f 72 74 20 69 73 20 6f 70 65 6e 65 64 2c 20 75 73 65 20 25 64 20 6d 73 2e}
		$s8 = {43 6f 64 65 20 62 79 20 67 6c 61 63 69 65 72 20 3c 67 6c 61 63 69 65 72 40 78 66 6f 63 75 73 2e 6f 72 67 3e}
		$s9 = {68 74 74 70 3a 2f 2f 77 77 77 2e 78 66 6f 63 75 73 2e 6f 72 67}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 100KB and 2 of them
}

rule Pc_xai : hardened
{
	meta:
		description = "Chinese Hacktool Set - file xai.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "f285a59fd931ce137c08bd1f0dae858cc2486491"

	strings:
		$s1 = {50 00 6f 00 77 00 65 00 72 00 65 00 64 00 20 00 62 00 79 00 20 00 43 00 6f 00 6f 00 6c 00 44 00 69 00 79 00 65 00 72 00 20 00 40 00 20 00 43 00 2e 00 52 00 75 00 66 00 75 00 73 00 20 00 53 00 65 00 63 00 75 00 72 00 69 00 74 00 79 00 20 00 54 00 65 00 61 00 6d 00 20 00 30 00 35 00 2f 00 31 00 39 00 2f 00 32 00 30 00 30 00 38 00 20 00 20 00 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 77 00 77 00 77 00 2e 00 78 00 63 00 6f 00 64 00 65 00 7a 00 2e 00 63 00 6f 00 6d 00 2f 00}
		$s2 = {25 53 79 73 74 65 6d 52 6f 6f 74 25 5c 53 79 73 74 65 6d 33 32 5c}
		$s3 = {25 41 50 50 44 41 54 41 25 5c}
		$s4 = {2d 00 2d 00 2d 00 2d 00 20 00 43 00 2e 00 52 00 75 00 66 00 75 00 73 00 20 00 53 00 65 00 63 00 75 00 72 00 69 00 74 00 79 00 20 00 54 00 65 00 61 00 6d 00 20 00 2d 00 2d 00 2d 00 2d 00}
		$s5 = {77 00 77 00 77 00 2e 00 73 00 6e 00 7a 00 7a 00 6b 00 7a 00 2e 00 63 00 6f 00 6d 00}
		$s6 = {25 43 6f 6d 6d 6f 6e 50 72 6f 67 72 61 6d 46 69 6c 65 73 25 5c}
		$s7 = {47 65 74 52 61 6e 64 2e 64 6c 6c}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 3000KB and all of them
}

rule Radmin_Hash : hardened
{
	meta:
		description = "Chinese Hacktool Set - file Radmin_Hash.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "be407bd5bf5bcd51d38d1308e17a1731cd52f66b"

	strings:
		$s1 = {3c 64 65 73 63 72 69 70 74 69 6f 6e 3e 49 45 42 61 72 73 3c 2f 64 65 73 63 72 69 70 74 69 6f 6e 3e}
		$s2 = {50 45 43 6f 6d 70 61 63 74 32}
		$s3 = {52 00 61 00 64 00 6d 00 69 00 6e 00 2c 00 20 00 52 00 65 00 6d 00 6f 00 74 00 65 00 20 00 41 00 64 00 6d 00 69 00 6e 00 69 00 73 00 74 00 72 00 61 00 74 00 6f 00 72 00}
		$s4 = {52 00 61 00 64 00 6d 00 69 00 6e 00 20 00 33 00 2e 00 30 00 20 00 48 00 61 00 73 00 68 00 20 00}
		$s5 = {48 00 41 00 53 00 48 00 31 00 2e 00 30 00}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 600KB and all of them
}

rule OSEditor : hardened
{
	meta:
		description = "Chinese Hacktool Set - file OSEditor.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "6773c3c6575cf9cfedbb772f3476bb999d09403d"

	strings:
		$s1 = {4f 00 53 00 45 00 64 00 69 00 74 00 6f 00 72 00 2e 00 65 00 78 00 65 00}
		$s2 = {6e 00 65 00 74 00 73 00 61 00 66 00 65 00}
		$s3 = {4f 00 53 00 43 00 20 00 45 00 64 00 69 00 74 00 6f 00 72 00}
		$s4 = {47 49 46 38 39}
		$s5 = {55 6e 6c 6f 63 6b}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 100KB and all of them
}

rule GoodToolset_ms11011 : hardened
{
	meta:
		description = "Chinese Hacktool Set - file ms11011.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "5ad7a4962acbb6b0e3b73d77385eb91feb88b386"

	strings:
		$s0 = {5c 69 33 38 36 5c 48 65 6c 6c 6f 2e 70 64 62}
		$s1 = {4f 53 20 6e 6f 74 20 73 75 70 70 6f 72 74 65 64 2e}
		$s3 = {4e 00 6f 00 74 00 20 00 73 00 75 00 70 00 70 00 6f 00 72 00 74 00 65 00 64 00 2e 00}
		$s4 = {53 00 79 00 73 00 74 00 65 00 6d 00 44 00 65 00 66 00 61 00 75 00 6c 00 74 00 45 00 55 00 44 00 43 00 46 00 6f 00 6e 00 74 00}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 100KB and all of them
}

rule FreeVersion_release : hardened
{
	meta:
		description = "Chinese Hacktool Set - file release.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "f42e4b5748e92f7a450eb49fc89d6859f4afcebb"

	strings:
		$s1 = {2d 2d 3e 47 6f 74 20 57 4d 49 20 70 72 6f 63 65 73 73 20 50 69 64 3a 20 25 64 20}
		$s2 = {54 68 69 73 20 65 78 70 6c 6f 69 74 20 77 69 6c 6c 20 65 78 65 63 75 74 65 20 22 6e 65 74 20 75 73 65 72 20}
		$s3 = {6e 65 74 20 75 73 65 72 20 74 65 6d 70 20 31 32 33 34 35 36 20 2f 61 64 64 20 26 20 6e 65 74 20 6c 6f 63 61 6c 67 72 6f 75 70 20 61 64 6d 69 6e 69 73 74 72 61 74 6f 72 73 20 74 65 6d 70 20 2f 61 64 64}
		$s4 = {52 75 6e 6e 69 6e 67 20 72 65 76 65 72 73 65 20 73 68 65 6c 6c}
		$s5 = {77 6d 69 70 72 76 73 65 2e 65 78 65}
		$s6 = {53 45 4c 45 43 54 20 2a 20 46 52 4f 4d 20 49 49 73 57 65 62 49 6e 66 6f}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 100KB and 3 of them
}

rule churrasco : hardened
{
	meta:
		description = "Chinese Hacktool Set - file churrasco.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "a8d4c177948a8e60d63de9d0ed948c50d0151364"

	strings:
		$s1 = {44 6f 6e 65 2c 20 63 6f 6d 6d 61 6e 64 20 73 68 6f 75 6c 64 20 68 61 76 65 20 72 61 6e 20 61 73 20 53 59 53 54 45 4d 21}
		$s2 = {52 75 6e 6e 69 6e 67 20 63 6f 6d 6d 61 6e 64 20 77 69 74 68 20 53 59 53 54 45 4d 20 54 6f 6b 65 6e 2e 2e 2e}
		$s3 = {54 68 72 65 61 64 20 69 6d 70 65 72 73 6f 6e 61 74 69 6e 67 2c 20 67 6f 74 20 4e 45 54 57 4f 52 4b 20 53 45 52 56 49 43 45 20 54 6f 6b 65 6e 3a 20 30 78 25 78}
		$s4 = {46 6f 75 6e 64 20 53 59 53 54 45 4d 20 74 6f 6b 65 6e 20 30 78 25 78}
		$s5 = {54 68 72 65 61 64 20 6e 6f 74 20 69 6d 70 65 72 73 6f 6e 61 74 69 6e 67 2c 20 6c 6f 6f 6b 69 6e 67 20 66 6f 72 20 61 6e 6f 74 68 65 72 20 74 68 72 65 61 64 2e 2e 2e}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 150KB and 2 of them
}

rule x64_KiwiCmd : hardened
{
	meta:
		description = "Chinese Hacktool Set - file KiwiCmd.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "569ca4ff1a5ea537aefac4a04a2c588c566c6d86"

	strings:
		$s1 = {50 00 72 00 6f 00 63 00 65 00 73 00 73 00 20 00 4f 00 6b 00 2c 00 20 00 4d 00 65 00 6d 00 6f 00 72 00 79 00 20 00 4f 00 6b 00 2c 00 20 00 72 00 65 00 73 00 75 00 6d 00 69 00 6e 00 67 00 20 00 70 00 72 00 6f 00 63 00 65 00 73 00 73 00 20 00 3a 00 29 00}
		$s2 = {4b 00 69 00 77 00 69 00 20 00 43 00 6d 00 64 00 20 00 6e 00 6f 00 2d 00 67 00 70 00 6f 00}
		$s3 = {4b 00 69 00 77 00 69 00 41 00 6e 00 64 00 43 00 4d 00 44 00}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 400KB and 2 of them
}

rule sql1433_SQL : hardened
{
	meta:
		description = "Chinese Hacktool Set - file SQL.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "025e87deadd1c50b1021c26cb67b76b476fafd64"

	strings:
		$s0 = { 50 00 72 00 6F 00 64 00 75 00 63 00 74 00 4E 00 61 00 6D 00 65 00 00 00 00 00 31 00 34 00 33 00 33 }
		$s1 = { 50 00 72 00 6F 00 64 00 75 00 63 00 74 00 56 00 65 00 72 00 73 00 69 00 6F 00 6E 00 00 00 31 00 2C 00 34 00 2C 00 33 00 2C 00 33 }

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 90KB and all of them
}

rule CookieTools2 : hardened
{
	meta:
		description = "Chinese Hacktool Set - file CookieTools2.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "cb67797f229fdb92360319e01277e1345305eb82"

	strings:
		$s1 = {77 00 77 00 77 00 2e 00 67 00 78 00 67 00 6c 00 2e 00 63 00 6f 00 6d 00 26 00 77 00 77 00 77 00 2e 00 67 00 78 00 67 00 6c 00 2e 00 6e 00 65 00 74 00}
		$s2 = {69 70 2e 61 73 70 3f 49 50 3d}
		$s3 = {4d 53 49 45 20 35 2e 35 3b}
		$s4 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 700KB and all of them
}

rule cyclotron : hardened
{
	meta:
		description = "Chinese Hacktool Set - file cyclotron.sys"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "5b63473b6dc1e5942bf07c52c31ba28f2702b246"

	strings:
		$s1 = {5c 00 44 00 65 00 76 00 69 00 63 00 65 00 5c 00 49 00 44 00 54 00 50 00 72 00 6f 00 74 00}
		$s2 = {49 6f 44 65 6c 65 74 65 53 79 6d 62 6f 6c 69 63 4c 69 6e 6b}
		$s3 = {5c 00 3f 00 3f 00 5c 00 73 00 6c 00 49 00 44 00 54 00 50 00 72 00 6f 00 74 00}
		$s4 = {49 6f 44 65 6c 65 74 65 44 65 76 69 63 65}
		$s5 = {49 6f 43 72 65 61 74 65 53 79 6d 62 6f 6c 69 63 4c 69 6e 6b}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 3KB and all of them
}

rule xscan_gui : hardened
{
	meta:
		description = "Chinese Hacktool Set - file xscan_gui.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "a9e900510396192eb2ba4fb7b0ef786513f9b5ab"

	strings:
		$s1 = {25 73 20 2d 6d 75 74 65 78 20 25 73 20 2d 68 6f 73 74 20 25 73 20 2d 69 6e 64 65 78 20 25 64 20 2d 63 6f 6e 66 69 67 20 22 25 73 22}
		$s2 = {77 77 77 2e 74 61 72 67 65 74 2e 63 6f 6d}
		$s3 = {25 73 5c 73 63 72 69 70 74 73 5c 64 65 73 63 5c 25 73 2e 64 65 73 63}
		$s4 = {25 63 20 41 63 74 69 76 65 2f 4d 61 78 69 6d 75 6d 20 68 6f 73 74 20 74 68 72 65 61 64 3a 20 25 64 2f 25 64 2c 20 43 75 72 72 65 6e 74 2f 4d 61 78 69 6d 75 6d 20 74 68 72 65 61 64 3a 20 25 64 2f 25 64 2c 20 54 69 6d 65 28 73 29 3a 20 25 6c}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 3000KB and all of them
}

rule CN_Tools_hscan : hardened
{
	meta:
		description = "Chinese Hacktool Set - file hscan.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "17a743e40790985ececf5c66eaad2a1f8c4cffe8"

	strings:
		$s1 = {25 73 20 2d 66 20 68 6f 73 74 73 2e 74 78 74 20 2d 70 6f 72 74 20 2d 69 70 63 20 2d 70 6f 70 20 2d 6d 61 78 20 33 30 30 2c 32 30 20 2d 74 69 6d 65 20 31 30 30 30 30}
		$s2 = {25 73 20 2d 68 20 31 39 32 2e 31 36 38 2e 30 2e 31 20 31 39 32 2e 31 36 38 2e 30 2e 32 35 34 20 2d 70 6f 72 74 20 2d 66 74 70 20 2d 6d 61 78 20 32 30 30 2c 32 30}
		$s3 = {25 73 20 2d 68 20 77 77 77 2e 74 61 72 67 65 74 2e 63 6f 6d 20 2d 61 6c 6c}
		$s4 = {2e 5c 72 65 70 6f 72 74 5c 25 73 2d 25 73 2e 68 74 6d 6c}
		$s5 = {2e 5c 6c 6f 67 5c 48 73 63 61 6e 2e 6c 6f 67}
		$s6 = {5b 25 73 5d 3a 20 46 6f 75 6e 64 20 63 69 73 63 6f 20 45 6e 61 62 6c 65 20 70 61 73 73 77 6f 72 64 3a 20 25 73 20 21 21 21}
		$s7 = {25 73 40 66 74 70 73 63 61 6e 23 46 54 50 20 41 63 63 6f 75 6e 74 3a 20 20 25 73 2f 5b 6e 75 6c 6c 5d}
		$s8 = {2e 5c 63 6f 6e 66 5c 6d 79 73 71 6c 5f 70 61 73 73 2e 64 69 63}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 300KB and all of them
}

rule GoodToolset_pr : hardened
{
	meta:
		description = "Chinese Hacktool Set - file pr.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "f6676daf3292cff59ef15ed109c2d408369e8ac8"

	strings:
		$s1 = {2d 2d 3e 47 6f 74 20 57 4d 49 20 70 72 6f 63 65 73 73 20 50 69 64 3a 20 25 64 20}
		$s2 = {2d 2d 3e 54 68 69 73 20 65 78 70 6c 6f 69 74 20 67 69 76 65 73 20 79 6f 75 20 61 20 4c 6f 63 61 6c 20 53 79 73 74 65 6d 20 73 68 65 6c 6c 20}
		$s3 = {77 6d 69 70 72 76 73 65 2e 65 78 65}
		$s4 = {54 72 79 20 74 68 65 20 66 69 72 73 74 20 25 64 20 74 69 6d 65}
		$s5 = {2d 2d 3e 42 75 69 6c 64 26 26 43 68 61 6e 67 65 20 42 79 20 70 20}
		$s6 = {72 00 6f 00 6f 00 74 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 49 00 49 00 53 00 76 00 32 00}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 200KB and all of them
}

rule hydra_7_4_1_hydra : hardened
{
	meta:
		description = "Chinese Hacktool Set - file hydra.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "3411d0380a1c1ebf58a454765f94d4f1dd714b5b"

	strings:
		$s1 = {25 64 20 6f 66 20 25 64 20 74 61 72 67 65 74 25 73 25 73 63 6f 6d 70 6c 65 74 65 64 2c 20 25 6c 75 20 76 61 6c 69 64 20 70 61 73 73 77 6f 72 64 25 73 20 66 6f 75 6e 64}
		$s2 = {5b 25 64 5d 5b 73 6d 62 5d 20 48 6f 73 74 3a 20 25 73 20 41 63 63 6f 75 6e 74 3a 20 25 73 20 45 72 72 6f 72 3a 20 41 43 43 4f 55 4e 54 5f 43 48 41 4e 47 45 5f 50 41 53 53 57 4f 52 44}
		$s3 = {68 79 64 72 61 20 2d 50 20 70 61 73 73 2e 74 78 74 20 74 61 72 67 65 74 20 63 69 73 63 6f 2d 65 6e 61 62 6c 65 20 20 28 64 69 72 65 63 74 20 63 6f 6e 73 6f 6c 65 20 61 63 63 65 73 73 29}
		$s4 = {5b 25 64 5d 5b 73 6d 62 5d 20 48 6f 73 74 3a 20 25 73 20 41 63 63 6f 75 6e 74 3a 20 25 73 20 45 72 72 6f 72 3a 20 50 41 53 53 57 4f 52 44 20 45 58 50 49 52 45 44}
		$s5 = {5b 45 52 52 4f 52 5d 20 53 4d 54 50 20 4c 4f 47 49 4e 20 41 55 54 48 2c 20 65 69 74 68 65 72 20 74 68 69 73 20 61 75 74 68 20 69 73 20 64 69 73 61 62 6c 65 64}
		$s6 = {22 2f 6c 6f 67 69 6e 2e 70 68 70 3a 75 73 65 72 3d 5e 55 53 45 52 5e 26 70 61 73 73 3d 5e 50 41 53 53 5e 26 6d 69 64 3d 31 32 33 3a 69 6e 63 6f 72 72 65 63 74 22}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 1000KB and 2 of them
}

rule CN_Tools_srss_2 : hardened
{
	meta:
		description = "Chinese Hacktool Set - file srss.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "c418b30d004051bbf1b2d3be426936b95b5fea6f"

	strings:
		$x1 = {75 73 65 64 20 70 65 70 61 63 6b 21}
		$s1 = {4b 45 52 4e 45 4c 33 32 2e 64 6c 6c}
		$s2 = {4b 45 52 4e 45 4c 33 32 2e 44 4c 4c}
		$s3 = {4c 6f 61 64 4c 69 62 72 61 72 79 41}
		$s4 = {47 65 74 50 72 6f 63 41 64 64 72 65 73 73}
		$s5 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74}
		$s6 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63}
		$s7 = {56 69 72 74 75 61 6c 46 72 65 65}
		$s8 = {45 78 69 74 50 72 6f 63 65 73 73}

	condition:
		uint16( 0 ) == 0x5a4d and ( $x1 at 0 ) and filesize < 14KB and all of ( $s* )
}

rule Dos_NtGod : hardened
{
	meta:
		description = "Chinese Hacktool Set - file NtGod.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "adefd901d6bbd8437116f0170b9c28a76d4a87bf"

	strings:
		$s0 = {5c 74 65 6d 70 5c 4e 74 47 6f 64 4d 6f 64 65 2e 65 78 65}
		$s4 = {4e 74 47 6f 64 4d 6f 64 65 2e 65 78 65}
		$s10 = {6e 74 67 6f 64 2e 62 61 74}
		$s19 = {73 66 78 63 6d 64}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 250KB and all of them
}

rule CN_Tools_VNCLink : hardened
{
	meta:
		description = "Chinese Hacktool Set - file VNCLink.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "cafb531822cbc0cfebbea864489eebba48081aa1"

	strings:
		$s1 = {43 3a 5c 74 65 6d 70 5c 76 6e 63 76 69 65 77 65 72 34 2e 6c 6f 67}
		$s2 = {5b 42 4c 34 43 4b 5d 20 50 61 74 63 68 65 64 20 62 79 20 72 65 64 73 61 6e 64 20 7c 7c 20 68 74 74 70 3a 2f 2f 62 6c 61 63 6b 73 65 63 75 72 69 74 79 2e 6f 72 67}
		$s3 = {66 61 6b 65 20 72 65 6c 65 61 73 65 20 65 78 74 65 6e 64 65 64 56 6b 65 79 20 30 78 25 78 2c 20 6b 65 79 73 79 6d 20 30 78 25 78}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 580KB and 2 of them
}

rule tools_NTCmd : hardened
{
	meta:
		description = "Chinese Hacktool Set - file NTCmd.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "a3ae8659b9a673aa346a60844208b371f7c05e3c"

	strings:
		$s1 = {70 69 70 65 63 6d 64 20 5c 5c 25 73 20 2d 55 3a 25 73 20 2d 50 3a 22 22 20 25 73}
		$s2 = {5b 55 73 61 67 65 5d 3a 20 20 25 73 20 3c 48 6f 73 74 4e 61 6d 65 7c 49 50 3e 20 3c 55 73 65 72 6e 61 6d 65 3e 20 3c 50 61 73 73 77 6f 72 64 3e}
		$s3 = {70 69 70 65 63 6d 64 20 5c 5c 25 73 20 2d 55 3a 25 73 20 2d 50 3a 25 73 20 25 73}
		$s4 = {3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 42 79 20 75 68 68 75 68 79 20 28 46 65 62 20 31 38 2c 32 30 30 33 29 20 2d 20 68 74 74 70 3a 2f 2f 77 77 77 2e 63 6e 68 6f 6e 6b 65 72 2e 6e 65 74 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d}
		$s5 = {3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 4e 54 63 6d 64 20 76 30 2e 31 31 20 66 6f 72 20 48 53 63 61 6e 20 76 31 2e 32 30 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d}
		$s6 = {4e 54 63 6d 64 3e}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 80KB and 2 of them
}

rule mysql_pwd_crack : hardened
{
	meta:
		description = "Chinese Hacktool Set - file mysql_pwd_crack.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "57d1cb4d404688804a8c3755b464a6e6248d1c73"

	strings:
		$s1 = {6d 79 73 71 6c 5f 70 77 64 5f 63 72 61 63 6b 20 31 32 37 2e 30 2e 30 2e 31 20 2d 78 20 33 33 30 36 20 2d 70 20 72 6f 6f 74 20 2d 64 20 75 73 65 72 64 69 63 74 2e 74 78 74}
		$s2 = {53 75 63 63 65 73 73 66 75 6c 6c 79 20 2d 2d 3e 20 75 73 65 72 6e 61 6d 65 20 25 73 20 70 61 73 73 77 6f 72 64 20 25 73 20}
		$s3 = {7a 68 6f 75 7a 68 65 6e 40 67 6d 61 69 6c 2e 63 6f 6d 20 68 74 74 70 3a 2f 2f 7a 68 6f 75 7a 68 65 6e 2e 65 76 69 6c 6f 63 74 61 6c 2e 6f 72 67}
		$s4 = {2d 61 20 61 75 74 6f 6d 6f 64 65 20 20 61 75 74 6f 6d 61 74 69 63 20 63 72 61 63 6b 20 74 68 65 20 6d 79 73 71 6c 20 70 61 73 73 77 6f 72 64 20}
		$s5 = {6d 79 73 71 6c 5f 70 77 64 5f 63 72 61 63 6b 20 31 32 37 2e 30 2e 30 2e 31 20 2d 78 20 33 33 30 36 20 2d 61}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 100KB and 1 of them
}

rule CmdShell64 : hardened
{
	meta:
		description = "Chinese Hacktool Set - file CmdShell64.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "5b92510475d95ae5e7cd6ec4c89852e8af34acf1"

	strings:
		$s1 = {43 00 3a 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 4a 00 41 00 56 00 41 00 53 00 59 00 53 00 2e 00 45 00 58 00 45 00}
		$s2 = {53 65 72 76 69 63 65 43 6d 64 53 68 65 6c 6c}
		$s3 = {3c 21 2d 2d 20 49 66 20 79 6f 75 72 20 61 70 70 6c 69 63 61 74 69 6f 6e 20 69 73 20 64 65 73 69 67 6e 65 64 20 74 6f 20 77 6f 72 6b 20 77 69 74 68 20 57 69 6e 64 6f 77 73 20 38 2e 31 2c 20 75 6e 63 6f 6d 6d 65 6e 74 20 74 68 65 20 66 6f 6c}
		$s4 = {53 00 65 00 72 00 76 00 69 00 63 00 65 00 53 00 79 00 73 00 74 00 65 00 6d 00 53 00 68 00 65 00 6c 00 6c 00}
		$s5 = {5b 00 52 00 6f 00 6f 00 74 00 40 00 43 00 6d 00 64 00 53 00 68 00 65 00 6c 00 6c 00 20 00 7e 00 5d 00 23 00}
		$s6 = {48 00 65 00 6c 00 6c 00 6f 00 20 00 4d 00 61 00 6e 00 20 00 32 00 30 00 31 00 35 00 20 00 21 00}
		$s7 = {43 6d 64 53 68 65 6c 6c}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 30KB and 4 of them
}

rule Ms_Viru_v : hardened
{
	meta:
		description = "Chinese Hacktool Set - file v.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "ecf4ba6d1344f2f3114d52859addee8b0770ed0d"

	strings:
		$s1 = {63 3a 5c 77 69 6e 64 6f 77 73 5c 73 79 73 74 65 6d 33 32 5c 63 6f 6d 6d 61 6e 64 2e 63 6f 6d 20 2f 63 20}
		$s2 = {45 61 73 79 20 55 73 61 67 65 20 56 65 72 73 69 6f 6e 20 2d 2d 20 45 64 69 74 65 64 20 42 79 3a 20 72 61 63 6c 65 40 74 69 61 6e 36 2e 63 6f 6d}
		$s3 = {4f 48 2c 53 72 79 2e 54 6f 6f 20 6c 6f 6e 67 20 63 6f 6d 6d 61 6e 64 2e}
		$s4 = {53 75 63 63 65 73 73 21 20 43 6f 6d 6d 61 6e 64 65 72 2e}
		$s5 = {48 65 79 2c 68 6f 77 20 63 61 6e 20 72 61 63 6c 65 20 77 6f 72 6b 20 77 69 74 68 6f 75 74 20 75 72 20 63 6f 6d 6d 61 6e 64 20 3f}
		$s6 = {54 68 65 20 65 78 70 6c 6f 69 74 20 74 68 72 65 61 64 20 77 61 73 20 75 6e 61 62 6c 65 20 74 6f 20 6d 61 70 20 74 68 65 20 76 69 72 74 75 61 6c 20 38 30 38 36 20 61 64 64 72 65 73 73 20 73 70 61 63 65}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 100KB and 3 of them
}

rule CN_Tools_Vscan : hardened
{
	meta:
		description = "Chinese Hacktool Set - file Vscan.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "0365fe05e2de0f327dfaa8cd0d988dbb7b379612"

	strings:
		$s1 = {5b 2b 5d 20 55 73 61 67 65 3a 20 56 4e 43 5f 62 79 70 61 75 74 68 20 3c 74 61 72 67 65 74 3e 20 3c 73 63 61 6e 74 79 70 65 3e 20 3c 6f 70 74 69 6f 6e 3e}
		$s2 = {3d 3d 3d 3d 3d 3d 3d 3d 52 65 61 6c 56 4e 43 20 3c 3d 20 34 2e 31 2e 31 20 42 79 70 61 73 73 20 41 75 74 68 65 6e 74 69 63 61 74 69 6f 6e 20 53 63 61 6e 6e 65 72 3d 3d 3d 3d 3d 3d 3d}
		$s3 = {5b 2b 5d 20 54 79 70 65 20 56 4e 43 5f 62 79 70 61 75 74 68 20 3c 74 61 72 67 65 74 3e 2c 3c 73 63 61 6e 74 79 70 65 3e 20 6f 72 20 3c 6f 70 74 69 6f 6e 3e 20 66 6f 72 20 6d 6f 72 65 20 69 6e 66 6f 72 6d 61 74 69 6f 6e 73}
		$s4 = {56 4e 43 5f 62 79 70 61 75 74 68 20 2d 69 20 31 39 32 2e 31 36 38 2e 30 2e 31 2c 31 39 32 2e 31 36 38 2e 30 2e 32 2c 31 39 32 2e 31 36 38 2e 30 2e 33 2c 2e 2e 2e}
		$s5 = {2d 76 6e 3a 25 2d 31 35 73 3a 25 2d 37 64 20 20 63 6f 6e 6e 65 63 74 69 6f 6e 20 63 6c 6f 73 65 64}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 60KB and 2 of them
}

rule Dos_iis : hardened
{
	meta:
		description = "Chinese Hacktool Set - file iis.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "61ffd2cbec5462766c6f1c44bd44eeaed4f3d2c7"

	strings:
		$s1 = {63 6f 6d 73 70 65 63}
		$s2 = {70 72 6f 67 72 61 6d 20 74 65 72 6d 69 6e 67}
		$s3 = {57 69 6e 53 74 61 30 5c 44 65 66 61 75}
		$s4 = {2a 20 46 52 4f 4d 20 49 49 73 57 65 62 49 6e 66 6f}
		$s5 = {77 77 77 2e 69 63 65 68 61 63 6b 2e}
		$s6 = {77 6d 69 70 72 76 73 65 2e 65 78 65}
		$s7 = {50 69 64 3a 20 25 64}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 70KB and all of them
}

rule IISPutScannesr : hardened
{
	meta:
		description = "Chinese Hacktool Set - file IISPutScannesr.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "2dd8fee20df47fd4eed5a354817ce837752f6ae9"

	strings:
		$s1 = {79 6f 64 61 20 26 20 4d 2e 6f 2e 44 2e}
		$s2 = {2d 3e 20 63 6f 6d 65 2e 74 6f 2f 66 32 66 20 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a 2a}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 500KB and all of them
}

rule Generate : hardened
{
	meta:
		description = "Chinese Hacktool Set - file Generate.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "2cb4c3916271868c30c7b4598da697f59e9c7a12"

	strings:
		$s1 = {43 3a 5c 54 45 4d 50 5c}
		$s2 = {43 00 6f 00 6e 00 6e 00 65 00 63 00 74 00 69 00 6f 00 6e 00 20 00 43 00 6c 00 6f 00 73 00 65 00 64 00 20 00 47 00 72 00 61 00 63 00 65 00 66 00 75 00 6c 00 6c 00 79 00 2e 00 3b 00 43 00 6f 00 75 00 6c 00 64 00 20 00 6e 00 6f 00 74 00 20 00 62 00 69 00 6e 00 64 00 20 00 73 00 6f 00 63 00 6b 00 65 00 74 00 2e 00 20 00 41 00 64 00 64 00 72 00 65 00 73 00 73 00 20 00 61 00 6e 00 64 00 20 00 70 00 6f 00 72 00 74 00 20 00 61 00 72 00 65 00 20 00 61 00 6c 00 72 00 65 00 61 00 64 00}
		$s3 = {24 35 33 30 20 50 6c 65 61 73 65 20 6c 6f 67 69 6e 20 77 69 74 68 20 55 53 45 52 20 61 6e 64 20 50 41 53 53 2e}
		$s4 = {5f 53 68 65 6c 6c 2e 65 78 65}
		$s5 = {66 74 70 63 57 61 69 74 69 6e 67 50 61 73 73 77 6f 72 64}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 2000KB and 3 of them
}

rule Pc_rejoice : hardened
{
	meta:
		description = "Chinese Hacktool Set - file rejoice.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "fe634a9f5d48d5c64c8f8bfd59ac7d8965d8f372"

	strings:
		$s1 = {40 6d 65 6d 62 65 72 73 2e 33 33 32 32 2e 6e 65 74 2f 64 79 6e 64 6e 73 2f 75 70 64 61 74 65 3f 73 79 73 74 65 6d 3d 64 79 6e 64 6e 73 26 68 6f 73 74 6e 61 6d 65 3d}
		$s2 = {68 74 74 70 3a 2f 2f 77 77 77 2e 78 78 78 2e 63 6f 6d 2f 78 78 78 2e 65 78 65}
		$s3 = {40 64 64 6e 73 2e 6f 72 61 79 2e 63 6f 6d 2f 70 68 2f 75 70 64 61 74 65 3f 68 6f 73 74 6e 61 6d 65 3d}
		$s4 = {4e 00 6f 00 20 00 64 00 61 00 74 00 61 00 20 00 74 00 6f 00 20 00 72 00 65 00 61 00 64 00 2e 00 24 00 43 00 61 00 6e 00 20 00 6e 00 6f 00 74 00 20 00 62 00 69 00 6e 00 64 00 20 00 69 00 6e 00 20 00 70 00 6f 00 72 00 74 00 20 00 72 00 61 00 6e 00 67 00 65 00 20 00 28 00 25 00 64 00 20 00 2d 00 20 00 25 00 64 00 29 00}
		$s5 = {4c 69 73 74 56 69 65 77 50 72 6f 63 65 73 73 4c 69 73 74 43 6f 6c 75 6d 6e 43 6c 69 63 6b 21}
		$s6 = {68 74 74 70 3a 2f 2f 69 66 72 61 6d 65 2e 69 70 31 33 38 2e 63 6f 6d 2f 69 63 2e 61 73 70}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 3000KB and 3 of them
}

rule ms11080_withcmd : hardened
{
	meta:
		description = "Chinese Hacktool Set - file ms11080_withcmd.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "745e5058acff27b09cfd6169caf6e45097881a49"

	strings:
		$s1 = {55 73 61 67 65 20 3a 20 6d 73 31 31 2d 30 38 30 2e 65 78 65 20 63 6d 64 2e 65 78 65 20 43 6f 6d 6d 61 6e 64 20}
		$s2 = {5c 6d 73 31 31 30 38 30 5c 6d 73 31 31 30 38 30 5c 44 65 62 75 67 5c 6d 73 31 31 30 38 30 2e 70 64 62}
		$s3 = {5b 3e 5d 20 62 79 3a 4d 65 72 34 65 6e 37 79 40 39 30 73 65 63 2e 6f 72 67}
		$s4 = {5b 3e 5d 20 63 72 65 61 74 65 20 70 6f 72 63 65 73 73 20 65 72 72 6f 72}
		$s5 = {5b 3e 5d 20 6d 73 31 31 2d 30 38 30 20 45 78 70 6c 6f 69 74}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 300KB and 1 of them
}

rule OtherTools_xiaoa : hardened
{
	meta:
		description = "Chinese Hacktool Set - file xiaoa.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "6988acb738e78d582e3614f83993628cf92ae26d"

	strings:
		$s1 = {55 73 61 67 65 3a 73 79 73 74 65 6d 5f 65 78 70 2e 65 78 65 20 22 63 6d 64 22}
		$s2 = {54 68 65 20 73 68 65 6c 6c 20 22 63 6d 64 22 20 73 75 63 63 65 73 73 21}
		$s3 = {4e 6f 74 20 57 69 6e 64 6f 77 73 20 4e 54 20 66 61 6d 69 6c 79 20 4f 53 2e}
		$s4 = {55 6e 61 62 6c 65 20 74 6f 20 67 65 74 20 6b 65 72 6e 65 6c 20 62 61 73 65 20 61 64 64 72 65 73 73 2e}
		$s5 = {72 75 6e 20 22 25 73 22 20 66 61 69 6c 65 64 2c 63 6f 64 65 3a 20 25 64}
		$s6 = {57 69 6e 64 6f 77 73 20 4b 65 72 6e 65 6c 20 4c 6f 63 61 6c 20 50 72 69 76 69 6c 65 67 65 20 45 78 70 6c 6f 69 74 20}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 100KB and 2 of them
}

rule unknown2 : hardened
{
	meta:
		description = "Chinese Hacktool Set - file unknown2.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "32508d75c3d95e045ddc82cb829281a288bd5aa3"

	strings:
		$s1 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 6d 00 64 00 35 00 2e 00 63 00 6f 00 6d 00 2e 00 63 00 6e 00 2f 00 69 00 6e 00 64 00 65 00 78 00 2e 00 70 00 68 00 70 00 2f 00 6d 00 64 00 35 00 72 00 65 00 76 00 65 00 72 00 73 00 65 00 2f 00 69 00 6e 00 64 00 65 00 78 00 2f 00 6d 00 64 00 2f 00}
		$s2 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 77 00 77 00 77 00 2e 00 6d 00 64 00 35 00 64 00 65 00 63 00 72 00 79 00 70 00 74 00 65 00 72 00 2e 00 63 00 6f 00 2e 00 75 00 6b 00 2f 00 66 00 65 00 65 00 64 00 2f 00 61 00 70 00 69 00 2e 00 61 00 73 00 70 00 78 00 3f 00}
		$s3 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 77 00 77 00 77 00 2e 00 6d 00 64 00 35 00 2e 00 63 00 6f 00 6d 00 2e 00 63 00 6e 00}
		$s4 = {31 00 2e 00 35 00 2e 00 65 00 78 00 65 00}
		$s5 = {5c 00 53 00 65 00 74 00 2e 00 69 00 6e 00 69 00}
		$s6 = {4f 00 70 00 65 00 6e 00 46 00 69 00 6c 00 65 00 44 00 69 00 61 00 6c 00 6f 00 67 00 31 00}
		$s7 = {20 00 28 00 2a 00 2e 00 74 00 78 00 74 00 29 00 7c 00 2a 00 2e 00 74 00 78 00 74 00}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 300KB and 4 of them
}

rule hydra_7_3_hydra : hardened
{
	meta:
		description = "Chinese Hacktool Set - file hydra.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "2f82b8bf1159e43427880d70bcd116dc9e8026ad"

	strings:
		$s1 = {5b 41 54 54 45 4d 50 54 2d 45 52 52 4f 52 5d 20 74 61 72 67 65 74 20 25 73 20 2d 20 6c 6f 67 69 6e 20 22 25 73 22 20 2d 20 70 61 73 73 20 22 25 73 22 20 2d 20 63 68 69 6c 64 20 25 64 20 2d 20 25 6c 75 20 6f 66 20 25 6c 75}
		$s2 = {28 44 45 53 43 52 49 50 54 49 4f 4e 3d 28 43 4f 4e 4e 45 43 54 5f 44 41 54 41 3d 28 43 49 44 3d 28 50 52 4f 47 52 41 4d 3d 29 29 28 43 4f 4d 4d 41 4e 44 3d 72 65 6c 6f 61 64 29 28 50 41 53 53 57 4f 52 44 3d 25 73 29 28 53 45 52 56 49 43 45}
		$s3 = {63 6e 3d 5e 55 53 45 52 5e 2c 63 6e 3d 75 73 65 72 73 2c 64 63 3d 66 6f 6f 2c 64 63 3d 62 61 72 2c 64 63 3d 63 6f 6d 20 66 6f 72 20 64 6f 6d 61 69 6e 20 66 6f 6f 2e 62 61 72 2e 63 6f 6d}
		$s4 = {5b 25 64 5d 5b 73 6d 62 5d 20 48 6f 73 74 3a 20 25 73 20 41 63 63 6f 75 6e 74 3a 20 25 73 20 45 72 72 6f 72 3a 20 41 43 43 4f 55 4e 54 5f 43 48 41 4e 47 45 5f 50 41 53 53 57 4f 52 44}
		$s5 = {68 79 64 72 61 20 2d 50 20 70 61 73 73 2e 74 78 74 20 74 61 72 67 65 74 20 63 69 73 63 6f 2d 65 6e 61 62 6c 65 20 20 28 64 69 72 65 63 74 20 63 6f 6e 73 6f 6c 65 20 61 63 63 65 73 73 29}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 700KB and 1 of them
}

rule OracleScan : hardened
{
	meta:
		description = "Chinese Hacktool Set - file OracleScan.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "10ff7faf72fe6da8f05526367b3522a2408999ec"

	strings:
		$s1 = {4d 59 42 4c 4f 47 3a 48 54 54 50 3a 2f 2f 48 49 2e 42 41 49 44 55 2e 43 4f 4d 2f 30 58 32 34 51}
		$s2 = {5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c}
		$s3 = {55 53 45 52 5f 4e 41 4d 45}
		$s4 = {46 52 4f 4d 57 57 48 45 52 45}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 300KB and all of them
}

rule SQLTools : hardened
{
	meta:
		description = "Chinese Hacktool Set - file SQLTools.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "38a9caa2079afa2c8d7327e7762f7ed9a69056f7"

	strings:
		$s1 = {44 00 42 00 4e 00 5f 00 50 00 4f 00 53 00 54 00}
		$s2 = {4c 4f 41 44 45 52 20 45 52 52 4f 52}
		$s3 = {77 00 77 00 77 00 2e 00 31 00 32 00 38 00 35 00 2e 00 6e 00 65 00 74 00}
		$s4 = {54 00 55 00 50 00 46 00 49 00 4c 00 45 00 46 00 4f 00 52 00 4d 00}
		$s5 = {44 00 42 00 4e 00 5f 00 44 00 45 00 4c 00 45 00 54 00 45 00}
		$s6 = {44 00 42 00 49 00 4e 00 53 00 45 00 52 00 54 00}
		$s7 = {43 00 6f 00 70 00 79 00 72 00 69 00 67 00 68 00 74 00 20 00 28 00 43 00 29 00 20 00 4b 00 69 00 62 00 6f 00 73 00 6f 00 66 00 74 00 20 00 43 00 6f 00 72 00 70 00 2e 00 20 00 32 00 30 00 30 00 31 00 2d 00 32 00 30 00 30 00 36 00}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 2350KB and all of them
}

rule portscanner : hardened
{
	meta:
		description = "Chinese Hacktool Set - file portscanner.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "1de367d503fdaaeee30e8ad7c100dd1e320858a4"

	strings:
		$s0 = {50 6f 72 74 4c 69 73 74 66 4e 6f}
		$s1 = {2e 35 33 33 2e 6e 65 74}
		$s2 = {43 52 54 44 4c 4c 2e 44 4c 4c}
		$s3 = {65 78 69 74 66 63}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 25KB and all of them
}

rule kappfree : hardened
{
	meta:
		description = "Chinese Hacktool Set - file kappfree.dll"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "e57e79f190f8a24ca911e6c7e008743480c08553"

	strings:
		$s1 = {42 00 69 00 65 00 6e 00 76 00 65 00 6e 00 75 00 65 00 20 00 64 00 61 00 6e 00 73 00 20 00 75 00 6e 00 20 00 70 00 72 00 6f 00 63 00 65 00 73 00 73 00 75 00 73 00 20 00 64 00 69 00 73 00 74 00 61 00 6e 00 74 00}
		$s2 = {6b 61 70 70 66 72 65 65 2e 64 6c 6c}
		$s3 = {6b 00 61 00 70 00 70 00 66 00 72 00 65 00 65 00 20 00 64 00 65 00 20 00 6d 00 69 00 6d 00 69 00 6b 00 61 00 74 00 7a 00 20 00 70 00 6f 00 75 00 72 00 20 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 28 00 61 00 6e 00 74 00 69 00 20 00 41 00 70 00 70 00 4c 00 6f 00 63 00 6b 00 65 00 72 00 29 00}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 200KB and all of them
}

rule Smartniff : hardened
{
	meta:
		description = "Chinese Hacktool Set - file Smartniff.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "67609f21d54a57955d8fe6d48bc471f328748d0a"

	strings:
		$s1 = {73 00 6d 00 73 00 6e 00 69 00 66 00 66 00 2e 00 65 00 78 00 65 00}
		$s2 = {73 75 70 70 6f 72 74 40 6e 69 72 73 6f 66 74 2e 6e 65 74 30}
		$s3 = {3c 2f 72 65 71 75 65 73 74 65 64 50 72 69 76 69 6c 65 67 65 73 3e 3c 2f 73 65 63 75 72 69 74 79 3e 3c 2f 74 72 75 73 74 49 6e 66 6f 3e 3c 2f 61 73 73 65 6d 62 6c 79 3e}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 200KB and all of them
}

rule ChinaChopper_caidao : hardened
{
	meta:
		description = "Chinese Hacktool Set - file caidao.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "056a60ec1f6a8959bfc43254d97527b003ae5edb"

	strings:
		$s1 = {50 61 73 73 2c 43 6f 6e 66 69 67 2c 6e 7b 29}
		$s2 = {70 68 4d 59 53 51 4c 5a}
		$s3 = {5c 44 48 4c 50 5c 2e}
		$s4 = {5c 64 68 6c 70 5c 2e}
		$s5 = {53 48 41 75 74 6f 43 6f 6d 70 6c 65}
		$s6 = {4d 61 69 6e 46 72 61 6d 65}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 1077KB and all of them
}

rule KiwiTaskmgr_2 : hardened
{
	meta:
		description = "Chinese Hacktool Set - file KiwiTaskmgr.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "8bd6c9f2e8be3e74bd83c6a2d929f8a69422fb16"

	strings:
		$s1 = {50 00 72 00 6f 00 63 00 65 00 73 00 73 00 20 00 4f 00 6b 00 2c 00 20 00 4d 00 65 00 6d 00 6f 00 72 00 79 00 20 00 4f 00 6b 00 2c 00 20 00 72 00 65 00 73 00 75 00 6d 00 69 00 6e 00 67 00 20 00 70 00 72 00 6f 00 63 00 65 00 73 00 73 00 20 00 3a 00 29 00}
		$s2 = {4b 00 69 00 77 00 69 00 20 00 54 00 61 00 73 00 6b 00 6d 00 67 00 72 00 20 00 6e 00 6f 00 2d 00 67 00 70 00 6f 00}
		$s3 = {4b 00 69 00 77 00 69 00 41 00 6e 00 64 00 54 00 61 00 73 00 6b 00 4d 00 67 00 72 00}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 300KB and all of them
}

rule kappfree_2 : hardened
{
	meta:
		description = "Chinese Hacktool Set - file kappfree.dll"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "5d578df9a71670aa832d1cd63379e6162564fb6b"

	strings:
		$s1 = {6b 61 70 70 66 72 65 65 2e 64 6c 6c}
		$s2 = {6b 00 61 00 70 00 70 00 66 00 72 00 65 00 65 00 20 00 64 00 65 00 20 00 6d 00 69 00 6d 00 69 00 6b 00 61 00 74 00 7a 00 20 00 70 00 6f 00 75 00 72 00 20 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 28 00 61 00 6e 00 74 00 69 00 20 00 41 00 70 00 70 00 4c 00 6f 00 63 00 6b 00 65 00 72 00 29 00}
		$s3 = {27 00 20 00 69 00 6e 00 74 00 72 00 6f 00 75 00 76 00 61 00 62 00 6c 00 65 00 20 00 21 00}
		$s4 = {6b 00 69 00 77 00 69 00 5c 00 6d 00 69 00 6d 00 69 00 6b 00 61 00 74 00 7a 00}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 200KB and 2 of them
}

rule x_way2_5_sqlcmd : hardened
{
	meta:
		description = "Chinese Hacktool Set - file sqlcmd.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "5152a57e3638418b0d97a42db1c0fc2f893a2794"

	strings:
		$s1 = {4c 4f 41 44 45 52 20 45 52 52 4f 52}
		$s2 = {54 68 65 20 70 72 6f 63 65 64 75 72 65 20 65 6e 74 72 79 20 70 6f 69 6e 74 20 25 73 20 63 6f 75 6c 64 20 6e 6f 74 20 62 65 20 6c 6f 63 61 74 65 64 20 69 6e 20 74 68 65 20 64 79 6e 61 6d 69 63 20 6c 69 6e 6b 20 6c 69 62 72 61 72 79 20 25 73}
		$s3 = {54 68 65 20 6f 72 64 69 6e 61 6c 20 25 75 20 63 6f 75 6c 64 20 6e 6f 74 20 62 65 20 6c 6f 63 61 74 65 64 20 69 6e 20 74 68 65 20 64 79 6e 61 6d 69 63 20 6c 69 6e 6b 20 6c 69 62 72 61 72 79 20 25 73}
		$s4 = {6b 65 72 6e 65 6c 33 32 2e 64 6c 6c}
		$s5 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63}
		$s6 = {56 69 72 74 75 61 6c 46 72 65 65}
		$s7 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74}
		$s8 = {45 78 69 74 50 72 6f 63 65 73 73}
		$s9 = {75 73 65 72 33 32 2e 64 6c 6c}
		$s16 = {4d 65 73 73 61 67 65 42 6f 78 41}
		$s10 = {77 73 70 72 69 6e 74 66 41}
		$s11 = {6b 65 72 6e 65 6c 33 32 2e 64 6c 6c}
		$s12 = {47 65 74 50 72 6f 63 41 64 64 72 65 73 73}
		$s13 = {47 65 74 4d 6f 64 75 6c 65 48 61 6e 64 6c 65 41}
		$s14 = {4c 6f 61 64 4c 69 62 72 61 72 79 41}
		$s15 = {6f 64 62 63 33 32 2e 64 6c 6c}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 23KB and filesize > 20KB and all of them
}

rule Win32_klock : hardened
{
	meta:
		description = "Chinese Hacktool Set - file klock.dll"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "7addce4434670927c4efaa560524680ba2871d17"

	strings:
		$s1 = {6b 6c 6f 63 6b 2e 64 6c 6c}
		$s2 = {45 00 72 00 72 00 65 00 75 00 72 00 20 00 3a 00 20 00 69 00 6d 00 70 00 6f 00 73 00 73 00 69 00 62 00 6c 00 65 00 20 00 64 00 65 00 20 00 62 00 61 00 73 00 63 00 75 00 6c 00 65 00 72 00 20 00 6c 00 65 00 20 00 62 00 75 00 72 00 65 00 61 00 75 00 20 00 3b 00 20 00 53 00 77 00 69 00 74 00 63 00 68 00 44 00 65 00 73 00 6b 00 74 00 6f 00 70 00 20 00 3a 00 20 00}
		$s3 = {6b 00 6c 00 6f 00 63 00 6b 00 20 00 64 00 65 00 20 00 6d 00 69 00 6d 00 69 00 6b 00 61 00 74 00 7a 00 20 00 70 00 6f 00 75 00 72 00 20 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 250KB and all of them
}

rule ipsearcher : hardened
{
	meta:
		description = "Chinese Hacktool Set - file ipsearcher.dll"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "1e96e9c5c56fcbea94d26ce0b3f1548b224a4791"

	strings:
		$s0 = {68 74 74 70 3a 2f 2f 77 77 77 2e 77 7a 70 67 2e 63 6f 6d}
		$s1 = {69 70 73 65 61 72 63 68 65 72 5c 69 70 73 65 61 72 63 68 65 72 5c 52 65 6c 65 61 73 65 5c 69 70 73 65 61 72 63 68 65 72 2e 70 64 62}
		$s3 = {5f 47 65 74 41 64 64 72 65 73 73}
		$s5 = {69 70 73 65 61 72 63 68 65 72 2e 64 6c 6c}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 140KB and all of them
}

rule ms10048_x64 : hardened
{
	meta:
		description = "Chinese Hacktool Set - file ms10048-x64.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "418bec3493c85e3490e400ecaff5a7760c17a0d0"

	strings:
		$s1 = {54 68 65 20 74 61 72 67 65 74 20 69 73 20 6d 6f 73 74 20 6c 69 6b 65 6c 79 20 70 61 74 63 68 65 64 2e}
		$s2 = {44 6f 6a 69 62 69 72 6f 6e 20 62 79 20 52 6f 6e 61 6c 64 20 48 75 69 7a 65 72 2c 20 28 63 29 20 6d 61 73 74 65 72 23 68 34 63 6b 65 72 2e 75 73 20 20}
		$s3 = {5b 20 5d 20 43 72 65 61 74 69 6e 67 20 65 76 69 6c 20 77 69 6e 64 6f 77}
		$s4 = {5b 2b 5d 20 53 65 74 20 74 6f 20 25 64 20 65 78 70 6c 6f 69 74 20 68 61 6c 66 20 73 75 63 63 65 65 64 65 64}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 40KB and 1 of them
}

rule hscangui : hardened
{
	meta:
		description = "Chinese Hacktool Set - file hscangui.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "af8aced0a78e1181f4c307c78402481a589f8d07"

	strings:
		$s1 = {5b 25 73 5d 3a 20 46 6f 75 6e 64 20 22 46 54 50 20 61 63 63 6f 75 6e 74 3a 20 61 6e 79 6f 6e 65 2f 61 6e 79 6f 6e 65 40 61 6e 79 2e 6e 65 74 22 20 20 21 21 21}
		$s2 = {68 74 74 70 3a 2f 2f 77 77 77 2e 63 6e 68 6f 6e 6b 65 72 2e 63 6f 6d}
		$s3 = {25 73 40 66 74 70 73 63 61 6e 23 43 72 61 63 6b 65 64 20 61 63 63 6f 75 6e 74 3a 20 20 25 73 2f 25 73}
		$s4 = {5b 25 73 5d 3a 20 46 6f 75 6e 64 20 22 46 54 50 20 61 63 63 6f 75 6e 74 3a 20 25 73 2f 25 73 22 20 21 21 21}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 220KB and 2 of them
}

rule GoodToolset_ms11080 : hardened
{
	meta:
		description = "Chinese Hacktool Set - file ms11080.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "f0854c49eddf807f3a7381d3b20f9af4a3024e9f"

	strings:
		$s1 = {5b 2a 5d 20 63 6f 6d 6d 61 6e 64 20 61 64 64 20 75 73 65 72 20 39 30 73 65 63 20 39 30 73 65 63}
		$s2 = {5c 6d 73 31 31 30 38 30 5c 44 65 62 75 67 5c 6d 73 31 31 30 38 30 2e 70 64 62}
		$s3 = {5b 3e 5d 20 62 79 3a 4d 65 72 34 65 6e 37 79 40 39 30 73 65 63 2e 6f 72 67}
		$s4 = {5b 2a 5d 20 41 64 64 20 74 6f 20 41 64 6d 69 6e 69 73 74 72 61 74 6f 72 73 20 73 75 63 63 65 73 73}
		$s5 = {5b 2a 5d 20 55 73 65 72 20 68 61 73 20 62 65 65 6e 20 73 75 63 63 65 73 73 66 75 6c 6c 79 20 61 64 64 65 64}
		$s6 = {5b 3e 5d 20 6d 73 31 31 2d 30 38 20 45 78 70 6c 6f 69 74}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 240KB and 2 of them
}

rule epathobj_exp64 : hardened
{
	meta:
		description = "Chinese Hacktool Set - file epathobj_exp64.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "09195ba4e25ccce35c188657957c0f2c6a61d083"

	strings:
		$s1 = {57 61 74 63 68 64 6f 67 20 74 68 72 65 61 64 20 25 64 20 77 61 69 74 69 6e 67 20 6f 6e 20 4d 75 74 65 78}
		$s2 = {45 78 70 6c 6f 69 74 20 6f 6b 20 72 75 6e 20 63 6f 6d 6d 61 6e 64}
		$s3 = {5c 65 70 61 74 68 6f 62 6a 5f 65 78 70 5c 78 36 34 5c 52 65 6c 65 61 73 65 5c 65 70 61 74 68 6f 62 6a 5f 65 78 70 2e 70 64 62}
		$s4 = {41 6c 6c 6c 6f 63 61 74 65 64 20 75 73 65 72 73 70 61 63 65 20 50 41 54 48 52 45 43 4f 52 44 20 28 29 20 25 70}
		$s5 = {4d 75 74 65 78 20 6f 62 6a 65 63 74 20 64 69 64 20 6e 6f 74 20 74 69 6d 65 6f 75 74 2c 20 6c 69 73 74 20 6e 6f 74 20 70 61 74 63 68 65 64}
		$s6 = {2d 00 20 00 69 00 6e 00 63 00 6f 00 6e 00 73 00 69 00 73 00 74 00 65 00 6e 00 74 00 20 00 6f 00 6e 00 65 00 78 00 69 00 74 00 20 00 62 00 65 00 67 00 69 00 6e 00 2d 00 65 00 6e 00 64 00 20 00 76 00 61 00 72 00 69 00 61 00 62 00 6c 00 65 00 73 00}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 150KB and 2 of them
}

rule kelloworld_2 : hardened
{
	meta:
		description = "Chinese Hacktool Set - file kelloworld.dll"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "55d5dabd96c44d16e41f70f0357cba1dda26c24f"

	strings:
		$s1 = {48 00 65 00 6c 00 6c 00 6f 00 20 00 57 00 6f 00 72 00 6c 00 64 00 21 00}
		$s2 = {6b 65 6c 6c 6f 77 6f 72 6c 64 2e 64 6c 6c}
		$s3 = {6b 00 65 00 6c 00 6c 00 6f 00 77 00 6f 00 72 00 6c 00 64 00 20 00 64 00 65 00 20 00 6d 00 69 00 6d 00 69 00 6b 00 61 00 74 00 7a 00 20 00 70 00 6f 00 75 00 72 00 20 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 200KB and all of them
}

rule HScan_v1_20_hscan : hardened
{
	meta:
		description = "Chinese Hacktool Set - file hscan.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "568b06696ea0270ee1a744a5ac16418c8dacde1c"

	strings:
		$s1 = {5b 25 73 5d 3a 20 46 6f 75 6e 64 20 22 46 54 50 20 61 63 63 6f 75 6e 74 3a 20 61 6e 79 6f 6e 65 2f 61 6e 79 6f 6e 65 40 61 6e 79 2e 6e 65 74 22 20 20 21 21 21}
		$s2 = {25 73 20 2d 68 20 31 39 32 2e 31 36 38 2e 30 2e 31 20 31 39 32 2e 31 36 38 2e 30 2e 32 35 34 20 2d 70 6f 72 74 20 2d 66 74 70 20 2d 6d 61 78 20 32 30 30 2c 31 30 30}
		$s3 = {2e 5c 72 65 70 6f 72 74 5c 25 73 2d 25 73 2e 68 74 6d 6c}
		$s4 = {2e 5c 6c 6f 67 5c 48 73 63 61 6e 2e 6c 6f 67}
		$s5 = {5b 25 73 5d 3a 20 46 6f 75 6e 64 20 63 69 73 63 6f 20 45 6e 61 62 6c 65 20 70 61 73 73 77 6f 72 64 3a 20 25 73 20 21 21 21}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 200KB and 2 of them
}

rule _Project1_Generate_rejoice : hardened
{
	meta:
		description = "Chinese Hacktool Set - from files Project1.exe, Generate.exe, rejoice.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		super_rule = 1
		hash0 = "d1a5e3b646a16a7fcccf03759bd0f96480111c96"
		hash1 = "2cb4c3916271868c30c7b4598da697f59e9c7a12"
		hash2 = "fe634a9f5d48d5c64c8f8bfd59ac7d8965d8f372"

	strings:
		$s1 = {73 66 55 73 65 72 41 70 70 44 61 74 61 52 6f 61 6d 69 6e 67}
		$s2 = {24 54 52 7a 46 72 61 6d 65 43 6f 6e 74 72 6f 6c 6c 65 72 50 72 6f 70 65 72 74 79 43 6f 6e 6e 65 63 74 69 6f 6e}
		$s3 = {64 65 6c 70 68 69 33 32 2e 65 78 65}
		$s4 = {68 6b 65 79 43 75 72 72 65 6e 74 55 73 65 72}
		$s5 = {25 00 73 00 20 00 69 00 73 00 20 00 6e 00 6f 00 74 00 20 00 61 00 20 00 76 00 61 00 6c 00 69 00 64 00 20 00 49 00 50 00 20 00 61 00 64 00 64 00 72 00 65 00 73 00 73 00 2e 00}
		$s6 = {43 69 74 61 64 65 6c 20 68 6f 6f 6b 69 6e 67 20 65 72 72 6f 72}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 2000KB and all of them
}

rule _hscan_hscan_hscangui : hardened
{
	meta:
		description = "Chinese Hacktool Set - from files hscan.exe, hscan.exe, hscangui.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		super_rule = 1
		hash0 = "17a743e40790985ececf5c66eaad2a1f8c4cffe8"
		hash1 = "568b06696ea0270ee1a744a5ac16418c8dacde1c"
		hash2 = "af8aced0a78e1181f4c307c78402481a589f8d07"

	strings:
		$s1 = {2e 5c 6c 6f 67 5c 48 73 63 61 6e 2e 6c 6f 67}
		$s2 = {2e 5c 72 65 70 6f 72 74 5c 25 73 2d 25 73 2e 68 74 6d 6c}
		$s3 = {5b 25 73 5d 3a 20 63 68 65 63 6b 69 6e 67 20 22 46 54 50 20 61 63 63 6f 75 6e 74 3a 20 66 74 70 2f 66 74 70 40 66 74 70 2e 6e 65 74 22 20 2e 2e 2e}
		$s4 = {5b 25 73 5d 3a 20 49 50 43 20 4e 55 4c 4c 20 73 65 73 73 69 6f 6e 20 63 6f 6e 6e 65 63 74 69 6f 6e 20 73 75 63 63 65 73 73 20 21 21 21}
		$s5 = {53 63 61 6e 20 25 64 20 74 61 72 67 65 74 73 2c 75 73 65 20 25 34 2e 31 66 20 6d 69 6e 75 74 65 73}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 240KB and all of them
}

rule kiwi_tools : hardened
{
	meta:
		description = "Chinese Hacktool Set - from files kappfree.dll, kelloworld.dll, KiwiCmd.exe, KiwiRegedit.exe, KiwiTaskmgr.exe, klock.dll, mimikatz.exe, mimikatz.sys, sekurlsa.dll, kappfree.dll, kelloworld.dll, KiwiCmd.exe, KiwiRegedit.exe, KiwiTaskmgr.exe, klock.dll, mimikatz.exe, mimikatz.sys, sekurlsa.dll"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		super_rule = 1
		hash0 = "e57e79f190f8a24ca911e6c7e008743480c08553"
		hash1 = "55d5dabd96c44d16e41f70f0357cba1dda26c24f"
		hash2 = "7ac7541e20af7755b7d8141c5c1b7432465cabd8"
		hash3 = "9fbfe3eb49d67347ab57ae743f7542864bc06de6"
		hash4 = "5c90d648c414bdafb549291f95fe6f27c0c9b5ec"
		hash5 = "7addce4434670927c4efaa560524680ba2871d17"
		hash6 = "28c5c0bdb7786dc2771672a2c275be7d9b742ec7"
		hash7 = "b5c93489a1b62181594d0fb08cc510d947353bc8"
		hash8 = "6acecd18fc7da1c5eb0d04e848aae9ce59d2b1b5"
		hash9 = "5d578df9a71670aa832d1cd63379e6162564fb6b"
		hash10 = "febadc01a64a071816eac61a85418711debaf233"
		hash11 = "569ca4ff1a5ea537aefac4a04a2c588c566c6d86"
		hash12 = "56a61c808b311e2225849d195bbeb69733efe49a"
		hash13 = "8bd6c9f2e8be3e74bd83c6a2d929f8a69422fb16"
		hash14 = "44825e848bc3abdb6f31d0a49725bb6f498e9ccc"
		hash15 = "f661d6516d081c37ab7da0f4ec21b2cc6a9257c6"
		hash16 = "20facf1fa2d87cccf177403ca1a7852128a9a0ab"
		hash17 = "6e0ffa472d63fdda5abc4c1b164ba8724dcb25b5"

	strings:
		$s1 = {68 74 74 70 3a 2f 2f 62 6c 6f 67 2e 67 65 6e 74 69 6c 6b 69 77 69 2e 63 6f 6d 2f 6d 69 6d 69 6b 61 74 7a}
		$s2 = {42 65 6e 6a 61 6d 69 6e 20 44 65 6c 70 79}
		$s3 = {47 6c 6f 62 61 6c 53 69 67 6e}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 1000KB and all of them
}

rule kiwi_tools_gentil_kiwi : hardened
{
	meta:
		description = "Chinese Hacktool Set - from files kappfree.dll, kelloworld.dll, KiwiCmd.exe, KiwiRegedit.exe, KiwiTaskmgr.exe, klock.dll, mimikatz.exe, sekurlsa.dll, kappfree.dll, kelloworld.dll, KiwiCmd.exe, KiwiRegedit.exe, KiwiTaskmgr.exe, klock.dll, mimikatz.exe, sekurlsa.dll"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		super_rule = 1
		hash0 = "e57e79f190f8a24ca911e6c7e008743480c08553"
		hash1 = "55d5dabd96c44d16e41f70f0357cba1dda26c24f"
		hash2 = "7ac7541e20af7755b7d8141c5c1b7432465cabd8"
		hash3 = "9fbfe3eb49d67347ab57ae743f7542864bc06de6"
		hash4 = "5c90d648c414bdafb549291f95fe6f27c0c9b5ec"
		hash5 = "7addce4434670927c4efaa560524680ba2871d17"
		hash6 = "28c5c0bdb7786dc2771672a2c275be7d9b742ec7"
		hash7 = "6acecd18fc7da1c5eb0d04e848aae9ce59d2b1b5"
		hash8 = "5d578df9a71670aa832d1cd63379e6162564fb6b"
		hash9 = "febadc01a64a071816eac61a85418711debaf233"
		hash10 = "569ca4ff1a5ea537aefac4a04a2c588c566c6d86"
		hash11 = "56a61c808b311e2225849d195bbeb69733efe49a"
		hash12 = "8bd6c9f2e8be3e74bd83c6a2d929f8a69422fb16"
		hash13 = "44825e848bc3abdb6f31d0a49725bb6f498e9ccc"
		hash14 = "f661d6516d081c37ab7da0f4ec21b2cc6a9257c6"
		hash15 = "6e0ffa472d63fdda5abc4c1b164ba8724dcb25b5"

	strings:
		$s1 = {6d 00 69 00 6d 00 69 00 6b 00 61 00 74 00 7a 00}
		$s2 = {43 00 6f 00 70 00 79 00 72 00 69 00 67 00 68 00 74 00 20 00 28 00 43 00 29 00 20 00 32 00 30 00 31 00 32 00 20 00 47 00 65 00 6e 00 74 00 69 00 6c 00 20 00 4b 00 69 00 77 00 69 00}
		$s3 = {47 00 65 00 6e 00 74 00 69 00 6c 00 20 00 4b 00 69 00 77 00 69 00}

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 1000KB and all of them
}

