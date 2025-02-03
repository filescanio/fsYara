rule clean_apt15_patchedcmd : hardened
{
	meta:
		author = "Ahmed Zaki"
		description = "This is a patched CMD. This is the CMD that RoyalCli uses."
		reference = "https://www.nccgroup.trust/us/about-us/newsroom-and-events/blog/2018/march/apt15-is-alive-and-strong-an-analysis-of-royalcli-and-royaldns/"
		sha256 = "90d1f65cfa51da07e040e066d4409dc8a48c1ab451542c894a623bc75c14bf8f"

	strings:
		$ = {65 00 69 00 73 00 61 00 62 00 6c 00 65 00 43 00 4d 00 44 00}
		$ = {25 00 57 00 49 00 4e 00 44 00 4f 00 57 00 53 00 5f 00 43 00 4f 00 50 00 59 00 52 00 49 00 47 00 48 00 54 00 25 00}
		$ = {43 00 6d 00 64 00 2e 00 45 00 78 00 65 00}
		$ = {57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 43 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 20 00 50 00 72 00 6f 00 63 00 65 00 73 00 73 00 6f 00 72 00}

	condition:
		all of them
}

rule malware_apt15_royalcli_1 : hardened
{
	meta:
		description = "Generic strings found in the Royal CLI tool"
		reference = "https://www.nccgroup.trust/us/about-us/newsroom-and-events/blog/2018/march/apt15-is-alive-and-strong-an-analysis-of-royalcli-and-royaldns/"
		author = "David Cannings"
		sha256 = "6df9b712ff56009810c4000a0ad47e41b7a6183b69416251e060b5c80cd05785"

	strings:
		$ = {25 73 7e 63 6c 69 74 65 6d 70 25 30 38 78 2e 74 6d 70}
		$ = {71 67 2e 74 6d 70}
		$ = {25 73 20 2f 63 20 25 73 3e 25 73}
		$ = {68 6b 63 6d 64 2e 65 78 65}
		$ = {25 73 6e 65 77 63 6d 64 2e 65 78 65}
		$ = {25 73 68 6b 63 6d 64 2e 65 78 65}
		$ = {25 73 7e 63 6c 69 74 65 6d 70 25 30 38 78 2e 69 6e 69}
		$ = {6d 79 52 4f 62 6a 65 63 74}
		$ = {6d 79 57 4f 62 6a 65 63 74}
		$ = {31 30 20 25 64 20 25 78 0d 0a}
		$ = {34 20 25 73 20 20 25 64 0d 0a}
		$ = {36 20 25 73 20 20 25 64 0d 0a}
		$ = {31 20 25 73 20 20 25 64 0d 0a}
		$ = {33 20 25 73 20 20 25 64 0d 0a}
		$ = {35 20 25 73 20 20 25 64 0d 0a}
		$ = {32 20 25 73 20 20 25 64 20 30 20 25 64 0d 0a}
		$ = {32 20 25 73 20 20 25 64 20 31 20 25 64 0d 0a}
		$ = {25 73 20 66 69 6c 65 20 6e 6f 74 20 65 78 69 73 74}

	condition:
		5 of them
}

rule malware_apt15_royalcli_2 : hardened
{
	meta:
		author = "Nikolaos Pantazopoulos"
		description = "APT15 RoyalCli backdoor"
		reference = "https://www.nccgroup.trust/us/about-us/newsroom-and-events/blog/2018/march/apt15-is-alive-and-strong-an-analysis-of-royalcli-and-royaldns/"

	strings:
		$string1 = {25 73 68 6b 63 6d 64 2e 65 78 65}
		$string2 = {6d 79 52 4f 62 6a 65 63 74}
		$string3 = {25 73 6e 65 77 63 6d 64 2e 65 78 65}
		$string4 = {25 73 7e 63 6c 69 74 65 6d 70 25 30 38 78 2e 74 6d 70}
		$string5 = {68 6b 63 6d 64 2e 65 78 65}
		$string6 = {6d 79 57 4f 62 6a 65 63 74}

	condition:
		uint16( 0 ) == 0x5A4D and 2 of them
}

import "pe"

rule malware_apt15_bs2005 : hardened
{
	meta:
		author = "Ahmed Zaki"
		md5 = "ed21ce2beee56f0a0b1c5a62a80c128b"
		description = "APT15 bs2005"
		reference = "https://www.nccgroup.trust/us/about-us/newsroom-and-events/blog/2018/march/apt15-is-alive-and-strong-an-analysis-of-royalcli-and-royaldns/"

	strings:
		$ = {((25 73 26 25 73 26 25 73 26 25 73) | (25 00 73 00 26 00 25 00 73 00 26 00 25 00 73 00 26 00 25 00 73 00))}
		$ = {((25 73 5c 25 73) | (25 00 73 00 5c 00 25 00 73 00))}
		$ = {((57 61 72 4f 6e 50 6f 73 74 52 65 64 69 72 65 63 74) | (57 00 61 00 72 00 4f 00 6e 00 50 00 6f 00 73 00 74 00 52 00 65 00 64 00 69 00 72 00 65 00 63 00 74 00))}
		$ = {((57 61 72 6e 6f 6e 5a 6f 6e 65 43 72 6f 73 73 69 6e 67) | (57 00 61 00 72 00 6e 00 6f 00 6e 00 5a 00 6f 00 6e 00 65 00 43 00 72 00 6f 00 73 00 73 00 69 00 6e 00 67 00))}
		$ = {((5e 5e 5e 5e 5e) | (5e 00 5e 00 5e 00 5e 00 5e 00))}
		$ = /"?%s\s*"?\s*\/C\s*"?%s\s*>\s*\\?"?%s\\(\w+\.\w+)?"\s*2>&1\s*"?/
		$ = {((49 45 68 61 72 64 65 6e) | (49 00 45 00 68 00 61 00 72 00 64 00 65 00 6e 00))}
		$ = {((44 45 50 4f 66 66) | (44 00 45 00 50 00 4f 00 66 00 66 00))}
		$ = {((53 68 6f 77 6e 56 65 72 69 66 79 42 61 6c 6c 6f 6f 6e) | (53 00 68 00 6f 00 77 00 6e 00 56 00 65 00 72 00 69 00 66 00 79 00 42 00 61 00 6c 00 6c 00 6f 00 6f 00 6e 00))}
		$ = {((49 45 48 61 72 64 65 6e 49 45 4e 6f 57 61 72 6e) | (49 00 45 00 48 00 61 00 72 00 64 00 65 00 6e 00 49 00 45 00 4e 00 6f 00 57 00 61 00 72 00 6e 00))}

	condition:
		( uint16( 0 ) == 0x5A4D and 5 of them ) or ( uint16( 0 ) == 0x5A4D and 3 of them and ( pe.imports ( "advapi32.dll" , "CryptDecrypt" ) and pe.imports ( "advapi32.dll" , "CryptEncrypt" ) and pe.imports ( "ole32.dll" , "CoCreateInstance" ) ) )
}

rule malware_apt15_royaldll : hardened
{
	meta:
		author = "David Cannings"
		description = "DLL implant, originally rights.dll and runs as a service"
		reference = "https://www.nccgroup.trust/us/about-us/newsroom-and-events/blog/2018/march/apt15-is-alive-and-strong-an-analysis-of-royalcli-and-royaldns/"
		sha256 = "bc937f6e958b339f6925023bc2af375d669084e9551fd3753e501ef26e36b39d"

	strings:
		$opcodes_jshash = { B8 A7 C6 67 4E 83 C1 02 BA 04 00 00 00 57 90 }
		$opcodes_encode = { 0F B6 1C 03 8B 55 08 30 1C 17 47 3B 7D 0C }
		$opcodes_sleep_loop = { 68 (88|B8) (13|0B) 00 00 FF D6 4F 75 F6 }
		$ = {4e 77 73 61 70 61 67 65 6e 74}
		$ = {22 25 73 22 3e 3e 22 25 73 22 5c 73 2e 74 78 74}
		$ = {6d 79 57 4f 62 6a 65 63 74}
		$ = {64 65 6c 20 63 3a 5c 77 69 6e 64 6f 77 73 5c 74 65 6d 70 5c 72 2e 65 78 65 20 2f 66 20 2f 71}
		$ = {64 65 6c 20 63 3a 5c 77 69 6e 64 6f 77 73 5c 74 65 6d 70 5c 72 2e 69 6e 69 20 2f 66 20 2f 71}

	condition:
		3 of them
}

import "pe"

rule malware_apt15_royaldll_2 : hardened
{
	meta:
		author = "Ahmed Zaki"
		sha256 = "bc937f6e958b339f6925023bc2af375d669084e9551fd3753e501ef26e36b39d"
		description = "DNS backdoor used by APT15"
		reference = "https://www.nccgroup.trust/us/about-us/newsroom-and-events/blog/2018/march/apt15-is-alive-and-strong-an-analysis-of-royalcli-and-royaldns/"

	strings:
		$ = {((53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 53 76 63 68 6f 73 74) | (53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 4e 00 54 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 53 00 76 00 63 00 68 00 6f 00 73 00 74 00))}
		$ = {((6e 65 74 73 76 63 73) | (6e 00 65 00 74 00 73 00 76 00 63 00 73 00))}
		$ = {((25 53 79 73 74 65 6d 52 6f 6f 74 25 5c 53 79 73 74 65 6d 33 32 5c 73 76 63 68 6f 73 74 2e 65 78 65 20 2d 6b 20 6e 65 74 73 76 63 73) | (25 00 53 00 79 00 73 00 74 00 65 00 6d 00 52 00 6f 00 6f 00 74 00 25 00 5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 73 00 76 00 63 00 68 00 6f 00 73 00 74 00 2e 00 65 00 78 00 65 00 20 00 2d 00 6b 00 20 00 6e 00 65 00 74 00 73 00 76 00 63 00 73 00))}
		$ = {((53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 76 69 63 65 73 5c) | (53 00 59 00 53 00 54 00 45 00 4d 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 43 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 53 00 65 00 74 00 5c 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 73 00 5c 00))}
		$ = {((6d 79 57 4f 62 6a 65 63 74) | (6d 00 79 00 57 00 4f 00 62 00 6a 00 65 00 63 00 74 00))}

	condition:
		uint16( 0 ) == 0x5A4D and all of them and pe.exports ( "ServiceMain" ) and filesize > 50KB and filesize < 600KB
}

rule malware_apt15_exchange_tool : hardened
{
	meta:
		author = "Ahmed Zaki"
		md5 = "d21a7e349e796064ce10f2f6ede31c71"
		description = "This is a an exchange enumeration/hijacking tool used by an APT 15"
		reference = "https://www.nccgroup.trust/us/about-us/newsroom-and-events/blog/2018/march/apt15-is-alive-and-strong-an-analysis-of-royalcli-and-royaldns/"

	strings:
		$s1 = {73 75 62 6a 65 63 74 6e 61 6d 65}
		$s2 = {73 65 6e 64 65 72 6e 61 6d 65}
		$s3 = {57 65 62 43 72 65 64 65 6e 74 69 61 6c 73}
		$s4 = {45 78 63 68 61 6e 67 65 56 65 72 73 69 6f 6e}
		$s5 = {45 78 63 68 61 6e 67 65 43 72 65 64 65 6e 74 69 61 6c 73}
		$s6 = {73 6c 66 69 6c 65 6e 61 6d 65}
		$s7 = {45 6e 75 6d 4d 61 69 6c}
		$s8 = {45 6e 75 6d 46 6f 6c 64 65 72}
		$s9 = {73 65 74 5f 43 72 65 64 65 6e 74 69 61 6c 73}
		$s10 = {2f 00 64 00 65 00}
		$s11 = {2f 00 73 00 6e 00}
		$s12 = {2f 00 73 00 62 00 6e 00}
		$s13 = {2f 00 6c 00 69 00 73 00 74 00}
		$s14 = {2f 00 65 00 6e 00 75 00 6d 00}
		$s15 = {2f 00 73 00 61 00 76 00 65 00}
		$s16 = {2f 00 61 00 6f 00}
		$s17 = {2f 00 73 00 6c 00}
		$s18 = {2f 00 76 00 20 00 6f 00 72 00 20 00 2f 00 74 00 20 00 69 00 73 00 20 00 6e 00 75 00 6c 00 6c 00}
		$s19 = {32 00 30 00 30 00 37 00}
		$s20 = {32 00 30 00 31 00 30 00}
		$s21 = {32 00 30 00 31 00 30 00 73 00 70 00 31 00}
		$s22 = {32 00 30 00 31 00 30 00 73 00 70 00 32 00}
		$s23 = {32 00 30 00 31 00 33 00}
		$s24 = {32 00 30 00 31 00 33 00 73 00 70 00 31 00}

	condition:
		uint16( 0 ) == 0x5A4D and 15 of ( $s* )
}

rule malware_apt15_generic : hardened
{
	meta:
		author = "David Cannings"
		description = "Find generic data potentially relating to AP15 tools"
		reference = "https://www.nccgroup.trust/us/about-us/newsroom-and-events/blog/2018/march/apt15-is-alive-and-strong-an-analysis-of-royalcli-and-royaldns/"

	strings:
		$str01 = {6d 79 57 4f 62 6a 65 63 74}
		$str02 = {6d 79 52 4f 62 6a 65 63 74}
		$opcodes01 = { 6A (02|03) 6A 00 6A 00 68 00 00 00 C0 50 FF 15 }

	condition:
		2 of them
}

