rule INDICATOR_EXE_Packed_ConfuserEx : hardened
{
	meta:
		author = "ditekSHen"
		description = "Detects executables packed with ConfuserEx Mod"
		snort2_sid = "930016-930018"
		snort3_sid = "930005-930006"

	strings:
		$s1 = {43 6f 6e 66 75 73 65 72 45 78 20}
		$s2 = {43 6f 6e 66 75 73 65 64 42 79 41 74 74 72 69 62 75 74 65}
		$c1 = {((43 6f 6e 66 75 73 65 72 2e 43 6f 72 65 20) | (43 00 6f 00 6e 00 66 00 75 00 73 00 65 00 72 00 2e 00 43 00 6f 00 72 00 65 00 20 00))}
		$u1 = {43 6f 6e 66 75 20 76}
		$u2 = {43 6f 6e 66 75 42 79 41 74 74 72 69 62 75 74 65}

	condition:
		uint16( 0 ) == 0x5a4d and ( all of ( $s* ) or all of ( $c* ) or all of ( $u* ) )
}

rule INDICATOR_EXE_Packed_ConfuserEx_Custom : hardened
{
	meta:
		author = "ditekSHen"
		description = "Detects executables packed with ConfuserEx Custom; outside of GIT"

	strings:
		$s1 = { 43 6f 6e 66 75 73 65 72 45 78 20 76 [1-2] 2e [1-2] 2e [1-2] 2d 63 75 73 74 6f 6d }

	condition:
		uint16( 0 ) == 0x5a4d and all of them
}

rule INDICATOR_EXE_Packed_ConfuserExMod_BedsProtector : hardened
{
	meta:
		author = "ditekSHen"
		description = "Detects executables packed with ConfuserEx Mod Beds Protector"
		snort2_sid = "930019-930024"
		snort3_sid = "930007-930008"

	strings:
		$s1 = {42 65 64 73 20 50 72 6f 74 65 63 74 6f 72 20 76}
		$s2 = {42 65 64 73 2d 50 72 6f 74 65 63 74 6f 72 2d 76}

	condition:
		uint16( 0 ) == 0x5a4d and 1 of them
}

rule INDICATOR_EXE_Packed_ConfuserExMod_Trinity : hardened
{
	meta:
		author = "ditekSHen"
		description = "Detects executables packed with ConfuserEx Mod Trinity Protector"
		snort2_sid = "930025-930030"
		snort3_sid = "930009-930010"

	strings:
		$s1 = {54 72 69 6e 69 74 79 30 2d 70 72 6f 74 65 63 6f 72 7c}
		$s2 = {23 54 72 69 6e 69 74 79 50 72 6f 74 65 63 74 6f 72}
		$s3 = /Trinity\d-protector\|/ ascii

	condition:
		uint16( 0 ) == 0x5a4d and 1 of them
}

rule INDICATOR_EXE_Packed_PS2EXE : hardened
{
	meta:
		author = "ditekSHen"
		description = "Detects executables built or packed with PS2EXE"
		snort2_sid = "930004-930006"
		snort3_sid = "930001"

	strings:
		$s1 = {50 53 32 45 58 45}
		$s2 = {50 53 32 45 58 45 41 70 70}
		$s3 = {50 53 32 45 58 45 48 6f 73 74}
		$s4 = {50 53 32 45 58 45 48 6f 73 74 55 49}
		$s5 = {50 53 32 45 58 45 48 6f 73 74 52 61 77 55 49}

	condition:
		uint16( 0 ) == 0x5a4d and 1 of them
}

rule INDICATOR_EXE_Packed_LSD : hardened
{
	meta:
		author = "ditekSHen"
		description = "Detects executables built or packed with LSD packer"
		snort2_sid = "930058-930060"
		snort3_sid = "930021"

	strings:
		$s1 = {54 68 69 73 20 66 69 6c 65 20 69 73 20 70 61 63 6b 65 64 20 77 69 74 68 20 74 68 65 20 4c 53 44 20 65 78 65 63 75 74 61 62 6c 65 20 70 61 63 6b 65 72}
		$s2 = {68 74 74 70 3a 2f 2f 6c 73 64 2e 64 67 2e 63 6f 6d}
		$s3 = {26 56 30 4c 53 44 21 24}

	condition:
		( uint16( 0 ) == 0x5a4d or uint16( 0 ) == 0x457f ) and 1 of them
}

rule INDICATOR_EXE_Packed_AspireCrypt : hardened
{
	meta:
		author = "ditekSHen"
		description = "Detects executables packed with AspireCrypt"
		snort2_sid = "930013-930015"
		snort3_sid = "930004"

	strings:
		$s1 = {41 73 70 69 72 65 43 72 79 70 74}
		$s2 = {61 73 70 69 72 65 63 72 79 70 74 2e 6e 65 74}
		$s3 = {70 72 6f 74 65 63 74 65 64 20 62 79 20 41 73 70 69 72 65 43 72 79 70 74}

	condition:
		uint16( 0 ) == 0x5a4d and 1 of them
}

rule INDICATOR_EXE_Packed_Spices : hardened
{
	meta:
		author = "ditekSHen"
		description = "Detects executables packed with 9Rays.Net Spices.Net Obfuscator."
		snort2_sid = "930001-930003"
		snort3_sid = "930000"

	strings:
		$s1 = {39 52 61 79 73 2e 4e 65 74 20 53 70 69 63 65 73 2e 4e 65 74}
		$s2 = {70 72 6f 74 65 63 74 65 64 20 62 79 20 39 52 61 79 73 2e 4e 65 74 20 53 70 69 63 65 73 2e 4e 65 74 20 4f 62 66 75 73 63 61 74 6f 72}

	condition:
		uint16( 0 ) == 0x5a4d and 1 of them
}

rule INDICATOR_JAVA_Packed_Allatori : hardened
{
	meta:
		author = "ditekSHen"
		description = "Detects files packed with Allatori Java Obfuscator"

	strings:
		$s1 = {((23 20 4f 62 66 75 73 63 61 74 69 6f 6e 20 62 79 20 41 6c 6c 61 74 6f 72 69 20 4f 62 66 75 73 63 61 74 6f 72) | (23 00 20 00 4f 00 62 00 66 00 75 00 73 00 63 00 61 00 74 00 69 00 6f 00 6e 00 20 00 62 00 79 00 20 00 41 00 6c 00 6c 00 61 00 74 00 6f 00 72 00 69 00 20 00 4f 00 62 00 66 00 75 00 73 00 63 00 61 00 74 00 6f 00 72 00))}

	condition:
		all of them
}

import "pe"

rule INDICATOR_EXE_Packed_Titan : hardened
{
	meta:
		author = "ditekSHen"
		description = "Detects executables packed with Titan"
		snort2_sid = "930010-930012"
		snort3_sid = "930003"

	strings:
		$s1 = { 00 00 ?? 2e 74 69 74 61 6e 00 00 }

	condition:
		uint16( 0 ) == 0x5a4d and all of them or for any i in ( 0 .. pe.number_of_sections ) : ( ( pe.sections [ i ] . name == ".titan" ) )
}

rule INDICATOR_EXE_Packed_aPLib : hardened
{
	meta:
		author = "ditekSHen"
		description = "Detects executables packed with aPLib."

	strings:
		$header = { 41 50 33 32 18 00 00 00 [0-35] 4D 38 5A 90 }

	condition:
		(( uint32( 0 ) == 0x32335041 and uint32( 24 ) == 0x905a384d ) or ( uint16( 0 ) == 0x5a4d and $header ) )
}

rule INDICATOR_EXE_Packed_LibZ : hardened
{
	meta:
		author = "ditekSHen"
		description = "Detects executables built or packed with LibZ"
		snort2_sid = "930055-930057"
		snort3_sid = "930019-930020"

	strings:
		$s1 = {4c 69 62 5a 2e 49 6e 6a 65 63 74 65 64}
		$s2 = {7b 00 30 00 3a 00 4e 00 7d 00 2e 00 64 00 6c 00 6c 00}
		$s3 = {61 00 73 00 6d 00 7a 00 3a 00 2f 00 2f 00 28 00 3f 00 3c 00 67 00 75 00 69 00 64 00 3e 00 5b 00 30 00 2d 00 39 00 61 00 2d 00 66 00 41 00 2d 00 46 00 5d 00 7b 00 33 00 32 00 7d 00 29 00 2f 00 28 00 3f 00 3c 00 73 00 69 00 7a 00 65 00 3e 00 5b 00 30 00 2d 00 39 00 5d 00 2b 00 29 00 28 00 2f 00 28 00 3f 00 3c 00 66 00 6c 00 61 00 67 00 73 00 3e 00 5b 00 61 00 2d 00 7a 00 41 00 2d 00 5a 00 30 00 2d 00 39 00 5d 00 2a 00 29 00 29 00 3f 00}
		$s4 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 53 00 6f 00 66 00 74 00 70 00 61 00 72 00 6b 00 5c 00 4c 00 69 00 62 00 5a 00}
		$s5 = {28 00 41 00 73 00 6d 00 5a 00 2f 00 7b 00}
		$s6 = {61 73 6d 7a 3a 2f 2f}
		$s7 = {47 65 74 52 65 67 69 73 74 72 79 44 57 4f 52 44}
		$s8 = {52 45 47 49 53 54 52 59 5f 4b 45 59 5f 4e 41 4d 45}
		$s9 = {52 45 47 49 53 54 52 59 5f 4b 45 59 5f 50 41 54 48}
		$s10 = {49 6e 69 74 69 61 6c 69 7a 65 44 65 63 6f 64 65 72 73}

	condition:
		uint16( 0 ) == 0x5a4d and 5 of them
}

rule INDICATOR_EXE_Python_Byte_Compiled : hardened
{
	meta:
		author = "ditekSHen"
		description = "Detects python-byte compiled executables"

	strings:
		$s1 = {62 36 34 64 65 63 6f 64 65}
		$s2 = {64 65 63 6f 6d 70 72 65 73 73}

	condition:
		uint32( 0 ) == 0x0a0df303 and filesize < 5KB and all of them
}

rule INDICATOR_MSI_EXE2MSI : hardened
{
	meta:
		author = "ditekSHen"
		description = "Detects executables converted to .MSI packages using a free online converter."
		snort2_sid = "930061-930063"
		snort3_sid = "930022"

	strings:
		$winin = {57 69 6e 64 6f 77 73 20 49 6e 73 74 61 6c 6c 65 72}
		$title = {45 78 65 20 74 6f 20 6d 73 69 20 63 6f 6e 76 65 72 74 65 72 20 66 72 65 65}

	condition:
		uint32( 0 ) == 0xe011cfd0 and ( $winin and $title )
}

import "pe"

rule INDICATOR_EXE_Packed_MPress : hardened
{
	meta:
		author = "ditekSHen"
		description = "Detects executables built or packed with MPress PE compressor"
		snort2_sid = "930031-930033"
		snort3_sid = "930011"

	strings:
		$s1 = {2e 4d 50 52 45 53 53 31}
		$s2 = {2e 4d 50 52 45 53 53 32}

	condition:
		uint16( 0 ) == 0x5a4d and 1 of them or for any i in ( 0 .. pe.number_of_sections ) : ( ( pe.sections [ i ] . name == ".MPRESS1" or pe.sections [ i ] . name == ".MPRESS2" ) )
}

import "pe"

rule INDICATOR_EXE_Packed_Nate : hardened
{
	meta:
		author = "ditekSHen"
		description = "Detects executables built or packed with Nate packer"
		snort2_sid = "930034-930036"
		snort3_sid = "930012"

	strings:
		$s1 = {40 2e 6e 61 74 65 30}
		$s2 = {60 2e 6e 61 74 65 31}

	condition:
		uint16( 0 ) == 0x5a4d and 1 of them or for any i in ( 0 .. pe.number_of_sections ) : ( ( pe.sections [ i ] . name == ".nate0" or pe.sections [ i ] . name == ".nate1" ) )
}

import "pe"

rule INDICATOR_EXE_Packed_VMProtect : hardened
{
	meta:
		author = "ditekSHen"
		description = "Detects executables packed with VMProtect."
		snort2_sid = "930049-930051"
		snort3_sid = "930017"

	strings:
		$s1 = {2e 76 6d 70 30}
		$s2 = {2e 76 6d 70 31}

	condition:
		uint16( 0 ) == 0x5a4d and all of them or for any i in ( 0 .. pe.number_of_sections ) : ( ( pe.sections [ i ] . name == ".vmp0" or pe.sections [ i ] . name == ".vmp1" ) )
}

rule INDICATOR_EXE_DotNET_Encrypted : hardened
{
	meta:
		author = "ditekSHen"
		description = "Detects encrypted or obfuscated .NET executables"
		score = 65

	strings:
		$s1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67}
		$s2 = {54 6f 43 68 61 72 41 72 72 61 79}
		$s3 = {52 65 61 64 42 79 74 65 73}
		$s4 = {61 64 64 5f 41 73 73 65 6d 62 6c 79 52 65 73 6f 6c 76 65}
		$s5 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d}
		$s6 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72}
		$bytes1 = { 08 01 00 08 00 00 00 00 00 1e 01 00 01 00 54 02
                    16 57 72 61 70 4e 6f 6e 45 78 63 65 70 74 69 6f 
                    6e 54 68 72 6f 77 73 01 }
		$bytes2 = { 00 00 42 53 4a 42 01 00 01 00 00 00 00 00 0c 00 
                    00 00 76 3? 2e 3? 2e ?? ?? ?? ?? ?? 00 00 00 00
                    05 00 }
		$bytes3 = { 00 00 23 53 74 72 69 6e 67 73 00 00 00 00 [5] 00 
                    00 00 23 55 53 00 [5] 00 00 00 23 47 55 49 44 00 
                    00 00 [6] 00 00 23 42 6c 6f 62 00 00 00 }
		$bytes4 = { 00 47 65 74 53 74 72 69 6e 67 00 73 65 74 5f 57
                    6f 72 6b 69 6e 67 44 69 72 65 63 74 6f 72 79 00
                    57 61 69 74 46 6f 72 45 78 69 74 00 43 6c 6f 73
                    65 00 54 68 72 65 61 64 00 53 79 73 74 65 6d 2e
                    54 68 72 65 61 64 69 6e 67 00 53 6c 65 65 70 00
                    54 6f 49 6e 74 33 32 00 67 65 74 5f 4d 61 69 6e
                    4d 6f 64 75 6c 65 00 50 72 6f 63 65 73 73 4d 6f
                    64 75 6c 65 00 67 65 74 5f 46 69 6c 65 4e 61 6d
                    65 00 53 70 6c 69 74 00 }

	condition:
		uint16( 0 ) == 0x5a4d and 3 of ( $bytes* ) and all of ( $s* )
}

rule INDICATOR_PY_Packed_PyMinifier : hardened
{
	meta:
		author = "ditekSHen"
		description = "Detects python code potentially obfuscated using PyMinifier"

	strings:
		$s1 = {65 78 65 63 28 6c 7a 6d 61 2e 64 65 63 6f 6d 70 72 65 73 73 28 62 61 73 65 36 34 2e 62 36 34 64 65 63 6f 64 65 28}

	condition:
		( uint32( 0 ) == 0x6f706d69 or uint16( 0 ) == 0x2123 or uint16( 0 ) == 0x0a0d or uint16( 0 ) == 0x5a4d ) and all of them
}

import "pe"

rule INDICATOR_EXE_Packed_BoxedApp : hardened
{
	meta:
		author = "ditekSHen"
		description = "Detects executables packed with BoxedApp"
		snort2_sid = "930037-930042"
		snort3_sid = "930013-930014"

	strings:
		$s1 = {42 6f 78 65 64 41 70 70 53 44 4b 5f 48 6f 6f 6b 46 75 6e 63 74 69 6f 6e}
		$s2 = {42 6f 78 65 64 41 70 70 53 44 4b 5f 53 74 61 74 69 63 4c 69 62 2e 63 70 70}
		$s3 = {65 6d 62 65 64 64 69 6e 67 20 42 6f 78 65 64 41 70 70 20 69 6e 74 6f 20 63 68 69 6c 64 20 70 72 6f 63 65 73 73 65 73 3a 20 25 73}
		$s4 = {47 65 74 43 6f 6d 6d 61 6e 64 4c 69 6e 65 41 20 70 72 65 70 61 72 69 6e 67 20 74 6f 20 69 6e 74 65 72 63 65 70 74}

	condition:
		uint16( 0 ) == 0x5a4d and 2 of them or for any i in ( 0 .. pe.number_of_sections ) : ( ( pe.sections [ i ] . name contains ".bxpck" ) )
}

import "pe"

rule INDICATOR_EXE_Packed_eXPressor : hardened
{
	meta:
		author = "ditekSHen"
		description = "Detects executables packed with eXPressor"
		snort2_sid = "930043-930048"
		snort3_sid = "930015-930016"

	strings:
		$s1 = {65 58 50 72 65 73 73 6f 72 5f 49 6e 73 74 61 6e 63 65 43 68 65 63 6b 65 72 5f}
		$s2 = {54 68 69 73 20 61 70 70 6c 69 63 61 74 69 6f 6e 20 77 61 73 20 70 61 63 6b 65 64 20 77 69 74 68 20 61 6e 20 55 6e 72 65 67 69 73 74 65 72 65 64 20 76 65 72 73 69 6f 6e 20 6f 66 20 65 58 50 72 65 73 73 6f 72}
		$s3 = {2c 20 70 6c 65 61 73 65 20 76 69 73 69 74 20 77 77 77 2e 63 67 73 6f 66 74 6c 61 62 73 2e 72 6f}
		$s4 = /eXPr-v\.\d+\.\d+/ ascii

	condition:
		uint16( 0 ) == 0x5a4d and 2 of them or for any i in ( 0 .. pe.number_of_sections ) : ( ( pe.sections [ i ] . name contains ".ex_cod" ) )
}

import "pe"

rule INDICATOR_EXE_Packed_MEW : hardened
{
	meta:
		author = "ditekSHen"
		description = "Detects executables packed with MEW"

	condition:
		uint16( 0 ) == 0x5a4d and for any i in ( 0 .. pe.number_of_sections ) : ( ( pe.sections [ i ] . name == "MEW" or pe.sections [ i ] . name == "\x02\xd2u\xdb\x8a\x16\xeb\xd4" ) )
}

import "pe"

rule INDICATOR_EXE_Packed_RLPack : hardened
{
	meta:
		author = "ditekSHen"
		description = "Detects executables packed with RLPACK"
		snort2_sid = "930064-930066"
		snort3_sid = "930023"

	strings:
		$s1 = {2e 70 61 63 6b 65 64}
		$s2 = {2e 52 4c 50 61 63 6b}

	condition:
		uint16( 0 ) == 0x5a4d and all of them or for any i in ( 0 .. pe.number_of_sections ) : ( ( pe.sections [ i ] . name == ".RLPack" ) )
}

rule INDICATOR_EXE_Packed_Cassandra : hardened
{
	meta:
		author = "ditekSHen"
		description = "Detects executables packed with Cassandra/CyaX"

	strings:
		$s1 = {((41 6e 74 69 45 4d) | (41 00 6e 00 74 00 69 00 45 00 4d 00))}
		$s2 = {((41 6e 74 69 53 42) | (41 00 6e 00 74 00 69 00 53 00 42 00))}
		$s3 = {((41 6e 74 69 73) | (41 00 6e 00 74 00 69 00 73 00))}
		$s4 = {((58 4f 52 5f 44 45 43) | (58 00 4f 00 52 00 5f 00 44 00 45 00 43 00))}
		$s5 = {((53 74 61 72 74 49 6e 6a 65 63 74) | (53 00 74 00 61 00 72 00 74 00 49 00 6e 00 6a 00 65 00 63 00 74 00))}
		$s6 = {((44 65 74 65 63 74 47 61 77 61 64 61 6b 61) | (44 00 65 00 74 00 65 00 63 00 74 00 47 00 61 00 77 00 61 00 64 00 61 00 6b 00 61 00))}
		$c1 = {((43 79 61 58 2d 53 68 61 72 70) | (43 00 79 00 61 00 58 00 2d 00 53 00 68 00 61 00 72 00 70 00))}
		$c2 = {((43 79 61 58 5f 53 68 61 72 70) | (43 00 79 00 61 00 58 00 5f 00 53 00 68 00 61 00 72 00 70 00))}
		$c3 = {((43 79 61 58 2d 50 4e 47) | (43 00 79 00 61 00 58 00 2d 00 50 00 4e 00 47 00))}
		$c4 = {((43 79 61 58 5f 50 4e 47) | (43 00 79 00 61 00 58 00 5f 00 50 00 4e 00 47 00))}
		$pdb = {((5c 43 79 61 58 5c 6f 62 6a 5c 44 65 62 75 67 5c 43 79 61 58 2e 70 64 62) | (5c 00 43 00 79 00 61 00 58 00 5c 00 6f 00 62 00 6a 00 5c 00 44 00 65 00 62 00 75 00 67 00 5c 00 43 00 79 00 61 00 58 00 2e 00 70 00 64 00 62 00))}

	condition:
		( uint16( 0 ) == 0x5a4d and ( 4 of ( $s* ) or 2 of ( $c* ) or $pdb ) ) or ( 7 of them )
}

rule INDICATOR_EXE_Packed_SilentInstallBuilder : hardened
{
	meta:
		author = "ditekSHen"
		description = "Detects executables packed with Silent Install Builder"
		snort2_sid = "930070-930072"
		snort3_sid = "930025"

	strings:
		$s1 = {43 3a 5c 55 73 65 72 73 5c 4f 70 65 72 61 74 69 6f 6e 73 5c 53 6f 75 72 63 65 5c 57 6f 72 6b 73 70 61 63 65 73 5c 53 69 62 5c 53 69 62 6c 5c 52 65 6c 65 61 73 65 5c 53 69 62 75 69 61 2e 70 64 62}
		$s2 = {2d 00 3e 00 6d 00 62 00 21 00 53 00 69 00 6c 00 65 00 6e 00 74 00 20 00 49 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 20 00 42 00 75 00 69 00 6c 00 64 00 65 00 72 00 20 00 44 00 65 00 6d 00 6f 00 20 00 50 00 61 00 63 00 6b 00 61 00 67 00 65 00 2e 00}

	condition:
		uint16( 0 ) == 0x5a4d and 1 of them
}

rule INDICATOR_EXE_Packed_Bonsai : hardened
{
	meta:
		author = "ditekSHen"
		description = "Detects .NET executables developed using Bonsai"

	strings:
		$bonsai1 = {3c 42 6f 6e 73 61 69 2e}
		$bonsai2 = {42 6f 6e 73 61 69 2e 50 72 6f 70 65 72 74 69 65 73}
		$bonsai3 = {42 00 6f 00 6e 00 73 00 61 00 69 00 2e 00 43 00 6f 00 72 00 65 00 2e 00 64 00 6c 00 6c 00}
		$bonsai4 = {42 00 6f 00 6e 00 73 00 61 00 69 00 2e 00 44 00 65 00 73 00 69 00 67 00 6e 00 2e 00}

	condition:
		uint16( 0 ) == 0x5a4d and 2 of ( $bonsai* )
}

import "pe"

rule INDICATOR_EXE_Packed_TriumphLoader : hardened
{
	meta:
		author = "ditekSHen"
		description = "Detects TriumphLoader"
		snort2_sid = "920101"
		snort3_sid = "920099"
		clamav_sig = "INDICATOR.Packed.TriumphLoader"

	strings:
		$id1 = {((55 73 65 72 2d 41 67 65 6e 74 3a 20 54 72 69 75 6d 70 68 4c 6f 61 64 65 72) | (55 00 73 00 65 00 72 00 2d 00 41 00 67 00 65 00 6e 00 74 00 3a 00 20 00 54 00 72 00 69 00 75 00 6d 00 70 00 68 00 4c 00 6f 00 61 00 64 00 65 00 72 00))}
		$id2 = {5c 00 6c 00 6f 00 61 00 64 00 65 00 72 00 5c 00 61 00 62 00 73 00 65 00 6e 00 74 00 2d 00 6c 00 6f 00 61 00 64 00 65 00 72 00 2d 00 6d 00 61 00 73 00 74 00 65 00 72 00 5c 00 63 00 6c 00 69 00 65 00 6e 00 74 00 5c 00 66 00 75 00 6c 00 6c 00 5c 00 61 00 62 00 73 00 65 00 6e 00 74 00 63 00 6c 00 69 00 65 00 6e 00 74 00 66 00 75 00 6c 00 6c 00 5c 00 61 00 62 00 73 00 65 00 6e 00 74 00 63 00 6c 00 69 00 65 00 6e 00 74 00 66 00 75 00 6c 00 6c 00 5c 00 61 00 62 00 73 00 65 00 6e 00 74 00 5c 00 6a 00 73 00 6f 00 6e 00 2e 00 68 00 70 00 70 00}
		$id3 = {5c 00 74 00 72 00 69 00 75 00 6d 00 70 00 68 00 6c 00 6f 00 61 00 64 00 65 00 72 00 5c 00 74 00 72 00 69 00 75 00 6d 00 70 00 68 00 6c 00 6f 00 61 00 64 00 65 00 72 00 66 00 69 00 6c 00 65 00 73 00 5c 00 74 00 72 00 69 00 75 00 6d 00 70 00 68 00 5c 00 6a 00 73 00 6f 00 6e 00 2e 00 68 00}
		$s1 = {63 00 75 00 72 00 72 00 65 00 6e 00 74 00 20 00 3d 00 3d 00 20 00 27 00 5c 00 5c 00 22 00 27 00}
		$s2 = {30 30 30 31 30 32 30 33 30 34 30 35 30 36 30 37 30 38 30 39 31 30 31 31 31 32 31 33 31 34 31 35 31 36 31 37 31 38 31 39 32 30 32 31 32 32 32 33 32 34 32 35 32 36 32 37 32 38 32 39 33 30 33 31 33 32 33 33 33 34 33 35 33 36 33 37 33 38 33 39 34 30 34 31 34 32 34 33 34 34 34 35 34 36 34 37 34 38 34 39 35 30 35 31 35 32 35 33 35 34 35 35 35 36 35 37 35 38 35 39 36 30 36 31 36 32 36 33}
		$s3 = {36 34 36 35 36 36 36 37 36 38 36 39 37 30 37 31 37 32 37 33 37 34 37 35 37 36 37 37 37 38 37 39 38 30 38 31 38 32 38 33 38 34 38 35 38 36 38 37 38 38 38 39 39 30 39 31 39 32 39 33 39 34 39 35 39 36 39 37 39 38 39 39 6f 62 6a 65 63 74 20 6b 65 79}
		$s4 = {65 00 6e 00 64 00 70 00 74 00 72 00 20 00 3d 00 3d 00 20 00 74 00 6f 00 6b 00 65 00 6e 00 5f 00 62 00 75 00 66 00 66 00 65 00 72 00 2e 00 64 00 61 00 74 00 61 00 28 00 29 00 20 00 2b 00 20 00 74 00 6f 00 6b 00 65 00 6e 00 5f 00 62 00 75 00 66 00 66 00 65 00 72 00 2e 00 73 00 69 00 7a 00 65 00 28 00 29 00}
		$s5 = {6c 00 61 00 73 00 74 00 20 00 2d 00 20 00 66 00 69 00 72 00 73 00 74 00 20 00 3e 00 3d 00 20 00 32 00 20 00 2b 00 20 00 28 00 2d 00 6b 00 4d 00 69 00 6e 00 45 00 78 00 70 00 20 00 2d 00 20 00 31 00 29 00 20 00 2b 00 20 00 73 00 74 00 64 00 3a 00 3a 00 6e 00 75 00 6d 00 65 00 72 00 69 00 63 00 5f 00 6c 00 69 00 6d 00 69 00 74 00 73 00 3c 00 46 00 6c 00 6f 00 61 00 74 00 54 00 79 00 70 00 65 00 3e 00 3a 00 3a 00 6d 00 61 00 78 00 5f 00 64 00 69 00 67 00 69 00 74 00 73 00 31 00 30 00}
		$s6 = {70 00 32 00 20 00 3c 00 3d 00 20 00 28 00 73 00 74 00 64 00 3a 00 3a 00 6e 00 75 00 6d 00 65 00 72 00 69 00 63 00 5f 00 6c 00 69 00 6d 00 69 00 74 00 73 00 3c 00 73 00 74 00 64 00 3a 00 3a 00 75 00 69 00 6e 00 74 00 36 00 34 00 5f 00 74 00 3e 00 3a 00 3a 00 6d 00 61 00 78 00 29 00 28 00 29 00 20 00 2f 00 20 00 31 00 30 00}

	condition:
		uint16( 0 ) == 0x5a4d and ( 1 of ( $id* ) or all of ( $s* ) or ( 3 of ( $s* ) and 1 of ( $id* ) ) or ( 4 of them and pe.imphash ( ) == "784001f4b755832ae9085d98afc9ce83" ) )
}

import "pe"

rule INDICATOR_EXE_Packed_LLVMLoader : hardened
{
	meta:
		author = "ditekSHen"
		description = "Detects LLVM obfuscator/loader"
		clamav_sig = "INDICATOR.Packed.LLVMLoader"

	strings:
		$s1 = {65 78 65 4c 6f 61 64 65 72 44 6c 6c 5f 4c 4c 56 4d 4f 2e 64 6c 6c}
		$b = { 64 6c 6c 00 53 74 61 72 74 46 75 6e 63 00 00 00
               ?? ?? 00 00 00 00 00 00 00 00 00 ?? 96 01 00 00
               ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00
               00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? 00 00
               00 00 00 00 00 00 00 00 00 00 00 ?? ?? 45 78 69
               74 50 72 6f 63 65 73 73 00 4b 45 52 4e 45 4c 33
               32 2e 64 6c 6c 00 00 00 00 00 00 }

	condition:
		( uint16( 0 ) == 0x5a4d or uint16( 0 ) == 0x0158 ) and ( ( pe.exports ( "StartFunc" ) and 1 of ( $s* ) ) or all of ( $s* ) or ( $b ) )
}

import "pe"

rule INDICATOR_EXE_Packed_NoobyProtect : hardened
{
	meta:
		author = "ditekSHen"
		description = "Detects executables packed with NoopyProtect"

	strings:
		$s1 = {4e 6f 6f 62 79 50 72 6f 74 65 63 74 20 53 45}

	condition:
		uint16( 0 ) == 0x5a4d and all of them or for any i in ( 0 .. pe.number_of_sections ) : ( ( pe.sections [ i ] . name == "SE" ) )
}

rule INDICATOR_EXE_Packed_nBinder : hardened
{
	meta:
		author = "ditekSHen"
		description = "Detects executables packed with nBinder"

	strings:
		$s1 = {54 68 69 73 20 66 69 6c 65 20 77 61 73 20 63 72 65 61 74 65 64 20 75 73 69 6e 67 20 6e 42 69 6e 64 65 72}
		$s2 = {57 61 72 6e 69 6e 67 3a 20 43 6f 6e 74 61 69 6e 73 20 62 69 6e 64 65 64 20 66 69 6c 65 73 20 74 68 61 74 20 6d 61 79 20 70 6f 73 65 20 61 20 73 65 63 75 72 69 74 79 20 72 69 73 6b 2e}
		$s3 = {61 20 66 69 6c 65 20 63 72 65 61 74 65 64 20 77 69 74 68 20 6e 42 69 6e 64 65 72}
		$s4 = {6e 61 6d 65 3d 22 4e 4b 50 72 6f 64 73 2e 6e 42 69 6e 64 65 72 2e 55 6e 70 61 63 6b 65 72 22 20 74 79 70 65 3d 22 77 69 6e}
		$s5 = {3c 64 65 73 63 72 69 70 74 69 6f 6e 3e 6e 42 69 6e 64 65 72 20 55 6e 70 61 63 6b 65 72 2e 20 77 77 77 2e 6e 6b 70 72 6f 64 73 2e 63 6f 6d 3c 2f 64 65 73 63 72 69 70 74 69 6f 6e 3e}
		$s6 = {6e 00 42 00 69 00 6e 00 64 00 65 00 72 00 20 00 55 00 6e 00 70 00 61 00 63 00 6b 00 65 00 72 00 20 00 28 00 43 00 29 00 20 00 4e 00 4b 00 50 00 72 00 6f 00 64 00 73 00}
		$s7 = {5c 50 72 6f 69 65 63 74 65 5c 6e 42 69 6e}

	condition:
		uint16( 0 ) == 0x5a4d and 2 of them
}

rule INDICATOR_EXE_Packed_AgileDotNet : hardened
{
	meta:
		author = "ditekSHen"
		description = "Detects executables packed with Agile.NET / CliSecure"

	strings:
		$x1 = {41 67 69 6c 65 44 6f 74 4e 65 74 52 54}
		$x2 = {41 67 69 6c 65 44 6f 74 4e 65 74 52 54 36 34}
		$x3 = {3c 41 67 69 6c 65 44 6f 74 4e 65 74 52 54 3e}
		$x4 = {41 67 69 6c 65 44 6f 74 4e 65 74 52 54 2e 64 6c 6c}
		$x5 = {41 67 69 6c 65 44 6f 74 4e 65 74 52 54 36 34 2e 64 6c 6c}
		$x6 = {67 65 74 5f 41 67 69 6c 65 44 6f 74 4e 65 74}
		$x7 = {75 73 65 41 67 69 6c 65 44 6f 74 4e 65 74 53 74 61 63 6b 46 72 61 6d 65 73}
		$x8 = {41 67 69 6c 65 44 6f 74 4e 65 74 2e}
		$x9 = {3a 2f 2f 73 65 63 75 72 65 74 65 61 6d 2e 6e 65 74 2f 77 65 62 73 65 72 76 69 63 65 73}
		$x10 = {41 67 69 6c 65 44 6f 74 4e 65 74 50 72 6f 74 65 63 74 6f 72 2e}
		$s1 = {43 61 6c 6c 76 69 72 74}
		$s2 = {5f 49 6e 69 74 69 61 6c 69 7a 65 36 34}
		$s3 = {5f 41 74 45 78 69 74 36 34}
		$s4 = {44 6f 6d 61 69 6e 55 6e 6c 6f 61 64}

	condition:
		uint16( 0 ) == 0x5a4d and ( 2 of ( $x* ) or ( 1 of ( $x* ) and 2 of ( $s* ) ) or all of ( $s* ) )
}

rule INDICATOR_EXE_Packed_Costura : hardened
{
	meta:
		author = "ditekSHen"
		description = "Detects executables packed with Costura DotNetGuard"

	strings:
		$s1 = {44 6f 74 4e 65 74 47 75 61 72 64}
		$s2 = {((63 6f 73 74 75 72 61 2e) | (63 00 6f 00 73 00 74 00 75 00 72 00 61 00 2e 00))}
		$s3 = {((41 73 73 65 6d 62 6c 79 4c 6f 61 64 65 72) | (41 00 73 00 73 00 65 00 6d 00 62 00 6c 00 79 00 4c 00 6f 00 61 00 64 00 65 00 72 00))}

	condition:
		uint16( 0 ) == 0x5a4d and all of them
}

rule INDICATOR_EXE_Packed_SimplePolyEngine : hardened
{
	meta:
		author = "ditekSHen"
		description = "Detects executables packed with Sality Polymorphic Code Generator or Simple Poly Engine or Sality"

	strings:
		$s1 = {53 69 6d 70 6c 65 20 50 6f 6c 79 20 45 6e 67 69 6e 65 20 76}
		$b1 = {79 72 66 3c 5b 4c 6f 72 64 50 45 5d}
		$b2 = {48 00 65 00 6c 00 6c 00 6f 00 20 00 77 00 6f 00 72 00 6c 00 64 00 21 00}

	condition:
		uint16( 0 ) == 0x5a4d and ( all of ( $s* ) or all of ( $b* ) )
}

rule INDICATOR_EXE_Packed_DotNetReactor : hardened
{
	meta:
		author = "ditekSHen"
		description = "Detects executables packed with unregistered version of .NET Reactor"

	strings:
		$s1 = {69 00 73 00 20 00 70 00 72 00 6f 00 74 00 65 00 63 00 74 00 65 00 64 00 20 00 62 00 79 00 20 00 61 00 6e 00 20 00 75 00 6e 00 72 00 65 00 67 00 69 00 73 00 74 00 65 00 72 00 65 00 64 00 20 00 76 00 65 00 72 00 73 00 69 00 6f 00 6e 00 20 00 6f 00 66 00 20 00 45 00 7a 00 69 00 72 00 69 00 7a 00 27 00 73 00 22 00 2e 00 4e 00 45 00 54 00 20 00 52 00 65 00 61 00 63 00 74 00 6f 00 72 00 22 00 21 00}
		$s2 = {69 00 73 00 20 00 70 00 72 00 6f 00 74 00 65 00 63 00 74 00 65 00 64 00 20 00 62 00 79 00 20 00 61 00 6e 00 20 00 75 00 6e 00 72 00 65 00 67 00 69 00 73 00 74 00 65 00 72 00 65 00 64 00 20 00 76 00 65 00 72 00 73 00 69 00 6f 00 6e 00 20 00 6f 00 66 00 20 00 2e 00 4e 00 45 00 54 00 20 00 52 00 65 00 61 00 63 00 74 00 6f 00 72 00 21 00 22 00 20 00 29 00 3b 00 3c 00 2f 00 73 00 63 00 72 00 69 00 70 00 74 00 3e 00}

	condition:
		uint16( 0 ) == 0x5a4d and 1 of them
}

rule INDICATOR_EXE_Packed_DNGuard : hardened
{
	meta:
		author = "ditekSHen"
		description = "Detects executables packed with DNGuard"

	strings:
		$s1 = {44 00 4e 00 47 00 75 00 61 00 72 00 64 00 20 00 52 00 75 00 6e 00 74 00 69 00 6d 00 65 00 20 00 6c 00 69 00 62 00 72 00 61 00 72 00 79 00}
		$s2 = {5b 00 2a 00 3d 00 2a 00 5d 00 54 00 68 00 69 00 73 00 20 00 61 00 70 00 70 00 6c 00 69 00 63 00 61 00 74 00 69 00 6f 00 6e 00 20 00 69 00 73 00 20 00 65 00 78 00 70 00 69 00 72 00 65 00 64 00 20 00 21 00 5b 00 2a 00 3d 00 2a 00 5d 00}
		$s3 = {((44 4e 47 75 61 72 64 2e 52 75 6e 74 69 6d 65) | (44 00 4e 00 47 00 75 00 61 00 72 00 64 00 2e 00 52 00 75 00 6e 00 74 00 69 00 6d 00 65 00))}
		$s4 = {45 6e 61 62 6c 65 48 56 4d}
		$s5 = {44 4e 47 75 61 72 64 2e 53 44 4b}
		$s6 = {44 00 4e 00 47 00 75 00 61 00 72 00 64 00 20 00 48 00 56 00 4d 00 20 00 52 00 75 00 6e 00 74 00 69 00 6d 00 65 00}
		$s7 = {48 00 56 00 4d 00 52 00 75 00 6e 00 74 00 6d 00 2e 00 64 00 6c 00 6c 00}

	condition:
		uint16( 0 ) == 0x5a4d and 2 of them
}

rule INDICATOR_EXE_Packed_NETProtectIO : hardened
{
	meta:
		author = "ditekSHen"
		description = "Detects executables packed with NETProtect.IO"

	strings:
		$s1 = {4e 45 54 50 72 6f 74 65 63 74 2e 49 4f 20 76}

	condition:
		uint16( 0 ) == 0x5a4d and 1 of them
}

rule INDICATOR_EXE_Packed_KoiVM : hardened
{
	meta:
		author = "ditekSHen"
		description = "Detects executables packed with or use KoiVM"

	strings:
		$s1 = {((4b 6f 69 56 4d 20 76) | (4b 00 6f 00 69 00 56 00 4d 00 20 00 76 00))}
		$s2 = {((44 61 72 6b 73 56 4d 20) | (44 00 61 00 72 00 6b 00 73 00 56 00 4d 00 20 00))}
		$s3 = {((4b 6f 69 2e 4e 47) | (4b 00 6f 00 69 00 2e 00 4e 00 47 00))}

	condition:
		uint16( 0 ) == 0x5a4d and 1 of them
}

rule INDICATOR_EXE_Packed_Babel : hardened
{
	meta:
		author = "ditekSHen"
		description = "Detects executables packed with Babel"

	strings:
		$s1 = {42 61 62 65 6c 4f 62 66 75 73 63 61 74 6f 72 41 74 74 72 69 62 75 74 65}

	condition:
		uint16( 0 ) == 0x5a4d and 1 of them
}

