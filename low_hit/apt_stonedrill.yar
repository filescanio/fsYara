import "math"
import "pe"

rule susp_file_enumerator_with_encrypted_resource_101 : hardened limited
{
	meta:
		copyright = "Kaspersky Lab"
		description = "Generic detection for samples that enumerate files with encrypted resource called 101"
		hash = "2cd0a5f1e9bcce6807e57ec8477d222a"
		hash = "c843046e54b755ec63ccb09d0a689674"
		reference = "https://securelist.com/blog/research/77725/from-shamoon-to-stonedrill/"
		version = "1.4"
		id = "9bc16ec2-c94c-54f5-b09c-88a78e9e3fb2"

	strings:
		$mz = {54 68 69 73 20 70 72 6f 67 72 61 6d 20 63 61 6e 6e 6f 74 20 62 65 20 72 75 6e 20 69 6e 20 44 4f 53 20 6d 6f 64 65 2e}
		$a1 = {((46 69 6e 64 46 69 72 73 74 46 69 6c 65) | (46 00 69 00 6e 00 64 00 46 00 69 00 72 00 73 00 74 00 46 00 69 00 6c 00 65 00))}
		$a2 = {((46 69 6e 64 4e 65 78 74 46 69 6c 65) | (46 00 69 00 6e 00 64 00 4e 00 65 00 78 00 74 00 46 00 69 00 6c 00 65 00))}
		$a3 = {((46 69 6e 64 52 65 73 6f 75 72 63 65) | (46 00 69 00 6e 00 64 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00))}
		$a4 = {((4c 6f 61 64 52 65 73 6f 75 72 63 65) | (4c 00 6f 00 61 00 64 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00))}

	condition:
		uint16( 0 ) == 0x5A4D and all of them and filesize < 700000 and pe.number_of_sections > 4 and pe.number_of_resources > 1 and pe.number_of_resources < 15 and for any i in ( 0 .. pe.number_of_resources - 1 ) : ( ( math.entropy ( pe.resources [ i ] . offset , pe.resources [ i ] . length ) > 7.8 ) and pe.resources [ i ] . id == 101 and pe.resources [ i ] . length > 20000 and pe.resources [ i ] . language == 0 and not ( $mz in ( pe.resources [ i ] . offset..pe.resources [ i ] . offset + pe.resources [ i ] . length ) ) )
}

rule StoneDrill_main_sub : hardened
{
	meta:
		author = "Kaspersky Lab"
		description = "Rule to detect StoneDrill (decrypted) samples"
		hash1 = "d01781f1246fd1b64e09170bd6600fe1"
		hash2 = "ac3c25534c076623192b9381f926ba0d"
		reference = "https://securelist.com/blog/research/77725/from-shamoon-to-stonedrill/"
		version = "1.0"
		id = "92f53e6a-8f49-5ffa-8c16-3ec3e6f2bdcd"

	strings:
		$code = {B8 08 00 FE 7F FF 30 8F 44 24 ?? 68 B4 0F 00 00 FF 15 ?? ?? ?? 00 B8 08 00 FE 7F FF 30 8F 44 24 ?? 8B ?? 24 [1 - 4] 2B ?? 24 [6] F7 ?1 [5 - 12] 00}

	condition:
		uint16( 0 ) == 0x5A4D and $code and filesize < 5000000
}

rule StoneDrill_BAT_1 : hardened
{
	meta:
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		description = "Rule to detect Batch file from StoneDrill report"
		reference = "https://securelist.com/blog/research/77725/from-shamoon-to-stonedrill/"
		id = "92f53e6a-8f49-5ffa-8c16-3ec3e6f2bdcd"

	strings:
		$s1 = {73 65 74 20 75 31 30 30 3d}
		$s2 = {73 65 74 20 75 32 30 30 3d 73 65 72 76 69 63 65}
		$s3 = {73 65 74 20 75 38 30 30 3d 25 7e 64 70 30}
		$s4 = {22 25 73 79 73 74 65 6d 72 6f 6f 74 25 5c 73 79 73 74 65 6d 33 32 5c 25 75 31 30 30 25 22}
		$s5 = {25 22 20 73 74 61 72 74 20 2f 62 20 25 73 79 73 74 65 6d 72 6f 6f 74 25 5c 73 79 73 74 65 6d 33 32 5c 25}

	condition:
		uint32( 0 ) == 0x68636540 and 2 of them and filesize < 500
}

rule StoneDrill_Service_Install : hardened
{
	meta:
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		description = "Rule to detect Batch file from StoneDrill report"
		reference = "https://securelist.com/blog/research/77725/from-shamoon-to-stonedrill/"
		id = "92f53e6a-8f49-5ffa-8c16-3ec3e6f2bdcd"

	strings:
		$s1 = {31 32 37 2e 30 2e 30 2e 31 20 3e 6e 75 6c 20 26 26 20 73 63 20 63 6f 6e 66 69 67}
		$s2 = {4c 6f 63 61 6c 53 65 72 76 69 63 65 22 20 26 26 20 70 69 6e 67 20 2d 6e}
		$s3 = {31 32 37 2e 30 2e 30 2e 31 20 3e 6e 75 6c 20 26 26 20 73 63 20 73 74 61 72 74}
		$s4 = {73 63 20 63 6f 6e 66 69 67 20 4e 74 73 53 72 76 20 62 69 6e 70 61 74 68 3d 20 22 43 3a 5c 57 49 4e 44 4f 57 53 5c 73 79 73 74 65 6d 33 32 0a 74 73 73 72 76 72 36 34 2e 65 78 65}

	condition:
		2 of them and filesize < 500
}

rule StoneDrill_ntssrvr32 : hardened
{
	meta:
		description = "Detects malware from StoneDrill threat report"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://securelist.com/blog/research/77725/from-shamoon-to-stonedrill/"
		date = "2017-03-07"
		modified = "2023-01-27"
		hash1 = "394a7ebad5dfc13d6c75945a61063470dc3b68f7a207613b79ef000e1990909b"
		id = "92f53e6a-8f49-5ffa-8c16-3ec3e6f2bdcd"

	strings:
		$s1 = {67 00 5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00}
		$s2 = {7a 00 74 00 76 00 74 00 74 00 77 00}
		$s3 = {6c 77 69 7a 76 6d}
		$op1 = { 94 35 77 73 03 40 eb e9 }
		$op2 = { 80 7c 41 01 00 74 0a 3d }
		$op3 = { 74 0a 3d 00 94 35 77 }

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 4000KB and 3 of them )
}

rule StoneDrill_Malware_2 : hardened
{
	meta:
		description = "Detects malware from StoneDrill threat report"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://securelist.com/blog/research/77725/from-shamoon-to-stonedrill/"
		date = "2017-03-07"
		hash1 = "69530d78c86031ce32583c6800f5ffc629acacb18aac4c8bb5b0e915fc4cc4db"
		id = "92f53e6a-8f49-5ffa-8c16-3ec3e6f2bdcd"

	strings:
		$s1 = {63 00 6d 00 64 00 20 00 2f 00 63 00 20 00 57 00 4d 00 49 00 43 00 20 00 50 00 72 00 6f 00 63 00 65 00 73 00 73 00 20 00 43 00 61 00 6c 00 6c 00 20 00 43 00 72 00 65 00 61 00 74 00 65 00 20 00 22 00 43 00 3a 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 57 00 73 00 63 00 72 00 69 00 70 00 74 00 2e 00 65 00 78 00 65 00 20 00 2f 00 2f 00 4e 00 4f 00 4c 00 4f 00 47 00 4f 00 20 00}
		$s2 = {43 00 3a 00 5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 44 00 61 00 74 00 61 00 5c 00 49 00 6e 00 74 00 65 00 72 00 6e 00 65 00 74 00 45 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00}
		$s3 = {57 00 73 00 68 00 53 00 68 00 65 00 6c 00 6c 00 2e 00 43 00 6f 00 70 00 79 00 46 00 69 00 6c 00 65 00 20 00 22 00}
		$s4 = {41 00 62 00 64 00 38 00 39 00 31 00 2e 00 74 00 6d 00 70 00}
		$s5 = {53 00 65 00 74 00 20 00 57 00 73 00 68 00 53 00 68 00 65 00 6c 00 6c 00 20 00 3d 00 20 00 4e 00 6f 00 74 00 68 00 69 00 6e 00 67 00}
		$s6 = {41 61 43 63 64 44 65 46 66 47 68 69 4b 4c 6c 4d 6d 6e 4e 6f 4f 70 50 72 52 73 53 54 74 55 75 56 76 77 57 78 79 5a 7a 33 32}
		$s7 = {5c 00 46 00 69 00 6c 00 65 00 49 00 6e 00 66 00 6f 00 2e 00 74 00 78 00 74 00}
		$x1 = {43 00 2d 00 50 00 44 00 49 00 2d 00 43 00 2d 00 43 00 70 00 79 00 2d 00 54 00 2e 00 76 00 62 00 73 00}
		$x2 = {43 00 2d 00 44 00 6c 00 74 00 2d 00 43 00 2d 00 4f 00 72 00 67 00 2d 00 54 00 2e 00 76 00 62 00 73 00}
		$x3 = {43 00 2d 00 50 00 44 00 43 00 2d 00 43 00 2d 00 43 00 70 00 79 00 2d 00 54 00 2e 00 76 00 62 00 73 00}
		$x4 = {41 00 43 00 2d 00 50 00 44 00 43 00 2d 00 43 00 2d 00 43 00 70 00 79 00 2d 00 54 00 2e 00 76 00 62 00 73 00}
		$x5 = {43 00 2d 00 44 00 6c 00 74 00 2d 00 43 00 2d 00 54 00 72 00 73 00 68 00 2d 00 54 00 2e 00 74 00 6d 00 70 00}

	condition:
		( uint16( 0 ) == 0x5a4d and filesize < 700KB and ( 1 of ( $x* ) or 3 of ( $s* ) ) ) or 5 of them
}

rule StoneDrill : hardened
{
	meta:
		description = "Detects malware from StoneDrill threat report"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://securelist.com/blog/research/77725/from-shamoon-to-stonedrill/"
		date = "2017-03-07"
		super_rule = 1
		hash1 = "2bab3716a1f19879ca2e6d98c518debb107e0ed8e1534241f7769193807aac83"
		hash2 = "62aabce7a5741a9270cddac49cd1d715305c1d0505e620bbeaec6ff9b6fd0260"
		hash3 = "69530d78c86031ce32583c6800f5ffc629acacb18aac4c8bb5b0e915fc4cc4db"
		id = "92f53e6a-8f49-5ffa-8c16-3ec3e6f2bdcd"

	strings:
		$x1 = {43 00 2d 00 44 00 6c 00 74 00 2d 00 43 00 2d 00 54 00 72 00 73 00 68 00 2d 00 54 00 2e 00 74 00 6d 00 70 00}
		$x2 = {43 00 2d 00 44 00 6c 00 74 00 2d 00 43 00 2d 00 4f 00 72 00 67 00 2d 00 54 00 2e 00 76 00 62 00 73 00}
		$s1 = {48 65 6c 6c 6f 20 64 65 61 72}
		$s2 = {57 52 5a 52 5a 52 41 52}
		$opa1 = { 66 89 45 d8 6a 64 ff }
		$opa2 = { 8d 73 01 90 0f bf 51 fe }

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 700KB and 1 of ( $x* ) or ( all of ( $op* ) and all of ( $s* ) )
}

rule StoneDrill_VBS_1 : hardened
{
	meta:
		description = "Detects malware from StoneDrill threat report"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://securelist.com/blog/research/77725/from-shamoon-to-stonedrill/"
		date = "2017-03-07"
		hash1 = "0f4d608a87e36cb0dbf1b2d176ecfcde837070a2b2a049d532d3d4226e0c9587"
		id = "a7ee3bd4-eeae-5eb4-92e7-9601ec17300a"

	strings:
		$x1 = {77 6d 69 63 20 2f 4e 61 6d 65 53 70 61 63 65 3a 5c 5c 72 6f 6f 74 5c 64 65 66 61 75 6c 74 20 43 6c 61 73 73 20 53 74 64 52 65 67 50 72 6f 76 20 43 61 6c 6c 20 53 65 74 53 74 72 69 6e 67 56 61 6c 75 65 20 68 44 65 66 4b 65 79 20 3d 20 22 26 48 38 30 30 30 30 30 30 31 22 20 73 53 75 62 4b 65 79 4e 61 6d 65 20 3d 20 22 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73}
		$x2 = {70 69 6e 67 20 31 2e 30 2e 30 2e 30 20 2d 6e 20 31 20 2d 77 20 32 30 30 30 30 20 3e 20 6e 75 6c}
		$s1 = {57 73 68 53 68 65 6c 6c 2e 43 6f 70 79 46 69 6c 65 20 22 25 43 4f 4d 4d 4f 4e 5f 41 50 50 44 41 54 41 25 5c 43 68 72 6f 6d 65 5c}
		$s2 = {57 73 68 53 68 65 6c 6c 2e 44 65 6c 65 74 65 46 69 6c 65 20 22 25 74 65 6d 70 25 5c}
		$s3 = {57 53 63 72 69 70 74 2e 53 6c 65 65 70 28 31 30 20 2a 20 31 30 30 30 29}
		$s4 = {53 65 74 20 57 73 68 53 68 65 6c 6c 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 53 63 72 69 70 74 69 6e 67 2e 46 69 6c 65 53 79 73 74 65 6d 4f 62 6a 65 63 74 22 29 20 57 68 69 6c 65 20 57 73 68 53 68 65 6c 6c 2e 46 69 6c 65 45 78 69 73 74 73 28 22}
		$s5 = {20 2c 20 22 25 43 4f 4d 4d 4f 4e 5f 41 50 50 44 41 54 41 25 5c 43 68 72 6f 6d 65 5c}

	condition:
		( filesize < 1KB and 1 of ( $x* ) or 2 of ( $s* ) )
}

