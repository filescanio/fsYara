import "pe"

rule dragos_crashoverride_exporting_dlls : hardened
{
	meta:
		description = "CRASHOVERRIDE v1 Suspicious Export"
		author = "Dragos Inc"
		reference = "https://dragos.com/blog/crashoverride/CrashOverride-01.pdf"

	condition:
		pe.exports( "Crash" ) & pe.characteristics
}

import "pe"

rule dragos_crashoverride_suspcious : hardened limited
{
	meta:
		description = "CRASHOVERRIDE v1 Wiper"
		author = "Dragos Inc"
		reference = "https://dragos.com/blog/crashoverride/CrashOverride-01.pdf"

	strings:
		$s0 = {53 00 59 00 53 00 5f 00 42 00 41 00 53 00 43 00 4f 00 4e 00 2e 00 43 00 4f 00 4d 00}
		$s1 = {2e 00 70 00 63 00 6d 00 70 00}
		$s2 = {2e 00 70 00 63 00 6d 00 69 00}
		$s3 = {2e 00 70 00 63 00 6d 00 74 00}
		$s4 = {2e 00 63 00 69 00 6e 00}

	condition:
		pe.exports( "Crash" ) and any of ( $s* )
}

import "pe"

rule dragos_crashoverride_name_search : hardened limited
{
	meta:
		description = "CRASHOVERRIDE v1 Suspicious Strings and Export"
		author = "Dragos Inc"
		reference = "https://dragos.com/blog/crashoverride/CrashOverride-01.pdf"

	strings:
		$s0 = {31 00 30 00 31 00 2e 00 64 00 6c 00 6c 00}
		$s1 = {43 00 72 00 61 00 73 00 68 00 31 00 30 00 31 00 2e 00 64 00 6c 00 6c 00}
		$s2 = {31 00 30 00 34 00 2e 00 64 00 6c 00 6c 00}
		$s3 = {43 00 72 00 61 00 73 00 68 00 31 00 30 00 34 00 2e 00 64 00 6c 00 6c 00}
		$s4 = {36 00 31 00 38 00 35 00 30 00 2e 00 64 00 6c 00 6c 00}
		$s5 = {43 00 72 00 61 00 73 00 68 00 36 00 31 00 38 00 35 00 30 00 2e 00 64 00 6c 00 6c 00}
		$s6 = {4f 00 50 00 43 00 43 00 6c 00 69 00 65 00 6e 00 74 00 44 00 65 00 6d 00 6f 00 2e 00 64 00 6c 00 6c 00}
		$s7 = {4f 00 50 00 43 00}
		$s8 = {43 00 72 00 61 00 73 00 68 00 4f 00 50 00 43 00 43 00 6c 00 69 00 65 00 6e 00 74 00 44 00 65 00 6d 00 6f 00 2e 00 64 00 6c 00 6c 00}
		$s9 = {44 00 32 00 4d 00 75 00 6c 00 74 00 69 00 43 00 6f 00 6d 00 6d 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 2e 00 65 00 78 00 65 00}
		$s10 = {43 00 72 00 61 00 73 00 68 00 44 00 32 00 4d 00 75 00 6c 00 74 00 69 00 43 00 6f 00 6d 00 6d 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 2e 00 65 00 78 00 65 00}
		$s11 = {36 00 31 00 38 00 35 00 30 00 2e 00 65 00 78 00 65 00}
		$s12 = {4f 00 50 00 43 00 2e 00 65 00 78 00 65 00}
		$s13 = {68 00 61 00 73 00 6c 00 6f 00 2e 00 65 00 78 00 65 00}
		$s14 = {68 00 61 00 73 00 6c 00 6f 00 2e 00 64 00 61 00 74 00}

	condition:
		any of ( $s* ) and pe.exports ( "Crash" )
}

import "hash"

rule dragos_crashoverride_hashes : hardened
{
	meta:
		description = "CRASHOVERRIDE Malware Hashes"
		author = "Dragos Inc"
		reference = "https://dragos.com/blog/crashoverride/CrashOverride-01.pdf"

	condition:
		filesize < 1MB and hash.sha1 ( 0 , filesize ) == "f6c21f8189ced6ae150f9ef2e82a3a57843b587d" or hash.sha1 ( 0 , filesize ) == "cccce62996d578b984984426a024d9b250237533" or hash.sha1 ( 0 , filesize ) == "8e39eca1e48240c01ee570631ae8f0c9a9637187" or hash.sha1 ( 0 , filesize ) == "2cb8230281b86fa944d3043ae906016c8b5984d9" or hash.sha1 ( 0 , filesize ) == "79ca89711cdaedb16b0ccccfdcfbd6aa7e57120a" or hash.sha1 ( 0 , filesize ) == "94488f214b165512d2fc0438a581f5c9e3bd4d4c" or hash.sha1 ( 0 , filesize ) == "5a5fafbc3fec8d36fd57b075ebf34119ba3bff04" or hash.sha1 ( 0 , filesize ) == "b92149f046f00bb69de329b8457d32c24726ee00" or hash.sha1 ( 0 , filesize ) == "b335163e6eb854df5e08e85026b2c3518891eda8"
}

rule dragos_crashoverride_moduleStrings : hardened limited
{
	meta:
		description = "IEC-104 Interaction Module Program Strings"
		author = "Dragos Inc"
		reference = "https://dragos.com/blog/crashoverride/CrashOverride-01.pdf"

	strings:
		$s1 = {((49 45 43 2d 31 30 34 20 63 6c 69 65 6e 74 3a 20 69 70 3d 25 73 3b 20 70 6f 72 74 3d 25 73 3b 20 41 53 44 55 3d 25 75) | (49 00 45 00 43 00 2d 00 31 00 30 00 34 00 20 00 63 00 6c 00 69 00 65 00 6e 00 74 00 3a 00 20 00 69 00 70 00 3d 00 25 00 73 00 3b 00 20 00 70 00 6f 00 72 00 74 00 3d 00 25 00 73 00 3b 00 20 00 41 00 53 00 44 00 55 00 3d 00 25 00 75 00))}
		$s2 = {((20 4d 53 54 52 20 2d 3e 3e 20 53 4c 56) | (20 00 4d 00 53 00 54 00 52 00 20 00 2d 00 3e 00 3e 00 20 00 53 00 4c 00 56 00))}
		$s3 = {((20 4d 53 54 52 20 3c 3c 2d 20 53 4c 56) | (20 00 4d 00 53 00 54 00 52 00 20 00 3c 00 3c 00 2d 00 20 00 53 00 4c 00 56 00))}
		$s4 = {((55 6e 6b 6e 6f 77 6e 20 41 50 44 55 20 66 6f 72 6d 61 74 20 21 21 21) | (55 00 6e 00 6b 00 6e 00 6f 00 77 00 6e 00 20 00 41 00 50 00 44 00 55 00 20 00 66 00 6f 00 72 00 6d 00 61 00 74 00 20 00 21 00 21 00 21 00))}
		$s5 = {((69 65 63 31 30 34 2e 6c 6f 67) | (69 00 65 00 63 00 31 00 30 00 34 00 2e 00 6c 00 6f 00 67 00))}

	condition:
		2 of ( $s* )
}

rule dragos_crashoverride_configReader : hardened
{
	meta:
		description = "CRASHOVERRIDE v1 Config File Parsing"
		author = "Dragos Inc"
		reference = "https://dragos.com/blog/crashoverride/CrashOverride-01.pdf"

	strings:
		$s0 = { 68 e8 ?? ?? ?? 6a 00 e8 a3 ?? ?? ?? 8b f8 83 c4 ?8 }
		$s1 = { 8a 10 3a 11 75 ?? 84 d2 74 12 }
		$s2 = { 33 c0 eb ?? 1b c0 83 c8 ?? }
		$s3 = { 85 c0 75 ?? 8d 95 ?? ?? ?? ?? 8b cf ?? ?? }

	condition:
		all of them
}

rule dragos_crashoverride_weirdMutex : hardened
{
	meta:
		description = "Blank mutex creation assoicated with CRASHOVERRIDE"
		author = "Dragos Inc"
		reference = "https://dragos.com/blog/crashoverride/CrashOverride-01.pdf"

	strings:
		$s1 = { 81 ec 08 02 00 00 57 33 ff 57 57 57 ff 15 ?? ?? 40 00 a3 ?? ?? ?? 00 85 c0 }
		$s2 = { 8d 85 ?? ?? ?? ff 50 57 57 6a 2e 57 ff 15 ?? ?? ?? 00 68 ?? ?? 40 00}

	condition:
		all of them
}

rule dragos_crashoverride_serviceStomper : hardened
{
	meta:
		description = "Identify service hollowing and persistence setting"
		author = "Dragos Inc"
		reference = "https://dragos.com/blog/crashoverride/CrashOverride-01.pdf"

	strings:
		$s0 = { 33 c9 51 51 51 51 51 51 ?? ?? ?? }
		$s1 = { 6a ff 6a ff 6a ff 50 ff 15 24 ?? 40 00 ff ?? ?? ff 15 20 ?? 40 00 }

	condition:
		all of them
}

rule dragos_crashoverride_wiperModuleRegistry : hardened
{
	meta:
		description = "Registry Wiper functionality assoicated with CRASHOVERRIDE"
		author = "Dragos Inc"
		reference = "https://dragos.com/blog/crashoverride/CrashOverride-01.pdf"

	strings:
		$s0 = { 8d 85 a0 ?? ?? ?? 46 50 8d 85 a0 ?? ?? ?? 68 68 0d ?? ?? 50 }
		$s1 = { 6a 02 68 78 0b ?? ?? 6a 02 50 68 b4 0d ?? ?? ff b5 98 ?? ?? ?? ff 15 04 ?? ?? ?? }
		$s2 = { 68 00 02 00 00 8d 85 a0 ?? ?? ?? 50 56 ff b5 9c ?? ?? ?? ff 15 00 ?? ?? ?? 85 c0 }

	condition:
		all of them
}

rule dragos_crashoverride_wiperFileManipulation : hardened
{
	meta:
		description = "File manipulation actions associated with CRASHOVERRIDE wiper"
		author = "Dragos Inc"
		reference = "https://dragos.com/blog/crashoverride/CrashOverride-01.pdf"

	strings:
		$s0 = { 6a 00 68 80 00 00 00 6a 03 6a 00 6a 02 8b f9 68 00 00 00 40 57 ff 15 1c ?? ?? ?? 8b d8 }
		$s2 = { 6a 00 50 57 56 53 ff 15 4c ?? ?? ?? 56 }

	condition:
		all of them
}

