rule SMB_Worm_Tool : hardened
{
	strings:
		$STR1 = {47 6c 6f 62 61 6c 5c 46 77 74 53 71 6d 53 65 73 73 69 6f 6e 31 30 36 38 32 39 33 32 33 5f 53 2d 31 2d 35 2d 31 39}
		$STR2 = {45 56 45 52 59 4f 4e 45}
		$STR3 = {79 30 75 61 72 33 40 73 21 6c 6c 79 69 64 21 30 37 2c 6f 75 37 34 6e 36 30 75 37 66 30 30 31}
		$STR4 = {5c 4b 42 32 35 34 36 38 2e 64 61 74}

	condition:
		( uint16( 0 ) == 0x5A4D or uint16( 0 ) == 0xCFD0 or uint16( 0 ) == 0xC3D4 or uint32( 0 ) == 0x46445025 or uint32( 1 ) == 0x6674725C ) and all of them
}

rule Lightweight_Backdoor1 : hardened
{
	strings:
		$STR1 = {4e 65 74 4d 67 53 74 61 72 74}
		$STR2 = {4e 65 74 6d 67 6d 74 2e 73 72 67}

	condition:
		( uint16( 0 ) == 0x5A4D ) and all of them
}

rule LightweightBackdoor2 : hardened limited
{
	strings:
		$STR1 = {((70 72 78 54 72 6f 79) | (70 00 72 00 78 00 54 00 72 00 6f 00 79 00))}

	condition:
		( uint16( 0 ) == 0x5A4D or uint16( 0 ) == 0xCFD0 or uint16( 0 ) == 0xC3D4 or uint32( 0 ) == 0x46445025 or uint32( 1 ) == 0x6674725C ) and all of them
}

rule LightweightBackdoor3 : hardened
{
	strings:
		$strl = { C6 45 E8 64 C6 45 E9 61 C6 45 EA 79 C6 45 EB 69 C6 45 EC 70 C6 45 ED 6D C6 45 EE 72 C6 45 EF 2E C6 45 F0 74 C6 45 F1  62 C6 45 F2 6C }

	condition:
		( uint16( 0 ) == 0x5A4D or uint16( 0 ) == 0xCFD0 or uint16( 0 ) == 0xC3D4 or uint32( 0 ) == 0x46445025 or uint32( 1 ) == 0x6674725C ) and all of them
}

rule LightweightBackdoor4 : hardened
{
	strings:
		$strl = { C6 45 F4 61 C6 45 F5 6E C6 45 F6 73 C6 45 F7 69 C6 45 F8 2E C6 45 F9 6E C6 45 FA 6C C6 45 FB 73 }

	condition:
		( uint16( 0 ) == 0x5A4D or uint16( 0 ) == 0xCFD0 or uint16( 0 ) == 0xC3D4 or uint32( 0 ) == 0x46445025 or uint32( 1 ) == 0x6674725C ) and all of them
}

rule LightweightBackdoor5 : hardened
{
	strings:
		$strl = { C6 45 F4 74 C6 45 F5 6C C6 45 F6 76 C6 45 F7 63 C6 45 F8 2E C6 45 F9 6E C6 45 FA 6C C6 45 FB 73 }

	condition:
		( uint16( 0 ) == 0x5A4D or uint16( 0 ) == 0xCFD0 or uint16( 0 ) == 0xC3D4 or uint32( 0 ) == 0x46445025 or uint32( 1 ) == 0x6674725C ) and all of them
}

rule LightweightBackdoor6 : hardened
{
	strings:
		$STR1 = { 8A 10 80 ?? 4E 80 ?? 79 88 10}
		$STR2 = { 8A 10 80?? 79 80 ?? 4E 88 10}

	condition:
		( uint16( 0 ) == 0x5A4D or uint16( 0 ) == 0xCFD0 or uint16( 0 ) == 0xC3D4 or uint32( 0 ) == 0x46445025 or uint32( 1 ) == 0x6674725C ) and all of them
}

rule ProxyTool1 : hardened
{
	strings:
		$STR1 = {70 00 6d 00 73 00 63 00 6f 00 6e 00 66 00 69 00 67 00 2e 00 6d 00 73 00 69 00}
		$STR2 = {70 00 6d 00 73 00 6c 00 6f 00 67 00 2e 00 6d 00 73 00 69 00}

	condition:
		( uint16( 0 ) == 0x5A4D or uint16( 0 ) == 0xCFD0 or uint16( 0 ) == 0xC3D4 or uint32( 0 ) == 0x46445025 or uint32( 1 ) == 0x6674725C ) and any of them
}

rule ProxyTool2 : hardened
{
	strings:
		$STR1 = { 82 F4 DE D4 D3 C2 CA F5 C8 C8 D3 82 FB F4 DE D4 D3 C2 CA 94 95 FB D4 D1 C4 CF C8 D4 D3 89 C2 DF C2 87 8A CC 87 00 }

	condition:
		( uint16( 0 ) == 0x5A4D or uint16( 0 ) == 0xCFD0 or uint16( 0 ) == 0xC3D4 or uint32( 0 ) == 0x46445025 or uint32( 1 ) == 0x6674725C ) and all of them
}

rule ProxyTool3 : hardened
{
	strings:
		$STR2 = {8A 04 17 8B FB 34 A7 46 88 02 83 C9 FF}

	condition:
		( uint16( 0 ) == 0x5A4D or uint16( 0 ) == 0xCFD0 or uint16( 0 ) == 0xC3D4 or uint32( 0 ) == 0x46445025 or uint32( 1 ) == 0x6674725C ) and $STR2
}

rule DestructiveHardDriveTool1 : hardened
{
	strings:
		$str0 = {4d 5a}
		$str1 = {c6 84 24 ?? ( 00 | 01 ) 00 00 }
		$xorInLoop = { 83 EC 20 B9 08 00 00 00 33 D2 56 8B 74 24 30 57 8D 7C 24 08 F3 A5 8B 7C 24 30 85 FF 7E 3A 8B 74 24 2C 8A 44 24 08 53 8A 4C 24 21 8A 5C 24 2B 32 C1 8A 0C 32 32 C3 32 C8 88 0C 32 B9 1E 00 00 00 8A 5C 0C 0C 88 5C 0C 0D 49 83 F9 FF 7F F2 42 88 44 24 0C 3B D7 7C D0 5B 5F 5E 83 C4 20 C3 }

	condition:
		$str0 at 0 and $xorInLoop and #str1 > 300
}

rule DestructiveTargetCleaningTool2 : hardened
{
	strings:
		$secureWipe = { 83 EC 34 53 55 8B 6C 24 40 56 57 83 CE FF 55 C7 44 24 2C D3 00 00 00 C7 44 24 30 2C 00 00 00 89 74 24 34 89 74 24   38 C7 44 24 3C 95 00 00 00 C7 44 24 40 6A 00 00 00 89 74 24 44 C7 44 24 14 07 00 00 00 FF 15 ?? ?? ?? ?? 3B C6 89 44 24 1C 0F 84 (D8 | d9) 01 00 00 33 FF 68 00 00 01 00 57 FF 15 ?? ?? ?? ?? 8B D8 3B DF 89 5C 24 14 0F 84 (BC | BD) 01 00 00 8B 44 24 1C A8 01 74 0A 24 FE 50 55 FF 15 ?? ?? ?? ?? 8B 44 24 4C 2B C7 74 20 48 74 0F 83 E8 02 75 1C C7 44 24 10 03 00 00 00 EB 12 C7 44 24 10 01 00 00 00 89 74 24 28 EB 04 89 7C 24 10 8B 44 24 10 89 7C 24 1C 3B C7 0F 8E ( 5C | 5d ) 01 00 00 8D 44 24 28 89 44 24 4C EB 03 83 CE FF 8B 4C 24 4C 8B 01 3B C6 74 17 8A D0 B9 00 40 00 00 8A F2 8B FB 8B C2 C1 E0 10 66 8B C2 F3 AB EB ( 13 | 14) 33 F6 (E8 | ff 15) ?? ?? ?? ?? 88 04 1E 46 81 FE 00 00 01 00 7C ( EF | ee) 6A 00 6A 00 6A 03 6A 00 6A 03 68 00 00 00 C0 55 FF 15 ?? ?? ?? ?? 8B F0 83 FE FF 0F 84 FA 00 00 00 8D 44 24 20 50 56 FF 15 ?? ?? ?? ?? 8B 2D ?? ?? ?? ?? 6A 02 6A 00 6A FF 56 FF D5 8D 4C 24 18 6A 00 51 6A 01 53 56 FF 15 ?? ?? ?? ?? 56 FF 15 ?? ?? ?? ?? 6A 00 6A 00 6A 00 56 FF D5 8B 44 24 24 8B 54 24 20 33 FF 33 DB 85 C0 7C 5A   7F 0A 85 D2 76 54 EB 04 8B 54 24 20 8B CA BD 00 00 01 00 2B CF 1B C3 85 C0 7F 0A 7C 04 3B CD 73 04 2B D7 8B EA 8B 44 24 14 8D 54 24 18 6A 00 52 55 50 56 FF 15 ?? ?? ?? ?? 8B 6C 24 18 8B 44 24 24 03 FD 83 D3 00 3B D8 7C BE 7F 08 8B 54 24 20 3B FA 72 B8 8B 2D ?? ?? ?? ?? 8B 5C 24 10 8B 7C 24 1C 8D 4B FF 3B F9 75 17 56 FF 15 ?? ?? ?? ?? 6A 00 6A 00 6A 00 56 FF D5 56 FF 15 ?? ?? ?? ?? 56 FF 15 ?? ?? ?? ?? 56 FF 15 ?? ?? ?? ?? 8B 4C 24 4C 8B 6C 24 48 47 83 C1 04 3B FB 8B 5C 24 14 89 7C 24 1C 89 4C 24 4C 0F 8C ( AE | AD) FE FF FF 6A 00 55 E8 ?? ?? ?? ?? 83 C4 08 53 FF 15 ?? ?? ?? ?? 5F 5E 5D 5B 83 C4 34 C3 }

	condition:
		$secureWipe
}

rule DestructiveTargetCleaningTool3 : hardened limited
{
	strings:
		$S1_CMD_Arg = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 2f 69 6e 73 74 61 6c 6c (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$S2_CMD_Parse = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 22 25 73 22 20 20 2f 69 6e 73 74 61 6c 6c 20 22 25 73 22 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$S3_CMD_Builder = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 22 25 73 22 20 20 22 25 73 22 20 22 25 73 22 20 25 73 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}

	condition:
		all of them
}

rule DestructiveTargetCleaningTool4 : hardened limited
{
	strings:
		$BATCH_SCRIPT_LN1_0 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 67 6f 74 6f 20 78 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$BATCH_SCRIPT_LN1_1 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 64 65 6c (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$BATCH_SCRIPT_LN2_0 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 69 66 20 65 78 69 73 74 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$BATCH_SCRIPT_LN3_0 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 3a 78 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$BATCH_SCRIPT_LN4_0 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 7a 7a 25 64 2e 62 61 74 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}

	condition:
		(#BATCH_SCRIPT_LN1_1 == 2 ) and all of them
}

rule DestructiveTargetCleaningTool5 : hardened
{
	strings:
		$MCU_DLL_ZLIB_COMPRESSED2 = { 5C EC AB AE 81 3C C9 BC D5 A5 42 F4 54 91 04 28 34 34 79 80 6F 71 D5 52 1E 2A 0D }

	condition:
		$MCU_DLL_ZLIB_COMPRESSED2
}

rule DestructiveTargetCleaningTool6 : hardened
{
	strings:
		$MCU_INF_StartHexDec = {010346080A30D63633000B6263750A5052322A00103D1B570A30E67F2A00130952690A503A0D2A000E00A26E15104556766572636C7669642E657865}
		$MCU_INF_StartHexEnc = {6C3272386958BF075230780A0A54676166024968790C7A6779588F5E47312739310163615B3D59686721CF5F2120263E1F5413531F1E004543544C55}

	condition:
		$MCU_INF_StartHexEnc or $MCU_INF_StartHexDec
}

rule DestructiveTargetCleaningTool7 : hardened
{
	strings:
		$a = {53 65 74 46 69 6c 65 50 6f 69 6e 74 65 72}
		$b = {53 65 74 45 6e 64 4f 66 46 69 6c 65}
		$c = {75 17 56 ff 15 ?? ?? ?? ?? 6a 00 6a 00 6a 00 56 ff D5 56 ff 15 ?? ?? ?? ?? 56}

	condition:
		( uint16( 0 ) == 0x5A4D and uint16( uint32( 0x3c ) ) == 0x4550 ) and all of them
}

rule DestructiveTargetCleaningTool8 : hardened
{
	strings:
		$license = {E903FFFF820050006F007200740069006F006E007300200063006F007000790072006900670068007400200052006F006200650072007400200064006500200042006100740068002C0020004A006F007200690073002000760061006E002000520061006E007400770069006A006B002C002000440065006C00690061006E000000000000000250000000000A002200CE000800EA03FFFF8200}
		$PuTTY = {50007500540054005900}

	condition:
		( uint16( 0 ) == 0x5A4D and uint16( uint32( 0x3c ) ) == 0x4550 ) and $license and not $PuTTY
}

rule Malwareusedbycyberthreatactor1 : hardened
{
	strings:
		$heapCreateFunction_0 = {33C06A003944240868001000000F94C050FF15????????85C0A3???????07436E893FEFFFF83F803A3???????0750D68F8030000E8??00000059EB0A83F8027518E8????000085C0750FFF35???????0FF15???????033C0C36A0158C3}
		$heapCreateFunction = { 55 8B EC B8 2C 12 00 00 E8 ?? ?? FF FF 8D 85 68 FF FF FF 53 50 C7 85 68 FF FF FF 94 00 00 00 FF 1? ?? ?? ?? ?0 85 C0 74 1A 83 BD 78 FF FF FF 02 75 11 83 BD 6C FF FF FF 05 72 08 6A 01 58 E9 02 01 00 00 8D 85 D4 ED FF F6 89 01 00 00 05 06 8? ?? ?? ?? 0F F1 5? ?? ?? ?? 08 5C 00 F8 4D 00 00 00 03 3D B8 D8 DD 4E DF FF F3 89 DD DF FF F7 41 38 A0 13 C6 17 C0 83 C7 A7 F0 42 C2 08 80 14 13 81 97 5E D8 D8 5D 4E DF FF F6 A1 65 06 8? ?? ?? ?? 0E 8? ?? ?0 00 08 3C 40 C8 5C 07 50 88 D8 5D 4E DF FF FE B4 98 D8 56 4F EF FF F6 80 40 10 00 05 05 3F F1 5? ?? ?? ?? 03 89 D6 4F EF FF F8 D8 D6 4F EF FF F7 41 38 A0 13 C6 17 C0 83 C7 A7 F0 42 C2 08 80 14 13 81 97 5E D8 D8 56 4F EF FF F5 08 D8 5D 4E DF FF F5 0E 8? ?? ?? ?? ?5 95 93 BC 37 43 E6 A2 C5 0E 8? ?? ?? ?? ?5 93 BC 35 97 43 04 08 BC 83 81 87 40 E8 03 93 B7 50 48 81 9E B0 14 13 81 97 5F 26 A0 A5 35 0E 8? ?? ?0 00 08 3C 40 C8 3F 80 27 41 D8 3F 80 37 41 88 3F 80 17 41 38 D4 5F C5 0E 89 8F EF FF F8 07 DF C0 65 91 BC 08 3C 00 35 BC 9C}
		$getMajorMinorLinker = {568B7424086A00832600FF15???????06681384D5A75148B483C85C9740D03C18A481A880E8A401B8846015EC3}
		$openServiceManager = {FF15???0?0?08B?885??74????????????????5?FF15???0?0?08B?????0?0?08BF?85F?74}

	condition:
		all of them
}

rule Malwareusedbycyberthreatactor2 : hardened
{
	strings:
		$str1 = {5f 71 75 69 74}
		$str2 = {5f 65 78 65}
		$str3 = {5f 70 75 74}
		$str4 = {5f 67 6f 74}
		$str5 = {5f 67 65 74}
		$str6 = {5f 64 65 6c}
		$str7 = {5f 64 69 72}
		$str8 = { C7 44 24 18 1F F7}

	condition:
		( uint16( 0 ) == 0x5A4D or uint16( 0 ) == 0xCFD0 or uint16( 0 ) == 0xC3D4 or uint32( 0 ) == 0x46445025 or uint32( 1 ) == 0x6674725C ) and all of them
}

rule Malwareusedbycyberthreatactor3 : hardened
{
	strings:
		$STR1 = { 50 68 80 00 00 00 68 FF FF 00 00 51 C7 44 24 1C 3a 8b 00 00 }

	condition:
		( uint16( 0 ) == 0x5A4D or uint16( 0 ) == 0xCFD0 or uint16( 0 ) == 0xC3D4 or uint32( 0 ) == 0x46445025 or uint32( 1 ) == 0x6674725C ) and all of them
}

