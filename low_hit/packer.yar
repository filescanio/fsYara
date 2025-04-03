rule emotet_packer : hardened
{
	meta:
		description = "recent Emotet packer pdb string"
		author = "Marc Salinas (@Bondey_m)"
		reference = "330fb2954c1457149988cda98ca8401fbc076802ff44bb30894494b1c5531119"
		reference = "d08a4dc159b17bde8887fa548b7d265108f5f117532d221adf7591fbad29b457"
		reference = "7b5b8aaef86b1a7a8e7f28f0bda0bb7742a8523603452cf38170e5253f7a5c82"
		reference = "e6abb24c70a205ab471028aee22c1f32690c02993b77ee0e77504eb360860776"
		reference = "5684850a7849ab475227da91ada8ac5741e36f98780d9e3b01ae3085a8ef02fc"
		reference = "acefdb67d5c0876412e4d079b38da1a5e67a7fcd936576c99cc712391d3a5ff5"
		reference = "14230ba12360a172f9f242ac98121ca76e7c4450bfcb499c2af89aa3a1ef7440"
		reference = "4fe9b38d2c32d0ee19d7be3c1a931b9448904aa72e888f40f43196e0b2207039"
		reference = "e31028282c38cb13dd4ede7e9c8aa62d45ddae5ebaa0fe3afb3256601dbf5de7"
		date = "2017-12-12"

	strings:
		$pdb1 = {31 32 33 45 45 72 72 72 74 6f 6f 6c 73 2e 70 64 62}
		$pdb2 = {67 47 45 57 5c 46 3f 3f 3f 2f 2e 70 64 62}

	condition:
		$pdb1 or $pdb2
}

rule silent_banker : banker hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a = {6A 40 68 00 30 00 00 6A 14 8D 91}
		$b = {8D 4D B0 2B C1 83 C0 27 99 6A 4E 59 F7 F9}
		$c = {55 56 4f 44 46 52 59 53 49 48 4c 4e 57 50 45 4a 58 51 5a 41 4b 43 42 47 4d 54}

	condition:
		$a or $b or $c
}

rule zbot : banker hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a = {5f 00 5f 00 53 00 59 00 53 00 54 00 45 00 4d 00 5f 00 5f 00}
		$b = {2a 74 61 6e 65 6e 74 72 79 2a}
		$c = {2a 3c 6f 70 74 69 6f 6e}
		$d = {2a 3c 73 65 6c 65 63 74}
		$e = {2a 3c 69 6e 70 75 74}

	condition:
		($a and $b ) or ( $c and $d and $e )
}

rule banbra : banker hardened limited
{
	meta:
		author = "malware-lu"

	strings:
		$a = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 73 65 6e 68 61 (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$b = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 63 61 72 74 61 6f (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$c = {63 61 69 78 61}
		$d = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 6c 6f 67 69 6e (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$e = {2e 63 6f 6d 2e 62 72}

	condition:
		#a> 3 and #b > 3 and #c > 3 and #d > 3 and #e > 3
}

rule Borland : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$patternBorland = {((42 6f 72 6c 61 6e 64) | (42 00 6f 00 72 00 6c 00 61 00 6e 00 64 00))}

	condition:
		$patternBorland
}

import "pe"

rule MSLRHv032afakePCGuard4xxemadicius : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { FC 55 50 E8 00 00 00 00 5D EB 01 E3 60 E8 03 00 00 00 D2 EB 0B 58 EB 01 48 40 EB 01 35 FF E0 E7 61 58 5D EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF }

	condition:
		$a0 at pe.entry_point
}

rule EnigmaProtector1XSukhovVladimirSergeNMarkin : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 00 00 00 56 69 72 74 75 61 6C 41 6C 6C 6F 63 00 00 00 56 69 72 74 75 61 6C 46 72 65 65 00 00 00 47 65 74 4D 6F 64 75 6C 65 48 61 6E 64 6C 65 41 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 45 78 69 74 50 72 6F 63 65 73 73 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 4D 65 73 73 61 67 65 42 6F 78 41 00 00 00 52 65 67 43 6C 6F 73 65 4B 65 79 00 00 00 53 79 73 46 72 65 65 53 74 72 69 6E 67 00 00 00 43 72 65 61 74 65 46 6F 6E 74 41 00 00 00 53 68 65 6C 6C 45 78 65 63 75 74 65 41 00 00 }

	condition:
		$a0
}

rule SPLayerv008 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 8D 40 00 B9 [4] 6A ?? 58 C0 0C [2] 48 [2] 66 13 F0 91 3B D9 [8] 00 00 00 00 }

	condition:
		$a0
}

import "pe"

rule DxPackV086Dxd : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 00 00 00 00 5D 8B FD 81 ED 06 10 40 00 2B BD 94 12 40 00 81 EF 06 00 00 00 83 BD 14 13 40 00 01 0F 84 2F 01 00 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule FSGv110EngdulekxtMicrosoftVisualC60 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 03 DE EB 01 F8 B8 80 ?? 42 00 EB 02 CD 20 68 17 A0 B3 AB EB 01 E8 59 0F B6 DB 68 0B A1 B3 }
		$a1 = { 03 DE EB 01 F8 B8 80 ?? 42 00 EB 02 CD 20 68 17 A0 B3 AB EB 01 E8 59 0F B6 DB 68 0B A1 B3 AB EB 02 CD 20 5E 80 CB AA 2B F1 EB 02 CD 20 43 0F BE 38 13 D6 80 C3 47 2B FE EB 01 F4 03 FE EB 02 4F 4E 81 EF 93 53 7C 3C 80 C3 29 81 F7 8A 8F 67 8B 80 C3 C7 2B FE }
		$a2 = { 91 EB 02 CD 20 BF 50 BC 04 6F 91 BE D0 [2] 6F EB 02 CD 20 2B F7 EB 02 F0 46 8D 1D F4 00 }
		$a3 = { C1 CE 10 C1 F6 0F 68 00 [2] 00 2B FA 5B 23 F9 8D 15 80 [2] 00 E8 01 00 00 00 B6 5E 0B }
		$a4 = { D1 E9 03 C0 68 80 [2] 00 EB 02 CD 20 5E 40 BB F4 00 00 00 33 CA 2B C7 0F B6 16 EB 01 3E }
		$a5 = { E8 01 00 00 00 0E 59 E8 01 00 00 00 58 58 BE 80 [2] 00 EB 02 61 E9 68 F4 00 00 00 C1 C8 }
		$a6 = { EB 01 4D 83 F6 4C 68 80 [2] 00 EB 02 CD 20 5B EB 01 23 68 48 1C 2B 3A E8 02 00 00 00 38 }
		$a7 = { EB 02 AB 35 EB 02 B5 C6 8D 05 80 [2] 00 C1 C2 11 BE F4 00 00 00 F7 DB F7 DB 0F BE 38 E8 }
		$a8 = { EB 02 CD 20 ?? CF [2] 80 [2] 00 [8] 00 }
		$a9 = { F7 DB 80 EA BF B9 2F 40 67 BA EB 01 01 68 AF [2] BA 80 EA 9D 58 C1 C2 09 2B C1 8B D7 68 }

	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point or $a2 at pe.entry_point or $a3 at pe.entry_point or $a4 at pe.entry_point or $a5 at pe.entry_point or $a6 at pe.entry_point or $a7 at pe.entry_point or $a8 at pe.entry_point or $a9 at pe.entry_point
}

import "pe"

rule TPPpackclane : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E8 00 00 00 00 5D 81 ED F5 8F 40 00 60 33 ?? E8 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule FSGv110EngdulekxtMicrosoftVisualC6070 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 0B D0 8B DA E8 02 00 00 00 40 A0 5A EB 01 9D B8 80 [2] 00 EB 02 CD 20 03 D3 8D 35 F4 00 00 00 EB 01 35 EB 01 88 80 CA 7C 80 F3 74 8B 38 EB 02 AC BA 03 DB E8 01 00 00 00 A5 5B C1 C2 0B 81 C7 DA 10 0A 4E EB 01 08 2B D1 83 EF 14 EB 02 CD 20 33 D3 83 EF 27 }
		$a1 = { 0B D0 8B DA E8 02 00 00 00 40 A0 5A EB 01 9D B8 80 [3] EB 02 CD 20 03 D3 8D 35 F4 00 }
		$a2 = { 87 FE E8 02 00 00 00 98 CC 5F BB 80 [2] 00 EB 02 CD 20 68 F4 00 00 00 E8 01 00 00 00 E3 }
		$a3 = { F7 D8 40 49 EB 02 E0 0A 8D 35 80 [3] 0F B6 C2 EB 01 9C 8D 1D F4 00 00 00 EB 01 3C 80 }
		$a4 = { F7 DB 80 EA BF B9 2F 40 67 BA EB 01 01 68 AF ?? A7 BA 80 EA 9D 58 C1 C2 09 2B C1 8B D7 68 }

	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point or $a2 at pe.entry_point or $a3 at pe.entry_point or $a4 at pe.entry_point
}

import "pe"

rule Thinstall24x25xJititSoftware : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC B8 [4] BB [4] 50 E8 00 00 00 00 58 2D [4] B9 [4] BA [4] BE [4] BF [4] BD [4] 03 E8 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule LocklessIntroPack : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 2C E8 [4] 5D 8B C5 81 ED F6 73 [2] 2B 85 [4] 83 E8 06 89 85 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule AHTeamEPProtector03faketElock061FEUERRADER : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 90 [46] 90 FF E0 E9 00 00 00 00 60 E8 00 00 00 00 58 83 C0 08 F3 EB FF E0 83 C0 28 50 E8 00 00 00 00 5E B3 33 8D 46 0E 8D 76 31 28 18 F8 73 00 C3 8B FE B9 3C 02 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule ExeStealth275aWebtoolMaster : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB 58 53 68 61 72 65 77 61 72 65 2D 56 65 72 73 69 6F 6E 20 45 78 65 53 74 65 61 6C 74 68 2C 20 63 6F 6E 74 61 63 74 20 73 75 70 70 6F 72 74 40 77 65 62 74 6F 6F 6C 6D 61 73 74 65 72 2E 63 6F 6D 20 2D 20 77 77 77 2E 77 65 62 74 6F 6F 6C 6D 61 73 74 65 72 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PEArmor046Hying : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E8 AA 00 00 00 2D [2] 00 00 00 00 00 00 00 00 00 3D [2] 00 2D [2] 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 4B [2] 00 5C [2] 00 6F [2] 00 00 00 00 00 4B 45 52 4E 45 4C 33 32 2E 64 6C 6C 00 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 47 65 74 4D 6F 64 75 6C 65 48 61 6E 64 6C 65 41 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 }
		$a1 = { E8 AA 00 00 00 2D [3] 00 00 00 00 00 00 00 00 3D }

	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point
}

import "pe"

rule eXPressorv13CGSoftLabs : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 45 78 50 72 2D 76 2E 31 2E 33 2E }
		$a1 = { 55 8B EC 83 EC ?? 53 56 57 EB 0C 45 78 50 72 2D 76 2E 31 2E 33 2E 2E B8 [4] 2B 05 [4] A3 [4] 83 3D [4] 00 74 13 A1 [4] 03 05 [4] 89 [2] E9 [2] 00 00 C7 05 }

	condition:
		$a0 or $a1 at pe.entry_point
}

rule Upackv032BetaDwing : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { BE 88 01 [2] AD 50 [2] AD 91 F3 A5 }
		$a1 = { BE 88 01 [2] AD 50 ?? AD 91 ?? F3 A5 }

	condition:
		$a0 or $a1
}

import "pe"

rule MSLRHV031emadicius : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 D1 CB 0F CA C1 CA E0 D1 CA 0F C8 EB 01 F1 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PECompactv184 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PCGuardforWin32v500SofProBlagojeCeklic : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { FC 55 50 E8 00 00 00 00 5D 60 E8 03 00 00 00 83 EB 0E EB 01 0C 58 EB 01 35 40 EB 01 36 FF E0 0B 61 B8 [3] 00 EB 01 E3 60 E8 03 00 00 00 D2 EB 0B 58 EB 01 48 40 EB 01 35 FF E0 E7 61 2B E8 9C EB 01 D5 9D EB 01 0B 58 60 E8 03 00 00 00 83 EB 0E EB 01 0C }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule WiseInstallerStub : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 81 EC 78 05 00 00 53 56 BE 04 01 00 00 57 8D 85 94 FD FF FF 56 33 DB 50 53 FF 15 34 20 40 00 8D 85 94 FD FF FF 56 50 8D 85 94 FD FF FF 50 FF 15 30 20 40 00 8B 3D 2C 20 40 00 53 53 6A 03 53 6A 01 8D 85 94 FD FF FF 68 00 00 00 80 50 FF D7 83 F8 FF }
		$a1 = { 55 8B EC 81 EC ?? 04 00 00 53 56 57 6A [7] FF 15 [2] 40 00 [56] 80 ?? 20 }
		$a2 = { 55 8B EC 81 EC [2] 00 00 53 56 57 6A 01 5E 6A 04 89 75 E8 FF 15 ?? 40 40 00 FF 15 ?? 40 40 00 8B F8 89 7D ?? 8A 07 3C 22 0F 85 ?? 00 00 00 8A 47 01 47 89 7D ?? 33 DB 3A C3 74 0D 3C 22 74 09 8A 47 01 47 89 7D ?? EB EF 80 3F 22 75 04 47 89 7D ?? 80 3F 20 }

	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point or $a2
}

rule AnskyaNTPackerGeneratorAnskya : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 83 C4 F0 53 B8 88 1D 00 10 E8 C7 FA FF FF 6A 0A 68 20 1E 00 10 A1 14 31 00 10 50 E8 71 FB FF FF 8B D8 85 DB 74 2F 53 A1 14 31 00 10 50 E8 97 FB FF FF 85 C0 74 1F 53 A1 14 31 00 10 50 E8 5F FB FF FF 85 C0 74 0F 50 E8 5D FB FF FF 85 C0 74 05 E8 70 FC FF FF 5B E8 F2 F6 FF FF 00 00 48 45 41 52 54 }

	condition:
		$a0
}

import "pe"

rule ThinstallVirtualizationSuite30493080ThinstallCompany : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 9C 60 68 53 74 41 6C 68 54 68 49 6E E8 00 00 00 00 58 BB 37 1F 00 00 2B C3 50 68 [4] 68 00 2C 00 00 68 04 01 00 00 E8 BA FE FF FF E9 90 FF FF FF CC CC CC CC CC CC CC 55 8B EC 83 C4 F4 FC 53 57 56 8B 75 08 8B 7D 0C C7 45 FC 08 00 00 00 33 DB BA 00 }
		$a1 = { 9C 60 68 53 74 41 6C 68 54 68 49 6E E8 00 00 00 00 58 BB 37 1F 00 00 2B C3 50 68 [4] 68 00 2C 00 00 68 04 01 00 00 E8 BA FE FF FF E9 90 FF FF FF CC CC CC CC CC CC CC 55 8B EC 83 C4 F4 FC 53 57 56 8B 75 08 8B 7D 0C C7 45 FC 08 00 00 00 33 DB BA 00 00 00 80 43 33 C0 E8 19 01 00 00 73 0E 8B 4D F8 E8 27 01 00 00 02 45 F7 AA EB E9 E8 04 01 00 00 0F 82 96 00 00 00 E8 F9 00 00 00 73 5B B9 04 00 00 00 E8 05 01 00 00 48 74 DE 0F 89 C6 00 00 00 E8 DF 00 00 00 73 1B 55 BD 00 01 00 00 E8 DF 00 00 00 88 07 47 4D 75 F5 E8 C7 00 00 00 72 E9 5D EB }

	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point
}

rule NsPack14byNorthStarLiuXingPing : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 8B DF 83 3F 00 75 0A 83 C7 04 B9 00 00 00 00 EB 16 B9 01 00 00 00 03 3B 83 C3 04 83 3B 00 74 2D 01 13 8B 33 03 7B 04 57 51 52 53 }

	condition:
		$a0
}

import "pe"

rule FSGv110EngbartxtWatcomCCEXE : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB 02 CD 20 03 ?? 8D ?? 80 [2] 00 [9] EB 02 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule AcidCrypt : Packer hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 B9 [3] 00 BA [3] 00 BE [3] 00 02 38 40 4E 75 FA 8B C2 8A 18 32 DF C0 CB }
		$a1 = { BE [4] 02 38 40 4E 75 FA 8B C2 8A 18 32 DF C0 CB }

	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point
}

import "pe"

rule eXPressorv1451CGSoftLabs : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 83 EC 58 53 56 57 83 65 DC 00 F3 EB 0C 65 58 50 72 2D 76 2E 31 2E 34 2E 00 A1 00 [3] 05 00 [3] A3 08 [3] A1 08 [3] B9 81 [3] 2B 48 18 89 0D 0C [3] 83 3D 10 [3] 00 74 16 A1 08 [3] 8B 0D 0C [3] 03 48 14 }
		$a1 = { 55 8B EC 83 EC 58 53 56 57 83 65 DC 00 F3 EB 0C 65 58 50 72 2D 76 2E 31 2E 34 2E 00 A1 00 [3] 05 00 [3] A3 08 [3] A1 08 [3] B9 81 [3] 2B 48 18 89 0D 0C [3] 83 3D 10 [3] 00 74 16 A1 08 [3] 8B 0D 0C [3] 03 48 14 89 4D CC }

	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point
}

import "pe"

rule BeRoEXEPackerv100LZMABeRoFarbrausch : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 68 [4] 68 [4] 68 [4] E8 [4] BE [4] B9 04 00 00 00 8B F9 81 FE [4] 7F 10 AC 47 04 18 2C 02 73 F0 29 3E 03 F1 03 F9 EB E8 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PackanoidArkanoid : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { BF 00 10 40 00 BE [3] 00 E8 9D 00 00 00 B8 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule DAEMONProtectv067 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 60 9C 8C C9 32 C9 E3 0C 52 0F 01 4C 24 FE 5A 83 C2 0C 8B 1A 9D 61 }

	condition:
		$a0 at pe.entry_point
}

rule EmbedPEV100V124cyclotron : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 00 00 00 00 [4] 00 00 00 00 00 00 00 00 [8] 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 [12] 00 00 00 00 [12] 00 00 00 00 4B 45 52 4E 45 4C 33 32 2E 64 6C 6C 00 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 47 65 74 4D 6F 64 75 6C 65 48 61 6E 64 6C 65 41 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 00 00 00 00 00 00 }

	condition:
		$a0
}

import "pe"

rule VProtectorV10Avcasm : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 6A FF 68 8A 8E 40 00 68 C6 8E 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 E8 03 00 00 00 C7 84 00 58 EB 01 E9 83 C0 07 50 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule EncryptPE2200481022005314WFS : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 9C 64 FF 35 00 00 00 00 E8 7A }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PseudoSigner02JDPack1xJDProtect09Anorganix : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 22 00 00 00 5D 8B D5 81 ED 90 90 90 90 2B 95 90 90 90 90 81 EA 06 90 90 90 89 95 90 90 90 90 83 BD 45 00 01 00 01 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule EmbedPEV1Xcyclotron : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 83 EC 50 60 68 [4] E8 [2] 00 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule EncryptPEV220070411WFS : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 9C 64 FF 35 00 00 00 00 E8 1B 02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 [8] 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 [36] 00 00 00 00 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 00 00 47 65 74 54 65 6D 70 50 61 74 68 41 00 00 00 43 72 65 61 74 65 46 69 6C 65 41 00 00 00 43 72 65 61 74 65 46 69 6C 65 4D 61 70 70 69 6E 67 41 00 00 00 4D 61 70 56 69 65 77 4F 66 46 69 6C 65 00 00 00 55 6E 6D 61 70 56 69 65 77 4F 66 46 69 6C 65 00 00 00 43 6C 6F 73 65 48 61 6E 64 6C 65 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 45 78 69 74 50 72 6F 63 65 73 73 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PseudoSigner01MicrosoftVisualBasic60DLLAnorganix : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 90 90 90 90 68 [4] 67 64 FF 36 00 00 67 64 89 26 00 00 F1 90 90 90 90 5A 68 90 90 90 90 68 90 90 90 90 52 E9 90 90 FF }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule NsPack14Liuxingping : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 9C 60 E8 00 00 00 00 5D B8 [2] 40 00 2D [2] 40 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule VxTrivial46 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { B4 4E B1 20 BA [2] CD 21 BA [2] B8 ?? 3D CD 21 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule STUDRC410JamieEditionScanTimeUnDetectablebyMarjinZ : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 68 2C 11 40 00 E8 F0 FF FF FF 00 00 00 00 00 00 30 00 00 00 38 00 00 00 00 00 00 00 37 BB 71 EC A4 E1 98 4C 9B FE 8F 0F FA 6A 07 F6 00 00 00 00 00 00 01 00 00 00 20 20 46 6F 72 20 73 74 75 64 00 20 54 6F 00 00 00 00 06 00 00 00 CC 1A 40 00 07 00 00 00 D4 18 40 00 07 00 00 00 7C 18 40 00 07 00 00 00 2C 18 40 00 07 00 00 00 E0 17 40 00 56 42 35 21 F0 1F 2A 00 00 00 00 00 00 00 00 00 00 00 00 00 7E 00 00 00 00 00 00 00 00 00 00 00 00 00 0A 00 09 04 00 00 00 00 00 00 E8 13 40 00 F4 13 40 00 00 F0 30 00 00 FF FF FF 08 00 00 00 01 00 00 00 00 00 00 00 E9 00 00 00 04 11 40 00 04 11 40 00 C8 10 40 00 78 00 00 00 7C 00 00 00 81 00 00 00 82 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 61 61 61 00 53 74 75 64 00 00 73 74 75 64 00 00 01 00 01 00 30 16 40 00 00 00 00 00 FF FF FF FF FF FF FF FF 00 00 00 00 B4 16 40 00 10 30 40 00 07 00 00 00 24 12 40 00 0E 00 20 00 00 00 00 00 1C 9E 21 00 EC 11 40 00 5C 10 40 00 E4 1A 40 00 2C 34 40 00 68 17 40 00 58 17 40 00 78 17 40 00 8C 17 40 00 8C 10 40 00 62 10 40 00 92 10 40 00 F8 1A 40 00 24 19 40 00 98 10 40 00 9E 10 40 00 77 04 18 FF 04 1C FF 05 00 00 24 01 00 0D 14 00 78 1C 40 00 48 21 40 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule VxSonikYouth : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 8A 16 02 00 8A 07 32 C2 88 07 43 FE C2 81 FB }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PseudoSigner01Anorganix : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 90 90 90 90 68 [4] 67 64 FF 36 00 00 67 64 89 26 00 00 F1 90 90 90 90 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule UPXShit006 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { B8 [2] 43 00 B9 15 00 00 00 80 34 08 ?? E2 FA E9 D6 FF FF FF }

	condition:
		$a0 at pe.entry_point
}

rule SetupFactoryv6003SetupLauncher : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 6A FF 68 90 61 40 00 68 70 3B 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF 15 14 61 40 00 33 D2 8A D4 89 15 5C 89 40 00 8B C8 81 E1 FF 00 00 00 89 0D 58 89 40 00 C1 E1 08 03 CA 89 0D 54 89 40 00 C1 E8 10 A3 50 89 }

	condition:
		$a0
}

import "pe"

rule CrypKeyV61XDLLCrypKeyCanadaInc : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 83 3D [4] 00 75 34 68 [4] E8 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule VcAsmProtectorVcAsm : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 6A FF 68 [4] 68 [4] 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 E8 03 00 00 00 C7 84 00 58 EB 01 E9 83 C0 07 50 C3 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PECompact2xxSlimLoaderBitSumTechnologies : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { B8 [4] 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 50 45 43 32 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule ENIGMAProtectorV11V12SukhovVladimir : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 00 00 00 00 5D 83 ED 06 81 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule yodasProtectorv10bAshkbizDanehkar : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 53 56 57 60 E8 00 00 00 00 5D 81 ED 4C 32 40 00 E8 03 00 00 00 EB 01 ?? B9 EA 47 40 00 81 E9 E9 32 40 00 8B D5 81 C2 E9 32 40 00 8D 3A 8B F7 33 C0 E8 04 00 00 00 90 EB 01 ?? E8 03 00 00 00 EB 01 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PEDiminisherv01 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 53 51 52 56 57 55 E8 00 00 00 00 5D 8B D5 81 ED A2 30 40 00 2B 95 91 33 40 00 81 EA 0B 00 00 00 89 95 9A 33 40 00 80 BD 99 33 40 00 00 74 }
		$a1 = { 5D 8B D5 81 ED A2 30 40 ?? 2B 95 91 33 40 ?? 81 EA 0B [3] 89 95 9A 33 40 ?? 80 BD 99 }

	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point
}

import "pe"

rule SOFTWrapperforWin9xNTEvaluationVersion : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E8 00 00 00 00 5D 8B C5 2D [3] 00 50 81 ED 05 00 00 00 8B C5 2B 85 03 0F 00 00 89 85 03 0F 00 00 8B F0 03 B5 0B 0F 00 00 8B F8 03 BD 07 0F 00 00 83 7F 0C 00 74 2B 56 57 8B 7F 10 03 F8 8B 76 10 03 F0 83 3F 00 74 0C 8B 1E 89 1F 83 C6 04 83 C7 04 EB EF }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule Armadillov200 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 6A FF 68 00 02 41 00 68 C4 A0 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule Armadillov201 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 6A FF 68 08 02 41 00 68 04 9A 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule FreeJoinerSmallbuild014021024027GlOFF : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E8 [2] FF FF 6A 00 E8 0D 00 00 00 CC FF 25 78 10 40 00 FF 25 7C 10 40 00 FF 25 80 10 40 00 FF 25 84 10 40 00 FF 25 88 10 40 00 FF 25 8C 10 40 00 FF 25 90 10 40 00 FF 25 94 10 40 00 FF 25 98 10 40 00 FF 25 9C 10 40 00 FF 25 A0 10 40 00 FF 25 A4 10 40 00 FF 25 AC 10 40 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule SDProtector1xRandyLi : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 6A FF 68 1D 32 13 05 68 88 88 88 08 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 58 64 A3 00 00 00 00 58 58 58 58 8B E8 E8 3B 00 00 00 E8 01 00 00 00 FF 58 05 53 00 00 00 51 8B 4C 24 10 89 81 B8 00 00 00 B8 55 01 00 00 89 41 20 33 C0 89 41 04 89 41 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule NSISInstallerNullSoft : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 83 EC 20 53 55 56 33 DB 57 89 5C 24 18 C7 44 24 10 [4] C6 44 24 14 20 FF 15 30 70 40 00 53 FF 15 80 72 40 00 68 [4] 68 [4] A3 [4] E8 [4] BE }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PEXv099 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 01 [4] 83 C4 04 E8 01 [4] 5D 81 }

	condition:
		$a0 at pe.entry_point
}

rule IMPPacker10MahdiHezavehiIMPOSTER : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 28 [3] 00 00 00 00 00 00 00 00 40 [3] 34 [3] 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 4C [3] 5C [3] 00 00 00 00 [8] 00 00 00 00 4B 45 52 4E 45 4C 33 32 2E 64 6C 6C 00 00 47 65 74 50 72 6F 63 }

	condition:
		$a0
}

import "pe"

rule PEProtectv09 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 52 51 55 57 64 67 A1 30 00 85 C0 78 0D E8 [4] 58 83 C0 07 C6 ?? C3 }
		$a1 = { E9 ?? 00 00 00 0D 0A 0D 0A C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 0D 0A 50 45 2D 50 52 4F 54 45 43 54 20 30 2E 39 20 28 43 29 6F }

	condition:
		$a0 at pe.entry_point or $a1
}

import "pe"

rule nbuildv10soft : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { B9 [2] BB [2] C0 [2] 80 [2] 43 E2 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PseudoSigner01StelthPE101Anorganix : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 0B C0 0B C0 0B C0 0B C0 0B C0 0B C0 0B C0 0B C0 BA [4] FF E2 BA E0 10 40 00 B8 68 24 1A 40 89 02 83 C2 03 B8 40 00 E8 EE 89 02 83 C2 FD FF E2 2D 3D 5B 20 48 69 64 65 50 45 20 5D 3D 2D 90 00 00 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule IProtect10FxSubdllmodebyFuXdas : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB 33 2E 46 55 58 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 46 78 53 75 62 2E 64 6C 6C 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 [3] 00 60 E8 00 00 00 00 5D 81 ED B6 13 40 00 FF 74 24 20 E8 40 00 00 00 0B C0 74 2F 89 85 A8 13 40 00 8D 85 81 13 40 00 50 FF B5 A8 13 40 00 E8 92 00 00 00 0B C0 74 13 89 85 A4 13 40 00 8D 85 8E 13 40 00 50 FF 95 A4 13 40 00 8B 85 AC 13 40 00 89 44 24 1C 61 FF E0 8B 7C 24 04 8D 85 00 10 40 00 50 64 FF 35 00 00 00 00 8D 85 98 13 40 00 89 20 89 68 04 8D 9D 4F 14 40 00 89 58 08 64 89 25 00 00 00 00 81 E7 00 00 FF FF 66 81 3F 4D 5A 75 0F 8B F7 03 76 3C 81 3E 50 45 00 00 75 02 EB 17 81 EF 00 00 01 00 81 FF 00 00 00 70 73 07 BF 00 00 F7 BF EB 02 EB D3 97 64 8F 05 00 00 00 00 83 C4 04 C2 04 00 8D 85 00 10 40 00 50 64 FF 35 00 00 00 00 8D 85 98 13 40 00 89 20 89 68 04 8D 9D 4F 14 40 00 89 58 08 64 89 25 00 00 00 00 8B 74 24 0C 66 81 3E 4D 5A 74 05 E9 8A 00 00 00 03 76 3C 81 3E 50 45 00 00 74 02 EB 7D 8B 7C 24 10 B9 96 00 00 00 32 C0 F2 AE 8B CF 2B 4C 24 10 8B 56 78 03 54 24 0C 8B 5A 20 03 5C 24 0C 33 C0 8B 3B 03 7C 24 0C 8B 74 24 10 51 F3 A6 75 05 83 C4 04 EB 0A 59 83 C3 04 40 3B 42 18 75 E2 3B 42 18 75 02 EB 35 8B 72 24 03 74 24 0C 52 BB 02 00 00 00 33 D2 F7 E3 5A 03 C6 33 C9 66 8B 08 8B 7A 1C 33 D2 BB 04 00 00 00 8B C1 F7 E3 03 44 24 0C 03 C7 8B 00 03 44 24 0C EB 02 33 C0 64 8F 05 00 00 00 00 83 C4 04 C2 08 00 E8 B5 FA FF FF }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule MSVisualCv8DLLhsmallsig2 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 8B FF 55 8B EC 53 8B 5D 08 56 8B 75 0C 85 F6 57 8B 7D 10 0F 84 [2] 00 00 83 FE 01 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule MSVisualCv8DLLhsmallsig1 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 8B FF 55 8B EC 83 7D 0C 01 75 05 E8 [3] FF 5D E9 D6 FE FF FF CC CC CC CC CC }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule RCryptorv16xVaska : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 90 61 61 80 7F F0 45 90 60 0F 85 1B 8B 1F FF 68 [4] C3 }

	condition:
		$a0 at pe.entry_point
}

rule UPXv20MarkusLaszloReiser : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 FF 96 [4] 09 C0 74 07 89 03 83 C3 04 EB ?? FF 96 [4] 8B AE [4] 8D BE 00 F0 FF FF BB 00 10 00 00 50 54 6A 04 53 57 FF D5 8D 87 [2] 00 00 80 20 7F 80 60 28 7F 58 50 54 50 53 57 FF D5 58 61 8D 44 24 80 6A 00 39 C4 75 FA 83 EC 80 }

	condition:
		$a0
}

import "pe"

rule BladeJoinerv15 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 81 C4 E4 FE FF FF 53 56 57 33 C0 89 45 F0 89 85 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule FSGv133Engdulekxt : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { BE A4 01 40 00 AD 93 AD 97 AD 56 96 B2 80 A4 B6 80 FF 13 73 F9 33 C9 FF 13 73 16 33 C0 FF }
		$a1 = { BE A4 01 40 00 AD 93 AD 97 AD 56 96 B2 80 A4 B6 80 FF 13 73 F9 33 C9 FF 13 73 16 33 C0 FF 13 73 1F B6 80 41 B0 10 FF 13 12 C0 73 FA 75 3C AA EB E0 FF 53 08 02 F6 83 D9 01 75 0E FF 53 04 EB 26 AC D1 E8 74 2F 13 C9 EB 1A 91 48 C1 E0 08 AC FF 53 04 3D 00 7D }

	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point
}

import "pe"

rule FSGv13 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { BB D0 01 40 00 BF 00 10 40 00 BE [4] 53 E8 0A 00 00 00 02 D2 75 05 8A 16 46 12 D2 C3 B2 80 A4 6A 02 5B FF 14 24 73 F7 33 C9 FF 14 24 73 18 33 C0 FF 14 24 73 21 B3 02 41 B0 10 FF 14 24 12 C0 73 F9 75 3F AA EB DC E8 43 00 00 00 2B CB 75 10 E8 38 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule FSGv12 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 4B 45 52 4E 45 4C 33 32 2E 64 6C 6C 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 ?? 00 00 00 00 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule FSGv11 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { BB D0 01 40 ?? BF ?? 10 40 ?? BE [4] FC B2 80 8A 06 46 88 07 47 02 D2 75 05 8A 16 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule FSGv10 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { BB D0 01 40 00 BF 00 10 40 00 BE [4] 53 E8 0A 00 00 00 02 D2 75 05 8A 16 46 12 D2 C3 FC B2 80 A4 6A 02 5B }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule FSGv120EngdulekxtMicrosoftVisualC6070 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB 02 CD 20 EB 01 91 8D 35 80 [2] 00 33 C2 68 83 93 7E 7D 0C A4 5B 23 C3 68 77 93 7E 7D EB 01 FA 5F E8 02 00 00 00 F7 FB 58 33 DF EB 01 3F E8 02 00 00 00 11 88 58 0F B6 16 EB 02 CD 20 EB 02 86 2F 2A D3 EB 02 CD 20 80 EA 2F EB 01 52 32 D3 80 E9 CD 80 EA }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule SuperDAT : Packer PEiD hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 6A FF 68 40 F3 42 00 68 A4 BF 42 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF 15 08 F2 42 00 33 D2 8A D4 89 15 60 42 43 00 8B C8 81 E1 FF 00 00 00 89 0D }

	condition:
		$a0 at pe.entry_point
}

rule PECompactv200alpha38 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { B8 [4] 80 B8 BF 10 00 10 01 74 7A C6 80 BF 10 00 10 01 9C 55 53 51 57 52 56 8D 98 0F 10 00 10 8B 53 14 8B E8 6A 40 68 00 10 00 00 FF 73 04 6A 00 8B 4B 10 03 CA 8B 01 FF D0 8B F8 50 8B 33 8B 53 14 03 F2 8B 4B 0C 03 CA 8D 85 B7 10 00 10 FF 73 04 8F }

	condition:
		$a0
}

import "pe"

rule RCryptor16cVaska : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 8B C7 03 04 24 2B C7 80 38 50 0F 85 1B 8B 1F FF 68 [4] B8 [4] 3D [4] 74 06 80 30 ?? 40 EB F3 B8 [4] 3D [4] 74 06 80 30 ?? 40 EB F3 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule TheGuardLibrary : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 50 E8 [4] 58 25 ?? F0 FF FF 8B C8 83 C1 60 51 83 C0 40 83 EA 06 52 FF 20 9D C3 }

	condition:
		$a0 at pe.entry_point
}

rule FreeCryptor01build001GlOFF : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 8B 04 24 40 90 83 C0 07 80 38 90 90 74 02 EB FF 68 26 [2] 00 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 FF E4 90 8B 04 24 64 A3 00 00 00 00 8B 64 24 08 90 83 C4 08 }

	condition:
		$a0
}

import "pe"

rule PseudoSigner02BJFNT12Anorganix : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB 02 69 B1 83 EC 04 EB 03 CD 20 EB EB 01 EB 9C EB 01 EB EB 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule DingBoysPElockPhantasmv08 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 57 56 52 51 53 E8 00 00 00 00 5D 8B D5 81 ED 0D 39 40 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule Thinstall2736Jitit : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 9C 60 E8 00 00 00 00 58 BB F3 1C 00 00 2B C3 50 68 00 00 40 00 68 00 26 00 00 68 CC 00 00 00 E8 C1 FE FF FF E9 97 FF FF FF CC CC CC CC CC CC CC CC CC CC CC 55 8B EC 83 C4 F4 FC 53 57 56 8B 75 08 8B 7D 0C C7 45 FC 08 00 00 00 33 DB BA 00 00 00 80 43 33 C0 E8 19 01 00 00 73 0E 8B 4D F8 E8 27 01 00 00 02 45 F7 AA EB E9 E8 04 01 00 00 0F 82 96 00 00 00 E8 F9 00 00 00 73 5B B9 04 00 00 00 E8 05 01 00 00 48 74 DE 0F 89 C6 00 00 00 E8 DF 00 00 00 73 1B 55 BD 00 01 00 00 E8 DF 00 00 00 88 07 47 4D 75 F5 E8 C7 00 00 00 72 E9 5D EB A2 B9 01 00 00 00 E8 D0 00 00 00 83 C0 07 89 45 F8 C6 45 F7 00 83 F8 08 74 89 E8 B1 00 00 00 88 45 F7 E9 7C FF FF FF B9 07 00 00 00 E8 AA 00 00 00 50 33 C9 B1 02 E8 A0 00 00 00 8B C8 41 41 58 0B C0 74 04 8B D8 EB 5E 83 F9 02 74 6A 41 E8 88 00 00 00 89 45 FC E9 48 FF FF FF E8 87 00 00 00 49 E2 09 8B C3 E8 7D 00 00 00 EB 3A 49 8B C1 55 8B 4D FC 8B E8 33 C0 D3 E5 E8 5D 00 00 00 0B C5 5D 8B D8 E8 5F 00 00 00 3D 00 00 01 00 73 14 3D FF 37 00 00 73 0E 3D 7F 02 00 00 73 08 83 F8 7F 77 04 41 41 41 41 56 8B F7 2B F0 F3 A4 5E E9 F0 FE FF FF 33 C0 EB 05 8B C7 2B 45 0C 5E 5F 5B C9 C2 08 00 }

	condition:
		$a0 at pe.entry_point
}

rule UnnamedScrambler11Cp0ke : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 83 C4 E4 53 56 33 C0 89 45 E4 89 45 E8 89 45 EC B8 C0 47 00 10 E8 4F F3 FF FF BE 5C 67 00 10 33 C0 55 68 D2 4A 00 10 64 FF 30 64 89 20 E8 EB DE FF FF E8 C6 F8 FF FF BA E0 4A 00 10 B8 CC 67 00 10 E8 5F F8 FF FF 8B D8 8B D6 8B C3 8B 0D CC 67 00 10 E8 3A DD FF FF 8B 46 50 8B D0 B8 D4 67 00 10 E8 5B EF FF FF B8 D4 67 00 10 E8 09 EF FF FF 8B D0 8D 46 14 8B 4E 50 E8 14 DD FF FF 8B 46 48 8B D0 B8 D8 67 00 [5] FF B8 D8 67 00 10 E8 E3 EE FF FF 8B D0 8B C6 8B 4E 48 E8 EF DC FF FF FF 76 5C FF 76 58 FF 76 64 FF 76 60 B9 D4 67 00 10 8B 15 D8 67 00 10 A1 D4 67 00 10 E8 76 F6 FF FF A1 D4 67 00 10 E8 5C EE FF FF 8B D0 B8 CC 67 00 10 E8 CC F7 FF FF 8B D8 B8 DC 67 00 10 }

	condition:
		$a0
}

import "pe"

rule y0dasCrypterv1xModified : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED [4] B9 [2] 00 00 8D BD [4] 8B F7 AC }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule Armadillov252b2 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 6A FF 68 B0 [3] 68 60 [3] 64 A1 [4] 50 64 89 25 [4] 83 EC 58 53 56 57 89 65 E8 FF 15 24 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule Upackv036betaDwing : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { BE E0 11 [2] FF 36 E9 C3 00 00 00 48 01 [2] 0B 01 4B 45 52 4E 45 4C 33 32 2E 44 4C 4C }
		$a1 = { BE E0 11 [2] FF 36 E9 C3 00 00 00 48 01 [2] 0B 01 4B 45 52 4E 45 4C 33 32 2E 44 4C 4C [162] 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 [54] 82 8E FE FF FF 58 8B 4E 40 5F E3 }

	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point
}

import "pe"

rule VxNecropolis : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 50 FC AD 33 C2 AB 8B D0 E2 F8 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule WinUpackv039finalrelocatedimagebaseByDwingc2005h2 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 09 00 00 00 [3] 00 E9 06 02 00 00 33 C9 5E 87 0E E3 F4 2B F1 8B DE AD 2B D8 AD 03 C3 50 97 AD 91 F3 A5 5E AD 56 91 01 1E AD E2 FB AD 8D 6E 10 01 5D 00 8D 7D 1C B5 ?? F3 AB 5E AD 53 50 51 97 58 8D 54 85 5C FF 16 72 57 2C 03 73 02 B0 00 3C 07 72 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule ASPackv1061bAlexeySolodovnikov : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 [4] 5D 81 ED EA A8 43 ?? B8 E4 A8 43 ?? 03 C5 2B 85 78 AD 43 ?? 89 85 84 AD 43 ?? 80 BD 6E AD 43 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule aPackv062 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 1E 06 8C C8 8E D8 [3] 8E C0 50 BE [2] 33 FF FC B6 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule tElockv071 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 ED 10 00 00 C3 83 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule tElockv070 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 BD 10 00 00 C3 83 E2 00 F9 75 FA 70 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule Ningishzida10CyberDoom : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 9C 60 96 E8 00 00 00 00 5D 81 ED 03 25 40 00 B9 04 1B 00 00 8D BD 4B 25 40 00 8B F7 AC [48] AA E2 CC }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule ASProtectSKE21xdllAlexeySolodovnikov : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ED FF FF FF 03 DD 81 EB 00 [3] 80 7D 4D 01 75 0C 8B 74 24 28 83 FE 01 89 5D 4E 75 31 8D 45 53 50 53 FF B5 ED 09 00 00 8D 45 35 50 E9 82 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

	condition:
		$a0 at pe.entry_point
}

rule PAVCryptorPawningAntiVirusCryptormasha_dev : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 53 56 57 55 BB 2C [2] 70 BE 00 30 00 70 BF 20 [2] 70 80 7B 28 00 75 16 83 3F 00 74 11 8B 17 89 D0 33 D2 89 17 8B E8 FF D5 83 3F 00 75 EF 83 3D 04 30 00 70 00 74 06 FF 15 54 30 00 70 80 7B 28 02 75 0A 83 3E 00 75 05 33 C0 89 43 0C FF 15 1C 30 00 70 80 7B 28 01 76 05 83 3E 00 74 22 8B 43 10 85 C0 74 1B FF 15 14 30 00 70 8B 53 10 8B 42 10 3B 42 04 74 0A 85 C0 74 06 50 E8 8F FA FF FF FF 15 20 30 00 70 80 7B 28 01 75 03 FF 53 24 80 7B 28 00 74 05 E8 35 FF FF FF 83 3B 00 75 17 83 3D 10 [2] 70 00 74 06 FF 15 10 [2] 70 8B 06 50 E8 A9 FA FF FF 8B 03 56 8B F0 8B FB B9 0B 00 00 00 F3 A5 5E E9 73 FF FF FF 5D 5F 5E 5B C3 A3 00 30 00 70 E8 26 FF FF FF C3 90 8F 05 04 30 00 70 E9 E9 FF FF FF C3 }

	condition:
		$a0
}

import "pe"

rule ExeShieldCryptor13RCTomCommander : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 53 56 57 60 E8 00 00 00 00 5D 81 ED 8C 21 40 00 B9 51 2D 40 00 81 E9 E6 21 40 00 8B D5 81 C2 E6 21 40 00 8D 3A 8B F7 33 C0 EB 04 90 EB 01 C2 AC }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule CrinklerV01V02RuneLHStubbeandAskeSimonChristensen : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { B9 [4] 01 C0 68 [4] 6A 00 58 50 6A 00 5F 48 5D BB 03 00 00 00 BE [4] E9 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule VxGRUNT4Family : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E8 1C 00 8D 9E 41 01 40 3E 8B 96 14 03 B9 EA 00 87 DB F7 D0 31 17 83 C3 02 E2 F7 C3 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule nPackV112002006BetaNEOxuinC : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 83 3D 40 [3] 00 75 05 E9 01 00 00 00 C3 E8 41 00 00 00 B8 80 [3] 2B 05 08 [3] A3 3C [3] E8 5E 00 00 00 E8 EC 01 00 00 E8 F8 06 00 00 E8 03 06 00 00 A1 3C [3] C7 05 40 [3] 01 00 00 00 01 05 00 [3] FF 35 00 [3] C3 C3 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule VxEddie1800 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E8 [2] 5E 81 EE [2] FC 2E [4] 4D 5A [2] FA 8B E6 81 C4 [2] FB 3B [5] 50 06 56 1E 8B FE 33 C0 50 8E D8 C4 [3] 2E [4] 2E }

	condition:
		$a0 at pe.entry_point
}

rule EncryptPEV22006115WFS : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 45 50 45 3A 20 45 6E 63 72 79 70 74 50 45 20 56 32 2E 32 30 30 36 2E 31 2E 31 35 }

	condition:
		$a0
}

rule PrincessSandyv10eMiNENCEProcessPatcherPatch : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 68 27 11 40 00 E8 3C 01 00 00 6A 00 E8 41 01 00 00 A3 00 20 40 00 8B 58 3C 03 D8 0F B7 43 14 0F B7 4B 06 8D 7C 18 18 81 3F 2E 4C 4F 41 74 0B 83 C7 28 49 75 F2 E9 A7 00 00 00 8B 5F 0C 03 1D 00 20 40 00 89 1D 04 20 40 00 8B FB 83 C7 04 68 4C 20 40 00 68 08 }

	condition:
		$a0
}

import "pe"

rule aPackv082 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 1E 06 8C CB BA [2] 03 DA 8D [3] FC 33 F6 33 FF 48 4B 8E C0 8E DB }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule NJoiner01AsmVersionNEX : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 6A 00 68 00 14 40 00 68 00 10 40 00 6A 00 E8 14 00 00 00 6A 00 E8 13 00 00 00 CC FF 25 AC 12 40 00 FF 25 B0 12 40 00 FF 25 B4 12 40 00 FF 25 B8 12 40 00 FF 25 BC 12 40 00 FF 25 C0 12 40 00 FF 25 C4 12 40 00 FF 25 C8 12 40 00 FF 25 CC 12 40 00 FF 25 D0 12 40 00 FF 25 D4 12 40 00 FF 25 D8 12 40 00 FF 25 DC 12 40 00 FF 25 E4 12 40 00 FF 25 EC 12 40 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule Obsiduim1304ObsiduimSoftware : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB 02 [2] E8 25 00 00 00 EB 04 [4] EB 01 ?? 8B 54 24 0C EB 01 ?? 83 82 B8 00 00 00 23 EB 01 ?? 33 C0 EB 02 [2] C3 EB 02 [2] EB 04 [4] 64 67 FF 36 00 00 EB 03 [3] 64 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PseudoSigner02FSG131Anorganix : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { BE 90 90 90 00 BF 90 90 90 00 BB 90 90 90 00 53 BB 90 90 90 00 B2 80 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PseudoSigner01CodeSafe20Anorganix : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 EB 0B 83 EC 10 53 56 57 E8 C4 01 00 85 E9 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PseudoSigner01NorthStarPEShrinker13Anorganix : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 9C 60 E8 00 00 00 00 5D B8 B3 85 40 00 2D AC 85 40 00 2B E8 8D B5 00 00 00 00 E9 }

	condition:
		$a0 at pe.entry_point
}

rule ocBat2Exe10OC : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC B9 08 00 00 00 6A 00 6A 00 49 75 F9 53 56 57 B8 58 3C 40 00 E8 6C FA FF FF 33 C0 55 68 8A 3F 40 00 64 FF 30 64 89 20 6A 00 6A 00 6A 03 6A 00 6A 01 68 00 00 00 80 8D 55 EC 33 C0 E8 81 E9 FF FF 8B 45 EC E8 41 F6 FF FF 50 E8 F3 FA FF FF 8B F8 83 FF FF 0F 84 83 02 00 00 6A 02 6A 00 6A EE 57 E8 FC FA FF FF 6A 00 68 60 99 4F 00 6A 12 68 18 57 40 00 57 E8 E0 FA FF FF 83 3D 60 99 4F 00 12 0F 85 56 02 00 00 8D 45 E4 50 8D 45 E0 BA 18 57 40 00 B9 40 42 0F 00 E8 61 F4 FF FF 8B 45 E0 B9 12 00 00 00 BA 01 00 00 00 E8 3B F6 FF FF 8B 45 E4 8D 55 E8 E8 04 FB [4] E8 B8 58 99 4F 00 E8 67 F3 FF FF 33 C0 A3 60 99 4F 00 8D 45 DC 50 B9 05 00 00 00 BA 01 00 00 00 A1 58 99 4F 00 E8 04 F6 FF FF 8B 45 DC BA A4 3F 40 00 E8 E3 F4 FF FF }

	condition:
		$a0
}

import "pe"

rule ASDPack20asd : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 00 00 00 00 [4] 00 00 00 00 00 00 00 00 [8] 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 [4] 00 00 00 00 4B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 8D 49 00 1F 01 47 65 74 4D 6F 64 75 6C 65 48 61 6E 64 6C 65 41 00 90 }
		$a1 = { 5B 43 83 7B 74 00 0F 84 08 00 00 00 89 43 14 E9 }
		$a2 = { 8B 44 24 04 56 57 53 E8 CD 01 00 00 C3 00 00 00 00 00 00 00 00 00 00 00 00 00 10 00 00 00 }

	condition:
		$a0 or $a1 or $a2 at pe.entry_point
}

rule EXECryptor2021protectedIAT : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { A4 [3] 00 00 00 00 FF FF FF FF 3C [3] 94 [3] D8 [3] 00 00 00 00 FF FF FF FF B8 [3] D4 [3] 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 00 00 00 00 00 47 65 74 4D 6F 64 75 6C 65 48 61 6E 64 6C 65 41 00 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 00 00 00 45 78 69 74 50 72 6F 63 65 73 73 00 00 00 [19] 00 60 [3] 70 [3] 84 [3] 00 00 00 00 75 73 65 72 33 32 2E 64 6C 6C 00 00 00 00 4D 65 73 73 61 67 65 42 6F 78 41 }

	condition:
		$a0
}

import "pe"

rule ShrinkWrapv14 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 58 60 8B E8 55 33 F6 68 48 01 [2] E8 49 01 [2] EB }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule UnknownbySMT : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 BE [4] 8D BE [4] 83 [2] 57 EB }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PseudoSigner01VOBProtectCD5Anorganix : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 36 3E 26 8A C0 60 E8 00 00 00 00 E9 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule SimplePack10Xbagie : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 00 00 00 00 5B 8D 5B FA 6A 00 FF 93 [2] 00 00 89 C5 8B 7D 3C 8D 74 3D 00 8D BE F8 00 00 00 8B 86 88 00 00 00 09 C0 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule ThemidaWinLicenseV18XV19XOreansTechnologies : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { B8 [4] 60 0B C0 74 68 E8 00 00 00 00 58 05 53 00 00 00 80 38 E9 75 13 61 EB 45 DB 2D [4] FF FF FF FF FF FF FF FF 3D [4] 00 00 58 25 00 F0 FF FF 33 FF 66 BB [2] 66 83 [2] 66 39 18 75 12 0F B7 50 3C 03 D0 BB [4] 83 C3 ?? 39 1A 74 07 2D [4] EB DA 8B F8 B8 [4] 03 C7 B9 [4] 03 CF EB 0A B8 [4] B9 [4] 50 51 E8 [4] E8 [4] 58 2D [4] B9 [4] C6 00 E9 83 E9 05 89 48 01 61 E9 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule EXEjoinerAmok : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { A1 14 A1 40 00 C1 E0 02 A3 18 A1 40 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule EmbedPEv124cyclotron : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 83 EC 50 60 68 [4] E8 CB FF 00 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule tElockv04xv05x : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { C1 EE 00 66 8B C9 EB 01 EB 60 EB 01 EB 9C E8 00 00 00 00 5E 83 C6 ?? 8B FE 68 79 01 [2] 59 EB 01 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule Armadillov301v305 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 00 00 00 00 5D 50 51 EB 0F B9 EB 0F B8 EB 07 B9 EB 0F 90 EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC E9 59 58 50 51 EB 0F B9 EB 0F B8 EB 07 B9 EB 0F 90 EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC E9 59 58 50 51 EB 0F }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule DingBoysPElockv007 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 57 56 52 51 53 E8 00 00 00 00 5D 8B D5 81 ED 23 35 40 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule mPack003DeltaAziz : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 83 C4 F0 33 C0 89 45 F0 B8 A8 76 00 10 E8 67 C4 FF FF 33 C0 55 68 C2 78 00 10 64 FF 30 64 89 20 8D 55 F0 33 C0 E8 93 C8 FF FF 8B 45 F0 E8 87 CB FF FF A3 08 A5 00 10 33 C0 55 68 A5 78 00 10 64 FF 30 64 89 20 A1 08 A5 00 10 E8 FA C9 FF FF 83 F8 FF 75 0A E8 88 B2 FF FF E9 1B 01 00 00 C7 05 14 A5 00 10 32 00 00 00 A1 08 A5 00 10 8B 15 14 A5 00 10 E8 C9 C9 FF FF BA 14 A5 00 10 A1 08 A5 00 10 B9 04 00 00 00 E8 C5 C9 FF FF 83 3D 14 A5 00 10 32 77 0A E8 47 B2 FF FF E9 DA 00 00 00 A1 08 A5 00 10 8B 15 14 A5 00 10 E8 92 C9 FF FF BA 18 A5 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule SixtoFourv10 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 50 55 4C 50 83 [2] FC BF [2] BE [2] B5 ?? 57 F3 A5 C3 33 ED }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule FreeJoinerSmallbuild029GlOFF : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 50 32 C4 8A C3 58 E8 DE FD FF FF 6A 00 E8 0D 00 00 00 CC FF 25 78 10 40 00 FF 25 7C 10 40 00 FF 25 80 10 40 00 FF 25 84 10 40 00 FF 25 88 10 40 00 FF 25 8C 10 40 00 FF 25 90 10 40 00 FF 25 94 10 40 00 FF 25 98 10 40 00 FF 25 9C 10 40 00 FF 25 A0 10 40 00 FF 25 A4 10 40 00 FF 25 AC 10 40 00 }

	condition:
		$a0 at pe.entry_point
}

rule ThemidaWinLicenseV1XNoCompressionSecureEngineOreansTechnologies : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 8B C5 8B D4 60 E8 00 00 00 00 5D 81 ED [4] 89 95 [4] 89 B5 [4] 89 85 [4] 83 BD [5] 74 0C 8B E8 8B E2 B8 01 00 00 00 C2 0C 00 8B 44 24 24 89 85 [4] 6A 45 E8 A3 00 00 00 68 9A 74 83 07 E8 DF 00 00 00 68 25 4B 89 0A E8 D5 00 00 00 E9 [4] 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

	condition:
		$a0
}

rule WinUpackv030betaByDwing : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E9 [4] 42 79 44 77 69 6E 67 40 00 00 00 50 45 00 00 }
		$a1 = { E9 [4] 42 79 44 77 69 6E 67 40 00 00 00 50 45 00 00 4C 01 02 }

	condition:
		$a0 or $a1
}

import "pe"

rule Armadillov260b2 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 6A FF 68 90 [3] 68 24 [3] 64 A1 [4] 50 64 89 25 [4] 83 EC 58 53 56 57 89 65 E8 FF 15 60 [3] 33 D2 8A D4 89 15 3C }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule Armadillov260b1 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 6A FF 68 50 [3] 68 74 [3] 64 A1 [4] 50 64 89 25 [4] 83 EC 58 53 56 57 89 65 E8 FF 15 58 [3] 33 D2 8A D4 89 15 FC }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule ExeLockerv10IonIce : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E8 00 00 00 00 60 8B 6C 24 20 81 ED 05 00 00 00 3E 8F 85 6C 00 00 00 3E 8F 85 68 00 00 00 3E 8F 85 64 00 00 00 3E 8F 85 60 00 00 00 3E 8F 85 5C 00 00 00 3E 8F 85 58 00 00 00 3E 8F 85 54 00 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule RLPackV10betaap0x : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 00 00 00 00 8D 64 24 04 8B 6C 24 FC 8D B5 4C 02 00 00 8D 9D 13 01 00 00 33 FF EB 0F FF 74 37 04 FF 34 37 FF D3 83 C4 08 83 C7 08 83 3C 37 00 75 EB }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PellesC300400450EXEX86CRTDLL : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 89 E5 6A FF 68 [4] 68 [4] 64 FF 35 [4] 64 89 25 [4] 83 EC ?? 53 56 57 89 65 E8 C7 45 FC [4] 68 [4] E8 [4] 59 BE [4] EB }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule BeRoEXEPackerv100LZBRRBeRoFarbrausch : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 BE [4] BF [4] FC B2 80 33 DB A4 B3 02 E8 [4] 73 F6 33 C9 E8 [4] 73 1C 33 C0 E8 [4] 73 23 B3 02 41 B0 10 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule Armadillov190a : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 64 FF 68 10 F2 40 00 68 14 9B 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule WWPACKv305c4Modified : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { B8 [2] 8C CA 03 D0 8C C9 81 C1 [2] 51 B9 [2] 51 06 06 B1 ?? 51 8C D3 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule APatchGUIv11 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 52 31 C0 E8 FF FF FF FF }

	condition:
		$a0 at pe.entry_point
}

rule ExeSafeguardv10simonzh : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { C0 5D EB 4E EB 47 DF 69 4E 58 DF 59 74 F3 EB 01 DF 75 EE 9A 59 9C 81 C1 E2 FF FF FF EB 01 DF 9D FF E1 E8 51 E8 EB FF FF FF DF 22 3F 9A C0 81 ED 19 18 40 00 EB 48 EB 47 DF 69 4E 58 DF 59 79 EE EB 01 DF 78 E9 DF 59 9C 81 C1 E5 FF FF FF 9D FF E1 EB 51 E8 EE }

	condition:
		$a0
}

import "pe"

rule PseudoSigner01CDCopsIIAnorganix : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 53 60 BD 90 90 90 90 8D 45 90 8D 5D 90 E8 00 00 00 00 8D 01 E9 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule AHTeamEPProtector03fakeVIRUSIWormHybrisFEUERRADER : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 90 [46] 90 FF E0 EB 16 A8 54 00 00 47 41 42 4C 4B 43 47 43 00 00 00 00 00 00 52 49 53 00 FC 68 4C 70 40 00 FF 15 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule Obsidium1322ObsidiumSoftware : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB 04 [4] E8 2A 00 00 00 EB 03 [3] EB 04 [4] 8B 54 24 0C EB 02 [2] 83 82 B8 00 00 00 26 EB 04 [4] 33 C0 EB 02 [2] C3 EB 01 ?? EB 03 [3] 64 67 FF 36 00 00 EB 02 [2] 64 67 89 26 00 00 EB 02 [2] EB 01 ?? 50 EB 04 [4] 33 C0 EB 04 [4] 8B 00 EB 02 [2] C3 EB 03 [3] E9 FA 00 00 00 EB 04 [4] E8 D5 FF FF FF EB 02 [2] EB 04 [4] 58 EB 01 ?? EB 01 ?? 64 67 8F 06 00 00 EB 01 ?? 83 C4 04 EB 04 }

	condition:
		$a0 at pe.entry_point
}

rule PrivateEXEProtector20SetiSoft : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 89 [2] 38 00 00 00 8B ?? 00 00 00 00 81 [5] 89 ?? 00 00 00 00 81 ?? 04 00 00 00 81 ?? 04 00 00 00 81 ?? 00 00 00 00 0F 85 D6 FF FF FF }

	condition:
		$a0
}

rule NTkrnlSecureSuite01015DLLNTkrnlSoftware : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 00 00 00 00 00 00 00 00 00 00 00 00 34 10 00 00 28 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 [8] 00 00 00 00 4B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 8B 44 24 04 05 [4] 50 E8 01 00 00 00 C3 C3 }

	condition:
		$a0
}

rule UPXHiTv001DJSiba : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 94 BC [3] 00 B9 ?? 00 00 00 80 34 0C ?? E2 FA 94 FF E0 61 }

	condition:
		$a0
}

rule Vpackerttui : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 89 C6 C7 45 E0 01 00 00 00 F7 03 00 00 FF FF 75 18 0F B7 03 50 8B 45 D8 50 FF 55 F8 89 07 8B C3 E8 ?? FE FF FF 8B D8 EB 13 53 8B 45 D8 50 FF 55 F8 89 07 8B C3 E8 ?? FE FF FF 8B D8 83 C7 04 FF 45 E0 4E 75 C4 8B F3 83 3E 00 75 88 8B 45 E4 8B 40 10 03 45 DC 8B 55 14 83 C2 20 89 02 68 00 80 00 00 6A 00 8B 45 D4 50 FF 55 EC 8B 55 DC 8B 42 3C 03 45 DC 83 C0 04 8B D8 83 C3 14 8D 45 E0 50 6A 40 68 00 10 00 00 52 FF 55 E8 8D 43 60 }

	condition:
		$a0
}

import "pe"

rule IProtect10FxlibdllmodebyFuXdas : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB 33 2E 46 55 58 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 46 78 4C 69 62 2E 64 6C 6C 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 [3] 00 60 E8 00 00 00 00 5D 81 ED 71 10 40 00 FF 74 24 20 E8 40 00 00 00 0B C0 74 2F 89 85 63 10 40 00 8D 85 3C 10 40 00 50 FF B5 63 10 40 00 E8 92 00 00 00 0B C0 74 13 89 85 5F 10 40 00 8D 85 49 10 40 00 50 FF 95 5F 10 40 00 8B 85 67 10 40 00 89 44 24 1C 61 FF E0 8B 7C 24 04 8D 85 00 10 40 00 50 64 FF 35 00 00 00 00 8D 85 53 10 40 00 89 20 89 68 04 8D 9D 0A 11 40 00 89 58 08 64 89 25 00 00 00 00 81 E7 00 00 FF FF 66 81 3F 4D 5A 75 0F 8B F7 03 76 3C 81 3E 50 45 00 00 75 02 EB 17 81 EF 00 00 01 00 81 FF 00 00 00 70 73 07 BF 00 00 F7 BF EB 02 EB D3 97 64 8F 05 00 00 00 00 83 C4 04 C2 04 00 8D 85 00 10 40 00 50 64 FF 35 00 00 00 00 8D 85 53 10 40 00 89 20 89 68 04 8D 9D 0A 11 40 00 89 58 08 64 89 25 00 00 00 00 8B 74 24 0C 66 81 3E 4D 5A 74 05 E9 8A 00 00 00 03 76 3C 81 3E 50 45 00 00 74 02 EB 7D 8B 7C 24 10 B9 96 00 00 00 32 C0 F2 AE 8B CF 2B 4C 24 10 8B 56 78 03 54 24 0C 8B 5A 20 03 5C 24 0C 33 C0 8B 3B 03 7C 24 0C 8B 74 24 10 51 F3 A6 75 05 83 C4 04 EB 0A 59 83 C3 04 40 3B 42 18 75 E2 3B 42 18 75 02 EB 35 8B 72 24 03 74 24 0C 52 BB 02 00 00 00 33 D2 F7 E3 5A 03 C6 33 C9 66 8B 08 8B 7A 1C 33 D2 BB 04 00 00 00 8B C1 F7 E3 03 44 24 0C 03 C7 8B 00 03 44 24 0C EB 02 33 C0 64 8F 05 00 00 00 00 83 C4 04 C2 08 00 E8 FA FD FF FF }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PseudoSigner02DxPack10Anorganix : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 00 00 00 00 5D 8B FD 81 ED 90 90 90 90 2B B9 00 00 00 00 81 EF 90 90 90 90 83 BD 90 90 90 90 90 0F 84 00 00 00 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule SecureEXE30ZipWorx : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E9 B8 00 00 00 [3] 00 [3] 00 [3] 00 00 00 00 00 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule eXPressorv12CGSoftLabs : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 45 78 50 72 2D 76 2E 31 2E 32 2E }
		$a1 = { 55 8B EC 81 EC D4 01 00 00 53 56 57 EB 0C 45 78 50 72 2D 76 2E 31 2E 32 2E 2E B8 [4] 2B 05 84 [3] A3 [4] 83 3D [4] 00 74 16 A1 [4] 03 05 80 [3] 89 85 54 FE FF FF E9 ?? 07 00 00 C7 05 [4] 01 00 00 00 68 04 }
		$a2 = { 55 8B EC 81 EC D4 01 00 00 53 56 57 EB 0C 45 78 50 72 2D 76 2E 31 2E 32 2E 2E B8 [4] 2B 05 84 [3] A3 [4] 83 3D [4] 00 74 16 A1 [4] 03 05 80 [3] 89 85 54 FE FF FF E9 ?? 07 00 00 C7 05 [4] 01 00 00 00 68 04 01 00 00 8D 85 F0 FE FF FF 50 6A 00 FF 15 }

	condition:
		$a0 or $a1 at pe.entry_point or $a2 at pe.entry_point
}

import "pe"

rule NullsoftPIMPInstallSystemv13x : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 81 EC [2] 00 00 56 57 6A ?? BE [4] 59 8D BD }

	condition:
		$a0 at pe.entry_point
}

rule Enigmaprotector110111VladimirSukhov : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 00 00 00 00 5D 83 ED 06 81 ED [35] E8 01 00 00 00 9A 83 C4 04 EB 02 FF 35 60 E8 24 00 00 00 00 00 FF EB 02 CD 20 8B 44 24 0C 83 80 B8 00 00 00 03 31 }
		$a1 = { 60 E8 00 00 00 00 5D 83 ED 06 81 ED [35] E8 01 00 00 00 9A 83 C4 04 EB 02 FF 35 60 E8 24 00 00 00 00 00 FF EB 02 CD 20 8B 44 24 0C 83 80 B8 00 00 00 03 31 C0 C3 83 C0 08 EB 02 FF 15 89 C4 61 EB 2E EA EB 2B 83 04 24 03 EB 01 00 31 C0 EB 01 85 64 FF 30 EB 01 83 64 89 20 EB 02 CD 20 89 00 9A 64 8F 05 00 00 00 00 EB 02 C1 90 58 61 EB 01 3E EB [41] E8 01 00 00 00 9A 83 C4 04 01 E8 [31] E8 01 00 00 00 9A 83 C4 04 05 F6 01 00 00 [31] E8 01 00 00 00 9A 83 C4 04 B9 3D 1A }

	condition:
		$a0 or $a1
}

import "pe"

rule PECompactv140b5v140b6 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB 06 68 [4] C3 9C 60 E8 02 [3] 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F A0 40 ?? 87 DD 8B 85 A6 A0 40 ?? 01 85 03 A0 40 ?? 66 C7 85 ?? A0 40 ?? 90 90 01 85 9E A0 40 ?? BB 8A 11 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule VxExplosion1000 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E8 [2] 5E 1E 06 50 81 [3] 56 FC B8 21 35 CD 21 2E [4] 2E [4] 26 [6] 74 ?? 8C D8 48 8E D8 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PKZIPSFXv11198990 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { FC 2E 8C 0E [2] A1 [2] 8C CB 81 C3 [2] 3B C3 72 ?? 2D [2] 2D [2] FA BC [2] 8E D0 FB }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PEBundlev20b5v23 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 9C 60 E8 02 [3] 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB [2] 40 ?? 87 DD 01 AD [4] 01 AD }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PUNiSHERV15DemoFEUERRADER : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB 04 83 A4 BC CE 60 EB 04 80 BC 04 11 E8 00 00 00 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule HACKSTOPv110v111 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { B4 30 CD 21 86 E0 3D [2] 73 ?? B4 2F CD 21 B0 ?? B4 4C CD 21 50 B8 [2] 58 EB }

	condition:
		$a0 at pe.entry_point
}

rule Obsidium1336ObsidiumSoftware : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB 04 [4] E8 28 00 00 00 EB 01 [7] 8B 54 24 0C EB 01 ?? 83 82 B8 00 00 00 26 EB 04 [4] 33 C0 EB 01 ?? C3 EB 03 [3] EB 04 [4] 64 67 FF 36 00 00 EB 04 [4] 64 67 89 26 00 00 EB 03 [3] EB 04 [4] 50 EB 01 ?? 33 C0 EB 02 [2] 8B 00 EB 04 [4] C3 EB 04 [4] E9 FA 00 00 00 EB 03 [3] E8 D5 FF FF FF EB 01 ?? EB 03 [3] 58 EB 02 [2] EB 04 [4] 64 67 8F 06 00 00 EB 04 }

	condition:
		$a0
}

import "pe"

rule DualseXeEncryptor10bDual : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 81 EC 00 05 00 00 E8 00 00 00 00 5D 81 ED 0E 00 00 00 8D 85 3A 04 00 00 89 28 33 FF 8D 85 80 03 00 00 8D 8D 3A 04 00 00 2B C8 8B 9D 8A 04 00 00 E8 24 02 00 00 8D 9D 58 03 00 00 8D B5 7F 03 00 00 46 80 3E 00 74 24 56 FF 95 58 05 00 00 46 80 3E 00 75 FA 46 80 3E 00 74 E7 50 56 50 FF 95 5C 05 00 00 89 03 58 83 C3 04 EB E3 8D 85 69 02 00 00 FF D0 8D 85 56 04 00 00 50 68 1F 00 02 00 6A 00 8D 85 7A 04 00 00 50 }

	condition:
		$a0 at pe.entry_point
}

rule MarjinZEXEScramblerSEbyMarjinZ : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E8 A3 02 00 00 E9 35 FD FF FF FF 25 C8 20 00 10 6A 14 68 C0 21 00 10 E8 E4 01 00 00 FF 35 7C 33 00 10 8B 35 8C 20 00 10 FF D6 59 89 45 E4 83 F8 FF 75 0C FF 75 08 FF 15 88 20 00 10 59 EB 61 6A 08 E8 02 03 00 00 59 83 65 FC 00 FF 35 7C 33 00 10 FF D6 89 45 E4 FF 35 78 33 00 10 FF D6 89 45 E0 8D 45 E0 50 8D 45 E4 50 FF 75 08 E8 D1 02 00 00 89 45 DC FF 75 E4 8B 35 74 20 00 10 FF D6 A3 7C 33 00 10 FF 75 E0 FF D6 83 C4 1C A3 78 33 00 10 C7 45 FC FE FF FF FF E8 09 00 00 00 8B 45 DC E8 A0 01 00 00 C3 }

	condition:
		$a0
}

import "pe"

rule nPack111502006BetaNEOx : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 83 3D [5] 75 05 E9 01 00 00 00 C3 E8 41 00 00 00 B8 [4] 2B 05 [4] A3 [4] E8 5E 00 00 00 E8 E0 01 00 00 E8 EC 06 00 00 E8 F7 05 00 00 A1 [4] C7 05 [8] 01 05 [4] FF 35 [4] C3 C3 56 57 68 [4] FF 15 [4] 8B 35 [4] 8B F8 68 [4] 57 FF D6 68 [4] 57 A3 [4] FF D6 5F A3 [4] 5E C3 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule DingBoysPElockPhantasmv15b3 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 9C 55 57 56 52 51 53 9C FA E8 00 00 00 00 5D 81 ED 5B 53 40 00 B0 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule ShellModify01pll621 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 6A FF 68 98 66 41 00 68 3C 3D 41 00 64 A1 00 00 00 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PseudoSigner01MacromediaFlashProjector60Anorganix : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 90 90 90 90 68 [4] 67 64 FF 36 00 00 67 64 89 26 00 00 F1 90 90 90 90 83 EC 44 56 FF 15 24 81 49 00 8B F0 8A 06 3C 22 75 1C 8A 46 01 46 3C 22 74 0C 84 C0 74 08 8A 46 01 46 3C 22 75 F4 80 3E 22 75 0F 46 EB 0C E9 }

	condition:
		$a0 at pe.entry_point
}

rule Packman0001Bubbasoft : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 0F 85 ?? FF FF FF 8D B3 [4] EB 3D 8B 46 0C 03 C3 50 FF 55 00 56 8B 36 0B F6 75 02 8B F7 03 F3 03 FB EB 1B D1 C1 D1 E9 73 05 0F B7 C9 EB 05 03 CB 8D 49 02 50 51 50 FF 55 04 AB 58 83 C6 04 8B 0E 85 C9 75 DF 5E 83 C6 14 8B 7E 10 85 FF 75 BC 8D 8B 00 }

	condition:
		$a0
}

rule aPackv098bDSESnotsaved : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 8C CB BA [2] 03 DA FC 33 F6 33 FF 4B 8E DB 8D [3] 8E C0 B9 [2] F3 A5 4A 75 }

	condition:
		$a0
}

rule ASProtectvIfyouknowthisversionpostonPEiDboardh2 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 90 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ED FF FF FF 03 DD 81 EB 00 [2] 00 80 7D 4D 01 75 0C 8B 74 24 28 83 FE 01 89 5D 4E 75 31 8D 45 53 50 53 FF B5 DD 09 00 00 8D 45 35 50 E9 82 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

	condition:
		$a0
}

import "pe"

rule Aluwainv809 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 8B EC 1E E8 [2] 9D 5E }

	condition:
		$a0 at pe.entry_point
}

rule AntiDote12DLLDemoSISTeam : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB 10 66 62 3A 43 2B 2B 48 4F 4F 4B 90 E9 08 32 90 90 90 90 90 90 90 90 90 90 80 7C 24 08 01 0F 85 [4] 60 BE [4] 8D BE [4] 57 83 CD FF EB 0B 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 EF 75 09 8B 1E 83 EE FC 11 DB 73 E4 31 C9 83 E8 03 72 0D C1 E0 08 8A 06 46 83 F0 FF 74 74 89 C5 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C9 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C9 75 20 41 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C9 01 DB 73 EF 75 09 8B 1E 83 EE FC 11 DB 73 E4 83 C1 02 81 FD 00 F3 FF FF 83 D1 01 8D 14 2F 83 FD FC 76 0F 8A 02 42 88 07 47 49 75 F7 E9 63 FF FF FF 90 8B 02 83 C2 04 89 07 83 C7 04 83 E9 04 77 F1 01 CF E9 4C FF FF FF }

	condition:
		$a0
}

import "pe"

rule MSLRHv032afakeMicrosoftVisualCemadicius : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 6A FF 68 CA 37 41 00 68 06 38 41 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 64 8F 05 00 00 00 00 83 C4 0C 5D EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 2B 04 24 74 04 75 02 EB 02 EB 01 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule SoftwareCompressV12BGSoftwareProtectTechnologies : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E9 BE 00 00 00 60 8B 74 24 24 8B 7C 24 28 FC B2 80 33 DB A4 B3 02 E8 6D 00 00 }

	condition:
		$a0 at pe.entry_point
}

rule Themida1201OreansTechnologies : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 8B C5 8B D4 60 E8 00 00 00 00 5D 81 ED [2] 35 09 89 95 [2] 35 09 89 B5 [2] 35 09 89 85 [2] 35 09 83 BD [2] 35 09 00 74 0C 8B E8 8B E2 B8 01 00 00 00 C2 0C 00 8B 44 24 24 89 85 [2] 35 09 6A 45 E8 A3 00 00 00 68 9A 74 83 07 E8 DF 00 00 00 68 25 }

	condition:
		$a0
}

import "pe"

rule PECompactv126b1v126b2 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB 06 68 [4] C3 9C 60 E8 02 [3] 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 70 40 ?? 87 DD 8B 85 A6 70 40 ?? 01 85 03 70 40 ?? 66 C7 85 70 40 90 ?? 90 01 85 9E 70 40 BB ?? 05 0E }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule Cruncherv10 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 2E [4] 2E [3] B4 30 CD 21 3C 03 73 ?? BB [2] 8E DB 8D [3] B4 09 CD 21 06 33 C0 50 CB }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule AntiDote1214SEDLLSISTeam : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB 10 66 62 3A 43 2B 2B 48 4F 4F 4B 90 E9 08 32 90 90 90 90 90 90 90 90 90 90 80 7C 24 08 01 0F 85 [4] 60 BE [4] 8D BE [4] 57 83 CD FF EB 0B 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 ?? 75 ?? 8B 1E 83 EE FC 11 DB }

	condition:
		$a0 at pe.entry_point
}

rule ASProtectSKE21xexeAlexeySolodovnikov : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 90 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ED FF FF FF 03 DD 81 EB 00 [3] 80 7D 4D 01 75 0C 8B 74 24 28 83 FE 01 89 5D 4E 75 31 8D 45 53 50 53 FF B5 ED 09 00 00 8D 45 35 50 E9 82 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

	condition:
		$a0
}

import "pe"

rule DBPEv210DingBoy : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB 20 [32] 9C 55 57 56 52 51 53 9C E8 [4] 5D 81 ED [4] EB 58 75 73 65 72 33 32 2E 64 6C 6C ?? 4D 65 73 73 61 67 65 42 6F 78 41 ?? 6B 65 72 6E 65 6C }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule NsPacKV37LiuXingPing : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 9C 60 E8 00 00 00 00 5D 83 ED 07 8D [4] ?? 80 39 01 0F [3] 00 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule tElock099tE : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E9 5E DF FF FF 00 00 00 [4] E5 [2] 00 00 00 00 00 00 00 00 00 05 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule WinZipSelfExtractor22personaleditionWinZipComputing : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 53 FF 15 58 70 40 00 B3 22 38 18 74 03 80 C3 FE 40 33 D2 8A 08 3A CA 74 10 3A CB 74 07 40 8A 08 3A CA 75 F5 38 10 74 01 40 52 50 52 52 FF 15 5C 70 40 00 50 E8 15 FB FF FF 50 FF 15 8C 70 40 00 5B }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule ZipWorxSecureEXEv25ZipWORXTechnologiesLLC : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E9 B8 00 00 00 [12] 00 00 00 00 00 [10] 00 53 65 63 75 72 65 45 58 45 20 45 78 65 63 75 74 61 62 6C 65 20 46 69 6C 65 20 50 72 6F 74 65 63 74 6F 72 0D 0A 43 6F 70 79 72 69 67 68 74 28 63 29 20 32 30 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule RLPackFullEdition117iBoxaPLibAp0x : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 [15] 8D B5 79 29 00 00 8D 9D 2C 03 00 00 33 FF [15] EB 0F FF 74 37 04 FF 34 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule Alloyv1x2000 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 9C 60 E8 02 [3] 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 07 20 40 ?? 87 DD 6A 04 68 ?? 10 [2] 68 ?? 02 [2] 6A ?? FF 95 46 23 40 ?? 0B }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule FreeJoiner153Stubengine171GlOFF : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E8 02 FD FF FF 6A 00 E8 0D 00 00 00 CC FF 25 80 10 40 00 FF 25 84 10 40 00 FF 25 88 10 40 00 FF 25 8C 10 40 00 FF 25 90 10 40 00 FF 25 94 10 40 00 FF 25 98 10 40 00 FF 25 9C 10 40 00 FF 25 A0 10 40 00 FF 25 A8 10 40 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PseudoSigner02MicrosoftVisualC70DLLAnorganix : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8D 6C 01 00 81 EC 00 00 00 00 8B 45 90 83 F8 01 56 0F 84 00 00 00 00 85 C0 0F 84 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule EYouDiDaiYueHeiFengGao : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC B8 [4] E8 [4] 53 56 57 0F 31 8B D8 0F 31 8B D0 2B D3 C1 EA 10 B8 [4] 0F 6E C0 B8 [4] 0F 6E C8 0F F5 C1 0F 7E C0 0F 77 03 C2 [5] FF E0 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule EXECryptorV21Xsoftcompletecom : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 83 C6 14 8B 55 FC E9 ?? FF FF FF }
		$a1 = { E9 [4] 66 9C 60 50 8D 88 [4] 8D 90 04 16 [2] 8B DC 8B E1 }

	condition:
		$a0 or $a1 at pe.entry_point
}

import "pe"

rule PCShrinkerv045 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { BD [4] 01 AD E3 38 40 ?? FF B5 DF 38 40 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule yodasProtectorV1033AshkbizDanehkar : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E8 03 00 00 00 EB 01 ?? BB 55 00 00 00 E8 03 00 00 00 EB 01 ?? E8 8E 00 00 00 E8 03 00 00 00 EB 01 ?? E8 81 00 00 00 E8 03 00 00 00 EB 01 ?? E8 B7 00 00 00 E8 03 00 00 00 EB 01 ?? E8 AA 00 00 00 E8 03 00 00 00 EB 01 ?? 83 FB 55 E8 03 00 00 00 EB 01 ?? 75 2D E8 03 00 00 00 EB 01 ?? 60 E8 00 00 00 00 5D 81 ED 07 E2 40 00 8B D5 81 C2 56 E2 40 00 52 E8 01 00 00 00 C3 C3 E8 03 00 00 00 EB 01 ?? E8 0E 00 00 00 E8 D1 FF FF FF C3 E8 03 00 00 00 EB 01 ?? 33 C0 64 FF 30 64 89 20 CC C3 E8 03 00 00 00 EB 01 ?? 33 C0 64 FF 30 64 89 20 4B CC C3 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule SoftSentryv211 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 83 EC ?? 53 56 57 E9 50 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule FSGv120EngdulekxtBorlandDelphiBorlandC : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 0F BE C1 EB 01 0E 8D 35 C3 BE B6 22 F7 D1 68 43 [2] 22 EB 02 B5 15 5F C1 F1 15 33 F7 80 E9 F9 BB F4 00 00 00 EB 02 8F D0 EB 02 08 AD 8A 16 2B C7 1B C7 80 C2 7A 41 80 EA 10 EB 01 3C 81 EA CF AE F1 AA EB 01 EC 81 EA BB C6 AB EE 2C E3 32 D3 0B CB 81 EA AB }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule AHTeamEPProtector03fakeStonesPEEncryptor20FEUERRADER : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 90 [46] 90 FF E0 53 51 52 56 57 55 E8 00 00 00 00 5D 81 ED 42 30 40 00 FF 95 32 35 40 00 B8 37 30 40 00 03 C5 2B 85 1B 34 40 00 89 85 27 34 40 00 83 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule Armadillov300 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 [4] 5D 50 51 EB 0F B9 EB 0F B8 EB 07 B9 EB 0F 90 EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC E9 59 58 60 33 C9 }

	condition:
		$a0 at pe.entry_point
}

rule RCryptorv11Vaska : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 8B 04 24 83 E8 4F 68 [4] FF D0 }
		$a1 = { 8B 04 24 83 E8 4F 68 [4] FF D0 B8 [4] 3D [4] 74 06 80 30 ?? 40 EB F3 }

	condition:
		$a0 or $a1
}

import "pe"

rule Fusion10jaNooNi : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 68 04 30 40 00 68 04 30 40 00 E8 09 03 00 00 68 04 30 40 00 E8 C7 02 00 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule UpxLock1012CyberDoomTeamXBoBBobSoft : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED 48 12 40 00 60 E8 2B 03 00 00 61 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PCPEEncryptorAlphapreview : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 53 51 52 56 57 55 E8 00 00 00 00 5D 8B CD 81 ED 33 30 40 ?? 2B 8D EE 32 40 00 83 E9 0B 89 8D F2 32 40 ?? 80 BD D1 32 40 ?? 01 0F 84 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule VxKeypress1212 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E8 [2] E8 [2] E8 [2] E8 [4] E8 [4] E8 [4] EA [4] 1E 33 DB 8E DB BB }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule SoftwareCompressv12BGSoftwareProtectTechnologies : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E9 BE 00 00 00 60 8B 74 24 24 8B 7C 24 28 FC B2 80 33 DB A4 B3 02 E8 6D 00 00 00 73 F6 33 C9 E8 64 00 00 00 73 1C 33 C0 E8 5B 00 00 00 73 23 B3 02 41 B0 10 E8 4F 00 00 00 12 C0 73 F7 75 3F AA EB D4 E8 4D 00 00 00 2B CB 75 10 E8 42 00 00 00 EB 28 AC D1 E8 74 4D 13 C9 EB 1C 91 48 C1 E0 08 AC E8 2C 00 00 00 3D 00 7D 00 00 73 0A 80 FC 05 73 06 83 F8 7F 77 02 41 41 95 8B C5 B3 01 56 8B F7 2B F0 F3 A4 5E EB 8E 02 D2 75 05 8A 16 46 12 D2 C3 33 C9 41 E8 EE FF FF FF 13 C9 E8 E7 FF FF FF 72 F2 C3 2B 7C 24 28 89 7C 24 1C 61 C3 60 FF 74 24 24 6A 40 FF 95 1A 0F 41 00 89 44 24 1C 61 C2 04 00 E8 00 00 00 00 81 2C 24 3A 10 41 00 5D E8 00 00 00 00 81 2C 24 31 01 00 00 8B 85 2A 0F 41 00 29 04 24 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule NsPackV14LiuXingPing : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 9C 60 E8 00 00 00 00 5D B8 B1 85 40 00 2D AA 85 40 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule VProtectorV11Avcasm : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB 0B 5B 56 50 72 6F 74 65 63 74 5D 00 E8 24 00 00 00 8B 44 24 04 8B 00 3D 04 00 00 80 75 08 8B 64 24 08 EB 04 58 EB 0C E9 64 8F 05 00 00 00 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule Obsidium1300ObsidiumSoftware : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB 04 [4] E8 29 00 00 00 EB 02 [2] EB 01 ?? 8B 54 24 0C EB 02 [2] 83 82 B8 00 00 00 22 EB 02 [2] 33 C0 EB 04 [4] C3 EB 04 [4] EB 04 [4] 64 67 FF 36 00 00 EB 04 [4] 64 67 89 26 00 00 EB 04 [4] EB 01 ?? 50 EB 03 [3] 33 C0 EB 02 [2] 8B 00 EB 01 ?? C3 EB 04 [4] E9 FA 00 00 00 EB 01 ?? E8 D5 FF FF FF EB 02 [2] EB 03 [3] 58 EB 04 [4] EB 01 ?? 64 67 8F 06 00 00 EB 02 [2] 83 C4 04 EB 02 [2] E8 47 26 00 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule XXPack01bagie : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E8 04 00 00 00 83 60 EB 0C 5D EB 05 45 55 EB 04 B8 EB F9 00 C3 E8 00 00 00 00 5D EB 01 00 81 ED 5E 1F 40 00 EB 02 83 09 8D B5 EF 1F 40 00 EB 02 83 09 BA A3 11 00 00 EB 00 68 00 [3] C3 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule ExeLocker10IonIce : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E8 00 00 00 00 60 8B 6C 24 20 81 ED 05 00 00 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule yodasProtectorV101AshkbizDanehkar : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 53 56 57 E8 03 00 00 00 EB 01 ?? E8 86 00 00 00 E8 03 00 00 00 EB 01 ?? E8 79 00 00 00 E8 03 00 00 00 EB 01 ?? E8 A4 00 00 00 E8 03 00 00 00 EB 01 ?? E8 97 00 00 00 E8 03 00 00 00 EB 01 ?? E8 2D 00 00 00 E8 03 00 00 00 EB 01 ?? 60 E8 00 00 00 00 5D 81 ED D5 E4 41 00 8B D5 81 C2 23 E5 41 00 52 E8 01 00 00 00 C3 C3 E8 03 00 00 00 EB 01 ?? E8 0E 00 00 00 E8 D1 FF FF FF C3 E8 03 00 00 00 EB 01 ?? 33 C0 64 FF 30 64 89 20 CC C3 E8 03 00 00 00 EB 01 ?? 33 C0 64 FF 30 64 89 20 CC C3 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule ASPackv2001AlexeySolodovnikov : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 72 05 00 00 EB 4C }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule USERNAMEv300 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { FB 2E [4] 2E [4] 2E [4] 2E [4] 8C C8 2B C1 8B C8 2E [4] 2E [4] 33 C0 8E D8 06 0E 07 FC 33 F6 }

	condition:
		$a0 at pe.entry_point
}

rule nSpackV2xLiuXingPing : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 9C 60 E8 00 00 00 00 5D B8 07 00 00 00 2B E8 8D B5 }

	condition:
		$a0
}

import "pe"

rule GameGuardv20065xxdllsignbyhot_UNP : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 31 FF 74 06 61 E9 4A 4D 50 30 BA 4C 00 00 00 80 7C 24 08 01 0F 85 ?? 01 00 00 60 BE 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule Upack_PatchoranyVersionDwing : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 09 00 00 00 [3] 00 E9 06 02 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PCPECalpha : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 53 51 52 56 57 55 E8 [4] 5D 8B CD 81 [4] ?? 2B [4] ?? 83 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule WWPACKv305c4Unextractable : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 03 05 00 1B B8 [2] 8C CA 03 D0 8C C9 81 C1 [2] 51 B9 [2] 51 06 06 B1 ?? 51 8C D3 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule Escargot01finalMeat : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB 04 40 30 2E 31 60 68 61 [3] 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 B8 92 [3] 8B 00 FF D0 50 B8 CD [3] 81 38 DE C0 37 13 75 2D 68 C9 [3] 6A 40 68 00 ?? 00 00 68 00 00 [2] B8 96 [3] 8B 00 FF D0 8B 44 24 F0 8B 4C 24 F4 EB 05 49 C6 04 01 40 0B C9 75 F7 BE 00 10 [2] B9 00 [2] 00 EB 05 49 80 34 31 40 0B C9 75 F7 58 0B C0 74 08 33 C0 C7 00 DE C0 AD 0B BE [4] E9 AC 00 00 00 8B 46 0C BB 00 00 [2] 03 C3 50 50 }

	condition:
		$a0 at pe.entry_point
}

rule MetrowerksCodeWarriorv20GUI : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 89 E5 53 56 83 EC 44 55 B8 FF FF FF FF 50 50 68 [2] 40 00 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 68 [12] E8 [2] 00 00 E8 [2] 00 00 E8 }

	condition:
		$a0
}

rule UnnamedScrambler21Beta211p0ke : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC B9 15 00 00 00 6A 00 6A 00 49 75 F9 53 56 57 B8 ?? 3A [2] E8 ?? EE FF FF 33 C0 55 68 ?? 43 [2] 64 FF 30 64 89 20 BA ?? 43 [2] B8 E4 64 [2] E8 0F FD FF FF 8B D8 85 DB 75 07 6A 00 E8 ?? EE FF FF BA E8 64 [2] 8B C3 8B 0D E4 64 [2] E8 ?? D7 FF FF B8 F8 [3] BA 04 00 00 00 E8 ?? EF FF FF 33 C0 A3 F8 [3] BB [4] C7 45 EC E8 64 [2] C7 45 E8 [4] C7 45 E4 [4] BE [4] BF [4] B8 E0 [3] BA 04 00 00 00 E8 ?? EF FF FF 68 F4 01 00 00 E8 ?? EE FF FF 83 7B 04 00 75 0B 83 3B 00 0F 86 ?? 07 00 00 EB 06 0F 8E ?? 07 00 00 8B 03 8B D0 B8 E4 [3] E8 ?? E5 FF FF B8 E4 [3] E8 ?? E3 FF FF 8B D0 8B 45 EC 8B 0B E8 }

	condition:
		$a0
}

import "pe"

rule NoodleCryptv20 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB 01 9A E8 3D 00 00 00 EB 01 9A E8 EB 01 00 00 EB 01 9A E8 2C 04 00 00 EB 01 }
		$a1 = { EB 01 9A E8 ?? 00 00 00 EB 01 9A E8 [2] 00 00 EB 01 9A E8 [2] 00 00 EB 01 }

	condition:
		$a0 at pe.entry_point or $a1
}

import "pe"

rule PoPa001PackeronPascalbagie : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 83 C4 EC 53 56 57 33 C0 89 45 EC B8 A4 3E 00 10 E8 30 F6 FF FF 33 C0 55 68 BE 40 00 10 [4] 89 20 6A 00 68 80 00 00 00 6A 03 6A 00 6A 01 68 00 00 00 80 8D 55 EC 33 C0 E8 62 E7 FF FF 8B 45 EC E8 32 F2 FF FF 50 E8 B4 F6 FF FF A3 64 66 00 10 33 D2 55 68 93 40 00 10 64 FF 32 64 89 22 83 3D 64 66 00 10 FF 0F 84 3A 01 00 00 6A 00 6A 00 6A 00 A1 64 66 00 10 50 E8 9B F6 FF FF 83 E8 10 50 A1 64 66 00 10 50 E8 BC F6 FF FF 6A 00 68 80 66 00 10 6A 10 68 68 66 00 10 A1 64 66 00 10 50 E8 8B F6 FF FF }

	condition:
		$a0 at pe.entry_point
}

rule BlindSpot10s134k : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 81 EC 50 02 00 00 8D 85 B0 FE FF FF 53 56 A3 90 12 40 00 57 8D 85 B0 FD FF FF 68 00 01 00 00 33 F6 50 56 FF 15 24 10 40 00 56 68 80 00 00 00 6A 03 56 56 8D 85 B0 FD FF FF 68 00 00 00 80 50 FF 15 20 10 40 00 56 56 68 00 08 00 00 50 89 45 FC FF 15 1C 10 40 00 8D 45 F8 8B 1D 18 10 40 00 56 50 6A 34 FF 35 90 12 40 00 FF 75 FC FF D3 85 C0 0F 84 7F 01 00 00 39 75 F8 0F 84 76 01 00 00 A1 90 12 40 00 66 8B 40 30 66 3D 01 00 75 14 8D 85 E4 FE FF FF 68 04 01 00 00 50 FF 15 14 10 40 00 EB 2C 66 3D 02 00 75 14 8D 85 E4 FE FF FF 50 68 04 01 00 00 FF 15 10 10 40 00 EB 12 8D 85 E4 FE FF FF 68 04 01 00 00 50 FF 15 0C 10 40 00 8B 3D 08 10 40 00 8D 85 E4 FE FF FF 68 54 10 40 00 50 }

	condition:
		$a0
}

import "pe"

rule GamehouseMediaProtectorVersionUnknown : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 68 [4] 6A 00 FF 15 [4] 50 FF 15 [3] 00 00 00 00 00 00 00 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule tElockv042 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { C1 EE 00 66 8B C9 EB 01 EB 60 EB 01 EB 9C E8 00 00 00 00 5E 83 C6 52 8B FE 68 79 01 59 EB 01 EB AC 54 E8 03 5C EB 08 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule EXEStealthv274WebToolMaster : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB 00 EB 17 [23] 60 90 E8 00 00 00 00 5D }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule EXEManagerVersion301994cSolarDesigner : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { B4 30 1E 06 CD 21 2E [3] BF [2] B9 [2] 33 C0 2E [2] 47 E2 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule Upackv02BetaDwing : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { BE 88 01 [2] AD 8B F8 95 A5 33 C0 33 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule DEFv100Engbartxt : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { BE ?? 01 40 00 6A ?? 59 80 7E 07 00 74 11 8B 46 0C 05 00 00 40 00 8B 56 10 30 10 40 4A 75 FA 83 C6 28 E2 E4 68 [2] 40 00 C3 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule AnslymCrypter : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 83 C4 F0 53 56 B8 38 17 05 10 E8 5A 45 FB FF 33 C0 55 68 21 1C 05 10 64 FF 30 64 89 20 EB 08 FC FC FC FC FC FC 27 54 E8 85 4C FB FF 6A 00 E8 0E 47 FB FF 6A 0A E8 27 49 FB FF E8 EA 47 FB FF 6A 0A 68 30 1C 05 10 A1 60 56 05 10 50 E8 68 47 FB FF 8B D8 85 DB 0F 84 B6 02 00 00 53 A1 60 56 05 10 50 E8 F2 48 FB FF 8B F0 85 F6 0F 84 A0 02 00 00 E8 F3 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule ARMProtectorv02SMoKE : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E8 04 00 00 00 83 60 EB 0C 5D EB 05 45 55 EB 04 B8 EB F9 00 C3 E8 00 00 00 00 5D EB 01 00 81 ED 09 20 40 00 EB 02 83 09 8D B5 9A 20 40 00 EB 02 83 09 BA 0B 12 00 00 EB 01 00 8D 8D A5 32 40 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule CrypKeyV56XDLLKenonicControlsLtd : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 8B 1D [4] 83 FB 00 75 0A E8 [4] E8 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PEiDBundlev102v104BoBBobSoft : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 36 [3] 2E [3] 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 00 80 00 00 00 00 4B 65 72 6E 65 6C 33 32 2E 44 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule VxHeloween1172 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E8 [2] 5E 81 EE [2] 56 50 06 0E 1F 8C C0 01 [2] 01 [2] 80 [4] 8B [2] A3 [2] 8A [2] A2 [2] B8 [2] CD 21 3D }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PackedwithPKLITEv150withCRCcheck1 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 1F B4 09 BA [2] CD 21 B8 [2] CD 21 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule Pe123v2006412 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 8B C0 60 9C E8 01 00 00 00 C3 53 E8 72 00 00 00 50 E8 1C 03 00 00 8B D8 FF D3 5B C3 8B C0 E8 00 00 00 00 58 83 C0 05 C3 8B C0 55 8B EC 60 8B 4D 10 8B 7D 0C 8B 75 08 F3 A4 61 5D C2 0C 00 E8 00 00 00 00 58 83 E8 05 C3 8B C0 E8 00 00 00 00 58 83 C0 05 C3 8B }

	condition:
		$a0 at pe.entry_point
}

rule DropperCreatorV01Conflict : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 00 00 00 00 5D 8D 05 [4] 29 C5 8D 85 [4] 31 C0 64 03 40 30 78 0C 8B 40 0C 8B 70 1C AD 8B 40 08 EB 09 }

	condition:
		$a0
}

import "pe"

rule XCRv013 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 93 71 08 [8] 8B D8 78 E2 [4] 9C 33 C3 [4] 60 79 CE [4] E8 01 [4] 83 C4 04 E8 AB FF FF FF [4] 2B E8 [4] 03 C5 FF 30 [4] C6 ?? EB }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule XCRv012 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 9C E8 [4] 8B DD 5D 81 ED [4] 89 9D }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule InnoSetupModulev129 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 83 C4 C0 53 56 57 33 C0 89 45 F0 89 45 EC 89 45 C0 E8 5B 73 FF FF E8 D6 87 FF FF E8 C5 A9 FF FF E8 E0 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule Armadillov3xx : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 [4] 5D 50 51 EB 0F B9 EB 0F B8 EB 07 B9 EB 0F 90 EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC E9 59 58 }

	condition:
		$a0 at pe.entry_point
}

rule dUP2xPatcherwwwdiablo2oo2cjbnet : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 8B CB 85 C9 74 ?? 80 3A 01 74 08 AC AE 75 0A 42 49 EB EF 47 46 42 49 EB E9 }

	condition:
		$a0
}

import "pe"

rule PseudoSigner02PEProtect09Anorganix : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 52 51 55 57 64 67 A1 30 00 85 C0 78 0D E8 07 00 00 00 58 83 C0 07 C6 90 C3 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule pscrambler12byp0ke : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC B9 04 00 00 00 6A 00 6A 00 49 75 F9 51 53 [4] 10 E8 2D F3 FF FF 33 C0 55 68 E8 31 00 10 64 FF 30 64 89 20 8D 45 E0 E8 53 F5 FF FF 8B 45 E0 8D 55 E4 E8 30 F6 FF FF 8B 45 E4 8D 55 E8 E8 A9 F4 FF FF 8B 45 E8 8D 55 EC E8 EE F7 FF FF 8B 55 EC B8 C4 54 00 10 E8 D9 EC FF FF 83 3D C4 54 00 10 00 0F 84 05 01 00 00 80 3D A0 40 00 10 00 74 41 A1 C4 54 00 10 E8 D9 ED FF FF E8 48 E0 FF FF 8B D8 A1 C4 54 00 10 E8 C8 ED FF FF 50 B8 C4 54 00 10 E8 65 EF FF FF 8B D3 59 E8 69 E1 FF FF 8B C3 E8 12 FA FF FF 8B C3 E8 33 E0 FF FF E9 AD 00 00 00 B8 05 01 00 00 E8 0C E0 FF FF 8B D8 53 68 05 01 00 00 E8 57 F3 FF FF 8D 45 DC 8B D3 E8 39 ED FF FF 8B 55 DC B8 14 56 00 10 B9 00 32 00 10 E8 BB ED FF FF 8B 15 14 56 00 10 B8 C8 54 00 10 E8 53 E5 FF FF BA 01 00 00 00 B8 C8 54 00 10 E8 8C E8 FF FF E8 DF E0 FF FF 85 C0 75 52 6A 00 A1 C4 54 00 10 E8 3B ED FF FF 50 B8 C4 54 00 10 E8 D8 EE FF FF 8B D0 B8 C8 54 00 10 59 E8 3B E6 FF FF E8 76 E0 FF FF B8 C8 54 00 10 E8 4C E6 FF FF E8 67 E0 FF FF 6A 00 6A 00 6A 00 A1 14 56 00 10 E8 53 EE FF FF 50 6A 00 6A 00 E8 41 F3 FF FF 80 3D 9C 40 00 10 00 74 05 E8 EF FB FF FF 33 C0 5A 59 59 64 89 10 68 EF 31 00 10 8D 45 DC BA 05 00 00 00 E8 7D EB FF FF C3 E9 23 E9 FF FF EB EB 5B E8 63 EA FF FF 00 00 00 FF FF FF FF 08 00 00 00 74 65 6D 70 2E 65 78 65 }

	condition:
		$a0 at pe.entry_point
}

rule EXECryptor2223compressedcodewwwstrongbitcom : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E8 00 00 00 00 58 [5] 8B 1C 24 81 EB [4] B8 [4] 50 6A 04 68 00 10 00 00 50 6A 00 B8 C4 [3] 8B 04 18 FF D0 59 BA [4] 01 DA 52 53 50 89 C7 89 D6 FC F3 A4 B9 [4] 01 D9 FF D1 58 8B 1C 24 68 00 80 00 00 6A 00 50 }
		$a1 = { E8 00 00 00 00 58 [5] 8B 1C 24 81 EB [4] B8 [4] 50 6A 04 68 00 10 00 00 50 6A 00 B8 C4 [3] 8B 04 18 FF D0 59 BA [4] 01 DA 52 53 50 89 C7 89 D6 FC F3 A4 B9 [4] 01 D9 FF D1 58 8B 1C 24 68 00 80 00 00 6A 00 50 B8 C8 [3] 8B 04 18 FF D0 59 58 5B 83 EB 05 C6 03 B8 43 89 03 83 C3 04 C6 03 C3 09 C9 74 46 89 C3 E8 A0 00 00 00 FC AD 83 F8 FF 74 38 53 89 CB 01 C3 01 0B 83 C3 04 AC 3C FE 73 07 25 FF 00 00 00 EB ED 81 C3 FE 00 00 00 09 C0 7A 09 66 AD 25 FF FF 00 00 EB DA AD 4E 25 FF FF FF 00 3D FF FF FF 00 75 CC [5] C3 }

	condition:
		$a0 or $a1
}

import "pe"

rule Armadillov265b1 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 6A FF 68 38 [3] 68 40 [3] 64 A1 [4] 50 64 89 25 [4] 83 EC 58 53 56 57 89 65 E8 FF 15 28 [3] 33 D2 8A D4 89 15 F4 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule RLPackFullEdition117aPLibAp0x : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 [15] 8D B5 74 1F 00 00 8D 9D 1E 03 00 00 33 FF [15] EB 0F FF 74 37 04 FF 34 }

	condition:
		$a0 at pe.entry_point
}

rule PolyCryptPE214b215JLabSoftwareCreationshoep : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 91 8B F4 AD FE C9 80 34 08 ?? E2 FA C3 60 E8 ED FF FF FF EB }

	condition:
		$a0
}

import "pe"

rule yodasProtector10xAshkbizDanehkar : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 53 56 57 E8 03 00 00 00 EB 01 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule Upack_UnknownDLLDwing : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 09 00 00 00 17 CD 00 00 E9 06 02 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule AINEXEv21 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { A1 [2] 2D [2] 8E D0 BC [2] 8C D8 36 A3 [2] 05 [2] 36 A3 [2] 2E A1 [2] 8A D4 B1 04 D2 EA FE C9 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule AppProtectorSilentTeam : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E9 97 00 00 00 0D 0A 53 69 6C 65 6E 74 20 54 65 61 6D 20 41 70 70 20 50 72 6F 74 65 63 74 6F 72 0D 0A 43 72 65 61 74 65 64 20 62 79 20 53 69 6C 65 6E 74 20 53 6F 66 74 77 61 72 65 0D 0A 54 68 65 6E 6B 7A 20 74 6F 20 44 6F 63 68 74 6F 72 20 58 0D 0A 0D 0A }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule RODHighTECHAyman : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 8B 15 1D 13 40 00 F7 E0 8D 82 83 19 00 00 E8 58 0C 00 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule ICrypt10byBuGGz : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 83 C4 EC 53 56 57 33 C0 89 45 EC B8 70 3B 00 10 E8 3C FA FF FF 33 C0 55 68 6C 3C 00 10 64 FF 30 64 89 20 6A 0A 68 7C 3C 00 10 A1 50 56 00 10 50 E8 D8 FA FF FF 8B D8 53 A1 50 56 00 10 50 E8 0A FB FF FF 8B F8 53 A1 50 56 00 10 50 E8 D4 FA FF FF 8B D8 53 E8 D4 FA FF FF 8B F0 85 F6 74 26 8B D7 4A B8 64 56 00 10 E8 25 F6 FF FF B8 64 56 00 10 E8 13 F6 FF FF 8B CF 8B D6 E8 E6 FA FF FF 53 E8 90 FA FF FF 8D 4D EC BA 8C 3C 00 10 A1 64 56 00 10 E8 16 FB FF FF 8B 55 EC B8 64 56 00 10 E8 C5 F4 FF FF B8 64 56 00 10 E8 DB F5 FF FF E8 56 FC FF FF 33 C0 5A 59 59 64 89 10 68 73 3C 00 10 8D 45 EC E8 4D F4 FF FF C3 E9 E3 EE FF FF EB F0 5F 5E 5B E8 4D F3 FF FF 00 53 45 54 [4] 00 FF FF FF FF 08 00 00 00 76 6F 74 72 65 63 6C 65 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PEPackv099 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 [4] 5D 83 ED 06 80 BD E0 04 [2] 01 0F 84 F2 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule RLPackV115V117LZMA430ap0x : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 [4] 8D 9D [4] 33 FF E8 83 01 00 00 6A ?? 68 [4] 68 [4] 6A ?? FF 95 [4] 89 85 [4] EB 14 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule VxQuake518 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 1E 06 8C C8 8E D8 [7] B8 21 35 CD 21 81 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule WWPACKv305c4UnextractableVirusShield : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 03 05 40 1B B8 [2] 8C CA 03 D0 8C C9 81 C1 [2] 51 B9 [2] 51 06 06 B1 ?? 51 8C D3 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule Obsidium13013ObsidiumSoftware : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB 01 ?? E8 26 00 00 00 EB 02 [2] EB 02 [2] 8B 54 24 0C EB 01 ?? 83 82 B8 00 00 00 21 EB 04 [4] 33 C0 EB 02 [2] C3 EB 01 ?? EB 04 [4] 64 67 FF 36 00 00 EB 02 [2] 64 67 89 26 00 00 EB 01 ?? EB 03 [3] 50 EB 01 ?? 33 C0 EB 03 [3] 8B 00 EB 02 [2] C3 EB 02 [2] E9 FA 00 00 00 EB 01 ?? E8 D5 FF FF FF EB 03 [3] EB 02 [2] 58 EB 03 [3] EB 04 [4] 64 67 8F 06 00 00 EB 03 [3] 83 C4 04 EB 03 [3] E8 13 26 00 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule ObsidiumV130XObsidiumSoftware : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB 03 [3] E8 2E 00 00 00 EB 04 [4] EB 04 [4] 8B [3] EB 04 [4] 83 [6] EB 01 ?? 33 C0 EB 04 [4] C3 }

	condition:
		$a0 at pe.entry_point
}

rule MetrowerksCodeWarriorv20Console : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 89 E5 55 B8 FF FF FF FF 50 50 68 [4] 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 68 [4] E8 [12] E8 [2] 00 00 E8 [2] 00 00 E8 }

	condition:
		$a0
}

import "pe"

rule PESpinv07Cyberbob : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 83 D5 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 17 EB 07 EA EB 01 EB EB 0D FF }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule SimpleUPXCryptorV3042005MANtiCORE : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 B8 [4] B9 [8] E2 FA 61 68 [4] C3 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule WinRAR32bitSFXModule : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E9 [2] 00 00 00 00 00 00 90 90 90 [6] 00 ?? 00 [5] FF }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule iPBProtect013017forgot : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 6A FF 68 4B 43 55 46 68 54 49 48 53 64 A1 00 00 00 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule MSLRHv032afakeASPack211demadicius : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 02 00 00 00 EB 09 5D 55 81 ED 39 39 44 00 C3 61 EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF }

	condition:
		$a0 at pe.entry_point
}

rule Upackv036alphaDwing : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { AB E2 E5 5D 59 8B 76 68 51 59 46 AD 85 C0 }

	condition:
		$a0
}

import "pe"

rule CrinklerV03V04RuneLHStubbeandAskeSimonChristensen : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { B8 00 00 42 00 31 DB 43 EB 58 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule DingBoysPElockPhantasmv10v11 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 57 56 52 51 53 66 81 C3 EB 02 EB FC 66 81 C3 EB 02 EB FC }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PECompactV2XBitsumTechnologies : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { B8 [4] 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 50 45 43 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule CRYPTVersion17cDismember : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 0E 17 9C 58 F6 [2] 74 ?? E9 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule VxXPEH4768 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E8 [2] 5B 81 [3] 50 56 57 2E [5] 2E [6] B8 01 00 50 B8 [2] 50 E8 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PECrypt32v102 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E8 00 00 00 00 5B 83 [2] EB ?? 52 4E 44 21 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PseudoSigner01PESHiELD025Anorganix : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 2B 00 00 00 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 CC CC E9 }

	condition:
		$a0 at pe.entry_point
}

rule NETDLLMicrosoft : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 00 00 00 00 00 00 00 00 5F 43 6F 72 44 6C 6C 4D 61 69 6E 00 6D 73 63 6F 72 65 65 2E 64 6C 6C 00 00 ?? 00 00 FF 25 }

	condition:
		$a0
}

import "pe"

rule MSLRH : Packer PEiD hardened
{
	meta:
		author = "malware-lu"
		note = "Added some checks"

	strings:
		$a0 = { 60 EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 2B 04 24 74 04 75 02 EB 02 EB 01 81 83 C4 04 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 3D FF 0F 00 00 EB 01 68 EB 02 CD 20 EB 01 E8 76 1B EB 01 68 EB 02 CD 20 EB 01 E8 CC 66 B8 FE 00 74 04 75 02 EB 02 EB 01 81 66 E7 64 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 2B 04 24 74 04 75 02 EB 02 EB 01 81 }
		$b = { EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 2B 04 24 74 04 75 02 EB 02 EB 01 81 83 C4 04 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 3D FF 0F 00 00 EB 01 68 EB 02 CD 20 EB 01 E8 76 1B EB 01 68 EB 02 CD 20 EB 01 E8 CC 66 B8 FE 00 74 04 75 02 EB 02 EB 01 81 66 E7 64 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 2B 04 24 74 04 75 02 EB 02 EB 01 81 83 C4 04 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 3D FF 0F 00 00 EB 01 68 EB 02 CD 20 EB 01 E8 76 1B EB 01 68 EB 02 CD 20 EB 01 E8 CC 66 B8 FE 00 74 04 75 02 EB 02 EB 01 81 66 E7 64 74 04 75 02 EB 02 EB 01 81 74 04 75 02 EB 02 EB 01 81 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 2B 04 24 74 04 75 02 EB 02 EB 01 81 83 C4 04 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 3D FF 0F 00 00 EB 01 68 EB 02 CD 20 EB 01 E8 76 1B EB 01 68 EB 02 CD 20 EB 01 E8 CC 66 B8 FE 00 74 04 75 02 EB 02 EB 01 81 66 E7 64 74 04 75 02 EB 02 EB 01 81 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 2B 04 24 74 04 75 02 EB 02 EB 01 81 83 C4 04 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 3D FF 0F 00 00 EB 01 68 EB 02 CD 20 EB 01 E8 76 1B EB 01 68 EB 02 CD 20 EB 01 E8 CC 66 B8 FE 00 74 04 75 02 EB 02 EB 01 81 66 E7 64 74 04 75 02 EB 02 EB 01 81 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 2B 04 24 74 04 75 02 EB 02 EB 01 81 83 C4 04 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 }
		$c = { 60 EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 2B 04 24 74 04 75 02 EB 02 EB 01 81 83 C4 04 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 3D FF 0F 00 00 EB 01 68 EB 02 CD 20 EB 01 E8 76 1B EB 01 68 EB 02 CD 20 EB 01 E8 CC 66 B8 FE 00 74 04 75 02 EB 02 EB 01 81 66 E7 64 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 }

	condition:
		for any of ( $* ) : ( $ at pe.entry_point )
}

import "pe"

rule BeRoEXEPackerv100DLLLZMABeRoFarbrausch : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 83 7C 24 08 01 0F 85 [4] 60 68 [4] 68 [4] 68 [4] E8 [4] BE [4] B9 [4] 8B F9 81 FE [4] 7F 10 AC 47 04 18 2C 02 73 F0 29 3E 03 F1 03 F9 EB E8 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PseudoSigner02ExeSmasherAnorganix : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 9C FE 03 90 60 BE 90 90 41 90 8D BE 90 10 FF FF 57 83 CD FF EB 10 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 FE 0B }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule ObsidiumV125ObsidiumSoftware : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E8 0E 00 00 00 8B 54 24 0C 83 82 B8 00 00 00 0D 33 C0 C3 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule ASPackv107bDLLAlexeySolodovnikov : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 00 00 00 00 5D [6] B8 [4] 03 C5 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule MicroJoiner17coban2k : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { BF 00 10 40 00 8D 5F 21 6A 0A 58 6A 04 59 60 57 E8 8E 00 00 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule AHTeamEPProtector03fakeVOBProtectCDFEUERRADER : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 90 [46] 90 FF E0 5F 81 EF 00 00 00 00 BE 00 00 40 00 8B 87 00 00 00 00 03 C6 57 56 8C A7 00 00 00 00 FF 10 89 87 00 00 00 00 5E 5F }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule CelsiusCrypt21Z3r0 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 89 E5 83 EC 08 C7 04 24 01 00 00 00 FF 15 84 92 44 00 E8 C8 FE FF FF 90 8D B4 26 00 00 00 00 55 89 E5 83 EC 08 C7 04 24 02 00 00 00 FF 15 84 92 44 00 E8 A8 FE FF FF 90 8D B4 26 00 00 00 00 55 8B 0D C4 92 44 00 89 E5 5D FF E1 8D 74 26 00 55 8B 0D AC 92 44 00 89 E5 5D FF E1 90 90 90 90 55 89 E5 5D E9 77 C2 00 00 90 90 90 90 90 90 90 55 89 E5 83 EC 28 8B 45 10 89 04 24 E8 3F 14 01 00 48 89 45 FC 8B 45 0C 48 89 45 F4 8D 45 F4 89 44 24 04 8D 45 FC 89 04 24 E8 12 A3 03 00 8B 00 89 45 F8 8B 45 FC 89 45 F0 C6 45 EF 01 C7 45 E8 00 00 00 00 8B 45 E8 3B 45 F8 73 39 80 7D EF 00 74 33 8B 45 F0 89 44 24 04 8B 45 10 89 04 24 E8 1C 1A 01 00 89 C1 8B 45 08 8B 55 E8 01 C2 0F B6 01 3A 02 0F 94 C0 88 45 EF 8D 45 F0 FF 08 8D 45 E8 FF 00 EB BF 83 7D F0 00 74 34 80 7D EF 00 74 2E 8B 45 F0 89 44 24 04 8B 45 10 89 04 24 E8 DD 19 01 00 89 C1 8B 45 08 8B 55 F8 01 C2 0F B6 01 3A 02 0F 94 C0 88 45 EF 8D 45 F0 FF 08 EB C6 C7 44 24 04 00 00 00 00 8B 45 10 89 04 24 E8 AE 19 01 00 89 C1 8B 45 08 8B 55 F8 01 C2 0F B6 01 3A 02 7F 0C 0F B6 45 EF 83 E0 01 88 45 E7 EB 04 C6 45 E7 00 0F B6 45 E7 88 45 EF 0F B6 45 EF C9 C3 }
		$a1 = { 55 89 E5 83 EC 28 8B 45 10 89 04 24 E8 3F 14 01 00 48 89 45 FC 8B 45 0C 48 89 45 F4 8D 45 F4 89 44 24 04 8D 45 FC 89 04 24 E8 12 A3 03 00 8B 00 89 45 F8 8B 45 FC 89 45 F0 C6 45 EF 01 C7 45 E8 00 00 00 00 8B 45 E8 3B 45 F8 73 39 80 7D EF 00 74 33 8B 45 F0 89 44 24 04 8B 45 10 89 04 24 E8 1C 1A 01 00 89 C1 8B 45 08 8B 55 E8 01 C2 0F B6 01 3A 02 0F 94 C0 88 45 EF 8D 45 F0 FF 08 8D 45 E8 FF 00 EB BF 83 7D F0 00 74 34 80 7D EF 00 74 2E 8B 45 F0 89 44 24 04 8B 45 10 89 04 24 E8 DD 19 01 00 89 C1 8B 45 08 8B 55 F8 01 C2 0F B6 01 3A 02 0F 94 C0 88 45 EF 8D 45 F0 FF 08 EB C6 C7 44 24 04 00 00 00 00 8B 45 10 89 04 24 E8 AE 19 01 00 89 C1 8B 45 08 8B 55 F8 01 C2 0F B6 01 3A 02 7F 0C 0F B6 45 EF 83 E0 01 88 45 E7 EB 04 C6 45 E7 00 0F B6 45 E7 88 45 EF 0F B6 45 EF C9 C3 }

	condition:
		$a0 at pe.entry_point or $a1
}

import "pe"

rule Armadillov260 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 6A FF 68 D0 [3] 68 34 [3] 64 A1 [4] 50 64 89 25 [4] 83 EC 58 53 56 57 89 65 E8 FF 15 68 [3] 33 D2 8A D4 89 15 84 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule Armadillov261 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 6A FF 68 28 [3] 68 E4 [3] 64 A1 [4] 50 64 89 25 [4] 83 EC 58 53 56 57 89 65 E8 FF 15 6C [3] 33 D2 8A D4 89 15 0C }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule MSLRHv032afakeASPack212emadicius : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ED FF FF FF 03 DD 81 EB 00 A0 02 EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule RatPackerGluestub : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 40 20 FF 00 00 00 00 00 00 00 ?? BE 00 60 40 00 8D BE 00 B0 FF FF }

	condition:
		$a0 at pe.entry_point
}

rule CreateInstallv200335 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 81 EC 0C 04 00 00 53 56 57 55 68 60 50 40 00 6A 01 6A 00 FF 15 D8 80 40 00 8B F0 FF 15 D4 80 40 00 3D B7 00 00 00 75 0F 56 FF 15 B8 80 40 00 6A 02 FF 15 A4 80 40 00 33 DB E8 F2 FE FF FF 68 02 7F 00 00 89 1D 94 74 40 00 53 89 1D 98 74 40 00 FF 15 E4 80 40 }

	condition:
		$a0
}

import "pe"

rule SPECb3 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 5B 53 50 45 43 5D E8 [4] 5D 8B C5 81 ED 41 24 40 ?? 2B 85 89 26 40 ?? 83 E8 0B 89 85 8D 26 40 ?? 0F B6 B5 91 26 40 ?? 8B FD }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule SPECb2 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 57 51 53 E8 [4] 5D 8B C5 81 ED [4] 2B 85 [4] 83 E8 09 89 85 [4] 0F B6 }

	condition:
		$a0 at pe.entry_point
}

rule UPXV200V290MarkusOberhumerLaszloMolnarJohnReiser : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { FF D5 8D 87 [4] 80 20 ?? 80 60 [2] 58 50 54 50 53 57 FF D5 58 61 8D 44 24 ?? 6A 00 39 C4 75 FA 83 EC 80 E9 }

	condition:
		$a0
}

import "pe"

rule PseudoSigner01MicrosoftVisualBasic5060Anorganix : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 68 [4] E8 0A 00 00 00 00 00 00 00 00 00 30 00 00 00 E9 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule UPXModifiedStubbFarbrauschConsumerConsulting : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 BE [4] 8D BE [4] 57 83 CD FF FC B2 80 31 DB A4 B3 02 E8 6D 00 00 00 73 F6 31 C9 E8 64 00 00 00 73 1C 31 C0 E8 5B 00 00 00 73 23 B3 02 41 B0 10 E8 4F 00 00 00 10 C0 73 F7 75 3F AA EB D4 E8 4D 00 00 00 29 D9 75 10 E8 42 00 00 00 EB 28 AC }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule E2CbyDoP : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { BE [2] BF [2] B9 [2] FC 57 F3 A5 C3 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule SVKProtectorv111 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 [4] 5D 81 ED 06 [3] 64 A0 23 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PCShrinkerv071 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 9C 60 BD [4] 01 AD 54 3A 40 ?? FF B5 50 3A 40 ?? 6A 40 FF 95 88 3A 40 ?? 50 50 2D [4] 89 85 }

	condition:
		$a0 at pe.entry_point
}

rule Petite21 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 66 9C 60 50 8B D8 }

	condition:
		$a0
}

import "pe"

rule BeRoEXEPackerv100DLLLZBRRBeRoFarbrausch : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 83 7C 24 08 01 0F 85 [4] 60 BE [4] BF [4] FC B2 80 33 DB A4 B3 02 E8 [4] 73 F6 33 C9 E8 [4] 73 1C 33 C0 E8 [4] 73 23 B3 02 41 B0 10 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule hmimysPackerV12hmimys : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E8 95 00 00 00 [149] 5E AD 50 AD 50 97 AD 50 AD 50 AD 50 E8 C0 01 00 00 AD 50 AD 93 87 DE B9 [4] E3 1D 8A 07 47 04 ?? 3C ?? 73 F7 8B 07 3C ?? 75 F3 B0 00 0F C8 05 [4] 2B C7 AB E2 E3 AD 85 C0 74 2B 97 56 FF 13 8B E8 AC 84 C0 75 FB 66 AD 66 85 C0 74 E9 AC 83 EE 03 84 C0 74 08 56 55 FF 53 04 AB EB E4 AD 50 55 FF 53 04 AB EB E0 C3 8B 0A 3B 4A 04 75 0A C7 42 10 01 00 00 00 0C FF C3 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule EnigmaProtector131Build20070615DllSukhovVladimirSergeNMarkin : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED 06 00 00 00 81 ED [4] E9 49 00 00 00 [40] 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 8A 84 24 28 00 00 00 80 F8 01 0F 84 07 00 00 00 B8 [4] FF E0 E9 04 00 00 00 [4] B8 [4] 03 C5 81 C0 [4] B9 [4] BA [4] 30 10 40 49 0F 85 F6 FF FF FF E9 04 00 00 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PureBasicDLLNeilHodgson : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 83 7C 24 08 01 75 ?? 8B 44 24 04 A3 [3] 10 E8 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule HPA : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E8 [2] 5E 8B D6 83 [2] 83 [2] 06 0E 1E 0E 1F 33 FF 8C D3 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule Armadillov310 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 6A FF 68 E0 97 44 00 68 20 C0 42 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF 15 4C 41 44 00 33 D2 8A D4 89 15 90 A1 44 00 8B C8 81 E1 FF 00 00 00 89 0D 8C A1 44 00 C1 E1 08 03 CA 89 0D 88 A1 44 00 C1 E8 10 A3 84 A1 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule Upack012betaDwing : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { BE 48 01 40 00 AD [3] A5 ?? C0 33 C9 [7] F3 AB [2] 0A [4] AD 50 97 51 ?? 87 F5 58 8D 54 86 5C ?? D5 72 [15] B6 5F FF C1 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule VxNcuLi1688 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 0E 1E B8 55 AA CD 21 3D 49 4C 74 ?? 0E 0E 1F 07 E8 }

	condition:
		$a0 at pe.entry_point
}

rule VProtectorvcasm : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 00 00 00 00 4B 45 52 4E 45 4C 33 32 2E 64 6C 6C 00 00 55 53 45 52 33 32 2E 64 6C 6C 00 00 47 44 49 33 32 2E 64 6C 6C 00 00 00 00 00 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 47 65 74 4D 6F 64 75 6C 65 48 61 6E 64 6C 65 41 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 53 6C 65 65 70 00 00 00 47 65 74 56 65 72 73 69 6F 6E 00 00 00 47 65 74 43 6F 6D 6D 61 6E 64 4C 69 6E 65 41 00 00 00 47 65 74 53 74 61 72 74 75 70 49 6E 66 6F 41 00 00 00 47 65 74 41 43 50 00 00 00 43 72 65 61 74 65 54 68 72 65 61 64 00 00 00 44 65 66 57 69 6E 64 6F 77 50 72 6F 63 41 00 00 00 52 65 67 69 73 74 65 72 43 6C 61 73 73 45 78 41 00 00 00 43 72 65 61 74 65 57 69 6E 64 6F 77 45 78 41 00 00 00 47 65 74 53 79 73 74 65 6D 4D 65 74 72 69 63 73 00 00 00 53 68 6F 77 57 69 6E 64 6F 77 00 00 00 47 65 74 44 43 00 00 00 52 65 6C 65 61 73 65 44 43 00 00 00 46 69 6E 64 57 69 6E 64 6F 77 41 00 00 00 47 65 74 4D 65 73 73 61 67 65 41 00 00 00 44 65 73 74 72 6F 79 57 69 6E 64 6F 77 00 00 00 53 65 74 50 69 78 65 6C }
		$a1 = { 00 00 00 00 4B 45 52 4E 45 4C 33 32 2E 64 6C 6C 00 00 55 53 45 52 33 32 2E 64 6C 6C 00 00 47 44 49 33 32 2E 64 6C 6C 00 00 00 00 00 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 47 65 74 4D 6F 64 75 6C 65 48 61 6E 64 6C 65 41 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 53 6C 65 65 70 00 00 00 47 65 74 56 65 72 73 69 6F 6E 00 00 00 47 65 74 43 6F 6D 6D 61 6E 64 4C 69 6E 65 41 00 00 00 47 65 74 53 74 61 72 74 75 70 49 6E 66 6F 41 00 00 00 47 65 74 41 43 50 00 00 00 43 72 65 61 74 65 54 68 72 65 61 64 00 00 00 44 65 66 57 69 6E 64 6F 77 50 72 6F 63 41 00 00 00 52 65 67 69 73 74 65 72 43 6C 61 73 73 45 78 41 00 00 00 43 72 65 61 74 65 57 69 6E 64 6F 77 45 78 41 00 00 00 47 65 74 53 79 73 74 65 6D 4D 65 74 72 69 63 73 00 00 00 53 68 6F 77 57 69 6E 64 6F 77 00 00 00 47 65 74 44 43 00 00 00 52 65 6C 65 61 73 65 44 43 00 00 00 46 69 6E 64 57 69 6E 64 6F 77 41 00 00 00 47 65 74 4D 65 73 73 61 67 65 41 00 00 00 44 65 73 74 72 6F 79 57 69 6E 64 6F 77 00 00 00 53 65 74 50 69 78 65 6C 00 00 00 00 }
		$a2 = { 00 00 00 00 55 73 65 72 33 32 2E 64 6C 6C 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 47 64 69 33 32 2E 64 6C 6C 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 4B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 08 00 44 65 66 57 69 6E 64 6F 77 50 72 6F 63 41 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 08 00 52 65 67 69 73 74 65 72 43 6C 61 73 73 45 78 41 00 00 00 00 00 00 00 00 00 00 00 00 00 00 08 00 43 72 65 61 74 65 57 69 6E 64 6F 77 45 78 41 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 08 00 47 65 74 53 79 73 74 65 6D 4D 65 74 72 69 63 73 00 00 00 00 00 00 00 00 00 00 00 00 00 00 08 00 53 68 6F 77 57 69 6E 64 6F 77 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 08 00 47 65 74 44 43 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 08 00 52 65 6C 65 61 73 65 44 43 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 08 00 46 69 6E 64 57 69 6E 64 6F 77 41 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 47 65 74 4D 65 73 73 61 67 65 41 00 }

	condition:
		$a0 or $a1 or $a2
}

rule XPackv142 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 72 ?? C3 8B DE 83 [2] C1 [2] 8C D8 03 C3 8E D8 8B DF 83 [2] C1 [2] 8C C0 03 C3 8E C0 C3 }

	condition:
		$a0
}

import "pe"

rule W32JeefoPEFileInfector : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 89 E5 83 EC 08 83 C4 F4 6A 02 A1 C8 [3] FF D0 E8 [4] C9 C3 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule ExeSplitter13SplitCryptMethodBillPrisonerTPOC : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 15 10 05 23 14 56 57 57 48 12 0B 16 66 66 66 66 66 66 66 66 66 02 C7 56 66 66 66 ED 26 6A ED 26 6A ED 66 E3 A6 69 E2 39 64 66 66 ED 2E 56 E6 5F 0D 12 61 E6 5F 2D 12 64 8D 81 E6 1F 6A 55 12 64 8D B9 ED 26 7E A5 33 ED 8A 8D 69 21 03 12 36 14 09 05 27 02 02 14 03 15 15 27 ED 2B 6A ED 13 6E ED B8 65 10 5A EB 10 7E EB 10 06 ED 50 65 95 30 ED 10 46 65 95 55 B4 ED A0 ED 50 65 95 37 ED 2B 6A EB DF AB 76 26 66 3F DF 68 66 66 66 9A 95 C0 6D AF 13 64 }
		$a1 = { E8 00 00 00 00 5D 81 ED 05 10 40 00 B9 [4] 8D 85 1D 10 40 00 80 30 66 40 E2 FA 8F 98 67 66 66 [7] 66 }

	condition:
		$a0 or $a1 at pe.entry_point
}

import "pe"

rule AntiDote12BetaDemoSISTeam : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 68 69 D6 00 00 E8 C6 FD FF FF 68 69 D6 00 00 E8 BC FD FF FF 83 C4 08 E8 A4 FF FF FF 84 C0 74 2F 68 04 01 00 00 68 B0 21 60 00 6A 00 FF 15 08 10 60 00 E8 29 FF FF FF 50 68 88 10 60 00 68 78 10 60 00 68 B0 21 60 00 E8 A4 FD FF FF 83 C4 10 33 C0 C2 10 00 90 90 90 90 90 90 90 90 90 90 90 90 8B 4C 24 08 56 8B 74 24 08 33 D2 8B C6 F7 F1 8B C6 85 D2 74 08 33 D2 F7 F1 40 0F AF C1 5E C3 90 8B 44 24 04 53 55 56 8B 48 3C 57 03 C8 33 D2 8B 79 54 8B 71 38 8B C7 F7 F6 85 D2 74 0C 8B C7 33 D2 F7 F6 8B F8 47 0F AF FE 33 C0 33 DB 66 8B 41 14 8D 54 08 18 33 C0 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule ASPackv211bAlexeySolodovnikov : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 02 00 00 00 EB 09 5D 55 81 ED 39 39 44 00 C3 E9 3D 04 00 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule EXECryptor224StrongbitSoftCompleteDevelopmenth1 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E8 F7 FE FF FF 05 [2] 00 00 FF E0 E8 EB FE FF FF 05 [2] 00 00 FF E0 E8 04 00 00 00 FF FF FF FF 5E C3 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule EXECryptor224StrongbitSoftCompleteDevelopmenth2 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E8 F7 FE FF FF 05 [2] 00 00 FF E0 E8 EB FE FF FF 05 [2] 00 00 FF E0 E8 ?? 00 00 00 }

	condition:
		$a0 at pe.entry_point
}

rule EXECryptor224StrongbitSoftCompleteDevelopmenth3 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 00 00 00 00 00 47 65 74 4D 6F 64 75 6C 65 48 61 6E 64 6C 65 41 00 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 00 00 00 45 78 69 74 50 72 6F 63 65 73 73 }

	condition:
		$a0
}

import "pe"

rule ProActivateV10XTurboPowerSoftwareCompany : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC B9 0E 00 00 00 6A 00 6A 00 49 75 F9 51 53 56 57 B8 [4] 90 90 90 90 90 33 C0 55 68 [4] 64 FF 30 64 89 20 A1 [4] 83 C0 05 A3 [4] C7 05 [4] 0D 00 00 00 E8 85 E2 FF FF 81 3D [4] 21 7E 7E 40 75 7A 81 3D [4] 43 52 43 33 75 6E 81 3D [4] 32 40 7E 7E 75 62 81 3D [4] 21 7E 7E 40 75 56 81 3D [4] 43 52 43 33 75 4A 81 3D [4] 32 40 7E 7E 75 3E 81 3D [4] 21 7E 7E 40 75 32 81 3D [4] 43 52 43 33 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PackMasterv10 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 01 00 00 00 E8 83 C4 04 E8 01 00 00 00 E9 5D 81 ED D3 22 40 00 E8 04 02 00 00 E8 EB 08 EB 02 CD 20 FF 24 24 9A 66 BE 47 46 }
		$a1 = { 60 E8 01 [3] E8 83 C4 04 E8 01 [3] E9 5D 81 ED D3 22 40 ?? E8 04 02 [2] E8 EB 08 EB 02 CD 20 FF 24 24 9A 66 BE 47 46 }

	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point
}

import "pe"

rule DBPEv153 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 9C 55 57 56 52 51 53 9C FA E8 [4] 5D 81 ED 5B 53 40 ?? B0 ?? E8 [4] 5E 83 C6 11 B9 27 [3] 30 06 46 49 75 FA }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule FreeJoiner152Stubengine16GlOFF : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E8 46 FD FF FF 50 E8 0C 00 00 00 FF 25 08 20 40 00 FF 25 0C 20 40 00 FF 25 10 20 40 00 FF 25 14 20 40 00 FF 25 18 20 40 00 FF 25 1C 20 40 00 FF 25 20 20 40 00 FF 25 24 20 40 00 FF 25 28 20 40 00 FF 25 00 20 40 00 }

	condition:
		$a0 at pe.entry_point
}

rule ASProtectv12AlexeySolodovnikovh1 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 90 60 E8 1B 00 00 00 E9 FC 8D B5 0F 06 00 00 8B FE B9 97 00 00 00 AD 35 78 56 34 12 AB 49 75 F6 EB 04 5D 45 55 C3 E9 [3] 00 }

	condition:
		$a0
}

import "pe"

rule FSGv110EngdulekxtBorlandDelphiMicrosoftVisualCx : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 1B DB E8 02 00 00 00 1A 0D 5B 68 80 [2] 00 E8 01 00 00 00 EA 5A 58 EB 02 CD 20 68 F4 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PENightMare2Beta : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E9 [4] EF 40 03 A7 07 8F 07 1C 37 5D 43 A7 04 B9 2C 3A }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule MinGWGCC3x : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 89 E5 83 EC 08 C7 04 24 ?? 00 00 00 FF 15 [4] E8 [2] FF FF [8] 55 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PIRITv15 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { B4 4D CD 21 E8 [2] FD E8 [2] B4 51 CD 21 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule Reg2Exe224byJanVorel : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 6A 00 E8 CF 20 00 00 A3 F4 45 40 00 E8 CB 20 00 00 6A 0A 50 6A 00 FF 35 F4 45 40 00 E8 07 00 00 00 50 E8 BB 20 00 00 CC 68 48 00 00 00 68 00 00 00 00 68 F8 45 40 00 E8 06 19 00 00 83 C4 0C 8B 44 24 04 A3 FC 45 40 00 68 00 00 00 00 68 A0 0F 00 00 68 00 00 00 00 E8 8C 20 00 00 A3 F8 45 40 00 E8 02 20 00 00 E8 32 1D 00 00 E8 20 19 00 00 E8 A3 16 00 00 68 01 00 00 00 68 38 46 40 00 68 00 00 00 00 8B 15 38 46 40 00 E8 71 4F 00 00 B8 00 00 10 00 BB 01 00 00 00 E8 82 4F 00 00 FF 35 48 41 40 00 B8 00 01 00 00 E8 9D 15 00 00 8D 0D 1C 46 40 00 5A E8 82 16 00 00 68 00 01 00 00 FF 35 1C 46 40 00 E8 24 20 00 00 A3 24 46 40 00 FF 35 48 41 40 00 FF 35 24 46 40 00 FF 35 1C 46 40 00 E8 DC 10 00 00 8D 0D 14 46 40 00 5A E8 4A 16 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule SVKProtectorv13xEngPavolCerven : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED 06 00 00 00 EB 05 B8 [2] 42 00 64 A0 23 00 00 00 EB 03 C7 84 E8 84 C0 EB 03 C7 84 E9 75 67 B9 49 00 00 00 8D B5 C5 02 00 00 56 80 06 44 46 E2 FA 8B 8D C1 02 00 00 5E 55 51 6A 00 56 FF 95 0C 61 00 00 59 5D 40 85 C0 75 3C 80 3E }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule ThinstallEmbedded2609Jitit : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E8 00 00 00 00 58 BB AD 19 00 00 2B C3 50 68 [4] 68 B0 1C 00 00 68 80 00 00 00 E8 35 FF FF FF E9 99 FF FF FF 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule UPXcrypterarchphaseNWC : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { BF [3] 00 81 FF [3] 00 74 10 81 2F ?? 00 00 00 83 C7 04 BB 05 [2] 00 FF E3 BE [3] 00 FF E6 00 00 00 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule StarForceProtectionDriverProtectionTechnology : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 57 68 ?? 0D 01 00 68 00 [2] 00 E8 50 ?? FF FF 68 [3] 00 68 [3] 00 68 [3] 00 68 [3] 00 68 [3] 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule FishPEV10Xhellfish : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 [4] C3 90 09 00 00 00 2C 00 00 00 [4] C4 03 00 00 BC A0 00 00 00 40 01 00 [4] 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 99 00 00 00 00 8A 00 00 00 10 00 00 [2] 00 00 [4] 00 00 02 00 00 00 A0 00 00 18 01 00 00 [4] 00 00 0C 00 00 00 B0 00 00 38 0A 00 00 [4] 00 00 00 00 00 00 C0 00 00 40 39 00 00 [4] 00 00 08 00 00 00 00 01 00 C8 06 00 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PECrypter : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 00 00 00 00 5D EB 26 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule tElockv051 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { C1 EE 00 66 8B C9 EB 01 EB 60 EB 01 EB 9C E8 00 00 00 00 5E 83 C6 5E 8B FE 68 79 01 59 EB 01 EB AC 54 E8 03 5C EB 08 }

	condition:
		$a0 at pe.entry_point
}

rule LY_WGKXwwwszleyucom : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 4D 79 46 75 6E 00 62 73 }

	condition:
		$a0
}

import "pe"

rule ASProtect13321RegisteredAlexeySolodovnikov : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 68 01 [3] E8 01 00 00 00 C3 C3 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule RLPackV111ap0x : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 4A 02 00 00 8D 9D 11 01 00 00 33 FF EB 0F FF 74 37 04 FF 34 37 FF D3 83 C4 08 83 C7 08 83 3C 37 00 75 EB }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule FSGv110EngdulekxtMicrosoftVisualC4xLCCWin321x : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 2C 71 1B CA EB 01 2A EB 01 65 8D 35 80 [2] 00 80 C9 84 80 C9 68 BB F4 00 00 00 EB 01 EB }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule dePACKdeNULL : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB 01 DD 60 68 00 [3] 68 [2] 00 00 E8 ?? 00 00 00 }
		$a1 = { EB 01 DD 60 68 00 [3] 68 [3] 00 E8 ?? 00 00 00 [128] D2 }

	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point
}

import "pe"

rule EXECryptorv1401 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E8 24 00 00 00 8B 4C 24 0C C7 01 17 00 01 00 C7 81 B8 00 00 00 00 [2] 00 31 C0 89 41 14 89 41 18 80 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule MSLRHv032afakePELockNT204emadicius : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB 03 CD 20 C7 1E EB 03 CD 20 EA 9C EB 02 EB 01 EB 01 EB 60 EB 03 CD 20 EB EB 01 EB E8 03 00 00 00 E9 EB 04 58 40 50 C3 EB 03 CD 20 EB EB 03 CD 20 03 61 9D 83 C4 04 EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PELockNTv203 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB 02 C7 85 1E EB 03 CD 20 C7 9C EB 02 69 B1 60 EB 02 EB 01 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule Reg2Exe220221byJanVorel : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 6A 00 E8 7D 12 00 00 A3 A0 44 40 00 E8 79 12 00 00 6A 0A 50 6A 00 FF 35 A0 44 40 00 E8 0F 00 00 00 50 E8 69 12 00 00 CC CC CC CC CC CC CC CC CC 68 2C 02 00 00 68 00 00 00 00 68 B0 44 40 00 E8 3A 12 00 00 83 C4 0C 8B 44 24 04 A3 B8 44 40 00 68 00 00 00 00 68 A0 0F 00 00 68 00 00 00 00 E8 32 12 00 00 A3 B0 44 40 00 68 F4 01 00 00 68 BC 44 40 00 FF 35 B8 44 40 00 E8 1E 12 00 00 B8 BC 44 40 00 89 C1 8A 30 40 80 FE 5C 75 02 89 C1 80 FE 00 75 F1 C6 01 00 E8 EC 18 00 00 E8 28 16 00 00 E8 4A 12 00 00 68 00 FA 00 00 68 08 00 00 00 FF 35 B0 44 40 00 E8 E7 11 00 00 A3 B4 44 40 00 8B 15 D4 46 40 00 E8 65 0A 00 00 BB 00 00 10 00 B8 01 00 00 00 E8 72 0A 00 00 74 09 C7 00 01 00 00 00 83 C0 04 A3 D4 46 40 00 FF 35 B4 44 40 00 E8 26 05 00 00 8D 0D B8 46 40 00 5A E8 CF 0F 00 00 FF 35 B4 44 40 00 FF 35 B8 46 40 00 E8 EE 06 00 00 8D 0D B4 46 40 00 5A E8 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PELockNTv201 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB 03 CD 20 EB EB 01 EB 1E EB 01 EB EB 02 CD 20 9C EB 03 CD }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PELockNTv204 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB ?? CD [5] CD [5] EB ?? EB ?? EB ?? EB ?? CD [5] E8 [4] E9 [4] 50 C3 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule UPXFreakv01BorlandDelphiHMX0101 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { BE [4] 83 C6 01 FF E6 00 00 00 [3] 00 03 00 00 00 [4] 00 10 00 00 00 00 [4] 00 00 ?? F6 ?? 00 B2 4F 45 00 ?? F9 ?? 00 EF 4F 45 00 ?? F6 ?? 00 8C D1 42 00 ?? 56 ?? 00 [3] 00 [3] 00 [3] 00 ?? 24 ?? 00 [3] 00 }
		$a1 = { BE [4] 83 C6 01 FF E6 00 00 00 [3] 00 03 00 00 00 [4] 00 10 00 00 00 00 [4] 00 00 ?? F6 ?? 00 B2 4F 45 00 ?? F9 ?? 00 EF 4F 45 00 ?? F6 ?? 00 8C D1 42 00 ?? 56 ?? 00 [3] 00 [3] 00 [3] 00 ?? 24 ?? 00 [3] 00 34 50 45 00 [3] 00 FF FF 00 00 ?? 24 ?? 00 ?? 24 ?? 00 [3] 00 40 00 00 C0 00 00 [4] 00 00 ?? 00 00 00 ?? 1E ?? 00 ?? F7 ?? 00 A6 4E 43 00 ?? 56 ?? 00 AD D1 42 00 ?? F7 ?? 00 A1 D2 42 00 ?? 56 ?? 00 0B 4D 43 00 ?? F7 ?? 00 ?? F7 ?? 00 ?? 56 ?? 00 [5] 00 00 00 [7] 77 [3] 00 [3] 00 [3] 77 [2] 00 00 [3] 00 [6] 00 00 [3] 00 [11] 00 [4] 00 00 00 00 [3] 00 }

	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point
}

import "pe"

rule Obsidium13017Obsidiumsoftware : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB 02 [2] E8 28 00 00 00 EB 04 [4] EB 01 ?? 8B 54 24 0C EB 01 ?? 83 82 B8 00 00 00 25 EB 02 [2] 33 C0 EB 03 [3] C3 EB 03 [3] EB 02 [2] 64 67 FF 36 00 00 EB 01 ?? 64 67 89 26 00 00 EB 03 [3] EB 04 [4] 50 EB 04 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule Petite22c199899IanLuck : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 68 [4] 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 66 9C 60 50 68 00 00 [2] 8B 3C 24 8B 30 66 81 C7 80 07 8D 74 06 08 89 38 8B 5E 10 50 56 6A 02 68 80 08 00 00 57 6A ?? 6A 06 56 6A 04 68 80 08 00 00 57 FF D3 83 EE 08 59 F3 A5 59 66 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PluginToExev101BoBBobSoft : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E8 00 00 00 00 29 C0 5D 81 ED C6 41 40 00 50 8F 85 71 40 40 00 50 FF 95 A5 41 40 00 89 85 6D 40 40 00 FF 95 A1 41 40 00 50 FF 95 B5 41 40 00 80 38 00 74 16 8A 08 80 F9 22 75 07 50 FF 95 B9 41 40 00 89 85 75 40 40 00 EB 6C 6A 01 8F 85 71 40 40 00 6A 58 6A 40 FF 95 A9 41 40 00 89 85 69 40 40 00 89 C7 68 00 08 00 00 6A 40 FF 95 A9 41 40 00 89 47 1C C7 07 58 00 00 00 C7 47 20 00 08 00 00 C7 47 18 01 00 00 00 C7 47 34 04 10 88 00 8D 8D B9 40 40 00 89 4F 0C 8D 8D DB 40 40 00 89 4F 30 FF B5 69 40 40 00 FF 95 95 41 40 00 FF 77 1C 8F 85 75 40 40 00 8B 9D 6D 40 40 00 60 6A 00 6A 01 53 81 C3 [3] 00 FF D3 61 6A 00 68 44 69 45 50 FF B5 75 40 40 00 6A 00 81 C3 [2] 00 00 FF D3 83 C4 10 83 BD 71 40 40 00 00 74 10 FF 77 1C FF 95 AD 41 40 00 57 FF 95 AD 41 40 00 6A 00 FF 95 9D 41 40 00 }

	condition:
		$a0 at pe.entry_point
}

rule Enigmaprotector110unregistered : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 72 80 72 88 72 8C 72 90 72 94 72 98 72 9C 72 A0 72 A4 59 A8 B0 5C E8 39 D5 39 E4 39 F1 31 F9 5C 3D 58 CA 5F 56 B1 2D 20 7A 2E 30 16 32 72 2B 72 36 1C A5 33 A9 9C AD 9C B1 9C B5 9C B9 9C BD 9C C1 9C C5 9C C9 9C CD 9C D1 9C D5 9C D9 9C DD 9C E1 9C E5 89 }
		$a1 = { 60 72 80 72 88 72 8C 72 90 72 94 72 98 72 9C 72 A0 72 A4 59 A8 B0 5C E8 39 D5 39 E4 39 F1 31 F9 5C 3D 58 CA 5F 56 B1 2D 20 7A 2E 30 16 32 72 2B 72 36 1C A5 33 A9 9C AD 9C B1 9C B5 9C B9 9C BD 9C C1 9C C5 9C C9 9C CD 9C D1 9C D5 9C D9 9C DD 9C E1 9C E5 89 E9 51 0B C4 80 BC 7E 35 09 37 E7 C9 3D C9 45 C9 4D 74 92 BA E4 E9 24 6B DF 3E 0E 38 0C 49 10 27 80 51 A1 8E 3A A3 C8 AE 3B 1C 35 }

	condition:
		$a0 or $a1
}

import "pe"

rule Obsidium1341ObsidiumSoftware : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB 01 ?? E8 2A 00 00 00 EB 04 [4] EB 02 [2] 8B 54 24 0C EB 03 [3] 83 82 B8 00 00 00 21 EB 02 [2] 33 C0 EB 03 [3] C3 EB 02 [2] EB 01 ?? 64 67 FF 36 00 00 EB 01 ?? 64 67 89 26 00 00 EB 02 [2] EB 03 [3] 50 EB 04 [4] 33 C0 EB 02 [2] 8B 00 EB 04 [4] C3 EB 02 [2] E9 FA 00 00 00 EB 02 [2] E8 D5 FF FF FF EB 01 ?? EB 01 ?? 58 EB 03 [3] EB 04 [4] 64 67 8F 06 00 00 EB 04 [4] 83 C4 04 EB 02 [2] E8 C3 27 00 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule WebCopsDLLLINKDataSecurity : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { A8 BE 58 DC D6 CC C4 63 4A 0F E0 02 BB CE F3 5C 50 23 FB 62 E7 3D 2B }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PseudoSigner01PackMaster10PEXCloneAnorganix : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 01 01 00 00 E8 83 C4 04 E8 01 90 90 90 E9 5D 81 ED D3 22 40 90 E8 04 02 90 90 E8 EB 08 EB 02 CD 20 FF 24 24 9A 66 BE 47 46 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 }

	condition:
		$a0 at pe.entry_point
}

rule Upackv037v038BetaStripbaserelocationtableOptionDwing : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 53 18 33 C0 55 40 51 D3 E0 8B EA 91 FF 56 4C 33 }

	condition:
		$a0
}

import "pe"

rule AHTeamEPProtector03fakeSVKP13xFEUERRADER : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 90 [46] 90 FF E0 60 E8 00 00 00 00 5D 81 ED 06 00 00 00 EB 05 B8 00 00 00 00 64 A0 23 00 00 00 EB 03 C7 84 E8 84 C0 EB 03 C7 84 E9 75 67 B9 49 00 00 00 8D B5 C5 02 00 00 56 80 06 44 46 E2 FA 8B 8D C1 02 00 00 5E 55 51 6A 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule InstallShieldCustom : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 83 EC 44 56 FF 15 [2] 41 00 8B F0 85 F6 75 08 6A FF FF 15 [2] 41 00 8A 06 57 8B 3D [2] 41 00 3C 22 75 1B 56 FF D7 8B F0 8A 06 3C 22 74 04 84 C0 75 F1 80 3E 22 75 15 56 FF D7 8B }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule Petitevafterv14 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { B8 [4] 66 9C 60 50 8D [5] 68 [4] 83 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule ExeToolsv21EncruptorbyDISMEMBER : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E8 [2] 5D 83 [2] 1E 8C DA 83 [2] 8E DA 8E C2 BB [2] BA [2] 85 D2 74 }

	condition:
		$a0 at pe.entry_point
}

rule NTkrnlSecureSuiteNTkrnlteam : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 34 10 00 00 28 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 41 10 00 00 50 10 00 00 00 00 00 00 4B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 }

	condition:
		$a0
}

import "pe"

rule PESpinv0b : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 72 C8 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 26 E8 01 00 00 00 EA 5A 33 C9 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule VXTibsZhelatinStormWormvariant : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { FF 74 24 1C 58 8D 80 [2] 77 04 50 68 62 34 35 04 E8 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule MSLRHv032afakePEX099emadicius : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 01 00 00 00 E8 83 C4 04 E8 01 00 00 00 E9 5D 81 ED FF 22 40 00 61 EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 2B 04 24 74 04 75 02 EB 02 EB 01 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule NSPack3xLiuXingPing : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 9C 60 E8 00 00 00 00 5D 83 ED 07 8D 85 [2] FF FF ?? 38 01 0F 84 ?? 02 00 00 ?? 00 01 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PECompactv25RetailBitsumTechnologies : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { B8 [3] 01 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 50 45 43 6F 6D 70 61 63 74 32 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule WARNINGTROJANXiaoHui : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 9C E8 00 00 00 00 5D B8 ?? 85 40 00 2D ?? 85 40 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule NFOv10 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 8D 50 12 2B C9 B1 1E 8A 02 34 77 88 02 42 E2 F7 C8 8C }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PMODEWv112116121133DOSextender : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { FC 16 07 BF [2] 8B F7 57 B9 [2] F3 A5 06 1E 07 1F 5F BE [2] 06 0E A4 }

	condition:
		$a0 at pe.entry_point
}

rule AaseCrypterbysantasdad : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 83 C4 F0 53 B8 A0 3E 00 10 E8 93 DE FF FF 68 F8 42 00 10 E8 79 DF FF FF 68 00 43 00 10 68 0C 43 00 10 E8 42 DF FF FF 50 E8 44 DF FF FF A3 98 66 00 10 83 3D 98 66 00 10 00 75 13 6A 00 68 18 43 00 10 68 1C 43 00 10 6A 00 E8 4B DF FF FF 68 2C 43 00 10 68 0C 43 [4] DF FF FF 50 E8 0E DF FF FF A3 94 66 00 10 83 3D 94 66 00 10 00 75 13 6A 00 68 18 43 00 10 68 38 43 00 10 6A 00 E8 15 DF FF FF 68 48 43 00 10 68 0C 43 00 10 E8 D6 DE FF FF 50 E8 D8 DE FF FF A3 A0 66 00 10 83 3D A0 66 00 10 00 75 13 6A 00 68 18 43 00 10 68 58 43 00 10 6A 00 E8 DF DE FF FF 68 6C 43 00 10 68 0C 43 00 10 E8 A0 DE FF FF 50 E8 A2 DE FF FF }

	condition:
		$a0
}

rule aPackv098bJibz : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 93 07 1F 05 [2] 8E D0 BC [2] EA }

	condition:
		$a0
}

rule UPackv011Dwing : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { BE 48 01 40 00 AD 8B F8 95 A5 33 C0 33 C9 AB 48 AB F7 D8 B1 04 F3 AB C1 E0 0A B5 1C F3 AB AD 50 97 51 AD 87 F5 58 8D 54 86 5C FF D5 72 5A 2C 03 73 02 B0 00 3C 07 72 02 2C 03 50 0F B6 5F FF C1 E3 03 B3 00 8D 1C 5B 8D 9C 9E 0C 10 00 00 B0 01 67 E3 29 8B D7 }

	condition:
		$a0
}

rule NsPacKNetLiuXingPing : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 56 69 72 74 75 61 6C 50 72 6F 74 65 63 74 00 00 BB 01 47 65 74 53 79 73 74 65 6D 49 6E 66 6F 00 4B 45 52 4E 45 4C 33 32 2E 64 6C 6C 00 00 5E 00 5F 43 6F 72 [3] 4D 61 69 6E 00 6D 73 63 6F 72 65 65 2E 64 6C 6C }

	condition:
		$a0
}

import "pe"

rule PseudoSigner02PENightMare2BetaAnorganix : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E9 10 00 00 00 EF 40 03 A7 07 8F 07 1C 37 5D 43 A7 04 B9 2C 3A }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PseudoSigner01MicrosoftVisualC60DebugVersionAnorganix : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 51 90 90 90 01 01 90 90 90 90 68 [4] 90 90 90 90 90 90 90 90 90 90 90 90 00 01 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 00 01 90 90 90 90 90 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule DJoinv07publicRC4encryptiondrmist : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { C6 05 [2] 40 00 00 C6 05 [2] 40 00 00 [8] 00 [4] 00 [5] 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule UPXv103v104 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 8A 07 72 EB B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 ?? 75 ?? 8B 1E 83 EE FC }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PEDiminisherV01Teraphy : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 53 51 52 56 57 55 E8 00 00 00 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule WWPACKv305c4ExtrPasswcheckVirshield : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 03 05 C0 1A B8 [2] 8C CA 03 D0 8C C9 81 C1 [2] 51 B9 [2] 51 06 06 B1 ?? 51 8C D3 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule ExeGuarderv18Exeiconcom : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 83 C4 D0 53 56 57 8D 75 FC 8B 44 24 30 25 00 00 FF FF 81 38 4D 5A 90 00 74 07 2D 00 10 00 00 EB F1 89 45 FC E8 C8 FF FF FF 2D B2 04 00 00 89 45 F4 8B 06 8B 40 3C 03 06 8B 40 78 03 06 8B C8 8B 51 20 03 16 8B 59 24 03 1E 89 5D F0 8B 59 1C 03 1E 89 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule codeCrypter031Tibbar : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 50 58 53 5B 90 BB [3] 00 FF E3 90 CC CC CC 55 8B EC 5D C3 CC CC CC CC CC CC CC CC CC CC CC }

	condition:
		$a0 at pe.entry_point
}

rule RLPv073betaap0x : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 8B DD E8 00 00 00 00 5D 95 32 C0 95 89 9D 80 00 00 00 B8 42 31 40 00 BB 41 30 40 00 2B C3 03 C5 33 D2 8A 10 40 B9 [2] 00 00 8B F9 30 10 8A 10 40 49 75 F8 64 EF 86 3D 30 00 00 0F B9 FF 4B 89 52 5C 4C BD 77 C2 0C CE 88 4E 2D E8 00 00 00 5D 0D DB 5E 56 }

	condition:
		$a0
}

import "pe"

rule PEnguinCryptv10 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { B8 93 [2] 00 55 50 67 64 FF 36 00 00 67 64 89 26 00 00 BD 4B 48 43 42 B8 04 00 00 00 CC 3C 04 75 04 90 90 C3 90 67 64 8F 06 00 00 58 5D BB 00 00 40 00 33 C9 33 C0 }

	condition:
		$a0 at pe.entry_point
}

rule MetrowerksCodeWarriorDLLv20 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 89 E5 53 56 57 8B 75 0C 8B 5D 10 83 FE 01 74 05 83 FE 02 75 12 53 56 FF 75 08 E8 6E FF FF FF 09 C0 75 04 31 C0 EB 21 53 56 FF 75 08 E8 [4] 89 C7 09 F6 74 05 83 FE 03 75 0A 53 56 FF 75 08 E8 47 FF FF FF 89 F8 8D 65 F4 5F 5E 5B 5D C2 0C 00 C9 }

	condition:
		$a0
}

import "pe"

rule PECrc32088ZhouJinYu : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED B6 A4 45 00 8D BD B0 A4 45 00 81 EF 82 00 00 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PECompactv123b3v1241 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB 06 68 [4] C3 9C 60 E8 02 [3] 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 70 40 ?? 87 DD 8B 85 A6 70 40 ?? 01 85 03 70 40 ?? 66 C7 85 70 40 90 ?? 90 01 85 9E 70 40 BB ?? D2 08 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule Noodlecrypt2rsc : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB 01 9A E8 76 00 00 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule RLPack120BasicEditionLZMAAp0x : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 83 7C 24 28 01 75 0C 8B 44 24 24 89 85 9C 0C 00 00 EB 0C 8B 85 98 0C 00 00 89 85 9C 0C 00 00 8D B5 C4 0C 00 00 8D 9D 82 04 00 00 33 FF 6A 40 68 00 10 00 00 68 00 20 0C 00 6A 00 FF 95 2D 0C 00 00 89 85 94 0C 00 00 E8 59 01 00 00 EB 20 60 8B 85 9C 0C 00 00 FF B5 94 0C 00 00 FF 34 37 01 04 24 FF 74 37 04 01 04 24 FF D3 61 83 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PseudoSigner01PENightMare2BetaAnorganix : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E9 10 00 00 00 EF 40 03 A7 07 8F 07 1C 37 5D 43 A7 04 B9 2C 3A E9 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule AHTeamEPProtector03fakeXtremeProtector105FEUERRADER : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 90 [46] 90 FF E0 E8 00 00 00 00 5D 81 00 00 00 00 00 6A 45 E8 A3 00 00 00 68 00 00 00 00 E8 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule RLPackv118BasicDLLLZMAAp0x : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 80 7C 24 08 01 0F 85 [4] 60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 21 0B 00 00 8D 9D FF 02 00 00 33 FF E8 9F 01 00 00 6A 40 68 00 10 00 00 68 00 20 0C 00 6A 00 FF 95 AA 0A 00 00 89 85 F9 0A 00 00 EB 14 60 FF B5 F9 0A }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule CrypKeyv5v6 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E8 [4] 58 83 E8 05 50 5F 57 8B F7 81 EF [4] 83 C6 39 BA [4] 8B DF B9 0B [3] 8B 06 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule InnoSetupModulev109a : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 83 C4 C0 53 56 57 33 C0 89 45 F0 89 45 C4 89 45 C0 E8 A7 7F FF FF E8 FA 92 FF FF E8 F1 B3 FF FF 33 C0 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule ObsidiumV1300ObsidiumSoftware : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB 04 [4] E8 29 00 00 00 }
		$a1 = { EB 04 [4] E8 ?? 00 00 00 }

	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point
}

import "pe"

rule PCryptv351 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 50 43 52 59 50 54 FF 76 33 2E 35 31 00 E9 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule ThinstallEmbedded2312Jitit : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 6A 00 FF 15 [4] E8 D4 F8 FF FF E9 E9 AD FF FF FF 8B C1 8B 4C 24 04 89 88 29 04 00 00 C7 40 0C 01 00 00 00 0F B6 49 01 D1 E9 89 48 10 C7 40 14 80 00 00 00 C2 04 00 8B 44 24 04 C7 41 0C 01 00 00 00 89 81 29 04 00 00 0F B6 40 01 D1 E8 89 41 10 C7 41 14 80 00 00 00 C2 04 00 55 8B EC 53 56 57 33 C0 33 FF 39 45 0C 8B F1 76 0C 8B 4D 08 03 3C 81 40 3B 45 0C 72 F4 8B CE E8 43 00 00 00 8B 46 14 33 D2 F7 F7 8B 5E 10 33 D2 8B F8 8B C3 F7 F7 89 7E 18 89 45 0C 33 C0 33 C9 8B 55 08 03 0C 82 40 39 4D 0C 73 F4 48 8B 14 82 2B CA 0F AF CF 2B D9 0F AF FA 89 7E 14 89 5E 10 5F 5E 5B 5D C2 08 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule WWPACKv305c4Extractable : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 03 05 00 1A B8 [2] 8C CA 03 D0 8C C9 81 C1 [2] 51 B9 [2] 51 06 06 B1 ?? 51 8C D3 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule RLPackAp0x : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 2C 0A 00 00 8D 9D 22 02 00 00 33 FF E8 83 01 00 00 6A 40 68 00 10 00 00 68 00 20 0C 00 6A 00 FF 95 CD 09 00 00 89 85 14 0A 00 00 EB 14 60 FF B5 14 0A }
		$a1 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 5A 0A 00 00 8D 9D 40 02 00 00 33 FF E8 83 01 00 00 6A 40 68 00 10 00 00 68 00 20 0C 00 6A 00 FF 95 EB 09 00 00 89 85 3A 0A 00 00 EB 14 60 FF B5 3A 0A }
		$a2 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 EB 03 0C 00 00 EB 03 0C 00 00 8D B5 CB 22 00 00 8D 9D F0 02 00 00 33 FF E8 47 02 00 00 EB 03 15 00 00 6A 40 68 00 10 00 00 68 00 20 0C 00 6A 00 FF 95 9B 0A }
		$a3 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 2C 0A 00 00 8D 9D 22 02 00 00 33 FF E8 [4] 6A 40 68 [4] 68 [4] 6A 00 FF 95 CD 09 00 00 89 85 [4] EB 14 60 FF B5 14 0A }
		$a4 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 5A 0A 00 00 8D 9D 40 02 00 00 33 FF E8 [4] 6A 40 68 [4] 68 [4] 6A 00 FF 95 EB 09 00 00 89 85 [4] EB 14 60 FF B5 3A 0A }
		$a5 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 EB 03 [3] EB 03 [3] 8D B5 CB 22 00 00 8D 9D F0 02 00 00 33 FF E8 [4] EB 03 [3] 6A 40 68 [4] 68 [4] 6A 00 FF 95 9B 0A }

	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point or $a2 at pe.entry_point or $a3 at pe.entry_point or $a4 at pe.entry_point or $a5 at pe.entry_point
}

import "pe"

rule PseudoSigner02VOBProtectCD5Anorganix : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 36 3E 26 8A C0 60 E8 00 00 00 00 }

	condition:
		$a0 at pe.entry_point
}

rule PESpinv04x : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB 01 68 60 E8 00 00 00 00 8B }

	condition:
		$a0
}

import "pe"

rule PseudoSigner02WatcomCCDLLAnorganix : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 53 56 57 55 8B 74 24 14 8B 7C 24 18 8B 6C 24 1C 83 FF 03 0F 87 01 00 00 00 F1 }

	condition:
		$a0 at pe.entry_point
}

rule D1NS1GD1N : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 18 37 00 00 00 00 00 00 01 00 0A 00 00 00 18 00 00 80 00 00 00 00 [2] 18 37 00 00 00 00 02 00 00 00 88 00 00 80 38 00 00 80 96 00 00 80 50 00 00 80 00 00 00 00 [2] 18 37 00 00 00 00 00 00 01 00 00 00 00 00 68 00 00 00 00 00 00 00 [2] 18 37 00 00 00 00 00 00 01 00 00 00 00 00 78 00 00 00 B0 F0 00 00 10 00 00 00 00 00 00 00 00 00 00 00 C0 F0 00 00 60 00 00 00 00 00 00 00 00 00 00 00 06 00 44 00 56 00 43 00 4C 00 41 00 4C 00 0B 00 50 00 41 00 43 00 4B 00 41 00 47 00 45 00 49 00 4E 00 46 00 4F 00 00 00 00 00 00 00 00 00 00 00 00 00 }

	condition:
		$a0
}

import "pe"

rule FSGv110EngdulekxtMicrosoftVisualC6070ASM : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E8 01 00 00 00 5A 5E E8 02 00 00 00 BA DD 5E 03 F2 EB 01 64 BB 80 [2] 00 8B FA EB 01 A8 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule ASPackv102aAlexeySolodovnikov : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 [4] 5D 81 ED 3E D9 43 ?? B8 38 [3] 03 C5 2B 85 0B DE 43 ?? 89 85 17 DE 43 ?? 80 BD 01 DE 43 [2] 75 15 FE 85 01 DE 43 ?? E8 1D [3] E8 79 02 [2] E8 12 03 [2] 8B 85 03 DE 43 ?? 03 85 17 DE 43 ?? 89 44 24 1C 61 FF }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PseudoSigner01MinGWGCC2xAnorganix : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 89 E5 E8 02 00 00 00 C9 C3 90 90 45 58 45 E9 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule Armadillov253 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 6A FF 68 40 [3] 68 54 [3] 64 A1 [4] 50 64 89 25 [4] 83 EC 58 53 56 57 89 65 E8 FF 15 58 [3] 33 D2 8A D4 89 15 EC }
		$a1 = { 55 8B EC 6A FF 68 [4] 40 [4] 68 54 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF [3] 15 58 33 D2 8A D4 89 }

	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point
}

import "pe"

rule Armadillov252 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 6A FF 68 [4] E0 [4] 68 D4 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF [3] 15 38 }
		$a1 = { 55 8B EC 6A FF 68 E0 [3] 68 D4 [3] 64 A1 [4] 50 64 89 25 [4] 83 EC 58 53 56 57 89 65 E8 FF 15 38 }

	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point
}

import "pe"

rule Armadillov251 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 6A FF 68 B8 [3] 68 D0 [3] 64 A1 [4] 50 64 89 25 [4] 83 EC 58 53 56 57 89 65 E8 FF 15 20 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule Armadillov250 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 6A FF 68 B8 [3] 68 F8 [3] 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF 15 20 [3] 33 D2 8A D4 89 15 D0 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule Obsidium1331ObsidiumSoftware : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB 01 ?? E8 29 00 00 00 EB 02 [2] EB 03 [3] 8B 54 24 0C EB 02 [2] 83 82 B8 00 00 00 24 EB 04 [4] 33 C0 EB 02 [2] C3 EB 02 [2] EB 02 [2] 64 67 FF 36 00 00 EB 04 [4] 64 67 89 26 00 00 EB 01 ?? EB 02 [2] 50 EB 01 ?? 33 C0 EB 04 [4] 8B 00 EB 03 [3] C3 EB 03 [3] E9 FA 00 00 00 EB 02 [2] E8 D5 FF FF FF EB 01 ?? EB 04 [4] 58 EB 02 [2] EB 04 [4] 64 67 8F 06 00 00 EB 01 ?? 83 C4 04 EB 02 [2] E8 5F 27 00 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule CExev10a : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 81 EC 0C 02 [2] 56 BE 04 01 [2] 8D 85 F8 FE FF FF 56 50 6A ?? FF 15 54 10 40 ?? 8A 8D F8 FE FF FF 33 D2 84 C9 8D 85 F8 FE FF FF 74 16 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule DIETv144v145f : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { F8 9C 06 1E 57 56 52 51 53 50 0E FC 8C C8 BA [2] 03 D0 52 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PECompactv098 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB 06 68 [4] C3 9C 60 E8 02 [3] 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB D7 84 40 ?? 87 DD 8B 85 5C 85 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PECompactv099 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB 06 68 [4] C3 9C 60 E8 02 [3] 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 2F 85 40 ?? 87 DD 8B 85 B4 85 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule NsPacKV30LiuXingPing : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 9C 60 E8 00 00 00 00 5D B8 07 00 00 00 2B E8 8D B5 [4] 66 8B 06 66 83 F8 00 74 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule FSGv110EngdulekxtMicrosoftVisualBasic5060 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { C1 CB 10 EB 01 0F B9 03 74 F6 EE 0F B6 D3 8D 05 83 [2] EF 80 F3 F6 2B C1 EB 01 DE 68 77 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PECompactv090 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB 06 68 [2] 40 00 C3 9C 60 BD [2] 00 00 B9 02 00 00 00 B0 90 8D BD 7A 42 40 00 F3 AA 01 AD D9 43 40 00 FF B5 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PECompactv092 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB 06 68 [4] C3 9C 60 BD [4] B9 02 [3] B0 90 8D BD A5 4F 40 ?? F3 AA 01 AD 04 51 40 ?? FF B5 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PECompactv094 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB 06 68 [4] C3 9C 60 E8 [4] 5D 55 58 81 ED [4] 2B 85 [4] 01 85 [4] 50 B9 02 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PeX099bartCrackPl : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E9 F5 [3] 0D 0A C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule ObsidiumV1304ObsidiumSoftware : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB 02 [2] E8 ?? 00 00 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule SoftwareCompressv14LITEBGSoftwareProtectTechnologies : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E8 00 00 00 00 81 2C 24 AA 1A 41 00 5D E8 00 00 00 00 83 2C 24 6E 8B 85 5D 1A 41 00 29 04 24 8B 04 24 89 85 5D 1A 41 00 58 8B 85 5D 1A 41 00 8B 50 3C 03 D0 8B 92 80 00 00 00 03 D0 8B 4A 58 89 8D 49 1A 41 00 8B 4A 5C 89 8D 4D 1A 41 00 8B 4A 60 89 8D 55 1A }
		$a1 = { E8 00 00 00 00 81 2C 24 AA 1A 41 00 5D E8 00 00 00 00 83 2C 24 6E 8B 85 5D 1A 41 00 29 04 24 8B 04 24 89 85 5D 1A 41 00 58 8B 85 5D 1A 41 00 8B 50 3C 03 D0 8B 92 80 00 00 00 03 D0 8B 4A 58 89 8D 49 1A 41 00 8B 4A 5C 89 8D 4D 1A 41 00 8B 4A 60 89 8D 55 1A 41 00 8B 4A 64 89 8D 51 1A 41 00 8B 4A 74 89 8D 59 1A 41 00 68 00 20 00 00 E8 D2 00 00 00 50 8D 8D 00 1C 41 00 50 51 E8 1B 00 00 00 83 C4 08 58 8D 78 74 8D B5 49 1A 41 00 B9 18 00 00 00 F3 A4 05 A4 00 00 00 50 C3 60 8B 74 24 24 8B 7C 24 28 FC B2 80 33 DB A4 B3 02 E8 6D 00 00 00 73 F6 33 C9 E8 64 00 00 00 73 1C 33 C0 E8 5B 00 00 00 73 23 B3 02 41 B0 10 E8 4F 00 00 00 12 C0 73 F7 75 3F AA EB D4 E8 4D 00 00 00 2B CB 75 10 E8 42 00 00 00 EB 28 AC D1 E8 74 4D 13 C9 EB 1C 91 48 C1 E0 08 AC E8 2C 00 00 00 3D 00 7D 00 00 73 0A 80 FC 05 73 06 83 F8 7F 77 02 41 41 95 8B C5 B3 01 56 8B F7 2B F0 F3 A4 5E EB 8E 02 D2 75 05 8A 16 46 12 D2 C3 33 C9 41 E8 EE FF FF FF 13 C9 E8 E7 FF FF FF 72 F2 C3 2B 7C 24 28 89 7C 24 1C 61 C3 60 FF 74 24 24 6A 40 FF 95 4D 1A 41 00 89 44 24 1C 61 C2 04 }

	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point
}

import "pe"

rule FixupPakv120 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 E8 00 00 00 00 5D 81 ED [2] 00 00 BE 00 ?? 00 00 03 F5 BA 00 00 [2] 2B D5 8B DD 33 C0 AC 3C 00 74 3D 3C 01 74 0E 3C 02 74 0E 3C 03 74 0D 03 D8 29 13 EB E7 66 AD EB F6 AD EB F3 AC 0F B6 C8 3C 00 74 06 3C 01 74 09 EB 0A 66 AD 0F B7 C8 EB 03 AD 8B C8 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule ARCSFXArchive : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 8C C8 8C DB 8E D8 8E C0 89 [3] 2B C3 A3 [2] 89 [3] BE [2] B9 [2] BF [2] BA [2] FC AC 32 C2 8A D8 }

	condition:
		$a0 at pe.entry_point
}

rule MoleBoxv230Teggo : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 42 04 E8 [2] 00 00 A3 [3] 00 8B 4D F0 8B 11 89 15 [3] 00 ?? 45 FC A3 [3] 00 5F 5E 8B E5 5D C3 CC CC CC CC CC CC CC CC CC CC CC E8 EB FB FF FF 58 E8 ?? 07 00 00 58 89 44 24 20 61 58 FF D0 E8 [2] 00 00 CC CC CC CC CC CC CC }

	condition:
		$a0
}

import "pe"

rule VxIgor : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 1E B8 CD 7B CD 21 81 FB CD 7B 75 03 E9 87 00 33 DB 0E 1F 8C }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule FACRYPTv10 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { B9 [2] B3 ?? 33 D2 BE [2] 8B FE AC 32 C3 AA 49 43 32 E4 03 D0 E3 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PseudoSigner01WATCOMCCEXEAnorganix : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E9 00 00 00 00 90 90 90 90 57 41 E9 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule RLPackV115V117aPlib043ap0x : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 [4] 8D 9D [4] 33 FF E8 45 01 00 00 EB 0F FF 74 37 04 FF 34 37 FF D3 83 C4 08 83 C7 08 83 3C 37 00 75 EB }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule EmbedPEv113cyclotron : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 83 EC 50 60 68 5D B9 52 5A E8 2F 99 00 00 DC 99 F3 57 05 68 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule eXcaliburv103forgotus : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E9 00 00 00 00 60 E8 14 00 00 00 5D 81 ED 00 00 00 00 6A 45 E8 A3 00 00 00 68 00 00 00 00 E8 58 61 EB 39 20 45 78 63 61 6C 69 62 75 72 20 28 63 29 20 62 79 20 66 6F 72 67 6F 74 2F 75 53 2F 44 46 43 47 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 }

	condition:
		$a0 at pe.entry_point
}

rule Petite14 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 66 9C 60 50 8B D8 03 00 68 54 BC 00 00 6A 00 FF 50 14 8B CC }

	condition:
		$a0
}

import "pe"

rule Petite12 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 66 9C 60 E8 CA 00 00 00 03 00 04 00 05 00 06 00 07 00 08 00 }

	condition:
		$a0 at pe.entry_point
}

rule Petite13 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 66 9C 60 50 8D 88 00 F0 00 00 8D 90 04 16 00 00 8B DC 8B E1 }

	condition:
		$a0
}

import "pe"

rule Upack021betaDwing : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { BE 88 01 40 00 AD 8B F8 6A 04 95 A5 33 C0 AB 48 AB F7 D8 59 F3 AB C1 E0 0A B5 ?? F3 AB AD 50 97 51 58 8D 54 85 5C FF 16 72 5A 2C 03 73 02 B0 00 3C 07 72 02 2C 03 50 0F B6 5F FF C1 E3 ?? B3 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule WebCopsEXELINKDataSecurity : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB 03 05 EB 02 EB FC 55 EB 03 EB 04 05 EB FB EB 53 E8 04 00 00 00 72 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PseudoSigner02FSG10Anorganix : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 90 90 90 90 68 [4] 67 64 FF 36 00 00 67 64 89 26 00 00 F1 90 90 90 90 BB D0 01 40 00 BF 00 10 40 00 BE 90 90 90 90 53 E8 0A 00 00 00 02 D2 75 05 8A 16 46 12 D2 C3 FC B2 80 A4 6A 02 5B }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule ThemidaOreansTechnologies2004 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { B8 00 00 00 00 60 0B C0 74 58 E8 00 00 00 00 58 05 43 00 00 00 80 38 E9 75 03 61 EB 35 E8 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule VxNumberOne : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { F9 07 3C 53 6D 69 6C 65 3E E8 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule WinKriptv10MrCrimson : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 33 C0 8B B8 00 [3] 8B 90 04 [3] 85 FF 74 1B 33 C9 50 EB 0C 8A 04 39 C0 C8 04 34 1B 88 04 39 41 3B CA 72 F0 58 83 C0 08 EB D5 61 E9 [4] 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule tElockv085f : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 02 00 00 00 CD 20 E8 00 00 00 00 5E 2B C9 58 74 02 }

	condition:
		$a0 at pe.entry_point
}

rule RosAsm2050aBetov : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 60 8B 5D 08 B9 08 00 00 00 BF [4] 83 C7 07 FD 8A C3 24 0F 04 30 3C 39 76 02 04 07 AA C1 EB 04 E2 EE FC 68 00 10 00 00 68 [4] 68 [4] 6A 00 FF 15 [4] 61 8B E5 5D C2 04 00 }

	condition:
		$a0
}

import "pe"

rule Obsidium13021ObsidiumSoftware : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB 03 [3] E8 2E 00 00 00 EB 04 [4] EB 04 [4] 8B 54 24 0C EB 04 [4] 83 82 B8 00 00 00 23 EB 01 ?? 33 C0 EB 04 [4] C3 EB 03 [3] EB 02 [2] 64 67 FF 36 00 00 EB 01 ?? 64 67 89 26 00 00 EB 02 [2] EB 02 [2] 50 EB 01 ?? 33 C0 EB 03 [3] 8B 00 EB 03 [3] C3 EB 03 [3] E9 FA 00 00 00 EB 04 [4] E8 D5 FF FF FF EB 01 ?? EB 01 ?? 58 EB 04 [4] EB 04 [4] 64 67 8F 06 00 00 EB 03 [3] 83 C4 04 EB 04 [4] E8 2B 26 00 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule ASPackv211dAlexeySolodovnikov : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 02 00 00 00 EB 09 5D 55 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule ASPackv211cAlexeySolodovnikov : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 02 00 00 00 EB 09 5D 55 81 ED 39 39 44 00 C3 E9 59 04 00 00 }

	condition:
		$a0 at pe.entry_point
}

rule ACProtect14xRISCOsoft : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 47 65 74 4D 6F 64 75 6C 65 48 61 6E 64 6C 65 41 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 45 78 69 74 50 72 6F 63 65 73 73 00 00 00 4D 65 73 73 61 67 65 42 6F 78 41 00 90 4D 69 6E 65 49 6D 70 }

	condition:
		$a0
}

import "pe"

rule SplashBitmapv100BoBBobsoft : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E8 00 00 00 00 60 8B 6C 24 20 55 81 ED [4] 8D BD [4] 8D 8D [4] 29 F9 31 C0 FC F3 AA 8B 04 24 48 66 25 00 F0 66 81 38 4D 5A 75 F4 8B 48 3C 81 3C 01 50 45 00 00 75 E8 89 85 [4] 8D BD [4] 6A 00 }

	condition:
		$a0 at pe.entry_point
}

rule PEZipv10byBaGIE : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { D9 D0 F8 74 02 23 DB F5 F5 50 51 52 53 8D 44 24 10 50 55 56 57 D9 D0 22 C9 C1 F7 A0 55 66 C1 C8 B0 5D 81 E6 FF FF FF FF F8 77 07 52 76 03 72 01 90 5A C1 E0 60 90 BD 1F 01 00 00 87 E8 E2 07 E3 05 17 5D 47 E4 42 41 7F 06 50 66 83 EE 00 58 25 FF FF FF FF 51 }

	condition:
		$a0
}

import "pe"

rule LamerStopv10ccStefanEsser : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E8 [2] 05 [2] CD 21 33 C0 8E C0 26 [3] 2E [3] 26 [3] 2E [3] BA [2] FA }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule ACProtectV14Xrisco : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 01 00 00 00 7C 83 04 24 06 C3 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule VxGRUNT2Family : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 48 E2 F7 C3 51 53 52 E8 DD FF 5A 5B 59 C3 B9 00 00 E2 FE C3 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule AHTeamEPProtector03fakeMicrosoftVisualC70FEUERRADER : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 90 [46] 90 FF E0 6A 00 68 [4] E8 [4] BF [4] 8B C7 E8 [4] 89 65 00 8B F4 89 3E 56 FF 15 [4] 8B 4E ?? 89 0D [3] 00 8B 46 00 A3 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule InstallStub32bit : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 81 EC 14 ?? 00 00 53 56 57 6A 00 FF 15 [4] 68 [4] FF 15 [4] 85 C0 74 29 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule VcasmProtector10evcasm : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB 0A 5B 56 50 72 6F 74 65 63 74 5D }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule MSLRHv032afakePEBundle20x24xemadicius : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 9C 60 E8 02 00 00 00 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 07 30 40 00 87 DD 83 BD 9C 38 40 00 01 61 9D EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule Armadillov190b4 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 6A FF 68 08 E2 40 00 68 B4 96 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule UPXv103v104Modified : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 01 DB ?? 07 8B 1E 83 EE FC 11 DB 8A 07 ?? EB B8 01 00 00 00 01 DB ?? 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 EF }

	condition:
		$a0 at pe.entry_point
}

rule NsPackV2XLiuXingPing : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 6E 73 70 61 63 6B 24 40 }

	condition:
		$a0
}

import "pe"

rule ThemidaWinLicenseV1000V1800OreansTechnologies : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { B8 00 00 00 00 60 0B C0 74 58 E8 00 00 00 00 58 05 ?? 00 00 00 80 38 E9 75 ?? 61 EB ?? E8 00 00 00 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PACKWINv101p : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 8C C0 FA 8E D0 BC [2] FB 06 0E 1F 2E [4] 8B F1 4E 8B FE 8C DB 2E [4] 8E C3 FD F3 A4 53 B8 [2] 50 CB }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PECompactv110b1 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB 06 68 [4] C3 9C 60 E8 02 [3] 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 28 63 40 ?? 87 DD 8B 85 AD 63 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule MicroJoiner15coban2k : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { BF 05 10 40 00 83 EC 30 8B EC E8 C8 FF FF FF E8 C3 FF FF FF }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule ANDpakk2018byDmitryANDAndreev : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { FC BE D4 00 40 00 BF 00 [2] 00 57 83 CD FF 33 C9 F9 EB 05 A4 02 DB 75 05 8A 1E 46 12 DB 72 F4 33 C0 40 02 DB 75 05 8A 1E 46 12 DB 13 C0 02 DB 75 05 8A 1E 46 12 DB 72 0E 48 02 DB 75 05 8A 1E 46 12 DB 13 C0 EB DC 83 E8 03 72 0F C1 E0 08 AC 83 F0 FF 74 4D D1 F8 8B E8 EB 09 02 DB 75 05 8A 1E 46 12 DB 13 C9 02 DB 75 05 8A 1E 46 12 DB 13 C9 75 1A 41 02 DB 75 05 8A 1E 46 12 DB 13 C9 02 DB 75 05 8A 1E 46 12 DB 73 EA 83 C1 02 81 FD 00 FB FF FF 83 D1 01 56 8D 34 2F F3 A4 5E E9 73 FF FF FF C3 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PECompactv110b2 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB 06 68 [4] C3 9C 60 E8 02 [3] 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 60 40 ?? 87 DD 8B 85 94 60 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PECompactv110b5 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB 06 68 [4] C3 9C 60 E8 02 [3] 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 60 40 ?? 87 DD 8B 85 95 60 40 ?? 01 85 03 60 40 ?? 66 C7 85 ?? 60 40 ?? 90 90 BB 49 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule NJoy10NEX : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 83 C4 F0 B8 9C 3B 40 00 E8 8C FC FF FF 6A 00 68 E4 39 40 00 6A 0A 6A 00 E8 40 FD FF FF E8 EF F5 FF FF 8D 40 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PECompactv110b7 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB 06 68 [4] C3 9C 60 E8 02 [3] 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 60 40 ?? 87 DD 8B 85 9A 60 40 ?? 01 85 03 60 40 ?? 66 C7 85 ?? 60 40 ?? 90 90 01 85 92 60 40 ?? BB 14 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PECompactv110b6 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB 06 68 [4] C3 9C 60 E8 02 [3] 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 60 ?? 00 87 DD 8B 85 9A 60 40 ?? 01 85 03 60 40 ?? 66 C7 85 ?? 60 40 ?? 90 90 01 85 92 60 40 ?? BB B7 }

	condition:
		$a0 at pe.entry_point
}

rule KBysPacker028BetaShoooo : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 00 00 00 00 5E 83 EE 0A 8B 06 03 C2 8B 08 89 4E F3 83 EE 0F 56 52 8B F0 AD AD 03 C2 8B D8 6A 04 BF 00 10 00 00 57 57 6A 00 FF 53 08 5A 59 BD 00 80 00 00 55 6A 00 50 51 52 50 89 06 AD AD 03 C2 50 AD 03 C2 FF D0 6A 04 57 AD 50 6A 00 FF 53 }

	condition:
		$a0
}

import "pe"

rule nPack113002006BetaNEOx : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 83 3D [5] 75 05 E9 01 00 00 00 C3 E8 46 00 00 00 E8 73 00 00 00 B8 [4] 2B 05 [4] A3 [4] E8 9C 00 00 00 E8 2D 02 00 00 E8 DD 06 00 00 E8 2C 06 00 00 A1 [4] C7 05 [8] 01 05 [4] FF 35 [4] C3 C3 56 57 68 [4] FF 15 [4] 8B 35 [4] 8B F8 68 [4] 57 FF D6 68 [4] 57 A3 [4] FF D6 5F A3 [4] 5E C3 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PseudoSigner02BorlandC1999Anorganix : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB 10 66 62 3A 43 2B 2B 48 4F 4F 4B 90 E9 90 90 90 90 A1 [4] A3 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule ASPackv100bAlexeySolodovnikov : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 [4] 5D 81 ED 92 1A 44 ?? B8 8C 1A 44 ?? 03 C5 2B 85 CD 1D 44 ?? 89 85 D9 1D 44 ?? 80 BD C4 1D 44 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule SEAAXEv22 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { FC BC [2] 0E 1F A3 [2] E8 [2] A1 [2] 8B [3] 2B C3 8E C0 B1 03 D3 E3 8B CB BF [2] 8B F7 F3 A5 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PureBasic4xDLLNeilHodgson : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 83 7C 24 08 01 75 0E 8B 44 24 04 A3 [3] 10 E8 22 00 00 00 83 7C 24 08 02 75 00 83 7C 24 08 00 75 05 E8 ?? 00 00 00 83 7C 24 08 03 75 00 B8 01 00 00 00 C2 0C 00 68 00 00 00 00 68 00 10 00 00 68 00 00 00 00 E8 ?? 0F 00 00 A3 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule EXEPackerv70byTurboPowerSoftware : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 1E 06 8C C3 83 [2] 2E [4] B9 [2] 8C C8 8E D8 8B F1 4E 8B FE }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule VxSYP : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 47 8B C2 05 1E 00 52 8B D0 B8 02 3D CD 21 8B D8 5A }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule DSHIELD : Packer PEiD hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 06 E8 [2] 5E 83 EE ?? 16 17 9C 58 B9 [2] 25 [2] 2E }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule kkrunchy023alphaRyd : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { BD 08 [2] 00 C7 45 00 [3] 00 FF 4D 08 C6 45 0C 05 8D 7D 14 31 C0 B4 04 89 C1 F3 AB BF [3] 00 57 BE [3] 00 31 C9 41 FF 4D 0C 8D 9C 8D A0 00 00 00 FF D6 10 C9 73 F3 FF 45 0C 91 AA 83 C9 FF 8D 5C 8D 18 FF D6 74 DD E3 17 8D 5D 1C FF D6 74 10 8D 9D A0 08 00 00 E8 ?? 00 00 00 8B 45 10 EB 42 8D 9D A0 04 00 00 E8 ?? 00 00 00 49 49 78 40 8D 5D 20 74 03 83 C3 40 31 D2 42 E8 ?? 00 00 00 8D 0C 48 F6 C2 10 74 F3 41 91 8D 9D A0 08 00 00 E8 ?? 00 00 00 3D 00 08 00 00 83 D9 FF 83 F8 60 83 D9 FF 89 45 10 56 89 FE 29 C6 F3 A4 5E EB 90 BE [3] 00 BB [3] 00 55 46 AD 85 C0 74 ?? 97 56 FF 13 85 C0 74 16 95 AC 84 C0 75 FB 38 06 74 E8 78 ?? 56 55 FF 53 04 AB 85 C0 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule NJoy12NEX : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 83 C4 F0 B8 A4 32 40 00 E8 E8 F1 FF FF 6A 00 68 54 2A 40 00 6A 0A 6A 00 E8 A8 F2 FF FF E8 C7 EA FF FF 8D 40 00 }

	condition:
		$a0 at pe.entry_point
}

rule AntiDote12DemoSISTeam : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E8 F7 FE FF FF 05 CB 22 00 00 FF E0 E8 EB FE FF FF 05 BB 19 00 00 FF E0 E8 BD 00 00 00 08 B2 62 00 01 52 17 0C 0F 2C 2B 20 7F 52 79 01 30 07 17 29 4F 01 3C 30 2B 5A 3D C7 26 11 26 06 59 0E 78 2E 10 14 0B 13 1A 1A 3F 64 1D 71 33 57 21 09 24 8B 1B 09 37 08 61 0F 1D 1D 2A 01 87 35 4C 07 39 0B }

	condition:
		$a0
}

import "pe"

rule EXE32Packv137 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 3B C0 74 02 81 83 55 3B C0 74 02 81 83 53 3B C9 74 01 BC [4] 02 81 [7] 3B DB 74 01 BE 5D 8B D5 81 ED 4C 8E 40 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule EXE32Packv136 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 3B C0 74 02 81 83 55 3B C0 74 02 81 83 53 3B C9 74 01 BC [4] 02 81 [7] 3B DB 74 01 BE 5D 8B D5 81 ED CC 8D 40 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule AINEXEv230 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 0E 07 B9 [2] BE [2] 33 FF FC F3 A4 A1 [2] 2D [2] 8E D0 BC [2] 8C D8 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule ThinstallEmbedded20XJitit : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { B8 EF BE AD DE 50 6A 00 FF 15 [4] E9 AD FF FF FF 8B C1 8B 4C 24 04 89 88 29 04 00 00 C7 40 0C 01 00 00 00 0F B6 49 01 D1 E9 89 48 10 C7 40 14 80 00 00 00 C2 04 00 8B 44 24 04 C7 41 0C 01 00 00 00 89 81 29 04 00 00 0F B6 40 01 D1 E8 89 41 10 C7 41 14 80 00 00 00 C2 04 00 55 8B EC 53 56 57 33 C0 33 FF 39 45 0C 8B F1 76 0C 8B 4D 08 03 3C 81 40 3B 45 0C 72 F4 8B CE E8 43 00 00 00 8B 46 14 33 D2 F7 F7 8B 5E 10 33 D2 8B F8 8B C3 F7 F7 89 7E 18 89 45 0C 33 C0 33 C9 8B 55 08 03 0C 82 40 39 4D 0C 73 F4 48 8B 14 82 2B CA 0F AF CF 2B D9 0F AF FA 89 7E 14 89 5E 10 5F 5E 5B 5D C2 08 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule EXECryptorv151x : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E8 24 [3] 8B 4C 24 0C C7 01 17 ?? 01 ?? C7 81 B8 [7] 31 C0 89 41 14 89 41 18 80 A1 C1 [3] FE C3 31 C0 64 FF 30 64 89 20 CC C3 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule Obsidiumv1304ObsidiumSoftware : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB 02 [2] E8 25 00 00 00 EB 04 [4] EB 01 ?? 8B 54 24 0C EB 01 ?? 83 82 B8 00 00 00 23 EB 01 ?? 33 C0 EB 02 [2] C3 EB 02 [2] EB 04 [4] 64 67 FF 36 00 00 EB 03 [3] 64 67 89 26 00 00 EB 02 [2] EB 01 ?? 50 EB 01 ?? 33 C0 EB 01 }
		$a1 = { EB 02 [2] E8 25 00 00 00 EB 04 [4] EB 01 ?? 8B 54 24 0C EB 01 ?? 83 82 B8 00 00 00 23 EB 01 ?? 33 C0 EB 02 [2] C3 EB 02 [2] EB 04 [4] 64 67 FF 36 00 00 EB 03 [3] 64 67 89 26 00 00 EB 02 [2] EB 01 ?? 50 EB 01 ?? 33 C0 EB 01 ?? 8B 00 EB 01 ?? C3 EB 02 [2] E9 FA 00 00 00 EB 02 [2] E8 D5 FF FF FF EB 03 [3] EB 04 [4] 58 EB 02 [2] EB 04 [4] 64 67 8F 06 00 00 EB 03 [3] 83 C4 04 EB 01 ?? E8 3B 26 00 00 }

	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point
}

import "pe"

rule CopyProtectorv20 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 2E A2 [2] 53 51 52 1E 06 B4 ?? 1E 0E 1F BA [2] CD 21 1F }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule EXE32Packv139 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 3B C0 74 02 81 83 55 3B C0 74 02 81 83 53 3B C9 74 01 BC [4] 02 81 [7] 3B DB 74 01 BE 5D 8B D5 81 ED EC 8D 40 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule EXE32Packv138 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 3B C0 74 02 81 83 55 3B C0 74 02 81 83 53 3B C9 74 01 BC [4] 02 81 [7] 3B DB 74 01 BE 5D 8B D5 81 ED DC 8D 40 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule FSGv110EngdulekxtBorlandC1999 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB 02 CD 20 2B C8 68 80 [2] 00 EB 02 1E BB 5E EB 02 CD 20 68 B1 2B 6E 37 40 5B 0F B6 C9 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule ThinstallEmbedded2547V2600Jitit : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E8 00 00 00 00 58 BB BC 18 00 00 2B C3 50 68 [4] 68 60 1B 00 00 68 60 00 00 00 E8 35 FF FF FF E9 99 FF FF FF 00 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule FSGv131Engdulekxt : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { BB D0 01 40 00 BF 00 10 40 00 BE [3] 00 53 BB [3] 00 B2 80 A4 B6 80 FF D3 73 F9 33 C9 FF D3 73 16 33 C0 FF D3 73 23 B6 80 41 B0 10 FF D3 12 C0 73 FA 75 42 AA EB E0 E8 46 00 00 00 02 F6 83 D9 01 75 10 E8 38 00 00 00 EB 28 AC D1 E8 74 48 13 C9 EB }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule SDProtectorBasicProEdition110RandyLi : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 6A FF 68 1D 32 13 05 68 88 88 88 08 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 58 64 A3 00 00 00 00 58 58 58 58 8B E8 50 83 EC 08 64 A1 00 00 00 00 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 83 C4 08 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 64 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule Petite12c1998IanLuck : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 66 9C 60 E8 CA 00 00 00 03 00 04 00 05 00 06 00 07 00 08 00 09 00 0A 00 0B 00 0D 00 0F 00 11 00 13 00 17 00 1B 00 1F 00 23 00 2B 00 33 00 3B 00 43 00 53 00 63 00 73 00 83 00 A3 00 C3 00 E3 00 02 01 00 00 00 00 00 00 00 00 00 00 00 00 01 01 01 01 02 02 02 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PcSharev40 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 6A FF 68 90 34 40 00 68 B6 28 40 00 64 A1 }

	condition:
		$a0 at pe.entry_point
}

rule VProtector0X12Xvcasm : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 00 00 56 69 72 74 75 61 6C 41 6C 6C 6F 63 00 00 00 00 00 76 63 61 73 6D 5F 70 72 6F 74 65 63 74 5F [10] 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 33 F6 E8 10 00 00 00 8B 64 24 08 64 8F 05 00 00 00 00 58 EB 13 C7 83 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 AD CD 20 EB 01 0F 31 F0 EB 0C 33 C8 EB 03 EB 09 0F 59 74 05 75 F8 51 EB F1 B9 04 00 00 00 E8 1F 00 00 00 EB FA E8 16 00 00 00 E9 EB F8 00 00 58 EB 09 0F 25 E8 F2 FF FF FF 0F B9 49 75 F1 EB 05 EB F9 EB F0 D6 E8 07 00 00 00 C7 83 83 C0 13 EB 0B 58 EB 02 CD 20 83 C0 02 EB 01 E9 50 C3 }

	condition:
		$a0
}

import "pe"

rule STNPEE113 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 57 56 52 51 53 E8 00 00 00 00 5D 8B D5 81 ED 97 3B 40 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule SoftDefenderV11xRandyLi : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 74 07 75 05 19 32 67 E8 E8 74 1F 75 1D E8 68 39 44 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule CDCopsII : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 53 60 BD [4] 8D 45 ?? 8D 5D ?? E8 [4] 8D }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule RLPack11BasicEditionap0x : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 4A 02 00 00 8D 9D 11 01 00 00 33 FF EB 0F FF 74 37 04 FF 34 37 FF D3 83 C4 08 83 C7 08 83 3C 37 00 75 EB 8D 74 37 04 53 6A 40 68 00 10 00 00 68 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule EXE32Packv13x : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 3B ?? 74 02 81 83 55 3B ?? 74 02 81 ?? 53 3B ?? 74 01 [5] 02 81 [2] E8 [4] 3B 74 01 ?? 5D 8B D5 81 ED }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule VxInvoluntary1349 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { BA [2] B9 [2] 8C DD ?? 8C C8 ?? 8E D8 8E C0 33 F6 8B FE FC [2] AD ?? 33 C2 AB }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule WinZip32bit6x : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { FF 15 FC 81 40 00 B1 22 38 08 74 02 B1 20 40 80 38 00 74 10 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule NsPacKV36LiuXingPing : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 9C 60 E8 00 00 00 00 5D 83 ED 07 8D [5] 83 38 01 0F 84 47 02 00 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PseudoSigner02LCCWin321xAnorganix : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 64 A1 01 00 00 00 55 89 E5 6A FF 68 [4] 68 9A 10 40 90 50 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule EXECrypt10ReBirth : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 90 90 60 E8 00 00 00 00 5D 81 ED D1 27 40 00 B9 15 00 00 00 83 C1 04 83 C1 01 EB 05 EB FE 83 C7 56 EB 00 EB 00 83 E9 02 81 C1 78 43 27 65 EB 00 81 C1 10 25 94 00 81 E9 63 85 00 00 B9 96 0C 00 00 90 8D BD 4E 28 40 00 8B F7 AC }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule NJoy11NEX : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 83 C4 F0 B8 0C 3C 40 00 E8 24 FC FF FF 6A 00 68 28 3A 40 00 6A 0A 6A 00 E8 D8 FC FF FF E8 7F F5 FF FF 8D 40 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PEcryptbyarchphase : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 83 C4 E0 53 56 33 C0 89 45 E4 89 45 E0 89 45 EC [4] 64 82 40 00 E8 7C C7 FF FF 33 C0 55 68 BE 84 40 00 64 FF 30 64 89 20 68 CC 84 40 00 [4] 00 A1 10 A7 40 00 50 E8 1D C8 FF FF 8B D8 85 DB 75 39 E8 3A C8 FF FF 6A 00 6A 00 68 A0 A9 40 00 68 00 04 00 00 50 6A 00 68 00 13 00 00 E8 FF C7 FF FF 6A 00 68 E0 84 40 00 A1 A0 A9 40 00 50 6A 00 E8 [4] E9 7D 01 00 00 53 A1 10 A7 40 00 50 E8 42 C8 FF FF 8B F0 85 F6 75 18 6A 00 68 E0 84 40 00 68 E4 84 40 00 6A 00 E8 71 C8 FF FF E9 53 01 00 00 53 6A 00 E8 2C C8 FF FF A3 [4] 83 3D 48 A8 40 00 00 75 18 6A 00 68 E0 84 40 00 68 F8 84 40 00 6A 00 E8 43 C8 FF FF E9 25 01 00 00 56 E8 F8 C7 FF FF A3 4C A8 40 00 A1 48 A8 40 00 E8 91 A1 FF FF 8B D8 8B 15 48 A8 40 00 85 D2 7C 16 42 33 C0 8B 0D 4C A8 40 00 03 C8 8A 09 8D 34 18 88 0E 40 4A 75 ED 8B 15 48 A8 40 00 85 D2 7C 32 42 33 C0 8D 34 18 8A 0E 80 F9 01 75 05 C6 06 FF EB 1C 8D 0C 18 8A 09 84 [5] 00 EB 0E 8B 0D 4C A8 40 00 03 C8 0F B6 09 49 88 0E 40 4A 75 D1 8D [4] E8 A5 A3 FF FF 8B 45 E8 8D 55 EC E8 56 D5 FF FF 8D 45 EC BA 18 85 40 00 E8 79 BA FF FF 8B 45 EC E8 39 BB FF FF 8B D0 B8 54 A8 40 00 E8 31 A6 FF FF BA 01 00 00 00 B8 54 A8 40 00 E8 12 A9 FF FF E8 DD A1 FF FF 68 50 A8 40 00 8B D3 8B 0D 48 A8 40 00 B8 54 A8 40 00 E8 56 A7 FF FF E8 C1 A1 FF FF }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule CrunchPEv30xx : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB 10 [16] 55 E8 [4] 5D 81 ED 18 [3] 8B C5 55 60 9C 2B 85 [4] 89 85 [4] FF 74 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule LameCryptLaZaRus : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 66 9C BB 00 [2] 00 80 B3 00 10 40 00 90 4B 83 FB FF 75 F3 66 9D 61 B8 [2] 40 00 FF E0 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule NsPack29NorthStar : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 9C 60 E8 00 00 00 00 5D B8 07 00 00 00 2B E8 8D B5 [2] FF FF 8A 06 3C 00 74 12 8B F5 8D B5 [2] FF FF 8A 06 3C 01 0F 84 42 02 00 00 C6 06 01 8B D5 2B 95 [2] FF FF 89 95 [2] FF FF 01 95 [2] FF FF 8D B5 [2] FF FF 01 16 60 6A 40 68 00 10 00 00 68 00 10 00 00 6A 00 FF 95 [2] FF FF 85 C0 0F 84 6A 03 00 00 89 85 [2] FF FF E8 00 00 00 00 5B B9 68 03 00 00 03 D9 50 53 E8 B1 02 00 00 61 8B 36 8B FD 03 BD [2] FF FF 8B DF 83 3F 00 75 0A 83 C7 04 B9 00 00 00 00 EB 16 B9 01 00 00 00 03 3B 83 C3 04 83 3B 00 74 36 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule BeRoEXEPackerv100LZBRSBeRoFarbrausch : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 BE [4] BF [4] FC AD 8D 1C 07 B0 80 3B FB 73 3B E8 [4] 72 03 A4 EB F2 E8 [4] 8D 51 FF E8 [4] 56 8B F7 2B F2 F3 A4 5E EB DB 02 C0 75 03 AC 12 C0 C3 33 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule FSGv110EngdulekxtBorlandC : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 23 CA EB 02 5A 0D E8 02 00 00 00 6A 35 58 C1 C9 10 BE 80 [2] 00 0F B6 C9 EB 02 CD 20 BB }
		$a1 = { 23 CA EB 02 5A 0D E8 02 00 00 00 6A 35 58 C1 C9 10 BE 80 [2] 00 0F B6 C9 EB 02 CD 20 BB F4 00 00 00 EB 02 04 FA EB 01 FA EB 01 5F EB 02 CD 20 8A 16 EB 02 11 31 80 E9 31 EB 02 30 11 C1 E9 11 80 EA 04 EB 02 F0 EA 33 CB 81 EA AB AB 19 08 04 D5 03 C2 80 EA }

	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point
}

rule VIRUSIWormKLEZ : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 6A FF 68 40 D2 40 ?? 68 04 AC 40 ?? 64 A1 [4] 50 64 89 25 [4] 83 EC 58 53 56 57 89 65 E8 FF 15 BC D0 }

	condition:
		$a0
}

import "pe"

rule YZPack12UsAr : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 4D 5A 52 45 60 83 EC 18 8B EC 8B FC 33 C0 64 8B 40 30 78 0C 8B 40 0C 8B 70 1C AD 8B 40 08 EB 09 8B 40 34 83 C0 7C 8B 40 3C AB E9 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PseudoSigner02LocklessIntroPackAnorganix : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 2C E8 EB 1A 90 90 5D 8B C5 81 ED F6 73 90 90 2B 85 90 90 90 90 83 E8 06 89 85 FF 01 EC AD }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PKLITE3211 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 50 4B 4C 49 54 45 33 32 20 43 6F 70 79 72 69 67 68 74 20 31 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule FSGv20bartxt : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 87 25 [3] 00 61 94 55 A4 B6 80 FF 13 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule MSLRHv032afakeSVKP111emadicius : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED 06 00 00 00 64 A0 23 00 00 00 83 C5 06 61 EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 2B 04 24 74 04 75 02 EB 02 EB 01 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule FSGv110EngdulekxtMASM32TASM32MicrosoftVisualBasic : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { F7 D8 0F BE C2 BE 80 [2] 00 0F BE C9 BF 08 3B 65 07 EB 02 D8 29 BB EC C5 9A F8 EB 01 94 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule EXECryptor239DLLminimumprotection : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 51 68 [4] 87 2C 24 8B CD 5D 81 E1 [4] E9 [3] 00 89 45 F8 51 68 [4] 59 81 F1 [4] 0B 0D [4] 81 E9 [4] E9 [3] 00 81 C2 [4] E8 [3] 00 87 0C 24 59 51 64 8B 05 30 00 00 00 8B 40 0C 8B 40 0C E9 [3] 00 F7 D6 2B D5 E9 [3] 00 87 3C 24 8B CF 5F 87 14 24 1B CA E9 [3] 00 83 C4 08 68 [4] E9 [3] 00 C3 E9 [3] 00 E9 [3] 00 50 8B C5 87 04 24 8B EC 51 0F 88 [3] 00 FF 05 [4] E9 [3] 00 87 0C 24 59 99 03 04 24 E9 [3] 00 C3 81 D5 [4] 9C E9 [3] 00 81 FA [4] E9 [3] 00 C1 C3 15 81 CB [4] 81 F3 [4] 81 C3 [4] 87 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule Frusionbiff : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 83 EC 0C 53 55 56 57 68 04 01 00 00 C7 44 24 14 }

	condition:
		$a0 at pe.entry_point
}

rule OpenSourceCodeCrypterp0ke : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC B9 09 00 00 00 6A 00 6A 00 49 75 F9 53 56 57 B8 34 44 40 00 E8 28 F8 FF FF 33 C0 55 68 9F 47 40 00 64 FF 30 64 89 20 BA B0 47 40 00 B8 1C 67 40 00 E8 07 FD FF FF 8B D8 85 DB 75 07 6A 00 E8 C2 F8 FF FF BA 28 67 40 00 8B C3 8B 0D 1C 67 40 00 E8 F0 E0 FF FF BE 01 00 00 00 B8 2C 68 40 00 E8 E1 F0 FF FF BF 0A 00 00 00 8D 55 EC 8B C6 E8 92 FC FF FF 8B 4D EC B8 2C 68 40 00 BA BC 47 40 00 E8 54 F2 FF FF A1 2C 68 40 00 E8 52 F3 FF FF 8B D0 B8 20 67 40 00 E8 A2 FC FF FF 8B D8 85 DB 0F 84 52 02 00 00 B8 24 67 40 00 8B 15 20 67 40 00 E8 78 F4 FF FF B8 24 67 40 00 E8 7A F3 FF FF 8B D0 8B C3 8B 0D 20 67 40 00 E8 77 E0 FF FF 8D 55 E8 A1 24 67 40 00 E8 42 FD FF FF 8B 55 E8 B8 24 67 40 00 }

	condition:
		$a0
}

import "pe"

rule QrYPt0rbyNuTraL : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 80 F9 00 0F 84 8D 01 00 00 8A C3 [50] 32 C1 3C F3 75 89 [50] BA D9 04 00 00 E8 00 00 00 00 5F 81 C7 16 01 00 00 80 2C 3A 01 }
		$a1 = { 86 18 CC 64 FF 35 00 00 00 00 [50] 64 89 25 00 00 00 00 BB 00 00 F7 BF [50] B8 78 56 34 12 87 03 E8 CD FE FF FF E8 B3 }
		$a2 = { EB 00 E8 B5 00 00 00 E9 2E 01 00 00 64 FF 35 00 00 00 00 [50] 64 89 25 00 00 00 00 8B 44 24 04 }

	condition:
		$a0 or $a1 or $a2 at pe.entry_point
}

rule EXECryptor2xxmaxcompressedresources : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 83 C4 EC FC 53 57 56 89 45 FC 89 55 F8 89 C6 89 D7 66 81 3E 4A 43 0F 85 23 01 00 00 83 C6 0A C7 45 F4 08 00 00 00 31 DB BA 00 00 00 80 43 31 C0 E8 11 01 00 00 73 0E 8B 4D F0 E8 1F 01 00 00 02 45 EF AA EB E9 E8 FC 00 00 00 0F 82 97 00 00 00 E8 F1 00 00 00 73 5B B9 04 00 00 00 E8 FD 00 00 00 48 74 DE 0F 89 C7 00 00 00 E8 D7 00 00 00 73 1B 55 BD 00 01 00 00 E8 D7 00 00 00 88 07 47 4D 75 F5 E8 BF 00 00 00 72 E9 5D EB A2 B9 01 00 00 00 E8 C8 00 00 00 83 C0 07 89 45 F0 C6 45 EF 00 83 F8 08 74 89 E8 A9 00 00 00 88 45 EF E9 7C FF FF FF B9 07 00 00 00 E8 A2 00 00 00 50 }

	condition:
		$a0
}

import "pe"

rule Upackv024v028AlphaDwing : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { BE 88 01 40 00 AD [2] 95 AD 91 F3 A5 AD }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule ThinstallEmbedded24222428Jitit : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC B8 [4] BB [4] 50 E8 00 00 00 00 58 2D 9B 1A 00 00 B9 84 1A 00 00 BA 14 1B 00 00 BE 00 10 00 00 BF B0 53 00 00 BD E0 1A 00 00 03 E8 81 75 00 [4] 81 75 04 [4] 81 75 08 [4] 81 75 0C [4] 81 75 10 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule SVKProtectorv1051 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 EB 03 C7 84 E8 EB 03 C7 84 9A E8 00 00 00 00 5D 81 ED 10 00 00 00 EB 03 C7 84 E9 64 A0 23 00 00 00 EB }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule AHTeamEPProtector03fakeZCode101FEUERRADER : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 90 [46] 90 FF E0 E9 12 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 E9 FB FF FF FF C3 68 00 00 00 00 64 FF 35 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PEPacker : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { FC 8B 35 70 01 40 ?? 83 EE 40 6A 40 68 ?? 30 10 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule ProgramProtectorXPv10 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E8 [4] 58 83 D8 05 89 C3 81 C3 [4] 8B 43 64 50 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule SimplePack111Method2NTbagieTMX : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 4D 5A 90 EB 01 00 52 E9 89 01 00 00 50 45 00 00 4C 01 02 00 00 00 00 00 00 00 00 00 00 00 00 00 E0 00 0F 03 0B 01 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule MSLRHv032aemadicius : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 2B 04 24 74 04 75 02 EB 02 EB 01 81 83 C4 04 E8 0A 00 00 00 E8 }
		$a1 = { EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 }
		$a2 = { E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 2B 04 24 74 04 75 02 EB 02 EB 01 81 83 C4 04 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 3D FF FF FF 00 EB 01 68 EB 02 CD 20 EB 01 E8 76 1B EB 01 68 EB 02 CD 20 EB 01 E8 CC 66 B8 FE 00 74 04 75 02 EB 02 EB 01 81 66 E7 64 74 04 75 02 EB 02 EB 01 81 E8 0A 00 00 00 E8 EB 0C }

	condition:
		$a0 or $a1 or $a2 at pe.entry_point
}

import "pe"

rule VxHafen1641 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E8 [2] 01 [3] CE CC 25 [2] 25 [2] 25 [2] 40 51 D4 [3] CC 47 CA [2] 46 8A CC 44 88 CC }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule NativeUDPacker11ModdedPoisonIvyShellcodeokkixot : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 31 C0 31 DB 31 C9 EB 0E 6A 00 6A 00 6A 00 6A 00 FF 15 28 41 40 00 FF 15 94 40 40 00 89 C7 68 88 13 00 00 FF 15 98 40 40 00 FF 15 94 40 40 00 81 C7 88 13 00 00 39 F8 73 05 E9 84 00 00 00 6A 40 68 00 10 00 00 FF 35 04 30 40 00 6A 00 FF 15 A4 40 40 00 89 C7 FF 35 04 30 40 00 68 CA 10 40 00 50 FF 15 A8 40 40 00 6A 40 68 00 10 00 00 FF 35 08 30 40 00 6A 00 FF 15 A4 40 40 00 89 C6 68 00 30 40 00 FF 35 04 30 40 00 57 FF 35 08 30 40 00 50 6A 02 FF 15 4E 41 40 00 6A 00 6A 00 6A 00 56 6A 00 6A 00 FF 15 9C 40 40 00 50 6A 00 6A 00 6A 11 50 FF 15 4A 41 40 00 58 6A FF 50 FF 15 AC 40 40 00 6A 00 FF 15 A0 40 }

	condition:
		$a0 at pe.entry_point
}

rule EXECryptor2xxcompressedresources : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 56 57 53 31 DB 89 C6 89 D7 0F B6 06 89 C2 83 E0 1F C1 EA 05 74 2D 4A 74 15 8D 5C 13 02 46 C1 E0 08 89 FA 0F B6 0E 46 29 CA 4A 29 C2 EB 32 C1 E3 05 8D 5C 03 04 46 89 FA 0F B7 0E 29 CA 4A 83 C6 02 EB 1D C1 E3 04 46 89 C1 83 E1 0F 01 CB C1 E8 05 73 07 43 89 F2 01 DE EB 06 85 DB 74 0E EB A9 56 89 D6 89 D9 F3 A4 31 DB 5E EB 9D 89 F0 5B 5F 5E C3 }

	condition:
		$a0
}

import "pe"

rule NXPEPackerv10 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { FF 60 FF CA FF 00 BA DC 0D E0 40 00 50 00 60 00 70 00 80 00 }

	condition:
		$a0 at pe.entry_point
}

rule PolyBoxCAnskya : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 83 C4 F0 53 56 B8 E4 41 00 10 E8 3A E1 FF FF 33 C0 55 68 11 44 00 10 64 FF 30 64 89 20 EB 08 FC FC FC FC FC FC 27 54 6A 0A 68 20 44 00 10 A1 1C 71 00 10 50 E8 CC E1 [4] 85 DB 0F 84 77 01 00 00 53 A1 1C 71 00 10 50 E8 1E E2 FF FF 8B F0 85 F6 0F 84 61 01 00 00 53 A1 1C 71 00 10 50 E8 E0 E1 FF FF 85 C0 0F 84 4D 01 00 00 50 E8 DA E1 FF FF 8B D8 85 DB 0F 84 3D 01 00 00 56 B8 70 80 00 10 B9 01 00 00 00 8B 15 98 41 00 10 E8 9E DE FF FF 83 C4 04 A1 70 80 00 10 8B CE 8B D3 E8 E1 E1 FF FF 6A 00 6A 00 A1 70 80 00 10 B9 30 44 00 10 8B D6 E8 F8 FD FF FF }

	condition:
		$a0
}

rule UPolyXv05 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC ?? 00 BD 46 00 8B ?? B9 ?? 00 00 00 80 [2] 51 [4] 00 [26] 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
		$a1 = { 83 EC 04 89 14 24 59 BA ?? 00 00 00 52 [56] 00 [13] 00 }
		$a2 = { BB 00 BD 46 00 83 EC 04 89 1C 24 ?? B9 ?? 00 00 00 80 33 [6] 00 [13] 00 [12] 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
		$a3 = { E8 00 00 00 00 59 83 C1 07 51 C3 C3 ?? 00 BD 46 00 83 EC 04 89 ?? 24 B9 ?? 00 00 00 81 [4] 00 [21] 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
		$a4 = { E8 00 00 00 00 59 83 C1 07 51 C3 C3 ?? 00 BD 46 00 ?? B9 ?? 00 00 00 [27] 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
		$a5 = { EB 01 C3 ?? 00 BD 46 00 [46] 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

	condition:
		$a0 or $a1 or $a2 or $a3 or $a4 or $a5
}

import "pe"

rule beriav007publicWIPsymbiont : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 83 EC 18 53 8B 1D 00 30 [2] 55 56 57 68 30 07 00 00 33 ED 55 FF D3 8B F0 3B F5 74 0D 89 AE 20 07 00 00 E8 88 0F 00 00 EB 02 33 F6 6A 10 55 89 35 30 40 [2] FF D3 8B F0 3B F5 74 09 89 2E E8 3C FE FF FF EB 02 33 F6 6A 18 55 89 35 D8 43 [2] FF D3 8B F0 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PCGuardv405dv410dv415d : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { FC 55 50 E8 00 00 00 00 5D EB 01 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule asscrypterbysantasdad : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 83 C4 EC 53 [4] 89 45 EC B8 98 40 00 10 E8 AC EA FF FF 33 C0 55 68 78 51 00 10 64 [4] 20 6A 0A 68 88 51 00 10 A1 E0 97 00 10 50 E8 D8 EA FF FF 8B D8 53 A1 E0 97 00 10 50 E8 12 EB FF FF 8B F8 53 A1 E0 97 00 10 50 E8 DC EA FF FF 8B D8 53 E8 DC EA FF FF 8B F0 85 F6 74 26 8B D7 4A B8 F0 97 00 10 E8 C9 E7 FF FF B8 F0 97 00 10 E8 B7 E7 FF FF 8B CF 8B D6 E8 EE EA FF FF 53 E8 98 EA FF FF 8D 4D EC BA 9C 51 00 10 A1 F0 97 00 10 E8 22 EB FF FF 8B 55 EC B8 F0 97 00 10 E8 89 E6 FF FF B8 F0 97 00 10 E8 7F E7 FF FF E8 6E EC FF FF 33 C0 5A 59 59 64 89 10 68 7F 51 00 10 8D 45 EC E8 11 E6 FF FF C3 E9 FF DF FF FF EB F0 5F 5E 5B E8 0D E5 FF FF 00 53 45 54 54 49 4E 47 53 00 00 00 00 FF FF FF FF 1C 00 00 00 45 4E 54 45 52 20 59 4F 55 52 20 4F 57 4E 20 50 41 53 53 57 4F 52 44 20 48 45 52 45 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule CopyControlv303 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { CC 90 90 EB 0B 01 50 51 52 53 54 61 33 61 2D 35 CA D1 07 52 D1 A1 3C }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule FSGv110Engbartxt : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { BB D0 01 40 00 BF 00 10 40 00 BE [3] 00 53 E8 0A 00 00 00 02 D2 75 05 8A 16 46 12 D2 C3 B2 80 A4 6A 02 5B FF 14 24 73 F7 33 C9 FF 14 24 73 18 33 C0 FF 14 24 73 21 B3 02 41 B0 10 FF 14 24 12 C0 73 F9 75 3F AA EB DC E8 43 00 00 00 2B CB 75 10 E8 38 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule Elanguage : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E8 06 00 00 00 50 E8 ?? 01 00 00 55 8B EC 81 C4 F0 FE FF FF }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule EXELOCK66615 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { BA [2] BF [2] EB ?? EA [4] 79 ?? 7F ?? 7E ?? 1C ?? 48 78 ?? E3 ?? 45 14 ?? 5A E9 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule AdysGluev010 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 2E 8C 06 [2] 0E 07 33 C0 8E D8 BE [2] BF [2] FC B9 [2] 56 F3 A5 1E 07 5F }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule SVKProtectorv132 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED 06 00 00 00 EB 05 B8 06 36 42 00 64 A0 23 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PKLITEv114v115v1203 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { B8 [2] BA [2] 05 [2] 3B [3] 72 ?? B4 09 BA ?? 01 CD 21 CD 20 4E 6F }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule SafeGuardV10Xsimonzh2000 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E8 00 00 00 00 EB 29 [26] 59 9C 81 C1 E2 FF FF FF EB 01 ?? 9D FF E1 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PEiDBundlev102v103DLLBoBBobSoft : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 83 7C 24 08 01 0F 85 [4] 60 E8 9C 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 41 00 08 00 39 00 08 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 00 80 00 00 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule FreeJoinerSmallbuild023GlOFF : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E8 E1 FD FF FF 6A 00 E8 0C 00 00 00 FF 25 78 10 40 00 FF 25 7C 10 40 00 FF 25 80 10 40 00 FF 25 84 10 40 00 FF 25 88 10 40 00 FF 25 8C 10 40 00 FF 25 90 10 40 00 FF 25 94 10 40 00 FF 25 98 10 40 00 FF 25 9C 10 40 00 FF 25 A0 10 40 00 FF 25 A4 10 40 00 FF 25 AC 10 40 00 }

	condition:
		$a0 at pe.entry_point
}

rule PrivatePersonalPackerPPP102ConquestOfTroycom : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E8 17 00 00 00 E8 68 00 00 00 FF 35 2C 37 00 10 E8 ED 01 00 00 6A 00 E8 2E 04 00 00 E8 41 04 00 00 A3 74 37 00 10 6A 64 E8 5F 04 00 00 E8 30 04 00 00 A3 78 37 00 10 6A 64 E8 4E 04 00 00 E8 1F 04 00 00 A3 7C 37 00 10 A1 74 37 00 10 8B 1D 78 37 00 10 2B D8 8B 0D 7C 37 00 10 2B C8 83 FB 64 73 0F 81 F9 C8 00 00 00 73 07 6A 00 E8 D9 03 00 00 C3 6A 0A 6A 07 6A 00 E8 D3 03 00 00 A3 20 37 00 10 50 6A 00 E8 DE 03 00 00 A3 24 37 00 10 FF 35 20 37 00 10 6A 00 E8 EA 03 00 00 A3 30 37 00 10 FF 35 24 37 00 10 E8 C2 03 00 00 A3 28 37 00 10 8B 0D 30 37 00 10 8B 3D 28 37 00 10 EB 09 49 C0 04 39 55 80 34 39 24 0B C9 }

	condition:
		$a0
}

import "pe"

rule DIETv102bv110av120 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { BE [2] BF [2] B9 [2] 3B FC 72 ?? B4 4C CD 21 FD F3 A5 FC }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule UPXECLiPSElayer : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { B8 [4] B9 [4] 33 D2 EB 01 0F 56 EB 01 0F E8 03 00 00 00 EB 01 0F EB 01 0F 5E EB 01 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule Obsidium1334ObsidiumSoftware : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB 02 [2] E8 29 00 00 00 EB 03 [3] EB 02 [2] 8B 54 24 0C EB 03 [3] 83 82 B8 00 00 00 25 EB 02 [2] 33 C0 EB 02 [2] C3 EB 03 [3] EB 01 ?? 64 67 FF 36 00 00 EB 02 [2] 64 67 89 26 00 00 EB 02 [2] EB 04 [4] 50 EB 02 [2] 33 }
		$a1 = { EB 02 [2] E8 29 00 00 00 EB 03 [3] EB 02 [2] 8B 54 24 0C EB 03 [3] 83 82 B8 00 00 00 25 EB 02 [2] 33 C0 EB 02 [2] C3 EB 03 [3] EB 01 ?? 64 67 FF 36 00 00 EB 02 [2] 64 67 89 26 00 00 EB 02 [2] EB 04 [4] 50 EB 02 [2] 33 C0 EB 01 ?? 8B 00 EB 04 [4] C3 EB 03 [3] E9 FA 00 00 00 EB 02 [2] E8 D5 FF FF FF EB 02 [2] EB 03 [3] 58 EB 02 [2] EB 03 [3] 64 67 8F 06 00 00 EB 03 }

	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point
}

import "pe"

rule PKLITEv150Devicedrivercompression : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { B4 09 BA 14 01 CD 21 B8 00 4C CD 21 F8 9C 50 53 51 52 56 57 55 1E 06 BB }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule VxGrazie883 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 1E 0E 1F 50 06 BF 70 03 B4 1A BA 70 03 CD 21 B4 47 B2 00 BE 32 04 CD 21 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PROTECTEXECOMv60 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 1E B4 30 CD 21 3C 02 73 ?? CD 20 BE [2] E8 }

	condition:
		$a0 at pe.entry_point
}

rule ENIGMAProtectorSukhovVladimir : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 45 6E 69 67 6D 61 20 70 72 6F 74 65 63 74 6F 72 20 76 31 }

	condition:
		$a0
}

import "pe"

rule CRYPToCRACksPEProtectorV093LukasFleischer : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 5B 81 E3 00 FF FF FF 66 81 3B 4D 5A 75 33 8B F3 03 73 3C 81 3E 50 45 00 00 75 26 0F B7 46 18 8B C8 69 C0 AD 0B 00 00 F7 E0 2D AB 5D 41 4B 69 C9 DE C0 00 00 03 C1 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PECompactv147v150 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB 06 68 [4] C3 9C 60 E8 02 [3] 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F A0 40 ?? 87 DD 8B 85 A6 A0 40 ?? 01 85 03 A0 40 ?? 66 C7 85 ?? A0 40 ?? 90 90 01 85 9E A0 40 ?? BB 5B 12 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PocketPCMIB : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E8 FF BD 27 14 00 BF AF 18 00 A4 AF 1C 00 A5 AF 20 00 A6 AF 24 00 A7 AF [3] 0C 00 00 00 00 18 00 A4 8F 1C 00 A5 8F 20 00 A6 8F [3] 0C 24 00 A7 8F [3] 0C 25 20 40 00 14 00 BF 8F 08 00 E0 03 18 00 BD 27 ?? FF BD 27 18 00 ?? AF ?? 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule WWPACKv305c4ExtractableVirusShield : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 03 05 40 1A B8 [2] 8C CA 03 D0 8C C9 81 C1 [2] 51 B9 [2] 51 06 06 B1 ?? 51 8C D3 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule VxNoon1163 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E8 [2] 5B 50 56 B4 CB CD 21 3C 07 [2] 81 [3] 2E [2] 4D 5A [2] BF 00 01 89 DE FC }

	condition:
		$a0 at pe.entry_point
}

rule PuNkMoD1xPuNkDuDe : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 94 B9 [2] 00 00 BC [4] 80 34 0C }

	condition:
		$a0
}

import "pe"

rule PECrypt32Consolev10v101v102 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E8 00 00 00 00 5B 83 EB 05 EB 04 52 4E 44 21 EB 02 CD 20 EB }

	condition:
		$a0 at pe.entry_point
}

rule InnoSetupModulev2018 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 83 C4 B8 53 56 57 33 C0 89 45 F0 89 45 BC 89 45 B8 E8 73 71 FF FF E8 DA 85 FF FF E8 81 A7 FF FF E8 C8 }

	condition:
		$a0
}

import "pe"

rule Nakedbind10nakedcrew : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 64 8B 38 48 8B C8 F2 AF AF 8B 1F 66 33 DB 66 81 3B 4D 5A 74 08 81 EB 00 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule NsPacKV31LiuXingPing : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 9C 60 E8 00 00 00 00 5D 83 ED 07 8D 9D [4] 8A 03 3C 00 74 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule AntiVirusVaccinev103 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { FA 33 DB B9 [2] 0E 1F 33 F6 FC AD 35 [2] 03 D8 E2 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule VxKuku448 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { AE 75 ED E2 F8 89 3E [2] BA [2] 0E 07 BF [2] EB }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule ASProtectv12xNewStrain : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 68 01 [3] E8 01 [3] C3 C3 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule SimpleUPXCryptorv3042005OnelayerencryptionMANtiCORE : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 B8 [3] 00 B9 ?? 01 00 00 80 34 08 ?? E2 FA 61 68 [3] 00 C3 }

	condition:
		$a0 at pe.entry_point
}

rule AntiDote10Demo12SISTeam : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 00 00 00 00 09 01 47 65 74 43 6F 6D 6D 61 6E 64 4C 69 6E 65 41 00 DB 01 47 65 74 56 65 72 73 69 6F 6E 45 78 41 00 73 01 47 65 74 4D 6F 64 75 6C 65 46 69 6C 65 4E 61 6D 65 41 00 00 7A 03 57 61 69 74 46 6F 72 53 69 6E 67 6C 65 4F 62 6A 65 63 74 00 BF 02 52 65 73 75 6D 65 54 68 72 65 61 64 00 00 29 03 53 65 74 54 68 72 65 61 64 43 6F 6E 74 65 78 74 00 00 94 03 57 72 69 74 65 50 72 6F 63 65 73 73 4D 65 6D 6F 72 79 00 00 6B 03 56 69 72 74 75 61 6C 41 6C 6C 6F 63 45 78 00 00 A6 02 52 65 61 64 50 72 6F 63 65 73 73 4D 65 6D 6F 72 79 00 CA 01 47 65 74 54 68 72 65 61 64 43 6F 6E 74 65 78 74 00 00 62 00 43 72 65 61 74 65 50 72 6F 63 65 73 73 41 00 00 4B 45 52 4E 45 4C 33 32 2E 64 6C 6C }

	condition:
		$a0
}

import "pe"

rule FSGv110EngbartxtWinRARSFX : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 80 E9 A1 C1 C1 13 68 E4 16 75 46 C1 C1 05 5E EB 01 9D 68 64 86 37 46 EB 02 8C E0 5F F7 D0 }
		$a1 = { EB 01 02 EB 02 CD 20 B8 80 ?? 42 00 EB 01 55 BE F4 00 00 00 13 DF 13 D8 0F B6 38 D1 F3 F7 }

	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point
}

import "pe"

rule BJFntv11b : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB 01 EA 9C EB 01 EA 53 EB 01 EA 51 EB 01 EA 52 EB 01 EA 56 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule ThinstallEmbedded26202623Jitit : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E8 00 00 00 00 58 BB AC 1E 00 00 2B C3 50 68 [4] 68 B0 21 00 00 68 C4 00 00 00 E8 C3 FE FF FF E9 99 FF FF FF 00 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule SLVc0deProtector11xSLVICU : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E8 00 00 00 00 58 C6 00 EB C6 40 01 08 FF E0 E9 4C [2] 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule RJoinerbyVaskaSignfrompinch250320071700 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E8 03 FD FF FF 6A 00 E8 0C 00 00 00 FF 25 6C 10 40 00 FF 25 70 10 40 00 FF 25 74 10 40 00 FF 25 78 10 40 00 FF 25 7C 10 40 00 FF 25 80 10 40 00 FF 25 84 10 40 00 FF 25 88 10 40 00 FF 25 8C 10 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule AverCryptor10os1r1s : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED 75 17 40 00 8B BD 9C 18 40 00 8B 8D A4 18 40 00 B8 BC 18 40 00 03 C5 80 30 05 83 F9 00 74 71 81 7F 1C AB 00 00 00 75 62 8B 57 0C 03 95 A0 18 40 00 33 C0 51 33 C9 66 B9 FA 00 66 83 F9 00 74 49 8B 57 0C 03 95 A0 18 40 00 8B 85 A8 18 40 00 83 F8 02 75 06 81 C2 00 02 00 00 51 8B 4F 10 83 F8 02 75 06 81 E9 00 02 00 00 57 BF C8 00 00 00 8B F1 E8 27 00 00 00 8B C8 5F B8 BC 18 40 00 03 C5 E8 24 00 00 00 59 49 EB B1 59 83 C7 28 49 EB 8A 8B 85 98 18 40 00 89 44 24 1C 61 FF E0 56 57 4F F7 D7 23 F7 8B C6 5F 5E C3 }

	condition:
		$a0 at pe.entry_point
}

rule nSpackV23LiuXingPing : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 9C 60 70 61 63 6B 24 40 }

	condition:
		$a0
}

import "pe"

rule SENDebugProtector : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { BB [4] 00 [5] 29 [2] 4E E8 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule xPEP03xxIkUg : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 53 56 51 52 57 E8 16 00 00 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule AntiDote14SESISTeam : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 68 90 03 00 00 E8 C6 FD FF FF 68 90 03 00 00 E8 BC FD FF FF 68 90 03 00 00 E8 B2 FD FF FF 50 E8 AC FD FF FF 50 E8 A6 FD FF FF 68 69 D6 00 00 E8 9C FD FF FF 50 E8 96 FD FF FF 50 E8 90 FD FF FF 83 C4 20 E8 78 FF FF FF 84 C0 74 4F 68 04 01 00 00 68 10 22 60 00 6A 00 FF 15 08 10 60 00 68 90 03 00 00 E8 68 FD FF FF 68 69 D6 00 00 E8 5E FD FF FF 50 E8 58 FD FF FF 50 E8 52 FD FF FF E8 DD FE FF FF 50 68 A4 10 60 00 68 94 10 60 00 68 10 22 60 00 E8 58 FD FF FF 83 C4 20 33 C0 C2 10 00 8B 4C 24 08 56 8B 74 24 08 33 D2 8B C6 F7 F1 8B C6 85 D2 74 08 33 D2 F7 F1 40 0F AF C1 5E C3 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule NsPack30NorthStar : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 9C 60 E8 00 00 00 00 5D B8 07 00 00 00 2B E8 8D B5 [2] FF FF 66 8B 06 66 83 F8 00 74 15 8B F5 8D B5 [2] FF FF 66 8B 06 66 83 F8 01 0F 84 42 02 00 00 C6 06 01 8B D5 2B 95 [2] FF FF 89 95 [2] FF FF 01 95 [2] FF FF 8D B5 [2] FF FF 01 16 60 6A 40 68 00 10 00 00 68 00 10 00 00 6A 00 FF 95 [2] FF FF 85 C0 0F 84 6A 03 00 00 89 85 [2] FF FF E8 00 00 00 00 5B B9 68 03 00 00 03 D9 50 53 E8 B1 02 00 00 61 8B 36 8B FD 03 BD [2] FF FF 8B DF 83 3F 00 75 0A 83 C7 04 B9 00 00 00 00 EB 16 B9 01 00 00 00 03 3B 83 C3 04 83 3B 00 74 36 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule ORiENV212FisunAV : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E9 5D 01 00 00 CE D1 CE CD 0D }

	condition:
		$a0 at pe.entry_point
}

rule NsPackv23NorthStar : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 9C 60 E8 00 00 00 00 5D B8 07 00 00 00 2B E8 8D B5 [2] FF FF 8B 06 83 F8 00 74 11 8D B5 [2] FF FF 8B 06 83 F8 01 0F 84 4B 02 00 00 C7 06 01 00 00 00 8B D5 8B 85 [2] FF FF 2B D0 89 95 [2] FF FF 01 95 [2] FF FF 8D B5 [2] FF FF 01 16 8B 36 8B FD }
		$a1 = { 9C 60 E8 00 00 00 00 5D B8 07 00 00 00 2B E8 8D B5 [2] FF FF 8B 06 83 F8 00 74 11 8D B5 [2] FF FF 8B 06 83 F8 01 0F 84 4B 02 00 00 C7 06 01 00 00 00 8B D5 8B 85 [2] FF FF 2B D0 89 95 [2] FF FF 01 95 [2] FF FF 8D B5 [2] FF FF 01 16 8B 36 8B FD 60 6A 40 68 00 10 00 00 68 00 10 00 00 6A 00 FF 95 [2] FF FF 85 C0 0F 84 56 03 00 00 89 85 [2] FF FF E8 00 00 00 00 5B B9 54 03 00 00 03 D9 50 53 E8 9D 02 00 00 61 }

	condition:
		$a0 or $a1
}

import "pe"

rule ObsidiumV1342ObsidiumSoftware : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB 02 [2] E8 26 00 00 00 EB 03 [3] EB 01 ?? 8B 54 24 0C EB 02 [2] 83 82 B8 00 00 00 24 EB 03 [3] 33 C0 EB 01 ?? C3 EB 02 [2] EB 02 [2] 64 67 FF 36 00 00 EB 03 [3] 64 67 89 26 00 00 EB 03 [3] EB 03 [3] 50 EB 04 [4] 33 C0 EB 03 [3] 8B 00 EB 03 [3] C3 EB 03 [3] E9 FA 00 00 00 EB 03 [3] E8 D5 FF FF FF EB 01 ?? EB 03 [3] 58 EB 04 [4] EB 04 [4] 64 67 8F 06 00 00 EB 04 [4] 83 C4 04 EB 01 ?? E8 C3 27 00 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule SplashBitmapv100WithUnpackCodeBoBBobsoft : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E8 00 00 00 00 60 8B 6C 24 20 55 81 ED [4] 8D BD [4] 8D 8D [4] 29 F9 31 C0 FC F3 AA 8B 04 24 48 66 25 00 F0 66 81 38 4D 5A 75 F4 8B 48 3C 81 3C 01 50 45 00 00 75 E8 89 85 [4] 6A 40 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule KBySV028shoooo : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 68 [4] E8 01 00 00 00 C3 C3 60 8B 74 24 24 8B 7C 24 28 FC B2 80 33 DB A4 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule ObsidiumV12XObsidiumSoftware : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E8 0E 00 00 00 33 C0 8B 54 24 0C 83 82 B8 00 00 00 0D C3 64 67 FF 36 00 00 64 67 89 26 00 00 50 33 C0 8B 00 C3 E9 FA 00 00 00 E8 D5 FF FF FF 58 64 67 8F 06 00 00 83 C4 04 E8 2B 13 00 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule NsPackV13LiuXingPing : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 9C 60 E8 00 00 00 00 5D B8 B3 85 40 00 2D AC 85 40 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PseudoSigner01PENinja131Anorganix : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 E9 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule Obsidiumv1300ObsidiumSoftware : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB 04 25 80 34 CA E8 29 00 00 00 EB 02 C1 81 EB 01 3A 8B 54 24 0C EB 02 32 92 83 82 B8 00 00 00 22 EB 02 F2 7F 33 C0 EB 04 65 7E 14 79 C3 EB 04 05 AD 7F 45 EB 04 05 65 0B E8 64 67 FF 36 00 00 EB 04 0D F6 A8 7F 64 67 89 26 00 00 EB 04 8D 68 C7 FB EB 01 6B }
		$a1 = { EB 04 25 80 34 CA E8 29 00 00 00 EB 02 C1 81 EB 01 3A 8B 54 24 0C EB 02 32 92 83 82 B8 00 00 00 22 EB 02 F2 7F 33 C0 EB 04 65 7E 14 79 C3 EB 04 05 AD 7F 45 EB 04 05 65 0B E8 64 67 FF 36 00 00 EB 04 0D F6 A8 7F 64 67 89 26 00 00 EB 04 8D 68 C7 FB EB 01 6B 50 EB 03 8A 0B 93 33 C0 EB 02 28 B9 8B 00 EB 01 04 C3 EB 04 65 B3 54 0A E9 FA 00 00 00 EB 01 A2 E8 D5 FF FF FF EB 02 2B 49 EB 03 7C 3E 76 58 EB 04 B8 94 92 56 EB 01 72 64 67 8F 06 00 00 EB 02 23 72 83 C4 04 EB 02 A9 CB E8 47 26 00 00 }

	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point
}

import "pe"

rule Feokt : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 89 25 A8 11 40 00 BF [3] 00 31 C0 B9 [3] 00 29 F9 FC F3 AA [61] E8 }

	condition:
		$a0 at pe.entry_point
}

rule NTkrnlSecureSuite01015NTkrnlSoftware : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 00 00 00 00 00 00 00 00 00 00 00 00 34 10 00 00 28 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 [8] 00 00 00 00 4B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 68 [4] E8 01 00 00 00 C3 C3 }

	condition:
		$a0
}

import "pe"

rule PEPROTECT09 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E9 CF 00 00 00 0D 0A 0D 0A C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule EXERefactorV01random : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 81 EC 90 0B 00 00 53 56 57 E9 58 8C 01 00 55 53 43 41 54 49 4F 4E }

	condition:
		$a0 at pe.entry_point
}

rule CrunchPEv40 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB 10 [16] 55 E8 [4] 5D 81 ED 18 [3] 8B C5 55 60 9C 2B 85 E9 06 [2] 89 85 E1 06 [2] FF 74 24 2C E8 BB 01 00 00 0F 82 92 05 00 00 E8 F1 03 00 00 49 0F 88 86 05 00 00 68 6C D9 B2 96 33 C0 50 E8 24 }

	condition:
		$a0
}

import "pe"

rule NullsoftPIMPInstallSystemv1x : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 83 EC 5C 53 55 56 57 FF 15 [3] 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule Pohernah100byKas : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 58 60 E8 00 00 00 00 5D 81 ED 20 25 40 00 8B BD 86 25 40 00 8B 8D 8E 25 40 00 6B C0 05 83 F0 04 89 85 92 25 40 00 83 F9 00 74 2D 81 7F 1C AB 00 00 00 75 1E 8B 77 0C 03 B5 8A 25 40 00 31 C0 3B 47 10 74 0E 50 8B 85 92 25 40 00 30 06 58 40 46 EB ED 83 C7 28 49 EB CE 8B 85 82 25 40 00 89 44 24 1C 61 FF E0 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule dUP2diablo2oo2 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E8 [4] E8 [4] 8B F0 6A 00 68 [4] 56 E8 [4] A2 [4] 6A 00 68 [4] 56 E8 [4] A2 [4] 6A 00 68 [4] 56 E8 [4] A2 [4] 68 [4] 68 [4] 56 E8 [4] 3C 01 75 19 BE [4] 68 00 02 00 00 56 68 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PseudoSigner01ASPack2xxHeuristicAnorganix : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 90 90 90 90 68 [4] 67 64 FF 36 00 00 67 64 89 26 00 00 F1 90 90 90 90 A8 03 00 00 61 75 08 B8 01 00 00 00 C2 0C 00 68 00 00 00 00 C3 8B 85 26 04 00 00 8D 8D 3B 04 00 00 51 50 FF 95 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule eXpressorv145CGSoftLabs : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 83 EC 58 53 56 57 83 65 DC 00 F3 EB 0C }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule hmimysProtectv10 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E8 BA 00 00 00 ?? 00 00 00 00 [2] 00 00 10 40 00 [3] 00 [3] 00 00 [2] 00 [3] 00 [3] 00 [3] 00 [3] 00 [3] 00 ?? 00 00 00 00 00 00 00 [3] 00 00 00 00 00 00 00 00 00 [3] 00 [3] 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 [3] 00 [3] 00 [3] 00 [3] 00 00 00 00 00 4B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 56 69 72 74 75 61 6C 46 72 65 65 00 00 00 56 69 72 74 75 61 6C 41 6C 6C 6F 63 00 5E 83 C6 64 AD 50 AD 50 83 EE 6C AD 50 AD 50 AD 50 AD 50 AD 50 E8 E7 07 00 00 AD 8B DE 8B F0 83 C3 44 AD 85 C0 74 32 8B F8 56 FF 13 8B E8 AC 84 C0 75 FB AC 84 C0 74 EA 4E AD A9 }
		$a1 = { E8 BA 00 00 00 ?? 00 00 00 00 [2] 00 00 10 40 00 [3] 00 [3] 00 00 [2] 00 [3] 00 [3] 00 [3] 00 [3] 00 [3] 00 ?? 00 00 00 00 00 00 00 [3] 00 00 00 00 00 00 00 00 00 [3] 00 [3] 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 [3] 00 [3] 00 [3] 00 [3] 00 00 00 00 00 4B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 56 69 72 74 75 61 6C 46 72 65 65 00 00 00 56 69 72 74 75 61 6C 41 6C 6C 6F 63 00 5E 83 C6 64 AD 50 AD 50 83 EE 6C AD 50 AD 50 AD 50 AD 50 AD 50 E8 E7 07 00 00 AD 8B DE 8B F0 83 C3 44 AD 85 C0 74 32 8B F8 56 FF 13 8B E8 AC 84 C0 75 FB AC 84 C0 74 EA 4E AD A9 00 00 00 }

	condition:
		$a0 at pe.entry_point or $a1
}

import "pe"

rule VProtectorV10Evcasm : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB 0A 5B 56 50 72 6F 74 65 63 74 5D E8 24 00 00 00 8B 44 24 04 8B 00 3D 04 00 00 80 75 08 8B 64 24 08 EB 04 58 EB 0C E9 64 8F 05 00 00 00 00 74 F3 75 F1 EB 24 64 FF 35 00 00 00 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PseudoSigner01LCCWin32DLLAnorganix : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 89 E5 53 56 57 83 7D 0C 01 75 05 E8 17 90 90 90 FF 75 10 FF 75 0C FF 75 08 A1 [4] E9 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule CodeCryptv014b : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E9 C5 02 00 00 EB 02 83 3D 58 EB 02 FF 1D 5B EB 02 0F C7 5F }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PellesC450DLLX86CRTLIB : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 89 E5 53 56 57 8B 5D 0C 8B 75 10 85 DB 75 0D 83 3D [4] 00 75 04 31 C0 EB 57 83 FB 01 74 05 83 FB 02 75 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule EEXEVersion112 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { B4 30 CD 21 3C 03 73 ?? BA 1F 00 0E 1F B4 09 CD 21 B8 FF 4C CD 21 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule FSGv120EngdulekxtMASM32TASM32 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 33 C2 2C FB 8D 3D 7E 45 B4 80 E8 02 00 00 00 8A 45 58 68 02 ?? 8C 7F EB 02 CD 20 5E 80 C9 16 03 F7 EB 02 40 B0 68 F4 00 00 00 80 F1 2C 5B C1 E9 05 0F B6 C9 8A 16 0F B6 C9 0F BF C7 2A D3 E8 02 00 00 00 99 4C 58 80 EA 53 C1 C9 16 2A D3 E8 02 00 00 00 9D CE }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PEDiminisherv01Teraphy : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 53 51 52 56 57 55 E8 00 00 00 00 5D 8B D5 81 ED A2 30 40 00 2B 95 91 33 40 00 81 EA 0B 00 00 00 89 95 9A 33 40 00 80 BD 99 33 40 00 00 74 50 E8 02 01 00 00 8B FD 8D 9D 9A 33 40 00 8B 1B 8D 87 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PseudoSigner02VBOX43MTEAnorganix : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 0B C0 0B C0 0B C0 0B C0 0B C0 0B C0 0B C0 0B C0 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule SEAAXE : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { FC BC [2] 0E 1F E8 [2] 26 A1 [2] 8B 1E [2] 2B C3 8E C0 B1 ?? D3 E3 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule UpackV010V011Dwing : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { BE [4] AD 8B F8 95 A5 33 C0 33 C9 AB 48 AB F7 D8 B1 ?? F3 AB C1 E0 ?? B5 ?? F3 AB AD 50 97 51 AD 87 F5 58 8D 54 86 5C FF D5 72 5A 2C ?? 73 ?? B0 ?? 3C ?? 72 02 2C ?? 50 0F B6 5F FF C1 E3 ?? B3 ?? 8D 1C 5B 8D [6] B0 ?? 67 E3 29 8B D7 2B 56 0C 8A 2A 33 D2 84 E9 0F 95 C6 52 FE C6 8A D0 8D 14 93 FF D5 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule AHTeamEPProtector03fakePCGuard403415FEUERRADER : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 90 [46] 90 FF E0 FC 55 50 E8 00 00 00 00 5D EB 01 E3 60 E8 03 00 00 00 D2 EB 0B 58 EB 01 48 40 EB 01 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule SimplePack111Method1bagieTMX : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 00 00 00 00 5B 8D 5B FA BD 00 00 [2] 8B 7D 3C 8D 74 3D 00 8D BE F8 00 00 00 0F B7 76 06 4E 8B 47 10 09 C0 74 55 0F B7 47 22 09 C0 74 4D 6A 04 68 00 10 00 00 FF 77 10 6A 00 FF 93 38 03 00 00 50 56 57 89 EE 03 77 0C 8B 4F 10 89 C7 89 C8 C1 E9 02 FC }
		$a1 = { 60 E8 00 00 00 00 5B 8D 5B FA BD 00 00 [2] 8B 7D 3C 8D 74 3D 00 8D BE F8 00 00 00 0F B7 76 06 4E 8B 47 10 09 C0 74 55 0F B7 47 22 09 C0 74 4D 6A 04 68 00 10 00 00 FF 77 10 6A 00 FF 93 38 03 00 00 50 56 57 89 EE 03 77 0C 8B 4F 10 89 C7 89 C8 C1 E9 02 FC F3 A5 89 C1 83 E1 03 F3 A4 5F 5E 8B 04 24 89 EA 03 57 0C E8 3F 01 00 00 58 68 00 40 00 00 FF 77 10 50 FF 93 3C 03 00 00 83 C7 28 4E 75 9E BE [4] 09 F6 0F 84 0C 01 00 00 01 EE 8B 4E 0C 09 C9 0F 84 FF 00 00 00 01 E9 89 CF 57 FF 93 30 03 00 00 09 C0 75 3D 6A 04 68 00 10 00 00 68 00 10 00 00 6A 00 FF 93 38 03 00 00 89 C6 8D 83 6F 02 00 00 57 50 56 FF 93 44 03 00 00 6A 10 6A 00 56 6A 00 FF 93 48 03 00 00 89 E5 }

	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point
}

import "pe"

rule MASM32 : Packer PEiD hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 6A ?? 68 00 30 40 00 68 ?? 30 40 00 6A 00 E8 07 00 00 00 6A 00 E8 06 00 00 00 FF 25 08 20 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule SoftDefenderv10v11 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 74 07 75 05 19 32 67 E8 E8 74 1F 75 1D E8 68 39 44 CD ?? 59 9C 50 74 0A 75 08 E8 59 C2 04 ?? 55 8B EC E8 F4 FF FF FF 56 57 53 78 0F 79 0D E8 34 99 47 49 34 33 EF 31 34 52 47 23 68 A2 AF 47 01 59 E8 [4] 58 05 BA 01 [2] 03 C8 74 BE 75 BC E8 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule XtremeProtectorv106 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { B8 [3] 00 B9 75 [2] 00 50 51 E8 05 00 00 00 E9 4A 01 00 00 60 8B 74 24 24 8B 7C 24 28 FC B2 80 8A 06 46 88 07 47 BB 02 00 00 00 02 D2 75 05 8A 16 46 12 D2 73 EA 02 D2 75 05 8A 16 46 12 D2 73 4F 33 C0 02 D2 75 05 8A 16 46 12 D2 0F 83 DF 00 00 00 02 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule VcasmProtector1112vcasm : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB 0B 5B 56 50 72 6F 74 65 63 74 5D }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule Obsidiumv1111 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB 02 [2] E8 E7 1C 00 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule VxEddie1530 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E8 [2] 5E 81 EE [2] FC 2E [4] 4D 5A [2] FA 8B E6 81 C4 [2] FB 3B [5] 2E [4] 50 06 56 1E 33 C0 50 1F C4 [3] 2E [4] 2E }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule KBySV028DLLshoooo : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { B8 [4] BA [4] 03 C2 FF E0 [4] 60 E8 00 00 00 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PEncrypt10JunkCode : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 9C BE 00 10 40 00 8B FE B9 [4] BB 78 56 34 12 AD 33 C3 AB E2 FA 9D 61 E9 [3] FF }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PEPasswordv02SMTSMF : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E8 04 [3] 8B EC 5D C3 33 C0 5D 8B FD 81 ED 33 26 40 ?? 81 EF [4] 83 EF 05 89 AD 88 27 40 ?? 8D 9D 07 29 40 ?? 8D B5 62 28 40 ?? 46 80 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule EncryptPE22006710220061025WFS : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 9C 64 FF 35 00 00 00 00 E8 73 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 [8] 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 [36] 00 00 00 00 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 00 00 47 65 74 54 65 6D 70 50 61 74 68 41 00 00 00 43 72 65 61 74 65 46 69 6C 65 41 00 00 00 43 72 65 61 74 65 46 69 6C 65 4D 61 70 70 69 6E 67 41 00 00 00 4D 61 70 56 69 65 77 4F 66 46 69 6C 65 00 00 00 55 6E 6D 61 70 56 69 65 77 4F 66 46 69 6C 65 00 00 00 43 6C 6F 73 65 48 61 6E 64 6C 65 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 45 78 69 74 50 72 6F 63 65 73 73 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule RCryptorv16Vaska : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 33 D0 68 [4] FF D2 }
		$a1 = { 33 D0 68 [4] FF D2 B8 [4] 3D [4] 74 06 80 30 ?? 40 EB F3 }

	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point
}

rule PEPaCKv10CCopyright1998byANAKiN : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 0D 0A 20 2D 3D FE 20 50 45 2D 50 41 43 4B 20 76 31 2E 30 20 2D FE 2D 20 28 43 29 20 43 6F 70 }

	condition:
		$a0
}

import "pe"

rule YodasProtectorv1032Beta2AshkbizDanehkar : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E8 03 00 00 00 EB 01 ?? BB 55 00 00 00 E8 03 00 00 00 EB 01 ?? E8 8F 00 00 00 E8 03 00 00 00 EB 01 ?? E8 82 00 00 00 E8 03 00 00 00 EB 01 ?? E8 B8 00 00 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule VxMTEnonencrypted : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { F7 D9 80 E1 FE 75 02 49 49 97 A3 [2] 03 C1 24 FE 75 02 48 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PseudoSigner01FSG131Anorganix : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { BE 90 90 90 00 BF 90 90 90 00 BB 90 90 90 00 53 BB 90 90 90 00 B2 80 E9 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule ASPackv212AlexeySolodovnikov : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 }
		$a1 = { 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ED FF FF FF 03 DD 81 EB }

	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point
}

import "pe"

rule Upack022023betaDwing : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 6A 07 BE 88 01 40 00 AD 8B F8 59 95 F3 A5 AD B5 ?? F3 AB AD 50 97 51 58 8D 54 }
		$a1 = { 6A 07 BE 88 01 40 00 AD 8B F8 59 95 F3 A5 AD B5 ?? F3 AB AD 50 97 51 58 8D 54 85 5C FF 16 72 59 2C 03 73 02 B0 00 3C 07 72 02 2C 03 50 0F B6 5F FF C1 E3 ?? B3 00 8D 1C 5B 8D 9C 9D 0C 10 00 00 }
		$a2 = { AD 8B F8 59 95 F3 A5 AD B5 ?? F3 AB AD 50 97 51 58 8D 54 85 5C FF 16 72 ?? 2C 03 73 02 B0 00 3C 07 72 02 2C 03 50 0F B6 5F FF C1 E3 ?? B3 00 8D 1C 5B 8D 9C 9D 0C 10 00 00 }

	condition:
		$a0 or $a1 at pe.entry_point or $a2 at pe.entry_point
}

import "pe"

rule PseudoSigner01CodeLockAnorganix : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 43 4F 44 45 2D 4C 4F 43 4B 2E 4F 43 58 00 01 28 01 50 4B 47 05 4C 3F B4 04 4D 4C 47 4B E9 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PKLITEv100c1 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 2E 8C 1E [2] 8B 1E [2] 8C DA 81 C2 [2] 3B DA 72 ?? 81 EB [2] 83 EB ?? FA 8E D3 BC [2] FB FD BE [2] 8B FE }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule MSLRHv032afakenSPack13emadicius : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 9C 60 E8 00 00 00 00 5D B8 B3 85 40 00 2D AC 85 40 00 2B E8 8D B5 D3 FE FF FF 8B 06 83 F8 00 74 11 8D B5 DF FE FF FF 8B 06 83 F8 01 0F 84 F1 01 00 00 61 9D EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 2B 04 24 74 04 75 02 EB 02 EB 01 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PKLITEv100c2 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { BA [2] A1 [2] 2D [2] 8C CB 81 C3 [2] 3B C3 77 ?? 05 [2] 3B C3 77 ?? B4 09 BA [2] CD 21 CD 20 90 }

	condition:
		$a0 at pe.entry_point
}

rule kkrunchyv017FGiesen : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { FC FF 4D 08 31 D2 8D 7D 30 BE }

	condition:
		$a0
}

import "pe"

rule ACProtectv190gRiscosoftwareInc : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 0F 87 02 00 00 00 1B F8 E8 01 00 00 00 73 83 04 24 06 C3 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule UPX293300LZMAMarkusOberhumerLaszloMolnarJohnReiser : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 BE [4] 8D BE [4] 57 89 E5 8D 9C 24 [4] 31 C0 50 39 DC 75 FB 46 46 53 68 [4] 57 83 C3 04 53 68 [4] 56 83 C3 04 53 50 C7 03 03 00 02 00 90 90 90 90 90 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule Obsidium133720070623ObsidiumSoftware : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB 02 [2] E8 27 00 00 00 EB 03 [3] EB 01 ?? 8B 54 24 0C EB 03 [3] 83 82 B8 00 00 00 23 EB 03 [3] 33 C0 EB 02 [2] C3 EB 01 ?? EB 03 [3] 64 67 FF 36 00 00 EB 04 [4] 64 67 89 26 00 00 EB 01 ?? EB 01 ?? 50 EB 02 [2] 33 C0 EB 01 ?? 8B 00 EB 04 [4] C3 EB 02 [2] E9 FA 00 00 00 EB 04 [4] E8 D5 FF FF FF EB 01 ?? EB 01 ?? 58 EB 04 [4] EB 01 ?? 64 67 8F 06 00 00 EB 02 [2] 83 C4 04 EB 01 ?? E8 F7 26 00 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule ASPackv2000AlexeySolodovnikov : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 70 05 00 00 EB 4C }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule Armadillov4000053SiliconRealmsToolworks : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 6A FF 68 20 8B 4B 00 68 80 E4 48 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF 15 88 31 4B 00 33 D2 8A D4 89 15 A4 A1 4B 00 8B C8 81 E1 FF 00 00 00 89 0D A0 A1 4B 00 C1 E1 08 03 CA 89 0D 9C A1 4B 00 C1 E8 10 A3 98 A1 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule Armadillov160a : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 6A FF 68 98 71 40 00 68 48 2D 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 }

	condition:
		$a0 at pe.entry_point
}

rule ACProtectUltraProtect10X20XRiSco : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 00 00 00 00 00 00 00 00 [12] 00 00 00 00 00 00 00 00 [13] 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 4B 45 52 4E 45 4C 33 32 2E 44 4C 4C 00 [16] 00 00 00 00 55 53 45 52 33 32 2E 44 4C 4C 00 [4] 00 00 00 00 [20] 00 00 00 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 47 65 74 4D 6F 64 75 6C 65 48 61 6E 64 6C 65 41 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 45 78 69 74 50 72 6F 63 65 73 73 00 00 00 4D 65 73 73 61 67 65 42 6F 78 41 00 90 4D 69 6E 65 49 6D 70 6F 72 74 5F 45 6E 64 73 73 00 }

	condition:
		$a0
}

import "pe"

rule Thinstall3035Jtit : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 9C 60 68 53 74 41 6C 68 54 68 49 6E E8 00 00 00 00 58 BB 37 1F 00 00 2B C3 50 68 [4] 68 00 28 00 00 68 04 01 00 00 E8 BA FE FF FF E9 90 FF FF FF CC CC CC CC CC CC CC 55 8B EC 83 C4 F4 FC 53 57 56 8B 75 08 8B 7D 0C C7 45 FC 08 00 00 00 33 DB BA 00 }
		$a1 = { 9C 60 68 53 74 41 6C 68 54 68 49 6E E8 00 00 00 00 58 BB 37 1F 00 00 2B C3 50 68 [4] 68 00 28 00 00 68 04 01 00 00 E8 BA FE FF FF E9 90 FF FF FF CC CC CC CC CC CC CC 55 8B EC 83 C4 F4 FC 53 57 56 8B 75 08 8B 7D 0C C7 45 FC 08 00 00 00 33 DB BA 00 00 00 80 43 33 C0 E8 19 01 00 00 73 0E 8B 4D F8 E8 27 01 00 00 02 45 F7 AA EB E9 E8 04 01 00 00 0F 82 96 00 00 00 E8 F9 00 00 00 73 5B B9 04 00 00 00 E8 05 01 00 00 48 74 DE 0F 89 C6 00 00 00 E8 DF 00 00 00 73 1B 55 BD 00 01 00 00 E8 DF 00 00 00 88 07 47 4D 75 F5 E8 C7 00 00 00 72 E9 5D EB A2 B9 01 00 00 00 E8 D0 00 00 00 83 C0 07 89 45 F8 C6 45 F7 00 83 F8 08 74 89 E8 B1 00 00 00 88 45 F7 E9 7C FF FF FF B9 07 00 00 00 E8 AA 00 00 00 50 33 C9 B1 02 E8 A0 00 00 00 8B C8 41 41 58 0B C0 74 04 8B D8 EB 5E 83 F9 02 74 6A 41 E8 88 00 00 00 89 45 FC E9 48 FF FF FF E8 87 00 00 00 49 E2 09 8B C3 E8 7D 00 00 00 EB 3A 49 8B C1 55 8B 4D FC 8B E8 33 C0 D3 E5 E8 5D 00 00 00 0B C5 5D 8B D8 E8 5F 00 00 00 3D 00 00 01 00 73 14 3D FF 37 00 00 73 0E 3D 7F 02 00 00 73 08 83 F8 7F 77 04 41 41 41 41 56 8B F7 2B F0 F3 A4 5E E9 F0 FE FF FF 33 C0 EB 05 8B C7 2B 45 0C 5E 5F 5B C9 C2 08 00 03 D2 75 08 8B 16 83 C6 04 F9 13 D2 C3 B9 08 00 00 00 E8 01 00 00 00 C3 33 C0 E8 E1 FF FF FF 13 C0 E2 F7 C3 33 C9 41 E8 D4 FF FF FF 13 C9 E8 CD FF FF FF 72 F2 C3 }

	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point
}

import "pe"

rule PENinjav10DzAkRAkerTNT : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { BE 5B 2A 40 00 BF 35 12 00 00 E8 40 12 00 00 3D 22 83 A3 C6 0F 85 67 0F 00 00 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule ThinstallEmbedded19XJitit : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 51 53 56 57 6A 00 6A 00 FF 15 [4] 50 E8 87 FC FF FF 59 59 A1 [4] 8B 40 10 03 05 [4] 89 45 FC 8B 45 FC FF E0 5F 5E 5B C9 C3 00 00 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule EXECryptorv13045 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E8 24 00 00 00 8B 4C 24 0C C7 01 17 00 01 00 C7 81 [7] 31 C0 89 41 14 89 41 18 80 A1 }
		$a1 = { E8 24 [3] 8B 4C 24 0C C7 01 17 ?? 01 ?? C7 81 [7] 31 C0 89 41 14 89 41 18 80 A1 }

	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point
}

import "pe"

rule Obsidium1338ObsidiumSoftware : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB 04 [4] E8 28 00 00 00 EB 01 ?? EB 01 ?? 8B 54 24 0C EB 04 [4] 83 82 B8 00 00 00 ?? EB 04 [4] 33 C0 EB 03 [3] C3 EB 01 ?? EB 01 ?? 64 67 FF 36 00 00 EB 03 [3] 64 67 89 26 00 00 EB 02 [2] EB 01 ?? 50 EB 04 [4] 33 C0 EB 02 [2] 8B 00 EB 03 [3] C3 EB 03 [3] E9 FA 00 00 00 EB 03 [3] E8 D5 FF FF FF EB 02 [2] EB 04 [4] 58 EB 04 [4] EB 02 [2] 64 67 8F 06 00 00 EB 04 [4] 83 C4 04 EB 04 [4] E8 57 27 00 00 }

	condition:
		$a0 at pe.entry_point
}

rule RLPV073betaap0x : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 2E 72 6C 70 00 00 00 00 00 50 00 00 [12] 00 00 00 00 00 00 00 00 00 00 00 00 20 00 00 E0 }

	condition:
		$a0
}

rule yCv13byAshkbizDanehkar : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 81 EC C0 00 00 00 53 56 57 8D BD 40 FF FF FF B9 30 00 00 00 B8 CC CC CC CC F3 AB 60 E8 00 00 00 00 5D 81 ED 84 52 41 00 B9 75 5E 41 00 81 E9 DE 52 41 00 8B D5 81 C2 DE 52 41 00 8D 3A 8B F7 33 C0 EB 04 90 EB 01 C2 AC }

	condition:
		$a0
}

import "pe"

rule PCPECalphapreview : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 53 51 52 56 57 55 E8 00 00 00 00 5D 8B CD 81 ED 33 30 40 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule AlexProtectorv10Alex : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED 06 10 40 00 E8 24 00 00 00 EB 01 E9 8B }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule Shrinkv10 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 50 9C FC BE [2] BF [2] 57 B9 [2] F3 A4 8B [3] BE [2] BF [2] F3 A4 C3 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule AHPack01FEUERRADER : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 68 54 [2] 00 B8 48 [2] 00 FF 10 68 B3 [2] 00 50 B8 44 [2] 00 FF 10 68 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule SentinelSuperProAutomaticProtectionv640Safenet : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 68 [4] 6A 01 6A 00 FF 15 [4] A3 [4] FF 15 [4] 33 C9 3D B7 00 00 00 A1 [4] 0F 94 C1 85 C0 89 0D [4] 0F 85 [4] 55 56 C7 05 [4] 01 00 00 00 FF 15 [4] 01 05 [4] FF 15 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule DxPack10 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 [4] 5D 8B FD 81 ED [4] 2B B9 [4] 81 EF [4] 83 BD [4] ?? 0F 84 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule Pohernah103byKas : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED 2A 27 40 00 31 C0 40 83 F0 06 40 3D 40 1F 00 00 75 07 BE 6A 27 40 00 EB 02 EB EB 8B 85 9E 28 40 00 83 F8 01 75 17 31 C0 01 EE 3D 99 00 00 00 74 0C 8B 8D 86 28 40 00 30 0E 40 46 EB ED [153] 56 57 4F F7 D7 21 FE 89 F0 5F 5E C3 60 83 F0 05 40 90 48 83 F0 05 89 C6 89 D7 60 E8 0B 00 00 00 61 83 C7 08 83 E9 07 E2 F1 61 C3 57 8B 1F 8B 4F 04 68 B9 79 37 9E 5A 42 89 D0 48 C1 E0 05 BF 20 00 00 00 4A 89 DD C1 E5 04 29 E9 8B 6E 08 31 DD 29 E9 89 DD C1 ED 05 31 C5 29 E9 2B 4E 0C 89 CD C1 E5 04 29 EB 8B 2E 31 CD 29 EB 89 CD C1 ED 05 31 C5 29 EB 2B 5E 04 29 D0 4F 75 C8 5F 89 1F 89 4F 04 C3 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule ObsidiumV1258ObsidiumSoftware : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB 01 ?? E8 ?? 00 00 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule nPackv11150200BetaNEOx : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 83 3D 40 [3] 00 75 05 E9 01 00 00 00 C3 E8 41 00 00 00 B8 80 [3] 2B 05 08 [3] A3 3C [2] 00 E8 5E 00 00 00 E8 E0 01 00 00 E8 EC 06 00 00 E8 F7 05 00 00 }

	condition:
		$a0 at pe.entry_point
}

rule PerlApp602ActiveState : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 68 2C EA 40 00 FF D3 83 C4 0C 85 C0 0F 85 CD 00 00 00 6A 09 57 68 20 EA 40 00 FF D3 83 C4 0C 85 C0 75 12 8D 47 09 50 FF 15 1C D1 40 00 59 A3 B8 07 41 00 EB 55 6A 08 57 68 14 EA 40 00 FF D3 83 C4 0C 85 C0 75 11 8D 47 08 50 FF 15 1C D1 40 00 59 89 44 24 10 EB 33 6A 09 57 68 08 EA 40 00 FF D3 83 C4 0C 85 C0 74 22 6A 08 57 68 FC E9 40 00 FF D3 83 C4 0C 85 C0 74 11 6A 0B 57 68 F0 E9 40 00 FF D3 83 C4 0C 85 C0 75 55 }
		$a1 = { 68 9C E1 40 00 FF 15 A4 D0 40 00 85 C0 59 74 0F 50 FF 15 1C D1 40 00 85 C0 59 89 45 FC 75 62 6A 00 8D 45 F8 FF 75 0C F6 45 14 01 50 8D 45 14 50 E8 9B 01 00 00 83 C4 10 85 C0 0F 84 E9 00 00 00 8B 45 F8 83 C0 14 50 FF D6 85 C0 59 89 45 FC 75 0E FF 75 14 FF 15 78 D0 40 00 E9 C9 00 00 00 68 8C E1 40 00 FF 75 14 50 }

	condition:
		$a0 or $a1
}

rule UPXProtectorv10x2 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB [5] 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB }

	condition:
		$a0
}

import "pe"

rule ThinstallEmbedded2501Jitit : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC B8 [4] BB [4] 50 E8 00 00 00 00 58 2D A8 1A 00 00 B9 6D 1A 00 00 BA 21 1B 00 00 BE 00 10 00 00 BF C0 53 00 00 BD F0 1A 00 00 03 E8 81 75 00 [4] 81 75 04 [4] 81 75 08 [4] 81 75 0C [4] 81 75 10 }

	condition:
		$a0 at pe.entry_point
}

rule CodeVirtualizer1310OreansTechnologies : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 9C FC E8 00 00 00 00 5F 81 EF [4] 8B C7 81 C7 [4] 3B 47 2C 75 02 EB 2E 89 47 2C B9 A7 00 00 00 EB 05 01 44 8F ?? 49 0B C9 75 F7 83 7F 40 00 74 15 8B 77 40 03 F0 EB 09 8B 1E 03 D8 01 03 83 C6 04 83 3E 00 75 F2 8B 74 24 24 8B DE 03 F0 B9 01 00 00 00 33 C0 F0 0F B1 4F 30 75 F7 AC }

	condition:
		$a0
}

import "pe"

rule VProtector13Xvcasm : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 00 00 00 00 00 [4] 00 00 00 00 00 00 00 00 [8] 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 [12] 00 00 00 00 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 47 65 74 4D 6F 64 75 6C 65 48 61 6E 64 6C 65 41 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 60 8B B4 24 24 00 00 00 8B BC 24 28 00 00 00 FC C6 C2 80 33 DB A4 C6 C3 02 E8 A9 00 00 00 0F 83 F1 FF FF FF 33 C9 E8 9C 00 00 00 0F 83 2D 00 00 00 33 C0 E8 8F 00 00 00 0F 83 37 00 00 00 C6 C3 02 41 C6 C0 10 E8 7D 00 00 00 10 C0 0F 83 F3 FF FF FF }
		$a1 = { E9 B9 16 00 00 55 8B EC 81 EC 74 04 00 00 57 68 00 00 00 00 68 00 00 C2 14 68 FF FF 00 00 68 [4] 9C 81 [10] 9D 54 FF 14 24 68 00 00 00 00 68 00 00 C2 10 68 [4] 9C 81 [10] 9D 54 FF 14 24 68 00 00 00 00 68 [4] 9C 81 [10] 9D 54 FF 14 24 68 00 00 00 00 68 FF FF C2 10 68 [4] 9C 81 [10] 9D 54 FF 14 24 68 00 00 00 00 68 [4] 9C 81 [10] 9D 54 FF 14 24 68 00 00 00 00 68 00 00 C2 14 68 FF FF 00 00 68 [4] 9C 81 [10] 9D 54 FF 14 24 68 00 00 00 00 68 [4] 9C 81 [10] 9D 54 FF 14 24 68 00 00 00 00 }

	condition:
		$a0 or $a1 at pe.entry_point
}

import "pe"

rule Packman0001bubba : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 00 00 00 00 58 8D A8 ?? FE FF FF 8D 98 [3] FF 8D [2] 01 00 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule SimplePackV11XV12XMethod1bagie : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 00 00 00 00 5B 8D 5B FA BD [4] 8B 7D 3C 8D 74 3D 00 8D BE F8 00 00 00 0F B7 76 06 4E 8B 47 10 09 C0 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PEEncryptv40bJunkCode : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 66 [2] 00 66 83 ?? 00 }

	condition:
		$a0 at pe.entry_point
}

rule PEQuake006forgat : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E8 A5 00 00 00 2D [2] 00 00 00 00 00 00 00 00 00 3D [2] 00 2D [2] 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 4A [2] 00 5B [2] 00 6E [2] 00 00 00 00 00 6B 45 72 4E 65 4C 33 32 2E 64 4C 6C 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 47 65 74 4D 6F 64 75 6C 65 48 61 6E 64 6C 65 41 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 [2] 00 00 56 69 72 74 75 61 6C 41 6C 6C 6F 63 00 00 00 00 00 00 }

	condition:
		$a0
}

import "pe"

rule Kryptonv02 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 8B 0C 24 E9 0A 7C 01 ?? AD 42 40 BD BE 9D 7A 04 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule AHTeamEPProtector03fakePELockNT204FEUERRADER : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 90 [46] 90 FF E0 EB 03 CD 20 C7 1E EB 03 CD 20 EA 9C EB 02 EB 01 EB 01 EB 60 EB 03 CD 20 EB EB 01 EB }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule eXPressorPacK150XCGSoftLabs : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 81 EC [4] 53 56 57 83 A5 [5] F3 EB 0C 65 58 50 72 2D 76 2E 31 2E 35 2E 00 83 7D 0C ?? 75 23 8B 45 08 A3 [4] 6A 04 68 00 10 00 00 68 20 03 00 00 6A 00 FF 15 [4] A3 [4] EB 04 }

	condition:
		$a0 at pe.entry_point
}

rule D1S1Gv11BetaScrambledEXED1N : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E8 07 00 00 00 E8 1E 00 00 00 C3 90 58 89 C2 89 C2 25 00 F0 FF FF 50 83 C0 55 8D 00 FF 30 8D 40 04 FF 30 52 C3 8D 40 00 55 8B EC 83 C4 E8 53 56 57 8B 4D 10 8B 45 08 89 45 F8 8B 45 0C 89 45 F4 8D 41 61 8B 38 8D 41 65 8B 00 03 C7 89 45 FC 8D 41 69 8B 00 03 C7 8D 51 6D 8B 12 03 D7 83 C1 71 8B 09 03 CF 2B CA 72 0A 41 87 D1 80 31 FF 41 4A 75 F9 89 45 F0 EB 71 8B }

	condition:
		$a0
}

import "pe"

rule ReversingLabsProtector074betaAp0x : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 68 00 00 41 00 E8 01 00 00 00 C3 C3 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule ACProtect109gRiscosoftwareInc : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 F9 50 E8 01 00 00 00 7C 58 58 49 50 E8 01 00 00 00 7E 58 58 79 04 66 B9 B8 72 E8 01 00 00 00 7A 83 C4 04 85 C8 EB 01 EB C1 F8 BE 72 03 73 01 74 0F 81 01 00 00 00 F9 EB 01 75 F9 E8 01 00 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule NorthStarPEShrinker13Liuxingping : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 9C 60 E8 00 00 00 00 5D B8 B3 85 40 00 2D AC 85 40 00 2B E8 8D B5 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule eXPressorV13CGSoftLabs : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 83 EC ?? 53 56 57 EB 0C 45 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule FreeJoinerSmallbuild035GlOFF : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 51 33 CB 86 C9 59 E8 9E FD FF FF 66 87 DB 6A 00 E8 0C 00 00 00 FF 25 78 10 40 00 FF 25 7C 10 40 00 FF 25 80 10 40 00 FF 25 84 10 40 00 FF 25 88 10 40 00 FF 25 8C 10 40 00 FF 25 90 10 40 00 FF 25 94 10 40 00 FF 25 98 10 40 00 FF 25 9C 10 40 00 FF 25 A0 10 40 00 FF 25 A4 10 40 00 FF 25 AC 10 40 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule Upack020betaDwing : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { BE 88 01 40 00 AD 8B F8 95 A5 33 C0 33 C9 AB 48 AB F7 D8 B1 04 F3 AB C1 E0 0A B5 ?? F3 AB AD 50 97 51 58 8D 54 85 5C FF 16 72 5A 2C 03 73 02 B0 00 3C 07 72 02 2C 03 50 0F B6 5F FF C1 E3 ?? B3 }

	condition:
		$a0 at pe.entry_point
}

rule UPX20030XMarkusOberhumerLaszloMolnarJohnReiser : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 5E 89 F7 B9 [4] 8A 07 47 2C E8 3C 01 77 F7 80 3F ?? 75 F2 8B 07 8A 5F 04 66 C1 E8 08 C1 C0 10 86 C4 29 F8 80 EB E8 01 F0 89 07 83 C7 05 88 D8 E2 D9 8D [5] 8B 07 09 C0 74 3C 8B 5F 04 8D [6] 01 F3 50 83 C7 08 FF [5] 95 8A 07 47 08 C0 74 DC 89 F9 57 48 F2 AE 55 FF [5] 09 C0 74 07 89 03 83 C3 04 EB E1 FF [5] 8B AE [4] 8D BE 00 F0 FF FF BB 00 10 00 00 50 54 6A 04 53 57 FF D5 8D 87 [4] 80 20 7F 80 60 28 7F 58 50 54 50 53 57 FF D5 58 61 8D 44 24 80 6A 00 39 C4 75 FA 83 EC 80 E9 }

	condition:
		$a0
}

import "pe"

rule WinUpackv039finalByDwingc2005h1 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { BE B0 11 [2] AD 50 FF 76 34 EB 7C 48 01 [2] 0B 01 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 18 10 00 00 10 00 00 00 00 [3] 00 00 [2] 00 10 00 00 00 02 00 00 04 00 00 00 00 00 39 00 04 00 00 00 00 00 00 00 00 [3] 00 02 00 00 00 00 00 00 }

	condition:
		$a0 at pe.entry_point
}

rule UnnamedScrambler12Bp0ke : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 83 C4 D8 53 56 57 33 C0 89 45 D8 89 45 DC 89 45 E0 89 45 E4 89 45 E8 B8 70 3A 40 00 E8 C4 EC FF FF 33 C0 55 68 5C 3F 40 00 64 FF 30 64 89 20 E8 C5 D7 FF FF E8 5C F5 FF FF B8 20 65 40 00 33 C9 BA 04 01 00 00 E8 D3 DB FF FF 68 04 01 00 00 68 20 65 40 00 6A 00 FF 15 10 55 40 00 BA 6C 3F 40 00 B8 14 55 40 00 E8 5A F4 FF FF 85 C0 0F 84 1B 04 00 00 BA 18 55 40 00 8B 0D 14 55 40 00 E8 16 D7 FF FF 8B 05 88 61 40 00 8B D0 B8 54 62 40 00 E8 D4 E3 FF FF B8 54 62 40 00 E8 F2 E2 FF FF 8B D0 B8 18 55 40 00 8B 0D 88 61 40 00 E8 E8 D6 FF FF FF 35 34 62 40 00 FF 35 30 62 40 00 FF 35 3C 62 40 00 FF 35 38 62 40 00 8D 55 E8 A1 88 61 40 00 E8 E3 F0 FF FF 8B 55 E8 }

	condition:
		$a0
}

import "pe"

rule Upack010012betaDwing : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { BE 48 01 40 00 AD 8B F8 95 A5 33 C0 33 C9 AB 48 AB F7 D8 B1 04 F3 AB C1 E0 0A B5 ?? F3 AB AD 50 97 51 AD 87 F5 58 8D 54 86 5C FF D5 72 5A 2C 03 73 02 B0 00 3C 07 72 02 2C 03 50 0F B6 5F FF C1 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PEArmorV07Xhying : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED [4] 8D B5 [4] 55 56 81 C5 [4] 55 C3 }

	condition:
		$a0 at pe.entry_point
}

rule LauncherGeneratorv103 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 68 00 20 40 00 68 10 20 40 00 6A 00 6A 00 6A 20 6A 00 6A 00 6A 00 68 F0 22 40 00 6A 00 E8 93 00 00 00 85 C0 0F 84 7E 00 00 00 B8 00 00 00 00 3B 05 68 20 40 00 74 13 6A ?? 68 60 23 40 00 68 20 23 40 00 6A 00 E8 83 00 00 00 A1 58 20 40 00 3B 05 6C 20 40 00 }

	condition:
		$a0
}

import "pe"

rule yodasProtector102103AshkbizDanehkar : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E8 03 00 00 00 EB 01 ?? BB 55 00 00 00 E8 03 00 00 00 EB 01 ?? E8 8F 00 00 00 E8 03 00 00 00 EB 01 ?? E8 82 00 00 00 E8 03 00 00 00 EB 01 ?? E8 B8 00 00 00 E8 03 00 00 00 EB 01 ?? E8 AB 00 00 }

	condition:
		$a0 at pe.entry_point
}

rule NakedPacker10byBigBoote : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 FC 0F B6 05 34 [3] 85 C0 75 31 B8 50 [3] 2B 05 04 [3] A3 30 [3] A1 00 [3] 03 05 30 [3] A3 38 [3] E8 9A 00 00 00 A3 50 [3] C6 05 34 [3] 01 83 3D 50 [3] 00 75 07 61 FF 25 38 [3] 61 FF 74 24 04 6A 00 FF 15 44 [3] 50 FF 15 40 [3] C3 FF 74 24 04 6A 00 FF 15 44 [3] 50 FF 15 48 [3] C3 8B 4C 24 04 56 8B 74 24 10 57 85 F6 8B F9 74 0D 8B 54 24 10 8A 02 88 01 }

	condition:
		$a0
}

import "pe"

rule tElockv080 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 F9 11 00 00 C3 83 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PseudoSigner01YodasProtector102Anorganix : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E8 03 00 00 00 EB 01 90 90 E9 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule VProtector11Xvcasm : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB 0B 5B 56 50 72 6F 74 65 63 74 5D 00 E8 24 00 00 00 8B 44 24 04 8B 00 3D 04 00 00 80 75 08 8B 64 24 08 EB 04 58 EB 0C E9 64 8F 05 00 00 00 00 74 F3 75 F1 EB 24 64 FF 35 00 00 00 00 EB 12 FF 9C 74 03 75 01 E9 81 0C 24 00 01 00 00 9D 90 EB F4 64 89 25 00 00 00 00 EB E6 E8 16 00 00 00 8B 5C 24 0C 8B A3 C4 00 00 00 64 8F 05 00 00 00 00 83 C4 04 EB 14 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C9 99 F7 F1 E9 E8 03 00 00 00 C7 84 00 58 EB 01 E9 83 C0 07 50 C3 FF 35 E8 16 00 00 00 8B 5C 24 0C 8B A3 C4 00 00 00 64 8F 05 00 00 00 00 83 C4 04 EB 14 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C9 99 F7 F1 E9 E8 03 00 00 00 C7 84 00 58 EB 01 E9 83 C0 07 50 C3 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule FSGv110EngdulekxtMASM32 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB 01 DB E8 02 00 00 00 86 43 5E 8D 1D D0 75 CF 83 C1 EE 1D 68 50 ?? 8F 83 EB 02 3D 0F 5A }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule Pohernah102byKas : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED DE 26 40 00 8B BD 05 28 40 00 8B 8D 0D 28 40 00 B8 25 28 40 00 01 E8 80 30 05 83 F9 00 74 71 81 7F 1C AB 00 00 00 75 62 8B 57 0C 03 95 09 28 40 00 31 C0 51 31 C9 66 B9 F7 00 66 83 F9 00 74 49 8B 57 0C 03 95 09 28 40 00 8B 85 11 28 40 00 83 F8 02 75 06 81 C2 00 02 00 00 51 8B 4F 10 83 F8 02 75 06 81 E9 00 02 00 00 57 BF C8 00 00 00 89 CE E8 27 00 00 00 89 C1 5F B8 25 28 40 00 01 E8 E8 24 00 00 00 59 49 EB B1 59 83 C7 28 49 EB 8A 8B 85 01 28 40 00 89 44 24 1C 61 FF E0 56 57 4F F7 D7 21 FE 89 F0 5F 5E C3 60 83 F0 05 40 90 48 83 F0 05 89 C6 89 D7 60 E8 0B 00 00 00 61 83 C7 08 83 E9 07 E2 F1 61 C3 57 8B 1F 8B 4F 04 68 B9 79 37 9E 5A 42 89 D0 48 C1 E0 05 BF 20 00 00 00 4A 89 DD C1 E5 04 29 E9 8B 6E 08 31 DD 29 E9 89 DD C1 ED 05 31 C5 29 E9 2B 4E 0C 89 CD C1 E5 04 29 EB 8B 2E 31 CD 29 EB 89 CD C1 ED 05 31 C5 29 EB 2B 5E 04 29 D0 4F 75 C8 5F 89 1F 89 4F 04 C3 }

	condition:
		$a0 at pe.entry_point
}

rule ActiveMARK5xTrymediaSystemsInc : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 20 2D 2D 4D 50 52 4D 4D 47 56 41 2D 2D 00 75 73 65 72 33 32 2E 64 6C 6C 00 4D 65 73 73 61 67 65 42 6F 78 41 00 54 68 69 73 20 61 70 70 6C 69 63 61 74 69 6F 6E 20 63 61 6E 6E 6F 74 20 72 75 6E 20 77 69 74 68 20 61 6E 20 61 63 74 69 76 65 20 64 65 62 75 67 }

	condition:
		$a0
}

import "pe"

rule RCryptorv20HideEPVaska : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { F7 D1 83 F1 FF 6A 00 F7 D1 83 F1 FF 81 04 24 DC 20 ?? 00 F7 D1 83 F1 FF E8 00 00 00 00 F7 D1 83 F1 FF C3 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule Armadillov172v173 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 6A FF 68 E8 C1 [2] 68 F4 86 [2] 64 A1 [4] 50 64 89 25 [4] 83 EC 58 }

	condition:
		$a0 at pe.entry_point
}

rule AsCryptv01SToRM2 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 80 [3] 83 [4] 90 90 90 83 [2] E2 }

	condition:
		$a0
}

rule AsCryptv01SToRM3 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 80 [3] 83 [4] 90 90 90 51 [3] 01 00 00 00 83 [2] E2 }

	condition:
		$a0
}

import "pe"

rule ASProtectV2XDLLAlexeySolodovnikov : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 03 00 00 00 E9 [2] 5D 45 55 C3 E8 01 00 00 00 EB 5D BB [4] 03 DD }

	condition:
		$a0 at pe.entry_point
}

rule AsCryptv01SToRM4 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 80 [3] 83 [4] 90 90 90 E2 }

	condition:
		$a0
}

import "pe"

rule yzpack20UsAr : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 25 [4] 61 87 CC 55 45 45 55 81 ED CA 00 00 00 55 A4 B3 02 FF 14 24 73 F8 33 C9 FF 14 24 73 18 33 C0 FF 14 24 73 1F B3 02 41 B0 10 FF 14 24 12 C0 73 F9 75 3C AA EB DC FF 54 24 04 2B CB 75 0F FF 54 24 08 EB 27 AC D1 E8 74 30 13 C9 EB 1B 91 48 C1 E0 08 AC FF 54 24 08 3D 00 7D 00 00 73 0A 80 FC 05 73 06 83 F8 7F 77 02 41 41 95 8B C5 B3 01 56 8B F7 2B F0 F3 A4 5E EB 99 BD [4] FF 65 28 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PasswordprotectormySMT : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E8 [4] 5D 8B FD 81 [5] 81 [5] 83 [2] 89 [5] 8D [5] 8D [5] 46 80 [2] 74 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule ObsidiumV1258V133XObsidiumSoftware : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB 01 ?? E8 ?? 00 00 00 EB 02 [2] EB }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule ReflexiveArcadeWrapper : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 6A FF 68 98 68 42 00 68 14 FA 41 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF 15 F8 50 42 00 33 D2 8A D4 89 15 3C E8 42 00 8B C8 81 E1 FF 00 00 00 89 0D 38 E8 42 00 C1 E1 08 03 CA 89 0D 34 E8 42 00 C1 E8 10 A3 30 E8 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule VxTrojanTelefoon : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 1E E8 3B 01 BF CC 01 2E 03 3E CA 01 2E C7 05 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule Upackv030betaDwing : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E9 [4] 42 79 44 77 69 6E 67 40 00 00 00 50 45 00 00 4C 01 02 [20] 30 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule VxACMEClonewarMutant : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { FC AD 3D FF FF 74 20 E6 42 8A C4 E6 42 E4 61 0C 03 E6 61 AD B9 40 1F E2 FE }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule Armadillov2xxCopyMemII : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 6A ?? 8B B5 [4] C1 E6 04 8B 85 [4] 25 07 [2] 80 79 05 48 83 C8 F8 40 33 C9 8A 88 [4] 8B 95 [4] 81 E2 07 [2] 80 79 05 4A 83 CA F8 42 33 C0 8A 82 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule TPACKv05cm1 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 68 [2] FD 60 BE [2] BF [2] B9 [2] F3 A4 8B F7 BF [2] FC 46 E9 8E FE }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule EXEStealthv271 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB 00 60 EB 00 E8 00 00 00 00 5D 81 ED B0 27 40 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule TPACKv05cm2 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 68 [2] FD 60 BE [2] BF [2] B9 [2] F3 A4 8B F7 BF [2] FC 46 E9 CE FD }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule ExeJoiner10Yodaf2f : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 68 00 10 40 00 68 04 01 00 00 E8 39 03 00 00 05 00 10 40 00 C6 00 5C 68 04 01 00 00 68 04 11 40 00 6A 00 E8 1A 03 00 00 6A 00 68 80 00 00 00 6A 03 6A 00 6A 01 68 00 00 00 80 68 04 11 40 00 E8 EC 02 00 00 83 F8 FF 0F 84 83 02 00 00 A3 08 12 40 00 6A 00 50 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule ASPackv101bAlexeySolodovnikov : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 [4] 5D 81 ED D2 2A 44 ?? B8 CC 2A 44 ?? 03 C5 2B 85 A5 2E 44 ?? 89 85 B1 2E 44 ?? 80 BD 9C 2E 44 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule MacromediaWindowsFlashProjectorPlayerv30 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 83 EC 44 56 FF 15 94 13 42 00 8B F0 B1 22 8A 06 3A C1 75 13 8A 46 01 46 3A C1 74 04 84 C0 75 F4 38 0E 75 0D 46 EB 0A 3C 20 7E 06 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PESpinV11cyberbob : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 7D DE 46 00 0B E4 74 9E }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule RLPack118aPlib043ap0x : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 ?? 8D B5 1A 04 00 00 8D 9D C1 02 00 00 33 FF E8 61 01 00 00 EB 0F FF 74 37 04 FF 34 37 FF D3 83 C4 ?? 83 C7 ?? 83 3C 37 00 75 EB 83 BD 06 04 00 00 00 74 0E 83 BD 0A 04 00 00 00 74 05 E8 D7 01 00 00 8D 74 37 04 53 6A ?? 68 [4] 68 [4] 6A 00 FF 95 A7 03 00 00 89 85 16 04 00 00 5B FF B5 16 04 00 00 56 FF D3 83 C4 ?? 8B B5 16 04 00 00 8B C6 EB 01 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule DotFixNiceProtectvna : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 55 00 00 00 8D BD 00 10 40 00 68 [3] 00 03 3C 24 8B F7 90 68 31 10 40 00 9B DB E3 55 DB 04 24 8B C7 DB 44 24 04 DE C1 DB 1C 24 8B 1C 24 66 AD 51 DB 04 24 90 90 DA 8D 77 10 40 00 DB 1C 24 D1 E1 29 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule Upackv032betaDwing : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E9 [4] 42 79 44 77 69 6E 67 40 00 00 00 50 45 00 00 4C 01 02 [20] 32 }

	condition:
		$a0 at pe.entry_point
}

rule PackItBitch10archphase : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 00 00 00 00 00 00 00 00 00 00 00 00 28 [3] 35 [3] 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 4B 45 52 4E 45 4C 33 32 2E 44 4C 4C 00 41 [3] 50 [3] 00 00 00 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 [7] 79 [3] 7D [3] 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

	condition:
		$a0
}

import "pe"

rule JDPack2xJDPack : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 6A FF 68 68 51 40 00 68 04 25 40 00 64 A1 00 00 00 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule RPolyCryptv10personalpolycryptorsignfrompinch : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 50 58 97 97 60 61 8B 04 24 80 78 F3 6A E8 00 00 00 00 58 E8 00 00 00 00 58 91 91 EB 00 0F 85 6B F4 76 6F E8 00 00 00 00 83 C4 04 E8 00 00 00 00 58 90 E8 00 00 00 00 83 C4 04 8B 04 24 80 78 F1 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule Upackv031betaDwing : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E9 [4] 42 79 44 77 69 6E 67 40 00 00 00 50 45 00 00 4C 01 02 [20] 31 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule Packmanv0001 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 00 00 00 00 58 8D A8 [2] FF FF 8D 98 [3] FF 8D [2] 01 00 00 [28] 00 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PseudoSigner01PEPack099Anorganix : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 11 00 00 00 5D 83 ED 06 80 BD E0 04 90 90 01 0F 84 F2 FF CC 0A E9 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule EXECryptor239minimumprotection : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 68 [4] E9 [3] FF 50 C1 C8 18 89 05 [4] C3 C1 C0 18 51 E9 [3] FF 84 C0 0F 84 6A F9 FF FF E9 [3] FF C3 E9 [3] FF E8 CF E9 FF FF B8 01 00 00 00 E9 [3] FF 2B D0 68 A0 36 80 D4 59 81 C9 64 98 FF 99 E9 [3] FF 84 C0 0F 84 8E EC FF FF E9 [3] FF C3 87 3C 24 5F 8B 00 03 45 FC 83 C0 18 E9 [3] FF 87 0C 24 59 B8 01 00 00 00 D3 E0 23 D0 E9 02 18 00 00 0F 8D DB 00 00 00 C1 E8 14 E9 CA 00 00 00 9D 87 0C 24 59 87 1C 24 68 AE 73 B9 96 E9 C5 10 00 00 0F 8A [4] E9 [3] FF 81 FD F5 FF 8F 07 E9 4F 10 00 00 C3 E9 5E 12 00 00 87 3C 24 E9 [3] FF E8 [3] FF 83 3D [4] 00 0F 85 [4] 8D 55 EC B8 [4] E9 [3] FF E8 A7 1A 00 00 E8 2A CB FF FF E9 [3] FF C3 E9 [3] FF 59 89 45 E0 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule FSGv110EngdulekxtMicrosoftVisualC60ASM : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { F7 D0 EB 02 CD 20 BE BB 74 1C FB EB 02 CD 20 BF 3B [2] FB C1 C1 03 33 F7 EB 02 CD 20 68 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule HaspdongleAlladin : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 50 53 51 52 57 56 8B 75 1C 8B 3E [5] 8B 5D 08 8A FB [2] 03 5D 10 8B 45 0C 8B 4D 14 8B 55 18 80 FF 32 }

	condition:
		$a0 at pe.entry_point
}

rule SafeDiscv4 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 00 00 00 00 00 00 00 00 00 00 00 00 42 6F 47 5F }

	condition:
		$a0
}

import "pe"

rule PKLITEv112v115v1201 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { B8 [2] BA [2] 05 [2] 3B 06 [2] 73 ?? 2D [2] FA 8E D0 FB 2D [2] 8E C0 50 B9 [2] 33 FF 57 BE [2] FC F3 A5 CB B4 09 BA [2] CD 21 CD 20 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PKLITEv112v115v1202 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { B8 [2] BA [2] 3B C4 73 }

	condition:
		$a0 at pe.entry_point
}

rule EXECryptorv153 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E8 24 00 00 00 8B 4C 24 0C C7 01 17 00 01 00 C7 81 B8 00 00 00 00 [2] 00 31 C0 89 41 14 89 41 18 80 A1 C1 00 00 00 FE C3 31 C0 64 FF 30 64 89 20 CC C3 }

	condition:
		$a0
}

import "pe"

rule MSLRHv032afakeEXE32Pack13xemadicius : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 3B C0 74 02 81 83 55 3B C0 74 02 81 83 53 3B C9 74 01 BC 56 3B D2 74 02 81 85 57 E8 00 00 00 00 3B DB 74 01 90 83 C4 14 EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule eXpressorv11CGSoftLabs : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E9 15 13 00 00 E9 F0 12 00 00 E9 58 12 00 00 E9 AF 0C 00 00 E9 AE 02 00 00 E9 B4 0B 00 00 E9 E0 0C 00 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule NsPackV11LiuXingPing : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 9C 60 E8 00 00 00 00 5D B8 57 84 40 00 2D 50 84 40 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PrivatePersonalPackerPPPv102ConquestOfTroycom : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E8 17 00 00 00 E8 68 00 00 00 FF 35 2C 37 00 10 E8 ED 01 00 00 6A 00 E8 2E 04 00 00 E8 41 04 00 00 A3 74 37 00 10 6A 64 E8 5F 04 00 00 E8 30 04 00 00 A3 78 37 00 10 6A 64 E8 4E 04 00 00 E8 1F 04 00 00 A3 7C 37 00 10 A1 74 37 00 10 8B 1D 78 37 00 10 2B D8 8B 0D 7C 37 00 10 2B C8 83 FB 64 73 0F 81 F9 C8 00 00 00 73 07 6A 00 E8 D9 03 00 00 C3 6A 0A 6A 07 6A 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule VxHorse1776 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E8 [2] 5D 83 [2] 06 1E 26 [4] BF [2] 1E 0E 1F 8B F7 01 EE B9 [2] FC F3 A6 1F 1E 07 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PEShit : Packer PEiD hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { B8 [4] B9 [4] 83 F9 00 7E 06 80 30 ?? 40 E2 F5 E9 [3] FF }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule DrWebVirusFindingEngineInSoftEDVSysteme : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { B8 01 00 00 00 C2 0C 00 8D 80 00 00 00 00 8B D2 8B ?? 24 04 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PluginToExev100BoBBobSoft : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E8 00 00 00 00 29 C0 5D 81 ED D1 40 40 00 50 FF 95 B8 40 40 00 89 85 09 40 40 00 FF 95 B4 40 40 00 89 85 11 40 40 00 50 FF 95 C0 40 40 00 8A 08 80 F9 22 75 07 50 FF 95 C4 40 40 00 89 85 0D 40 40 00 8B 9D 09 40 40 00 60 6A 00 6A 01 53 81 C3 [3] 00 FF D3 61 6A 00 68 44 69 45 50 FF B5 0D 40 40 00 6A 00 81 C3 [3] 00 FF D3 83 C4 10 FF 95 B0 40 40 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule RCryptorv15PrivateVaska : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 83 2C 24 4F 68 [4] FF 54 24 04 83 44 24 04 4F B8 [4] 3D [4] 74 06 80 30 ?? 40 EB F3 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule NeoLitev200 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 8B 44 24 04 23 05 [4] 50 E8 [4] 83 C4 04 FE 05 [4] 0B C0 74 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PKLITEv200bextra : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 50 B8 [2] BA [2] 05 [2] 3B 06 02 00 72 ?? B4 09 BA [2] CD 21 B8 01 4C CD 21 [30] EA [4] F3 A5 C3 59 2D [2] 8E D0 51 2D [2] 50 80 }

	condition:
		$a0 at pe.entry_point
}

rule Crunch5Fusion4 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB 15 03 [3] 06 [11] 68 [4] 55 E8 }

	condition:
		$a0
}

import "pe"

rule MSLRHv032afakePEBundle023xemadicius : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 9C 60 E8 02 00 00 00 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 07 30 40 00 87 DD 61 9D EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PEMangle : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 9C BE [4] 8B FE B9 [4] BB 44 52 4F 4C AD 33 C3 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule WWPACKv302v302av304Relocationspack : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { BE [2] BF [2] B9 [2] 8C CD 81 ED [2] 8B DD 81 EB [2] 8B D3 FC FA 1E 8E DB 01 15 33 C0 2E AC }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule UPXProtectorv10x : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB EC [4] 8A 06 46 88 07 47 01 DB 75 07 }

	condition:
		$a0 at pe.entry_point
}

rule NorthStarPEShrinkerv13byLiuxingping : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 9C 60 E8 00 00 00 00 5D B8 B3 85 40 00 2D AC 85 40 00 2B E8 8D B5 73 ?? FF FF 8B 06 83 F8 00 74 11 8D B5 7F ?? FF FF 8B 06 83 F8 01 0F 84 F1 01 00 00 C7 06 01 00 00 00 8B D5 8B 85 4F ?? FF FF 2B D0 89 95 4F ?? FF FF 01 95 67 ?? FF FF 8D B5 83 ?? FF FF 01 }

	condition:
		$a0
}

import "pe"

rule CodeCryptv015b : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E9 31 03 00 00 EB 02 83 3D 58 EB 02 FF 1D 5B EB 02 0F C7 5F }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule RLPackFullEdition117Ap0x : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 [15] 8D B5 [4] 8D 9D [4] 33 FF }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PECompactv100 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB 06 68 [4] C3 9C 60 E8 02 [3] 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB C4 84 40 ?? 87 DD 8B 85 49 85 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule AHTeamEPProtector03fakeASProtect10FEUERRADER : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 90 [46] 90 FF E0 60 E8 01 00 00 00 90 5D 81 ED 00 00 00 00 BB 00 00 00 00 03 DD 2B 9D }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule KGCryptvxx : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E8 [4] 5D 81 ED [4] 64 A1 30 [3] 84 C0 74 ?? 64 A1 20 [3] 0B C0 74 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule VxKBDflags1024 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 8B EC 2E 89 2E 24 03 BC 00 04 8C D5 2E 89 2E 22 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule yodasProtectorV102AshkbizDanehkar : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E8 03 00 00 00 EB 01 ?? BB 55 00 00 00 E8 03 00 00 00 EB 01 ?? E8 8F 00 00 00 E8 03 00 00 00 EB 01 ?? E8 82 00 00 00 E8 03 00 00 00 EB 01 ?? E8 B8 00 00 00 E8 03 00 00 00 EB 01 ?? E8 AB 00 00 00 E8 03 00 00 00 EB 01 ?? 83 FB 55 E8 03 00 00 00 EB 01 ?? 75 2E E8 03 00 00 00 EB 01 ?? C3 60 E8 00 00 00 00 5D 81 ED 23 3F 42 00 8B D5 81 C2 72 3F 42 00 52 E8 01 00 00 00 C3 C3 E8 03 00 00 00 EB 01 ?? E8 0E 00 00 00 E8 D1 FF FF FF C3 E8 03 00 00 00 EB 01 ?? 33 C0 64 FF 30 64 89 20 CC C3 E8 03 00 00 00 EB 01 ?? 33 C0 64 FF 30 64 89 20 4B CC C3 E8 03 00 00 00 EB 01 ?? 33 DB B9 3A 66 42 00 81 E9 1D 40 42 00 8B D5 81 C2 1D 40 42 00 8D 3A 8B F7 33 C0 E8 03 00 00 00 EB 01 ?? E8 17 00 00 00 90 90 90 E9 C3 1F 00 00 33 C0 64 FF 30 64 89 20 43 CC C3 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule Obsidium1311ObsidiumSoftware : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB 02 [2] E8 27 00 00 00 EB 02 [2] EB 03 [3] 8B 54 24 0C EB 01 ?? 83 82 B8 00 00 00 22 EB 04 [4] 33 C0 EB 01 ?? C3 EB 02 [2] EB 02 [2] 64 67 FF 36 00 00 EB 04 [4] 64 67 89 26 00 00 EB 01 ?? EB 03 [3] 50 EB 03 [3] 33 C0 EB 01 ?? 8B 00 EB 03 [3] C3 EB 01 ?? E9 FA 00 00 00 EB 03 [3] E8 D5 FF FF FF EB 01 ?? EB 03 [3] 58 EB 03 [3] EB 01 ?? 64 67 8F 06 00 00 EB 01 ?? 83 C4 04 EB 03 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PseudoSigner01MicrosoftVisualC620Anorganix : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 90 90 90 90 68 [4] 67 64 FF 36 00 00 67 64 89 26 00 00 F1 90 90 90 90 55 8B EC 83 EC 50 53 56 57 BE 90 90 90 90 8D 7D F4 A5 A5 66 A5 8B }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule MEGALITEv120a : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { B8 [2] BA [2] 05 [2] 3B 2D 73 ?? 72 ?? B4 09 BA [2] CD 21 CD 90 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule GoatsMutilatorV16Goat_e0f : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E8 EA 0B 00 00 [3] 8B 1C 79 F6 63 D8 8D 22 B0 BF F6 49 08 C3 02 BD 3B 6C 29 46 13 28 5D }

	condition:
		$a0 at pe.entry_point
}

rule Armadillo430aSiliconRealmsToolworks : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 44 64 65 44 61 74 61 20 69 6E 69 74 69 61 6C 69 7A 65 64 20 28 41 4E 53 49 29 2C 20 61 70 70 20 73 74 72 69 6E 67 73 20 61 72 65 20 27 25 73 27 20 61 6E 64 20 27 25 73 27 00 00 00 44 64 65 44 61 74 61 20 69 6E 69 74 69 61 6C 69 7A 65 64 20 28 55 4E 49 43 }

	condition:
		$a0
}

import "pe"

rule Upackv038betaDwing : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { BE B0 11 [2] AD 50 FF 76 34 EB 7C 48 01 [2] 0B 01 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 18 10 00 00 10 00 00 00 00 [3] 00 00 [2] 00 10 00 00 00 02 00 00 04 00 00 00 00 00 38 00 04 00 00 00 00 00 00 00 00 [3] 00 02 00 00 00 00 00 00 }
		$a1 = { BE B0 11 [2] AD 50 FF 76 34 EB 7C 48 01 [2] 0B 01 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 18 10 00 00 10 00 00 00 00 [3] 00 00 [2] 00 10 00 00 00 02 00 00 04 00 00 00 00 00 38 00 04 00 00 00 00 00 00 00 00 [3] 00 02 00 00 00 00 00 00 ?? 00 00 ?? 00 00 ?? 00 00 [2] 00 00 00 10 00 00 10 00 00 00 00 00 00 0A 00 00 00 00 00 00 00 00 00 00 00 EE [3] 14 00 00 00 00 [6] 00 FF 76 38 AD 50 8B 3E BE F0 [3] 6A 27 59 F3 A5 FF 76 04 83 C8 FF 8B DF AB EB 1C 00 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 [5] 00 00 00 40 AB 40 B1 04 F3 AB C1 E0 0A B5 ?? F3 AB 8B 7E 0C 57 51 E9 [4] E3 B1 04 D3 E0 03 E8 8D 53 18 33 C0 55 40 51 D3 E0 8B EA 91 FF 56 4C 33 D2 59 D1 E8 13 D2 E2 FA 5D 03 EA 45 59 89 6B 08 56 8B F7 2B F5 F3 A4 AC 5E B1 80 AA 3B 7E 34 0F 82 97 FE FF FF 58 5F 59 E3 1B 8A 07 47 04 18 3C 02 73 F7 8B 07 3C ?? 75 F1 B0 00 0F C8 03 46 38 2B C7 AB E2 E5 5E 5D 59 51 59 46 AD 85 C0 74 1F }

	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point
}

import "pe"

rule DCryptPrivate09bdrmist : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { B9 [3] 00 E8 00 00 00 00 58 68 [3] 00 83 E8 0B 0F 18 00 D0 00 48 E2 FB C3 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule kkrunchyV02XRyd : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { BD [4] C7 45 [5] FF 4D 08 C6 45 0C 05 8D 7D 14 31 C0 B4 04 89 C1 F3 AB BF [4] 57 BE [4] 31 C9 41 FF 4D 0C 8D 9C 8D A0 00 00 00 FF D6 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule SkDUndetectabler3NoFSG2MethodSkD : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 81 EC 10 02 00 00 68 00 02 00 00 8D 85 F8 FD FF FF 50 6A 00 FF 15 38 10 00 01 50 FF 15 3C 10 00 01 8D 8D F8 FD FF FF 51 E8 4F FB FF FF 83 C4 04 8B 15 ?? 16 00 01 52 A1 ?? 16 00 01 50 E8 50 FF FF FF 83 C4 08 A3 ?? 16 00 01 C7 85 F4 FD FF FF 00 00 00 00 EB 0F 8B 8D F4 FD FF FF 83 C1 01 89 8D F4 FD FF FF 8B 95 F4 FD FF FF 3B 15 ?? 16 00 01 73 1C 8B 85 F4 FD FF FF 8B 0D ?? 16 00 01 8D 54 01 07 81 FA 74 10 00 01 75 02 EB 02 EB C7 8B 85 F4 FD FF FF 50 E8 ?? 00 00 00 83 C4 04 89 85 F0 FD FF FF 8B 8D F0 FD FF FF 89 4D FC C7 45 F8 00 00 00 00 EB 09 8B 55 F8 83 C2 01 89 55 F8 8B 45 F8 3B 85 F4 FD FF FF 73 15 8B 4D FC 03 4D F8 8B 15 ?? 16 00 01 03 55 F8 8A 02 88 01 EB D7 83 3D ?? 16 00 01 00 74 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule NTPacker10ErazerZ : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 83 C4 E0 53 33 C0 89 45 E0 89 45 E4 89 45 E8 89 45 EC B8 [2] 40 00 E8 [2] FF FF 33 C0 55 68 [2] 40 00 64 FF 30 64 89 20 8D 4D EC BA [2] 40 00 A1 [2] 40 00 E8 ?? FC FF FF 8B 55 EC B8 [2] 40 00 E8 [2] FF FF 8D 4D E8 BA [2] 40 00 A1 [2] 40 00 E8 ?? FE FF FF 8B 55 E8 B8 [2] 40 00 E8 [2] FF FF B8 [2] 40 00 E8 ?? FB FF FF 8B D8 A1 [2] 40 00 BA [2] 40 00 E8 [2] FF FF 75 26 8B D3 A1 [2] 40 00 E8 [2] FF FF 84 C0 75 2A 8D 55 E4 33 C0 E8 [2] FF FF 8B 45 E4 8B D3 E8 [2] FF FF EB 14 8D 55 E0 33 C0 E8 [2] FF FF 8B 45 E0 8B D3 E8 [2] FF FF 6A 00 E8 [2] FF FF 33 C0 5A 59 59 64 89 10 68 [2] 40 00 8D 45 E0 BA 04 00 00 00 E8 [2] FF FF C3 E9 [2] FF FF EB EB 5B E8 [2] FF FF 00 00 00 FF FF FF FF 01 00 00 00 25 00 00 00 FF FF FF FF 01 00 00 00 5C 00 00 00 FF FF FF FF 06 00 00 00 53 45 52 56 45 52 00 00 FF FF FF FF 01 00 00 00 31 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule SexeCrypter11bysantasdad : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 83 C4 EC 53 56 57 33 C0 89 45 EC B8 D8 39 00 10 E8 30 FA FF FF 33 C0 55 68 D4 3A 00 10 64 FF 30 64 89 [4] E4 3A 00 10 A1 00 57 00 10 50 E8 CC FA FF FF 8B D8 53 A1 00 57 00 10 50 E8 FE FA FF FF 8B F8 53 A1 00 57 00 10 50 E8 C8 FA FF FF 8B D8 53 E8 C8 FA FF FF 8B F0 85 F6 74 26 8B D7 4A B8 14 57 00 10 E8 AD F6 FF FF B8 14 57 00 10 E8 9B F6 FF FF 8B CF 8B D6 E8 DA FA FF FF 53 E8 84 FA FF FF 8D 4D EC BA F8 3A 00 10 A1 14 57 00 10 E8 0A FB FF FF 8B 55 EC B8 14 57 00 10 E8 65 F5 FF FF B8 14 57 00 10 E8 63 F6 FF FF E8 52 FC FF FF 33 C0 5A 59 59 64 89 10 68 DB 3A 00 10 8D 45 EC E8 ED F4 FF FF C3 E9 83 EF FF FF EB F0 5F 5E 5B E8 ED F3 FF FF 00 53 45 54 54 49 4E 47 53 00 00 00 00 FF FF FF FF 12 00 00 00 6B 75 74 68 37 36 67 62 62 67 36 37 34 76 38 38 67 79 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule VxGotcha879 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E8 [2] 5B 81 EB [2] 9C FC 2E [7] 8C D8 05 [2] 2E [4] 50 2E [6] 8B C3 05 [2] 8B F0 BF 00 01 B9 20 00 F3 A4 0E B8 00 01 50 B8 DA DA CD 21 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule MZ0oPE106bTaskFall : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB CA 89 03 83 C3 04 87 FE 32 C0 AE 75 FD 87 FE 80 3E FF 75 E2 46 5B 83 C3 04 53 8B 1B 80 3F FF 75 C9 8B E5 61 68 [4] C3 }
		$a1 = { EB CA 89 03 83 C3 04 87 FE 32 C0 AE 75 FD 87 FE 80 3E FF 75 E2 46 5B 83 C3 04 53 8B 1B 80 3F FF 75 C9 8B E5 61 68 [4] C3 FC B2 80 33 DB A4 B3 02 E8 6D 00 00 00 73 F6 33 C9 E8 64 00 00 00 73 1C 33 C0 E8 5B 00 00 00 73 23 B3 02 41 B0 10 E8 4F 00 00 00 12 C0 73 F7 75 3F AA EB D4 E8 4D 00 00 00 2B CB 75 10 E8 42 00 00 00 EB 28 AC D1 E8 74 4C 13 C9 EB 1C 91 48 C1 E0 08 AC E8 2C 00 00 00 3D 00 7D 00 00 73 0A 80 FC 05 73 06 83 F8 7F 77 02 41 41 95 8B C5 B3 01 56 8B F7 2B F0 F3 A4 5E EB 8E 02 D2 75 05 8A 16 46 12 D2 C3 33 C9 41 E8 EE FF FF FF 13 C9 E8 E7 FF FF FF 72 F2 C3 }

	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point
}

import "pe"

rule SoftDefenderv11xRandyLi : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 74 07 75 05 [6] 74 1F 75 1D ?? 68 [3] 00 59 9C 50 74 0A 75 08 ?? 59 C2 04 00 [3] E8 F4 FF FF FF [3] 78 0F 79 0D }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule Upackv010v012BetaDwing : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { BE 48 01 [5] 95 A5 33 C0 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule AHTeamEPProtector03fakeBorlandDelphi6070FEUERRADER : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 90 [46] 90 FF E0 53 8B D8 33 C0 A3 00 00 00 00 6A 00 E8 00 00 00 FF A3 00 00 00 00 A1 00 00 00 00 A3 00 00 00 00 33 C0 A3 00 00 00 00 33 C0 A3 00 00 00 00 E8 }

	condition:
		$a0 at pe.entry_point
}

rule STProtectorV15SilentSoftware : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 00 00 00 00 4B 65 52 6E 45 6C 33 32 2E 64 4C 6C 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 }

	condition:
		$a0
}

import "pe"

rule ASPackv105bAlexeySolodovnikov : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 [4] 5D 81 ED CE 3A 44 ?? B8 C8 3A 44 ?? 03 C5 2B 85 B5 3E 44 ?? 89 85 C1 3E 44 ?? 80 BD AC 3E 44 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule EXECryptor226minimumprotection : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 50 68 [4] 58 81 E0 [4] E9 [3] 00 87 0C 24 59 E8 [3] 00 89 45 F8 E9 [4] 0F 83 [3] 00 E9 [4] 87 14 24 5A 57 68 [4] E9 [4] 58 81 C0 [4] 2B 05 [4] 81 C8 [4] 81 E0 [4] E9 [3] 00 C3 E9 [4] C3 BF [4] 81 CB [4] BA [4] 52 E9 [3] 00 E8 [3] 00 E9 [3] 00 E9 [4] 87 34 24 5E 66 8B 00 66 25 [2] E9 [4] 8B CD 87 0C 24 8B EC 51 89 EC 5D 8B 05 [4] 09 C0 E9 [4] 59 81 C1 [4] C1 C1 ?? 23 0D [4] 81 F9 [4] E9 [4] C3 E9 [3] 00 13 D0 0B F9 E9 [4] 51 E8 [4] 8B 64 24 08 31 C0 64 8F 05 00 00 00 00 5A E9 [4] 3C A4 0F 85 [3] 00 8B 45 FC 66 81 38 [2] 0F 84 05 00 00 00 E9 [4] 0F 84 [4] E9 [4] 87 3C 24 5F 31 DB 31 C9 31 D2 68 [4] E9 [4] 89 45 FC 33 C0 89 45 F4 83 7D FC 00 E9 [4] 53 52 8B D1 87 14 24 81 C0 [4] 0F 88 [4] 3B CB }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PEProtector093CRYPToCRACk : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 5B 81 E3 00 FF FF FF 66 81 3B 4D 5A 75 33 8B F3 03 73 3C 81 3E 50 45 00 00 75 26 0F B7 46 18 8B C8 69 C0 AD 0B 00 00 F7 E0 2D AB 5D 41 4B 69 C9 DE C0 00 00 03 C1 75 09 83 EC 04 0F 85 DD 00 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PellesC300400450EXEX86CRTLIB : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 89 E5 6A FF 68 [4] 68 [4] 64 FF 35 [4] 64 89 25 [4] 83 EC ?? 53 56 57 89 65 E8 68 00 00 00 02 E8 [4] 59 A3 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule RLPackv118BasicaPLibAp0x : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 1A 04 00 00 8D 9D C1 02 00 00 33 FF E8 61 01 00 00 EB 0F FF 74 37 04 FF 34 37 FF D3 83 C4 08 83 C7 08 83 3C 37 00 75 EB 83 BD 06 04 00 00 00 74 0E 83 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule vfpexeNcV500WangJianGuo : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 00 00 00 00 5D [12] 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 CC }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule FreeJoiner153Stubengine17GlOFF : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E8 33 FD FF FF 50 E8 0D 00 00 00 CC FF 25 08 20 40 00 FF 25 0C 20 40 00 FF 25 10 20 40 00 FF 25 14 20 40 00 FF 25 18 20 40 00 FF 25 1C 20 40 00 FF 25 20 20 40 00 FF 25 24 20 40 00 FF 25 28 20 40 00 FF 25 00 20 40 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule TheHypersprotectorTheHyper : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 83 EC 14 8B FC E8 14 00 00 00 [2] 01 01 [2] 01 01 [3] 00 [2] 01 01 [2] 02 01 5E E8 0D 00 00 00 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 8B 46 04 FF 10 8B D8 E8 0D 00 00 00 56 69 72 74 75 61 6C 41 6C 6C 6F 63 00 53 8B 06 FF 10 89 07 E8 }

	condition:
		$a0 at pe.entry_point
}

rule ANDpakk2006DmitryAndreev : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 FC BE D4 00 40 00 BF 00 10 00 01 57 83 CD FF 33 C9 F9 EB 05 A4 02 DB 75 05 8A 1E 46 12 DB 72 F4 33 C0 40 02 DB 75 05 8A 1E 46 12 DB 13 C0 02 DB 75 05 8A 1E 46 12 DB 72 0E 48 02 DB 75 05 8A 1E 46 12 DB 13 C0 EB DC 83 E8 03 72 0F C1 E0 08 AC 83 F0 FF 74 4D D1 F8 8B E8 EB 09 02 DB 75 05 8A 1E 46 12 DB 13 C9 02 DB 75 05 8A 1E 46 12 DB 13 C9 75 1A 41 02 DB 75 05 8A 1E 46 12 DB 13 C9 02 DB 75 05 8A 1E 46 12 DB 73 EA 83 C1 02 81 FD 00 FB FF FF 83 D1 01 56 8D 34 2F F3 A4 5E E9 73 FF FF FF C3 }

	condition:
		$a0
}

import "pe"

rule Thinstall2628Jtit : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E8 00 00 00 00 58 BB 34 1D 00 00 2B C3 50 68 00 00 40 00 68 00 40 00 00 68 BC 00 00 00 E8 C3 FE FF FF E9 99 FF FF FF CC CC CC CC CC CC CC CC CC CC 55 8B EC 83 C4 F4 FC 53 57 56 8B 75 08 8B 7D 0C C7 45 FC 08 00 00 00 33 DB BA 00 00 00 80 43 33 C0 E8 19 01 }
		$a1 = { E8 00 00 00 00 58 BB 34 1D 00 00 2B C3 50 68 00 00 40 00 68 00 40 00 00 68 BC 00 00 00 E8 C3 FE FF FF E9 99 FF FF FF CC CC CC CC CC CC CC CC CC CC 55 8B EC 83 C4 F4 FC 53 57 56 8B 75 08 8B 7D 0C C7 45 FC 08 00 00 00 33 DB BA 00 00 00 80 43 33 C0 E8 19 01 00 00 73 0E 8B 4D F8 E8 27 01 00 00 02 45 F7 AA EB E9 E8 04 01 00 00 0F 82 96 00 00 00 E8 F9 00 00 00 73 5B B9 04 00 00 00 E8 05 01 00 00 48 74 DE 0F 89 C6 00 00 00 E8 DF 00 00 00 73 1B 55 BD 00 01 00 00 E8 DF 00 00 00 88 07 47 4D 75 F5 E8 C7 00 00 00 72 E9 5D EB A2 B9 01 00 00 00 E8 D0 00 00 00 83 C0 07 89 45 F8 C6 45 F7 00 83 F8 08 74 89 E8 B1 00 00 00 88 45 F7 E9 7C FF FF FF B9 07 00 00 00 E8 AA 00 00 00 50 33 C9 B1 02 E8 A0 00 00 00 8B C8 41 41 58 0B C0 74 04 8B D8 EB 5E 83 F9 02 74 6A 41 E8 88 00 00 00 89 45 FC E9 48 FF FF FF E8 87 00 00 00 49 E2 09 8B C3 E8 7D 00 00 00 EB 3A 49 8B C1 55 8B 4D FC 8B E8 33 C0 D3 E5 E8 5D 00 00 00 0B C5 5D 8B D8 E8 5F 00 00 00 3D 00 00 01 00 73 14 3D FF 37 00 00 73 0E 3D 7F 02 00 00 73 08 83 F8 7F 77 04 41 41 41 41 56 8B F7 2B F0 F3 }

	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point
}

import "pe"

rule UPXModifierv01x : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 50 BE [4] 8D BE [4] 57 83 CD }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule Obsidium1333ObsidiumSoftware : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB 02 [2] E8 29 00 00 00 EB 03 [3] EB 03 [3] 8B 54 24 0C EB 01 ?? 83 82 B8 00 00 00 28 EB 03 [3] 33 C0 EB 01 ?? C3 EB 04 [4] EB 02 [2] 64 67 FF 36 00 00 EB 04 [4] 64 67 89 26 00 00 EB 02 [2] EB 04 [4] 50 EB 04 }
		$a1 = { EB 02 [2] E8 29 00 00 00 EB 03 [3] EB 03 [3] 8B 54 24 0C EB 01 ?? 83 82 B8 00 00 00 28 EB 03 [3] 33 C0 EB 01 ?? C3 EB 04 [4] EB 02 [2] 64 67 FF 36 00 00 EB 04 [4] 64 67 89 26 00 00 EB 02 [2] EB 04 [4] 50 EB 04 [4] 33 C0 EB 01 ?? 8B 00 EB 03 [3] C3 EB 03 [3] E9 FA 00 00 00 EB 03 [3] E8 D5 FF FF FF EB 04 [4] EB 04 [4] 58 EB 01 ?? EB 03 [3] 64 67 8F 06 00 00 EB 04 [4] 83 C4 04 EB 04 [4] E8 2B 27 }

	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point
}

import "pe"

rule PureBasic4xNeilHodgson : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 68 [2] 00 00 68 00 00 00 00 68 [3] 00 E8 [3] 00 83 C4 0C 68 00 00 00 00 E8 [3] 00 A3 [3] 00 68 00 00 00 00 68 00 10 00 00 68 00 00 00 00 E8 [3] 00 A3 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule VxAugust16thIronMaiden : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { BA 79 02 03 D7 B4 1A CD 21 B8 24 35 CD 21 5F 57 89 9D 4E 02 8C 85 50 02 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule VProtector10Xvcasm : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 6A FF 68 [4] 68 [4] 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 E8 03 00 00 00 C7 84 00 58 EB 01 E9 83 C0 07 50 C3 FF 35 E8 03 00 00 00 C7 84 00 58 EB 01 E9 83 C0 07 50 C3 FF 35 E8 07 00 00 00 C7 83 83 C0 13 EB 0B 58 EB 02 CD 20 83 C0 02 EB 01 E9 50 C3 E8 B9 04 00 00 00 E8 1F 00 00 00 EB FA E8 16 00 00 00 E9 EB F8 00 00 58 EB 09 0F 25 E8 F2 FF FF FF 0F B9 49 75 F1 EB 05 EB F9 EB F0 D6 EB 01 0F 31 F0 EB 0C 33 C8 EB 03 EB 09 0F 59 74 05 75 F8 51 EB F1 E8 16 00 00 00 8B 5C 24 0C 8B A3 C4 00 00 00 64 8F 05 00 00 00 00 83 C4 04 EB 14 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C9 99 F7 F1 E9 E8 05 00 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PEPACK099 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 00 00 00 00 5D 83 ED 06 80 BD E0 04 00 00 01 0F 84 F2 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule Freshbindv20gFresh : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 64 A1 00 00 00 00 55 89 E5 6A FF 68 1C A0 41 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule UPXSCRAMBLER306OnToL : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E8 00 00 00 00 59 83 C1 07 51 C3 C3 BE [4] 83 EC 04 89 34 24 B9 80 00 00 00 81 36 [4] 50 B8 04 00 00 00 50 03 34 24 58 58 83 E9 03 E2 E9 EB D6 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PECompact2xxBitSumTechnologies : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { B8 [4] 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 50 45 43 6F 6D 70 61 63 74 32 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PESpinv01Cyberbob : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 5C CB 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 17 EB 07 EA EB 01 EB EB 0D FF }
		$a1 = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 5C CB 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 17 EB 07 EA EB 01 EB EB 0D FF E8 01 00 00 00 EA 5A 83 EA 0B FF E2 8B 95 B3 28 40 00 8B 42 3C 03 C2 89 85 BD 28 40 00 41 C1 E1 07 8B 0C 01 03 CA 8B 59 10 03 DA 8B 1B 89 9D D1 28 40 00 53 8F 85 C4 27 40 00 BB ?? 00 00 00 B9 A5 08 00 00 8D BD 75 29 40 00 4F 30 1C 39 FE CB E2 F9 68 2D 01 00 00 59 8D BD AA 30 40 00 C0 0C 39 02 E2 FA E8 02 00 00 00 FF 15 5A 8D 85 07 4F 56 00 BB 54 13 0B 00 D1 E3 2B C3 FF E0 E8 01 00 00 00 68 E8 1A 00 00 00 8D 34 28 B8 [4] 2B C9 83 C9 15 0F A3 C8 0F 83 81 00 00 00 8D B4 0D C4 28 40 00 8B D6 B9 10 00 00 00 AC 84 C0 74 06 C0 4E FF 03 E2 F5 E8 00 00 00 00 59 81 C1 1D 00 00 00 52 51 C1 E9 05 23 D1 FF }

	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point
}

import "pe"

rule VxEddie2100 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E8 [2] 4F 4F 0E E8 [2] 47 47 1E FF [2] CB E8 [2] 84 C0 [2] 50 53 56 57 1E 06 B4 51 CD 21 8E C3 [7] 8B F2 B4 2F CD 21 AC }

	condition:
		$a0 at pe.entry_point
}

rule NETexecutableMicrosoft : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 00 00 00 00 00 00 00 00 5F 43 6F 72 45 78 65 4D 61 69 6E 00 6D 73 63 6F 72 65 65 2E 64 6C 6C 00 00 00 00 00 FF 25 }

	condition:
		$a0
}

import "pe"

rule tElockv098 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E9 25 E4 FF FF 00 00 00 [4] 1E }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule AZProtect0001byAlexZakaAZCRC : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB 70 FC 60 8C 80 4D 11 00 70 25 81 00 40 0D 91 BB 60 8C 80 4D 11 00 70 21 81 1D 61 0D 81 00 40 CE 60 8C 80 4D 11 00 70 25 81 25 81 25 81 25 81 29 61 41 81 31 61 1D 61 00 40 B7 30 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 60 BE 00 [2] 00 BF 00 00 40 00 EB 17 4B 45 52 4E 45 4C 33 32 2E 44 4C 4C 00 00 00 00 00 FF 25 [3] 00 8B C6 03 C7 8B F8 57 55 8B EC 05 7F 00 00 00 50 E8 E5 FF FF FF BA 8C [2] 00 89 02 E9 1A 01 00 00 ?? 00 00 00 47 65 74 4D 6F 64 75 6C 65 46 69 6C 65 4E 61 6D 65 41 00 47 65 74 56 6F 6C 75 6D 65 49 6E 66 6F 72 6D 61 74 69 6F 6E 41 00 4D 65 73 73 61 67 65 42 6F 78 41 00 45 78 69 74 50 72 6F 63 65 73 73 00 47 65 74 4D 6F 64 75 6C 65 48 61 6E 64 6C 65 41 }
		$a1 = { FC 33 C9 49 8B D1 33 C0 33 DB AC 32 C1 8A CD 8A EA 8A D6 B6 08 66 D1 EB 66 D1 D8 73 09 66 35 20 83 66 81 F3 B8 ED FE CE 75 EB 33 C8 33 D3 4F 75 D5 F7 D2 F7 D1 8B C2 C1 C0 10 66 8B C1 C3 F0 DA 55 8B EC 53 56 33 C9 33 DB 8B 4D 0C 8B 55 10 8B 75 08 4E 4A 83 FB 08 72 05 33 DB 43 EB 01 43 33 C0 8A 04 31 8A 24 13 2A C4 88 04 31 E2 E6 5E 5B C9 C2 0C }

	condition:
		$a0 at pe.entry_point or $a1
}

import "pe"

rule UPX290LZMAMarkusOberhumerLaszloMolnarJohnReiser : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 BE [4] 8D BE [4] 57 83 CD FF 89 E5 8D 9C 24 [4] 31 C0 50 39 DC 75 FB 46 46 53 68 [4] 57 83 C3 04 53 68 [4] 56 83 C3 04 53 50 C7 03 [4] 90 90 }
		$a1 = { 60 BE [4] 8D BE [4] 57 83 CD FF EB 10 90 90 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB }

	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point
}

import "pe"

rule MEW510Northfox : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { BE 5B 00 40 00 AD 91 AD 93 53 AD 96 56 5F AC C0 C0 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule tElockv090 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E8 02 00 00 00 E8 00 E8 00 00 00 00 5E 2B }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule Obsidium1258ObsidiumSoftware : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB 01 ?? E8 29 00 00 00 EB 02 [2] EB 01 ?? 8B 54 24 0C EB 04 [4] 83 82 B8 00 00 00 24 EB 04 [4] 33 C0 EB 02 [2] C3 EB 02 [2] EB 03 [3] 64 67 FF 36 00 00 EB 01 ?? 64 67 89 26 00 00 EB 03 [3] EB 01 ?? 50 EB 03 [3] 33 C0 EB 04 [4] 8B 00 EB 03 [3] C3 EB 01 ?? E9 FA 00 00 00 EB 02 [2] E8 D5 FF FF FF EB 04 [4] EB 03 [3] EB 01 ?? 58 EB 01 ?? EB 02 [2] 64 67 8F 06 00 00 EB 04 [4] 83 C4 04 EB 01 ?? E8 7B 21 00 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule SVKProtectorv132EngPavolCerven : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED 06 00 00 00 EB 05 B8 06 36 42 00 64 A0 23 00 00 00 EB 03 C7 84 E8 84 C0 EB 03 C7 84 E9 75 67 B9 49 00 00 00 8D B5 C5 02 00 00 56 80 06 44 46 E2 FA 8B 8D C1 02 00 00 5E 55 51 6A 00 56 FF 95 0C 61 00 00 59 5D 40 85 C0 75 3C 80 3E }

	condition:
		$a0 at pe.entry_point
}

rule ExeSplitter12BillPrisonerTPOC : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E9 95 02 00 00 64 A1 00 00 00 00 83 38 FF 74 04 8B 00 EB F7 8B 40 04 C3 55 8B EC B8 00 00 00 00 8B 75 08 81 E6 00 00 FF FF B9 06 00 00 00 56 56 E8 B0 00 00 00 5E 83 F8 01 75 06 8B C6 C9 C2 04 00 81 EE 00 00 01 00 E2 E5 C9 C2 04 00 55 8B EC 8B 75 0C 8B DE 03 76 3C 8D 76 18 8D 76 60 8B 36 03 F3 56 8B 76 20 03 F3 33 D2 8B C6 8B 36 03 F3 8B 7D 08 B9 0E 00 00 00 FC F3 A6 0B C9 75 02 EB 08 }

	condition:
		$a0
}

import "pe"

rule COPv10c1988 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { BF [2] BE [2] B9 [2] AC 32 [3] AA E2 ?? 8B [3] EB ?? 90 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PECompactv25RetailSlimLoaderBitsumTechnologies : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { B8 [3] 01 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 50 45 43 32 00 }

	condition:
		$a0 at pe.entry_point
}

rule Morphinev27Holy_FatherRatter29A : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 00 00 00 00 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
		$a1 = { 00 00 00 00 00 00 00 00 [8] 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 [8] 00 00 00 00 [8] 00 00 00 00 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 00 47 65 74 50 72 6F 63 }

	condition:
		$a0 or $a1
}

import "pe"

rule diPackerV1XdiProtectorSoftware : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 0F 00 2D E9 01 00 A0 E3 68 01 00 EB 8C 00 00 EB 2B 00 00 EB 00 00 20 E0 1C 10 8F E2 8E 20 8F E2 00 30 A0 E3 67 01 00 EB 0F 00 BD E8 00 C0 8F E2 00 F0 9C E5 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PseudoSigner01REALBasicAnorganix : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 89 E5 90 90 90 90 90 90 90 90 90 90 50 90 90 90 90 90 00 01 E9 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PPCPROTECT11XAlexeyGorchakov : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { FF 5F 2D E9 20 00 9F E5 00 00 90 E5 18 00 8F E5 18 00 9F E5 00 00 90 E5 10 00 8F E5 01 00 A0 E3 00 00 00 EB 02 00 00 EA 04 F0 1F E5 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule nPackV111502006BetaNEOxuinC : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 83 3D 40 [3] 00 75 05 E9 01 00 00 00 C3 E8 41 00 00 00 B8 80 [3] 2B 05 08 [3] A3 3C [3] E8 5E 00 00 00 E8 E0 01 00 00 E8 EC 06 00 00 E8 F7 05 00 00 A1 3C [3] C7 05 40 [3] 01 00 00 00 01 05 00 [3] FF 35 00 [3] C3 C3 }

	condition:
		$a0 at pe.entry_point
}

rule EnigmaProtector11X13XSukhovVladimirSergeNMarkin : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 83 C4 F0 B8 00 10 40 00 E8 01 00 00 00 9A 83 C4 10 8B E5 5D E9 }

	condition:
		$a0
}

import "pe"

rule HardlockdongleAlladin : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 5C 5C 2E 5C 48 41 52 44 4C 4F 43 4B 2E 56 58 44 00 00 00 00 5C 5C 2E 5C 46 45 6E 74 65 44 65 76 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule Armadillov190c : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 6A FF 68 10 F2 40 00 68 74 9D 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule Upack_PatchDwing : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 81 3A 00 00 00 02 00 00 00 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule ExeJoinerV10Yodaf2f : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 68 00 10 40 00 68 04 01 00 00 E8 39 03 00 00 05 00 10 40 00 C6 00 5C 68 04 01 00 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PCShrink071beta : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 01 AD 54 3A 40 00 FF B5 50 3A 40 00 6A 40 FF 95 88 3A 40 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule FSGv110EngdulekxtMASM32TASM32 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 03 F7 23 FE 33 FB EB 02 CD 20 BB 80 ?? 40 00 EB 01 86 EB 01 90 B8 F4 00 00 00 83 EE 05 2B }
		$a1 = { 03 F7 23 FE 33 FB EB 02 CD 20 BB 80 ?? 40 00 EB 01 86 EB 01 90 B8 F4 00 00 00 83 EE 05 2B F2 81 F6 EE 00 00 00 EB 02 CD 20 8A 0B E8 02 00 00 00 A9 54 5E C1 EE 07 F7 D7 EB 01 DE 81 E9 B7 96 A0 C4 EB 01 6B EB 02 CD 20 80 E9 4B C1 CF 08 EB 01 71 80 E9 1C EB }

	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point
}

import "pe"

rule PEiDBundlev101BoBBobSoft : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 23 02 00 00 8B 44 24 04 52 48 66 31 C0 66 81 38 4D 5A 75 F5 8B 50 3C 81 3C 02 50 45 00 00 75 E9 5A C2 04 00 60 89 DD 89 C3 8B 45 3C 8B 54 28 78 01 EA 52 8B 52 20 01 EA 31 C9 41 8B 34 8A }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule UPX072 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 00 00 00 00 83 CD FF 31 DB 5E }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule AdFlt2 : Packer PEiD hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 68 00 01 9C 0F A0 0F A8 60 FD 6A 00 0F A1 BE [2] AD }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule RLPack120BasicEditionaPLibAp0x : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 83 7C 24 28 01 75 0C 8B 44 24 24 89 85 92 05 00 00 EB 0C 8B 85 8E 05 00 00 89 85 92 05 00 00 8D B5 BA 05 00 00 8D 9D 41 04 00 00 33 FF E8 38 01 00 00 EB 1B 8B 85 92 05 00 00 FF 74 37 04 01 04 24 FF 34 37 01 04 24 FF D3 83 C4 08 83 C7 08 83 3C 37 00 75 DF 83 BD 9E 05 00 00 00 74 0E 83 BD A2 05 00 00 00 74 05 E8 D6 01 00 00 }

	condition:
		$a0 at pe.entry_point
}

rule AsCryptv01SToRM1 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 81 [6] 83 [7] 83 [2] E2 ?? EB }

	condition:
		$a0
}

import "pe"

rule SmartEMicrosoft : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB 15 03 00 00 00 ?? 00 00 00 00 00 00 00 00 00 00 00 68 00 00 00 00 55 E8 00 00 00 00 5D 81 ED 1D 00 00 00 8B C5 55 60 9C 2B 85 8F 07 00 00 89 85 83 07 00 00 FF 74 24 2C E8 BB 01 00 00 0F 82 2F 06 00 00 E8 8E 04 00 00 49 0F 88 23 06 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PE_Admin10EncryptPE12003518SoldFlyingCat : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 9C 64 FF 35 00 00 00 00 E8 79 01 00 00 90 00 00 00 00 00 00 00 00 00 00 00 [8] 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 [36] 00 00 00 00 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 00 00 47 65 74 53 79 73 74 65 6D 44 69 72 65 63 74 6F 72 79 41 00 00 00 43 72 65 61 74 65 46 69 6C 65 41 00 00 00 43 72 65 61 74 65 46 69 6C 65 4D 61 70 70 69 6E 67 41 00 00 00 4D 61 70 56 69 65 77 4F 66 46 69 6C 65 00 00 00 55 6E 6D 61 70 56 69 65 77 4F 66 46 69 6C 65 00 00 00 43 6C 6F 73 65 48 61 6E 64 6C 65 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 45 78 69 74 50 72 6F 63 65 73 73 }
		$a1 = { 60 9C 64 FF 35 00 00 00 00 E8 79 01 00 00 90 00 00 00 00 00 00 00 00 00 00 00 [8] 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 [36] 00 00 00 00 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 00 00 47 65 74 53 79 73 74 65 6D 44 69 72 65 63 74 6F 72 79 41 00 00 00 43 72 65 61 74 65 46 69 6C 65 41 00 00 00 43 72 65 61 74 65 46 69 6C 65 4D 61 70 70 69 6E 67 41 00 00 00 4D 61 70 56 69 65 77 4F 66 46 69 6C 65 00 00 00 55 6E 6D 61 70 56 69 65 77 4F 66 46 69 6C 65 00 00 00 43 6C 6F 73 65 48 61 6E 64 6C 65 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 45 78 69 74 50 72 6F 63 65 73 73 00 00 00 00 }

	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point
}

import "pe"

rule MacromediaWindowsFlashProjectorPlayerv40 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 83 EC 44 56 FF 15 24 41 43 00 8B F0 8A 06 3C 22 75 1C 8A 46 01 46 3C 22 74 0C 84 C0 74 08 8A 46 01 46 3C 22 75 F4 80 3E 22 75 0F 46 EB 0C }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule WWPack32v100v111v112v120 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 53 55 8B E8 33 DB EB 60 0D 0A 0D 0A 57 57 50 61 63 6B 33 32 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule VProtectorV11vcasm : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { B8 1A ED 41 00 B9 EC EB 41 00 50 51 E8 74 00 00 00 E8 51 6A 00 00 58 83 E8 10 B9 B3 00 00 00 }

	condition:
		$a0 at pe.entry_point
}

rule MaskPE16yzkzero : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 36 81 2C 24 [3] 00 C3 60 }

	condition:
		$a0
}

import "pe"

rule bambam001bedrock : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 6A 14 E8 9A 05 00 00 8B D8 53 68 [4] E8 6C FD FF FF B9 05 00 00 00 8B F3 BF [4] 53 F3 A5 E8 8D 05 00 00 8B 3D [4] A1 [4] 66 8B 15 [4] B9 [4] 2B CF 89 45 E8 89 0D [4] 66 89 55 EC 8B 41 3C 33 D2 03 C1 83 C4 10 66 8B 48 06 66 8B 50 14 81 E1 FF FF 00 00 8D 5C 02 18 8D 41 FF 85 C0 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PseudoSigner01MEW11SE10Anorganix : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E9 09 00 00 00 00 00 00 02 00 00 00 0C 90 E9 }

	condition:
		$a0 at pe.entry_point
}

rule ASProtectv20 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 68 01 ?? 40 00 E8 01 00 00 00 C3 C3 }

	condition:
		$a0
}

import "pe"

rule PseudoSigner01BorlandDelphi6070Anorganix : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 90 90 90 90 68 [4] 67 64 FF 36 00 00 67 64 89 26 00 00 F1 90 90 90 90 53 8B D8 33 C0 A3 09 09 09 00 6A 00 E8 09 09 00 FF A3 09 09 09 00 A1 09 09 09 00 A3 09 09 09 00 33 C0 A3 09 09 09 00 33 C0 A3 09 09 09 00 E8 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule ObsidiumV12ObsidiumSoftware : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB 02 [2] E8 77 1E 00 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PseudoSigner01PEProtect09Anorganix : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 52 51 55 57 64 67 A1 30 00 85 C0 78 0D E8 07 00 00 00 58 83 C0 07 C6 90 C3 E9 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule WWPack32v1x : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 53 55 8B E8 33 DB EB 60 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule ChSfxsmallv11 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { BA [2] E8 [2] 8B EC 83 EC ?? 8C C8 BB [2] B1 ?? D3 EB 03 C3 8E D8 05 [2] 89 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule UPXModifiedStubcFarbrauschConsumerConsulting : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 BE [4] 8D BE [4] 57 83 CD FF FC B2 80 E8 00 00 00 00 5B 83 C3 66 A4 FF D3 73 FB 31 C9 FF D3 73 14 31 C0 FF D3 73 1D 41 B0 10 FF D3 10 C0 73 FA 75 3C AA EB E2 E8 4A 00 00 00 49 E2 10 E8 40 00 00 00 EB 28 AC D1 E8 74 45 11 C9 EB 1C 91 48 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PseudoSigner02NorthStarPEShrinker13Anorganix : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 9C 60 E8 00 00 00 00 5D B8 B3 85 40 00 2D AC 85 40 00 2B E8 8D B5 00 00 00 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule tElockv098tE : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E9 25 E4 FF FF 00 00 00 [8] 00 00 00 00 00 00 00 00 [12] 00 00 00 00 00 00 00 00 [8] 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 [4] 00 00 00 00 [4] 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule FSGv110EngdulekxtMicrosoftVisualBasicMASM32 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB 02 09 94 0F B7 FF 68 80 [2] 00 81 F6 8E 00 00 00 5B EB 02 11 C2 8D 05 F4 00 00 00 47 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule Upackv022v023BetaDwing : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 6A 07 BE 88 01 40 00 AD 8B F8 59 95 F3 A5 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule VxVirusConstructorbased : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { BB [2] B9 [2] 2E [4] 43 43 [2] 8B EC CC 8B [2] 81 [3] 06 1E B8 [2] CD 21 3D [4] 8C D8 48 8E D8 }
		$a1 = { E8 [2] 5D 81 [3] 06 1E E8 [2] E8 [4] 2E [6] B4 4A BB FF FF CD 21 83 [2] B4 4A CD 21 }

	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point
}

import "pe"

rule PESHiELD02 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 00 00 00 00 41 4E 41 4B 49 4E 5D 83 ED 06 EB 02 EA 04 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PseudoSigner02Gleam100Anorganix : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 EB 0B 83 EC 0C 53 56 57 E8 24 02 00 FF }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule DBPEv233DingBoy : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB 20 [2] 40 [29] 9C 55 57 56 52 51 53 9C E8 [4] 5D 81 ED [4] 9C 6A 10 73 0B EB 02 C1 51 E8 06 [3] C4 11 73 F7 5B CD 83 C4 04 EB 02 99 EB FF 0C 24 71 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PseudoSigner01PEtite2xlevel0Anorganix : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 90 90 90 90 68 [4] 67 64 FF 36 00 00 67 64 89 26 00 00 F1 90 90 90 90 B8 00 90 90 00 6A 00 68 90 90 90 00 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 66 9C 60 50 8B D8 03 00 68 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule EPack14litefinalby6aHguT : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 33 C0 8B C0 68 [4] 68 [4] E8 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule tElock098tE : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E9 25 E4 FF FF 00 00 00 [4] 1E [2] 00 00 00 00 00 00 00 00 00 3E [2] 00 2E [2] 00 26 [2] 00 00 00 00 00 00 00 00 00 4B [2] 00 36 [2] 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 56 [2] 00 00 00 00 00 69 [2] 00 00 00 00 00 56 [2] 00 00 00 00 00 69 [2] 00 00 00 00 00 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 75 73 65 }

	condition:
		$a0 at pe.entry_point
}

rule UnnamedScrambler10p0ke : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 83 C4 EC 53 56 33 C0 89 45 [4] 40 00 E8 11 F4 FF FF BE 30 6B 40 00 33 C0 55 68 C9 42 40 00 64 FF 30 64 89 20 E8 C9 FA FF FF BA D8 42 40 00 8B [4] FF FF 8B D8 B8 28 6B 40 00 8B 16 E8 37 F0 FF FF B8 2C 6B 40 00 8B 16 E8 2B F0 FF FF B8 28 6B 40 00 E8 19 F0 FF FF 8B D0 8B C3 8B 0E E8 42 E3 FF FF BA DC 42 40 00 8B C6 E8 2A FA FF FF 8B D8 B8 20 6B 40 00 8B 16 E8 FC EF FF FF B8 24 6B 40 00 8B 16 E8 F0 EF FF FF B8 20 6B 40 00 E8 DE EF FF FF 8B D0 8B C3 8B 0E E8 07 E3 FF FF 6A 00 6A 19 6A 00 6A 32 A1 28 6B 40 00 E8 59 EF FF FF 83 E8 05 03 C0 8D 55 EC E8 94 FE FF FF 8B 55 EC B9 24 6B 40 00 A1 20 6B 40 00 E8 E2 F6 FF FF 6A 00 6A 19 6A 00 6A 32 }

	condition:
		$a0
}

import "pe"

rule WARNINGTROJANADinjector : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 90 61 BE 00 20 44 00 8D BE 00 F0 FB FF C7 87 9C E0 04 00 6A F0 8A 5E 57 83 CD FF EB 0E }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule TopSpeedv3011989 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 1E BA [2] 8E DA 8B [3] 8B [3] FF [3] 50 53 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule CodeCryptv0164 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E9 2E 03 00 00 EB 02 83 3D 58 EB 02 FF 1D 5B EB 02 0F C7 5F EB 03 FF 1D 34 }

	condition:
		$a0 at pe.entry_point
}

rule UPXHiT001DJSiba : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E2 FA 94 FF E0 61 00 00 00 00 00 00 00 }

	condition:
		$a0
}

import "pe"

rule PseudoSigner01ASProtectAnorganix : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 90 90 90 90 90 90 5D 90 90 90 90 90 90 90 90 90 90 90 03 DD E9 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PocketPCARM : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { F0 40 2D E9 00 40 A0 E1 01 50 A0 E1 02 60 A0 E1 03 70 A0 E1 ?? 00 00 EB 07 30 A0 E1 06 20 A0 E1 05 10 A0 E1 04 00 A0 E1 [3] EB F0 40 BD E8 ?? 00 00 EA ?? 40 2D E9 [2] 9F E5 [5] 00 [8] 9F E5 00 [4] 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule AnskyaBinderv11Anskya : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { BE [3] 00 BB F8 11 40 00 33 ED 83 EE 04 39 2E 74 11 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule VProtectorV10Bvcasm : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 6A FF 68 CA 37 41 00 68 06 38 41 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 E8 03 00 00 00 C7 84 00 58 EB 01 E9 83 C0 07 50 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule SecurePE1Xwwwdeepzoneorg : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 8B 04 24 E8 00 00 00 00 5D 81 ED 4C 2F 40 00 89 85 61 2F 40 00 8D 9D 65 2F 40 00 53 C3 00 00 00 00 8D B5 BA 2F 40 00 8B FE BB 65 2F 40 00 B9 C6 01 00 00 AD 2B C3 C1 C0 03 33 C3 AB 43 81 FB 8E 2F 40 00 75 05 BB 65 2F 40 00 E2 E7 89 AD 1A 31 40 00 89 AD 55 34 40 00 89 AD 68 34 40 00 8D 85 BA 2F 40 00 50 C3 }

	condition:
		$a0 at pe.entry_point
}

rule yPv10bbyAshkbizDanehkar : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 53 56 57 60 E8 00 00 00 00 5D 81 ED 4C 32 40 00 E8 03 00 00 00 EB 01 ?? B9 EA 47 40 00 81 E9 E9 32 40 00 8B D5 81 C2 E9 32 40 00 8D 3A 8B F7 33 C0 E8 04 00 00 00 90 EB 01 C2 E8 03 00 00 00 EB 01 ?? AC [7] EB 01 E8 }

	condition:
		$a0
}

import "pe"

rule MSLRHv031a : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 D1 CB 0F CA C1 CA E0 D1 CA 0F C8 EB 01 F1 0F C0 C9 D2 D1 0F C1 C0 D3 DA C0 D6 A8 EB 01 DE D0 EC 0F C1 CB D0 CF 0F C1 D1 D2 DB 0F C8 EB 01 BC C0 E9 C6 C1 D0 91 0F CB EB 01 73 0F CA 87 D9 87 D2 D0 CF 87 D9 0F C8 EB 01 C1 EB 01 A2 86 CA D0 E1 0F C0 CB 0F }
		$a1 = { 60 D1 CB 0F CA C1 CA E0 D1 CA 0F C8 EB 01 F1 0F C0 C9 D2 D1 0F C1 C0 D3 DA C0 D6 A8 EB 01 DE D0 EC 0F C1 CB D0 CF 0F C1 D1 D2 DB 0F C8 EB 01 BC C0 E9 C6 C1 D0 91 0F CB EB 01 73 0F CA 87 D9 87 D2 D0 CF 87 D9 0F C8 EB 01 C1 EB 01 A2 86 CA D0 E1 0F C0 CB 0F CA C0 C7 91 0F CB C1 D9 0C 86 F9 86 D7 D1 D9 EB 01 A5 EB 01 11 EB 01 1D 0F C1 C2 0F CB 0F C1 C2 EB 01 A1 C0 E9 FD 0F C1 D1 EB 01 E3 0F CA 87 D9 EB 01 F3 0F CB 87 C2 0F C0 F9 D0 F7 EB 01 2F 0F C9 C0 DC C4 EB 01 35 0F CA D3 D1 86 C8 EB 01 01 0F C0 F5 87 C8 D0 DE EB 01 95 EB 01 E1 EB 01 FD EB 01 EC 87 D3 0F CB C1 DB 35 D3 E2 0F C8 86 E2 86 EC C1 FB 12 D2 EE 0F C9 D2 F6 0F CA 87 C3 C1 D3 B3 EB 01 BF D1 CB 87 C9 0F CA 0F C1 DB EB 01 44 C0 CA F2 0F C1 D1 0F CB EB 01 D3 EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 }

	condition:
		$a0 or $a1 at pe.entry_point
}

rule Upackv039finalDwing : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 56 10 E2 E3 B1 04 D3 E0 03 E8 8D 53 18 33 C0 55 40 51 D3 E0 8B EA 91 }
		$a1 = { FF 76 38 AD 50 8B 3E BE F0 [3] 6A 27 59 F3 A5 FF 76 04 83 C8 FF }

	condition:
		$a0 or $a1
}

import "pe"

rule vprotector12vcasm : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB 0B 5B 56 50 72 6F 74 65 63 74 5D 00 E8 24 00 00 00 8B 44 24 04 8B 00 3D 04 00 00 80 75 08 8B 64 24 08 EB 04 58 EB 0C E9 64 8F 05 00 00 00 00 74 F3 75 F1 EB 24 64 FF 35 00 00 00 00 EB 12 FF 9C 74 03 75 01 E9 81 0C 24 00 01 00 00 9D 90 EB F4 64 89 25 00 }
		$a1 = { EB 0B 5B 56 50 72 6F 74 65 63 74 5D 00 E8 24 00 00 00 8B 44 24 04 8B 00 3D 04 00 00 80 75 08 8B 64 24 08 EB 04 58 EB 0C E9 64 8F 05 00 00 00 00 74 F3 75 F1 EB 24 64 FF 35 00 00 00 00 EB 12 FF 9C 74 03 75 01 E9 81 0C 24 00 01 00 00 9D 90 EB F4 64 89 25 00 00 00 00 EB E6 E8 16 00 00 00 8B 5C 24 0C 8B A3 C4 00 00 00 64 8F 05 00 00 00 00 83 C4 04 EB 14 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C9 99 F7 F1 E9 E8 03 00 00 00 C7 84 00 58 EB 01 E9 83 C0 07 50 C3 FF 35 E8 16 00 00 00 8B 5C 24 0C 8B A3 C4 00 00 00 64 8F 05 00 00 00 00 83 C4 04 EB 14 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C9 99 F7 F1 E9 E8 03 00 00 00 C7 84 00 58 EB 01 E9 83 C0 07 50 C3 FF 35 33 F6 E8 10 00 00 00 8B 64 24 08 64 8F 05 00 00 00 00 58 EB 13 C7 83 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 AD CD 20 E8 05 00 00 00 0F 01 EB 05 E8 EB FB 00 00 83 C4 04 E8 08 00 00 00 0F 01 83 C0 }

	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point
}

rule FakeNinjav28Spirit : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { BA [4] FF E2 64 11 40 00 FF 35 84 11 40 00 E8 40 }

	condition:
		$a0
}

import "pe"

rule PECompactv133 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB 06 68 [4] C3 9C 60 E8 02 [3] 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 80 40 ?? 87 DD 8B 85 A6 80 40 ?? 01 85 03 80 40 ?? 66 C7 85 00 80 40 ?? 90 90 01 85 9E 80 40 ?? BB E8 0E }

	condition:
		$a0 at pe.entry_point
}

rule DragonArmorOrient : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { BF 4C [2] 00 83 C9 FF 33 C0 68 34 [2] 00 F2 AE F7 D1 49 51 68 4C [2] 00 E8 11 0A 00 00 83 C4 0C 68 4C [2] 00 FF 15 00 [2] 00 8B F0 BF 4C [2] 00 83 C9 FF 33 C0 F2 AE F7 D1 49 BF 4C [2] 00 8B D1 68 34 [2] 00 C1 E9 02 F3 AB 8B CA 83 E1 03 F3 AA BF 5C [2] 00 83 C9 FF 33 C0 F2 AE F7 D1 49 51 68 5C [2] 00 E8 C0 09 00 00 8B 1D 04 [2] 00 83 C4 0C 68 5C [2] 00 56 FF D3 A3 D4 [2] 00 BF 5C [2] 00 83 C9 FF 33 C0 F2 AE F7 D1 49 BF 5C [2] 00 8B D1 68 34 [2] 00 C1 E9 02 F3 AB 8B CA 83 E1 }

	condition:
		$a0
}

import "pe"

rule ThemidaWinLicenseV1802OreansTechnologies : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { B8 00 00 00 00 60 0B C0 74 68 E8 00 00 00 00 58 05 ?? 00 00 00 80 38 E9 75 ?? 61 EB ?? DB 2D [4] FF FF FF FF FF FF FF FF 3D 40 E8 00 00 00 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule SoftDefender1xRandyLi : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 74 07 75 05 19 32 67 E8 E8 74 1F 75 1D E8 68 39 44 CD 00 59 9C 50 74 0A 75 08 E8 59 C2 04 00 55 8B EC E8 F4 FF FF FF 56 57 53 78 0F 79 0D E8 34 99 47 49 34 33 EF 31 34 52 47 23 68 A2 AF 47 01 59 E8 01 00 00 00 FF 58 05 E6 01 00 00 03 C8 74 BD 75 BB E8 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PellesC2x4xDLLPelleOrinius : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 89 E5 53 56 57 8B 5D 0C 8B 75 10 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule UPX290LZMADelphistubMarkusOberhumerLaszloMolnarJohnReiser : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 BE [4] 8D BE [4] C7 87 [8] 57 83 CD FF 89 E5 8D 9C 24 [4] 31 C0 50 39 DC 75 FB 46 46 53 68 [4] 57 83 C3 04 53 68 [4] 56 83 C3 04 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule RLPackV119aPlib043ap0x : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 83 7C 24 28 01 75 0C 8B 44 24 24 89 85 3C 04 00 00 EB 0C 8B 85 38 04 00 00 89 85 3C 04 00 00 8D B5 60 04 00 00 8D 9D EB 02 00 00 33 FF E8 52 01 00 00 EB 1B 8B 85 3C 04 00 00 FF 74 37 04 01 04 24 FF 34 37 01 04 24 FF D3 83 C4 08 83 C7 08 83 3C 37 00 75 DF 83 BD 48 04 00 00 00 74 0E 83 BD 4C 04 00 00 00 74 05 E8 B8 01 00 00 8D 74 37 04 53 6A 40 68 00 10 00 00 68 [4] 6A 00 FF 95 D1 03 00 00 89 85 5C 04 00 00 5B FF B5 5C 04 00 00 56 FF D3 83 C4 08 8B B5 5C 04 00 00 8B C6 EB 01 40 80 38 01 75 FA 40 8B 38 03 BD 3C 04 00 00 83 C0 04 89 85 58 04 00 00 E9 94 00 00 00 56 FF 95 C9 03 00 00 85 C0 0F 84 B4 00 00 00 89 85 54 04 00 00 8B C6 EB 5B 8B 85 58 04 00 00 8B 00 A9 00 00 00 80 74 14 35 00 00 00 80 50 8B 85 58 04 00 00 C7 00 20 20 20 00 EB 06 FF B5 58 04 00 00 FF B5 54 04 00 00 FF 95 CD 03 00 00 85 C0 74 71 89 07 83 C7 04 8B 85 58 04 00 00 EB 01 40 80 38 00 75 FA 40 89 85 58 04 00 00 66 81 78 02 00 80 74 A5 80 38 00 75 A0 EB 01 46 80 3E 00 75 FA 46 40 8B 38 03 BD 3C 04 00 00 83 C0 04 89 85 58 04 00 00 80 3E 01 0F 85 63 FF FF FF 68 00 40 00 00 68 [4] FF B5 5C 04 00 00 FF 95 D5 03 00 00 E8 3D 00 00 00 E8 24 01 00 00 61 E9 [4] 61 C3 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule VirogensPEShrinkerv014 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 9C 55 E8 [4] 87 D5 5D 60 87 D5 8D [5] 8D [5] 57 56 AD 0B C0 74 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule FSGv110EngdulekxtBorlandDelphiBorlandC : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 2B C2 E8 02 00 00 00 95 4A 59 8D 3D 52 F1 2A E8 C1 C8 1C BE 2E [2] 18 EB 02 AB A0 03 F7 }
		$a1 = { 2B C2 E8 02 00 00 00 95 4A 59 8D 3D 52 F1 2A E8 C1 C8 1C BE 2E [2] 18 EB 02 AB A0 03 F7 EB 02 CD 20 68 F4 00 00 00 0B C7 5B 03 CB 8A 06 8A 16 E8 02 00 00 00 8D 46 59 EB 01 A4 02 D3 EB 02 CD 20 02 D3 E8 02 00 00 00 57 AB 58 81 C2 AA 87 AC B9 0F BE C9 80 }
		$a2 = { EB 01 2E EB 02 A5 55 BB 80 [2] 00 87 FE 8D 05 AA CE E0 63 EB 01 75 BA 5E CE E0 63 EB 02 }

	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point or $a2 at pe.entry_point
}

import "pe"

rule PseudoSigner01ACProtect109Anorganix : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 EB 02 00 00 90 90 90 04 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule RCryptorV16dVaska : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 90 61 61 80 7F F0 45 90 60 0F 85 1B 8B 1F FF 68 [4] B8 [4] 90 3D [4] 74 06 80 30 ?? 40 EB F3 B8 [4] 90 3D [4] 74 06 80 30 ?? 40 EB F3 }

	condition:
		$a0 at pe.entry_point
}

rule Upackv032BetaPatchDwing : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { BE 88 01 [2] AD 50 ?? AD 91 F3 A5 }

	condition:
		$a0
}

rule Apex30alpha500mhz : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 5F B9 14 00 00 00 51 BE 00 10 40 00 B9 00 [2] 00 8A 07 30 06 46 E2 FB 47 59 E2 EA 68 [3] 00 C3 }

	condition:
		$a0
}

import "pe"

rule SimbiOZPoly21Extranger : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 50 8B C4 83 C0 04 C7 00 [4] 58 C3 90 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule Armadillov184 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 6A FF 68 E8 C1 40 00 68 F4 86 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule Armadillov183 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 6A FF 68 E0 C1 40 00 68 64 84 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule Armadillov182 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 6A FF 68 E0 C1 40 00 68 74 81 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule Armadillov180 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 6A FF 68 E8 C1 00 00 68 F4 86 00 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule ExeSplitter13SplitMethodBillPrisonerTPOC : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E8 00 00 00 00 5D 81 ED 08 12 40 00 E8 66 FE FF FF 55 50 8D 9D 81 11 40 00 53 8D 9D 21 11 40 00 53 6A 08 E8 76 FF FF FF 6A 40 68 00 30 00 00 68 00 01 00 00 6A 00 FF 95 89 11 40 00 89 85 61 10 40 00 50 68 00 01 00 00 FF 95 85 11 40 00 8D 85 65 10 40 00 50 FF B5 61 10 40 00 FF 95 8D 11 40 00 6A 00 68 80 00 00 00 6A 02 6A 00 [4] 01 1F 00 FF B5 61 10 40 00 FF 95 91 11 40 00 89 85 72 10 40 00 6A 00 8D [4] 00 50 FF B5 09 10 40 00 8D 85 F5 12 40 00 50 FF B5 72 10 40 00 FF 95 95 11 40 00 FF B5 72 10 40 00 FF 95 99 11 40 00 8D 85 0D 10 40 00 50 8D 85 1D 10 40 00 50 B9 07 00 00 00 6A 00 E2 FC }
		$a1 = { E9 FE 01 00 00 [7] 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 73 76 63 45 72 30 31 31 2E 74 6D 70 00 00 00 00 00 00 00 00 00 64 A1 30 00 00 00 8B 40 0C 8B 40 0C 8B 00 85 C0 0F 84 5F 02 00 00 8B 48 30 80 39 6B 74 07 80 39 4B 74 02 EB E7 80 79 0C 33 74 02 EB DF 8B 40 18 C3 }

	condition:
		$a0 or $a1 at pe.entry_point
}

rule RJoiner12aVaska : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 81 EC 0C 01 00 00 8D 85 F4 FE FF FF 56 50 68 04 01 00 00 FF 15 0C 10 40 00 94 90 94 8D 85 F4 FE FF FF 50 FF 15 08 10 40 00 94 90 94 BE 00 20 40 00 94 90 94 83 3E FF 74 7D 53 57 33 DB 8D 7E 04 94 90 94 53 68 80 00 00 00 6A 02 53 6A 01 68 00 00 00 C0 57 FF 15 04 10 40 00 89 45 F8 94 90 94 8B 06 8D 74 06 04 94 90 94 8D 45 FC 53 50 8D 46 04 FF 36 50 FF 75 F8 FF 15 00 10 40 00 94 90 94 FF 75 F8 FF 15 10 10 40 00 94 90 94 8D 85 F4 FE FF FF 6A 0A 50 53 57 68 20 10 40 00 53 FF 15 18 10 40 00 94 90 94 8B 06 8D 74 06 04 94 90 94 83 3E FF 75 89 5F 5B 33 C0 5E C9 C2 10 00 CC CC 24 11 }

	condition:
		$a0
}

import "pe"

rule VxVirusConstructorIVPbased : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E9 [2] E8 [2] 5D [5] 81 ED [6] E8 [2] 81 FC [4] 8D [3] BF [2] 57 A4 A5 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule EncryptPE12003518WFS : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 9C 64 FF 35 00 00 00 00 E8 79 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PECompactv168v184 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB 06 68 [4] C3 9C 60 E8 02 [3] 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 3F 90 40 87 DD 8B 85 E6 90 40 01 85 33 90 40 66 C7 85 90 40 90 90 01 85 DA 90 40 01 85 DE 90 40 01 85 E2 90 40 BB 7B 11 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule SDProtectorProEdition116RandyLi : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 6A FF 68 1D 32 13 05 68 88 88 88 08 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 58 64 A3 00 00 00 00 58 58 58 58 8B E8 E8 3B 00 00 00 E8 01 00 00 00 FF 58 05 53 00 00 00 51 8B 4C 24 10 89 81 B8 00 00 00 B8 55 01 00 00 89 41 18 33 C0 89 41 04 89 41 }
		$a1 = { 55 8B EC 6A FF 68 1D 32 13 05 68 88 88 88 08 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 58 64 A3 00 00 00 00 58 58 58 58 8B E8 E8 3B 00 00 00 E8 01 00 00 00 FF 58 05 53 00 00 00 51 8B 4C 24 10 89 81 B8 00 00 00 B8 55 01 00 00 89 41 18 33 C0 89 41 04 89 41 08 89 41 0C 89 41 10 59 C3 C3 C3 C3 C3 C3 C3 C3 C3 C3 C3 C3 C3 33 C0 64 FF 30 64 89 20 9C 80 4C 24 01 01 9D 90 90 C3 C3 C3 C3 C3 C3 C3 C3 C3 C3 C3 C3 64 8F 00 58 74 07 75 05 19 32 67 E8 E8 74 27 75 25 EB 00 EB FC 68 39 44 CD 00 59 9C 50 74 0F 75 0D E8 59 C2 04 00 55 8B EC E9 FA FF FF 0E E8 EF FF FF FF 56 57 53 78 03 79 01 E8 68 A2 AF 47 01 59 E8 01 00 00 00 FF 58 05 93 03 00 00 03 C8 74 C4 75 C2 E8 }

	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point
}

import "pe"

rule Reg2Exe222223byJanVorel : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 6A 00 E8 2F 1E 00 00 A3 C4 35 40 00 E8 2B 1E 00 00 6A 0A 50 6A 00 FF 35 C4 35 40 00 E8 07 00 00 00 50 E8 1B 1E 00 00 CC 68 48 00 00 00 68 00 00 00 00 68 C8 35 40 00 E8 76 16 00 00 83 C4 0C 8B 44 24 04 A3 CC 35 40 00 68 00 00 00 00 68 A0 0F 00 00 68 00 00 00 00 E8 EC 1D 00 00 A3 C8 35 40 00 E8 62 1D 00 00 E8 92 1A 00 00 E8 80 16 00 00 E8 13 14 00 00 68 01 00 00 00 68 08 36 40 00 68 00 00 00 00 8B 15 08 36 40 00 E8 71 3F 00 00 B8 00 00 10 00 BB 01 00 00 00 E8 82 3F 00 00 FF 35 48 31 40 00 B8 00 01 00 00 E8 0D 13 00 00 8D 0D EC 35 40 00 5A E8 F2 13 00 00 68 00 01 00 00 FF 35 EC 35 40 00 E8 84 1D 00 00 A3 F4 35 40 00 FF 35 48 31 40 00 FF 35 F4 35 40 00 FF 35 EC 35 40 00 E8 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule FSGv120EngdulekxtBorlandDelphiMicrosoftVisualC : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 0F B6 D0 E8 01 00 00 00 0C 5A B8 80 [2] 00 EB 02 00 DE 8D 35 F4 00 00 00 F7 D2 EB 02 0E EA 8B 38 EB 01 A0 C1 F3 11 81 EF 84 88 F4 4C EB 02 CD 20 83 F7 22 87 D3 33 FE C1 C3 19 83 F7 26 E8 02 00 00 00 BC DE 5A 81 EF F7 EF 6F 18 EB 02 CD 20 83 EF 7F EB 01 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule CrunchPE : Packer PEiD hardened
{
	meta:
		author = "malware-lu"
		note = "Added extra checks"

	strings:
		$a0 = { 55 E8 [4] 5D 83 ED 06 8B C5 55 60 89 AD [4] 2B 85 }
		$b = { EB 10 [16] 55 E8 [4] 5D 81 ED 18 [3] 8B C5 55 60 9C 2B 85 E9 06 [2] 89 85 E1 06 [2] FF 74 24 2C E8 BB 01 00 00 0F 82 92 05 00 00 E8 F1 03 00 00 49 0F 88 86 05 00 00 68 6C D9 B2 96 33 C0 50 E8 24 03 00 00 89 85 D9 41 00 00 68 EC 49 7B 79 33 C0 50 E8 11 03 00 00 89 85 D1 41 00 00 E8 67 05 00 00 E9 56 05 00 00 51 52 53 33 C9 49 8B D1 33 C0 33 DB AC 32 C1 8A CD 8A EA 8A D6 B6 08 66 D1 EB 66 D1 D8 73 09 66 35 20 83 66 81 F3 B8 ED FE CE 75 EB 33 C8 33 D3 4F 75 D5 F7 D2 F7 D1 5B 8B C2 C1 C0 10 66 8B C1 5A 59 C3 68 03 02 00 00 E8 80 04 00 00 0F 82 A8 02 00 00 96 8B 44 24 04 0F C8 8B D0 25 0F 0F 0F 0F 33 D0 C1 C0 08 0B C2 8B D0 25 33 33 33 33 33 D0 C1 C0 04 0B C2 8B D0 25 55 55 55 55 33 D0 C1 C0 02 0B C2 }

	condition:
		for any of ( $* ) : ( $ at pe.entry_point )
}

import "pe"

rule CICompressv10 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 6A 04 68 00 10 00 00 FF 35 9C 14 40 00 6A 00 FF 15 38 10 40 00 A3 FC 10 40 00 97 BE 00 20 40 00 E8 71 00 00 00 3B 05 9C 14 40 00 75 61 6A 00 6A 20 6A 02 6A 00 6A 03 68 00 00 00 C0 68 94 10 40 00 FF 15 2C 10 40 00 A3 F8 10 40 00 6A 00 68 F4 10 40 00 FF 35 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule ExeShieldv27b : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB 06 68 40 85 06 00 C3 9C 60 E8 02 00 00 00 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 3F 90 40 00 87 DD 8B 85 E6 90 40 00 01 85 33 90 40 00 66 C7 85 30 90 40 00 90 90 01 85 DA 90 40 00 01 85 DE 90 40 00 01 85 E2 90 40 00 BB 7B 11 00 00 03 9D EA 90 40 }

	condition:
		$a0 at pe.entry_point
}

rule UPXInlinerv10byGPcH : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 9C 60 E8 00 00 00 00 5D B8 B3 85 40 00 2D AC 85 40 00 2B E8 8D B5 D5 FE FF FF 8B 06 83 F8 00 74 11 8D B5 E1 FE FF FF 8B 06 83 F8 01 0F 84 F1 01 00 00 C7 06 01 00 00 00 8B D5 8B 85 B1 FE FF FF 2B D0 89 95 B1 FE FF FF 01 95 C9 FE FF FF 8D B5 E5 FE FF FF 01 }

	condition:
		$a0
}

import "pe"

rule PKLITEv114v120 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { B8 [2] BA [2] 05 [2] 3B 06 [2] 72 ?? B4 09 BA [2] CD 21 CD 20 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule ExeToolsCOM2EXE : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E8 [2] 5D 83 ED ?? 8C DA 2E 89 96 [2] 83 C2 ?? 8E DA 8E C2 2E 01 96 [2] 60 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule ThinstallEmbedded2545Jitit : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E8 F2 FF FF FF 50 68 [4] 68 40 1B 00 00 E8 42 FF FF FF E9 9D FF FF FF 00 00 00 00 00 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule VxARCV4 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E8 00 00 5D 81 ED 06 01 81 FC 4F 50 74 0B 8D B6 86 01 BF 00 01 57 A4 EB 11 1E 06 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule Armadillo3X5XSiliconRealmsToolworks : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 00 00 00 00 5D 50 51 0F CA F7 D2 9C F7 D2 0F CA EB 0F B9 EB 0F B8 EB 07 B9 EB 0F 90 EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC E9 9D 0F C9 8B CA F7 D1 59 58 50 51 0F CA F7 D2 9C F7 D2 0F CA EB 0F B9 EB 0F B8 EB 07 B9 EB 0F 90 EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC E9 9D 0F C9 8B CA F7 D1 59 58 50 51 0F CA F7 D2 9C F7 D2 0F CA EB 0F B9 EB 0F B8 EB 07 B9 EB 0F 90 EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC E9 9D 0F C9 8B CA F7 D1 59 58 60 33 C9 75 02 EB 15 EB 33 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule MSLRHv032afakePESHiELD025emadicius : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 2B 00 00 00 0D 0A 0D 0A 0D 0A 52 65 67 69 73 74 41 72 65 64 20 74 6F 3A 20 4E 4F 4E 2D 43 4F 4D 4D 45 52 43 49 41 4C 21 21 0D 0A 0D 0A 0D 00 58 61 EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule Armadillov252beta2 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 6A FF 68 [4] B0 [4] 68 60 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF [3] 15 24 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule CipherWallSelfExtratorDecryptorConsolev15 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 90 61 BE 00 10 42 00 8D BE 00 00 FE FF C7 87 C0 20 02 00 0B 6E 5B 9B 57 83 CD FF EB 0E 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 EF 75 09 8B 1E 83 EE FC 11 DB 73 E4 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PCShrinkerv029 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { BD [4] 01 AD 55 39 40 ?? 8D B5 35 39 40 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule NsPacKV33LiuXingPing : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 9C 60 E8 00 00 00 00 5D 83 ED 07 8D 85 [4] 80 38 00 74 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule CopyMinderMicrocosmLtd : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 83 25 [4] EF 6A 00 E8 [4] E8 [4] CC FF 25 [4] FF 25 [4] FF 25 [4] FF 25 [4] FF 25 [4] FF 25 [4] FF 25 [4] FF 25 [4] FF 25 [4] FF 25 [4] FF 25 [4] FF 25 [4] FF 25 [4] FF 25 [4] FF 25 [4] FF 25 [4] FF 25 [4] FF 25 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule Crunchv5BitArts : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB 15 03 00 00 00 06 00 00 00 00 00 00 00 00 00 00 00 68 00 00 00 00 55 E8 00 00 00 00 5D 81 ED 1D 00 00 00 8B C5 55 60 9C 2B 85 FC 07 00 00 89 85 E8 07 00 00 FF 74 24 2C E8 20 02 00 00 0F 82 94 06 00 00 E8 F3 04 00 00 49 0F 88 88 06 00 00 8B B5 E8 07 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PCShrinkerv020 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E8 E8 01 [2] 60 01 AD B3 27 40 ?? 68 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule Armadillo500SiliconRealmsToolworks : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E8 E3 40 00 00 E9 16 FE FF FF 6A 0C 68 [4] E8 44 15 00 00 8B 4D 08 33 FF 3B CF 76 2E 6A E0 58 33 D2 F7 F1 3B 45 0C 1B C0 40 75 1F E8 36 13 00 00 C7 00 0C 00 00 00 57 57 57 57 57 E8 C7 12 00 00 83 C4 14 33 C0 E9 D5 00 00 00 0F AF 4D 0C 8B F1 89 75 08 3B F7 75 03 33 F6 46 33 DB 89 5D E4 83 FE E0 77 69 83 3D [4] 03 75 4B 83 C6 0F 83 E6 F0 89 75 0C 8B 45 08 3B 05 [4] 77 37 6A 04 E8 48 11 00 00 59 89 7D FC FF 75 08 E8 01 49 00 00 59 89 45 E4 C7 45 FC FE FF FF FF E8 5F 00 00 00 8B 5D E4 3B DF 74 11 FF 75 08 57 53 E8 66 D3 FF FF 83 C4 0C 3B DF 75 61 56 6A 08 FF 35 [4] FF 15 [4] 8B D8 3B DF 75 4C 39 3D [4] 74 33 56 E8 AF F9 FF FF 59 85 C0 0F 85 72 FF FF FF 8B 45 10 3B C7 0F 84 50 FF FF FF C7 00 0C 00 00 00 E9 45 FF FF FF 33 FF 8B 75 0C 6A 04 E8 EE 0F 00 00 59 C3 }

	condition:
		$a0 at pe.entry_point
}

rule SLVc0deProtector060SLVICU : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB 02 FA 04 E8 49 00 00 00 69 E8 49 00 00 00 95 E8 4F 00 00 00 68 E8 1F 00 00 00 49 E8 E9 FF FF FF 67 E8 1F 00 00 00 93 E8 31 00 00 00 78 E8 DD }

	condition:
		$a0
}

import "pe"

rule Kryptonv03 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 8B 0C 24 E9 C0 8D 01 ?? C1 3A 6E CA 5D 7E 79 6D B3 64 5A 71 EA }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule CrackStopv101cStefanEsser1997 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { B4 48 BB FF FF B9 EB 27 8B EC CD 21 FA FC }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule Kryptonv05 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 54 E8 [4] 5D 8B C5 81 ED 71 44 [2] 2B 85 64 60 [2] EB 43 DF }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule Kryptonv04 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 54 E8 [4] 5D 8B C5 81 ED 61 34 [2] 2B 85 60 37 [2] 83 E8 06 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PassLock2000v10EngMoonlightSoftware : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 53 56 57 BB 00 50 40 00 66 2E F7 05 34 20 40 00 04 00 0F 85 98 00 00 00 E8 1F 01 00 00 C7 43 60 01 00 00 00 8D 83 E4 01 00 00 50 FF 15 F0 61 40 00 83 EC 44 C7 04 24 44 00 00 00 C7 44 24 2C 00 00 00 00 54 FF 15 E8 61 40 00 B8 0A 00 00 00 F7 44 24 }

	condition:
		$a0 at pe.entry_point
}

rule Upackv029Betav031BetaDwing : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { BE 88 01 [2] AD 8B F8 95 AD 91 F3 A5 AD B5 ?? F3 }

	condition:
		$a0
}

rule AlexProtector10beta2byAlex : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED 06 10 40 00 E8 24 00 00 00 EB 01 E9 8B 44 24 0C EB 03 EB 03 C7 EB FB E8 01 00 00 00 A8 83 C4 04 83 80 B8 00 00 00 02 33 C0 EB 01 E9 C3 58 83 C4 04 EB 03 EB 03 C7 EB FB E8 01 00 00 00 A8 83 C4 04 50 64 FF 35 00 00 00 00 64 89 25 }

	condition:
		$a0
}

rule MoleBoxv254Teggo : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 00 8B 4D F0 8B 11 89 15 [3] 00 8B 45 FC A3 [3] 00 5F 5E 8B E5 5D C3 CC CC CC E8 EB FB FF FF 58 E8 ?? 07 00 00 58 89 44 24 24 61 58 58 FF D0 E8 [2] 00 00 6A 00 FF 15 [3] 00 CC CC CC CC CC CC CC CC CC CC CC CC CC CC }

	condition:
		$a0
}

import "pe"

rule Obsidium1337ObsidiumSoftware : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB 02 [2] E8 2C 00 00 00 EB 04 [4] EB 04 [4] 8B 54 24 0C EB 02 [2] 83 82 B8 00 00 00 27 EB 04 [4] 33 C0 EB 02 [2] C3 EB 02 [2] EB 03 [3] 64 67 FF 36 00 00 EB 04 [4] 64 67 89 26 00 00 EB 03 [3] EB 01 ?? 50 EB 02 [2] 33 C0 EB 02 [2] 8B 00 EB 04 [4] C3 EB 02 [2] E9 FA 00 00 00 EB 04 [4] E8 D5 FF FF FF EB 02 [2] EB 04 [4] 58 EB 04 [4] EB 03 [3] 64 67 8F 06 00 00 EB 01 ?? 83 C4 04 EB 03 [3] E8 23 27 00 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PESpinv03Engcyberbob : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 B7 CD 46 }
		$a1 = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 B7 CD 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 17 EB 07 EA EB 01 EB EB 0D FF }

	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point
}

import "pe"

rule PseudoSigner02PEPack099Anorganix : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 11 00 00 00 5D 83 ED 06 80 BD E0 04 90 90 01 0F 84 F2 FF CC 0A }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule VxVCL : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { AC B9 00 80 F2 AE B9 04 00 AC AE 75 ?? E2 FA 89 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule VterminalV10XLeiPeng : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E8 00 00 00 00 58 05 [4] 9C 50 C2 04 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PEEncrypt10Liwuyue : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 83 C4 D0 53 56 57 8D 75 FC 8B 44 24 30 25 00 00 FF FF 81 38 4D 5A 90 00 74 07 2D 00 10 00 00 EB F1 89 45 FC E8 C8 FF FF FF 2D 0F 05 00 00 89 45 F4 8B 06 8B 40 3C 03 06 8B 40 78 03 06 8B C8 8B 51 20 03 16 8B 59 24 03 1E 89 5D F0 8B 59 1C 03 1E 89 5D EC 8B 41 18 8B C8 49 85 C9 72 5A 41 33 C0 8B D8 C1 E3 02 03 DA 8B 3B 03 3E 81 3F 47 65 74 50 75 40 8B DF 83 C3 04 81 3B 72 6F 63 41 75 33 8B DF 83 C3 08 81 3B 64 64 72 65 75 26 83 C7 0C 66 81 3F 73 73 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule InstallAnywhere61ZeroGSoftwareInc : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 BE 00 A0 42 00 8D BE 00 70 FD FF 57 83 CD FF EB 10 90 90 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 EF 75 09 8B 1E 83 EE FC 11 DB 73 E4 31 C9 83 E8 03 72 0D C1 E0 }
		$a1 = { 60 BE 00 A0 42 00 8D BE 00 70 FD FF 57 83 CD FF EB 10 90 90 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 }

	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point
}

import "pe"

rule iLUCRYPTv4018exe : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 8B EC FA C7 [4] 4C 4C C3 FB BF [2] B8 [2] 2E [2] D1 C8 4F 81 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PseudoSigner02ASProtectAnorganix : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 90 90 90 90 90 90 5D 90 90 90 90 90 90 90 90 90 90 90 03 DD }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule EncryptPEV22006710WFS : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 9C 64 FF 35 00 00 00 00 E8 73 01 00 00 }
		$a1 = { 60 9C 64 FF 35 00 00 00 00 E8 73 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 [8] 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 [36] 00 00 00 00 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 00 00 47 65 74 54 65 6D 70 50 61 74 68 41 00 00 00 43 72 65 61 74 65 46 69 6C 65 41 00 00 00 43 72 65 61 74 65 46 69 6C 65 4D 61 70 70 69 6E 67 41 00 00 00 4D 61 70 56 69 65 77 4F 66 46 69 6C 65 00 00 00 55 6E 6D 61 70 56 69 65 77 4F 66 46 69 6C 65 00 00 00 43 6C 6F 73 65 48 61 6E 64 6C 65 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 45 78 69 74 50 72 6F 63 65 73 73 00 00 00 00 }

	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point
}

rule Themida10xx18xxnocompressionOreansTechnologies : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 83 C4 D8 60 E8 00 00 00 00 5A 81 EA [4] 8B DA C7 45 D8 00 00 00 00 8B 45 D8 40 89 45 D8 81 7D D8 80 00 00 00 74 0F 8B 45 08 89 83 [4] FF 45 08 43 EB E1 89 45 DC 61 8B 45 DC C9 C2 04 00 55 8B EC 81 C4 7C FF FF FF 60 E8 00 00 00 00 }
		$a1 = { 55 8B EC 83 C4 D8 60 E8 00 00 00 00 5A 81 EA [4] 8B DA C7 45 D8 00 00 00 00 8B 45 D8 40 89 45 D8 81 7D D8 80 00 00 00 74 0F 8B 45 08 89 83 [4] FF 45 08 43 EB E1 89 45 DC 61 8B 45 DC C9 C2 04 00 55 8B EC 81 C4 7C FF FF FF 60 E8 00 00 00 00 5A 81 EA [4] 8D 45 80 8B 5D 08 C7 85 7C FF FF FF 00 00 00 00 8B 8D 7C FF FF FF D1 C3 88 18 41 89 8D 7C FF FF FF 81 BD 7C FF FF FF 80 00 00 00 75 E3 C7 85 7C FF FF FF 00 00 00 00 8D BA [4] 8D 75 80 8A 0E BB F4 01 00 00 B8 AB 37 54 78 D3 D0 8A 0F D3 D0 4B 75 F7 0F AF C3 47 46 8B 8D 7C FF FF FF 41 89 8D 7C FF FF FF 81 F9 80 00 00 00 75 D1 61 C9 C2 04 00 55 8B EC 83 C4 F0 8B 75 08 C7 45 FC 00 00 00 00 EB 04 FF 45 FC 46 80 3E 00 75 F7 BA 00 00 00 00 8B 75 08 8B 7D 0C EB 7F C7 45 F8 00 00 00 00 EB }

	condition:
		$a0 or $a1
}

import "pe"

rule StonesPEEncryptorv10 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 57 56 52 51 53 E8 [4] 5D 8B D5 81 ED 63 3A 40 ?? 2B 95 C2 3A 40 ?? 83 EA 0B 89 95 CB 3A 40 ?? 8D B5 CA 3A 40 ?? 0F B6 36 }

	condition:
		$a0 at pe.entry_point
}

rule PolyBoxDAnskya : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 33 C9 51 51 51 51 51 53 33 C0 55 68 84 2C 40 00 64 FF 30 64 89 20 C6 45 FF 00 B8 B8 46 40 00 BA 24 00 00 00 E8 8C F3 FF FF 6A 24 BA B8 46 40 00 8B 0D B0 46 40 00 A1 94 46 40 00 E8 71 FB FF FF 84 C0 0F 84 6E 01 00 00 8B 1D D0 46 40 00 8B C3 83 C0 24 03 05 D8 46 40 00 3B 05 B4 46 40 00 0F 85 51 01 00 00 8D 45 F4 BA B8 46 40 00 B9 10 00 00 00 E8 A2 EC FF FF 8B 45 F4 BA 9C 2C 40 00 E8 F1 ED FF FF }

	condition:
		$a0
}

import "pe"

rule Mew10execoder10NorthfoxHCC : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 33 C0 E9 [2] FF FF 6A [5] 70 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PECrypt102 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E8 00 00 00 00 5B 83 EB 05 EB 04 52 4E 44 21 85 C0 73 02 F7 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule DIETv100d : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { FC 06 1E 0E 8C C8 01 [3] BA [2] 03 [14] 00 00 00 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule RLPackV119LZMA430ap0x : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 83 7C 24 28 01 75 0C 8B 44 24 24 89 85 49 0B 00 00 EB 0C 8B 85 45 0B 00 00 89 85 49 0B 00 00 8D B5 6D 0B 00 00 8D 9D 2F 03 00 00 33 FF 6A 40 68 00 10 00 00 68 00 20 0C 00 6A 00 FF 95 DA 0A 00 00 89 85 41 0B 00 00 E8 76 01 00 00 EB 20 60 8B 85 49 0B 00 00 FF B5 41 0B 00 00 FF 34 37 01 04 24 FF 74 37 04 01 04 24 FF D3 61 83 C7 08 83 3C 37 00 75 DA 83 BD 55 0B 00 00 00 74 0E 83 BD 59 0B 00 00 00 74 05 E8 D7 01 00 00 8D 74 37 04 53 6A 40 68 00 10 00 00 68 [4] 6A 00 FF 95 DA 0A 00 00 89 85 69 0B 00 00 5B 60 FF B5 41 0B 00 00 56 FF B5 69 0B 00 00 FF D3 61 8B B5 69 0B 00 00 8B C6 EB 01 40 80 38 01 75 FA 40 8B 38 03 BD 49 0B 00 00 83 C0 04 89 85 65 0B 00 00 E9 98 00 00 00 56 FF 95 D2 0A 00 00 89 85 61 0B 00 00 85 C0 0F 84 C8 00 00 00 8B C6 EB 5F 8B 85 65 0B 00 00 8B 00 A9 00 00 00 80 74 14 35 00 00 00 80 50 8B 85 65 0B 00 00 C7 00 20 20 20 00 EB 06 FF B5 65 0B 00 00 FF B5 61 0B 00 00 FF 95 D6 0A 00 00 85 C0 0F 84 87 00 00 00 89 07 83 C7 04 8B 85 65 0B 00 00 EB 01 40 80 38 00 75 FA 40 89 85 65 0B 00 00 66 81 78 02 00 80 74 A1 80 38 00 75 9C EB 01 46 80 3E 00 75 FA 46 40 8B 38 03 BD 49 0B 00 00 83 C0 04 89 85 65 0B 00 00 80 3E 01 0F 85 5F FF FF FF 68 00 40 00 00 68 [4] FF B5 69 0B 00 00 FF 95 DE 0A 00 00 68 00 40 00 00 68 00 20 0C 00 FF B5 41 0B 00 00 FF 95 DE 0A 00 00 E8 3D 00 00 00 E8 24 01 00 00 61 E9 [4] 61 C3 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule ENIGMAProtectorV112SukhovVladimir : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 00 00 00 00 5D 83 C5 FA 81 ED [3] 00 [31] E8 01 00 00 00 9A 83 C4 04 EB 02 FF 35 60 E8 24 00 00 00 00 00 FF EB 02 CD 20 8B 44 24 0C 83 80 B8 00 00 00 03 31 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule AHTeamEPProtector03fakeASPack212FEUERRADER : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 90 [46] 90 FF E0 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ED FF FF FF 03 DD 81 EB }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule MacromediaWindowsFlashProjectorPlayerv50 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 83 EC 44 56 FF 15 70 61 44 00 8B F0 8A 06 3C 22 75 1C 8A 46 01 46 3C 22 74 0C 84 C0 74 08 8A 46 01 46 3C 22 75 F4 80 3E 22 75 0F 46 EB 0C 3C 20 7E 08 8A 46 01 46 3C 20 7F F8 8A 06 84 C0 74 0C 3C 20 7F 08 8A 46 01 46 84 C0 75 F4 8D 44 24 04 C7 44 24 30 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule IDApplicationProtector12IDSecuritySuite : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED F2 0B 47 00 B9 19 22 47 00 81 E9 EA 0E 47 00 89 EA 81 C2 EA 0E 47 00 8D 3A 89 FE 31 C0 E9 D3 02 00 00 CC CC CC CC E9 CA 02 00 00 43 3A 5C 57 69 6E 64 6F 77 73 5C 53 6F 66 74 57 61 72 65 50 72 6F 74 65 63 74 6F 72 5C }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule WWPACKv305c4ExtractablePasswordchecking : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 03 05 80 1A B8 [2] 8C CA 03 D0 8C C9 81 C1 [2] 51 B9 [2] 51 06 06 B1 ?? 51 8C D3 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule HASPHLProtectionV1XAladdin : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 53 56 57 60 8B C4 A3 [4] B8 [4] 2B 05 [4] A3 [4] 83 3D [4] 00 74 15 8B 0D [4] 51 FF 15 [4] 83 C4 04 E9 A5 00 00 00 68 [4] FF 15 [4] A3 [4] 68 [4] FF 15 }
		$a1 = { 55 8B EC 53 56 57 60 8B C4 A3 [4] B8 [4] 2B 05 [4] A3 [4] 83 3D [4] 00 74 15 8B 0D [4] 51 FF 15 [4] 83 C4 04 E9 A5 00 00 00 68 [4] FF 15 [4] A3 [4] 68 [4] FF 15 [4] A3 [4] 8B 15 }

	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point
}

import "pe"

rule ASProtectv10 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 01 [3] 90 5D 81 ED [4] BB [4] 03 DD 2B 9D }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule ASProtectv11 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E9 ?? 04 [2] E9 [7] EE }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule Armadillov275a : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 6A FF 68 68 [3] 68 D0 [3] 64 A1 [4] 50 64 89 25 [4] 83 EC 58 53 56 57 89 65 E8 FF 15 28 [3] 33 D2 8A D4 89 15 24 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PseudoSigner0132Lite003Anorganix : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 06 FC 1E 07 BE 90 90 90 90 6A 04 68 90 10 90 90 68 [4] E9 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule VxDoom666 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E8 [3] 5E 83 EE ?? B8 CF 7B CD 21 3D CF 7B [2] 0E 1F 81 C6 [2] BF [2] B9 [2] FC F3 A4 06 1F 06 B8 [2] 50 CB B4 48 BB 2C 00 CD 21 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule VxSpanz : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E8 00 00 5E 81 EE [2] 8D 94 [2] B4 1A CD 21 C7 84 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule BeRoEXEPackerv100DLLLZBRSBeRoFarbrausch : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 83 7C 24 08 01 0F 85 [4] 60 BE [4] BF [4] FC AD 8D 1C 07 B0 80 3B FB 73 3B E8 [4] 72 03 A4 EB F2 E8 [4] 8D 51 FF E8 [4] 56 8B F7 2B F2 F3 A4 5E EB DB 02 C0 75 03 AC 12 C0 C3 33 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule Pksmart10b : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { BA [2] 8C C8 8B C8 03 C2 81 [3] 51 B9 [2] 51 1E 8C D3 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PELockv106 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 00 00 00 00 00 00 00 00 [8] 00 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 56 69 72 74 75 61 6C 41 6C 6C 6F 63 00 4B 45 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule LaunchAnywherev4001 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 89 E5 53 83 EC 48 55 B8 FF FF FF FF 50 50 68 E0 3E 42 00 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 68 C0 69 44 00 E8 E4 80 FF FF 59 E8 4E 29 00 00 E8 C9 0D 00 00 85 C0 75 08 6A FF E8 6E 2B 00 00 59 E8 A8 2C 00 00 E8 23 2E 00 00 FF 15 4C C2 44 00 89 C3 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule Upackv033v034BetaDwing : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 59 F3 A5 83 C8 FF 8B DF AB 40 AB 40 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule GameGuardnProtect : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 31 FF 74 06 61 E9 4A 4D 50 30 5A BA 7D 00 00 00 80 7C 24 08 01 E9 00 00 00 00 60 BE [4] 31 FF 74 06 61 E9 4A 4D 50 30 8D BE [4] 31 C9 74 06 61 E9 4A 4D 50 30 B8 7D 00 00 00 39 C2 B8 4C 00 00 00 F7 D0 75 3F 64 A1 30 00 00 00 85 C0 78 23 8B 40 0C 8B 40 0C C7 40 20 00 10 00 00 64 A1 18 00 00 00 8B 40 30 0F B6 40 02 85 C0 75 16 E9 12 00 00 00 31 C0 64 A0 20 00 00 00 85 C0 75 05 E9 01 00 00 00 61 57 83 CD FF EB 0B 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule yodasProtectorV1032AshkbizDanehkar : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E8 03 00 00 00 EB 01 ?? BB 55 00 00 00 E8 03 00 00 00 EB 01 ?? E8 8F 00 00 00 E8 03 00 00 00 EB 01 ?? E8 82 00 00 00 E8 03 00 00 00 EB 01 ?? E8 B8 00 00 00 E8 03 00 00 00 EB 01 ?? E8 AB 00 00 00 E8 03 00 00 00 EB 01 ?? 83 FB 55 E8 03 00 00 00 EB 01 ?? 75 2E E8 03 00 00 00 EB 01 ?? C3 60 E8 00 00 00 00 5D 81 ED 94 73 42 00 8B D5 81 C2 E3 73 42 00 52 E8 01 00 00 00 C3 C3 E8 03 00 00 00 EB 01 ?? E8 0E 00 00 00 E8 D1 FF FF FF C3 E8 03 00 00 00 EB 01 ?? 33 C0 64 FF 30 64 89 20 CC C3 E8 03 00 00 00 EB 01 ?? 33 C0 64 FF 30 64 89 20 4B CC C3 E8 03 00 00 00 EB 01 ?? 33 DB B9 BF A4 42 00 81 E9 8E 74 42 00 8B D5 81 C2 8E 74 42 00 8D 3A 8B F7 33 C0 E8 03 00 00 00 EB 01 ?? E8 17 00 00 00 90 90 90 E9 63 29 00 00 33 C0 64 FF 30 64 89 20 43 CC C3 }

	condition:
		$a0 at pe.entry_point
}

rule nBinderv40 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 5C 6E 62 34 5F 74 6D 70 5F 30 31 33 32 34 35 34 33 35 30 5C 00 00 00 00 00 00 00 00 00 E9 55 43 4C FF 01 1A 00 00 00 00 96 30 07 77 2C 61 0E EE BA 51 09 99 19 C4 6D 07 8F F4 6A 70 35 A5 63 E9 A3 95 64 9E 32 88 DB 0E A4 B8 DC 79 }

	condition:
		$a0
}

import "pe"

rule AnslymFUDCrypter : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 83 C4 F0 53 56 B8 38 17 05 10 E8 5A 45 FB FF 33 C0 55 68 21 1C 05 10 64 FF 30 64 89 20 EB 08 FC FC FC FC FC FC 27 54 E8 85 4C FB FF 6A 00 E8 0E 47 FB FF 6A 0A E8 27 49 FB FF E8 EA 47 FB FF 6A 0A }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule EPExEPackV10EliteCodingGroup : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 68 [4] B8 [4] FF 10 }

	condition:
		$a0 at pe.entry_point
}

rule SimplePack12build3009Method2bagie : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 4D 5A 90 EB 01 00 52 E9 86 01 00 00 50 45 00 00 4C 01 02 00 00 00 00 00 00 00 00 00 00 00 00 00 E0 00 0F 03 0B 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 0C 00 00 00 00 [3] 00 10 00 00 00 02 00 00 01 00 00 00 00 00 00 00 04 00 00 00 00 00 00 00 }

	condition:
		$a0
}

import "pe"

rule WinZip32bitSFXv6xmodule : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { FF 15 [3] 00 B1 22 38 08 74 02 B1 20 40 80 38 00 74 10 38 08 74 06 40 80 38 00 75 F6 80 38 00 74 01 40 33 C9 [4] FF 15 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule VxEinstein : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 00 42 CD 21 72 31 B9 6E 03 33 D2 B4 40 CD 21 72 19 3B C1 75 15 B8 00 42 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule VideoLanClient : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 89 E5 83 EC 08 [15] FF FF }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule CrunchPEv10xx : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 E8 [4] 5D 83 ED 06 8B C5 55 60 89 AD [4] 2B 85 [4] 89 85 [4] 80 BD [5] 75 09 C6 85 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule VxTravJack883 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB ?? 9C 9E 26 [2] 51 04 ?? 7D ?? 00 ?? 2E [4] 8C C8 8E C0 8E D8 80 [4] 74 ?? 8A [3] BB [2] 8A ?? 32 C2 88 ?? FE C2 43 81 }

	condition:
		$a0 at pe.entry_point
}

rule RSCsProcessPatcherv151 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 68 00 20 40 00 E8 C3 01 00 00 80 38 00 74 0D 66 81 78 FE 22 20 75 02 EB 03 40 EB EE 8B F8 B8 04 60 40 00 68 C4 20 40 00 68 D4 20 40 00 6A 00 6A 00 6A 04 6A 00 6A 00 6A 00 57 50 E8 9F 01 00 00 85 C0 0F 84 39 01 00 00 BE 00 60 40 00 8B 06 A3 28 21 40 00 83 }

	condition:
		$a0
}

import "pe"

rule kryptor9 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 [4] 5E B9 [4] 2B C0 02 04 0E D3 C0 49 79 F8 41 8D 7E 2C 33 46 ?? 66 B9 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule SecuPackv15 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 83 C4 F0 53 56 57 33 C0 89 45 F0 B8 CC 3A 40 ?? E8 E0 FC FF FF 33 C0 55 68 EA 3C 40 ?? 64 FF 30 64 89 20 6A ?? 68 80 [3] 6A 03 6A ?? 6A 01 [3] 80 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule kryptor5 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E8 03 [3] E9 EB 6C 58 40 FF E0 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule kryptor6 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E8 03 [3] E9 EB 68 58 33 D2 74 02 E9 E9 40 42 75 02 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule ACProtectV13Xrisco : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 50 E8 01 00 00 00 75 83 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PELockNTv202c : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB 02 C7 85 1E EB 03 CD 20 EB EB 01 EB 9C EB 01 EB EB 02 CD }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PseudoSigner02MinGWGCC2xAnorganix : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 89 E5 E8 02 00 00 00 C9 C3 90 90 45 58 45 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule FreeBASIC016b : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 89 E5 83 EC 08 C7 04 24 01 00 00 00 FF 15 [3] 00 E8 88 FF FF FF 89 EC 31 C0 5D C3 89 F6 55 89 E5 83 EC 08 C7 04 24 02 00 00 00 FF 15 [3] 00 E8 68 FF FF FF 89 EC 31 C0 5D C3 89 F6 55 89 E5 83 EC 08 8B 45 08 89 04 24 FF 15 [3] 00 89 EC 5D C3 8D 76 00 8D BC 27 00 00 00 00 55 89 E5 83 EC 08 8B 45 08 89 04 24 FF 15 [3] 00 89 EC 5D C3 90 90 90 90 90 90 90 90 90 90 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule RCryptorv16bv16cVaska : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 8B C7 03 04 24 2B C7 80 38 50 0F 85 1B 8B 1F FF 68 }
		$a1 = { 8B C7 03 04 24 2B C7 80 38 50 0F 85 1B 8B 1F FF 68 [4] B8 [4] 3D [4] 74 06 80 30 ?? 40 EB F3 }

	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point
}

import "pe"

rule FileShield : Packer PEiD hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 50 1E EB ?? 90 00 00 8B D8 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule SDC12SelfDecryptingBinaryGeneratorbyClaesMNyberg : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 89 E5 83 EC 08 C7 04 24 01 00 00 00 FF 15 A0 91 40 00 E8 DB FE FF FF 55 89 E5 53 83 EC 14 8B 45 08 8B 00 8B 00 3D 91 00 00 C0 77 3B 3D 8D 00 00 C0 72 4B BB 01 00 00 00 C7 44 24 04 00 00 00 00 C7 04 24 08 00 00 00 E8 CE 24 00 00 83 F8 01 0F 84 C4 00 00 00 85 C0 0F 85 A9 00 00 00 31 C0 83 C4 14 5B 5D C2 04 00 3D 94 00 00 C0 74 56 3D 96 00 00 C0 74 1E 3D 93 00 00 C0 75 E1 EB B5 3D 05 00 00 C0 8D B4 26 00 00 00 00 74 43 3D 1D 00 00 C0 75 CA C7 44 24 04 00 00 00 00 C7 04 24 04 00 00 00 E8 73 24 00 00 83 F8 01 0F 84 99 00 00 00 85 C0 74 A9 C7 04 24 04 00 00 00 FF D0 B8 FF FF FF FF EB 9B 31 DB 8D 74 26 00 E9 69 FF FF FF C7 44 24 04 00 00 00 00 C7 04 24 0B 00 00 00 E8 37 24 00 00 83 F8 01 74 7F 85 C0 0F 84 6D FF FF FF C7 04 24 0B 00 00 00 8D 76 00 FF D0 B8 FF FF FF FF E9 59 FF FF FF C7 04 24 08 00 00 00 FF D0 B8 FF FF FF FF E9 46 FF FF FF C7 44 24 04 01 00 00 00 C7 04 24 08 00 00 00 E8 ED 23 00 00 B8 FF FF FF FF 85 DB 0F 84 25 FF FF FF E8 DB 15 00 00 B8 FF FF FF FF E9 16 FF FF FF C7 44 24 04 01 00 00 00 C7 04 24 04 00 00 00 E8 BD 23 00 00 B8 FF FF FF FF E9 F8 FE FF FF C7 44 24 04 01 00 00 00 C7 04 24 0B 00 00 00 E8 9F 23 00 00 B8 FF FF FF FF E9 DA FE FF FF }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PKLITEv1501 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 50 B8 [2] BA [2] 05 [2] 3B 06 [2] 72 ?? B4 ?? BA [2] CD 21 B8 [2] CD 21 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule Inbuildv10hard : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { B9 [2] BB [2] 2E [2] 2E [2] 43 E2 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule ExeShieldvxx : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 65 78 65 73 68 6C 2E 64 6C 6C C0 5D 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule RCryptorv20Vaska : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { F7 D1 83 F1 FF 6A 00 F7 D1 83 F1 FF 81 04 24 ?? 02 00 00 F7 D1 83 F1 FF 59 BA 32 21 ?? 00 F7 D1 83 F1 FF F7 D1 83 F1 FF 80 02 E3 F7 D1 83 F1 FF C0 0A 05 F7 D1 83 F1 FF 80 02 6F F7 D1 83 F1 FF 80 32 A4 F7 D1 83 F1 FF 80 02 2D F7 D1 83 F1 FF 42 49 85 C9 75 CD 1C 4F 8D 5B FD 62 1E 1C 4F 8D 5B FD 4D 9D B9 [3] 1E 1C 4F 8D 5B FD 22 1C 4F 8D 5B FD 8E A2 B9 B9 E2 83 DB E2 E5 4D CD 1E BF 60 AB 1F 4D DB 1E 1E 3D 1E 92 1B 8E DC 7D EC A4 E2 4D E5 20 C6 CC B2 8E EC 2D 7D DC 1C 4F 8D 5B FD 83 56 8E E0 3A 7D D0 8E 9D 6E 7D D6 4D 25 06 C2 AB 20 CC 3A 4D 2D 9D 6B 0B 81 45 CC 18 4D 2D 1F A1 A1 6B C2 CC F7 E2 4D 2D 9E 8B 8B CC DE 2E 2D F7 1E AB 7D 45 92 30 8E E6 B9 7D D6 8E 9D 27 DA FD FD 1E 1E 8E DF B8 7D CF 8E A3 4D 7D DC 1C 4F 8D 5B FD 33 D7 1E 1E 1E A6 0B 41 A1 A6 42 61 6B 41 6B 4C 45 1E 21 F6 26 BC E2 62 1E 62 1E 62 1E 23 63 59 ?? 1E 62 1E 62 1E 33 D7 1E 1E 1E 85 6B C2 41 AB C2 9F 23 6B C2 41 A1 1E C0 FD F0 FD 30 20 33 9E 1E 1E 1E 85 A2 0B 8B C2 27 41 EB A1 A2 C2 1E C0 FD F0 FD 30 62 1E 33 7E 1E 1E 1E C6 2D 42 AB 9F 23 6B C2 41 A1 1E C0 FD F0 FD 30 C0 FD F0 8E 1D 1C 4F 8D 5B FD E0 00 33 5E 1E 1E 1E BF 0B EC C2 E6 42 A2 C2 45 1E C0 FD F0 FD 30 CE 36 CC F2 1C 4F 8D 5B FD }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PECompactv125 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB 06 68 [4] C3 9C 60 E8 02 [3] 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 70 40 ?? 87 DD 8B 85 A6 70 40 ?? 01 85 03 70 40 ?? 66 C7 85 70 40 90 ?? 90 01 85 9E 70 40 BB ?? F3 0D }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule RCryptorv1Vaska : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 90 58 90 50 90 8B 00 90 3C 50 90 58 0F 85 67 D6 EF 11 50 68 }
		$a1 = { 90 58 90 50 90 8B 00 90 3C 50 90 58 0F 85 67 D6 EF 11 50 68 [4] B8 [4] 3D [4] 74 06 80 30 ?? 40 EB F3 }

	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point
}

import "pe"

rule PECompactv122 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB 06 68 [4] C3 9C 60 E8 02 [3] 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 70 40 ?? 87 DD 8B 85 A6 70 40 ?? 01 85 03 70 40 ?? 66 C7 85 ?? 70 40 ?? 90 90 01 85 9E 70 40 ?? BB F3 08 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule Packmanv10BrandonLaCombe : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 00 00 00 00 5B 8D 5B C6 01 1B 8B 13 8D 73 14 6A 08 59 01 16 AD 49 75 FA 8B E8 C6 06 E9 8B 43 0C 89 46 01 6A 04 68 00 10 00 00 FF 73 08 51 FF 55 08 8B }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule SpecialEXEPaswordProtectorV101EngPavolCerven : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED 06 00 00 00 89 AD 8C 01 00 00 8B C5 2B 85 FE 75 00 00 89 85 3E }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule ExeSmashervxx : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 9C FE 03 ?? 60 BE [2] 41 ?? 8D BE ?? 10 FF FF 57 83 CD FF EB 10 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PEArmor046ChinaCrackingGroup : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E8 AA 00 00 00 2D [2] 00 00 00 00 00 00 00 00 00 3D [2] 00 2D [2] 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 4B [2] 00 5C [2] 00 6F [2] 00 00 00 00 00 4B 45 52 4E 45 4C 33 32 2E 64 6C 6C 00 00 00 00 47 65 74 50 72 6F 63 41 }

	condition:
		$a0 at pe.entry_point
}

rule VMProtect106107PolyTech : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 9C 60 68 00 00 00 00 8B 74 24 28 BF [4] FC 89 F3 03 34 24 AC 00 D8 }

	condition:
		$a0
}

rule USSR031bySpirit : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E8 00 00 00 00 5D 83 C5 12 55 C3 20 83 B8 ED 20 37 EF C6 B9 79 37 9E 8C C9 30 C9 E3 01 C3 BE 32 [3] B0 ?? 30 06 8A 06 46 81 FE 00 [3] 7C F3 }

	condition:
		$a0
}

import "pe"

rule PeCompact253DLLSlimLoaderBitSumTechnologies : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { B8 [4] 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 50 45 43 32 00 00 08 0C 00 48 E1 01 56 57 53 55 8B 5C 24 1C 85 DB 0F 84 AB 21 E8 BD 0E E6 60 0D 0B 6B 65 72 6E 6C 33 32 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule LameCryptv10 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 66 9C BB [4] 80 B3 00 10 40 00 90 4B 83 FB FF 75 F3 66 9D 61 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule Cygwin32 : Packer PEiD hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 89 E5 83 EC 04 83 3D }

	condition:
		$a0 at pe.entry_point
}

rule ASProtectv123RC4build0807exeAlexeySolodovnikov : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 90 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ED FF FF FF 03 DD 81 EB [4] 80 7D 4D 01 75 0C 8B 74 24 28 83 FE 01 89 5D 4E 75 31 8D 45 53 50 53 FF B5 D5 09 00 00 8D 45 35 50 E9 82 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

	condition:
		$a0
}

import "pe"

rule Armadillov210b2 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 6A FF 68 18 12 41 00 68 24 A0 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule Armadillov190 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 6A FF 68 10 F2 40 00 68 64 9A 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 }

	condition:
		$a0 at pe.entry_point
}

rule eXPressorProtection150XCGSoftLabs : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB 01 68 EB 01 [4] 83 EC 0C 53 56 57 EB 01 ?? 83 3D [4] 00 74 08 EB 01 E9 E9 56 01 00 00 EB 02 E8 E9 C7 05 [4] 01 00 00 00 EB 01 C2 E8 E2 05 00 00 EB 02 DA 9F 68 [4] 68 [4] B8 [4] FF D0 59 59 EB 01 C8 EB 02 66 F0 68 [4] E8 0E 05 00 00 59 EB 01 DD 83 65 F4 00 EB 07 8B 45 F4 40 89 45 F4 83 7D F4 61 73 1F EB 02 DA 1A 8B 45 F4 0F [6] 33 45 F4 8B 4D F4 88 [5] EB 01 EB EB }

	condition:
		$a0
}

import "pe"

rule VxNecropolis1963 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { B4 30 CD 21 3C 03 [2] B8 00 12 CD 2F 3C FF B8 [4] B4 4A BB 40 01 CD 21 [2] FA 0E 17 BC [2] E8 [2] FB A1 [2] 0B C0 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule Shrinkv20 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E9 [2] 50 9C FC BE [2] 8B FE 8C C8 05 [2] 8E C0 06 57 B9 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PseudoSigner02UPX06Anorganix : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 00 00 00 00 58 83 E8 3D 50 8D B8 00 00 00 FF 57 8D B0 E8 00 00 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PESpinV071cyberbob : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 83 D5 46 00 0B E4 74 9E }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule XHider10GlobaL : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 83 C4 EC 33 C0 89 45 EC B8 54 20 44 44 E8 DF F8 FF FF 33 C0 55 68 08 21 44 44 64 FF 30 64 89 20 8D 55 EC B8 1C 21 44 44 E8 E0 F9 FF FF 8B 55 EC B8 40 [2] 44 E8 8B F5 FF FF 6A 00 6A 00 6A 02 6A 00 6A 01 68 00 00 00 40 A1 40 [2] 44 E8 7E F6 FF FF 50 E8 4C F9 FF FF 6A 00 50 E8 4C F9 FF FF A3 28 [2] 44 E8 CE FE FF FF 33 C0 5A 59 59 64 89 10 68 0F 21 44 44 8D 45 EC E8 F1 F4 FF FF C3 E9 BB F2 FF FF EB F0 E8 FC F3 FF FF FF FF FF FF 0E 00 00 00 63 3A 5C 30 30 30 30 30 30 31 2E 64 61 74 00 }
		$a1 = { 85 D2 74 23 8B 4A F8 41 7F 1A 50 52 8B 42 FC E8 30 00 00 00 89 C2 58 52 8B 48 FC E8 48 FB FF FF 5A 58 EB 03 FF 42 F8 87 10 85 D2 74 13 8B 4A F8 49 7C 0D FF 4A F8 75 08 8D 42 F8 E8 5C FA FF FF C3 8D 40 00 85 C0 7E 24 50 83 C0 0A 83 E0 FE 50 E8 2F FA FF FF 5A 66 C7 44 02 FE 00 00 83 C0 08 5A 89 50 FC C7 40 F8 01 00 00 00 C3 31 C0 C3 90 }

	condition:
		$a0 at pe.entry_point or $a1
}

import "pe"

rule PseudoSigner01MicrosoftVisualC70DLLAnorganix : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8D 6C 01 00 81 EC 00 00 00 00 8B 45 90 83 F8 01 56 0F 84 00 00 00 00 85 C0 0F 84 [4] E9 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule EXEShieldV05Smoke : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E8 04 00 00 00 83 60 EB 0C 5D EB 05 45 55 EB 04 B8 EB F9 00 C3 E8 00 00 00 00 5D 81 ED BC 1A 40 00 EB 01 00 8D B5 46 1B 40 00 BA B3 0A 00 00 EB 01 00 8D 8D F9 25 40 00 8B 09 E8 14 00 00 00 83 EB 01 00 8B FE E8 00 00 00 00 58 83 C0 07 50 C3 00 EB 04 58 40 }
		$a1 = { E8 04 00 00 00 83 60 EB 0C 5D EB 05 45 55 EB 04 B8 EB F9 00 C3 E8 00 00 00 00 5D 81 ED BC 1A 40 00 EB 01 00 8D B5 46 1B 40 00 BA B3 0A 00 00 EB 01 00 8D 8D F9 25 40 00 8B 09 E8 14 00 00 00 83 EB 01 00 8B FE E8 00 00 00 00 58 83 C0 07 50 C3 00 EB 04 58 40 50 C3 8A 06 46 EB 01 00 D0 C8 E8 14 00 00 00 83 EB 01 00 2A C2 E8 00 00 00 00 5B 83 C3 07 53 C3 00 EB 04 5B 43 53 C3 EB 01 00 32 C2 E8 0B 00 00 00 00 32 C1 EB 01 00 C0 C0 02 EB 09 2A C2 5B EB 01 00 43 53 C3 88 07 EB 01 00 47 4A 75 B4 90 }

	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point
}

rule UnnamedScrambler25Ap0ke : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC B9 0B 00 00 00 6A 00 6A 00 49 75 F9 51 53 56 57 B8 6C 3E 40 00 E8 F7 EA FF FF 33 C0 55 68 60 44 40 00 64 FF 30 64 89 20 BA 70 44 40 00 B8 B8 6C 40 00 E8 62 F3 FF FF 8B D8 85 DB 75 07 6A 00 E8 A1 EB FF FF BA E8 64 40 00 8B C3 8B 0D B8 6C 40 00 E8 37 D3 FF FF C7 05 BC 6C 40 00 0A 00 00 00 BB 68 6C 40 00 BE 90 6C 40 00 BF E8 64 40 00 B8 C0 6C 40 00 BA 04 00 00 00 E8 07 EC FF FF 83 3B 00 74 04 33 C0 89 03 8B D7 8B C6 E8 09 F3 FF FF 89 03 83 3B 00 0F 84 BB 04 00 00 B8 C0 6C 40 00 8B 16 E8 06 E2 FF FF B8 C0 6C 40 00 E8 24 E1 FF FF 8B D0 8B 03 8B 0E E8 D1 D2 FF FF 8B C7 A3 20 6E 40 00 8D 55 EC 33 C0 E8 0C D4 FF FF 8B 45 EC B9 1C 6E 40 00 BA 18 6E 40 00 }

	condition:
		$a0
}

import "pe"

rule Armadillov177 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 6A FF 68 B0 71 40 00 68 6C 37 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule VxTrivial25 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { B4 4E FE C6 CD 21 B8 ?? 3D BA ?? 00 CD 21 93 B4 40 CD }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule KBySV022shoooo : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 68 [4] E8 01 00 00 00 C3 C3 11 55 07 8B EC B8 [4] E8 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule InnoSetupModule : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 49 6E 6E 6F 53 65 74 75 70 4C 64 72 57 69 6E 64 6F 77 00 00 53 54 41 54 49 43 }
		$a1 = { 55 8B EC 83 C4 ?? 53 56 57 33 C0 89 45 F0 89 45 ?? 89 45 ?? E8 [2] FF FF E8 [2] FF FF E8 [2] FF FF E8 [2] FF FF E8 [2] FF FF }

	condition:
		$a0 at pe.entry_point or $a1
}

import "pe"

rule piritv15 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 5B 24 55 50 44 FB 32 2E 31 5D }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule SoftSentryv30 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 83 EC ?? 53 56 57 E9 B0 06 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule EncryptPEV22007411WFS : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 9C 64 FF 35 00 00 00 00 E8 1B 02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 [8] 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 [36] 00 00 00 00 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 00 00 47 65 74 54 65 6D 70 50 61 74 68 41 00 00 00 43 72 65 61 74 65 46 69 6C 65 41 00 00 00 43 72 65 61 74 65 46 69 6C 65 4D 61 70 70 69 6E 67 41 00 00 00 4D 61 70 56 69 65 77 4F 66 46 69 6C 65 00 00 00 55 6E 6D 61 70 56 69 65 77 4F 66 46 69 6C 65 00 00 00 43 6C 6F 73 65 48 61 6E 64 6C 65 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 45 78 69 74 50 72 6F 63 65 73 73 00 00 00 00 00 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule Armadillov19x : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 6A FF 68 98 [3] 68 10 [3] 64 A1 [4] 50 64 89 25 [4] 83 EC 58 53 56 57 89 65 E8 FF 15 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule Armadillov285 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 6A FF 68 68 [3] 68 [4] 64 A1 [4] 50 64 89 25 [4] 83 EC 58 53 56 57 89 65 E8 FF 15 28 [3] 33 D2 8A D4 89 15 24 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule ASProtectvxx : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 [5] 90 5D [11] 03 DD }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule ExeShieldv17 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB 06 68 90 1F 06 00 C3 9C 60 E8 02 00 00 00 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 3F 90 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule Splasherv10v30 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 9C 60 8B 44 24 24 E8 [4] 5D 81 ED [4] 50 E8 ED 02 [2] 8C C0 0F 84 }

	condition:
		$a0 at pe.entry_point
}

rule FreeCryptor01build002GlOFF : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 8B 04 24 40 90 83 C0 07 80 38 90 90 74 02 EB FF 90 68 27 [2] 00 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 FF E4 90 8B 04 24 64 A3 00 00 00 00 8B 64 24 08 90 83 C4 08 }

	condition:
		$a0
}

import "pe"

rule EXEShieldV06SMoKE : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E8 04 00 00 00 83 60 EB 0C 5D EB 05 45 55 EB 04 B8 EB F9 00 C3 E8 00 00 00 00 5D 81 ED D4 1A 40 00 EB 01 00 8D B5 5E 1B 40 00 BA A1 0B 00 00 EB 01 00 8D 8D FF 26 40 00 8B 09 E8 14 00 00 00 83 EB 01 00 8B FE E8 00 00 00 00 58 83 C0 07 50 C3 00 EB 04 58 40 }
		$a1 = { E8 04 00 00 00 83 60 EB 0C 5D EB 05 45 55 EB 04 B8 EB F9 00 C3 E8 00 00 00 00 5D 81 ED D4 1A 40 00 EB 01 00 8D B5 5E 1B 40 00 BA A1 0B 00 00 EB 01 00 8D 8D FF 26 40 00 8B 09 E8 14 00 00 00 83 EB 01 00 8B FE E8 00 00 00 00 58 83 C0 07 50 C3 00 EB 04 58 40 50 C3 8A 06 46 EB 01 00 D0 C8 E8 14 00 00 00 83 EB 01 00 2A C2 E8 00 00 00 00 5B 83 C3 07 53 C3 00 EB 04 5B 43 53 C3 EB 01 00 32 C2 E8 0B 00 00 00 00 32 C1 EB 01 00 C0 C0 02 EB 09 2A C2 5B EB 01 00 43 53 C3 88 07 EB 01 00 47 4A 75 B4 90 }

	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point
}

import "pe"

rule PseudoSigner02MicrosoftVisualBasic5060Anorganix : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 68 [4] E8 0A 00 00 00 00 00 00 00 00 00 30 00 00 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule RLPack118DllLZMA430ap0x : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 80 7C 24 08 01 0F 85 ?? 01 00 00 60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 [4] 8D 9D [4] 33 FF E8 9F 01 00 00 6A ?? 68 [4] 68 [4] 6A ?? FF 95 AA 0A 00 00 89 85 F9 0A 00 00 EB 14 60 FF B5 F9 0A 00 00 FF 34 37 FF 74 37 04 FF D3 61 83 C7 08 83 3C 37 00 75 E6 83 BD 0D 0B 00 00 00 74 0E 83 BD 11 0B 00 00 00 74 05 E8 F6 01 00 00 8D 74 37 04 53 6A ?? 68 [4] 68 [4] 6A ?? FF 95 AA 0A 00 00 89 85 1D 0B 00 00 5B 60 FF B5 F9 0A 00 00 56 FF B5 1D 0B 00 00 FF D3 61 8B B5 1D 0B 00 00 8B C6 EB 01 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PKLITEv100v103 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { B8 [2] BA [2] 8C DB 03 D8 3B }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule Shrinkerv34 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 83 3D B4 [4] 55 8B EC 56 57 75 6B 68 00 01 00 00 E8 ?? 0B 00 00 83 C4 04 8B 75 08 A3 B4 [3] 85 F6 74 23 83 7D 0C 03 77 1D 68 FF }
		$a1 = { BB [2] BA [2] 81 C3 07 00 B8 40 B4 B1 04 D3 E8 03 C3 8C D9 49 8E C1 26 03 0E 03 00 2B }

	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point
}

import "pe"

rule Shrinkerv32 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 83 3D [5] 55 8B EC 56 57 75 65 68 00 01 [2] E8 ?? E6 FF FF 83 C4 04 8B 75 08 A3 [4] 85 F6 74 1D 68 FF }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule Shrinkerv33 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 83 3D [3] 00 00 55 8B EC 56 57 75 65 68 00 01 00 00 E8 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PseudoSigner01JDPack1xJDProtect09Anorganix : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 22 00 00 00 5D 8B D5 81 ED 90 90 90 90 2B 95 90 90 90 90 81 EA 06 90 90 90 89 95 90 90 90 90 83 BD 45 00 01 00 01 E9 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule Upack024027beta028alphaDwing : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { BE 88 01 40 00 AD 8B F8 95 AD 91 F3 A5 AD B5 ?? F3 AB AD 50 97 51 58 8D 54 85 5C FF 16 72 57 2C 03 73 02 B0 00 3C 07 72 02 2C 03 50 0F B6 5F FF C1 E3 ?? B3 00 8D 1C 5B 8D 9C 9D 0C 10 00 00 B0 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PseudoSigner01LocklessIntroPackAnorganix : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 2C E8 EB 1A 90 90 5D 8B C5 81 ED F6 73 90 90 2B 85 90 90 90 90 83 E8 06 89 85 FF 01 EC AD E9 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule Armadillov250b3 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 6A FF 68 B8 [3] 68 F8 [3] 64 A1 [4] 50 64 89 25 [4] 83 EC 58 53 56 57 89 65 E8 FF 15 20 [3] 33 D2 8A D4 89 15 D0 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PEBundlev02v20x : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 9C 60 E8 02 [3] 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB [2] 40 ?? 87 DD 6A 04 68 ?? 10 [2] 68 ?? 02 [2] 6A ?? FF 95 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule SoftProtectwwwsoftprotectbyru : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E8 [4] 8D [5] C7 00 00 00 00 00 E8 [4] E8 [4] 8D [5] 50 E8 [4] 83 [5] 01 }

	condition:
		$a0 at pe.entry_point
}

rule NTPackerV2XErazerZ : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 4B 57 69 6E 64 6F 77 73 00 10 55 54 79 70 65 73 00 00 3F 75 6E 74 4D 61 69 6E 46 75 6E 63 74 69 6F 6E 73 00 00 47 75 6E 74 42 79 70 61 73 73 00 00 B7 61 50 4C 69 62 75 00 00 00 }

	condition:
		$a0
}

rule SiliconRealmsInstallStub : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 6A FF 68 ?? 92 40 00 68 [2] 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF 15 [2] 40 00 33 D2 8A D4 89 15 [2] 40 00 8B C8 81 E1 FF 00 00 00 89 0D [2] 40 00 C1 E1 08 03 CA 89 0D [2] 40 00 C1 E8 10 A3 }

	condition:
		$a0
}

import "pe"

rule Armadillov430v440SiliconRealmsToolworks : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 6A FF 68 40 [2] 00 68 80 [2] 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF 15 88 [2] 00 33 D2 8A D4 89 15 30 [2] 00 8B C8 81 E1 FF 00 00 00 89 0D 2C [2] 00 C1 E1 08 03 CA 89 0D 28 [2] 00 C1 E8 10 A3 24 }
		$a1 = { 60 E8 00 00 00 00 5D 50 51 0F CA F7 D2 9C F7 D2 0F CA EB 0F B9 EB 0F B8 EB 07 B9 EB 0F 90 EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC E9 9D 0F C9 8B CA F7 D1 59 58 50 51 0F CA F7 D2 9C F7 D2 0F CA EB 0F B9 EB 0F B8 EB 07 B9 EB 0F 90 EB 08 }

	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point
}

rule MoleBoxv20 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E8 [4] 60 E8 4F }

	condition:
		$a0
}

import "pe"

rule FucknJoyv10cUsAr : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED D8 05 40 00 FF 74 24 20 E8 8C 02 00 00 0B C0 0F 84 2C 01 00 00 89 85 6C 08 40 00 8D 85 2F 08 40 00 50 FF B5 6C 08 40 00 E8 EF 02 00 00 0B C0 0F 84 0C 01 00 00 89 85 3B 08 40 00 8D 85 3F 08 40 00 50 FF B5 6C 08 40 00 E8 CF 02 00 }
		$a1 = { 60 E8 00 00 00 00 5D 81 ED D8 05 40 00 FF 74 24 20 E8 8C 02 00 00 0B C0 0F 84 2C 01 00 00 89 85 6C 08 40 00 8D 85 2F 08 40 00 50 FF B5 6C 08 40 00 E8 EF 02 00 00 0B C0 0F 84 0C 01 00 00 89 85 3B 08 40 00 8D 85 3F 08 40 00 50 FF B5 6C 08 40 00 E8 CF 02 00 00 0B C0 0F 84 EC 00 00 00 89 85 4D 08 40 00 8D 85 51 08 40 00 50 FF B5 6C 08 40 00 E8 AF 02 00 00 0B C0 0F 84 CC 00 00 00 89 85 5C 08 40 00 8D 85 67 07 40 00 E8 7B 02 00 00 8D B5 C4 07 40 00 56 6A 64 FF 95 74 07 40 00 46 80 3E 00 75 FA C7 06 74 6D 70 2E 83 C6 04 C7 06 65 78 65 00 8D 85 36 07 40 00 E8 4C 02 00 00 33 DB 53 53 6A 02 53 53 68 00 00 00 40 8D 85 C4 07 40 00 50 FF 95 74 07 40 00 89 85 78 07 40 00 8D 85 51 07 40 00 E8 21 02 00 00 6A 00 8D 85 7C 07 40 00 50 68 00 [2] 00 8D 85 F2 09 40 00 50 FF }

	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point
}

import "pe"

rule PseudoSigner02VideoLanClientAnorganix : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 89 E5 83 EC 08 90 90 90 90 90 90 90 90 90 90 90 90 90 90 01 FF FF 01 01 01 00 01 90 90 90 90 90 90 90 90 90 90 90 90 90 90 00 01 00 01 00 01 90 90 00 01 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule SoftWrap : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 52 53 51 56 57 55 E8 [4] 5D 81 ED 36 [3] E8 ?? 01 [2] 60 BA [4] E8 [4] 5F }

	condition:
		$a0 at pe.entry_point
}

rule AI1Creator1Beta2byMZ : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E8 FE FD FF FF 6A 00 E8 0D 00 00 00 CC FF 25 78 10 40 00 FF 25 7C 10 40 00 FF 25 80 10 40 00 FF 25 84 10 40 00 FF 25 88 10 40 00 FF 25 8C 10 40 00 FF 25 90 10 40 00 FF 25 94 10 40 00 FF 25 98 10 40 00 FF 25 9C 10 40 00 FF 25 A0 10 40 00 FF 25 A4 10 40 00 FF 25 AC 10 40 00 }

	condition:
		$a0
}

import "pe"

rule JAMv211 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 50 06 16 07 BE [2] 8B FE B9 [2] FD FA F3 2E A5 FB 06 BD [2] 55 CB }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PECompactv0978 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB 06 68 [4] C3 9C 60 E8 02 [3] 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 24 88 40 ?? 87 DD 8B 85 A9 88 }

	condition:
		$a0 at pe.entry_point
}

rule Setup2GoInstallerStub : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 5B 53 45 54 55 50 5F 49 4E 46 4F 5D 0D 0A 56 65 72 }

	condition:
		$a0
}

import "pe"

rule themida1005httpwwworeanscom : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { B8 00 00 00 00 60 0B C0 74 58 E8 00 00 00 00 58 05 43 00 00 00 80 38 E9 75 03 61 EB 35 E8 00 00 00 00 58 25 00 F0 FF FF 33 FF 66 BB 19 5A 66 83 C3 34 66 39 18 75 12 0F B7 50 3C 03 D0 BB E9 44 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule yodasProtectorv1033exescrcomAshkbizDanehkar : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E8 03 00 00 00 EB 01 ?? BB 55 00 00 00 E8 03 00 00 00 EB 01 ?? E8 8E 00 00 00 E8 03 00 00 00 EB 01 ?? E8 81 00 00 00 E8 03 00 00 00 EB 01 ?? E8 B7 00 00 00 E8 03 00 00 00 EB 01 ?? E8 AA 00 00 00 E8 03 00 00 00 EB 01 ?? 83 FB 55 E8 03 00 00 00 EB 01 ?? 75 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule ORiENv211DEMO : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E9 5D 01 00 00 CE D1 CE CE 0D 0A 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 0D 0A 2D 20 4F 52 69 45 4E 20 65 78 65 63 75 74 61 62 6C 65 20 66 69 6C 65 73 20 70 72 6F }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PECompactv0977 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB 06 68 [4] C3 9C 60 E8 02 [3] 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB A0 86 40 ?? 87 DD 8B 85 2A 87 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PESpinv13betaCyberbob : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 71 DF 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 17 EB 07 EA EB 01 EB EB 0D FF }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule RCryptorv13bVaska : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 61 83 EF 4F 60 68 [4] FF D7 }
		$a1 = { 61 83 EF 4F 60 68 [4] FF D7 B8 [4] 3D [4] 74 06 80 30 ?? 40 EB F3 }

	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point
}

rule mkfpackllydd : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E8 00 00 00 00 5B 81 EB 05 00 00 00 8B 93 9F 08 00 00 53 6A 40 68 00 10 00 00 52 6A 00 FF 93 32 08 00 00 5B 8B F0 8B BB 9B 08 00 00 03 FB 56 57 E8 86 08 00 00 83 C4 08 8D 93 BB 08 00 00 52 53 FF E6 }

	condition:
		$a0
}

import "pe"

rule PESpinV03cyberbob : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 B7 CD 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 17 EB 07 EA EB 01 EB EB 0D FF E8 01 00 00 00 EA 5A 83 EA 0B FF E2 8B 95 CB 2C 40 00 8B 42 3C 03 C2 89 85 D5 2C 40 00 41 C1 E1 07 8B 0C 01 03 CA 8B 59 10 03 DA 8B 1B 89 9D E9 2C 40 00 53 8F 85 B6 2B 40 00 BB ?? 00 00 00 B9 75 0A 00 00 8D BD 7E 2D 40 00 4F 30 1C 39 FE CB E2 F9 68 3C 01 00 00 59 8D BD B6 36 40 00 C0 0C 39 02 E2 FA E8 02 00 00 00 FF 15 5A 8D 85 1F 53 56 00 BB 54 13 0B 00 D1 E3 2B C3 FF E0 E8 01 00 00 00 68 E8 1A 00 00 00 8D 34 28 B9 08 00 00 00 B8 [4] 2B C9 83 C9 15 0F A3 C8 0F 83 81 00 00 00 8D B4 0D DC 2C 40 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PseudoSigner02BorlandDelphiSetupModuleAnorganix : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 83 C4 90 53 56 57 33 C0 89 45 F0 89 45 D4 89 45 D0 E8 00 00 00 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PELOCKnt204 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB 03 CD 20 C7 1E EB 03 CD 20 EA 9C EB 02 EB 01 EB 01 EB 60 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule MacromediaWindowsFlashProjectorPlayerv60 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 83 EC 44 56 FF 15 24 81 49 00 8B F0 8A 06 3C 22 75 1C 8A 46 01 46 3C 22 74 0C 84 C0 74 08 8A 46 01 46 3C 22 75 F4 80 3E 22 75 0F 46 EB 0C }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule IMPostorPack10MahdiHezavehi : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { BE [3] 00 83 C6 01 FF E6 00 00 00 00 [2] 00 00 00 00 00 00 00 00 00 [3] 00 ?? 02 [2] 00 10 00 00 00 02 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PluginToExev102BoBBobSoft : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E8 00 00 00 00 29 C0 5D 81 ED 32 42 40 00 50 8F 85 DD 40 40 00 50 FF 95 11 42 40 00 89 85 D9 40 40 00 FF 95 0D 42 40 00 50 FF 95 21 42 40 00 80 38 00 74 16 8A 08 80 F9 22 75 07 50 FF 95 25 42 40 00 89 85 E1 40 40 00 EB 6C 6A 01 8F 85 DD 40 40 00 6A 58 6A 40 FF 95 15 42 40 00 89 85 D5 40 40 00 89 C7 68 00 08 00 00 6A 40 FF 95 15 42 40 00 89 47 1C C7 07 58 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PKLITEv120 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { B8 [2] BA [2] 05 [2] 3B 06 [2] 72 ?? B4 09 BA [2] CD 21 B4 4C CD 21 }

	condition:
		$a0 at pe.entry_point
}

rule PrivateexeProtectorV18SetiSoftTeam : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 4B 45 52 4E 45 4C 33 32 2E 44 4C 4C 00 [4] 00 00 00 00 00 00 45 78 69 74 50 72 6F 63 65 73 73 }

	condition:
		$a0
}

import "pe"

rule PENinjamodified : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 5D 8B C5 81 ED B2 2C 40 00 2B 85 94 3E 40 00 2D 71 02 00 00 89 85 98 3E 40 00 0F B6 B5 9C 3E 40 00 8B FD }

	condition:
		$a0 at pe.entry_point
}

rule DotFixNiceProtect21GPcHSoft : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E9 FF 00 00 00 60 8B 74 24 24 8B 7C 24 28 FC B2 80 33 DB A4 B3 02 E8 6D 00 00 00 73 F6 33 C9 E8 64 00 00 00 73 1C 33 C0 E8 5B 00 00 00 73 23 B3 02 41 B0 10 E8 4F 00 00 00 12 C0 73 F7 75 3F AA EB D4 E8 4D 00 00 00 2B CB 75 10 E8 42 00 00 00 EB 28 AC D1 E8 74 4D 13 C9 EB 1C 91 48 C1 E0 08 AC E8 2C 00 00 00 3D 00 7D 00 00 73 0A 80 FC 05 73 06 83 F8 7F 77 02 41 41 95 8B C5 B3 01 56 8B F7 2B F0 F3 A4 5E EB 8E 02 D2 75 05 8A 16 46 12 D2 C3 33 C9 41 E8 EE FF FF FF 13 C9 E8 E7 FF FF FF 72 F2 C3 2B 7C 24 28 89 7C 24 1C 61 C3 60 B8 [4] 03 C5 50 B8 [4] 03 C5 FF 10 BB [4] 03 DD 83 C3 0C 53 50 B8 [4] 03 C5 FF 10 6A 40 68 00 10 00 00 FF 74 24 2C 6A 00 FF D0 89 44 24 1C 61 C3 }

	condition:
		$a0
}

import "pe"

rule EXEStealthv276WebToolMaster : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB 65 45 78 65 53 74 65 61 6C 74 68 20 56 32 20 2D 20 77 77 77 2E 77 65 62 74 6F 6F 6C 6D 61 73 74 65 72 2E 63 6F 6D 20 59 4F 55 52 20 41 44 20 48 45 52 45 21 50 69 52 41 43 59 20 69 53 20 41 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule EXECryptor239DLLcompressedresources : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 50 68 [4] 58 C1 C0 0F E9 [3] 00 87 04 24 58 89 45 FC E9 [3] FF FF 05 [4] E9 [3] 00 C1 C3 18 E9 [4] 8B 55 08 09 42 F8 E9 [3] FF 83 7D F0 01 0F 85 [4] E9 [3] 00 87 34 24 5E 8B 45 FC 33 D2 56 8B F2 E9 [3] 00 BA [4] E8 [3] 00 A3 [4] C3 E9 [3] 00 C3 83 C4 04 C3 E9 [3] FF 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 E8 [3] 00 E9 [3] FF C1 C2 03 81 CA [4] 81 C2 [4] 03 C2 5A E9 [3] FF 81 E7 [4] 81 EF [4] 81 C7 [4] 89 07 E9 [4] 0F 89 [4] 87 14 24 5A 50 C1 C8 10 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule UnoPiX103110BaGiE : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 83 EC 04 C7 04 24 00 [3] C3 00 [2] 00 00 00 00 00 00 00 00 00 00 00 00 [2] 00 10 00 00 00 02 00 00 01 00 00 00 00 00 00 00 04 00 00 00 00 00 00 00 00 [2] 00 00 10 00 00 00 00 00 00 02 00 00 ?? 00 00 ?? 00 00 [2] 00 00 00 10 00 00 10 00 00 00 00 00 00 10 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PECompactv110b3 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB 06 68 [4] C3 9C 60 E8 02 [3] 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 60 40 ?? 87 DD 8B 85 95 60 40 ?? 01 85 03 60 40 ?? 66 C7 85 ?? 60 40 ?? 90 90 BB 95 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule IonicWindSoftware : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 9B DB E3 9B DB E2 D9 2D 00 [2] 00 55 89 E5 E8 }

	condition:
		$a0 at pe.entry_point
}

rule SimplePackV11XMethod2bagie : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 4D 5A 90 EB 01 00 52 E9 89 01 00 00 50 45 00 00 4C 01 02 00 }
		$a1 = { 4D 5A 90 EB 01 00 52 E9 89 01 00 00 50 45 00 00 4C 01 02 00 00 00 00 00 00 00 00 00 00 00 00 00 E0 00 0F 03 0B 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 0C 00 00 00 00 [3] 00 10 00 00 00 02 00 00 01 00 00 00 00 00 00 00 04 00 00 00 00 00 00 00 }

	condition:
		$a0 or $a1
}

import "pe"

rule PCGuardv500d : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { FC 55 50 E8 00 00 00 00 5D 60 E8 03 00 00 00 83 EB 0E EB 01 0C 58 EB 01 35 40 EB 01 36 FF E0 0B 61 B8 30 D2 40 00 EB 01 E3 60 E8 03 00 00 00 D2 EB 0B 58 EB 01 48 40 EB 01 35 FF E0 E7 61 2B E8 9C EB 01 D5 9D EB 01 0B 58 60 E8 03 00 00 00 83 EB 0E EB 01 0C }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PESHiELDv0251 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 5D 83 ED 06 EB 02 EA 04 8D }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule RLPackFullEdition117DLLaPLibAp0x : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 80 7C 24 08 01 0F 85 [4] 60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 53 03 00 00 8D 9D 02 02 00 00 33 FF E8 [4] EB 0F FF 74 37 04 FF 34 37 FF D3 83 C4 08 83 C7 08 83 3C 37 00 75 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PECompactv110b4 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB 06 68 [4] C3 9C 60 E8 02 [3] 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 60 40 ?? 87 DD 8B 85 95 60 40 ?? 01 85 03 60 40 ?? 66 C7 85 ?? 60 40 ?? 90 90 BB 44 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PseudoSigner02PEX099Anorganix : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 01 00 00 00 55 83 C4 04 E8 01 00 00 00 90 5D 81 FF FF FF 00 01 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule ThinstallVirtualizationSuite30XThinstallCompany : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 9C 60 68 [4] 68 [4] E8 00 00 00 00 58 BB [4] 2B C3 50 68 [4] 68 [4] 68 [4] E8 BA FE FF FF E9 [4] CC CC CC CC CC CC CC 55 8B EC 83 C4 F4 FC 53 57 56 8B 75 08 8B 7D 0C C7 45 FC 08 00 00 00 33 DB BA }
		$a1 = { 9C 60 68 [4] 68 [4] E8 00 00 00 00 58 BB [4] 2B C3 50 68 [4] 68 [4] 68 [4] E8 BA FE FF FF E9 [4] CC CC CC CC CC CC CC 55 8B EC 83 C4 F4 FC 53 57 56 8B 75 08 8B 7D 0C C7 45 FC 08 00 00 00 33 DB BA [4] 43 33 C0 E8 19 01 00 00 73 0E 8B 4D F8 E8 27 01 00 00 02 45 F7 AA EB E9 E8 04 01 00 00 0F 82 96 00 00 00 E8 F9 00 00 00 73 5B B9 04 00 00 00 E8 05 01 00 00 48 74 DE 0F 89 [4] E8 DF 00 00 00 73 1B 55 BD [4] E8 DF 00 00 00 88 07 47 4D 75 F5 E8 C7 00 00 00 72 E9 5D EB }

	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point
}

rule NullsoftInstallSystemv20 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 83 EC 0C 53 55 56 57 C7 44 24 10 70 92 40 00 33 DB C6 44 24 14 20 FF 15 2C 70 40 00 53 FF 15 84 72 40 00 BE 00 54 43 00 BF 00 04 00 00 56 57 A3 A8 EC 42 00 FF 15 C4 70 40 00 E8 8D FF FF FF 8B 2D 90 70 40 00 85 C0 75 21 68 FB 03 00 00 56 FF 15 5C 71 40 00 }

	condition:
		$a0
}

import "pe"

rule SLVc0deProtectorv11SLV : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E8 00 00 00 00 58 C6 00 EB C6 40 01 08 FF E0 E9 4C }
		$a1 = { E8 01 00 00 00 A0 5D EB 01 69 81 ED 5F 1A 40 00 8D 85 92 1A 40 00 F3 8D 95 83 1A 40 00 8B C0 8B D2 2B C2 83 E8 05 89 42 01 E8 FB FF FF FF 69 83 C4 08 E8 06 00 00 00 69 E8 F2 FF FF FF F3 B9 05 00 00 00 51 8D B5 BF 1A 40 00 8B FE B9 58 15 00 00 AC 32 C1 F6 }

	condition:
		$a0 at pe.entry_point or $a1
}

import "pe"

rule FreeJoinerSmallbuild031032GlOFF : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 50 32 ?? 66 8B C3 58 E8 ?? FD FF FF 6A 00 E8 0D 00 00 00 CC FF 25 78 10 40 00 FF 25 7C 10 40 00 FF 25 80 10 40 00 FF 25 84 10 40 00 FF 25 88 10 40 00 FF 25 8C 10 40 00 FF 25 90 10 40 00 FF 25 94 10 40 00 FF 25 98 10 40 00 FF 25 9C 10 40 00 FF 25 A0 10 40 00 FF 25 A4 10 40 00 FF 25 AC 10 40 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule SLVc0deProtectorv06SLV : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E8 49 00 00 00 69 E8 49 00 00 00 95 E8 4F 00 00 00 68 E8 1F 00 00 00 49 E8 E9 FF FF FF 67 E8 1F 00 00 00 93 E8 31 00 00 00 78 E8 DD FF FF FF 38 E8 E3 FF FF FF 66 E8 0D 00 00 00 04 E8 E3 FF FF FF 70 E8 CB FF FF FF 69 E8 DD FF FF FF 58 E8 DD FF FF FF 69 E8 E3 FF FF FF 79 E8 BF FF FF FF 69 83 C4 40 E8 00 00 00 00 5D 81 ED 97 11 40 00 8D B5 EF 11 40 00 B9 FE 2D 00 00 8B FE AC F8 [6] 90 }

	condition:
		$a0 at pe.entry_point
}

rule PEArmor04600759hying : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 00 00 00 00 00 00 00 00 [8] 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 [12] 00 00 00 00 4B 45 52 4E 45 4C 33 32 2E 64 6C 6C 00 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 47 65 74 4D 6F 64 75 6C 65 48 61 6E 64 6C 65 41 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 }

	condition:
		$a0
}

rule RpolycryptbyVaska2003071841 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 58 [7] E8 00 00 00 58 E8 00 [45] 00 00 00 [2] 04 }

	condition:
		$a0
}

import "pe"

rule DBPEvxxxDingBoy : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB 20 [2] 40 [29] 9C 55 57 56 52 51 53 9C E8 [4] 5D 81 ED }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule SoftwareCompressBGSoftware : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E9 BE 00 00 00 60 8B 74 24 24 8B 7C 24 28 FC B2 80 33 DB A4 B3 02 E8 6D 00 00 00 73 F6 33 C9 E8 64 00 00 00 73 1C 33 C0 E8 5B 00 00 00 73 23 B3 02 41 B0 10 E8 4F 00 00 00 12 C0 73 F7 75 3F AA EB D4 E8 4D 00 00 00 2B CB 75 10 E8 42 00 00 00 EB 28 AC D1 E8 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule WWPACKv305c4UnextrPasswcheckVirshield : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 03 05 C0 1B B8 [2] 8C CA 03 D0 8C C9 81 C1 [2] 51 B9 [2] 51 06 06 B1 ?? 51 8C D3 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule Upackv0399Dwing : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 0B 01 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 18 10 00 00 10 00 00 00 00 [2] 00 00 00 40 00 00 10 00 00 00 02 00 00 04 00 00 00 00 00 3A 00 04 00 00 00 00 00 00 00 00 [2] 00 00 02 00 00 00 00 00 00 ?? 00 00 00 00 00 10 00 00 ?? 00 00 00 00 10 00 00 10 00 00 00 00 00 00 0A 00 00 00 00 00 00 00 00 00 00 00 EE [2] 00 14 00 00 00 00 [2] 00 [2] 00 00 FF 76 38 AD 50 8B 3E BE F0 [2] 00 6A 27 59 F3 A5 FF 76 04 83 C8 FF 8B DF AB EB 1C 00 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 [3] 00 ?? 00 00 00 40 AB 40 B1 04 F3 AB C1 E0 0A B5 }
		$a1 = { BE B0 11 [2] AD 50 FF 76 34 EB 7C 48 01 [2] 0B 01 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 18 10 00 00 10 00 00 00 00 [3] 00 00 [2] 00 10 00 00 00 02 00 00 04 00 00 00 00 00 3A 00 04 00 00 00 00 00 00 00 00 [3] 00 02 00 00 00 00 00 00 }
		$a2 = { BE B0 11 [2] AD 50 FF 76 34 EB 7C 48 01 [2] 0B 01 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 18 10 00 00 10 00 00 00 00 [3] 00 00 [2] 00 10 00 00 00 02 00 00 04 00 00 00 00 00 3A 00 04 00 00 00 00 00 00 00 00 [3] 00 02 00 00 00 00 00 00 ?? 00 00 ?? 00 00 10 00 00 [2] 00 00 00 10 00 00 10 00 00 00 00 00 00 0A 00 00 00 00 00 00 00 00 00 00 00 EE [3] 14 00 00 00 00 [5] 00 00 FF 76 38 AD 50 8B 3E BE F0 [3] 6A 27 59 F3 A5 FF 76 04 83 C8 FF 8B DF AB EB 1C 00 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 [5] 00 00 00 40 AB 40 B1 04 F3 AB C1 E0 0A B5 ?? F3 AB 8B 7E 0C 57 51 E9 [4] 56 10 E2 E3 B1 04 D3 E0 03 E8 8D 53 18 33 C0 55 40 51 D3 E0 8B EA 91 FF 56 4C 99 59 D1 E8 13 D2 E2 FA 5D 03 EA 45 59 89 6B 08 56 8B F7 2B F5 F3 A4 AC 5E B1 80 AA 3B }

	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point or $a2 at pe.entry_point
}

import "pe"

rule UPXModifiedstub : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 79 07 0F B7 07 47 50 47 B9 57 48 F2 AE 55 FF 96 84 ?? 00 00 09 C0 74 07 89 03 83 C3 04 EB D8 FF 96 88 ?? 00 00 61 E9 [3] FF }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule Cryptic20Tughack : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { B8 00 00 40 00 BB [3] 00 B9 00 10 00 00 BA [3] 00 03 D8 03 C8 03 D1 3B CA 74 06 80 31 ?? 41 EB F6 FF E3 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule KGBSFX : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 BE 00 A0 46 00 8D BE 00 70 F9 FF 57 83 CD FF EB 10 90 90 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PECompactv20betaJeremyCollake : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { B8 [4] 05 [4] 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 CC 90 90 90 90 }

	condition:
		$a0 at pe.entry_point
}

rule DevCv4 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 89 E5 83 EC 08 83 C4 F4 6A ?? A1 [3] 00 FF D0 E8 ?? FF FF FF }

	condition:
		$a0
}

rule DevCv5 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 89 E5 83 EC 14 6A ?? FF 15 [3] 00 [14] 00 00 00 00 }

	condition:
		$a0
}

import "pe"

rule CRYPToCRACksPEProtectorV092LukasFleischer : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E8 01 00 00 00 E8 58 5B 81 E3 00 FF FF FF 66 81 3B 4D 5A 75 37 84 DB 75 33 8B F3 03 [2] 81 3E 50 45 00 00 75 26 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule UpackV037Dwing : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 0B 01 [14] 18 10 00 00 10 00 00 00 [8] 00 10 00 00 00 02 00 00 [12] 00 00 00 00 [32] 00 00 00 00 0A 00 00 00 00 00 00 00 00 00 00 00 [4] 14 00 00 00 [40] 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 }
		$a1 = { 60 E8 09 00 00 00 [9] 33 C9 5E 87 0E }
		$a2 = { BE [4] AD 50 FF [2] EB }

	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point or $a2 at pe.entry_point
}

import "pe"

rule Obsidiumv13037ObsidiumSoftware : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB 02 [2] E8 26 00 00 00 EB 03 [3] EB 01 ?? 8B 54 24 0C EB 04 [4] 83 82 B8 00 00 00 26 EB 01 ?? 33 C0 EB 02 [2] C3 EB 01 ?? EB 04 [4] 64 67 FF 36 00 00 EB 01 ?? 64 67 89 26 00 00 EB 01 ?? EB 03 [3] 50 EB 03 [3] 33 C0 EB 03 [3] 8B 00 EB 04 [4] C3 EB 03 [3] E9 FA 00 00 00 EB 03 [3] E8 D5 FF FF FF EB 04 [4] EB 01 ?? 58 EB 02 [2] EB 03 [3] 64 67 8F 06 00 00 EB 01 ?? 83 C4 04 EB 03 [3] E8 23 27 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule VxCompiler : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 8C C3 83 C3 10 2E 01 1E ?? 02 2E 03 1E ?? 02 53 1E }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule BJFntv13 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB ?? 3A [2] 1E EB ?? CD 20 9C EB ?? CD 20 EB ?? CD 20 60 EB }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule MSLRHv032afakePEtite21emadicius : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { B8 00 50 40 00 6A 00 68 BB 21 40 00 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 66 9C 60 50 83 C4 04 61 66 9D 64 8F 05 00 00 00 00 83 C4 08 EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule UPXShitv01500mhz : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E8 00 00 00 00 5E 83 C6 14 AD 89 C7 AD 89 C1 AD 30 07 47 E2 FB AD FF E0 C3 00 [2] 00 [3] 00 [3] 01 [3] 00 55 50 58 2D 53 68 69 74 20 76 30 2E 31 20 2D 20 77 77 77 2E 62 6C 61 63 6B 6C 6F 67 69 63 2E 6E 65 74 20 2D 20 63 6F 64 65 20 62 79 }
		$a1 = { E8 00 00 00 00 5E 83 C6 14 AD 89 C7 AD 89 C1 AD 30 07 47 E2 FB AD FF E0 C3 00 [2] 00 [3] 00 [7] 00 55 50 58 2D 53 68 69 74 20 76 30 2E 31 20 2D 20 77 77 77 2E 62 6C 61 63 6B 6C 6F 67 69 63 2E 6E 65 74 20 2D 20 63 6F 64 65 20 62 79 }
		$a2 = { E8 [4] 5E 83 C6 ?? AD 89 C7 AD 89 C1 AD 30 07 47 E2 ?? AD FF E0 C3 }

	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point or $a2 at pe.entry_point
}

import "pe"

rule PackmanV0001Bubbasoft : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 00 00 00 00 58 8D [5] 8D [5] 8D [5] 8D [2] 48 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule DJoinv07publicxorencryptiondrmist : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { C6 05 [2] 40 00 00 [8] 00 [4] 00 [5] 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule FreeJoinerSmallbuild033GlOFF : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 50 66 33 C3 66 8B C1 58 E8 AC FD FF FF 6A 00 E8 0D 00 00 00 CC FF 25 78 10 40 00 FF 25 7C 10 40 00 FF 25 80 10 40 00 FF 25 84 10 40 00 FF 25 88 10 40 00 FF 25 8C 10 40 00 FF 25 90 10 40 00 FF 25 94 10 40 00 FF 25 98 10 40 00 FF 25 9C 10 40 00 FF 25 A0 10 40 00 FF 25 A4 10 40 00 FF 25 AC 10 40 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule AnticrackSoftwareProtectorv109ACProtect : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 [8] 00 00 [12] E8 01 00 00 00 ?? 83 04 24 06 C3 [5] 00 }

	condition:
		$a0 at pe.entry_point
}

rule UnderGroundCrypterbyBooster2000 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 83 C4 F0 B8 74 3C 00 11 E8 94 F9 FF FF E8 BF FE FF FF E8 0A F3 FF FF 8B C0 }

	condition:
		$a0
}

import "pe"

rule MicroJoiner16coban2k : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 33 C0 64 8B 38 48 8B C8 F2 AF AF 8B 1F 66 33 DB 66 81 3B }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule WiseInstallerStubv11010291 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 81 EC 40 0F 00 00 53 56 57 6A 04 FF 15 F4 30 40 00 FF 15 74 30 40 00 8A 08 89 45 E8 80 F9 22 75 48 8A 48 01 40 89 45 E8 33 F6 84 C9 74 0E 80 F9 22 74 09 8A 48 01 40 89 45 E8 EB EE 80 38 22 75 04 40 89 45 E8 80 38 20 75 09 40 80 38 20 74 FA 89 45 }

	condition:
		$a0 at pe.entry_point
}

rule PrivateEXEProtector18 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { BB DC EE 0D 76 D9 D0 8D 16 85 D8 90 D9 D0 }

	condition:
		$a0
}

import "pe"

rule SimpleUPXCryptorv3042005multilayerencryptionMANtiCORE : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 B8 [3] 00 B9 18 00 00 00 80 34 08 ?? E2 FA 61 68 [3] 00 C3 }
		$a1 = { 60 B8 [4] B9 18 00 00 00 80 34 08 ?? E2 FA 61 68 [4] C3 }

	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point
}

import "pe"

rule Themida1201compressedOreansTechnologies : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { B8 00 00 [2] 60 0B C0 74 58 E8 00 00 00 00 58 05 43 00 00 00 80 38 E9 75 03 61 EB 35 E8 00 00 00 00 58 25 00 F0 FF FF 33 FF 66 BB 19 5A 66 83 C3 34 66 39 18 75 12 0F B7 50 3C 03 D0 BB E9 44 00 00 83 C3 67 39 1A 74 07 2D 00 10 00 00 EB DA 8B F8 B8 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PECompactv155 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB 06 68 [4] C3 9C 60 E8 02 [3] 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 80 40 ?? 87 DD 8B 85 A2 80 40 ?? 01 85 03 80 40 ?? 66 C7 85 ?? 80 40 ?? 90 90 01 85 9E 80 40 ?? BB 2D 12 }

	condition:
		$a0 at pe.entry_point
}

rule PolyCryptPE214b215JLabSoftwareCreationshsigned : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 50 6F 6C 79 43 72 79 70 74 20 50 45 20 28 63 29 20 32 30 30 34 2D 32 30 30 35 2C 20 4A 4C 61 62 53 6F 66 74 77 61 72 65 2E 00 50 00 43 00 50 00 45 }

	condition:
		$a0
}

import "pe"

rule PECompactv156 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB 06 68 [4] C3 9C 60 E8 02 [3] 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 90 40 ?? 87 DD 8B 85 A2 90 40 ?? 01 85 03 90 40 ?? 66 C7 85 ?? 90 40 ?? 90 90 01 85 9E 90 40 ?? BB 2D 12 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PGMPACKv013 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { FA 1E 17 50 B4 30 CD 21 3C 02 73 ?? B4 4C CD 21 FC BE [2] BF [2] E8 [2] E8 [2] BB [2] BA [2] 8A C3 8B F3 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PGMPACKv014 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 1E 17 50 B4 30 CD 21 3C 02 73 ?? B4 4C CD 21 FC BE [2] BF [2] E8 [2] E8 [2] BB [2] BA [2] 8A C3 8B F3 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PseudoSigner0232Lite003Anorganix : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 06 FC 1E 07 BE 90 90 90 90 6A 04 68 90 10 90 90 68 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule AHTeamEPProtector03fakePEtite22FEUERRADER : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 90 [46] 90 FF E0 B8 00 00 00 00 68 00 00 00 00 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 66 9C 60 50 }

	condition:
		$a0 at pe.entry_point
}

rule MEW10byNorthfox : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 33 C0 E9 [2] FF FF ?? 1C [2] 40 }

	condition:
		$a0
}

import "pe"

rule theWRAPbyTronDoc : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 83 C4 F0 53 56 57 33 C0 89 45 F0 B8 48 D2 4B 00 E8 BC 87 F4 FF BB 04 0B 4D 00 33 C0 55 68 E8 D5 4B 00 64 FF 30 64 89 20 E8 9C F4 FF FF E8 F7 FB FF FF 6A 40 8D 55 F0 A1 F0 ED 4B 00 8B 00 E8 42 2E F7 FF 8B 4D F0 B2 01 A1 F4 C2 40 00 E8 F7 20 F5 FF 8B F0 B2 01 A1 B4 C3 40 00 E8 F1 5B F4 FF 89 03 33 D2 8B 03 E8 42 1E F5 FF 66 B9 02 00 BA FC FF FF FF 8B C6 8B 38 FF 57 0C BA B8 A7 4D 00 B9 04 00 00 00 8B C6 8B 38 FF 57 04 83 3D B8 A7 4D 00 00 0F 84 5E 01 00 00 8B 15 B8 A7 4D 00 83 C2 04 F7 DA 66 B9 02 00 8B C6 8B 38 FF 57 0C 8B 0D B8 A7 4D 00 8B D6 8B 03 E8 2B 1F F5 FF 8B C6 E8 B4 5B F4 FF 33 D2 8B 03 E8 DF 1D F5 FF BA F0 44 4E 00 B9 01 00 00 00 8B 03 8B 30 FF 56 04 80 3D F0 44 4E 00 0A 75 3F BA B8 A7 4D 00 B9 04 00 00 00 8B 03 8B 30 FF 56 04 8B 15 B8 A7 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule Petitev211 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { B8 [4] 68 [4] 64 [6] 64 [6] 66 9C 60 50 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule Petitev212 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { B8 [4] 6A 00 68 [4] 64 [6] 64 [6] 66 9C 60 50 }

	condition:
		$a0 at pe.entry_point
}

rule MaskPEV20yzkzero : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { B8 18 00 00 00 64 8B 18 83 C3 30 C3 40 3E 0F B6 00 C1 E0 ?? 83 C0 ?? 36 01 04 24 C3 }

	condition:
		$a0
}

import "pe"

rule PseudoSigner01Morphine12Anorganix : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 EB 06 00 90 90 90 90 90 90 90 90 EB 08 E8 90 00 00 00 66 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 51 66 90 90 90 59 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule EZIPv10 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E9 19 32 00 00 E9 7C 2A 00 00 E9 19 24 00 00 E9 FF 23 00 00 E9 1E 2E 00 00 E9 88 2E 00 00 E9 2C }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule y0dasCrypterv12 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED F3 1D 40 00 B9 7B 09 00 00 8D BD 3B 1E 40 00 8B F7 AC [48] AA E2 CC }

	condition:
		$a0 at pe.entry_point
}

rule ChinaProtectdummy : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { C3 E8 [4] B9 [4] E8 [4] FF 30 C3 B9 [4] E8 [4] FF 30 C3 B9 [4] E8 [4] FF 30 C3 B9 [4] E8 [4] FF 30 C3 56 8B [3] 6A 40 68 00 10 00 00 8D [2] 50 6A 00 E8 [4] 89 30 83 C0 04 5E C3 8B 44 [2] 56 8D [2] 68 00 40 00 00 FF 36 56 E8 [4] 68 00 80 00 00 6A 00 56 E8 [4] 5E C3 }

	condition:
		$a0
}

import "pe"

rule BopCryptv10 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 BD [4] E8 [2] 00 00 }

	condition:
		$a0 at pe.entry_point
}

rule MinkeV101Codius : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 26 3D 4F 38 C2 82 37 B8 F3 24 42 03 17 9B 3A 83 01 00 00 CC 00 00 00 00 06 00 00 00 01 64 53 74 75 62 00 10 55 54 79 70 65 73 00 00 C7 53 79 73 74 65 6D 00 00 81 53 79 73 49 6E 69 74 00 0C 4B 57 69 6E 64 6F 77 73 00 00 8A 75 46 75 6E 63 74 69 6F 6E 73 }

	condition:
		$a0
}

import "pe"

rule PseudoSigner02BorlandDelphiDLLAnorganix : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 83 C4 B4 B8 90 90 90 90 E8 00 00 00 00 E8 00 00 00 00 8D 40 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule bambam004bedrock : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { BF [4] 83 C9 FF 33 C0 68 [4] F2 AE F7 D1 49 51 68 [4] E8 11 0A 00 00 83 C4 0C 68 [4] FF 15 [4] 8B F0 BF [4] 83 C9 FF 33 C0 F2 AE F7 D1 49 BF [4] 8B D1 68 [4] C1 E9 02 F3 AB 8B CA 83 E1 03 F3 AA BF [4] 83 C9 FF 33 C0 F2 AE F7 D1 49 51 68 [4] E8 C0 09 00 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule RLPackFullEdition117DLLLZMAAp0x : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 80 7C 24 08 01 0F 85 [4] 60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 5A 0A 00 00 8D 9D 40 02 00 00 33 FF E8 [4] 6A 40 68 [4] 68 [4] 6A 00 FF 95 EB 09 00 00 89 85 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PEtitev22 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { B8 [4] 68 [4] 64 FF 35 [4] 64 89 25 [4] 66 9C 60 50 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PEtitev20 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { B8 [4] 66 9C 60 50 8B D8 03 ?? 68 54 BC [2] 6A ?? FF 50 18 8B CC 8D A0 54 BC [2] 8B C3 8D 90 E0 15 [2] 68 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PEtitev21 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { B8 [4] 6A ?? 68 [4] 64 FF 35 [4] 64 89 25 [4] 66 9C 60 50 }

	condition:
		$a0 at pe.entry_point
}

rule ElicenseSystemV4000ViaTechInc : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 00 00 00 00 63 79 62 00 65 6C 69 63 65 6E 34 30 2E 64 6C 6C 00 00 00 00 }

	condition:
		$a0
}

import "pe"

rule VProtectorV10Build20041213testvcasm : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 6A FF 68 1A 89 40 00 68 56 89 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 E8 03 00 00 00 C7 84 00 58 EB 01 E9 83 C0 07 50 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule Themida18xxOreansTechnologies : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { B8 [4] 60 0B C0 74 68 E8 00 00 00 00 58 05 53 00 00 00 80 38 E9 75 13 61 EB 45 DB 2D 37 [3] FF FF FF FF FF FF FF FF 3D 40 E8 00 00 00 00 58 25 00 F0 FF FF 33 FF 66 BB 19 5A 66 83 C3 34 66 39 18 75 12 0F B7 50 3C 03 D0 BB E9 44 00 00 83 C3 67 }
		$a1 = { B8 [4] 60 0B C0 74 68 E8 00 00 00 00 58 05 53 00 00 00 80 38 E9 75 13 61 EB 45 DB 2D 37 [3] FF FF FF FF FF FF FF FF 3D 40 E8 00 00 00 00 58 25 00 F0 FF FF 33 FF 66 BB 19 5A 66 83 C3 34 66 39 18 75 12 0F B7 50 3C 03 D0 BB E9 44 00 00 83 C3 67 39 1A 74 07 2D 00 10 00 00 EB DA 8B F8 B8 [4] 03 C7 B9 [4] 03 CF EB 0A B8 [4] B9 [4] 50 51 E8 84 00 00 00 E8 00 00 00 00 58 2D 26 00 00 00 B9 EF 01 00 00 C6 00 E9 83 E9 05 89 48 01 61 E9 }

	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point
}

import "pe"

rule EXEJoinerv10 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 68 00 10 40 00 68 04 01 00 00 E8 39 03 00 00 05 00 10 40 C6 00 5C 68 [4] 68 [4] 6A 00 E8 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule MicroJoiner11coban2k : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { BE 0C 70 40 00 BB F8 11 40 00 33 ED 83 EE 04 39 2E 74 11 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PseudoSigner01FSG10Anorganix : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 90 90 90 90 68 [4] 67 64 FF 36 00 00 67 64 89 26 00 00 F1 90 90 90 90 BB D0 01 40 00 BF 00 10 40 00 BE 90 90 90 90 53 E8 0A 00 00 00 02 D2 75 05 8A 16 46 12 D2 C3 FC B2 80 A4 6A 02 5B E9 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule Armadillov200b2200b3 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 6A FF 68 00 F2 40 00 68 C4 A0 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule RAZOR1911encruptor : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E8 [2] BF [2] 3B FC 72 ?? B4 4C CD 21 BE [2] B9 [2] FD F3 A5 FC }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule tElock051tE : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { C1 EE 00 66 8B C9 EB 01 EB 60 EB 01 EB 9C E8 00 00 00 00 5E 83 C6 5E 8B FE 68 79 01 00 00 59 EB 01 EB AC 54 E8 03 00 00 00 5C EB 08 8D 64 24 04 FF 64 24 FC 6A 05 D0 2C 24 72 01 E8 01 24 24 5C F7 DC EB 02 CD 20 8D 64 24 FE F7 DC EB 02 CD 20 FE C8 E8 00 00 00 00 32 C1 EB 02 82 0D AA EB 03 82 0D 58 EB 02 1D 7A 49 EB 05 E8 01 00 00 00 7F AE 14 7E A0 77 76 75 74 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule SDProtectorBasicProEdition112RandyLi : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 6A FF 68 1D 32 13 05 68 88 88 88 08 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 58 64 A3 00 00 00 00 58 58 58 58 8B E8 E8 3B 00 00 00 E8 01 00 00 00 FF 58 05 53 00 00 00 51 8B 4C 24 10 89 81 B8 00 00 00 B8 55 01 00 00 89 41 20 33 C0 89 41 04 89 41 08 89 41 0C 89 41 10 59 C3 C3 C3 C3 C3 C3 C3 C3 C3 C3 C3 C3 C3 33 C0 64 FF 30 64 89 20 9C 80 4C 24 01 01 9D 90 90 C3 C3 C3 C3 C3 C3 C3 C3 C3 C3 C3 C3 64 8F 00 58 74 07 75 05 19 32 67 E8 E8 74 27 75 25 EB 00 EB FC 68 39 44 CD 00 59 9C 50 74 0F 75 0D E8 59 C2 04 00 55 8B EC E9 FA FF FF 0E E8 EF FF FF FF 56 57 53 78 03 79 01 E8 68 A2 AF 47 01 59 E8 01 00 00 00 FF 58 05 7B 03 00 00 03 C8 74 C4 75 C2 E8 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 E2 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule VxFaxFreeTopo : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { FA 06 33 C0 8E C0 B8 [2] 26 [4] 50 8C C8 26 [4] 50 CC 58 9D 58 26 [4] 58 26 [4] 07 FB }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PseudoSigner02MEW11SE10Anorganix : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E9 09 00 00 00 00 00 00 02 00 00 00 0C 90 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule Joinersignfrompinch250320072010 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 81 EC 04 01 00 00 8B F4 68 04 01 00 00 56 6A 00 E8 7C 01 00 00 33 C0 6A 00 68 80 00 00 00 6A 03 6A 00 6A 00 68 00 00 00 80 56 E8 50 01 00 00 8B D8 6A 00 6A 00 6A 00 6A 02 6A 00 53 E8 44 01 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule VxSK : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { CD 20 B8 03 00 CD 10 51 E8 00 00 5E 83 EE 09 }

	condition:
		$a0 at pe.entry_point
}

rule PEStubOEPv1x : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 40 48 BE 00 [2] 00 40 48 60 33 C0 B8 [3] 00 FF E0 C3 C3 }

	condition:
		$a0
}

import "pe"

rule MoleBoxV23XMoleStudiocom : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E8 00 00 00 00 60 E8 4F 00 00 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule VxHymn1865 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E8 [2] 5E 83 EE 4C FC 2E [4] 4D 5A [2] FA 8B E6 81 [3] FB 3B [5] 2E [5] 50 06 56 1E 0E 1F B8 00 C5 CD 21 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule kkrunchyRyd : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { BD 08 [2] 00 C7 45 00 [3] 00 FF 4D 08 C6 45 0C 05 8D 7D 14 31 C0 B4 04 89 C1 F3 AB BF [3] 00 57 BE [3] 00 31 C9 41 FF 4D 0C 8D 9C 8D A0 00 00 00 FF D6 10 C9 73 F3 FF 45 0C 91 AA 83 C9 FF 8D 5C 8D 18 FF D6 74 DD E3 17 8D 5D 1C FF D6 74 10 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PECryptv100v101 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E8 [4] 5B 83 EB 05 EB 04 52 4E 44 21 EB 02 CD 20 EB }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule CERBERUSv20 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 9C 2B ED 8C [2] 8C [2] FA E4 ?? 88 [2] 16 07 BF [2] 8E DD 9B F5 B9 [2] FC F3 A5 }

	condition:
		$a0 at pe.entry_point
}

rule EXECryptor2117StrongbitSoftCompleteDevelopment : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { BE [4] B8 00 00 [2] 89 45 FC 89 C2 8B 46 0C 09 C0 0F 84 ?? 00 00 00 01 D0 89 C3 50 FF 15 94 [3] 09 C0 0F 85 0F 00 00 00 53 FF 15 98 [3] 09 C0 0F 84 ?? 00 00 00 89 45 F8 6A 00 8F 45 F4 8B 06 09 C0 8B 55 FC 0F 85 03 00 00 00 8B 46 10 01 }

	condition:
		$a0
}

import "pe"

rule WWPACKv303 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { B8 [2] 8C CA 03 D0 8C C9 81 C1 [2] 51 B9 [2] 51 06 06 BB [2] 53 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule GHFProtectorpackonlyGPcH : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 68 [4] B8 [4] FF 10 68 [4] 50 B8 [4] FF 10 68 00 00 00 00 6A 40 FF D0 89 05 [4] 89 C7 BE [4] 60 FC B2 80 31 DB A4 B3 02 E8 6D 00 00 00 73 F6 31 C9 E8 64 00 00 00 73 1C 31 C0 E8 5B 00 00 00 73 23 B3 02 41 B0 10 E8 4F 00 00 00 10 C0 73 F7 75 3F AA EB D4 E8 4D 00 00 00 29 D9 75 10 E8 42 00 00 00 EB 28 AC D1 E8 74 4D 11 C9 EB 1C 91 48 C1 E0 08 AC E8 2C 00 00 00 3D 00 7D 00 00 73 0A 80 FC 05 73 06 83 F8 7F 77 02 41 41 95 89 E8 B3 01 56 89 FE 29 C6 F3 A4 5E EB 8E 00 D2 75 05 8A 16 46 10 D2 C3 31 C9 41 E8 EE FF FF FF 11 C9 E8 E7 FF FF FF 72 F2 C3 61 B9 FC FF FF FF 8B 1C 08 89 99 [4] E2 F5 90 90 BA [4] BE [4] 01 D6 8B 46 0C 85 C0 0F 84 87 00 00 00 01 D0 89 C3 50 B8 [4] FF 10 85 C0 75 08 53 B8 [4] FF 10 89 05 [4] C7 05 [4] 00 00 00 00 BA [4] 8B 06 85 C0 75 03 8B 46 10 01 D0 03 05 [4] 8B 18 8B 7E 10 01 D7 03 3D [4] 85 DB 74 2B F7 C3 00 00 00 80 75 04 01 D3 43 43 81 E3 FF FF FF 0F 53 FF 35 [4] B8 [4] FF 10 89 07 83 05 [4] 04 EB AE 83 C6 14 BA [4] E9 6E FF FF FF 68 [4] B8 [4] FF 10 68 [4] 50 B8 [4] FF 10 8B 15 [4] 52 FF D0 61 BA [4] FF E2 90 C3 }
		$a1 = { 60 68 [4] B8 [4] FF 10 68 [4] 50 B8 [4] FF 10 68 00 00 00 00 6A 40 FF D0 89 05 [4] 89 C7 BE [4] 60 FC B2 80 31 DB A4 B3 02 E8 6D 00 00 00 73 F6 31 C9 E8 64 00 00 00 73 1C 31 C0 E8 5B 00 00 00 73 23 B3 02 41 }

	condition:
		$a0 at pe.entry_point or $a1
}

import "pe"

rule yzpackV11UsAr : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 33 C0 8D 48 07 50 E2 FD 8B EC 64 8B 40 30 78 0C 8B 40 0C 8B 70 1C AD 8B 40 08 EB 09 8B 40 34 8D 40 7C 8B 40 3C 89 45 04 E8 F3 07 00 00 60 8B 5D 04 8B 73 3C 8B 74 33 78 03 F3 56 8B 76 20 03 F3 33 C9 49 92 41 AD 03 C3 52 33 FF 0F B6 10 38 F2 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule VxDanishtiny : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 33 C9 B4 4E CD 21 73 02 FF ?? BA ?? 00 B8 ?? 3D CD 21 }

	condition:
		$a0 at pe.entry_point
}

rule UPXV194MarkusOberhumerLaszloMolnarJohnReiser : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { FF D5 80 A7 [5] 58 50 54 50 53 57 FF D5 58 61 8D 44 24 ?? 6A 00 39 C4 75 FA 83 EC 80 E9 }

	condition:
		$a0
}

import "pe"

rule yzpack112UsAr : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 5A 52 45 60 83 EC 18 8B EC 8B FC 33 C0 64 8B 40 30 78 0C 8B 40 0C 8B 70 1C AD 8B 40 08 EB 09 8B 40 34 83 C0 7C 8B 40 3C AB E9 [4] B4 09 BA 00 00 1F CD 21 B8 01 4C CD 21 40 00 00 00 50 45 00 00 4C 01 02 00 [4] 00 00 00 00 00 00 00 00 E0 00 [2] 0B 01 [4] 00 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PseudoSigner02YodasProtector102Anorganix : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E8 03 00 00 00 EB 01 90 90 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PseudoSigner02PESHiELD025Anorganix : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 2B 00 00 00 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 CC CC }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule NsPacKV34V35LiuXingPing : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 9C 60 E8 00 00 00 00 5D 83 ED 07 8D 85 [4] 80 38 01 0F 84 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule DualseXe10 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 81 EC 00 05 00 00 E8 00 00 00 00 5D 81 ED 0E 00 00 00 8D 85 08 03 00 00 89 28 33 FF 8D 85 7D 02 00 00 8D 8D 08 03 00 00 2B C8 8B 9D 58 03 00 00 E8 1C 02 00 00 8D 9D 61 02 00 00 8D B5 7C 02 00 00 46 80 3E 00 74 24 56 FF 95 0A 04 00 00 46 80 3E 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule NoodleCryptv200EngNoodleSpa : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB 01 9A E8 76 00 00 00 EB 01 9A E8 65 00 00 00 EB 01 9A E8 7D 00 00 00 EB 01 9A E8 55 00 00 00 EB 01 9A E8 43 04 00 00 EB 01 9A E8 E1 00 00 00 EB 01 9A E8 3D 00 00 00 EB 01 9A E8 EB 01 00 00 EB 01 9A E8 2C 04 00 00 EB 01 9A E8 25 00 00 00 EB 01 9A E8 02 }

	condition:
		$a0 at pe.entry_point
}

rule SoftComp1xBGSoftPT : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E8 00 00 00 00 81 2C 24 3A 10 41 00 5D E8 00 00 00 00 81 2C 24 31 01 00 00 8B 85 2A 0F 41 00 29 04 24 8B 04 24 89 85 2A 0F 41 00 58 8B 85 2A 0F 41 00 }

	condition:
		$a0
}

import "pe"

rule Petite13c1998IanLuck : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 9C 60 50 8D 88 00 [3] 8D 90 [2] 00 00 8B DC 8B E1 68 00 00 [2] 53 50 80 04 24 08 50 80 04 24 42 50 80 04 24 61 50 80 04 24 9D 50 80 04 24 BB 83 3A 00 0F 84 DA 14 00 00 8B 44 24 18 F6 42 03 80 74 19 FD 80 72 03 80 8B F0 8B F8 03 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PENightMarev13 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 00 00 00 00 5D B9 [4] 80 31 15 41 81 F9 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule Armadillo50DllSiliconRealmsToolworks : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 83 7C 24 08 01 75 05 E8 DE 4B 00 00 FF 74 24 04 8B 4C 24 10 8B 54 24 0C E8 ED FE FF FF 59 C2 0C 00 6A 0C 68 [4] E8 E5 24 00 00 8B 4D 08 33 FF 3B CF 76 2E 6A E0 58 33 D2 F7 F1 3B 45 0C 1B C0 40 75 1F E8 8F 15 00 00 C7 00 0C 00 00 00 57 57 57 57 57 E8 20 15 00 00 83 C4 14 33 C0 E9 D5 00 00 00 0F AF 4D 0C 8B F1 89 75 08 3B F7 75 03 33 F6 46 33 DB 89 5D E4 83 FE E0 77 69 83 3D [4] 03 75 4B 83 C6 0F 83 E6 F0 89 75 0C 8B 45 08 3B 05 [4] 77 37 6A 04 E8 D7 23 00 00 59 89 7D FC FF 75 08 E8 EC 53 00 00 59 89 45 E4 C7 45 FC FE FF FF FF E8 5F 00 00 00 8B 5D E4 3B DF 74 11 FF 75 08 57 53 E8 2B C5 FF FF 83 C4 0C 3B DF 75 61 56 6A 08 FF 35 [4] FF 15 [4] 8B D8 3B DF 75 4C 39 3D [4] 74 33 56 E8 19 ED FF FF 59 85 C0 0F 85 72 FF FF FF 8B 45 10 3B C7 0F 84 50 FF FF FF C7 00 0C 00 00 00 E9 45 FF FF FF 33 FF 8B 75 0C 6A 04 E8 7D 22 00 00 59 C3 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule ObsidiumV1350ObsidiumSoftware : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB 03 [3] E8 [4] EB 02 [2] EB 04 [4] 8B 54 24 0C EB 04 [4] 83 82 B8 00 00 00 20 EB 03 [3] 33 C0 EB 01 ?? C3 EB 02 [2] EB 03 [3] 64 67 FF 36 00 00 EB 03 [3] 64 67 89 26 00 00 EB 01 ?? EB 04 [4] 50 EB 04 [4] 33 C0 EB 04 [4] 8B 00 EB 03 [3] C3 EB 02 [2] E9 FA 00 00 00 EB 01 ?? E8 [4] EB 01 ?? EB 02 [2] 58 EB 04 [4] EB 02 [2] 64 67 8F 06 00 00 EB 02 [2] 83 C4 04 EB 01 ?? E8 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule ASProtectv123RC1 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 68 01 [2] 00 E8 01 00 00 00 C3 C3 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PUNiSHERv15DEMOFEUERRADERAHTeam : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB 04 83 A4 BC CE 60 EB 04 80 BC 04 11 E8 00 00 00 00 81 2C 24 CA C2 41 00 EB 04 64 6B 88 18 5D E8 00 00 00 00 EB 04 64 6B 88 18 81 2C 24 86 00 00 00 EB 04 64 6B 88 18 8B 85 9C C2 41 00 EB 04 64 6B 88 18 29 04 24 EB 04 64 6B 88 18 EB 04 64 6B 88 18 8B 04 }
		$a1 = { EB 04 83 A4 BC CE 60 EB 04 80 BC 04 11 E8 00 00 00 00 81 2C 24 CA C2 41 00 EB 04 64 6B 88 18 5D E8 00 00 00 00 EB 04 64 6B 88 18 81 2C 24 86 00 00 00 EB 04 64 6B 88 18 8B 85 9C C2 41 00 EB 04 64 6B 88 18 29 04 24 EB 04 64 6B 88 18 EB 04 64 6B 88 18 8B 04 24 EB 04 64 6B 88 18 89 85 9C C2 41 00 EB 04 64 6B 88 18 58 68 9F 6F 56 B6 50 E8 5D 00 00 00 EB FF 71 78 C2 50 00 EB D3 5B F3 68 89 5C 24 48 5C 24 58 FF 8D 5C 24 58 5B 83 C3 4C 75 F4 5A 8D 71 78 75 09 81 F3 EB FF 52 BA 01 00 83 EB FC 4A FF 71 0F 75 19 8B 5C 24 00 00 81 33 50 53 8B 1B 0F FF C6 75 1B 81 F3 EB 87 1C 24 8B 8B 04 24 83 EC FC EB 01 E8 83 EC FC E9 E7 00 00 00 58 EB FF F0 EB FF C0 83 E8 FD EB FF 30 E8 C9 00 00 00 89 E0 EB FF D0 EB FF 71 0F 83 C0 01 EB FF 70 F0 71 EE EB FA EB 83 C0 14 EB FF 70 ED }

	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point
}

import "pe"

rule PECompactv140b2v140b4 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB 06 68 [4] C3 9C 60 E8 02 [3] 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F A0 40 ?? 87 DD 8B 85 A6 A0 40 ?? 01 85 03 A0 40 ?? 66 C7 85 ?? A0 40 ?? 90 90 01 85 9E A0 40 ?? BB 86 11 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule NullsoftInstallSystemv198 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 83 EC 0C 53 56 57 FF 15 2C 81 40 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule CryptoLockv202EngRyanThian : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 BE 15 90 40 00 8D BE EB 7F FF FF 57 83 CD FF EB 10 90 90 90 90 90 90 8A 06 46 88 07 47 }
		$a1 = { 60 BE 15 90 40 00 8D BE EB 7F FF FF 57 83 CD FF EB 10 90 90 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 EF 75 09 8B 1E 83 EE FC 11 DB 73 E4 31 C9 83 E8 03 72 0D C1 E0 }
		$a2 = { 60 BE ?? 90 40 00 8D BE [2] FF FF 57 83 CD FF EB 10 90 90 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 EF 75 09 8B 1E 83 EE FC 11 DB 73 E4 31 C9 83 E8 03 72 0D C1 E0 }

	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point or $a2 at pe.entry_point
}

import "pe"

rule vfpexeNcv600WangJianGuo : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 01 00 00 00 63 58 E8 01 00 00 00 7A 58 2D 0D 10 40 00 8D 90 C1 10 40 00 52 50 8D 80 49 10 40 00 5D 50 8D 85 65 10 40 00 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 CC }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule XPEORv099b : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E8 00 00 00 00 5D 8B CD 81 ED 7A 29 40 00 89 AD 0F 6D 40 00 }
		$a1 = { E8 [4] 5D 8B CD 81 ED 7A 29 40 ?? 89 AD 0F 6D 40 }

	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point
}

import "pe"

rule PEiDBundlev100BoBBobSoft : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 21 02 00 00 8B 44 24 04 52 48 66 31 C0 66 81 38 4D 5A 75 F5 8B 50 3C 81 3C 02 50 45 00 00 75 E9 5A C2 04 00 60 89 DD 89 C3 8B 45 3C 8B 54 28 78 01 EA 52 8B 52 20 01 EA 31 C9 41 8B 34 8A }

	condition:
		$a0 at pe.entry_point
}

rule PeCompact2253276BitSumTechnologies : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { B8 [4] 55 53 51 57 56 52 8D 98 C9 11 00 10 8B 53 18 52 8B E8 6A 40 68 00 10 00 00 FF 73 04 6A 00 8B 4B 10 03 CA 8B 01 FF D0 5A 8B F8 50 52 8B 33 8B 43 20 03 C2 8B 08 89 4B 20 8B 43 1C 03 C2 8B 08 89 4B 1C 03 F2 8B 4B 0C 03 CA 8D 43 1C 50 57 56 FF }

	condition:
		$a0
}

import "pe"

rule PseudoSigner02CodeLockAnorganix : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 43 4F 44 45 2D 4C 4F 43 4B 2E 4F 43 58 00 01 28 01 50 4B 47 05 4C 3F B4 04 4D 4C 47 4B }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule FSGv100Engdulekxt : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { BB D0 01 40 00 BF 00 10 40 00 BE [3] 00 53 E8 0A 00 00 00 02 D2 75 05 8A 16 46 12 D2 C3 FC B2 80 A4 6A 02 5B FF 14 24 73 F7 33 C9 FF 14 24 73 18 33 C0 FF 14 24 73 21 B3 02 41 B0 10 FF 14 24 12 C0 73 F9 75 3F AA EB DC E8 43 00 00 00 2B CB 75 10 E8 38 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PseudoSigner01BorlandDelphi50KOLMCKAnorganix : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 90 90 90 90 68 [4] 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 00 FF 90 90 90 90 90 90 90 90 00 01 90 90 90 90 90 90 90 90 90 EB 04 00 00 00 01 90 90 90 90 90 90 90 00 01 90 90 90 90 90 90 90 90 90 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule FlyCrypter10ut1lz : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 53 56 57 55 BB 2C [2] 44 BE 00 30 44 44 BF 20 [2] 44 80 7B 28 00 75 16 83 3F 00 74 11 8B 17 89 D0 33 D2 89 17 8B E8 FF D5 83 3F 00 75 EF 83 3D 04 30 44 44 00 74 06 FF 15 58 30 44 44 80 7B 28 02 75 0A 83 3E 00 75 05 33 C0 89 43 0C FF 15 20 30 44 44 80 7B 28 01 76 05 83 3E 00 74 22 8B 43 10 85 C0 74 1B FF 15 18 30 44 44 8B 53 10 8B 42 10 3B 42 04 74 0A 85 C0 74 06 50 E8 2F FA FF FF FF 15 24 30 44 44 80 7B 28 01 75 03 FF 53 24 80 7B 28 00 74 05 E8 35 FF FF FF 83 3B 00 75 17 83 3D 10 [2] 44 00 74 06 FF 15 10 [2] 44 8B 06 50 E8 51 FA FF FF 8B 03 56 8B F0 8B FB B9 0B 00 00 00 F3 A5 5E E9 73 FF FF FF 5D 5F 5E 5B C3 A3 00 30 44 44 E8 26 FF FF FF C3 }
		$a1 = { 55 8B EC 83 C4 F0 53 B8 18 22 44 44 E8 7F F7 FF FF E8 0A F1 FF FF B8 09 00 00 00 E8 5C F1 FF FF 8B D8 85 DB 75 05 E8 85 FD FF FF 83 FB 01 75 05 E8 7B FD FF FF 83 FB 02 75 05 E8 D1 FD FF FF 83 FB 03 75 05 E8 87 FE FF FF 83 FB 04 75 05 E8 5D FD FF FF 83 FB 05 75 05 E8 B3 FD FF FF 83 FB 06 75 05 E8 69 FE FF FF 83 FB 07 75 05 E8 5F FE FF FF 83 FB 08 75 05 E8 95 FD FF FF 83 FB 09 75 05 E8 4B FE FF FF 5B E8 9D F2 FF FF 90 }

	condition:
		$a0 or $a1 at pe.entry_point
}

import "pe"

rule MSLRHv032afakePECompact14xemadicius : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB 06 68 2E A8 00 00 C3 9C 60 E8 02 00 00 00 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 3F 90 40 00 61 9D EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule muckisprotectorIImucki : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E8 24 00 00 00 8B 4C 24 0C C7 01 17 00 01 00 C7 81 B8 00 00 00 00 00 00 00 31 C0 89 41 14 89 41 18 80 6A 00 E8 85 C0 74 12 64 8B 3D 18 00 00 00 8B 7F 30 0F B6 47 02 85 C0 74 01 C3 C7 04 24 [4] BE [4] B9 [4] 8A 06 F6 D0 88 06 46 E2 F7 C3 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule VcasmProtector10 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 6A FF 68 [3] 00 68 [3] 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 E8 03 00 00 00 C7 84 00 58 EB 01 E9 83 C0 07 50 C3 FF 35 E8 03 00 00 00 C7 84 00 58 EB 01 E9 83 C0 07 50 C3 FF 35 E8 07 00 00 00 C7 83 83 C0 13 EB 0B 58 EB 02 CD 20 83 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule NullsoftInstallSystemv20b2v20b3 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 83 EC 0C 53 55 56 57 FF 15 ?? 70 40 00 8B 35 ?? 92 40 00 05 E8 03 00 00 89 44 24 14 B3 20 FF 15 2C 70 40 00 BF 00 04 00 00 68 [3] 00 57 FF 15 [2] 40 00 57 FF 15 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule VProtectorV10Dvcasm : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 6A FF 68 CA 31 41 00 68 06 32 41 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 E8 03 00 00 00 C7 84 00 58 EB 01 E9 83 C0 07 50 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule GardianAngel10 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 06 8C C8 8E D8 8E C0 FC BF [2] EB }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule eXpressorv12CGSoftLabs : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 81 EC D4 01 00 00 53 56 57 EB 0C 45 78 50 72 2D 76 }

	condition:
		$a0 at pe.entry_point
}

rule RSCsProcessPatcherv14 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E8 E1 01 00 00 80 38 22 75 13 80 38 00 74 2E 80 38 20 75 06 80 78 FF 22 74 18 40 EB ED 80 38 00 74 1B EB 19 40 80 78 FF 20 75 F9 80 38 00 74 0D EB 0B 40 80 38 00 74 05 80 38 22 74 00 8B F8 B8 04 60 40 00 68 00 20 40 00 C7 05 A2 20 40 00 44 00 00 00 68 92 }

	condition:
		$a0
}

import "pe"

rule Armadillov190b1 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 6A FF 68 E0 C1 40 00 68 04 89 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule Armadillov190b2 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 6A FF 68 F0 C1 40 00 68 A4 89 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule Armadillov190b3 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 6A FF 68 08 E2 40 00 68 94 95 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule FSGv110EngdulekxtBorlandDelphiMicrosoftVisualCASM : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB 02 CD 20 EB 02 CD 20 EB 02 CD 20 C1 E6 18 BB 80 [2] 00 EB 02 82 B8 EB 01 10 8D 05 F4 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule Thinstall25xxJtit : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC B8 [4] BB [4] 50 E8 00 00 00 00 58 2D ?? 1A 00 00 B9 ?? 1A 00 00 BA ?? 1B 00 00 BE 00 10 00 00 BF ?? 53 00 00 BD ?? 1A 00 00 03 E8 81 75 00 [5] 75 04 [4] 81 75 08 [4] 81 75 0C [4] 81 75 10 }
		$a1 = { 55 8B EC B8 [4] BB [4] 50 E8 00 00 00 00 58 2D ?? 1A 00 00 B9 ?? 1A 00 00 BA ?? 1B 00 00 BE 00 10 00 00 BF ?? 53 00 00 BD ?? 1A 00 00 03 E8 81 75 00 [5] 75 04 [4] 81 75 08 [4] 81 75 0C [4] 81 75 10 [4] 03 [23] 3B F1 7C 04 3B F2 7C 02 89 2E 83 C6 04 3B F7 7C E3 58 50 68 00 00 40 00 68 80 5A }

	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point
}

rule hmimysPacker10hmimys : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 5E 83 C6 64 AD 50 AD 50 83 EE 6C AD 50 AD 50 AD 50 AD 50 AD 50 E8 E7 07 }

	condition:
		$a0
}

import "pe"

rule ACProtectV20risco : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 68 [4] 68 [4] C3 C3 }

	condition:
		$a0 at pe.entry_point
}

rule RLPackV112V114LZMA430ap0x : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 [4] 8D 9D [4] 33 FF 6A ?? 68 [4] 68 [4] 6A ?? FF 95 [4] 89 85 [4] EB ?? 60 }

	condition:
		$a0
}

import "pe"

rule JDPack : Packer PEiD hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 [4] 5D 8B D5 81 ED [4] 2B 95 [4] 81 EA 06 [3] 89 95 [4] 83 BD 45 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PESpinv1304Cyberbob : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 88 DF 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 17 EB 07 EA EB 01 EB EB 0D FF }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule ScObfuscatorSuperCRacker : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 33 C9 8B 1D [4] 03 1D [4] 8A 04 19 84 C0 74 09 3C ?? 74 05 34 ?? 88 04 19 41 3B 0D [4] 75 E7 A1 [4] 01 05 [4] 61 FF 25 [4] 00 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule tElock098SpecialBuildforgotheXer : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E9 99 D7 FF FF 00 00 00 [4] AA [2] 00 00 00 00 00 00 00 00 00 CA }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PseudoSigner01DEF10Anorganix : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { BE 00 01 40 00 6A 05 59 80 7E 07 00 74 11 8B 46 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 83 C1 01 E9 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PseudoSigner02REALBasicAnorganix : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 89 E5 90 90 90 90 90 90 90 90 90 90 50 90 90 90 90 90 00 01 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule Armadillov260c : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 6A FF 68 40 [3] 68 F4 [3] 64 A1 [4] 50 64 89 25 [4] 83 EC 58 53 56 57 89 65 E8 FF 15 6C [3] 33 D2 8A D4 89 15 F4 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule Armadillov260a : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 6A FF 68 [4] 68 94 [3] 64 A1 [4] 50 64 89 25 [4] 83 EC 58 53 56 57 89 65 E8 FF 15 6C [3] 33 D2 8A D4 89 15 B4 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule ThemidaWinLicenseV10XV17XDLLOreansTechnologies : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { B8 [4] 60 0B C0 74 58 E8 00 00 00 00 58 05 [4] 80 38 E9 75 03 61 EB 35 E8 00 00 00 00 58 25 00 F0 FF FF 33 FF 66 BB [2] 66 83 [2] 66 39 18 75 12 0F B7 50 3C 03 D0 BB [4] 83 C3 ?? 39 1A 74 07 2D 00 10 00 00 EB DA 8B F8 B8 [4] 03 C7 B9 [4] 03 CF EB 0A B8 [4] B9 [4] 50 51 E8 84 00 00 00 E8 00 00 00 00 58 2D [4] B9 [4] C6 00 E9 83 E9 ?? 89 48 01 61 E9 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule eXPressor12CGSoftLabs : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 81 EC D4 01 00 00 53 56 57 EB 0C 45 78 50 72 2D 76 2E 31 2E 32 2E 2E }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule NeoLitev10 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 8B 44 24 04 8D 54 24 FC 23 05 [4] E8 [4] FF 35 [4] 50 FF 25 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule ExeBundlev30standardloader : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 00 00 00 00 60 BE 00 B0 42 00 8D BE 00 60 FD FF C7 87 B0 E4 02 00 31 3C 4B DF 57 83 CD FF EB 0E 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule ProtectionPlusvxx : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 50 60 29 C0 64 FF 30 E8 [4] 5D 83 ED 3C 89 E8 89 A5 14 [3] 2B 85 1C [3] 89 85 1C [3] 8D 85 27 03 [2] 50 8B ?? 85 C0 0F 85 C0 [3] 8D BD 5B 03 [2] 8D B5 43 03 [2] E8 DD [3] 89 85 1F 03 [2] 6A 40 68 ?? 10 [2] 8B 85 }

	condition:
		$a0 at pe.entry_point
}

rule EXECryptorV22Xsoftcompletecom : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { FF E0 E8 04 00 00 00 FF FF FF FF 5E C3 00 }

	condition:
		$a0
}

import "pe"

rule ThinstallVirtualizationSuite30353043ThinstallCompany : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 9C 60 68 53 74 41 6C 68 54 68 49 6E E8 00 00 00 00 58 BB 37 1F 00 00 2B C3 50 68 [4] 68 00 28 00 00 68 04 01 00 00 E8 BA FE FF FF E9 90 FF FF FF CC CC CC CC CC CC CC 55 8B EC 83 C4 F4 FC 53 57 56 8B 75 08 8B 7D 0C C7 45 FC 08 00 00 00 33 DB BA 00 00 00 80 43 33 C0 E8 19 01 00 00 73 0E 8B 4D F8 E8 27 01 00 00 02 45 F7 AA EB E9 E8 04 01 00 00 0F 82 96 00 00 00 E8 F9 00 00 00 73 5B B9 04 00 00 00 E8 05 01 00 00 48 74 DE 0F 89 C6 00 00 00 E8 DF 00 00 00 73 1B 55 BD 00 01 00 00 E8 DF 00 00 00 88 07 47 4D 75 F5 E8 C7 00 00 00 72 E9 5D EB }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PseudoSigner01CrunchPEHeuristicAnorganix : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 E8 0E 00 00 00 5D 83 ED 06 8B C5 55 60 89 AD [4] 2B 85 00 00 00 00 E9 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule FSGv120EngdulekxtBorlandC : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { C1 F0 07 EB 02 CD 20 BE 80 [2] 00 1B C6 8D 1D F4 00 00 00 0F B6 06 EB 02 CD 20 8A 16 0F B6 C3 E8 01 00 00 00 DC 59 80 EA 37 EB 02 CD 20 2A D3 EB 02 CD 20 80 EA 73 1B CF 32 D3 C1 C8 0E 80 EA 23 0F B6 C9 02 D3 EB 01 B5 02 D3 EB 02 DB 5B 81 C2 F6 56 7B F6 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule EXEPACKv405v406 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 8C C0 05 [2] 0E 1F A3 [2] 03 06 [2] 8E C0 8B 0E [2] 8B F9 4F 8B F7 FD F3 A4 }

	condition:
		$a0 at pe.entry_point
}

rule PeStubOEPv1x : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 90 33 C9 33 D2 B8 [3] 00 B9 FF }
		$a1 = { E8 05 00 00 00 33 C0 40 48 C3 E8 05 }

	condition:
		$a0 or $a1
}

import "pe"

rule EXEShieldv01bv03bv03SMoKE : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E8 04 00 00 00 83 60 EB 0C 5D EB 05 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PEArmor049Hying : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 56 52 51 53 55 E8 15 01 00 00 32 [2] 00 00 00 00 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PECompactv14x : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB 06 68 [4] C3 9C 60 E8 02 [3] 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PocketPCSHA : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 86 2F 96 2F A6 2F B6 2F 22 4F 43 68 53 6B 63 6A 73 69 F0 7F 0B D0 0B 40 09 00 09 D0 B3 65 A3 66 93 67 0B 40 83 64 03 64 04 D0 0B 40 09 00 10 7F 26 4F F6 6B F6 6A F6 69 0B 00 F6 68 [3] 00 [3] 00 [3] 00 22 4F F0 7F 0A D0 06 D4 06 D5 0B 40 09 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule eXPressorV1451CGSoftLabs : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 83 EC 58 53 56 57 83 65 DC 00 F3 EB 0C 65 58 50 72 2D 76 2E 31 2E 34 2E 00 A1 00 [2] 00 05 00 [2] 00 A3 08 [2] 00 A1 08 [2] 00 B9 81 [2] 00 2B 48 18 89 0D 0C [2] 00 83 3D }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule Thinstall25 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC B8 [4] BB [4] 50 E8 00 00 00 00 58 2D A7 1A 00 00 B9 6C 1A 00 00 BA 20 1B 00 00 BE 00 10 00 00 BF B0 53 00 00 BD EC 1A 00 00 03 E8 81 75 00 [4] 81 75 04 [4] 81 75 08 [4] 81 75 0C [4] 81 75 10 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule SuckStopv111 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB [3] BE [2] B4 30 CD 21 EB ?? 9B }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule DEFv10 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { BE ?? 01 40 00 6A 05 59 80 7E 07 00 74 11 8B 46 }
		$a1 = { BE ?? 01 40 00 6A ?? 59 80 7E 07 00 74 11 8B 46 0C 05 00 00 40 00 8B 56 10 30 10 40 4A 75 FA 83 C6 28 E2 E4 68 ?? 10 40 00 C3 }

	condition:
		$a0 at pe.entry_point or $a1
}

rule UnnamedScrambler251Beta2252p0ke : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC B9 ?? 00 00 00 6A 00 6A 00 49 75 F9 53 56 57 B8 [2] 40 00 E8 ?? EA FF FF 33 C0 55 68 [2] 40 00 64 FF 30 64 89 20 BA [2] 40 00 B8 [2] 40 00 E8 63 F3 FF FF 8B D8 85 DB 75 07 6A 00 E8 [2] FF FF BA [2] 40 00 8B C3 8B 0D [2] 40 00 E8 [2] FF FF C7 05 [2] 40 00 0A 00 00 00 BB [2] 40 00 BE [2] 40 00 BF [2] 40 00 B8 [2] 40 00 BA 04 00 00 00 E8 ?? EB FF FF 83 3B 00 74 04 33 C0 89 03 8B D7 8B C6 E8 0A F3 FF FF 89 03 83 3B 00 0F 84 F7 04 00 00 B8 [2] 40 00 8B 16 E8 ?? E1 FF FF B8 [2] 40 00 E8 ?? E0 FF FF 8B D0 8B 03 8B 0E E8 [2] FF FF 8B C7 A3 [2] 40 00 8D 55 EC 33 C0 E8 ?? D3 FF FF 8B 45 EC B9 [2] 40 00 BA [2] 40 00 E8 8B ED FF FF 3C 01 75 2B A1 }

	condition:
		$a0
}

import "pe"

rule Crunchv40 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 55 E8 00 00 00 00 5D 81 ED 18 00 00 00 8B C5 55 60 9C 2B 85 E9 06 00 00 89 85 E1 06 00 00 FF 74 24 2C E8 BB 01 00 00 0F 82 92 05 00 00 E8 F1 03 00 00 49 0F 88 86 05 00 00 68 6C D9 B2 96 33 C0 50 E8 24 }

	condition:
		$a0 at pe.entry_point
}

rule PrivateEXEProtector18SetiSoft : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { A4 B3 02 E8 6D 00 00 00 73 F6 31 C9 E8 64 00 00 00 73 1C 31 C0 E8 5B 00 00 00 73 23 B3 02 41 B0 10 E8 4F 00 00 00 10 C0 73 F7 75 3F AA EB D4 E8 4D 00 00 00 29 D9 75 10 E8 42 00 00 00 EB 28 AC D1 E8 74 4D 11 C9 EB 1C 91 48 C1 E0 08 AC E8 2C 00 00 00 3D 00 7D 00 00 73 0A 80 FC 05 73 06 83 F8 7F 77 02 41 41 95 89 E8 B3 01 56 89 FE 29 C6 F3 A4 5E EB 8E 00 D2 75 05 8A 16 46 10 D2 C3 31 C9 41 E8 EE FF FF FF 11 C9 E8 E7 FF FF FF 72 F2 C3 31 FF 31 F6 C3 }

	condition:
		$a0
}

import "pe"

rule PseudoSigner02Armadillo300Anorganix : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 2A 00 00 00 5D 50 51 EB 0F B9 EB 0F B8 EB 07 B9 EB 0F 90 EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC E9 59 58 50 51 EB 85 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule hmimyssPEPack01hmimys : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E8 00 00 00 00 5D 83 ED 05 6A 00 FF 95 E1 0E 00 00 89 85 85 0E 00 00 8B 58 3C 03 D8 81 C3 F8 00 00 00 80 AD 89 0E 00 00 01 89 9D 63 0F 00 00 8B 4B 0C 03 8D 85 0E 00 00 8B 53 08 80 BD 89 0E 00 00 00 75 0C 03 8D 91 0E 00 00 2B 95 91 0E 00 00 89 8D 57 0F 00 00 89 95 5B 0F 00 00 8B 5B 10 89 9D 5F 0F 00 00 8B 9D 5F 0F 00 00 8B 85 57 0F 00 00 53 50 E8 B7 0B 00 00 89 85 73 0F 00 00 6A 04 68 00 10 00 00 50 6A 00 FF 95 E9 0E 00 00 89 85 6B 0F 00 00 6A 04 68 00 10 00 00 68 D8 7C 00 00 6A 00 FF 95 E9 0E 00 00 89 85 6F 0F 00 00 8D 85 67 0F 00 00 8B 9D 73 0F 00 00 8B 8D 6B 0F 00 00 8B 95 5B 0F 00 00 83 EA 0E 8B B5 57 0F 00 00 83 C6 0E 8B BD 6F 0F 00 00 50 53 51 52 56 68 D8 7C 00 00 57 E8 01 01 00 00 8B 9D 57 0F 00 00 8B 03 3C 01 75 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PECompactv146 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB 06 68 [4] C3 9C 60 E8 02 [3] 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F A0 40 ?? 87 DD 8B 85 A6 A0 40 ?? 01 85 03 A0 40 ?? 66 C7 85 ?? A0 40 ?? 90 90 01 85 9E A0 40 ?? BB 60 12 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PseudoSigner02XCR011Anorganix : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 8B F0 33 DB 83 C3 01 83 C0 01 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule EXEPACKLINKv360v364v365or50121 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 8C C0 05 [2] 0E 1F A3 [2] 03 [3] 8E C0 8B [3] 8B ?? 4F 8B F7 FD F3 A4 50 B8 [2] 50 CB }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule SpecialEXEPasswordProtectorv10 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED 06 00 00 00 89 AD 8C 01 00 00 8B C5 2B 85 FE 75 00 00 89 85 3E 77 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule RCryptor15Vaska : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 83 2C 24 4F 68 [4] FF 54 24 04 83 44 24 04 4F B8 [4] 3D [4] 74 06 80 30 [2] EB F3 B8 [4] 3D [4] 74 06 80 30 ?? 40 EB F3 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule ExeJoiner10Yoda : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 68 00 10 40 00 68 04 01 00 00 E8 39 03 00 00 05 00 10 40 00 C6 00 5C 68 04 01 00 00 68 04 11 40 00 6A 00 E8 1A 03 00 00 6A 00 68 80 00 00 00 6A 03 6A 00 6A 01 68 00 00 00 80 68 04 11 40 00 E8 EC 02 00 00 83 F8 FF 0F 84 83 02 00 00 A3 08 12 40 00 6A 00 50 E8 E2 02 00 00 83 F8 FF 0F 84 6D 02 00 00 A3 0C 12 40 00 8B D8 83 EB 04 6A 00 6A 00 53 FF 35 08 12 40 00 E8 E3 02 00 00 6A 00 68 3C 12 40 00 6A 04 68 1E 12 40 00 FF 35 08 12 40 00 E8 C4 02 00 00 83 EB 04 6A 00 6A 00 53 FF 35 08 12 40 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule RLPackV119DllaPlib043ap0x : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 80 7C 24 08 01 0F 85 89 01 00 00 60 E8 00 00 00 00 8B 2C 24 83 C4 04 83 7C 24 28 01 75 0C 8B 44 24 24 89 85 3C 04 00 00 EB 0C 8B 85 38 04 00 00 89 85 3C 04 00 00 8D B5 60 04 00 00 8D 9D EB 02 00 00 33 FF E8 52 01 00 00 EB 1B 8B 85 3C 04 00 00 FF 74 37 04 01 04 24 FF 34 37 01 04 24 FF D3 83 C4 08 83 C7 08 83 3C 37 00 75 DF 83 BD 48 04 00 00 00 74 0E 83 BD 4C 04 00 00 00 74 05 E8 B8 01 00 00 8D 74 37 04 53 6A 40 68 00 10 00 00 68 [4] 6A 00 FF 95 D1 03 00 00 89 85 5C 04 00 00 5B FF B5 5C 04 00 00 56 FF D3 83 C4 08 8B B5 5C 04 00 00 8B C6 EB 01 40 80 38 01 75 FA 40 8B 38 03 BD 3C 04 00 00 83 C0 04 89 85 58 04 00 00 E9 94 00 00 00 56 FF 95 C9 03 00 00 85 C0 0F 84 B4 00 00 00 89 85 54 04 00 00 8B C6 EB 5B 8B 85 58 04 00 00 8B 00 A9 00 00 00 80 74 14 35 00 00 00 80 50 8B 85 58 04 00 00 C7 00 20 20 20 00 EB 06 FF B5 58 04 00 00 FF B5 54 04 00 00 FF 95 CD 03 00 00 85 C0 74 71 89 07 83 C7 04 8B 85 58 04 00 00 EB 01 40 80 38 00 75 FA 40 89 85 58 04 00 00 66 81 78 02 00 80 74 A5 80 38 00 75 A0 EB 01 46 80 3E 00 75 FA 46 40 8B 38 03 BD 3C 04 00 00 83 C0 04 89 85 58 04 00 00 80 3E 01 0F 85 63 FF FF FF 68 00 40 00 00 68 [4] FF B5 5C 04 00 00 FF 95 D5 03 00 00 E8 3D 00 00 00 E8 24 01 00 00 61 E9 [4] 61 C3 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule CrypKeyV56XKenonicControlsLtd : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E8 [4] E8 [4] 83 F8 00 75 07 6A 00 E8 }

	condition:
		$a0 at pe.entry_point
}

rule Safe20 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 83 EC 10 53 56 57 E8 C4 01 00 }

	condition:
		$a0
}

rule MZ_Crypt10byBrainSt0rm : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED 25 14 40 00 8B BD 77 14 40 00 8B 8D 7F 14 40 00 EB 28 83 7F 1C 07 75 1E 8B 77 0C 03 B5 7B 14 40 00 33 C0 EB 0C 50 8A A5 83 14 40 00 30 26 58 40 46 3B 47 10 76 EF 83 C7 28 49 0B C9 75 D4 8B 85 73 14 40 00 89 44 24 1C 61 FF E0 }

	condition:
		$a0
}

import "pe"

rule EPWv130 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 06 57 1E 56 55 52 51 53 50 2E 8C 06 08 00 8C C0 83 C0 10 2E }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule WindofCrypt10byDarkPressure : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 83 C4 EC 53 [4] 89 45 EC B8 64 40 00 10 E8 28 EA FF FF 33 C0 55 68 CE 51 00 10 64 [4] 20 6A 00 68 80 00 00 00 6A 03 6A 00 6A 01 68 00 00 00 80 8D 55 EC 33 C0 E8 F6 DB FF FF 8B 45 EC E8 12 E7 FF FF 50 E8 3C EA FF FF 8B D8 83 FB FF 0F 84 A6 00 00 00 6A 00 53 E8 41 EA FF FF 8B F0 81 EE 00 5E 00 00 6A 00 6A 00 68 00 5E 00 00 53 E8 52 EA FF FF B8 F4 97 00 10 8B D6 E8 2E E7 FF FF B8 F8 97 00 10 8B D6 E8 22 E7 FF FF 8B C6 E8 AB D8 FF FF 8B F8 6A 00 68 F0 97 00 10 56 A1 F4 97 00 10 50 53 E8 05 EA FF FF 53 E8 CF E9 FF FF B8 FC 97 00 10 BA E8 51 00 10 E8 74 EA FF FF A1 F4 97 00 10 85 C0 74 05 83 E8 04 8B 00 50 B9 F8 97 00 10 B8 FC 97 00 10 8B 15 F4 97 00 10 E8 D8 EA FF FF B8 FC 97 00 10 E8 5A EB FF FF 8B CE 8B 15 F8 97 00 10 8B C7 E8 EB E9 FF FF 8B C7 85 C0 74 05 E8 E4 EB FF FF 33 C0 5A 59 59 64 89 10 68 D5 51 00 10 8D 45 EC E8 BB E5 FF FF C3 E9 A9 DF FF FF EB F0 5F 5E 5B E8 B7 E4 FF FF 00 00 00 FF FF FF FF 0A 00 00 00 63 5A 6C 56 30 55 6C 6B 70 4D }

	condition:
		$a0 at pe.entry_point
}

rule NTKrnlPackerAshkbizDanehkar : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 00 00 00 00 00 00 00 00 00 00 00 00 34 10 00 00 28 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 41 10 00 00 50 10 00 00 00 00 00 00 4B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 47 65 74 }

	condition:
		$a0
}

import "pe"

rule PseudoSigner01LCCWin321xAnorganix : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 64 A1 01 00 00 00 55 89 E5 6A FF 68 [4] 68 9A 10 40 90 50 E9 }

	condition:
		$a0 at pe.entry_point
}

rule NME11Publicbyredlime : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 83 C4 F0 53 56 B8 30 35 14 13 E8 9A E6 FF FF 33 C0 55 68 6C 36 14 13 64 FF 30 64 89 20 B8 08 5C 14 13 BA 84 36 14 13 E8 7D E2 FF FF E8 C0 EA FF FF 8B 15 CC 45 14 13 A1 C8 45 14 13 E8 04 F8 FF FF 8B 15 D0 45 14 13 A1 C8 45 14 13 E8 F4 F7 FF FF 8B 15 CC 45 14 13 A1 C8 45 14 13 E8 2C F9 FF FF A3 F8 5A 14 13 8B 15 D0 45 14 13 A1 C8 45 14 13 E8 17 F9 FF FF A3 FC 5A 14 13 B8 04 5C 14 13 E8 20 FB FF FF 8B D8 85 DB 74 48 B8 00 5B 14 13 8B 15 C4 45 14 13 E8 1E E7 FF FF A1 04 5C 14 13 E8 A8 DA FF FF [4] 5C 14 13 50 8B CE 8B D3 B8 00 5B 14 13 [4] FF 8B C6 E8 DF FB FF FF 8B C6 E8 9C DA FF FF B8 00 5B 14 13 E8 72 E7 FF FF 33 C0 5A 59 59 64 89 10 68 73 36 14 13 C3 E9 0F DF FF FF EB F8 5E 5B E8 7E E0 FF FF 00 00 FF FF FF FF 0C 00 00 00 4E 4D 45 20 31 2E 31 20 53 74 75 62 }

	condition:
		$a0
}

import "pe"

rule PEtitev13 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 66 9C 60 50 8D 88 ?? F0 [2] 8D 90 04 16 [2] 8B DC 8B E1 68 [4] 53 50 80 04 24 08 50 80 04 24 42 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PEtitev12 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 9C 60 E8 CA [3] 03 ?? 04 ?? 05 ?? 06 ?? 07 ?? 08 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PECompactv134v140b1 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB 06 68 [4] C3 9C 60 E8 02 [3] 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 80 40 ?? 87 DD 8B 85 A6 80 40 ?? 01 85 03 80 40 ?? 66 C7 85 ?? 00 80 ?? 40 90 90 01 85 9E 80 ?? 40 BB F8 10 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule MSLRHv032afakeMSVC70DLLMethod3emadicius : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 53 8B 5D 08 56 8B 75 0C 5E 5B 5D EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PEtitev14 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 66 9C 60 50 8B D8 03 ?? 68 54 BC [2] 6A ?? FF 50 14 8B CC }
		$a1 = { 66 9C 60 50 8B D8 03 00 68 54 BC 00 00 6A 00 FF 50 14 8B CC }

	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point
}

import "pe"

rule SoftProtectSoftProtectbyru : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB 01 E3 60 E8 03 [3] D2 EB 0B 58 EB 01 48 40 EB 01 35 FF E0 E7 61 60 E8 03 [3] 83 EB 0E EB 01 0C 58 EB 01 35 40 EB 01 36 FF E0 0B 61 EB 01 83 9C EB 01 D5 EB 08 35 9D EB 01 89 EB 03 0B EB F7 E8 [4] 58 E8 [4] 59 83 01 01 80 39 5C }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PseudoSigner02CDCopsIIAnorganix : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 53 60 BD 90 90 90 90 8D 45 90 8D 5D 90 E8 00 00 00 00 8D 01 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule RLPack118LZMA430ap0x : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 ?? 8D B5 21 0B 00 00 8D 9D FF 02 00 00 33 FF E8 9F 01 00 00 6A ?? 68 [4] 68 [4] 6A 00 FF 95 AA 0A 00 00 89 85 F9 0A 00 00 EB 14 60 FF B5 F9 0A 00 00 FF 34 37 FF 74 37 04 FF D3 61 83 C7 ?? 83 3C 37 00 75 E6 83 BD 0D 0B 00 00 00 74 0E 83 BD 11 0B 00 00 00 74 05 E8 F6 01 00 00 8D 74 37 04 53 6A ?? 68 [4] 68 [4] 6A 00 FF 95 AA 0A 00 00 89 85 1D 0B 00 00 5B 60 FF B5 F9 0A 00 00 56 FF B5 1D 0B 00 00 FF D3 61 8B B5 1D 0B 00 00 8B C6 EB 01 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule ASPackv108xAlexeySolodovnikov : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 EB 03 5D FF E5 E8 F8 FF FF FF 81 ED 1B 6A 44 00 BB 10 6A 44 00 03 DD 2B 9D 2A }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PseudoSigner02BorlandCDLLMethod2Anorganix : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB 10 66 62 3A 43 2B 2B 48 4F 4F 4B 90 E9 90 90 90 90 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule ARMProtector01bySMoKE : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E8 04 00 00 00 83 60 EB 0C 5D EB 05 45 55 EB 04 B8 EB F9 00 C3 E8 00 00 00 00 5D EB 01 00 81 ED 5E 1F 40 00 EB 02 83 09 8D B5 EF 1F 40 00 EB 02 83 09 BA A3 11 00 00 EB 01 00 8D 8D 92 31 40 00 8B 09 E8 14 00 00 00 83 EB 01 00 8B FE E8 00 00 00 00 58 83 C0 07 50 C3 00 EB 04 58 40 50 C3 8A 06 46 EB 01 00 D0 C8 E8 14 00 00 00 83 EB 01 00 2A C2 E8 00 00 00 00 5B 83 C3 07 53 C3 00 EB 04 5B 43 53 C3 EB 01 00 32 C2 E8 0B 00 00 00 00 32 C1 EB 01 00 C0 C0 02 EB 09 2A C2 5B EB 01 00 43 53 C3 88 07 EB 01 00 47 4A 75 B4 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule tElock099cPrivateECLIPSEtE : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E9 3F DF FF FF 00 00 00 [4] 04 [2] 00 00 00 00 00 00 00 00 00 24 [2] 00 14 [2] 00 0C [2] 00 00 00 00 00 00 00 00 00 31 [2] 00 1C [2] 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 3C [2] 00 00 00 00 00 4F [2] 00 00 00 00 00 3C [2] 00 00 00 00 00 4F [2] 00 00 00 00 00 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 75 73 65 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule XPack152164 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 8B EC FA 33 C0 8E D0 BC [2] 2E [4] 2E [4] EB }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule ASProtectv123RC4build0807dllAlexeySolodovnikov : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ED FF FF FF 03 DD 81 EB 00 [3] 80 7D 4D 01 75 0C 8B 74 24 28 83 FE 01 89 5D 4E 75 31 8D 45 53 50 53 FF B5 D5 09 00 00 8D 45 35 50 E9 82 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule Armadillov253b3 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 6A FF 68 D8 [3] 68 14 [3] 64 A1 [4] 50 64 89 25 [4] 83 EC 58 53 56 57 89 65 E8 FF 15 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule Imploderv104BoBBobSoft : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 A0 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 36 [3] 2E [3] 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 00 80 00 00 00 00 4B 65 72 6E 65 6C 33 32 2E 44 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PEiDBundlev100v101BoBBobSoft : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 ?? 02 00 00 8B 44 24 04 52 48 66 31 C0 66 81 38 4D 5A 75 F5 8B 50 3C 81 3C 02 50 45 00 00 75 E9 5A C2 04 00 60 89 DD 89 C3 8B 45 3C 8B 54 28 78 01 EA 52 8B 52 20 01 EA 31 C9 41 8B 34 8A }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule JExeCompressor10byArashVeyskarami : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 8D 2D D3 4A E5 14 0F BB F7 0F BA E5 73 0F AF D5 8D 0D 0C 9F E6 11 C0 F8 EF F6 DE 80 DC 5B F6 DA 0F A5 C1 0F C1 F1 1C F3 4A 81 E1 8C 1F 66 91 0F BE C6 11 EE 0F C0 E7 33 D9 64 F2 C0 DC 73 0F C0 D5 55 8B EC BA C0 1F 41 00 8B C2 B9 97 00 00 00 80 32 79 50 B8 02 00 00 00 50 03 14 24 58 58 51 2B C9 B9 01 00 00 00 83 EA 01 E2 FB 59 E2 E1 FF E0 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule Alloy4xPGWareLLC : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 9C 60 E8 02 00 00 00 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 07 30 40 00 87 DD 6A 04 68 00 10 00 00 68 00 02 00 00 6A 00 FF 95 A8 33 40 00 0B C0 0F 84 F6 01 00 00 89 85 2E 33 40 00 83 BD E8 32 40 00 01 74 0D 83 BD E4 32 40 00 01 74 2A 8B F8 EB 3E 68 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule ThinstallV2403Jitit : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 6A 00 FF 15 20 50 40 00 E8 D4 F8 FF FF E9 E9 AD FF FF FF 8B C1 8B 4C 24 04 89 88 29 04 00 00 C7 40 0C 01 00 00 00 0F B6 49 01 D1 E9 89 48 10 C7 40 14 80 00 00 00 C2 04 00 8B 44 24 04 C7 41 0C 01 00 00 00 89 81 29 04 00 00 0F B6 40 01 D1 E8 89 41 10 C7 41 }
		$a1 = { 6A 00 FF 15 20 50 40 00 E8 D4 F8 FF FF E9 E9 AD FF FF FF 8B C1 8B 4C 24 04 89 88 29 04 00 00 C7 40 0C 01 00 00 00 0F B6 49 01 D1 E9 89 48 10 C7 40 14 80 00 00 00 C2 04 00 8B 44 24 04 C7 41 0C 01 00 00 00 89 81 29 04 00 00 0F B6 40 01 D1 E8 89 41 10 C7 41 14 80 00 00 00 C2 04 00 55 8B EC 53 56 57 33 C0 33 FF 39 45 0C 8B F1 76 0C 8B 4D 08 03 3C 81 40 3B 45 0C 72 F4 8B CE E8 43 00 00 00 8B 46 14 33 D2 F7 F7 8B 5E 10 33 D2 8B F8 8B C3 F7 F7 89 7E 18 89 45 0C 33 C0 33 C9 8B 55 08 03 0C 82 40 39 4D 0C 73 F4 48 8B 14 82 2B CA 0F AF CF 2B D9 0F AF FA 89 7E 14 89 5E 10 5F 5E 5B 5D C2 08 00 57 BF 00 00 80 00 39 79 14 77 36 53 56 8B B1 29 04 00 00 8B 41 0C 8B 59 10 03 DB 8A 14 30 83 E2 01 0B D3 C1 E2 07 40 89 51 10 89 41 0C 0F B6 04 30 C1 61 14 08 D1 E8 09 41 10 39 }

	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point
}

rule FakeNinjav28AntiDebugSpirit : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 64 A1 18 00 00 00 EB 02 C3 11 8B 40 30 EB 01 0F 0F B6 40 02 83 F8 01 74 FE EB 01 E8 90 C0 FF FF EB 03 BD F4 B5 64 A1 30 00 00 00 0F B6 40 02 74 01 BA 74 E0 50 00 64 A1 30 00 00 00 83 C0 68 8B 00 EB 00 83 F8 70 74 CF EB 02 EB FE 90 90 90 0F 31 33 C9 03 C8 0F 31 2B C1 3D FF 0F 00 00 73 EA E8 08 00 00 00 C1 3D FF 0F 00 00 74 AA EB 07 E8 8B 40 30 EB 08 EA 64 A1 18 00 00 00 EB F2 90 90 90 BA [4] FF E2 64 11 40 00 FF 35 84 11 40 00 E8 40 11 00 00 6A 00 6A 00 FF 35 70 11 40 00 FF 35 84 11 40 00 E8 25 11 00 00 FF }

	condition:
		$a0
}

import "pe"

rule ExeLockv100 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 06 8C C8 8E C0 BE [2] 26 [2] 34 ?? 26 [2] 46 81 [3] 75 ?? 40 B3 ?? B3 ?? F3 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PEtitevxx : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { B8 [4] 66 9C 60 50 }

	condition:
		$a0 at pe.entry_point
}

rule EnigmaProtector10XSukhovVladimir : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 00 00 00 00 5D 83 [2] 81 ED [35] E8 01 00 00 00 ?? 83 C4 04 EB 02 [2] 60 E8 24 00 00 00 00 00 ?? EB 02 [2] 8B 44 24 0C 83 80 B8 00 00 00 03 31 C0 C3 83 C0 08 EB 02 [2] 89 C4 61 EB 2E [7] EB 01 ?? 31 C0 EB 01 ?? 64 FF 30 EB 01 ?? 64 89 20 EB 02 [2] 89 00 9A 64 8F 05 00 00 00 00 EB 02 C1 ?? 58 61 EB 01 }

	condition:
		$a0
}

import "pe"

rule ThinstallEmbedded27172719Jitit : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 9C 60 E8 00 00 00 00 58 BB [4] 2B C3 50 68 [4] 68 [4] 68 [4] E8 C1 FE FF FF E9 97 FF FF FF CC CC 55 8B EC 83 C4 F4 FC 53 57 56 8B 75 08 8B 7D 0C C7 45 FC 08 00 00 00 33 DB BA 00 00 00 80 43 33 C0 E8 19 01 00 00 73 0E 8B 4D F8 E8 27 01 00 00 02 45 F7 AA EB E9 E8 04 01 00 00 0F 82 96 00 00 00 E8 F9 00 00 00 73 5B B9 04 00 00 00 E8 05 01 00 00 48 74 DE 0F 89 C6 00 00 00 E8 DF 00 00 00 73 1B 55 BD 00 01 00 00 E8 DF 00 00 00 88 07 47 4D 75 F5 E8 C7 00 00 00 72 E9 5D EB A2 B9 01 00 00 00 E8 D0 00 00 00 83 C0 07 89 45 F8 C6 45 F7 00 83 F8 08 74 89 E8 B1 00 00 00 88 45 F7 E9 7C FF FF FF B9 07 00 00 00 E8 AA 00 00 00 50 33 C9 B1 02 E8 A0 00 00 00 8B C8 41 41 58 0B C0 74 04 8B D8 EB 5E 83 F9 02 74 6A 41 E8 88 00 00 00 89 45 FC E9 48 FF FF FF E8 87 00 00 00 49 E2 09 8B C3 E8 7D 00 00 00 EB 3A 49 8B C1 55 8B 4D FC 8B E8 33 C0 D3 E5 E8 5D 00 00 00 0B C5 5D 8B D8 E8 5F 00 00 00 3D 00 00 01 00 73 14 3D FF 37 00 00 73 0E 3D 7F 02 00 00 73 08 83 F8 7F 77 04 41 41 41 41 56 8B F7 2B F0 F3 A4 5E E9 F0 FE FF FF 33 C0 EB 05 8B C7 2B 45 0C 5E 5F 5B C9 C2 08 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule ASPackv102bAlexeySolodovnikov : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED 96 78 43 00 B8 90 78 43 00 03 C5 }
		$a1 = { 60 E8 [4] 5D 81 ED 96 78 43 ?? B8 90 78 43 ?? 03 C5 2B 85 7D 7C 43 ?? 89 85 89 7C 43 ?? 80 BD 74 7C 43 }

	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point
}

rule PEProtect09byCristophGabler1998 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 50 45 2D 50 52 4F 54 45 43 54 20 30 2E 39 }

	condition:
		$a0
}

import "pe"

rule VxPredator2448 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 0E 1F BF [2] B8 [2] B9 [2] 49 [4] 2A C1 4F 4F [2] F9 CC }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule MSLRHv032afakeMSVC60DLLemadicius : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 53 8B 5D 08 56 8B 75 0C 57 8B 7D 10 85 F6 5F 5E 5B 5D EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule RCryptorv16dVaska : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 90 61 61 80 7F F0 45 90 60 0F 85 1B 8B 1F FF 68 }
		$a1 = { 60 90 61 61 80 7F F0 45 90 60 0F 85 1B 8B 1F FF 68 [4] B8 [4] 90 3D [4] 74 06 80 30 ?? 40 EB F3 }

	condition:
		$a0 at pe.entry_point or $a1
}

rule Enigmaprotector112VladimirSukhov : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 00 00 00 00 5D 83 ED 06 81 ED [35] E8 01 00 00 00 9A 83 C4 04 EB 02 FF 35 60 E8 24 00 00 00 00 00 FF EB 02 CD 20 8B 44 24 0C 83 80 B8 00 00 00 03 31 C0 C3 83 C0 08 EB 02 FF 15 89 C4 61 EB 2E EA EB 2B 83 04 24 03 EB 01 00 31 C0 EB 01 85 64 FF 30 EB 01 83 64 89 20 EB 02 CD 20 89 00 9A 64 8F 05 00 00 00 00 EB 02 C1 90 58 61 EB 01 3E EB 04 [4] B8 [35] E8 01 00 00 00 9A 83 C4 04 01 E8 [31] E8 01 00 00 00 9A 83 C4 04 05 F6 01 00 00 [31] E8 01 00 00 00 9A 83 C4 04 B9 44 1A }

	condition:
		$a0
}

import "pe"

rule hyingsPEArmorV076hying : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E9 00 00 00 00 60 E8 14 00 00 00 5D 81 ED 00 00 00 00 6A ?? E8 A3 00 00 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule JDPackV200JDPack : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 6A FF 68 [4] 68 [4] 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 [3] E8 01 00 00 00 [6] 05 00 00 00 00 83 C4 0C 5D 60 E8 00 00 00 00 5D 8B D5 64 FF 35 00 00 00 00 EB }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule Upackv01xv02xDwing : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { BE 88 01 [2] AD 8B F8 95 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule VcasmProtectorV1Xvcasm : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB ?? 5B 56 50 72 6F 74 65 63 74 5D }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule kkrunchy023alpha2Ryd : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { BD [4] C7 45 00 [3] 00 B8 [3] 00 89 45 04 89 45 54 50 C7 45 10 [3] 00 FF 4D 0C FF 45 14 FF 45 58 C6 45 1C 08 B8 00 08 00 00 8D 7D 30 AB AB AB AB BB 00 00 D8 00 BF }
		$a1 = { BD [4] C7 45 00 [3] 00 B8 [3] 00 89 45 04 89 45 54 50 C7 45 10 [3] 00 FF 4D 0C FF 45 14 FF 45 58 C6 45 1C 08 B8 00 08 00 00 8D 7D 30 AB AB AB AB BB 00 00 D8 00 BF [3] 01 31 C9 41 8D 74 09 01 B8 CA 8E 2A 2E 99 F7 F6 01 C3 89 D8 C1 E8 15 AB FE C1 75 E8 BE }

	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point
}

rule PolyEnEV001LennartHedlund : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 50 6F 6C 79 45 6E 45 00 4D 65 73 73 61 67 65 42 6F 78 41 00 55 53 45 52 33 32 2E 64 6C 6C }

	condition:
		$a0
}

import "pe"

rule Winkriptv10 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 33 C0 8B B8 00 [3] 8B 90 04 [3] 85 FF 74 1B 33 C9 50 EB 0C 8A 04 39 C0 C8 04 34 1B 88 04 39 41 3B CA 72 F0 58 }

	condition:
		$a0 at pe.entry_point
}

rule TrainerCreationKitv5Trainer : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 6A 00 68 80 00 00 00 6A 02 6A 00 6A 00 68 00 00 00 40 68 25 45 40 00 E8 3C 02 00 00 50 6A 00 68 40 45 40 00 68 00 10 00 00 68 00 30 40 00 50 E8 54 02 00 00 58 50 E8 17 02 00 00 6A 00 E8 2E 02 00 00 A3 70 45 40 00 68 25 45 40 00 E8 2B 02 00 00 A3 30 45 40 }

	condition:
		$a0
}

import "pe"

rule EXEStealthv272 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB 00 EB 2F 53 68 61 72 65 77 61 72 65 20 2D 20 }

	condition:
		$a0 at pe.entry_point
}

rule EXEStealthv273 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB 00 EB 2F 53 68 61 72 65 77 61 72 65 20 2D 20 45 78 65 53 74 65 61 6C 74 68 00 EB 16 77 77 77 2E 77 65 62 74 6F 6F 6C 6D 61 73 74 65 72 2E 63 6F 6D 00 60 90 E8 00 00 00 00 5D 81 ED F0 27 40 00 B9 15 00 00 00 83 C1 05 EB 05 EB FE 83 C7 56 EB 00 83 E9 02 }

	condition:
		$a0
}

import "pe"

rule PseudoSigner02DEF10Anorganix : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { BE 00 01 40 00 6A 05 59 80 7E 07 00 74 11 8B 46 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 83 C1 01 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule AHpack01FEUERRADER : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 68 54 [3] B8 48 [3] FF 10 68 B3 [3] 50 B8 44 [3] FF 10 68 00 [3] 6A 40 FF D0 89 05 CA [3] 89 C7 BE 00 10 [2] 60 FC B2 80 31 DB A4 B3 02 E8 6D 00 00 00 73 F6 31 C9 E8 64 00 00 00 73 1C 31 C0 E8 5B 00 00 00 73 23 B3 02 41 }

	condition:
		$a0 at pe.entry_point
}

rule EXEStealthv274 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB 00 EB 17 53 68 61 72 65 77 61 72 65 20 2D 20 45 78 65 53 74 65 61 6C 74 68 00 60 90 E8 00 00 00 00 5D 81 ED C4 27 40 00 B9 15 00 00 00 83 C1 04 83 C1 01 EB 05 EB FE 83 C7 56 EB 00 83 E9 02 81 C1 78 43 27 65 EB 00 81 C1 10 25 94 00 81 E9 63 85 00 00 B9 }

	condition:
		$a0
}

import "pe"

rule ThinstallEmbedded22X2308Jitit : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { B8 EF BE AD DE 50 6A 00 FF 15 [4] E9 B9 FF FF FF 8B C1 8B 4C 24 04 89 88 29 04 00 00 C7 40 0C 01 00 00 00 0F B6 49 01 D1 E9 89 48 10 C7 40 14 80 00 00 00 C2 04 00 8B 44 24 04 C7 41 0C 01 00 00 00 89 81 29 04 00 00 0F B6 40 01 D1 E8 89 41 10 C7 41 14 80 00 00 00 C2 04 00 55 8B EC 53 56 57 33 C0 33 FF 39 45 0C 8B F1 76 0C 8B 4D 08 03 3C 81 40 3B 45 0C 72 F4 8B CE E8 43 00 00 00 8B 46 14 33 D2 F7 F7 8B 5E 10 33 D2 8B F8 8B C3 F7 F7 89 7E 18 89 45 0C 33 C0 33 C9 8B 55 08 03 0C 82 40 39 4D 0C 73 F4 48 8B 14 82 2B CA 0F AF CF 2B D9 0F AF FA 89 7E 14 89 5E 10 5F 5E 5B 5D C2 08 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PolyCryptorbySMTVersionv3v4 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB ?? 28 50 6F 6C 79 53 63 72 79 70 74 20 [3] 20 62 79 20 53 4D 54 29 }

	condition:
		$a0 at pe.entry_point
}

rule ProtectSharewareV11eCompservCMS : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 53 00 74 00 72 00 69 00 6E 00 67 00 46 00 69 00 6C 00 65 00 49 00 6E 00 66 00 6F 00 00 00 ?? 01 00 00 01 00 30 00 34 00 30 00 39 00 30 00 34 00 42 00 30 00 00 00 34 00 ?? 00 01 00 43 00 6F 00 6D 00 70 00 61 00 6E 00 79 00 4E 00 61 00 6D 00 65 00 00 00 00 }

	condition:
		$a0
}

rule Upackv035alphaDwing : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 8B F2 8B CA 03 4C 19 1C 03 54 1A 20 }

	condition:
		$a0
}

import "pe"

rule ASPackv10801AlexeySolodovnikov : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 EB 0A 5D EB 02 FF 25 45 FF E5 E8 E9 E8 F1 FF FF FF E9 81 [3] 44 00 BB 10 ?? 44 00 03 DD 2B 9D }
		$a1 = { 60 EB 0A 5D EB 02 FF 25 45 FF E5 E8 E9 E8 F1 FF FF FF E9 81 [3] 44 ?? BB 10 ?? 44 ?? 03 DD 2B 9D }
		$a2 = { 60 EB ?? 5D EB ?? FF [5] E9 }

	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point or $a2 at pe.entry_point
}

import "pe"

rule ENIGMAProtectorV11SukhovVladimir : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 00 00 00 00 5D 83 [2] 81 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PEncrypt20junkcode : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB 25 00 00 F7 BF 00 00 00 00 00 00 00 00 00 00 12 00 E8 00 56 69 72 74 75 61 6C 50 72 6F 74 65 63 74 00 00 00 00 00 E8 00 00 00 00 5D 81 ED 2C 10 40 00 8D B5 14 10 40 00 E8 33 00 00 00 89 85 10 10 40 00 BF 00 00 40 00 8B F7 03 7F 3C 8B 4F 54 51 56 8D 85 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule SimbiOZExtranger : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 50 60 E8 00 00 00 00 5D 81 ED 07 10 40 00 68 80 0B 00 00 8D 85 1F 10 40 00 50 E8 84 0B 00 00 }

	condition:
		$a0 at pe.entry_point
}

rule InnoSetupModulev304betav306v307 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 83 C4 B8 53 56 57 33 C0 89 45 F0 89 45 BC 89 45 B8 E8 B3 70 FF FF E8 1A 85 FF FF E8 25 A7 FF FF E8 6C }

	condition:
		$a0
}

import "pe"

rule ASPackv107bAlexeySolodovnikov : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 [4] 5D 81 ED [4] B8 [4] 03 C5 2B 85 ?? 0B DE ?? 89 85 17 DE [2] 80 BD 01 DE }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PROPACKv208emphasisonpackedsizelocked : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 83 EC ?? 8B EC BE [2] FC E8 [2] 05 [2] 8B C8 E8 [2] 8B }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule HACKSTOPv110p1 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { B4 30 CD 21 86 E0 3D 00 03 73 ?? B4 2F CD 21 B4 2A CD 21 B4 2C CD 21 B0 FF B4 4C CD 21 50 B8 [2] 58 EB }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule AdysGlue110 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 2E [4] 0E 1F BF [2] 33 DB 33 C0 AC }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule VxEddiebased1745 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E8 [2] 5E 81 EE [2] FC ?? 2E [4] 4D 5A [2] FA ?? 8B E6 81 [3] FB ?? 3B [5] 50 06 ?? 56 1E 8B FE 33 C0 ?? 50 8E D8 }

	condition:
		$a0 at pe.entry_point
}

rule ASDPackv10asd : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 56 53 E8 5C 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 10 00 00 [3] 00 00 00 00 00 00 00 40 00 00 [2] 00 00 00 00 00 00 00 00 00 [3] 00 00 00 00 00 00 00 00 00 00 00 00 00 [3] 00 00 00 00 00 00 00 00 00 00 [2] 00 00 10 00 00 00 ?? 00 00 00 [2] 00 00 [2] 00 00 [2] 00 00 ?? 00 00 00 [2] 00 00 ?? 00 00 00 [2] 00 00 ?? 00 00 00 [2] 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 5B 81 EB E6 1D 40 00 83 7D 0C 01 75 11 55 E8 4F 01 00 00 E8 6A 01 00 00 5D E8 2C 00 00 00 8B B3 1A 1E 40 00 03 B3 FA 1D 40 00 8B 76 0C AD 0B C0 74 0D FF 75 10 FF 75 0C FF 75 08 FF D0 EB EE B8 01 00 00 00 5B 5E C9 C2 0C 00 55 6A 00 FF 93 20 21 40 00 89 83 FA 1D 40 00 6A 40 68 00 10 00 00 FF B3 02 1E 40 00 6A 00 FF 93 2C 21 40 00 89 83 06 1E 40 00 8B 83 F2 1D 40 00 03 83 FA 1D 40 00 50 FF B3 06 1E 40 00 50 E8 6D 01 00 00 5F }

	condition:
		$a0
}

rule ORiENV1XV2XFisunAV : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 4F 52 69 45 4E 20 65 78 65 63 75 74 61 62 6C 65 20 66 69 6C 65 73 20 70 72 6F 74 65 63 74 69 6F 6E 20 73 79 73 74 65 6D }

	condition:
		$a0
}

import "pe"

rule StonesPEEncryptorv113 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 57 56 52 51 53 E8 [4] 5D 8B D5 81 ED 97 3B 40 ?? 2B 95 2D 3C 40 ?? 83 EA 0B 89 95 36 3C 40 ?? 01 95 24 3C 40 ?? 01 95 28 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule WWPACKv302v302aExtractable : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { B8 [2] 8C CA 03 D0 8C C9 81 C1 [2] 51 33 C9 B1 ?? 51 06 06 BB [2] 53 8C D3 }

	condition:
		$a0 at pe.entry_point
}

rule ARMProtector03bySMoKE : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E8 04 00 00 00 83 60 EB 0C 5D EB 05 45 55 EB 04 B8 EB F9 00 C3 E8 00 00 00 00 5D EB 01 00 81 ED 13 24 40 00 EB 02 83 09 8D B5 A4 24 40 00 EB 02 83 09 BA 4B 15 00 00 EB 01 00 8D 8D EF 39 40 00 8B 09 E8 14 00 00 00 83 EB 01 00 8B FE E8 00 00 00 00 58 83 C0 07 50 C3 00 EB 04 58 40 50 C3 8A 06 46 EB 01 00 D0 C8 E8 14 00 00 00 83 EB 01 00 2A C2 E8 00 00 00 00 5B 83 C3 07 53 C3 00 EB 04 5B 43 53 C3 EB 01 00 32 C2 E8 0B 00 00 00 00 32 C1 EB 01 00 C0 C0 02 EB 09 2A C2 5B EB 01 00 43 53 C3 88 07 EB 01 00 47 4A 75 B4 }

	condition:
		$a0
}

import "pe"

rule VxSlowload : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 03 D6 B4 40 CD 21 B8 02 42 33 D2 33 C9 CD 21 8B D6 B9 78 01 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule AntiDote10BetaSISTeam : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E8 BB FF FF FF 84 C0 74 2F 68 04 01 00 00 68 C0 23 60 00 6A 00 FF 15 08 10 60 00 E8 40 FF FF FF 50 68 78 11 60 00 68 68 11 60 00 68 C0 23 60 00 E8 AB FD FF FF 83 C4 10 33 C0 C2 10 00 90 90 90 8B 4C 24 08 56 8B 74 24 08 33 D2 8B C6 F7 F1 8B C6 85 D2 74 08 33 D2 F7 F1 40 0F AF C1 5E C3 90 8B 44 24 04 53 55 56 8B 48 3C 57 03 C8 33 D2 8B 79 54 8B 71 38 8B C7 F7 F6 85 D2 74 0C 8B C7 33 D2 F7 F6 8B F8 47 0F AF FE 33 C0 33 DB 66 8B 41 14 8D 54 08 18 33 C0 66 8B 41 06 89 54 24 14 8D 68 FF 85 ED 7C 37 33 C0 }

	condition:
		$a0 at pe.entry_point
}

rule DzAPatcherv13Loader : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { BF 00 40 40 00 99 68 48 20 40 00 68 00 20 40 00 52 52 52 52 52 52 52 57 E8 15 01 00 00 85 C0 75 1C 99 52 52 57 52 E8 CB 00 00 00 FF 35 4C 20 40 00 E8 D2 00 00 00 6A 00 E8 BF 00 00 00 99 68 58 20 40 00 52 52 68 63 10 40 00 52 52 E8 DB 00 00 00 6A FF FF 35 }

	condition:
		$a0
}

import "pe"

rule CDSSS10beta1CyberDoom : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED CA 47 40 00 FF 74 24 20 E8 D3 03 00 00 0B C0 0F 84 13 03 00 00 89 85 B8 4E 40 00 66 8C D8 A8 04 74 0C C7 85 8C 4E 40 00 01 00 00 00 EB 12 64 A1 30 00 00 00 0F B6 40 02 0A C0 0F 85 E8 02 00 00 8D 85 F6 4C 40 00 50 FF B5 B8 4E 40 00 E8 FC 03 00 00 0B C0 0F 84 CE 02 00 00 E8 1E 03 00 00 89 85 90 4E 40 00 8D 85 03 4D 40 00 50 FF B5 B8 4E 40 00 E8 D7 03 00 00 0B C0 0F 84 A9 02 00 00 E8 F9 02 00 00 89 85 94 4E 40 00 8D 85 12 4D 40 00 50 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule y0dasCrypterv10 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED E7 1A 40 00 E8 A1 00 00 00 E8 D1 00 00 00 E8 85 01 00 00 F7 85 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule y0dasCrypterv11 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED 8A 1C 40 00 B9 9E 00 00 00 8D BD 4C 23 40 00 8B F7 33 }

	condition:
		$a0 at pe.entry_point
}

rule NullsoftPiMPInstallSystemv1x : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 83 EC 0C 53 56 57 FF 15 [2] 40 00 05 E8 03 00 00 BE [3] 00 89 44 24 10 B3 20 FF 15 28 ?? 40 00 68 00 04 00 00 FF 15 [2] 40 00 50 56 FF 15 [2] 40 00 80 3D [3] 00 22 75 08 80 C3 02 BE [3] 00 8A 06 8B 3D [2] 40 00 84 C0 74 ?? 3A C3 74 }

	condition:
		$a0
}

import "pe"

rule ExeBundlev30smallloader : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 00 00 00 00 60 BE 00 F0 40 00 8D BE 00 20 FF FF 57 83 CD FF EB 10 90 90 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule UPXAlternativestub : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 01 DB 07 8B 1E 83 EE FC 11 DB ED B8 01 00 00 00 01 DB 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 0B }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule EmbedPE113cyclotron : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 83 EC 50 60 68 5D B9 52 5A E8 2F 99 00 00 DC 99 F3 57 05 68 B8 5E 2D C6 DA FD 48 63 05 3C 71 B8 5E 97 7C 36 7E 32 7C 08 4F 06 51 64 10 A3 F1 4E CF 25 CB 80 D2 99 54 46 ED E1 D3 46 86 2D 10 68 93 83 5C 46 4D 43 9B 8C D6 7C BB 99 69 97 71 2A 2F A3 38 6B 33 }

	condition:
		$a0 at pe.entry_point
}

rule EXECryptor2223protectedIAT : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { CC [3] 00 00 00 00 FF FF FF FF 3C [3] B4 [3] 08 [3] 00 00 00 00 FF FF FF FF E8 [3] 04 [3] 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 00 00 00 00 00 47 65 74 4D 6F 64 75 6C 65 48 61 6E 64 6C 65 41 00 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 00 00 00 45 78 69 74 50 72 6F 63 65 73 73 00 00 00 00 00 56 69 72 74 75 61 6C 41 6C 6C 6F 63 00 00 00 00 56 69 72 74 75 61 6C 46 72 65 65 00 00 00 [24] 4C [3] 60 [3] 70 [3] 84 [3] 94 [3] A4 [3] 00 00 00 00 75 73 65 72 33 32 2E 64 6C 6C 00 00 00 00 4D 65 73 73 61 67 65 42 6F 78 }

	condition:
		$a0
}

import "pe"

rule PseudoSigner01Armadillo300Anorganix : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 2A 00 00 00 5D 50 51 EB 0F B9 EB 0F B8 EB 07 B9 EB 0F 90 EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC E9 59 58 50 51 EB 85 E9 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule EXECryptorvxxxx : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E8 24 [3] 8B 4C 24 0C C7 01 17 ?? 01 ?? C7 81 B8 [7] 31 C0 89 41 }

	condition:
		$a0 at pe.entry_point
}

rule Morphinev33SilentSoftwareSilentShieldc2005 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 28 [3] 00 00 00 00 00 00 00 00 40 [3] 34 [3] 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 4C [3] 5C [3] 00 00 00 00 4C [3] 5C [3] 00 00 00 00 4B 65 52 6E 45 6C 33 32 2E 64 4C 6C 00 00 47 65 74 50 72 6F 63 }
		$a1 = { 28 [3] 00 00 00 00 00 00 00 00 40 [3] 34 [3] 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 4C [3] 5C [3] 00 00 00 00 4C [3] 5C [3] 00 00 00 00 4B 65 52 6E 45 6C 33 32 2E 64 4C 6C 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 }

	condition:
		$a0 or $a1
}

import "pe"

rule DEF10bartxt : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { BE [2] 40 00 6A ?? 59 80 7E 07 00 74 11 8B 46 0C 05 00 00 40 00 8B 56 10 30 10 40 4A 75 FA 83 C6 28 E2 E4 68 [2] 40 00 C3 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PECompactv0971v0976 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB 06 68 C3 9C 60 E8 5D 55 5B 81 ED 8B 85 01 85 66 C7 85 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PCShrinkv040b : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 9C 60 BD [4] 01 [5] FF [5] 6A ?? FF [5] 50 50 2D }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule MSLRHv032afakePECrypt102emadicius : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E8 00 00 00 00 5B 83 EB 05 EB 04 52 4E 44 21 85 C0 73 02 F7 05 50 E8 08 00 00 00 EA FF 58 EB 18 EB 01 0F EB 02 CD 20 EB 03 EA CD 20 58 58 EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule ORiENv211212FisunAlexander : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E9 5D 01 00 00 CE D1 CE ?? 0D 0A 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 2D 0D 0A 2D 20 4F 52 69 45 4E 20 65 78 65 63 75 74 61 62 6C 65 20 66 69 6C 65 73 20 70 72 6F }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule StonesPEEncruptorv113 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 57 56 52 51 53 E8 [4] 5D 8B D5 81 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule ASProtectv11MTEc : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 90 60 E8 1B [3] E9 FC }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule CreateInstallStubvxx : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 81 EC 20 02 00 00 53 56 57 6A 00 FF 15 18 61 40 00 68 00 70 40 00 89 45 08 FF 15 14 61 40 00 85 C0 74 27 6A 00 A1 00 20 40 00 50 FF 15 3C 61 40 00 8B F0 6A 06 56 FF 15 38 61 40 00 6A 03 56 FF 15 38 61 40 00 E9 36 03 00 00 68 02 7F 00 00 33 F6 56 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule WinZip32bitSFXv8xmodule : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 53 FF 15 [3] 00 B3 22 38 18 74 03 80 C3 FE 8A 48 01 40 33 D2 3A CA 74 0A 3A CB 74 06 8A 48 01 40 EB F2 38 10 74 01 40 [4] FF 15 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule Upxv12MarcusLazlo : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 BE [4] 8D BE [4] 57 83 CD FF EB 05 A4 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 F2 31 C0 40 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 75 07 8B 1E 83 EE FC 11 DB 73 E6 31 C9 83 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PEPACKv10byANAKiN1998 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 74 ?? E9 [4] 00 00 00 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule NeoLitev20 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E9 [28] 4E 65 6F 4C 69 74 65 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule AHTeamEPProtector03fakeSpalsher1x3xFEUERRADER : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 90 [46] 90 FF E0 9C 60 8B 44 24 24 E8 00 00 00 00 5D 81 ED 00 00 00 00 50 E8 ED 02 00 00 8C C0 0F 84 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule ASPackv10803AlexeySolodovnikov : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED 0A 4A 44 00 BB 04 4A 44 00 03 DD }
		$a1 = { 60 E8 00 00 00 00 5D 81 ED 0A 4A 44 00 BB 04 4A 44 00 03 DD 2B 9D B1 50 44 00 83 BD AC 50 44 00 00 89 9D BB 4E }
		$a2 = { 60 E8 00 00 00 00 5D [6] BB [4] 03 DD }
		$a3 = { 60 E8 00 00 00 00 5D [6] BB [4] 03 DD 2B 9D B1 50 44 00 83 BD AC 50 44 00 00 89 9D BB 4E }

	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point or $a2 at pe.entry_point or $a3 at pe.entry_point
}

rule VMProtect07x08PolyTech : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 5B 20 56 4D 50 72 6F 74 65 63 74 20 76 20 30 2E 38 20 28 43 29 20 50 6F 6C 79 54 65 63 68 20 5D }

	condition:
		$a0
}

import "pe"

rule ExeShieldProtectorV36wwwexeshieldcom : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { B8 [3] 00 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 50 45 43 6F 6D 70 61 63 74 32 00 CE 1E 42 AF F8 D6 CC }

	condition:
		$a0 at pe.entry_point
}

rule WerusCrypter10Kas : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 68 98 11 40 00 6A 00 E8 50 00 00 00 C9 C3 ED B3 FE FF FF 6A 00 E8 0C 00 00 00 FF 25 80 10 40 00 FF 25 84 10 40 00 FF 25 88 10 40 00 FF 25 8C 10 40 00 FF 25 90 10 40 00 FF 25 94 10 40 00 FF 25 98 10 40 00 FF 25 9C 10 40 00 FF 25 A0 10 40 00 FF 25 A4 10 40 00 FF 25 A8 10 40 00 FF 25 B0 10 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 BB E8 12 40 00 80 33 05 E9 7D FF FF FF }

	condition:
		$a0
}

import "pe"

rule Themida10xx1800compressedengineOreansTechnologies : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { B8 [4] 60 0B C0 74 58 E8 00 00 00 00 58 05 43 00 00 00 80 38 E9 75 03 61 EB 35 E8 00 00 00 00 58 25 00 F0 FF FF 33 FF 66 BB 19 5A 66 83 C3 34 66 39 18 75 12 0F B7 50 3C 03 D0 BB E9 44 00 00 83 C3 67 39 1A 74 07 2D 00 10 00 00 EB DA 8B F8 B8 }
		$a1 = { B8 [4] 60 0B C0 74 58 E8 00 00 00 00 58 05 43 00 00 00 80 38 E9 75 03 61 EB 35 E8 00 00 00 00 58 25 00 F0 FF FF 33 FF 66 BB 19 5A 66 83 C3 34 66 39 18 75 12 0F B7 50 3C 03 D0 BB E9 44 00 00 83 C3 67 39 1A 74 07 2D 00 10 00 00 EB DA 8B F8 B8 [4] 03 C7 B9 5A [3] 03 CF EB 0A B8 [4] B9 5A [3] 50 51 E8 84 00 00 00 E8 00 00 00 00 58 2D 26 00 00 00 B9 EF 01 00 00 C6 00 E9 83 E9 05 89 48 01 61 E9 AF 01 }

	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point
}

import "pe"

rule CHECKPRGc1992 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 33 C0 BE [2] 8B D8 B9 [2] BF [2] BA [2] 47 4A 74 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule eXPressor11CGSoftLabs : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E9 [2] 00 00 E9 [2] 00 00 E9 ?? 12 00 00 E9 ?? 0C 00 00 E9 [2] 00 00 E9 [2] 00 00 E9 [2] 00 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule VxEddie1028 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E8 [2] 5E FC 83 [2] 81 [3] 4D 5A [2] FA 8B E6 81 C4 [2] FB 3B [5] 50 06 56 1E B8 FE 4B CD 21 81 FF BB 55 [2] 07 [3] 07 B4 49 CD 21 BB FF FF B4 48 CD 21 }

	condition:
		$a0 at pe.entry_point
}

rule PEQuakev006byfORGAT : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E8 A5 00 00 00 2D ?? 00 00 00 00 00 00 00 00 00 00 3D ?? 00 00 2D ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 4A ?? 00 00 5B ?? 00 00 6E ?? 00 00 00 00 00 00 6B 45 72 4E 65 4C 33 32 2E 64 4C 6C 00 00 00 47 65 74 50 72 6F 63 41 64 }

	condition:
		$a0
}

import "pe"

rule LTCv13 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 54 E8 00 00 00 00 5D 8B C5 81 ED F6 73 40 00 2B 85 87 75 40 00 83 E8 06 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule tElockv071b7 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 48 11 00 00 C3 83 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule tElockv071b2 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 44 11 00 00 C3 83 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule UnknownJoinersignfrompinch260320070212 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 44 90 4C 90 B9 DE 00 00 00 BA 00 10 40 00 83 C2 03 44 90 4C B9 07 00 00 00 44 90 4C 33 C9 C7 05 08 30 40 00 00 00 00 00 90 68 00 01 00 00 68 21 30 40 00 6A 00 E8 C5 02 00 00 90 6A 00 68 80 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule DIETv100v100d : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { BF [2] 3B FC 72 ?? B4 4C CD 21 BE [2] B9 [2] FD F3 A5 FC }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule APEX_CBLTApex40500mhz : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 68 [4] B9 FF FF FF 00 01 D0 F7 E2 72 01 48 E2 F7 B9 FF 00 00 00 8B 34 24 80 36 FD 46 E2 FA C3 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule StealthPEv11 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { BA [3] 00 FF E2 BA [3] 00 B8 [4] 89 02 83 C2 03 B8 [4] 89 02 83 C2 FD FF E2 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule RLPackFullEdition117DLLAp0x : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 80 7C 24 08 01 0F 85 [4] 60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 [4] 8D 9D [4] 33 FF E8 }

	condition:
		$a0 at pe.entry_point
}

rule Anti007V26LiuXingPing : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 56 69 72 74 75 61 6C 50 72 6F 74 65 63 74 00 00 00 56 69 72 74 75 61 6C 41 6C 6C 6F 63 00 00 00 56 69 72 74 75 61 6C 46 72 65 65 00 00 00 47 65 74 53 79 73 74 65 6D 44 69 72 65 63 74 6F 72 79 41 00 00 00 43 72 65 61 74 65 46 69 6C 65 41 00 00 00 57 72 69 74 65 46 69 6C 65 00 00 00 43 6C 6F 73 65 48 61 6E 64 6C 65 00 00 00 45 78 69 74 50 72 6F 63 65 73 73 00 00 }

	condition:
		$a0
}

import "pe"

rule AppEncryptorSilentTeam : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED 1F 1F 40 00 B9 7B 09 00 00 8D BD 67 1F 40 00 8B F7 AC }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule VirogenCryptv075 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 9C 55 E8 EC 00 00 00 87 D5 5D 60 87 D5 80 BD 15 27 40 00 01 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule Armadillov300a : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 [4] 5D 50 51 EB 0F B9 EB 0F B8 EB 07 B9 EB 0F 90 EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC E9 59 58 50 51 EB }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule WWPACKv300v301Extractable : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { B8 [2] 8C CA 03 D0 8C C9 81 C1 [2] 51 6A ?? 06 06 8C D3 83 [2] 53 6A ?? FC }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule VxUddy2617 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 2E [5] 2E [5] 2E [3] 8C C8 8E D8 8C [3] 2B [3] 03 [3] A3 [2] A1 [2] A3 [2] A1 [2] A3 [2] 8C C8 2B [3] 03 [3] A3 [2] B8 AB 9C CD 2F 3D 76 98 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PLINK8619841985 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { FA 8C C7 8C D6 8B CC BA [2] 8E C2 26 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule ASPackv10804AlexeySolodovnikov : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 41 06 00 00 EB 41 }

	condition:
		$a0 at pe.entry_point
}

rule aPackv098m : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 1E 06 8C C8 8E D8 05 [2] 8E C0 50 BE [2] 33 FF FC B2 ?? BD [2] 33 C9 50 A4 BB [2] 3B F3 76 }

	condition:
		$a0
}

rule BamBamv001Bedrock : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 6A 14 E8 9A 05 00 00 8B D8 53 68 FB [2] 00 E8 6C FD FF FF B9 05 00 00 00 8B F3 BF FB [2] 00 53 F3 A5 E8 8D 05 00 00 8B 3D 03 [2] 00 A1 2B [2] 00 66 8B 15 2F [2] 00 B9 80 [2] 00 2B CF 89 45 E8 89 0D 6B [2] 00 66 89 55 EC 8B 41 3C 33 D2 03 C1 }

	condition:
		$a0
}

import "pe"

rule PESHiELDv02v02bv02b2 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 [4] 41 4E 41 4B 49 4E 5D 83 ED 06 EB 02 EA 04 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule EXEStealthv27 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB 00 60 EB 00 E8 00 00 00 00 5D 81 ED D3 26 40 }

	condition:
		$a0 at pe.entry_point
}

rule EXEStealthv25 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 90 EB 22 45 78 65 53 74 65 61 6C 74 68 20 2D 20 77 77 77 2E 77 65 62 74 6F 6F 6C 6D 61 73 74 65 72 2E 63 6F 6D E8 00 00 00 00 5D 81 ED 40 1E 40 00 B9 99 09 00 00 8D BD 88 1E 40 00 8B F7 AC }

	condition:
		$a0
}

import "pe"

rule VxHaryanto : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 81 EB 2A 01 8B 0F 1E 5B 03 CB 0E 51 B9 10 01 51 CB }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule ASPRStripperv2xunpacked : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { BB [4] E9 [4] 60 9C FC BF [4] B9 [4] F3 AA 9D 61 C3 55 8B EC }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PseudoSigner01UPX06Anorganix : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 00 00 00 00 58 83 E8 3D 50 8D B8 00 00 00 FF 57 8D B0 E8 00 00 00 E9 }

	condition:
		$a0 at pe.entry_point
}

rule Shrinker33 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 00 00 55 8B EC 56 57 75 65 68 00 01 00 00 E8 }

	condition:
		$a0
}

rule Shrinker32 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 56 57 75 65 68 00 01 00 00 E8 F1 E6 FF FF 83 C4 04 }

	condition:
		$a0
}

rule Shrinker34 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 56 57 75 6B 68 00 01 00 00 E8 11 0B 00 00 83 C4 04 }

	condition:
		$a0
}

import "pe"

rule PESPinv13Cyberbob : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 AC DF 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 17 EB 07 EA EB 01 EB EB 0D FF }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PECompactv160v165 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB 06 68 [4] C3 9C 60 E8 02 [3] 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 3F 80 40 ?? 87 DD 8B 85 D2 80 40 ?? 01 85 33 80 40 ?? 66 C7 85 ?? 80 40 ?? 90 90 01 85 CE 80 40 ?? BB BB 12 }

	condition:
		$a0 at pe.entry_point
}

rule eXPressorv120b : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 81 EC D4 01 00 00 53 56 57 EB 0C 45 78 50 72 2D 76 2E 31 2E 32 2E 2E B8 [3] 00 2B 05 84 [2] 00 A3 [3] 00 83 3D [3] 00 00 74 16 A1 [3] 00 03 05 80 [2] 00 89 85 54 FE FF FF E9 ?? 07 00 00 C7 05 [3] 00 01 00 00 00 68 04 }

	condition:
		$a0
}

import "pe"

rule EPWv12 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 06 57 1E 56 55 52 51 53 50 2E [4] 8C C0 05 [2] 2E [3] 8E D8 A1 [2] 2E }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule ASProtectv12x : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 00 00 68 01 [3] C3 AA }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule Packanoidv1Arkanoid : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { BF [4] BE [4] E8 9D 00 00 00 B8 [4] 8B 30 8B 78 04 BB [4] 8B 43 04 91 E3 1F 51 FF D6 56 96 8B 13 8B 02 91 E3 0D 52 51 56 FF D7 5A 89 02 83 C2 04 EB EE 83 C3 08 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule EscargotV01Meat : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB 04 40 30 2E 31 60 68 61 }

	condition:
		$a0 at pe.entry_point
}

rule SCObfuscatorSuperCRacker : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 33 C9 8B 1D 00 [3] 03 1D 08 [3] 8A 04 19 84 C0 74 09 3C ?? 74 05 34 ?? 88 04 19 41 3B 0D 04 [3] 75 E7 A1 08 [3] 01 05 0C [3] 61 FF 25 0C }

	condition:
		$a0
}

import "pe"

rule EXEStealth275WebtoolMaster : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 90 60 90 E8 00 00 00 00 5D 81 ED D1 27 40 00 B9 15 00 00 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PasswordProtectorcMiniSoft1992 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 06 0E 0E 07 1F E8 00 00 5B 83 EB 08 BA 27 01 03 D3 E8 3C 02 BA EA }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule VxEddie2000 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E8 [2] 5E 81 EE [2] FC 2E [4] 2E [4] 4D 5A [2] FA 8B E6 81 C4 [2] FB 3B [5] 50 06 56 1E 8B FE 33 C0 50 8E D8 C5 [3] B4 30 CD 21 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule VideoLanClientUnknownCompiler : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 89 E5 83 EC 08 [15] FF FF [19] 00 [7] 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule eXPressorv14CGSoftLabs : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 83 EC ?? 53 56 57 EB 0C 45 78 50 72 2D 76 2E 31 2E 34 2E 2E B8 }
		$a1 = { 65 58 50 72 2D 76 2E 31 2E 34 2E }

	condition:
		$a0 at pe.entry_point or $a1
}

import "pe"

rule SkDUndetectablerPro20NoUPXMethodSkD : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 83 C4 F0 B8 FC 26 00 10 E8 EC F3 FF FF 6A 0F E8 15 F5 FF FF E8 64 FD FF FF E8 BB ED FF FF 8D 40 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule RJcrushv100 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 06 FC 8C C8 BA [2] 03 D0 52 BA [2] 52 BA [2] 03 C2 8B D8 05 [2] 8E DB 8E C0 33 F6 33 FF B9 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule ExeShieldv27 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB 06 68 F4 86 06 00 C3 9C 60 E8 02 00 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule ExeShieldv29 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED 0B 20 40 00 B9 EB 08 00 00 8D BD 53 20 40 00 8B F7 AC [3] F8 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PEiDBundlev102v103BoBBobSoft : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 9C 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 36 [3] 2E [3] 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 00 80 00 00 00 00 4B 65 72 6E 65 6C 33 32 2E 44 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule FSGv110EngdulekxtMicrosoftVisualC5060 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 33 D2 0F BE D2 EB 01 C7 EB 01 D8 8D 05 80 [3] EB 02 CD 20 EB 01 F8 BE F4 00 00 00 EB }

	condition:
		$a0 at pe.entry_point
}

rule PUNiSHERV15FEUERRADER : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 3F 00 00 80 66 20 ?? 00 7E 20 ?? 00 92 20 ?? 00 A4 20 ?? 00 00 00 00 00 4B 45 52 4E 45 4C 33 32 }

	condition:
		$a0
}

import "pe"

rule ExcaliburV103forgot : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E9 00 00 00 00 60 E8 14 00 00 00 5D 81 ED 00 00 00 00 6A 45 E8 A3 00 00 00 68 00 00 00 00 E8 58 61 EB 39 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule RLPack10betaap0x : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 00 00 00 00 8D 64 24 04 8B 6C 24 FC 8D B5 4C 02 00 00 8D 9D 13 01 00 00 33 FF EB 0F FF 74 37 04 FF 34 37 FF D3 83 C4 08 83 C7 08 83 3C 37 00 75 EB 8D 74 37 04 53 6A 40 68 00 10 00 00 68 [4] 6A 00 FF 95 F9 01 00 00 89 85 48 02 00 00 5B FF B5 }
		$a1 = { 60 E8 00 00 00 00 8D 64 24 04 8B 6C 24 FC 8D B5 4C 02 00 00 8D 9D 13 01 00 00 33 FF EB 0F FF 74 37 04 FF 34 37 FF D3 83 C4 08 83 C7 08 83 3C 37 00 75 EB 8D 74 37 04 53 6A 40 68 00 10 00 00 68 [4] 6A 00 FF 95 F9 01 00 00 89 85 48 02 00 00 5B FF B5 48 02 00 00 56 FF D3 83 C4 08 8B B5 48 02 00 00 8B C6 EB 01 40 80 38 01 75 FA 40 8B 38 83 C0 04 89 85 44 02 00 00 EB 7A 56 FF 95 F1 01 00 00 89 85 40 02 00 00 8B C6 EB 4F 8B 85 44 02 00 00 8B 00 A9 00 00 00 80 74 14 35 00 00 00 80 50 8B 85 44 02 00 00 C7 00 20 20 20 00 EB 06 FF B5 44 02 00 00 FF B5 40 02 00 00 FF 95 F5 01 00 00 89 07 83 C7 04 8B 85 44 02 00 00 EB 01 40 80 38 00 75 FA 40 89 85 44 02 00 00 80 38 00 75 AC EB 01 46 80 3E 00 75 FA 46 40 8B 38 83 C0 04 89 85 44 02 00 00 80 3E 01 75 81 68 00 40 00 00 68 [4] FF B5 48 02 00 00 FF 95 FD 01 00 00 61 68 [4] C3 60 8B 74 24 24 8B 7C }

	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point
}

rule nMacrorecorder10 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 5C 6E 6D 72 5F 74 65 6D 70 2E 6E 6D 72 00 00 00 72 62 00 00 58 C7 41 00 10 F8 41 00 11 01 00 00 00 00 00 00 46 E1 00 00 46 E1 00 00 35 00 00 00 F6 88 41 00 }

	condition:
		$a0
}

import "pe"

rule PrivateEXEv20a : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 53 E8 00 00 00 00 5B 8B C3 2D }
		$a1 = { 06 60 C8 [3] 0E 68 [2] 9A [4] 3D [2] 0F [3] 50 50 0E 68 [2] 9A [4] 0E }
		$a2 = { 53 E8 [4] 5B 8B C3 2D [4] 50 81 [5] 8B }

	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point or $a2 at pe.entry_point
}

import "pe"

rule PackmanV10BrandonLaCombe : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 00 00 00 00 5B 8D 5B C6 01 1B 8B 13 8D 73 14 6A 08 59 01 16 AD 49 75 FA }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PseudoSigner01PEX099Anorganix : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 01 00 00 00 55 83 C4 04 E8 01 00 00 00 90 5D 81 FF FF FF 00 01 E9 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PAKSFXArchive : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 83 [2] A1 [2] 2E [3] 2E [5] 8C D7 8E C7 8D [2] BE [2] FC AC 3C 0D }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule ASPackv2xxAlexeySolodovnikov : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { A8 03 00 00 61 75 08 B8 01 00 00 00 C2 0C 00 68 00 00 00 00 C3 8B 85 26 04 00 00 8D 8D 3B 04 00 00 51 50 FF 95 }
		$a1 = { A8 03 [2] 61 75 08 B8 01 [3] C2 0C ?? 68 [4] C3 8B 85 26 04 [2] 8D 8D 3B 04 [2] 51 50 FF 95 }

	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point
}

import "pe"

rule SimbiOZ13Extranger : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 57 57 8D 7C 24 04 50 B8 00 [3] AB 58 5F C3 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule muckisprotectorImucki : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { BE [4] B9 [4] 8A 06 F6 D0 88 06 46 E2 F7 E9 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule Obsidium1339ObsidiumSoftware : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB 02 [2] E8 29 00 00 00 EB 03 [3] EB 01 ?? 8B 54 24 0C EB 04 [4] 83 82 B8 00 00 00 28 EB 02 [2] 33 C0 EB 02 [2] C3 EB 03 [3] EB 04 [4] 64 67 FF 36 00 00 EB 03 [3] 64 67 89 26 00 00 EB 01 ?? EB 01 ?? 50 EB 03 [3] 33 C0 EB 03 [3] 8B 00 EB 04 [4] C3 EB 04 [4] E9 FA 00 00 00 EB 03 [3] E8 D5 FF FF FF EB 02 [2] EB 04 [4] 58 EB 03 [3] EB 04 [4] 64 67 8F 06 00 00 EB 03 [3] 83 C4 04 EB 04 [4] E8 CF 27 00 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule LOCK98V10028keenvim : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 E8 00 00 00 00 5D 81 [5] EB 05 E9 [4] EB 08 }

	condition:
		$a0 at pe.entry_point
}

rule iPBProtectv013 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 6A FF 68 4B 43 55 46 68 54 49 48 53 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 68 53 56 57 89 65 FA 33 DB 89 5D F8 6A 02 EB 01 F8 58 5F 5E 5B 64 8B 25 00 00 00 00 64 8F 05 00 00 00 00 58 58 58 5D 68 9F 6F 56 B6 50 E8 5D 00 00 00 EB FF 71 78 }

	condition:
		$a0
}

rule PrivateEXEProtector197SetiSoft : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 83 C4 F4 FC 53 57 56 8B 74 24 20 8B 7C 24 24 66 81 3E 4A 43 0F 85 A5 02 00 00 83 C6 0A 33 DB BA 00 00 00 80 C7 44 24 14 08 00 00 00 43 8D A4 24 00 00 00 00 8B FF 03 D2 75 08 8B 16 83 C6 04 F9 13 D2 73 2C 8B 4C 24 10 33 C0 8D A4 24 00 00 00 00 05 00 00 00 00 03 D2 75 08 8B 16 83 C6 04 F9 13 D2 13 C0 49 75 EF 02 44 24 0C 88 07 47 EB C6 03 D2 75 08 8B 16 83 C6 04 F9 13 D2 0F 82 6E 01 00 00 03 D2 75 08 8B 16 83 C6 04 F9 13 D2 0F 83 DC 00 00 00 B9 04 00 00 00 33 C0 8D A4 24 00 00 00 00 8D 64 24 00 03 D2 75 08 8B 16 83 C6 04 F9 13 D2 13 C0 49 75 EF 48 74 B1 0F 89 EF 01 00 00 03 D2 75 08 8B 16 83 C6 04 F9 13 D2 73 42 BD 00 01 00 00 B9 08 00 00 00 33 C0 8D A4 24 00 00 00 00 05 00 00 00 00 03 D2 75 08 8B 16 83 C6 04 F9 13 D2 13 C0 49 75 EF 88 07 47 4D 75 D6 }

	condition:
		$a0
}

import "pe"

rule ASPackv21AlexeySolodovnikov : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 72 05 00 00 EB 33 87 DB 90 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule ASPackv103bAlexeySolodovnikov : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 [4] 5D 81 ED AE 98 43 ?? B8 A8 98 43 ?? 03 C5 2B 85 18 9D 43 ?? 89 85 24 9D 43 ?? 80 BD 0E 9D 43 }

	condition:
		$a0 at pe.entry_point
}

rule FSGv20 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 87 25 [4] 61 94 55 A4 B6 80 FF 13 73 F9 33 C9 FF 13 73 16 33 C0 FF 13 73 1F B6 80 41 B0 10 FF 13 12 C0 73 FA 75 }

	condition:
		$a0
}

import "pe"

rule PseudoSigner01PEIntro10Anorganix : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 8B 04 24 9C 60 E8 14 00 00 00 5D 81 ED 0A 45 40 90 80 BD 67 44 40 90 90 0F 85 48 FF ED 0A E9 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule tElockv099SpecialBuildheXerforgot : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E9 5E DF FF FF 00 00 00 [4] E5 [2] 00 00 00 00 00 00 00 00 00 05 [2] 00 F5 [2] 00 ED [2] 00 00 00 00 00 00 00 00 00 12 [2] 00 FD [2] 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 1D [2] 00 00 00 00 00 30 [2] 00 00 }
		$a1 = { E9 5E DF FF FF 00 00 00 [4] E5 [2] 00 00 00 00 00 00 00 00 00 05 [2] 00 F5 [2] 00 ED [2] 00 00 00 00 00 00 00 00 00 12 [2] 00 FD [2] 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 1D [2] 00 00 00 00 00 30 [2] 00 00 00 00 00 1D [2] 00 00 00 00 00 30 [2] 00 00 00 00 00 }

	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point
}

import "pe"

rule VxBackfont900 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E8 [2] B4 30 CD 21 3C 03 [2] B8 [2] BA [2] CD 21 81 FA [4] BA [2] 8C C0 48 8E C0 8E D8 80 [3] 5A [2] 03 [3] 40 8E D8 80 [3] 5A [2] 83 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule CrunchPEv20xx : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 E8 [4] 5D 83 ED 06 8B C5 55 60 89 AD [4] 2B 85 [4] 89 85 [4] 55 BB [4] 03 DD 53 64 67 FF 36 [2] 64 67 89 26 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule Litev003a : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 06 FC 1E 07 BE [4] 6A 04 68 ?? 10 [2] 68 }

	condition:
		$a0 at pe.entry_point
}

rule SimplePack1XMethod2bagie : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 4D 5A 90 EB 01 00 52 E9 ?? 01 00 00 50 45 00 00 4C 01 02 00 00 00 00 00 00 00 00 00 00 00 00 00 E0 00 0F 03 0B 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 0C 00 00 00 00 [3] 00 10 00 00 00 02 00 00 01 00 00 00 00 00 00 00 04 00 00 00 00 00 00 00 }

	condition:
		$a0
}

import "pe"

rule PEncryptv10 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 9C BE 00 10 40 00 8B FE B9 28 03 00 00 BB 78 56 34 12 AD 33 C3 AB E2 FA 9D 61 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule BJFntv12RC : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB 02 69 B1 83 EC 04 EB 03 CD 20 EB EB 01 EB 9C EB 01 EB EB }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule FishPEShield112116HellFish : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 83 C4 D0 53 56 57 8B 45 10 83 C0 0C 8B 00 89 45 DC 83 7D DC 00 75 08 E8 BD FE FF FF 89 45 DC E8 E1 FD FF FF 8B 00 03 45 DC 89 45 E4 E8 DC FE FF FF 8B D8 BA 8E 4E 0E EC 8B C3 E8 2E FF FF FF 89 45 F4 BA 04 49 32 D3 8B C3 E8 1F FF FF FF 89 45 F8 BA 54 CA AF 91 8B C3 E8 10 FF FF FF 89 45 F0 BA AC 33 06 03 8B C3 E8 01 FF FF FF 89 45 EC BA 1B C6 46 79 8B C3 E8 F2 FE FF FF 89 45 E8 BA AA FC 0D 7C 8B C3 E8 E3 FE FF FF 89 45 FC 8B 45 E4 8B 58 04 03 5D E4 8B FB 8B 45 E4 8B 30 4E 85 F6 72 2B }
		$a1 = { 60 E8 EA FD FF FF FF D0 C3 8D 40 00 ?? 00 00 00 2C 00 00 00 [3] 00 [2] 00 00 [3] 00 00 [2] 00 [3] 00 [3] 00 ?? 00 00 00 00 [2] 00 [2] 00 00 ?? 00 00 00 00 [2] 00 00 10 00 00 [3] 00 40 [3] 00 00 [2] 00 00 [2] 00 [3] 00 40 [3] 00 00 ?? 00 00 00 [2] 00 [2] 00 00 40 }

	condition:
		$a0 or $a1 at pe.entry_point
}

import "pe"

rule CodeCryptv016bv0163b : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E9 2E 03 00 00 EB 02 83 3D 58 EB 02 FF 1D 5B EB 02 0F C7 5F }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule VOBProtectCD : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 5F 81 EF [4] BE [2] 40 ?? 8B 87 [4] 03 C6 57 56 8C A7 [4] FF 10 89 87 [4] 5E 5F }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule diProtectorV1XdiProtectorSoftware : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 01 00 A0 E3 14 00 00 EB 00 00 20 E0 44 10 9F E5 03 2A A0 E3 40 30 A0 E3 AE 00 00 EB 30 00 8F E5 00 20 A0 E1 3A 0E 8F E2 00 00 80 E2 1C 10 9F E5 20 30 8F E2 0E 00 00 EB 14 00 9F E5 14 10 9F E5 7F 20 A0 E3 C5 00 00 EB 04 C0 8F E2 00 F0 9C E5 }

	condition:
		$a0 at pe.entry_point
}

rule PrivateexeProtector20SetiSoftTeam : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 00 00 00 00 00 00 00 00 [8] 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 4B 45 52 4E 45 4C 33 32 2E 44 4C 4C 00 [4] 00 00 00 00 00 00 }

	condition:
		$a0
}

import "pe"

rule AHTeamEPProtector03fakekkryptor9kryptoraFEUERRADER : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 90 [46] 90 FF E0 60 E8 [4] 5E B9 00 00 00 00 2B C0 02 04 0E D3 C0 49 79 F8 41 8D 7E 2C 33 46 ?? 66 B9 }

	condition:
		$a0 at pe.entry_point
}

rule PEBundlev310 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 9C 60 E8 02 00 00 00 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 07 20 40 00 87 DD [4] 40 00 01 }

	condition:
		$a0
}

import "pe"

rule NsPack34NorthStar : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 9C 60 E8 00 00 00 00 5D 83 ED 07 8D 85 [2] FF FF 80 38 01 0F 84 42 02 00 00 C6 00 01 8B D5 2B 95 [2] FF FF 89 95 [2] FF FF 01 95 [2] FF FF 8D B5 [2] FF FF 01 16 60 6A 40 68 00 10 00 00 68 00 10 00 00 6A 00 FF 95 [2] FF FF 85 C0 0F 84 6A 03 00 00 89 85 [2] FF FF E8 00 00 00 00 5B B9 68 03 00 00 03 D9 50 53 E8 B1 02 00 00 61 8B 36 8B FD 03 BD [2] FF FF 8B DF 83 3F 00 75 0A 83 C7 04 B9 00 00 00 00 EB 16 B9 01 00 00 00 03 3B 83 C3 04 83 3B 00 74 36 01 13 8B 33 03 7B 04 57 51 52 53 FF B5 [2] FF FF FF B5 [2] FF FF 8B D6 8B CF 8B 85 [2] FF FF 05 AA 05 00 00 FF D0 5B 5A 59 5F 83 F9 00 74 05 83 C3 08 EB C5 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PellesC280290EXEX86CRTLIB : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 89 E5 6A FF 68 [4] 68 [4] 64 FF 35 [4] 64 89 25 [4] 83 EC ?? 83 EC ?? 53 56 57 89 65 E8 68 00 00 00 ?? E8 [4] 59 A3 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule RLPackV115V117Dllap0x : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 80 7C 24 08 01 0F 85 ?? 01 00 00 60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 [4] 8D 9D [4] 33 FF E8 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PellesC28x45xPelleOrinius : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 89 E5 6A FF 68 [4] 68 [4] 64 FF 35 [4] 64 89 25 [4] 83 EC }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule Thinstallv2460Jitit : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 51 53 56 57 6A 00 6A 00 FF 15 F4 18 40 00 50 E8 87 FC FF FF 59 59 A1 94 1A 40 00 8B 40 10 03 05 90 1A 40 00 89 45 FC 8B 45 FC FF E0 5F 5E 5B C9 C3 00 00 00 76 0C 00 00 D4 0C 00 00 1E }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule FSGv110Engdulekxt : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { BB D0 01 40 ?? BF ?? 10 40 ?? BE }
		$a1 = { E8 01 00 00 00 [2] E8 ?? 00 00 00 }
		$a2 = { EB 01 ?? EB 02 [3] 80 [2] 00 }

	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point or $a2 at pe.entry_point
}

rule PECompactv2xx : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { B8 [3] 00 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 50 45 43 6F 6D 70 61 63 74 32 00 }

	condition:
		$a0
}

import "pe"

rule ASPackv10802AlexeySolodovnikov : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 EB 0A 5D EB 02 FF 25 45 FF E5 E8 E9 E8 F1 FF FF FF E9 81 ED 23 6A 44 00 BB 10 ?? 44 00 03 DD 2B 9D 72 }

	condition:
		$a0 at pe.entry_point
}

rule Armadillo440SiliconRealmsToolworks : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 31 2E 31 2E 34 00 00 00 C2 E0 94 BE 93 FC DE C6 B6 24 83 F7 D2 A4 92 77 40 27 CF EB D8 6F 50 B4 B5 29 24 FA 45 08 04 52 D5 1B D2 8C 8A 1E 6E FF 8C 5F 42 89 F1 83 B1 27 C5 69 57 FC 55 0A DD 44 BE 2A 02 97 6B 65 15 AA 31 E9 28 7D 49 1B DF B5 5D 08 A8 BA A8 }

	condition:
		$a0
}

import "pe"

rule Armadillov1xxv2xx : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 53 8B 5D 08 56 8B 75 0C 57 8B 7D 10 85 F6 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule HACKSTOPv111c : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { B4 30 CD 21 86 E0 3D [2] 73 ?? B4 ?? CD 21 B0 ?? B4 4C CD 21 53 BB [2] 5B EB }

	condition:
		$a0 at pe.entry_point
}

rule EXEStealth276UnregisteredWebtoolMaster : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB ?? 45 78 65 53 74 65 61 6C 74 68 20 56 32 20 53 68 61 72 65 77 61 72 65 20 }

	condition:
		$a0
}

import "pe"

rule PseudoSigner02LCCWin32DLLAnorganix : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 89 E5 53 56 57 83 7D 0C 01 75 05 E8 17 90 90 90 FF 75 10 FF 75 0C FF 75 08 A1 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule CDSSSv10Beta1CyberDoomTeamX : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED CA 47 40 00 FF 74 24 20 E8 D3 03 00 00 0B C0 0F 84 13 03 00 00 89 85 B8 4E 40 00 66 8C D8 A8 04 74 0C C7 85 8C 4E 40 00 01 00 00 00 EB 12 64 A1 30 00 00 00 0F B6 40 02 0A C0 0F 85 E8 02 00 00 8D 85 F6 4C 40 00 50 FF B5 B8 4E 40 00 E8 FC 03 00 00 0B C0 0F 84 CE 02 00 00 E8 1E 03 00 00 89 85 90 4E 40 00 8D 85 03 4D 40 00 50 FF B5 B8 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule tElockv041x : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 66 8B C0 8D 24 24 EB 01 EB 60 EB 01 EB 9C E8 00 00 00 00 5E 83 C6 50 8B FE 68 78 01 [2] 59 EB 01 EB AC 54 E8 03 [3] 5C EB 08 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule ZCodeWin32PEProtectorv101 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E9 12 00 00 00 [12] E9 FB FF FF FF C3 68 [4] 64 FF 35 }

	condition:
		$a0 at pe.entry_point
}

rule ABCCryptor10byZloY : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 68 FF 64 24 F0 68 58 58 58 58 90 FF D4 50 8B 40 F2 05 B0 95 F6 95 0F 85 01 81 BB FF 68 [4] BF 00 [3] B9 00 [3] 80 37 ?? 47 39 CF 75 F8 [54] BF 00 [3] B9 00 [3] 80 37 ?? 47 39 CF 75 F8 }

	condition:
		$a0
}

import "pe"

rule FSGv120EngdulekxtMicrosoftVisualC60 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { C1 E0 06 EB 02 CD 20 EB 01 27 EB 01 24 BE 80 ?? 42 00 49 EB 01 99 8D 1D F4 00 00 00 EB 01 5C F7 D8 1B CA EB 01 31 8A 16 80 E9 41 EB 01 C2 C1 E0 0A EB 01 A1 81 EA A8 8C 18 A1 34 46 E8 01 00 00 00 62 59 32 D3 C1 C9 02 EB 01 68 80 F2 1A 0F BE C9 F7 D1 2A D3 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule SLVc0deProtectorv061SLV : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB 02 FA 04 E8 49 00 00 00 69 E8 49 00 00 00 95 E8 4F 00 00 00 68 E8 1F 00 00 00 49 E8 E9 FF FF FF 67 E8 1F 00 }
		$a1 = { EB 02 FA 04 E8 49 00 00 00 69 E8 49 00 00 00 95 E8 4F 00 00 00 68 E8 1F 00 00 00 49 E8 E9 FF FF FF 67 E8 1F 00 00 00 93 E8 31 00 00 00 78 E8 DD FF FF FF 38 E8 E3 FF FF FF 66 E8 0D 00 00 00 04 E8 E3 FF FF FF 70 E8 CB FF FF FF 69 E8 DD FF FF FF 58 E8 DD FF FF FF 69 E8 E3 FF FF FF 79 E8 BF FF FF FF 69 83 C4 40 E8 00 00 00 00 5D 81 ED 9D 11 40 00 8D 95 B4 11 40 00 E8 CB 2E 00 00 33 C0 F7 F0 69 8D B5 05 12 40 00 B9 5D 2E 00 00 8B FE AC }

	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point
}

import "pe"

rule FSG131dulekxt : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { BE [3] 00 BF [3] 00 BB [3] 00 53 BB [3] 00 B2 80 }

	condition:
		$a0 at pe.entry_point
}

rule RLPackV112V114aPlib043ap0x : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 [4] 8D 9D [4] 33 FF EB 0F FF [3] FF [3] D3 83 C4 ?? 83 C7 ?? 83 3C 37 00 75 EB }

	condition:
		$a0
}

rule Crypter31SLESH : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 68 FF 64 24 F0 68 58 58 58 58 FF D4 50 8B 40 F2 05 B0 95 F6 95 0F 85 01 81 BB FF 68 }

	condition:
		$a0
}

import "pe"

rule PseudoSigner01VBOX43MTEAnorganix : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 0B C0 0B C0 0B C0 0B C0 0B C0 0B C0 0B C0 0B C0 E9 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule MSLRHv032afakeBJFNT13emadicius : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB 03 3A 4D 3A 1E EB 02 CD 20 9C EB 02 CD 20 EB 02 CD 20 60 EB 02 C7 05 EB 02 CD 20 E8 03 00 00 00 E9 EB 04 58 40 50 C3 61 9D 1F EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 2B 04 24 74 04 75 02 EB 02 EB 01 }

	condition:
		$a0 at pe.entry_point
}

rule FreeCryptor02build002GlOFF : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 33 D2 90 1E 68 1B [3] 0F A0 1F 8B 02 90 50 54 8F 02 90 90 8E 64 24 08 FF E2 58 50 33 D2 52 83 F8 01 9B 40 8A 10 89 14 24 90 D9 04 24 90 D9 FA D9 5C 24 FC 8B 5C 24 FC 81 F3 C2 FC 1D 1C 75 E3 74 01 62 FF D0 90 5A 33 C0 8B 54 24 08 90 64 8F 00 90 83 C2 08 52 5C 5A }

	condition:
		$a0
}

rule PackItBitchV10archphase : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 00 00 00 00 00 00 00 00 00 00 00 00 [8] 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 4B 45 52 4E 45 4C 33 32 2E 44 4C 4C 00 [8] 00 00 00 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 ?? 00 00 00 00 00 00 [8] 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

	condition:
		$a0
}

import "pe"

rule nPackv11250BetaNEOx : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 83 3D 04 [3] 00 75 05 E9 01 00 00 00 C3 E8 46 00 00 00 E8 73 00 00 00 B8 2E [3] 2B 05 08 [3] A3 00 [3] E8 9C 00 00 00 E8 04 02 00 00 E8 FB 06 00 00 E8 1B 06 00 00 A1 00 [3] C7 05 04 [3] 01 00 00 00 01 05 00 [3] FF 35 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule UnpackedBSSFXArchivev19 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 1E 33 C0 50 B8 [2] 8E D8 FA 8E D0 BC [2] FB B8 [2] CD 21 3C 03 73 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PseudoSigner01VideoLanClientAnorganix : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 89 E5 83 EC 08 90 90 90 90 90 90 90 90 90 90 90 90 90 90 01 FF FF 01 01 01 00 01 90 90 90 90 90 90 90 90 90 90 90 90 90 90 00 01 00 01 00 01 90 90 00 01 E9 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PseudoSigner01PECompact14Anorganix : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 90 90 90 90 68 [4] 67 64 FF 36 00 00 67 64 89 26 00 00 F1 90 90 90 90 EB 06 68 90 90 90 90 C3 9C 60 E8 02 90 90 90 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PseudoSigner01DxPack10Anorganix : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 00 00 00 00 5D 8B FD 81 ED 90 90 90 90 2B B9 00 00 00 00 81 EF 90 90 90 90 83 BD 90 90 90 90 90 0F 84 00 00 00 00 E9 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule Splice11byTw1stedL0gic : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 68 00 1A 40 00 E8 EE FF FF FF 00 00 00 00 00 00 30 00 00 00 40 00 00 00 00 00 00 00 [16] 00 00 00 00 00 00 01 00 00 00 [6] 50 72 6F 6A 65 63 74 31 00 [7] 00 00 00 00 06 00 00 00 AC 29 40 00 07 00 00 00 BC 28 40 00 07 00 00 00 74 28 40 00 07 00 00 00 2C 28 40 00 07 00 00 00 08 23 40 00 01 00 00 00 38 21 40 00 00 00 00 00 FF FF FF FF FF FF FF FF 00 00 00 00 8C 21 40 00 08 ?? 40 00 01 00 00 00 AC 19 40 00 00 00 00 00 00 00 00 00 00 00 00 00 AC 19 40 00 4F 00 43 00 50 00 00 00 E7 AF 58 2F 9A 4C 17 4D B7 A9 CA 3E 57 6F F7 76 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PECompactv140v145 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB 06 68 [4] C3 9C 60 E8 02 [3] 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F A0 40 ?? 87 DD 8B 85 A6 A0 40 ?? 01 85 03 A0 40 ?? 66 C7 85 ?? A0 40 ?? 90 90 01 85 9E A0 40 ?? BB C3 11 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule Armadillo300aSiliconRealmsToolworks : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 00 00 00 00 5D 50 51 EB 0F ?? EB 0F ?? EB 07 ?? EB 0F ?? EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC ?? 59 58 50 51 EB 0F ?? EB 0F ?? EB 07 ?? EB 0F ?? EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC ?? 59 58 50 51 EB 0F }

	condition:
		$a0 at pe.entry_point
}

rule NullsoftInstallSystemv20b4 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 83 EC 10 53 55 56 57 C7 44 24 14 F0 91 40 00 33 ED C6 44 24 13 20 FF 15 2C 70 40 00 55 FF 15 88 72 40 00 BE 00 D4 42 00 BF 00 04 00 00 56 57 A3 60 6F 42 00 FF 15 C4 70 40 00 E8 9F FF FF FF 8B 1D 90 70 40 00 85 C0 75 21 68 FB 03 00 00 56 FF 15 60 71 40 00 }
		$a1 = { 83 EC 14 83 64 24 04 00 53 55 56 57 C6 44 24 13 20 FF 15 30 70 40 00 BE 00 20 7A 00 BD 00 04 00 00 56 55 FF 15 C4 70 40 00 56 E8 7D 2B 00 00 8B 1D 8C 70 40 00 6A 00 56 FF D3 BF 80 92 79 00 56 57 E8 15 26 00 00 85 C0 75 38 68 F8 91 40 00 55 56 FF 15 60 71 }

	condition:
		$a0 or $a1
}

import "pe"

rule PESHiELDv01bMTE : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E8 [26] B9 1B 01 [2] D1 }

	condition:
		$a0 at pe.entry_point
}

rule BeRoEXEPackerV100BeRo : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { BA [4] 8D B2 [4] 8B 46 ?? 85 C0 74 51 03 C2 8B 7E ?? 8B 1E 85 DB 75 02 8B DF 03 DA 03 FA 52 57 50 FF 15 [4] 5F 5A 85 C0 74 2F 8B C8 8B 03 85 C0 74 22 0F BA F0 1F 72 04 8D 44 [2] 51 52 57 50 51 FF 15 [4] 5F 5A 59 85 C0 74 0B AB 83 C3 04 EB D8 83 C6 14 EB AA 61 C3 }

	condition:
		$a0
}

import "pe"

rule MSLRHv32aemadicius : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 2B 04 24 74 04 75 02 EB 02 EB 01 81 83 C4 04 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 3D FF 0F 00 00 EB 01 68 EB 02 CD 20 EB 01 E8 76 1B EB 01 68 EB 02 CD 20 EB 01 E8 CC 66 B8 FE 00 74 04 75 02 EB 02 EB 01 81 66 E7 64 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule SpecialEXEPaswordProtectorv101EngPavolCerven : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED 06 00 00 00 89 AD 8C 01 00 00 8B C5 2B 85 FE 75 00 00 89 85 3E 77 00 00 8D 95 C6 77 00 00 8D 8D FF 77 00 00 55 68 00 20 00 00 51 52 6A 00 FF 95 04 7A 00 00 5D 6A 00 FF 95 FC 79 00 00 8D 8D 60 78 00 00 8D 95 85 01 00 00 55 68 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PECompactv166 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB 06 68 [4] C3 9C 60 E8 02 [3] 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 3F 90 40 ?? 87 DD 8B 85 E6 90 40 ?? 01 85 33 90 40 ?? 66 C7 85 ?? 90 40 ?? 90 90 01 85 DA 90 40 ?? 01 85 DE 90 40 ?? 01 85 E2 90 40 ?? BB 5B 11 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PECompactv167 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB 06 68 [4] C3 9C 60 E8 02 [3] 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 3F 90 40 87 DD 8B 85 E6 90 40 01 85 33 90 40 66 C7 85 90 40 90 90 01 85 DA 90 40 01 85 DE 90 40 01 85 E2 90 40 BB 8B 11 }

	condition:
		$a0 at pe.entry_point
}

rule VIRUSIWormHybris : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB 16 A8 54 [2] 47 41 42 4C 4B 43 47 43 [6] 52 49 53 ?? FC 68 4C 70 40 ?? FF 15 }

	condition:
		$a0
}

rule GPInstallv50332 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 33 C9 51 51 51 51 51 51 51 53 56 57 B8 C4 1C 41 00 E8 6B 3E FF FF 33 C0 55 68 76 20 41 00 64 FF 30 64 89 20 BA A0 47 41 00 33 C0 E8 31 0A FF FF 33 D2 A1 A0 }

	condition:
		$a0
}

import "pe"

rule PseudoSigner02PEIntro10Anorganix : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 8B 04 24 9C 60 E8 14 00 00 00 5D 81 ED 0A 45 40 90 80 BD 67 44 40 90 90 0F 85 48 FF ED 0A }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule Armadillov410SiliconRealmsToolworks : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 6A FF 68 F8 8E 4C 00 68 D0 EA 49 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF 15 88 31 4C 00 33 D2 8A D4 89 15 7C A5 4C 00 8B C8 81 E1 FF 00 00 00 89 0D 78 A5 4C 00 C1 E1 08 03 CA 89 0D 74 A5 4C 00 C1 E8 10 A3 70 A5 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule AverCryptor102betaos1r1s : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED 0C 17 40 00 8B BD 33 18 40 00 8B 8D 3B 18 40 00 B8 51 18 40 00 03 C5 80 30 05 83 F9 00 74 71 81 7F 1C AB 00 00 00 75 62 8B 57 0C 03 95 37 18 40 00 33 C0 51 33 C9 66 B9 F7 00 66 83 F9 00 74 49 8B 57 0C 03 95 37 18 40 00 8B 85 3F 18 40 00 83 F8 02 75 06 81 C2 00 02 00 00 51 8B 4F 10 83 F8 02 75 06 81 E9 00 02 00 00 57 BF C8 00 00 00 8B F1 E8 27 00 00 00 8B C8 5F B8 51 18 40 00 03 C5 E8 24 00 00 00 59 49 EB B1 59 83 C7 28 49 EB 8A 8B 85 2F 18 40 00 89 44 24 1C 61 FF E0 56 57 4F F7 D7 23 F7 8B C6 5F 5E C3 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule FSGv131 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { BB D0 01 40 00 BF 00 10 40 00 BE [4] 53 BB [4] B2 80 A4 B6 80 FF D3 73 F9 33 C9 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule FSGv133 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { BE A4 01 40 00 AD 93 AD 97 AD 56 96 B2 80 A4 B6 80 FF 13 73 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule HidePE101BGCorp : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { BA [3] 00 B8 [4] 89 02 83 C2 04 B8 [4] 89 02 83 C2 04 B8 [4] 89 02 83 C2 F8 FF E2 0D 0A 2D 3D 5B 20 48 69 64 65 50 45 20 62 79 20 42 47 43 6F 72 70 20 5D 3D 2D }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule EXEStealthv11 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED FB 1D 40 00 B9 7B 09 00 00 8B F7 AC }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule Thinstallvxx : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { B8 EF BE AD DE 50 6A ?? FF 15 10 19 40 ?? E9 AD FF FF FF }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule Obsidium1200ObsidiumSoftware : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB 02 [2] E8 3F 1E 00 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PrivatePersonalPackerPPP103ConquestOfTroycom : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E8 19 00 00 00 90 90 E8 68 00 00 00 FF 35 2C 37 00 10 E8 ED 01 00 00 6A 00 E8 2E 04 00 00 E8 41 04 00 00 A3 74 37 00 10 6A 64 E8 5F 04 00 00 E8 30 04 00 00 A3 78 37 00 10 6A 64 E8 4E 04 00 00 E8 1F 04 00 00 A3 7C 37 00 10 A1 74 37 00 10 8B 1D 78 37 00 10 2B D8 8B 0D 7C 37 00 10 2B C8 83 FB 64 73 0F 81 F9 C8 00 00 00 73 07 6A 00 E8 D9 03 00 00 C3 6A 0A 6A 07 6A 00 E8 D3 03 00 00 A3 20 37 00 10 50 6A 00 E8 DE 03 00 00 A3 24 37 00 10 FF 35 20 37 00 10 6A 00 E8 EA 03 00 00 A3 30 37 00 10 FF 35 24 37 00 10 E8 C2 03 00 00 A3 28 37 00 10 8B 0D 30 37 00 10 8B 3D 28 37 00 10 EB 09 49 C0 04 39 55 80 34 39 24 0B C9 }

	condition:
		$a0 at pe.entry_point
}

rule VIRUSIWormBagle : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 6A 00 E8 95 01 00 00 E8 9F E6 FF FF 83 3D 03 50 40 00 00 75 14 68 C8 AF 00 00 E8 01 E1 FF FF 05 88 13 00 00 A3 03 50 40 00 68 5C 57 40 00 68 F6 30 40 00 FF 35 03 50 40 00 E8 B0 EA FF FF E8 3A FC FF FF 83 3D 54 57 40 00 00 74 05 E8 F3 FA FF FF 68 E8 03 00 }

	condition:
		$a0
}

import "pe"

rule RLPackv118BasicLZMAAp0x : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 21 0B 00 00 8D 9D FF 02 00 00 33 FF E8 9F 01 00 00 6A 40 68 00 10 00 00 68 00 20 0C 00 6A 00 FF 95 AA 0A 00 00 89 85 F9 0A 00 00 EB 14 60 FF B5 F9 0A }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule StonesPEEncryptorv20 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 53 51 52 56 57 55 E8 [4] 5D 81 ED 42 30 40 ?? FF 95 32 35 40 ?? B8 37 30 40 ?? 03 C5 2B 85 1B 34 40 ?? 89 85 27 34 40 ?? 83 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule Upackv029betaDwing : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E9 [4] 42 79 44 77 69 6E 67 40 00 00 00 50 45 00 00 4C 01 02 [20] 29 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PseudoSigner02BJFNT11bAnorganix : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB 01 EA 9C EB 01 EA 53 EB 01 EA 51 EB 01 EA 52 EB 01 EA 56 90 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule UPXScramblerRCv1x : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 90 61 BE [4] 8D BE [4] 57 83 CD FF }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PECrypt15BitShapeSoftware : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED 55 20 40 00 B9 7B 09 00 00 8D BD 9D 20 40 00 8B F7 AC [48] AA E2 CC }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule Upackv021BetaDwing : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { BE 88 01 [2] AD 8B F8 [4] 33 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule UPXFreakV01HMX0101 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { BE [4] 83 C6 01 FF E6 00 00 }

	condition:
		$a0 at pe.entry_point
}

rule UnnamedScrambler20p0ke : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC B9 0A 00 00 00 6A 00 6A 00 49 75 F9 53 56 57 B8 1C 2F 40 00 E8 C8 F1 FF FF 33 C0 55 68 FB 33 40 00 64 FF 30 64 89 20 BA 0C 34 40 00 B8 E4 54 40 00 E8 EF FE FF FF 8B D8 85 DB 75 07 6A 00 E8 5A F2 FF FF BA E8 54 40 00 8B C3 8B 0D E4 54 40 00 E8 74 E2 FF FF C7 05 20 6B 40 00 09 00 00 00 BB 98 69 40 00 C7 45 EC E8 54 40 00 C7 45 E8 31 57 40 00 C7 45 E4 43 60 40 00 BE D3 6A 40 00 BF E0 6A 40 00 83 7B 04 00 75 0B 83 3B 00 0F 86 AA 03 00 00 EB 06 0F 8E A2 03 00 00 8B 03 8B D0 B8 0C 6B 40 00 E8 C1 EE FF FF B8 0C 6B 40 00 E8 6F EE FF FF 8B D0 8B 45 EC 8B 0B E8 0B E2 FF FF 6A 00 6A 1E 6A 00 6A 2C A1 0C 6B 40 00 E8 25 ED FF FF 8D 55 E0 E8 15 FE FF FF 8B 55 E0 B9 10 6B 40 00 A1 0C 6B 40 00 }

	condition:
		$a0
}

import "pe"

rule HACKSTOPv100 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { FA BD [2] FF E5 6A 49 48 0C ?? E4 ?? 3F 98 3F }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule ExeShield36wwwexeshieldcom : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { B8 [3] 00 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 50 45 43 6F 6D 70 61 63 74 32 00 CE 1E 42 AF F8 D6 CC E9 FB C8 4F 1B 22 7C B4 C8 0D BD 71 A9 C8 1F 5F B1 29 8F 11 73 8F 00 D1 88 87 A9 3F 4D 00 6C 3C BF C0 80 F7 AD 35 23 EB 84 82 6F }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule Pe123v200644 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 8B C0 EB 01 34 60 EB 01 2A 9C EB 02 EA C8 E8 0F 00 00 00 EB 03 3D 23 23 EB 01 4A EB 01 5B C3 8D 40 00 53 EB 01 6C EB 01 7E EB 01 8F E8 15 01 00 00 50 E8 67 04 00 00 EB 01 9A 8B D8 FF D3 5B C3 8B C0 E8 00 00 00 00 58 83 C0 05 C3 8B C0 55 8B EC 60 8B 4D 10 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule SDProtectorV11xRandyLi : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 6A FF 68 [4] 68 88 88 88 08 64 A1 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule BobPackv100BoBBobSoft : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 00 00 00 00 8B 0C 24 89 CD 83 E9 06 81 ED [4] E8 3D 00 00 00 89 85 [4] 89 C2 B8 5D 0A 00 00 8D 04 08 E8 E4 00 00 00 8B 70 04 01 D6 E8 76 00 00 00 E8 51 01 00 00 E8 01 01 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule DBPEv210 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 9C 6A 10 73 0B EB 02 C1 51 E8 06 [3] C4 11 73 F7 5B CD 83 C4 04 EB 02 99 EB FF 0C 24 71 01 E8 79 E0 7A 01 75 83 C4 04 9D EB 01 75 68 5F 20 40 ?? E8 B0 EF FF FF 72 03 73 01 75 BE }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule NsPackv31NorthStar : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 9C 60 E8 00 00 00 00 5D 83 ED 07 8D 9D [2] FF FF 8A 03 3C 00 74 10 8D 9D [2] FF FF 8A 03 3C 01 0F 84 42 02 00 00 C6 03 01 8B D5 2B 95 [2] FF FF 89 95 [2] FF FF 01 95 [2] FF FF 8D B5 [2] FF FF 01 16 60 6A 40 68 00 10 00 00 68 00 10 00 00 6A 00 }
		$a1 = { 9C 60 E8 00 00 00 00 5D 83 ED 07 8D 9D [2] FF FF 8A 03 3C 00 74 10 8D 9D [2] FF FF 8A 03 3C 01 0F 84 42 02 00 00 C6 03 01 8B D5 2B 95 [2] FF FF 89 95 [2] FF FF 01 95 [2] FF FF 8D B5 [2] FF FF 01 16 60 6A 40 68 00 10 00 00 68 00 10 00 00 6A 00 FF 95 [2] FF FF 85 C0 0F 84 6A 03 00 00 89 85 [2] FF FF E8 00 00 00 00 5B B9 68 03 00 00 03 D9 50 53 E8 B1 02 00 00 61 8B 36 8B FD 03 BD [2] FF FF 8B DF 83 3F 00 75 0A 83 C7 04 B9 00 00 00 00 EB 16 B9 01 00 00 00 03 3B 83 C3 04 83 3B 00 74 36 01 13 8B 33 03 7B 04 57 51 52 53 FF B5 [2] FF FF FF B5 [2] FF FF 8B D6 8B CF 8B 85 [2] FF FF 05 AA 05 00 00 FF D0 5B 5A 59 5F 83 F9 00 74 05 83 C3 08 EB C5 68 00 80 00 00 6A 00 }

	condition:
		$a0 at pe.entry_point or $a1
}

import "pe"

rule SVKProtectorV13XPavolCerven : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED 06 00 00 00 EB 05 B8 [2] 42 00 64 A0 23 00 00 00 EB 03 C7 84 E8 84 C0 EB 03 C7 84 E9 75 67 B9 49 00 00 00 8D B5 C5 02 00 00 56 80 06 44 46 E2 FA 8B 8D C1 02 00 00 5E 55 51 6A 00 56 FF 95 0C 61 00 00 59 5D 40 85 C0 75 3C 80 3E 00 74 03 46 EB F8 46 E2 E3 8B C5 8B 4C 24 20 2B 85 BD 02 00 00 89 85 B9 02 00 00 80 BD B4 02 00 00 01 75 06 8B 8D 0C 61 00 00 89 8D B5 02 00 00 8D 85 0E 03 00 00 8B DD FF E0 55 68 10 10 00 00 8D 85 B4 00 00 00 50 8D 85 B4 01 00 00 50 6A 00 FF 95 18 61 00 00 5D 6A FF FF 95 10 61 00 00 44 65 62 75 67 67 65 72 20 6F 72 20 74 6F 6F 6C 20 66 6F 72 20 6D 6F 6E 69 74 6F 72 69 6E 67 20 64 65 74 65 63 74 65 64 21 21 21 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule AHTeamEPProtector03fakePECrypt102FEUERRADER : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 90 [46] 90 FF E0 E8 00 00 00 00 5B 83 EB 05 EB 04 52 4E 44 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PseudoSigner02WATCOMCCEXEAnorganix : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E9 00 00 00 00 90 90 90 90 57 41 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PENinja : Packer PEiD hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule UpackV036Dwing : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 0B 01 [14] 18 10 00 00 10 00 00 00 [8] 00 10 00 00 00 02 00 00 [12] 00 00 00 00 [32] 00 00 00 00 0A 00 00 00 00 00 00 00 00 00 00 00 [4] 14 00 00 00 [64] 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 FF 76 08 FF 76 0C BE 1C 01 }
		$a1 = { BE [4] FF 36 E9 C3 00 00 00 }

	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point
}

import "pe"

rule yodasProtectorv101AshkbizDanehkar : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 53 56 57 E8 03 00 00 00 EB 01 ?? E8 86 00 00 00 E8 03 00 00 00 EB 01 ?? E8 79 00 00 00 E8 03 00 00 00 EB 01 ?? E8 A4 00 00 00 E8 03 00 00 00 EB 01 ?? E8 97 00 00 00 E8 03 00 00 00 EB 01 ?? E8 2D 00 00 00 E8 03 00 00 00 EB 01 ?? 60 E8 00 00 00 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule UPX050070 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 00 00 00 00 58 83 E8 3D }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule VxVCLencrypted : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 01 B9 [2] 81 34 [2] 46 46 E2 F8 C3 }
		$a1 = { 01 B9 [2] 81 35 [2] 47 47 E2 F8 C3 }

	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point
}

import "pe"

rule VxXRCV1015 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E8 [2] 5E 83 [2] 53 51 1E 06 B4 99 CD 21 80 FC 21 [5] 33 C0 50 8C D8 48 8E C0 1F A1 [2] 8B }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule RLPackv118BasicDLLaPLibAp0x : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 80 7C 24 08 01 0F 85 [4] 60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 1A 04 00 00 8D 9D C1 02 00 00 33 FF E8 61 01 00 00 EB 0F FF 74 37 04 FF 34 37 FF D3 83 C4 08 83 C7 08 83 3C 37 00 75 EB 83 BD 06 04 00 00 00 74 0E 83 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PellesC290300400DLLX86CRTLIB : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 89 E5 53 56 57 8B 5D 0C 8B 75 10 BF 01 00 00 00 85 DB 75 10 83 3D [4] 00 75 07 31 C0 E9 [4] 83 FB 01 74 05 83 FB 02 75 ?? 85 FF 74 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule UnnamedScrambler13Bp0ke : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC B9 08 00 00 00 6A 00 6A 00 49 75 F9 53 56 57 B8 98 56 00 10 E8 48 EB FF FF 33 C0 55 68 AC 5D 00 10 64 FF 30 64 89 20 6A 00 68 BC 5D 00 10 68 C4 5D 00 10 6A 00 E8 23 EC FF FF E8 C6 CE FF FF 6A 00 68 BC 5D 00 10 68 [4] 6A 00 E8 0B EC FF FF E8 F2 F4 FF FF B8 08 BC 00 10 33 C9 BA 04 01 00 00 E8 C1 D2 FF FF 6A 00 68 BC 5D 00 10 68 E4 5D 00 10 6A 00 E8 E2 EB FF FF 68 04 01 00 00 68 08 BC 00 10 6A 00 FF 15 68 77 00 10 6A 00 68 BC 5D 00 10 68 FC 5D 00 10 6A 00 E8 BD EB FF FF BA 10 5E 00 10 B8 70 77 00 10 E8 CA F3 FF FF 85 C0 0F 84 F7 05 00 00 BA 74 77 00 10 8B 0D 70 77 00 10 E8 FE CD FF FF 6A 00 }

	condition:
		$a0 at pe.entry_point
}

rule HyingsPEArmor075exeHyingCCG : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 00 00 00 00 00 00 00 00 [2] 00 00 00 00 00 00 [2] 01 00 00 00 00 00 00 00 00 00 56 69 72 74 75 61 6C 41 6C 6C 6F 63 00 00 00 00 00 00 00 00 [19] 00 00 00 00 00 00 00 00 00 74 [3] 00 00 00 00 00 }

	condition:
		$a0
}

import "pe"

rule SimbiOZPolyCryptorvxxExtranger : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 60 E8 00 00 00 00 5D 81 ED [4] 8D 85 [4] 68 [4] 50 E8 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule AVPACKv120 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 50 1E 0E 1F 16 07 33 F6 8B FE B9 [2] FC F3 A5 06 BB [2] 53 CB }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule Armadillov220 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 6A FF 68 10 12 41 00 68 F4 A0 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule XPack167 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { B8 8C D3 15 33 75 81 3E E8 0F 00 9A E8 F9 FF 9A 9C EB 01 9A 59 80 CD 01 51 9D EB }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule NullsoftInstallSystemv1xx : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 83 EC 2C 53 56 33 F6 57 56 89 75 DC 89 75 F4 BB A4 9E 40 00 FF 15 60 70 40 00 BF C0 B2 40 00 68 04 01 00 00 57 50 A3 AC B2 40 00 FF 15 4C 70 40 00 56 56 6A 03 56 6A 01 68 00 00 00 80 57 FF 15 9C 70 40 00 8B F8 83 FF FF 89 7D EC 0F 84 C3 00 00 00 }
		$a1 = { 83 EC 0C 53 56 57 FF 15 20 71 40 00 05 E8 03 00 00 BE 60 FD 41 00 89 44 24 10 B3 20 FF 15 28 70 40 00 68 00 04 00 00 FF 15 28 71 40 00 50 56 FF 15 08 71 40 00 80 3D 60 FD 41 00 22 75 08 80 C3 02 BE 61 FD 41 00 8A 06 8B 3D F0 71 40 00 84 C0 74 0F 3A C3 74 }

	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point
}

import "pe"

rule BobSoftMiniDelphiBoBBobSoft : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 83 C4 F0 53 56 B8 [4] E8 [4] 33 C0 55 68 [4] 64 FF 30 64 89 20 B8 }
		$a1 = { 55 8B EC 83 C4 F0 53 B8 [4] E8 [4] 33 C0 55 68 [4] 64 FF 30 64 89 20 B8 [4] E8 }
		$a2 = { 55 8B EC 83 C4 F0 B8 [4] E8 }

	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point or $a2 at pe.entry_point
}

import "pe"

rule UltraProV10SafeNet : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { A1 [4] 85 C0 0F 85 3B 06 00 00 55 56 C7 05 [4] 01 00 00 00 FF 15 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PECompactv1242v1243 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB 06 68 [4] C3 9C 60 E8 02 [3] 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 70 40 ?? 87 DD 8B 85 A6 70 40 ?? 01 85 03 70 40 ?? 66 C7 85 70 40 90 ?? 90 01 85 9E 70 40 BB ?? D2 09 }

	condition:
		$a0 at pe.entry_point
}

rule SimplePack121build0909Method2bagie : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 4D 5A 90 EB 01 00 52 E9 8A 01 00 00 50 45 00 00 4C 01 02 00 00 00 00 00 00 00 00 00 00 00 00 00 E0 00 0F 03 0B 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 0C 00 00 00 00 [3] 00 10 00 00 00 02 00 00 01 00 00 00 00 00 00 00 04 00 00 00 00 00 00 00 }

	condition:
		$a0
}

import "pe"

rule Obsidium13037ObsidiumSoftware : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB 02 [2] E8 26 00 00 00 EB 03 [3] EB 01 ?? 8B 54 24 0C EB 04 [4] 83 82 B8 00 00 00 26 EB 01 ?? 33 C0 EB 02 [2] C3 EB 01 ?? EB 04 [4] 64 67 FF 36 00 00 EB 01 ?? 64 67 89 26 00 00 EB 01 ?? EB 03 [3] 50 EB 03 [3] 33 C0 EB 03 [3] 8B 00 EB 04 [4] C3 EB 03 [3] E9 FA 00 00 00 EB 03 [3] E8 D5 FF FF FF EB 04 [4] EB 01 ?? 58 EB 02 [2] EB 03 [3] 64 67 8F 06 00 00 EB 01 ?? 83 C4 04 EB 03 [3] E8 23 27 00 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule VxPhoenix927 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E8 00 00 5E 81 C6 [2] BF 00 01 B9 04 00 F3 A4 E8 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule Petite14c199899IanLuck : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 66 9C 60 50 8B D8 03 00 68 54 BC 00 00 6A 00 FF 50 14 8B CC 8D A0 54 BC 00 00 50 8B C3 8D 90 ?? 16 00 00 68 00 00 [2] 51 50 80 04 24 08 50 80 04 24 42 50 80 04 24 61 50 80 04 24 9D 50 80 04 24 BB 83 3A 00 0F 84 D8 14 00 00 8B 44 24 18 F6 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule eXPressorV10CGSoftLabs : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E9 35 14 00 00 E9 31 13 00 00 E9 98 12 00 00 E9 EF 0C 00 00 E9 42 13 00 00 E9 E9 02 00 00 E9 EF 0B 00 00 E9 1B 0D 00 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule RECryptv07xCruddRETh2 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 00 00 00 00 5D 55 81 04 24 0A 00 00 00 C3 8B F5 81 C5 [2] 00 00 89 6D 34 89 75 38 8B 7D 38 81 E7 00 FF FF FF 81 C7 48 00 00 00 47 03 7D 60 8B 4D 5C 83 F9 00 7E 0F 8B 17 33 55 58 89 17 83 C7 04 83 C1 FC EB EC 8B }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PassEXEv20 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 06 1E 0E 0E 07 1F BE [2] B9 [2] 87 14 81 [3] EB ?? C7 [3] 84 00 87 [3] FB 1F 58 4A }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule RECryptv07xCruddRETh1 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED F3 1D 40 00 B9 7B 09 00 00 8D BD 3B 1E 40 00 8B F7 61 60 E8 00 00 00 00 5D 55 81 04 24 0A 00 00 00 C3 8B F5 81 C5 [2] 00 00 89 6D 34 89 75 38 8B 7D 38 81 E7 00 FF FF FF 81 C7 48 00 00 00 47 03 7D 60 8B 4D 5C 83 F9 00 7E 0F 8B }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule WIBUKeyV410Ahttpwibucomus : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { F7 05 [4] FF 00 00 00 75 12 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule Mew501NorthFoxHCC : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { BE 5B 00 40 00 AD 91 AD 93 53 AD 96 56 5F AC C0 C0 ?? 04 ?? C0 C8 ?? AA E2 F4 C3 00 [2] 00 [3] 00 00 10 40 00 4D 45 57 20 30 2E 31 20 62 79 20 4E 6F 72 74 68 66 6F 78 00 4D 45 57 20 30 2E 31 20 62 79 20 4E 6F 72 74 68 66 6F 78 00 4D 45 57 20 30 2E 31 20 62 79 20 4E 6F 72 74 68 66 6F 78 00 4D 45 57 20 30 2E 31 20 62 79 20 4E 6F 72 74 68 66 6F 78 00 4D }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PseudoSigner01ExeSmasherAnorganix : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 9C FE 03 90 60 BE 90 90 41 90 8D BE 90 10 FF FF 57 83 CD FF EB 10 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 FE 0B E9 }

	condition:
		$a0 at pe.entry_point
}

rule UnnamedScrambler12C12Dp0ke : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC B9 05 00 00 00 6A 00 6A 00 49 75 F9 51 53 56 57 B8 ?? 3A [2] E8 ?? EC FF FF 33 C0 55 68 [4] 64 FF 30 64 89 20 E8 ?? D7 FF FF E8 [2] FF FF B8 20 [3] 33 C9 BA 04 01 00 00 E8 ?? DB FF FF 68 04 01 00 00 68 20 [3] 6A 00 FF 15 10 [3] BA [4] B8 14 [3] E8 [2] FF FF 85 C0 0F 84 ?? 04 00 00 BA 18 [3] 8B 0D 14 [3] E8 [2] FF FF 8B 05 88 [3] 8B D0 B8 54 [3] E8 ?? E3 FF FF B8 54 [3] E8 ?? E2 FF FF 8B D0 B8 18 [3] 8B 0D 88 [3] E8 ?? D6 FF FF FF 35 34 [3] FF 35 30 [3] FF 35 3C [3] FF 35 38 [3] 8D 55 E8 A1 88 [3] E8 ?? F0 FF FF 8B 55 E8 B9 54 }

	condition:
		$a0
}

rule AlexProtectorv04beta1byAlex : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 01 00 00 00 C7 83 C4 04 33 C9 E8 01 00 00 00 68 83 C4 04 E8 01 00 00 00 68 83 C4 04 B9 ?? 00 00 00 E8 01 00 00 00 68 83 C4 04 E8 00 00 00 00 E8 01 00 00 00 C7 83 C4 04 8B 2C 24 83 C4 04 E8 01 00 00 00 A9 83 C4 04 81 ED 3C 13 40 00 E8 01 00 00 00 68 }

	condition:
		$a0
}

import "pe"

rule UG2002Cruncherv03b3 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 [4] 5D 81 ED [4] E8 0D [16] 58 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule FishPEShield101HellFish : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 83 C4 D0 53 56 57 8B 45 10 83 C0 0C 8B 00 89 45 DC 83 7D DC 00 75 08 E8 AD FF FF FF 89 45 DC E8 C1 FE FF FF 8B 10 03 55 DC 89 55 E4 83 C0 04 8B 10 89 55 FC 83 C0 04 8B 10 89 55 F4 83 C0 04 8B 10 89 55 F8 83 C0 04 8B 10 89 55 F0 83 C0 04 8B 10 89 55 EC 83 C0 04 8B 00 89 45 E8 8B 45 E4 8B 58 04 03 5D E4 8B FB 8B 45 E4 8B 30 4E 85 F6 72 2B 46 C7 45 E0 00 00 00 00 83 7B 04 00 74 14 }
		$a1 = { 60 E8 12 FE FF FF C3 90 09 00 00 00 2C 00 00 00 [4] C4 03 00 00 BC A0 00 00 00 40 01 00 [4] 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 99 00 00 00 00 8A 00 00 00 10 00 00 28 88 00 00 40 ?? 4B 00 00 00 02 00 00 00 A0 00 00 18 01 00 00 40 ?? 4C 00 00 00 0C 00 00 00 B0 00 00 38 0A 00 00 40 ?? 4E 00 00 00 00 00 00 00 C0 00 00 40 39 00 00 40 ?? 4E 00 00 00 08 00 00 00 00 01 00 C8 06 00 00 40 }

	condition:
		$a0 or $a1 at pe.entry_point
}

import "pe"

rule PseudoSigner01Neolite20Anorganix : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E9 A6 00 00 00 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PEIntrov10 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 8B 04 24 9C 60 E8 [4] 5D 81 ED 0A 45 40 ?? 80 BD 67 44 40 [2] 0F 85 48 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule Obsidiumv1250ObsidiumSoftware : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E8 0E 00 00 00 8B 54 24 0C 83 82 B8 00 00 00 0D 33 C0 C3 64 67 FF 36 00 00 64 67 89 26 00 00 50 33 C0 8B 00 C3 E9 FA 00 00 00 E8 D5 FF FF FF 58 64 67 8F 06 00 00 83 C4 04 E8 2B 13 00 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule DevC4992BloodshedSoftware : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 89 E5 83 EC 08 C7 04 24 01 00 00 00 FF 15 [3] 00 E8 C8 FE FF FF 90 8D B4 26 00 00 00 00 55 89 E5 83 EC 08 C7 04 24 02 00 00 00 FF 15 [3] 00 E8 A8 FE FF FF 90 8D B4 26 00 00 00 00 55 8B 0D [3] 00 89 E5 5D FF E1 8D 74 26 00 55 8B 0D }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule RLPackV119DllLZMA430ap0x : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 80 7C 24 08 01 0F 85 C7 01 00 00 60 E8 00 00 00 00 8B 2C 24 83 C4 04 83 7C 24 28 01 75 0C 8B 44 24 24 89 85 49 0B 00 00 EB 0C 8B 85 45 0B 00 00 89 85 49 0B 00 00 8D B5 6D 0B 00 00 8D 9D 2F 03 00 00 33 FF 6A 40 68 00 10 00 00 68 00 20 0C 00 6A 00 FF 95 DA 0A 00 00 89 85 41 0B 00 00 E8 76 01 00 00 EB 20 60 8B 85 49 0B 00 00 FF B5 41 0B 00 00 FF 34 37 01 04 24 FF 74 37 04 01 04 24 FF D3 61 83 C7 08 83 3C 37 00 75 DA 83 BD 55 0B 00 00 00 74 0E 83 BD 59 0B 00 00 00 74 05 E8 D7 01 00 00 8D 74 37 04 53 6A 40 68 00 10 00 00 68 [4] 6A 00 FF 95 DA 0A 00 00 89 85 69 0B 00 00 5B 60 FF B5 41 0B 00 00 56 FF B5 69 0B 00 00 FF D3 61 8B B5 69 0B 00 00 8B C6 EB 01 40 80 38 01 75 FA 40 8B 38 03 BD 49 0B 00 00 83 C0 04 89 85 65 0B 00 00 E9 98 00 00 00 56 FF 95 D2 0A 00 00 89 85 61 0B 00 00 85 C0 0F 84 C8 00 00 00 8B C6 EB 5F 8B 85 65 0B 00 00 8B 00 A9 00 00 00 80 74 14 35 00 00 00 80 50 8B 85 65 0B 00 00 C7 00 20 20 20 00 EB 06 FF B5 65 0B 00 00 FF B5 61 0B 00 00 FF 95 D6 0A 00 00 85 C0 0F 84 87 00 00 00 89 07 83 C7 04 8B 85 65 0B 00 00 EB 01 40 80 38 00 75 FA 40 89 85 65 0B 00 00 66 81 78 02 00 80 74 A1 80 38 00 75 9C EB 01 46 80 3E 00 75 FA 46 40 8B 38 03 BD 49 0B 00 00 83 C0 04 89 85 65 0B 00 00 80 3E 01 0F 85 5F FF FF FF 68 00 40 00 00 68 [4] FF B5 69 0B 00 00 FF 95 DE 0A 00 00 68 00 40 00 00 68 00 20 0C 00 FF B5 41 0B 00 00 FF 95 DE 0A 00 00 E8 3D 00 00 00 E8 24 01 00 00 61 E9 [4] 61 C3 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule XJXPALLiNSoN : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 6A FF 68 [2] 40 00 68 [2] 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 44 53 56 57 66 9C }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule Armadillov220b1 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 6A FF 68 30 12 41 00 68 A4 A5 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule RCryptor20Vaska : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { F7 D1 83 F1 FF 6A 00 F7 D1 83 F1 FF 81 04 24 [4] F7 D1 83 F1 FF }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule SentinelSuperProAutomaticProtectionv641Safenet : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { A1 [4] 55 8B [3] 85 C0 74 ?? 85 ED 75 ?? A1 [4] 50 55 FF 15 [4] 8B 0D [4] 55 51 FF 15 [4] 85 C0 74 ?? 8B 15 [4] 52 FF 15 [4] 6A 00 6A 00 68 [4] E8 [4] B8 01 00 00 00 5D C2 0C 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule TMTPascalv040 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 0E 1F 06 8C 06 [2] 26 A1 [2] A3 [2] 8E C0 66 33 FF 66 33 C9 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PseudoSigner02CrunchPEHeuristicAnorganix : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 E8 0E 00 00 00 5D 83 ED 06 8B C5 55 60 89 AD [4] 2B 85 00 00 00 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule MSLRHv032afakeMSVCDLLMethod4emadicius : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 56 57 BF 01 00 00 00 8B 75 0C 85 F6 5F 5E 5D EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule VcAsmProtectorV10XVcAsm : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 6A FF 68 [4] 68 [4] 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 E8 03 00 00 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule VBOXv42MTE : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 8C E0 0B C5 8C E0 0B C4 03 C5 74 00 74 00 8B C5 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule MSLRHv032afakeUPX0896102105124emadicius : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 BE 00 90 8B 00 8D BE 00 80 B4 FF 57 83 CD FF EB 3A 90 90 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 0B 75 19 8B 1E 83 EE FC 11 DB 72 10 58 61 90 EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule FSGv110EngdulekxtBorlandDelphiMicrosoftVisualC : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 1B DB E8 02 00 00 00 1A 0D 5B 68 80 [2] 00 E8 01 00 00 00 EA 5A 58 EB 02 CD 20 68 F4 00 00 00 EB 02 CD 20 5E 0F B6 D0 80 CA 5C 8B 38 EB 01 35 EB 02 DC 97 81 EF F7 65 17 43 E8 02 00 00 00 97 CB 5B 81 C7 B2 8B A1 0C 8B D1 83 EF 17 EB 02 0C 65 83 EF 43 13 }
		$a1 = { C1 C8 10 EB 01 0F BF 03 74 66 77 C1 E9 1D 68 83 [2] 77 EB 02 CD 20 5E EB 02 CD 20 2B F7 }

	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point
}

import "pe"

rule VxHafen809 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E8 [2] 1C ?? 81 EE [2] 50 1E 06 8C C8 8E D8 06 33 C0 8E C0 26 [3] 07 3D }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule RLPackFullEdition117LZMAAp0x : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 [15] 8D B5 73 26 00 00 8D 9D 58 03 00 00 33 FF [10] 6A 40 68 [4] 68 [4] 6A }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PseudoSigner01LTC13Anorganix : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 54 E8 00 00 00 00 5D 8B C5 81 ED F6 73 40 00 2B 85 87 75 40 00 83 E8 06 E9 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule ACProtectv141 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 76 03 77 01 7B 74 03 75 01 78 47 87 EE E8 01 00 00 00 76 83 C4 04 85 EE EB 01 7F 85 F2 EB 01 79 0F 86 01 00 00 00 FC EB 01 78 79 02 87 F2 61 51 8F 05 19 38 01 01 60 EB 01 E9 E9 01 00 00 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule yodasProtectorV1031AshkbizDanehkar : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E8 03 00 00 00 EB 01 ?? BB 55 00 00 00 E8 03 00 00 00 EB 01 ?? E8 8F 00 00 00 E8 03 00 00 00 EB 01 ?? E8 82 00 00 00 E8 03 00 00 00 EB 01 ?? E8 B8 00 00 00 E8 03 00 00 00 EB 01 ?? E8 AB 00 00 00 E8 03 00 00 00 EB 01 ?? 83 FB 55 E8 03 00 00 00 EB 01 ?? 75 2E E8 03 00 00 00 EB 01 ?? C3 60 E8 00 00 00 00 5D 81 ED 74 72 42 00 8B D5 81 C2 C3 72 42 00 52 E8 01 00 00 00 C3 C3 E8 03 00 00 00 EB 01 ?? E8 0E 00 00 00 E8 D1 FF FF FF C3 E8 03 00 00 00 EB 01 ?? 33 C0 64 FF 30 64 89 20 CC C3 E8 03 00 00 00 EB 01 ?? 33 C0 64 FF 30 64 89 20 4B CC C3 E8 03 00 00 00 EB 01 ?? 33 DB B9 3F A9 42 00 81 E9 6E 73 42 00 8B D5 81 C2 6E 73 42 00 8D 3A 8B F7 33 C0 E8 03 00 00 00 EB 01 ?? E8 17 00 00 00 90 90 90 E9 98 2E 00 00 33 C0 64 FF 30 64 89 20 43 CC C3 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule tElock096tE : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E9 59 E4 FF FF 00 00 00 00 00 00 00 [4] EE [2] 00 00 00 00 00 00 00 00 00 0E [2] 00 FE [2] 00 F6 [2] 00 00 00 00 00 00 00 00 00 1B [2] 00 06 [2] 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 26 [2] 00 00 00 00 00 39 [2] 00 00 00 00 00 26 [2] 00 00 00 00 00 39 [2] 00 00 00 00 00 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule WerusCrypter10byKas : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { BB E8 12 40 00 80 33 05 E9 7D FF FF FF }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule HEALTHv51byMuslimMPolyak : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 1E E8 [2] 2E 8C 06 [2] 2E 89 3E [2] 8B D7 B8 [2] CD 21 8B D8 0E 1F E8 [2] 06 57 A1 [2] 26 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PCGuardv303dv305d : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 50 E8 [4] 5D EB 01 E3 60 E8 03 [3] D2 EB 0B 58 EB 01 48 40 EB 01 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule VxNovember17768 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E8 [2] 5E 81 EE [2] 50 33 C0 8E D8 80 3E [3] 0E 1F [2] FC }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule BeRoTinyPascalBeRo : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E9 [4] 20 43 6F 6D 70 69 6C 65 64 20 62 79 3A 20 42 65 52 6F 54 69 6E 79 50 61 73 63 61 6C 20 2D 20 28 43 29 20 43 6F 70 79 72 69 67 68 74 20 32 30 30 36 2C 20 42 65 6E 6A 61 6D 69 6E 20 27 42 65 52 6F 27 20 52 6F 73 73 65 61 75 78 20 }

	condition:
		$a0 at pe.entry_point
}

rule PrivateexeProtector21522XSetiSoftTeam : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 00 00 00 00 00 00 00 00 00 00 00 00 00 [8] 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 4B 45 52 4E 45 4C 33 32 2E 44 4C 4C 00 00 00 00 00 }

	condition:
		$a0
}

import "pe"

rule Protectorv1111DDeMPEEnginev09DDeMCIv092 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 53 51 56 E8 00 00 00 00 5B 81 EB 08 10 00 00 8D B3 34 10 00 00 B9 F3 03 00 00 BA 63 17 2A EE 31 16 83 C6 04 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PseudoSigner01XCR011Anorganix : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 8B F0 33 DB 83 C3 01 83 C0 01 E9 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule Trivial173bySMTSMF : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB [2] 28 54 72 69 76 69 61 6C 31 37 33 20 62 79 20 53 4D 54 2F 53 4D 46 29 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule ASProtectv11MTE : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E9 [4] 91 78 79 79 79 E9 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule WARNINGTROJANRobinPE : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 6A 00 6A 20 6A 02 6A 00 6A 03 68 00 00 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PiCryptor10byScofield : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 83 C4 EC 53 56 57 31 C0 89 45 EC B8 40 1E 06 00 E8 48 FA FF FF 33 C0 55 68 36 1F 06 00 64 FF 30 64 89 20 6A 00 68 80 00 00 00 6A 03 6A 00 6A 01 68 00 00 00 80 8D 55 EC 31 C0 E8 4E F4 FF FF 8B 45 EC E8 F6 F7 FF FF 50 E8 CC FA FF FF 8B D8 83 FB FF 74 4E 6A 00 53 E8 CD FA FF FF 8B F8 81 EF AC 26 00 00 6A 00 6A 00 68 AC 26 00 00 53 E8 DE FA FF FF 89 F8 E8 E3 F1 FF FF 89 C6 6A 00 68 28 31 06 00 57 56 53 E8 AE FA FF FF 53 E8 80 FA FF FF 89 FA 81 EA 72 01 00 00 8B C6 E8 55 FE FF FF 89 C6 89 F0 09 C0 74 05 E8 A8 FB FF FF 31 C0 }
		$a1 = { 55 8B EC 83 C4 EC 53 56 57 31 C0 89 45 EC B8 40 1E 06 00 E8 48 FA FF FF 33 C0 55 68 36 1F 06 00 64 FF 30 64 89 20 6A 00 68 80 00 00 00 6A 03 6A 00 6A 01 68 00 00 00 80 8D 55 EC 31 C0 E8 4E F4 FF FF 8B 45 EC E8 F6 F7 FF FF 50 E8 CC FA FF FF 8B D8 83 FB FF 74 4E 6A 00 53 E8 CD FA FF FF 8B F8 81 EF AC 26 00 00 6A 00 6A 00 68 AC 26 00 00 53 E8 DE FA FF FF 89 F8 E8 E3 F1 FF FF 89 C6 6A 00 68 28 31 06 00 57 56 53 E8 AE FA FF FF 53 E8 80 FA FF FF 89 FA 81 EA 72 01 00 00 8B C6 E8 55 FE FF FF 89 C6 89 F0 09 C0 74 05 E8 A8 FB FF FF 31 C0 5A 59 59 64 89 10 68 3D 1F 06 00 8D 45 EC E8 C3 F6 FF FF C3 }
		$a2 = { 89 55 F8 BB 01 00 00 00 8A 04 1F 24 0F 8B 55 FC 8A 14 32 80 E2 0F 32 C2 8A 14 1F 80 E2 F0 02 D0 88 14 1F 46 8D 45 F4 8B 55 FC E8 [4] 8B 45 F4 E8 [4] 3B F0 7E 05 BE 01 00 00 00 43 FF 4D F8 75 C2 [4] 5A 59 59 64 89 10 68 [4] 8D 45 F4 E8 [4] C3 E9 }

	condition:
		$a0 or $a1 at pe.entry_point or $a2
}

import "pe"

rule PseudoSigner02MacromediaFlashProjector60Anorganix : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 90 90 90 90 68 [4] 67 64 FF 36 00 00 67 64 89 26 00 00 F1 90 90 90 90 83 EC 44 56 FF 15 24 81 49 00 8B F0 8A 06 3C 22 75 1C 8A 46 01 46 3C 22 74 0C 84 C0 74 08 8A 46 01 46 3C 22 75 F4 80 3E 22 75 0F 46 EB 0C }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule MSLRHv032afakeWWPack321xemadicius : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 53 55 8B E8 33 DB EB 60 0D 0A 0D 0A 57 57 50 61 63 6B 33 32 20 64 65 63 6F 6D 70 72 65 73 73 69 6F 6E 20 72 6F 75 74 69 6E 65 20 76 65 72 73 69 6F 6E 20 31 2E 31 32 0D 0A 28 63 29 20 31 39 39 38 20 50 69 6F 74 72 20 57 61 72 65 7A 61 6B 20 61 6E 64 20 52 61 66 61 6C 20 57 69 65 72 7A 62 69 63 6B 69 0D 0A 0D 0A 5D 5B 90 EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF }

	condition:
		$a0 at pe.entry_point
}

rule PEArmor07600765hying : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 00 00 00 00 00 00 00 00 [4] 00 00 00 00 00 00 00 00 [8] 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 [12] 00 00 00 00 4B 45 52 4E 45 4C 33 32 2E 64 6C 6C 00 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 47 65 74 4D 6F 64 75 6C 65 48 61 6E 64 6C 65 41 00 00 00 00 00 08 00 00 00 00 00 00 00 60 E8 00 00 00 00 }

	condition:
		$a0
}

import "pe"

rule PECryptv102 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E8 [4] 5B 83 EB 05 EB 04 52 4E 44 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule ILUCRYPTv4015exe : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 8B EC FA C7 46 F7 [2] 42 81 FA [2] 75 F9 FF 66 F7 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule NJoy13NEX : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 83 C4 F0 B8 48 36 40 00 E8 54 EE FF FF 6A 00 68 D8 2B 40 00 6A 0A 6A 00 E8 2C EF FF FF E8 23 E7 FF FF 8D 40 00 }

	condition:
		$a0 at pe.entry_point
}

rule VBOXv43v46 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 8B C5 8B C5 8B C5 8B C5 8B C5 8B C5 8B C5 8B C5 8B C5 8B C5 8B C5 8B C5 8B C5 8B C5 8B C5 8B C5 }
		$a1 = { 90 03 C4 33 C4 33 C5 2B C5 33 C5 8B C5 [2] 2B C5 48 [2] 0B C0 86 E0 8C E0 [2] 8C E0 86 E0 03 C4 40 }

	condition:
		$a0 or $a1
}

import "pe"

rule CodeLockvxx : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 43 4F 44 45 2D 4C 4F 43 4B 2E 4F 43 58 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule CipherWallSelfExtratorDecryptorGUIv15 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 90 61 BE 00 10 42 00 8D BE 00 00 FE FF C7 87 C0 20 02 00 F9 89 C7 6A 57 83 CD FF EB 0E 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 EF 75 09 8B 1E 83 EE FC 11 DB 73 E4 }

	condition:
		$a0 at pe.entry_point
}

rule ARMProtectorv01bySMoKE : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E8 04 00 00 00 83 60 EB 0C 5D EB 05 45 55 EB 04 B8 EB F9 00 C3 E8 00 00 00 00 5D EB 01 00 81 ED 5E 1F 40 00 EB 02 83 09 8D B5 EF 1F 40 00 EB 02 83 09 BA A3 11 00 00 EB 01 00 8D 8D 92 31 40 00 8B 09 E8 14 00 00 00 83 EB 01 00 8B FE E8 00 00 00 00 58 83 C0 }

	condition:
		$a0
}

import "pe"

rule Upackv037betaDwing : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { BE B0 11 [2] AD 50 FF 76 34 EB 7C 48 01 [2] 0B 01 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 18 10 00 00 10 00 00 00 00 [3] 00 00 [2] 00 10 00 00 00 02 00 00 04 00 00 00 00 00 37 00 04 00 00 00 00 00 00 00 00 [3] 00 02 00 00 00 00 00 00 }
		$a1 = { BE B0 11 [2] AD 50 FF 76 34 EB 7C 48 01 [2] 0B 01 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 18 10 00 00 10 00 00 00 00 [3] 00 00 [2] 00 10 00 00 00 02 00 00 04 00 00 00 00 00 37 00 04 00 00 00 00 00 00 00 00 [3] 00 02 00 00 00 00 00 00 ?? 00 00 ?? 00 00 ?? 00 00 [2] 00 00 00 10 00 00 10 00 00 00 00 00 00 0A 00 00 00 00 00 00 00 00 00 00 00 EE [3] 14 00 00 00 00 [6] 00 FF 76 38 AD 50 8B 3E BE F0 [3] 6A 27 59 F3 A5 FF 76 04 83 C8 FF 8B DF AB EB 1C 00 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 [5] 00 00 00 40 AB 40 B1 04 F3 AB C1 E0 0A B5 ?? F3 AB 8B 7E 0C 57 51 E9 [4] E3 B1 04 D3 E0 03 E8 8D 53 18 33 C0 55 40 51 D3 E0 8B EA 91 FF 56 4C 33 D2 59 D1 E8 13 D2 E2 FA 5D 03 EA 45 59 89 6B 08 56 8B F7 2B F5 F3 A4 AC 5E B1 80 AA 3B 7E 34 0F 82 8E FE FF FF 58 5F 59 E3 1B 8A 07 47 04 18 3C 02 73 F7 8B 07 3C ?? 75 F1 B0 00 0F C8 03 46 38 2B C7 AB E2 E5 5E 5D 59 51 59 46 AD 85 C0 74 1F }

	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point
}

import "pe"

rule PrivateExeProtector1xsetisoft : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { B8 [4] B9 ?? 90 01 ?? BE ?? 10 40 ?? 68 50 91 41 ?? 68 01 [3] C3 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule Petitev14 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { B8 [4] 66 9C 60 50 8B D8 03 00 68 [4] 6A 00 }

	condition:
		$a0 at pe.entry_point
}

rule NullsoftInstallSystemv20a0 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 83 EC 0C 53 56 57 FF 15 B4 10 40 00 05 E8 03 00 00 BE E0 E3 41 00 89 44 24 10 B3 20 FF 15 28 10 40 00 68 00 04 00 00 FF 15 14 11 40 00 50 56 FF 15 10 11 40 00 80 3D E0 E3 41 00 22 75 08 80 C3 02 BE E1 E3 41 00 8A 06 8B 3D 14 12 40 00 84 C0 74 19 3A C3 74 }

	condition:
		$a0
}

import "pe"

rule Obsidium1332ObsidiumSoftware : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB 01 ?? E8 2B 00 00 00 EB 02 [2] EB 02 [2] 8B 54 24 0C EB 03 [3] 83 82 B8 00 00 00 24 EB 04 [4] 33 C0 EB 04 [4] C3 EB 02 [2] EB 01 ?? 64 67 FF 36 00 00 EB 03 [3] 64 67 89 26 00 00 EB 01 ?? EB 02 [2] 50 EB 02 [2] 33 C0 EB 02 [2] 8B 00 EB 02 [2] C3 EB 04 [4] E9 FA 00 00 00 EB 03 [3] E8 D5 FF FF FF EB 03 [3] EB 01 ?? 58 EB 01 ?? EB 02 [2] 64 67 8F 06 00 00 EB 02 [2] 83 C4 04 EB 02 [2] E8 3B 27 00 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule modifiedHACKSTOPv111f : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 52 B4 30 CD 21 52 FA ?? FB 3D [2] EB ?? CD 20 0E 1F B4 09 E8 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule VxKuku886 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 06 1E 50 8C C8 8E D8 BA 70 03 B8 24 25 CD 21 [5] 90 B4 2F CD 21 53 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule VxCIHVersion12TTITWIN95CIH : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8D [3] 33 DB 64 87 03 E8 [4] 5B 8D }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule ShegerdDongleV478MSCo : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E8 32 00 00 00 B8 [4] 8B 18 C1 CB 05 89 DA 36 8B 4C 24 0C }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule SDProtectRandyLi : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 6A FF 68 [4] 68 88 88 88 08 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 58 64 A3 00 00 00 00 58 58 58 58 8B E8 E8 3B 00 00 00 E8 01 00 00 00 FF 58 05 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule SmokesCryptv12 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 B8 [4] B8 [4] 8A 14 08 80 F2 ?? 88 14 08 41 83 F9 ?? 75 F1 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PEncryptv31 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E9 [3] 00 F0 0F C6 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PEncryptv30 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E8 00 00 00 00 5D 81 ED 05 10 40 00 8D B5 24 10 40 00 8B FE B9 0F 00 00 00 BB [4] AD 33 C3 E2 FA }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule RJoiner12byVaska250320071658 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 81 EC 0C 02 00 00 8D 85 F4 FD FF FF 56 50 68 04 01 00 00 FF 15 14 10 40 00 90 8D 85 F4 FD FF FF 50 FF 15 10 10 40 00 90 BE 00 20 40 00 90 83 3E FF 0F 84 84 00 00 00 53 57 33 FF 8D 46 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule Minke101byCodius : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 83 C4 F0 53 [5] 10 E8 7A F6 FF FF BE 68 66 00 10 33 C0 55 68 DB 40 00 10 64 FF 30 64 89 20 E8 FA F8 FF FF BA EC 40 00 10 8B C6 E8 F2 FA FF FF 8B D8 B8 6C 66 00 10 8B 16 E8 88 F2 FF FF B8 6C 66 00 10 E8 76 F2 FF FF 8B D0 8B C3 8B 0E E8 E3 E4 FF FF E8 2A F9 FF FF E8 C1 F8 FF FF B8 6C 66 00 10 8B 16 E8 6D FA FF FF E8 14 F9 FF FF E8 AB F8 FF FF 8B 06 E8 B8 E3 FF FF 8B D8 B8 6C 66 00 10 E8 38 F2 FF FF 8B D3 8B 0E E8 A7 E4 FF [4] C4 FB FF FF E8 E7 F8 FF FF 8B C3 E8 B0 E3 FF FF E8 DB F8 FF FF 33 C0 5A 59 59 64 89 10 68 E2 40 00 10 C3 E9 50 EB FF FF EB F8 5E 5B E8 BB EF FF FF 00 00 00 43 41 31 38 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule CrypWrapvxx : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E8 B8 [3] E8 90 02 [2] 83 F8 ?? 75 07 6A ?? E8 [4] FF 15 49 8F 40 ?? A9 [3] 80 74 0E }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule WarningmaybeSimbyOZpolycryptorby3xpl01tver2xx250320072200 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 57 57 8D 7C 24 04 50 B8 00 D0 17 13 AB 58 5F C3 00 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule WARNINGTROJANHuiGeZi : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 81 C4 ?? FE FF FF 53 56 57 33 C0 89 85 ?? FE FF FF }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule MSLRHv032afakeyodascryptor12emadicius : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED F3 1D 40 00 B9 7B 09 00 00 8D BD 3B 1E 40 00 8B F7 AC 90 2C 8A C0 C0 78 90 04 62 EB 01 00 61 EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule EPv10 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 50 83 C0 17 8B F0 97 33 C0 33 C9 B1 24 AC 86 C4 AC AA 86 C4 AA E2 F6 00 B8 40 00 03 00 3C 40 D2 33 8B 66 14 50 70 8B 8D 34 02 44 8B 18 10 48 70 03 BA 0C [4] C0 33 FE 8B 30 AC 30 D0 C1 F0 10 C2 D0 30 F0 30 C2 C1 AA 10 42 42 CA C1 E2 04 5F E9 5E B1 }

	condition:
		$a0 at pe.entry_point
}

rule D1S1Gv11betaD1N : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 00 00 00 00 [4] 00 00 00 00 00 00 01 00 0A 00 00 00 18 00 00 80 00 00 00 00 [4] 00 00 00 00 02 00 00 00 88 00 00 80 38 00 00 80 96 00 00 80 50 00 00 80 00 00 00 00 [4] 00 00 00 00 00 00 01 00 00 00 00 00 68 00 00 00 00 00 00 00 [4] 00 00 00 00 00 00 01 00 00 00 00 00 78 00 00 00 B0 [2] 00 10 00 00 00 00 00 00 00 00 00 00 00 C0 [4] 00 00 00 00 00 00 00 00 00 00 00 06 00 44 00 56 00 43 00 4C 00 41 00 4C 00 0B 00 50 00 41 00 43 00 4B 00 41 00 47 00 45 00 49 00 4E 00 46 00 4F 00 00 00 }

	condition:
		$a0
}

import "pe"

rule PROPACKv208 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 8C D3 8E C3 8C CA 8E DA 8B 0E [2] 8B F1 83 [2] 8B FE D1 ?? FD F3 A5 53 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule BlackEnergyDDoSBotCrypter : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 [2] 81 EC 1C 01 00 00 53 56 57 6A 04 BE 00 30 00 00 56 FF 35 00 20 11 13 6A 00 E8 ?? 03 00 00 [2] 83 C4 10 ?? FF 89 7D F4 0F }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule HACKSTOPv113 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 52 B8 [2] 1E CD 21 86 E0 3D [2] 73 ?? CD 20 0E 1F B4 09 E8 [2] 24 ?? EA }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule FreeJoiner151GlOFF : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 90 87 FF 90 90 B9 2B 00 00 00 BA 07 10 40 00 83 C2 03 90 87 FF 90 90 B9 04 00 00 00 90 87 FF 90 33 C9 C7 05 09 30 40 00 00 00 00 00 68 00 01 00 00 68 21 30 40 00 6A 00 E8 B7 02 00 00 6A 00 68 80 00 00 00 6A 03 6A 00 6A 00 68 00 00 00 80 68 21 30 40 00 E8 8F 02 00 00 A3 19 30 40 00 90 87 FF 90 8B 15 09 30 40 00 81 C2 04 01 00 00 F7 DA 6A 02 6A 00 52 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PeXv099EngbartCrackPl : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E9 F5 00 00 00 0D 0A C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule HACKSTOPv119 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 52 BA [2] 5A EB ?? 9A [4] 30 CD 21 [3] D6 02 [2] CD 20 0E 1F 52 BA [2] 5A EB }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule HACKSTOPv118 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 52 BA [2] 5A EB ?? 9A [4] 30 CD 21 [3] FD 02 [2] CD 20 0E 1F 52 BA [2] 5A EB }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PKLITEv200b : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 50 B8 [2] BA [2] 05 [2] 3B 06 02 00 72 ?? B4 09 BA [2] CD 21 B8 01 4C CD 21 [30] 59 2D [2] 8E D0 51 2D [2] 8E C0 50 B9 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PKLITEv200c : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 50 B8 [2] BA [2] 3B C4 73 ?? 8B C4 2D [2] 25 [2] 8B F8 B9 [2] BE [2] FC }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule MSLRHv032afakeNeolite20emadicius : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E9 A6 00 00 00 B0 7B 40 00 78 60 40 00 7C 60 40 00 00 00 00 00 B0 3F 00 00 12 62 40 00 4E 65 6F 4C 69 74 65 20 45 78 65 63 75 74 61 62 6C 65 20 46 69 6C 65 20 43 6F 6D 70 72 65 73 73 6F 72 0D 0A 43 6F 70 79 72 69 67 68 74 20 28 63 29 20 31 39 39 38 2C 31 39 39 39 20 4E 65 6F 57 6F 72 78 20 49 6E 63 0D 0A 50 6F 72 74 69 6F 6E 73 20 43 6F 70 79 72 69 67 68 74 20 28 63 29 20 31 39 39 37 2D 31 39 39 39 20 4C 65 65 20 48 61 73 69 75 6B 0D 0A 41 6C 6C 20 52 69 67 68 74 73 20 52 65 73 65 72 76 65 64 2E 00 00 00 00 EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B C0 03 E8 02 00 00 00 29 5A 83 C4 04 58 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 2B 04 24 74 04 75 02 EB 02 EB 01 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule WWPACKv300v301Relocationspack : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { BE [2] BA [2] BF [2] B9 [2] 8C CD 8E DD 81 ED [2] 06 06 8B DD 2B DA 8B D3 FC }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PseudoSigner02CodeSafe20Anorganix : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 EB 0B 83 EC 10 53 56 57 E8 C4 01 00 85 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PseudoSigner02ZCode101Anorganix : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E9 12 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 E9 FB FF FF FF C3 68 00 00 00 00 64 FF 35 00 00 00 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule VxCaz1204 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E8 [2] 5E 83 EE 03 1E 06 B8 FF FF CD 2F 3C 10 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule ZealPack10Zeal : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { C7 45 F4 00 00 40 00 C7 45 F0 [4] 8B 45 F4 05 [4] 89 45 F4 C7 45 FC 00 00 00 00 EB 09 8B 4D FC 83 C1 01 89 4D FC 8B 55 FC 3B 55 F0 7D 22 8B 45 F4 03 45 FC 8A 08 88 4D F8 0F BE 55 F8 83 F2 0F 88 55 F8 8B 45 F4 03 45 FC 8A 4D F8 88 08 EB CD FF 65 F4 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule CPAV : Packer PEiD hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E8 [2] 4D 5A B1 01 93 01 00 00 02 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule RLPackFullEdition117iBoxLZMAAp0x : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 [15] 8D B5 67 30 00 00 8D 9D 66 03 00 00 33 FF [10] 6A 40 68 [4] 68 [4] 6A }

	condition:
		$a0 at pe.entry_point
}

rule INCrypter03INinYbyz3e_NiFe : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 64 A1 30 00 00 00 8B 40 0C 8B 40 0C 8D 58 20 C7 03 00 00 00 00 E8 00 00 00 00 5D 81 ED 4D 16 40 00 8B 9D 0E 17 40 00 64 A1 18 00 00 00 8B 40 30 0F B6 40 02 83 F8 01 75 05 03 DB C1 CB 10 8B 8D 12 17 40 00 8B B5 06 17 40 00 51 81 3E 2E 72 73 72 74 65 8B 85 16 17 40 00 E8 23 00 00 00 8B 85 1A 17 40 00 E8 18 00 00 00 8B 85 1E 17 40 00 E8 0D 00 00 00 8B 85 22 17 40 00 E8 02 00 00 00 EB 18 8B D6 3B 46 0C 72 0A 83 F9 01 74 0B 3B 46 34 72 06 BA 00 00 00 00 C3 58 83 FA 00 75 1A 8B 4E 10 8B 7E 0C 03 BD 02 17 40 00 83 F9 00 74 09 F6 17 31 0F 31 1F 47 E2 F7 59 83 C6 28 49 83 F9 00 75 88 8B 85 0A 17 40 00 89 44 24 1C 61 50 C3 }

	condition:
		$a0
}

rule MorphineV27Holy_FatherRatter29A : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 00 00 00 00 00 00 00 00 [8] 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 [8] 00 00 00 00 [8] 00 00 00 00 4B 65 52 6E 45 6C 33 32 2E 64 4C 6C 00 00 47 65 74 50 72 6F 63 41 64 64 72 }

	condition:
		$a0
}

rule nBinderv361 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 6E 35 36 34 35 36 35 33 32 33 34 35 34 33 5F 6E 62 33 5C 00 5C 6E 35 36 34 35 36 35 33 32 33 34 35 34 33 5F 6E 62 33 5C }

	condition:
		$a0
}

import "pe"

rule MatrixDongleTDiGmbH : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 00 00 00 00 00 00 00 00 00 00 00 00 [8] 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 [8] 00 00 00 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 4B 45 52 4E 45 4C 33 32 2E 44 4C 4C 00 E8 B6 00 00 00 00 00 00 00 00 00 [6] E8 00 00 00 00 5B 2B D9 8B F8 8B 4C 24 2C 33 C0 2B CF F2 AA 8B 3C 24 8B 0A 2B CF 89 5C 24 20 80 37 A2 47 49 75 F9 8D 64 24 04 FF 64 24 FC 60 C7 42 08 [4] E8 C5 FF FF FF C3 C2 F7 29 4E 29 5A 29 E6 86 8A 89 63 5C A2 65 E2 A3 A2 }
		$a1 = { E8 00 00 00 00 E8 00 00 00 00 59 5A 2B CA 2B D1 E8 1A FF FF FF }

	condition:
		$a0 or $a1 at pe.entry_point
}

rule NullsoftInstallSystemv20RC2 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 83 EC 10 53 55 56 57 C7 44 24 14 70 92 40 00 33 ED C6 44 24 13 20 FF 15 2C 70 40 00 55 FF 15 84 72 40 00 BE 00 54 43 00 BF 00 04 00 00 56 57 A3 A8 EC 42 00 FF 15 C4 70 40 00 E8 8D FF FF FF 8B 1D 90 70 40 00 85 C0 75 21 68 FB 03 00 00 56 FF 15 5C 71 40 00 }

	condition:
		$a0
}

import "pe"

rule UnoPiX075BaGiE : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 07 00 00 00 61 68 [2] 40 00 C3 83 04 24 18 C3 20 83 B8 ED 20 37 EF C6 B9 79 37 9E 61 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule WWPACKv305c4UnextractablePasswordchecking : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 03 05 80 1B B8 [2] 8C CA 03 D0 8C C9 81 C1 [2] 51 B9 [2] 51 06 06 B1 ?? 51 8C D3 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule FSGv110EngdulekxtBorlandDelphi20 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB 01 56 E8 02 00 00 00 B2 D9 59 68 80 ?? 41 00 E8 02 00 00 00 65 32 59 5E EB 02 CD 20 BB }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule Reg2Exe225byJanVorel : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 68 68 00 00 00 68 00 00 00 00 68 70 7D 40 00 E8 AE 20 00 00 83 C4 0C 68 00 00 00 00 E8 AF 52 00 00 A3 74 7D 40 00 68 00 00 00 00 68 00 10 00 00 68 00 00 00 00 E8 9C 52 00 00 A3 70 7D 40 00 E8 24 50 00 00 E8 E2 48 00 00 E8 44 34 00 00 E8 54 28 00 00 E8 98 27 00 00 E8 93 20 00 00 68 01 00 00 00 68 D0 7D 40 00 68 00 00 00 00 8B 15 D0 7D 40 00 E8 89 8F 00 00 B8 00 00 10 00 68 01 00 00 00 E8 9A 8F 00 00 FF 35 A4 7F 40 00 68 00 01 00 00 E8 3A 23 00 00 8D 0D A8 7D 40 00 5A E8 5E 1F 00 00 FF 35 A8 7D 40 00 68 00 01 00 00 E8 2A 52 00 00 A3 B4 7D 40 00 FF 35 A4 7F 40 00 FF 35 B4 7D 40 00 FF 35 A8 7D 40 00 E8 5C 0C 00 00 8D 0D A0 7D 40 00 5A E8 26 1F 00 00 FF 35 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule Armadillov420SiliconRealmsToolworks : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 6A FF 68 F8 8E 4C 00 68 F0 EA 49 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF 15 88 31 4C 00 33 D2 8A D4 89 15 84 A5 4C 00 8B C8 81 E1 FF 00 00 00 89 0D 80 A5 4C 00 C1 E1 08 03 CA 89 0D 7C A5 4C 00 C1 E8 10 A3 78 A5 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule DalKrypt10byDalKiT : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 68 00 10 40 00 58 68 [3] 00 5F 33 DB EB 0D 8A 14 03 80 EA 07 80 F2 04 88 14 03 43 81 FB [3] 00 72 EB FF E7 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule RCryptorv15Vaska : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 83 2C 24 4F 68 [4] FF 54 24 04 83 44 24 04 4F }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule EXECryptor239compressedresources : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 51 68 [4] 59 81 F1 12 3C CB 98 E9 53 2C 00 00 F7 D7 E9 EB 60 00 00 83 45 F8 02 E9 E3 36 00 00 F6 45 F8 20 0F 84 1E 21 00 00 55 E9 80 62 00 00 87 0C 24 8B E9 [4] 00 00 23 C1 81 E9 [4] 57 E9 ED 00 00 00 0F 88 [4] E9 2C 0D 00 00 81 ED BB 43 CB 79 C1 E0 1C E9 9E 14 00 00 0B 15 [4] 81 E2 2A 70 7F 49 81 C2 9D 83 12 3B E8 0C 50 00 00 E9 A0 16 00 00 59 5B C3 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 E8 41 42 00 00 E9 93 33 00 00 31 DB 89 D8 59 5B C3 A1 [4] 8A 00 2C 99 E9 82 30 00 00 0F 8A [4] B8 01 00 00 00 31 D2 0F A2 25 FF 0F 00 00 E9 72 21 00 00 0F 86 57 0B 00 00 E9 [4] C1 C0 03 E8 F0 36 00 00 E9 41 0A 00 00 81 F7 B3 6E 85 EA 81 C7 [4] 87 3C 24 E9 74 52 00 00 0F 8E [4] E8 5E 37 00 00 68 B1 74 96 13 5A E9 A1 04 00 00 81 D1 49 C0 12 27 E9 50 4E 00 00 C1 C8 1B 1B C3 81 E1 96 36 E5 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule GameGuardv20065xxexesignbyhot_UNP : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 31 FF 74 06 61 E9 4A 4D 50 30 5A BA 7D 00 00 00 80 7C 24 08 01 E9 00 00 00 00 60 BE 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule EnigmaProtectorv112LITE : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 00 00 00 00 5D 83 ED 06 81 ED [3] 00 [31] E8 01 00 00 00 9A 83 C4 04 EB 02 FF 35 60 E8 24 00 00 00 00 00 FF EB 02 CD 20 8B 44 24 0C 83 80 B8 00 00 00 03 31 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule MSLRHv01emadicius : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 E8 0A 00 00 00 E8 EB 0C 00 00 E8 }
		$a1 = { 60 EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 2B 04 24 74 04 75 02 EB 02 EB 01 81 83 C4 04 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 3D FF 0F 00 00 EB 01 68 EB 02 CD 20 EB 01 E8 76 1B EB 01 68 EB 02 CD 20 EB 01 E8 CC 66 B8 FE 00 74 04 75 02 EB 02 EB 01 81 66 E7 64 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 0F 31 50 0F 31 E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 }

	condition:
		$a0 or $a1 at pe.entry_point
}

import "pe"

rule Apex_cbeta500mhz : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 68 [4] B9 FF FF FF 00 01 D0 F7 E2 72 01 48 E2 F7 B9 FF 00 00 00 8B 34 24 80 36 FD 46 E2 FA C3 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

	condition:
		$a0 at pe.entry_point
}

rule VProtector11A12vcasm : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 00 00 56 69 72 74 75 61 6C 41 6C 6C 6F 63 00 00 00 00 00 76 63 61 73 6D 5F 70 72 6F 74 65 63 74 5F 32 30 30 35 5F 33 5F 31 38 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 33 F6 E8 10 00 00 00 8B 64 24 08 64 8F 05 00 00 00 00 58 EB 13 C7 83 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 AD CD 20 EB 01 0F 31 F0 EB 0C 33 C8 EB 03 EB 09 0F 59 74 05 75 F8 51 EB F1 B9 04 00 00 00 E8 1F 00 00 00 EB FA E8 16 00 00 00 E9 EB F8 00 00 58 EB 09 0F 25 E8 F2 FF FF FF 0F B9 49 75 F1 EB 05 EB F9 EB F0 D6 E8 07 00 00 00 C7 83 83 C0 13 EB 0B 58 EB 02 CD 20 83 C0 02 EB 01 E9 50 C3 }

	condition:
		$a0
}

rule codeCrypter031 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 50 58 53 5B 90 BB [2] 40 00 FF E3 90 CC CC CC 55 8B EC 5D C3 CC CC CC CC CC CC CC CC CC CC CC }

	condition:
		$a0
}

import "pe"

rule PKTINYv10withTINYPROGv38 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 2E C6 06 [3] 2E C6 06 [3] 2E C6 06 [3] E9 [2] E8 [2] 83 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule AHTeamEPProtector03fakePESHiELD2xFEUERRADER : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 90 [46] 90 FF E0 60 E8 00 00 00 00 41 4E 41 4B 49 4E 5D 83 ED 06 EB 02 EA 04 }

	condition:
		$a0 at pe.entry_point
}

rule RLPackFullEditionV11Xap0x : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 00 00 00 00 00 00 00 00 00 00 00 00 [8] 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 [24] 00 00 00 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 56 69 72 74 75 61 6C 41 6C 6C 6F 63 00 00 56 69 72 74 75 61 6C 46 72 65 65 00 00 56 69 72 74 75 61 6C 50 72 6F 74 65 63 74 00 00 47 65 74 4D 6F 64 75 6C 65 48 61 6E 64 6C 65 41 00 00 00 10 }

	condition:
		$a0
}

import "pe"

rule Excalibur103forgot : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E9 00 00 00 00 60 E8 14 00 00 00 5D 81 ED 00 00 00 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule RLPack118DllaPlib043ap0x : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 80 7C 24 08 01 0F 85 5C 01 00 00 60 E8 00 00 00 00 8B 2C 24 83 C4 ?? 8D B5 1A 04 00 00 8D 9D C1 02 00 00 33 FF E8 61 01 00 00 EB 0F FF 74 37 04 FF 34 37 FF D3 83 C4 ?? 83 C7 ?? 83 3C 37 00 75 EB 83 BD 06 04 00 00 00 74 0E 83 BD 0A 04 00 00 00 74 05 E8 D7 01 00 00 8D 74 37 04 53 6A ?? 68 [4] 68 [4] 6A ?? FF 95 A7 03 00 00 89 85 16 04 00 00 5B FF B5 16 04 00 00 56 FF D3 83 C4 ?? 8B B5 16 04 00 00 8B C6 EB 01 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PseudoSigner01MicrosoftVisualC50MFCAnorganix : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 6A FF 68 [4] 68 [4] 64 A1 00 00 00 00 50 E9 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule Pohernah101byKas : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED F1 26 40 00 8B BD 18 28 40 00 8B 8D 20 28 40 00 B8 38 28 40 00 01 E8 80 30 05 83 F9 00 74 71 81 7F 1C AB 00 00 00 75 62 8B 57 0C 03 95 1C 28 40 00 31 C0 51 31 C9 66 B9 FA 00 66 83 F9 00 74 49 8B 57 0C 03 95 1C 28 40 00 8B 85 24 28 40 00 83 F8 02 75 06 81 C2 00 02 00 00 51 8B 4F 10 83 F8 02 75 06 81 E9 00 02 00 00 57 BF C8 00 00 00 89 CE E8 27 00 00 00 89 C1 5F B8 38 28 40 00 01 E8 E8 24 00 00 00 59 49 EB B1 59 83 C7 28 49 EB 8A 8B 85 14 28 40 00 89 44 24 1C 61 FF E0 56 57 4F F7 D7 21 FE 89 F0 5F 5E C3 60 83 F0 05 40 90 48 83 F0 05 89 C6 89 D7 60 E8 0B 00 00 00 61 83 C7 08 83 E9 07 E2 F1 61 C3 57 8B 1F 8B 4F 04 68 B9 79 37 9E 5A 42 89 D0 48 C1 E0 05 BF 20 00 00 00 4A 89 DD C1 E5 04 29 E9 8B 6E 08 31 DD 29 E9 89 DD C1 ED 05 31 C5 29 E9 2B 4E 0C 89 CD C1 E5 04 29 EB 8B 2E 31 CD 29 EB 89 CD C1 ED 05 31 C5 29 EB 2B 5E 04 29 D0 4F 75 C8 5F 89 1F 89 4F 04 C3 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule Armadillov25xv26x : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 6A FF 68 [4] 68 [4] 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF 15 58 [3] 33 D2 8A D4 89 15 EC }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PESpinv11Cyberbob : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B FD 82 2C 24 7D DE 46 00 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 00 43 B7 F6 C3 6B B7 00 00 F9 FF E3 C9 C2 08 00 A3 68 72 01 FF 5D 33 C9 41 E2 17 EB 07 EA EB 01 EB EB 0D FF }

	condition:
		$a0 at pe.entry_point
}

rule Escargot01byueMeat : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB 08 28 65 73 63 30 2E 31 29 60 68 2B [3] 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 B8 5C [3] 8B 00 FF D0 50 BE 00 10 [2] B9 00 [2] 00 EB 05 49 80 34 31 40 0B C9 75 F7 58 0B C0 74 08 33 C0 C7 00 DE C0 AD 0B BE [4] E9 AC 00 00 00 8B 46 0C BB 00 00 [2] 03 C3 50 50 B8 54 [3] 8B 00 FF D0 5F 80 3F 00 74 06 C6 07 00 47 EB F5 33 FF 8B 16 0B D2 75 03 8B 56 10 03 D3 03 D7 8B 0A C7 02 00 00 00 00 0B C9 74 4B F7 C1 00 00 00 80 74 14 81 E1 FF FF 00 00 50 51 50 B8 50 }

	condition:
		$a0
}

import "pe"

rule EncryptPE2200461622006630WFS : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 9C 64 FF 35 00 00 00 00 E8 7A 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 [8] 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 [36] 00 00 00 00 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 00 00 47 65 74 53 79 73 74 65 6D 44 69 72 65 63 74 6F 72 79 41 00 00 00 43 72 65 61 74 65 46 69 6C 65 41 00 00 00 43 72 65 61 74 65 46 69 6C 65 4D 61 70 70 69 6E 67 41 00 00 00 4D 61 70 56 69 65 77 4F 66 46 69 6C 65 00 00 00 55 6E 6D 61 70 56 69 65 77 4F 66 46 69 6C 65 00 00 00 43 6C 6F 73 65 48 61 6E 64 6C 65 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 45 78 69 74 50 72 6F 63 65 73 73 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule tElockv060 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E9 00 00 00 00 60 E8 00 00 00 00 58 83 C0 08 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PseudoSigner01BorlandDelphi30Anorganix : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 83 C4 90 90 90 90 68 [4] 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule ActiveMARKTMR5311140Trymedia : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 79 11 7F AB 9A 4A 83 B5 C9 6B 1A 48 F9 27 B4 25 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PEBundlev244 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 9C 60 E8 02 [3] 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB [2] 40 ?? 87 DD 83 BD }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PECompactv120v1201 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB 06 68 [4] C3 9C 60 E8 02 [3] 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 70 40 ?? 87 DD 8B 85 9A 70 40 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule ASPackv104bAlexeySolodovnikov : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 [4] 5D 81 ED [4] B8 [4] 03 C5 2B 85 ?? 12 9D ?? 89 85 1E 9D [2] 80 BD 08 9D }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule MESSv120 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { FA B9 [2] F3 [2] E3 ?? EB ?? EB ?? B6 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule RCryptorv13v14Vaska : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 8B 44 24 04 83 E8 4F 68 [4] FF D0 58 59 50 }
		$a1 = { 55 8B EC 8B 44 24 04 83 E8 4F 68 [4] FF D0 58 59 50 B8 [4] 3D [4] 74 06 80 30 ?? 40 EB F3 }

	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point
}

import "pe"

rule ThinstallV27XJitit : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 9C 60 E8 00 00 00 00 58 BB [4] 2B C3 50 68 [4] 68 [4] 68 [4] E8 [4] E9 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule eXPressor120BetaPEPacker : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 55 8B EC 81 EC [4] 53 56 57 EB ?? 45 78 50 72 2D 76 2E 31 2E 32 2E 2E }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule Packanoid10ackanoid : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { BF 00 ?? 40 00 BE [3] 00 E8 9D 00 00 00 B8 [3] 00 8B 30 8B 78 04 BB [3] 00 8B 43 04 91 E3 1F 51 FF D6 56 96 8B 13 8B 02 91 E3 0D 52 51 56 FF D7 5A 89 02 83 C2 04 EB EE 83 C3 08 5E EB DB B9 [2] 00 00 BE 00 [2] 00 EB 01 00 BF [3] 00 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule EncryptPE1200331812003518WFS : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 9C 64 FF 35 00 00 00 00 E8 79 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 [8] 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 [36] 00 00 00 00 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 00 00 47 65 74 53 79 73 74 65 6D 44 69 72 65 63 74 6F 72 79 41 00 00 00 43 72 65 61 74 65 46 69 6C 65 41 00 00 00 43 72 65 61 74 65 46 69 6C 65 4D 61 70 70 69 6E 67 41 00 00 00 4D 61 70 56 69 65 77 4F 66 46 69 6C 65 00 00 00 55 6E 6D 61 70 56 69 65 77 4F 66 46 69 6C 65 00 00 00 43 6C 6F 73 65 48 61 6E 64 6C 65 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 45 78 69 74 50 72 6F 63 65 73 73 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PECompactv09781 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB 06 68 [4] C3 9C 60 E8 02 [3] 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 49 87 40 ?? 87 DD 8B 85 CE 87 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PECompactv09782 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { EB 06 68 [4] C3 9C 60 E8 02 [3] 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB D1 84 40 ?? 87 DD 8B 85 56 85 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule PseudoSigner01Gleam100Anorganix : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 EB 0B 83 EC 0C 53 56 57 E8 24 02 00 FF E9 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule UPackAltStubDwing : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 60 E8 09 00 00 00 C3 F6 00 00 E9 06 02 00 00 33 C9 5E 87 0E E3 F4 2B F1 8B DE AD 2B D8 AD }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule VxModificationofHi924 : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 50 53 51 52 1E 06 9C B8 21 35 CD 21 53 BB [2] 26 [2] 49 48 5B }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule EXECryptor226DLLminimumprotection : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 50 8B C6 87 04 24 68 [4] 5E E9 [4] 85 C8 E9 [4] 81 C3 [4] 0F 81 [3] 00 81 FA [4] 33 D0 E9 [3] 00 0F 8D [3] 00 81 D5 [4] F7 D1 0B 15 [4] C1 C2 ?? 81 C2 [4] 9D E9 [4] C1 E2 ?? C1 E8 ?? 81 EA [4] 13 DA 81 E9 [4] 87 04 24 8B C8 E9 [4] 55 8B EC 83 C4 F8 89 45 FC 8B 45 FC 89 45 F8 8B 45 08 E9 [4] 8B 45 E0 C6 00 00 FF 45 E4 E9 [4] FF 45 E4 E9 [3] 00 F7 D3 0F 81 [4] E9 [4] 87 34 24 5E 8B 45 F4 E8 [3] 00 8B 45 F4 8B E5 5D C3 E9 }

	condition:
		$a0 at pe.entry_point
}

import "pe"

rule yodasProtector102AshkibizDanehlar : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { E8 03 00 00 00 EB 01 ?? BB 55 00 00 00 E8 03 00 00 00 EB 01 ?? E8 8F 00 00 00 E8 03 00 00 00 EB 01 ?? E8 82 00 00 00 E8 03 00 00 00 EB 01 ?? E8 B8 00 00 00 E8 03 00 00 00 EB 01 ?? E8 AB 00 00 00 E8 03 00 00 00 EB 01 ?? 83 FB 55 E8 03 00 00 00 EB 01 ?? 75 }

	condition:
		$a0 at pe.entry_point
}

rule ACProtectv135riscosoftwareIncAnticrackSoftware : hardened
{
	meta:
		author = "malware-lu"

	strings:
		$a0 = { 4B 45 52 4E 45 4C 33 32 2E 44 4C 4C 00 [20] 55 53 45 52 33 32 2E 44 4C 4C 00 [33] 00 47 65 74 50 72 6F 63 }

	condition:
		$a0
}

import "pe"

rule upx_0_80_to_1_24 : Packer hardened
{
	meta:
		author = "Kevin Falcoz"
		date_create = "25/02/2013"
		description = "UPX 0.80 to 1.24"

	strings:
		$str1 = {6A 60 68 60 02 4B 00 E8 8B 04 00 00 83 65 FC 00 8D 45 90 50 FF 15 8C F1 48 00 C7 45 FC FE FF FF FF BF 94 00 00 00 57}

	condition:
		$str1 at pe.entry_point
}

import "pe"

rule upx_1_00_to_1_07 : Packer hardened
{
	meta:
		author = "Kevin Falcoz"
		date_create = "19/03/2013"
		description = "UPX 1.00 to 1.07"

	strings:
		$str1 = {60 BE 00 ?0 4? 00 8D BE 00 B0 F? FF ?7 8? [3] ?0 9? [0-9] 90 90 90 90 [0-2] 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0}

	condition:
		$str1 at pe.entry_point
}

import "pe"

rule upx_3 : Packer hardened
{
	meta:
		author = "Kevin Falcoz"
		date_create = "25/02/2013"
		description = "UPX 3.X"

	strings:
		$str1 = {60 BE 00 [2] 00 8D BE 00 [2] FF [1-12] EB 1? 90 90 90 90 90 [1-3] 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01}

	condition:
		$str1 at pe.entry_point
}

import "pe"

rule obsidium : Packer hardened
{
	meta:
		author = "Kevin Falcoz"
		date_create = "21/01/2013"
		last_edit = "17/03/2013"
		description = "Obsidium"

	strings:
		$str1 = {EB 02 [2] E8 25 00 00 00 EB 04 [4] EB 01 ?? 8B 54 24 0C EB 01 ?? 83 82 B8 00 00 00 23 EB 01 ?? 33 C0 EB 02 [2] C3 EB 02 [2] EB 04}

	condition:
		$str1 at pe.entry_point
}

import "pe"

rule pecompact2 : Packer hardened
{
	meta:
		author = "Kevin Falcoz"
		date_create = "25/02/2013"
		description = "PECompact"

	strings:
		$str1 = {B8 [3] 00 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 50 45 43}

	condition:
		$str1 at pe.entry_point
}

import "pe"

rule aspack : Packer hardened
{
	meta:
		author = "Kevin Falcoz"
		date_create = "25/02/2013"
		description = "ASPack"

	strings:
		$str1 = {60 E8 00 00 00 00 5D 81 ED 5D 3B 40 00 64 A1 30 00 00 00 0F B6 40 02 0A C0 74 04 33 C0 87 00 B9 [2] 00 00 8D BD B7 3B 40 00 8B F7 AC}

	condition:
		$str1 at pe.entry_point
}

import "pe"

rule execryptor : Protector hardened
{
	meta:
		author = "Kevin Falcoz"
		date_create = "25/02/2013"
		description = "EXECryptor"

	strings:
		$str1 = {E8 24 00 00 00 8B 4C 24 0C C7 01 17 00 01 00 C7 81 B8 00 00 00 00 00 00 00 31 C0 89 41 14 89 41 18 80 A1 C1 00 00 00 FE C3 31 C0 64 FF 30 64 89 20 64 8F 05 00 00 00 00}

	condition:
		$str1 at pe.entry_point
}

rule winrar_sfx : Packer hardened
{
	meta:
		author = "Kevin Falcoz"
		date_create = "18/03/2013"
		description = "Winrar SFX Archive"

	strings:
		$signature1 = {00 00 53 6F 66 74 77 61 72 65 5C 57 69 6E 52 41 52 20 53 46 58 00}

	condition:
		$signature1
}

import "pe"

rule mpress_2_xx_x86 : Packer hardened
{
	meta:
		author = "Kevin Falcoz"
		date_create = "19/03/2013"
		last_edit = "24/03/2013"
		description = "MPRESS v2.XX x86  - no .NET"

	strings:
		$signature1 = {60 E8 00 00 00 00 58 05 [2] 00 00 8B 30 03 F0 2B C0 8B FE 66 AD C1 E0 0C 8B C8 50 AD 2B C8 03 F1 8B C8 57 51 49 8A 44 39 06 88 04 31 75 F6}

	condition:
		$signature1 at pe.entry_point
}

import "pe"

rule mpress_2_xx_x64 : Packer hardened
{
	meta:
		author = "Kevin Falcoz"
		date_create = "19/03/2013"
		last_edit = "24/03/2013"
		description = "MPRESS v2.XX x64  - no .NET"

	strings:
		$signature1 = {57 56 53 51 52 41 50 48 8D 05 DE 0A 00 00 48 8B 30 48 03 F0 48 2B C0 48 8B FE 66 AD C1 E0 0C 48 8B C8 50 AD 2B C8 48 03 F1 8B C8 57 44 8B C1 FF C9 8A 44 39 06 88 04 31}

	condition:
		$signature1 at pe.entry_point
}

rule mpress_2_xx_net : Packer hardened
{
	meta:
		author = "Kevin Falcoz"
		date_create = "24/03/2013"
		description = "MPRESS v2.XX .NET"

	strings:
		$signature1 = {21 46 00 69 00 6C 00 65 00 20 00 69 00 73 00 20 00 69 00 6E 00 76 00 61 00 6C 00 69 00 64 00 2E 00 00 0D 4D 00 50 00 52 00 45 00 53 00 53 00 00 00 00 00 2D 2D 93 6B 35 04 2E 43 85 EF}

	condition:
		$signature1
}

rule rpx_1_xx : Packer hardened
{
	meta:
		author = "Kevin Falcoz"
		date_create = "24/03/2013"
		description = "RPX v1.XX"

	strings:
		$signature1 = {52 50 58 20 31 2e}
		$signature2 = {43 6f 70 79 72 69 67 68 74 20 32 30}

	condition:
		$signature1 and $signature2
}

rule mew_11_xx : Packer hardened
{
	meta:
		author = "Kevin Falcoz"
		date_create = "25/03/2013"
		description = "MEW 11"

	strings:
		$signature1 = {50 72 6F 63 41 64 64 72 65 73 73 00 E9 [6-7] 00 00 00 00 00 00 00 00 00 [7] 00}
		$signature2 = {4d 45 57}

	condition:
		$signature1 and $signature2
}

import "pe"

rule yoda_crypter_1_2 : Crypter hardened
{
	meta:
		author = "Kevin Falcoz"
		date_create = "15/04/2013"
		description = "Yoda Crypter 1.2"

	strings:
		$signature1 = {60 E8 00 00 00 00 5D 81 ED F3 1D 40 00 B9 7B 09 00 00 8D BD 3B 1E 40 00 8B F7 AC [19] EB 01 [27] AA E2 CC}

	condition:
		$signature1 at pe.entry_point
}

import "pe"

rule yoda_crypter_1_3 : Crypter hardened
{
	meta:
		author = "Kevin Falcoz"
		date_create = "15/04/2013"
		description = "Yoda Crypter 1.3"

	strings:
		$signature1 = {55 8B EC 53 56 57 60 E8 00 00 00 00 5D 81 ED 6C 28 40 00 B9 5D 34 40 00 81 E9 C6 28 40 00 8B D5 81 C2 C6 28 40 00 8D 3A 8B F7 33 C0 EB 04 90 EB 01 C2 AC}

	condition:
		$signature1 at pe.entry_point
}

rule dotfuscator : packer hardened
{
	meta:
		author = "Jean-Philippe Teissier / @Jipe_"
		description = "Dotfuscator"
		date = "2013-02-01"
		filetype = "memory"
		version = "1.0"

	strings:
		$a = {4f 62 66 75 73 63 61 74 65 64 20 77 69 74 68 20 44 6f 74 66 75 73 63 61 74 6f 72}

	condition:
		$a
}

rule AutoIt_2 : packer hardened
{
	meta:
		author = "Jean-Philippe Teissier / @Jipe_"
		description = "AutoIT packer"
		date = "2013-02-01"
		filetype = "memory"
		version = "1.0"

	strings:
		$a = {54 68 69 73 20 69 73 20 61 20 63 6f 6d 70 69 6c 65 64 20 41 75 74 6f 49 74 20 73 63 72 69 70 74 2e 20 41 56 20 72 65 73 65 61 72 63 68 65 72 73 20 70 6c 65 61 73 65 20 65 6d 61 69 6c 20 61 76 73 75 70 70 6f 72 74 40 61 75 74 6f 69 74 73 63 72 69 70 74 2e 63 6f 6d 20 66 6f 72 20 73 75 70 70 6f 72 74 2e}

	condition:
		$a
}

rule mumblehard_packer : hardened
{
	meta:
		description = "Mumblehard i386 assembly code responsible for decrypting Perl code"
		author = "Marc-Etienne M.Leveille"
		date = "2015-04-07"
		reference = "http://www.welivesecurity.com"
		version = "1"

	strings:
		$decrypt = { 31 db [1-10] ba ?? 00 00 00 [0-6] (56 5f | 89 F7) 39 d3 75 13 81 fa ?? 00 00 00 75 02 31 d2 81 c2 ?? 00 00 00 31 db 43 ac 30 d8 aa 43 e2 e2 }

	condition:
		$decrypt
}

