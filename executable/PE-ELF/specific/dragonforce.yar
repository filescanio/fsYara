rule DragonForce : hardened limited
{
	meta:
		author = "Idan Malihi"
		created = "08/03/2025"
		description = "Yara Rule for DragonForce Ransomware"
		md5 = "05f13a9c902297debecb4c94c6674c"
		score = 75
		tag = "dragonforce"

	strings:
		$mz = { 4D 5A }
		$ChaCha20 = {((65 78 70 61 6e 64 20 33 32 2d 62 79 74 65 20 6b) | (65 00 78 00 70 00 61 00 6e 00 64 00 20 00 33 00 32 00 2d 00 62 00 79 00 74 00 65 00 20 00 6b 00))}
		$Renaming = {((52 65 6e 61 6d 69 6e 67) | (52 00 65 00 6e 00 61 00 6d 00 69 00 6e 00 67 00))}
		$newName = {((4e 65 77 20 6e 61 6d 65 3a) | (4e 00 65 00 77 00 20 00 6e 00 61 00 6d 00 65 00 3a 00))}
		$processIsElevated = {((50 72 6f 63 65 73 73 20 69 73 20 65 6c 65 76 61 74 65 64 3a) | (50 00 72 00 6f 00 63 00 65 00 73 00 73 00 20 00 69 00 73 00 20 00 65 00 6c 00 65 00 76 00 61 00 74 00 65 00 64 00 3a 00))}
		$shadowCopyWmi = {((53 45 4c 45 43 54 20 2a 20 46 52 4f 4d 20 57 69 6e 33 32 5f 53 68 61 64 6f 77 43 6f 70 79) | (53 00 45 00 4c 00 45 00 43 00 54 00 20 00 2a 00 20 00 46 00 52 00 4f 00 4d 00 20 00 57 00 69 00 6e 00 33 00 32 00 5f 00 53 00 68 00 61 00 64 00 6f 00 77 00 43 00 6f 00 70 00 79 00))}
		$ransomFile = {((72 65 61 64 6d 65 2e 74 78 74) | (72 00 65 00 61 00 64 00 6d 00 65 00 2e 00 74 00 78 00 74 00))}
		$decompressProcess = {((41 37 44 65 63 6f 6d 70 72 65 73 73 20 61 73 73 65 74 3a) | (41 00 37 00 44 00 65 00 63 00 6f 00 6d 00 70 00 72 00 65 00 73 00 73 00 20 00 61 00 73 00 73 00 65 00 74 00 3a 00))}

	condition:
		$mz at 0 and 4 of ( $ChaCha20 , $Renaming , $newName , $processIsElevated , $shadowCopyWmi , $ransomFile , $decompressProcess )
}

