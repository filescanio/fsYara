rule MAL_Prolock_Malware : hardened limited
{
	meta:
		description = "Detects Prolock malware in encrypted and decrypted mode"
		author = "Frank Boldewin (@r3c0nst)"
		reference = "https://raw.githubusercontent.com/fboldewin/YARA-rules/master/Prolock.Malware.yar"
		date = "2020-05-17"
		hash1 = "a6ded68af5a6e5cc8c1adee029347ec72da3b10a439d98f79f4b15801abd7af0"
		hash2 = "dfbd62a3d1b239601e17a5533e5cef53036647901f3fb72be76d92063e279178"
		id = "269bf0c5-8315-5405-8e44-e2cc5507a36a"

	strings:
		$DecryptionRoutine = {01 C2 31 DB B8 ?? ?? ?? ?? 31 04 1A 81 3C 1A}
		$DecryptedString1 = {73 75 70 70 6f 72 74 39 38 31 37 32 33 37 32 31 40 70 72 6f 74 6f 6e 6d 61 69 6c 2e 63 6f 6d}
		$DecryptedString2 = {59 6f 75 72 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 20 62 79 20 50 72 6f 4c 6f 63 6b 20 52 61 6e 73 6f 6d 77 61 72 65}
		$DecryptedString3 = {6d 73 61 6f 79 72 61 79 6f 68 6e 70 33 32 74 63 67 77 63 61 6e 68 6a 6f 75 65 74 62 35 6b 35 34 61 65 6b 67 6e 77 67 37 64 63 76 74 67 74 65 63 70 75 6d 72 78 70 71 64 2e 6f 6e 69 6f 6e}
		$CryptoCode = {B8 63 51 E1 B7 31 D2 8D BE ?? ?? ?? ?? B9 63 51 E1 B7 81 C1 B9 79 37 9E}

	condition:
		(( uint16( 0 ) == 0x5A4D ) or ( uint16( 0 ) == 0x4D42 ) ) and filesize < 100KB and ( ( $DecryptionRoutine ) or ( 1 of ( $DecryptedString* ) and $CryptoCode ) )
}

