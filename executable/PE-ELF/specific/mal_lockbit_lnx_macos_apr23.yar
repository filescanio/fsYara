rule MAL_RANSOM_LNX_macOS_LockBit_Apr23_1 : hardened
{
	meta:
		description = "Detects LockBit ransomware samples for Linux and macOS"
		author = "Florian Roth"
		reference = "https://twitter.com/malwrhunterteam/status/1647384505550876675?s=20"
		date = "2023-04-15"
		hash1 = "0a2bffa0a30ec609d80591eef1d0994d8b37ab1f6a6bad7260d9d435067fb48e"
		hash2 = "9ebcbaf3c9e2bbce6b2331238ab584f95f7ced326ca4aba2ddcc8aa8ee964f66"
		hash3 = "a405d034c01a357a89c9988ffe8a46a165915df18fd297469b2bcaaf97578442"
		hash4 = "c9cac06c9093e9026c169adc3650b018d29c8b209e3ec511bbe34cbe1638a0d8"
		hash5 = "dc3d08480f5e18062a0643f9c4319e5c3f55a2e7e93cd8eddd5e0c02634df7cf"
		hash6 = "e77124c2e9b691dbe41d83672d3636411aaebc0aff9a300111a90017420ff096"
		hash7 = "0be6f1e927f973df35dad6fc661048236d46879ad59f824233d757ec6e722bde"
		hash8 = "3e4bbd21756ae30c24ff7d6942656be024139f8180b7bddd4e5c62a9dfbd8c79"
		score = 85
		id = "c01cb907-7d30-5487-b908-51f69ddb914c"

	strings:
		$x1 = {72 65 73 74 6f 72 65 2d 6d 79 2d 66 69 6c 65 73 2e 74 78 74}
		$s1 = {6e 74 75 73 65 72 2e 64 61 74 2e 6c 6f 67}
		$s2 = {62 6f 6f 74 73 65 63 74 2e 62 61 6b}
		$s3 = {61 75 74 6f 72 75 6e 2e 69 6e 66}
		$s4 = {6c 6f 63 6b 62 69 74}
		$xc1 = { 33 38 36 00 63 6D 64 00 61 6E 69 00 61 64 76 00 6D 73 69 00 6D 73 70 00 63 6F 6D 00 6E 6C 73 }
		$xc2 = { 6E 74 6C 64 72 00 6E 74 75 73 65 72 2E 64 61 74 2E 6C 6F 67 00 62 6F 6F 74 73 65 63 74 2E 62 61 6B }
		$xc3 = { 76 6D 2E 73 74 61 74 73 2E 76 6D 2E 76 5F 66 72 65 65 5F 63 6F 75 6E 74 00 61 2B 00 2F 2A }
		$op1 = { 84 e5 f0 00 f0 e7 10 40 2d e9 2e 10 a0 e3 00 40 a0 e1 ?? fe ff }
		$op2 = { 00 90 a0 e3 40 20 58 e2 3f 80 08 e2 3f 30 c2 e3 09 20 98 e1 08 20 9d }
		$op3 = { 2d e9 01 70 43 e2 07 00 13 e1 01 60 a0 e1 08 d0 4d e2 02 40 }

	condition:
		( uint32be( 0 ) == 0x7f454c46 or uint16( 0 ) == 0xfeca or uint16( 0 ) == 0xfacf or uint32( 0 ) == 0xbebafeca ) and ( 1 of ( $x* ) or 3 of them ) or 2 of ( $x* ) or 5 of them
}

rule MAL_RANSOM_LockBit_Apr23_1 : hardened limited
{
	meta:
		description = "Detects indicators found in LockBit ransomware"
		author = "Florian Roth"
		reference = "https://objective-see.org/blog/blog_0x75.html"
		date = "2023-04-17"
		score = 75
		id = "75dc8b95-16f0-5170-a7d6-fc10bb778348"

	strings:
		$xe1 = {2d 69 20 27 2f 70 61 74 68 2f 74 6f 2f 63 72 79 70 74 27}
		$xe2 = {68 74 74 70 3a 2f 2f 6c 6f 63 6b 62 69 74}
		$s1 = {69 64 65 6c 61 79 69 6e 6d 69 6e}
		$s2 = {62 56 4d 44 4b 6d 6f 64 65}
		$s3 = {62 53 65 6c 66 52 65 6d 6f 76 65}
		$s4 = {69 53 70 6f 74 4d 61 78 69 6d 75 6d}
		$fp1 = {3c 68 74 6d 6c}

	condition:
		(1 of ( $x* ) or 4 of them ) and not 1 of ( $fp* )
}

rule MAL_RANSOM_LockBit_Locker_LOG_Apr23_1 : hardened
{
	meta:
		description = "Detects indicators found in LockBit ransomware log files"
		author = "Florian Roth"
		reference = "https://objective-see.org/blog/blog_0x75.html"
		date = "2023-04-17"
		score = 75
		id = "aa0a2393-e5a2-5151-8afb-91a9bb922179"

	strings:
		$s1 = {20 69 73 20 65 6e 63 72 79 70 74 65 64 2e 20 43 68 65 63 6b 73 75 6d 20 61 66 74 65 72 20 65 6e 63 72 79 70 74 69 6f 6e 20}
		$s2 = {7e 7e 7e 7e 7e 48 61 72 64 77 61 72 65 7e 7e 7e 7e}
		$s3 = {5b 2b 5d 20 41 64 64 20 64 69 72 65 63 74 6f 72 79 20 74 6f 20 65 6e 63 72 79 70 74 3a}
		$s4 = {5d 5b 2b 5d 20 4c 61 75 6e 63 68 20 70 61 72 61 6d 65 74 65 72 73 3a 20}

	condition:
		2 of them
}

rule MAL_RANSOM_LockBit_ForensicArtifacts_Apr23_1 : hardened
{
	meta:
		description = "Detects forensic artifacts found in LockBit intrusions"
		author = "Florian Roth"
		reference = "https://objective-see.org/blog/blog_0x75.html"
		date = "2023-04-17"
		score = 75
		id = "e716030c-ee78-51dc-919c-cf59e93da976"

	strings:
		$x1 = {2f 74 6d 70 2f 6c 6f 63 6b 65 72 2e 6c 6f 67}
		$x2 = {45 78 65 63 75 74 61 62 6c 65 3d 4c 6f 63 6b 42 69 74 2f 6c 6f 63 6b 65 72 5f}
		$xc1 = { 54 6F 72 20 42 72 6F 77 73 65 72 20 4C 69 6E 6B 73 3A 0D 0A 68 74 74 70 3A 2F 2F 6C 6F 63 6B 62 69 74 }

	condition:
		1 of ( $x* )
}

