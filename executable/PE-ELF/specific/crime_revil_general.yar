import "pe"

rule APT_MAL_REvil_Kaseya_Jul21_1 : hardened limited
{
	meta:
		description = "Detects malware used in the Kaseya supply chain attack"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://doublepulsar.com/kaseya-supply-chain-attack-delivers-mass-ransomware-event-to-us-companies-76e4ec6ec64b"
		date = "2021-07-02"
		hash1 = "1fe9b489c25bb23b04d9996e8107671edee69bd6f6def2fe7ece38a0fb35f98e"
		hash2 = "aae6e388e774180bc3eb96dad5d5bfefd63d0eb7124d68b6991701936801f1c7"
		hash3 = "dc6b0e8c1e9c113f0364e1c8370060dee3fcbe25b667ddeca7623a95cd21411f"
		hash4 = "df2d6ef0450660aaae62c429610b964949812df2da1c57646fc29aa51c3f031e"
		id = "7356f4ea-183f-52ec-a167-fc16b8bfb55a"

	strings:
		$s1 = {(bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff) 4d 00 70 00 73 00 76 00 63 00 2e 00 64 00 6c 00 6c 00 (bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff)}
		$s2 = {(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff) 3a 30 3a 34 3a 38 3a 3c 3a 40 3a 44 3a 48 3a 4c 3a 50 3a 54 3a 58 3a 5c 3a 60 3a 64 3a 68 3a 6c 3a 70 3a 74 3a 78 3a 48 3c 4c 3c 50 3c 5c 3c 60 3c (bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)}
		$op1 = { 40 87 01 c3 6a 08 68 f8 0e 41 00 e8 ae db ff ff be 80 25 41 00 39 35 ?? 32 41 00 }
		$op2 = { 8b 40 04 2b c2 c1 f8 02 3b c8 0f 84 56 ff ff ff 68 15 50 40 00 2b c1 6a 04 }
		$op3 = { 74 73 db e2 e8 ad 07 00 00 68 60 1a 40 00 e8 8f 04 00 00 e8 3a 05 00 00 50 e8 25 26 00 00 }
		$op4 = { 75 05 8b 45 fc eb 4c c7 45 f8 00 00 00 00 6a 00 8d 45 f0 50 8b 4d 0c }
		$op5 = { 83 7d 0c 00 75 05 8b 45 fc eb 76 6a 00 68 80 00 00 00 6a 01 6a 00 }

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 3000KB and ( pe.imphash ( ) == "c36dcd2277c4a707a1a645d0f727542a" or 2 of them )
}

rule APT_MAL_REvil_Kaseya_Jul21_2 : hardened
{
	meta:
		description = "Detects malware used in the Kaseya supply chain attack"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://doublepulsar.com/kaseya-supply-chain-attack-delivers-mass-ransomware-event-to-us-companies-76e4ec6ec64b"
		score = 70
		date = "2021-07-02"
		hash1 = "0496ca57e387b10dfdac809de8a4e039f68e8d66535d5d19ec76d39f7d0a4402"
		hash2 = "8dd620d9aeb35960bb766458c8890ede987c33d239cf730f93fe49d90ae759dd"
		hash3 = "cc0cdc6a3d843e22c98170713abf1d6ae06e8b5e34ed06ac3159adafe85e3bd6"
		hash4 = "d5ce6f36a06b0dc8ce8e7e2c9a53e66094c2adfc93cfac61dd09efe9ac45a75f"
		hash5 = "d8353cfc5e696d3ae402c7c70565c1e7f31e49bcf74a6e12e5ab044f306b4b20"
		hash6 = "e2a24ab94f865caeacdf2c3ad015f31f23008ac6db8312c2cbfb32e4a5466ea2"
		id = "38b168d4-e761-544e-9859-eb155bbfe54a"

	strings:
		$opa1 = { 8b 4d fc 83 c1 01 89 4d fc 81 7d f0 ff 00 00 00 77 1? ba 01 00 00 00 6b c2 00 8b 4d 08 }
		$opa2 = { 89 45 f0 8b 4d fc 83 c1 01 89 4d fc 81 7d f0 ff 00 00 00 77 1? ba 01 00 00 00 6b c2 00 }
		$opa3 = { 83 c1 01 89 4d fc 81 7d f0 ff 00 00 00 77 1? ba 01 00 00 00 6b c2 00 8b 4d 08 0f b6 14 01 }
		$opa4 = { 89 45 f4 8b 0d ?? ?0 07 10 89 4d f8 8b 15 ?? ?1 07 10 89 55 fc ff 75 fc ff 75 f8 ff 55 f4 }
		$opb1 = { 18 00 10 bd 18 00 10 bd 18 00 10 0e 19 00 10 cc cc cc }
		$opb2 = { 18 00 10 0e 19 00 10 cc cc cc cc 8b 44 24 04 }
		$opb3 = { 10 c4 18 00 10 bd 18 00 10 bd 18 00 10 0e 19 00 10 cc cc }

	condition:
		uint16( 0 ) == 0x5a4d and filesize < 3000KB and ( 2 of ( $opa* ) or 3 of them )
}

