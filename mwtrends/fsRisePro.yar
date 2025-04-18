rule RisePro : hardened
{
	meta:
		author = "kevoreilly"
		cape_options = "bp0=$c2+15,action0=string:edx,bp1=$c2+41,action1=string:ecx,count=1"
		hash = "1b69a1dd5961241b926605f0a015fa17149c3b2759fb077a30a22d4ddcc273f6"
		ruleset = "RisePro.yar"
		repository = "kevoreilly/CAPEv2"
		source_url = "https://github.com/kevoreilly/CAPEv2/blob/3c6d7d4f232e43db68ca2dd711f5e9d8e9e033cb/analyzer/windows/data/yara/RisePro.yar"
		license = "Other"
		score = 75

	strings:
		$decode1 = {8A 06 46 84 C0 75 F9 2B F1 B8 FF FF FF 7F 8B 4D ?? 8B 51 ?? 2B C2 3B C6 72 38 83 79 ?? 10 72 02 8B 09 52 51 56 53 51 FF 75 ?? 8B CF E8}
		$decode2 = {8B D9 81 FF FF FF FF 7F 0F [2] 00 00 00 C7 43 ?? 0F 00 00 00 83 FF 10 73 1A 57 FF 75 ?? 89 7B ?? 53 E8 [4] 83 C4 0C C6 04 1F 00 5F 5B 5D C2 08 00}
		$c2 = {FF 75 30 83 3D [4] 10 BA [4] B9 [4] 0F 43 15 [4] 83 3D [4] 10 0F 43 0D [4] E8 [4] A3}

	condition:
		uint16( 0 ) == 0x5A4D and any of them
}

rule win_risepro_auto : hardened
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.risepro."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.risepro"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		ruleset = "win.risepro_auto.yar"
		repository = "malpedia/signator-rules"
		source_url = "https://github.com/malpedia/signator-rules/blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.risepro_auto.yar"
		score = 75

	strings:
		$sequence_0 = { 0fb645ff 50 8b4de8 e8???????? 8b4dec 83c901 894dec }
		$sequence_1 = { e8???????? 8945c8 8d4d0c e8???????? 8945cc 8d45d7 50 }
		$sequence_2 = { 8bec 83ec0c 8955f8 894dfc 8b4dfc e8???????? 8bc8 }
		$sequence_3 = { 894214 8b4df8 e8???????? 8945d4 837de010 }
		$sequence_4 = { 8bcc 8965bc 8d552c 52 e8???????? 8945b8 c645fc04 }
		$sequence_5 = { 33c0 8885eafeffff 33c9 888de9feffff }
		$sequence_6 = { 6800000080 680000cf00 68???????? 68???????? 6800020000 ff15???????? 89859cfeffff }
		$sequence_7 = { 6886e4fa74 6829895415 e8???????? 8b4dfc 894108 89510c }
		$sequence_8 = { 33c5 8945ec 56 50 8d45f4 64a300000000 894da8 }
		$sequence_9 = { 85ff 780f 3b3d???????? 7307 }

	condition:
		7 of them and filesize < 280576
}

rule risepro : hardened
{
	meta:
		author = "c3rb3ru5d3d53c"
		description = "Detects RisePro"
		hash = "2cd2f077ca597ad0ef234a357ea71558d5e039da9df9958d0b8bd0efa92e74c9"
		created = "2023-06-18"
		os = "windows"
		tlp = "white"
		rev = 1
		ruleset = "risepro.yara-4.0.2.yara"
		repository = "c3rb3ru5d3d53c/signatures"
		source_url = "https://github.com/c3rb3ru5d3d53c/signatures/blob/edc52b6519f00b6ed1a7fdd3b1040e87df7dbad7/signatures/malware/risepro/risepro.yara-4.0.2.yara"
		license = "The Unlicense"
		score = 75

	strings:
		$trait_0 = {
            8b ff 55 8b ec 83 ec 28 8d 4d ?? 56 57 6a 00 e8
            d6 f5 ff ff 8d 45 ?? 50 ff 75 ?? e8 b7 f9 ff ff
            59 59 8d 4d ?? 8b f0 8b fa e8 04 f6 ff ff 8b d7
            8b c6 5f 5e c9 c3}
		$trait_2 = {
            8b c7 83 ff 40 99 89 46 ?? 6a 3f 58 0f 4d f8 89
            56 ?? 8b 55 ?? 33 c0 33 c9 0f ab f8 83 ff 20 0f
            43 c8 33 c1 83 ff 40 0f 43 c8 09 44 1a ?? 09 4c
            1a ?? 66 83 4e ?? ?? 5f 8b c6 5e 5b c9 c3}
		$trait_4 = {
            8b 45 ?? 0f b7 c0 8d 04 48 0f b6 4c 1f ?? 89 45
            ?? 8b 45 ?? 0f b7 c0 83 c0 fc 66 c1 e1 08 89 45
            ?? 0f b6 44 1f ?? 66 0b c8 0f b6 44 1f ?? 66 03
            45 ?? 0f b7 c9 0f b7 d0 66 85 c9 74 69}
		$trait_5 = {
            8b 43 ?? 56 0f b7 73 ?? 2b d6 0f b7 48 ?? 8b c2
            33 d2 83 e9 04 f7 f1 0f b7 43 ?? 03 d6 3b d0 6a
            04 0f 47 d6 59 03 d1 5e 2b 7d ?? 03 d7 3b d1 5f
            0f 42 d1 66 8b c2 5b c9 c3}
		$trait_6 = {
            8a 4d ?? 8a 45 ?? 8a 55 ?? 8b 7d ?? c0 e9 04 80
            e1 03 c0 e0 02 02 c8 8a 45 ?? 88 4d ?? 8a ca c0
            e9 02 80 e1 0f c0 e0 04 c0 e2 06 02 c8 02 55 ??
            4b 88 4d ?? 88 55 ?? 85 db 7e 24}
		$trait_7 = {
            89 75 ?? ff 75 ?? e8 9b 0d 00 00 59 89 75 ?? ff
            75 ?? ff 75 ?? e8 c1 00 00 00 59 59 8b f0 89 75
            ?? c7 45 ?? ?? ?? ?? ?? e8 15 00 00 00 8b c6 8b
            4d ?? 64 89 0d 00 00 00 00 59 5f 5e 5b c9 c3}
		$trait_8 = {
            b6 45 f8 88 4d ?? c1 e9 08 03 c8 0f b6 45 ?? 88
            4d ?? c1 e9 08 03 c8 0f b6 45 ?? 88 4d ?? c1 e9
            08 03 c8 88 4d ?? c1 e9 08 00 4d ?? 83 c6 c0 8b
            c6 83 d7 ff 83 c3 40 85 ff 77 88}
		$trait_9 = {
            56 b2 2e 8b f1 e8 13 00 00 00 85 c0 74 03 40 eb
            02 8b c6 b2 2f 8b c8 5e e9 00 00 00 00 53 8a da
            eb 0d 3a c3 74 13 51 ff 15 ?? ?? ?? ?? 8b c8 8a
            01 84 c0 75 ed 33 c0 5b c3}
		$trait_10 = {
            56 8b f1 8b 4e ?? e8 3a 01 00 00 8b 4e ?? 8a d0
            85 c9 74 06 5e e9 24 00 00 00 b8 00 10 00 00 66
            85 46 ?? 74 0c 8b 46 ?? 8b 00 8b 48 ?? 8b 09 eb
            e3 6a 62 59 84 d2 0f b6 c2 5e 0f 44 c1 c3}
		$trait_11 = {
            56 8b f1 85 d2 74 34 53 8a 5a ?? f6 c3 04 75 2a
            83 7e ?? ?? 74 08 8b 02 f6 40 ?? ?? 74 1c 8b 4a
            ?? 80 cb 04 88 5a ?? 85 c9 78 0f 8b 42 ?? 6b d1
            28 03 50 ?? 80 6a ?? ?? 74 ce 5b 5e c3}
		$trait_12 = {
            56 8b f1 0f b7 46 ?? a9 60 24 00 00 74 2e a9 00
            20 00 00 74 0f 8b 16 e8 3a 00 00 00 8b ce 5e e9
            b0 ff ff ff a9 00 04 00 00 74 13 8b 4e ?? 85 c9
            74 0c ff 76 ?? ff d1 83 66 ?? ?? 59 5e c3}
		$trait_13 = {
            56 8b 71 ?? 57 6a 05 58 c7 06 40 42 0f 00 8b 51
            ?? eb 04 89 04 96 4a 3b d0 7d f8 33 ff 47 eb 09
            6a 0b 58 2b c2 89 04 96 4a 3b d7 7d f3 80 79 ??
            ?? 74 06 8b 41 ?? 89 3c 86 5f 5e c3}
		$trait_14 = {
            55 8b ec 8b 41 ?? 56 85 c0 74 14 ff 75 ?? ff 75
            ?? ff 75 ?? 52 ff 71 ?? ff d0 83 c4 14 eb 1d 8b
            45 ?? 33 f6 3b 75 ?? 75 10 ff 75 ?? 50 52 ff 71
            ?? ff 51 ?? 83 c4 10 eb 03 83 c8 ff 5e 5d c3}
		$trait_15 = {
            55 8b ec 83 ec 58 53 56 57 8b 7d ?? 33 db 89 4d
            ?? 33 f6 0f 57 c0 89 55 ?? 8b 0f 89 4d ?? 8a 41
            ?? 88 45 ?? 8b 01 89 45 ?? 33 c0 21 45 ?? 66 89
            45 ?? 8a 02 66 0f 13 45 ?? 3c 80 73 07}
		$trait_16 = {
            55 8b ec 83 ec 24 56 8d 75 ?? eb 1e 85 d2 74 1e
            8b 41 ?? 3b 42 ?? 73 0a 89 4e ?? 8b f1 8b 49 ??
            eb 08 89 56 ?? 8b f2 8b 52 ?? 85 c9 75 de 85 c9
            0f 44 ca 89 4e ?? 8b 45 ?? 5e c9 c3}
		$trait_17 = {
            8d 45 ?? 50 8d 45 ?? 50 8d 45 ?? 50 e8 b7 0a ff
            ff 8d 45 ?? 50 8d 45 ?? 50 e8 8a 14 ff ff 83 c4
            14 be 09 00 00 00 ?? ?? 8d 45 ?? 50 50 e8 76 14
            ff ff 83 c4 08 83 ee 01 75 ee}
		$trait_18 = {
            55 8b ec 83 e4 f8 51 56 8b f1 83 7e ?? ?? 75 23
            80 7e ?? ?? 72 1d a1 ?? ?? ?? ?? 85 c0 74 02 ff
            d0 8b ce e8 f8 df ff ff a1 ?? ?? ?? ?? 85 c0 74
            02 ff d0 8b ce e8 18 00 00 00 5e 8b e5 5d c3}
		$trait_19 = {
            55 8b ec 53 8b 5d ?? 56 57 8b 7d ?? 8d 47 ?? 50
            57 53 e8 b9 fd fe ff 8d 77 ?? 56 8d 47 ?? 50 8d
            43 ?? 50 e8 a8 fd fe ff 8d 47 ?? 50 8d 43 ?? 56
            50 e8 9a fd fe ff 83 c4 24 5f 5e 5b 5d c3}
		$trait_20 = {
            55 8b ec 51 56 8b 71 ?? 57 8b fa eb 22 3b 75 ??
            74 1a 85 ff 74 05 39 7e ?? 75 11 80 7e ?? ?? 75
            0b 8b ce e8 12 00 00 00 85 c0 75 09 8b 76 ?? 85
            f6 75 da 33 c0 5f 5e 59 5d c3}
		$trait_21 = {
            55 8b ec 51 56 57 8b fa 8b f1 eb 28 8b 4e ?? e8
            92 01 00 00 85 c0 75 19 3b 7e ?? 73 14 ff 75 ??
            8b d7 8b ce e8 14 00 00 00 59 85 c0 74 03 89 46
            ?? 8b 76 ?? 85 f6 75 d4 5f 5e 59 5d c3}
		$trait_22 = {
            55 8b ec 51 56 57 6a 01 8d 45 ?? 8b f1 50 8b fa
            57 ff 76 ?? ff 56 ?? 83 c4 10 83 f8 01 75 0d 8b
            45 ?? 0f b6 4d ?? 89 08 33 c0 eb 0d 57 ff 76 ??
            ff 56 ?? f7 d8 59 59 1b c0 5f 5e c9 c3}
		$trait_23 = {
            55 8b ec 51 51 53 56 8b 75 ?? 57 8b 46 ?? 8b 4e
            ?? 83 c0 fb 3b c1 0f 46 c8 8b 06 89 4d ?? 33 ff
            8b 40 ?? 89 45 ?? 8b 86 ?? ?? ?? ?? 8b 16 83 c0
            2a c1 f8 03 8b 5a ?? 3b d8 0f 82 04 01 00 00}
		$trait_24 = {
            53 8b dc 83 ec 08 83 e4 f0 83 c4 04 55 8b 6b ??
            89 6c 24 ?? 8b ec 83 ec 28 a1 ?? ?? ?? ?? 33 c5
            89 45 ?? 8b 4b ?? 8b 53 ?? 56 33 f6 89 55 ?? 57
            8b 7b ?? 81 f9 e0 00 00 00 0f 82 15 01 00 00}
		$trait_25 = {
            8d 45 ?? 50 8d 45 ?? 50 8d 45 ?? 50 e8 1d 0a ff
            ff 8d 45 ?? 50 8d 45 ?? 50 e8 f0 13 ff ff 83 c4
            14 be 31 00 00 00 8d 45 ?? 50 50 e8 de 13 ff ff
            83 c4 08 83 ee 01 75 ee}
		$trait_26 = {
            13 c0 03 d1 8b 4d ?? 83 d0 00 23 5d ?? 0b 5d ??
            c1 e3 08 c1 e9 12 0b d9 8b 4d ?? 03 d8 8b 45 ??
            51 03 59 ?? 89 38 89 70 ?? 89 50 ?? 89 58 ?? e8
            82 f8 ff ff 83 c4 08 5f 5e 5b 8b e5 5d c3}
		$trait_27 = {
            0f b6 47 ?? 0f b6 0f 83 c7 02 c1 e0 08 03 c8 8b
            c2 83 e2 3f 25 c0 03 00 00 83 c2 40 81 e1 ff 03
            00 00 03 d0 c1 e2 0a 03 d1 8b 4d ?? 8d 46 ?? 89
            45 ?? 81 fa 80 00 00 00 73 06}
		$trait_28 = {
            0f b6 0f 0f b6 47 ?? 83 c7 02 c1 e1 08 03 c8 8b
            c2 83 e2 3f 25 c0 03 00 00 83 c2 40 81 e1 ff 03
            00 00 03 d0 c1 e2 0a 03 d1 8b 4d ?? 8d 46 ?? 89
            45 ?? 81 fa 80 00 00 00 73 06}

	condition:
		uint16( 0 ) == 0x5a4d and uint32( uint32( 0x3c ) ) == 0x00004550 and 7 of them
}

rule RisePro_1 : hardened limited
{
	meta:
		author = "ditekShen"
		description = "Detects RisePro infostealer"
		cape_type = "RisePro Payload"
		original_yara_name = "RisePro"
		ruleset = "RisePro.yar"
		repository = "CAPESandbox/community"
		source_url = "https://github.com/CAPESandbox/community/blob/ed71b5eb9179e25174c1a2d0fe451e25cbf97dd1/data/yara/CAPE/RisePro.yar"
		score = 75

	strings:
		$x1 = {((74 2e 6d 65 2f 72 69 73 65 70 72 6f 73 75 70 70 6f 72 74) | (74 00 2e 00 6d 00 65 00 2f 00 72 00 69 00 73 00 65 00 70 00 72 00 6f 00 73 00 75 00 70 00 70 00 6f 00 72 00 74 00))}
		$s1 = {(bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff) 66 00 61 00 69 00 6c 00 65 00 64 00 20 00 72 00 65 00 61 00 64 00 70 00 61 00 63 00 6b 00 65 00 74 00 (bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff)}
		$s2 = {(bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff) 66 00 61 00 69 00 65 00 6c 00 64 00 20 00 73 00 65 00 6e 00 64 00 70 00 61 00 63 00 6b 00 65 00 74 00 (bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff)}
		$s3 = {(bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff) 50 00 65 00 72 00 73 00 69 00 73 00 74 00 57 00 61 00 6c 00 (bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff)}
		$s4 = /CRED_ENUMERATE_(ALL|SESSION)_CREDENTIALS/ fullword ascii
		$s5 = {(bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff) 4d 00 6f 00 7a 00 69 00 6c 00 6c 00 61 00 2f 00 35 00 2e 00 30 00 20 00 28 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 4e 00 54 00 20 00 31 00 30 00 2e 00 30 00 3b 00 20 00 57 00 69 00 6e 00 36 00 34 00 3b 00 20 00 78 00 36 00 34 00 29 00 20 00 41 00 70 00 70 00 6c 00 65 00 57 00 65 00 62 00 4b 00 69 00 74 00 2f 00 35 00 33 00 37 00 2e 00 33 00 36 00 20 00 28 00 4b 00 48 00 54 00 4d 00 4c 00 2c 00 20 00 6c 00 69 00 6b 00 65 00 20 00 47 00 65 00 63 00 6b 00 6f 00 29 00 20 00 43 00 68 00 72 00 6f 00 6d 00 65 00 2f 00 31 00 31 00 35 00 2e 00 30 00 2e 00 30 00 2e 00 30 00 20 00 53 00 61 00 66 00 61 00 72 00 69 00 2f 00 35 00 33 00 37 00 2e 00 33 00 36 00 (bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff)}
		$s6 = { 4c 00 6f 00 67 00 69 00 6e 00 20 00 44 00 61 00
                74 00 61 [10] 57 00 65 00 62 00 20 00 44 00 61 00
                74 00 61 [2] 48 00 69 00 73 00 74 00 6f 00 72 00
                79 [21] 43 00 6f 00 6f 00 6b 00 69 00 65 00 73 }
		$s7 = { 61 00 70 00 70 00 6c 00 69 00 63 00 61 00 74 00
                69 00 6f 00 6e 00 2f 00 78 00 2d 00 77 00 77 00
                77 00 2d 00 66 00 6f 00 72 00 6d 00 2d 00 75 00
                72 00 6c 00 65 00 6e 00 63 00 6f 00 64 00 65 00
                64 00 3b 00 20 00 63 00 68 00 61 00 72 00 73 00
                65 00 74 00 3d 00 75 00 74 00 66 00 2d 00 38 00
                42 61 00 70 00 70 00 6c 00 69 00 63 00 61 00 74
                00 69 00 6f 00 6e 00 2f 00 6a 00 73 00 6f 00 6e
                00 2c 00 20 00 74 00 65 00 78 00 74 00 2f 00 70
                00 6c 00 61 00 69 00 6e 00 2c 00 20 00 2a 00 2f
                00 2a }
		$s8 = /_(SET|GET)_(GRABBER|LOADER)/ wide
		$s9 = /catch (save )?(windows cred|screen|pluginscrypto|historyCC|autofill|cookies|passwords|passwords sql|autofills sql|dwnlhistory sql|discordToken|quantum|isDropped)/ fullword wide

	condition:
		uint16( 0 ) == 0x5a4d and ( 1 of ( $x* ) or 6 of ( $s* ) )
}

rule win_risepro_auto_1 : hardened
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-03-28"
		version = "1"
		description = "Detects win.risepro."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.risepro"
		malpedia_rule_date = "20230328"
		malpedia_hash = "9d2d75cef573c1c2d861f5197df8f563b05a305d"
		malpedia_version = "20230407"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		original_yara_name = "win_risepro_auto"
		ruleset = "win.risepro_auto.yar"
		repository = "linuxwellness/secure_linux"
		source_url = "https://github.com/linuxwellness/secure_linux/blob/5dc90d8ad2493a08aebf2441c8b8ae8ae49a22e8/yara_rules/win.risepro_auto.yar"
		score = 75

	strings:
		$sequence_0 = { 6a22 e8???????? 8bf0 83c410 85f6 7415 ff750c }
		$sequence_1 = { e8???????? 837dec08 721f 8b4dec 83c101 51 }
		$sequence_2 = { 8bd0 8b4dec e8???????? a3???????? 33c9 884dd7 }
		$sequence_3 = { 8b4dc4 c7410c08bf4100 c745fcffffffff 8b45c4 8b4df4 64890d00000000 59 }
		$sequence_4 = { e8???????? 8bd0 8b4d08 e8???????? ebdb 8b4df4 64890d00000000 }
		$sequence_5 = { 8b54017c 8995a8feffff 8b85f0feffff 8b8df4feffff 034824 }
		$sequence_6 = { 85c0 745f 8bfe 83e63f c1ff06 6bde38 8b04bd00ef4100 }
		$sequence_7 = { e8???????? 8b08 894dc4 8b55c8 52 8b45c4 50 }
		$sequence_8 = { 50 8b4dfc e8???????? 6b4d0818 8b55fc 030a 8b45fc }
		$sequence_9 = { 51 0fb655d0 52 0fb645cf 50 }

	condition:
		7 of them and filesize < 280576
}

rule RisePro_2 : hardened
{
	meta:
		author = "ANY.RUN"
		description = "Detects RisePro (stealer version)"
		date = "2023-11-27"
		reference = "https://any.run/cybersecurity-blog/risepro-malware-communication-analysis/"
		original_yara_name = "RisePro"
		ruleset = "RisePro.yar"
		repository = "anyrun/YARA"
		source_url = "https://github.com/anyrun/YARA/blob/9b9ff743b22b99c96c80d57462fc416576eaa6de/RisePro.yar"
		score = 75

	strings:
		$ = { 74 2e 6d 65 2f 52 69 73 65 50 72 6f 53 55 50 50 4f 52 54 }

	condition:
		any of them
}

rule RisePro_stealer : hardened
{
	meta:
		version = "1.0"
		malware = "RisePro"
		description = "RisePro Stealer detection base on deobfuscation routine repetition"
		source = "SEKOIA.IO"
		classification = "TLP:GREEN"
		ruleset = "994256c7d4affb121a5c4b28414789de95e141fd.yar"
		repository = "LeakIX/yara-repo-otx"
		source_url = "https://github.com/LeakIX/yara-repo-otx/blob/211ad0b9355b0b1aafc850494449a2603f012a07/994256c7d4affb121a5c4b28414789de95e141fd.yar"
		score = 75

	strings:
		$pxor = {66 0f ef 85}
		$mov_dword_ptr1 = {c7 85}
		$mov_dword_ptr2 = {c7 45}

	condition:
		uint16be( 0 ) == 0x4d5a and #mov_dword_ptr1 > 5000 and #mov_dword_ptr2 > 800 and #pxor > 1000
}

rule win_risepro_auto_2 : hardened
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.risepro."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.risepro"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"
		original_yara_name = "win_risepro_auto"
		ruleset = "d7bc489ee5282e48f381c69e3a1263fe171ced3f.yar"
		repository = "kid0604/yara-rules"
		source_url = "https://github.com/kid0604/yara-rules/blob/c081883d8387ba2a898b84bdbefd40fa910a2b31/executable_windows/d7bc489ee5282e48f381c69e3a1263fe171ced3f.yar"
		score = 75

	strings:
		$sequence_0 = { 8d55f8 8b4df0 e8???????? 8b45ec }
		$sequence_1 = { 740c e8???????? f6d8 1ac0 fec0 c3 32c0 }
		$sequence_2 = { c745fc00000000 8b4de8 e8???????? 0fb6c0 85c0 751b c645f300 }
		$sequence_3 = { 53 56 57 8b7d18 85ff 7e14 57 }
		$sequence_4 = { 8806 46 8b7df8 83c702 }
		$sequence_5 = { 68???????? 6a22 e8???????? 8bf0 83c410 85f6 7415 }
		$sequence_6 = { 8a07 8806 46 8a1f 47 0fbec3 50 }
		$sequence_7 = { eb03 8a45ff 84c0 eb10 807dfe00 741b 807dfd00 }
		$sequence_8 = { e8???????? 8b4dfc 894108 89510c 686d7237ec 687e79cd0e }
		$sequence_9 = { e8???????? 50 8d4dd4 e8???????? 8d5320 }

	condition:
		7 of them and filesize < 280576
}

rule fsRisePro : hardened
{
	meta:
		description = "FsYARA - Malware Trends"
		vetted_family = "risepro"
		score = 75

	condition:
		RisePro or win_risepro_auto or risepro or RisePro_1 or win_risepro_auto_1 or RisePro_2 or RisePro_stealer or win_risepro_auto_2
}

