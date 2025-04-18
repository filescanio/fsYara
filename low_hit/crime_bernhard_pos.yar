rule BernhardPOS : hardened
{
	meta:
		author = "Nick Hoffman / Jeremy Humble"
		last_update = "2015-07-14"
		source = "Morphick Inc."
		description = "BernhardPOS Credit Card dumping tool"
		reference = "http://morphick.com/blog/2015/7/14/bernhardpos-new-pos-malware-discovered-by-morphick"
		md5 = "e49820ef02ba5308ff84e4c8c12e7c3d"
		score = 70
		id = "9b9e1507-cf1b-5653-beaa-458205e367c3"

	strings:
		$shellcode_kernel32_with_junk_code = { 33 c0 83 ?? ?? 83 ?? ?? 64 a1 30 00 00 00 83 ?? ?? 83 ?? ?? 8b 40 0c 83 ?? ?? 83 ?? ?? 8b 40 14 83 ?? ?? 83 ?? ?? 8b 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 8b 00 83 ?? ?? 83 ?? ?? 8b 40 10 83 ?? ?? }
		$mutex_name = {4f 50 53 45 43 5f 42 45 52 4e 48 41 52 44}
		$build_path = {43 3a 5c 62 65 72 6e 68 61 72 64 5c 44 65 62 75 67 5c 62 65 72 6e 68 61 72 64 2e 70 64 62}
		$string_decode_routine = { 55 8b ec 83 ec 50 53 56 57 a1 ?? ?? ?? ?? 89 45 f8 66 8b 0d ?? ?? ?? ?? 66 89 4d fc 8a 15 ?? ?? ?? ?? 88 55 fe 8d 45 f8 50 ff ?? ?? ?? ?? ?? 89 45 f0 c7 45 f4 00 00 00 00 ?? ?? 8b 45 f4 83 c0 01 89 45 f4 8b 45 08 50 ff ?? ?? ?? ?? ?? 39 45 f4 ?? ?? 8b 45 08 03 45 f4 0f be 08 8b 45 f4 99 f7 7d f0 0f be 54 15 f8 33 ca 8b 45 08 03 45 f4 88 08 ?? ?? 5f 5e 5b 8b e5 5d }

	condition:
		any of them
}

