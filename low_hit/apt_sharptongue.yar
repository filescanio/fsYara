rule APT_SharpTongue_JS_SharpExt_Chrome_Extension : SharpTongue hardened
{
	meta:
		author = "threatintel@volexity.com"
		date = "2021-09-14"
		description = "A malicious Chrome browser extention used by the SharpTongue threat actor to steal mail data from a victim"
		reference = "https://www.volexity.com/blog/2022/07/28/sharptongue-deploys-clever-mail-stealing-browser-extension-sharpext/"
		hash1 = "1c9664513fe226beb53268b58b11dacc35b80a12c50c22b76382304badf4eb00"
		hash2 = "6025c66c2eaae30c0349731beb8a95f8a5ba1180c5481e9a49d474f4e1bb76a4"
		hash3 = "6594b75939bcdab4253172f0fa9066c8aee2fa4911bd5a03421aeb7edcd9c90c"
		memory_suitable = 1
		score = 85
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		id = "61b5176a-ff73-5fce-bc70-c9e09bb5afed"

	strings:
		$s1 = {22 6d 6f 64 65 3d 61 74 74 61 63 68 26 6e 61 6d 65 3d 22}
		$s2 = {22 6d 6f 64 65 3d 6e 65 77 26 6d 69 64 3d 22}
		$s3 = {22 6d 6f 64 65 3d 61 74 74 6c 69 73 74 22}
		$s4 = {22 6d 6f 64 65 3d 6c 69 73 74 22}
		$s5 = {22 6d 6f 64 65 3d 64 6f 6d 61 69 6e 22}
		$s6 = {22 6d 6f 64 65 3d 62 6c 61 63 6b 22}
		$s7 = {22 6d 6f 64 65 3d 6e 65 77 44 26 64 3d 22}
		$mark1 = {63 68 72 6f 6d 65 2e 72 75 6e 74 69 6d 65 2e 6f 6e 4d 65 73 73 61 67 65 2e 61 64 64 4c 69 73 74 65 6e 65 72}
		$mark2 = {63 68 72 6f 6d 65 2e 77 65 62 4e 61 76 69 67 61 74 69 6f 6e 2e 6f 6e 43 6f 6d 70 6c 65 74 65 64 2e 61 64 64 4c 69 73 74 65 6e 65 72}
		$enc1 = {66 75 6e 63 74 69 6f 6e 20 42 53 75 65 28 73 74 72 69 6e 67 29 7b}
		$enc2 = {66 75 6e 63 74 69 6f 6e 20 42 53 45 28 69 6e 70 75 74 29 7b}
		$enc3 = {66 75 6e 63 74 69 6f 6e 20 62 69 6e 32 68 65 78 28 62 79 74 65 41 72 72 61 79 29}
		$xhr1 = {2e 73 65 6e 64 28 22 6d 6f 64 65 3d 63 64 31}
		$xhr2 = {2e 73 65 6e 64 28 22 6d 6f 64 65 3d 62 6c 61 63 6b}
		$xhr3 = {2e 73 65 6e 64 28 22 6d 6f 64 65 3d 64 6f 6d 61 69 6e}
		$xhr4 = {2e 73 65 6e 64 28 22 6d 6f 64 65 3d 6c 69 73 74}
		$manifest1 = {22 64 65 73 63 72 69 70 74 69 6f 6e 22 3a 22 61 64 76 61 6e 63 65 64 20 66 6f 6e 74 22 2c}
		$manifest2 = {22 73 63 72 69 70 74 73 22 3a 5b 22 62 67 2e 6a 73 22 5d}
		$manifest3 = {22 64 65 76 74 6f 6f 6c 73 5f 70 61 67 65 22 3a 22 64 65 76 2e 68 74 6d 6c 22}

	condition:
		(5 of ( $s* ) and all of ( $mark* ) ) or all of ( $enc* ) or 3 of ( $xhr* ) or 2 of ( $manifest* )
}

