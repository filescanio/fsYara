rule MAL_QBot_HTML_Smuggling_Indicators_Oct22_1 : refined hardened
{
	meta:
		description = "Detects double encoded PKZIP headers"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://twitter.com/ankit_anubhav/status/1578257383133876225?s=20&t=Bu3CCJCzImpTGOQX_KGsdA"
		date = "2022-10-07"
		score = 70
		hash1 = "4f384bcba31fda53e504d0a6c85cee0ce3ea9586226633d063f34c53ddeaca3f"
		hash2 = "8e61c2b751682becb4c0337f5a79b2da0f5f19c128b162ec8058104b894cae9b"
		hash3 = "c5d23d991ce3fbcf73b177bc6136d26a501ded318ccf409ca16f7c664727755a"
		hash4 = "5072d91ee0d162c28452123a4d9986f3df6b3244e48bf87444ce88add29dd8ed"
		hash5 = "ff4e21f788c36aabe6ba870cf3b10e258c2ba6f28a2d359a25d5a684c92a0cad"
		id = "8034d6af-4dae-5ff6-b635-efb5175fe4d1"

	strings:
		$sd1 = {56 55 56 7a 52 45 4a 43 55 55 46 42 55 55 46 4a 51}
		$sd2 = {56 46 63 30 52 43 51 6c 46 42 51 56 46 42 53 55}
		$sd3 = {56 52 58 4e 45 51 6b 4a 52 51 55 46 52 51 55 6c 42}
		$sdr1 = {51 4a 46 55 55 42 46 55 55 43 4a 45 52 7a 56 55 56}
		$sdr2 = {55 53 42 46 56 51 42 46 6c 51 43 52 30 63 46 56}
		$sdr3 = {42 6c 55 51 52 46 55 51 52 4a 6b 51 45 4e 58 52 56}
		$st1 = {56 6c 56 57 65 6c 4a 46 53 6b 4e 56 56 55 5a 43 56 56 56 47 53 6c}
		$st2 = {5a 56 56 6e 70 53 52 55 70 44 56 56 56 47 51 6c 56 56 52 6b 70 52}
		$st3 = {57 56 56 5a 36 55 6b 56 4b 51 31 56 56 52 6b 4a 56 56 55 5a 4b 55}
		$st4 = {56 6b 5a 6a 4d 46 4a 44 55 57 78 47 51 6c 46 57 52 6b 4a 54 56}
		$st5 = {5a 47 59 7a 42 53 51 31 46 73 52 6b 4a 52 56 6b 5a 43 55 31}
		$st6 = {57 52 6d 4d 77 55 6b 4e 52 62 45 5a 43 55 56 5a 47 51 6c 4e 56}
		$st7 = {56 6c 4a 59 54 6b 56 52 61 30 70 53 55 56 56 47 55 6c 46 56 62 45}
		$st8 = {5a 53 57 45 35 46 55 57 74 4b 55 6c 46 56 52 6c 4a 52 56 57 78 43}
		$st9 = {57 55 6c 68 4f 52 56 46 72 53 6c 4a 52 56 55 5a 53 55 56 56 73 51}
		$str1 = {55 55 70 47 56 56 56 43 52 6c 56 56 51 30 70 46 55 6e 70 57 56 56}
		$str2 = {46 4b 52 6c 56 56 51 6b 5a 56 56 55 4e 4b 52 56 4a 36 56 6c 56 57}
		$str3 = {52 53 6b 5a 56 56 55 4a 47 56 56 56 44 53 6b 56 53 65 6c 5a 56 56}
		$str4 = {56 56 4e 43 52 6c 5a 52 51 6b 5a 73 55 55 4e 53 4d 47 4e 47 56}
		$str5 = {56 54 51 6b 5a 57 55 55 4a 47 62 46 46 44 55 6a 42 6a 52 6c}
		$str6 = {56 55 30 4a 47 56 6c 46 43 52 6d 78 52 51 31 49 77 59 30 5a 57}
		$str7 = {51 6d 78 56 55 56 4a 47 56 56 46 53 53 6d 74 52 52 55 35 59 55 6c}
		$str8 = {4a 73 56 56 46 53 52 6c 56 52 55 6b 70 72 55 55 56 4f 57 46 4a 57}
		$str9 = {43 62 46 56 52 55 6b 5a 56 55 56 4a 4b 61 31 46 46 54 6c 68 53 56}
		$htm = {3c 68 74 6d 6c}
		$eml = {43 6f 6e 74 65 6e 74 2d 54 72 61 6e 73 66 65 72 2d 45 6e 63 6f 64 69 6e 67 3a}

	condition:
		filesize < 10MB and ( ( 1 of ( $sd* ) and $htm and not $eml ) or ( 1 of ( $st* ) and $eml ) )
}

