rule RoyalRoad_code_pattern1 : hardened
{
	meta:
		description = "Detects RoyalRoad weaponized RTF documents"
		reference = "https://jsac.jpcert.or.jp/archive/2020/pdf/JSAC2020_8_koike-nakajima_jp.pdf"
		date = "2020/01/15"
		author = "nao_sec"
		score = 80
		id = "db2fb24c-df99-5622-ac3d-d31c34481984"

	strings:
		$S1 = {34 38 39 30 35 64 30 30 36 63 39 63 35 62 30 30 30 30 30 30 30 30 30 30 30 33 30 31 30 31 30 33 30 61 30 61 30 31 30 38 35 61 35 61 62 38 34 34 65 62 37 31 31 32 62 61 37 38 35 36 33 34 31 32 33 31}
		$RTF = {7b 5c 72 74}

	condition:
		$RTF at 0 and $S1
}

rule RoyalRoad_code_pattern2 : hardened
{
	meta:
		description = "Detects RoyalRoad weaponized RTF documents"
		reference = "https://jsac.jpcert.or.jp/archive/2020/pdf/JSAC2020_8_koike-nakajima_jp.pdf"
		date = "2020/01/15"
		author = "nao_sec"
		score = 80
		id = "135024ae-9ecf-5691-95ca-96002e500fd5"

	strings:
		$S1 = {36 35 33 30 33 37 33 39 36 31 33 32 33 35 33 32 33 34 36 36 36 31 33 36 33 33 36 31 33 35 33 35 36 36 36 32 36 33 36 36 36 35}
		$RTF = {7b 5c 72 74}

	condition:
		$RTF at 0 and $S1
}

rule RoyalRoad_code_pattern3 : hardened
{
	meta:
		description = "Detects RoyalRoad weaponized RTF documents"
		reference = "https://jsac.jpcert.or.jp/archive/2020/pdf/JSAC2020_8_koike-nakajima_jp.pdf"
		date = "2020/01/15"
		author = "nao_sec"
		score = 80
		id = "7bce2fe6-a921-51ec-8b5f-5d7f55ab3864"

	strings:
		$S1 = {34 37 34 36 34 32 34 31 35 31 35 31 35 31 35 31 35 30 35 30 35 30 35 30 30 30 30 30 30 30 30 30 30 30 35 38 34 32 34 32 65 62 30 36 34 32 34 32 34 32 33 35 33 35 33 33 33 36 32 30 34 34 36 30 36 30 36 30 36 30 36 30 36 30 36 30 36 30 36 30 36 31 36 31 36 31 36 31 36 31 36 31 36 31 36 31 36 31 36 31 36 31 36 31 36 31 36 31 36 31 36 31}
		$RTF = {7b 5c 72 74}

	condition:
		$RTF at 0 and $S1
}

rule RoyalRoad_code_pattern4ab : hardened
{
	meta:
		description = "Detects RoyalRoad weaponized RTF documents"
		reference = "https://jsac.jpcert.or.jp/archive/2020/pdf/JSAC2020_8_koike-nakajima_jp.pdf"
		date = "2020/01/15"
		author = "nao_sec"
		score = 80
		id = "b4926888-b576-59f7-932a-03b9326845da"

	strings:
		$S1 = {34 37 34 36 34 32 34 31 35 31 35 31 35 31 35 31 35 30 35 30 35 30 35 30 30 30 30 30 30 30 30 30 30 30 35 38 34 32 34 32 45 42 30 36 34 32 34 32 34 32 33 35 33 35 33 33 33 36 32 30 34 34 36 30 36 30 36 30 36 30 36 30 36 30 36 30 36 30 36 30 36 31 36 31 36 31 36 31 36 31 36 31 36 7d 31 36 31 36 31 36 31 36 31 36 31 36 31 36 31 36 31 36 31}
		$RTF = {7b 5c 72 74}

	condition:
		$RTF at 0 and $S1
}

rule RoyalRoad_code_pattern4ce : hardened
{
	meta:
		description = "Detects RoyalRoad weaponized RTF documents"
		reference = "https://jsac.jpcert.or.jp/archive/2020/pdf/JSAC2020_8_koike-nakajima_jp.pdf"
		date = "2020/01/15"
		author = "nao_sec"
		score = 80
		id = "c6e8a072-23cd-5f6a-9b4f-57d3e4500d13"

	strings:
		$S1 = {35 38 34 32 34 32 65 62 30 36 34 32 34 32 34 32 33 35 33 35 33 33 33 36 32 30 34 34 36 30 36 30 36 30 36 30 36 30 36 30 36 30 36 30 36 30 36 31 36 31 36 31 36 31 36 31 36 31 36 31 36 31 36 31 36 31 36 31 36 31 36 7d 31 36 31 36 31 36 31}
		$RTF = {7b 5c 72 74}

	condition:
		$RTF at 0 and $S1
}

rule RoyalRoad_code_pattern4d : hardened
{
	meta:
		description = "Detects RoyalRoad weaponized RTF documents"
		reference = "https://jsac.jpcert.or.jp/archive/2020/pdf/JSAC2020_8_koike-nakajima_jp.pdf"
		date = "2020/01/15"
		author = "nao_sec"
		score = 80
		id = "1677dfb4-7611-5bef-87d1-4cec6285791f"

	strings:
		$S1 = {35 38 34 32 34 32 65 62 30 36 34 32 34 32 34 32 33 35 33 35 33 33 33 36 32 30 34 34 36 30 36 30 36 30 36 30 36 30 36 30 36 30 36 30 36 30 36 31 36 31 36 31 36 31 36 31 36 31 36 31 36 31 36 31 36 31 36 7d 31 36 31 36 31 36 31 36 31 36 31}
		$RTF = {7b 5c 72 74}

	condition:
		$RTF at 0 and $S1
}

rule RoyalRoad_RTF : hardened
{
	meta:
		description = "Detects RoyalRoad weaponized RTF documents"
		reference = "https://jsac.jpcert.or.jp/archive/2020/pdf/JSAC2020_8_koike-nakajima_jp.pdf"
		date = "2020/01/15"
		author = "nao_sec"
		score = 80
		id = "366ec9c3-e6ad-5198-88d5-15aa84a8358f"

	strings:
		$S1 = {6f 62 6a 77 32 31 38 30 5c 6f 62 6a 68 33 30 30}
		$RTF = {7b 5c 72 74}

	condition:
		$RTF at 0 and $S1
}

rule RoyalRoad_RTF_v7 : hardened
{
	meta:
		description = "Detects RoyalRoad weaponized RTF documents"
		reference = "https://jsac.jpcert.or.jp/archive/2020/pdf/JSAC2020_8_koike-nakajima_jp.pdf"
		date = "2020/01/15"
		author = "nao_sec"
		score = 60
		id = "9d2af980-a851-533a-b25d-ee52277e319c"

	strings:
		$v7_1 = {7b 5c 6f 62 6a 65 63 74 5c 6f 62 6a 6f 63 78 7b 5c 6f 62 6a 64 61 74 61}
		$v7_2 = {6f 64 73 30 30 30 30}
		$RTF = {7b 5c 72 74}

	condition:
		$RTF at 0 and all of ( $v7* )
}

rule RoyalRoad_encode_in_RTF : hardened
{
	meta:
		description = "Detects RoyalRoad weaponized RTF documents"
		reference = "https://jsac.jpcert.or.jp/archive/2020/pdf/JSAC2020_8_koike-nakajima_jp.pdf"
		date = "2020/01/15"
		author = "nao_sec"
		score = 60
		id = "66614152-8f9b-5e62-b6bd-ba0286e66d4d"

	strings:
		$enc_hex_1 = {42 30 37 34 37 37 34 36}
		$enc_hex_2 = {42 32 41 36 36 44 46 46}
		$enc_hex_3 = {46 32 41 33 32 30 37 32}
		$enc_hex_4 = {42 32 41 34 36 45 46 46}
		$enc_hex_1l = {62 30 37 34 37 37 34 36}
		$enc_hex_2l = {62 32 61 36 36 44 66 66}
		$enc_hex_3l = {66 32 61 33 32 30 37 32}
		$enc_hex_4l = {62 32 61 34 36 65 66 66}
		$RTF = {7b 5c 72 74}

	condition:
		$RTF at 0 and 1 of ( $enc_hex* )
}

