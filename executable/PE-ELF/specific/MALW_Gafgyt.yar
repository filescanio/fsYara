rule Gafgyt_Botnet_generic : MALW hardened
{
	meta:
		description = "Gafgyt Trojan"
		author = "Joan Soriano / @joanbtl"
		date = "2017-05-01"
		score = 60
		version = "1.0"
		MD5 = "e3fac853203c3f1692af0101eaad87f1"
		SHA1 = "710781e62d49419a3a73624f4a914b2ad1684c6a"

	strings:
		$etcTZ = {2f 62 69 6e 2f 62 75 73 79 62 6f 78 3b 65 63 68 6f 20 2d 65 20 27 67 61 79 66 67 74 27}
		$s2 = {2f 70 72 6f 63 2f 6e 65 74 2f 72 6f 75 74 65}
		$s3 = {61 64 6d 69 6e}
		$s4 = {72 6f 6f 74}

	condition:
		$etcTZ and $s2 and $s3 and $s4
}

rule Gafgyt_Botnet_oh : MALW hardened
{
	meta:
		description = "Gafgyt Trojan"
		author = "Joan Soriano / @joanbtl"
		date = "2017-05-025"
		version = "1.0"
		MD5 = "97f5edac312de349495cb4afd119d2a5"
		SHA1 = "916a51f2139f11e8be6247418dca6c41591f4557"

	strings:
		$s1 = {62 75 73 79 62 6f 78 74 65 72 72 6f 72 69 73 74}
		$s2 = {42 4f 47 4f 4d 49 50 53}
		$s3 = {31 32 34 2e 31 30 35 2e 39 37 2e 25 64}
		$s4 = {66 75 63 6b 6e 65 74}

	condition:
		$s1 and $s2 and $s3 and $s4
}

rule Gafgyt_Botnet_bash : MALW hardened
{
	meta:
		description = "Gafgyt Trojan"
		author = "Joan Soriano / @joanbtl"
		date = "2017-05-25"
		version = "1.0"
		MD5 = "c8d58acfe524a09d4df7ffbe4a43c429"
		SHA1 = "b41fefa8470f3b3657594af18d2ea4f6ac4d567f"

	strings:
		$s1 = {50 4f 4e 47 21}
		$s2 = {47 45 54 4c 4f 43 41 4c 49 50}
		$s3 = {48 54 54 50 46 4c 4f 4f 44}
		$s4 = {4c 55 43 4b 59 4c 49 4c 44 55 44 45}

	condition:
		$s1 and $s2 and $s3 and $s4
}

rule Gafgyt_Botnet_hoho : MALW hardened
{
	meta:
		description = "Gafgyt Trojan"
		author = "Joan Soriano / @joanbtl"
		date = "2017-05-25"
		version = "1.0"
		MD5 = "369c7c66224b343f624803d595aa1e09"
		SHA1 = "54519d2c124cb536ed0ddad5683440293d90934f"

	strings:
		$s1 = {50 49 4e 47}
		$s2 = {50 52 49 56 4d 53 47}
		$s3 = {52 65 6d 6f 74 65 20 49 52 43 20 42 6f 74}
		$s4 = {32 33 2e 39 35 2e 34 33 2e 31 38 32}

	condition:
		$s1 and $s2 and $s3 and $s4
}

rule Gafgyt_Botnet_jackmy : MALW hardened
{
	meta:
		description = "Gafgyt Trojan"
		author = "Joan Soriano / @joanbtl"
		date = "2017-05-25"
		version = "1.0"
		MD5 = "419b8a10a3ac200e7e8a0c141b8abfba"
		SHA1 = "5433a5768c5d22dabc4d133c8a1d192d525939d5"
		score = 80

	strings:
		$s1 = {50 49 4e 47}
		$s2 = {50 4f 4e 47}
		$s3 = {6a 61 63 6b 6d 79}
		$s4 = {32 30 33 2e 31 33 34 2e 25 64 2e 25 64}

	condition:
		$s1 and $s2 and $s3 and $s4
}

rule Gafgyt_Botnet_HIHI : MALW hardened
{
	meta:
		description = "Gafgyt Trojan"
		author = "Joan Soriano / @joanbtl"
		date = "2017-05-01"
		version = "1.0"
		MD5 = "cc99e8dd2067fd5702a4716164865c8a"
		SHA1 = "b9b316c1cc9f7a1bf8c70400861de08d95716e49"

	strings:
		$s1 = {50 49 4e 47}
		$s2 = {50 4f 4e 47}
		$s3 = {54 45 4c 4e 45 54 20 4c 4f 47 49 4e 20 43 52 41 43 4b 45 44 20 2d 20 25 73 3a 25 73 3a 25 73}
		$s4 = {41 44 56 41 4e 43 45 44 42 4f 54}
		$s5 = {34 36 2e 31 36 36 2e 31 38 35 2e 39 32}
		$s6 = {4c 4f 4c 4e 4f 47 54 46 4f}

	condition:
		$s1 and $s2 and $s3 and $s4 and $s5 and $s6
}

