rule Erebus : ransom hardened
{
	meta:
		description = "Erebus Ransomware"
		author = "Joan Soriano / @joanbtl"
		date = "2017-06-23"
		version = "1.0"
		MD5 = "27d857e12b9be5d43f935b8cc86eaabf"
		SHA256 = "0b7996bca486575be15e68dba7cbd802b1e5f90436ba23f802da66292c8a055f"
		ref1 = "http://blog.trendmicro.com/trendlabs-security-intelligence/erebus-resurfaces-as-linux-ransomware/"
		score = 75

	strings:
		$a = {2f 7b 35 66 35 38 64 36 66 30 2d 62 62 39 63 2d 34 36 65 32 2d 61 34 64 61 2d 38 65 62 63 37 34 36 66 32 34 61 35 7d 2f 2f 6c 6f 67 2e 6c 6f 67}
		$b = {45 52 45 42 55 53 20 49 53 20 42 45 53 54 2e}

	condition:
		all of them
}

