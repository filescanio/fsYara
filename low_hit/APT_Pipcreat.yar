rule APT_Win_Pipcreat : hardened
{
	meta:
		author = "chort (@chort0)"
		description = "APT backdoor Pipcreat"
		filetype = "pe,dll"
		date = "2013-03"
		MD5 = "f09d832bea93cf320986b53fce4b8397"
		Reference = "http://www.cyberengineeringservices.com/login-exe-analysis-trojan-pipcreat/"
		version = "1.0"

	strings:
		$strA = {70 00 69 00 70 00 20 00 63 00 72 00 65 00 61 00 74 00 20 00 66 00 61 00 69 00 6c 00 65 00 64 00}
		$strB = {43 72 61 61 74 65 50 69 70 65}
		$strC = {61 00 72 00 65 00 20 00 79 00 6f 00 75 00 20 00 74 00 68 00 65 00 72 00 65 00 3f 00 20 00}
		$strD = {73 00 75 00 63 00 63 00 65 00 73 00 73 00 20 00 6b 00 69 00 6c 00 6c 00 20 00 70 00 72 00 6f 00 63 00 65 00 73 00 73 00 20 00 6f 00 6b 00}
		$strE = {56 00 69 00 73 00 74 00 61 00 7c 00 30 00 38 00 7c 00 57 00 69 00 6e 00 37 00}
		$rut = {61 72 65 20 79 6f 75 20 74 68 65 72 65 21 40 23 24 25 5e 26 2a 28 29 5f 2b}

	condition:
		$rut or ( 2 of ( $str* ) )
}

