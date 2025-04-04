import "pe"

rule Gazer_certificate_subject : hardened
{
	meta:
		description = "Detects Tura's Gazer malware"
		author = "ESET"
		reference = "https://www.welivesecurity.com/2017/08/30/eset-research-cyberespionage-gazer/"
		date = "30.08.2017"
		id = "4eace653-003e-5cae-9db8-f26502f35fc4"

	condition:
		for any i in ( 0 .. pe.number_of_signatures - 1 ) : ( pe.signatures [ i ] . subject contains "Solid Loop" or pe.signatures [ i ] . subject contains "Ultimate Computer Support" )
}

rule Gazer_certificate : hardened
{
	meta:
		description = "Detects Tura's Gazer malware"
		author = "ESET"
		reference = "https://www.welivesecurity.com/2017/08/30/eset-research-cyberespionage-gazer/"
		date = "30.08.2017"
		id = "4eace653-003e-5cae-9db8-f26502f35fc4"

	strings:
		$certif1 = { 52 76 a4 53 cd 70 9c 18 da 65 15 7e 5f 1f de 02 }
		$certif2 = { 12 90 f2 41 d9 b2 80 af 77 fc da 12 c6 b4 96 9c }

	condition:
		uint16( 0 ) == 0x5a4d and 1 of them and filesize < 2MB
}

rule Gazer_logfile_name : hardened
{
	meta:
		description = "Detects Tura's Gazer malware"
		author = "ESET"
		reference = "https://www.welivesecurity.com/2017/08/30/eset-research-cyberespionage-gazer/"
		date = "30.08.2017"
		id = "c10d440f-dc9e-54c8-b329-9f22cba05e86"

	strings:
		$s1 = {43 56 52 47 37 32 42 35 2e 74 6d 70 2e 63 76 72}
		$s2 = {43 56 52 47 31 41 36 42 2e 74 6d 70 2e 63 76 72}
		$s3 = {43 56 52 47 33 38 44 39 2e 74 6d 70 2e 63 76 72}

	condition:
		uint16( 0 ) == 0x5a4d and 1 of them
}

