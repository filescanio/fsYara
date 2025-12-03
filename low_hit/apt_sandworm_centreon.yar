rule APT_MAL_Sandworm_Exaramel_Configuration_Key : hardened
{
	meta:
		author = "FR/ANSSI/SDO"
		description = "Detects the encryption key for the configuration file used by Exaramel malware as seen in sample e1ff72[...]"
		reference = "https://www.cert.ssi.gouv.fr/uploads/CERTFR-2021-CTI-005.pdf"
		date = "2021-02-15"
		score = 80
		id = "8078de62-3dd2-5ee0-8bda-f508e4013144"

	strings:
		$ = {6f 64 68 79 72 66 6a 63 6e 66 6b 64 74 73 6c 74}

	condition:
		all of them
}

rule APT_MAL_Sandworm_Exaramel_Configuration_Name_Encrypted : hardened
{
	meta:
		author = "FR/ANSSI/SDO"
		description = "Detects the specific name of the configuration file in Exaramel malware as seen in sample e1ff72[...]"
		reference = "https://www.cert.ssi.gouv.fr/uploads/CERTFR-2021-CTI-005.pdf"
		date = "2021-02-15"
		score = 80
		id = "1c06f5fc-3435-51cd-92fb-17a4ab6b63ad"

	strings:
		$ = {63 6f 6e 66 69 67 74 78 2e 6a 73 6f 6e}

	condition:
		all of them
}

rule APT_MAL_Sandworm_Exaramel_Configuration_File_Plaintext : hardened
{
	meta:
		author = "FR/ANSSI/SDO"
		description = "Detects contents of the configuration file used by Exaramel (plaintext)"
		reference = "https://www.cert.ssi.gouv.fr/uploads/CERTFR-2021-CTI-005.pdf"
		date = "2021-02-15"
		score = 80
		id = "6f0d834b-e6c8-59e6-bf9a-b4fd9c0b2297"

	strings:
		$ = /{"Hosts":\[".{10,512}"\],"Proxy":".{0,512}","Version":".{1,32}","Guid":"/

	condition:
		all of them
}

rule APT_MAL_Sandworm_Exaramel_Configuration_File_Ciphertext : hardened
{
	meta:
		author = "FR/ANSSI/SDO"
		description = "Detects contents of the configuration file used by Exaramel (encrypted with key odhyrfjcnfkdtslt, sample e1ff72[...]"
		reference = "https://www.cert.ssi.gouv.fr/uploads/CERTFR-2021-CTI-005.pdf"
		date = "2021-02-15"
		score = 80
		id = "763dbb17-2bad-5b40-8a7b-b71bc5849cd9"

	strings:
		$ = { 6F B6 08 E9 A3 0C 8D 5E DD BE D4 }

	condition:
		all of them
}

rule APT_MAL_Sandworm_Exaramel_Socket_Path : hardened
{
	meta:
		author = "FR/ANSSI/SDO"
		description = "Detects path of the unix socket created to prevent concurrent executions in Exaramel malware"
		reference = "https://www.cert.ssi.gouv.fr/uploads/CERTFR-2021-CTI-005.pdf"
		date = "2021-02-15"
		score = 80
		id = "3aab84c9-9748-5d11-9cd7-efa9151036cf"

	strings:
		$ = {2f 74 6d 70 2f 2e 61 70 70 6c 6f 63 6b 74 78}

	condition:
		all of them
}

rule APT_MAL_Sandworm_Exaramel_Task_Names : hardened
{
	meta:
		author = "FR/ANSSI/SDO"
		description = "Detects names of the tasks received from the CC server in Exaramel malware"
		reference = "https://www.cert.ssi.gouv.fr/uploads/CERTFR-2021-CTI-005.pdf"
		date = "2021-02-15"
		score = 80
		id = "185f2f3b-bf5c-54af-bca2-400d08bf9c91"

	strings:
		$ = {41 70 70 2e 44 65 6c 65 74 65}
		$ = {41 70 70 2e 53 65 74 53 65 72 76 65 72}
		$ = {41 70 70 2e 53 65 74 50 72 6f 78 79}
		$ = {41 70 70 2e 53 65 74 54 69 6d 65 6f 75 74}
		$ = {41 70 70 2e 55 70 64 61 74 65}
		$ = {49 4f 2e 52 65 61 64 46 69 6c 65}
		$ = {49 4f 2e 57 72 69 74 65 46 69 6c 65}
		$ = {4f 53 2e 53 68 65 6c 6c 45 78 65 63 75 74 65}

	condition:
		all of them
}

rule APT_MAL_Sandworm_Exaramel_Struct : hardened
{
	meta:
		author = "FR/ANSSI/SDO"
		description = "Detects the beginning of type _type struct for some of the most important structs in Exaramel malware"
		reference = "https://www.cert.ssi.gouv.fr/uploads/CERTFR-2021-CTI-005.pdf"
		date = "2021-02-15"
		score = 80
		id = "8282e485-966c-554d-8e41-70dc1657f5ea"

	strings:
		$struct_le_config = {70 00 00 00 00 00 00 00 58 00 00 00 00 00 00 00 47 2d 28 42 0? [2] 19}
		$struct_le_worker = {30 00 00 00 00 00 00 00 30 00 00 00 00 00 00 00 46 6a 13 e2 0? [2] 19}
		$struct_le_client = {20 00 00 00 00 00 00 00 10 00 00 00 00 00 00 00 7b 6a 49 84 0? [2] 19}
		$struct_le_report = {30 00 00 00 00 00 00 00 28 00 00 00 00 00 00 00 bf 35 0d f9 0? [2] 19}
		$struct_le_task = {50 00 00 00 00 00 00 00 20 00 00 00 00 00 00 00 88 60 a1 c5 0? [2] 19}

	condition:
		any of them
}

rule APT_MAL_Sandworm_Exaramel_Strings_Typo : hardened
{
	meta:
		author = "FR/ANSSI/SDO"
		description = "Detects misc strings in Exaramel malware with typos"
		reference = "https://www.cert.ssi.gouv.fr/uploads/CERTFR-2021-CTI-005.pdf"
		date = "2021-02-15"
		score = 80
		id = "fdc79b87-eb9e-5751-9474-ff653b073165"

	strings:
		$typo1 = {2f 73 62 69 6e 2f 69 6e 69 74 20 7c 20 61 77 6b 20}
		$typo2 = {53 79 73 6c 6f 67 20 73 65 72 76 69 63 65 20 66 6f 72 20 6d 6f 6e 69 74 6f 72 69 6e 67 20 0a}
		$typo3 = {45 72 72 6f 72 2e 43 61 6e 27 74 20 75 70 64 61 74 65 20 61 70 70 21 20 4e 6f 74 20 65 6e 6f 75 67 68 20 75 70 64 61 74 65 20 61 72 63 68 69 76 65 2e}
		$typo4 = {3a 22 6d 65 74 6f 64 22}

	condition:
		3 of ( $typo* )
}

rule APT_MAL_Sandworm_Exaramel_Strings : hardened
{
	meta:
		author = "FR/ANSSI/SDO (composed from 4 saparate rules by Florian Roth)"
		description = "Detects Strings used by Exaramel malware"
		reference = "https://www.cert.ssi.gouv.fr/uploads/CERTFR-2021-CTI-005.pdf"
		date = "2021-02-15"
		score = 80
		id = "fdc79b87-eb9e-5751-9474-ff653b073165"

	strings:
		$persistence1 = {73 79 73 74 65 6d 64}
		$persistence2 = {75 70 73 74 61 72 74}
		$persistence3 = {73 79 73 74 65 6d 56}
		$persistence4 = {66 72 65 65 62 73 64 20 72 63}
		$report1 = {73 79 73 74 65 6d 64 75 70 64 61 74 65 2e 72 65 70}
		$report2 = {75 70 73 74 61 72 74 75 70 64 61 74 65 2e 72 65 70}
		$report3 = {72 65 6d 6f 76 65 2e 72 65 70}
		$url1 = {2f 74 61 73 6b 73 2e 67 65 74 2f}
		$url2 = {2f 74 69 6d 65 2e 67 65 74 2f}
		$url3 = {2f 74 69 6d 65 2e 73 65 74}
		$url4 = {2f 74 61 73 6b 73 2e 72 65 70 6f 72 74}
		$url5 = {2f 61 74 74 61 63 68 6d 65 6e 74 2e 67 65 74 2f}
		$url6 = {2f 61 75 74 68 2f 61 70 70}

	condition:
		(5 of ( $url* ) and all of ( $persistence* ) ) or ( all of ( $persistence* ) and all of ( $report* ) ) or ( 5 of ( $url* ) and all of ( $report* ) )
}

