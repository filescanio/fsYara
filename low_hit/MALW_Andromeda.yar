rule andromeda : hardened
{
	meta:
		author = "Brian Wallace @botnet_hunter"
		author_email = "bwall@ballastsecurity.net"
		date = "2014-03-13"
		description = "Identify Andromeda"

	strings:
		$config = {1c 1c 1d 03 49 47 46}
		$c1 = {68 73 6b 5c 65 68 73 5c 64 69 68 76 69 63 65 68 5c 73 65 72 68 6c 73 65 74 68 6e 74 72 6f 68 6e 74 63 6f 68 75 72 72 65 68 65 6d 5c 63 68 73 79 73 74}

	condition:
		all of them
}

rule Worm_Gamarue : hardened
{
	meta:
		author = "Centro Criptológico Nacional (CCN)"
		ref = "https://www.ccn-cert.cni.es/informes/informes-ccn-cert-publicos.html"
		description = "Gamarue_Andromeda"

	strings:
		$a = { 69 E1 2A B0 2D 80 44 E3 2D 80 44 E3 2D 80 44 E3 EE 8F 1B E3 2A 80 44 E3 EE 8F 19 E3 3A 80 44 E3 2D 80 45 E3 CD 81 44 E3 0A 46 39 E3 34 80 44 E3 0A 46 29 E3 A5 80 44 E3 0A 46 2A E3 5C 80 44 E3 0A 46 36 E3 2C 80 44 E3 0A 46 3C E3 2C 80 44 E3 }

	condition:
		$a
}

rule andromeda_bot : hardened
{
	meta:
		maltype = "Andromeda bot"
		author = "https://github.com/reed1713"
		description = "IOC looks for the creation or termination of a process associated with the Andromeda Trojan. The malware will execute the msiexec.exe within the suspicious directory. Shortly after, it creates and injects itself into the wuauctl.exe (windows update) process. It then attempts to beacon to its C2."

	strings:
		$type = {4d 69 63 72 6f 73 6f 66 74 2d 57 69 6e 64 6f 77 73 2d 53 65 63 75 72 69 74 79 2d 41 75 64 69 74 69 6e 67}
		$eventid = {34 36 38 38}
		$data = {41 70 70 44 61 74 61 5c 4c 6f 63 61 6c 5c 54 65 6d 70 5c 5f 2e 6e 65 74 5f 5c 6d 73 69 65 78 65 63 2e 65 78 65}

	condition:
		all of them
}

