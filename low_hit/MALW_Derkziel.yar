rule Derkziel : hardened
{
	meta:
		description = "Derkziel info stealer (Steam, Opera, Yandex, ...)"
		author = "The Malware Hunter"
		filetype = "pe"
		date = "2015-11"
		md5 = "f5956953b7a4acab2e6fa478c0015972"
		site = "https://zoo.mlw.re/samples/f5956953b7a4acab2e6fa478c0015972"
		reference = "https://bhf.su/threads/137898/"

	strings:
		$drz = {7b 21 7d 44 52 5a 7b 21 7d}
		$ua = {55 73 65 72 2d 41 67 65 6e 74 3a 20 55 70 6c 6f 61 64 6f 72}
		$steam = {53 74 65 61 6d 41 70 70 44 61 74 61 2e 76 64 66}
		$login = {6c 6f 67 69 6e 75 73 65 72 73 2e 76 64 66}
		$config = {63 6f 6e 66 69 67 2e 76 64 66}

	condition:
		all of them
}

