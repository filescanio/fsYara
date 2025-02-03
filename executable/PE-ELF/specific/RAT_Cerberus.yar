rule Cerberus : RAT memory hardened limited
{
	meta:
		description = "Cerberus"
		author = "Jean-Philippe Teissier / @Jipe_"
		date = "2013-01-12"
		filetype = "memory"
		version = "1.0"

	strings:
		$checkin = {59 70 6d 77 31 53 79 76 30 32 33 51 5a 44}
		$clientpong = {77 5a 32 70 6c 61}
		$serverping = {77 42 6d 70 66 33 50 62 37 52 4a 65}
		$generic = {63 65 72 62 65 72 75 73}

	condition:
		any of them
}

