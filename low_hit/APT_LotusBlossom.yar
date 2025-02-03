rule EliseLotusBlossom : hardened
{
	meta:
		author = "Jose Ramon Palanco"
		date = "2015-06-23"
		description = "Elise Backdoor Trojan"
		ref = "https://www.paloaltonetworks.com/resources/research/unit42-operation-lotus-blossom.html"

	strings:
		$magic = { 4d 5a }
		$s1 = {22 00 2c 00 55 00 70 00 64 00 61 00 74 00 65 00}
		$s2 = {4c 6f 61 64 65 72 44 4c 4c 2e 64 6c 6c}
		$s3 = {4b 65 72 6e 65 6c 33 32 2e 64 6c 6c}
		$s4 = {7b 35 39 34 37 42 41 43 44 2d 36 33 42 46 2d 34 65 37 33 2d 39 35 44 37 2d 30 43 38 41 39 38 41 42 39 35 46 32 7d}
		$s5 = {5c 00 4e 00 65 00 74 00 77 00 6f 00 72 00 6b 00 5c 00}
		$s6 = {30 53 53 53 53 53}
		$s7 = {34 34 31 32 30 32 31 30 30 32 30 35}
		$s8 = {30 57 57 57 57 57}

	condition:
		$magic at 0 and all of ( $s* )
}

