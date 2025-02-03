rule genericSMS : smsFraud android hardened
{
	meta:
		author = "https://twitter.com/plutec_net"
		reference = "https://koodous.com/"
		score = 70
		sample = "3fc533d832e22dc3bc161e5190edf242f70fbc4764267ca073de5a8e3ae23272"
		sample2 = "3d85bdd0faea9c985749c614a0676bb05f017f6bde3651f2b819c7ac40a02d5f"

	strings:
		$a = {53 48 41 31 2d 44 69 67 65 73 74 3a 20 2b 52 73 72 54 78 35 53 4e 6a 73 74 72 6e 74 37 70 4e 61 65 51 41 7a 59 34 6b 63 3d}
		$b = {53 48 41 31 2d 44 69 67 65 73 74 3a 20 52 74 32 6f 52 74 73 30 77 57 54 6a 66 66 47 6c 45 54 47 66 46 69 78 31 64 66 45 3d}
		$c = {68 74 74 70 3a 2f 2f 69 6d 61 67 65 2e 62 61 69 64 75 2e 63 6f 6d 2f 77 69 73 65 62 72 6f 77 73 65 2f 69 6e 64 65 78 3f 74 61 67 31 3d 25 45 36 25 39 38 25 38 45 25 45 36 25 39 38 25 39 46 26 74 61 67 32 3d 25 45 35 25 41 35 25 42 33 25 45 36 25 39 38 25 38 45 25 45 36 25 39 38 25 39 46 26 74 61 67 33 3d 25 45 35 25 38 35 25 41 38 25 45 39 25 38 33 25 41 38 26 70 6e 3d 30 26 72 6e 3d 31 30 26 66 6d 70 61 67 65 3d 69 6e 64 65 78 26 70 6f 73 3d 6d 61 67 69 63 23 2f 63 68 61 6e 6e 65 6c}
		$d = {70 69 74 63 68 66 6f 72 6b 3d 30 32 32 44 34}

	condition:
		all of them
}

rule genericSMS2 : smsFraud android hardened
{
	meta:
		author = "https://twitter.com/plutec_net"
		reference = "https://koodous.com/"
		score = 70
		sample = "1f23524e32c12c56be0c9a25c69ab7dc21501169c57f8d6a95c051397263cf9f"
		sample2 = "2cf073bd8de8aad6cc0d6ad5c98e1ba458bd0910b043a69a25aabdc2728ea2bd"
		sample3 = "20575a3e5e97bcfbf2c3c1d905d967e91a00d69758eb15588bdafacb4c854cba"

	strings:
		$a = {4e 6f 74 4c 65 66 74 54 72 69 61 6e 67 6c 65 45 71 75 61 6c 3d 30 32 32 45 43}
		$b = {53 48 41 31 2d 44 69 67 65 73 74 3a 20 58 32 37 5a 70 77 39 63 36 65 79 58 76 45 46 75 5a 66 43 4c 32 4c 6d 75 6d 74 49 3d}
		$c = {5f 5a 4e 53 74 31 32 5f 56 65 63 74 6f 72 5f 62 61 73 65 49 53 73 53 61 49 53 73 45 45 31 33 5f 4d 5f 64 65 61 6c 6c 6f 63 61 74 65 45 50 53 73 6a}
		$d = {46 42 54 50 32 41 48 52 33 57 4b 43 36 4c 45 59 4f 4e 37 44 35 47 5a 58 56 49 53 4d 4a 34 51 55}

	condition:
		all of them
}

