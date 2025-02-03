rule Madness : DoS hardened
{
	meta:
		author = "Jason Jones <jasonjones@arbor.net>"
		date = "2014-01-15"
		description = "Identify Madness Pro DDoS Malware"
		source = "https://github.com/arbor/yara/blob/master/madness.yara"

	strings:
		$ua1 = {54 57 39 36 61 57 78 73 59 53 38 31 4c 6a 41 67 4b 46 64 70 62 6d 52 76 64 33 4d 37 49 46 55 37 49 46 64 70 62 6d 52 76 64 33 4d 67 54 6c 51 67 4e 53 34 78 4f 79 42 6c 62 69 31 56 55 7a 73 67 63 6e 59 36 4d 53 34 34 4c 6a 41 75 4e 53 6b 67 52 32 56 6a 61 32 38 76 4d 6a 41 77 4e 6a 41 33 4d 7a 45 67 52 6d 6c 79 5a 57 5a 76 65 43 38 78 4c 6a 55 75 4d 43 34 31 49 45 5a 73 62 32 4e 72 4c 7a 41 75 4e 79 34 30 4c 6a 45}
		$ua2 = {54 57 39 36 61 57 78 73 59 53 38 31 4c 6a 41 67 4b 46 67 78 4d 54 73 67 56 54 73 67 54 47 6c 75 64 58 67 67 4d 69 34 30 4c 6a 49 74 4d 69 42 70 4e 54 67 32 4f 79 42 6c 62 69 31 56 55 7a 73 67 62 54 45 34 4b 53 42 48 5a 57 4e 72 62 79 38 79 4d 44 41 78 4d 44 45 7a 4d 53 42 4f 5a 58 52 7a 59 32 46 77 5a 54 59 76 4e 69 34 77 4d 51 3d 3d}
		$str1 = {64 6f 63 75 6d 65 6e 74 2e 63 6f 6f 6b 69 65 3d}
		$str2 = {5b 22 63 6f 6f 6b 69 65 22 2c 22}
		$str3 = {22 72 65 61 6c 61 75 74 68 3d}
		$str4 = {22 6c 6f 63 61 74 69 6f 6e 22 5d 3b}
		$str5 = {64 33 52 6d}
		$str6 = {5a 58 68 6c}

	condition:
		all of them
}

