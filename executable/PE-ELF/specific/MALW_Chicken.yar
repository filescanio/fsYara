rule ChickenDOS : hardened
{
	meta:
		author = "Jason Jones <jasonjones@arbor.net>"
		description = "Win32-variant of Chicken ident for both dropper and dropped file"
		source = "https://github.com/arbor/yara/blob/master/chicken.yara"

	strings:
		$pdb1 = {5c 43 68 69 63 6b 65 6e 5c 52 65 6c 65 61 73 65 5c 73 76 63 68 6f 73 74 2e 70 64 62}
		$pdb2 = {5c 49 6e 74 65 72 67 72 61 74 65 43 48 4b 5c 52 65 6c 65 61 73 65 5c 49 6e 74 65 72 67 72 61 74 65 43 48 4b 2e 70 64 62}
		$str2 = {66 61 6b 65 2e 63 66}
		$str3 = {38 2e 38 2e 38 2e 38}
		$str4 = {50 72 6f 63 65 73 73 6f 72 28 25 64 29 5c}
		$str5 = {44 62 50 72 6f 74 65 63 74 53 75 70 70 6f 72 74}
		$str1 = {64 6d 31 37 31 32 2f 60 6a 76 70 6e 70 6b 74 65 2f 62 70 6c}
		$str6 = {49 6e 73 74 61 6c 6c 53 65 72 76 69 63 65 20 4e 50 46 20 25 64}
		$str7 = {36 38 39 36 31}
		$str8 = {49 6e 73 74 61 6c 6c 53 65 72 76 69 63 65 20 44 62 50 72 6f 74 65 63 74 53 75 70 70 6f 72 74 20 25 64}
		$str9 = {43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 44 62 50 72 6f 74 65 63 74 53 75 70 70 6f 72 74 5c 6e 70 66 2e 73 79 73}

	condition:
		($pdb1 or $pdb2 ) and 5 of ( $str* )
}

rule ChickenDOS_Linux : hardened
{
	meta:
		author = "Jason Jones <jasonjones@arbor.net>"
		description = "Linux-variant of Chicken ident for both dropper and dropped file"
		source = "https://github.com/arbor/yara/blob/master/chicken.yara"

	strings:
		$cfg = {66 61 6b 65 2e 63 66 67}
		$file1 = {54 68 72 65 61 64 41 74 74 61 63 6b 2e 63 70 70}
		$file2 = {46 61 6b 65 2e 63 70 70}
		$str1 = {64 6e 73 5f 61 72 72 61 79}
		$str2 = {44 6f 6d 61 69 6e 52 61 6e 64 45 78}
		$str3 = {63 70 75 20 25 6c 6c 75 20 25 6c 6c 75 20 25 6c 6c 75 20 25 6c 6c 75}
		$str4 = {5b 20 25 30 32 64 2e 25 30 32 64 20 25 30 32 64 3a 25 30 32 64 3a 25 30 32 64 2e 25 30 33 6c 64 20 5d 20 5b 25 6c 75 5d 20 5b 25 73 5d 20 25 73}

	condition:
		$cfg and all of ( $file* ) and 3 of ( $str* )
}

