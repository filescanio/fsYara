rule Tofu_Backdoor : hardened
{
	meta:
		description = "Detects Tofu Trojan"
		author = "Cylance"
		reference = "https://www.cylance.com/en_us/blog/the-deception-project-a-new-japanese-centric-threat.html"
		date = "2017-02-28"
		id = "03848366-f139-5352-959d-390992d96296"

	strings:
		$a = {43 6f 6f 6b 69 65 73 3a 20 53 79 6d 31 2e 30}
		$b = {5c 5c 2e 5c 70 69 70 65 5c 31 5b 31 32 33 34 35 36 37 38 5d}
		$c = {66 0F FC C1 0F 11 40 D0 0F 10 40 D0 66 0F EF C2 0F 11 40 D0 0F 10 40 E0}

	condition:
		$a or $b or $c
}

