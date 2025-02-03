rule APT_DeputyDog_Fexel : hardened limited
{
	meta:
		author = "ThreatConnect Intelligence Research Team"

	strings:
		$180 = {((31 38 30 2e 31 35 30 2e 32 32 38 2e 31 30 32) | (31 00 38 00 30 00 2e 00 31 00 35 00 30 00 2e 00 32 00 32 00 38 00 2e 00 31 00 30 00 32 00))}
		$0808cmd = {25 30 38 78 30 38 78 00 5C 00 63 00 6D 00 64 00 2E 00 65 00 78 00 65 [2-6] 43 00 61 00 6E 00 27 00 74 00 20 00 6F 00 70 00 65 00 6E 00 20 00 73 00 68 00 65 00 6C 00 6C 00 21}
		$cUp = {((55 70 6c 6f 61 64 20 66 61 69 6c 65 64 21 20 5b 52 65 6d 6f 74 65 20 65 72 72 6f 72 20 63 6f 64 65 3a) | (55 00 70 00 6c 00 6f 00 61 00 64 00 20 00 66 00 61 00 69 00 6c 00 65 00 64 00 21 00 20 00 5b 00 52 00 65 00 6d 00 6f 00 74 00 65 00 20 00 65 00 72 00 72 00 6f 00 72 00 20 00 63 00 6f 00 64 00 65 00 3a 00))}
		$DGGYDSYRL = {00 44 47 47 59 44 53 59 52 4C 00}
		$GDGSYDLYR = {((47 44 47 53 59 44 4c 59 52 5f 25) | (47 00 44 00 47 00 53 00 59 00 44 00 4c 00 59 00 52 00 5f 00 25 00))}

	condition:
		any of them
}

rule APT_DeputyDog : hardened
{
	meta:
		Author = "FireEye Labs"
		Date = "2013/09/21"
		Description = "detects string seen in samples used in 2013-3893 0day attacks"
		Reference = "https://www.fireeye.com/blog/threat-research/2013/09/operation-deputydog-zero-day-cve-2013-3893-attack-against-japanese-targets.html"

	strings:
		$mz = {4d 5a}
		$a = {44 47 47 59 44 53 59 52 4c}

	condition:
		($mz at 0 ) and $a
}

