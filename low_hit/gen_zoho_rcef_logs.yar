rule EXPL_Zoho_RCE_Fix_Lines_Dec21_1 : hardened
{
	meta:
		description = "Detects lines in log lines of Zoho products that indicate RCE fixes (silent removal of evidence)"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://twitter.com/cyb3rops/status/1467784104930385923"
		date = "2021-12-06"
		score = 65
		id = "633287e3-a377-5b3c-8520-a7790168eff5"

	strings:
		$s1 = {52 43 45 46 3d}
		$sa1 = {22 61 74 74 61 63 6b 53 74 61 74 75 73 22 5c 3a 22 61 63 74 69 76 65 22}
		$sa2 = {22 61 74 74 61 63 6b 53 74 61 74 75 73 22 3a 22 61 63 74 69 76 65 22}
		$sd1 = {64 65 6c 65 74 65 64 43 6f 75 6e 74}
		$sd_fp1 = {22 64 65 6c 65 74 65 64 43 6f 75 6e 74 22 5c 3a 30}
		$sd_fp2 = {22 64 65 6c 65 74 65 64 43 6f 75 6e 74 22 3a 30}

	condition:
		filesize < 6MB and $s1 and ( 1 of ( $sa* ) or ( $sd1 and not 1 of ( $sd_fp* ) ) )
}

