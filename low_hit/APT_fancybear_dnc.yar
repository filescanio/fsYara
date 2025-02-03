rule COZY_FANCY_BEAR_Hunt : hardened
{
	meta:
		description = "Detects Cozy Bear / Fancy Bear C2 Server IPs"
		author = "Florian Roth"
		reference = "https://www.crowdstrike.com/blog/bears-midst-intrusion-democratic-national-committee/"
		date = "2016-06-14"

	strings:
		$s1 = {((31 38 35 2e 31 30 30 2e 38 34 2e 31 33 34) | (31 00 38 00 35 00 2e 00 31 00 30 00 30 00 2e 00 38 00 34 00 2e 00 31 00 33 00 34 00))}
		$s2 = {((35 38 2e 34 39 2e 35 38 2e 35 38) | (35 00 38 00 2e 00 34 00 39 00 2e 00 35 00 38 00 2e 00 35 00 38 00))}
		$s3 = {((32 31 38 2e 31 2e 39 38 2e 32 30 33) | (32 00 31 00 38 00 2e 00 31 00 2e 00 39 00 38 00 2e 00 32 00 30 00 33 00))}
		$s4 = {((31 38 37 2e 33 33 2e 33 33 2e 38) | (31 00 38 00 37 00 2e 00 33 00 33 00 2e 00 33 00 33 00 2e 00 38 00))}
		$s5 = {((31 38 35 2e 38 36 2e 31 34 38 2e 32 32 37) | (31 00 38 00 35 00 2e 00 38 00 36 00 2e 00 31 00 34 00 38 00 2e 00 32 00 32 00 37 00))}
		$s6 = {((34 35 2e 33 32 2e 31 32 39 2e 31 38 35) | (34 00 35 00 2e 00 33 00 32 00 2e 00 31 00 32 00 39 00 2e 00 31 00 38 00 35 00))}
		$s7 = {((32 33 2e 32 32 37 2e 31 39 36 2e 32 31 37) | (32 00 33 00 2e 00 32 00 32 00 37 00 2e 00 31 00 39 00 36 00 2e 00 32 00 31 00 37 00))}

	condition:
		uint16( 0 ) == 0x5a4d and 1 of them
}

rule COZY_FANCY_BEAR_pagemgr_Hunt : hardened
{
	meta:
		description = "Detects a pagemgr.exe as mentioned in the CrowdStrike report"
		author = "Florian Roth"
		reference = "https://www.crowdstrike.com/blog/bears-midst-intrusion-democratic-national-committee/"
		date = "2016-06-14"

	strings:
		$s1 = {70 00 61 00 67 00 65 00 6d 00 67 00 72 00 2e 00 65 00 78 00 65 00}

	condition:
		uint16( 0 ) == 0x5a4d and 1 of them
}

