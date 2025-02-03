rule urausy_skype_dat : memory hardened
{
	meta:
		author = "AlienVault Labs"
		description = "Yara rule to match against memory of processes infected by Urausy skype.dat"

	strings:
		$a = {((73 6b 79 70 65 2e 64 61 74) | (73 00 6b 00 79 00 70 00 65 00 2e 00 64 00 61 00 74 00))}
		$b = {((73 6b 79 70 65 2e 69 6e 69) | (73 00 6b 00 79 00 70 00 65 00 2e 00 69 00 6e 00 69 00))}
		$win1 = {43 72 65 61 74 65 57 69 6e 64 6f 77}
		$win2 = {((59 49 57 45 46 48 49 57 51) | (59 00 49 00 57 00 45 00 46 00 48 00 49 00 57 00 51 00))}
		$desk1 = {43 72 65 61 74 65 44 65 73 6b 74 6f 70}
		$desk2 = {((4d 79 44 65 73 6b 74 6f 70) | (4d 00 79 00 44 00 65 00 73 00 6b 00 74 00 6f 00 70 00))}

	condition:
		$a and $b and ( all of ( $win* ) or all of ( $desk* ) )
}

