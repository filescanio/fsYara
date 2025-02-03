rule crime_win_rat_AlienSpy : hardened
{
	meta:
		description = "Alien Spy Remote Access Trojan"
		author = "General Dynamics Fidelis Cybersecurity Solutions - Threat Research Team"
		reference_1 = "www.fidelissecurity.com/sites/default/files/FTA_1015_Alienspy_FINAL.pdf"
		reference_2 = "www.fidelissecurity.com/sites/default/files/AlienSpy-Configs2_1_2.csv"
		date = "04-Apr-15"
		filetype = "Java"
		hash_1 = "075fa0567d3415fbab3514b8aa64cfcb"
		hash_2 = "818afea3040a887f191ee9d0579ac6ed"
		hash_3 = "973de705f2f01e82c00db92eaa27912c"
		hash_4 = "7f838907f9cc8305544bd0ad4cfd278e"
		hash_5 = "071e12454731161d47a12a8c4b3adfea"
		hash_6 = "a7d50760d49faff3656903c1130fd20b"
		hash_7 = "f399afb901fcdf436a1b2a135da3ee39"
		hash_8 = "3698a3630f80a632c0c7c12e929184fb"
		hash_9 = "fdb674cadfa038ff9d931e376f89f1b6"
		score = 70
		id = "a79789cd-9b16-58f5-ab51-48bb900583d1"

	strings:
		$sa_1 = {4d 45 54 41 2d 49 4e 46 2f 4d 41 4e 49 46 45 53 54 2e 4d 46}
		$sa_2 = {4d 61 69 6e 2e 63 6c 61 73 73 50 4b}
		$sa_3 = {70 6c 75 67 69 6e 73 2f 53 65 72 76 65 72 2e 63 6c 61 73 73 50 4b}
		$sa_4 = {49 44 50 4b}
		$sb_1 = {63 6f 6e 66 69 67 2e 69 6e 69 50 4b}
		$sb_2 = {70 61 73 73 77 6f 72 64 2e 69 6e 69 50 4b}
		$sb_3 = {70 6c 75 67 69 6e 73 2f 53 65 72 76 65 72 2e 63 6c 61 73 73 50 4b}
		$sb_4 = {4c 6f 61 64 53 74 75 62 2e 63 6c 61 73 73 50 4b}
		$sb_5 = {4c 6f 61 64 53 74 75 62 44 65 63 72 79 70 74 65 64 2e 63 6c 61 73 73 50 4b}
		$sb_7 = {4c 6f 61 64 50 61 73 73 77 6f 72 64 2e 63 6c 61 73 73 50 4b}
		$sb_8 = {44 65 63 72 79 70 74 53 74 75 62 2e 63 6c 61 73 73 50 4b}
		$sb_9 = {43 6c 61 73 73 4c 6f 61 64 65 72 73 2e 63 6c 61 73 73 50 4b}
		$sc_1 = {63 6f 6e 66 69 67 2e 78 6d 6c}
		$sc_2 = {6f 70 74 69 6f 6e 73}
		$sc_3 = {70 6c 75 67 69 6e 73}
		$sc_5 = {75 74 69 6c 2f 4f 53 48 65 6c 70 65 72}
		$sc_6 = {53 74 61 72 74 2e 63 6c 61 73 73}
		$sc_7 = {41 6c 69 65 6e 53 70 79}

	condition:
		uint16( 0 ) == 0x4B50 and filesize < 800KB and ( ( all of ( $sa_* ) ) or ( all of ( $sb_* ) ) or ( all of ( $sc_* ) ) )
}

