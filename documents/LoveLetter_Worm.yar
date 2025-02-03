rule Worm_VBS_LoveLetter : hardened
{
	meta:
		description = "Worm.VBS.LoveLetter"
		author = "opswat"
		ref = "https://github.com/onx/ILOVEYOU"
		score = 80

	strings:
		$signature1 = {62 61 72 6f 6b 20 2d 6c 6f 76 65 6c 65 74 74 65 72 28 76 62 65 29 20 3c 69 20 68 61 74 65 20 67 6f 20 74 6f 20 73 63 68 6f 6f 6c 3e}
		$signature2 = {4c 4f 56 45 2d 4c 45 54 54 45 52 2d 46 4f 52 2d 59 4f 55}
		$copy_file1 = {4d 53 4b 65 72 6e 65 6c 33 32 2e 76 62 73}
		$copy_file2 = {57 69 6e 33 32 44 4c 4c 2e 76 62 73}
		$copy_file3 = {4c 4f 56 45 2d 4c 45 54 54 45 52 2d 46 4f 52 2d 59 4f 55 2e 54 58 54 2e 76 62 73}
		$copy_file4 = {4c 4f 56 45 2d 4c 45 54 54 45 52 2d 46 4f 52 2d 59 4f 55 2e 48 54 4d}
		$download_explorer = {49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 4d 61 69 6e 5c 53 74 61 72 74 50 61 67 65}
		$download_startup = {4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e}
		$download_file = {57 49 4e 2d 42 55 47 53 46 49 58 2e 65 78 65}
		$irc1 = {73 63 72 69 70 74 2e 69 6e 69}
		$irc2 = {6d 49 52 43 20 53 63 72 69 70 74}
		$irc3 = {68 74 74 70 3a 2f 2f 77 77 77 2e 6d 69 72 63 2e 63 6f 6d}
		$email_subject = {5375626a656374203d2022494c4f5645594f5522}
		$email_outlook = {4372656174654f626a65637428224f75746c6f6f6b2e4170706c69636174696f6e2229}
		$email_mapi = {4765744e616d65537061636528224d4150492229}
		$email_history = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 41 42}
		$email_contacts1 = {41 64 64 72 65 73 73 4c 69 73 74 73}
		$email_contacts2 = {41 64 64 72 65 73 73 45 6e 74 72 69 65 73}

	condition:
		filesize < 25KB and ( all of ( $signature1 , $signature2 ) or ( 9 of ( $copy_file* , $download_* , $irc* , $email_* ) ) )
}

