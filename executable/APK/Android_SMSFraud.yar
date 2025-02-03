rule smsfraud1 : android hardened
{
	meta:
		author = "Antonio Sánchez https://twitter.com/plutec_net"
		reference = "https://koodous.com/"
		description = "This rule detects a kind of SMSFraud trojan"
		score = 50
		sample = "265890c3765d9698091e347f5fcdcf1aba24c605613916820cc62011a5423df2"
		sample2 = "112b61c778d014088b89ace5e561eb75631a35b21c64254e32d506379afc344c"

	strings:
		$a = {45 21 51 51 41 5a 58 53}
		$b = {5f 5f 65 78 69 64 78 5f 65 6e 64}
		$c = {72 65 73 2f 6c 61 79 6f 75 74 2f 6e 6f 74 69 66 79 5f 61 70 6b 69 6e 73 74 61 6c 6c 2e 78 6d 6c 50 4b}

	condition:
		all of them
}

rule smsfraud2 : android hardened
{
	meta:
		author = "Antonio Sánchez https://twitter.com/plutec_net"
		reference = "https://koodous.com/"
		score = 60
		sample = "0200a454f0de2574db0b58421ea83f0f340bc6e0b0a051fe943fdfc55fea305b"
		sample2 = "bff3881a8096398b2ded8717b6ce1b86a823e307c919916ab792a13f2f5333b6"

	strings:
		$a = {70 6c 75 67 69 6e 53 4d 53 5f 64 65 63 72 79 70 74}
		$b = {70 6c 75 67 69 6e 53 4d 53 5f 65 6e 63 72 79 70 74}
		$c = {5f 5f 64 73 6f 5f 68 61 6e 64 6c 65}
		$d = {6c 69 62 2f 61 72 6d 65 61 62 69 2f 6c 69 62 6d 79 6c 69 62 2e 73 6f 55 54}
		$e = {5d 44 69 6f 6b 22 33 7c}

	condition:
		all of them
}

