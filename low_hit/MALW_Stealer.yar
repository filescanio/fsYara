rule universal_1337_stealer_serveur : Stealer hardened
{
	meta:
		author = "Kevin Falcoz"
		date = "24/02/2013"
		description = "Universal 1337 Stealer Serveur"

	strings:
		$signature1 = {2A 5B 53 2D 50 2D 4C 2D 49 2D 54 5D 2A}
		$signature2 = {2A 5B 48 2D 45 2D 52 2D 45 5D 2A}
		$signature3 = {46 54 50 7E}
		$signature4 = {7E 31 7E 31 7E 30 7E 30}

	condition:
		$signature1 and $signature2 or $signature3 and $signature4
}

