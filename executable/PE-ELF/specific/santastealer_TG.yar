import "pe"

rule santastealer_telegram : hardened
{
	meta:
		author = "OPSWAT"
		description = "Detects SantaStealer's telegram channel string"
		score = 75

	strings:
		$SantaStealer_tg = {74 2e 6d 65 2f 53 61 6e 74 61 53 74 65 61 6c 65 72}

	condition:
		pe.is_pe and $SantaStealer_tg
}

