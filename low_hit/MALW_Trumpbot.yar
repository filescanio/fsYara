rule TrumpBot : MALW hardened
{
	meta:
		description = "TrumpBot"
		author = "Joan Soriano / @joanbtl"
		date = "2017-04-16"
		version = "1.0"
		MD5 = "77122e0e6fcf18df9572d80c4eedd88d"
		SHA1 = "108ee460d4c11ea373b7bba92086dd8023c0654f"

	strings:
		$string = {74 72 75 6d 70 69 73 64 61 64 64 79}
		$ip = {31 39 38 2e 35 30 2e 31 35 34 2e 31 38 38}

	condition:
		all of them
}

