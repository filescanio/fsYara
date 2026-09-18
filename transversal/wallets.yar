rule MoneroAddress : hardened
{
	meta:
		description = "Contains a valid Monero address"
		author = "Emilien LE JAMTEL (@__Emilien__)"

	strings:
		$monero = /\b4[0-9AB][0-9a-zA-Z]{93}|4[0-9AB][0-9a-zA-Z]{104}\b/ wide ascii

	condition:
		any of them
}

rule BitcoinAddress : hardened
{
	meta:
		description = "Contains a valid Bitcoin address"
		author = "Didier Stevens (@DidierStevens)"

	strings:
		$btc = /[^a-zA-Z0-9_+\/][13][a-km-zA-HJ-NP-Z1-9]{25,33}[^a-zA-Z0-9_+\/]/ wide ascii
		$base64_content_transfer_encoding = /content-transfer-encoding:\s{0,5}base64/ nocase

	condition:
		$btc and not $base64_content_transfer_encoding
}

rule EthereumAddress : hardened
{
	meta:
		description = "Contains a valid Ethereum address"
		author = "OPSWAT"

	strings:
		$eth = /\b0x[0-9a-fA-F]{40}\b/ wide ascii

	condition:
		any of them
}

