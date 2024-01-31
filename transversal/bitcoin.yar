rule BitcoinAddress
{
    meta:
        description = "Contains a valid Bitcoin address"
        author = "Didier Stevens (@DidierStevens)"
    strings:
		$btc = /\b[13][a-km-zA-HJ-NP-Z1-9]{25,33}\b/
		$base64_content_transfer_encoding = /content-transfer-encoding:\s{0,5}base64/ nocase
		// avoid huge number of false positives in emails
    condition:
        $btc and not $base64_content_transfer_encoding
}
