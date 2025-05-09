rule finspy : cdshide android hardened
{
	meta:
		description = "Detect Gamma/FinFisher FinSpy for Android #GovWare"
		date = "2020/01/07"
		author = "Thorsten Schröder - ths @ ccc.de (https://twitter.com/__ths__)"
		reference1 = "https://github.com/devio/FinSpy-Tools"
		reference2 = "https://github.com/Linuzifer/FinSpy-Dokumentation"
		reference3 = "https://www.ccc.de/de/updates/2019/finspy"
		score = 70
		sample = "c2ce202e6e08c41e8f7a0b15e7d0781704e17f8ed52d1b2ad7212ac29926436e"

	strings:
		$re = /\x50\x4B\x01\x02[\x00-\xff]{32}[A-Za-z0-9+\/]{6}/

	condition:
		uint32( 0 ) == 0x04034b50 and $re and ( #re > 50 )
}

