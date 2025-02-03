rule EXPL_LOG_CVE_2021_27065_Exchange_Forensic_Artefacts_Mar21_1 : LOG hardened
{
	meta:
		description = "Detects forensic artefacts found in HAFNIUM intrusions exploiting CVE-2021-27065"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.volexity.com/blog/2021/03/02/active-exploitation-of-microsoft-exchange-zero-day-vulnerabilities/"
		date = "2021-03-02"
		id = "dcc1f741-cab0-5a0b-a261-a6bd05989723"

	strings:
		$s1 = {((53 3a 43 4d 44 3d 53 65 74 2d 4f 61 62 56 69 72 74 75 61 6c 44 69 72 65 63 74 6f 72 79 2e 45 78 74 65 72 6e 61 6c 55 72 6c 3d 27) | (53 00 3a 00 43 00 4d 00 44 00 3d 00 53 00 65 00 74 00 2d 00 4f 00 61 00 62 00 56 00 69 00 72 00 74 00 75 00 61 00 6c 00 44 00 69 00 72 00 65 00 63 00 74 00 6f 00 72 00 79 00 2e 00 45 00 78 00 74 00 65 00 72 00 6e 00 61 00 6c 00 55 00 72 00 6c 00 3d 00 27 00))}

	condition:
		1 of them
}

rule EXPL_LOG_CVE_2021_26858_Exchange_Forensic_Artefacts_Mar21_1 : LOG hardened
{
	meta:
		description = "Detects forensic artefacts found in HAFNIUM intrusions exploiting CVE-2021-26858"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.volexity.com/blog/2021/03/02/active-exploitation-of-microsoft-exchange-zero-day-vulnerabilities/"
		date = "2021-03-02"
		score = 65
		modified = "2021-03-04"
		id = "f6fa90c7-c2c0-56db-bf7b-dc146761a995"

	strings:
		$xr1 = /POST (\/owa\/auth\/Current\/themes\/resources\/logon\.css|\/owa\/auth\/Current\/themes\/resources\/owafont_ja\.css|\/owa\/auth\/Current\/themes\/resources\/lgnbotl\.gif|\/owa\/auth\/Current\/themes\/resources\/owafont_ko\.css|\/owa\/auth\/Current\/themes\/resources\/SegoeUI-SemiBold\.eot|\/owa\/auth\/Current\/themes\/resources\/SegoeUI-SemiLight\.ttf|\/owa\/auth\/Current\/themes\/resources\/lgnbotl\.gif)/

	condition:
		$xr1
}

rule LOG_APT_HAFNIUM_Exchange_Log_Traces_Mar21_1 : LOG hardened
{
	meta:
		description = "Detects suspicious log entries that indicate requests as described in reports on HAFNIUM activity"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.volexity.com/blog/2021/03/02/active-exploitation-of-microsoft-exchange-zero-day-vulnerabilities/"
		date = "2021-03-04"
		score = 65
		id = "a51f0bd5-c6fd-5ee4-9d30-9a6001778013"

	strings:
		$xr1 = /POST \/(ecp\/y\.js|ecp\/main\.css|ecp\/default\.flt|ecp\/auth\/w\.js|owa\/auth\/w\.js)[^\n]{100,600} (200|301|302) /
		$xr3 = /POST \/owa\/auth\/Current\/[^\n]{100,600} (DuckDuckBot\/1\.0;\+\(\+http:\/\/duckduckgo\.com\/duckduckbot\.html\)|facebookexternalhit\/1\.1\+\(\+http:\/\/www\.facebook\.com\/externalhit_uatext\.php\)|Mozilla\/5\.0\+\(compatible;\+Baiduspider\/2\.0;\+\+http:\/\/www\.baidu\.com\/search\/spider\.html\)|Mozilla\/5\.0\+\(compatible;\+Bingbot\/2\.0;\+\+http:\/\/www\.bing\.com\/bingbot\.htm\)|Mozilla\/5\.0\+\(compatible;\+Googlebot\/2\.1;\+\+http:\/\/www\.google\.com\/bot\.html|Mozilla\/5\.0\+\(compatible;\+Konqueror\/3\.5;\+Linux\)\+KHTML\/3\.5\.5\+\(like\+Gecko\)\+\(Exabot-Thumbnails\)|Mozilla\/5\.0\+\(compatible;\+Yahoo!\+Slurp;\+http:\/\/help\.yahoo\.com\/help\/us\/ysearch\/slurp\)|Mozilla\/5\.0\+\(compatible;\+YandexBot\/3\.0;\+\+http:\/\/yandex\.com\/bots\)|Mozilla\/5\.0\+\(X11;\+Linux\+x86_64\)\+AppleWebKit\/537\.36\+\(KHTML,\+like\+Gecko\)\+Chrome\/51\.0\.2704\.103\+Safari\/537\.3)/
		$xr4 = /POST \/ecp\/[^\n]{100,600} (ExchangeServicesClient\/0\.0\.0\.0|python-requests\/2\.19\.1|python-requests\/2\.25\.1)[^\n]{200,600} (200|301|302) /
		$xr5 = /POST \/(aspnet_client|owa)\/[^\n]{100,600} (antSword\/v2\.1|Googlebot\/2\.1\+\(\+http:\/\/www\.googlebot\.com\/bot\.html\)|Mozilla\/5\.0\+\(compatible;\+Baiduspider\/2\.0;\+\+http:\/\/www\.baidu\.com\/search\/spider\.html\))[^\n]{200,600} (200|301|302) /

	condition:
		1 of them
}

rule LOG_Exchange_Forensic_Artefacts_CleanUp_Activity_Mar21_1 : LOG hardened
{
	meta:
		description = "Detects forensic artefacts showing cleanup activity found in HAFNIUM intrusions exploiting"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://twitter.com/jdferrell3/status/1368626281970024448"
		date = "2021-03-08"
		score = 70
		id = "95b19544-147b-5496-b717-669cbc488179"

	strings:
		$x1 = {((63 6d 64 2e 65 78 65 20 2f 63 20 63 64 20 2f 64 20 43 3a 2f 69 6e 65 74 70 75 62 2f 77 77 77 72 6f 6f 74 2f 61 73 70 6e 65 74 5f 63 6c 69 65 6e 74) | (63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 20 00 2f 00 63 00 20 00 63 00 64 00 20 00 2f 00 64 00 20 00 43 00 3a 00 2f 00 69 00 6e 00 65 00 74 00 70 00 75 00 62 00 2f 00 77 00 77 00 77 00 72 00 6f 00 6f 00 74 00 2f 00 61 00 73 00 70 00 6e 00 65 00 74 00 5f 00 63 00 6c 00 69 00 65 00 6e 00 74 00))}
		$x2 = {((63 6d 64 2e 65 78 65 20 2f 63 20 63 64 20 2f 64 20 43 3a 5c 69 6e 65 74 70 75 62 5c 77 77 77 72 6f 6f 74 5c 61 73 70 6e 65 74 5f 63 6c 69 65 6e 74) | (63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 20 00 2f 00 63 00 20 00 63 00 64 00 20 00 2f 00 64 00 20 00 43 00 3a 00 5c 00 69 00 6e 00 65 00 74 00 70 00 75 00 62 00 5c 00 77 00 77 00 77 00 72 00 6f 00 6f 00 74 00 5c 00 61 00 73 00 70 00 6e 00 65 00 74 00 5f 00 63 00 6c 00 69 00 65 00 6e 00 74 00))}
		$s1 = {61 73 70 6e 65 74 5f 63 6c 69 65 6e 74 26 64 65 6c 20 27}
		$s2 = {61 73 70 6e 65 74 5f 63 6c 69 65 6e 74 26 61 74 74 72 69 62 20 2b 68 20 2b 73 20 2b 72 20}
		$s3 = {26 65 63 68 6f 20 5b 53 5d}

	condition:
		1 of ( $x* ) or 2 of them
}

rule EXPL_LOG_CVE_2021_27055_Exchange_Forensic_Artefacts : LOG hardened
{
	meta:
		description = "Detects suspicious log entries that indicate requests as described in reports on HAFNIUM activity"
		author = "Zach Stanford - @svch0st, Florian Roth"
		reference = "https://www.microsoft.com/security/blog/2021/03/02/hafnium-targeting-exchange-servers/#scan-log"
		reference_2 = "https://www.praetorian.com/blog/reproducing-proxylogon-exploit/"
		date = "2021-03-10"
		modified = "2021-03-15"
		score = 65
		id = "8b0110a9-fd03-5f7d-bdd8-03ff48bcac68"

	strings:
		$x1 = {((53 65 72 76 65 72 49 6e 66 6f 7e) | (53 00 65 00 72 00 76 00 65 00 72 00 49 00 6e 00 66 00 6f 00 7e 00))}
		$sr1 = /\/ecp\/[0-9a-zA-Z]{1,3}\.js/ ascii wide
		$s1 = {((2f 65 63 70 2f 61 75 74 68 2f 77 2e 6a 73) | (2f 00 65 00 63 00 70 00 2f 00 61 00 75 00 74 00 68 00 2f 00 77 00 2e 00 6a 00 73 00))}
		$s2 = {((2f 6f 77 61 2f 61 75 74 68 2f 77 2e 6a 73) | (2f 00 6f 00 77 00 61 00 2f 00 61 00 75 00 74 00 68 00 2f 00 77 00 2e 00 6a 00 73 00))}
		$s3 = {((2f 6f 77 61 2f 61 75 74 68 2f 78 2e 6a 73) | (2f 00 6f 00 77 00 61 00 2f 00 61 00 75 00 74 00 68 00 2f 00 78 00 2e 00 6a 00 73 00))}
		$s4 = {((2f 65 63 70 2f 6d 61 69 6e 2e 63 73 73) | (2f 00 65 00 63 00 70 00 2f 00 6d 00 61 00 69 00 6e 00 2e 00 63 00 73 00 73 00))}
		$s5 = {((2f 65 63 70 2f 64 65 66 61 75 6c 74 2e 66 6c 74) | (2f 00 65 00 63 00 70 00 2f 00 64 00 65 00 66 00 61 00 75 00 6c 00 74 00 2e 00 66 00 6c 00 74 00))}
		$s6 = {((2f 6f 77 61 2f 61 75 74 68 2f 43 75 72 72 65 6e 74 2f 74 68 65 6d 65 73 2f 72 65 73 6f 75 72 63 65 73 2f 6c 6f 67 6f 6e 2e 63 73 73) | (2f 00 6f 00 77 00 61 00 2f 00 61 00 75 00 74 00 68 00 2f 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 2f 00 74 00 68 00 65 00 6d 00 65 00 73 00 2f 00 72 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 2f 00 6c 00 6f 00 67 00 6f 00 6e 00 2e 00 63 00 73 00 73 00))}

	condition:
		$x1 and 1 of ( $s* )
}

rule LOG_CVE_2021_27065_Exchange_Forensic_Artefacts_Mar21_2 : LOG hardened
{
	meta:
		description = "Detects suspicious log entries that indicate requests as described in reports on HAFNIUM activity"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.praetorian.com/blog/reproducing-proxylogon-exploit/"
		date = "2021-03-10"
		score = 65
		id = "37a26def-b360-518e-a4ab-9604a5b39afd"

	strings:
		$sr1 = /GET \/rpc\/ &CorrelationID=<empty>;&RequestId=[^\n]{40,600} (200|301|302)/

	condition:
		$sr1
}

