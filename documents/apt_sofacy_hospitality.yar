rule APT28_HospitalityMalware_document : hardened
{
	meta:
		description = "Yara Rule for APT28_Hospitality_Malware document identification"
		author = "CSE CybSec Enterprise - Z-Lab"
		reference = "http://csecybsec.com/download/zlab/APT28_Hospitality_Malware_report.pdf"
		last_updated = "2017-10-02"
		tlp = "white"
		id = "722e80ef-d729-5887-9853-cd06128f506d"

	strings:
		$a = {75 52 B9 ED 1B D6 83 0F DB 24 CA 87 4F 5F 25 36 BF 66 BA}
		$b = {EC 3B 6D 74 5B C5 95 F3 9E 24 5B FE 4A 64 C7 09 CE 07 C9 58 4E 62 3B}

	condition:
		all of them and filesize > 75KB and filesize < 82KB
}

