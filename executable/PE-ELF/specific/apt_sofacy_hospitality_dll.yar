import "pe"

rule APT28_HospitalityMalware_mvtband_file : hardened
{
	meta:
		description = "Yara Rule for mvtband.dll malware"
		author = "CSE CybSec Enterprise - Z-Lab"
		reference = "http://csecybsec.com/download/zlab/APT28_Hospitality_Malware_report.pdf"
		last_updated = "2017-10-02"
		tlp = "white"
		id = "f9e34c77-38b3-513e-bb29-148ac7058596"

	strings:
		$a = {44 47 4d 4e 4f 45 50}
		$b = {C7 45 94 0A 25 73 30 8D 45 94}

	condition:
		all of them and pe.sections [ 2 ] . raw_data_size == 0
}

