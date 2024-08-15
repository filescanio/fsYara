// source: https://github.com/Neo23x0/signature-base/blob/master/yara/apt_sofacy_hospitality.yar

import "pe"

rule APT28_HospitalityMalware_mvtband_file {
   meta:
      description = "Yara Rule for mvtband.dll malware"
      author = "CSE CybSec Enterprise - Z-Lab"
      reference = "http://csecybsec.com/download/zlab/APT28_Hospitality_Malware_report.pdf"
      last_updated = "2017-10-02"
      tlp = "white"
      id = "f9e34c77-38b3-513e-bb29-148ac7058596"
   strings:
      $a = "DGMNOEP"
      $b = {C7 45 94 0A 25 73 30 8D 45 94}  // two significant instructions
   condition:
      all of them and pe.sections[2].raw_data_size == 0
}
