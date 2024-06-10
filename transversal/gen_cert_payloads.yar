// source : https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/gen_cert_payloads.yar#L4

rule SUSP_certificate_payload {
   meta:
      description = "Detects payloads that pretend to be certificates"
      date = "2018/08/02"
      author = "Didier Stevens, Florian Roth"
      reference = "https://blog.nviso.be/2018/08/02/powershell-inside-a-certificate-part-3/"
      score = 50
      id = "6f1fe410-591a-5a59-a683-67cad9777dfe"
   strings:
      $re1 = "-----BEGIN CERTIFICATE-----"

      $fp1 = "replace it with the PEM-encoded root certificate"
   condition:
      uint32(0) == 0x2D2D2D2D
      and $re1 at 0
      /* not 'M' at position 29, which is after the BEGIN CERTIFICATE header plus line break */
      /* \r\n */
      and not uint8(29) == 0x4D
      /* \n */
      and not uint8(28) == 0x4D
      and not 1 of ($fp*)
}
