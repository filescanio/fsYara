// source: https://www.cyfirma.com/research/inside-firescam-an-information-stealer-with-spyware-capabilities/

rule FireScam_Malware_Indicators {
meta:
    description = "Detects FireScam malware based on file hashes, URLs, and network indicators"
    author = "Cyfirma Research"
    score = 70
    last_modified = "2024-12-25"
strings:
    $md5_1 = "5d21c52e6ea7769be45f10e82b973b1e" ascii
    $md5_2 = "cae5a13c0b06de52d8379f4c61aece9c" ascii
    $sha256_1 = "b041ff57c477947dacd73036bf0dee7a0d6221275368af8b6dbbd5c1ab4e981b" ascii
    $sha256_2 = "12305b2cacde34898f02bed0b12f580aff46531aa4ef28ae29b1bf164259e7d1" ascii
    $url_1 = "https://androidscamru-default-rtdb.firebaseio.com" ascii
    $url_2 = "https://s-usc1b-nss-2100.firebaseio.com/.ws?ns=androidscamru-default-rtdb&v=5&ls=" ascii
    $url_3 = "https://rustore-apk.github.io/telegram_premium/" ascii
condition:
    ($md5_1 or $md5_2 or $sha256_1 or $sha256_2) or
    ($url_1 or $url_2 or $url_3)
}

