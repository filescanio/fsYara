// source: https://github.com/advanced-threat-research/Yara-Rules/blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/ransomware/RANSOM_netwalker.yar

import "pe"

rule netwalker_ransomware
    
    {
        meta:

            description = "Rule to detect Netwalker ransomware"
            author = "McAfee ATR Team"
            date = "2020-03-30"
            rule_version = "v1"
            malware_type = "ransomware"
            reference = "https://www.ccn-cert.cni.es/comunicacion-eventos/comunicados-ccn-cert/9802-publicado-un-informe-de-codigo-danino-sobre-netwalker.html"
            note = "The rule doesn't detect the samples packed with UPX"
            
        strings:

            $pattern = { 8B????8B????89??C7????????????EB??8B????52E8????????83????8B????8B??5DC3CCCCCCCCCCCCCCCCCCCCCCCC558B??83????C7????????????83??????74??83??????72??83??????75??8B????E9????????C7????????????8B????33??B9????????F7??83????89????8B????8B????8D????51E8????????83????89????83??????0F84????????C7????????????C7????????????C6??????C6??????C6??????8B????3B????0F84????????8B????2B????39????73??8B????89????EB??8B????2B????89????8B????89????C7????????????8B????03????8B????2B??89????74??83??????7E??83??????7D??C7????????????8B????03????89????8B????518B????03????528B????03????50E8????????83????8B????03????89????83??????75??6A??8D????528B????03????50E8????????83????8B????83????89????8B????03????89????E9????????8B????8B????89??83??????74??8B????52E8????????83????8B????89??C7????????????8B????8B??5DC3CCCCCCCC558B??51B8????????6B????8B????0FB6????B9????????C1????8B????0FB6????C1????0B??BA????????D1??8B????0FB6????C1????0B??B9????????6B????8B????0FB6????C1????0B??B9????????C1????8B????89????B8????????6B????8B????0FB6??????B9????????C1????8B????0FB6??????C1????0B??BA????????D1??8B????0FB6??????C1????0B??B9????????6B????8B????0FB6??????C1????0B??B9????????6B????8B????89????BA????????6B????8B????0FB6??????B8????????C1????8B????0FB6??????C1????0B??B9????????D1??8B????0FB6??????C1????0B??B8????????6B????8B????0FB6??????C1????0B??B8????????6B????8B????89????B9????????6B????8B????0FB6??????BA????????C1????8B????0FB6??????C1????0B??B8????????D1??8B????0FB6??????C1????0B??BA????????6B????8B????0FB6??????C1????0B??BA????????6B????8B????89????81????????????75??8B????83????89????C7????????????EB??C7????????????B9????????6B????8B????0FB6????BA????????C1????8B????0FB6????C1????0B??B8????????D1??8B????0FB6????C1????0B??BA????????6B????8B????0FB6????C1????0B??BA????????C1????8B????89????B9????????6B????8B????0FB6??????BA????????C1????8B????0FB6??????C1????0B??B8????????D1??8B????0FB6??????C1????0B??BA????????6B????8B????0FB6??????C1????0B??BA????????6B????8B????89????B8????????6B????8B????0FB6??????B9????????C1????8B????0FB6??????C1????0B??BA????????D1??8B????0FB6??????C1????0B??B9????????6B????8B????0FB6??????C1????0B??B9????????6B????8B????89????BA????????6B????8B????0FB6??????B8????????C1????8B????0FB6??????C1????0B??B9????????D1??8B????0FB6??????C1????0B??B8????????6B????8B????0FB6??????C1????0B??B8????????6B????8B????89????B9????????6B????8B????0FBE????BA????????C1????8B????0FBE????C1????0B??B8????????D1??8B????0FBE????C1????0B??BA????????6B????8B????0FBE????C1????0B??BA????????6B????8B????89????B8????????6B????8B????0FBE??????B9????????C1????8B????0FBE??????C1????0B??BA????????D1??8B????0FBE??????C1????0B??B9????????6B????8B????0FBE??????C1????0B??B9????????C1????8B????89????B8????????6B????8B????0FBE??????B9????????C1????8B????0FBE??????C1????0B??BA????????D1??8B????0FBE??????C1????0B??B9????????6B????8B????0FBE??????C1????0B??B9????????D1??8B????89????B8????????6B????8B????0FBE??????B9????????C1????8B????0FBE??????C1????0B??BA????????D1??8B????0FBE??????C1????0B??B9????????6B????8B????0FBE??????C1????0B??B9????????6B????8B????89????8B??5DC3CCCCCC558B??B8????????6B????8B????C7????????????B8????????6B????8B????C7????????????B8????????6B????8B????0FB6????B9????????C1????8B????0FB6????C1????0B??BA????????D1??8B????0FB6????C1????0B??B9????????6B????8B????0FB6????C1????0B??B9????????6B????8B????89????BA????????6B????8B????0FB6??????B8????????C1????8B????0FB6??????C1????0B??B9????????D1??8B????0FB6??????C1????0B??B8????????6B????8B????0FB6??????C1????0B??B8????????6B????8B????89????5DC3CCCCCC558B??83????83??????75??E9????????8B????508D????51E8????????83????BA????????6B????8B????8B????83????B8????????6B????8B????89????B9????????6B????8B????83??????75??B9????????6B????8B????8B????83????BA????????6B????8B????89????83??????77??C7????????????EB??8B????83????89????8B????3B????73??8B????03????0FB6??8B????0FB6??????33??8B????03????88??EB??EB??C7????????????EB??8B????83????89????83??????73??8B????03????0FB6??8B????0FB6??????33??8B????03????88??EB??8B????83????89????8B????83????89????8B????83????89????E9????????8B??5DC3CCCCCCCCCCCCCCCC558B??83????C7????????????EB??8B????83????89????83??????7D??8B????8B????8B????8B????89??????EB??C7????????????EB??8B????83????89????83??????0F8E????????B9????????6B????B8????????C1????8B??????03??????BA????????6B????89??????B9????????6B????B8????????6B????8B??????33??????C1????B8????????6B????B8????????6B????8B??????33??????C1????0B??B8????????6B????89??????BA????????C1????B8????????6B????8B??????03??????B8????????C1????89??????B9????????C1????BA????????C1????8B??????33??????C1????B9????????C1????BA????????C1????8B??????33??????C1????0B??BA????????C1????89??????B8????????6B????BA????????C1????8B??????03??????B9????????6B????89??????B8????????6B????BA????????6B????8B??????33??????C1????BA????????6B????BA????????6B????8B??????33??????C1????0B??BA????????6B????89??????B9????????C1????BA????????6B????8B??????03??????BA????????C1????89??????B8????????C1????B9????????C1????8B??????33??????C1????B8????????C1????B9????????C1????8B??????33??????C1????0B??B9????????C1????89??????BA????????C1????B8????????6B????8B??????03??????B8????????C1????89??????B9????????6B????B8????????C1????8B??????33??????C1????BA????????6B????BA????????C1????8B??????33??????C1????0B??BA????????6B????89??????B9????????6B????B8????????6B????8B??????03??????B8????????6B????89??????BA????????6B????B9????????6B????8B??????33??????C1????B9????????6B????B9????????6B????8B??????33??????C1????0B??B9????????6B????89??????B8????????C1????B9????????6B????8B??????03??????B9????????C1????89??????BA????????6B????B9????????C1????8B??????33??????C1????B8????????6B????B8????????C1????8B??????33??????C1????0B??B8????????6B????89??????BA????????6B????B9????????6B????8B??????03??????B9????????6B????89??????B8????????6B????BA????????6B????8B??????33??????C1????BA????????6B????BA????????6B????8B??????33??????C1????0B??BA????????6B????89??????B9????????D1??BA????????6B????8B??????03??????BA????????D1??89??????B8????????6B????BA????????D1??8B??????33??????C1????B9????????6B????B9????????D1??8B??????33??????C1????0B??B9????????6B????89??????B8????????6B????BA????????6B????8B??????03??????BA????????6B????89??????B9????????6B????B8????????6B????8B??????33??????C1????B8????????6B????B8????????6B????8B??????33??????C1????0B??B8????????6B????89??????BA????????D1??B8????????6B????8B??????03??????B8????????D1??89??????B9????????6B????B8????????D1??8B??????33??????C1????BA????????6B????BA????????D1??8B??????33??????C1????0B??BA????????6B????89??????B9????????6B????B8????????6B????8B??????03??????B8????????6B????89??????BA????????6B????B9????????6B????8B??????33??????C1????B9????????6B????B9????????6B????8B??????33??????C1????0B??B9????????6B????89??????B8????????6B????BA????????6B????8B??????03??????BA????????6B????89??????B9????????6B????B8????????6B????8B??????33??????C1????B8????????6B????B8????????6B????8B??????33??????C1????0B??B8????????6B????89??????BA????????6B???? }

            $pattern2 = { CCCCCCCCCCA1????????C3CCCCCCCCCCCCCCCCCCCC538B??????5533??5785??74??8B??????85??74??8B????85??74??C1????50E8????????83????89??85??74??8B????5633??85??74??5653E8????????83????85??74??8B????85??74??8D??????89??????5150E8????????83????85??74??8B????8B??8B??????89????FF????8B????463B??72??39????B9????????5E0F44??5F8B??5D5BC35F5D33??5BC3CCCCCCCCCCCCCCCCCCCCCCCCCCCC535556578B??????85??74??83????74??8B????85??74??8B??????85??74??33??85??74??8B??????660F1F??????85??74??8B??53FF????E8????????EB??E8????????8D????8B??FF????8B??53FF??83????85??75??463B????72??5F5E5D33??5BC35F5E5DB8????????5BC3CCCCCCCCCCCCCCCCCCCCCCCCCCCCCC6A??FF??????FF??????E8????????83????C3CCCCCCCCCCCCCCCCCCCCCCCCCC6A??FF??????FF??????E8????????83????C3CCCCCCCCCCCCCCCCCCCCCCCCCC83????????????5674??8B??????85??74??56E8????????8B????50E8????????83????85??75??A1????????6A??83????5650E8????????83????85??75??56E8????????83????85??74??8D????66??????74??83????83????75??33??5EC383????74??A1????????6A??83????5150E8????????83????85??74??B8????????5EC3CCCCCCCCCCCCCCCCCCCC83????????????74??8B??????85??74??A1????????6A??83????5150E8????????83????85??74??B8????????C333??C3CCCCCCCCCCCCCCCCCCCCCCCCCCCC83????????????5674??A1????????83??????74??8B??????85??74??56E8????????8B??????????83????83????75??83??????74??66????????75??0FB7??83????72??83????76??83????66??????76??6A??8D????5650E8????????83????85??74??B8????????5EC333??5EC3CCCCCCCCCCCCCCCCCCCCCCCCCCCC83????????????74??A1????????83????????????74??8B??????85??74??6A??05????????5150E8????????83????85??74??B8????????C333??C3CCCCCC83????????????74??A1????????83????????????74??8B??????85??74??6A??05????????5150E8????????83????85??74??B8????????C333??C3CCCCCC83????????????74??8B??????85??74??A1????????83??????74??6A??83????5150E8????????83????85??74??B8????????C333??C3CCCCCCCCCCCCCCCC83????????????74??8B??????85??74??A1????????83??????74??6A??83????5150E8????????83????85??74??B8????????C333??C3CCCCCCCCCCCCCCCC83????????????5674??8B??????85??74??A1????????83??????74??51E8????????8B??83????85??74??8B??????????6A??83????5651E8????????83????85??74??B8????????5EC356E8????????83????33??5EC3CCCCCCCCCCCCCC535556576A??E8????????8B??83????85??0F84????????8B??660F1F??????0FB7????83????51E8????????8B??83????85??74??0FB7????51FF????57E8????????83????83????????????74??A1????????83??????74??6A??83????5750E8????????83????85??74??E8????????8B????3B????74??6A??51E8????????8B??83????85??74??E8????????6A??538B????FF??E8????????538B??????????FF??57E8????????83????8B??03??85??0F85????????55E8????????83????E8????????6A??8B??????????FF??E9????????CCCCCCCCCCCCCC83????5533??565739??????????0F84????????8B??????85??0F84????????8B??????85??0F84????????53E8????????8B??????????FF??83??????8B??74??E8????????FF????8B??????????FF??89??????E8????????8D??????516A??8B??????????8D??????516A??57FF??85??74??8B??????89????83????74??E8????????8B??????????FF??2B??3D????????77??83??????75??5B5F5E8B??5D83????C3BD????????5B5F5E8B??5D83????C35F5E33??5D83????C383????558B??????85??0F84????????5333??5733??89??????89??????E8????????8D??????518D??????8B??????????5157576A??FF????FF??85??0F85????????E8????????8B??????????FF??3D????????0F85????????FF??????E8????????83????89??????85??0F84????????56E8????????8D??????518D??????8B??????????51FF??????FF??????6A??FF????FF??85??74??33??39??????76??8B??????0F1F??????????E8????????8B??????68????????FF????8B??????????FF??FF??89??????8D????????????5053E8????????8B??83????85??74??FF??????68????????E8????????83????89????474683????3B??????72??8B??????FF??????E8????????83????85??74??85??74??E8????????6A??6A??538B??????????57FF??33??85??74??E8????????FF????8B??????????FF??463B??72??53E8????????83????5EE8????????8D??????516A??FF????8B??????????FF??5F5B85??74??8D??????50FF????E8????????83????E8????????FF????8B??????????FF??55E8????????83????33??5D83????C2????CCCCCCCCCCCCCCCCCCCCCCCC83????568B??????85??74??E8????????8D??????516A??8B??????????56FF??85??74??8D??????5056E8????????83????E8????????568B??????????FF??33??5E83????C2????CCCCCCCCCCCC83????83????????????5356570F84????????A1????????83??????0F84????????55E8????????68????????6A??6A??8B??????????FF??8B??89??????85??0F84????????660F1F????????????C7??????????????C7??????????????C7??????????????E8????????8D??????518D??????8B??????????518D??????516A??6A??6A??6A??55FF??85??0F85????????E8????????8B??????????FF??3D????????0F85????????FF??????E8????????83????89??????85??0F84????????E8????????8B??????8D??????518D??????8B??????????518D??????51FF??????566A??6A??55FF??85??0F84????????33??33??89??????39??????0F86????????0F1F??????????FF??E8????????83????85??75??FF????E8????????83????85??74??E8????????68????????FF??8B??????????55FF??89??????85??74??6A??E8????????8B??83????85??74??8B??????8D????????????5189????8B??????5389????E8????????8B??83????85??74??5568????????E8????????83????89????478B??????8B??????83????4089??????3B??????0F82????????85??74??85??74??E8????????6A??6A??538B??????????57FF??33??85??74??0F1F????E8????????FF????8B??????????FF??463B??72??53E8????????83????FF??????E8????????83????E8????????68????????8B??????????FF??E9????????5D5F5E33??5B83????C2????CCCCCC83????53558B??????565785??0F84????????8B????8D??????516A??55C7??????????????FF????85??0F88????????8B??????8D??????C7??????????????52508B??FF????85??0F88????????6A??8D??????6A??50E8????????33??83????B8????????66????????39??????0F8E????????8B??????8D??????5083????C7??????????????438B??89??????0F10??????8B??510F11??FF????85??0F88????????8B??????8D??????C7??????????????52508B??FF????85??0F88????????8B??????8D??????C7??????????????33??52508B??FF????83????????0F84????????FF??????E8????????83????85??0F85????????8B??????8D??????89??????52508B??FF????85??0F88????????8B??????8D??????89??????52508B??FF????85??0F88????????8B??????8D??????89??????52508B??FF????85??0F88????????33?? }

            $pattern3 = { CCCCCCCCCC558B??FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF??????????68????????FF??????????FF?????????? }

        condition:
            
            uint16(0) == 0x5a4d and
            any of ($pattern*) 
}

rule netwalker_signed {
    
   meta:
   
        description = "Rule to detect Netwalker ransomware digitally signed."
        author = "Marc Rivero | McAfee ATR Team"
        reference = "https://www.ccn-cert.cni.es/comunicacion-eventos/comunicados-ccn-cert/9802-publicado-un-informe-de-codigo-danino-sobre-netwalker.html"
        date = "2020-03-30"
        note = "The rule will hit also some Dridex samples digitally signed"
        
    condition:
    
      uint16(0) == 0x5a4d and
      for any i in (0 .. pe.number_of_signatures) : (
         pe.signatures[i].subject contains "/CN=EWBTCAXQKUMDTHCXCZ"  and
         pe.signatures[i].serial == "17:16:bb:93:fb:a9:a2:41:ba:a8:2e:c7:5e:ff:0c" or
         pe.signatures[i].thumbprint == "a4:28:e9:4a:61:3a:1f:cf:ff:08:bf:e7:61:51:64:31:1a:6f:87:bc")
}

rule Netwalker {

    meta:

        description = "Rule based on code overlap in RagnarLocker ransomware"
        author = "McAfee ATR team"
        date = "2020-06-14"
        rule_version = "v1"
        malware_type = "ransomware"
        actor_group = "Unknown"

  strings:

    $0 = {C88BF28B4330F76F3803C88B434813F2F76F2003C88B433813F2F76F3003C88B434013F2F76F2803C88B432813F2F76F4003C8894D6813F289756C8B4338F76F388BC88BF28B4328F76F4803C88B434813F2F76F2803C88B433013F2F76F400FA4CE}
    $1 = {89542414895424108BEA8BDA8BFA423C22747C3C5C75588A023C5C744F3C2F744B3C2274473C6275078D5702B008EB3F3C6675078D5302B00CEB343C6E75078D5502B00AEB293C72750B8B542410B00D83C202EB1A3C74750B8B542414B00983C2}
    $2 = {C8894D7013F28975748B4338F76F408BC88BF28B4340F76F3803C88B433013F2F76F4803C88B434813F2F76F3003C8894D7813F289757C8B4348F76F388BC88BF28B4338F76F4803C88B434013F2F76F400FA4CE}
    $3 = {C07439473C2F75E380FB2A74DEEB2D8D4ABF8D422080F9190FB6D80FB6C28AD60F47D88AC6042080EA410FB6C880FA190FB6C60F47C83ACB754B46478A1684D2}
    $4 = {8B433013F2F76F0803C88B432013F2F76F1803C88B0313F2F76F3803C88B430813F2F76F3003C88B433813F2F72F03C8894D3813F289753C8B4338F76F088BC8}
    $5 = {F73101320E32213234329832E3320C332D334733643383339133A833BD33053463347C34543564358335AE36C3362937E9379A39BA390A3A203A443A183B2B3B}
    $6 = {8B431813F2F76F4803C88B432813F2F76F3803C88B434013F2F76F200FA4CE0103C903C88B432013F2F76F4003C88B433013F2F76F3003C8894D6013F2897564}
  
  condition:

    uint16(0) == 0x5A4D and
    uint32(uint32(0x3C)) == 0x00004550 and 
    all of them
    }
    
rule win_netwalker_reflective_dll_injection_decoded {

    meta:

        description = "Rule to detect Reflective DLL Injection Powershell Script dropping Netwalker, after hexadecimal decoded and xor decrypted "
        author = "McAfee ATR Team"
        date = "2020-05-28"
        rule_version = "v1"
        malware_type = "ransomware"
        reference = "https://blog.trendmicro.com/trendlabs-security-intelligence/netwalker-fileless-ransomware-injected-via-reflective-loading/ | https://news.sophos.com/en-us/2020/05/27/netwalker-ransomware-tools-give-insight-into-threat-actor/"
        hash = "fd29001b8b635e6c51270788bab7af0bb5adba6917c278b93161cfc2bc7bd6ae"
        score = 75
        strings:

        // API addresses of the functions the script needs from kernel32.dll
        $api0 = { 5b 44 6c 6c 49 6d 70 6f 72 74 28 22 6b 65 72 6e 65 6c 33 32 2e 64 6c 6c 22 2c 53 65 74 4c 61 73 74 45 72 72 6f 72 20 3d 20 74 72 75 65 2c 20 45 6e 74 72 79 50 6f 69 6e 74 20 3d 20 22 56 69 72 74 75 61 6c 41 6c 6c 6f 63 22 29 5d }
        // [DllImport("kernel32.dll",SetLastError = true, EntryPoint = "VirtualAlloc")]
        $api1 = { 5b 44 6c 6c 49 6d 70 6f 72 74 28 22 6b 65 72 6e 65 6c 33 32 2e 64 6c 6c 22 2c 53 65 74 4c 61 73 74 45 72 72 6f 72 20 3d 20 74 72 75 65 2c 45 6e 74 72 79 50 6f 69 6e 74 20 3d 20 22 47 65 74 50 72 6f 63 41 64 64 72 65 73 73 22 29 5d }
        // [DllImport("kernel32.dll",SetLastError = true,EntryPoint = "GetProcAddress")]
        $api2 = { 5b 44 6c 6c 49 6d 70 6f 72 74 28 22 6b 65 72 6e 65 6c 33 32 2e 64 6c 6c 22 2c 53 65 74 4c 61 73 74 45 72 72 6f 72 20 3d 20 74 72 75 65 2c 45 6e 74 72 79 50 6f 69 6e 74 20 3d 20 22 4c 6f 61 64 4c 69 62 72 61 72 79 41 22 29 5d }
        // [DllImport("kernel32.dll",SetLastError = true,EntryPoint = "LoadLibraryA")]
        $api3 = { 5b 44 6c 6c 49 6d 70 6f 72 74 28 22 6b 65 72 6e 65 6c 33 32 2e 64 6c 6c 22 2c 53 65 74 4c 61 73 74 45 72 72 6f 72 20 3d 20 74 72 75 65 2c 45 6e 74 72 79 50 6f 69 6e 74 20 3d 20 22 57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 22 29 5d }
        // [DllImport("kernel32.dll",SetLastError = true,EntryPoint = "WriteProcessMemory")]
        $api4 = { 5b 44 6c 6c 49 6d 70 6f 72 74 28 22 6b 65 72 6e 65 6c 33 32 2e 64 6c 6c 22 2c 53 65 74 4c 61 73 74 45 72 72 6f 72 20 3d 20 74 72 75 65 2c 45 6e 74 72 79 50 6f 69 6e 74 20 3d 20 22 56 69 72 74 75 61 6c 46 72 65 65 22 29 5d }
        // [DllImport("kernel32.dll",SetLastError = true,EntryPoint = "VirtualFree")]
        $api5 = { 5b 44 6c 6c 49 6d 70 6f 72 74 28 22 6b 65 72 6e 65 6c 33 32 2e 64 6c 6c 22 2c 53 65 74 4c 61 73 74 45 72 72 6f 72 20 3d 20 74 72 75 65 2c 45 6e 74 72 79 50 6f 69 6e 74 20 3d 20 22 47 65 74 43 75 72 72 65 6e 74 50 72 6f 63 65 73 73 22 29 5d }
        // [DllImport("kernel32.dll",SetLastError = true,EntryPoint = "GetCurrentProcess")]
        $api6 = { 5b 44 6c 6c 49 6d 70 6f 72 74 28 22 6b 65 72 6e 65 6c 33 32 2e 64 6c 6c 22 2c 53 65 74 4c 61 73 74 45 72 72 6f 72 20 3d 20 74 72 75 65 2c 45 6e 74 72 79 50 6f 69 6e 74 20 3d 20 22 43 6c 6f 73 65 48 61 6e 64 6c 65 22 29 5d }
        // [DllImport("kernel32.dll",SetLastError = true,EntryPoint = "CloseHandle")]
        $api7 = { 5b 44 6c 6c 49 6d 70 6f 72 74 28 22 6b 65 72 6e 65 6c 33 32 2e 64 6c 6c 22 2c 20 53 65 74 4c 61 73 74 45 72 72 6f 72 3d 74 72 75 65 2c 45 6e 74 72 79 50 6f 69 6e 74 20 3d 20 22 56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 22 29 5d }
        // [DllImport("kernel32.dll", SetLastError=true,EntryPoint = "VirtualAllocEx")]
        $api8 = { 5b 44 6c 6c 49 6d 70 6f 72 74 28 22 6b 65 72 6e 65 6c 33 32 2e 64 6c 6c 22 2c 20 53 65 74 4c 61 73 74 45 72 72 6f 72 3d 74 72 75 65 2c 45 6e 74 72 79 50 6f 69 6e 74 20 3d 20 22 56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 45 78 22 29 5d }
        // [DllImport("kernel32.dll", SetLastError=true,EntryPoint = "VirtualProtectEx")]
        $api9 = { 5b 44 6c 6c 49 6d 70 6f 72 74 28 22 6b 65 72 6e 65 6c 33 32 2e 64 6c 6c 22 2c 20 53 65 74 4c 61 73 74 45 72 72 6f 72 20 3d 20 74 72 75 65 2c 45 6e 74 72 79 50 6f 69 6e 74 20 3d 20 22 4f 70 65 6e 50 72 6f 63 65 73 73 22 29 5d }
        // [DllImport("kernel32.dll", SetLastError = true,EntryPoint = "OpenProcess")]
        $api10 = { 5b 44 6c 6c 49 6d 70 6f 72 74 28 22 6b 65 72 6e 65 6c 33 32 2e 64 6c 6c 22 2c 45 6e 74 72 79 50 6f 69 6e 74 20 3d 20 22 43 72 65 61 74 65 52 65 6d 6f 74 65 54 68 72 65 61 64 22 29 5d }
        // [DllImport("kernel32.dll",EntryPoint = "CreateRemoteThread")]
        // Other Artifacts 
        $artifact0 = { 5b 44 6c 6c 49 6d 70 6f 72 74 28 22 6b 65 72 6e 65 6c 33 32 2e 64 6c 6c 22 2c 45 6e 74 72 79 50 6f 69 6e 74 20 3d 20 22 43 72 65 61 74 65 52 65 6d 6f 74 65 54 68 72 65 61 64 22 29 5d }
        // Get-WmiObject Win32_Shadowcopy | ForEach-Object {$_.Delete();} | Out-Null
        $artifact1 = { 53 79 73 74 65 6d 2e 52 75 6e 74 69 6d 65 2e 49 6e 74 65 72 6f 70 53 65 72 76 69 63 65 73 2e 4d 61 72 73 68 61 6c 5d 3a 3a 50 74 72 54 6f 53 74 72 75 63 74 75 72 65 }
        // System.Runtime.InteropServices.Marshal]::PtrToStructure
        $artifact2 = { 53 79 73 74 65 6d 2e 52 75 6e 74 69 6d 65 2e 49 6e 74 65 72 6f 70 53 65 72 76 69 63 65 73 2e 4d 61 72 73 68 61 6c 5d 3a 3a 52 65 61 64 49 6e 74 31 36 }
        // System.Runtime.InteropServices.Marshal]::ReadInt16
        $artifact3 = { 65 6e 76 3a 57 49 4e 44 49 52 5c 73 79 73 77 6f 77 36 34 5c 77 69 6e 64 6f 77 73 70 6f 77 65 72 73 68 65 6c 6c 5c 76 31 2e 30 5c 70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 22 20 2d 4e 6f 6e 49 6e 74 65 72 61 63 74 69 76 65 20 2d 4e 6f 50 72 6f 66 69 6c 65 20 2d 65 78 65 63 20 62 79 70 61 73 73}
        // env:WINDIR\syswow64\windowspowershell\v1.0\powershell.exe" -NonInteractive -NoProfile -exec bypass
        $artifact4 = { 65 6e 76 3a 57 49 4e 44 49 52 5c 73 79 73 77 6f 77 36 34 5c 77 69 6e 64 6f 77 73 70 6f 77 65 72 73 68 65 6c 6c 5c 76 31 2e 30 5c 70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 22 20 2d 4e 6f 6e 49 6e 74 65 72 61 63 74 69 76 65 20 2d 4e 6f 50 72 6f 66 69 6c 65 20 2d 65 78 65 63 20 62 79 70 61 73 73 20 2d 66 69 6c 65}
        // env:WINDIR\syswow64\windowspowershell\v1.0\powershell.exe" -NonInteractive -NoProfile -exec bypass -file
        $artifact5 = {5b 50 61 72 61 6d 65 74 65 72 28 50 6f 73 69 74 69 6f 6e 20 3d 20 30 20 2c 20 4d 61 6e 64 61 74 6f 72 79}
        // [Parameter(Position = 0 , Mandatory
        $artifact6 = {5b 50 61 72 61 6d 65 74 65 72 28 50 6f 73 69 74 69 6f 6e 20 3d 20 31 20 2c 20 4d 61 6e 64 61 74 6f 72 79}
        // [Parameter(Position = 1 , Mandatory
        $artifact7 = {2d 45 78 65 63 75 74 69 6f 6e 50 6f 6c 69 63 79 20 42 79 50 61 73 73 20 2d 4e 6f 4c 6f 67 6f 20 2d 4e 6f 6e 49 6e 74 65 72 61 63 74 69 76 65 20 2d 4e 6f 50 72 6f 66 69 6c 65 20 2d 4e 6f 45 78 69 74}
        // -ExecutionPolicy ByPass -NoLogo -NonInteractive -NoProfile -NoExit
        $artifact8 = {72 65 74 75 72 6e 20 5b 42 69 74 43 6f 6e 76 65 72 74 65 72 5d 3a 3a 54 6f 49 6e 74 36 34}
        // return [BitConverter]::ToInt64
        
        condition:

            6 of ($api*) or
            ( 
                (3 of ($artifact*))
            )
}
