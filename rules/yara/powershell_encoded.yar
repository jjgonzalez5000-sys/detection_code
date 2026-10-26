rule DAC_PowerShell_EncodedCommand
{
    meta:
        description = "Script or command line that launches PowerShell with a long Base64-encoded command"
        author = "José Javier González García"
        mitre_technique_id = "T1059.001"
        mitre_tactic_id = "TA0002"

    strings:
        $ps = "powershell" nocase
        // -e, -ec, -enc and -EncodedCommand followed by a long Base64 blob
        $enc = /\s-e(nc(odedcommand)?|c)?\s+[A-Za-z0-9+\/=]{40,}/ nocase

    condition:
        $ps and $enc
}
