rule DAC_PHP_Webshell_Command_Exec
{
    meta:
        description = "PHP file that evaluates decoded input or passes request parameters to OS command functions"
        author = "José Javier González García"
        mitre_technique_id = "T1505.003"
        mitre_tactic_id = "TA0003"

    strings:
        $php = "<?php" nocase
        $eval_b64 = /eval\s*\(\s*base64_decode\s*\(/ nocase
        $exec_input = /(system|passthru|shell_exec|exec|popen)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)\s*\[/ nocase

    condition:
        filesize < 200KB and $php and ($eval_b64 or $exec_input)
}
