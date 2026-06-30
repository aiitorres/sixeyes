rule Suspicious_Indicators {
    meta:
        description = "Detects plain-text patterns commonly tied to basic malware scripts"
        author = "SixEyes"
    strings:
        $url = /https?:\/\/([\w\.-]+)/
        $cmd = "cmd.exe" ascii nocase
        $ps = "powershell.exe" ascii nocase
    condition:
        any of them
}
