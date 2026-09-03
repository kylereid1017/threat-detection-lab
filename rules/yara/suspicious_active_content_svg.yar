rule Suspicious_Active_Content_SVG_Attachment
{
    meta:
        description = "Detects SVG files combining active script, navigation, and an external destination"
        author = "Kyle Reid"
        date = "2026-09-03"
        status = "experimental"
        scope = "file"
        reference = "https://www.bleepingcomputer.com/news/security/phishing-attacks-use-svg-attachments-to-evade-detection/"

    strings:
        $svg_root = /<([a-zA-Z0-9_-]+:)?svg[\x09\x0a\x0d\x20>]/ nocase

        $active_script = /<([a-zA-Z0-9_-]+:)?script[\x09\x0a\x0d\x20>]/ nocase
        $active_handler = /on(load|click|error)[\x09\x0a\x0d\x20]*=/ nocase
        $javascript_uri = /javascript[\x09\x0a\x0d\x20]*:/ nocase

        $navigation = /(window\.)?location(\.href)?[\x09\x0a\x0d\x20]*=/ nocase
        $navigation_method = /(window\.)?location\.(assign|replace)[\x09\x0a\x0d\x20]*\(/ nocase
        $navigation_bracket = /(window\s*\[\s*['"]loc['"]\s*\+\s*['"]ation['"]|window\s*\[\s*['"]location['"]|(window\.)?location\s*\[\s*['"]href['"])/ nocase
        $window_open = /window\.open[\x09\x0a\x0d\x20]*\(/ nocase

        $external_http = "http://" nocase
        $external_https = "https://" nocase

    condition:
        filesize < 2MB and
        $svg_root in (0..4096) and
        1 of ($active_script, $active_handler, $javascript_uri) and
        1 of ($navigation, $navigation_method, $navigation_bracket, $window_open, $javascript_uri) and
        1 of ($external_http, $external_https)
}
