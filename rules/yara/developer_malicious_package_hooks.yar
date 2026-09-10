rule Suspicious_Developer_Package_Lifecycle_Hooks
{
    meta:
        description = "Detects package.json and setup.py manifests where an install-time lifecycle hook VALUE contains an execution, decoding, or remote-retrieval primitive"
        author = "Kyle Reid"
        date = "2026-09-05"
        status = "experimental"
        scope = "file"
        reference = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-059a"
        measurement = "docs/detections/evaluation-package-manifests.json"
        revision_note = "v2: hook matching is scoped to the hook's own JSON value. v1 matched primitives anywhere in the file, which produced a measured 0.51% false-positive rate on a benign npm tree (n=1755), firing on popular HTTP libraries whose keywords or descriptions mention curl, wget, or Buffer."

    strings:
        // A lifecycle hook whose VALUE contains an evaluation or decoding
        // primitive. Value scoping is what separates a hook that executes a
        // decoded payload from a package that merely mentions encoding.
        // (\\" | [^"]) walks a JSON string body including escaped quotes,
        // which install hooks routinely contain: "node -e \"...\"".
        $json_hook_exec = /"(preinstall|postinstall|prepare|postpack|prepublish)"[ \t]*:[ \t]*"(\\"|[^"]){0,600}(eval|atob|Buffer|base64|Function\()/ nocase

        // A lifecycle hook whose VALUE retrieves remote content or spawns a
        // shell. The download cradle form of the same lure.
        $json_hook_net = /"(preinstall|postinstall|prepare|postpack|prepublish)"[ \t]*:[ \t]*"(\\"|[^"]){0,600}(curl |wget |https?:\/\/|child_process|Invoke-WebRequest)/ nocase

        // setup.py install-time execution: setuptools command override.
        $py_cmdclass = "cmdclass" nocase
        $py_install_run = "install.run(self)" nocase

        // Primitives that make a command override meaningful.
        $py_net_urllib = "urllib" nocase
        $py_net_requests = "requests." nocase
        $py_exec = "exec(" nocase
        $py_eval = "eval(" nocase
        $py_b64 = "b64decode" nocase
        $py_subprocess = "subprocess" nocase
        $py_url = /https?:\/\// nocase

    condition:
        filesize < 2MB and
        (
            any of ($json_hook_*)
            or
            (
                any of ($py_cmdclass, $py_install_run) and
                (
                    (any of ($py_net_urllib, $py_net_requests) and $py_url)
                    or any of ($py_exec, $py_eval, $py_b64, $py_subprocess)
                )
            )
        )
}
