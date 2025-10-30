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
        script, err = main_menu.modulesv2.get_module_source(
            module_name=module.script_path,
            obfuscate=obfuscate,
            obfuscate_command=obfuscation_command,
        )

        script_end = "\nInvoke-Script"

        if params["File"]:
            encoded_script = params["File"].get_base64_file()
            script_end += f" -EncodedScript '{encoded_script}'"
        elif params["ScriptUrl"]:
            script_end += " -ScriptUrl '" + str(params["ScriptUrl"]) + "'"

        script_end += " -FunctionCommand '" + str(params["FunctionCommand"]) + "'"

        return main_menu.modulesv2.finalize_module(
            script=script,
            script_end=script_end,
            obfuscate=obfuscate,
            obfuscation_command=obfuscation_command,
        )
