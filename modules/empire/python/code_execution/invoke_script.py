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
            module_name=module.script_path
        )

        script_end = "\nmain(None,"

        if params["File"]:
            encoded_script = params["File"].get_base64_file()
            script_end += f" None, '{encoded_script}'"
        elif params["ScriptUrl"]:
            script_end += f" '{params['ScriptUrl']}'"

        if params.get("FunctionCommand"):
            script_end += f", '{params['FunctionCommand']}'"

        script_end += ")"  # Ensure we close the parentheses here

        return script + script_end
