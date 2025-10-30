import pathlib

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
        # read in the common powerview.ps1 module source code
        module_source = (
            main_menu.installPath
            + "/data/module_source/situational_awareness/network/powerview.ps1"
        )
        if obfuscate:
            obfuscated_module_source = module_source.replace(
                "module_source", "obfuscated_module_source"
            )
            if pathlib.Path(obfuscated_module_source).is_file():
                module_source = obfuscated_module_source

        try:
            with open(module_source) as f:
                module_code = f.read()
        except Exception:
            return handle_error_message(
                "[!] Could not read module source path at: " + str(module_source)
            )

        if obfuscate and not pathlib.Path(obfuscated_module_source).is_file():
            script = main_menu.obfuscationv2.obfuscate(module_code, obfuscation_command)
        else:
            script = module_code

        script_end = "\nGet-DomainOU "

        for option, values in params.items():
            if (
                (
                    option.lower() != "agent"
                    and option.lower() != "guid"
                    and option.lower() != "outputfunction"
                )
                and values
                and values != ""
            ):
                if values.lower() == "true":
                    # if we're just adding a switch
                    script_end += " -" + str(option)
                else:
                    script_end += " -" + str(option) + " " + str(values)

        script_end += (
            "-GPLink "
            + str(params["GUID"])
            + " | %{ Get-DomainComputer -SearchBase $_.distinguishedname"
        )

        for option, values in params.items():
            if (
                (
                    option.lower() != "agent"
                    and option.lower() != "guid"
                    and option.lower() != "outputfunction"
                )
                and values
                and values != ""
            ):
                if values.lower() == "true":
                    # if we're just adding a switch
                    script_end += " -" + str(option)
                else:
                    script_end += " -" + str(option) + " " + str(values)

        outputf = params.get("OutputFunction", "Out-String")
        script_end += (
            f"}} | {outputf}  | "
            + '%{$_ + "`n"};"`n'
            + str(module.name.split("/")[-1])
            + ' completed!"'
        )

        if obfuscate:
            script_end = main_menu.obfuscationv2.obfuscate(
                script_end, obfuscation_command
            )
        script += script_end
        return main_menu.obfuscationv2.obfuscate_keywords(script)
