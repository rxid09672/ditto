import base64
import json

from empire.server.common.empire import MainMenu
from empire.server.core.module_models import EmpireModule
from empire.server.utils.bof_packer import process_arguments


class Module:
    @staticmethod
    def generate(
        main_menu: MainMenu,
        module: EmpireModule,
        params: dict,
        obfuscate: bool = False,
        obfuscation_command: str = "",
    ):
        script_file = main_menu.dotnet_compiler.compile_task(
            module.compiler_yaml,
            module.name,
            dot_net_version=params["DotNetVersion"].lower(),
            confuse=obfuscate,
        )

        params_dict = {}
        params_dict["Entrypoint"] = params["EntryPoint"]
        params_dict["File"] = params["File"].get_base64_file()
        params_dict["HexData"] = process_arguments(
            params["Format String"], params["Arguments"]
        )

        param_json = json.dumps(params_dict)
        base64_json = base64.b64encode(param_json.encode("utf-8")).decode("utf-8")

        return f"{script_file}|,{base64_json}"
