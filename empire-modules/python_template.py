from empire.server.common.empire import MainMenu
from empire.server.core.module_models import EmpireModule
from empire.server.utils.module_util import handle_error_message


class Module:
    """
    STOP. In most cases you will not need this file.
    Take a look at the wiki to see if you truly need this.
    https://bc-security.gitbook.io/empire-wiki/module-development/python-modules
    """

    @staticmethod
    def generate(
        main_menu: MainMenu,
        module: EmpireModule,
        params: dict,
        obfuscate: bool = False,
        obfuscation_command: str = "",
    ) -> tuple[str | None, str | None]:
        # Step 1: Get the module source code
        # The script should be stripped of comments, with a link to any
        #   original reference script included in the comments.
        # If your script is more than a few lines, it's probably best to use
        #   the first method to source it.
        #
        # First method: Read in the source script from module_source
        # get_module_source will return the source code, getting the obfuscated version if necessary.
        # (In the case of python, obfuscation is not supported)
        # It will also return an error message if there was an issue reading the source code.
        script, err = main_menu.modulesv2.get_module_source(
            module_name=module.script_path,
            obfuscate=obfuscate,
            obfuscate_command=obfuscation_command,
        )

        if err:
            return handle_error_message(err)

        # Second method: Use the script from the module's yaml.
        script = module.script

        # Step 2: Parse the module options, and insert them into the script
        # The params dict contains the validated options that were sent.
        for key, value in params.items():
            if key.lower() != "agent" and key.lower() != "computername":
                script = script.replace("{{ " + key + " }}", value).replace(
                    "{{" + key + "}}", value
                )

        # Step 3: Return the final script
        return script
