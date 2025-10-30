from empire.server.common.empire import MainMenu
from empire.server.core.module_models import EmpireModule
from empire.server.utils.module_util import handle_error_message


class Module:
    """
    STOP. In most cases you will not need this file.
    Take a look at the wiki to see if you truly need this.
    https://bc-security.gitbook.io/empire-wiki/module-development/powershell-modules
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
        # It will also return an error message if there was an issue reading the source code.
        script, err = main_menu.modulesv2.get_module_source(
            module_name=module.script_path,
            obfuscate=obfuscate,
            obfuscate_command=obfuscation_command,
        )

        if err:
            return handle_error_message(err)

        # If you'd just like to import a subset of the functions from the
        #   module source, use the following:
        #   script = helpers.generate_dynamic_powershell_script(module_code, ["Get-Something", "Set-Something"])

        # Second method: Use the script from the module's yaml.
        script = module.script

        # Step 2: Parse the module options
        # The params dict contains the validated options that were sent.
        script_end = ""
        # Add any arguments to the end execution of the script
        for option, values in params.items():
            if option.lower() != "agent" and values and values != "":
                if values.lower() == "true":
                    # if we're just adding a switch
                    script_end += " -" + str(option)
                else:
                    script_end += " -" + str(option) + " " + str(values)

        # Step 3: Return the final script
        # finalize_module will obfuscate the "script_end" (if needed), then append it to the script.
        return main_menu.modulesv2.finalize_module(
            script=script,
            script_end=script_end,
            obfuscate=obfuscate,
            obfuscation_command=obfuscation_command,
        )
