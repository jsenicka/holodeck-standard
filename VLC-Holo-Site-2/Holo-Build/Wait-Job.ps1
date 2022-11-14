[CmdletBinding()]
param(
    [string]$vmName,
    [string]$user,
    [string]$pswd,
    [string]$vcsaName,
    [string]$SessionId
)

#$VerbosePreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'

Write-Verbose "Wait job running"

$sleepTime = 5
Write-Verbose "Wait: connect to VCSA"
Connect-VIServer -Server $vcsaName -Session $SessionId | Out-Null
$notFinished = $true
while ($notFinished)
{
    Try
    {
        Write-Verbose "Wait: Invoke script on $($vm.Name)"
        $vm = Get-VM -Name $vmName -ErrorAction Stop
        while ($vm.PowerState -ne 'PoweredOn' -and -not $vm.ExtensionData.Guest.GuestOperationsReady)
        {
            Start-Sleep -Seconds $sleepTime
        }
        $fileExist = $false
        while (-not $fileExist)
        {
            $sInvoke = @{
                VM = $vm
                ScriptType = 'bash'
                ScriptText = '[ -f /var/lib/cloud/instance/boot-finished ] && echo "File exist"'
                GuestUser = $user
                GuestPassword = $pswd
                ErrorAction = 'Stop'
            }
            try
            {
                $result = Invoke-VMScript @sInvoke
                $fileExist = [Boolean]$result.ScriptOutput
            }
            catch
            {
                Write-Verbose "$(Get-Date -Format 'HH:mm:ss.fff') Exception:`tId: $($error[0].Exception.ErrorId)  Category: $($error[0].Exception.ErrorCategory)"
                Write-Verbose "$(Get-Date -Format 'HH:mm:ss.fff')`t`tLine: $($error[0].InvocationInfo.Line)"
            }
        }
        $sInvoke = @{
            VM = $vm
            ScriptType = 'bash'
            ScriptText = 'cat /var/lib/cloud/instance/boot-finished'
            GuestUser = $user
            GuestPassword = $pswd
        }
        $result = Invoke-VMScript @sInvoke
        #$result.ScriptOutput
        $notFinished = $false
    }
    catch
    {
        Write-Verbose "$(Get-Date -Format 'HH:mm:ss.fff') Exception:`tId: $($error[0].Exception.ErrorId)  Category: $($error[0].Exception.ErrorCategory)"
        Write-Verbose "$(Get-Date -Format 'HH:mm:ss.fff')`t`tLine: $($error[0].InvocationInfo.Line)"
    }
    Start-Sleep -Seconds $sleepTime
}
