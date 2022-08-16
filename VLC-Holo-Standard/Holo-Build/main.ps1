#region Prep work
# PowerCLI configuration
Set-PowerCLIConfiguration -ParticipateInCeip:$false -DisplayDeprecationWarnings:$false -Scope AllUsers,User,Session -Confirm:$false | Out-Null

# Disable the progress bar on all cmdlets
$ProgressPreference = 'SilentlyContinue'

# dot source Install-CloudInitVM
. .\Install-CloudInitVM.ps1
#endregion

#region Config data
# Environment configuration data
$mainJSON = '.\holo-generate-v1.json'
$main = Get-Content -Path $mainJSON | ConvertFrom-Json
#endregion

#region Outer loop (Sets)
$setNr = 1
foreach($set in $main.Sets){
Write-Host -ForegroundColor Magenta "Deploying Set $setnr"

#region Inner loop (Instances)
  foreach($instance in $set.Instances){
    Write-Host -ForegroundColor Yellow "`tInstance $($instance.HostName)" -NoNewline

    # Create instance YAML from template YAML
    $tempFile = New-TemporaryFile
    Get-Content -Path ".\$($instance.YamlTemplate)" -PipelineVariable line |
    ForEach-Object -Process {
      $instance | Get-Member -MemberType NoteProperty |
      where {$_.Name -ne 'YamlTemplate'} |
      ForEach-Object -Process {
        $line = $line -replace "##$($_.Name)##",$instance."$($_.Name)"
      }
      $line
    } | Set-Content -Path $tempFile

    # Create VM

    # Get credential for logging on to the guest OS (VICredentialStore version)
    #$viCred = Get-VICredentialStoreItem -Host $instance.HostName
    #$secPassword = ConvertTo-SecureString -String $viCred.Password -AsPlainText -Force
    #$cred = [Management.Automation.PSCredential]::new($viCred.User, $secPassword)

    # Get credential for loggin on to the guest OS (SecretStore version)
    $cred = Get-Secret -Name $instance.HostName

    # Create destination folder if it does not exist
    try{
        Get-Folder -Name $main.VMFolder -Type VM -ErrorAction Stop | Out-Null
    }
    catch{
        New-Folder -Name $main.VMFolder -Location 'vm' -Confirm:$false | Out-Null
    }

    # Start the import
    $sCloudInitVM = @{
      OvaFile = $main.OvaFile
      VmName = $instance.HostName
      ClusterName = $main.Cluster
      VMFolder = Get-Folder -Name $main.VMFolder -Type VM
      DsName = $main.Datastore
      PgName = $main.Portgroup
      CloudConfig = $tempFile.FullName
      Credential = $cred
#      Verbose = $true
    }
    Install-CloudInitVM @sCloudInitVM
    write-host -ForegroundColor Green "`tCompleted"

    # Remove temp file
    Remove-Item -Path $tempFile -Confirm:$false
  }
#endregion Inner loop (Instances)

  Write-Host -ForegroundColor Magenta "Set $setnr completed"
  $setNr++
}
#endregion Outer loop (Sets)