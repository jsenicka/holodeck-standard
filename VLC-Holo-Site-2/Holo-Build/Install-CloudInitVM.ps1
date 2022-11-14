function Install-CloudInitVM
{
<#
.SYNOPSIS
  Deploy a VM from an OVA file and use cloud-init for the configuration
  .DESCRIPTION
  This function will deploy an OVA file.
  The function transfer the user-data to the cloud-init process on the VM with
  one of the OVF properties.
.NOTES
  Author:  Luc Dekens
  Version:
  1.0 05/12/19  Initial release
.PARAMETER OvaFile
  Specifies the path to the OVA file
.PARAMETER VmName
  The displayname of the VM
.PARAMETER ClusterName
  The cluster onto which the VM shall be deployed
.PARAMETER DsName
  The datastore on which the VM shall be deployed
.PARAMETER PgName
  The portgroupname to which the VM shall be connected
.PARAMETER CloudConfig
  The path to the YAML file containing the user-data
.PARAMETER Credential
  The credentials for a user in the VM's guest OS
.EXAMPLE
  $sCloudInitVM = @{
    OvaFile = '.\bionic-server-cloudimg-amd64.ova'
    VmName = $vmName
    ClusterName = $clusterName
    DsName = $dsName
    PgName = $pgName
    CloudConfig = '.\user-data.yaml'
    Credential = $cred
  }
  Install-CloudInitVM @sCloudInitVM
#>

  [cmdletbinding()]
  param(
    [string]$OvaFile,
    [string]$VmName,
    [string]$ClusterName,
    [string]$VMFolder,
    [string]$DsName,
    [string]$PgName,
    [string]$CloudConfig,
    [PSCredential[]]$Credential
  )

  $waitJob = (Get-Command -Name .\Wait-Job.ps1).ScriptBlock
  $userData = Get-Content -Path $CloudConfig -Raw

  Write-Verbose "$(Get-Date -Format 'HH:mm:ss.fff') - Starting deployment of $vmName"

  $start = Get-Date

  $vm = Get-VM -Name $vmName -ErrorAction SilentlyContinue
  if ($vm)
  {
    Write-Verbose "$(Get-Date -Format 'HH:mm:ss.fff') - Cleaning up"
    if ($vm.PowerState -eq 'PoweredOn')
    {
      Stop-VM -VM $vm -Confirm:$false | Out-Null
    }
    Remove-VM -VM $vm -DeletePermanently -Confirm:$false
  }

  $ovfProp = Get-OvfConfiguration -Ovf $ovaFile
  $ovfProp.Common.user_data.Value = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($userData))
  $ovfProp.NetworkMapping.VM_Network.Value = $pgName

  $sApp = @{
    Source = $ovaFile
    Name = $vmName
    Datastore = Get-Datastore -Name $dsName
    InventoryLocation = $VMFolder
    DiskStorageFormat = 'Thin'
    VMHost = Get-Cluster -Name $clusterName | Get-VMHost | Get-Random
    OvfConfiguration = $ovfProp
  }
  Write-Verbose "$(Get-Date -Format 'HH:mm:ss.fff') - Importing OVA"
  $vm = Import-VApp @sApp

  Write-Verbose "$(Get-Date -Format 'HH:mm:ss.fff') - Starting the VM"
  Start-VM -VM $vm -Confirm:$false -RunAsync | Out-Null

  Write-Verbose "$(Get-Date -Format 'HH:mm:ss.fff') - Waiting for cloud-init to finish"

  $User = $Credential.GetNetworkCredential().UserName
  $Password = $Credential.GetNetworkCredential().Password

  $sJob = @{
    Name = 'WaitForCloudInit'
    ScriptBlock = $waitJob
    ArgumentList = $vm.Name, $User, $Password, $global:DefaultVIServer.Name, $global:DefaultVIServer.SessionId
  }
  Start-Job @sJob | Receive-Job -Wait

  Write-Verbose "$(Get-Date -Format 'HH:mm:ss.fff') - Deployment complete"

  Write-Verbose "`nDeployment took $([math]::Round((New-TimeSpan -Start $start -End (Get-Date)).TotalSeconds,0)) seconds"
}