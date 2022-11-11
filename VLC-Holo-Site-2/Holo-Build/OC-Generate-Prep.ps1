Connect-VIServer -Server vcenter-mgmt.vcf2.sddc.lab -User administrator@vsphere.local -Password VMware123!
New-VICredentialStoreItem -host Holo-Template -User ocuser -Password VMware123!