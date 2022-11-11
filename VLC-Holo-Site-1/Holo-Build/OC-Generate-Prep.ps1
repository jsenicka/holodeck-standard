Connect-VIServer -Server vcenter-mgmt.vcf.sddc.lab -User administrator@vsphere.local -Password VMware123!
New-VICredentialStoreItem -host OC-MySQL -User ocuser -Password VMware123!
New-VICredentialStoreItem -host OC-Apache-A -User ocuser -Password VMware123!
New-VICredentialStoreItem -host OC-Apache-B -User ocuser -Password VMware123!
New-VICredentialStoreItem -host OC-Apache-C -User ocuser -Password VMware123!
New-VICredentialStoreItem -host Holo-Template -User ocuser -Password VMware123!