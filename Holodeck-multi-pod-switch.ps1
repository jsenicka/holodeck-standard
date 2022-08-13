Connect-VIServer -Server my-server.home.lab -User root -Password 'ESXiserverPassword'
New-VirtualSwitch -Name VLC-A -Mtu 9000 
New-VirtualSwitch -Name VLC-B -Mtu 9000 
New-VirtualSwitch -Name VLC-C -Mtu 9000 
New-VirtualSwitch -Name VLC-D -Mtu 9000 
New-VirtualPortGroup -Name VLC-A-PG -VirtualSwitch VLC-A -VLanId 4095
New-VirtualPortGroup -Name VLC-B-PG -VirtualSwitch VLC-B -VLanId 4095
New-VirtualPortGroup -Name VLC-C-PG -VirtualSwitch VLC-C -VLanId 4095
New-VirtualPortGroup -Name VLC-D-PG -VirtualSwitch VLC-D -VLanId 4095
Get-VirtualPortGroup -Name VLC-A-PG | Get-SecurityPolicy |  Set-SecurityPolicy     -AllowPromiscuous $true -ForgedTransmits $true -MacChanges $true
Get-VirtualPortGroup -Name VLC-B-PG | Get-SecurityPolicy |  Set-SecurityPolicy     -AllowPromiscuous $true -ForgedTransmits $true -MacChanges $true
Get-VirtualPortGroup -Name VLC-C-PG | Get-SecurityPolicy |  Set-SecurityPolicy     -AllowPromiscuous $true -ForgedTransmits $true -MacChanges $true
Get-VirtualPortGroup -Name VLC-D-PG | Get-SecurityPolicy |  Set-SecurityPolicy     -AllowPromiscuous $true -ForgedTransmits $true -MacChanges $true