<#
.SYNOPSIS
    Creates the honeypot VM in Azure: Ubuntu 24.04, Cowrie on port 22, admin SSH on 22222.

.DESCRIPTION
    - Public port 22 is open to the internet (that is the point of a honeypot).
    - Admin SSH (22222) is only reachable from -AdminSourceIp (defaults to your current public IP).
    - The VM gets a system-assigned managed identity, which deploy.ps1 can grant
      "Monitoring Metrics Publisher" on the DCR so the shipper needs no secrets.
    - The VM sits in its own VNet with nothing else in it. Never peer that VNet with production.

.EXAMPLE
    ./honeypot/deploy-vm.ps1 -ResourceGroup rg-ai-soc -Location eastus
#>
[CmdletBinding()]
param(
    [string]$ResourceGroup = "rg-ai-soc",
    [string]$Location = "eastus",
    [string]$VmName = "vm-cowrie",
    [string]$VmSize = "Standard_B1s",
    [string]$AdminSourceIp,
    [string]$SshPublicKeyPath = (Join-Path $HOME ".ssh\id_ed25519.pub")
)

$ErrorActionPreference = "Stop"
$HoneypotDir = Split-Path -Parent $MyInvocation.MyCommand.Path

function Invoke-Az {
    $output = & az @args
    if ($LASTEXITCODE -ne 0) { throw "az $($args -join ' ') failed with exit code $LASTEXITCODE" }
    return $output
}

if (-not $AdminSourceIp) {
    $AdminSourceIp = (Invoke-RestMethod -Uri "https://api.ipify.org").Trim()
    Write-Host "Admin access restricted to your current IP: $AdminSourceIp"
}
if (-not (Test-Path $SshPublicKeyPath)) { throw "SSH public key not found at $SshPublicKeyPath (ssh-keygen -t ed25519)" }

Invoke-Az group create -n $ResourceGroup -l $Location -o none

Write-Host "Creating network security group"
$nsg = "$VmName-nsg"
Invoke-Az network nsg create -g $ResourceGroup -n $nsg -l $Location -o none
Invoke-Az network nsg rule create -g $ResourceGroup --nsg-name $nsg -n allow-honeypot-ssh --priority 100 `
    --direction Inbound --access Allow --protocol Tcp --source-address-prefixes Internet --destination-port-ranges 22 -o none
Invoke-Az network nsg rule create -g $ResourceGroup --nsg-name $nsg -n allow-admin-ssh --priority 110 `
    --direction Inbound --access Allow --protocol Tcp --source-address-prefixes "$AdminSourceIp/32" --destination-port-ranges 22222 -o none

Write-Host "Creating VM $VmName ($VmSize)"
Invoke-Az vm create -g $ResourceGroup -n $VmName -l $Location --size $VmSize `
    --image Canonical:ubuntu-24_04-lts:server:latest `
    --admin-username azureuser --ssh-key-values $SshPublicKeyPath `
    --nsg $nsg --nsg-rule NONE --public-ip-sku Standard `
    --vnet-name "$VmName-vnet" --subnet honeypot --private-ip-address 10.0.0.4 `
    --custom-data (Join-Path $HoneypotDir "cloud-init.yaml") `
    --assign-identity -o none

$publicIp = Invoke-Az vm show -d -g $ResourceGroup -n $VmName --query publicIps -o tsv
$principalId = Invoke-Az vm show -g $ResourceGroup -n $VmName --query identity.principalId -o tsv

Write-Host ""
Write-Host "VM ready at $publicIp (cloud-init needs a few minutes to move sshd and install Docker)." -ForegroundColor Green
Write-Host ""
Write-Host "Next steps:"
Write-Host "  1. Let the VM's identity ship logs:"
Write-Host "       ./siem/infra/deploy.ps1 -ResourceGroup $ResourceGroup -ShipperPrincipalId $principalId"
Write-Host "  2. Copy the code and your .env (with the DCE/DCR values) to the VM:"
Write-Host "       scp -P 22222 -r honeypot ingestion requirements.txt .env azureuser@$($publicIp):/opt/ai-soc-pipeline/"
Write-Host "  3. Start Cowrie and the shipper:"
Write-Host "       ssh -p 22222 azureuser@$publicIp 'cd /opt/ai-soc-pipeline/honeypot && docker compose up -d --build'"
Write-Host "  4. Check that events arrive (allow ~5 minutes for first ingestion):"
Write-Host "       Cowrie_CL | summarize count() by eventid"
