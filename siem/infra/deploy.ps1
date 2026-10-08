<#
.SYNOPSIS
    Deploys the Sentinel side of the AI SOC pipeline.

.DESCRIPTION
    1. Resource group + Log Analytics workspace, with Microsoft Sentinel enabled
    2. Cowrie_CL custom table (table-schema.json)
    3. Data collection endpoint + rule for the Logs Ingestion API (dcr-cowrie.json)
    4. "Monitoring Metrics Publisher" on the DCR for you and, optionally, the honeypot's managed identity
    5. One scheduled analytics rule per detections/kql/*.kql file (metadata from the file headers)
    6. The honeypot overview workbook

    Idempotent: re-running updates everything in place. Requires Azure CLI 2.50+ and `az login`.

.EXAMPLE
    ./siem/infra/deploy.ps1 -ResourceGroup rg-ai-soc -Location eastus

.EXAMPLE
    # After creating the honeypot VM, let its managed identity ship logs (and run triage):
    $id = az vm show -g rg-ai-soc -n vm-cowrie --query identity.principalId -o tsv
    ./siem/infra/deploy.ps1 -ShipperPrincipalId $id -TriagePrincipalId $id
#>
[CmdletBinding()]
param(
    [string]$ResourceGroup = "rg-ai-soc",
    [string]$Location = "eastus",
    [string]$WorkspaceName = "law-ai-soc",
    [string]$ShipperPrincipalId,
    # Identity that runs the triage job (VM, container app, automation account): gets
    # Log Analytics Reader (to run detections) and Microsoft Sentinel Responder (to comment/update incidents).
    [string]$TriagePrincipalId,
    [switch]$SkipAnalyticsRules,
    [switch]$SkipWorkbook
)

$ErrorActionPreference = "Stop"
$InfraDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = (Resolve-Path (Join-Path $InfraDir "..\..")).Path
$TmpDir = Join-Path ([IO.Path]::GetTempPath()) "ai-soc-deploy"
New-Item -ItemType Directory -Force -Path $TmpDir | Out-Null
$Arm = "https://management.azure.com"

function Invoke-Az {
    # Runs az and throws on a non-zero exit code, so failures stop the script.
    $output = & az @args
    if ($LASTEXITCODE -ne 0) { throw "az $($args -join ' ') failed with exit code $LASTEXITCODE" }
    return $output
}

function Write-JsonFile([string]$Path, $Object) {
    # UTF-8 without BOM: az rest cannot parse a body file that starts with a BOM.
    $json = if ($Object -is [string]) { $Object } else { $Object | ConvertTo-Json -Depth 20 }
    [IO.File]::WriteAllText($Path, $json, (New-Object Text.UTF8Encoding $false))
    return $Path
}

function Get-StableGuid([string]$Seed) {
    $md5 = [Security.Cryptography.MD5]::Create()
    return ([guid]::new($md5.ComputeHash([Text.Encoding]::UTF8.GetBytes($Seed)))).ToString()
}

function Grant-Publisher([string]$PrincipalId, [string]$PrincipalType, [string]$Scope) {
    $existing = Invoke-Az role assignment list --assignee $PrincipalId --role "Monitoring Metrics Publisher" --scope $Scope --query "[].id" -o tsv
    if ($existing) { Write-Host "    already assigned to $PrincipalId"; return }
    Invoke-Az role assignment create --assignee-object-id $PrincipalId --assignee-principal-type $PrincipalType `
        --role "Monitoring Metrics Publisher" --scope $Scope -o none
    Write-Host "    granted to $PrincipalType $PrincipalId"
}

$SubscriptionId = Invoke-Az account show --query id -o tsv
Write-Host "Subscription $SubscriptionId, resource group $ResourceGroup ($Location)"

# 1. Workspace + Sentinel ---------------------------------------------------------------
Write-Host "[1/6] Log Analytics workspace + Microsoft Sentinel"
Invoke-Az group create -n $ResourceGroup -l $Location -o none
Invoke-Az monitor log-analytics workspace create -g $ResourceGroup -n $WorkspaceName -l $Location --retention-time 90 -o none
$WorkspaceResourceId = Invoke-Az monitor log-analytics workspace show -g $ResourceGroup -n $WorkspaceName --query id -o tsv
$WorkspaceCustomerId = Invoke-Az monitor log-analytics workspace show -g $ResourceGroup -n $WorkspaceName --query customerId -o tsv
$body = Write-JsonFile (Join-Path $TmpDir "onboarding.json") '{"properties":{}}'
Invoke-Az rest --method put -o none `
    --url "$Arm$WorkspaceResourceId/providers/Microsoft.SecurityInsights/onboardingStates/default?api-version=2024-03-01" `
    --body "@$body"

# 2. Custom table ----------------------------------------------------------------------
Write-Host "[2/6] Cowrie_CL table"
Invoke-Az rest --method put -o none `
    --url "$Arm$WorkspaceResourceId/tables/Cowrie_CL?api-version=2022-10-01" `
    --body "@$(Join-Path $InfraDir 'table-schema.json')"

# 3. DCE + DCR ---------------------------------------------------------------------------
Write-Host "[3/6] Data collection endpoint + rule"
$outputs = Invoke-Az deployment group create -g $ResourceGroup -n "cowrie-dcr" `
    --template-file (Join-Path $InfraDir "dcr-cowrie.json") `
    --parameters workspaceResourceId=$WorkspaceResourceId location=$Location `
    --query properties.outputs -o json | Out-String | ConvertFrom-Json
$IngestionEndpoint = $outputs.logsIngestionEndpoint.value
$DcrImmutableId = $outputs.dcrImmutableId.value
$DcrResourceId = $outputs.dcrResourceId.value

# 4. RBAC ---------------------------------------------------------------------------------
Write-Host "[4/6] Monitoring Metrics Publisher on the DCR"
try {
    $me = Invoke-Az ad signed-in-user show --query id -o tsv
    Grant-Publisher $me "User" $DcrResourceId
} catch {
    Write-Warning "Could not resolve the signed-in user (service principal login?); grant the role manually if you ship from this machine."
}
if ($ShipperPrincipalId) { Grant-Publisher $ShipperPrincipalId "ServicePrincipal" $DcrResourceId }
if ($TriagePrincipalId) {
    foreach ($role in "Log Analytics Reader", "Microsoft Sentinel Responder", "Microsoft Sentinel Contributor") {
        # Responder covers comments and incident updates; Contributor is needed only to publish the IOC watchlist.
        $existing = Invoke-Az role assignment list --assignee $TriagePrincipalId --role $role --scope $WorkspaceResourceId --query "[].id" -o tsv
        if (-not $existing) {
            Invoke-Az role assignment create --assignee-object-id $TriagePrincipalId --assignee-principal-type ServicePrincipal `
                --role $role --scope $WorkspaceResourceId -o none
        }
        Write-Host "    $role -> $TriagePrincipalId"
    }
}

# 5. Analytics rules -------------------------------------------------------------------
if (-not $SkipAnalyticsRules) {
    Write-Host "[5/6] Analytics rules"
    foreach ($file in Get-ChildItem (Join-Path $RepoRoot "detections\kql") -Filter *.kql | Sort-Object Name) {
        $meta = @{}
        foreach ($line in Get-Content $file.FullName) {
            if ($line -match '^//\s*([a-z_]+)\s*:\s*(.*?)\s*$') { $meta[$Matches[1]] = $Matches[2] }
            elseif ($line.Trim() -and -not $line.TrimStart().StartsWith("//")) { break }
        }
        # Sentinel takes parent technique ids here; sub-techniques stay documented in the KQL header.
        $techniques = @($meta.techniques -split "," | ForEach-Object { ($_.Trim() -split "\.")[0] } | Select-Object -Unique)
        $tactics = @($meta.tactics -split "," | ForEach-Object { $_.Trim() } | Where-Object { $_ })
        $rule = @{
            kind       = "Scheduled"
            properties = @{
                displayName           = "Cowrie - $($meta.name)"
                description           = $meta.description
                severity              = $meta.severity
                enabled               = $true
                query                 = (Get-Content $file.FullName -Raw)
                queryFrequency        = $meta.frequency
                queryPeriod           = $meta.period
                triggerOperator       = "GreaterThan"
                triggerThreshold      = 0
                suppressionDuration   = "PT1H"
                suppressionEnabled    = $false
                tactics               = $tactics
                techniques            = $techniques
                entityMappings        = @(@{ entityType = "IP"; fieldMappings = @(@{ identifier = "Address"; columnName = "src_ip" }) })
                eventGroupingSettings = @{ aggregationKind = "AlertPerResult" }
                incidentConfiguration = @{
                    createIncident        = $true
                    groupingConfiguration = @{
                        enabled              = $true
                        reopenClosedIncident = $false
                        lookbackDuration     = "PT6H"
                        matchingMethod       = "AllEntities"
                        groupByEntities      = @()
                        groupByAlertDetails  = @()
                        groupByCustomDetails = @()
                    }
                }
            }
        }
        $ruleId = Get-StableGuid "ai-soc-pipeline/$($file.BaseName)"
        $body = Write-JsonFile (Join-Path $TmpDir "rule-$($file.BaseName).json") $rule
        Invoke-Az rest --method put -o none `
            --url "$Arm$WorkspaceResourceId/providers/Microsoft.SecurityInsights/alertRules/$($ruleId)?api-version=2024-03-01" `
            --body "@$body"
        Write-Host "    $($file.BaseName) -> $($meta.name) [$($meta.severity)]"
    }
}

# 6. Workbook ----------------------------------------------------------------------------
if (-not $SkipWorkbook) {
    Write-Host "[6/6] Workbook"
    $workbookId = Get-StableGuid "ai-soc-pipeline/honeypot-overview"
    $workbook = @{
        location   = $Location
        kind       = "shared"
        properties = @{
            displayName    = "Cowrie Honeypot Overview"
            category       = "sentinel"
            sourceId       = $WorkspaceResourceId
            serializedData = (Get-Content (Join-Path $RepoRoot "siem\workbooks\honeypot-overview.json") -Raw)
        }
    }
    $body = Write-JsonFile (Join-Path $TmpDir "workbook.json") $workbook
    Invoke-Az rest --method put -o none `
        --url "$Arm/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.Insights/workbooks/$($workbookId)?api-version=2022-04-01" `
        --body "@$body"
}

Write-Host ""
Write-Host "Done. Add these to .env (and to the honeypot's shipper environment):" -ForegroundColor Green
Write-Host "AZURE_DCE_ENDPOINT=$IngestionEndpoint"
Write-Host "AZURE_DCR_IMMUTABLE_ID=$DcrImmutableId"
Write-Host "AZURE_DCR_STREAM=Custom-Cowrie_CL"
Write-Host "AZURE_LOG_ANALYTICS_WORKSPACE_ID=$WorkspaceCustomerId"
Write-Host "AZURE_WORKSPACE_RESOURCE_ID=$WorkspaceResourceId"
Write-Host ""
Write-Host "Role assignments can take a few minutes to apply; the first uploads may return 403 until then."
