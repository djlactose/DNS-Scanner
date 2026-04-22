#!/usr/bin/env pwsh
$ErrorActionPreference = 'Stop'

$image = 'djlactose/dnsscaner'
$platforms = 'linux/amd64,linux/arm64'

# Use a named buildx builder so repeated builds hit the same cache.
$builderName = 'dnsscanner-builder'
$existing = docker buildx ls --format '{{.Name}}' 2>$null
if ($existing -notcontains $builderName) {
    docker buildx create --name $builderName --use | Out-Null
} else {
    docker buildx use $builderName | Out-Null
}

# Build, attest, and push in one shot. SBOM + provenance attestations are
# what Docker Scout reads to grade supply-chain posture — without these the
# image cannot earn the top rating.
docker buildx build `
    --platform $platforms `
    --sbom=true `
    --provenance=mode=max `
    --tag "$($image):latest" `
    --push `
    .

# Post-push Scout report for the freshly pushed image.
if (Get-Command docker -ErrorAction SilentlyContinue) {
    Write-Host "`n--- Docker Scout quickview ---"
    docker scout quickview "$($image):latest"
}
