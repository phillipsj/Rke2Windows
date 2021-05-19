$ErrorActionPreference = "Stop"
# Local
$serverIp = Get-Content -Path C:\sync\server
$requiredWindowsFeatures = @("Containers")
$kubernetesPath = "C:\k"
$serviceCidr = "10.42.0.0/16"
$dnsServers = "10.43.0.10"
$cniBinDir = "c:\opt\cni\bin"
$cniConfDir = "c:\etc\cni\net.d"

# Looad modules here
Write-Host "Loading modules...."
Import-Module C:\vagrant\modules\rke2.psm1 
Import-Module C:\vagrant\modules\rke2-calico.psm1 

# Checking windows features
Write-Host "Checking Windows features...."
Get-WindowsFeatures -RequiredFeatures $requiredWindowsFeatures -InstallFeatures

# Setup 
New-Item -ItemType Directory -Path $kubernetesPath -Force > Out-Null

Write-Host "Generating Kube Config...."
New-Item -ItemType Directory -Path $kubernetesPath\etc -Force > Out-Null
(Get-Content -Path C:\sync\config).Replace("127.0.0.1", $serverIp) | Set-Content -Path $kubernetesPath\config

Install-Containerd
Install-CNI

# Get K8s components
Install-K8sComponents -Path $kubernetesPath

# Adding Defender Exclusions
Add-DefenderExclusions -ExcludeList @("$kubernetesPath\kubelet.exe", "$kubernetesPath\kube-proxy.exe", "$kubernetesPath\wins.exe", "$Env:ProgramFiles\containerd\containerd.exe")

# Get HNS Module
Install-HNSModule -Path $kubernetesPath
Import-Module $kubernetesPath\hns.psm1 -DisableNameChecking

# Kubelet Config
#Write-Host "Getting kubelet config...."
#Invoke-Curl -Uri https://raw.githubusercontent.com/nickgerace/vista/main/kubelet-config.yaml -OutFile $kubernetesPath\kubelet-config.yaml
# TODO: Determine if we should just use the kubelet-config.yaml or be dynamic and use the CLI flags.

# Installing Calico
Write-Host "Installing Calico...."
Get-Calico -ServiceCidr $serviceCidr -DNSServerIPs $dnsServers

# Starting Kubelet
Write-Host "Starting Kube services...."
c:\CalicoWindows\kubernetes\install-kube-services.ps1

Start-Service kubelet
while ((Get-Service kubelet).Status -ne 'Running') { Start-Sleep -s 2 }

Start-Service "kube-proxy"
while ((Get-Service "kube-proxy").Status -ne 'Running') { Start-Sleep -s 2 }

# Configure Calico
Write-Host "Configuring Calico...."
c:\CalicoWindows\install-calico.ps1

exit 0