# Global
$global:NODENAME = $env:COMPUTERNAME
$global:K8S_SERVICE_CIDR = "10.42.0.0/16"
$global:DNS_NAME_SERVERS = "10.43.0.10"
$global:KUBECONFIG = "$PSScriptRoot\calico-kube-config"
$global:CNI_BIN_DIR = "c:\opt\cni\bin"
$global:CNI_CONF_DIR = "c:\etc\cni\net.d"
$global:CALICO_DATASTORE_TYPE = "kubernetes"

# Local
$serverIp = Get-Content -Path C:\sync\server
$requiredWindowsFeatures = @("Containers")
$kubernetesPath = "C:\k"

Write-Output "[INFO]  Generating Kube Config...."
New-Item -ItemType Directory -Path $env:kubernetesPath\etc -Force > Out-Null
(Get-Content -Path C:\sync\config).Replace("127.0.0.1", $serverIp) | Set-Content -Path $kubernetesPath\config

Install-Module C:\vagrant\modules\rke2.psm1
Install-Module C:\vagrant\modules\rke2-calico.psm1

Get-WindowsFeature -RequiredWindowsFeatures $requiredWindowsFeatures -InstallFeatures

Install-Containerd
Install-CNI

# Get K8s components
New-Item -ItemType Directory -Path $kubernetesPath -Force > $null
Install-K8sComponents -Path $kubernetesPath

# Adding Defender Exclusions
Add-DefenderExclusions -ExcludeList @("$kubernetesPath\kubelet.exe", "$kubernetesPath\kube-proxy.exe", "$kubernetesPath\wins.exe", "$Env:ProgramFiles\containerd\containerd.exe")

# Get HNS Module
Install-HNSModule -Path $kubernetesPath
Import-Module $kubernetesPath\hns.psm1

# Kubelet Config
Write-Output "[Info]  Getting kubelet config...."
Invoke-RestMethod -Uri https://raw.githubusercontent.com/nickgerace/vista/main/kubelet-config.yaml -OutFile $kubernetesPath\kubelet-config.yaml

# Installing Calico
Write-Output "[INFO]  Installing Calico...."
Get-Calico -ServiceCidr $global:K8S_SERVICE_CIDR -DNSServerIPs $global:DNS_NAME_SERVERS

# Starting Kubelet
Start-Kubelet -NodeName $global:NODENAME -DnsServerIps $global:DNS_NAME_SERVERS

# Configure Calico
Write-Output "[INFO]  Configuring Calico...."
c:\CalicoWindows\install-calico.ps1

Write-Output "[INFO]  Getting Source IP...."
$sourceIp = Get-SourceVip

# Starting KubeProxy
Start-KubeProxy -NodeName $global:NODENAME -SourceIp $sourceIp -ServiceCidr $global:K8S_SERVICE_CIDR
exit 0