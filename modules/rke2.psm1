function Confirm-WindowsFeatures {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [String[]]
        $RequiredFeatures
    )
    $allFeaturesInstalled = $true
    foreach ($feature in $RequiredFeatures) {
        $f = Get-WindowsFeature -Name $feature
        if (-not $f.Installed) {
            Write-Warning "[WARN]  Windows feature: '$feature' is not installed."
            $allFeaturesInstalled = $false
        }
    }
    return $allFeaturesInstalled
}

function Get-WindowsFeatures {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [String[]]
        $RequiredFeatures,
        [Parameter()]
        [Switch]
        $InstallFeatures
    )

    if (-not (Confirm-WindowsFeatures -RequiredFeatures $RequiredFeatures)) {
        if ($InstallFeatures) {
            Write-Output "[INFO]  Installing required windows features...."
    
            foreach ($feature in $requiredWindowsFeatures) {
                Install-WindowsFeature -Name $feature
            }
    
            Write-Output "[INFO]  Please reboot and re-run this script...."
            exit 0
        }
        else {
            Write-Output "[INFO]  Required windows features are not installed...."
    
            foreach ($feature in $requiredWindowsFeatures) {
                Write-Output "Install-WindowsFeature -Name $feature"
            }
    
            Write-Output "[INFO]  Please run the commands above to install...."
            exit 0
        }
    }
}

function Invoke-Curl {
    [CmdletBinding()]
    param (
        [Parameter()]
        [String]
        $Uri,
        [Parameter()]
        [String]
        $OutFile
    )
    Write-Host("Downloading $Uri to $OutFile")
    curl.exe --silent --fail -Lo $OutFile $Uri

    if (!$?) {
        Write-Error "Download $Uri failed"
        exit 1
    }
}

function Install-Containerd {
    [CmdletBinding()]
    param (       
        [Parameter()]
        [String]
        $Version = "1.4.4",
        [Parameter()]
        [String]
        $Path = "$env:ProgramFiles\containerd"
    )
    Write-Output "Getting Containerd binaries"
    New-Item -ItemType Directory -Path $Path -Force > Out-Null
    Push-Location $Path
    Invoke-Curl -Uri "https://github.com/containerd/containerd/releases/download/v${Version}/containerd-${Version}-windows-amd64.tar.gz" -OutFile "containerd.tar.gz"
    tar.exe -xvf "containerd.tar.gz" --strip=1 -C $Path
    Remove-Item -Path containerd.tar.gz
    Rename-Item -Path "containerd-shim-runhcs-v1.exe" -NewName "containerd-shim-grpc-v1.exe"

    Invoke-Curl -Uri "https://github.com/kubernetes-sigs/cri-tools/releases/download/v1.21.0/crictl-v1.21.0-windows-amd64.tar.gz" -OutFile "crictl.tar.gz"
    tar.exe -xvf "crictl.tar.gz"
    Remove-Item -Path crictl.tar.gz
    Start-Process -FilePath "$Path\crictl.exe" -ArgumentList "config --set runtime-endpoint=npipe:////./pipe/containerd-containerd" -NoNewWindow

    Invoke-Curl -Uri "https://raw.githubusercontent.com/nickgerace/vista/main/config.toml" -OutFile "config.toml"

    Pop-Location

    Start-Process -FilePath "$Path\containerd.exe" -ArgumentList "--register-service" -NoNewWindow
    Start-Sleep 2

    Set-Service -Name containerd -StartupType Automatic
    Start-Service containerd    
}

function Install-CNI {
    [CmdletBinding()]
    param (
        [Parameter()]
        [String]
        $Path = "c:\opt",
        [Parameter()]
        [String]
        $EtcPath = "c:\etc"
    )
    Write-Output "Downloading CNI binaries"
    $cniPath = "$Path\cni"
    New-Item -ItemType Directory -Path $cniPath -Force > Out-Null
    New-Item -ItemType Directory -Path $cniPath\bin -Force > Out-Null
    New-Item -ItemType Directory -Path $cniPath\conf -Force > Out-Null
    New-Item -ItemType Directory -Path $EtcPath\cni\net.d -Force > Out-Null
    New-Item -ItemType File -Path $cniPath\config -Force > Out-Null
     
    Invoke-Curl -Uri "https://github.com/containernetworking/plugins/releases/download/v0.9.1/cni-plugins-windows-amd64-v0.9.1.tgz" -OutFile "$cniPath\bin\cniplugins.tgz"
    tar -xzf $cniPath\bin\cniplugins.tgz   
    Remove-Item -Path $cniPath\bin\cniplugins.tgz
}

function Install-HNSModule {
    [CmdletBinding()]
    param (
        [Parameter()]
        [String]
        $Path = "c:\k"
    )
    Write-Output "Downloading Windows Kubernetes scripts"
    Invoke-Curl -Uri "https://github.com/Microsoft/SDN/raw/master/Kubernetes/windows/hns.psm1" -OutFile "$Path\hns.psm1"    
}

function Install-K8sComponents {
    [CmdletBinding()]
    param (
        [Parameter(HelpMessage = "The K8s version to use.")]
        [String]
        $Version = "1.21.1",
        [Parameter()]
        [String]
        $Path = "$env:SystemDrive\k",
        [Parameter()]
        [String]
        $WinsVersion = "0.1.1"
    )

    Write-Output "Using K8s version: $Version...."
    New-Item -Path $Path -ItemType Directory -Force > Out-Null
    $env:Path += ";$Path"
    [Environment]::SetEnvironmentVariable("Path", $env:Path, [System.EnvironmentVariableTarget]::Machine)

    Write-Output "Installing components...."   
    Invoke-Curl -Uri "https://dl.k8s.io/v$Version/kubernetes-node-windows-amd64.tar.gz" -OutFile "$Path\kubenode.tar.gz"
    tar.exe -xvf "$Path\kubenode.tar.gz" --strip=3 -C $Path *.exe
    Remove-Item -Path "$Path\kubenode.tar.gz"
    Remove-Item -Path "$Path\kubeadm.exe"
        
    Write-Output "Installing Wins $WinsVersion...."
    Invoke-Curl -Uri "https://github.com/rancher/wins/releases/download/v$WinsVersion/wins.exe" -OutFile "$Path\wins.exe"
}

function Add-DefenderExclusions() {
    [CmdletBinding()]
    param (
        [Parameter()]
        [String[]]
        $ExcludeList
    )
    $ExcludeList | ForEach-Object { Add-MpPreference -ExclusionProcess $_ }
}

function Start-Kubelet {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [String]
        $NodeName,
        [Parameter(Mandatory = $true)]
        [String]
        $DnsServerIps,
        [Parameter()]
        [String]
        $KubernetesPath = "c:\k"
    )
    Write-Output "[INFO]  Starting Kubelet...."
    $kubeletArgs = @(
        "--v=4",
        "--config=$KubernetesPath\kubelet-config.yaml",
        "--kubeconfig=$KubernetesPath\config",
        "--hostname-override=$NodeName",
        "--container-runtime=remote",
        "--container-runtime-endpoint='npipe:////./pipe/containerd-containerd'",
        "--cluster-dns=$DnsServerIps",
        "--feature-gates=`"WinOverlay=true`""
    )
    Start-Process -FilePath $KubernetesPath\kubelet.exe -ArgumentList $kubeletArgs
}

function Start-KubeProxy {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [String]
        $NodeName,
        [Parameter(Mandatory = $true)]
        [String]
        $ServiceCidr,
        [Parameter(Mandatory = $true)]
        [String]
        $SourceIp,
        [Parameter()]
        [String]
        $KubernetesPath = "c:\k",
        [Parameter()]
        [String]
        $NetworkName = "Calico"
    )
    Write-Output "[INFO]  Starting Kube Proxy...."
    $kubeProxyArgs = @(
        "--kubeconfig=$KubernetesPath\config",
        "--source-vip=$SourceIp",
        "--hostname-override=$NodeName",
        "--proxy-mode=kernelspace",
        "--v=4",
        "--cluster-cidr=`"$ServiceCidr`"",
        "--network-name=$NetworkName",
        "--feature-gates=`"WinOverlay=true`"",
        "--masquerade-all=false"
    )
    Start-Process -FilePath $KubernetesPath\kube-proxy.exe -ArgumentList $kubeProxyArgs 
}

function Get-SourceVip {
    $hnsNetwork = Get-HnsNetwork | Where-Object Name -EQ Calico
    $subnet = $hnsNetwork.Subnets[0].AddressPrefix

    $ipamConfig = @"
    {"cniVersion": "0.3.1", "name": "Calico", "ipam":{"type":"host-local","ranges":[[{"subnet":"$subnet"}]],"dataDir":"/var/lib/cni/networks"}}
"@

    Push-Location
    $env:CNI_COMMAND = "ADD"
    $env:CNI_CONTAINERID = "dummy"
    $env:CNI_NETNS = "dummy"
    $env:CNI_IFNAME = "dummy"
    $env:CNI_PATH = "c:\opt\cni\bin"
    Set-Location $env:CNI_PATH
    $sourceVipJSONData = $ipamConfig | c:\opt\cni\host-local.exe | ConvertFrom-Json

    Remove-Item env:CNI_COMMAND
    Remove-Item env:CNI_CONTAINERID
    Remove-Item env:CNI_NETNS
    Remove-Item env:CNI_IFNAME
    Remove-Item env:CNI_PATH
    Pop-Location

    return $sourceVipJSONData.ips[0].address.Split("/")[0]
}

Export-ModuleMember Get-WindowsFeatures
Export-ModuleMember Invoke-Curl
Export-ModuleMember Install-Containerd
Export-ModuleMember Install-CNI
Export-ModuleMember Install-HNSModule
Export-ModuleMember Install-K8sComponents
Export-ModuleMember Add-DefenderExclusions
Export-ModuleMember Start-Kubelet
Export-ModuleMember Start-KubeProxy
Export-ModuleMember Get-SourceVip
