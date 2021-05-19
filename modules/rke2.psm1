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
            Write-Host "Installing required windows features...."
    
            foreach ($feature in $requiredWindowsFeatures) {
                Install-WindowsFeature -Name $feature
            }
    
            Write-Host "Please reboot and re-run this script...."
            exit 0
        }
        else {
            Write-Host "Required windows features are not installed...."
    
            foreach ($feature in $requiredWindowsFeatures) {
                Write-Host "Install-WindowsFeature -Name $feature"
            }
    
            Write-Host "Please run the commands above to install...."
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
    Write-Host "Getting Containerd binaries"
    New-Item -ItemType Directory -Path $Path -Force > Out-Null
    Push-Location $Path
    Invoke-Curl -Uri "https://github.com/containerd/containerd/releases/download/v${Version}/containerd-${Version}-windows-amd64.tar.gz" -OutFile "containerd.tar.gz"
    tar.exe -xvf "containerd.tar.gz" --strip=1 -C $Path
    Remove-Item -Path containerd.tar.gz
    Rename-Item -Path "containerd-shim-runhcs-v1.exe" -NewName "containerd-shim-grpc-v1.exe"
    $env:Path += ";$Path"
    [Environment]::SetEnvironmentVariable("Path", $env:Path, [System.EnvironmentVariableTarget]::Machine)

    Invoke-Curl -Uri "https://github.com/kubernetes-sigs/cri-tools/releases/download/v1.21.0/crictl-v1.21.0-windows-amd64.tar.gz" -OutFile "crictl.tar.gz"
    tar.exe -xvf "crictl.tar.gz"
    Remove-Item -Path crictl.tar.gz
    Start-Process -FilePath "$Path\crictl.exe" -ArgumentList "config --set runtime-endpoint=npipe:////./pipe/containerd-containerd" -NoNewWindow

    # Set containerd config.toml
    $ProcessInfo = New-Object System.Diagnostics.ProcessStartInfo
    $ProcessInfo.FileName = "$Path\containerd.exe"
    $ProcessInfo.RedirectStandardError = $true
    $ProcessInfo.RedirectStandardHost = $true
    $ProcessInfo.UseShellExecute = $false
    $ProcessInfo.Arguments = "config default"
    $Process = New-Object System.Diagnostics.Process
    $Process.StartInfo = $ProcessInfo
    $Process.Start() | Out-Null
    $Process.WaitForExit()
    $config = $Process.StandardHost.ReadToEnd()
    $config = $config -replace "bin_dir = (.)*$", "bin_dir = `"c:/opt/cni/bin`""
    $config = $config -replace "conf_dir = (.)*$", "conf_dir = `"c:/etc/cni/net.d`""
    Set-Content -Path $Path\config.toml -Value $config -Force

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
    Write-Host "Downloading CNI binaries"
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
    Write-Host "Downloading Windows Kubernetes scripts"
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

    Write-Host "Using K8s version: $Version...."
    New-Item -Path $Path -ItemType Directory -Force > Out-Null
    $env:Path += ";$Path"
    [Environment]::SetEnvironmentVariable("Path", $env:Path, [System.EnvironmentVariableTarget]::Machine)

    Write-Host "Installing components...."   
    Invoke-Curl -Uri "https://dl.k8s.io/v$Version/kubernetes-node-windows-amd64.tar.gz" -OutFile "$Path\kubenode.tar.gz"
   
    Remove-Item -Path "$Path\kubenode.tar.gz"
    Remove-Item -Path "$Path\kubeadm.exe"
        
    Write-Host "Installing Wins $WinsVersion...."
    Invoke-Curl -Uri "https://github.com/rancher/wins/releases/download/v$WinsVersion/wins.exe" -OutFile "$Path\wins.exe"
}

function Install-Nssm {
    [CmdletBinding()]
    param (
        [Parameter()]
        [String]
        $Path = "c:\etc\rancher\rke2"
    )
    Write-Host "Downloading NSSM scripts"
    New-Item -ItemType Directory -Path $Path\nssm -Force > Out-Null
    Invoke-Curl -Uri "https://k8stestinfrabinaries.blob.core.windows.net/nssm-mirror/nssm-2.24.zip" -OutFile "$Path\nssm.zip"    
    tar.exe -xvf "$Path\nssm.zip " --strip-components 2 */$arch/*.exe -C $Path\nssm *.exe
    Remove-Item -Force .\nssm.zip
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

function Get-NodeIp {
    [CmdletBinding()]
    param (
        [Parameter()]
        [String]
        $InterfaceName = "Ethernet"
    )


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
    $kubeletConfigPath = "$KubernetesPath\kubelet-config.yaml"
    New-Item -Path $kubeletConfigPath -ItemType File -Force
    $kubeletConfig = @"
    kind: KubeletConfiguration
    apiVersion: kubelet.config.k8s.io/v1beta1
    featureGates:
      RuntimeClass: true
      WinOverlay: true
    runtimeRequestTimeout: 20m
    resolverConfig: ""
    enableDebuggingHandlers: true
    clusterDomain: "cluster.local"
    clusterDNS: ["$DnsServerIPs"]
    hairpinMode: "promiscuous-bridge"
    cgroupsPerQOS: false
    enforceNodeAllocatable: []
"@
    Set-Content -Path $kubeletConfigPath -Value $kubeletConfig
    

    
    Write-Host "Starting Kubelet...."
    $kubeletArgs = @(
        "--v=4",
        "--config=""$kubeletConfigPath""",
        "--kubeconfig=""$KubernetesPath\config""",
        "--hostname-override=$NodeName", # Do we really need this?
        "--node-ip=$NodeIp"
        "--container-runtime=remote",
        "--container-runtime-endpoint='npipe:////./pipe/containerd-containerd'"
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
    Write-Host "Starting Kube Proxy...."
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
Export-ModuleMember Install-Nssm
