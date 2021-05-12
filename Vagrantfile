Vagrant.configure(2) do |config|
    config.vagrant.plugins = ["vagrant-reload"]
    config.vm.network "private_network", bridge: "Default Switch"
    config.vm.define :main do |main|
      main.vm.host_name = "main"
      main.vm.box = "hashicorp/bionic64"
  
      main.vm.provider :virtualbox do |vb|
        vb.memory = 2048
        vb.cpus = 2
      end
      main.vm.provider :hyperv do |hv|
        hv.memory = 2048
        hv.cpus = 2
      end

      main.vm.synced_folder "./sync", "/var/sync", smb_username: ENV['SMB_USERNAME'], smb_password: ENV['SMB_PASSWORD']
     
      main.vm.provision :shell, privileged: true, inline: "curl -sfL https://get.rke2.io | sh -"
      main.vm.provision :shell, privileged: true, inline: "systemctl enable rke2-server.service"
      main.vm.provision :shell, privileged: true, inline: "systemctl start rke2-server.service"
      main.vm.provision :shell, privileged: true, inline: "touch /etc/profile.d/rancher.sh"
      main.vm.provision :shell, privileged: true, inline: "echo \"export KUBECONFIG=/etc/rancher/rke2/rke2.yaml\" >> /etc/profile.d/rancher.sh"
      main.vm.provision :shell, privileged: true, inline: "echo \"export PATH=$PATH:/var/lib/rancher/rke2/bin\" >> /etc/profile.d/rancher.sh"
      main.vm.provision :shell, privileged: true, inline: "while [ ! -f /var/lib/rancher/rke2/server/node-token ]; do sleep 2; done;"
      main.vm.provision :shell, privileged: true, inline: "chmod a=r /etc/rancher/rke2/rke2.yaml"
      main.vm.provision :shell, privileged: true, inline: "rm -f /var/sync/token"
      main.vm.provision :shell, privileged: true, inline: "rm -f /var/sync/server"
      main.vm.provision :shell, privileged: true, inline: "cat /var/lib/rancher/rke2/server/node-token > /var/sync/token" 
      main.vm.provision :shell, privileged: true, inline: "cat /var/lib/rancher/rke2/server/node-token > /var/sync/server"     
    end
  


    config.vm.define :winworker do |winworker|
      winworker.vm.host_name = "winworker"
      winworker.vm.box = "StefanScherer/windows_2019"     
      winworker.vm.provider :virtualbox do |vb|
        vb.memory = 2048
        vb.cpus = 2
        vb.gui = true
      end 
      winworker.vm.provider :hyperv do |hv|
        hv.enable_virtualization_extensions = true      
        hv.memory = 2048
        hv.cpus = 2
      end
  
      winworker.vm.synced_folder "./sync", "c:\\sync", smb_username: ENV['SMB_USERNAME'], smb_password: ENV['SMB_PASSWORD']
  
    end
    
  end