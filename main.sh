#! /bin/bash
set -e
curl -sfL https://get.rke2.io | sh -
mkdir -p /var/lib/rancher/rke2/server/manifests/
systemctl enable rke2-server.service
curl -s https://raw.githubusercontent.com/nickgerace/vista/main/calico-vxlan.yaml -o /var/lib/rancher/rke2/server/manifests/calico-vxlan.yaml
mkdir -p /etc/rancher/rke2
cat <<EOF | sudo tee /etc/rancher/rke2/config.yaml
disable: "rke2-canal"
node-ip:
  - "priv-ip"
EOF
sed -i 's/priv-ip/'"$(hostname -I | xargs)/g" /etc/rancher/rke2/config.yaml
systemctl start rke2-server.service

echo "[INFO] Setting up environment variables...."
touch /etc/profile.d/rancher.sh
echo "export KUBECONFIG=/etc/rancher/rke2/rke2.yaml" >> /etc/profile.d/rancher.sh
echo "export PATH=$PATH:/var/lib/rancher/rke2/bin" >> /etc/profile.d/rancher.sh
echo "export FELIX_AWSSRCDSTCHECK=DoNothing" >> /etc/profile.d/rancher.sh
echo "export FELIX_ALLOWVXLANPACKETSFROMWORKLOADS=true" >> /etc/profile.d/rancher.sh
echo "export FELIX_IPV6SUPPORT=false" >> /etc/profile.d/rancher.sh
export PATH=$PATH:/var/lib/rancher/rke2/bin
export KUBECONFIG=/etc/rancher/rke2/rke2.yaml
curl -o /usr/local/bin/calicoctl -sOL https://github.com/projectcalico/calicoctl/releases/download/v3.19.0/calicoctl
chmod +x /usr/local/bin/calicoctl
while [ ! -f /var/lib/rancher/rke2/server/node-token ]; do sleep 2; done;
until journalctl -u rke2-server | grep -q "rke2 is up and running"; do sleep 10; echo "Waiting for RKE2 to be ready..."; done;
echo "[INFO] Starting Calico Setup...."
crictl config --set runtime-endpoint=unix:///run/k3s/containerd/containerd.sock
chmod a=r /etc/rancher/rke2/rke2.yaml
until calicoctl get felixConfiguration default | grep -q "default"; do sleep 2; echo "Waiting for Calico to be ready..."; done;
calicoctl ipam configure --strictaffinity=true
calicoctl get felixConfiguration default -o yaml --export > ~/config.yaml
calicoctl replace -f ~/config.yaml
rm -f /var/sync/token
rm -f /var/sync/server
cat /var/lib/rancher/rke2/server/node-token > /var/sync/token
hostname -I | xargs > /var/sync/server    
cat /etc/rancher/rke2/rke2.yaml > /var/sync/kubeconfig