# Wazuh SOC training lab -- the whole thing in one VM.
#
#   vagrant up                # boots Ubuntu VM, installs Wazuh AIO + lab + tool
#   vagrant ssh               # shell into the server
#   open https://<VM_IP>      # Wazuh dashboard (admin)
#   open http://<VM_IP>:8101  # training tool
#
# The repo is synced to /vagrant inside the VM and bootstrap.sh runs there.
# Only real component = this VM. Endpoints/agents are DB-only (simulated).
#
# Needs a provider with nested virt OFF requirement (this is a normal VM, not
# nested) -- libvirt/KVM or VirtualBox. Give it >=4GB RAM (indexer is hungry).

Vagrant.configure("2") do |config|
  config.vm.box = "generic/ubuntu2204"      # works on libvirt AND virtualbox
  config.vm.hostname = "wazuh-lab"

  # Private network so you can reach the dashboard/tool from the host.
  config.vm.network "private_network", ip: "192.168.56.20"

  mem = ENV.fetch("LAB_MEM_MB", "6144")     # 6 GB default
  cpus = ENV.fetch("LAB_CPUS", "2")

  config.vm.provider "libvirt" do |v|
    v.memory = mem
    v.cpus = cpus
  end
  config.vm.provider "virtualbox" do |v|
    v.memory = mem
    v.cpus = cpus
    v.customize ["modifyvm", :id, "--nictype1", "virtio"]
  end

  # Run the same bootstrap used for bare metal.
  config.vm.provision "shell", inline: <<-SHELL
    set -e
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq python3 openssl curl >/dev/null
    bash /vagrant/bootstrap.sh
  SHELL
end
