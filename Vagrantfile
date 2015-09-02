# -*- mode: ruby -*-
# vi: set ft=ruby :

# Vagrantfile API/syntax version. Don't touch unless you know what you're doing!
VAGRANTFILE_API_VERSION = "2"

# Url to box has been packaged on local
# use Python simple sesrver to share box file
# python -m SimpleHTTPServer 9300
# SHARED_BOX_URL = "http://xxx.xxx.xxx.xxx:<POST>/project.box"

Vagrant.configure(VAGRANTFILE_API_VERSION) do |config|

  #config.vm.network :private_network, ip: "192.168.33.10"

  # Data folder
  config.vm.synced_folder "./", "/home/vagrant/tweetnacl"

  if defined?(SHARED_BOX_URL)
    config.vm.box = "amaryllis-amaryllis"
    config.vm.box_url = SHARED_BOX_URL
  else
    config.vm.box = "precise64"
    config.vm.box_url = "../../precise64.box"
    config.vm.provision "shell", :path => "bootstrap.sh", :privileged => false
  end


  config.vm.provider :virtualbox do |vb|
    # Use VBoxManage to customize the VM. For example to change memory:
    vb.customize ["modifyvm", :id, "--memory", "2048"]
  end
end