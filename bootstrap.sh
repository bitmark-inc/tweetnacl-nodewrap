echo 'Install git'
sudo apt-get install -y git-core

# config UTF-8 for server environment
sudo localedef -v -c -i en_US -f UTF-8 en_US.UTF-8 
sudo dpkg-reconfigure locales

echo 'Install curl for installation tool'
sudo apt-get install -y curl

# Note the new setup script name for Node.js v0.12
curl -sL https://deb.nodesource.com/setup_0.12 | sudo bash -

# Then install with:
sudo apt-get install -y nodejs
sudo apt-get install -y npm

echo '============= Install node success =============='
node -v

echo prefix = ~/.node >> ~/.npmrc
echo 'export PATH=$HOME/.node/bin:$PATH' >> ~/.bashrc
source ~/.bashrc
sudo npm config set registry http://registry.npmjs.org/

sudo apt-get install g++