#!/bin/bash

# Install dependencies
sudo apt-get update
sudo apt-get install -y build-essential libssl-dev zlib1g-dev libbz2-dev \
libreadline-dev libsqlite3-dev wget curl llvm libncurses5-dev libncursesw5-dev \
xz-utils tk-dev libffi-dev liblzma-dev python3-openssl git

# Install pyenv
git clone https://github.com/pyenv/pyenv.git ~/.pyenv
echo 'export PYENV_ROOT="$HOME/.pyenv"' >> ~/.bashrc
echo 'export PATH="$PYENV_ROOT/bin:$PATH"' >> ~/.bashrc
echo -e 'if command -v pyenv 1>/dev/null 2>&1; then\n  eval "$(pyenv init --no-rehash -)"\nfi' >> ~/.bashrc
source ~/.bashrc

# Install Python 3.9
pyenv install 3.9.0

# Set global Python version
pyenv global 3.9.0

# Verify installation
python --version

echo "pyenv and Python 3.9 installation complete!"

# chmod +x install_pyenv.sh
# ./install_pyenv.sh
