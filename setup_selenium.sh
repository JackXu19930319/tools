#!/bin/bash

# Install Python
sudo apt-get update
sudo apt-get install -y python3

# Install pip
sudo apt-get install -y python3-pip

# Install Selenium
pip3 install selenium

apt install unzip

# Download ChromeDriver
wget https://chromedriver.storage.googleapis.com/$(curl -sS https://chromedriver.storage.googleapis.com/LATEST_RELEASE)/chromedriver_linux64.zip
unzip chromedriver_linux64.zip
sudo mv chromedriver /usr/local/bin/

# chmod +x setup_selenium.sh
# ./setup_selenium.sh
