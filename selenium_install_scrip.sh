
sudo apt update
sudo apt install python3-pip

pip3 install selenium

wget https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb
sudo dpkg -i google-chrome-stable_current_amd64.deb
sudo apt install -f

wget https://edgedl.me.gvt1.com/edgedl/chrome/chrome-for-testing/118.0.5993.70/linux64/chromedriver-linux64.zip
wget https://edgedl.me.gvt1.com/edgedl/chrome/chrome-for-testing/118.0.5993.70/linux64/chrome-linux64.zip
apt install unzip
unzip chromedriver-linux64.zip
unzip chrome-linux64.zip
sudo mv chromedriver-linux64/chromedriver /usr/local/bin/
sudo mv chrome-linux64/chrome /usr/local/bin/



# chmod +x selenium_install_scrip.sh
# ./selenium_install_scrip.sh