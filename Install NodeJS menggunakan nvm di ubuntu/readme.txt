sudo apt install curl

curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.37.2/install.sh | bash
# Close and reopen your terminal after this step

nvm install 18.17.1
nvm install 20.5.1

nvm use 18.17.1

node -v
npm -v
