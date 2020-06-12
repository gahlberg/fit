# Firewall Inspection Tester (fit)
Author: Alex Harvey, @meshmeld""")
Here are the Fit Files for Download and instructions below to install and run on Ubuntu (tested with 18.04 and 20.04):

### Pre-requisites to install:
    sudo apt update
    sudo apt-get install vim git python3-pip -y

### Python 3 Modules to Install:
    click==6.6
    requests==2.10.0
    selenium==2.53.6
    requests-toolbelt==0.7.0

### Install all at once with Pip3:
    pip3 install click==6.6 requests==2.10.0 selenium==2.53.6 requests-toolbelt==0.7.0

### Clone repository into home directory:
    git clone https://github.com/gahlberg/fit.git

### To make repeatFit.py and repeatFitMalware.py executable without specifying python (./repeatFit.py), perform the following:
    [host]$ chmod 700 repeatFit.py 
    [host]$ chmod 700 repeatFitMalware.py 

### Issue the command appropriate in the fit/ directory to run:
    [host]$ ./repeatFit.py
  
### To quit the Fit program from running: 
    simply issue Ctrl-Z to stop... Ctrl-C will just abort and restart fit...
