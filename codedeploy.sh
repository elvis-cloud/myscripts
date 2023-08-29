sudo su -c " cd /home/ssm-user &&
# Install CodeDeploy agent if not already installed
if [ ! -f /etc/init.d/codedeploy-agent ]; then
    curl -O https://aws-codedeploy-us-east-1.s3.us-east-1.amazonaws.com/latest/install
    chmod +x ./install
    sudo ./install auto
fi &&

# Start CodeDeploy agent if not already running
if [ "$(sudo service codedeploy-agent status | grep running)" == "" ]; then
    sudo service codedeploy-agent start
fi
" ssm-user


sed -i 's/yfs.yfs.app.identifyconnection=Y/#yfs.yfs.app.identifyconnection=Y/g' filename 

ls /path/to/source_folder | grep "\.txt$" | xargs -I {} cp {} /path/to/destination_folder
