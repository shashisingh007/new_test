import boto3
import time
import paramiko
import os
import sys
ec2 = boto3.resource('ec2')
client = boto3.client('ec2')





def create():
    global var3, var1
    ec2 = boto3.resource('ec2')
    client = boto3.client('ec2')
    #Default values
    prefix_name="demo"
    cidr_block="172.16.0.0/16"
    public_cidr_block="172.16.64.0/24"
    private_cidr_block="172.16.128.0/24"
    nat_ami_id="ami-00999044593c895de"
    public_ami_id="ami-04b1ddd35fd71475a"
    private_ami_id="ami-04b1ddd35fd71475a"
    servername = prefix_name+"-server.com"
    serveralias = "www."+prefix_name+".com"


    #User's default inputs
    print("Your default prefix name is: " + prefix_name)
    print("Your default CIDR block for vpc is: " + cidr_block)
    print("Your default CIDR block for public subnet is: " + public_cidr_block)
    print("Your default CIDR block for private subnet is: " + private_cidr_block)
    print("Your default nat ami id is: " + nat_ami_id)
    print("Your default public ami id is: " + public_ami_id)
    print("Your default private ami id is: " + private_ami_id)
    print("Your default server name is: "+servername)
    print("Your default server alias is: "+serveralias)


    #User's changing input function
    def read_input(): 
        global prefix_name, cidr_block, public_cidr_block, private_cidr_block, nat_ami_id, public_ami_id, private_ami_id, servername, serveralias
        prefix_name = str(input("Enter your prefix name: "))  
        cidr_block = str(input("Enter your cidr block for vpc: "))  
        public_cidr_block = str(input("Enter your cidr block for public subnet: "))  
        private_cidr_block = str(input("Enter your cidr block for private subnet: "))   
        nat_ami_id = str(input("Enter your nat ami id: "))  
        public_ami_id = str(input("Enter your public ami id: "))  
        private_ami_id= str(input("Enter your private ami id: "))  
        servername = str(input("Enter your server name: "))
        serveralias = str(input("Enter your server alias: "))




    #User's changed inputs display function
    def show_input():
        print("Your prefix name is: " + prefix_name)
        print("Your CIDR block for vpc is: " + cidr_block)
        print("Your CIDR block for public subnet is: " + public_cidr_block)
        print("Your CIDR block for private subnet is: " + private_cidr_block)
        print("Your nat ami id is: " + nat_ami_id)
        print("Your public ami id is: " + public_ami_id)
        print("Your private ami id is: " + private_ami_id)
        print("Your server name is: "+ servername)
        print("Your server alias is: "+serveralias)





    #Funtion to either select to change or go with the default values
    def input_option():
        global var
        print("Enter '0' to change your input")
        print("Enter '1' to save and exit")
        var = str(input("Enter your option: "))
        if var != '1':
            if var == '0':
                exit
            else:
                print("Invalid option")
                input_option()


    def option():
        global change_your_option, prefix_name, cidr_block, public_cidr_block, private_cidr_block, nat_ami_id, public_ami_id, private_ami_id, servername, serveralias
        while var != '1':
            print("Enter '1' to go with the default values")
            print("Enter '2' to change your prefix name")
            print("Enter '3' to change CIDR block for vpc")
            print("Enter '4' to change CIDR block for public subnet")
            print("Enter '5' to change CIDR block for private subnet")
            print("Enter '6' to change nat ami id")
            print("Enter '7' to change public ami id")
            print("Enter '8' to change private ami id")
            print("Enter '9' to change your server name")
            print("Enter '10' to change your server alias")
            print("Enter '11' to proceed")
            def change_your_option_fun():
                global change_your_option
                change_your_option = str(input("Enter your option: "))
            change_your_option_fun()
            if change_your_option == '1':
                prefix_name="demo"
                cidr_block="172.16.0.0/16"
                public_cidr_block="172.16.64.0/24"
                private_cidr_block="172.16.128.0/24"
                nat_ami_id="ami-00999044593c895de"
                public_ami_id="ami-04b1ddd35fd71475a"
                private_ami_id="ami-04b1ddd35fd71475a"
                servername=prefix_name+"-server.com"
                serveralias="www."+prefix_name+".com"
            elif change_your_option == '2':
                prefix_name = str(input("Enter your prefix name: ")) 
            elif change_your_option == '3':
                cidr_block = str(input("Enter your CIDR block for vpc: "))
            elif change_your_option == '4':
                public_cidr_block = str(input("Enter your CIDR block for public subnet: ")) 
            elif change_your_option == '5':
                private_cidr_block = str(input("Enter your CIDR block for private subnet: ")) 
            elif change_your_option == '6':
                nat_ami_id = str(input("Enter your nat ami id: ")) 
            elif change_your_option == '7':
                public_ami_id = str(input("Enter your public ami id: ")) 
            elif change_your_option == '8':
                private_ami_id = str(input("Enter your private ami id: ")) 
            elif change_your_option == '9':
                servername = str(input("Enter your servername: "))
            elif change_your_option == '10':
                serveralias = str(input("Enter your server alias: "))
            elif change_your_option == '11':
                break
            else:
                print("Invalid option!!! Enter the correct option")
                option()


            show_input()
            input_option()
            if var == '0':
                option()
            elif var == '1':
                print("Your input's has been saved")
                break
            else:
                print("Invalid input!!!")
                option()
            break




    #calling change function  and input_option function
    def default_option():
        global default
        default = str(input("Enter '0' to change and '1' to go with the default values: ")) 
        if default == '0':
            read_input()
            show_input()
            input_option()
            if var == '0':
                option()
            elif var == '1':
                print("Your input's has been saved")
            else:
                print("Invalid input!!!")
                input_option()
        elif default == '1':
            print("Your default value has been saved!!!")
            exit
        else:
            print("invalid option selected!!! Please enter the right option")
            default_option()

    default_option()



    #SSL file creation
    var3 ="""#!/bin/bash
    #Required
    domain="demo_ssl"
    commonname=$domain
    #Change to your company details
    country=IN
    state=BR
    locality=Patna
    organization=ct.com
    organizationalunit=IT
    email=demo@gmail.com
    #Optional
    password=dummypassword
    if [ -z "$domain" ]
    then
        echo "Argument not present."
        echo "Useage $0 [common name]"
        exit 99
    fi
    echo "Generating key request for $domain"
    #Generate a key
    openssl genrsa -des3 -passout pass:$password -out $domain.key 2048 -noout
    #Remove passphrase from the key. Comment the line out to keep the passphrase
    echo "Removing passphrase from key"
    openssl rsa -in $domain.key -passin pass:$password -out $domain.key
    #Create the request
    echo "Creating CSR"
    openssl req -new -key $domain.key -out $domain.csr -passin pass:$password -subj "/C=$country/ST=$state/L=$locality/O=$organization/OU=$organizationalunit/CN=$commonname/emailAddress=$email"   
    openssl x509 -req -days 365 -in $domain.csr -signkey $domain.key -out $domain.crt
    """
    var1="""domain=satyam.com
    commonname=$domain
    
    #your company details
    country=IN
    state=BR
    locality=Patna
    organization=www.ct.com
    organizationalunit=IT
    email=demo@gmail.com"""

    #Bydefault your SSL certification value is below:
    def changecompany():
        global  country, state, locality, organization, email, organizationalunit, var3

        country = str(input("Enter country: "))  
        state = str(input("Enter state: "))
        locality = str(input("Enter locality: "))
        organization = str(input("Enter organization: "))
        organizationalunit = str(input("Enter organizationalunit: "))
        email = str(input("Enter email: "))
        var3 = var3.replace("IN", country)
        var3 = var3.replace("BR", state)
        var3 = var3.replace("Patna", locality)
        var3 = var3.replace("ct.com", organization)
        var3 = var3.replace("IT", organizationalunit)
        var3 = var3.replace("demo@gmail.com", email)
        var3 = var3.replace("demo_ssl",prefix_name+"_ssl")

    
    print(var1)
    def ssl_opt():
        print("if you want to change the value type 0 or type 1 to go by default")
        var2=str(input("Enter 1 or 0: "))
        if var2 == "0":
            changecompany()
        elif var2 =="1" :
            exit
        else:
            print("Invalid Input")
            ssl_opt()

    ssl_opt()

    #Creation of ssl.sh file
    file = open("ssl.sh", "w") 
    file.write(var3) 
    file.close()





    #VPC creation
    vpc = ec2.create_vpc(CidrBlock=cidr_block)
    vpc.create_tags(Tags=[{"Key": "Name", "Value": prefix_name+"-vpc"}])
    vpc_id=vpc.id
    print("Your vpc has been created successfully!!! Your vpc id is: "+str(vpc_id))




    #Public subnet creation
    pub_subnet = ec2.create_subnet(CidrBlock=public_cidr_block, VpcId=vpc_id, AvailabilityZone='ap-south-1a')
    pub_subnet.create_tags(Tags=[{"Key": "Name", "Value": prefix_name+"-public_subnet"}])
    public_subnet_id=pub_subnet.id
    print("Your public subnet has been created successfully!!! Your public subnet id is: "+str(pub_subnet))




    #private subnet creation 
    pri_subnet = ec2.create_subnet(CidrBlock=private_cidr_block, VpcId=vpc_id, AvailabilityZone='ap-south-1a')
    pri_subnet.create_tags(Tags=[{"Key": "Name", "Value": prefix_name+"-private_subnet"}])
    private_subnet_id=pri_subnet.id
    print("Your private subnet has been created successfully!!! Your private subnet id is: "+str(pri_subnet))





    #Internet gateway creation and attachment to vpc
    internetgateway = ec2.create_internet_gateway()
    internetgateway.create_tags(Tags=[{"Key": "Name", "Value": prefix_name+"-igw"}])
    print("Your internet gateway has been created successfully!!! Your internet gateway id is: "+str(internetgateway.id))
    vpc.attach_internet_gateway(InternetGatewayId=internetgateway.id)
    print("Your internet gateway has been attached to vpc successfully!!!")



    #Public route table creation
    pub_routetable = vpc.create_route_table()
    pub_routetable.create_tags(Tags=[{"Key": "Name", "Value": prefix_name+"-public_rt"}])
    public_rt=pub_routetable.id
    print("Your public routetable has been created successfully!!! Your public routetable id is: "+str(pub_routetable))
    pub_route = pub_routetable.create_route(DestinationCidrBlock='0.0.0.0/0', GatewayId=internetgateway.id)
    print("Your internet gateway has been added to public route table's route successfully!!!")


    #Private route table creation
    pri_routetable = vpc.create_route_table()
    pri_routetable.create_tags(Tags=[{"Key": "Name", "Value": prefix_name+"-private_rt"}])
    private_rt=pri_routetable.id
    print("Your private routetable has been created successfully!!! Your private routetable id is: "+str(pri_routetable))


    #Association of route tables
    pub_routetable.associate_with_subnet(SubnetId=public_subnet_id)
    print("Your public routetable has been associated with public subnet successfully!!!")
    pri_routetable.associate_with_subnet(SubnetId=private_subnet_id)
    print("Your private routetable has been associated with private subnet successfully!!!")

    #Nat security group creation and addition of rules
    nat_securitygroup = ec2.create_security_group(GroupName=prefix_name+"-nat_sg", Description='My nat security group', VpcId=vpc_id)
    nat_securitygroup.create_tags(Tags=[{"Key": "Name", "Value": prefix_name+"-nat_sg"}])
    nat_sg_id=nat_securitygroup.id
    print("Your nat security group has been created successfully!!! Your nat security group id is: "+str(nat_sg_id))
    nat_securitygroup.authorize_ingress(CidrIp='0.0.0.0/0', IpProtocol='tcp', FromPort=22, ToPort=22)
    nat_securitygroup.authorize_ingress(CidrIp=private_cidr_block, IpProtocol='tcp', FromPort=80, ToPort=80)
    nat_securitygroup.authorize_ingress(CidrIp=private_cidr_block, IpProtocol='tcp', FromPort=443, ToPort=443)
    nat_securitygroup.authorize_ingress(CidrIp=private_cidr_block, IpProtocol='icmp', FromPort=-1, ToPort=-1)




    #Public security group creation and addition of rules
    pub_securitygroup = ec2.create_security_group(GroupName=prefix_name+"-public_sg", Description='My public security group', VpcId=vpc_id)
    pub_securitygroup.create_tags(Tags=[{"Key": "Name", "Value": prefix_name+"-public_sg"}])
    public_sg_id=pub_securitygroup.id
    print("Your public security group has been created successfully!!! Your public security group id is: "+str(public_sg_id))
    pub_securitygroup.authorize_ingress(CidrIp='0.0.0.0/0', IpProtocol='tcp', FromPort=22, ToPort=22)
    pub_securitygroup.authorize_ingress(CidrIp='0.0.0.0/0', IpProtocol='tcp', FromPort=80, ToPort=80)
    pub_securitygroup.authorize_ingress(CidrIp='0.0.0.0/0', IpProtocol='tcp', FromPort=443, ToPort=443)
    pub_securitygroup.authorize_ingress(CidrIp='13.233.177.0/29', IpProtocol='icmp', FromPort=22, ToPort=22)



    #Nat security group creation and addition of rules
    pri_securitygroup = ec2.create_security_group(GroupName=prefix_name+"-private_sg", Description='My private security group', VpcId=vpc_id)
    pri_securitygroup.create_tags(Tags=[{"Key": "Name", "Value": prefix_name+"-private_sg"}])
    private_sg_id=pri_securitygroup.id
    print("Your private security group has been created successfully!!! Your private security group id is: "+str(private_sg_id))
    pri_sg = client.authorize_security_group_ingress(
        GroupId=private_sg_id,
        IpPermissions=[
            {'IpProtocol': 'tcp',
             'FromPort': 80,
             'ToPort': 80,
             'IpRanges': [{'CidrIp': '0.0.0.0/0'}]},
            {'IpProtocol': 'tcp',
             'FromPort': 22,
             'ToPort': 22,
             'IpRanges': [{'CidrIp': '0.0.0.0/0'}]},
            {'IpProtocol': 'tcp',
             'FromPort': 443,
             'ToPort': 443,
             'IpRanges': [{'CidrIp': '0.0.0.0/0'}]},
            {'IpProtocol': 'tcp',
             'FromPort': 22,
             'ToPort': 22,
             'IpRanges': [{'CidrIp': public_cidr_block }]},
            {'IpProtocol': '-1',
             'FromPort': -1,
             'ToPort': -1,
             'UserIdGroupPairs': [{
            'GroupId': nat_sg_id }]},
            {'IpProtocol': 'tcp',
             'FromPort': 8080,
             'ToPort': 8080,
             'UserIdGroupPairs': [{
            'GroupId': public_sg_id }]}
        ])






    # create a file to store the key locally
    outfile = open(prefix_name+'-key_pair.pem', 'w')
    # call the boto ec2 function to create a key pair
    key_pair_out = ec2.create_key_pair(KeyName=prefix_name+'-key_pair')
    print("Your key pair has been created successfully!!! Key pair name is: "+prefix_name+"-key_pair")
    # capture the key and store it in a file
    key_pair = str(key_pair_out.key_material)
    outfile.write(key_pair)
    outfile.close()




    #Nat instance creation
    nat_instance = ec2.create_instances(
    ImageId=nat_ami_id,
    InstanceType='t2.micro',
    MaxCount=1,
    MinCount=1,
    Placement ={'AvailabilityZone':'ap-south-1a'},
    NetworkInterfaces=[{
    'SubnetId': public_subnet_id,
    'DeviceIndex': 0,
    'AssociatePublicIpAddress': True,
    'Groups': [nat_sg_id]
    }],
    KeyName=prefix_name+"-key_pair")
    print("Please wait while we make your instance to be running--------------------------------------------------")
    nat_instance[0].wait_until_running()
    nat_instance_id=nat_instance[0].id
    print("Your nat instance has been created successfully!!! Your nat instance id is: "+str(nat_instance_id))
    ec2.create_tags(Resources=[nat_instance_id], Tags=[{'Key': 'Name', 'Value': prefix_name+'_nat_instance'}])
    result = client.modify_instance_attribute(InstanceId=nat_instance_id, SourceDestCheck={'Value': False})
    pri_route = pri_routetable.create_route(DestinationCidrBlock='0.0.0.0/0', InstanceId=nat_instance_id)
    print("Your nat instance has been added to private route table's route")



    #Public instance creation
    public_instance = ec2.create_instances(
    ImageId=public_ami_id,
    InstanceType='t2.micro',
    MaxCount=1,
    MinCount=1,
    Placement ={'AvailabilityZone':'ap-south-1a'}, 
    NetworkInterfaces=[{
    'SubnetId': public_subnet_id,
    'DeviceIndex': 0,
    'AssociatePublicIpAddress': True,
    'Groups': [public_sg_id]
    }],
    KeyName=prefix_name+"-key_pair")
    print("Please wait while we make your instance to be running----------------------------------------------")
    public_instance[0].wait_until_running()
    public_instance_id=public_instance[0].id
    print("Your public instance has been created successfully!!! Your public instance id is: "+str(public_instance_id))
    ec2.create_tags(Resources=[public_instance_id], Tags=[{'Key': 'Name', 'Value': prefix_name+'_public_instance'}])
    def get_public_ip(instance_id):
        ec2_client = boto3.client("ec2", region_name="ap-south-1")
        reservations = ec2_client.describe_instances(InstanceIds=[instance_id]).get("Reservations")
        for reservation in reservations:
            for instance in reservation['Instances']:
                return instance.get("PublicIpAddress")

    public_ip = get_public_ip(public_instance_id)
    print("Your public instance's public ip is: "+str(public_ip))




    #Private instance creation
    private_instance = ec2.create_instances(
    ImageId=private_ami_id,
    InstanceType='t2.micro',
    MaxCount=1,
    MinCount=1,
    Placement ={'AvailabilityZone':'ap-south-1a'},
    NetworkInterfaces=[{
    'SubnetId': private_subnet_id,
    'DeviceIndex': 0,
    'AssociatePublicIpAddress': False,
    'Groups': [private_sg_id]
    }],
    KeyName=prefix_name+"-key_pair")
    print("Please wait while we make your instance to be running----------------------------------------------")
    private_instance[0].wait_until_running()
    private_instance_id=private_instance[0].id
    print("Your private instance has been created successfully!!! Your private instance id is: "+str(private_instance_id))
    ec2.create_tags(Resources=[private_instance_id], Tags=[{'Key': 'Name', 'Value': prefix_name+'_private_instance'}])


    def get_private_ip(instance_id):
        ec2_client = boto3.client("ec2", region_name="ap-south-1")
        reservations = ec2_client.describe_instances(InstanceIds=[instance_id]).get("Reservations")
        for reservation in reservations:
            for instance in reservation['Instances']:
                return instance.get("PrivateIpAddress")

    private_ip = get_private_ip(private_instance_id)
    print("Your private instance's private ip is: "+str(private_ip))








    #Sending file's to guest os
    KEY=prefix_name+"-key_pair.pem"
    localpath = prefix_name+'-key_pair.pem'
    remotepath = prefix_name+'-key_pair.pem'
    localpath1= "ssl.sh"
    remotepath1 = "ssl.sh"
    ssh=paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(hostname=public_ip,username="ec2-user",key_filename=KEY)
    sftp=ssh.open_sftp()
    sftp.put(localpath,remotepath)
    sftp.put(localpath1,remotepath1)
    sftp.close()
    ssh.close()





    #INSTALLATION 
    key = paramiko.RSAKey.from_private_key_file(prefix_name+"-key_pair.pem")
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    # Connect/ssh to an instance
    
    try:
    
        # Here 'ubuntu' is user name and 'instance_ip' is public IP of EC2
    
        client.connect(hostname=public_ip, username="ec2-user", pkey=key)
    
        # Execute a command(cmd) after connecting/ssh to an instance
    
        #Apache, mod ssl and dos2unix installation
        stdin, stdout, stderr = client.exec_command("sudo yum install httpd -y")
        print("Your apache has been installed successfully!!!")
        stdin, stdout, stderr = client.exec_command("sudo yum install -y mod_ssl")
        print("Your mod ssl has been installed successfully!!!")
        stdin, stdout, stderr = client.exec_command("sudo yum install dos2unix -y")
        time.sleep(10)
        print("Your dos2unix has been installed successfully!!!")


        #Permissions to ssl file and execution of ssl.sh file
        stdin, stdout, stderr = client.exec_command("sudo chmod +wrx ssl.sh")
        stdin, stdout, stderr = client.exec_command("dos2unix ssl.sh")
        time.sleep(10)
        stdin, stdout, stderr = client.exec_command("sh ssl.sh")
        time.sleep(20)
        print("Your ssl certificate has been created successfully!!!")
        stdin, stdout, stderr = client.exec_command("sudo mv "+prefix_name+"_ssl.* /etc/pki/tls/certs/")



        #Configuration file creation and permissions
        stdin, stdout, stderr = client.exec_command("sudo touch virtualhost")
        stdin, stdout, stderr = client.exec_command("sudo chmod 666 virtualhost")
        stdin, stdout, stderr = client.exec_command("echo '<VirtualHost *:443>' >>virtualhost")
        stdin, stdout, stderr = client.exec_command("echo '          ServerAdmin webmaster@localhost'>>virtualhost")
        stdin, stdout, stderr = client.exec_command("echo '          ServerName '"+servername+">>virtualhost")
        stdin, stdout, stderr = client.exec_command("echo '          ServerAlias '"+serveralias+">>virtualhost")
        stdin, stdout, stderr = client.exec_command("echo '          DocumentRoot /var/www/html/'>>virtualhost")
        stdin, stdout, stderr = client.exec_command("echo '          SSLEngine on'>>virtualhost")
        stdin, stdout, stderr = client.exec_command("echo '          SSLCertificateFile /etc/pki/tls/certs/'"+prefix_name+"_ssl'.crt'>>virtualhost")
        stdin, stdout, stderr = client.exec_command("echo '          SSLCertificateKeyFile /etc/pki/tls/certs/'"+prefix_name+"_ssl'.key'>>virtualhost")
        stdin, stdout, stderr = client.exec_command("echo '          '>>virtualhost")
        stdin, stdout, stderr = client.exec_command("echo '          SSLProxyEngine on'>>virtualhost")
        stdin, stdout, stderr = client.exec_command("echo '          ProxyPass / http://'"+private_ip+"':8080/'>>virtualhost")
        stdin, stdout, stderr = client.exec_command("echo '          ProxyPassReverse / http://'"+private_ip+"':8080/'>>virtualhost")
        stdin, stdout, stderr = client.exec_command("echo '</VirtualHost>'>>virtualhost")
        stdin, stdout, stderr = client.exec_command("sudo chmod 666 /etc/httpd/conf.d/virtualhost.conf")
        stdin, stdout, stderr = client.exec_command("sudo cp virtualhost /etc/httpd/conf.d/virtualhost.conf")
        print("Your Configuration file has been created successfully!!!")
        stdin, stdout, stderr = client.exec_command("sudo chmod 666 /etc/hosts")
        stdin, stdout, stderr = client.exec_command("echo "+public_ip+ " "+servername+">>/etc/hosts")
        stdin, stdout, stderr = client.exec_command("sudo chmod 600 "+prefix_name+"-key_pair.pem")




        #Private instance entrance and java installation, tomcat and jenkins download
        stdin, stdout, stderr = client.exec_command("ssh -o StrictHostKeyChecking=no ec2-user@"+private_ip+"")
        stdin, stdout, stderr = client.exec_command("ssh -o StrictHostKeyChecking=no ec2-user@"+private_ip+" uptime")
        stdin, stdout, stderr = client.exec_command("ssh -i "+prefix_name+"-key_pair.pem ec2-user@"+private_ip+" sudo yum install java -y")
        print("Your java has been installed successfully!!!")
        print("Please wait...Your tomact tar file is downloading-----------------------------------------------------")
        stdin, stdout, stderr = client.exec_command("ssh -i "+prefix_name+"-key_pair.pem ec2-user@"+private_ip+" sudo wget https://downloads.apache.org/tomcat/tomcat-8/v8.5.61/bin/apache-tomcat-8.5.61.tar.gz")
        time.sleep(20)
        print("Your tomcat's tar file has been downloaded successfully!!!")
        print("Please wait...Your tomcat tar file is extracting------------------------------------------------------")
        stdin, stdout, stderr = client.exec_command("ssh -i "+prefix_name+"-key_pair.pem ec2-user@"+private_ip+" sudo tar -xvf apache-tomcat-8.5.61.tar.gz")
        time.sleep(20)
        print("Your tomcat has been extracted successfully!!!")
        print("Please wait...Your Jenkins war file is downloading----------------------------------------------------")
        stdin, stdout, stderr = client.exec_command("ssh -i "+prefix_name+"-key_pair.pem ec2-user@"+private_ip+" sudo wget https://get.jenkins.io/war/2.272/jenkins.war")
        time.sleep(20)
        print("Your jenkin's war file has been downloaded successfully!!!")
        stdin, stdout, stderr = client.exec_command("ssh -i "+prefix_name+"-key_pair.pem ec2-user@"+private_ip+" sudo chmod +xr /home/ec2-user/apache-tomcat-8.5.61/webapps/")
        stdin, stdout, stderr = client.exec_command("ssh -i "+prefix_name+"-key_pair.pem ec2-user@"+private_ip+" sudo mv /home/ec2-user/jenkins.war /home/ec2-user/apache-tomcat-8.5.61/webapps/")


        #Apache and tomcat starting
        stdin, stdout, stderr = client.exec_command("ssh -i "+prefix_name+"-key_pair.pem ec2-user@"+private_ip+" sudo chmod +xr /home/ec2-user/apache-tomcat-8.5.61/bin/")
        stdin, stdout, stderr = client.exec_command("ssh -i "+prefix_name+"-key_pair.pem ec2-user@"+private_ip+" sudo sh apache-tomcat-8.5.61/bin/startup.sh")
        print("Your tomcat server has been started successfully!!!")
        stdin, stdout, stderr = client.exec_command("sudo systemctl start httpd")
        print("Your apache server has been started successfully!!!")
        print(stdout.read())
    
        # close the client connection once the job is done
    
        client.close()

    
    except Exception as e:
        print(e)


    #Finishing the process
    print("Now go to your windows hosts file whose path is 'C:\\Windows\\System32\\drivers\\etc\\hosts' and run as administrator then add "+public_ip+ " "+servername+" and then save it")
    print("Now you are good to go with your public ip, Let's chech it out on to your browser...")
    print("Enter http://"+servername+" To check for apache server")
    print("Enter https://"+servername+" To check for tomcat server")
    print("Enter https://"+servername+"/jenkins To check your jenkins")


#Deleting everything
def delete_all():
    print("Enter 0 to go back")
    print("Enter 1 to Enter the project name which you want to delete")
    del_opt = str(input("Enter your option: "))
    if del_opt == '0':
        todo_func()
    elif del_opt == '1':            
        prefix_name = str(input("Enter your project name: "))
        
        del_private_instance = list(ec2.instances.filter(Filters=[{'Name': 'tag:Name', 'Values': [prefix_name+"_private_instance"]}]))
        #print(del_nat_instance[0].id)
        #del_nat_instance1=del_nat_instance[0].id
        if len(del_private_instance) == 0:
            print("Invalid project name!!! Please enter a valid project name")
            delete_all()
        else:
            
            vpc = list(ec2.vpcs.filter(Filters=[{'Name': 'tag:Name', 'Values': [prefix_name+"-vpc"]}]))
            del_vpc_id=vpc[0].id
            delnat_sg = list(ec2.security_groups.filter(Filters=[{'Name': 'tag:Name', 'Values': [prefix_name+"-nat_sg"]}]))
            del_nat_sg_id=delnat_sg[0].id
            delpub_sg = list(ec2.security_groups.filter(Filters=[{'Name': 'tag:Name', 'Values': [prefix_name+"-public_sg"]}]))
            del_pub_sg_id=delpub_sg[0].id
            delpri_sg = list(ec2.security_groups.filter(Filters=[{'Name': 'tag:Name', 'Values': [prefix_name+"-private_sg"]}]))
            del_pri_sg_id=delpri_sg[0].id
            delpub_rt = list(ec2.route_tables.filter(Filters=[{'Name': 'tag:Name', 'Values': [prefix_name+"-public_rt"]}]))
            del_pub_rt_id=delpub_rt[0].id
            delpri_rt = list(ec2.route_tables.filter(Filters=[{'Name': 'tag:Name', 'Values': [prefix_name+"-private_rt"]}]))
            del_pri_rt_id=delpri_rt[0].id
            delnatinstance = list(ec2.instances.filter(Filters=[{'Name': 'tag:Name', 'Values': [prefix_name+"_nat_instance"]}]))
            del_nat_instance_id=delnatinstance[0].id
            delpubinstance = list(ec2.instances.filter(Filters=[{'Name': 'tag:Name', 'Values': [prefix_name+"_public_instance"]}]))
            del_pub_instance_id=delpubinstance[0].id
            delpriinstance = list(ec2.instances.filter(Filters=[{'Name': 'tag:Name', 'Values': [prefix_name+"_private_instance"]}]))
            del_pri_instance_id=delpriinstance[0].id

            delpubsubnet = list(ec2.subnets.filter(Filters=[{'Name': 'tag:Name', 'Values': [prefix_name+"-public_subnet"]}]))
            del_pub_subnet_id=delpubsubnet[0].id
            delprisubnet = list(ec2.subnets.filter(Filters=[{'Name': 'tag:Name', 'Values': [prefix_name+"-private_subnet"]}]))
            del_pri_subnet_id=delprisubnet[0].id

            deligw = list(ec2.internet_gateways.filter(Filters=[{'Name': 'tag:Name', 'Values': [prefix_name+"-igw"]}]))
            del_igw_id=deligw[0].id

            print("The resources which is going to be deleted are: ")
            print("Name: "+prefix_name+"_nat_instance , ID: "+del_nat_instance_id)
            print("Name: "+prefix_name+"_public_instance , ID: "+del_pub_instance_id)
            print("Name: "+prefix_name+"_private_instance , ID: "+del_pri_instance_id)
            print("Name: "+prefix_name+"-public_subnet , ID: "+del_pub_subnet_id)
            print("Name: "+prefix_name+"-private_subnet , ID: "+del_pri_subnet_id)
            print("Name: "+prefix_name+"-nat_sg , ID: "+del_nat_sg_id)
            print("Name: "+prefix_name+"-public_sg , ID: "+del_pub_sg_id)
            print("Name: "+prefix_name+"-private_sg , ID: "+del_pri_sg_id)
            print("Name: "+prefix_name+"-igw , ID: "+del_igw_id)
            print("Name: "+prefix_name+"-public_rt , ID: "+del_pub_rt_id)
            print("Name: "+prefix_name+"-private_rt , ID: "+del_pri_rt_id)
            print("Name: "+prefix_name+"-key_pair")
            print("Name: "+prefix_name+"-vpc , ID: "+del_vpc_id)


            def confirmation():
                print("Enter 0 to confirm")
                print("Enter 1 to go back")
                confirm = str(input("Enter your option: "))

                if confirm == "0":
                    def vpc_cleanup(vpcid):
                        if not vpcid:
                            return
                        print('Removing VPC ({}) from AWS'.format(vpcid))
                        ec2 = boto3.resource('ec2')
                        ec2client = ec2.meta.client
                        client = boto3.client('ec2')
                        vpc = ec2.Vpc(vpcid)
                        # delete any instances
                        for subnet in vpc.subnets.all():
                            for instance in subnet.instances.all():
                                instance.terminate()
                        print("Please wait...While we terminate your instances-----------------------------------------")
                        time.sleep(50)
                        print("All the instances has been terminated successfully!!!")
                        # delete network interfaces
                        for subnet in vpc.subnets.all():
                            subnet.delete()
                        print("All the subnets has been deleted successfully!!!")
                        del_nat_sg = ec2.SecurityGroup(del_nat_sg_id)
                        del_nat_sg.revoke_ingress(IpPermissions=del_nat_sg.ip_permissions)
                        del_pub_sg = ec2.SecurityGroup(del_pub_sg_id)
                        del_pub_sg.revoke_ingress(IpPermissions=del_pub_sg.ip_permissions)
                        del_pri_sg = ec2.SecurityGroup(del_pri_sg_id)
                        del_pri_sg.revoke_ingress(IpPermissions=del_pri_sg.ip_permissions)
                        print("All the inbound rules has been deleted successfully!!!")
                        #delete our security groups
                        for sg in vpc.security_groups.all():
                            if sg.group_name != 'default':
                                sg.delete()
                        print("All the security groups has been deleted successfully!!!")
                        # detach and delete all gateways associated with the vpc
                        for gw in vpc.internet_gateways.all():
                            vpc.detach_internet_gateway(InternetGatewayId=gw.id)
                            gw.delete()
                        print("Your internet gateway has been deleted successfully!!!")
                        # delete all route table associations
                        pub_rt = ec2.RouteTable(del_pub_rt_id)
                        pub_rt.delete()
                        pri_rt = ec2.RouteTable(del_pri_rt_id)
                        pri_rt.delete()
                        print("All the route table has been deleted successfully!!!")

                        client.delete_key_pair(KeyName=prefix_name+'-key_pair')
                        print("Your key pair has been deleted successfully!!!")

                        # finally, delete the vpc
                        ec2client.delete_vpc(VpcId=vpcid)
                        print("Your VPC has been deleted successfully!!!")
                    vpc_cleanup(del_vpc_id)
                elif confirm == "1":
                    todo_func()
                else:
                    print("Invalid option!!! Please enter valid option")
                    confirmation()
            confirmation()    
            todo_func()
    else:
        print("Invalid option!!! Please enter the valid option")
        delete_all()







def todo_func():
    print("Enter 0 to create any project")
    print("Enter 1 to delete any existing project")
    print("Enter 2 to exit")
    todo_option= str(input("Enter your option: "))
    if todo_option == '0':
        create()
        todo_func()
    elif todo_option == '1':
        delete_all()
    elif todo_option == '2':
        exit
    else:
        print("Invalid option!!! Please select valid option")
        todo_func()
    exit
todo_func()

print("Thank you for using this service!!!")
