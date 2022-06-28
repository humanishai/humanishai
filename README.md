## First unzip your zipped up file from me

Unzip the file like so
```
tar -xf chasebrignac.tar.gz
mv chasebrignac simtooreal
cd simtooreal
```

## For local development

Install homebrew

```
sudo /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install.sh)"
```

For Unix/Linux OS you might go to the official Terraform site and download bin-file with software.  
  
Install docker  
Download here https://www.docker.com/products/docker-desktop  
Follow the instructions to install it and start docker desktop  
  
Install Postman  
Download here https://www.postman.com/downloads/  
Follow the instructions to install it  

Install terraform  
```
brew tap hashicorp/tap
brew install hashicorp/tap/terraform
```

This was my version of terraform and my providers
chase@Chases-MacBook-Pro simtooreal % terraform --version  
Terraform v0.14.9
+ provider registry.terraform.io/hashicorp/aws v3.33.0
+ provider registry.terraform.io/hashicorp/template v2.2.0

Install aws cli
```
brew install awscli
```

Install ansible
```
brew install ansible
```

Install postgres
```
brew install postgres
```

Install python annd packages for testing the API
```
brew install python3
pip3 install requests
pip3 install coolname
```

Only use this command when you want to setup your local environment variables in a new shell window
```
export PGPASSWORD=magical_password && export POSTGRESQL_HOST_FROM_DOCKER=simtooreal_database_1 && export POSTGRESQL_USER_NAME=unicorn_user && export POSTGRESQL_PASSWORD=magical_password && POSTGRESQL_HOST=localhost
```

To start the app locally
```
untar chasebrignac.tar.gz
cd simtooreal
echo 'OPENAI_API_KEY=<your OpenAI API key>' > .env
docker-compose down --volumes && docker-compose build --no-cache && docker-compose up
```

To enter the local database in another terminal on your machine
```
psql --host=localhost --username=unicorn_user --dbname=simtooreal -w
```
When you want to quit the app locally use ctrl+c in the window you started the app in
If you would like to restart the app with some code changes locally use this command
```
docker-compose down --volumes && docker-compose build --no-cache && docker-compose up
```
To see log messages related to simtooreal_app run this command
```
docker service logs simtooreal_app
```
To see the "CURRENT STATE" of a service and even "ERROR" messages run this command
```
docker service ps simtooreal_app
```
visit localhost in your browser to see the app running
If you ever run into this error
```
ERROR: for simtooreal_app_1  Cannot create container for service app: max depth exceeded

ERROR: for app  Cannot create container for service app: max depth exceeded
ERROR: Encountered errors while bringing up the project.
```
Have no fear it just means you have made too many docker images
To make this message go away run this command
```
docker system prune -a
```
If you want to replace all data from the database but you are running a docker stack you will first need to run these commands
```
docker stack rm simtooreal
docker system prune -a
docker volume rm simtooreal_database-data
docker stack deploy --compose-file=docker-compose.yml simtooreal
```

## Buy a domain

Buy a domain like simtooreal.com domain and make sure you can use it in your us-east-1 account  
Don't forget to update any instance of simtooreal.com with your domain in main.tf  
  
## Setup AWS credentials

Setup an AWS key pair in IAM console in us-east-1 for setting up the infrastructure in terraform and use these as `<your aws id>` and `<your aws key>`

## Gain access to GPT-3

Setup a GPT-3 Beta access account and use the key found here https://beta.openai.com/docs/developer-quickstart/your-api-keys as `<your OpenAI API key>`

## Make a private and public ssh key pair
```
ssh-keygen -t rsa -b 4096 -C "chase.brignac@gmail.com"
```
Press enter a few times to accept defaults until the command is done

Start the ssh agent in the background
```
eval "$(ssh-agent -s)"
```

Add SSH private key to the ssh-agent
```
ssh-add ~/.ssh/id_rsa
```

## Run the following commands to setup all infrastructure

Put your public ssh key (~/.ssh/id_rsa.pub) in the resource "aws_key_pair" "simtooreal" section of the main.tf terraform file as the string value of public_key in quotation marks so you can login to the bastion later  
  
You also need to update the IP address allowed to attempt public subnet SSH access in main.tf  
you will find this in the following section:  
"aws_security_group" "simtooreal_public"  
  
To initialize terraform and get the external modules used use these commands  
  
Setup a terraform cloud account at https://app.terraform.io/  
  
Make an organization and a workspace in terraform cloud making sure to integrate your workspace with your github repo
  
Export your sensitive information as environment variables in terraform cloud located here https://app.terraform.io/app/simtooreal/workspaces/simtooreal/variables under `Environment Variables`

Your environment variables are all sensitive so be sure when you add a variable key value pair you check "sensitive" checkbox
```
TF_VAR_openai_api_key = <your OpenAI API key>
TF_VAR_db_password = <insert database password>
AWS_ACCESS_KEY_ID = <your aws id>
AWS_SECRET_ACCESS_KEY = <your aws key>
TF_VAR_aws_access_key_id = <your aws id>
TF_VAR_aws_secret_access_key = <your aws key>
```

Now when you push to github terraform cloud will automatically attempt an apply, show you the resulting changes, and ask for your manual confirmation of a run here before terraform infrastructure is applied https://app.terraform.io/app/simtooreal/workspaces/simtooreal/runs  
  
Then state is updated and managed in the cloud automatically for you here https://app.terraform.io/app/simtooreal/workspaces/simtooreal/states  
  
Multiple people can use this, you don't always need to terraform apply, and you don't need to manage sensitive passwords or state on your local machine  
  
Wait for terraform apply to finish and you should have a green output in your run if all goes well

## Enable ssh key agent forwarding and login to the bastion and the private instance to setup the database

Open up your ssh config and edit it making sure to use the IP addresses you just found for your instances
```
nano ~/.ssh/config
```

```
Host *
  AddKeysToAgent yes
  UseKeychain yes
  IdentityFile ~/.ssh/id_rsa
Host 3.237.80.32
  HostName 3.237.80.32
  ForwardAgent yes
  IdentityFile ~/.ssh/id_rsa
  User ubuntu
Host 172.17.0.41
  User ubuntu
  IdentityFile ~/.ssh/id_rsa
  ProxyCommand ssh -W %h:%p 3.237.80.32
```
Close the file
Make sure the config file isn't accessible to everyone
```
chmod 600 ~/.ssh/config
```

Now you will login to your private machine without storing any credentials on the bastion
```
ssh -A -i "~/.ssh/id_rsa" ubuntu@public.simtooreal.com
```
If you get the error Host key verification failed. you need to open your ~/.ssh/known_hosts file and empty it  
This error means that someone may have replaced the public instance with another one and is trying to trick you  
Usually the simpler explanation is that you yourself or the local infrastructure admin have replaced the bastion  
But be security minded and be careful  
```
ssh -o StrictHostKeyChecking=no -i "~/.ssh/id_rsa" ubuntu@private.simtooreal.com
```
ssm and aws_instance user_data have put a zipped up version of simtooreal on the instance for your convenience
```
cd /simtooreal
```

Run these commands on the private instance to setup and seed the database with data to your liking
```
export PGPASSWORD=<insert database password>
ansible-playbook -i hosts setup.yml
ansible-playbook -i hosts insert_item.yml -e "item_name='action toy'"
ansible-playbook -i hosts insert_item.yml -e "item_name='race car'"
ansible-playbook -i hosts insert_item.yml -e "item_name='candy bar'"
ansible-playbook -i hosts insert_item.yml -e "item_name='ice cream'"
ansible-playbook -i hosts insert_item.yml -e "item_name='big thing'"
ansible-playbook -i hosts insert_item.yml -e "item_name='small thing'"
ansible-playbook -i hosts insert_item.yml -e "item_name='doll'"
ansible-playbook -i hosts insert_item.yml -e "item_name='box'"
ansible-playbook -i hosts insert_item.yml -e "item_name='envelope'"
ansible-playbook -i hosts insert_robot.yml -e "robot_name='big robot'"
ansible-playbook -i hosts insert_robot.yml -e "robot_name='little robot'"
ansible-playbook -i hosts insert_robot.yml -e "robot_name='optimus'"
ansible-playbook -i hosts item_picks.yml -e "item_name='candy bar'"
ansible-playbook -i hosts robot_picks.yml -e "robot_name='walle'"
```

Press ctrl+D twice when you setup the database to get back to your machine

## Setup github secrets

Start a new repo in github called simtooreal  
You want to initialize the simtooreal folder as a git repo
```
git init
git branch -m main
```
Make sure to setup ssh keys in github and locally using these instructions  
https://docs.github.com/en/github/authenticating-to-github/connecting-to-github-with-ssh  
Or use https  
Push to github and setup your repo in github to allow actions
```
git add .
git commit -m "initial commit"
git push origin main
```

Make sure you add AWS_ACCESS_KEY_ID with a value of `<your aws id>` and AWS_SECRET_ACCESS_KEY with a value of `<your aws key>` in your Github secrets, for example my secrets are found here https://github.com/chasebrignac/simtooreal/settings/secrets/actions

## Set github workflows environment variables

I have my environment variables set in github workflow but you will need to put your own values in, my settings are found here   https://github.com/chasebrignac/simtooreal/blob/main/.github/workflows/aws.yml

## Run a Github action so that you can push an image to ECR and deploy automatically

When you are ready to zip up some of the scripts to put on the private instance run this command
```
rm simtooreal.tar.gz && rsync -a *.sql simtooreal && rsync -a *.py simtooreal && rsync -a *.yml simtooreal && rsync -a *.txt simtooreal && rsync -a topics.csv simtooreal && rsync -a Dockerfile simtooreal && rsync -a clf.joblib simtooreal && rsync -a templates simtooreal && rsync -a *.json simtooreal && tar -zcvf simtooreal.tar.gz simtooreal && rm -rf simtooreal
```
This also updates the version of simtooreal found on the private instance after you destroy an instance and re-run the terraform apply in terraform cloud  
  
When you are ready to update your bastion make a new version with tar
```
tar -zcvf bastion.tar.gz bastion
```
Now you can update the bastion in the instance by running the terraform apply in terraform cloud again  
  
Login to github and setup a repo under your username called simtooreal without a README.md  
Now on your local machine's terminal in the simtooreal folder initialize git and push your code to github
```
git init
git add .
git commit -m "first commit"
git remote add origin https://github.com/<your github username>/simtooreal.git
git branch -M main
git push -u origin main
```

## Automated training and pushing of pickle file to github and then to ECS happens on the private instance

The data engine can turn every day by training on the AWS private instance as long as your github credentials are setup  
Make sure to setup ssh keys in github and on the private instance in AWS using these instructions. 
https://docs.github.com/en/github/authenticating-to-github/connecting-to-github-with-ssh  
Or use https  
After cloning the repo onto your private instance you can run the training automatically by starting a tmux session  
Then you can set environment variables and run the command to train your model and update your pickle file  
```
export PGPASSWORD=<insert database password> && export POSTGRESQL_HOST=database.simtooreal.com && export POSTGRESQL_USER_NAME=postgres && export POSTGRESQL_PASSWORD=<insert database password>
```
It will repeate every 24 hours, automatically updating your models for inference, and pickle file history is kept in github
