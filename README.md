# RUN auto update on CloudFlare
*Project test on Linux*

This project helps to update CloudFlare DNS with register A or AAAA with suporte to CloudFlare proxy, and time TTL define. 

You can run this project in your own computer or you can run on a docker.

This project support add JWT token to check the IP address and api-key. This is useful for some security reasons.

## Define your variables

create a file .env in the root of the project. Do not sincronized this file on Git repository for security reasons
```
URL_CHECK_IP="{CREATE_YOUR_OWN_SERVER}"
CLOUDFLARE_TOKEN= "{TOKEN_CLOUDFLARE}"
DOMAINS= "{test@example.com=proxy&example@server.com=1}"
JWT_SECRET = "{your-256-bit-secret}"
API_KEY= "{api-key}"
REGISTER_LOCAL="{my_computer_local@example.com=1"
TIME_UPDATE={900 for 15 minutes}
WEEBHOOK="{WEEBHOOK_URL}"
```

> About the variables:

If you wan to run just locally you can't run on docker, because the script get the local ip address. In this case you just need configure REGISTER_LOCAL and CLOUDFLARE_TOKEN

If you want to run for public access you can run on docker, in this case you need CLOUDFLARE_TOKEN and DOMAINS

Description

- JWT_SECRET -> used if you want to add Bearer token on request
- API_KEY -> add x-api-key value on the request url
- URL_CHECK_IP -> is the URL to check your public ip, this script accept return json body 
```json
{
    "ip": "0.0.0.0"
}
```
- WEEBHOOK -> if you want weebhook action after the job is done
- TIME_UPDATE -> the inteval in minutes to check and update the registers, if you running without docker considering use crontab for this job



## Steps do run this project with Docker

- Create your own .env file
- Add your variables to the file
- Use docker compose to build and run

```bash
docker-compose up

# to run on background
docker-compose up -d
```

## In your computer

You need have python 3 and pip installed

```bash
# Create your virtualenv 
virtualenv virtual_name 

# Accessing the virtualenv
source virtual_name/bin/activate

# Install the pip packages
pip3 install -r requirements.txt

# Test the script
python3 index.py

# Add job on crontab. Use root
crontab -e
```

```
*/1 * * * * /data/virtual_name/bin/python /data/script_location/index.py
```




#### Feel free to send me news, bugs and suggestions to this package

## Rafael Schneider - rafaelscone