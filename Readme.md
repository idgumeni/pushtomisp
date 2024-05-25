**PUSHTOMISP**

Pushtomisp is an interface between Assemblyline 4 (AL4 for short) ([https://cybercentrecanada.github.io/assemblyline4_docs/](https://cybercentrecanada.github.io/assemblyline4_docs/) - file triage and malware analysis system) and MISP ([https://www.misp-project.org/](https://www.misp-project.org/) - opensource threat intelligence and sharing platform) written in python.

Pushtomisp is uploading malware analysis results data from Assemblyline to MISP using an assemblyline’s webhook post-process action.

This interface is compatible with Assemblyline's RESTfull API v4 and MISP API v2.4.

**Setting up:**

In order to be able to establish communication between these modules, it is necessary to create an addressing plan:

- ip class address for pushtomisp network: <pushtomisp_network_class> ( x.x.x.x/x )
- name and ip address that will be allocated to pushtomisp container: <pushtomisp_ip> (x.x.x.x)
- tcp port where pushtomisp interface should listen: <pushtomisp_port> (xxxx)
- name and ip address where AL4 web interface is accessible (normally IP address of host): <al4_ip>(x.x.x.x)
- tcp port where AL4 web interface is accessible (normally default HTTPS port – 443): <al4_port> (xxxx)
- name and ip address where MISP web interface is accessible (normally IP address of host): <misp_ip> (x.x.x.x)
- tcp port where MISP web interface is accessible (should be specified other port than the default one): <misp_port> (xxxx)

Once all those parameters are established you can continue with configurations.

  

**Configurations:**

To understand how to configure all the elements (AL4, pushtomisp, MISP) you need to understand the data flow. Post-action webhook defined in Assemblyline (AL4) trigger pushtomisp interface by sending submission data (AL4 -> Pushtomisp). Then Pushtomisp query Assemblyline REST API for ontology related to current submission (Pushtomisp -> AL4). Indicators extracted from AL4 ontology will be pushed to MISP as event with related attributes (Pushtomisp -> MISP).

  

1.) Install CCCS-AL as described in [https://cybercentrecanada.github.io/assemblyline4_docs/installation/appliance/docker/](https://cybercentrecanada.github.io/assemblyline4_docs/installation/appliance/docker/)

  1.1) Dispatcher service container from Assemblyline should be able to call the URL that will be configured as post-action webhook (see bellow) so dispatcher service need to see “external” network.

Edit docker-compose.yml to enable “external” network for service dispatcher.

Edited dispatcher’s network section in docker-compose.yml should look like this:

```

dispatcher:
. . .
  networks: [core, external]
. . .   
```


  

2.) Install MISP as docker - misp-core and misp-modules as described in [https://github.com/MISP/misp-docker](https://github.com/MISP/misp-docker). If you run Assemblyline and MISP containers on same host you need to configure Misp service to run on different port (8443 for example) to avoid conflict with Assemblyline service (al-nginx frontend) which runs on standard HTTPS port (443) – see instructions bellow at paragraph “Install MISP as containers and run on non-default port”


3.) Create in Assemblyline interface a post-action webhook to trigger pushtomisp interface.

On Assemblyline interface follow “Administration-> Post-process actions” path:

  

```

pushtomisp:

  archive_submission: false
  enabled: true
  filter: 'max_score: >0'
  raise_alert: false
  resubmit:
    additional_services: []
    random_below: 500
  run_on_cache: true
  run_on_completed: true
  webhook:
    uri: http://<pushtomisp_ip>:<pushtomisp_port>/newSubmission
    headers: []
    retries: 1
    ssl_ignore_errors: True
    method: POST

```

4.) Generate apikey in Assemblyline for pushtomisp interface.

On Assemblyline interface follow “Administration -> Users -> [Select the user for which you want to generate the API key from the list] -> Manage API Keys -> click '+' to add a new API key” path.

  

5.) Generate API key in MISP for pushtomisp interface.

On MISP web interface follow “Administration -> List Auth Keys -> Add authentication key” path.

  


6.) Run pushtomisp interface as container.

```

cd  ~/git

git clone [https://github.com/idgumeni/pushtomisp.git](https://github.com/idgumeni/pushtomisp.git)

cp -R ~/git/pushtomisp ~/deployments/pushtomisp

cd ~/deployments/pushtomisp

cp conf/config.yaml.example conf/config.yaml

  

```

  6.1.) Configure pushtomisp interface.

  Pushtomisp interface have an example configuration file located in conf/config.yaml.example that should be renamed to “conf/config.yaml” and edited with your actual parameters:

  

  

```

pushtomisp:
  network:
    address_bind: "<pushtomisp_ip>" #without <>
    port: <pushtomisp_port>
    method: POST
    ssl: false
  system:
    maxthreads: 4
  logging:
    logfile: pushtomisp.log
    loglevel: WARNING
assemblyline:
  host: "<al4_ip>"
  user: "admin"
  apikey: "**username:...apikey...**"
  tool_name: "assemblyline_v4"
misp:
  url: "**https://<misp_ip>:<misp_port>/**"
  apikey: "**...apikey...**"
  content_type: "json"
  analysis: "0" #initial analisys
  threat_level_id: "4" #undefined
  distribution: "0" #Organization
```

Build pushtomisp container image and run:

```
sudo docker network create –subnet=<pushtomisp_network_class> pushtomisp_network

sudo docker build -t pushtomisp .

sudo docker run -d --name pushtomisp-app --net pushtomisp_network --ip <pushtomisp_ip> pushtomisp

```

  

7.) Enable ipv4 forwarding on host to enable communications between containers (AL4, pushtomisp, MISP):

 ```
 #find network interface associated with assemblyline dispatcher "al_external" network (run as root)
 al_dispatcher_subnet=`docker network inspect  al_external -f '{{range .IPAM.Config}}{{print .Subnet}}{{end}}' | awk -F"." '{ print $1"."$2"."$3 }'`
 net_if_al=`ip -o -f inet addr show | grep $al_dispatcher_subnet | awk -F 'global' '{ print $2}' | awk -F'\\' '{ print $1 }'`

 #find network interface associated with misp-core "misp-docker_default" network
 misp_core_subnet=`docker network inspect misp-docker_default -f '{{range .IPAM.Config}}{{print .Subnet}}{{end}}' | awk -F"." '{ print $1"."$2"."$3 }'`
 net_if_misp=`ip -o -f inet addr show | grep $misp_core_subnet | awk -F 'global' '{ print $2}' | awk -F'\\' '{ print $1 }'`

 #insert rules in iptables chain "DOCKER-ISOLATION-STAGE-2":

iptables -I DOCKER-ISOLATION-STAGE-2 -o $net_if_al -i $net_if_misp -j ACCEPT
iptables -I DOCKER-ISOLATION-STAGE-2 -o $net_if_misp -i $net_if_al -j ACCEPT
```  


  

**Additional instructions:**

**Install MISP as containers and run on non-default port**

  

Clone misp-docker repository:

```

cd  ~/git

git clone [https://github.com/MISP/misp-docker.git](https://github.com/MISP/misp-docker.git)

cp -R ~/git/misp-docker ~/deployments/misp-docker

```

  

Edit docker-compose.yml and change default ports 80 -> 8080 and 443 -> 8443 :

```

cd ~/deployments/misp-docker

cp template.env .env

sed -i 's/80:80/8080:8080/g' docker-compose.yml

sed -i 's/443:443/8443:8443/g' docker-compose.yml

```

Change also listening ports in nginx config files:

```

sed -i 's/80/8080/g' ./core/files/etc/nginx/sites-available/misp80

sed -i 's/443/8443/g' ./core/files/etc/nginx/sites-available/misp

  

sudo docker-compose pull

```

Because we use same host to run assemblyline and MISP containers, in order to avoid address pool collision , we have to add specify a subnet for “misp-docker_default” network by adding following lines to misp-docker/docker-compose.yml file:

  
```
networks:
  default:
    ipam:
      config:
      - subnet: 10.29.0.0/16

```
  
(be aware that YAML files are sensitive to indentation !)

Also edit in .env BASE_URL=[https://localhost:8443](https://localhost:8443/)

  ```

sudo docker-compose build
sudo docker-compose up -d

```

You should see :

misp-core-1 | MISP | Mark instance live

misp-core-1 | Set live status to True in Redis.

misp-core-1 | Set live status in PHP config file.

misp-core-1 | MISP is now live. Users can now log in.


Create HTTPS certificates:
```
sudo openssl req -nodes -x509 -newkey rsa:4096 -keyout ~/deployments/misp-docker/ssl/key.pem -out ~/deployments/misp-docker/ssl/cert.pem -days 1095 -subj "/C=US/ST=US/L=LosAngeles/O=MISP/CN=misp.local"
```

To stop containers:

```

cd ~/deployments/misp-docker

sudo  docker-compose  stop

sudo  docker  rm  --force  $(sudo docker ps -a –filter label=com.docker.compose.project=misp-docker -q)

sudo  docker-compose  down  --remove-orphans  
```

To bring up:

```
sudo docker-compose up -d
```






