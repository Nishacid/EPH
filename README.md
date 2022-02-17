# EPH (Exposed Panels Hunting)

`EPH` is a tool which allows you to perform scans to find exposed administration panels that can lead to security vulnerabilities.

It can be used offensively (`Pentest`, `Bug Bounty`...) or defensively (`Threat Hunting`).

The search is realized by Shodan, so you will need an API key (free API keys are not working).
Queries can be done with a custom favicon or by using the available database containing a list of dangerous and frequently used panels.

## Hash in [database](./database.yml): 

- Gitlab 
- FS Switch
- Spring Boot
- Tomcat
- PhpMyAdmin
- Jenkis
- OpenVPN
- Portainer
- GraphQL
- Adminer
- Roundcube Webmail
- pfSense
- cPanel Login
- Magento 
- SeaFile
[...]

## Installation 

```bash
git clone https://github.com/Nishacid/EPH.git
cd  EPH/
pip3 install -r requirements.txt
```

## Usage

```bash
usage: main.py [-h] --api API [--org ORG] [--url URL] [--img IMG] [--hash HASH] [--common]

optional arguments:
  -h, --help   show this help message and exit
  --api API    Shodan API Key
  --org ORG    Targeted organization
  --url URL    URL of the favicon
  --img IMG    Image source of the favicon
  --hash HASH  Hash of the favicon
  --common     Common Favicon Scan
```

## Exemple 

### Exemple with a local favicon
```python
╰─➤ python3 main.py --api YourAPIKey --img ./samples/adminer.ico --org MyOrg
[+] The hash of the favicon is : 572074752
[+] Perfoming a shodan scan...
[+] Total results found : 2

IP : 10.10.10.01
Port : 80
Organization : MyOrg

IP : 10.10.10.02
Port : 8080
Organization : MyOrg
```

### Exemple with a favicon of an url
```python
╰─➤ python3 main.py --api YourAPIKey --url https://www.phpmyadmin.net/static/favicon.ico
[+] The hash of the favicon is : -476231906
[+] Perfoming a shodan scan...
[+] Total results found : 35602

IP : 10.10.10.01
Port : 80
Organization : YourOrg

IP : 127.0.0.1
Port : 443
Organization : MyOrg
[...]
```

### Exemple with a hash
```python
╰─➤ python3 main.py --api YourAPIKey --org l33t --hash -297069493
[+] The hash of the favicon is : -297069493
[+] Perfoming a shodan scan...
[+] Total results found : 18

IP : 10.10.10.01
Port : 8080
Organization : l33t

IP : 10.10.13.37
Port : 443
Organization : l33t
[...]
```

## Scan for common and dangerous exposed panels
```python
╰─➤ python3 main.py --api YourAPIKey --org My0rG --common
[+] Perfoming a common scan...
[+] Scanning for Gitlab
[+] Total results found : 2

IP : 10.10.10.01
Port : 80
Organization : My0rG

IP : 10.10.13.37
Port : 443
Organization : My0rG

[+] Scanning for FS Switch
[+] Total results found : 0

[+] Scanning for Tomcat
[+] Total results found : 1
IP : 172.0.4.20
Port : 8080
Organization : My0rG
```

# Contributing

Pull requests are welcome. Feel free to contribute to complete this database or to make improvements.

You can contact me on Twitter [@Nishacid](https://twitter.com/Nishacid) or [nishacid@protonmail.com](mailto:nishacid@protonmail.com)