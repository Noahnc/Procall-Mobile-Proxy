#!/bin/bash

##############################################################################################################
####################################### CoppyRight by Noah Canadea ###########################################
##############################################################################################################

RequestCertificate() {
    # Requestet das Zertifikat von LetsEncrypt und erstellt einen Cron job für die erneuerung
    varDomain="$1"

    certbot certonly --standalone -d "$varDomain" --non-interactive --agree-tos -m support@btcjost.ch
}

InstallCertbot() {
    # Installiert den Certbot für die LetsEncrypt Zertifikatsanforderung

    apt-get install certbot -y

}

InstallUFW() {
    # Installiert die UFW Firewall

    apt-get install ufw -y

}

ConfigureCertbot() {
    # Erstellt die befehle, das vor der erneuerung des Zertifikats der Nginx gestopt wird.

    varDomain="$1"
    echo "pre_hook = service nginx stop" >>"/etc/letsencrypt/renewal/$varDomain.conf"
    echo "post_hook = service nginx start" >>"/etc/letsencrypt/renewal/$varDomain.conf"

}

InstallNginx() {

    # Installiert den
    if ! [ -x "$(command -v nginx)" ]; then
        apt-get install nginx -y
    fi

    if ! [[ -f "/etc/ssl/certs/dhparam.pem" ]]; then
        echo "###############################################################################################"
        echo "Diffie-Hellman Schlüssel wird generiert, dies kann je nach Systemleistung bis zu 30min dauern!"
        echo "###############################################################################################"
        cd /etc/ssl/certs && openssl dhparam -out dhparam.pem 4096
    fi

    if [[ -f "/etc/nginx/sites-enabled/default" ]]; then
        rm /etc/nginx/sites-enabled/default
    fi

}

CreatenginxConfig() {
    # Erstellt den nginx proxy virtual Host
    varDomain="$1"
    varPort="$2"
    varUCServerIP="$3"
    varFullChainPath="$4"
    varKeyPath="$5"

    cat >/etc/nginx/sites-enabled/"$varDomain" <<EOF
server {
  listen       $varPort ssl;
  server_name  $varDomain;

  # Hinzufügen diverser security Header
  add_header Strict-Transport-Security "max-age=31536000; preload" always;
  add_header X-Frame-Options SAMEORIGIN;
  add_header X-Content-Type-Options nosniff;
  add_header X-XSS-Protection "1; mode=block";

  # Alle erlaubten TLS Versionen und Cipher
  ssl_prefer_server_ciphers on;
  ssl_protocols TLSv1.2 TLSv1.3;
  ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384';
  
  # SSL Private-Key & Public-Key
  ssl_certificate $varFullChainPath;
  ssl_certificate_key $varKeyPath;

  # DHparam für Verschlüsselung
  ssl_dhparam /etc/ssl/certs/dhparam.pem;
  
  ssl_session_cache shared:SSL:10m;
  index index.html index.htm;
  proxy_read_timeout 3600s;

  # Proxy Location für Frontend
  location / {
    proxy_set_header X-Real-IP \$remote_addr;
    proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    proxy_set_header Host \$http_host;
    proxy_set_header X-NginX-Proxy true;
    proxy_pass http://$varUCServerIP:7772;
    proxy_redirect off;
  }

  # Proxy Location für Websocket
  location /ws/client/websocket {
    proxy_pass http://$varUCServerIP:7772;
    proxy_http_version 1.1;
    proxy_set_header Upgrade \$http_upgrade;
    proxy_set_header Connection "upgrade";
  }
}
EOF

}

########################################## Script entry point ################################################

DependenciesOK=
varCertPEM=
varChainPEM=
varKeyPEM=
varDomain=
varUCServerIP=
varCertbotDependencysOK=
varLetsEncrypt=
varHTTPsPort=
varFullChainPath=
varKeyPath=

echo "
                  _____               _               _     _         
                 |___ /  _____  __   | |__  _   _    | |__ | |_ ___   
                   |_ \ / __\ \/ /   | '_ \| | | |   | '_ \| __/ __|  
                  ___) | (__ >  <    | |_) | |_| |   | |_) | || (__ _ 
                 |____/ \___/_/\_\   |_.__/ \__, |   |_.__/ \__\___(_)
                                            |___/  
____________________________________________________________________________________________

Dies ist das Setup Script für den btc ProCall Mobile Remote Proyx.

Bitte stelle sicher, das folgende Bedingungen erfüllt sind:
- Dieser Server ist über eine public IP über 80/443 oder einen anderen HTTPs Port erreichbar.
- Ein DNS A Record verweist auf die public IP dieses Servers.
- Dieser Server kann den Business CTI Server über TCP 7775 erreichen
"

# Auslesen ob alle Bedingungen erfüllt sind
while [[ $DependenciesOK != @("j"|"n") ]]; do
    read -r -p "Sind alle Bedingungen erfüllt? (j = Ja, n = Nein): " DependenciesOK
done

# Script beenden, wenn nicht alle Bedingungen OK
if [[ $DependenciesOK == "n" ]]; then
    echo "Bitte sorg dafür dass alle Bedingunen erfüllt sind und starte dann das Script erneut, bis bald."
    exit
fi

# Domain Auslesen
while [[ $varDomain = "" ]]; do
    read -r -p "Bitte die gewünschte Domain eingeben: " varDomain
done

# UCServer IP auslesen
while [[ $varUCServerIP = "" ]]; do
    read -r -p "Bitte die IP des UCServer eingeben: " varUCServerIP
done

# Auslesen ob das Zertifikat manuell oder automatisch per LetsEncrypt angelegt werden soll.
while [[ $varLetsEncrypt != @("j"|"n") ]]; do
    read -r -p "Möchtest du die Zertifikate über Lets'Encrypt beziehen? (j = Ja, n = Nein): " varLetsEncrypt
done

# Fragen ob die Bedingungen für LetsEncrypt gegeben sind
if [[ $varLetsEncrypt == "j" ]]; then

    while [[ $varCertbotDependencysOK != @("j"|"n") ]]; do
        read -r -p "Damit Let's Encrypt funktioniert, muss als HTTP/s Port 80 / 443 verwendet werden, ist dies der Fall? (j = Ja, n = Nein): " varCertbotDependencysOK
    done

    if [[ $varCertbotDependencysOK == "n" ]]; then
        echo "Öffne entweder die Ports 80/443 oder wähle die manuelle Zertifikatsverwaltung."
        exit
    fi

    varHTTPsPort="443"

fi

# Auslesen der Zertifikate und des HTTPs Ports
if [[ $varLetsEncrypt == "n" ]]; then

    read -r -p "Bitte den gewünschten HTTPs Port eingeben (ohne Eingabe wird 443 verwendet: ) " varHTTPsPort

    if [[ $varHTTPsPort == "" ]]; then
        varHTTPsPort="443"
    fi

    echo ""
    while [[ $varCertPEM = "" ]]; do
        echo "Bitte das Zertifikat als PEM einfügen (von -----BEGIN CERTIFICATE----- bis -----END CERTIFICATE-----"
        IFS= read -r -d '' -n 1 varCertPEM
        while IFS= read -r -d '' -n 1 -t 2 c; do
            varCertPEM+=$c
        done

    done

    echo ""
    while [[ $varChainPEM = "" ]]; do
        echo "Bitte das Zwischenzertifikat als PEM einfügen (von -----BEGIN CERTIFICATE----- bis -----END CERTIFICATE-----"
        IFS= read -r -d '' -n 1 varChainPEM
        while IFS= read -r -d '' -n 1 -t 2 c; do
            varChainPEM+=$c
        done
    done

    echo ""
    while [[ $varKeyPEM = "" ]]; do
        echo "Bitte den Key als PEM einfügen (von -----BEGIN RSA PRIVATE KEY----- bis -----END RSA PRIVATE KEY-----"
        IFS= read -r -d '' -n 1 varKeyPEM
        while IFS= read -r -d '' -n 1 -t 2 c; do
            varKeyPEM+=$c
        done

    done

fi

# Paketliste aktuallisieren
apt-get update
sleep 5

# UFW Firewall installieren fals noch nicht installiert.
if ! [ -x "$(command -v ufw)" ]; then
    apt-get install ufw
fi

# UFW default Policys erstellen
ufw default deny incoming
ufw default allow outgoing
ufw allow 22

if [[ $varLetsEncrypt == "j" ]]; then

    # Certbot installieren falls noch nicht installiert
    if ! [ -x "$(command -v certbot)" ]; then
        InstallCertbot
    fi

    # Zertifikat beantragen
    RequestCertificate "$varDomain"

    # Certbot für die automatische erneuerung konfigurieren
    ConfigureCertbot "$varDomain"
    varFullChainPath="/etc/letsencrypt/live/$varDomain/fullchain.pem"
    varKeyPath="/etc/letsencrypt/live/$varDomain/privkey.pem"

    # Firewall Policy für nginx und Certbot erstellen
    ufw allow 80
    ufw allow 443

fi

if [[ $varLetsEncrypt == "n" ]]; then

    # Verzeichniss für Zertifikate erstellen und Fullchain erstellen
    mkdir -p /etc/ssl/ProCallProxyCerts
    cat >/etc/ssl/ProCallProxyCerts/Fullchain.pem <<EOF
$varCertPEM
$varChainPEM
EOF

    cat >/etc/ssl/ProCallProxyCerts/Key.pem <<EOF
$varKeyPEM
EOF

    varFullChainPath="/etc/ssl/ProCallProxyCerts/Fullchain.pem"
    varKeyPath="/etc/ssl/ProCallProxyCerts/Key.pem"
    ufw allow $varHTTPsPort

fi

InstallNginx

# Anlegen des Nginx proxy V-Host File
CreatenginxConfig "$varDomain" "$varHTTPsPort" "$varUCServerIP" "$varFullChainPath" "$varKeyPath"

# Aktivieren der Firewall
yes | ufw enable

# Nginx proxy neustarten
service nginx restart
