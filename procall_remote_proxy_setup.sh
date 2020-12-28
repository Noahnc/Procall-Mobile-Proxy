#!/bin/bash

##############################################################################################################
####################################### CoppyRight by Noah Canadea ###########################################
##############################################################################################################

# Beende das Script sollte ein Fehler auftreten
#set -euo pipefail

OK() {
    echo -e "\e[32m$1\e[39m"
}

error() {
    echo -e "\e[31m
Fehler beim ausführen des Scripts, folgender Vorgang ist fehlgeschlagen:
$1
Bitte prüfe den Log-Output.\e[39m"
    rm -r "$ScriptFolderPath"
    exit 1
}

CheckDomainRecord() {

    # Variable zurücksetzen auf default
    varDomainRecordOK="true"

    # Prüfen ob ein A Record gefunden wird, wenn nein wird auf false gesetzt
    host -t a "${1}" | grep "has address" >/dev/null || {
        varDomainRecordOK="false"
        echo -e "\e[31mDie Für ${1} wurde leider kein DNS A Record gefunden\e[39m"
    }

    if [[ $varDomainRecordOK = "true" ]]; then
        varDomainRecordIP=$(host -t a "${1}" | grep "address" | cut -d" " -f4)
        if [[ "$varDomainRecordIP" = "${2}" ]]; then
            varDomainRecordOK="true"
        else
            varDomainRecordOK="false"
            echo -e "\e[31mDie Domain ${1} verweist nicht auf die IP ${2}, sondern auf $varDomainRecordIP\e[39m"
            echo -e "\e[31mPrüfe den DNS Record und die Public IP und versuche es nochmals!\e[39m"
        fi
    fi

}

RequestCertificate() {
    # Requestet das Zertifikat von LetsEncrypt und erstellt einen Cron job für die erneuerung
    varDomain="$1"

    certbot certonly --standalone -d "$varDomain" --non-interactive --agree-tos -m support@btcjost.ch || error "Beantragen des Zertifikats für $varDomain über LetsEncrypt fehlgeschlagen"
}

ConfigureCertbot() {
    # Erstellt die befehle, das vor der erneuerung des Zertifikats der Nginx gestopt wird.

    varDomain="$1"
    echo "post_hook = service nginx restart" >>"/etc/letsencrypt/renewal/$varDomain.conf"

}

InstallNginx() {

    # Installiert den
    if ! [ -x "$(command -v nginx)" ]; then
        apt-get install nginx -y || error "Installation des nginx proxy fehlgeschlagen"
    fi

    if ! [[ -f "/etc/ssl/certs/dhparam.pem" ]]; then
        echo "###############################################################################################"
        echo "Diffie-Hellman Schlüssel wird generiert, dies kann je nach Systemleistung bis zu 30min dauern!"
        echo "###############################################################################################"
        cd /etc/ssl/certs && openssl dhparam -out dhparam.pem 4096 || error "Generieren der DH Parameter fehlgeschlagen"
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

MyPublicIP=$(curl ipinfo.io/ip)
DependenciesOK=
varCertPEM=
varChainPEM=
varKeyPEM=
varDomain=
varUCServerIP=
varCertbotDependencysOK=
varLetsEncrypt=
varContentValid=
varHTTPsPort=
varFullChainPath=
varKeyPath=
ScriptFolderPath="$(dirname -- "$0")"

echo -e " \e[34m
 ____             ____      _ _       _                 _     _         
|  _ \ _ __ ___  / ___|__ _| | |     | |__  _   _      | |__ | |_ ___   
| |_) | '__/ _ \| |   / _  | | |     | '_ \| | | |     | '_ \| __/ __|  
|  __/| | | (_) | |__| (_| | | |     | |_) | |_| |     | |_) | || (__ _ 
|_|   |_|  \___/ \____\__,_|_|_|     |_.__/ \__, |     |_.__/ \__\___(_)
                                            |___/
____________________________________________________________________________________________

Dies ist das Setup Script für den btc ProCall Mobile Remote Proyx.

Bitte stelle sicher, das folgende Bedingungen erfüllt sind:
- Dieser Server ist über eine public IP über 80/443 oder einen anderen HTTPs Port erreichbar.
- Ein DNS A Record verweist auf die public IP dieses Servers.
- Dieser Server kann den Business CTI Server über TCP 7775 erreichen
\e[39m
"

# Auslesen ob alle Bedingungen erfüllt sind
while [[ $DependenciesOK != @("j"|"n") ]]; do
    read -r -p "Sind alle Bedingungen erfüllt? (j = Ja, n = Nein): " DependenciesOK
done

# Script beenden, wenn nicht alle Bedingungen OK
if [[ $DependenciesOK == "n" ]]; then
    echo "Bitte sorg dafür dass alle Bedingunen erfüllt sind und starte dann das Script erneut, bis bald."
    rm -r "$ScriptFolderPath"
    exit
fi

varContentValid="false"
while [[ $varContentValid = "false" ]]; do
    echo "Folgende public IP wurde erkannt, drücke Enter wenn diese korrekt ist oder passe sie manuell an:"
    read -r -e -i "$MyPublicIP" MyPublicIP
    if ! [[ $MyPublicIP =~ [^0-9.] ]]; then
        varContentValid="true"
    else
        echo -e "\e[31mKeine gültige Eingabe!\e[39m"
    fi

done

varDomainRecordOK="false"

while [[ $varDomainRecordOK = "false" ]]; do

        while [[ $varDomain = "" ]]; do
            echo "Bitte den gewünschte FQDN eingeben (Bspw. procall.musterag.ch):"
            read -r -e -i "$varDomain" varDomain
            CheckDomainRecord "$varDomain" "$MyPublicIP"
        done

done

varContentValid="false"
while [[ $varContentValid = "false" ]]; do
    echo "Gib die IP des UCServers ein"
    read -r -e -i "$varUCServerIP"
    if ! [[ $varUCServerIP =~ [^0-9.] ]]; then
        varContentValid="true"
    else
        echo -e "\e[31mKeine gültige Eingabe!\e[39m"
    fi

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
        error "Öffne entweder die Ports 80/443 oder wähle die manuelle Zertifikatsverwaltung."
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
    apt-get install ufw || error "Installation der UFW Firewall fehlgeschlagen"
fi

# UFW default Policys erstellen
ufw default deny incoming
ufw default allow outgoing
ufw allow 22

if [[ $varLetsEncrypt == "j" ]]; then

    # Certbot installieren falls noch nicht installiert
    if ! [ -x "$(command -v certbot)" ]; then
        apt-get install certbot -y || error "Installation von Certbot fehlgeschlagen"
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
    cat >/etc/ssl/certs/ProCallFullchain.pem <<EOF
$varCertPEM
$varChainPEM
EOF

    cat >/etc/ssl/private/ProCallKey.pem <<EOF
$varKeyPEM
EOF

    varFullChainPath="/etc/ssl/certs/ProCallFullchain.pem"
    varKeyPath="/etc/ssl/private/ProCallKey.pem"
    ufw allow $varHTTPsPort

fi

InstallNginx

# Anlegen des Nginx proxy V-Host File
CreatenginxConfig "$varDomain" "$varHTTPsPort" "$varUCServerIP" "$varFullChainPath" "$varKeyPath"

# Aktivieren der Firewall
yes | ufw enable

# Nginx proxy neustarten
service nginx restart
