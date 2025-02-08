#!/bin/bash

while getopts ":d:" input;do
        case "$input" in
                d) domain=${OPTARG}
                        ;;
                esac
        done
if [ -z "$domain" ]     
        then
                echo "Please give a domain like \"-d domain.com\""
                exit 1
fi

## Please uncomnment the the functionationality which you wanted use (script is still under active production)
#mkdir $domain

#cd $domain

#mkdir 1_tmp 2_bulk 3_juicy

####SUBDOMAIN ENUMERATION
#curl --insecure -L -s "https://urlscan.io/api/v1/search/?q=domain:$domain" 2> /dev/null | egrep "country|server|domain|ip|asn|$domain|prt"| sort -u | tee 1_tmp/urlscanio.list 2> /dev/null

#curl -s "https://api.certspotter.com/v1/issuances?domain=$domain&include_subdomains=true&expand=dns_names" | jq .[].dns_names | grep -Po "(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | sort -u | tee 1_tmp/certspotter.list

#curl -s "https://jldc.me/anubis/subdomains/$domain" | grep -Po "((http|https):\/\/)?(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | sort -u | tee 1_tmp/jldc.list

#curl -s "https://crt.sh/?q=%25.$domain&output=json" | jq -r '.[].name_value' 2>/dev/null | sed 's/\*\.//g' | sort -u | grep -o "\w.*$domain" | tee 1_tmp/cert.list

#curl -s "http://ci-www.threatcrowd.org/searchApi/v2/domain/report/?domain=$domain" | jq -r '.subdomains' | grep -o "\w.*$domain" | tee 1_tmp/threatcrowd.list

#cat 1_tmp/threatcrowd.txt | unfurl domains | anew 1_tmp/threatcrowd.list

#rm 1_tmp/threatcrowd.txt

#curl -s "https://api.hackertarget.com/hostsearch/?q=$domain" | grep -o "\w.*$domain" | tee 1_tmp/hacktarget.list

#curl -s "https://otx.alienvault.com/api/v1/indicators/domain/$domain/url_list?limit=100&page=1" | grep -o '"hostname": *"[^"]*' | sed 's/"hostname": "//' | sort -u | tee 1_tmp/alienvault.list

#curl "https://api.subdomain.center/?domain=$domain" | jq -r '.[]' | sort -u | tee 1_tmp/subdomaincenter.txt

#cat 1_tmp/subdomaincenter.txt | unfurl domains | anew 1_tmp/subdomaincenter.list

#rm 1_tmp/subdomaincenter.txt

#assetfinder --subs-only $domain | anew 1_tmp/assetfinder.list

#shosubgo -d $domain -s <token> | tee 1_tmp/shosubgo.txt

#cat 1_tmp/shosubgo.txt | unfurl domains | anew 1_tmp/shosubgo.list

#rm 1_tmp/shosubgo.txt

#github-subdomains -d $domain -t <token> 1_tmp/github-subdomain.txt

#cat 1_tmp/github-subdomain.txt | unfurl domain | 1_tmp/anew github-subdomain.list

#rm 1_tmp/github-subdomain.txt

#gitlab-subdomains -d $domain -t <token> | tee 1_tmp/gitlab-subdomain.list

#subfinder -d $domain | tee 1_tmp/subfinder.txt

#cat 1_tmp/subfinder.txt | unfurl domains | 1_tmp/anew subfinder.list

#rm 1_tmp/subfinder.txt

#chaos -d $domain -key <token> | tee 1_tmp/chaos.list

#waybackurls $domain 2> /dev/null | tee 1_tmp/waybackurls.txt

#cat 1_tmp/waybackurls.txt | unfurl domains | anew 1_tmp/waybackurls.list1

#cat 1_tmp/waybackurls.list1 | httprobe | anew 1_tmp/waybackurls.list

#gau $domain 2> /dev/null | tee 1_tmp/gau.txt

#cat 1_tmp/gau.txt | unfurl domains | 1_tmp/anew gau.list1

#cat 1_tmp/gau.list1 | httprobe | anew 1_tmp/gau.list

#### SUBDOMAIN FUZZING,PASSIVE DATA COLLECTION & PROBING

#ffuf -u http://FUZZ.$domain -w /usr/share/wordlists/seclists/Discovery/DNS/subdomainbrute.txt | anew 1_tmp/ffuf.http.list 

#cat 1_tmp/ffuf.http.list | awk '{print $1}' | anew 1_tmp/ffuf.http.txt

#rm 1_tmp/ffuf.http.list

#awk -v domain="$domain" '{print $0 "." domain}' 1_tmp/ffuf.http.txt | anew 1_tmp/ffuf.http.list

#ffuf -u https://FUZZ.$domain -w /usr/share/wordlists/seclists/Discovery/DNS/subdomainbrute.txt | anew 1_tmp/ffuf.https.list 

#cat 1_tmp/ffuf.https.list | awk '{print $1}' | anew 1_tmp/ffuf.https.txt

#rm 1_tmp/ffuf.https.list

#awk -v domain="$domain" '{print $0 "." domain}' 1_tmp/ffuf.https.txt | anew 1_tmp/ffuf.https.list 

#gobuster dns -d $domain -w /usr/share/wordlists/seclists/Discovery/DNS/<wordlist> -o 1_tmp/gobuster.txt

#cat 1_tmp/gobuster.txt | awk '{print $2}' | anew 1_tmp/gobuster.list

#rm 1_tmp/gobuster.txt 

#cat certspotter.list jldc.list cert.list threatcrowd.list hacktarget.list alienvault.list subdomaincenter.list assetfinder.list shosubgo.list github-subdomain.list gitlab-subdomain.list subfinder.list chaos.list waybackurls.list1 gau.list1 ffuf.http.list ffuf.https.list gobuster.list | anew 2_bulk/subdomain.list

#cat 2_bulk/subdomain.list | httprobe | anew 2_bulk/httprobe.list

#cat 2_bulk/httprobe.list | hakrawler | anew 1_tmp/hakrawler.txt

#cat 1_tmp/hakrawler.txt | unfurl domains | anew 1_tmp/hakrawler.list1

#cat 1_tmp/hakrawler.list1 | grep "$domain" | httprobe | anew 1_tmp/hakrawler.list

#cat 2_bulk/httprobe.list | katana | anew 1_tmp/katana.txt

#cat 1_tmp/katana.txt | unfurl domains | anew 1_tmp/katana.list1

#cat 1_tmp/katana.list1 | grep "$domain" | httprobe | anew 1_tmp/katana.list

#gospider -S 2_bulk/httprobe.list -d 10 -c 20 -t 50 -K 3 --no-redirect --js -a -w --blacklist ".(eot|jpg|jpeg|gif|css|tif|tiff|png|ttf|otf|woff|woff2|ico|svg|txt)" --include-subs -q  | anew -q 1_tmp/gospider.txt

#cat 1_tmp/gospider.txt | unfurl domains | anew 1_tmp/gospider.list1

#cat 1_tmp/gospider.list1 | grep "$domain" | httprobe | anew 1_tmp/gospider.list

#cat 1_tmp/waybackurls.list1 1_tmp/gau.list1 1_tmp/hakrawler.list1 1_tmp/katana.list1 1_tmp/subdomain.list | anew 2_bulk/subdomain.list

#cat 2_bulk/httprobe.list 1_tmp/waybackurls.list gau.list katana.list gospider.list | anew 2_bulk/httprobe.list

###BULK DATA PROCESSING 

#cat httprobe.list | httpx -mc 200,201 | anew 2_bulk/200.txt

#cat httprobe.list | httpx -mc 300,301,302 | anew 2_bulk/300.txt

#cat httprobe.list | httpx -mc 400,401,403,404,405 | anew 2_bulk/400.txt

#cat httprobe.list | httpx -mc 500,501 | anew 2_bulk/500.txt

#cat 2_bulk/subdomain.list | httpx -cname -ip -asn | anew 2_bulk/httpx.list

#cat 2_bulk/httpx.list | sed -n 's/.*\[\([^]]*\)\].*/\1/p' | anew 2_bulk/cname.txt

#cat 2_bulk/subdomain.list | dnsx -silent -cname -resp-only | anew 2_bulk/cname.txt

#cat 2_bulk/httpx.list | grep -oP 'AS\d+' | anew 2_bulk/asn.txt 

#cat 2_bulk/httpx.list | grep -E -o '(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)' | anew 2_bulk/ip.txt

#cat 2_bulk/subdomain.list | dnsx -silent -a -resp-only | anew 2_bulk/ip.txt

#whatweb -a 3 -i 2_bulk/httprobe.list | anew 2_bulk/whatweb.txt

#cat 2_bulk/httprobe.list | httpx -ct | grep "text/html" | awk '{print $1}' | anew 1_tmp/ct-text-html.txt

#webtech --ul 1_tmp/ct-text-html.txt | anew 2_bulk/webtech.txt

##passive Data Collection

#cat 1_tmp/waybackurls.txt 1_tmp/gau.txt 1_tmp/hakrawler.txt 1_tmp/katana.txt 1_tmp/gospider.txt | anew 2_bulk/passive.txt

###gf-url-secret
#cat 2_bulk/passive.txt | gf api-key | 1_tmp/anew gf-url-api-key-secrets.gf
#cat 2_bulk/passive.txt  | gf asymmetric-keys_secrets | 1_tmp/anew gf-url-asymmetric-keys_secrets.gf
#cat 2_bulk/passive.txt | gf aws-keys | 1_tmp/anew gf-url-aws-keys-secrets.gf
#cat 2_bulk/passive.txt | gf aws-s3_secrets | 1_tmp/anew gf-url-aws-s3_secrets.gf
#cat 2_bulk/passive.txt | gf base64 | 1_tmp/anew gf-url-base64-secrets.gf
#cat 2_bulk/passive.txt | gf facebook-oauth_secrets | 1_tmp/anew gf-url-facebook-oauth_secrets.gf
#cat 2_bulk/passive.txt | gf facebook-token_secrets | 1_tmp/anew gf-url-facebook-token_secrets.gf
#cat 2_bulk/passive.txt | gf firebase | 1_tmp/anew gf-url-secret-firebase-secrets.gf
#cat 2_bulk/passive.txt | gf facebook-oauth_secrets | 1_tmp/anew gf-url-facebook-oauth_secrets.gf
#cat 2_bulk/passive.txt | gf facebook-token_secrets | 1_tmp/anew gf-url-facebook-token_secrets.gf
#cat 2_bulk/passive.txt | gf github_secrets | 1_tmp/anew gf-url-github_secrets.gf
#cat 2_bulk/passive.txt | gf google-keys_secrets | 1_tmp/anew gf-url-google-keys_secrets.gf
#cat 2_bulk/passive.txt | gf google-oauth_secrets | 1_tmp/anew gf-url-google-oauth_secrets.gf
#cat 2_bulk/passive.txt | gf google-service-account_secrets | 1_tmp/anew gf-url-google-service-account_secrets.gf
#cat 2_bulk/passive.txt | gf google-token_secrets | 1_tmp/anew gf-url-google-token_secrets.gf
#cat 2_bulk/passive.txt | gf heroku-keys_secrets | 1_tmp/anew gf-url-heroku-keys_secrets.gf
#cat 2_bulk/passive.txt | gf http-auth | 1_tmp/anew gf-url-http-auth-secrets.gf
#cat 2_bulk/passive.txt | gf mailchimp-keys_secrets | 1_tmp/anew gf-url-mailchimp-keys_secrets.gf
#cat 2_bulk/passive.txt | gf mailgun-keys_secrets | 1_tmp/anew gf-url-mailgun-keys_secrets.gf
#cat 2_bulk/passive.txt | gf paypal-token_secrets | 1_tmp/anew gf-url-paypal-token_secrets.gf
#cat 2_bulk/passive.txt | gf picatic-keys_secrets | 1_tmp/anew gf-url-picatic-keys_secrets.gf
#cat 2_bulk/passive.txt | gf s3-buckets | 1_tmp/anew gf-url-secret-s3-secrets.gf
#cat 2_bulk/passive.txt | gf slack-token_secrets | 1_tmp/anew gf-url-slack-token_secrets.gf
#cat 2_bulk/passive.txt | gf slack-webhook_secrets | 1_tmp/anew gf-url-slack-webhook_secrets.gf
#cat 2_bulk/passive.txt | gf square-keys_secrets | 1_tmp/anew gf-url-square-keys_secrets.gf
#cat 2_bulk/passive.txt | gf stripe-keys_secrets | 1_tmp/anew gf-url-stripe-keys_secrets.gf
###cat 2_bulk/passive.txt | gf trufflehog | 1_tmp/anew gf-url-trufflehog-secrets.gf(depricted)
#cat 2_bulk/passive.txt | gf twilio-keys_secrets | 1_tmp/anew gf-url-twilio-keys_secrets.gf
#cat 2_bulk/passive.txt | gf twitter-oauth_secrets | 1_tmp/anew gf-url-twitter-oauth_secrets.gf
#cat 2_bulk/passive.txt | gf twitter-token_secrets | 1_tmp/anew gf-url-twitter-token_secrets.gf

#cat 1_tmp/*secrets.gf | 2_bulk/anew gf-url-secret.txt

###gf-url-exploit
#cat 2_bulk/passive.txt | gf cors | 1_tmp/anew gf-url-cors-exploit.gf
#cat 2_bulk/passive.txt | gf idor | 1_tmp/anew gf-url-idor-exploit.gf
#cat 2_bulk/passive.txt | gf img-traversal | 1_tmp/anew gf-url-img-traversal-exploit.gf
#cat 2_bulk/passive.txt | gf lfi | 1_tmp/anew gf-url-lfi-exploit.gf
#cat 2_bulk/passive.txt | gf rce | 1_tmp/anew gf-url-rce-exploit.gf
#cat 2_bulk/passive.txt | gf rce | 1_tmp/anew gf-url-redirect-exploit.gf
#cat 2_bulk/passive.txt | gf sqli | 1_tmp/anew gf-url-sqli-exploit.gf
#cat 2_bulk/passive.txt | gf ssrf | 1_tmp/anew gf-url-ssrf-exploit.gf
#cat 2_bulk/passive.txt | gf ssti | 1_tmp/anew gf-url-ssti-exploit.gf
#cat 2_bulk/passive.txt | gf xss | 1_tmp/anew gf-url-xss-exploit.gf
#cat 2_bulk/passive.txt | gf takeovers | 1_tmp/anew gf-url-takeovers-exploit.gf
#cat 2_bulk/passive.txt | gf upload-fields | 1_tmp/anew gf-url-upload-fields-exploit.gf

#cat 1_tmp/*exploit.gf | anew 2_bulk/anew gf-url-exploit.txt


###gf-url-others
#cat 2_bulk/passive.txt | gf debug-pages | 1_tmp/anew gf-url-debug-pages-others.gf
#cat 2_bulk/passive.txt | gf debug_logic | 1_tmp/anew gf-url-debug_logic-others.gf
#cat 2_bulk/passive.txt | gf fw | 1_tmp/anew gf-url-fw-others.gf
#cat 2_bulk/passive.txt | gf go-functions | 1_tmp/anew gf-url-go-functions-others.gf
#cat 2_bulk/passive.txt | gf interestingEXT | 1_tmp/anew gf-url-interestingEXT-others.gf
#cat 2_bulk/passive.txt | gf interestingparams | 1_tmp/anew gf-url-interestingparams-others.gf
#cat 2_bulk/passive.txt | gf interestingsubs | 1_tmp/anew gf-url-ssrf-others.gf
#cat 2_bulk/passive.txt | gf ip | 1_tmp/anew gf-url-ip-others.gf
#cat 2_bulk/passive.txt | gf json-sec | 1_tmp/anew gf-url-json-sec-others.gf
#cat 2_bulk/passive.txt | gf jsvar | 1_tmp/anew gf-url-jsvar-others.gf
#cat 2_bulk/passive.txt | gf meg-headers | 1_tmp/anew gf-url-meg-headers-others.gf
#cat 2_bulk/passive.txt | gf php-curl | 1_tmp/anew gf-url-php-curl-others.gf
#cat 2_bulk/passive.txt | gf php-errors | 1_tmp/anew gf-url-php-errors-others.gf
#cat 2_bulk/passive.txt | gf php-serialized | 1_tmp/anew gf-url-php-serialized-others.gf
#cat 2_bulk/passive.txt | gf php-sinks | 1_tmp/anew gf-url-php-sinks-others.gf
#cat 2_bulk/passive.txt | gf php-sources | 1_tmp/anew gf-url-php-sources-others.gf
#cat 2_bulk/passive.txt | gf php-sec | 1_tmp/anew gf-url-php-sec-others.gf
#cat 2_bulk/passive.txt | gf php-servers | 1_tmp/anew gf-url-php-servers-others.gf
#cat 2_bulk/passive.txt | gf strings | 1_tmp/anew gf-url-strings-others.gf
#cat 2_bulk/passive.txt | gf urls | 1_tmp/anew gf-url-urls-others.gf

#cat 1_tmp/*others.gf | anew 2_bulk/anew gf-url-others.txt

####Wordlists creation
#cat passive.txt | unfurl keys | sort -u | anew 2_bulk/parameters.txt
#cat passive.txt | unfurl values | sort -u | anew 2_bulk/value.txt
#cat passive.txt | unfurl keypairs | sort -u | anew 2_bulk/param+value.txt
#cat passive.txt | unfurl paths | sort -u | anew 2_bulk/paths.txt
#sed 's#/#\n#g' paths.txt | sort -u | anew wordlist.txt

