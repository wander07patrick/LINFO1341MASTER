#---------------------------  DNS --------------------------------------#
"""
1. Pour trouver les noms de domaines résolus dans un fichier de capture PCAP avec Tshark, on peut utiliser la commande suivante:
----------------
Cette commande va filtrer tous les paquets DNS dans le fichier file.pcap qui ont le drapeau de réponse dns.flags.response et le code de retour 
dns.flags.rcode égal à 0 (ce qui signifie que la requête a été résolue avec succès). Les noms de domaine résolus sont extraits en utilisant le champ dns.qry.name.
Les noms de domaines résolus sont affichés en utilisant l'option -e avec le champ dns.qry.name.
"""

#tshark -r file.pcap -Y "dns.flags.response && dns.flags.rcode == 0" -T fields -e dns.qry.name
#tshark -r '/home/patrick/Bureau/captures/MessageToutgenre.pcap' -Y "dns.flags.response && dns.flags.rcode == 0" -T fields -e dns.qry.name
#tshark -r '/home/patrick/Bureau/captures/MessageToutgenre.pcap' -Y "dns.flags.response && dns.a" -T fields -e dns.qry.name | sort -u | wc -l



"""
2-1 Quels sont les serveurs autoritatifs pour ces noms de domaines ? 
Cela va lire le fichier pcap file.pcap, filtrer les paquets DNS qui contiennent des réponses autoritatives
(dns.flags.response && dns.flags.authoritative), et afficher le champ dns.a (l'adresse IP du serveur autoritatif) pour chaque paquet.


Cette commande va filtrer tous les paquets DNS dans le fichier file.pcap qui ont le drapeau de réponse dns.flags.response et 
le drapeau autoritaire dns.flags.authoritative. Les serveurs autoritaires sont extraits en utilisant le champ dns.ns.
Les serveurs autoritaires sont affichés en utilisant l'option -e avec le champ dns.ns.
"""
#tshark -r file.pcap -Y "dns.flags.response && dns.flags.authoritative" -T fields -e dns.a  --> adresse ip
#puis je fais nslookup de adresse ip
#ensuite nslookup -debug edge-star-mini-shv-01-bru2.facebook.com
#-----------------------------------------------------------------------

#tip: pour afficher tout les serveurs authoritafifs de facebook ---------> nslookup -type=NS facebook.com


#
"""
2.2- Sont-ils gérés par des entreprises différentes ?

Pour déterminer à quelle entreprise appartient un nom de domaine résolu, vous pouvez utiliser la commande whois dans un terminal. La commande whois permet d'interroger 
les bases de données WHOIS pour obtenir des informations sur un nom de domaine.

Voici un exemple de commande whois pour obtenir les informations WHOIS pour le nom de domaine example.com

La réponse à la commande whois affichera plusieurs informations, telles que le registrar du nom de domaine (l'entreprise qui gère l'enregistrement du nom de domaine), 
la date d'expiration, les contacts administratifs et techniques, etc. À partir de ces informations, vous pouvez souvent déterminer à quelle entreprise appartient le nom de domaine.

Il est important de noter que toutes les informations WHOIS ne sont pas nécessairement exactes ou à jour, car la protection 
de la vie privée des propriétaires de noms de domaine peut parfois rendre ces informations difficiles à obtenir.


NB: Faut d'abord passer par le 2.1
"""
#whois example.com





"""
3- Quels sont les types de requête DNS effectuées ?

Cette commande lit le fichier pcap file.pcap et filtre les paquets DNS qui contiennent des requêtes DNS (pas des réponses DNS) avec dns.flags.response == 0. Elle affiche ensuite le type de requête DNS (dns.qry.type) pour chaque paquet.

Les types de requête DNS les plus courants sont A (pour obtenir l'adresse IPv4 d'un nom de domaine), AAAA (pour obtenir l'adresse IPv6 d'un nom de domaine), MX (pour obtenir les enregistrements de serveurs de messagerie associés à un nom de domaine), NS (pour obtenir les enregistrements de serveurs de noms pour un nom de domaine), et CNAME (pour obtenir le nom canonique associé à un nom de domaine).

Vous pouvez également modifier le filtre de capture pour afficher d'autres informations sur les requêtes DNS, telles que le nom de domaine lui-même, l'adresse IP source et destination, etc.



"""
#tshark -r file.pcap -Y "dns.flags.response == 0" -T fields -e dns.qry.type
#tshark -r '/home/patrick/Bureau/captures/MessageToutgenre.pcap'  -Y "dns.flags.response == 0" -T fields -e dns.qry.type




"""
4- Lorsqu’une requête DNS souhaite obtenir une adresse IP, quelle est sa famille ?

Lorsqu'une requête DNS souhaite obtenir une adresse IP, la famille de cette requête peut être déterminée en analysant 
le type de ressource (Resource Record Type ou RRTYPE) dans la requête DNS.
Pour trouver la famille de la requête DNS à partir d'un fichier de capture PCAP en utilisant Tshark, vous pouvez utiliser la commande suivante:


Cette commande filtre les paquets DNS de demande qui demandent une adresse IP (type de ressource A) et affiche les champs "dns.qry.name" et "dns.qry.type". 
Le champ "dns.qry.type" affiche le type de ressource demandé dans la requête DNS.
Si le type de ressource est "A" (adresse IPv4), alors la requête DNS demande une adresse IPv4 et donc la famille est IPv4. 
Si le type de ressource est "AAAA" (adresse IPv6), alors la requête DNS demande une adresse IPv6 et donc la famille est IPv6.
"""
#tshark -r file.pcap -Y "dns.flags.response==0 && dns.qry.type==1" -T fields -e dns.qry.name -e dns.qry.type
#tshark -r '/home/patrick/Bureau/captures/MessageToutgenre.pcap' -Y "dns.flags.response==0 && dns.qry.type==1" -T fields -e dns.qry.name -e dns.qry.type

#--------------------------------------------------------------------------------

"""
5- Les requêtes contiennent elles des records additionnels ? Le cas échéant, à quoi servent-ils ?

Cette commande lit le fichier pcap file.pcap et filtre les paquets DNS qui contiennent des requêtes DNS (pas des réponses DNS) avec dns.flags.response == 0.
 Elle affiche ensuite le nombre d'enregistrements additionnels (dns.count.add_rr) pour chaque paquet.
Les enregistrements additionnels dans une requête DNS sont généralement utilisés pour fournir des informations supplémentaires au serveur DNS, telles que les adresses IP 
de serveurs de noms supplémentaires. Cependant, dans la plupart des cas, les requêtes DNS n'incluent pas d'enregistrements additionnels.
Vous pouvez également utiliser d'autres options de filtrage pour afficher d'autres informations sur les requêtes DNS, telles que le nom de domaine lui-même, 
l'adresse IP source et destination, etc.

"""
#tshark -r file.pcap -Y "dns.flags.response == 0" -T fields -e dns.count.add_rr
#tshark -r '/home/patrick/Bureau/captures/MessageToutgenre.pcap' -Y "dns.flags.response == 0" -T fields -e dns.count.add_rr



"""
6- Observez-vous des comportements DNS inattendus ?

Pour observer des comportements DNS inattendus, vous pouvez utiliser la commande suivante en utilisant TShark :
Cette commande lit le fichier pcap file.pcap et filtre les paquets DNS qui contiennent des réponses DNS avec dns.flags.response == 1 et dns.resp.type == PTR, ce qui signifie que la réponse est un enregistrement PTR qui associe une adresse IP à un nom de domaine. La commande filtre également les réponses qui ont une adresse IP associée (dns.a). Ensuite, elle affiche l'adresse IP associée (dns.a) et le nom de domaine associé (dns.ptr) pour chaque réponse.

Les comportements DNS inattendus peuvent inclure des réponses DNS avec des enregistrements PTR incohérents (par exemple, une adresse IP qui est associée à un nom de domaine qui ne correspond pas à celui attendu), des réponses DNS avec des enregistrements A ou AAAA incorrects, des réponses DNS avec des enregistrements NS incorrects, etc.

Vous pouvez également utiliser d'autres options de filtrage pour afficher d'autres informations sur les requêtes et réponses DNS, telles que le nom de domaine lui-même, l'adresse IP source et destination, etc.


"""
#tshark -r file.pcap -Y "dns.flags.response == 1 and dns.resp.type == PTR and dns.a" -T fields -e dns.a -e dns.ptr
#tshark -r '/home/patrick/Bureau/captures/MessageToutgenre.pcap' -Y "dns.flags.response == 1 and dns.resp.type == PTR and dns.a" -T fields -e dns.a -e dns.ptr
#tshark -r '/home/patrick/Bureau/captures/MessageToutgenre.pcap' -Y 'dns.flags.rcode != 0'
#------------------------------------------------------------------------------------------------------------------------------------------------------------#
#tshark -r '/home/patrick/Bureau/captures/MessageToutgenre.pcap' -Y "dns.flags.response == 1 and (dns.qry.name != dns.resp.name or dns.qry.class != dns.resp.class or dns.qry.type != dns.resp.type)"
#tshark -r '/home/patrick/Bureau/captures/MessageToutgenre.pcap' -Y "dns.flags.response == 1 and dns.resp.ttl < 60"
#tshark -r '/home/patrick/Bureau/captures/MessageToutgenre.pcap' -Y "dns.flags.response == 1 and dns.flags.trunc == 1"
#tshark -r  '/home/patrick/Bureau/captures/MessageToutgenre.pcap' -Y "dns.flags.response == 1 and dns.qry.name.len > 100"








#---------------------------  Couche réseau --------------------------------------#
"""
Pour savoir si des techniques NAT sont utilisées dans un fichier de capture de réseau (pcap), vous pouvez utiliser la commande suivante en utilisant TShark :
Cette commande lit le fichier pcap file.pcap et filtre les paquets IP qui ont comme adresse source ou destination l'adresse IP NAT (NAT_IP_ADDRESS). Elle affiche ensuite l'adresse IP source (ip.src) et l'adresse IP destination (ip.dst) pour chaque paquet.

Si des paquets ont une adresse IP source ou destination qui correspond à l'adresse IP NAT, cela peut indiquer que des techniques NAT sont utilisées pour masquer les adresses IP d'origine ou de destination.

Il est important de noter que cette commande ne permet pas de déterminer le type de NAT utilisé. Pour cela, il faudrait examiner de plus près les adresses IP et les ports source et destination des paquets dans le fichier de capture.

"""
#tshark -r <nom_du_fichier_pcap> -Y 'stun'

#tshark -r file.pcap -Y "ip.addr == NAT_IP_ADDRESS" -T fields -e ip.src -e ip.dst
#tshark -r '/home/patrick/Bureau/captures/MessageToutgenre.pcap' -Y "ip.addr == NAT_IP_ADDRESS" -T fields -e ip.src -e ip.dst


"""
Pour obtenir les adresses vers lesquelles des paquets sont envoyés dans un fichier de capture de réseau (pcap), vous pouvez utiliser la commande suivante en utilisant TShark :
Cette commande lit le fichier pcap file.pcap et affiche l'adresse IP de destination (ip.dst) et l'adresse IPv6 de destination (ipv6.dst) de chaque paquet dans la capture.
"""
#tshark -r file.pcap -T fields -e ip.dst -e ipv6.dst
#tshark -r '/home/patrick/Bureau/captures/MessageToutgenre.pcap' -T fields -e ip.dst -e ipv6.dst + nslookup




#----------------------------------------          Couche transport ----------------------------------------------------------------#

"""
1- Pour connaître les protocoles de transport utilisés dans un fichier pcap avec tshark, vous pouvez utiliser la commande suivante :

tshark -r file.pcap -T fields -e frame.protocols

"""
# tshark -r '/home/patrick/Bureau/captures/MessageToutgenre.pcap' -T fields -e frame.protocols | sort -u 



"""

Il y a-t-il plusieurs connexions vers un même nom de domaine ? Si oui, pouvez-vous
l’expliquer ?
"""
#




"""
2-Pour savoir si l'utilisation du DNS est sécurisée dans un fichier de capture de réseau (pcap), vous pouvez utiliser la commande suivante en utilisant TShark :
Cette commande lit le fichier pcap file.pcap et filtre les paquets DNS qui contiennent une réponse (dns.flags.response == 1) sans erreur (dns.flags.rcode == 0) et une réponse de type A (dns.resp.type == 1) avec la sécurité de l'authentification de données (dns.flags.ad == 1).

Elle affiche ensuite l'adresse IP source (ip.src), l'adresse IP destination (ip.dst), le nom de domaine interrogé (dns.qry.name) et l'adresse IP correspondante (dns.a) pour chaque paquet DNS qui satisfait ces critères.

Si cette commande ne retourne aucun résultat, cela peut indiquer que l'utilisation du DNS n'est pas sécurisée dans le fichier de capture de réseau.
"""
#tshark -r file.pcap -Y "dns && dns.flags.response == 1 && dns.flags.rcode == 0 && dns.resp.type == 1 && dns.flags.ad == 1" -T fields -e ip.src -e ip.dst -e dns.qry.name -e dns.a


"""
Pour connaître les versions de QUIC utilisées dans un fichier pcap avec tshark, vous pouvez utiliser la commande suivante :

"""
#tshark -r file.pcap -Y "quic" -T fields -e quic.version
#tshark -r  '/home/patrick/Bureau/captures/MessageToutgenre.pcap' -Y "quic" -T fields -e quic.version


"""
Oui, vous pouvez identifier les extensions négociées dans le handshake TLS en utilisant tshark.
Voici la commande tshark pour extraire les extensions négociées dans un handshake TLS :
"""
#tshark -r file.pcap -Y "ssl.handshake.type==1 && ssl.handshake.extensions" -T fields -e ssl.handshake.extensions
#tshark -r '/home/patrick/Bureau/captures/MessageToutgenre.pcap' -Y "ssl.handshake.type==1 && ssl.handshake.extensions" -T fields -e ssl.handshake.extensions

#-------------------------------------------------------------------------------------------------------------------------#

"""
les autres protocoles 
"""
#tshark -r file.pcap -Y "udp" -T fields -e udp.port | sort | uniq
#tshark -r '/home/patrick/Bureau/captures/MessageToutgenre.pcap' -Y "udp" -T fields -e udp.port | sort | uniq





"""
Pour savoir s'il y a plusieurs connexions vers un même nom de domaine dans un fichier de capture de réseau (pcap), vous pouvez utiliser la commande suivante en utilisant TShark :
Cette commande lit le fichier pcap file.pcap et filtre les paquets DNS qui contiennent une réponse (dns.flags.response == 1) et une réponse de type A (dns.resp.type == 1).

Elle affiche ensuite l'adresse IP source (ip.src), l'adresse IP destination (ip.dst) et le nom de domaine interrogé (dns.qry.name) pour chaque paquet DNS.

En utilisant la commande awk, elle extrait seulement le nom de domaine et l'adresse IP source pour chaque ligne, puis les trie par ordre alphabétique et élimine les doublons avec sort et uniq -c.

Enfin, elle trie le résultat par ordre décroissant en nombre d'occurrences avec sort -rn, pour afficher les noms de domaine les plus fréquemment interrogés avec leur nombre d'occurrences et l'adresse IP source associée.

Si cette commande retourne plusieurs occurrences pour le même nom de domaine avec des adresses IP sources différentes, cela indique qu'il y a plusieurs connexions vers ce même nom de domaine dans le fichier de capture de réseau.
"""
#tshark -r file.pcap -Y "dns.flags.response == 1 && dns.resp.type == 1" -T fields -e ip.src -e ip.dst -e dns.qry.name | awk '{ print $3, $1 }' | sort | uniq -c | sort -rn
#tshark -r '/home/patrick/Bureau/captures/MessageToutgenre.pcap' -Y "dns.flags.response == 1 && dns.resp.type == 1" -T fields -e ip.src -e ip.dst -e dns.qry.name | awk '{ print $3, $1 }' | sort | uniq -c | sort -rn

#tshark -r '/home/patrick/Bureau/captures/MessageToutgenre.pcap' -Y "dns.qry.name == 'star-mini.c10r.facebook.com'" -T fields -e ip.src -e ip.dst

"""
Pour savoir quelles sont les versions de QUIC utilisées dans un fichier de capture de réseau (pcap), vous pouvez utiliser la commande suivante en utilisant TShark :

Cette commande lit le fichier pcap file.pcap et filtre les paquets QUIC avec l'expression quic.

Elle extrait ensuite la version QUIC de chaque paquet avec l'option -e quic.version et affiche le nombre d'occurrences de chaque version avec sort | uniq -c.

Le résultat de cette commande indiquera quelles sont les versions de QUIC qui sont utilisées dans le fichier de capture de réseau.

"""

#tshark -r file.pcap -Y "quic" -T fields -e quic.version | sort | uniq -c

#tshark -r '/home/patrick/Bureau/captures/MessageToutgenre.pcap' -Y "quic" -T fields -e quic.version | sort | uniq -c

"""
Lorsque vous observez du trafic UDP, identifiez-vous d’autres protocoles que QUIC et
DNS ? Expliquez comment ils sont utilisés par l’application.
"""


#tshark -r '/home/patrick/Bureau/captures/MessageToutgenre.pcap' -Y "udp" -T fields -e frame.protocols | sort | uniq -c



#----------------------- Chiffrement et sécurité -------------------------#
"""
Pour savoir si l'utilisation du DNS est sécurisée dans un fichier de capture de réseau (pcap), vous pouvez utiliser la commande suivante en utilisant TShark :

Cette commande lit le fichier pcap file.pcap et filtre les réponses DNS sécurisées avec les indicateurs dns.flags.response==1, dns.flags.tc==0, et dns.flags.ad==1.

Elle extrait ensuite les noms de domaines associés à ces réponses avec l'option -e dns.qry.name et affiche les noms de domaines uniques avec sort | uniq.

Le résultat de cette commande devrait vous montrer les noms de domaines pour lesquels des réponses DNS sécurisées ont été trouvées dans le fichier de capture de réseau. Si aucun résultat n'est retourné, cela signifie que l'utilisation du DNS n'est pas sécurisée pour les requêtes DNS capturées dans le fichier.


"""
#tshark -r '/home/patrick/Bureau/captures/MessageToutgenre.pcap' -Y "udp.port == 853 or tcp.port == 853"
#tshark -r '/home/patrick/Bureau/captures/MessageToutgenre.pcap' -Y "udp.port == 443 or tcp.port == 443" avec DoH



"""
Pour savoir quelles versions de TLS sont utilisées dans un fichier de capture de réseau (pcap), vous pouvez utiliser la commande suivante en utilisant TShark :
Cette commande lit le fichier pcap file.pcap et filtre les paquets TLS avec un type de poignée de main de 1 (Client Hello) à l'aide de l'expression ssl.handshake.type==1.

Elle extrait ensuite la version de TLS de chaque paquet avec l'option -e tls.handshake.version et affiche le nombre d'occurrences de chaque version avec sort | uniq -c.

Le résultat de cette commande indiquera quelles sont les versions de TLS qui sont utilisées dans le fichier de capture de réseau.


"""
#tshark -r file.pcap -Y "ssl.handshake.type==1" -T fields -e tls.handshake.version | sort | uniq -c
#tshark -r '/home/patrick/Bureau/captures/MessageToutgenre.pcap' -Y "ssl.handshake.type==1" -T fields -e tls.handshake.version | sort | uniq -c
#----------------------------

#tshark -r '/home/patrick/Téléchargements/tls-trace.pcap' -Y "ssl.handshake.type==1" -T fields -e tls.handshake.version | sort | uniq -c



"""
Pour trouver la durée de vie des certificats utilisés et les autorités de certification (AC) qui les ont émis, 
vous pouvez utiliser la fonctionnalité SSL/TLS de Tshark. 
Voici un exemple de commande Tshark pour extraire ces informations à partir d'un fichier pcap :

"""
#tshark -r '/home/patrick/Bureau/captures/MessageToutgenre.pcap' -Y "tls.handshake.type == 11" -T fields -e tls.handshake.extensions
#tshark -r '/home/patrick/Téléchargements/smtp-tls.pcap' -Y "tls.handshake.type == 11" -T fields -e tls.handshake.extensions

#tshark -r  '/home/patrick/Téléchargements/smtp-tls.pcap' -Y "ssl.handshake.type == 2" -T fields -e x509ce -V
#tshark -r  '/home/patrick/Téléchargements/smtp-tls.pcap' -Y "ssl.handshake.type == 2" -T fields -e x509sat -e x509ia
#type certif 
#tshark -r '/home/patrick/Téléchargements/smtp-tls.pcap' -Y "ssl.handshake.type == 2" -T fields -e ssl.handshake.cert_type





#mes paquets no-'ont pas ca je dois les refaires .........

"""
Pour trouver les algorithmes de chiffrement utilisés lors de l'établissement d'une session chiffrée, on peut utiliser la commande suivante avec Tshark:
"""
#tshark -r file.pcap -Y "ssl.handshake.ciphersuites" -T fields -e ssl.handshake.ciphersuite
#tshark -r '/home/patrick/Bureau/captures/MessageToutgenre.pcap' -Y "ssl.handshake.ciphersuites" -T fields -e ssl.handshake.ciphersuite
#tshark -r '/home/patrick/Téléchargements/smtp-tls.pcap' -Y "ssl.handshake.ciphersuites" -T fields -e ssl.handshake.ciphersuite
#tshark -nr '/home/patrick/Téléchargements/smtp-tls.pcap' -2 -R "ssl.handshake.certificate" -V > out.txt


"""
Pour savoir si le trafic UDP est chiffré  ou non, on peut utiliser la commande suivante avec Tshark:

"""
#tshark -r '/home/patrick/Bureau/captures/MessageToutgenre.pcap' -Y "udp" -x | grep "17 03"



"""
Pour savoir si le trafic UDP est   sécurisé ou non, on peut utiliser la commande suivante avec Tshark:

"""

#tshark -r '/home/patrick/Bureau/captures/MessageToutgenre.pcap' -Y "udp && (dtls || udp.port == 443)" -T fields -e udp.dstport




#----------------------- Application (le pouvoir de l'oeil)-------------------------#
"""

- Quels comportements observez-vous lors d’une conversation comparée à un appel ? Quel
impact à l’utilisation de la vidéo par rapport à un appel audio uniquement ?
"""
#---------------------------------------------------------------
#Pour observer les comportements dans un paquet à l'aide de Tshark, vous pouvez utiliser des filtres pour filtrer les paquets qui présentent des comportements spécifiques. Voici quelques exemples de filtres Tshark couramment utilisés pour observer différents comportements dans les paquets :

#    Filtre d'adresse IP source/destination : vous pouvez filtrer les paquets en fonction de leur adresse IP source ou destination pour observer les flux de trafic entre différents hôtes ou réseaux.

#Exemple : tshark -r capture.pcap -T fields -e ip.src -e ip.dst -Y "ip.src == 192.168.1.10"

#    Filtre de protocole : vous pouvez filtrer les paquets en fonction du protocole qu'ils utilisent, par exemple TCP, UDP, ICMP, etc. Cela peut vous aider à observer des comportements spécifiques à certains protocoles.

#Exemple : tshark -r capture.pcap -Y "udp"

#    Filtre de taille de paquet : vous pouvez filtrer les paquets en fonction de leur taille pour observer les paquets qui sont plus grands ou plus petits que la moyenne.

#Exemple : tshark -r capture.pcap -Y "frame.len > 1000"

#    Filtre de temps : vous pouvez filtrer les paquets en fonction de leur horodatage pour observer les paquets qui ont été envoyés ou reçus à des moments spécifiques.

#Exemple : tshark -r capture.pcap -Y "frame.time > '2022-01-01 00:00:00'"

#En utilisant ces filtres et d'autres filtres Tshark, vous pouvez observer différents comportements dans les paquets capturés.

"""
— Quel est le volume de données échangées par l’application pour chacune de ces fonctionnalités ?
Utilisez une base appropriée permettant la comparaison (par ex. par minute).
"""
#tshark -r capture.pcap -qz io,stat,1,"SUM(tcp.len)tcp","SUM(udp.length)udp" -qz io,stat,1,"SUM(tcp.len)tcp","SUM(udp.length)udp"



"""
— Il y a-t-il des serveurs relais utilisés pour interagir avec un utilisateur ou les applications
communiquent-elles directement ? Observez-vous autre chose lorsque les deux utilisateurs
sont sur le même réseau Wi-Fi 4 ?
"""
#----------------------------------------------


"""
— Est-ce qu’interagir avec un utilisateur se trouvant dans le même réseau Wi-Fi ou Ethernet
à un impact sur la façon dont le trafic applicatif est transporté ? Il y a-t-il des serveurs
relais ?
"""
#----------------------------------------------
