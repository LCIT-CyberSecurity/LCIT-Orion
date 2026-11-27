# Installation native de la sonde Orion

La sonde expose une API HTTPS appelée par Orion central. Elle n'établit aucune connexion de contrôle vers le central. Les connexions sortantes de mesure restent limitées aux cibles et ports autorisés, validés localement dans le CIDR affecté à la sonde.

> **État du prototype :** le paquet Debian signé n'est pas encore livré. Les étapes ci-dessous décrivent la configuration et l'unité systemd prévues; l'installation et le démarrage natifs sur un hôte vierge restent à valider avec le paquet.

## Prérequis

- Debian 13 minimal, architecture amd64 ou arm64.
- Paquet Orion Probe installé depuis une version approuvée du projet.
- Installer uniquement les moteurs autorisés : `nmap`, `ssh-audit` et/ou `ike-scan`. La sonde n'annonce que les capacités dont les exécutables sont présents; le module TLS nécessite également le paquet Python `python-nmap` livré avec Orion.
- Un certificat serveur HTTPS et sa clé privée provisionnés hors bande. Le certificat et la clé doivent appartenir à `orion-probe`; mode `0600` pour la clé.
- Règle de pare-feu autorisant l'adresse egress réelle d'Orion central vers le port d'écoute de cette sonde. L'authentification API et la vérification TLS restent obligatoires en complément.

## Configuration

Créer le compte système `orion-probe` s'il n'est pas déjà créé par le paquet :

```sh
sudo useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin orion-probe
```

Créer `/etc/orion-probe/config.json`, propriétaire `root:orion-probe`, mode `0640` (ou propriétaire `orion-probe`, mode `0600`). Le service refuse les liens symboliques, fichiers non réguliers, fichiers accessibles en écriture par le groupe/autres ou lisibles par tous, options inconnues et CIDR invalides.

```json
{
  "listen_address": "192.0.2.40",
  "port": 9443,
  "certificate_file": "/etc/orion-probe/tls.crt",
  "private_key_file": "/etc/orion-probe/tls.key",
  "state_dir": "/var/lib/orion-probe",
  "allowed_networks": ["10.20.0.0/16"],
  "token_hash": "",
  "pairing_code_hash": "<SHA-256 du code de jumelage temporaire>",
  "pairing_expires_at": 1795800000,
  "workers": 2
}
```

Le code temporaire doit être généré aléatoirement, transmis à Orion par un canal approuvé, haché avec SHA-256 avant stockage, et expirer rapidement. Le jumelage le consomme une seule fois et écrit le hash du jeton dans le répertoire d'état privé. Ne pas placer un code de jumelage, un jeton en clair ou une clé privée dans le fichier de configuration, les journaux, Jira ou Git. En production, retirer le code de jumelage et conserver uniquement le hash du jeton révocable.

Adapter l'adresse d'écoute, le certificat, le CIDR et le port au réseau réel. Les CIDR doivent représenter le périmètre autorisé par le propriétaire; une adresse publique ou une étiquette de zone ne constitue pas une autorisation implicite.

## Démarrage

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now orion-probe.service
sudo systemctl status orion-probe.service
```

Le service s'exécute sans privilèges, avec `/var/lib/orion-probe` comme seul emplacement persistant inscriptible. Il ne requiert ni conteneur, ni WebUI, ni base locale. Les résultats non acquittés sont conservés dans le tampon persistant. À l'arrêt, l'agent annule les tâches en cours et attend la fin des appels bornés.

## Capacités et limites du prototype

- TLS utilise le moteur `tls_scanner` Orion, scanne les IP épinglées par résolution locale et fournit le nom d'origine comme SNI. Un hôte sans preuve TLS exploitable reste `indeterminate`; il n'est pas déclaré fermé.
- SSH réutilise le service `ssh_audit.audit_target` avec `ssh-audit`, sans test de débit ni authentification.
- IPsec réutilise `services.ipsec.probe_targets` avec deux versions IKE, sans retry et avec parallélisme borné.
- DNS et les capacités avancées ne sont pas annoncés par ce prototype.
- La liste des capacités reflète les exécutables disponibles au démarrage. Après installation/retrait d'un moteur, redémarrer le service.
- Ce livrable ne fournit pas encore de paquet Debian signé, de procédure d'upgrade/rollback, de règle pare-feu automatisée ni de recette multi-zones. Le POC devra aussi mesurer CPU, mémoire, stockage et latence.

## Lancement et suivi des tâches dans Orion

Dans **Administration → Sondes**, un opérateur peut lancer manuellement une tâche sur une sonde active. L'interface ne propose que les capacités annoncées par la sonde et les cibles explicitement affectées à sa zone. L'API centrale revérifie la capacité, l'affectation et le CIDR; la sonde résout ensuite les noms et refuse toute adresse hors de son périmètre local.

Les budgets avant dispatch sont de 32 couples cible-port pour TLS et SSH, et de 128 couples pour IPsec (deux versions IKE). La sonde applique encore une borne après résolution, car un nom DNS peut produire plusieurs adresses. Un dépassement est rejeté et n'est pas converti en résultat « fermé ».

Le panneau permet aussi de synchroniser les événements depuis la sonde et de consulter ses 100 dernières tâches. La synchronisation importe les événements de façon dédupliquée et ne les acquitte qu'après leur commit dans PostgreSQL central. Une page contient au plus 20 événements; plusieurs synchronisations peuvent être nécessaires pour vider un tampon plus important.

Ces tâches manuelles ne sont pas encore lancées depuis une définition ou une planification de scan Orion. Elles ne reprennent pas les profils et politiques de scan existants et ne sont pas encore présentées dans l'historique, la cartographie ou les rapports Orion. Les résultats restent des observations techniques rattachées à la tâche et à la sonde; ils ne modifient pas la note cryptographique d'un scan central.
