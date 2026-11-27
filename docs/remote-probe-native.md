# Installation native de la sonde Orion

La sonde expose une API HTTPS appelée par Orion central. Elle n'établit aucune connexion de contrôle vers le central. Les connexions sortantes de mesure restent limitées aux cibles et ports autorisés, validés localement dans le CIDR affecté à la sonde.

> **État du lot :** un constructeur `.deb` est disponible sous `ops/package/` et un paquet de laboratoire a été construit/signé. Cette signature n'est pas une signature de publication officielle. L'installation et le démarrage réels sur un hôte Debian 13 vierge restent `NOT RUN`.

## Prérequis

- Debian 13 minimal, architecture amd64 ou arm64.
- Paquet Orion Probe installé depuis une version approuvée du projet.
- Installer uniquement les moteurs autorisés : `nmap`, `ssh-audit` et/ou `ike-scan`. La sonde n'annonce que les capacités dont les exécutables sont présents; le module TLS nécessite également le paquet Python `python-nmap` livré avec Orion.
- Un certificat serveur HTTPS et sa clé privée provisionnés hors bande. Le certificat et la clé doivent appartenir à `orion-probe`; mode `0600` pour la clé.
- Règle de pare-feu autorisant l'adresse egress réelle d'Orion central vers le port d'écoute de cette sonde. L'authentification API et la vérification TLS restent obligatoires en complément.

## Construire le paquet Debian

Sur une machine de construction Debian compatible, `ops/package/build-probe-deb.sh`
assemble le binaire Python, les moteurs Orion réutilisés, l'unité systemd et les
dépendances déclarées. Nmap, `ssh-audit` et `ike-scan` sont des paquets Debian
requis par cette version du paquet.

```sh
ops/package/build-probe-deb.sh 0.1.0 /tmp/orion-probe-packages
```

Pour un artefact de laboratoire uniquement, fournir l'identifiant d'une clé
GPG locale au constructeur; il crée une signature détachée `.asc`. Ne jamais
présenter cette signature comme une signature officielle. Les étapes et la
procédure d'installation figurent dans [`ops/package/README.md`](../ops/package/README.md).

Le paquet installe l'exemple dans `/etc/orion-probe/config.json.example` et
crée l'utilisateur système non privilégié. Il ne démarre pas le service tant
qu'une configuration réelle n'existe pas. La configuration doit contenir un
code de jumelage temporaire haché, expirant et transmis par canal approuvé,
ainsi qu'un certificat et une clé privée protégés.

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
- La signature testée est une signature de laboratoire; aucune clé de publication officielle n'est fournie. La procédure d'upgrade/rollback, la règle pare-feu automatisée et la recette multi-zones restent à faire. L'installation et le démarrage sous Debian 13 restent `NOT RUN`. Le POC devra aussi mesurer CPU, mémoire, stockage et latence.

## Lancement depuis une définition ou une planification

Un opérateur peut lancer une définition depuis **Scans → Mesurer depuis une sonde**
et sélectionner une ou plusieurs sondes actives. Une planification TLS peut utiliser
la même sélection. Les sondes doivent annoncer tous les moteurs sélectionnés, et les
zones choisies doivent collectivement contenir toutes les cibles affectées au scan.
La sélection est revalidée à chaque lancement planifié. La tâche est exécutée par les
sondes; le worker central ne lance jamais l'analyse locale en remplacement.

Le parcours distant produit des observations techniques limitées, sans évaluation
des politiques TLS/SSH/IPsec ni rapport de conformité. Les résultats sont conservés
dans PostgreSQL central avec l'identité de sonde, la zone, les cibles et ports. Un
timeout ou une absence de réponse est affiché comme indéterminé; cela ne prouve pas
qu'un flux est fermé. Ce parcours requiert des cibles IP/FQDN et des ports explicites
pour TLS; la découverte `fast`/`all` et les cibles CIDR sont rejetées.

## Lancement et suivi des tâches manuelles dans Orion

Dans **Administration → Sondes**, un opérateur peut lancer manuellement une tâche sur une sonde active. L'interface ne propose que les capacités annoncées par la sonde et les cibles explicitement affectées à sa zone. L'API centrale revérifie la capacité, l'affectation et le CIDR; la sonde résout ensuite les noms et refuse toute adresse hors de son périmètre local.

Les budgets avant dispatch sont de 32 couples cible-port pour TLS et SSH, et de 128 couples pour IPsec (deux versions IKE). La sonde applique encore une borne après résolution, car un nom DNS peut produire plusieurs adresses. Un dépassement est rejeté et n'est pas converti en résultat « fermé ».

Le panneau permet aussi de synchroniser les événements depuis la sonde et de consulter ses 100 dernières tâches. La synchronisation importe les événements de façon dédupliquée et ne les acquitte qu'après leur commit dans PostgreSQL central. Une page contient au plus 20 événements; plusieurs synchronisations peuvent être nécessaires pour vider un tampon plus important.

Les tâches lancées manuellement depuis **Administration → Sondes** restent séparées des définitions et de leurs planifications. Les résultats distants ne modifient pas la note cryptographique d'un scan central.
