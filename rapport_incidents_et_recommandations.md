# Rapport global des incidents et recommandations AIOps

Ce rapport synthétise uniquement les observations présentes dans les jeux de données DemoTech. Une proximité temporelle est considérée comme une corrélation possible et non comme une causalité démontrée.

## 1. État global

- **Statut :** `CRITICAL`
- **Alertes consolidées :** 13
- **Communications réseau :** 600
- **Communications échouées :** 9, soit 1,5 %
- **Communications lentes :** 12
- **Erreurs applicatives :** 40

## 2. Observations principales

### Sécurité et charge CPU

- L'adresse `203.0.113.77` produit 13 échecs d'authentification entre le 2 novembre 2026 à 05:00 et 06:24.
- Le CPU de `web-server-01` dépasse le seuil de 80 % à partir de 05:40 et atteint 94,9 %.
- Ces événements sont proches dans le temps. Une relation causale est possible, mais elle ne peut pas être démontrée sans les journaux HTTP, les traces des processus et les volumes de requêtes.

### Réseau et application

- 12 communications portent le statut `SLOW` entre le 1er novembre 2026 à 18:05 et 20:05.
- La latence maximale observée dans la période 18:00–20:00 est de 362 ms, au-dessus du seuil de 150 ms.
- 19 erreurs applicatives sont enregistrées pendant les heures 18:00 et 19:00.
- Cette coïncidence justifie une investigation conjointe. Elle ne prouve pas si le réseau ralentit l'application ou si un traitement applicatif lent allonge les communications.

### Communications avec la base de données

- 9 communications `FAILED` apparaissent sur le port 5432 entre le 2 novembre 2026 à 11:30 et 12:40.
- Leur latence maximale atteint 1 018,5 ms.
- Une erreur `Database connection failed` apparaît à 12:24 pendant cette fenêtre.
- Les données indiquent une corrélation cohérente avec un problème d'accès à la base, mais elles ne permettent pas d'identifier seules la cause exacte : service arrêté, saturation, pare-feu ou rupture réseau.

### Ressources système

- `web-server-01` : CPU maximal de 94,9 %, seuil configuré à 80 %.
- `db-server-01` : mémoire maximale de 97,3 %, seuil configuré à 85 %.
- `app-server-01` : disque maximal de 97,2 %, seuil configuré à 90 %.

## 3. Recommandations

| Priorité | Cible | Recommandation | Validation |
|---|---|---|---|
| P1 | Sécurité | Examiner `203.0.113.77`, les comptes ciblés et les éventuels succès suivant les échecs. Appliquer un blocage temporaire uniquement après validation. | Humaine |
| P1 | Base de données | Vérifier PostgreSQL, le port 5432, le pare-feu et les journaux de `db-server-01` pendant la fenêtre observée. | Humaine |
| P1 | `app-server-01` | Identifier les fichiers responsables du remplissage du disque avant toute suppression ou rotation. | Humaine |
| P2 | `db-server-01` | Examiner les processus et requêtes responsables de la consommation mémoire. | Humaine |
| P2 | Réseau et application | Corréler les requêtes lentes avec les timeouts et erreurs HTTP 500 à l'aide d'identifiants de requête. | Humaine |

## 4. Limites

- Les données sont synthétiques et ne constituent pas une vérité terrain complète.
- Les corrélations horaires peuvent inclure des coïncidences.
- Aucune action destructive, modification de configuration ou sanction de compte ne doit être exécutée automatiquement à partir de ce rapport.
- L'interprétation déterministe est utilisée tant qu'aucun client LLM externe n'est configuré.
