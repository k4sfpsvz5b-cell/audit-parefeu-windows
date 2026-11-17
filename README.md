# Audit du pare-feu Windows (PowerShell)

Script PowerShell qui audite la configuration du pare-feu d'un poste Windows 10/11 et, si on le demande, désactive les règles entrantes inutiles sur un poste personnel. Avant toute modification, il fait une sauvegarde complète.

## Pourquoi ce script

Des outils d'IA permettent désormais de trouver et d'exploiter des failles logicielles beaucoup plus vite. Un pare-feu ne corrige pas ces failles : seules les mises à jour le font. Il limite en revanche ce qui est **exposé** sur le réseau. Ce script vérifie en une commande ce qui est réellement ouvert sur un poste, en particulier sur les Wi-Fi publics.

## Ce qu'il vérifie

| # | Contrôle | Alerte si… |
|---|---|---|
| 1 | Profils du pare-feu (Domaine / Privé / Public) | un profil est désactivé ou autorise l'entrant par défaut |
| 2 | Catégorie du réseau connecté | (information) Public = le plus restrictif |
| 3 | Bureau à distance (RDP) et Assistance à distance | RDP est activé |
| 4 | Règles entrantes d'autorisation | export CSV complet + nombre de règles exposées en Public |
| 5 | Règles à risque | Assistance à distance, Teredo, AllJoyn, DIAL, Media Foundation, Wi-Fi Direct en Public |

## Utilisation

```powershell
# Audit seul, aucune modification (fonctionne sans droits admin, mais résultats partiels)
.\Audit-ParefeuWindows.ps1

# Simulation de la correction
.\Audit-ParefeuWindows.ps1 -Corriger -WhatIf

# Correction réelle (console administrateur requise)
.\Audit-ParefeuWindows.ps1 -Corriger
```

Le rapport `.txt` et l'export `.csv` sont enregistrés sur le Bureau. On peut choisir un autre dossier avec `-DossierSortie "C:\chemin"`.

### Si Windows bloque l'exécution du script

```powershell
Unblock-File .\Audit-ParefeuWindows.ps1
powershell -ExecutionPolicy Bypass -File .\Audit-ParefeuWindows.ps1
```

## Sécurité et réversibilité

- **Lecture seule par défaut** : rien n'est modifié sans `-Corriger`.
- **Sauvegarde automatique** avant correction : `sauvegarde_parefeu_<date>.wfw`. Si elle échoue, le script s'arrête.
- **Désactivation, jamais suppression** : une règle se réactive avec `Enable-NetFirewallRule`.
- **Restauration complète** :
  ```powershell
  netsh advfirewall import "<chemin>\sauvegarde_parefeu_<date>.wfw"
  ```
- Compatible `-WhatIf` (`SupportsShouldProcess`).

## Compatibilité

- Windows 10 / 11, Windows PowerShell 5.1 et PowerShell 7.
- Motifs de règles en français et en anglais.

## Compétences mises en œuvre

PowerShell (module `NetSecurity`, `CmdletBinding`, `ShouldProcess`), registre Windows, analyse de configuration réseau, export CSV, démarche de durcissement réversible (sauvegarde, simulation, puis application).

## Limites

- Ce script ne remplace ni les mises à jour, ni l'antivirus, ni les sauvegardes de données.
- La liste des règles à risque convient à un **poste personnel**. En entreprise, une GPO peut gérer le pare-feu et écraser ces réglages.
