<#
.SYNOPSIS
    Audit du pare-feu Windows : etat, profil reseau, regles entrantes exposees.

.DESCRIPTION
    Par defaut, le script est en LECTURE SEULE : il analyse la configuration
    et produit un rapport (texte + CSV) sur le Bureau, sans rien modifier.

    Avec le parametre -Corriger, il cree d'abord une sauvegarde complete du
    pare-feu (.wfw), puis desactive les regles entrantes juge inutiles pour
    un poste personnel (Assistance a distance, Teredo, AllJoyn, DIAL,
    Media Foundation, Wi-Fi Direct en profil Public).
    Les regles sont desactivees, jamais supprimees : tout est reversible.

    Compatible Windows PowerShell 5.1 et PowerShell 7. Interface FR et EN.

.PARAMETER Corriger
    Desactive les regles a risque apres sauvegarde. Necessite les droits administrateur.

.PARAMETER DossierSortie
    Dossier ou ecrire le rapport et la sauvegarde. Par defaut : le Bureau.

.EXAMPLE
    .\Audit-ParefeuWindows.ps1
    Audit simple, aucun changement.

.EXAMPLE
    .\Audit-ParefeuWindows.ps1 -Corriger -WhatIf
    Affiche ce qui serait desactive, sans rien modifier.

.EXAMPLE
    .\Audit-ParefeuWindows.ps1 -Corriger
    Sauvegarde puis desactive les regles a risque.

.NOTES
    Restauration : netsh advfirewall import "<chemin>\sauvegarde_parefeu_<date>.wfw"
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [switch]$Corriger,
    [string]$DossierSortie = [Environment]::GetFolderPath("Desktop")
)

# ---------------------------------------------------------------------------
# Regles jugees inutiles sur un poste personnel (motifs FR + EN)
# ---------------------------------------------------------------------------
$ReglesARisque = @(
    @{ Nom = "Assistance a distance"; Raison = "Utilise par les arnaques au faux support technique";
       Motifs = @("Assistance à distance*", "Remote Assistance*"); PublicSeulement = $false }
    @{ Nom = "Teredo"; Raison = "Ancien tunnel IPv6, plus necessaire";
       Motifs = @("*Teredo*"); PublicSeulement = $false }
    @{ Nom = "Routeur AllJoyn"; Raison = "Ancien protocole d'objets connectes";
       Motifs = @("*AllJoyn*"); PublicSeulement = $false }
    @{ Nom = "Serveur DIAL"; Raison = "Protocole de diffusion rarement utilise";
       Motifs = @("*protocole DIAL*", "*DIAL protocol*"); PublicSeulement = $false }
    @{ Nom = "Media Foundation reseau"; Raison = "Ports de streaming RTSP/RTP (554, 5004-5009)";
       Motifs = @("*Media Foundation*"); PublicSeulement = $false }
    @{ Nom = "Wi-Fi Direct (Public)"; Raison = "Ne doit pas etre ouvert sur un Wi-Fi public";
       Motifs = @("*Wi-Fi Direct*"); PublicSeulement = $true }
)

# ---------------------------------------------------------------------------
# Fonctions utilitaires
# ---------------------------------------------------------------------------
function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    return ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-ExposePublic($regle) {
    $p = $regle.Profile.ToString()
    return ($p -eq "Any" -or $p -match "Public")
}

$Rapport = New-Object System.Collections.Generic.List[string]
function Write-Ligne([string]$texte, [string]$couleur = "Gray") {
    Write-Host $texte -ForegroundColor $couleur
    $Rapport.Add($texte)
}

# ---------------------------------------------------------------------------
# 0. Pre-requis
# ---------------------------------------------------------------------------
$EstAdmin = Test-Admin
$Horodatage = Get-Date -Format "yyyy-MM-dd_HHmm"

if ($Corriger -and -not $EstAdmin) {
    Write-Host "Le mode -Corriger necessite une console administrateur." -ForegroundColor Red
    Write-Host "Clic droit sur Demarrer > Terminal (administrateur), puis relancer." -ForegroundColor Red
    exit 1
}

Write-Ligne "=== AUDIT DU PARE-FEU WINDOWS - $(Get-Date -Format 'dd/MM/yyyy HH:mm') ===" "Cyan"
Write-Ligne "Poste : $env:COMPUTERNAME | Admin : $EstAdmin" "Cyan"
Write-Ligne ""

$Alertes = 0

# ---------------------------------------------------------------------------
# 1. Etat des profils du pare-feu
# ---------------------------------------------------------------------------
Write-Ligne "[1] Profils du pare-feu" "White"
foreach ($profil in Get-NetFirewallProfile) {
    $ok = $profil.Enabled -and ($profil.DefaultInboundAction -ne "Allow")
    $statut = if ($ok) { "OK " } else { "!! " }
    $couleur = if ($ok) { "Green" } else { "Red" }
    if (-not $ok) { $Alertes++ }
    Write-Ligne ("  {0} {1,-8} Actif={2,-5} Entrant par defaut={3}" -f $statut, $profil.Name, $profil.Enabled, $profil.DefaultInboundAction) $couleur
}
Write-Ligne ""

# ---------------------------------------------------------------------------
# 2. Profil du reseau actuel
# ---------------------------------------------------------------------------
Write-Ligne "[2] Reseau(x) connecte(s)" "White"
foreach ($reseau in Get-NetConnectionProfile) {
    $info = if ($reseau.NetworkCategory -eq "Public") {
        "le plus restrictif (PC invisible, partage bloque)"
    } else {
        "partage local autorise : a reserver au reseau de la maison"
    }
    Write-Ligne ("  {0} -> {1} ({2})" -f $reseau.Name, $reseau.NetworkCategory, $info) "Green"
}
Write-Ligne ""

# ---------------------------------------------------------------------------
# 3. Bureau a distance et Assistance a distance (parametres systeme)
# ---------------------------------------------------------------------------
Write-Ligne "[3] Acces a distance" "White"
$rdp = (Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\Terminal Server" -ErrorAction SilentlyContinue).fDenyTSConnections
if ($rdp -eq 0) {
    Write-Ligne "  !! Bureau a distance (RDP) ACTIVE" "Red"; $Alertes++
} else {
    Write-Ligne "  OK Bureau a distance (RDP) desactive" "Green"
}
$ra = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -ErrorAction SilentlyContinue).fAllowToGetHelp
if ($ra -eq 1) {
    Write-Ligne "  !  Assistance a distance autorisee dans les parametres systeme" "Yellow"
    Write-Ligne "     (Parametres > Systeme > Informations systeme > Parametres avances > Utilisation a distance)" "Yellow"
} else {
    Write-Ligne "  OK Assistance a distance non autorisee" "Green"
}
Write-Ligne ""

# ---------------------------------------------------------------------------
# 4. Regles entrantes qui autorisent des connexions
# ---------------------------------------------------------------------------
Write-Ligne "[4] Regles entrantes d'autorisation actives" "White"
Write-Host "  Lecture des regles (peut prendre 10 a 30 secondes)..." -ForegroundColor DarkGray
$Autorisees = @(Get-NetFirewallRule -Direction Inbound -Enabled True -Action Allow)
$Publiques = @($Autorisees | Where-Object { Test-ExposePublic $_ })
Write-Ligne ("  Total : {0} regles | dont {1} actives sur le profil Public" -f $Autorisees.Count, $Publiques.Count)

$csv = Join-Path $DossierSortie "audit_parefeu_regles_$Horodatage.csv"
$Autorisees |
    Select-Object DisplayName, DisplayGroup,
        @{ n = "Profil"; e = { $_.Profile.ToString() } },
        @{ n = "ExposePublic"; e = { Test-ExposePublic $_ } } |
    Sort-Object DisplayName |
    Export-Csv $csv -NoTypeInformation -Encoding UTF8
Write-Ligne "  Liste complete exportee : $csv"
Write-Ligne ""

# ---------------------------------------------------------------------------
# 5. Detection des regles a risque
# ---------------------------------------------------------------------------
Write-Ligne "[5] Regles a risque encore actives" "White"
$ADesactiver = New-Object System.Collections.Generic.List[object]

foreach ($cat in $ReglesARisque) {
    $trouvees = @($Autorisees | Where-Object {
        $r = $_
        $correspond = $false
        foreach ($m in $cat.Motifs) { if ($r.DisplayName -like $m) { $correspond = $true } }
        $correspond -and (-not $cat.PublicSeulement -or (Test-ExposePublic $r))
    })
    if ($trouvees.Count -gt 0) {
        $Alertes++
        Write-Ligne ("  !! {0} : {1} regle(s) - {2}" -f $cat.Nom, $trouvees.Count, $cat.Raison) "Yellow"
        foreach ($t in $trouvees) { $ADesactiver.Add($t) }
    } else {
        Write-Ligne ("  OK {0}" -f $cat.Nom) "Green"
    }
}
Write-Ligne ""

# ---------------------------------------------------------------------------
# 6. Correction (optionnelle)
# ---------------------------------------------------------------------------
if ($Corriger -and $ADesactiver.Count -gt 0) {
    Write-Ligne "[6] Correction" "White"
    $sauvegarde = Join-Path $DossierSortie "sauvegarde_parefeu_$Horodatage.wfw"

    if ($PSCmdlet.ShouldProcess("Pare-feu Windows", "Sauvegarde vers $sauvegarde")) {
        netsh advfirewall export "$sauvegarde" | Out-Null
        if (-not (Test-Path $sauvegarde)) {
            Write-Ligne "  Echec de la sauvegarde : aucune modification effectuee." "Red"
            exit 1
        }
        Write-Ligne "  Sauvegarde : $sauvegarde" "Green"
    }

    foreach ($regle in $ADesactiver) {
        if ($PSCmdlet.ShouldProcess($regle.DisplayName, "Desactiver la regle")) {
            Disable-NetFirewallRule -Name $regle.Name
            Write-Ligne "  Desactivee : $($regle.DisplayName)" "Green"
        }
    }
    Write-Ligne "  Restauration possible : netsh advfirewall import `"$sauvegarde`"" "Cyan"
    Write-Ligne ""
}
elseif ($ADesactiver.Count -gt 0) {
    Write-Ligne "Pour desactiver ces regles (apres sauvegarde automatique) :" "Cyan"
    Write-Ligne "  .\Audit-ParefeuWindows.ps1 -Corriger -WhatIf   (simulation)" "Cyan"
    Write-Ligne "  .\Audit-ParefeuWindows.ps1 -Corriger           (application)" "Cyan"
    Write-Ligne ""
}

# ---------------------------------------------------------------------------
# Synthese
# ---------------------------------------------------------------------------
$couleurBilan = if ($Alertes -eq 0) { "Green" } else { "Yellow" }
Write-Ligne "=== BILAN : $Alertes point(s) d'attention ===" $couleurBilan
Write-Ligne "Rappel : le pare-feu reduit la surface d'attaque, mais seules les mises a jour corrigent les failles."

$txt = Join-Path $DossierSortie "audit_parefeu_$Horodatage.txt"
$Rapport | Out-File $txt -Encoding UTF8
Write-Host "Rapport enregistre : $txt" -ForegroundColor Cyan
