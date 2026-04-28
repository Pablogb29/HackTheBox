<#
  Copies and renames Obsidian-style "Pasted image ....png" files into this folder
  with stable names used by README.md.

  Usage (PowerShell):
    cd cases/HackTheBox/EASY/Teacher/screenshots
    .\copy-screenshots.ps1 -SourceFolder "D:\Vault\attachments"

  If your images live next to the note, try the folder that contains htb-teacher.md
  or your vault's default attachment directory.
#>
param(
    [Parameter(Mandatory = $true)]
    [string] $SourceFolder,

    [string] $DestFolder = $PSScriptRoot
)

$map = @(
    @{ src = 'Pasted image 20260408170328.png'; dst = 'teacher_01_ping.png' },
    @{ src = 'Pasted image 20260408170337.png'; dst = 'teacher_02_nmap_allports_01.png' },
    @{ src = 'Pasted image 20260408170349.png'; dst = 'teacher_03_nmap_allports_02.png' },
    @{ src = 'Pasted image 20260408170402.png'; dst = 'teacher_04_nmap_targeted.png' },
    @{ src = 'Pasted image 20260408170422.png'; dst = 'teacher_05_whatweb.png' },
    @{ src = 'Pasted image 20260408190505.png'; dst = 'teacher_06_http_enum.png' },
    @{ src = 'Pasted image 20260408190553.png'; dst = 'teacher_07_web_directory_listing_01.png' },
    @{ src = 'Pasted image 20260408190537.png'; dst = 'teacher_08_web_directory_listing_02.png' },
    @{ src = 'Pasted image 20260408190443.png'; dst = 'teacher_09_images_5png_plaintext.png' },
    @{ src = 'Pasted image 20260408190618.png'; dst = 'teacher_10_wfuzz_content_discovery.png' },
    @{ src = 'Pasted image 20260408174823.png'; dst = 'teacher_11_wfuzz_moodle_login_01.png' },
    @{ src = 'Pasted image 20260408174805.png'; dst = 'teacher_12_wfuzz_moodle_login_02.png' },
    @{ src = 'Pasted image 20260408190644.png'; dst = 'teacher_13_moodle_authenticated.png' },
    @{ src = 'Pasted image 20260408204611.png'; dst = 'teacher_14_moodle_quiz_add_activity.png' },
    @{ src = 'Pasted image 20260408204620.png'; dst = 'teacher_15_moodle_calculated_question_payload.png' },
    @{ src = 'Pasted image 20260408204627.png'; dst = 'teacher_16_moodle_rce_ping_tcpdump_01.png' },
    @{ src = 'Pasted image 20260408204633.png'; dst = 'teacher_17_moodle_rce_ping_tcpdump_02.png' },
    @{ src = 'Pasted image 20260408204648.png'; dst = 'teacher_18_reverse_shell_url.png' },
    @{ src = 'Pasted image 20260408204655.png'; dst = 'teacher_19_reverse_shell_netcat.png' },
    @{ src = 'Pasted image 20260408204828.png'; dst = 'teacher_20_config_php.png' },
    @{ src = 'Pasted image 20260408204856.png'; dst = 'teacher_21_mysql_login.png' },
    @{ src = 'Pasted image 20260408204927.png'; dst = 'teacher_22_mysql_show_databases.png' },
    @{ src = 'Pasted image 20260408204942.png'; dst = 'teacher_23_mysql_use_moodle.png' },
    @{ src = 'Pasted image 20260408205004.png'; dst = 'teacher_24_mdl_user_hashes.png' },
    @{ src = 'Pasted image 20260408205017.png'; dst = 'teacher_25_crackstation_giovannibak.png' },
    @{ src = 'Pasted image 20260408205024.png'; dst = 'teacher_26_user_flag_su_giovanni.png' },
    @{ src = 'Pasted image 20260408205038.png'; dst = 'teacher_27_pspy_wget.png' },
    @{ src = 'Pasted image 20260408205111.png'; dst = 'teacher_28_pspy_backup_sh_cron.png' },
    @{ src = 'Pasted image 20260408205203.png'; dst = 'teacher_29_backup_sh_symlink.png' },
    @{ src = 'Pasted image 20260408205238.png'; dst = 'teacher_30_suid_bash_root.png' },
    @{ src = 'Pasted image 20260408205351.png'; dst = 'teacher_31_root_flag.png' }
)

if (-not (Test-Path -LiteralPath $SourceFolder)) {
    throw "SourceFolder not found: $SourceFolder"
}

$missing = @()
foreach ($m in $map) {
    $src = Join-Path $SourceFolder $m.src
    $dst = Join-Path $DestFolder $m.dst
    if (Test-Path -LiteralPath $src) {
        Copy-Item -LiteralPath $src -Destination $dst -Force
        Write-Host "OK $($m.dst)"
    }
    else {
        $missing += $m.src
        Write-Warning "Missing source: $($m.src)"
    }
}

if ($missing.Count -gt 0) {
    Write-Host ""
    Write-Host "Copied $($map.Count - $missing.Count) / $($map.Count). Fix SourceFolder or copy missing files manually; see README.md in this folder."
}
