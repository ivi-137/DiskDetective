"""What is this folder/file, and is it safe to delete?

A rule-of-thumb knowledge base for Windows. Rules are regular expressions matched
(case-insensitively) against the full path; the first rule that matches wins, so
specific rules are listed before general ones. A folder that matches no rule
inherits the verdict of its nearest classified parent.

These are guidelines, not guarantees.
"""
import os
import re
from dataclasses import dataclass, replace

SAFE, CAUTION, DANGER, PERSONAL, UNKNOWN = 'safe', 'caution', 'danger', 'personal', 'unknown'

LEVEL_LABEL = {
    SAFE: '✔ Safe to delete',
    CAUTION: '! Be careful',
    DANGER: '✖ Don\'t delete',
    PERSONAL: '● Your files',
    UNKNOWN: '? Unknown',
}
LEVEL_RANK = {DANGER: 0, CAUTION: 1, UNKNOWN: 2, PERSONAL: 3, SAFE: 4}


@dataclass(frozen=True)
class Info:
    level: str
    title: str          # short "what it is"
    what: str           # longer explanation
    advice: str         # should you delete it?
    how: str = ''       # how to clean it up properly
    inherited: bool = False   # True when decided by a parent folder


@dataclass(frozen=True)
class Rule:
    rx: 're.Pattern'
    info: Info


_MACROS = {
    '<D>': r'[a-z]:',
    '<U>': r'[a-z]:\\users\\[^\\]+',
    '<PF>': r'[a-z]:\\program files(?: \(x86\))?',
    '<LOCAL>': r'[a-z]:\\users\\[^\\]+\\appdata\\local',
    '<ROAM>': r'[a-z]:\\users\\[^\\]+\\appdata\\roaming',
    '<SUB>': r'(?:\\|$)',   # "...and everything below it"
}
_RULES = []


def _r(pattern, level, title, what, advice, how=''):
    for key, value in _MACROS.items():
        pattern = pattern.replace(key, value)
    _RULES.append(Rule(re.compile('^' + pattern, re.I), Info(level, title, what, advice, how)))


STORAGE_SENSE = 'Settings > System > Storage > Temporary files (or run Disk Cleanup).'

# ───────────────────────────────────────────────────────────────────────────
# 1. Parts of Windows that ARE safe to clean (must come before the Windows rule)
# ───────────────────────────────────────────────────────────────────────────
_r(r'<D>\\windows\\temp<SUB>', SAFE, 'Windows temporary files',
   'Scratch files created by Windows, installers and services while they work.',
   'Safe to delete. Anything still in use is skipped, and Windows recreates what it needs.', STORAGE_SENSE)
_r(r'<D>\\windows\\softwaredistribution\\download<SUB>', SAFE, 'Windows Update download cache',
   'Update packages Windows has already downloaded or installed.',
   'Safe to delete. Windows re-downloads anything it still needs. If files are locked, stop the '
   '"Windows Update" service first.', STORAGE_SENSE + ' ("Windows Update Cleanup").')
_r(r'<D>\\windows\\softwaredistribution$', CAUTION, 'Windows Update working folder',
   'Where Windows Update keeps its database and downloads.',
   'Don\'t delete the folder itself - only its "Download" subfolder is safe to clear.')
_r(r'<D>\\windows\\(prefetch|minidump|livekernelreports|panther|logs)<SUB>', SAFE, 'Windows logs / crash dumps / prefetch',
   'Boot-and-launch speed-up data, crash dumps or setup/diagnostic logs.',
   'Safe to delete. They are only useful for troubleshooting and Windows rebuilds the prefetch data. '
   'Deleting prefetch gives no real benefit.')
_r(r'<D>\\windows\\memory\.dmp$', SAFE, 'Crash dump', 'A snapshot of memory from a Windows crash (blue screen).',
   'Safe to delete unless you are about to send it to someone to diagnose a crash.', STORAGE_SENSE)
_r(r'<D>\\windows\.old<SUB>', SAFE, 'Previous Windows installation',
   'Your old Windows version, kept after an upgrade so you can roll back.',
   'Safe to delete if you are happy with the current Windows (you lose the ability to roll back). '
   'Windows removes it by itself after about 10 days.',
   'Use ' + STORAGE_SENSE.replace('(or run Disk Cleanup)', '> "Previous Windows installation(s)"') +
   ' Plain Delete fails with permission errors.')
_r(r'<D>\\\$(windows\.~bt|windows\.~ws|getcurrent|sysreset)<SUB>', SAFE, 'Leftover Windows upgrade/reset files',
   'Temporary files and logs from a Windows upgrade or "Reset this PC".',
   'Safe to delete once the upgrade has finished and Windows works normally.', STORAGE_SENSE)
_r(r'<D>\\\$recycle\.bin<SUB>', SAFE, 'Recycle Bin',
   'Files you have deleted but that can still be restored.',
   'Safe to empty - but what is inside is gone for good afterwards. Check it first.',
   'Right-click the Recycle Bin on the desktop > Empty Recycle Bin.')
_r(r'<D>\\msdownld\.tmp<SUB>', SAFE, 'Old download leftovers', 'Temporary files from old Windows/Office downloads.',
   'Safe to delete.')
_r(r'<D>\\(nvidia|amd)<SUB>', SAFE, 'Extracted graphics-driver installer',
   'Files unpacked by an NVIDIA/AMD driver installer. They are not the installed driver.',
   'Safe to delete once the driver is installed and working. Keep it if you want to reinstall the driver offline.')
_r(r'<D>\\perflogs<SUB>', SAFE, 'Performance logs', 'Windows performance-monitor logs, usually empty.', 'Safe to delete.')

# ───────────────────────────────────────────────────────────────────────────
# 2. Windows itself and other protected system areas
# ───────────────────────────────────────────────────────────────────────────
_r(r'<D>\\windows\\winsxs<SUB>', DANGER, 'Windows component store (WinSxS)',
   'Every version of every Windows component, used for updates, repairs and "Reset this PC". '
   'Much of it is hard-linked to System32, so Explorer (and this tool) overstate the real size.',
   'Never delete anything here by hand - Windows can stop updating or booting.',
   'Run in an admin Command Prompt:  Dism.exe /Online /Cleanup-Image /StartComponentCleanup')
_r(r'<D>\\windows\\installer<SUB>', DANGER, 'Windows Installer cache',
   'Cached setup files that installed programs need to repair, update or uninstall themselves.',
   'Don\'t delete. Removing files here breaks uninstall/repair for the programs that own them.',
   'Uninstall programs you no longer use via Settings > Apps; this folder then shrinks on its own.')
_r(r'<D>\\windows\\system32\\driverstore<SUB>', DANGER, 'Driver store',
   'Copies of every hardware driver Windows has, so devices keep working.',
   'Don\'t delete by hand. Removing the wrong driver package can break hardware, networking or booting.',
   'Disk Cleanup > "Device driver packages" removes only superseded ones.')
_r(r'<D>\\windows\\system32\\config<SUB>', DANGER, 'Windows registry files',
   'The Windows registry hives.', 'Never delete. Windows will not boot without these.')
_r(r'<D>\\windows\\fonts<SUB>', DANGER, 'Windows fonts', 'System fonts used by Windows and programs.',
   'Don\'t delete. Remove fonts you added through Settings > Personalization > Fonts instead.')
_r(r'<D>\\windows\\(assembly|microsoft\.net)<SUB>', DANGER, '.NET Framework files',
   'Shared .NET libraries used by many programs.', 'Don\'t delete. Programs and Windows depend on them.')
_r(r'<D>\\windows\\system32<SUB>', DANGER, 'Core Windows system files',
   'The heart of Windows: system programs, drivers and libraries.',
   'NEVER delete. Removing files here can make Windows unbootable.')
_r(r'<D>\\windows\\syswow64<SUB>', DANGER, '32-bit Windows compatibility files',
   'Lets 32-bit programs run on 64-bit Windows.', 'NEVER delete.')
_r(r'<D>\\windows$', DANGER, 'Windows operating system',
   'The Windows operating system itself.', 'NEVER delete. Free space elsewhere or use Disk Cleanup for this drive.')
_r(r'<D>\\windows<SUB>', DANGER, 'Part of Windows',
   'A component of the Windows operating system.', 'Don\'t delete. Windows manages these files itself.')
_r(r'<D>\\(boot|efi|recovery|\$winreagent|\$extend|\$secure)<SUB>', DANGER, 'Boot / recovery data',
   'Files needed to start Windows or to recover it.', 'Don\'t delete. Your PC may stop booting.')
_r(r'<D>\\(bootmgr|bootnxt)$', DANGER, 'Boot manager', 'Starts Windows when the PC turns on.', 'Don\'t delete.')
_r(r'<D>\\system volume information<SUB>', DANGER, 'Restore points & shadow copies',
   'System Restore points and File History/Volume Shadow Copy data. Windows protects it.',
   'Don\'t touch it by hand. You can reduce how much space it may use.',
   'Control Panel > System > System protection > Configure (lower the max usage or Delete old restore points).')
_r(r'<D>\\users\\(default|default user|all users|defaultuser0)<SUB>', DANGER, 'Windows account template',
   'The template Windows copies when it creates a new user account.', 'Don\'t delete.')
_r(r'<PF>\\windowsapps<SUB>', DANGER, 'Microsoft Store apps',
   'Where Windows installs Store apps. It is locked down on purpose.',
   'Don\'t delete. Uninstall apps from Settings > Apps instead.')
_r(r'<PF>\\(common files|windows defender|windows defender advanced threat protection|windows security|windows nt|'
   r'windows mail|windows media player|windows photo viewer|windows portable devices|windows sidebar|windowspowershell|'
   r'internet explorer|modifiablewindowsapps|microsoft update health tools|uninstall information)<SUB>',
   DANGER, 'Windows / shared program components',
   'Shared libraries and built-in Windows programs that other software relies on.',
   'Don\'t delete. Other programs (and Windows) can break.')
_r(r'<D>\\programdata\\microsoft\\windows\\wer<SUB>', SAFE, 'Windows error reports',
   'Crash and error reports queued for Microsoft.', 'Safe to delete.', STORAGE_SENSE)
_r(r'<D>\\programdata\\microsoft<SUB>', DANGER, 'Windows / Microsoft system data',
   'Data used by Windows, Defender, Office and other Microsoft components.',
   'Don\'t delete by hand - it can break updates, security or Office.')

# ───────────────────────────────────────────────────────────────────────────
# 3. Per-user system data
# ───────────────────────────────────────────────────────────────────────────
_r(r'<ROAM>\\microsoft\\(protect|crypto|credentials|systemcertificates|vault)<SUB>', DANGER, 'Encryption keys & saved credentials',
   'Your Windows encryption master keys, certificates and saved logins.',
   'NEVER delete. Saved passwords, Wi-Fi keys and encrypted files become unreadable.')
_r(r'<ROAM>\\microsoft\\windows\\recent<SUB>', SAFE, 'Recent-files shortcuts',
   'Shortcuts behind "Recent files" lists.', 'Safe to delete. They are tiny and rebuild as you work.')
_r(r'<LOCAL>\\temp<SUB>', SAFE, 'Your temporary files',
   'Scratch files created by programs, installers and downloads.',
   'Safe to delete. Files that are in use are skipped. Close your programs first for best results.', STORAGE_SENSE)
_r(r'<LOCAL>\\microsoft\\windows\\(inetcache|explorer|wer|webcache)<SUB>', SAFE, 'Thumbnail / internet / error-report caches',
   'Cached thumbnails & icons, Internet Explorer/Edge-legacy cache and error reports.',
   'Safe to delete. Windows rebuilds them (thumbnails reappear as you browse folders).', STORAGE_SENSE + ' ("Thumbnails").')
_r(r'<LOCAL>\\crashdumps<SUB>', SAFE, 'Program crash dumps', 'Memory dumps written when a program crashed.',
   'Safe to delete unless a developer asked you to keep one.')
_r(r'<LOCAL>\\microsoft\\windowsapps<SUB>', CAUTION, 'App shortcuts', 'Launcher aliases for Store apps and tools (python.exe, winget.exe ...).',
   'Don\'t delete - commands like "python" or "winget" can stop working.')
_r(r'<LOCAL>\\packages\\(canonicalgrouplimited|thedebianproject|kalilinux|suse|ubuntu|debian|pengwin|oracle)[^\\]*<SUB>',
   CAUTION, 'WSL Linux distribution',
   'A Linux distribution for the Windows Subsystem for Linux. Your whole Linux home folder and files live in here.',
   'Don\'t delete unless you are sure you no longer need ANY of the Linux data. It cannot be recovered.',
   'Use "wsl --unregister <name>" or Settings > Apps to remove a distro properly; "wsl --manage <name> --move" relocates it.')
_r(r'<LOCAL>\\wsl<SUB>', CAUTION, 'WSL virtual disks',
   'Virtual disks (ext4.vhdx) holding the files of your WSL Linux distributions.',
   'Don\'t delete: all files inside those Linux systems would be lost.')
_r(r'<LOCAL>\\packages$', CAUTION, 'Microsoft Store app data',
   'Settings, caches and data for apps installed from the Microsoft Store (one folder per app).',
   'Don\'t delete the folder. To reclaim space, use "Reset" or "Uninstall" for the specific app in Settings > Apps.')
_r(r'<LOCAL>\\programs$', CAUTION, 'Programs installed just for you',
   'Programs that were installed without administrator rights (VS Code, Python, Discord, ...).',
   'Don\'t delete folders by hand. Uninstall the program from Settings > Apps.')
_r(r'<LOCAL>\\programs\\[^\\]+$', CAUTION, 'Installed program: {leaf}',
   'A program installed for your user account only.',
   'Don\'t just delete the folder; uninstall it from Settings > Apps so shortcuts and registry entries are cleaned up too.')

# ───────────────────────────────────────────────────────────────────────────
# 4. Your own stuff
# ───────────────────────────────────────────────────────────────────────────
_r(r'<U>\\downloads$', PERSONAL, 'Downloads',
   'Everything you have downloaded. A great place to find space: old installers, ZIPs and ISOs pile up here.',
   'Your call - review it. Installers (.exe/.msi), archives and disk images you already used can usually go.',
   'Sort by size, delete what you no longer need.')
_r(r'<U>\\(documents|desktop|pictures|videos|music|saved games|favorites|contacts|links|searches|3d objects|my documents)$',
   PERSONAL, 'Your {leaf} folder', 'A standard folder holding your own files.',
   'These are YOUR files. Delete only things you recognise and don\'t need. Back up what matters first.')
_r(r'<U>\\(onedrive[^\\]*|dropbox[^\\]*|google drive|my drive|icloud drive|iclouddrive|icloudphotos|box|box sync|mega|megasync)$',
   CAUTION, 'Cloud-synced folder: {leaf}',
   'A folder kept in sync with an online service. Files you delete here are usually deleted online and on your other devices too.',
   'Be careful: deleting here deletes everywhere. To free local space, use "Free up space" / "Online-only" '
   '(right-click the files in Explorer) so they stay in the cloud.')
_r(r'<D>\\users$', CAUTION, 'User accounts', 'Holds one folder per user account on this PC.', 'Don\'t delete.')
_r(r'<D>\\users\\public<SUB>', CAUTION, 'Shared (Public) files', 'Files shared between all users of this PC.',
   'Delete only what you recognise and don\'t need.')
_r(r'<U>$', CAUTION, 'Your user profile',
   'Everything for this Windows account: documents, desktop, settings and app data.',
   'Never delete the whole profile. Look inside for the big items.')
_r(r'<U>\\appdata$', CAUTION, 'Hidden app data',
   'Where programs keep settings, caches and local data (subfolders Local, LocalLow and Roaming).',
   'Don\'t delete the folder. Individual caches inside can be cleared - see the verdict on each subfolder.')

# ───────────────────────────────────────────────────────────────────────────
# 5. Games / launchers
# ───────────────────────────────────────────────────────────────────────────
_r(r'(?:.*\\)?steamapps\\(shadercache|downloading|temp)<SUB>', SAFE, 'Steam shader cache / unfinished downloads',
   'Steam\'s compiled-shader cache and partially downloaded updates.',
   'Safe to delete (Steam rebuilds shaders and restarts pending downloads).')
_r(r'(?:.*\\)?steamapps\\common\\[^\\]+$', CAUTION, 'Installed Steam game: {leaf}',
   'The installed files of a game.', 'Uninstall through Steam (right-click the game > Manage > Uninstall) - '
   'deleting the folder by hand leaves Steam thinking it is installed. Your save games may live elsewhere.')
_r(r'(?:.*\\)?steamapps(?:\\common|\\workshop)?$', CAUTION, 'Steam game library',
   'Games installed through Steam.', 'Uninstall games you no longer play through Steam.')
_r(r'<D>\\(games|xboxgames|epic games|riot games|gog games|gog galaxy|ubisoft|battle\.net|blizzard entertainment|origin games|ea games)$',
   CAUTION, 'Game install folder', 'Games installed here.',
   'Uninstall games through their launcher or Settings > Apps rather than deleting folders.')
_r(r'(?:<PF>|<D>\\(?:games|xboxgames|riot games|gog games|ubisoft))\\(epic games|riot games|gog games|ubisoft|games)\\[^\\]+$',
   CAUTION, 'Installed game: {leaf}', 'The installed files of a game.',
   'Uninstall it from its launcher (Epic Games Launcher, GOG Galaxy, ...) or Settings > Apps. Deleting the folder by '
   'hand leaves the launcher confused. Save games are usually stored elsewhere, in Documents or AppData.')
_r(r'<D>\\(games|xboxgames|gog games|ubisoft)\\[^\\]+$', CAUTION, 'Installed game: {leaf}', 'The installed files of a game.',
   'Uninstall it through its launcher, or delete the whole folder if you are done with the game (saves are usually elsewhere).')

# ───────────────────────────────────────────────────────────────────────────
# 6. Developer / AI-tool caches that regenerate
# ───────────────────────────────────────────────────────────────────────────
_r(r'<U>\\\.cache\\huggingface<SUB>', SAFE, 'Hugging Face model cache',
   'AI models and datasets downloaded by Python scripts.',
   'Safe to delete - they are re-downloaded when a script needs them again (which can take a while, several GB).')
_r(r'<U>\\\.ollama(\\models)?<SUB>', CAUTION, 'Ollama AI models',
   'Large language models downloaded with Ollama.', 'Deletable if you can re-download them ("ollama pull <model>"). '
   'Custom models you built would be lost.', 'Use "ollama rm <model>" to delete single models.')
_r(r'<U>\\\.(gradle\\(caches|wrapper\\dists|daemon)|nuget\\packages|cargo\\(registry|git)|npm|cache)<SUB>', SAFE,
   'Package / build cache', 'Downloaded libraries and build outputs that your developer tools cache.',
   'Safe to delete. They are re-downloaded when a project is built next time (needs internet).')
_r(r'<U>\\\.m2\\repository<SUB>', CAUTION, 'Maven local repository',
   'Java libraries downloaded for Maven, plus anything you "mvn install"ed locally.',
   'Usually re-downloadable, but locally installed artifacts would be lost.')
_r(r'(?:.*\\)?(anaconda3|miniconda3|miniforge3|mambaforge)\\pkgs$', SAFE, 'Conda package cache',
   'Downloaded conda packages kept for reuse.', 'Safe to delete.', 'Run "conda clean --all".')
_r(r'(?:.*\\)?(anaconda3|miniconda3|miniforge3|mambaforge)$', CAUTION, 'Python (Conda) distribution',
   'A Python distribution with all your conda environments.',
   'Don\'t delete by hand - uninstall it, or remove single environments with "conda env remove".')
_r(r'<LOCAL>\\(npm-cache|pip\\cache|yarn\\cache|pnpm\\(store|cache)|pnpm-store|nuget\\(v3-cache|plugins-cache|http-cache))<SUB>', SAFE,
   'Package manager cache', 'Downloads cached by npm / pip / yarn / pnpm / NuGet.',
   'Safe to delete. They are fetched again when needed.')
_r(r'<ROAM>\\npm<SUB>', CAUTION, 'Global npm packages',
   'Command-line tools installed with "npm install -g" (and the node_modules that belong to them).',
   'Don\'t delete casually: those tools stop working. They can be reinstalled, but you would need to remember what you had.')
_r(r'<LOCAL>\\docker<SUB>', CAUTION, 'Docker Desktop data',
   'Docker images, containers and volumes (often one huge virtual disk).',
   'Don\'t delete: you would lose containers and volumes. Prune unused things instead.',
   'Run "docker system prune -a" (and "docker volume prune" if you are sure).')
_r(r'<D>\\programdata\\docker(desktop)?<SUB>', CAUTION, 'Docker data', 'Docker Desktop images and volumes.',
   'Don\'t delete by hand.', 'Run "docker system prune -a" to reclaim space.')
_r(r'<U>\\\.android\\avd<SUB>', CAUTION, 'Android emulator devices',
   'Virtual Android phones created for the Android emulator.', 'Delete devices you no longer use from Android Studio > Device Manager.')

_r(r'<D>\\programdata\\nvidia corporation\\(downloader|nv_cache)<SUB>', SAFE, 'NVIDIA installer downloads',
   'Driver installers NVIDIA\'s software downloaded earlier.', 'Safe to delete. They are fetched again if you update the driver.')
_r(r'<LOCAL>\\android\\sdk\\system-images<SUB>', CAUTION, 'Android emulator system images',
   'Large virtual-phone operating system images for the Android emulator.',
   'Remove the ones you no longer test with via Android Studio > SDK Manager (they can be re-downloaded).')
_r(r'<LOCAL>\\android\\sdk<SUB>', CAUTION, 'Android SDK', 'Android developer tools, platforms and emulator images.',
   'Manage it from Android Studio > SDK Manager rather than deleting by hand. Everything can be re-downloaded.')
_r(r'<D>\\(msys64|msys32|mingw64|mingw32|cygwin64|cygwin)<SUB>', CAUTION, 'MSYS2 / MinGW / Cygwin toolchain',
   'A Unix-style build environment for Windows (compilers, shell, libraries).',
   'Uninstall it with its own uninstaller (or delete the folder if you are sure you no longer compile with it).')
_r(r'<U>\\(virtualbox vms|vmware|\.vagrant\.d|\.minikube)<SUB>', CAUTION, 'Virtual machines',
   'Virtual machines and their disks.', 'Each VM is a whole computer - delete only those you will never boot again, '
   'preferably from the VM program so it forgets them too.')
_r(r'<U>\\source(\\repos)?$', PERSONAL, 'Your Visual Studio projects',
   'Source code of your projects.', 'Your work. Build output and "node_modules" folders inside are safe to delete; the source is not.')
_r(r'<LOCAL>\\microsoft\\office\\[\d.]+\\(officefilecache|wef)<SUB>', SAFE, 'Office cache',
   'Cached documents and web add-in data of Microsoft Office.', 'Safe to delete (close Office first).')
_r(r'(?:.*\\)\.dropbox\.cache<SUB>', SAFE, 'Dropbox deleted-files cache',
   'Copies of files you deleted from Dropbox, kept briefly so you can undo.', 'Safe to delete; Dropbox clears it by itself after 3 days.')
_r(r'(?:.*\\)spotify\\(storage|data)<SUB>', SAFE, 'Spotify cache',
   'Songs Spotify cached for streaming and offline play.', 'Safe to delete. Offline downloads must be downloaded again.')
_r(r'(?:.*\\)steam\\(appcache|depotcache|dumps|logs)<SUB>', SAFE, 'Steam cache', 'Steam\'s download, crash and log caches.',
   'Safe to delete - Steam rebuilds them.')
_r(r'(?:.*\\)steam\\userdata<SUB>', CAUTION, 'Steam local user data',
   'Your Steam settings and, for some games, local save games and screenshots.', 'Don\'t delete unless you have cloud saves for your games.')
_r(r'<LOCAL>\\(unrealengine|unity|unitycache|blender foundation)<SUB>', CAUTION, 'Game-engine / 3D tool data',
   'Settings and caches of a game engine or 3D tool.', 'Caches inside are safe to clear; the rest holds your settings.')
_r(r'<LOCAL>\\roblox\\downloads<SUB>', SAFE, 'Roblox installer downloads', 'Installer files Roblox downloaded for updates.',
   'Safe to delete; Roblox downloads them again when needed.')

# Generic dev-project folders (match at any depth)
_r(r'(?:.*\\)node_modules<SUB>', SAFE, 'Node.js dependencies',
   'Libraries a JavaScript project downloaded into itself (npm/yarn/pnpm).',
   'Safe to delete if the project still has its package.json - run "npm install" to get them back. '
   'Often the biggest space hog in dev folders.')
_r(r'(?:.*\\)(__pycache__|\.pytest_cache|\.mypy_cache|\.ruff_cache|\.tox|\.nox|\.hypothesis|\.parcel-cache|\.next|\.nuxt|'
   r'\.turbo|\.angular|\.sass-cache|\.eslintcache|\.vs|componentmodelcache)<SUB>', SAFE, 'Build / tool cache',
   'Files generated automatically by a programming tool or IDE (compiled Python, test caches, build output).',
   'Safe to delete. They are recreated the next time you run or build the project.')
_r(r'(?:.*\\)\.git<SUB>', CAUTION, 'Git repository history',
   'The full version history of a project.',
   'Deleting it destroys the history (including any commits that were never pushed). The project files themselves stay.')
_r(r'(?:.*\\)(venv|\.venv|virtualenv)<SUB>', CAUTION, 'Python virtual environment',
   'A private copy of Python and libraries for one project.',
   'Deletable if you can recreate it (pip install -r requirements.txt). Check that the project has a requirements file first.')
_r(r'(?:.*\\)\.idea<SUB>', CAUTION, 'IDE project settings', 'JetBrains IDE settings for this project.',
   'Safe to delete in practice, but you lose your IDE configuration for the project.')

# ───────────────────────────────────────────────────────────────────────────
# 7. Browsers
# ───────────────────────────────────────────────────────────────────────────
_CHROMIUM = (r'(?:google\\chrome(?: beta| dev| sxs)?|microsoft\\edge(?: beta| dev| sxs)?|bravesoftware\\brave-browser|'
             r'vivaldi|chromium)')
_r(r'<LOCAL>\\' + _CHROMIUM + r'\\user data$', CAUTION, 'Browser profile data',
   'Everything the browser stores: profiles, bookmarks, saved passwords, history and caches.',
   'Don\'t delete the folder. Clear the cache from the browser (Ctrl+Shift+Del) instead.')
_r(r'<LOCAL>\\' + _CHROMIUM + r'\\user data\\(default|profile \d+|guest profile|system profile)$', CAUTION,
   'Browser profile',
   'One browser profile: bookmarks, saved passwords, extensions, cookies and history. Caches inside are safe to clear.',
   'Don\'t delete unless you have signed in to sync (or exported bookmarks/passwords). Open "Cache" inside to clear only that.')
_r(r'<LOCAL>\\mozilla\\firefox\\profiles\\[^\\]+$', CAUTION, 'Firefox profile (cache side)',
   'Firefox\'s cache for one profile; the main profile (bookmarks, passwords) is in AppData\\Roaming.',
   'Only the "cache2" subfolder is safe to delete.')
_r(r'<ROAM>\\mozilla\\firefox\\profiles(\\[^\\]+)?$', CAUTION, 'Firefox profile',
   'Firefox bookmarks, saved passwords, extensions and history.',
   'Don\'t delete unless you use Firefox Sync or have a backup.')
_r(r'(?:.*\\)storage\\default<SUB>', CAUTION, 'Website data stored by the browser',
   'Data that websites and web apps (e.g. WhatsApp Web) keep in your browser: logins, offline data, settings.',
   'Delete it from the browser (Settings > Privacy > Cookies and site data) rather than by hand - you may be signed out of sites.')

# ───────────────────────────────────────────────────────────────────────────
# 8. Generic leaf-name heuristics (anywhere that wasn't claimed above)
# ───────────────────────────────────────────────────────────────────────────
_r(r'(?:.*\\)(cache|caches|\.cache|code cache|gpucache|dawncache|grshadercache|shadercache|dxcache|glcache|vkcache|'
   r'nv_cache|d3dscache|cachestorage|scriptcache|cache2|startupcache|jumplistcache|htmlcache|component_crx_cache|'
   r'cacheddata|cachedextensionvsixs|cachedprofilesdata|_cacache|tempstate|inetcache|crashpad|crash reports|'
   r'webcache(?:_\d+)?|appcache|depotcache|officefilecache|shader_cache|shaders_cache|pipeline_cache|'
   r'blob_storage)<SUB>',
   SAFE, 'Cache', 'Temporary data an app keeps so it can start or load faster.',
   'Safe to delete. The app recreates it (it may start a little slower once, and you might be signed out of some apps).')
_r(r'(?:.*\\)(logs?|crashes)<SUB>', SAFE, 'Log files', 'Records of what a program did, useful only for troubleshooting.',
   'Safe to delete.')
_r(r'(?:.*\\)(temp|tmp)<SUB>', SAFE, 'Temporary files', 'Scratch space for programs.',
   'Usually safe to delete - make sure nothing you care about was saved there.')

# ───────────────────────────────────────────────────────────────────────────
# 9. Catch-alls by location
# ───────────────────────────────────────────────────────────────────────────
_r(r'<PF>$', CAUTION, 'Installed programs',
   'Programs installed on this PC.', 'Never delete folders here by hand. Uninstall programs from Settings > Apps.')
_r(r'<PF>\\dotnet$', CAUTION, '.NET runtimes', 'Runtime libraries many programs need.',
   'Don\'t delete. Old versions can be removed from Settings > Apps if nothing needs them.')
_r(r'<PF>\\[^\\]+$', CAUTION, 'Installed program: {leaf}',
   'A program installed on this PC.',
   'Don\'t just delete the folder - uninstall it from Settings > Apps so services, shortcuts and registry entries are '
   'cleaned up too. Unused programs are a good way to free space.')
_r(r'<D>\\programdata\\package cache<SUB>', CAUTION, 'Installer package cache',
   'Setup files for Visual Studio, .NET and other programs, kept for repair and uninstall.',
   'Deleting can make those programs impossible to repair or uninstall. Leave it unless you have uninstalled them already.')
_r(r'<D>\\programdata$', CAUTION, 'Shared program data',
   'Hidden folder where programs keep data shared by all users.', 'Don\'t delete the folder itself.')
_r(r'<D>\\programdata\\[^\\]+$', CAUTION, 'Shared data of {leaf}',
   'Settings, databases or caches that a program shares between all users.',
   'If you uninstalled the program, this is usually leftover and can go. If it is still installed, leave it.')
_r(r'<ROAM>$', CAUTION, 'Roaming app data', 'Settings and data of your programs that follow your account.',
   'Don\'t delete the folder; see the individual subfolders.')
_r(r'<LOCAL>$', CAUTION, 'Local app data', 'Caches and data of your programs that stay on this PC.',
   'Don\'t delete the folder; see the individual subfolders.')
_r(r'<U>\\appdata\\locallow$', CAUTION, 'Low-integrity app data', 'Data for sandboxed programs and games.',
   'Don\'t delete the folder; see the individual subfolders.')
_r(r'(?:<ROAM>|<LOCAL>|[a-z]:\\users\\[^\\]+\\appdata\\locallow)\\[^\\]+$', CAUTION, 'App data: {leaf}',
   'Settings, saved data and caches of "{leaf}".',
   'If you uninstalled this program, the folder is usually leftover and can be deleted. If you still use it, '
   'deleting resets its settings and may lose local-only data (for example saved sessions or offline files).')
_r(r'<U>\\\.ssh<SUB>', CAUTION, 'SSH keys', 'Private keys used to log in to servers and Git hosts.',
   'Don\'t delete - you could lose access to servers that have no other login.')
_r(r'<U>\\\.[^\\]+$', CAUTION, 'Tool settings: {leaf}',
   'Configuration and data for a command-line or developer tool.',
   'Leave it unless you know the tool is uninstalled. Deleting resets that tool\'s configuration.')
_r(r'<D>\\(inetpub|msocache|swsetup|config\.msi)<SUB>', CAUTION, 'System-created folder',
   'Created by IIS, Office setup, an OEM driver kit or a Windows installer.',
   'Usually leave alone. If you know you have no use for it (no IIS, setup finished) it can go.')
_r(r'<D>\\?$', CAUTION, 'Drive root', 'The top level of a drive.', 'Nothing to delete here - look at the folders inside.')

UNKNOWN_DIR = Info(UNKNOWN, 'Unrecognised folder',
                   'Not part of Windows and not a program or cache this tool knows about. If you created it, it is your data.',
                   'Look inside before deciding. If it holds your files, treat it as personal data.',
                   'Right-click > "Search the web for this name" to find out what created it.')

# ───────────────────────────────────────────────────────────────────────────
# Files
# ───────────────────────────────────────────────────────────────────────────
_SPECIAL_FILES = {
    'pagefile.sys': Info(DANGER, 'Windows virtual memory (page file)',
                         'Windows uses this as extra RAM when memory runs low. Often several GB.',
                         'Don\'t delete (Windows holds it open anyway).',
                         'Change its size at System Properties > Advanced > Performance > Settings > Advanced > Virtual memory.'),
    'swapfile.sys': Info(DANGER, 'Windows app swap file', 'Used by Windows for Store apps.', 'Don\'t delete.'),
    'hiberfil.sys': Info(CAUTION, 'Hibernation file',
                         'A copy of your RAM saved so Windows can hibernate and use Fast Startup. About 40-75 % of your RAM.',
                         'Don\'t delete the file. If you never hibernate, you can switch the feature off and Windows removes it.',
                         'Admin Command Prompt:  powercfg /hibernate off   (also disables Fast Startup)'),
    'dumpstack.log.tmp': Info(SAFE, 'Debug log', 'A tiny debug log Windows recreates.', 'Safe to delete (usually locked anyway).'),
    'memory.dmp': Info(SAFE, 'Crash dump', 'Memory snapshot from a Windows crash.', 'Safe to delete unless you need to diagnose the crash.'),
    'thumbs.db': Info(SAFE, 'Thumbnail cache', 'Old-style picture thumbnail cache.', 'Safe to delete; it is recreated.'),
    'ehthumbs.db': Info(SAFE, 'Thumbnail cache', 'Old-style video thumbnail cache.', 'Safe to delete; it is recreated.'),
    'desktop.ini': Info(CAUTION, 'Folder display settings', 'Tiny hidden file that sets a folder\'s icon or localised name.',
                        'Harmless, but pointless to delete - it comes back.'),
    'usrclass.dat': Info(DANGER, 'Your user registry (classes)', 'Part of your Windows account settings.', 'NEVER delete.'),
}

_JUNK = {}
_EXT = {}
_OVERRIDE = {}


def _ext(table, exts, level, title, what, advice, how=''):
    info = Info(level, title, what, advice, how)
    for e in exts.split():
        table[e] = info


_ext(_JUNK, 'tmp temp', SAFE, 'Temporary file', 'A scratch file a program meant to throw away.',
     'Safe to delete when the program that made it is closed.')
_ext(_JUNK, 'log etl', SAFE, 'Log file', 'A record of what a program or Windows did.', 'Safe to delete; only useful for troubleshooting.')
_ext(_JUNK, 'dmp mdmp hdmp', SAFE, 'Crash dump', 'A memory snapshot taken when a program or Windows crashed.',
     'Safe to delete unless someone asked you to send it.')
_ext(_JUNK, 'crdownload part partial download', SAFE, 'Unfinished download', 'A download that was interrupted or is still running.',
     'Safe to delete if the download is not running any more.')
_ext(_JUNK, 'pyc pyo cache', SAFE, 'Generated cache file', 'A file a program or compiler generated and can rebuild.',
     'Safe to delete; it is recreated when needed.')
_ext(_JUNK, 'chk', SAFE, 'Disk-check fragment', 'Recovered file fragments from CHKDSK.', 'Usually safe to delete after a glance.')
_ext(_JUNK, 'bak old orig', CAUTION, 'Backup copy', 'A backup of another file, made by a program or by you.',
     'Delete only if the original file is fine.')

_ext(_OVERRIDE, 'vhd vhdx vmdk vdi qcow2 ova', CAUTION, 'Virtual machine / virtual disk',
     'A whole virtual hard disk (virtual machine, WSL, Docker...). Often tens of GB.',
     'Deleting destroys everything inside it. Only delete if you are sure you no longer need that VM.',
     'WSL: "wsl --shutdown" then compact it with Optimize-VHD / diskpart. Docker: prune from the app.')
_ext(_OVERRIDE, 'pst', PERSONAL, 'Outlook mail archive', 'An Outlook data file with emails, calendar and contacts.',
     'Your only copy of those emails may be in here. Do not delete unless you are sure.')
_ext(_OVERRIDE, 'ost', CAUTION, 'Outlook offline cache', 'A local copy of a mailbox that lives on a server.',
     'Normally safe if the account is on Exchange/Microsoft 365/IMAP (it re-syncs), but sync can be slow.')
_ext(_OVERRIDE, 'kdbx kdb', PERSONAL, 'Password database', 'A KeePass password file.', 'Do NOT delete unless you have a backup.')

_ext(_EXT, 'mp4 mkv avi mov wmv flv webm m4v mpg mpeg ts m2ts vob', PERSONAL, 'Video', 'A video file.',
     'Probably yours (a recording or download). Delete only if you no longer want it.')
_ext(_EXT, 'mp3 wav flac m4a aac ogg wma opus aiff', PERSONAL, 'Audio', 'A music or audio file.', 'Yours - delete only if you don\'t want it.')
_ext(_EXT, 'jpg jpeg png gif bmp tif tiff heic heif webp raw cr2 cr3 nef arw dng psd ai svg ico', PERSONAL, 'Picture / image',
     'A picture or graphic.', 'Photos are often irreplaceable - check you have a copy before deleting.')
_ext(_EXT, 'doc docx xls xlsx ppt pptx pdf odt ods odp rtf txt md csv epub one', PERSONAL, 'Document',
     'A document, spreadsheet, presentation or text file.', 'Your own work - only delete if you are sure you don\'t need it.')
_ext(_EXT, 'py js jsx ts tsx java c cpp h cs go rs php rb kt swift sql json xml yml yaml html css ps1 bat sh ipynb', PERSONAL,
     'Source code / data', 'A programming or data file.', 'Part of someone\'s project. Delete only if you know it is not needed.')
_ext(_EXT, 'blend fbx obj stl 3ds max ma mb unitypackage kra xcf', PERSONAL, '3D / creative project',
     'A 3D model, scene or art project file.', 'Your creative work - delete only if you are sure.')
_ext(_EXT, 'sav save dat0 savegame', PERSONAL, 'Game save', 'A saved game.', 'Deleting loses your progress in that game.')
_ext(_EXT, 'apk aab xapk jar whl nupkg', CAUTION, 'Package / app bundle',
     'An Android app, Java library or package archive. Often a download or build output.',
     'Usually re-downloadable or rebuildable. Delete it if you no longer need that exact file.')
_ext(_EXT, 'ini cfg conf config toml', CAUTION, 'Settings file', 'A configuration file of some program.',
     'Deleting it usually resets that program\'s settings. Harmless if the program is gone.')
_ext(_EXT, 'torrent magnet', PERSONAL, 'Torrent file', 'A small file that tells a torrent client what to download.',
     'Safe to delete once the download finished and you no longer seed it.')
_ext(_EXT, 'pak bdt bsa ba2 vpk wad uasset upk tfc xwb xnb forge arc', CAUTION, 'Game data file',
     'A packed asset file (textures, sound, levels) belonging to a game.',
     'Don\'t delete single files - the game breaks. If you are done with the game, delete or uninstall the whole game folder.')
_ext(_EXT, 'zip 7z rar tar gz tgz bz2 xz', CAUTION, 'Compressed archive',
     'A ZIP-style archive. If it is a download you have already extracted, you probably don\'t need it any more.',
     'Delete if you extracted it (or can re-download it). Otherwise it may be your only copy.')
_ext(_EXT, 'iso img', CAUTION, 'Disk image', 'A disk image, often an installer or OS download (Windows ISO, game, etc.).',
     'Usually re-downloadable. Safe to delete if you already installed from it and don\'t need the media.')
_ext(_EXT, 'exe msi msix msixbundle appx appxbundle msu cab', CAUTION, 'Program / installer',
     'A program or installer. If it is an installer you already ran, it is just taking up space.',
     'Installers in Downloads can usually be deleted after installing. Never delete programs that are installed.')
_ext(_EXT, 'dll sys drv ocx', CAUTION, 'Program library / driver', 'Code that programs or Windows load.',
     'Don\'t delete: programs or hardware may stop working.')
_ext(_EXT, 'db sqlite sqlite3 mdb accdb mdf ldf', CAUTION, 'Database file', 'A database that belongs to some program.',
     'Deleting it can erase that program\'s data. Delete only if you know it is not needed.')
_ext(_EXT, 'lnk url', SAFE, 'Shortcut', 'A shortcut to a file, folder or website.', 'Safe to delete - it only removes the shortcut.')

_dir_cache = {}


def norm(path):
    path = os.path.normpath(path)
    return path


def _expand(info, path):
    leaf = os.path.basename(path) or path
    return replace(info, title=info.title.replace('{leaf}', leaf), what=info.what.replace('{leaf}', leaf),
                   advice=info.advice.replace('{leaf}', leaf), how=info.how.replace('{leaf}', leaf))


def _inherit(info):
    """The same verdict, flagged as coming from a parent folder."""
    return info if info.inherited else replace(info, inherited=True, title='Inside: ' + info.title)


def classify_dir(path):
    """Return an Info for the folder at `path`."""
    path = norm(path)
    cached = _dir_cache.get(path)
    if cached is not None:
        return cached
    result = None
    for rule in _RULES:
        m = rule.rx.match(path)
        if m:
            result = _expand(rule.info, path)
            if m.end() < len(path):
                result = _inherit(result)
            break
    if result is None:
        parent = os.path.dirname(path)
        at_top = not parent or parent == path or os.path.dirname(parent) == parent   # parent is a drive root
        result = UNKNOWN_DIR if at_top else _inherit(classify_dir(parent))
    _dir_cache[path] = result
    return result


def _unknown_file(ext):
    label = f'.{ext}' if ext else 'no extension'
    return Info(UNKNOWN, 'Unrecognised file', f'A file of an unknown type ({label}).',
                'Check which program uses it before deleting.',
                'Right-click > "Search the web for this name" to find out what it is.')


def classify_file(path):
    """Return an Info for the file at `path`."""
    path = norm(path)
    name = os.path.basename(path).lower()
    ext = os.path.splitext(name)[1].lstrip('.')
    special = _SPECIAL_FILES.get(name)
    if special is None and name.startswith('ntuser.dat'):
        special = Info(DANGER, 'Your user registry', 'The registry hive holding your Windows account settings.', 'NEVER delete.')
    if special:
        return special
    parent = classify_dir(os.path.dirname(path))
    if parent.level == DANGER:
        return _inherit(parent)
    if ext in _JUNK:
        return _JUNK[ext]
    if parent.level == SAFE:
        return _inherit(parent)
    if ext in _OVERRIDE:
        return _OVERRIDE[ext]
    if parent.level == CAUTION:
        return _inherit(parent)
    if ext in _EXT:
        return _EXT[ext]
    if parent.level == PERSONAL:
        return _inherit(parent)
    return _unknown_file(ext)
