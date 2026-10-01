"""Sanity tests for the knowledge base and scanner.  Run:  python test_knowledge.py"""
import os
import tempfile

import knowledge as K
from scanner import Scanner, fmt_size

DIRS = {
    r'C:\Windows': K.DANGER,
    r'C:\Windows\System32': K.DANGER,
    r'C:\Windows\System32\drivers\etc': K.DANGER,
    r'C:\Windows\WinSxS': K.DANGER,
    r'C:\Windows\Installer': K.DANGER,
    r'C:\Windows\Temp': K.SAFE,
    r'C:\Windows\Temp\foo\bar': K.SAFE,
    r'C:\Windows\SoftwareDistribution\Download': K.SAFE,
    r'C:\Windows\SoftwareDistribution\DataStore': K.DANGER,
    r'C:\Windows\SoftwareDistribution': K.CAUTION,
    r'C:\Windows.old': K.SAFE,
    r'C:\$Recycle.Bin': K.SAFE,
    r'C:\Users\Bob\AppData\Local\Temp': K.SAFE,
    r'C:\Users\Bob\AppData\Local\Temp\x\y': K.SAFE,
    r'C:\Users\Bob\Documents': K.PERSONAL,
    r'C:\Users\Bob\Documents\game saves': K.PERSONAL,
    r'C:\Users\Bob\Documents\proj\node_modules': K.SAFE,
    r'C:\Users\Bob\Documents\proj\node_modules\left-pad': K.SAFE,
    r'C:\Users\Bob\Documents\proj\.git': K.CAUTION,
    r'C:\Users\Bob\Downloads': K.PERSONAL,
    r'C:\Users\Bob\OneDrive': K.CAUTION,
    r'C:\Users\Bob\OneDrive\Pictures': K.CAUTION,
    r'C:\Users\Bob\AppData\Local\Google\Chrome\User Data\Default\Cache': K.SAFE,
    r'C:\Users\Bob\AppData\Local\Google\Chrome\User Data\Default\Cache\Cache_Data': K.SAFE,
    r'C:\Users\Bob\AppData\Local\Google\Chrome\User Data\Default\Extensions': K.CAUTION,
    r'C:\Users\Bob\AppData\Local\Google\Chrome\User Data\Default': K.CAUTION,
    r'C:\Users\Bob\AppData\Roaming\Discord': K.CAUTION,
    r'C:\Users\Bob\AppData\Roaming\Discord\Cache': K.SAFE,
    r'C:\Users\Bob\AppData\Roaming\Microsoft\Protect': K.DANGER,
    r'C:\Users\Bob\AppData\Local\Packages\CanonicalGroupLimited.Ubuntu_79rhkp1fndgsc\LocalState': K.CAUTION,
    r'C:\Users\Bob\AppData\Local\Programs\Python': K.CAUTION,
    r'C:\Users\Bob\.gradle\caches': K.SAFE,
    r'C:\Users\Bob\.cache\huggingface\hub': K.SAFE,
    r'C:\Users\Bob\.ssh': K.CAUTION,
    r'C:\Program Files': K.CAUTION,
    r'C:\Program Files\Foo': K.CAUTION,
    r'C:\Program Files\Foo\bin': K.CAUTION,
    r'C:\Program Files (x86)\Bar': K.CAUTION,
    r'C:\Program Files\Common Files\x': K.DANGER,
    r'C:\Program Files\WindowsApps\Some.App': K.DANGER,
    r'C:\ProgramData\Package Cache': K.CAUTION,
    r'C:\ProgramData\Microsoft\Windows\WER\ReportQueue': K.SAFE,
    r'C:\ProgramData\Microsoft\Windows Defender': K.DANGER,
    r'C:\Program Files (x86)\Steam\steamapps\common\Half-Life': K.CAUTION,
    r'C:\Program Files (x86)\Steam\steamapps\shadercache': K.SAFE,
    r'D:\Foo': K.UNKNOWN,
    r'D:\Foo\Bar': K.UNKNOWN,
    r'D:\Games': K.CAUTION,
    r'D:\Photos\logs': K.SAFE,
    'C:\\': K.CAUTION,
    r'C:\Users\Bob\AppData\Roaming\npm\node_modules': K.CAUTION,
    r'C:\Users\Bob\AppData\Roaming\Mozilla\Firefox\Profiles\x.default\storage\default\https+++web.whatsapp.com\cache': K.CAUTION,
    r'C:\Program Files\Epic Games\rocketleague': K.CAUTION,
    r'C:\Users\Bob\AppData\Local\npm-cache': K.SAFE,
    r'C:\Users\Bob\AppData\Local\Google\Chrome\User Data\Profile 8\Storage\ext\glic': K.CAUTION,
    r'C:\Users\Bob\AppData\Local\Google\Chrome\User Data\Default\Network': K.CAUTION,
}

FILES = {
    r'C:\pagefile.sys': K.DANGER,
    r'C:\hiberfil.sys': K.CAUTION,
    r'C:\Windows\System32\kernel32.dll': K.DANGER,
    r'C:\Windows\System32\drivers\etc\hosts.log': K.DANGER,
    r'C:\Users\Bob\Downloads\setup.exe': K.CAUTION,
    r'C:\Users\Bob\Downloads\movie.MKV': K.PERSONAL,
    r'C:\Users\Bob\Downloads\thing.zip': K.CAUTION,
    r'C:\Users\Bob\Downloads\a.log': K.SAFE,
    r'C:\Users\Bob\AppData\Local\Temp\x.tmp': K.SAFE,
    r'C:\Users\Bob\AppData\Local\Temp\x.bin': K.SAFE,
    r'C:\Program Files\Foo\foo.dll': K.CAUTION,
    r'D:\stuff\a.log': K.SAFE,
    r'D:\stuff\a.xyz': K.UNKNOWN,
    r'D:\stuff\a.mp3': K.PERSONAL,
    r'D:\stuff\disk.vhdx': K.CAUTION,
    r'C:\Users\Bob\NTUSER.DAT': K.DANGER,
    r'C:\Users\Bob\Documents\notes.txt': K.PERSONAL,
    r'C:\Users\Bob\Desktop\games\X\data.pak': K.CAUTION,
    r'C:\Users\Bob\AppData\Local\Google\Chrome\User Data\Default\Login Data': K.CAUTION,
    r'C:\Users\Bob\AppData\Local\Google\Chrome\User Data\Default\Network\Cookies': K.CAUTION,
    r'C:\Users\Bob\AppData\Roaming\Mozilla\Firefox\Profiles\x.default\logins.json': K.CAUTION,
    r'C:\Users\Bob\AppData\Roaming\Mozilla\Firefox\Profiles\x.default\key4.db': K.CAUTION,
}

fails = []
for path, want in DIRS.items():
    got = K.classify_dir(path).level
    if got != want:
        fails.append(f'dir  {path}: expected {want}, got {got}')
for path, want in FILES.items():
    got = K.classify_file(path).level
    if got != want:
        fails.append(f'file {path}: expected {want}, got {got}')

# scanner: build a small tree and verify sizes
with tempfile.TemporaryDirectory() as tmp:
    os.makedirs(os.path.join(tmp, 'a', 'b'))
    os.makedirs(os.path.join(tmp, 'empty'))
    for rel, n in (('f1.bin', 1000), ('a/f2.bin', 2000), ('a/b/f3.bin', 4000), ('a/b/f4.bin', 8000)):
        with open(os.path.join(tmp, rel), 'wb') as fh:
            fh.write(b'x' * n)
    sc = Scanner(tmp, workers=4)
    sc.start()
    while not sc.finished:
        pass
    by_name = {n.name: n for n in sc.nodes}
    for name, size, files in ((os.path.normpath(tmp), 15000, 4), ('a', 14000, 3), ('b', 12000, 2), ('empty', 0, 0)):
        node = by_name[name]
        if (node.size, node.files) != (size, files):
            fails.append(f'scan {name}: expected {size}/{files}, got {node.size}/{node.files}')
    if [s for s, _ in sc.biggest] != [8000, 4000, 2000, 1000]:
        fails.append(f'biggest files wrong: {sc.biggest}')


# treemap layout: rectangles must tile the area exactly, with areas proportional to sizes
from treemap import squarify
sizes = [50, 30, 10, 5, 3, 2]
rects = squarify(sizes, 0, 0, 400, 300)
if len(rects) != len(sizes):
    fails.append('squarify returned the wrong number of rectangles')
else:
    if abs(sum(w * h for _, _, w, h in rects) - 400 * 300) > 1e-6:
        fails.append('squarify does not fill the area')
    for (x, y, w, h), s in zip(rects, sizes):
        if abs(w * h - s / 100 * 400 * 300) > 1e-6 or x < -1e-9 or y < -1e-9 or x + w > 400 + 1e-6 or y + h > 300 + 1e-6:
            fails.append(f'squarify rectangle wrong for size {s}: {(x, y, w, h)}')

# re-measuring part of a finished scan, and moving things to the Recycle Bin
import cleaner
from scanner import find_node, rescan_path
with tempfile.TemporaryDirectory() as tmp:
    for rel, n in (('keep.bin', 500), ('cache/a.bin', 2000), ('cache/sub/b.bin', 4000), ('other/c.bin', 1000)):
        os.makedirs(os.path.dirname(os.path.join(tmp, rel)), exist_ok=True)
        with open(os.path.join(tmp, rel), 'wb') as fh:
            fh.write(b'x' * n)
    sc = Scanner(tmp, workers=4)
    sc.start()
    while not sc.finished:
        pass
    if sc.root_node.size != 7500:
        fails.append(f'rescan setup: expected 7500, got {sc.root_node.size}')
    cache = os.path.join(tmp, 'cache')
    targets = cleaner.targets_for(cache, True)
    if sorted(os.path.basename(t) for t in targets) != ['a.bin', 'sub']:
        fails.append(f'targets_for(dir) wrong: {targets}')
    if cleaner.targets_for(os.path.join(cache, 'a.bin'), False) != [os.path.join(cache, 'a.bin')]:
        fails.append('targets_for(file) wrong')
    ok, aborted = cleaner.recycle(targets)
    if not ok or aborted or any(os.path.lexists(t) for t in targets):
        fails.append(f'recycle failed: ok={ok} aborted={aborted}')
    if not os.path.isdir(cache):
        fails.append('the folder itself must stay after its contents are recycled')
    if not rescan_path(sc, cache):
        fails.append('rescan_path could not find the folder')
    node = find_node(sc.root_node, cache)
    if (sc.root_node.size, sc.root_node.files, node.size, node.files) != (1500, 2, 0, 0):
        fails.append(f'after rescan expected root 1500/2 and cache 0/0, got {sc.root_node.size}/{sc.root_node.files}, {node.size}/{node.files}')
    if [os.path.basename(p) for _, p in sc.biggest] != ['c.bin', 'keep.bin']:
        fails.append(f'biggest files not updated: {sc.biggest}')
    if any(n.name == 'sub' for n in sc.nodes):
        fails.append('stale folder still in the node index')

# the credential guard: any folder holding saved logins / cookies / keys is refused, whatever its name says
with tempfile.TemporaryDirectory() as tmp:
    plain = os.path.join(tmp, 'Cache')
    webview = os.path.join(tmp, 'htmlcache', 'Default', 'Network')
    os.makedirs(plain)
    os.makedirs(webview)
    for p in (os.path.join(plain, 'data_0'), os.path.join(webview, 'Cookies')):
        with open(p, 'wb') as fh:
            fh.write(b'x')
    if cleaner.find_sensitive(plain) is not None:
        fails.append('guard flagged a plain cache folder')
    if cleaner.find_sensitive(os.path.join(tmp, 'htmlcache')) != os.path.join(webview, 'Cookies'):
        fails.append('guard missed Cookies nested inside a cache-like folder')
for name in ('Login Data', 'Login Data For Account', 'logins.json', 'key4.db', 'Cookies', 'cookies.sqlite', 'Bookmarks',
             'places.sqlite', 'id_rsa', 'passwords.kdbx'):
    if not cleaner.is_sensitive_name(name):
        fails.append(f'is_sensitive_name missed {name}')
with tempfile.TemporaryDirectory() as tmp:        # false-positive check: npm packages named after cookies/bookmarks
    os.makedirs(os.path.join(tmp, 'node_modules', 'cookies'))
    for p in (os.path.join(tmp, 'node_modules', 'cookies', 'index.js'), os.path.join(tmp, 'node_modules', 'cookies.js'),
              os.path.join(tmp, 'node_modules', 'bookmarks.html')):
        with open(p, 'wb') as fh:
            fh.write(b'x')
    if cleaner.find_sensitive(tmp) is not None:
        fails.append('guard wrongly flagged npm-style names (cookies folder, cookies.js, bookmarks.html)')
for name in ('data_0', 'index', 'f_000001', 'main.js', 'package.json', 'cookies.js', 'bookmarks.html', 'cookies.txt.bak'):
    if cleaner.is_sensitive_name(name):
        fails.append(f'is_sensitive_name wrongly flagged {name}')

# permanent delete: removes everything inside, but never follows a junction out of the folder
import stat
import subprocess
with tempfile.TemporaryDirectory() as tmp:
    victim = os.path.join(tmp, 'victim')                  # the folder whose *contents* get deleted
    outside = os.path.join(tmp, 'outside')                # must survive: a junction inside victim points here
    for rel in ('victim/a.bin', 'victim/sub/b.bin', 'victim/sub/deeper/c.bin', 'outside/precious.txt'):
        os.makedirs(os.path.dirname(os.path.join(tmp, rel)), exist_ok=True)
        with open(os.path.join(tmp, rel), 'wb') as fh:
            fh.write(b'x' * 100)
    readonly = os.path.join(victim, 'readonly.bin')
    with open(readonly, 'wb') as fh:
        fh.write(b'x')
    os.chmod(readonly, stat.S_IREAD)
    junction = os.path.join(victim, 'link_to_outside')
    made = subprocess.run(['cmd', '/c', 'mklink', '/J', junction, outside], capture_output=True).returncode == 0
    held = os.path.join(victim, 'in_use.bin')
    with open(held, 'wb') as fh:
        fh.write(b'x')
    keep_open = open(held, 'rb')                          # an open handle blocks deletion, like a running program would
    targets = cleaner.targets_for(victim, True)
    removed, failed = cleaner.delete_permanently(targets)
    keep_open.close()
    left = sorted(os.listdir(victim))
    if left != ['in_use.bin']:
        fails.append(f'delete_permanently left the wrong things behind: {left}')
    if [os.path.basename(p) for p, _ in failed] != ['in_use.bin']:
        fails.append(f'the in-use file should be reported as failed, got {[os.path.basename(p) for p, _ in failed]}')
    if not os.path.isfile(os.path.join(outside, 'precious.txt')):
        fails.append('DANGER: delete_permanently followed a junction and deleted files outside the folder')
    if not made:
        fails.append('could not create a test junction (mklink /J failed), junction safety was not tested')
    if removed < 7:
        fails.append(f'delete_permanently reported too few removed items: {removed}')
    removed2, failed2 = cleaner.delete_permanently(cleaner.targets_for(victim, True))      # handle closed now
    if failed2 or os.listdir(victim):
        fails.append(f'second pass should remove the last file: {failed2} {os.listdir(victim)}')
    gone, missing = cleaner.delete_permanently([os.path.join(tmp, 'does-not-exist')])
    if gone != 0 or len(missing) != 1:
        fails.append('a missing path should be reported, not crash')

if fmt_size(0) != '0 B' or fmt_size(1536) != '1.5 KB' or fmt_size(5 * 1024 ** 3) != '5.0 GB':
    fails.append('fmt_size wrong')

print('\n'.join(fails) if fails else f'OK - {len(DIRS)} folder rules, {len(FILES)} file rules, scanner and formatter pass')
raise SystemExit(1 if fails else 0)
