"""Text-mode report (no GUI):  python cli.py C:\\ [--depth 2] [--top 10]"""
import argparse
import sys
import time

import knowledge as K
from scanner import Scanner, fmt_size, find_cleanup_candidates

MARK = {K.SAFE: '[SAFE]   ', K.CAUTION: '[CAREFUL]', K.DANGER: '[DON\'T]  ', K.PERSONAL: '[YOURS]  ', K.UNKNOWN: '[?]       '}


def show(node, depth, max_depth, top, indent=''):
    for child in sorted(node.children or (), key=lambda c: c.size, reverse=True)[:top]:
        info = K.classify_dir(child.path())
        print(f'{indent}{fmt_size(child.size):>9}  {MARK[info.level]} {child.name}  - {info.title}')
        if depth < max_depth:
            show(child, depth + 1, max_depth, top, indent + '    ')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('path')
    ap.add_argument('--depth', type=int, default=2)
    ap.add_argument('--top', type=int, default=10)
    ap.add_argument('--list', type=int, default=20, help='rows in the safe / unknown lists')
    ap.add_argument('--unknown-mb', type=int, default=200)
    args = ap.parse_args()
    if hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')

    sc = Scanner(args.path)
    sc.start()
    while not sc.finished:
        time.sleep(1)
        s = sc.snapshot()
        print(f'\r  scanning... {s["files"]:,} files, {fmt_size(s["bytes"])}', end='', file=sys.stderr)
    s = sc.snapshot()
    print(file=sys.stderr)
    root = sc.root_node
    print(f'{root.name}: {fmt_size(root.size)} in {root.files:,} files / {root.dirs:,} folders '
          f'({s["errors"]} unreadable, {s["links"]} links skipped, {fmt_size(s["cloud_bytes"])} online-only) '
          f'in {sc.ended - sc.started:.1f}s\n')
    show(root, 1, args.depth, args.top)

    print('\nBiggest files')
    for size, path in sc.biggest[:args.top]:
        info = K.classify_file(path)
        print(f'{fmt_size(size):>9}  {MARK[info.level]} {path}  - {info.title}')

    print('\nSafe to clean (top-most folders)')
    cands = find_cleanup_candidates(sc, K.classify_dir, K.SAFE)
    print(f'  total: {fmt_size(sum(n.size for n in cands))} in {len(cands)} folders')
    for n in cands[:args.list]:
        print(f'{fmt_size(n.size):>9}  {n.path()}  - {K.classify_dir(n.path()).title}')

    unknown = [n for n in sc.nodes if n.size >= args.unknown_mb << 20 and K.classify_dir(n.path()).level == K.UNKNOWN]
    unknown = [n for n in unknown if n.parent is None or K.classify_dir(n.parent.path()).level != K.UNKNOWN or n.parent is sc.root_node]
    print('\nLarge folders the knowledge base does not recognise (top-most)')
    for n in sorted(unknown, key=lambda n: n.size, reverse=True)[:args.list]:
        print(f'{fmt_size(n.size):>9}  {n.path()}')


if __name__ == '__main__':
    main()
