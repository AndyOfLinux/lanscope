#!/bin/bash
# install-lanscope.sh — system-wide install of LanScope, with migration from
# the earlier "netscan" install if present. Run with sudo from inside the
# unzipped lanscope/ directory:
#
#     cd ~/lanscope && sudo ./install-lanscope.sh
#
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "Please run with sudo: sudo ./install-lanscope.sh" >&2
    exit 1
fi

cd "$(dirname "$0")"
for f in lanscope.py engine.py lanscope-helper io.github.lanscope.policy lanscope.desktop; do
    [[ -f $f ]] || { echo "Missing $f — run from the unzipped lanscope directory." >&2; exit 1; }
done

# ---- remove previous 'netscan' install, if any -------------------------
echo "==> Removing old netscan install (if present)"
removed=0
for path in \
    /opt/netscan \
    /usr/local/libexec/netscan-helper \
    /usr/share/polkit-1/actions/legacy-netscan-install.policy \
    /usr/local/bin/netscan \
    /usr/share/applications/netscan.desktop
do
    if [[ -e $path ]]; then
        rm -rf "$path"
        echo "    removed $path"
        removed=1
    fi
done
[[ $removed -eq 0 ]] && echo "    none found"

# ---- install LanScope ---------------------------------------------------
echo "==> Installing LanScope"
install -d /opt/lanscope
install -m 644 engine.py /opt/lanscope/
install -m 755 lanscope.py /opt/lanscope/
install -D -m 755 lanscope-helper /usr/local/libexec/lanscope-helper
install -m 644 io.github.lanscope.policy /usr/share/polkit-1/actions/
install -m 644 lanscope.desktop /usr/share/applications/

printf '#!/bin/sh\nexec python3 /opt/lanscope/lanscope.py "$@"\n' > /usr/local/bin/lanscope
chmod 755 /usr/local/bin/lanscope

command -v update-desktop-database >/dev/null && update-desktop-database -q /usr/share/applications || true

echo "==> Done. Run 'lanscope' or find LanScope in the applications menu (Network)."
