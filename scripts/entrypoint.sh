#!/bin/sh
# fastclaw entrypoint: install bundled plugins into FASTCLAW_HOME/plugins on
# first boot, then exec fastclaw. The bundled location (/opt/fastclaw/...) is
# baked into the image; the install target lives under FASTCLAW_HOME, which
# is typically a volume mount on production hosts — so we copy on each boot
# unless the plugin is already present.
set -e

PLUGINS_SRC=/opt/fastclaw/bundled-plugins
PLUGINS_DST="${FASTCLAW_HOME:-/data/.fastclaw}/plugins"

if [ -d "$PLUGINS_SRC" ]; then
    mkdir -p "$PLUGINS_DST"
    for plugin_src in "$PLUGINS_SRC"/*/; do
        [ -d "$plugin_src" ] || continue
        name=$(basename "$plugin_src")
        dst="$PLUGINS_DST/$name"
        if [ ! -d "$dst" ]; then
            echo "[entrypoint] Installing bundled plugin: $name"
            cp -r "$plugin_src" "$dst"
        fi
    done
fi

exec fastclaw "$@"
