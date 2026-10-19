#!/usr/bin/env bash
set -euo pipefail
test "$(id -u)" = 0
source_dir=${1:?staged configuration directory}
nginx=/opt/nginx-proxy/data/conf.d/nahan-control.conf
apache=/etc/apache2/conf.d/nahan-control.conf
backup=$(mktemp -d /root/nahan-core-control-backup.XXXXXXXX)
cp -p "$nginx" "$backup/nginx.conf"
cp -p "$apache" "$backup/apache.conf"
reloaded=false
rollback() {
  result=$?
  trap - EXIT
  if test "$result" != 0; then
    cp -p "$backup/nginx.conf" "$nginx"
    cp -p "$backup/apache.conf" "$apache"
    if $reloaded; then
      docker exec nginx-proxy nginx -t && docker exec nginx-proxy nginx -s reload
      httpd -t && systemctl reload lsws
    fi
    echo "Private-control configuration restored: $backup" >&2
  fi
  exit "$result"
}
trap rollback EXIT
install -m 644 "$source_dir/nginx.conf" "$nginx"
install -m 644 "$source_dir/apache.conf" "$apache"
docker exec nginx-proxy nginx -t
httpd -t
reloaded=true
docker exec nginx-proxy nginx -s reload
systemctl reload lsws
echo "Private-control API allowlist reloaded; rollback files: $backup"
