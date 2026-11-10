#!/usr/bin/env bash
# Usage : ./verify-before-run.sh <image:tag> [arguments pour docker run...]
# Refuse de lancer l'image si sa signature Cosign n'est pas valide.
set -euo pipefail

IMAGE="${1:?usage: $0 <image:tag> [args...]}"
shift
KEY="${COSIGN_PUB:-cosign.pub}"
REPO="${IMAGE%:*}"

# 1. Récupérer l'image et résoudre son digest (un tag peut être déplacé, un digest non)
docker pull -q "$IMAGE" > /dev/null
REF=$(docker image inspect --format '{{range .RepoDigests}}{{println .}}{{end}}' "$IMAGE" | grep "^${REPO}@" | head -n1)
[ -n "$REF" ] || { echo "REFUSÉ : digest introuvable pour $IMAGE" >&2; exit 1; }

# 2. Vérifier la signature de CE digest
if cosign verify --key "$KEY" --allow-http-registry --allow-insecure-registry "$REF" > /dev/null 2>&1; then
  echo "OK : signature valide pour $REF"
  # 3. Lancer exactement le digest vérifié, pas le tag
  exec docker run --rm "$REF" "$@"
else
  echo "REFUSÉ : signature invalide ou absente pour $REF" >&2
  exit 1
fi
