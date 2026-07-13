#!/bin/bash


TARGET_URL="${1:-http://erp-app.staging.svc:80}"
REPORT_DIR="${2:-reports}"

echo " Starting OWASP ZAP DAST scan against: ${TARGET_URL}"

mkdir -p ${REPORT_DIR}

docker run --rm \
    --network host \
    -v $(pwd)/${REPORT_DIR}:/zap/wrk:rw \
    -v $(pwd)/zap-rules.conf:/zap/wrk/zap-rules.conf:ro \
    ghcr.io/zaproxy/zaproxy:stable zap-full-scan.py \
    -t ${TARGET_URL} \
    -r zap-report.html \
    -J zap-report.json \
    -c zap-rules.conf \
    -I  # Ne pas retourner d'erreur (on évalue avec la Security Gate)

ZAP_EXIT=$?

echo " ZAP scan complete. Exit code: ${ZAP_EXIT}"
echo " Reports saved to ${REPORT_DIR}/zap-report.html and zap-report.json"

exit ${ZAP_EXIT}