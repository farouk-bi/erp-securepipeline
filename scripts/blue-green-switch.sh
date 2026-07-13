#!/bin/bash


NEW_SLOT="${1:-green}"
IMAGE_TAG="${2:-latest}"
NAMESPACE="production"
REGISTRY="ghcr.io/VOTRE_USERNAME/erp-app"

# Déterminer le slot actuel
CURRENT_SLOT=$(kubectl get svc erp-app -n ${NAMESPACE} -o jsonpath='{.spec.selector.slot}' 2>/dev/null || echo "blue")

echo " Current slot: ${CURRENT_SLOT}"
echo " Deploying to: ${NEW_SLOT} with image tag: ${IMAGE_TAG}"

# 1. Déployer la nouvelle version sur le nouveau slot
kubectl set image deployment/erp-app-${NEW_SLOT} \
    erp-app=${REGISTRY}:${IMAGE_TAG} \
    -n ${NAMESPACE} 2>/dev/null

if [ $? -ne 0 ]; then
    echo " Creating new deployment for slot ${NEW_SLOT}..."
    sed "s/BUILD_NUMBER/${IMAGE_TAG}/g; s/blue/${NEW_SLOT}/g" \
        k8s/production/deployment-blue.yaml | kubectl apply -f - -n ${NAMESPACE}
fi

# 2. Attendre que le nouveau déploiement soit prêt
echo " Waiting for ${NEW_SLOT} deployment to be ready..."
kubectl rollout status deployment/erp-app-${NEW_SLOT} -n ${NAMESPACE} --timeout=120s

if [ $? -ne 0 ]; then
    echo " Deployment failed! Rolling back..."
    kubectl rollout undo deployment/erp-app-${NEW_SLOT} -n ${NAMESPACE}
    exit 1
fi

# 3. Health check
echo " Running health check..."
POD=$(kubectl get pod -l app=erp-app,slot=${NEW_SLOT} -n ${NAMESPACE} -o jsonpath='{.items[0].metadata.name}')
kubectl exec ${POD} -n ${NAMESPACE} -- wget -qO- http://localhost:3000/health

if [ $? -ne 0 ]; then
    echo " Health check failed! NOT switching traffic."
    exit 1
fi

# 4. Basculer le traffic
echo " Switching traffic to ${NEW_SLOT}..."
kubectl patch svc erp-app -n ${NAMESPACE} \
    -p "{\"spec\":{\"selector\":{\"slot\":\"${NEW_SLOT}\"}}}"

echo " Traffic now pointing to: ${NEW_SLOT}"

# 5. Optionnel : supprimer l'ancien slot après 5 min
echo " Old slot (${CURRENT_SLOT}) will be kept for rollback"
echo "   To clean up: kubectl delete deployment erp-app-${CURRENT_SLOT} -n ${NAMESPACE}"