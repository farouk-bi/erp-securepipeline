pipeline {
    agent {
        kubernetes {
            yaml '''
                apiVersion: v1
                kind: Pod
                spec:
                  containers:
                  - name: node
                    image: node:20-alpine
                    command: ['sleep', '3600']
                    resources:
                      requests:
                        memory: "512Mi"
                        cpu: "250m"
                  - name: docker
                    image: docker:24-dind
                    securityContext:
                      privileged: true
                    resources:
                      requests:
                        memory: "512Mi"
                        cpu: "250m"
                  - name: trivy
                    image: aquasec/trivy:latest
                    command: ['sleep', '3600']
                  - name: gitleaks
                    image: ghcr.io/gitleaks/gitleaks:latest
                    command: ['sleep', '3600']
                  - name: python
                    image: python:3.11-slim
                    command: ['sleep', '3600']
            '''
        }
    }

    environment {
        GHCR_REGISTRY    = "ghcr.io/farouk-bi"
        IMAGE_NAME       = "erp-app"
        SONARQUBE_URL    = "http://sonarqube-sonarqube.security-tools.svc:9000"
        REPORTS_DIR      = "reports"
    }

    stages {

        // ════════════════════════════════════════════
        // STAGE 1 : CHECKOUT & BUILD
        // ════════════════════════════════════════════
        stage('Checkout') {
            steps {
                checkout scm
                sh "mkdir -p ${REPORTS_DIR}"
            }
        }

        stage('Install & Build') {
            steps {
                container('node') {
                    sh 'npm ci'
                    sh 'npm run build --if-present'
                }
            }
        }

        stage('Unit Tests') {
            steps {
                container('node') {
                    sh 'npm test -- --coverage'
                }
            }
            post {
                always {
                    publishHTML(target: [
                        reportName: 'Coverage Report',
                        reportDir: 'coverage/lcov-report',
                        reportFiles: 'index.html'
                    ])
                }
            }
        }

        stage('Docker Build') {
            steps {
                container('docker') {
                    sh "docker build -t ${GHCR_REGISTRY}/${IMAGE_NAME}:${BUILD_NUMBER} ."
                    sh "docker tag ${GHCR_REGISTRY}/${IMAGE_NAME}:${BUILD_NUMBER} ${GHCR_REGISTRY}/${IMAGE_NAME}:latest"
                }
            }
        }

        // ════════════════════════════════════════════
        // STAGE 2 : SECURITY SCANNING (parallélisé)
        // ════════════════════════════════════════════
        stage('Security Scanning') {
            parallel {
                stage('SAST — SonarQube') {
                    steps {
                        container('node') {
                            withSonarQubeEnv('SonarQube') {
                                sh '''
                                    npx sonarqube-scanner \
                                        -Dsonar.projectKey=erp-securepipeline \
                                        -Dsonar.sources=src \
                                        -Dsonar.tests=tests \
                                        -Dsonar.javascript.lcov.reportPaths=coverage/lcov.info
                                '''
                            }
                        }
                    }
                }

                stage('SCA — Trivy FS') {
                    steps {
                        container('trivy') {
                            sh "trivy fs --format json --output ${REPORTS_DIR}/trivy-sca.json --severity CRITICAL,HIGH ."
                            sh "trivy fs --format cyclonedx --output ${REPORTS_DIR}/sbom.json ."
                        }
                    }
                }

                stage('Secrets — GitLeaks') {
                    steps {
                        container('gitleaks') {
                            sh "gitleaks detect --source . --report-format json --report-path ${REPORTS_DIR}/gitleaks.json --no-git || true"
                        }
                    }
                }

                stage('Container Scan — Trivy Image') {
                    steps {
                        container('trivy') {
                            sh "trivy image --format json --output ${REPORTS_DIR}/trivy-image.json --severity CRITICAL,HIGH ${GHCR_REGISTRY}/${IMAGE_NAME}:${BUILD_NUMBER}"
                        }
                    }
                }
            }
        }

        // ════════════════════════════════════════════
        // STAGE 3 : SECURITY GATE #1
        // ════════════════════════════════════════════
        stage('Security Gate #1') {
            steps {
                container('python') {
                    sh "python3 scripts/security-gate/evaluate.py ${REPORTS_DIR} 1"
                }
            }
        }

        // ════════════════════════════════════════════
        // STAGE 4 : PUSH & DEPLOY STAGING
        // ════════════════════════════════════════════
        stage('Push to GHCR') {
            steps {
                container('docker') {
                    withCredentials([usernamePassword(credentialsId: 'ghcr-token', usernameVariable: 'GHCR_USER', passwordVariable: 'GHCR_PASS')]) {
                        sh "echo ${GHCR_PASS} | docker login ghcr.io -u ${GHCR_USER} --password-stdin"
                        sh "docker push ${GHCR_REGISTRY}/${IMAGE_NAME}:${BUILD_NUMBER}"
                        sh "docker push ${GHCR_REGISTRY}/${IMAGE_NAME}:latest"
                    }
                }
            }
        }

        stage('Deploy Staging') {
            steps {
                sh """
                    kubectl set image deployment/erp-app \
                        erp-app=${GHCR_REGISTRY}/${IMAGE_NAME}:${BUILD_NUMBER} \
                        -n staging
                    kubectl rollout status deployment/erp-app -n staging --timeout=120s
                """
                // Smoke test
                sh '''
                    sleep 10
                    kubectl exec -n staging deploy/erp-app -- \
                        wget -qO- http://localhost:3000/health
                '''
            }
        }

        // ════════════════════════════════════════════
        // STAGE 5 : DAST (sur staging)
        // ════════════════════════════════════════════
        stage('DAST — OWASP ZAP') {
            steps {
                container('docker') {
                    sh """
                        docker run --rm --network host \
                            -v \$(pwd)/${REPORTS_DIR}:/zap/wrk:rw \
                            ghcr.io/zaproxy/zaproxy:stable zap-full-scan.py \
                            -t http://erp-app.staging.svc:80 \
                            -r zap-report.html \
                            -J zap-report.json \
                            -I
                    """
                }
            }
            post {
                always {
                    publishHTML(target: [
                        reportName: 'ZAP Report',
                        reportDir: "${REPORTS_DIR}",
                        reportFiles: 'zap-report.html'
                    ])
                }
            }
        }

        // ════════════════════════════════════════════
        // STAGE 6 : SECURITY GATE #2
        // ════════════════════════════════════════════
        stage('Security Gate #2') {
            steps {
                container('python') {
                    sh "python3 scripts/security-gate/evaluate.py ${REPORTS_DIR} 2"
                }
            }
        }

        // ════════════════════════════════════════════
        // STAGE 7 : DEPLOY PRODUCTION (main branch only)
        // ════════════════════════════════════════════
        stage('Deploy Production') {
            when { branch 'main' }
            steps {
                sh """
                    bash scripts/blue-green-switch.sh green ${BUILD_NUMBER}
                """
            }
        }

        // ════════════════════════════════════════════
        // STAGE 8 : POST-DEPLOY
        // ════════════════════════════════════════════
        stage('Post-Deploy') {
            steps {
                container('python') {
                    sh "python3 scripts/etl/export_to_dw.py ${REPORTS_DIR} || true"
                }
                archiveArtifacts artifacts: "${REPORTS_DIR}/**", allowEmptyArchive: true
            }
        }
    }

    // ════════════════════════════════════════════
    // POST-ACTIONS
    // ════════════════════════════════════════════
   // post {
        //success {
            //slackSend(
              //  channel: '#devsecops-alerts',
                //color: '#36a64f',
                //message: "✅ *ERP SecurePipeline* — Build #${BUILD_NUMBER} SUCCESS\n<${BUILD_URL}|Voir le build>"
            //)
     //   }
       // failure {
         //   slackSend(
           //     channel: '#devsecops-alerts',
             //   color: '#ff0000',
              //  message: "❌ *ERP SecurePipeline* — Build #${BUILD_NUMBER} FAILED\n<${BUILD_URL}|Voir le build>"
            //)
        //}
        //always {
          //  cleanWs()
        //}
   // }
//}
// 
// 
// 
// // ════════════════════════════════════════════
    // POST-ACTIONS
    // ════════════════════════════════════════════
    post {
        success {
            echo "✅ ERP SecurePipeline — Build #${BUILD_NUMBER} SUCCESS"
        }
        failure {
            echo "❌ ERP SecurePipeline — Build #${BUILD_NUMBER} FAILED"
        }
        always {
            cleanWs()
        }
    }
}