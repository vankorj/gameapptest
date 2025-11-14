pipeline {
    agent any

    environment {
        // Credentials and image info
        DOCKERHUB_CREDENTIALS = 'docker-id'
        IMAGE_NAME = 'vankorj/gameappnewimage'
        TRIVY_SEVERITY = 'HIGH,CRITICAL'
        ZAP_TARGET_URL = 'http://45.79.140.194'
    }

    stages {
        stage('Checkout') {
            steps {
                checkout scm
            }
        }

        stage('SAST Test - Snyk') {
            steps {
                script {
                    snykSecurity(
                        snykInstallation: 'Snyk-installation',
                        snykTokenId: 'synk_id',
                        severity: 'critical',
                    )
                }
            }
        }

        stage('SonarQube Analysis') {
            agent { label 'CWEB-2140-60-Appserver-Korbin' }
            steps {
                script {
                    def scannerHome = tool 'SonarQube-Scanner'
                    withSonarQubeEnv('SonarQube-installations') {
                        sh "${scannerHome}/bin/sonar-scanner -Dsonar.projectKey=gameapp -Dsonar.sources=."
                    }
                }
            }
        }

        stage('Build and Tag Docker Image') {
            agent { label 'CWEB-2140-60-Appserver-Korbin' }
            steps {
                script {
                    echo "Building Docker image ${IMAGE_NAME}..."
                    app = docker.build("${IMAGE_NAME}")
                    app.tag('latest')
                }
            }
        }

        stage('Push to Docker Hub') {
            agent { label 'CWEB-2140-60-Appserver-Korbin' }
            steps {
                script {
                    echo "Pushing ${IMAGE_NAME}:latest to Docker Hub..."
                    docker.withRegistry('https://registry.hub.docker.com', DOCKERHUB_CREDENTIALS) {
                        app.push('latest')
                    }
                }
            }
        }

        stage('Deploy with Docker Compose') {
            agent { label 'CWEB-2140-60-Appserver-Korbin' }
            steps {
                echo 'Starting deployment...'
                sh '''
                    docker-compose down
                    docker-compose up -d
                    docker ps
                '''
                echo 'Deployment completed!'
            }
        }

        stage('Trivy Scan') {
            steps {
                script {
                    echo "Scanning ${IMAGE_NAME} for vulnerabilities..."
                    sh '''
                        docker run --rm aquasec/trivy:latest image \
                        --exit-code 0 \
                        --format json \
                        --severity ${TRIVY_SEVERITY} \
                        ${IMAGE_NAME} > trivy-report.json

                        docker run --rm aquasec/trivy:latest image \
                        --exit-code 0 \
                        --format template \
                        --template "@/contrib/html.tpl" \
                        --severity ${TRIVY_SEVERITY} \
                        ${IMAGE_NAME} > trivy-report.html
                    '''
                }
            }
            post {
                always {
                    archiveArtifacts artifacts: 'trivy-report.json,trivy-report.html', allowEmptyArchive: true
                }
            }
        }

        stage('Summarize Trivy Vulnerabilities') {
            steps {
                script {
                    if (fileExists('trivy-report.json')) {
                        def reportJson = new groovy.json.JsonSlurper().parseText(readFile('trivy-report.json'))
                        def highCount = 0, criticalCount = 0
                        reportJson.Results.each { result ->
                            result.Vulnerabilities?.each { vuln ->
                                if (vuln.Severity == 'HIGH') highCount++
                                if (vuln.Severity == 'CRITICAL') criticalCount++
                            }
                        }
                        echo "Trivy HIGH: ${highCount}, CRITICAL: ${criticalCount}"
                        if (criticalCount > 0) echo "⚠️ Critical vulnerabilities detected!"
                    } else {
                        echo "No Trivy JSON report found."
                    }
                }
            }
        }

        stage('DAST Scan - OWASP ZAP') {
            steps {
                script {
                    echo 'Running ZAP baseline scan...'
                    def volumeName = "zap-reports-${BUILD_NUMBER}"
                    sh "docker volume create ${volumeName}"

                    def zapExitCode = sh(script: """
                        docker run --rm --user root --network host \
                        -v ${volumeName}:/zap/wrk:rw \
                        ghcr.io/zaproxy/zaproxy:stable \
                        zap-baseline.py -t ${ZAP_TARGET_URL} -r zap_report.html -J zap_report.json
                    """, returnStatus: true)
                    echo "ZAP exit code: ${zapExitCode}"

                    def helperContainerId = sh(script: "docker run -d -v ${volumeName}:/data alpine sleep 300", returnStdout: true).trim()
                    sh """
                        docker cp ${helperContainerId}:/data/zap_report.html ./zap_report.html || true
                        docker cp ${helperContainerId}:/data/zap_report.json ./zap_report.json || true
                        docker rm -f ${helperContainerId}
                        docker volume rm ${volumeName}
                    """

                    if (fileExists('zap_report.json')) {
                        def zapJson = new groovy.json.JsonSlurper().parseText(readFile('zap_report.json'))
                        def high = 0, medium = 0, low = 0
                        zapJson.site.each { site ->
                            site.alerts.each { alert ->
                                switch (alert.risk) {
                                    case 'High': high++; break
                                    case 'Medium': medium++; break
                                    case 'Low': low++; break
                                }
                            }
                        }
                        echo "ZAP High: ${high}, Medium: ${medium}, Low: ${low}"
                    } else {
                        echo "No ZAP JSON report found."
                    }
                }
            }
            post {
                always {
                    archiveArtifacts artifacts: 'zap_report.html,zap_report.json', allowEmptyArchive: true
                }
            }
        }
    }

    post {
        always {
            echo 'Pipeline completed.'

            publishHTML([
                reportDir: '.',
                reportFiles: 'trivy-report.html',
                reportName: 'Trivy Vulnerability Report',
                keepAll: true,
                allowMissing: true
            ])
            publishHTML([
                reportDir: '.',
                reportFiles: 'zap_report.html',
                reportName: 'OWASP ZAP DAST Report',
                keepAll: true,
                allowMissing: true
            ])
        }
        failure {
            echo 'Pipeline failed!'
        }
    }
}
