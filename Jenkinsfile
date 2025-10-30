pipeline {
    agent any

    environment {
        // Docker Hub credentials ID stored in Jenkins
        DOCKERHUB_CREDENTIALS = 'docker-id'
        IMAGE_NAME = 'vankorj/gameappnewimage'
    }

    stages {
        stage('Cloning Git') {
            steps {
                checkout scm
            }
        }

        stage('SAST-TEST') {
            agent any
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
            agent {
                label 'CWEB-2140-60-Appserver-Korbin'
            }
            steps {
                script {
                    def scannerHome = tool 'SonarQube-Scanner'
                    withSonarQubeEnv('sonarqube') {
                        sh "${scannerHome}/bin/sonar-scanner \
                            -Dsonar.projectKey=gameapp \
                            -Dsonar.sources=."
                    }
                }
            }
        }

        stage('BUILD-AND-TAG') {
            agent { label 'CWEB-2140-60-Appserver-Korbin' }
            steps {
                script {
                    echo "Building Docker image ${IMAGE_NAME}..."
                    app = docker.build("${IMAGE_NAME}")
                    app.tag("latest")
                }
            }
        }

        stage('POST-TO-DOCKERHUB') {
            agent { label 'CWEB-2140-60-Appserver-Korbin' }
            steps {
                script {
                    echo "Pushing image ${IMAGE_NAME}:latest to Docker Hub..."
                    docker.withRegistry('https://registry.hub.docker.com', DOCKERHUB_CREDENTIALS) {
                        app.push('latest')
                    }
                }
            }
        }

        stage('DEPLOYMENT') {
            agent { label 'CWEB-2140-60-Appserver-Korbin' }
            steps {
                echo 'Starting deployment using docker-compose...'
                script {
                    sh '''
                        docker-compose down
                        docker-compose up -d
                        docker ps
                    '''
                }
                echo 'Deployment completed successfully!'
            }
        }
    }

    post {
        always {
            echo 'Pipeline completed (success or fail).'
        }
        failure {
            echo 'Pipeline failed!'
        }
    }
}



