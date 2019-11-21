pipeline {
    agent any

    stages {
        stage('Build') {
            steps {
                sh "${env.WORKSPACE}/distcheck"
            }
        }
        stage('Test') {
            steps {
                echo 'Testing..'
            }
        }
        stage('Deploy') {
            steps {
                echo 'Deploying....'
            }
        }
    }
}

