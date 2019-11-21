pipeline {
    agent any

    stages {
        stage('Build') {
            steps {
                sh './distcheck'
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

