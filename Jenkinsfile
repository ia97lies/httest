pipeline {
    agent any

    stages {
        stage('Build') {
            steps {
                sh "${env.WORKSPACE}/buildconf.sh"
                sh "${env.WORKSPACE}/configure"
                sh "make"
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

