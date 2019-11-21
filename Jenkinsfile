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
  post {
    failure {
      mail to: 'liesch@gmx.ch',
           subject: "Failed Pipeline: ${currentBuild.fullDisplayName}",
           body: "Something is wrong with ${env.BUILD_URL}"
    }
  }
}

