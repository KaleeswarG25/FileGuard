pipeline {
  agent any
  options { timestamps(); disableConcurrentBuilds() }
  stages {
    stage('Checkout') { steps { checkout scm } }
    stage('Python syntax') { steps { sh 'python3 -m compileall -q app.py analyzer.py virustotal.py report.py' } }
    stage('Install dependencies') { steps { sh 'python3 -m pip install --user -r requirements.txt' } }
    stage('Build image') { steps { sh 'docker build -t fileguard:${BUILD_NUMBER} -t fileguard:latest .' } }
    stage('Container smoke test') {
      steps {
        sh '''
          set -eu
          docker rm -f fileguard-smoke >/dev/null 2>&1 || true
          docker run -d --name fileguard-smoke -p 15000:5000 fileguard:${BUILD_NUMBER}
          trap 'docker rm -f fileguard-smoke >/dev/null 2>&1 || true' EXIT
          for i in $(seq 1 20); do
            if curl -fsS http://127.0.0.1:15000/health; then exit 0; fi
            sleep 2
          done
          docker logs fileguard-smoke
          exit 1
        '''
      }
    }
  }
  post { always { sh 'docker rm -f fileguard-smoke >/dev/null 2>&1 || true' } }
}
