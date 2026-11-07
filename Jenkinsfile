pipeline {
  agent any
  options { timestamps() }
  environment { IMAGE = "vuln-app:${BUILD_NUMBER}" }

  stages {
    stage('Security') {
      parallel {
        stage('Gitleaks') {
          steps {
            sh '''
              mkdir -p reports
              docker run --rm -v "$PWD:/repo" ghcr.io/gitleaks/gitleaks:latest git /repo --verbose > reports/gitleaks.txt 2>&1 || { cat reports/gitleaks.txt; exit 1; }
              cat reports/gitleaks.txt
            '''
          }
        }
        stage('Semgrep') {
          steps {
            sh '''
              mkdir -p reports
              docker run --rm -v "$PWD:/src" semgrep/semgrep semgrep scan --config p/javascript --config p/owasp-top-ten --error /src > reports/semgrep.txt 2>&1 || { cat reports/semgrep.txt; exit 1; }
              cat reports/semgrep.txt
            '''
          }
        }
        stage('npm audit') {
          steps {
            sh '''
              mkdir -p reports
              docker run --rm --user "$(id -u):$(id -g)" -e NPM_CONFIG_CACHE=/tmp/.npm -v "$PWD:/app" -w /app node:24-alpine npm audit --package-lock-only --audit-level=high > reports/npm-audit.txt 2>&1 || { cat reports/npm-audit.txt; exit 1; }
              cat reports/npm-audit.txt
            '''
          }
        }
      }
    }

    stage('Build') {
      steps {
        sh 'docker build -t $IMAGE .'
      }
    }

    stage('Image scan') {
      steps {
        sh '''
          mkdir -p reports
          docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v trivy-cache:/root/.cache/trivy aquasec/trivy:latest image --skip-version-check --severity CRITICAL --exit-code 1 --ignore-unfixed $IMAGE > reports/trivy.txt 2>&1 || { cat reports/trivy.txt; exit 1; }
          cat reports/trivy.txt
        '''
      }
    }
  }

  post {
    always {
      archiveArtifacts artifacts: 'reports/**', allowEmptyArchive: true
      sh 'docker rmi $IMAGE || true'
    }
  }
}
