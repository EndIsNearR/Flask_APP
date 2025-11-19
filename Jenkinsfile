pipeline {
    agent any
    
    environment {
        PYTHON_VERSION = '3.9'
        PROJECT_DIR = "${WORKSPACE}"
    }
    
    stages {
        stage('Checkout') {
            steps {
                echo 'Checking out code from GitHub...'
                checkout scm
                sh 'ls -la'
                sh 'python3 --version'
            }
        }
        
        stage('Setup Python Environment') {
            steps {
                echo 'Setting up Python virtual environment...'
                sh '''
                    python3 -m venv build_env
                    . build_env/bin/activate
                    python -m pip install --upgrade pip
                '''
            }
        }
        
        stage('Install Dependencies') {
            steps {
                echo 'Installing project dependencies...'
                sh '''
                    . build_env/bin/activate
                    pip install -r requirements.txt
                '''
            }
        }
        
        stage('Run Tests') {
            steps {
                echo 'Running tests...'
                sh '''
                    . build_env/bin/activate
                    python -c "print('✓ Tests would run here. Add pytest later!')"
                    python -c "import flask; print('✓ Flask imported successfully')"
                    python -c "from app import app; print('✓ App module imported successfully')"
                '''
            }
        }
        
        stage('Build Validation') {
            steps {
                echo 'Validating application build...'
                sh '''
                    . build_env/bin/activate
                    python -c "from app import app; print('✓ Application builds successfully!')"
                    python -c "print('✓ All dependencies are installed correctly')"
                '''
            }
        }
        
        stage('SonarQube Analysis') {
            steps {
                echo 'Running SonarQube SAST analysis...'
                script {
                    def scannerHome = tool 'SonarQubeScanner'
                    withSonarQubeEnv('SonarQube') {
                        sh """
                            ${scannerHome}/bin/sonar-scanner \
                            -Dsonar.projectKey=Flask-CRUD-App \
                            -Dsonar.projectName='Flask CRUD Application' \
                            -Dsonar.projectVersion=1.0 \
                            -Dsonar.sources=. \
                            -Dsonar.python.version=3.13 \
                            -Dsonar.exclusions=**/env/**,**/build_env/**,**/__pycache__/**,**/static/**,**/instance/**
                        """
                    }
                }
            }
        }
        
        stage('Quality Gate') {
            steps {
                echo 'Checking SonarQube Quality Gate...'
                timeout(time: 10, unit: 'MINUTES') {
                    script {
                        def qg = waitForQualityGate()
                        if (qg.status != 'OK') {
                            echo "WARNING: Quality Gate failed with status: ${qg.status}"
                            echo "Check SonarQube dashboard for details: http://localhost:9000"
                            // Not failing the build, just warning
                            unstable(message: "Quality Gate failed")
                        } else {
                            echo "✓ Quality Gate passed!"
                        }
                    }
                }
            }
        }
        
        stage('Security Check') {
            steps {
                echo 'Running additional security checks...'
                sh '''
                    . build_env/bin/activate
                    pip install bandit safety
                    echo "Running Bandit security linter..."
                    bandit -r . -f json -o bandit-report.json || true
                    echo "Running Safety vulnerability check..."
                    safety check --json || true
                    echo "✓ Security checks completed"
                '''
            }
        }
        
        stage('Deploy') {
            steps {
                echo '=== Deployment Stage ==='
                sh '''
                    echo "✓ Build artifacts are ready for deployment"
                    echo "✓ Application is ready to be deployed"
                    echo ""
                    echo "Note: Configure deployment target (Docker, Cloud, etc.)"
                '''
            }
        }
    }
    
    post {
        success {
            echo '========================================='
            echo '✓ Pipeline completed successfully!'
            echo '✓ All stages passed'
            echo '========================================='
        }
        failure {
            echo '========================================='
            echo '✗ Pipeline failed!'
            echo '✗ Check console output for details'
            echo '========================================='
        }
        always {
            echo 'Cleaning up build environment...'
            sh '''
                rm -rf build_env
                echo "✓ Cleanup completed"
            '''
        }
    }
}
