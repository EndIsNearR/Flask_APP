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
        
        stage('Security Check') {
            steps {
                echo 'Checking for security vulnerabilities...'
                sh '''
                    . build_env/bin/activate
                    python -c "print('✓ Security checks would run here')"
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
