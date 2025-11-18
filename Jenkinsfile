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
                bat 'dir'
            }
        }
        
        stage('Setup Python Environment') {
            steps {
                echo 'Setting up Python virtual environment...'
                bat '''
                    if exist build_env rmdir /s /q build_env
                    python -m venv build_env
                    call build_env\\Scripts\\activate.bat
                    python -m pip install --upgrade pip
                '''
            }
        }
        
        stage('Install Dependencies') {
            steps {
                echo 'Installing project dependencies...'
                bat '''
                    call build_env\\Scripts\\activate.bat
                    pip install -r requirements.txt
                '''
            }
        }
        
        stage('Run Tests') {
            steps {
                echo 'Running tests...'
                bat '''
                    call build_env\\Scripts\\activate.bat
                    python -c "print('✓ Tests would run here. Add pytest later!')"
                    python -c "import flask; print('✓ Flask imported successfully')"
                    python -c "from app import app; print('✓ App module imported successfully')"
                '''
            }
        }
        
        stage('Build Validation') {
            steps {
                echo 'Validating application build...'
                bat '''
                    call build_env\\Scripts\\activate.bat
                    python -c "from app import app; print('✓ Application builds successfully!')"
                    python -c "print('✓ All dependencies are installed correctly')"
                '''
            }
        }
        
        stage('Security Check') {
            steps {
                echo 'Checking for security vulnerabilities...'
                bat '''
                    call build_env\\Scripts\\activate.bat
                    python -c "print('✓ Security checks would run here')"
                '''
            }
        }
        
        stage('Deploy') {
            steps {
                echo '=== Deployment Stage ==='
                bat '''
                    echo ✓ Build artifacts are ready for deployment
                    echo ✓ Application is ready to be deployed
                    echo.
                    echo Note: Configure deployment target (Docker, Cloud, etc.)
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
            bat '''
                if exist build_env rmdir /s /q build_env
                echo ✓ Cleanup completed
            '''
        }
    }
}
