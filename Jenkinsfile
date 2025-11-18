pipeline {
    agent any
    
    environment {
        PYTHON_VERSION = '3.9'
    }
    
    stages {
        stage('Checkout') {
            steps {
                echo 'Checking out code from GitHub...'
                checkout scm
            }
        }
        
        stage('Setup Python Environment') {
            steps {
                echo 'Setting up Python virtual environment...'
                bat '''
                    python -m venv venv
                    call venv\\Scripts\\activate.bat
                    python -m pip install --upgrade pip
                '''
            }
        }
        
        stage('Install Dependencies') {
            steps {
                echo 'Installing project dependencies...'
                bat '''
                    call venv\\Scripts\\activate.bat
                    pip install -r requirements.txt
                '''
            }
        }
        
        stage('Run Tests') {
            steps {
                echo 'Running tests...'
                bat '''
                    call venv\\Scripts\\activate.bat
                    python -c "print('Tests would run here. Add pytest later!')"
                '''
            }
        }
        
        stage('Build') {
            steps {
                echo 'Building application...'
                bat '''
                    call venv\\Scripts\\activate.bat
                    python -c "from app import app; print('App builds successfully!')"
                '''
            }
        }
        
        stage('Deploy') {
            steps {
                echo 'Deployment stage - Configure based on your deployment target'
                bat '''
                    echo Deployment would happen here
                    echo For now, we just verify the app can start
                '''
            }
        }
    }
    
    post {
        success {
            echo 'Pipeline completed successfully!'
        }
        failure {
            echo 'Pipeline failed. Check logs for details.'
        }
        always {
            echo 'Cleaning up...'
            bat 'if exist venv rmdir /s /q venv || exit 0'
        }
    }
}
