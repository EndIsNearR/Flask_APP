# Flask CRUD Application with CI/CD Pipeline

A secure Flask-based CRUD (Create, Read, Update, Delete) application with user authentication, security features, and automated CI/CD pipeline using Jenkins and SonarQube.

## 🚀 Features

### Application Features
- ✅ **User Management**: Full CRUD operations for user data
- ✅ **Secure Authentication**: Registration and login with bcrypt password hashing
- ✅ **Session Management**: Secure session handling with HTTPOnly cookies
- ✅ **CSRF Protection**: Flask-WTF CSRF tokens on all forms
- ✅ **Input Validation**: Comprehensive form validation using WTForms
- ✅ **Error Handling**: Custom error pages (400, 403, 404, 500)
- ✅ **Security Headers**: X-Frame-Options, CSP, HSTS, etc.
- ✅ **Logging**: Rotating file logs for monitoring and debugging

### Security Features (Lab 8 Implementation)
1. **Input Validation & Sanitization** (Task 1)
   - WTForms validation for all user inputs
   - Email validation and sanitization
   - Phone number format validation

2. **SQL Injection Prevention** (Task 2)
   - SQLAlchemy ORM with parameterized queries
   - No raw SQL execution

3. **Session Management** (Task 3)
   - Secure session cookies (HTTPOnly, Secure, SameSite)
   - Session timeout (1 hour)
   - CSRF protection on all forms

4. **Secure Error Handling** (Task 4)
   - Custom error pages without sensitive information
   - Comprehensive logging with rotation
   - Exception handling with rollback

5. **Secure Password Storage** (Task 5)
   - Bcrypt password hashing
   - Account lockout after 5 failed attempts
   - Password strength validation

### CI/CD Pipeline
- 🔄 **Jenkins**: Automated build and deployment pipeline
- 🔒 **SonarQube**: Static Application Security Testing (SAST)
- 🛡️ **Bandit**: Python security linter
- 📦 **Safety**: Dependency vulnerability scanner
- 🐳 **Docker**: Containerized Jenkins and SonarQube

## 📋 Prerequisites

- Python 3.9+
- Docker Desktop (for Jenkins and SonarQube)
- Git

## 🔧 Installation

### 1. Clone the Repository

```bash
git clone https://github.com/EndIsNearR/Flask_APP.git
cd Flask_APP
```

### 2. Set Up Virtual Environment

```bash
# Windows
python -m venv env
.\env\Scripts\activate

# Linux/Mac
python3 -m venv env
source env/bin/activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Run the Application

```bash
python app.py
```

The application will be available at `http://127.0.0.1:5000`

## 🐳 CI/CD Setup

### Start Jenkins and SonarQube

```bash
# Start Jenkins
docker run -d --name jenkins \
  -p 8080:8080 -p 50000:50000 \
  -v jenkins_home:/var/jenkins_home \
  jenkins/jenkins:lts-jdk17

# Install Python in Jenkins
docker exec -u root jenkins apt-get update
docker exec -u root jenkins apt-get install -y python3 python3-pip python3-venv

# Start SonarQube
docker run -d --name sonarqube \
  -p 9000:9000 \
  sonarqube:lts-community

# Create network for Jenkins and SonarQube
docker network create jenkins-sonar-network
docker network connect jenkins-sonar-network jenkins
docker network connect jenkins-sonar-network sonarqube
```

### Access Jenkins

1. Open: `http://localhost:8080`
2. Get initial admin password:
   ```bash
   docker exec jenkins cat /var/jenkins_home/secrets/initialAdminPassword
   ```
3. Install suggested plugins
4. Create admin user

### Access SonarQube

1. Open: `http://localhost:9000`
2. Login: `admin` / `admin` (change password on first login)
3. Generate token: My Account → Security → Generate Token

### Configure Jenkins Pipeline

1. Create new Pipeline job in Jenkins
2. Configure:
   - **Pipeline Definition**: Pipeline script from SCM
   - **SCM**: Git
   - **Repository URL**: `https://github.com/EndIsNearR/Flask_APP.git`
   - **Branch**: `*/main`
   - **Script Path**: `Jenkinsfile`

3. Configure SonarQube:
   - **Manage Jenkins** → **System** → **SonarQube servers**
   - Add server: `http://sonarqube:9000`
   - Add authentication token

4. Configure SonarQube Scanner:
   - **Manage Jenkins** → **Tools** → **SonarQube Scanner**
   - Name: `SonarQubeScanner`
   - Install automatically

## 📊 Pipeline Stages

The Jenkins pipeline includes the following stages:

1. **Checkout**: Clone code from GitHub
2. **Setup Python Environment**: Create virtual environment
3. **Install Dependencies**: Install required packages
4. **Run Tests**: Execute unit tests and validation
5. **Build Validation**: Verify application builds correctly
6. **SonarQube Analysis**: Static code analysis and security scanning
7. **Quality Gate**: Check code quality standards
8. **Security Check**: Run Bandit and Safety security scans
9. **Deploy**: Deploy to target environment

## 🔒 Security Analysis

### View SonarQube Results

After running the pipeline, view security analysis at:
`http://localhost:9000/dashboard?id=Flask-CRUD-App`

The analysis includes:
- Security vulnerabilities
- Code smells
- Bugs
- Code coverage
- Code duplications

### Security Tools Used

- **SonarQube**: Comprehensive SAST analysis
- **Bandit**: Python-specific security issue detection
- **Safety**: Known security vulnerability detection in dependencies

## 📁 Project Structure

```
FlaskCRUDApp/
├── app.py                      # Main application file
├── forms.py                    # WTForms form definitions
├── requirements.txt            # Python dependencies
├── Jenkinsfile                 # CI/CD pipeline configuration
├── sonar-project.properties    # SonarQube configuration
├── templates/                  # HTML templates
│   ├── index.html             # Main page
│   ├── login.html             # Login page
│   ├── register.html          # Registration page
│   ├── update.html            # Update user page
│   └── errors/                # Error pages
│       ├── 400.html
│       ├── 403.html
│       ├── 404.html
│       └── 500.html
├── static/                     # Static files (CSS, JS, images)
├── instance/                   # SQLite database (created on first run)
└── logs/                       # Application logs
```

## 🔐 Environment Variables

For production deployment, set these environment variables:

```bash
# Secret key for session management
SECRET_KEY=your-secret-key-here

# Flask debug mode (False in production)
FLASK_DEBUG=False
```

## 🧪 Testing

Run tests using pytest (once test suite is added):

```bash
pytest tests/
```

## 📝 API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Display all users |
| `/add` | POST | Add new user |
| `/update/<id>` | GET, POST | Update user |
| `/delete/<id>` | POST | Delete user |
| `/register` | GET, POST | User registration |
| `/login` | GET, POST | User login |
| `/logout` | GET | User logout |

## 🛡️ Security Best Practices Implemented

1. ✅ Input validation and sanitization
2. ✅ SQL injection prevention with ORM
3. ✅ CSRF protection on all forms
4. ✅ Secure password hashing with bcrypt
5. ✅ Session security (HTTPOnly, Secure, SameSite cookies)
6. ✅ Account lockout mechanism
7. ✅ Security headers (CSP, HSTS, X-Frame-Options)
8. ✅ Error handling without information disclosure
9. ✅ Comprehensive logging
10. ✅ HTTPS enforcement headers

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📄 License

This project is part of a university lab assignment for SSD (Secure Software Development) course.

## 👤 Author

- **Name**: Student i221669
- **Course**: Secure Software Development Lab
- **Institution**: FAST National University
- **Lab**: Lab 08 - Secure CRUD Application with CI/CD

## 🙏 Acknowledgments

- Flask documentation and community
- Jenkins and SonarQube for CI/CD tools
- OWASP for security best practices
- FAST National University SSD Lab instructors

## 📞 Support

For issues and questions, please open an issue on GitHub or contact the course instructor.

---

**⚠️ Important Note**: This application is designed for educational purposes. For production deployment, additional security measures and configurations should be implemented, including:
- Use of production WSGI server (Gunicorn/uWSGI)
- Reverse proxy with Nginx/Apache
- SSL/TLS certificates
- Environment-specific configuration
- Database migration to PostgreSQL/MySQL
- Enhanced monitoring and alerting
