pipeline {
    agent any

    stages {
        stage('Creating Resources') {
            steps {
                sh("""
                    python aws_python.py
                """)
            }
        }
    }
}
