const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const path = require('path');
const fs = require('fs');
const { v4: uuidv4 } = require('uuid');

const app = express();
const PORT = process.env.PORT || 3001;

// Middleware
app.use(helmet());
app.use(cors());
app.use(morgan('combined'));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Quiz data storage (in production, use a proper database)
const quizData = {
  'azure-security': {
    id: 'azure-security',
    title: 'Azure Security Fundamentals',
    description: 'Test your knowledge of Azure security concepts and implementations',
    difficulty: 'Intermediate',
    estimatedTime: '15 minutes',
    questions: [
      {
        id: 'azure-1',
        type: 'multiple-choice',
        question: 'What is the primary purpose of Azure Network Security Groups (NSGs)?',
        options: [
          'Data encryption at rest',
          'Network traffic filtering',
          'Identity management',
          'Resource monitoring'
        ],
        correct: 1,
        explanation: 'NSGs are Azure\'s primary network traffic filtering solution, acting as virtual firewalls to control inbound and outbound traffic.'
      },
      {
        id: 'azure-2',
        type: 'multiple-choice',
        question: 'Which Azure service provides centralized identity and access management?',
        options: [
          'Azure Active Directory',
          'Azure Key Vault',
          'Azure Security Center',
          'Azure Monitor'
        ],
        correct: 0,
        explanation: 'Azure Active Directory (now Microsoft Entra ID) provides centralized identity and access management for Azure resources.'
      },
      {
        id: 'azure-3',
        type: 'true-false',
        question: 'Azure Key Vault is designed to store and manage cryptographic keys and secrets.',
        correct: true,
        explanation: 'Azure Key Vault is specifically designed to securely store and manage cryptographic keys, secrets, and certificates.'
      },
      {
        id: 'azure-4',
        type: 'multiple-choice',
        question: 'What is the recommended approach for implementing the principle of least privilege in Azure?',
        options: [
          'Grant all permissions to all users',
          'Use Role-Based Access Control (RBAC)',
          'Share admin accounts among team members',
          'Disable all access by default'
        ],
        correct: 1,
        explanation: 'Role-Based Access Control (RBAC) is the recommended approach for implementing least privilege by assigning minimum necessary permissions.'
      },
      {
        id: 'azure-5',
        type: 'multiple-select',
        question: 'Which of the following are Azure security best practices? (Select all that apply)',
        options: [
          'Use Network Security Groups',
          'Enable multi-factor authentication',
          'Share credentials via email',
          'Regularly review access permissions',
          'Use default passwords'
        ],
        correct: [0, 1, 3],
        explanation: 'Security best practices include using NSGs, enabling MFA, and regularly reviewing permissions. Never share credentials or use default passwords.'
      }
    ]
  },
  'terraform-security': {
    id: 'terraform-security',
    title: 'Terraform Security Best Practices',
    description: 'Assess your knowledge of secure Infrastructure as Code with Terraform',
    difficulty: 'Intermediate',
    estimatedTime: '20 minutes',
    questions: [
      {
        id: 'tf-1',
        type: 'multiple-choice',
        question: 'What is the primary purpose of Terraform state files?',
        options: [
          'Store configuration variables',
          'Track infrastructure state',
          'Manage provider versions',
          'Store secrets and credentials'
        ],
        correct: 1,
        explanation: 'Terraform state files track the current state of managed infrastructure and are essential for planning and applying changes.'
      },
      {
        id: 'tf-2',
        type: 'multiple-choice',
        question: 'Which Terraform feature should be used to handle sensitive data securely?',
        options: [
          'Plain text variables',
          'Terraform variables with default values',
          'External secret management systems',
          'Environment variables only'
        ],
        correct: 2,
        explanation: 'External secret management systems like Azure Key Vault, AWS Secrets Manager, or HashiCorp Vault should be used for sensitive data.'
      },
      {
        id: 'tf-3',
        type: 'true-false',
        question: 'Terraform modules should be versioned and treated like software dependencies.',
        correct: true,
        explanation: 'Terraform modules should be versioned using semantic versioning and managed like any other software dependency.'
      },
      {
        id: 'tf-4',
        type: 'multiple-choice',
        question: 'What is the purpose of Terraform workspaces?',
        options: [
          'Store different versions of Terraform',
          'Manage multiple environments',
          'Collaborate with team members',
          'Backup infrastructure configurations'
        ],
        correct: 1,
        explanation: 'Terraform workspaces allow you to manage multiple environments (dev, staging, prod) with the same configuration.'
      }
    ]
  },
  'compliance-soc2': {
    id: 'compliance-soc2',
    title: 'SOC 2 Compliance Fundamentals',
    description: 'Test your understanding of SOC 2 compliance requirements and implementation',
    difficulty: 'Advanced',
    estimatedTime: '25 minutes',
    questions: [
      {
        id: 'soc2-1',
        type: 'multiple-choice',
        question: 'Which of the five SOC 2 Trust Services Criteria focuses on system availability?',
        options: [
          'Security',
          'Availability',
          'Processing Integrity',
          'Confidentiality',
          'Privacy'
        ],
        correct: 1,
        explanation: 'Availability is one of the five SOC 2 Trust Services Criteria, focusing on system accessibility and performance.'
      },
      {
        id: 'soc2-2',
        type: 'multiple-choice',
        question: 'What type of SOC 2 report is intended for general distribution?',
        options: [
          'Type I - Restricted',
          'Type II - Restricted',
          'Type I - Public',
          'Type II - Public'
        ],
        correct: 3,
        explanation: 'Type II SOC 2 reports with public distribution are intended for general use and include detailed testing over a period of time.'
      },
      {
        id: 'soc2-3',
        type: 'multiple-select',
        question: 'Which controls are typically required for SOC 2 Security compliance? (Select all that apply)',
        options: [
          'Access control policies',
          'Incident response procedures',
          'Network security controls',
          'Data encryption',
          'Marketing materials review'
        ],
        correct: [0, 1, 2, 3],
        explanation: 'SOC 2 Security requires comprehensive controls including access management, incident response, network security, and encryption.'
      }
    ]
  }
};

// User progress storage (in production, use a database)
const userProgress = {};

// API Routes

// Get all available quizzes
app.get('/api/quizzes', (req, res) => {
  const quizzes = Object.values(quizData).map(quiz => ({
    id: quiz.id,
    title: quiz.title,
    description: quiz.description,
    difficulty: quiz.difficulty,
    estimatedTime: quiz.estimatedTime,
    questionCount: quiz.questions.length
  }));
  
  res.json(quizzes);
});

// Get specific quiz
app.get('/api/quizzes/:quizId', (req, res) => {
  const quizId = req.params.quizId;
  const quiz = quizData[quizId];
  
  if (!quiz) {
    return res.status(404).json({ error: 'Quiz not found' });
  }
  
  // Return quiz without correct answers for the user
  const quizForUser = {
    ...quiz,
    questions: quiz.questions.map(q => {
      const { correct, ...questionWithoutAnswer } = q;
      return questionWithoutAnswer;
    })
  };
  
  res.json(quizForUser);
});

// Submit quiz answers
app.post('/api/quizzes/:quizId/submit', (req, res) => {
  const quizId = req.params.quizId;
  const { answers, userId } = req.body;
  
  const quiz = quizData[quizId];
  if (!quiz) {
    return res.status(404).json({ error: 'Quiz not found' });
  }
  
  // Calculate score
  let correctAnswers = 0;
  const results = [];
  
  quiz.questions.forEach((question, index) => {
    const userAnswer = answers[question.id];
    const isCorrect = checkAnswer(question, userAnswer);
    
    if (isCorrect) {
      correctAnswers++;
    }
    
    results.push({
      questionId: question.id,
      question: question.question,
      userAnswer,
      correct: isCorrect,
      explanation: question.explanation
    });
  });
  
  const score = Math.round((correctAnswers / quiz.questions.length) * 100);
  
  // Save progress
  if (!userProgress[userId]) {
    userProgress[userId] = {};
  }
  
  userProgress[userId][quizId] = {
    score,
    completedAt: new Date().toISOString(),
    results
  };
  
  res.json({
    score,
    correctAnswers,
    totalQuestions: quiz.questions.length,
    passed: score >= 70, // Passing score is 70%
    results
  });
});

// Get user progress
app.get('/api/users/:userId/progress', (req, res) => {
  const userId = req.params.userId;
  const progress = userProgress[userId] || {};
  
  res.json(progress);
});

// Helper function to check answers
function checkAnswer(question, userAnswer) {
  if (question.type === 'multiple-select') {
    if (!Array.isArray(userAnswer)) return false;
    return JSON.stringify(userAnswer.sort()) === JSON.stringify(question.correct.sort());
  }
  
  if (question.type === 'true-false') {
    return userAnswer === question.correct;
  }
  
  return userAnswer === question.correct;
}

// Serve the frontend
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Something went wrong!' });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ error: 'Not found' });
});

app.listen(PORT, () => {
  console.log(`🚀 Cloud Security Quiz Server running on port ${PORT}`);
  console.log(`📚 Available quizzes: ${Object.keys(quizData).length}`);
  console.log(`🌐 Visit http://localhost:${PORT} to start learning!`);
});
