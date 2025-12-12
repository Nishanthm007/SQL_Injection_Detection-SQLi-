# SQL Injection Detection System

A robust, production-ready SQL Injection (SQLi) detection system that combines deep learning (CNN) with rule-based detection to achieve high accuracy in identifying malicious SQL queries.

## 🎯 Overview

This project implements a hybrid approach to SQL injection detection, leveraging:
- **Convolutional Neural Networks (CNN)** for pattern recognition
- **Rule-based Engine** for signature matching
- **Hybrid Fusion System** combining both approaches for optimal performance

The system achieves high accuracy by utilizing multiple validation methods and is designed for real-world deployment scenarios.

## 📊 Key Features

- **Hybrid Detection Architecture**: Combines CNN and rule-based detection for superior accuracy
- **RESTful API**: FastAPI-based backend for easy integration
- **Real-time Detection**: Low-latency query analysis
- **Comprehensive Evaluation Metrics**: Accuracy, Precision, Recall, F1-Score
- **Extensible Rule Engine**: Easy-to-update detection rules
- **Visualization Tools**: Performance metrics and ROC curves
- **Multi-phase Development**: Structured development from data preparation to deployment

## 🏗️ Architecture

### System Components

```
┌─────────────────────────────────────────────┐
│           Frontend (React/Vue)              │
│         (Dashboard & Query Testing)         │
└─────────────────┬───────────────────────────┘
                  │
                  ├─ HTTP/REST API
                  │
┌─────────────────▼───────────────────────────┐
│         FastAPI Backend Server              │
│  ┌─────────────────────────────────────┐   │
│  │      Hybrid Detector Service        │   │
│  │  ┌──────────┐      ┌─────────────┐ │   │
│  │  │   CNN    │      │ Rule Engine │ │   │
│  │  │  Model   │      │   (JSON)    │ │   │
│  │  └────┬─────┘      └──────┬──────┘ │   │
│  │       │                   │         │   │
│  │       └────────┬──────────┘         │   │
│  │            Fusion Logic              │   │
│  └─────────────────────────────────────┘   │
│                                             │
│  Preprocessor │ Model Loader │ Validators  │
└─────────────────────────────────────────────┘
```

### Detection Flow

1. **Input Query** → Preprocessing (tokenization, normalization)
2. **Parallel Analysis**:
   - CNN Model: Deep learning pattern detection
   - Rule Engine: Signature-based matching
3. **Fusion**: Weighted combination of CNN and Rule scores
4. **Output**: Binary classification (Benign/Malicious) + confidence scores

## 📈 Performance Metrics

The system's accuracy is calculated using the following parameters:

### Accuracy Calculation Formula

```
Accuracy = (TP + TN) / Total Samples
```

Where:
- **TP (True Positives)**: Malicious queries correctly identified as malicious
- **TN (True Negatives)**: Benign queries correctly identified as benign
- **FP (False Positives)**: Benign queries incorrectly flagged as malicious
- **FN (False Negatives)**: Malicious queries incorrectly classified as benign

### Additional Metrics

- **Precision**: `TP / (TP + FP)` - Accuracy of positive predictions
- **Recall**: `TP / (TP + FN)` - Coverage of actual positives
- **F1-Score**: `2 × (Precision × Recall) / (Precision + Recall)` - Harmonic mean

## 🚀 Quick Start

### Prerequisites

- Python 3.8+
- TensorFlow 2.13+
- Node.js 16+ (for frontend)
- 8GB+ RAM recommended

### Installation

1. **Clone the repository**
```bash
git clone https://github.com/Nishanthm007/SQL_Injection_Detection-SQLi-.git
cd SQL_Injection_Detection-SQLi-/Major-Project(SQLi)
```

2. **Set up Python environment**
```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install backend dependencies
pip install -r requirements.txt
cd backend
pip install -r requirements.txt
```

3. **Set up frontend** (optional)
```bash
cd frontend
npm install
```

### Running the Application

#### Backend Server

```bash
cd backend
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

The API will be available at `http://localhost:8000`

#### Frontend Development Server

```bash
cd frontend
npm run dev
```

## 📝 API Usage

### Health Check
```bash
GET /health
```

### Query Detection
```bash
POST /api/v1/detect
Content-Type: application/json

{
  "query": "SELECT * FROM users WHERE id = 1"
}
```

**Response:**
```json
{
  "query": "SELECT * FROM users WHERE id = 1",
  "is_malicious": false,
  "confidence": 0.95,
  "cnn_score": 0.12,
  "rule_score": 0.0,
  "hybrid_score": 0.06,
  "detected_patterns": [],
  "analysis_time_ms": 45.2
}
```

## 🔬 Model Training

### Training the CNN Model

```bash
cd model_training
python train.py
```

This will:
1. Load training data from `data/processed/`
2. Build and train the CNN architecture
3. Save the best model to `saved_model_final/`
4. Generate training history and metrics

### Evaluation

```bash
cd backend
python scripts/evaluate_model.py
```

Generates:
- `evaluation_results.csv`: Per-query predictions
- Console output with metrics for CNN, Rule-based, and Hybrid approaches

## 📊 Visualization

Generate performance visualizations:

```bash
cd backend
python scripts/generate_visuals.py
```

Outputs (in `backend/scripts/evaluation_outputs/`):
- Confusion matrices
- ROC curves
- Precision-Recall curves
- Training/validation curves

## 🧪 Testing

Run the test suite:

```bash
cd backend
pytest tests/
```

Individual component tests:
```bash
python test_models.py      # Test CNN model loading
python test_rules.py       # Test rule engine
python test_endpoint.py    # Test API endpoints
python test_database.py    # Test database connections
```

## 📁 Project Structure

```
Major-Project(SQLi)/
├── backend/               # FastAPI backend application
│   ├── app/
│   │   ├── api/          # API endpoints
│   │   ├── core/         # Configuration & settings
│   │   ├── models/       # Pydantic schemas
│   │   ├── services/     # Business logic (detector, preprocessor)
│   │   └── utils/        # Model loader & utilities
│   ├── scripts/          # Evaluation & visualization scripts
│   └── tests/            # Unit & integration tests
├── model_training/       # CNN model training code
│   ├── train.py          # Training script
│   ├── cnn_model.py      # Model architecture
│   ├── preprocessor.py   # Text preprocessing
│   └── saved_model_final/# Trained model files
├── data/                 # Datasets
│   ├── raw/              # Raw training data
│   ├── processed/        # Preprocessed datasets
│   └── models/           # Model checkpoints
├── rules/                # Detection rules (JSON)
├── frontend/             # React/Vue web interface
├── notebooks/            # Jupyter notebooks for experimentation
├── reports/              # Analysis reports
└── tests/                # Test datasets & edge cases
```

## 🔄 Development Phases

| Phase | Description | Status |
|-------|-------------|--------|
| Phase 1 | Data preparation & EDA | ✅ Complete |
| Phase 2 | Rule engine development | ✅ Complete |
| Phase 3 | Data augmentation & diversification | ✅ Complete |
| Phase 4 | CNN architecture design | ✅ Complete |
| Phase 5 | Curriculum learning & optimization | ✅ Complete |
| Phase 6 | ROC analysis & explainability | ✅ Complete |
| Phase 7 | Hybrid fusion system | ✅ Complete |
| Phase 8 | API development & deployment | ✅ Complete |

## 🛠️ Configuration

### Backend Configuration

Edit `backend/app/core/config.py` or use environment variables:

```bash
# .env file
LOG_LEVEL=INFO
CNN_MODEL_PATH=model_training/saved_model_final
VOCAB_PATH=model_training/vocab.json
WORD_TYPES_PATH=model_training/word_types.json
RULES_PATH=rules/rules_machine_v1.1.json
MAX_QUERY_LENGTH=512
CNN_THRESHOLD=0.5
RULE_THRESHOLD=0.5
```

### Rule Engine

Rules are defined in `rules/rules_machine_v1.1.json`. Each rule includes:
- Pattern (regex)
- Severity level
- Description
- Tags

## 📊 Dataset Information

- **Training Data**: Balanced dataset of benign and malicious SQL queries
- **Test Data**: Independent test set with diverse attack vectors
- **Sources**: 
  - Publicly available SQLi datasets
  - Synthetically generated queries
  - Real-world attack patterns

## 🤝 Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 👥 Authors

- **Nishanth M** - [@Nishanthm007](https://github.com/Nishanthm007)

## 🙏 Acknowledgments

- TensorFlow and Keras teams for the deep learning framework
- FastAPI community for the excellent web framework
- SQLparse library for SQL parsing utilities
- Research papers on SQL injection detection techniques

## 📞 Support

For issues, questions, or contributions:
- Open an issue on GitHub
- Contact: [Your email or contact information]

## 🔗 Related Resources

- [OWASP SQL Injection Guide](https://owasp.org/www-community/attacks/SQL_Injection)
- [TensorFlow Documentation](https://www.tensorflow.org/)
- [FastAPI Documentation](https://fastapi.tiangolo.com/)

---


