🛡️ Phishing Email Detection using NLP
This project is a phishing email detector built using Natural Language Processing (NLP) techniques and machine learning. It can analyze raw email text or .eml files to determine whether an email is likely a phishing attempt.
🚀 Features
•	Detects phishing emails based on content and metadata
•	Supports:
o	Raw email text input
o	.eml file analysis
•	Provides warnings for phishing indicators
•	Option to train or retrain the model using your own dataset
•	CLI-based user interface
🧠 Technologies Used
•	Python
•	Scikit-learn
•	Natural Language Toolkit (NLTK)
•	Pandas
•	TfidfVectorizer
•	Joblib for model saving/loading
📂 Project Structure
bash
CopyEdit
PHISHING-DETECTION-WITH-NLP/
│
├── project.py               # Main CLI program
├── phishing_dataset.csv     # Dataset for training
├── phishing_sample.eml      # Sample phishing email
├── legitimate_sample.eml    # Sample legitimate email
├── model.pkl                # Trained ML model (auto-generated)
├── vectorizer.pkl           # TF-IDF vectorizer (auto-generated)
└── requirements.txt         # Python dependencies
🛠️ How to Run
1. Clone the Repository
bash
CopyEdit
git clone https://github.com/yourusername/phishing-detector.git
cd phishing-detector
2. Create a Virtual Environment (Optional)
bash
CopyEdit
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
3. Install Dependencies
bash
CopyEdit
pip install -r requirements.txt
4. Run the Program
bash
CopyEdit
python project.py
🧪 Sample Email Input (Text Mode)
vbnet
CopyEdit
Subject: Urgent: Your Account Has Been Suspended
Dear Customer,
We detected suspicious activity on your account...
📊 Training Custom Model
Choose option 3 from the menu and provide the path to your CSV dataset in the following format:
csv
CopyEdit
text,label
"Your account has been compromised",phishing
"Monthly newsletter from our team",legitimate
📧 Analyze .eml Files
You can provide full paths to .eml files, and the tool will parse and analyze the content automatically.
📌 Note
•	This is a basic project for educational purposes.
•	Accuracy depends on the dataset used.
•	Not intended for real-time production use without enhancements.
🧑‍💻 Author
smita jagtap & jigisha bagul
Cybersecurity Intern — Digisuraksha Parhari Foundation x Infinisec Technologies Pvt. Ltd.

