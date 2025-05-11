import re
import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
import joblib
import email
import email.policy
import warnings
import os
warnings.filterwarnings('ignore')

class PhishingEmailDetector:
    def __init__(self):
        # Initialize or load the model
        try:
            # Try to load a pre-trained model
            self.model = joblib.load('phishing_model.pkl')
            self.vectorizer = joblib.load('tfidf_vectorizer.pkl')
            self.is_trained = True
            print("Loaded pre-trained model successfully.")
        except:
            self.model = RandomForestClassifier(n_estimators=100, random_state=42)
            self.vectorizer = TfidfVectorizer(max_features=1000, stop_words='english')
            self.is_trained = False
            print("No pre-trained model found. New model initialized.")
    
    def extract_features(self, email_text):
        """Extract features from email text for phishing detection"""
        features = {}
        
        # Basic email features
        features['num_links'] = len(re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', email_text))
        features['num_attachments'] = email_text.count('Content-Disposition: attachment')
        features['has_urgent_subject'] = 1 if any(word in email_text.lower() for word in ['urgent', 'immediate', 'attention', 'action required']) else 0
        
        # Improved sender detection
        sender_match = re.search(r'From:\s*(.*)', email_text, re.IGNORECASE)
        if sender_match:
            sender = sender_match.group(1)
            features['has_suspicious_sender'] = 1 if not re.search(r'@(gmail|yahoo|outlook|hotmail)\.com', sender) else 0
        else:
            features['has_suspicious_sender'] = 0
        
        # Content features
        features['has_greeting'] = 1 if any(greeting in email_text.lower() for greeting in ['dear', 'hello', 'hi', 'greetings']) else 0
        features['has_signature'] = 1 if any(word in email_text.lower() for word in ['regards', 'sincerely', 'best wishes']) else 0
        features['has_grammar_errors'] = 1 if len(re.findall(r'\b(?:your|you\'re|there|their|they\'re|its|it\'s)\b', email_text, re.IGNORECASE)) > 3 else 0
        
        # Suspicious keywords (expanded list)
        phishing_keywords = ['password', 'account', 'verify', 'login', 'security', 'update', 'confirm', 
                           'bank', 'paypal', 'irs', 'tax', 'ssn', 'click', 'suspend', 'verify', 'limited']
        features['num_phishing_keywords'] = sum(1 for word in phishing_keywords if word in email_text.lower())
        
        return features
    
    def train_model(self, dataset_path='phishing_dataset.csv'):
        """Train the phishing detection model"""
        try:
            if not os.path.exists(dataset_path):
                print(f"Error: Dataset file not found at {dataset_path}")
                return None
                
            # Load dataset
            data = pd.read_csv(dataset_path)
            
            # Check required columns
            if 'email' not in data.columns or 'label' not in data.columns:
                print("Error: Dataset must contain 'email' and 'label' columns")
                return None
            
            print(f"\nTraining model with {len(data)} examples...")
            
            # Extract features
            X = []
            for email_text in data['email']:
                features = self.extract_features(email_text)
                X.append(list(features.values()))
            
            # Vectorize email text
            X_text_features = self.vectorizer.fit_transform(data['email']).toarray()
            
            # Combine features
            X = np.hstack((X, X_text_features))
            y = data['label'].values
            
            # Split data
            X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
            
            # Train model
            self.model.fit(X_train, y_train)
            
            # Evaluate
            y_pred = self.model.predict(X_test)
            accuracy = accuracy_score(y_test, y_pred)
            print(f"Model trained successfully. Accuracy: {accuracy:.2f}")
            
            # Save model
            joblib.dump(self.model, 'phishing_model.pkl')
            joblib.dump(self.vectorizer, 'tfidf_vectorizer.pkl')
            self.is_trained = True
            
            return accuracy
        except Exception as e:
            print(f"Error training model: {e}")
            return None
    
    def analyze_email(self, email_text):
        """Analyze an email for phishing attempts"""
        if not self.is_trained:
            print("Warning: Model not trained. Using basic heuristic checks only.")
        
        # Extract features
        features = self.extract_features(email_text)
        feature_values = np.array(list(features.values())).reshape(1, -1)
        
        if self.is_trained:
            # Vectorize text
            text_features = self.vectorizer.transform([email_text]).toarray()
            
            # Combine features
            X = np.hstack((feature_values, text_features))
            
            # Predict
            prediction = self.model.predict(X)[0]
            probability = self.model.predict_proba(X)[0][1]
        else:
            # Basic heuristic if model not trained
            phishing_score = (features['num_links'] > 3) + \
                           (features['num_phishing_keywords'] > 2) + \
                           (features['has_suspicious_sender']) + \
                           (features['has_urgent_subject']) - \
                           (features['has_greeting']) - \
                           (features['has_signature'])
            
            prediction = 1 if phishing_score > 2 else 0
            probability = phishing_score / 4  # Normalize to 0-1 range
        
        # Generate report
        report = {
            'is_phishing': bool(prediction),
            'probability': float(probability),
            'features': features,
            'warnings': []
        }
        
        # Add specific warnings
        if features['num_links'] > 3:
            report['warnings'].append(f"Email contains {features['num_links']} links (suspicious)")
        if features['num_phishing_keywords'] > 2:
            report['warnings'].append(f"Email contains {features['num_phishing_keywords']} phishing-related keywords")
        if features['has_suspicious_sender']:
            report['warnings'].append("Sender email looks suspicious")
        if features['has_urgent_subject']:
            report['warnings'].append("Email uses urgent language")
        if not features['has_greeting']:
            report['warnings'].append("Email lacks proper greeting (may be impersonal)")
        
        return report
    
    def analyze_email_file(self, file_path):
        """Analyze an email from an .eml file"""
        try:
            if not os.path.exists(file_path):
                print(f"Error: File not found at {file_path}")
                return None
                
            with open(file_path, 'r', encoding='utf-8') as f:
                msg = email.message_from_file(f, policy=email.policy.default)
                email_text = msg.as_string()
                return self.analyze_email(email_text)
        except Exception as e:
            print(f"Error reading email file: {e}")
            return None

def main():
    detector = PhishingEmailDetector()
    
    # Check if model needs training
    if not detector.is_trained:
        print("\nNo trained model found. Would you like to train a new model? (y/n)")
        choice = input().lower()
        if choice == 'y':
            print("\nEnter path to training dataset (CSV file) or press Enter for default 'phishing_dataset.csv':")
            dataset_path = input().strip()
            if not dataset_path:
                dataset_path = 'phishing_dataset.csv'
            detector.train_model(dataset_path)
    
    while True:
        print("\nPhishing Email Detector")
        print("1. Analyze email text")
        print("2. Analyze .eml file")
        print("3. Train/re-train model")
        print("4. Exit")
        
        try:
            choice = input("\nEnter your choice (1-4): ").strip()
            
            if choice == '1':
                print("\nPaste the email text (press Enter twice to finish):")
                email_text = ""
                while True:
                    line = input()
                    if line == '':
                        break
                    email_text += line + "\n"
                
                if not email_text.strip():
                    print("Error: No email text provided")
                    continue
                    
                result = detector.analyze_email(email_text)
                print("\nAnalysis Results:")
                print(f"Phishing Probability: {result['probability']*100:.1f}%")
                print(f"Likely Phishing: {'Yes' if result['is_phishing'] else 'No'}")
                if result['warnings']:
                    print("\nWarnings:")
                    for warning in result['warnings']:
                        print(f"- {warning}")
                else:
                    print("\nNo significant warnings detected.")
            
            elif choice == '2':
                file_path = input("\nEnter path to .eml file: ").strip('"\'')
                if not file_path.lower().endswith('.eml'):
                    print("Error: Please provide a .eml file")
                    continue
                    
                result = detector.analyze_email_file(file_path)
                if result:
                    print("\nAnalysis Results:")
                    print(f"Phishing Probability: {result['probability']*100:.1f}%")
                    print(f"Likely Phishing: {'Yes' if result['is_phishing'] else 'No'}")
                    if result['warnings']:
                        print("\nWarnings:")
                        for warning in result['warnings']:
                            print(f"- {warning}")
                    else:
                        print("\nNo significant warnings detected.")
            
            elif choice == '3':
                print("\nEnter path to training dataset (CSV file) or press Enter for default 'phishing_dataset.csv':")
                dataset_path = input().strip()
                if not dataset_path:
                    dataset_path = 'phishing_dataset.csv'
                detector.train_model(dataset_path)
            
            elif choice == '4':
                print("\nExiting...")
                break
                
            else:
                print("\nInvalid choice. Please enter 1-4.")
                
        except Exception as e:
            print(f"\nAn error occurred: {str(e)}")

if __name__ == "__main__":
    main()