1) First, install the required Python packages: pip install -r requirements.txt

2) Run the Tool
Start the tool by running the following command: python project.py

3) Select an Option from the Menu
After running the script, you’ll see a menu like this:Phishing Email Detector
                                                    1. Analyze email text
                                                    2. Analyze .eml file
                                                    3. Train/re-train model
                                                    4. Exit
Choose the option you want:

Press 1 to analyze pasted email text

Press 2 to analyze a .eml file (you will be prompted to enter the file path)

Press 3 to train or re-train the phishing detection model using a dataset

Press 4 to exit the program

4)  Optional: Train the Model
If no model is found or you select option 3, you will be prompted to provide the path to a CSV training dataset. The dataset should contain two columns:

text: the email content

label: 1 for phishing, 0 for legitimate

example: text,label
        "Your account has been compromised",1
        "Welcome to your inbox!",0


After training, the model will be saved and used for future predictions.

---

Feel free to customize this file with additional details like screenshots or contributor info.
