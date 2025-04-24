#AIzaSyACbdOQ52M9PD_4kQ-XrsJnD9MlI6K1ZrQ

import google.generativeai as genai

# Replace with your actual API key
genai.configure(api_key="AIzaSyACbdOQ52M9PD_4kQ-XrsJnD9MlI6K1ZrQ")

# Initialize the model
model = genai.GenerativeModel("gemini-1.5-pro-latest")

# Function to get response from Gemini
def ask_gemini(question):
    response = model.generate_content(question)
    return response.text

# Example usage
while True:
    user_input = input("Ask a question (or type 'exit' to quit): ")
    if user_input.lower() == "exit":
        break
    answer = ask_gemini(user_input)
    print("\nGemini says:\n", answer, "\n")
