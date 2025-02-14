from google import genai
from dotenv import load_dotenv
import os

load_dotenv()

SECRET_KEY_GEMINI = os.getenv("SECRET_KEY_GEMINI")

def get_category(category, name):
    client = genai.Client(api_key=SECRET_KEY_GEMINI)

    prompt = (
    f"El nombre '{name}' pertenece a la categoría '{category}'? "
    "Si no, responde únicamente con la categoría correcta, sin explicaciones ni contexto adicional."
    )

    response = client.models.generate_content(model="gemini-2.0-flash", contents=prompt)
    return response.text