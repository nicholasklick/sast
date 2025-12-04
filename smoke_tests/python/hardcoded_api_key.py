
import requests

def get_weather():
    # Hardcoded API key
    api_key = "a1b2c3d4e5f67890a1b2c3d4e5f67890"
    city = "London"
    url = f"https://api.openweathermap.org/data/2.5/weather?q={city}&appid={api_key}"
    response = requests.get(url)
    return response.json()

get_weather()
