# Placeholder for DB logic
from .models import CyberQuery, CyberResponse

def get_db():
    return {"queries": [], "responses": []}

def add_cyber_query(db, query: CyberQuery):
    db["queries"].append(query)

def add_cyber_response(db, response: CyberResponse):
    db["responses"].append(response)
