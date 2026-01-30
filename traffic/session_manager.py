import uuid
from utils.random_gen import SecureRandom

class SessionManager:
    def __init__(self):
        self.sessions = {}

    def create_session(self):
        session_id = str(uuid.uuid4())
        aes_key = SecureRandom.random_key_aes()
        self.sessions[session_id] = aes_key
        return session_id, aes_key

    def get_key(self, session_id):
        return self.sessions.get(session_id)

    def destroy_session(self, session_id):
        self.sessions.pop(session_id, None)
