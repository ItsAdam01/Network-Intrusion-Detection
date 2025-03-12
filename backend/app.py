from flask import Flask
from flask_socketio import SocketIO 
from engine import start_nids
import threading

app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")

if __name__ == '__main__':
    nids_thread = threading.Thread(target=start_nids, args=(socketio,))
    nids_thread.daemon = True
    nids_thread.start()

    print("--- Server & NIDS Engine Starting ---")
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)
