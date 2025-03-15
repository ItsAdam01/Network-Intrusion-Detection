from flask import Flask, request, jsonify
from flask_socketio import SocketIO
from flask_cors import CORS
from engine import start_nids
import threading

app = Flask(__name__)
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# NIDS Attack Simulator Endpoint 

SIMULATIONS = None
_load_error = None

def _load_sims():
    global SIMULATIONS, _load_error
    if SIMULATIONS is not None:
        return
    try:
        import attacker as a


        listener_thread = threading.Thread(target=a.run_listener, args=(8080,), daemon=True)
        listener_thread.start()
        print("[*] Port 8080 listener started for cleartext sim")

        SIMULATIONS = {
            "icmp":      a.sim_icmp,
            "null_scan": a.sim_null_scan,
            "xmas_scan": a.sim_xmas_scan,
            "port_scan": a.sim_port_scan,
            "syn_flood": a.sim_syn_flood,
            "cleartext": a.sim_cleartext,
        }
        print("[*] attacker.py loaded — simulator ready")
    except Exception as e:
        _load_error = str(e)
        SIMULATIONS = {}
        print(f"[!] Could not load attacker.py: {e}")


@app.route("/simulate", methods=["POST"])
def simulate():
    _load_sims()

    if _load_error:
        return jsonify({"ok": False, "error": f"attacker.py failed to load: {_load_error}"}), 500

    data   = request.get_json(silent=True) or {}
    attack = data.get("attack", "").strip()

    if not attack:
        return jsonify({"ok": False, "error": "Missing 'attack' field"}), 400

    fn = SIMULATIONS.get(attack)
    if fn is None:
        return jsonify({
            "ok":        False,
            "error":     f"Unknown attack '{attack}'",
            "available": list(SIMULATIONS.keys()),
        }), 404

    error_box = []

    def run():
        try:
            fn()
        except Exception as e:
            error_box.append(str(e))
            print(f"[!] simulate '{attack}' runtime error: {e}")

    t = threading.Thread(target=run, daemon=True)
    t.start()
    t.join(timeout=2)

    if error_box:
        return jsonify({"ok": False, "error": error_box[0]}), 500

    return jsonify({"ok": True, "attack": attack})


@app.route("/", methods=["GET"])
def health():
    return jsonify({"status": "nids-ok"})


if __name__ == '__main__':
    nids_thread = threading.Thread(target=start_nids, args=(socketio,))
    nids_thread.daemon = True
    nids_thread.start()

    print("--- Server & NIDS Engine Starting ---")
    socketio.run(app, host='0.0.0.0', port=5000, debug=True,
                 use_reloader=False, allow_unsafe_werkzeug=True)