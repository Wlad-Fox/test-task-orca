from flask import Flask, request, abort, jsonify
from logic import App as LogicApp, Machine, FirewallAllowRule, MultipleChoiceError
import json
import sys

app = Flask(__name__)
logic = LogicApp()

@app.route('/attack/')
def attack():
    print(logic)
    machine_id = request.args.get('vm_id', '')
    print(1)
    if not machine_id:
        print(2)
        abort(400)
    try:
        return jsonify(logic.get_attack_vectors(machine_id))
    except KeyError:
        print(1)
        abort(404)
    except MultipleChoiceError:
        abort(400)


@app.route('/stats/')
def stats():
    return jsonify(logic.stats())


if __name__=="__main__":
    config_filename = sys.argv[1]
    with open(config_filename) as f:
        config = json.loads(f.read())
    logic.machines = [ Machine(obj["vm_id"], obj["name"], obj["tags"]) for obj in config["vms"]]
    logic.rules = [FirewallAllowRule(obj["fw_id"], obj["source_tag"], obj["dest_tag"]) for obj in config["fw_rules"]]

    app.run(debug=True)




