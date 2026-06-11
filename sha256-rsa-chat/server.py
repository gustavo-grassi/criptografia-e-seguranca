from flask import Flask, jsonify, request

app = Flask(__name__)

mailbox = {
    'julia': [],
    'lucas': []
}

@app.route('/messages/<user>')
def get_messages(user):
    msgs = mailbox[user]
    mailbox[user] = []
    return jsonify(msgs)

@app.route('/send', methods=['POST'])
def enviar_msg():
    data = request.json
    receiver = data['receiver']
    
    mailbox[receiver].append(data)
    return jsonify({"status": "ok"})

if __name__ == '__main__':
    app.run(port=5000, debug=True)