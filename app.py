from flask import Flask, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
import sqlite3
import os
import binascii
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature


app = Flask(__name__)
app.config['SECRET_KEY'] = 'mysecretkey'  


def init_db():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            recipient_id INTEGER,
            message TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id),
            FOREIGN KEY (recipient_id) REFERENCES users (id)
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS refresh_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            token TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'active',
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    conn.commit()
    conn.close()


@app.route('/ping', methods=['GET'])
def ping():
    return jsonify({'message': 'Сервер працює!'})

def verify_token(token):
    s = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    try:
        data = s.loads(token, salt='access-token', max_age=3600)  
        return data, None
    except SignatureExpired:
        return None, 'Термін дії токену закінчився'
    except BadSignature:
        return None, 'Невірний токен'



@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()

    if not data or not data.get('username') or not data.get('password'):
        return jsonify({"message": "Будь ласка, надайте ім'я користувача та пароль"}), 400

    username = data['username']
    password = data['password']

    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
    user = cursor.fetchone()
    conn.close()

    if user and check_password_hash(user[2], password):
       
        s = URLSafeTimedSerializer(app.config['SECRET_KEY'])
        token = s.dumps({'user_id': user[0]}, salt='access-token')

     
        refresh_token = binascii.hexlify(os.urandom(24)).decode()
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        cursor.execute('INSERT INTO refresh_tokens (user_id, token) VALUES (?, ?)', (user[0], refresh_token))
        conn.commit()
        conn.close()

        return jsonify({'access_token': token, 'refresh_token': refresh_token}), 200
    else:
        return jsonify({'message': 'Невірне ім\'я користувача або пароль'}), 401
    
# secure test
@app.route('/protected', methods=['GET'])
def protected():
    token = request.headers.get('Authorization')

    if not token:
        return jsonify({'message': 'Токен відсутній'}), 401

    s = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    try:
     
        data = s.loads(token, salt='access-token')
        user_id = data['user_id']
        return jsonify({'message': f'successful connection{user_id}!'}), 200
    except SignatureExpired:
        return jsonify({'message': 'Токен прострочений'}), 401
    except BadSignature:
        return jsonify({'message': 'Невірний токен'}), 401
    

@app.route('/send', methods=['POST'])
def send_message():
    token = request.headers.get('Authorization')
    data = request.get_json()

    if not token:
        return jsonify({'message': 'Токен відсутній'}), 401

    if not data or not data.get('message'):
        return jsonify({'message': 'Повідомлення не надано'}), 400

    s = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    try:
       
        token_data = s.loads(token, salt='access-token')
        user_id = token_data['user_id']
        
        
        message = data['message']
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        cursor.execute('INSERT INTO messages (user_id, message) VALUES (?, ?)', (user_id, message))
        conn.commit()
        conn.close()

        return jsonify({'message': 'Повідомлення надіслано успішно'}), 200

    except SignatureExpired:
        return jsonify({'message': 'Токен прострочений'}), 401
    except BadSignature:
        return jsonify({'message': 'Невірний токен'}), 401
    
@app.route('/refresh', methods=['POST'])
def refresh_token():
    data = request.get_json()
    refresh_token = data.get('refresh_token')

    if not refresh_token:
        return jsonify({'message': 'Рефреш токен відсутній'}), 400

  
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('SELECT user_id FROM refresh_tokens WHERE token = ? AND status = ?', (refresh_token, 'active'))
    result = cursor.fetchone()

    if result:
        user_id = result[0]
  
        cursor.execute('UPDATE refresh_tokens SET status = ? WHERE token = ?', ('revoked', refresh_token))

        s = URLSafeTimedSerializer(app.config['SECRET_KEY'])
        new_access_token = s.dumps({'user_id': user_id}, salt='access-token')
        new_refresh_token = binascii.hexlify(os.urandom(24)).decode()

   
        cursor.execute('INSERT INTO refresh_tokens (user_id, token, status) VALUES (?, ?, ?)', (user_id, new_refresh_token, 'active'))

        conn.commit()
        conn.close()

        return jsonify({'access_token': new_access_token, 'refresh_token': new_refresh_token}), 200
    else:
        conn.close()
        return jsonify({'message': 'Невірний або прострочений рефреш токен'}), 401



@app.route('/messages', methods=['GET'])
def get_messages():
    token = request.headers.get('Authorization')

    if not token:
        return jsonify({'message': 'token missing'}), 401

    s = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    try:
 
        token_data = s.loads(token, salt='access-token')
        user_id = token_data['user_id']

        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        cursor.execute('SELECT users.username, messages.message, messages.timestamp FROM messages JOIN users ON messages.user_id = users.id ORDER BY messages.timestamp DESC')
        messages = cursor.fetchall()
        conn.close()

 
        messages_list = []
        for message in messages:
            messages_list.append({
                'username': message[0],
                'message': message[1],
                'timestamp': message[2]
            })

        return jsonify({'messages': messages_list}), 200

    except SignatureExpired:
        return jsonify({'message': 'token is expired'}), 401
    except BadSignature:
        return jsonify({'message': 'wrong token'}), 401

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()

    if not data or not data.get('username') or not data.get('password'):
        return jsonify({"message": "Будь ласка, надайте ім'я користувача та пароль"}), 400

    username = data['username']
    password = generate_password_hash(data['password'])

    try:
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        cursor.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, password))
        conn.commit()
        conn.close()
        return jsonify({'message': 'Реєстрація успішна'}), 201
    except sqlite3.IntegrityError:
        return jsonify({'message': 'Ім\'я користувача вже існує'}), 409

@app.route('/users', methods=['GET'])
def get_users():
    token = request.headers.get('Authorization')

    if not token:
        return jsonify({'message': 'token missing'}), 401

    _, error = verify_token(token)
    if error:
        return jsonify({'message': error}), 401

    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('SELECT id, username FROM users')
    users = cursor.fetchall()
    conn.close()

    users_list = [{'id': user[0], 'username': user[1]} for user in users]
    return jsonify({'users': users_list}), 200

@app.route('/messages/<int:recipient_id>', methods=['GET'])
def get_private_messages(recipient_id):
    token = request.headers.get('Authorization')

    if not token:
        return jsonify({'message': 'token missing'}), 401

    sender_data, error = verify_token(token)
    if error:
        return jsonify({'message': error}), 401

    user_id = sender_data['user_id']

    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('''
        SELECT messages.user_id, users.username, messages.message, messages.timestamp
        FROM messages
        JOIN users ON messages.user_id = users.id
        WHERE (messages.user_id = ? AND messages.recipient_id = ?)
        OR (messages.user_id = ? AND messages.recipient_id = ?)
        ORDER BY messages.timestamp
    ''', (user_id, recipient_id, recipient_id, user_id))
    messages = cursor.fetchall()
    conn.close()


    messages_list = []
    for msg in messages:
        messages_list.append({
            'user_id': msg[0],
            'username': msg[1],
            'message': msg[2],
            'timestamp': msg[3]
        })

    return jsonify({'messages': messages_list}), 200



@app.route('/send_private', methods=['POST'])
def send_private_message():
    data = request.get_json()
    token = request.headers.get('Authorization')

    if not token:
        return jsonify({'message': 'Токен відсутній'}), 401

  
    sender_data, error = verify_token(token)
    if error:
        return jsonify({'message': error}), 401

    user_id = sender_data['user_id']
    recipient_id = data.get('recipient') 
    message = data.get('message')

    if not recipient_id or not message:
        return jsonify({'message': 'Будь ласка, вкажіть отримувача і повідомлення'}), 400

    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('SELECT id FROM users WHERE id = ?', (recipient_id,))
    recipient = cursor.fetchone()

    if recipient:
        cursor.execute('INSERT INTO messages (user_id, recipient_id, message) VALUES (?, ?, ?)', (user_id, recipient_id, message))
        conn.commit()
        conn.close()
        return jsonify({'message': 'Приватне повідомлення надіслано успішно'}), 200
    else:
        conn.close()
        return jsonify({'message': 'Отримувача не знайдено'}), 404



if __name__ == '__main__':
    init_db()  
    app.run(debug=True)

