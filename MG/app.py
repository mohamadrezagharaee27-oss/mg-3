from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from flask_socketio import SocketIO, emit, join_room, leave_room
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3, os, secrets, time
from datetime import datetime
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

DB = 'mg.db'

def get_db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as db:
        db.executescript('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                display_name TEXT,
                avatar_color TEXT,
                online INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender_id INTEGER,
                receiver_id INTEGER,
                group_id INTEGER,
                content TEXT NOT NULL,
                msg_type TEXT DEFAULT 'private',
                read_by TEXT DEFAULT '',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(sender_id) REFERENCES users(id)
            );
            CREATE TABLE IF NOT EXISTS groups (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                description TEXT,
                creator_id INTEGER,
                avatar_color TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS group_members (
                group_id INTEGER,
                user_id INTEGER,
                role TEXT DEFAULT 'member',
                joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY(group_id, user_id)
            );
        ''')

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Unauthorized'}), 401
        return f(*args, **kwargs)
    return decorated

COLORS = ['#6C63FF','#FF6B6B','#4ECDC4','#45B7D1','#96CEB4','#FFEAA7','#DDA0DD','#98D8C8','#F7DC6F','#BB8FCE']

@app.route('/')
def index():
    if 'user_id' in session:
        return render_template('app.html')
    return render_template('index.html')

@app.route('/api/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username','').strip().lower()
    password = data.get('password','')
    display_name = data.get('display_name','').strip() or username

    if not username or not password:
        return jsonify({'error': 'نام کاربری و رمز عبور الزامی است'}), 400
    if len(username) < 3:
        return jsonify({'error': 'نام کاربری باید حداقل ۳ کاراکتر باشد'}), 400
    if len(password) < 6:
        return jsonify({'error': 'رمز عبور باید حداقل ۶ کاراکتر باشد'}), 400

    color = COLORS[hash(username) % len(COLORS)]
    try:
        with get_db() as db:
            db.execute('INSERT INTO users (username,password,display_name,avatar_color) VALUES (?,?,?,?)',
                      (username, generate_password_hash(password), display_name, color))
        return jsonify({'success': True})
    except sqlite3.IntegrityError:
        return jsonify({'error': 'این نام کاربری قبلاً ثبت شده است'}), 400

@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username','').strip().lower()
    password = data.get('password','')

    with get_db() as db:
        user = db.execute('SELECT * FROM users WHERE username=?', (username,)).fetchone()
    if not user or not check_password_hash(user['password'], password):
        return jsonify({'error': 'نام کاربری یا رمز عبور اشتباه است'}), 401

    session['user_id'] = user['id']
    session['username'] = user['username']
    return jsonify({'success': True, 'user': {'id': user['id'], 'username': user['username'],
                    'display_name': user['display_name'], 'avatar_color': user['avatar_color']}})

@app.route('/api/logout', methods=['POST'])
def logout():
    uid = session.get('user_id')
    if uid:
        with get_db() as db:
            db.execute('UPDATE users SET online=0 WHERE id=?', (uid,))
        socketio.emit('user_offline', {'user_id': uid})
    session.clear()
    return jsonify({'success': True})

@app.route('/api/me')
@login_required
def me():
    with get_db() as db:
        user = db.execute('SELECT id,username,display_name,avatar_color FROM users WHERE id=?',
                         (session['user_id'],)).fetchone()
    return jsonify(dict(user))

@app.route('/api/users')
@login_required
def users():
    with get_db() as db:
        rows = db.execute('SELECT id,username,display_name,avatar_color,online FROM users WHERE id!=?',
                         (session['user_id'],)).fetchall()
    return jsonify([dict(r) for r in rows])

@app.route('/api/messages/private/<int:other_id>')
@login_required
def private_messages(other_id):
    me = session['user_id']
    with get_db() as db:
        rows = db.execute('''SELECT m.*,u.display_name,u.avatar_color,u.username 
            FROM messages m JOIN users u ON m.sender_id=u.id
            WHERE msg_type='private' AND (
                (sender_id=? AND receiver_id=?) OR (sender_id=? AND receiver_id=?)
            ) ORDER BY m.created_at ASC''', (me,other_id,other_id,me)).fetchall()
        # mark as read
        db.execute('''UPDATE messages SET read_by=read_by||? 
            WHERE msg_type='private' AND sender_id=? AND receiver_id=? AND read_by NOT LIKE ?''',
            (f',{me}', other_id, me, f'%{me}%'))
    return jsonify([dict(r) for r in rows])

@app.route('/api/messages/public')
@login_required
def public_messages():
    with get_db() as db:
        rows = db.execute('''SELECT m.*,u.display_name,u.avatar_color,u.username 
            FROM messages m JOIN users u ON m.sender_id=u.id
            WHERE msg_type='public' ORDER BY m.created_at ASC LIMIT 200''').fetchall()
    return jsonify([dict(r) for r in rows])

@app.route('/api/messages/group/<int:gid>')
@login_required
def group_messages(gid):
    me = session['user_id']
    with get_db() as db:
        member = db.execute('SELECT 1 FROM group_members WHERE group_id=? AND user_id=?',(gid,me)).fetchone()
        if not member:
            return jsonify({'error': 'دسترسی ندارید'}), 403
        rows = db.execute('''SELECT m.*,u.display_name,u.avatar_color,u.username 
            FROM messages m JOIN users u ON m.sender_id=u.id
            WHERE msg_type='group' AND group_id=? ORDER BY m.created_at ASC LIMIT 200''',(gid,)).fetchall()
    return jsonify([dict(r) for r in rows])

@app.route('/api/groups')
@login_required
def groups():
    with get_db() as db:
        rows = db.execute('''SELECT g.*,COUNT(gm.user_id) as member_count 
            FROM groups g JOIN group_members gm ON g.id=gm.group_id
            WHERE g.id IN (SELECT group_id FROM group_members WHERE user_id=?)
            GROUP BY g.id''', (session['user_id'],)).fetchall()
    return jsonify([dict(r) for r in rows])

@app.route('/api/groups', methods=['POST'])
@login_required
def create_group():
    data = request.json
    name = data.get('name','').strip()
    desc = data.get('description','').strip()
    members = data.get('members', [])

    if not name:
        return jsonify({'error': 'نام گروه الزامی است'}), 400

    color = COLORS[hash(name + str(time.time())) % len(COLORS)]
    me = session['user_id']

    with get_db() as db:
        cur = db.execute('INSERT INTO groups (name,description,creator_id,avatar_color) VALUES (?,?,?,?)',
                        (name, desc, me, color))
        gid = cur.lastrowid
        db.execute('INSERT INTO group_members (group_id,user_id,role) VALUES (?,?,?)', (gid, me, 'admin'))
        for uid in members:
            if uid != me:
                try:
                    db.execute('INSERT INTO group_members (group_id,user_id) VALUES (?,?)', (gid, uid))
                except:
                    pass
        group = db.execute('SELECT * FROM groups WHERE id=?', (gid,)).fetchone()

    return jsonify({'success': True, 'group': dict(group)})

@app.route('/api/groups/<int:gid>/members')
@login_required
def group_members(gid):
    with get_db() as db:
        rows = db.execute('''SELECT u.id,u.username,u.display_name,u.avatar_color,u.online,gm.role
            FROM group_members gm JOIN users u ON gm.user_id=u.id WHERE gm.group_id=?''', (gid,)).fetchall()
    return jsonify([dict(r) for r in rows])

@app.route('/api/groups/<int:gid>/add_member', methods=['POST'])
@login_required
def add_member(gid):
    data = request.json
    uid = data.get('user_id')
    me = session['user_id']
    with get_db() as db:
        role = db.execute('SELECT role FROM group_members WHERE group_id=? AND user_id=?',(gid,me)).fetchone()
        if not role or role['role'] != 'admin':
            return jsonify({'error': 'فقط ادمین می‌تواند عضو اضافه کند'}), 403
        try:
            db.execute('INSERT INTO group_members (group_id,user_id) VALUES (?,?)',(gid,uid))
        except:
            return jsonify({'error': 'کاربر قبلاً عضو است'}), 400
    return jsonify({'success': True})

@app.route('/api/unread')
@login_required
def unread_counts():
    me = session['user_id']
    with get_db() as db:
        rows = db.execute('''SELECT sender_id, COUNT(*) as cnt FROM messages 
            WHERE msg_type='private' AND receiver_id=? AND read_by NOT LIKE ?
            GROUP BY sender_id''', (me, f'%{me}%')).fetchall()
    return jsonify({str(r['sender_id']): r['cnt'] for r in rows})

# SocketIO events
@socketio.on('connect')
def on_connect():
    if 'user_id' in session:
        uid = session['user_id']
        with get_db() as db:
            db.execute('UPDATE users SET online=1 WHERE id=?',(uid,))
        emit('user_online', {'user_id': uid}, broadcast=True)

@socketio.on('disconnect')
def on_disconnect():
    if 'user_id' in session:
        uid = session['user_id']
        with get_db() as db:
            db.execute('UPDATE users SET online=0 WHERE id=?',(uid,))
        emit('user_offline', {'user_id': uid}, broadcast=True)

@socketio.on('join')
def on_join(data):
    room = data.get('room')
    if room:
        join_room(room)

@socketio.on('send_message')
def on_send_message(data):
    if 'user_id' not in session:
        return
    me = session['user_id']
    msg_type = data.get('type','public')
    content = data.get('content','').strip()
    if not content:
        return

    with get_db() as db:
        user = db.execute('SELECT * FROM users WHERE id=?',(me,)).fetchone()
        if msg_type == 'private':
            rid = data.get('receiver_id')
            cur = db.execute('INSERT INTO messages (sender_id,receiver_id,content,msg_type) VALUES (?,?,?,?)',
                           (me, rid, content, 'private'))
            msg_id = cur.lastrowid
            msg = db.execute('SELECT * FROM messages WHERE id=?',(msg_id,)).fetchone()
            payload = {**dict(msg), 'display_name': user['display_name'],
                      'avatar_color': user['avatar_color'], 'username': user['username']}
            room = f'private_{min(me,rid)}_{max(me,rid)}'
            emit('new_message', payload, room=room)

        elif msg_type == 'public':
            cur = db.execute('INSERT INTO messages (sender_id,content,msg_type) VALUES (?,?,?)',
                           (me, content, 'public'))
            msg_id = cur.lastrowid
            msg = db.execute('SELECT * FROM messages WHERE id=?',(msg_id,)).fetchone()
            payload = {**dict(msg), 'display_name': user['display_name'],
                      'avatar_color': user['avatar_color'], 'username': user['username']}
            emit('new_message', payload, room='public', broadcast=True)

        elif msg_type == 'group':
            gid = data.get('group_id')
            member = db.execute('SELECT 1 FROM group_members WHERE group_id=? AND user_id=?',(gid,me)).fetchone()
            if not member:
                return
            cur = db.execute('INSERT INTO messages (sender_id,group_id,content,msg_type) VALUES (?,?,?,?)',
                           (me, gid, content, 'group'))
            msg_id = cur.lastrowid
            msg = db.execute('SELECT * FROM messages WHERE id=?',(msg_id,)).fetchone()
            payload = {**dict(msg), 'display_name': user['display_name'],
                      'avatar_color': user['avatar_color'], 'username': user['username']}
            emit('new_message', payload, room=f'group_{gid}', broadcast=True)

if __name__ == '__main__':
    init_db()
    port = int(os.environ.get('PORT', 5000))
    socketio.run(app, host='0.0.0.0', port=port, debug=False)