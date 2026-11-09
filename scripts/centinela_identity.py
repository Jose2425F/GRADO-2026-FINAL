"""Persistent identities, revocable sessions and salted scrypt password hashes."""
import hashlib
import hmac
import re
import secrets
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
PUBLIC_USER = ('id','username','name','role','active','created_at','last_login')

def password_hash(password):
    if not isinstance(password,str) or not 8 <= len(password) <= 256:raise ValueError('Usa una contraseña de 8 a 256 caracteres.')
    salt=secrets.token_hex(16)
    return salt+':'+hashlib.scrypt(password.encode(),salt=bytes.fromhex(salt),n=16384,r=8,p=1).hex()

def password_matches(password, encoded):
    if not isinstance(password,str) or len(password)>256:return False
    salt,digest=encoded.split(':')
    return hmac.compare_digest(hashlib.scrypt(password.encode(),salt=bytes.fromhex(salt),n=16384,r=8,p=1).hex(),digest)

class IdentityStore:
    def __init__(self, directory):
        self.directory=Path(directory);self.directory.mkdir(parents=True,exist_ok=True,mode=0o700)
        self.path=self.directory/'accounts.sqlite3'
        with self.connect() as db:
            db.executescript('''
            CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY,username TEXT UNIQUE NOT NULL,name TEXT NOT NULL,password TEXT NOT NULL,role TEXT NOT NULL CHECK(role IN ('admin','auditor')),active INTEGER NOT NULL DEFAULT 1,created_at INTEGER NOT NULL,last_login INTEGER);
            CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY,user_id TEXT NOT NULL,csrf TEXT NOT NULL,expires INTEGER NOT NULL,workspace TEXT);
            CREATE TABLE IF NOT EXISTS attempts(ip TEXT NOT NULL,username TEXT NOT NULL,stamp INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY,actor TEXT,action TEXT NOT NULL,target TEXT,stamp INTEGER NOT NULL);
            ''')
        self.path.chmod(0o600);self.dummy=password_hash(secrets.token_urlsafe(24))
    @contextmanager
    def connect(self):
        db=sqlite3.connect(self.path,timeout=15)
        db.row_factory=sqlite3.Row
        try:
            with db:
                yield db
        finally:
            db.close()
    def users(self):
        with self.connect() as db:return [{k:r[k] for k in PUBLIC_USER} for r in db.execute('SELECT * FROM users ORDER BY created_at,username')]
    def create_user(self,username,name,password,role='auditor',actor=None):
        username=username.strip().lower() if isinstance(username,str) else ''
        if not re.fullmatch(r'[a-z0-9][a-z0-9._-]{2,39}',username):raise ValueError('El usuario debe tener 3–40 caracteres: letras, números, punto, guion o guion bajo.')
        if not isinstance(name,str) or not 2<=len(name.strip())<=80:raise ValueError('Indica un nombre de 2 a 80 caracteres.')
        if role not in ('admin','auditor'):raise ValueError('Rol no válido.')
        encoded=password_hash(password);uid=secrets.token_hex(16)
        try:
            with self.connect() as db:
                db.execute('INSERT INTO users VALUES(?,?,?,?,?,1,?,NULL)',(uid,username,name.strip(),encoded,role,int(time.time())))
                db.execute('INSERT INTO events(actor,action,target,stamp) VALUES(?,?,?,?)',(actor,'user_created',uid,int(time.time())))
        except sqlite3.IntegrityError:raise ValueError('Ese nombre de usuario ya existe.') from None
        return uid
    def login(self,username,password,ip):
        username=username.strip().lower() if isinstance(username,str) else '';now=int(time.time())
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE');db.execute('DELETE FROM attempts WHERE stamp<?',(now-900,))
            count=db.execute('SELECT count(*) FROM attempts WHERE ip=? OR username=?',(ip,username)).fetchone()[0]
            if count>=12:raise ValueError('Demasiados intentos. Vuelve a intentarlo en 15 minutos.')
            db.execute('INSERT INTO attempts VALUES(?,?,?)',(ip,username,now))
            row=db.execute('SELECT * FROM users WHERE username=?',(username,)).fetchone()
        valid=password_matches(password,row['password'] if row else self.dummy)
        if not row or not row['active'] or not valid:raise ValueError('Usuario o contraseña incorrectos.')
        token=secrets.token_urlsafe(32);csrf=secrets.token_urlsafe(32)
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            current=db.execute('SELECT active,password FROM users WHERE id=?',(row['id'],)).fetchone()
            if not current['active'] or current['password']!=row['password']:raise ValueError('Usuario o contraseña incorrectos.')
            db.execute('DELETE FROM attempts WHERE ip=? AND username=?',(ip,username))
            db.execute('DELETE FROM sessions WHERE expires<?',(now,))
            db.execute('INSERT INTO sessions VALUES(?,?,?,?,NULL)',(hashlib.sha256(token.encode()).hexdigest(),row['id'],csrf,now+8*3600))
            db.execute('UPDATE users SET last_login=? WHERE id=?',(now,row['id']))
        return token
    def session(self,token):
        if not token or len(token)>200:return None
        hashed=hashlib.sha256(token.encode()).hexdigest()
        with self.connect() as db:
            row=db.execute('SELECT u.*,s.csrf,s.workspace,s.expires FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token=? AND s.expires>? AND u.active=1',(hashed,int(time.time()))).fetchone()
        if not row:return None
        return {**{k:row[k] for k in PUBLIC_USER},'csrf':row['csrf'],'workspace':row['workspace'],'token_hash':hashed}
    def logout(self,token_hash):
        with self.connect() as db:db.execute('DELETE FROM sessions WHERE token=?',(token_hash,))
    def update_user(self,actor,uid,role,active,password=None):
        if role not in ('admin','auditor') or type(active) is not bool:raise ValueError('Rol o estado inválido.')
        encoded=password_hash(password) if password else None
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE');row=db.execute('SELECT * FROM users WHERE id=?',(uid,)).fetchone()
            if not row:raise ValueError('Usuario no disponible.')
            if uid==actor and (role!='admin' or not active):raise ValueError('No puedes quitarte el acceso de administrador.')
            if row['role']=='admin' and row['active'] and (role!='admin' or not active):
                if db.execute("SELECT count(*) FROM users WHERE role='admin' AND active=1").fetchone()[0]<=1:raise ValueError('Debe existir al menos un administrador activo.')
            db.execute('UPDATE users SET role=?,active=?,password=? WHERE id=?',(role,int(active),encoded or row['password'],uid))
            db.execute('DELETE FROM sessions WHERE user_id=?',(uid,))
            db.execute('INSERT INTO events(actor,action,target,stamp) VALUES(?,?,?,?)',(actor,'user_updated',uid,int(time.time())))
    def change_password(self,user,current,new):
        encoded=password_hash(new)
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE');row=db.execute('SELECT password FROM users WHERE id=?',(user['id'],)).fetchone()
            if not password_matches(current,row['password']):raise ValueError('La contraseña actual no es correcta.')
            db.execute('UPDATE users SET password=? WHERE id=?',(encoded,user['id']))
            db.execute('DELETE FROM sessions WHERE user_id=?',(user['id'],))
    def workspace(self,user,uid):
        if user['role']!='admin':raise ValueError('Acceso reservado al administrador.')
        with self.connect() as db:
            if uid and not db.execute('SELECT id FROM users WHERE id=?',(uid,)).fetchone():raise ValueError('Usuario no disponible.')
            db.execute('UPDATE sessions SET workspace=? WHERE token=?',(uid if uid!=user['id'] else None,user['token_hash']))
