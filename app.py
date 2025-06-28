from flask import Flask, render_template, request, redirect, url_for
import hashlib
import os
import pyodbc
from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad
from flask import session
from datetime import datetime

app = Flask(__name__, template_folder='views')

app.secret_key = os.urandom(24) 

# Kết nối đến SQL Server
def connect_to_db():
    conn = pyodbc.connect('DRIVER={ODBC Driver 17 for SQL Server};'
                          'SERVER=DESKTOP-1TVLSNT;'
                          'DATABASE=Authentication;'
                          'Trusted_Connection=yes')
    return conn

# Hàm băm SHA-256
def hash_sha256(data):
    return hashlib.sha256(data.encode()).hexdigest()

# Hàm mã hóa Triple DES
def encrypt_triple_des(data, key):
    cipher = DES3.new(key, DES3.MODE_CBC)
    padded_data = pad(data.encode(), DES3.block_size)  # Padding dữ liệu
    encrypted = cipher.encrypt(padded_data)
    return cipher.iv + encrypted  # Trả về IV + dữ liệu mã hóa

# Hàm kiểm tra tên đăng nhập có tồn tại hay không
def check_username_exists(username):
    # Băm tên người dùng trước khi kiểm tra
    hashed_username = hash_sha256(username)
    
    conn = connect_to_db()
    cursor = conn.cursor()
    cursor.execute('SELECT COUNT(*) FROM users WHERE username = ?', (hashed_username,))
    count = cursor.fetchone()[0]
    conn.close()
    return count > 0  # Nếu có ít nhất 1 tên đăng nhập trùng, trả về True

# ------ Hàm đăng ký tài khoản -------------
def register_account(username, password):
    # Kiểm tra xem username đã tồn tại trong cơ sở dữ liệu chưa
    if check_username_exists(username):
        return None  # Trả về None nếu tên đăng nhập đã tồn tại

    salt = os.urandom(16)  # Tạo Salt ngẫu nhiên cho người dùng

    # Băm mật khẩu với salt
    hashed_password = hash_sha256(password + salt.hex())
    print(f"mật khẩu đã băm với salt: {hashed_password}")

    # Băm tên người dùng
    hashed_username = hash_sha256(username)
    print(f"tên người dùng đã băm: {hashed_username}") 

    # Kết hợp cả hai giá trị hash và băm lại
    combined_hash = hash_sha256(hashed_password + hashed_username)
    print(f"Kết hợp 2 giá trị (password + username) và : {combined_hash}")

    # Mã hóa kết quả cuối bằng Triple DES
    key = os.urandom(24)  # Tạo khóa 24 bytes cho Triple DES
    cipher = DES3.new(key, DES3.MODE_CBC)
    padded_data = pad(combined_hash.encode(), DES3.block_size)  # Padding dữ liệu
    encrypted_password = cipher.encrypt(padded_data)
    print(f"Encrypted password (Triple DES): {encrypted_password.hex()}")
    
    # Lưu IV và password mã hóa vào cơ sở dữ liệu
    iv = cipher.iv
    print(f"IV: {iv.hex()}")

    # Lưu thông tin vào cơ sở dữ liệu
    conn = connect_to_db()
    cursor = conn.cursor()
    cursor.execute(''' 
    INSERT INTO users (username, salt, encrypted_password, encryption_key, iv, fail_attempts, is_locked, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ''', (hashed_username, salt.hex(), encrypted_password.hex(), key.hex(), iv.hex(), 0, False, datetime.now()))

    conn.commit()
    cursor.close()
    conn.close()

    # Trả về thông tin tài khoản đã đăng ký
    return {
        "username": username,
        "salt": salt.hex(),
        "encrypted_password": encrypted_password.hex(),
        "key": key.hex(),  # Trả về key để sử dụng sau này
        "iv": iv.hex(),  # Trả về IV
        "fail_attempts": 0,
        "is_locked": False
    }


# Hàm ghi log vào file và cơ sở dữ liệu
def log_login_activity(username, login_status):
    # Ghi vào file với encoding utf-8
    with open("login_logs.txt", "a", encoding="utf-8") as log_file:
        log_file.write(f"{datetime.now()} - Username: {username} - Status: {login_status}\n")
    
    # Lưu vào CSDL
    conn = connect_to_db()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO login_logs (username, login_status)
        VALUES (?, ?)
    ''', (username, login_status))
    conn.commit()
    cursor.close()
    conn.close()


# ---------- Hàm đăng nhập ------------
def login_account(username, password):
    if not check_username_exists(username):
        log_login_activity(username, "Tên đăng nhập không tồn tại")
        return "Tên đăng nhập không tồn tại!"

    hashed_username = hash_sha256(username)

    conn = connect_to_db()
    cursor = conn.cursor()
    cursor.execute('SELECT salt, encrypted_password, fail_attempts, is_locked, encryption_key, iv FROM users WHERE username = ?', (hashed_username,))
    result = cursor.fetchone()

    if result is None:
        log_login_activity(username, "Tên người dùng không tồn tại")
        return "Tên người dùng không tồn tại!"

    salt, encrypted_password, fail_attempts, is_locked, stored_key, iv = result

    if is_locked:
        log_login_activity(username, "Tài khoản bị khóa")
        return "Tài khoản bị khóa"

    hashed_password = hash_sha256(password + salt)

    combined_hash = hash_sha256(hashed_password + hashed_username)

    key = bytes.fromhex(stored_key)
    iv = bytes.fromhex(iv)
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    padded_data = pad(combined_hash.encode(), DES3.block_size)
    encrypted_input_password = cipher.encrypt(padded_data)

    if encrypted_input_password.hex() == encrypted_password:
        cursor.execute('UPDATE users SET fail_attempts = 0 WHERE username = ?', (hashed_username,))
        conn.commit()
        cursor.close()
        conn.close()
        session['username'] = username  # Lưu username vào session
        log_login_activity(username, "Thành công")
        return "Đăng nhập thành công"
    else:
        fail_attempts += 1
        if fail_attempts >= 5:
            cursor.execute('UPDATE users SET is_locked = 1 WHERE username = ?', (hashed_username,))
        cursor.execute('UPDATE users SET fail_attempts = ? WHERE username = ?', (fail_attempts, hashed_username))
        conn.commit()
        cursor.close()
        conn.close()
        log_login_activity(username, f"Sai mật khẩu ({fail_attempts}/5)")
        return f"Sai mật khẩu. Bạn còn {5 - fail_attempts} lần thử."

# Kiểm tra quyền truy cập vào trang quản trị
def is_admin():
    return 'username' in session and check_user_role(session['username']) == 'admin'

# Kiểm tra quyền admin
def check_user_role(username):
    hashed_username = hash_sha256(username)
    conn = connect_to_db()
    cursor = conn.cursor()
    cursor.execute('SELECT role FROM users WHERE username = ?', (hashed_username,))
    result = cursor.fetchone()
    conn.close()
    return result[0] if result else None

# Hàm kiểm tra mật khẩu cũ
def check_current_password(username, current_password):
    hashed_username = hash_sha256(username)  # Băm tên người dùng

    # Kết nối cơ sở dữ liệu và kiểm tra mật khẩu cũ
    conn = connect_to_db()
    cursor = conn.cursor()
    cursor.execute('SELECT salt, encrypted_password, encryption_key, iv FROM users WHERE username = ?', (hashed_username,))
    result = cursor.fetchone()

    if result is None:
        cursor.close()
        conn.close()
        return False  # Tên người dùng không tồn tại

    salt, encrypted_password, stored_key, iv = result  # Sửa lại để lấy đủ 4 giá trị

    # Băm mật khẩu cũ nhập vào với salt từ cơ sở dữ liệu
    hashed_password = hash_sha256(current_password + salt)  # Băm mật khẩu cũ với salt

    # Kết hợp băm mật khẩu và tên người dùng để tạo ra giá trị kết hợp
    combined_hash = hash_sha256(hashed_password + hashed_username)

    # Mã hóa kết quả băm cuối bằng Triple DES với key và IV từ CSDL
    key = bytes.fromhex(stored_key)  # Lấy key từ CSDL và chuyển từ hex thành byte
    iv = bytes.fromhex(iv)  # Lấy IV từ CSDL và chuyển từ hex thành byte
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    padded_data = pad(combined_hash.encode(), DES3.block_size)  # Padding dữ liệu
    encrypted_input_password = cipher.encrypt(padded_data)

    if encrypted_input_password.hex() == encrypted_password:
        cursor.close()
        conn.close()
        return True  # Mật khẩu cũ đúng
    else:
        cursor.close()
        conn.close()
        return False  # Mật khẩu cũ sai

# Trang đăng ký
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        # Kiểm tra nếu mật khẩu và nhập lại mật khẩu không khớp
        if password != confirm_password:
            return render_template('register.html', error="Mật khẩu không khớp!")

        # Đăng ký tài khoản
        user_data = register_account(username, password)

        # Kiểm tra nếu username đã tồn tại
        if user_data is None:
            return render_template('register.html', error="Tên đăng nhập đã tồn tại!")

        # Truyền thông tin tài khoản vào trang thành công
        return render_template('register_success.html', user_data=user_data)
    return render_template('register.html')

# Trang thành công khi đăng ký
@app.route('/register_success')
def register_success():
    return '<h1>Đăng ký thành công!</h1>'

# Trang đăng nhập
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        result = login_account(username, password)

        if result is None:
            # Nếu không tìm thấy người dùng, trả về lỗi
            return render_template('login.html', error="Tên đăng nhập không tồn tại!")

        if "Tài khoản bị khóa" in result:
            # Nếu tài khoản bị khóa
            return render_template('login.html', error=result)
        
        if "Đăng nhập thành công" in result:
            # Nếu đăng nhập thành công
            return render_template('welcome.html', username=username)
        
        # Nếu kết quả không phải là các trường hợp trên, hiển thị lỗi
        return render_template('login.html', error=result)

    return render_template('login.html')

@app.route('/change_password', methods=['POST'])
def change_password():
    if 'username' not in session:
        return "Bạn chưa đăng nhập!", 401
    username = session['username']
    current_password = request.form.get('current_password')
    new_password = request.form.get('new_password')
    confirm_password = request.form.get('confirm_password')

    if not username or not current_password or not new_password or not confirm_password:
        return "Dữ liệu không hợp lệ!", 400

    if new_password != confirm_password:
        return "Mật khẩu mới và xác nhận mật khẩu không khớp!", 400

    if not check_current_password(username, current_password):
        return "Mật khẩu cũ không chính xác!", 400

    # --- Bắt đầu cập nhật đúng yêu cầu bảo mật ---
    salt = os.urandom(16)
    hashed_password = hash_sha256(new_password + salt.hex())
    hashed_username = hash_sha256(username)
    combined_hash = hash_sha256(hashed_password + hashed_username)

    key = os.urandom(24)
    cipher = DES3.new(key, DES3.MODE_CBC)
    padded_data = pad(combined_hash.encode(), DES3.block_size)
    encrypted_password = cipher.encrypt(padded_data)
    iv = cipher.iv

    # --- Lưu xuống CSDL ---
    conn = connect_to_db()
    cursor = conn.cursor()
    cursor.execute('''
        UPDATE users 
        SET salt = ?, encrypted_password = ?, encryption_key = ?, iv = ? 
        WHERE username = ?
    ''', (salt.hex(), encrypted_password.hex(), key.hex(), iv.hex(), hashed_username))
    conn.commit()
    cursor.close()
    conn.close()

    return render_template('welcome.html', username=username, message="Đổi mật khẩu thành công!")
def admin_login_account(username, password):
    if not check_username_exists(username):
        return "Tên đăng nhập không tồn tại!"

    hashed_username = hash_sha256(username)
    conn = connect_to_db()
    cursor = conn.cursor()
    cursor.execute('SELECT role, salt, encrypted_password, encryption_key, iv FROM users WHERE username = ?', (hashed_username,))
    result = cursor.fetchone()
    if not result or result[0] != 'admin':
        return "Bạn không có quyền truy cập trang quản trị!"

    # Kiểm tra mật khẩu
    _, salt, encrypted_password, stored_key, iv = result
    hashed_password = hash_sha256(password + salt)
    combined_hash = hash_sha256(hashed_password + hashed_username)
    key = bytes.fromhex(stored_key)
    iv = bytes.fromhex(iv)
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    padded_data = pad(combined_hash.encode(), DES3.block_size)
    encrypted_input_password = cipher.encrypt(padded_data)
    if encrypted_input_password.hex() != encrypted_password:
        return "Sai mật khẩu!"

    session['username'] = username
    return "Đăng nhập thành công"  # Đăng nhập thành công

@app.route('/welcome')
def welcome():
    username = request.args.get('username')
    return render_template('welcome.html', username=username, message="Đổi mật khẩu thành công!")
@app.route('/admin', methods=['GET', 'POST'])
def admin_login():
    # Nếu đã đăng nhập và là admin thì chuyển hướng tới dashboard
    if 'username' in session and check_user_role(session['username']) == 'admin':
        return redirect(url_for('admin_dashboard'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        result = admin_login_account(username, password)

        if "Đăng nhập thành công" in result:
            return redirect(url_for('admin_dashboard'))  # Chuyển hướng đến trang dashboard sau khi đăng nhập thành công
        else:
            return render_template('admin.html', error=result)  # Hiển thị thông báo lỗi

    return render_template('admin.html')  # Hiển thị form đăng nhập admin

# Trang quản trị (admin dashboard)
@app.route('/admin_dashboard')
def admin_dashboard():
    if not is_admin():
        return render_template('admin.html', error="Bạn không có quyền truy cập trang quản trị!")
    message = request.args.get('message')
    conn = connect_to_db()
    cursor = conn.cursor()
    cursor.execute('SELECT username, salt, fail_attempts, is_locked, created_at FROM users')
    users = cursor.fetchall()
    cursor.execute('SELECT username, login_status, timestamp FROM login_logs ORDER BY timestamp DESC')
    logs = cursor.fetchall()
    cursor.close()
    conn.close()
    return render_template('admin_dashboard.html', users=users, logs=logs, message=message)

@app.route('/admin/delete/<username>', methods=['POST'])
def delete_user(username):
    if not is_admin():
        return redirect(url_for('admin'))
    # username ở đây đã là SHA256, không cần băm lại
    conn = connect_to_db()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM users WHERE username = ?', (username,))
    conn.commit()
    cursor.close()
    conn.close()
    return redirect(url_for('admin_dashboard', message="Xóa tài khoản thành công!"))

@app.route('/admin/unlock/<username>', methods=['POST'])
def unlock_user(username):
    if not is_admin():
        return redirect(url_for('admin'))
    # username ở đây đã là SHA256, không cần băm lại
    conn = connect_to_db()
    cursor = conn.cursor()
    cursor.execute('UPDATE users SET is_locked = 0, fail_attempts = 0 WHERE username = ?', (username,))
    conn.commit()
    cursor.close()
    conn.close()
    return redirect(url_for('admin_dashboard', message="Mở khóa tài khoản thành công!"))

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

# Chạy ứng dụng Flask
if __name__ == '__main__':
    app.run(debug=True)
