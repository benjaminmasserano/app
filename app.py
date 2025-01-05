import pymysql
from flask import Flask, render_template, request, redirect, url_for, flash, g, session, make_response
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import secrets
from datetime import datetime
from datetime import datetime, timedelta  # Asegúrate de importar timedelta
from flask import Flask, render_template, request, redirect, url_for
from flask_login import login_required, current_user
import pytz





app = Flask(__name__)

# Configuración de la base de datos MySQL
db_config = {
    'host': 'bvbommeciv4s5wmrf5nr-mysql.services.clever-cloud.com',
    'user': 'uqespxtiu94xbn2t',
    'password': '5Wd8UQ0uTgg33eKdyfbY',  # Reemplaza con tu contraseña
    'database': 'bvbommeciv4s5wmrf5nr',  # Nombre de la base de datos
}

app.secret_key = '1111'

# Configuración de Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Cargar el usuario
@login_manager.user_loader
def load_user(user_id):
    db = get_db()
    cursor = db.cursor(pymysql.cursors.DictCursor)  # Usar un cursor para ejecutar la consulta
    cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))
    user = cursor.fetchone()
    if user:
        return User(user['id'], user['username'], user['password'], user['role'], user['session_token'])
    return None

class User(UserMixin):
    def __init__(self, id, username, password, role, session_token):
        self.id = id
        self.username = username
        self.password = password
        self.role = role
        self.session_token = session_token

    def get_id(self):
        return str(self.id)

# Función para obtener la conexión a la base de datos MySQL
def get_db():
    if not hasattr(g, 'mysql_db'):
        g.mysql_db = pymysql.connect(**db_config)
    return g.mysql_db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, 'mysql_db', None)
    if db:
        db.close()

# Ruta para la página de login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        db = get_db()
        cursor = db.cursor(pymysql.cursors.DictCursor)  # Usar DictCursor para trabajar con resultados como diccionarios
        cursor.execute('SELECT * FROM users WHERE username = %s', (username,))
        user = cursor.fetchone()

        if user and user['password'] == password:  # Verificar si la contraseña es correcta
            # Generar un nuevo token de sesión
            session_token = secrets.token_hex(16)
            cursor.execute('UPDATE users SET session_token = %s WHERE id = %s', (session_token, user['id']))
            db.commit()

            # Crear el objeto de usuario y agregar el token a la sesión
            user_obj = User(user['id'], user['username'], user['password'], user['role'], session_token)
            login_user(user_obj)

            # Crear una respuesta personalizada para guardar el token en una cookie
            response = make_response(redirect(url_for('index')))
            response.set_cookie('session_token', session_token, httponly=True, secure=True, samesite='Strict')  # Se guarda en cookie

            return response
        else:
            flash("Credenciales incorrectas", 'error')

    return render_template('login.html')  # Mostrar formulario de login

# Validar el token de sesión en cada solicitud
@app.before_request
def validate_session():
    if current_user.is_authenticated:
        db = get_db()
        # Comprobar si el token de la cookie coincide con el de la base de datos
        cookie_token = request.cookies.get('session_token')
        if not cookie_token:
            logout_user()
            session.pop('session_token', None)
            flash("Tu sesión ha expirado o ha sido invalidada.", 'error')
            return redirect(url_for('login'))

        cursor = db.cursor(pymysql.cursors.DictCursor)
        cursor.execute('SELECT session_token FROM users WHERE id = %s', (current_user.id,))
        user = cursor.fetchone()
        if user and user['session_token'] != cookie_token:
            logout_user()
            session.pop('session_token', None)
            flash("Tu sesión ha expirado o ha sido invalidada.", 'error')
            return redirect(url_for('login'))

# Ruta para cerrar sesión
@app.route('/logout')
def logout():
    if current_user.is_authenticated:
        db = get_db()
        cursor = db.cursor()
        cursor.execute('UPDATE users SET session_token = NULL WHERE id = %s', (current_user.id,))
        db.commit()
    
    logout_user()
    session.clear()  # Limpiar toda la sesión
    response = make_response(redirect(url_for('login')))
    # Asegurar que la página de login tampoco se almacene en caché
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, proxy-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'

    # Eliminar cookie de sesión
    response.delete_cookie('session_token')

    return response

# Página de inicio (Despliega solo después de login)
@app.route('/')
@login_required
def index():
    # Asegurarse de que la página no se almacene en caché
    response = make_response(render_template('index.html'))
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, proxy-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response


@app.route('/personas')
@login_required
def personas():
    db = get_db()
    user_id = current_user.id  # Obtener el ID del usuario que ha iniciado sesión

    cursor = db.cursor(pymysql.cursors.DictCursor)  # Crear cursor para obtener resultados como diccionario
    cursor.execute('SELECT * FROM personas WHERE client_id = %s', (user_id,))
    personas = cursor.fetchall()
    return render_template('personas.html', personas=personas)

@app.route('/add_persona', methods=['GET', 'POST'])
@login_required
def add_persona():
    if request.method == 'POST':
        try:
            # Validar los datos ingresados
            nombre = request.form['nombre'].strip()
            apellido = request.form['apellido'].strip()
            mail = request.form['mail'].strip()
            telefono = request.form['telefono'].strip()
            dni = request.form['dni'].strip()

            if not nombre or not apellido or not mail or not telefono or not dni:
                return "Error: Todos los campos son obligatorios.", 400
            if len(dni) < 4:
                return "Error: DNI debe contener al menos 4 caracteres.", 400

            clave_fichaje = dni[-4:]  # Últimos 4 dígitos del DNI
            client_id = current_user.id  # Obtener el ID del usuario que ha iniciado sesión

            # Inserción en la base de datos, incluyendo el client_id
            db = get_db()
            cursor = db.cursor()  # Usar un cursor para ejecutar la consulta
            cursor.execute(
                'INSERT INTO personas (nombre, apellido, mail, telefono, dni, clave_fichaje, client_id) VALUES (%s, %s, %s, %s, %s, %s, %s)',
                (nombre, apellido, mail, telefono, dni, clave_fichaje, client_id)
            )
            db.commit()
            return redirect(url_for('personas'))
        except Exception as e:
            return f"Error al agregar persona: {e}", 500

    return render_template('form_persona.html')

@app.route('/edit_persona/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_persona(id):
    db = get_db()
    user_id = current_user.id  # Obtener el ID del usuario que ha iniciado sesión

    cursor = db.cursor(pymysql.cursors.DictCursor)  # Usar un cursor para obtener el resultado como diccionario
    # Verificar si la persona pertenece al usuario actual
    cursor.execute('SELECT * FROM personas WHERE id_persona = %s AND client_id = %s', (id, user_id))
    persona = cursor.fetchone()
    
    if not persona:
        flash("No tienes permisos para editar esta persona.", "error")
        return redirect(url_for('personas'))

    if request.method == 'POST':
        nuevo_dni = request.form['dni']
        nueva_clave_fichaje = generar_clave_fichaje(nuevo_dni)
        
        cursor.execute(
            '''
            UPDATE personas 
            SET nombre = %s, apellido = %s, mail = %s, telefono = %s, dni = %s, clave_fichaje = %s 
            WHERE id_persona = %s AND client_id = %s
            ''',
            (
                request.form['nombre'], 
                request.form['apellido'], 
                request.form['mail'], 
                request.form['telefono'], 
                nuevo_dni, 
                nueva_clave_fichaje, 
                id,
                user_id
            )
        )
        db.commit()
        return redirect(url_for('personas'))
    
    return render_template('form_persona.html', persona=persona)

@app.route('/delete_persona/<int:id>')
@login_required
def delete_persona(id):
    db = get_db()
    user_id = current_user.id  # Obtener el ID del usuario que ha iniciado sesión

    cursor = db.cursor(pymysql.cursors.DictCursor)  # Usar un cursor para obtener el resultado como diccionario
    # Verificar si la persona pertenece al usuario actual
    cursor.execute('SELECT * FROM personas WHERE id_persona = %s AND client_id = %s', (id, user_id))
    persona = cursor.fetchone()
    if persona:
        cursor.execute('DELETE FROM personas WHERE id_persona = %s AND client_id = %s', (id, user_id))
        db.commit()
    else:
        flash("No tienes permisos para eliminar esta persona.", "error")
    return redirect(url_for('personas'))

def generar_clave_fichaje(dni):
    return f"{dni[-4:]}"



@app.route('/proveedores')
@login_required
def proveedores():
    db = get_db()
    user_id = current_user.id  # Obtener el ID del usuario que ha iniciado sesión
    
    cursor = db.cursor(pymysql.cursors.DictCursor)  # Crear cursor para obtener resultados como diccionario
    cursor.execute('SELECT * FROM proveedores WHERE client_id = %s', (user_id,))
    proveedores = cursor.fetchall()
    
    # Obtener las localidades filtradas por el client_id
    cursor.execute('SELECT DISTINCT localidad FROM proveedores WHERE client_id = %s', (user_id,))
    localidades = [row['localidad'] for row in cursor.fetchall()]
    
    return render_template('proveedores.html', proveedores=proveedores, localidades=localidades)

@app.route('/add_proveedor', methods=['GET', 'POST'])
@login_required
def add_proveedor():
    if request.method == 'POST':
        # Validación de los datos
        nombre = request.form['nombre'].strip()
        telefono = request.form['telefono'].strip()
        mail = request.form['mail'].strip()
        localidad = request.form['localidad'].strip()

        if not nombre or not telefono or not mail or not localidad:
            flash("Todos los campos son obligatorios.", "error")
            return redirect(url_for('add_proveedor'))

        # Validación de correo (opcional)
        if '@' not in mail:
            flash("Correo no válido.", "error")
            return redirect(url_for('add_proveedor'))

        db = get_db()
        client_id = current_user.id  # Obtener el ID del usuario que ha iniciado sesión
        
        # Insertar proveedor con client_id
        cursor = db.cursor()  # Usar un cursor para ejecutar la consulta
        cursor.execute(
            'INSERT INTO proveedores (nombre, telefono, mail, localidad, client_id) VALUES (%s, %s, %s, %s, %s)',
            (nombre, telefono, mail, localidad, client_id)
        )
        db.commit()
        flash("Proveedor agregado con éxito.", "success")
        return redirect(url_for('proveedores'))

    return render_template('form_proveedor.html')

@app.route('/edit_proveedor/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_proveedor(id):
    db = get_db()
    user_id = current_user.id  # Obtener el ID del usuario que ha iniciado sesión

    cursor = db.cursor(pymysql.cursors.DictCursor)  # Usar un cursor para obtener el resultado como diccionario
    # Verificar si el proveedor pertenece al usuario actual
    cursor.execute('SELECT * FROM proveedores WHERE id_proveedor = %s AND client_id = %s', (id, user_id))
    proveedor = cursor.fetchone()
    
    if not proveedor:
        flash("No tienes permisos para editar este proveedor.", "error")
        return redirect(url_for('proveedores'))

    if request.method == 'POST':
        # Validación de los datos
        nombre = request.form['nombre'].strip()
        telefono = request.form['telefono'].strip()
        mail = request.form['mail'].strip()
        localidad = request.form['localidad'].strip()

        if not nombre or not telefono or not mail or not localidad:
            flash("Todos los campos son obligatorios.", "error")
            return redirect(url_for('edit_proveedor', id=id))

        # Validación de correo (opcional)
        if '@' not in mail:
            flash("Correo no válido.", "error")
            return redirect(url_for('edit_proveedor', id=id))

        # Actualizar proveedor
        cursor.execute(
            'UPDATE proveedores SET nombre = %s, telefono = %s, mail = %s, localidad = %s WHERE id_proveedor = %s AND client_id = %s',
            (nombre, telefono, mail, localidad, id, user_id)
        )
        db.commit()
        flash("Proveedor actualizado con éxito.", "success")
        return redirect(url_for('proveedores'))

    return render_template('form_proveedor.html', proveedor=proveedor)

@app.route('/delete_proveedor/<int:id>')
@login_required
def delete_proveedor(id):
    db = get_db()
    user_id = current_user.id  # Obtener el ID del usuario que ha iniciado sesión

    cursor = db.cursor(pymysql.cursors.DictCursor)  # Usar un cursor para obtener el resultado como diccionario
    # Verificar si el proveedor pertenece al usuario actual
    cursor.execute('SELECT * FROM proveedores WHERE id_proveedor = %s AND client_id = %s', (id, user_id))
    proveedor = cursor.fetchone()
    if proveedor:
        cursor.execute('DELETE FROM proveedores WHERE id_proveedor = %s AND client_id = %s', (id, user_id))
        db.commit()
        flash("Proveedor eliminado con éxito.", "success")
    else:
        flash("No tienes permisos para eliminar este proveedor.", "error")
    return redirect(url_for('proveedores'))



@app.route('/mercaderias')
@login_required
def mercaderias():
    db = get_db()
    user_id = current_user.id  # Obtener el ID del usuario que ha iniciado sesión
    
    cursor = db.cursor(pymysql.cursors.DictCursor)  # Crear cursor para obtener resultados como diccionario
    cursor.execute(''' 
        SELECT m.id_mercaderia, m.nombre, m.detalle, m.unidad,
               GROUP_CONCAT(p.nombre, ', ') AS proveedores
        FROM mercaderias m
        LEFT JOIN mercaderias_proveedores mp ON m.id_mercaderia = mp.id_mercaderia
        LEFT JOIN proveedores p ON mp.id_proveedor = p.id_proveedor
        WHERE m.client_id = %s
        GROUP BY m.id_mercaderia
    ''', (user_id,))
    mercaderias = cursor.fetchall()

    return render_template('mercaderias.html', mercaderias=mercaderias)


@app.route('/add_mercaderia', methods=['GET', 'POST'])
@login_required
def add_mercaderia():
    db = get_db()
    if request.method == 'POST':
        # Insertar la mercadería
        mercaderia = {
            'nombre': request.form['nombre'],
            'detalle': request.form['detalle'],
            'unidad': request.form['unidad'],
        }
        user_id = current_user.id  # Obtener el ID del usuario que ha iniciado sesión

        cursor = db.cursor()  # Crear cursor para insertar
        cursor.execute(
            'INSERT INTO mercaderias (nombre, detalle, unidad, client_id) VALUES (%s, %s, %s, %s)',
            (mercaderia['nombre'], mercaderia['detalle'], mercaderia['unidad'], user_id)
        )
        db.commit()

        # Obtener el ID de la mercadería recién creada
        id_mercaderia = cursor.lastrowid

        # Insertar las relaciones con proveedores
        id_proveedores = request.form.getlist('id_proveedores[]')  # Recoge una lista de IDs de proveedores seleccionados
        for id_proveedor in id_proveedores:
            cursor.execute(
                'INSERT INTO mercaderias_proveedores (id_mercaderia, id_proveedor) VALUES (%s, %s)',
                (id_mercaderia, id_proveedor)
            )
        db.commit()

        return redirect(url_for('mercaderias'))

    # Obtener la lista de proveedores para el formulario
    cursor = db.cursor(pymysql.cursors.DictCursor)
    cursor.execute('SELECT id_proveedor, nombre FROM proveedores WHERE client_id = %s', (current_user.id,))
    proveedores = cursor.fetchall()
    return render_template('form_mercaderia.html', proveedores=proveedores)


@app.route('/edit_mercaderia/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_mercaderia(id):
    db = get_db()
    user_id = current_user.id  # Obtener el ID del usuario que ha iniciado sesión

    cursor = db.cursor(pymysql.cursors.DictCursor)
    # Verificar si la mercadería pertenece al usuario actual
    cursor.execute(
        'SELECT * FROM mercaderias WHERE id_mercaderia = %s AND client_id = %s',
        (id, user_id)
    )
    mercaderia = cursor.fetchone()
    if not mercaderia:
        flash("No tienes permisos para editar esta mercadería.", "error")
        return redirect(url_for('mercaderias'))

    if request.method == 'POST':
        # Actualizar la mercadería
        cursor.execute(
            'UPDATE mercaderias SET nombre = %s, detalle = %s, unidad = %s WHERE id_mercaderia = %s AND client_id = %s',
            (request.form['nombre'], request.form['detalle'], request.form['unidad'], id, user_id)
        )
        db.commit()

        # Eliminar las relaciones anteriores
        cursor.execute('DELETE FROM mercaderias_proveedores WHERE id_mercaderia = %s', (id,))
        
        # Insertar las nuevas relaciones con proveedores
        id_proveedores = request.form.getlist('id_proveedores[]')
        for id_proveedor in id_proveedores:
            cursor.execute(
                'INSERT INTO mercaderias_proveedores (id_mercaderia, id_proveedor) VALUES (%s, %s)',
                (id, id_proveedor)
            )
        db.commit()

        return redirect(url_for('mercaderias'))

    # Obtener los proveedores asociados a la mercadería
    cursor.execute(
        'SELECT id_proveedor FROM mercaderias_proveedores WHERE id_mercaderia = %s',
        (id,)
    )
    proveedores_asociados = cursor.fetchall()
    proveedores_asociados = [row['id_proveedor'] for row in proveedores_asociados]

    # Obtener la lista de todos los proveedores del usuario
    cursor.execute('SELECT id_proveedor, nombre FROM proveedores WHERE client_id = %s', (user_id,))
    proveedores = cursor.fetchall()

    return render_template('form_mercaderia.html', mercaderia=mercaderia, proveedores=proveedores, proveedores_asociados=proveedores_asociados)


@app.route('/delete_mercaderia/<int:id>')
@login_required
def delete_mercaderia(id):
    db = get_db()
    user_id = current_user.id  # Obtener el ID del usuario que ha iniciado sesión

    cursor = db.cursor(pymysql.cursors.DictCursor)
    # Verificar si la mercadería pertenece al usuario actual
    cursor.execute(
        'SELECT * FROM mercaderias WHERE id_mercaderia = %s AND client_id = %s',
        (id, user_id)
    )
    mercaderia = cursor.fetchone()
    if mercaderia:
        cursor.execute('DELETE FROM mercaderias WHERE id_mercaderia = %s AND client_id = %s', (id, user_id))
        db.commit()
        flash("Mercadería eliminada con éxito.", "success")
    else:
        flash("No tienes permisos para eliminar esta mercadería.", "error")
    return redirect(url_for('mercaderias'))

@app.route('/almacen', methods=['GET', 'POST'])
def almacen():
    db = get_db()
    user_id = current_user.id  # Obtener el ID del usuario que ha iniciado sesión

    if request.method == 'POST':
        accion = request.form['accion']  # Obtener la acción del formulario (entrada o salida)

        if accion == 'salida':
            # Registrar una salida
            mercaderia_id = request.form['id_mercaderia_salida']
            persona_id = request.form['persona']
            clave_fichaje = request.form['clave_fichaje']
            cantidad_salida = int(request.form['cantidad_salida'])

            # Verificar si la clave de fichaje es válida
            cursor = db.cursor()
            cursor.execute('SELECT * FROM personas WHERE id_persona = %s AND clave_fichaje = %s AND client_id = %s', 
                           (persona_id, clave_fichaje, user_id))
            persona = cursor.fetchone()

            if not persona:
                flash('Clave de fichaje incorrecta o persona no encontrada.', 'error')
                return redirect(url_for('almacen'))

            # Obtener la mercadería seleccionada
            cursor.execute('SELECT * FROM mercaderias WHERE id_mercaderia = %s AND client_id = %s', 
                           (mercaderia_id, user_id))
            mercaderia = cursor.fetchone()

            if not mercaderia:
                flash('Mercadería no encontrada o no pertenece a tu cuenta', 'error')
                return redirect(url_for('almacen'))

            # Usar DictCursor para obtener los resultados como diccionario
            cursor = db.cursor(pymysql.cursors.DictCursor)
            # Obtener la cantidad actual en el almacén
            cursor.execute('SELECT cantidad FROM almacen WHERE id_mercaderia = %s AND client_id = %s', 
                           (mercaderia_id, user_id))
            almacen = cursor.fetchone()

            if almacen:
                # Verificar que haya suficiente cantidad en el almacén
                if almacen['cantidad'] >= cantidad_salida:
                    nueva_cantidad = almacen['cantidad'] - cantidad_salida
                    cursor.execute(''' 
                        UPDATE almacen
                        SET cantidad = %s
                        WHERE id_mercaderia = %s AND client_id = %s
                    ''', (nueva_cantidad, mercaderia_id, user_id))
                    
                    # Registrar el movimiento de salida en la tabla de movimientos_almacen
                    hora_argentina = datetime.utcnow() - timedelta(hours=3)
                    hora_argentina_str = hora_argentina.strftime('%Y-%m-%d %H:%M:%S')

                    cursor.execute(''' 
                        INSERT INTO movimientos_almacen (id_mercaderia, tipo_movimiento, cantidad, id_persona, fecha_hora, client_id)
                        VALUES (%s, %s, %s, %s, %s, %s)
                    ''', (mercaderia_id, 'salida', cantidad_salida, persona_id, hora_argentina_str, user_id))

                    # Actualizar el último movimiento y tipo de movimiento en la tabla almacen
                    cursor.execute(''' 
                        UPDATE almacen
                        SET ultimo_movimiento = %s, tipo_movimiento = %s
                        WHERE id_mercaderia = %s AND client_id = %s
                    ''', (hora_argentina_str, 'salida', mercaderia_id, user_id))

                    db.commit()
                    flash('Salida registrada correctamente', 'success')
                else:
                    flash('No hay suficiente cantidad en el almacén para realizar la salida.', 'error')
            else:
                flash('No se encontró la mercadería en el almacén.', 'error')

        elif accion == 'entrada':
            # Registrar una entrada
            mercaderia_id = request.form['id_mercaderia_entrada']
            persona_id = request.form['persona']
            cantidad_entrada = int(request.form['cantidad_entrada'])

            # Obtener la mercadería seleccionada
            cursor = db.cursor()
            cursor.execute('SELECT * FROM mercaderias WHERE id_mercaderia = %s AND client_id = %s', 
                           (mercaderia_id, user_id))
            mercaderia = cursor.fetchone()

            if not mercaderia:
                flash('Mercadería no encontrada o no pertenece a tu cuenta', 'error')
                return redirect(url_for('almacen'))

            # Usar DictCursor para obtener los resultados como diccionario
            cursor = db.cursor(pymysql.cursors.DictCursor)
            # Obtener la cantidad actual en el almacén
            cursor.execute('SELECT cantidad FROM almacen WHERE id_mercaderia = %s AND client_id = %s', 
                           (mercaderia_id, user_id))
            almacen = cursor.fetchone()

            if almacen:
                # Si ya existe mercadería, sumamos la cantidad de la entrada
                nueva_cantidad = almacen['cantidad'] + cantidad_entrada
                cursor.execute(''' 
                    UPDATE almacen
                    SET cantidad = %s
                    WHERE id_mercaderia = %s AND client_id = %s
                ''', (nueva_cantidad, mercaderia_id, user_id))
            else:
                # Si no existe la mercadería, la agregamos al almacén
                cursor.execute(''' 
                    INSERT INTO almacen (id_mercaderia, cantidad, client_id)
                    VALUES (%s, %s, %s)
                ''', (mercaderia_id, cantidad_entrada, user_id))

            # Registrar el movimiento de entrada en la tabla de movimientos_almacen
            hora_argentina = datetime.utcnow() - timedelta(hours=3)
            hora_argentina_str = hora_argentina.strftime('%Y-%m-%d %H:%M:%S')

            cursor.execute(''' 
                INSERT INTO movimientos_almacen (id_mercaderia, tipo_movimiento, cantidad, id_persona, fecha_hora, client_id)
                VALUES (%s, %s, %s, %s, %s, %s)
            ''', (mercaderia_id, 'entrada', cantidad_entrada, persona_id, hora_argentina_str, user_id))

            # Actualizar el último movimiento y tipo de movimiento en la tabla almacen
            cursor.execute(''' 
                UPDATE almacen
                SET ultimo_movimiento = %s, tipo_movimiento = %s
                WHERE id_mercaderia = %s AND client_id = %s
            ''', (hora_argentina_str, 'entrada', mercaderia_id, user_id))

            db.commit()
            flash('Entrada registrada correctamente', 'success')

        return redirect(url_for('almacen'))

    # Consultar el inventario
    cursor = db.cursor(pymysql.cursors.DictCursor)  # Usar DictCursor para obtener datos como diccionario

    # Obtener inventario
    cursor.execute(
        '''
        SELECT a.*, m.nombre, m.detalle, m.unidad
        FROM almacen a
        JOIN mercaderias m ON a.id_mercaderia = m.id_mercaderia
        WHERE a.cantidad > 0 AND a.client_id = %s
        ''', (user_id,)
    )
    almacen = cursor.fetchall()

    # Obtener personas y mercaderías
    cursor.execute('SELECT id_persona, nombre, apellido FROM personas WHERE client_id = %s', (user_id,))
    personas = cursor.fetchall()

    cursor.execute(
        '''
        SELECT id_mercaderia, nombre
        FROM mercaderias
        WHERE client_id = %s
        ''', (user_id,)
    )
    mercaderias = cursor.fetchall()

    cursor.execute(
        '''
        SELECT m.id_mercaderia, m.nombre
        FROM mercaderias m
        JOIN almacen a ON m.id_mercaderia = a.id_mercaderia
        WHERE a.cantidad > 0 AND a.client_id = %s
        ''', (user_id,)
    )
    mercaderias_en_almacen = cursor.fetchall()

    return render_template('almacen.html', almacen=almacen, personas=personas, mercaderias=mercaderias, mercaderias_en_almacen=mercaderias_en_almacen)



import pymysql.cursors
from datetime import datetime, timedelta
from flask import render_template, request, redirect, url_for, flash
from flask_login import current_user

@app.route('/almacen/edit/<int:id>', methods=['GET', 'POST'])
def edit_almacen(id):
    db = get_db()  # Suponiendo que get_db() devuelve la conexión pymysql
    user_id = current_user.id  # Obtener el ID del usuario que ha iniciado sesión

    # Usar un cursor que devuelva resultados como diccionarios
    cursor = db.cursor()
    cursor.execute(''' 
    SELECT a.*, m.nombre, m.detalle, m.unidad
    FROM almacen a
    JOIN mercaderias m ON a.id_mercaderia = m.id_mercaderia
    WHERE a.id_mercaderia = %s AND a.client_id = %s
    ''', (id, user_id))
    mercaderia = cursor.fetchone()

    if not mercaderia:
        flash('Mercadería no encontrada o no tienes permiso para editarla', 'error')
        return redirect(url_for('almacen'))

    # Obtener la lista de personas asociadas al cliente
    cursor.execute('SELECT id_persona, nombre, apellido FROM personas WHERE client_id = %s', (user_id,))
    personas = cursor.fetchall()

    if request.method == 'POST':
        persona_id = request.form['persona']
        clave_fichaje = request.form['clave_fichaje']

        # Verificar la clave de fichaje
        cursor.execute(''' 
            SELECT * FROM personas WHERE id_persona = %s AND clave_fichaje = %s AND client_id = %s
        ''', (persona_id, clave_fichaje, user_id))
        persona = cursor.fetchone()

        if not persona:
            flash('Clave de fichaje incorrecta o persona no encontrada.', 'error')
            return redirect(url_for('edit_almacen', id=id))

        # Obtener la nueva cantidad desde el formulario
        nueva_cantidad = request.form['cantidad']

        # Validar que la cantidad sea un número positivo
        try:
            nueva_cantidad = int(nueva_cantidad)
            if nueva_cantidad < 0:
                flash('La cantidad no puede ser negativa.', 'error')
                return redirect(url_for('edit_almacen', id=id))
        except ValueError:
            flash('La cantidad debe ser un número válido.', 'error')
            return redirect(url_for('edit_almacen', id=id))

        # Obtener la cantidad actual del almacén
        cantidad_anterior = mercaderia['cantidad']

        # Calcular la diferencia entre la nueva y la anterior cantidad
        diferencia = nueva_cantidad - cantidad_anterior

        # Obtener la hora actual en UTC y restarle 3 horas para ajustarla a Argentina
        hora_argentina = datetime.utcnow() - timedelta(hours=3)
        hora_argentina_str = hora_argentina.strftime('%Y-%m-%d %H:%M:%S')

        # Actualizar la cantidad y tipo de movimiento en la tabla de almacen
        cursor.execute(''' 
            UPDATE almacen
            SET cantidad = %s, ultimo_movimiento = %s, tipo_movimiento = %s
            WHERE id_mercaderia = %s AND client_id = %s
        ''', (nueva_cantidad, hora_argentina_str, 'ajuste', id, user_id))
        db.commit()

        # Registrar el movimiento como ajuste en la tabla de movimientos_almacen
        cursor.execute(''' 
            INSERT INTO movimientos_almacen (id_mercaderia, tipo_movimiento, cantidad, id_persona, fecha_hora, client_id)
            VALUES (%s, %s, %s, %s, %s, %s)
        ''', (id, 'ajuste', diferencia, persona_id, hora_argentina_str, user_id))
        db.commit()

        flash('Cantidad actualizada correctamente y movimiento registrado como ajuste', 'success')
        return redirect(url_for('almacen'))

    # Si no se está haciendo un POST, se pasa la información para autocompletar el formulario
    return render_template('edit_almacen.html', 
                           mercaderia=mercaderia, 
                           personas=personas)






@app.route('/historial_movimientos', methods=['GET', 'POST'])
def historial_movimientos():
    db = get_db()

    # Obtener el ID del usuario que ha iniciado sesión
    user_id = current_user.id

    # Obtener los parámetros de la URL (si existen)
    fecha_inicio = request.args.get('fecha_inicio', '')
    fecha_fin = request.args.get('fecha_fin', '')
    id_mercaderia = request.args.get('id_mercaderia', '')
    id_persona = request.args.get('id_persona', '')  # Filtro por cliente

    # Construir la cláusula WHERE dinámica según los filtros
    query = '''
        SELECT m.nombre AS mercaderia, mo.cantidad, mo.tipo_movimiento, mo.fecha_hora, 
               CONCAT(p.nombre, ' ', p.apellido) AS persona
        FROM movimientos_almacen mo
        JOIN mercaderias m ON mo.id_mercaderia = m.id_mercaderia
        JOIN personas p ON mo.id_persona = p.id_persona
        WHERE mo.client_id = %s  -- Filtrar por el usuario autenticado
    '''
    params = [user_id]  # Filtrar solo por el client_id del usuario actual

    if fecha_inicio:
        query += " AND mo.fecha_hora >= %s"
        params.append(fecha_inicio)
    
    if fecha_fin:
        query += " AND mo.fecha_hora <= %s"
        params.append(fecha_fin)
    
    if id_mercaderia:
        query += " AND mo.id_mercaderia = %s"
        params.append(id_mercaderia)

    if id_persona:
        query += " AND mo.id_persona = %s"
        params.append(id_persona)

    # Agregar orden por fecha_hora en orden descendente
    query += " ORDER BY mo.fecha_hora DESC"

    # Obtener los movimientos filtrados
    cursor = db.cursor()
    cursor.execute(query, tuple(params))  # Usar tuple para pasar correctamente los parámetros
    movimientos = cursor.fetchall()

    print("Movimientos:", movimientos)  # Esto ayudará a ver si los datos están llegando

    return render_template('historial_movimientos.html', movimientos=movimientos)



# Ruta para la gestión de fichajes
@app.route('/gestion_fichaje', methods=['GET', 'POST'])
def gestion_fichaje():
    db = get_db()

    if request.method == 'POST':
        clave_fichaje = request.form.get('clave_fichaje')
        accion = request.form.get('accion')
        hora = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        if not clave_fichaje or not accion:
            return render_template('gestion_fichaje.html', mensaje="Error: Clave de fichaje o acción no proporcionada.")

        # Verificar si la clave_fichaje existe y pertenece al usuario actual
        cursor = db.cursor(pymysql.cursors.DictCursor)  # Usar DictCursor para obtener resultados como diccionario
        cursor.execute('SELECT id_persona FROM personas WHERE clave_fichaje = %s AND client_id = %s', 
                       (clave_fichaje, current_user.id))
        persona = cursor.fetchone()

        if not persona:
            return render_template('gestion_fichaje.html', mensaje="Error: No existe una persona registrada con esa clave de fichaje o no pertenece a tu cuenta.")

        id_persona = persona['id_persona']

        # Verificar el último fichaje de la persona
        cursor.execute(''' 
            SELECT accion FROM historial_fichajes 
            WHERE id_persona = %s 
            ORDER BY hora DESC LIMIT 1
        ''', (id_persona,))
        ultimo_fichaje = cursor.fetchone()

        # Validar lógica de fichaje
        if ultimo_fichaje:
            if accion == 'inicio_turno' and ultimo_fichaje['accion'] == 'inicio_turno':
                return render_template('gestion_fichaje.html', mensaje="Error: Ya se ha registrado una entrada. Debes registrar una salida primero.")
            elif accion == 'fin_turno' and ultimo_fichaje['accion'] == 'fin_turno':
                return render_template('gestion_fichaje.html', mensaje="Error: Ya se ha registrado una salida. Debes registrar una entrada primero.")

        # Registrar el fichaje incluyendo client_id
        try:
            cursor.execute(''' 
                INSERT INTO historial_fichajes (id_persona, accion, hora, client_id) 
                VALUES (%s, %s, %s, %s)
            ''', (id_persona, accion, hora, current_user.id))
            db.commit()
            return render_template('gestion_fichaje.html', mensaje="Fichaje registrado correctamente.")
        except Exception as e:
            db.rollback()
            return render_template('gestion_fichaje.html', mensaje=f"Error al registrar el fichaje: {e}")

    return render_template('gestion_fichaje.html')



# Ruta para el historial de fichajes
@app.route('/historial_fichajes', methods=['GET', 'POST'])
def historial_fichajes():
    db = get_db()

    # Obtener el ID del usuario que ha iniciado sesión
    user_id = current_user.id

    # Obtener los valores del formulario para los filtros
    persona_id = request.form.get('persona')
    fecha = request.form.get('fecha')

    # Construir la consulta base
    query = '''
        SELECT hf.id_persona, p.nombre, hf.accion, hf.hora
        FROM historial_fichajes hf
        JOIN personas p ON hf.id_persona = p.id_persona
        WHERE hf.client_id = %s  -- Filtrar por el usuario autenticado
    '''
    filters = []
    params = [user_id]  # Filtrar solo por el client_id del usuario actual

    if persona_id:
        filters.append("hf.id_persona = %s")
        params.append(persona_id)

    if fecha:
        filters.append("DATE(hf.hora) = %s")
        params.append(fecha)

    if filters:
        query += " AND " + " AND ".join(filters)

    query += " ORDER BY hf.hora DESC"

    # Ejecutar la consulta con los parámetros
    try:
        cursor = db.cursor(pymysql.cursors.DictCursor)  # Usar DictCursor para resultados como diccionarios
        cursor.execute(query, tuple(params))
        historial = cursor.fetchall()
    except Exception as e:
        return render_template('historial_fichaje.html', mensaje=f"Error al cargar el historial: {e}")

    # Obtener la lista de personas para el formulario de filtro
    try:
        cursor.execute("SELECT id_persona, nombre FROM personas WHERE client_id = %s", (user_id,))
        personas = cursor.fetchall()
    except Exception as e:
        personas = []
        return render_template('historial_fichaje.html', mensaje=f"Error al cargar las personas: {e}")

    return render_template('historial_fichaje.html', historial=historial, personas=personas)

@app.route('/gestion_recetas', methods=['GET', 'POST'])
def gestion_recetas():
    db = get_db()
    user_id = current_user.id  # Obtener el ID del usuario que ha iniciado sesión

    # Obtener todas las recetas del usuario
    with db.cursor(pymysql.cursors.DictCursor) as cursor:  # Cambiar a DictCursor
        cursor.execute('SELECT id_receta, nombre FROM recetas WHERE client_id = %s', (user_id,))
        recetas = cursor.fetchall()
        print("Recetas disponibles:", recetas)  # Verifica las recetas que se obtienen

    receta_seleccionada = None
    ingredientes = []

    if request.method == 'POST':
        # Obtener la receta seleccionada
        id_receta = request.form['receta']
        print("ID Receta seleccionada:", id_receta)  # Verifica que el ID se está recibiendo
        
        with db.cursor(pymysql.cursors.DictCursor) as cursor:  # Cambiar a DictCursor
            cursor.execute('SELECT * FROM recetas WHERE id_receta = %s AND client_id = %s', (id_receta, user_id))
            receta_seleccionada = cursor.fetchone()
            print("Receta seleccionada:", receta_seleccionada)  # Verifica la receta seleccionada

        if receta_seleccionada:
            # Obtener los ingredientes de la receta seleccionada
            with db.cursor(pymysql.cursors.DictCursor) as cursor:  # Cambiar a DictCursor
                cursor.execute(''' 
                    SELECT i.nombre, ri.cantidad, ri.unidad 
                    FROM ingredientes i
                    JOIN receta_ingredientes ri ON i.id_ingrediente = ri.id_ingrediente
                    WHERE ri.id_receta = %s AND ri.client_id = %s
                ''', (id_receta, user_id))
                ingredientes = cursor.fetchall()
                print("Ingredientes de la receta:", ingredientes)  # Verifica los ingredientes

    return render_template('gestion_recetas.html', recetas=recetas, receta_seleccionada=receta_seleccionada, ingredientes=ingredientes)


@app.route('/agregar_receta', methods=['GET', 'POST'])
def agregar_receta():
    if request.method == 'POST':
        # Recoger los datos del formulario
        nombre = request.form['nombre']
        instrucciones = request.form['instrucciones']
        user_id = current_user.id  # Obtener el ID del usuario que ha iniciado sesión
        
        db = get_db()

        # Insertar la receta en la tabla 'recetas' con client_id
        with db.cursor() as cursor:
            cursor.execute('INSERT INTO recetas (nombre, instrucciones, client_id) VALUES (%s, %s, %s)', (nombre, instrucciones, user_id))
            db.commit()
        
        # Obtener el id de la receta recién agregada
        with db.cursor() as cursor:
            cursor.execute('SELECT id_receta FROM recetas WHERE nombre = %s AND instrucciones = %s AND client_id = %s', 
                           (nombre, instrucciones, user_id))
            id_receta = cursor.fetchone()[0]  # Acceder por índice, ya que es una tupla
        
        # Insertar los ingredientes y cantidades en la tabla 'receta_ingredientes'
        ingredientes = request.form.getlist('ingrediente[]')
        cantidades = request.form.getlist('cantidad[]')
        unidades = request.form.getlist('unidad[]')
        
        for i in range(len(ingredientes)):
            # Verificar si el ingrediente ya existe, si no, insertarlo
            with db.cursor() as cursor:
                cursor.execute('SELECT id_ingrediente FROM ingredientes WHERE nombre = %s', (ingredientes[i],))
                id_ingrediente = cursor.fetchone()
                if id_ingrediente:
                    id_ingrediente = id_ingrediente[0]  # Acceder por índice
                else:
                    cursor.execute('INSERT INTO ingredientes (nombre) VALUES (%s)', (ingredientes[i],))
                    db.commit()
                    cursor.execute('SELECT id_ingrediente FROM ingredientes WHERE nombre = %s', (ingredientes[i],))
                    id_ingrediente = cursor.fetchone()[0]  # Acceder por índice
            # Insertar en 'receta_ingredientes' con client_id
            with db.cursor() as cursor:
                cursor.execute('INSERT INTO receta_ingredientes (id_receta, id_ingrediente, cantidad, unidad, client_id) VALUES (%s, %s, %s, %s, %s)', 
                               (id_receta, id_ingrediente, cantidades[i], unidades[i], user_id))
                db.commit()

        return redirect(url_for('gestion_recetas'))
    
    return render_template('agregar_receta.html')

@app.route('/editar_receta/<int:id_receta>', methods=['GET', 'POST'])
def editar_receta(id_receta):
    db = get_db()
    user_id = current_user.id  # Obtener el ID del usuario que ha iniciado sesión

    with db.cursor(pymysql.cursors.DictCursor) as cursor:
        cursor.execute('SELECT * FROM recetas WHERE id_receta = %s AND client_id = %s', (id_receta, user_id))
        receta = cursor.fetchone()

    # Obtener los ingredientes relacionados con esta receta
    with db.cursor(pymysql.cursors.DictCursor) as cursor:
        cursor.execute(''' 
            SELECT i.id_ingrediente, i.nombre, ri.cantidad, ri.unidad
            FROM ingredientes i
            JOIN receta_ingredientes ri ON i.id_ingrediente = ri.id_ingrediente
            WHERE ri.id_receta = %s AND ri.client_id = %s
        ''', (id_receta, user_id))
        ingredientes = cursor.fetchall()

    if request.method == 'POST':
        # Actualizar los datos de la receta
        nombre = request.form['nombre']
        instrucciones = request.form['instrucciones']
        
        # Actualizar la receta en la base de datos
        with db.cursor() as cursor:
            cursor.execute('UPDATE recetas SET nombre = %s, instrucciones = %s WHERE id_receta = %s AND client_id = %s', 
                           (nombre, instrucciones, id_receta, user_id))
            db.commit()

        # Eliminar ingredientes existentes para la receta
        with db.cursor() as cursor:
            cursor.execute('DELETE FROM receta_ingredientes WHERE id_receta = %s AND client_id = %s', (id_receta, user_id))
            db.commit()

        # Insertar los nuevos ingredientes
        ingredientes_nuevos = request.form.getlist('ingrediente[]')
        cantidades_nuevas = request.form.getlist('cantidad[]')
        unidades_nuevas = request.form.getlist('unidad[]')

        for i in range(len(ingredientes_nuevos)):
            # Verificar si el ingrediente ya existe
            with db.cursor() as cursor:
                cursor.execute('SELECT id_ingrediente FROM ingredientes WHERE nombre = %s', (ingredientes_nuevos[i],))
                id_ingrediente = cursor.fetchone()
                
                if id_ingrediente is None:
                    cursor.execute('INSERT INTO ingredientes (nombre) VALUES (%s)', (ingredientes_nuevos[i],))
                    db.commit()
                    cursor.execute('SELECT id_ingrediente FROM ingredientes WHERE nombre = %s', (ingredientes_nuevos[i],))
                    id_ingrediente = cursor.fetchone()

                # Acceder a id_ingrediente como tupla y tomar el primer valor
                id_ingrediente = id_ingrediente[0]  # accediendo al primer valor de la tupla

            # Insertar el ingrediente en receta_ingredientes
            with db.cursor() as cursor:
                cursor.execute(''' 
                    INSERT INTO receta_ingredientes (id_receta, id_ingrediente, cantidad, unidad, client_id) 
                    VALUES (%s, %s, %s, %s, %s)
                ''', (id_receta, id_ingrediente, cantidades_nuevas[i], unidades_nuevas[i], user_id))
                db.commit()

        # Redirigir a la página de gestión de recetas después de actualizar
        return redirect(url_for('gestion_recetas'))

    return render_template('editar_receta.html', receta=receta, ingredientes=ingredientes)




@app.route('/heladeras')
def heladeras():
    # Asegúrate de que el usuario esté autenticado
    if not current_user.is_authenticated:
        return redirect(url_for('login'))

    user_id = current_user.id
    db = get_db()
    cursor = db.cursor(pymysql.cursors.DictCursor)  # Usar DictCursor para obtener resultados en formato diccionario
    cursor.execute('SELECT * FROM heladeras WHERE client_id = %s', (user_id,))
    heladeras = cursor.fetchall()
    cursor.close()
    return render_template('heladeras.html', heladeras=heladeras)

@app.route('/temperaturas/<int:id_heladera>', methods=['GET', 'POST'])
def temperaturas(id_heladera):
    if not current_user.is_authenticated:
        return redirect(url_for('login'))

    user_id = current_user.id
    db = get_db()

    # Recupera la heladera correspondiente
    cursor = db.cursor(pymysql.cursors.DictCursor)
    cursor.execute('SELECT * FROM heladeras WHERE id_heladera = %s AND client_id = %s', (id_heladera, user_id))
    heladera = cursor.fetchone()

    if not heladera:
        return redirect(url_for('heladeras'))  # Si no se encuentra la heladera, redirige a la lista de heladeras

    # Si es un POST, registra la temperatura medida
    if request.method == 'POST':
        temperatura_medida = request.form['temperatura_medida']
        fecha_hora = datetime.now().strftime('%Y-%m-%d %H:%M:%S')  # Obtén la fecha y hora actuales en formato adecuado

        # Inserta la nueva temperatura en la base de datos
        cursor.execute(
            'INSERT INTO temperaturas (id_heladera, temperatura_medida, temperatura_objetivo, fecha_hora, client_id) '
            'VALUES (%s, %s, %s, %s, %s)',
            (id_heladera, temperatura_medida, heladera['temperatura_objetivo'], fecha_hora, user_id)
        )
        db.commit()

        # Actualiza la fecha de la última medición en la heladera
        cursor.execute(
            'UPDATE heladeras SET fecha_ultima_medicion = %s WHERE id_heladera = %s AND client_id = %s',
            (fecha_hora, id_heladera, user_id)
        )
        db.commit()

    # Recupera el historial de temperaturas para la heladera, ordenado de más reciente a más antigua
    cursor.execute('SELECT * FROM temperaturas WHERE id_heladera = %s ORDER BY fecha_hora DESC', (id_heladera,))
    temperaturas = cursor.fetchall()

    cursor.close()
    return render_template('temperaturas.html', heladera=heladera, temperaturas=temperaturas)

# Ruta para agregar una nueva heladera
@app.route('/add_heladera', methods=['GET', 'POST'])
def add_heladera():
    if not current_user.is_authenticated:
        return redirect(url_for('login'))

    if request.method == 'POST':
        nombre = request.form['nombre']
        temperatura_objetivo = request.form['temperatura_objetivo']
        user_id = current_user.id

        db = get_db()
        cursor = db.cursor()
        cursor.execute(
            'INSERT INTO heladeras (nombre, temperatura_objetivo, client_id) VALUES (%s, %s, %s)',
            (nombre, temperatura_objetivo, user_id)
        )
        db.commit()
        cursor.close()
        return redirect(url_for('heladeras'))

    return render_template('form_heladera.html')

# Ruta para eliminar una heladera
@app.route('/delete_heladera/<int:id>', methods=['POST'])
def delete_heladera(id):
    if not current_user.is_authenticated:
        return redirect(url_for('login'))

    user_id = current_user.id
    db = get_db()
    cursor = db.cursor(pymysql.cursors.DictCursor)
    cursor.execute('SELECT * FROM heladeras WHERE id_heladera = %s AND client_id = %s', (id, user_id))
    heladera = cursor.fetchone()

    if heladera:
        cursor.execute('DELETE FROM heladeras WHERE id_heladera = %s', (id,))
        db.commit()

    cursor.close()
    return redirect(url_for('heladeras'))

# Ruta para editar una heladera
@app.route('/edit_heladera/<int:id>', methods=['GET', 'POST'])
def edit_heladera(id):
    if not current_user.is_authenticated:
        return redirect(url_for('login'))

    user_id = current_user.id
    db = get_db()
    cursor = db.cursor(pymysql.cursors.DictCursor)
    cursor.execute('SELECT * FROM heladeras WHERE id_heladera = %s AND client_id = %s', (id, user_id))
    heladera = cursor.fetchone()

    if heladera is None:
        return redirect(url_for('heladeras'))

    if request.method == 'POST':
        nombre = request.form['nombre']
        temperatura_objetivo = request.form['temperatura_objetivo']

        cursor.execute(
            '''UPDATE heladeras
               SET nombre = %s, temperatura_objetivo = %s
               WHERE id_heladera = %s AND client_id = %s''',
            (nombre, temperatura_objetivo, id, user_id)
        )
        db.commit()
        cursor.close()
        return redirect(url_for('heladeras'))

    cursor.close()
    return render_template('edit_heladera.html', heladera=heladera)


@app.route('/gestion_pedidos', methods=['GET', 'POST'])
@login_required
def gestion_pedidos():
    db = get_db()
    user_id = current_user.id  # Obtener el id del usuario autenticado

    # Obtener mercaderías y personas asociadas al usuario
    with db.cursor(pymysql.cursors.DictCursor) as cursor:
        cursor.execute(''' 
            SELECT m.id_mercaderia, m.nombre, m.unidad
            FROM mercaderias m
            WHERE m.client_id = %s
        ''', (user_id,))
        mercaderias = cursor.fetchall()

        cursor.execute(''' 
            SELECT id_persona, nombre, apellido FROM personas WHERE client_id = %s
        ''', (user_id,))
        personas = cursor.fetchall()

    # Obtener los proveedores de cada mercadería
    mercaderias_con_proveedores = []
    for mercaderia in mercaderias:
        with db.cursor(pymysql.cursors.DictCursor) as cursor:
            cursor.execute(''' 
                SELECT p.id_proveedor, p.nombre
                FROM proveedores p
                JOIN mercaderias_proveedores mp ON p.id_proveedor = mp.id_proveedor
                WHERE mp.id_mercaderia = %s
            ''', (mercaderia['id_mercaderia'],))
            proveedores = cursor.fetchall()

        mercaderias_con_proveedores.append({
            'mercaderia': mercaderia,
            'proveedores': proveedores
        })

    if request.method == 'POST':
        id_persona = request.form['persona']

        # Crear un nuevo pedido con el client_id
        with db.cursor() as cursor:
            cursor.execute(''' 
                INSERT INTO pedidos (id_persona, fecha, client_id) VALUES (%s, CURRENT_TIMESTAMP, %s)
            ''', (id_persona, user_id))
            db.commit()

        # Obtener el id del pedido recién creado
        with db.cursor() as cursor:
            cursor.execute('SELECT LAST_INSERT_ID()')
            id_pedido = cursor.fetchone()[0]

        # Insertar los detalles del pedido
        for mercaderia in mercaderias_con_proveedores:
            id_mercaderia = mercaderia['mercaderia']['id_mercaderia']
            cantidad = int(request.form.get(f'cantidad_{id_mercaderia}', 0))

            if cantidad > 0:
                id_proveedor = request.form.get(f'proveedor_{id_mercaderia}')
                if id_proveedor:
                    with db.cursor() as cursor:
                        cursor.execute(''' 
                            INSERT INTO detalle_pedidos (id_pedido, id_mercaderia, id_proveedor, cantidad, estado, fecha_pedido)
                            VALUES (%s, %s, %s, %s, %s, CURRENT_TIMESTAMP)
                        ''', (id_pedido, id_mercaderia, id_proveedor, cantidad, 'Pendiente'))
                        db.commit()

        return redirect(url_for('historial_pedidos'))

    return render_template('gestion_pedidos.html', 
                           mercaderias_con_proveedores=mercaderias_con_proveedores, 
                           personas=personas)


@app.route('/historial_pedidos')
@login_required
def historial_pedidos():
    db = get_db()

    # Obtener los pedidos con la persona que lo generó, filtrados por client_id del usuario autenticado
    with db.cursor(pymysql.cursors.DictCursor) as cursor:
        cursor.execute(''' 
            SELECT p.id_pedido, p.fecha, CONCAT(pe.nombre, ' ', pe.apellido) AS persona
            FROM pedidos p
            JOIN personas pe ON p.id_persona = pe.id_persona
            WHERE p.client_id = %s
            ORDER BY p.fecha DESC
        ''', (current_user.id,)) 
        pedidos = cursor.fetchall()

    # Si no hay pedidos, retornar un mensaje
    if not pedidos:
        return render_template('historial_pedidos.html', pedidos=[], mensaje="No hay pedidos disponibles.")

    # Ajustar las fechas a la zona horaria local y calcular el estado de entrega
    local_tz = pytz.timezone('America/Argentina/Buenos_Aires')
    utc_tz = pytz.utc  # Zona horaria UTC

    for pedido in pedidos:
        # Si 'fecha' ya es un objeto datetime, no es necesario convertirla de nuevo con strptime
        if isinstance(pedido['fecha'], datetime):
            # Si ya es un objeto datetime, solo convertimos a la zona horaria correcta
            fecha_pedido_local = pedido['fecha'].astimezone(local_tz)
            pedido['fecha'] = fecha_pedido_local.strftime('%Y-%m-%d %H:%M:%S')  # Formateamos la fecha
        else:
            # Si la fecha es un string, convertirla primero
            fecha_pedido_utc = datetime.strptime(pedido['fecha'], '%Y-%m-%d %H:%M:%S')
            fecha_pedido_utc = utc_tz.localize(fecha_pedido_utc)  # Convertir a UTC
            fecha_pedido_local = fecha_pedido_utc.astimezone(local_tz)  # Convertir a la zona horaria de Buenos Aires

            pedido['fecha'] = fecha_pedido_local.strftime('%Y-%m-%d %H:%M:%S')  # Formateamos la fecha

        # Verificar el estado de entrega del pedido
        with db.cursor() as cursor:
            cursor.execute(''' 
                SELECT estado FROM detalle_pedidos
                WHERE id_pedido = %s
            ''', (pedido['id_pedido'],))
            detalles = cursor.fetchall()

        # Comprobar si todos los detalles están entregados
        if detalles and all(detalle[0] == 'Entregado' for detalle in detalles):  # Corregido a índice 0
            pedido['estado_entrega'] = 'Entregado Completo'
        else:
            pedido['estado_entrega'] = 'Entrega Pendiente'

    # Finalmente, renderizar el template con los pedidos
    return render_template('historial_pedidos.html', pedidos=pedidos)



@app.route('/detalle_pedido/<int:id_pedido>', methods=['GET', 'POST'])
@login_required
def detalle_pedido(id_pedido):
    db = get_db()
    cursor = db.cursor(pymysql.cursors.DictCursor)

    # Verificar que el pedido pertenece al usuario autenticado (filtrado por client_id)
    cursor.execute('SELECT * FROM pedidos WHERE id_pedido = %s AND client_id = %s', (id_pedido, current_user.id))
    pedido = cursor.fetchone()
    if not pedido:
        return "No tienes acceso a este pedido", 403

    if request.method == 'POST':
        # Actualizar el estado de una mercadería a "Entregado"
        id_detalle = request.form['id_detalle']
        cursor.execute(''' 
            UPDATE detalle_pedidos
            SET estado = 'Entregado', fecha_entrega = CURRENT_TIMESTAMP
            WHERE id_detalle = %s AND estado != 'Entregado'
        ''', (id_detalle,))
        db.commit()

    cursor.execute(""" 
        SELECT dp.id_detalle, m.nombre AS mercaderia, dp.cantidad, m.unidad, 
               p.nombre AS proveedor, dp.estado, 
               dp.fecha_pedido, dp.fecha_entrega
        FROM detalle_pedidos dp
        JOIN mercaderias m ON dp.id_mercaderia = m.id_mercaderia
        JOIN proveedores p ON dp.id_proveedor = p.id_proveedor
        WHERE dp.id_pedido = %s
    """, (id_pedido,))

    detalles = cursor.fetchall()

    # Verificar si se recuperaron detalles del pedido
    if not detalles:
        return "No se encontraron detalles para este pedido.", 404

    # Convertir las fechas de pedido y entrega a la zona horaria local
    local_tz = pytz.timezone('America/Argentina/Buenos_Aires')
    for detalle in detalles:
        if detalle['fecha_pedido']:
            fecha_pedido_utc = detalle['fecha_pedido']
            fecha_pedido_local = fecha_pedido_utc.astimezone(local_tz)
            detalle['fecha_pedido'] = fecha_pedido_local.strftime('%Y-%m-%d %H:%M:%S')

        if detalle['fecha_entrega']:
            fecha_entrega_utc = detalle['fecha_entrega']
            fecha_entrega_local = fecha_entrega_utc.astimezone(local_tz)
            detalle['fecha_entrega'] = fecha_entrega_local.strftime('%Y-%m-%d %H:%M:%S')

    # Generar mensajes para cada proveedor
    proveedores = {}
    for detalle in detalles:
        proveedor = detalle['proveedor']
        if proveedor not in proveedores:
            proveedores[proveedor] = []
        proveedores[proveedor].append(detalle)

    mensajes = {}
    for proveedor, items in proveedores.items():
        mensaje = f"Buen día Sr. {proveedor}, le voy a realizar el siguiente pedido:\n"
        for item in items:
            mensaje += f"- {item['mercaderia']} (Cantidad: {item['cantidad']} {item['unidad']})\n"
        mensaje += "Saludos"
        mensajes[proveedor] = mensaje

    return render_template('detalle_pedido.html', detalles=detalles, id_pedido=id_pedido, mensajes=mensajes)

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=True)
