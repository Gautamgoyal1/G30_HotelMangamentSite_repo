from flask import Flask, render_template, request , redirect , url_for, flash,session
from flask_sqlalchemy import SQLAlchemy 
import os
from werkzeug.utils import secure_filename
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from datetime import datetime
app = Flask(__name__)
basedir = os.path.abspath(os.path.dirname(__file__))

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + \
    os.path.join(basedir, "app.db") 
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

app.config['SECRET_KEY'] = 'your_secret_key'

db = SQLAlchemy(app)

bcrypt = Bcrypt(app) # Enable password hashing
login_manager = LoginManager() #Initializes the login system
login_manager.init_app(app) #Explicitly binds the LoginManager to the flask app
login_manager.login_view = 'userlogin' #Redirects unauthorized users to the login page

class Userdata(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    phone = db.Column(db.String(200), nullable=False, unique=True)
    password = db.Column(db.String(200), nullable=False)
    confirmpassword = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(200), nullable=False , default='user')

    def set_password(self, password):
        self.password = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password, password)
    

class Property(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    location = db.Column(db.String(100), nullable=False)
    price = db.Column(db.Float, nullable=False)
    rooms_available = db.Column(db.Integer, nullable=False)
    license_number = db.Column(db.String(50), nullable=False)
    image_filename = db.Column(db.String(100), nullable=True)

    


class Admin(db.Model,UserMixin):
    __tablename__ = 'admins'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    email = db.Column(db.String(100), unique=True)
    phone = db.Column(db.String(15), unique=True)
    password = db.Column(db.String(100))

    

    def set_password(self, password):
        self.password = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password, password)
# Create the tables (run this once if you haven't created the DB yet)
# db.create_all()

# Function to check allowed file extensions
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']


@login_manager.user_loader
def load_user(user_id):
    if session.get("role") == "admin":
        return Admin.query.get(int(user_id))
    else:
        return Userdata.query.get(int(user_id))



with app.app_context():
    db.create_all()

@app.route("/usersignup", methods=["GET", "POST"])
def usersignup():
    if request.method == "POST":
        # Getting data from the form
        name = request.form.get("name")
        email = request.form.get("email")
        phone = request.form.get("phone")
        password = request.form.get("password")
        confirmpassword = request.form.get("confirm-password")
        role = request.form.get("role")  # Get the role from the form

        # Check if passwords match
        if password != confirmpassword:
            flash("Passwords do not match!", "danger")
            return redirect(url_for("usersignup"))
        
        # Check if email already exists
        if Userdata.query.filter_by(email=email).first():
            flash("Email already exists!", "danger")
            return redirect(url_for("usersignup"))
        
        # Check if phone already exists
        if Userdata.query.filter_by(phone=phone).first():
            flash("Phone number already registered. Please use a different one.", "danger")
            return redirect(url_for("usersignup"))

        # Create user object based on role
        
        if role == "admin":
            # Create new admin object
            new_admin = Admin(
                name=name,
                email=email,
                phone=phone,
                password=password,
            )
            new_admin.set_password(password)
            db.session.add(new_admin)
            db.session.commit()

            flash("Admin account created successfully!", "success")
            return redirect(url_for("userlogin"))
        else:
            # Create new user object
            new_user = Userdata(
                name=name,
                email=email,
                phone=phone,
                password=password,
                confirmpassword=confirmpassword,
                role=role
            )
            new_user.set_password(password)
            db.session.add(new_user)
            db.session.commit()

            flash("User signed up successfully!", "success")
            return redirect(url_for("userlogin"))

    return render_template('usersignup.html')

@app.route("/userlogin", methods=["GET", "POST"])
def userlogin():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")
        # Check for regular user
        user = Userdata.query.filter_by(email=email).first()
        if user and user.check_password(password):
            login_user(user)
            session["user_id"] = user.id
            session["role"] = "user"  # Store role in session
            flash("Logged in successfully!", "success")
            return redirect(url_for("home"))

        # Check for admin
        admin = Admin.query.filter_by(email=email).first()
        if admin and admin.check_password(password):
            login_user(admin)
            session["user_id"] = admin.id
            session["role"] = "admin"  # Store role in session
            flash("Logged in as admin!", "success")
            return redirect(url_for("admin_dashboard"))

        flash("Invalid credentials!", "danger")
        return redirect(url_for("userlogin"))

    return render_template("userlogin.html")

@app.route('/')
def home():
    return render_template("index.html")


@app.route('/list-property', methods=["GET", "POST"])
@login_required
def list_property():
    # Only allow admins to access this route
    if session.get("role") != "admin":
        flash("You do not have permission to access this page.", "danger")
        return redirect(url_for('userlogin'))

    if request.method == "POST":
        property_name = request.form.get("property-name")
        property_description = request.form.get("property-description")
        property_location = request.form.get("property-location")
        license_number = request.form.get("license-number")
        price = request.form.get("price")
        rooms_available = request.form.get("rooms-available")

        # Handling file upload
        property_image = request.files.get("property-image")
        filename = None
        if property_image:
            filename = secure_filename(property_image.filename)
            property_image.save(os.path.join('static/images', filename))

        # Store the data in the database
        new_property = Property(
            name=property_name,
            description=property_description,
            location=property_location,
            license_number=license_number,
            price=price,
            rooms_available=rooms_available,
            image_filename=filename
        )
        db.session.add(new_property)
        db.session.commit()

        flash("Property listed successfully!", "success")
        return redirect(url_for('admin_dashboard'))

    return render_template('listProperty.html')


@app.route("/privacy")
def privacy():
    return render_template('privacy.html')

@app.route("/about")
def about():
    return render_template('about_us.html')

@app.route("/contact")
def contact():
    return render_template('contact_us.html')
    
@app.route('/properties')
def properties():
    properties_list = Property.query.all()  # Fetch all properties from the database
    return render_template('hotels.html', properties=properties_list)

@app.route('/book/<int:property_id>', methods=["GET", "POST"])
def book_property(property_id):
    property = Property.query.get_or_404(property_id)
    
    if request.method == "POST":
        user_name = request.form.get("user-name")
        user_phone = request.form.get("user-phone")
        user_email = request.form.get("user-email")
        checkin_date = datetime.strptime(request.form['checkin-date'], '%Y-%m-%d')
        checkout_date = datetime.strptime(request.form['checkout-date'], '%Y-%m-%d')
        rooms = int(request.form.get("rooms"))

        # Validation: Check if check-in is before check-out
        if checkin_date >= checkout_date:
            flash("Check-out date must be after check-in date.", "danger")
            return redirect(url_for('book_property', property_id=property.id))

        # Check if enough rooms are available
        if rooms > property.rooms_available:
            flash(f"Only {property.rooms_available} rooms available!", "danger")
            return redirect(url_for('book_property', property_id=property.id))

        # Create a new booking object
        new_booking = Booking(
        user_name=user_name,
        user_phone=user_phone,
        user_email=user_email,
        rooms=rooms,
        property_id=property.id,
        checkin_date=checkin_date,
        checkout_date=checkout_date
    )




        # Save the booking to the database
        db.session.add(new_booking)
        db.session.commit()

        flash("Booking Successful!", "success")
        return redirect(url_for('bookings'))  # Redirect to the user's bookings page

    return render_template('book_property.html', property=property)


@app.route("/admin_dashboard")
def admin_dashboard():
    # Check if the user is logged in and has the "admin" role
    if "role" not in session or session["role"] != "admin":
        flash("You must be an admin to access this page.", "danger")
        return redirect(url_for("userlogin"))
    
    # Admin dashboard logic here
    return render_template("admin_dashboard.html")




@app.route("/dashboard")
def dashboard():
    return render_template("dashboard.html")

@app.route("/list_users")
@login_required
def list_users():
    if session.get("role") != "admin":
        flash("You do not have permission to access this page.", "danger")
        return redirect(url_for("userlogin"))
    
    # If user is an admin, display users
    users = Userdata.query.all()
    return render_template("list_users.html", users=users)



@app.route('/search')
def search_properties():
    location_to_search = request.args.get("location_to_search")
    if location_to_search:
        properties = Property.query.filter(
            Property.location.ilike(f"%{location_to_search}%")
        ).all()
    else:
        properties = []

    return render_template('search_results.html', properties=properties)



# from flask_sqlalchemy import SQLAlchemy
# from datetime import datetime

# db = SQLAlchemy()

class Booking(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_name = db.Column(db.String(100), nullable=False)
    user_phone = db.Column(db.String(15), nullable=False)
    user_email = db.Column(db.String(100), nullable=False)
    property_id = db.Column(db.Integer, db.ForeignKey('property.id'), nullable=False)
    rooms = db.Column(db.Integer, nullable=False)
    checkin_date = db.Column(db.DateTime, nullable=False)   # Use db.DateTime for dates
    checkout_date = db.Column(db.DateTime, nullable=False)  # Use db.DateTime for dates
    booking_date = db.Column(db.DateTime, default=datetime.utcnow)

    property = db.relationship('Property', backref='bookings')

    def __repr__(self):
        return f"Booking('{self.user_name}', '{self.property_id}', '{self.checkin_date}', '{self.checkout_date}')"


with app.app_context():
    db.create_all()



@app.route('/bookings', methods = ["POST","GET"])
@login_required
def bookings():
    bookings_list = Booking.query.all()  
    return render_template('bookings.html', bookings=bookings_list)

@app.route("/delete/<int:id>", methods=["POST", "GET"]) 
def delete_booking(id):
    # Try to get the booking by its ID
    booked = db.session.get(Booking, id)
    
    # Check if the booking exists
    if booked:
        db.session.delete(booked)
        db.session.commit()
        flash("Booking deleted successfully.", "success")
    else:
        flash("Booking not found.", "danger")
    
    # Redirect to the bookings page
    return redirect(url_for('bookings'))






@app.route("/logout")
@login_required
def logout():
    print(f"Before logout: {current_user.is_authenticated}")  # Debugging
    logout_user()  
    session.clear()  
    print(f"After logout: {current_user.is_authenticated}")  # Debugging
    flash("You have been logged out.", "info")
    return redirect(url_for("userlogin"))


@app.route("/forgot_password")
def forgot():
    return render_template("userforgot.html")

@app.route("/delete_profile", methods=["POST", "GET"])
@login_required
def delete_profile():
    # Only allow the logged-in user (whether admin or user) to delete their profile
    if request.method == "POST":
        if session["role"] == "admin" or session["role"] == "user":
            
            # Delete the logged-in user's profile
            db.session.delete(current_user)
            db.session.commit()

            # After deleting the user, log them out and clear the session
            logout_user()
            session.clear()
            flash("Your profile has been deleted successfully.", "success")
            return redirect(url_for("userlogin")) 

    return render_template("delete_profile.html")  

@app.route("/delete_profile_2")
def delete_profile_2():
    return render_template("delete_profile.html")

if __name__ == "__main__":
    app.run(debug=True) 