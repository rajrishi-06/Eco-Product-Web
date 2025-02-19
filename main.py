from flask import Flask, request, render_template, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, joinedload, QueryableAttribute, relationship
from sqlalchemy import Integer, String, Text, Boolean, or_, ForeignKey, Float
from flask_wtf import FlaskForm
from werkzeug.utils import redirect
from wtforms import StringField, TextAreaField, SubmitField, PasswordField, EmailField
from wtforms.fields.simple import BooleanField
from wtforms.validators import DataRequired, Email, Length, Regexp, ValidationError
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import current_user
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user

app = Flask(__name__)
app.config["SECRET_KEY"] = 'uoweb eobqwoir nqeorin oerws'
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///new.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

class Base(DeclarativeBase):
    pass

db = SQLAlchemy(model_class=Base)
db.init_app(app)
login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.init_app(app)

#################################
#          TABLES
#################################
class EcoFriendlyProduct(db.Model):
    __tablename__ = 'eco_friendly_products'

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    traditional_product: Mapped[str] = mapped_column(String(255), nullable=False)
    sustainable_alternative: Mapped[str] = mapped_column(String(255), nullable=False)
    material: Mapped[str] = mapped_column(String(255), nullable=True)
    brand: Mapped[str] = mapped_column(String(255), nullable=True)
    eco_certifications: Mapped[str] = mapped_column(String(255), nullable=True)
    description: Mapped[str] = mapped_column(Text, nullable=True)
    cost: Mapped[float] = mapped_column(Float, nullable=True)  # e.g., product cost in USD
    rating: Mapped[float] = mapped_column(Float, nullable=True)  # e.g., average rating (scale of 1-5)
    img_url: Mapped[str] = mapped_column(String(255), nullable=True)

    # Relationship: One eco-friendly product can be in many cart items.
    cart_items: Mapped[list["Cart"]] = relationship("Cart", back_populates="product", cascade="all, delete-orphan")


class User(db.Model, UserMixin):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(100), unique=True)
    password: Mapped[str] = mapped_column(String(100))
    name: Mapped[str] = mapped_column(String(1000), unique=True)

    # Relationship: One user can have many items in their cart.
    cart_items: Mapped[list["Cart"]] = relationship("Cart", back_populates="user", cascade="all, delete-orphan")
    def __init__(self, name, email, password):
        self.name = name
        self.email = email
        self.password = password


class Cart(db.Model):
    __tablename__ = "cart"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"), nullable=False)
    product_id: Mapped[int] = mapped_column(Integer, ForeignKey("eco_friendly_products.id"), nullable=False)

    # Relationships back to User and EcoFriendlyProduct
    user: Mapped["User"] = relationship("User", back_populates="cart_items")
    product: Mapped["EcoFriendlyProduct"] = relationship("EcoFriendlyProduct", back_populates="cart_items")


with app.app_context():
    db.create_all()

#################################
#          FUNCTIONS
#################################
def hash_password(password):
    hashed_pass = generate_password_hash(
        password=password,
        method="pbkdf2:sha256:600000",
        salt_length=8
    )
    return hashed_pass
def no_whitespace(form, field):
    if " " in field.data:
        raise ValidationError("No spaces allowed in the username.")

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

def get_products_data():
    data = db.session.execute(db.select(EcoFriendlyProduct)).scalars().all()
    return data

#################################
#          FORMS
#################################
class LoginForm(FlaskForm):
    email = EmailField("Email", validators=[DataRequired()])
    password = PasswordField("Password", validators=[
        DataRequired(),
        Length(min=8, message="Password must be at least 8 characters long."),
        Regexp(r'^(?=.*[A-Z]).+$', message="Password must contain at least one uppercase letter.")
    ])
    submit = SubmitField("Log In")

class RegisterForm(FlaskForm):
    name = StringField("Name", validators=[
        DataRequired(),
        Length(min=3, message="Name should have a length of at least 3."),
    ])
    email = EmailField("Email", validators=[DataRequired()])
    password = PasswordField("Password", validators=[
        DataRequired(),
        Length(min=8, message="Password must be at least 8 characters long."),
        Regexp(r'^(?=.*[A-Z]).+$', message="Password must contain at least one uppercase letter.")
    ])
    submit = SubmitField("Sign Up")

#################################
#          SCRAPE
#################################
# this is use to add data into DB from csv file
# import pandas as pd
# df = pd.read_csv("eco_friendly_products_inr.csv")
#
# with app.app_context():
#     for _, row in df.iterrows():  # Loop over each row
#         product = EcoFriendlyProduct(
#             traditional_product=row["Traditional Product"],
#             sustainable_alternative=row["Sustainable Alternative"],
#             material=row["Material"],
#             brand=row["Brand"],
#             eco_certifications=row["Eco-Certifications"],
#             description=row["Description"],
#             cost=float(row["Cost"]),  # Ensure it's a float
#             rating=float(row["Rating"]),  # Ensure it's a float
#             img_url=row["img_url"]  # Assign proper column value
#         )
#         db.session.add(product)
#     db.session.commit()  # Commit all changes after loop



#################################
#          ROUTES
#################################


@app.route('/login', methods=["GET", "POST"])
def login():
    form = LoginForm()
    if request.method == "POST" and form.validate_on_submit():
        user = db.session.execute(db.select(User).where(User.email == form.email.data.lower())).scalar_one_or_none()

        if user and check_password_hash(user.password, form.password.data):
            login_user(user, remember=True)
            return redirect(url_for('home'))
        else:
            flash('Invalid Username or Email or password. Please try again.', 'danger')
    return render_template('login.html', form=form)

@app.route('/register', methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if request.method == "POST" and form.validate_on_submit():
        user_email = form.email.data.strip().lower()
        if db.session.execute(db.select(User).where(User.email == user_email)).scalar_one_or_none():
            flash('Email already exists. Please log in.', 'warning')
            return redirect(url_for('login'))

        hashed_and_salted_password = hash_password(form.password.data)
        new_user = User(
            name=form.name.data,
            email=user_email.lower(),
            password=hashed_and_salted_password
        )
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user, remember=True)
        return redirect(url_for('home'))
    return render_template("register.html", form=form)

@app.route('/')
def home():
    return render_template('home.html' ,products_data=get_products_data())

if __name__ == "__main__":
    app.run(debug=True)