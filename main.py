from flask import Flask, render_template, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from sqlalchemy import Integer, String, Text, Boolean, ForeignKey, Float
from flask_wtf import FlaskForm
from werkzeug.utils import redirect
from wtforms import StringField, SubmitField, PasswordField, EmailField
from wtforms.validators import DataRequired, Length, Regexp, ValidationError
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import current_user
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user
from flask import request

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
    current_price: Mapped[float] = mapped_column(Float, nullable=True)  # Renamed from cost
    old_price: Mapped[float] = mapped_column(Float, nullable=True)  # New column for old price
    is_discounted: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)  # New boolean column
    rating: Mapped[float] = mapped_column(Float, nullable=True)  # e.g., average rating (scale of 1-5)
    img_url: Mapped[str] = mapped_column(String(255), nullable=True)

    # Relationship: One eco-friendly product can be in many cart items.
    cart_items: Mapped[list["Cart"]] = relationship("Cart", back_populates="product", cascade="all, delete-orphan")
    wish_items: Mapped[list["WishList"]] = relationship("WishList", back_populates="product", cascade="all, delete-orphan")

class User(db.Model, UserMixin):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(100), unique=True)
    password: Mapped[str] = mapped_column(String(100))
    name: Mapped[str] = mapped_column(String(1000), unique=True)

    # Relationship: One user can have many items in their cart and wishlist.
    cart_items: Mapped[list["Cart"]] = relationship("Cart", back_populates="user", cascade="all, delete-orphan")
    wish_items: Mapped[list["WishList"]] = relationship("WishList", back_populates="user", cascade="all, delete-orphan")

    def __init__(self, name, email, password):
        self.name = name
        self.email = email
        self.password = password

class Cart(db.Model):
    __tablename__ = "cart"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"), nullable=False)
    product_id: Mapped[int] = mapped_column(Integer, ForeignKey("eco_friendly_products.id"), nullable=False)
    quantity: Mapped[int] = mapped_column(Integer, nullable=False, default=1)  # New column for quantity

    # Relationships back to User and EcoFriendlyProduct
    user: Mapped["User"] = relationship("User", back_populates="cart_items")
    product: Mapped["EcoFriendlyProduct"] = relationship("EcoFriendlyProduct", back_populates="cart_items")

class WishList(db.Model):
    __tablename__ = "wish"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"), nullable=False)
    product_id: Mapped[int] = mapped_column(Integer, ForeignKey("eco_friendly_products.id"), nullable=False)

    # Relationships back to User and EcoFriendlyProduct
    user: Mapped["User"] = relationship("User", back_populates="wish_items")
    product: Mapped["EcoFriendlyProduct"] = relationship("EcoFriendlyProduct", back_populates="wish_items")

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

def get_cart_count():
    cart_count = 0  # Default value for non-logged-in users
    if current_user.is_authenticated:
        cart_count = db.session.query(db.func.sum(Cart.quantity)).filter(Cart.user_id == current_user.id).scalar() or 0
    return cart_count
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
#          ROUGH
#################################
# this is use to add data into DB from csv file
# import pandas as pd
# df = pd.read_csv("eco_friendly_products_updated.csv")
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
#             old_price=float(row["Old Price"]),
#             current_price=float(row["Current Price"]),
#             is_discounted=row["Is Discounted"],
#             rating=float(row["Rating"]),
#             img_url=row["img_url"]
#         )
#         db.session.add(product)
#     db.session.commit()



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
    return render_template('login.html', form=form, cart_count=get_cart_count())

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
    return render_template("register.html", form=form, cart_count=get_cart_count())

@app.route('/add_to_cart/<int:product_id>', methods=['GET','POST'])
@login_required
def cart_addition(product_id):
    product = db.session.execute(
        db.select(EcoFriendlyProduct).where(EcoFriendlyProduct.id == product_id)
    ).scalar_one_or_none()

    if not product:
        flash("Product not found!", "danger")
        return redirect(url_for('home'))

    try:
        quantity = int(request.args.get('quantity', 1))  # Convert to integer properly
        if quantity < 1:
            flash("Invalid quantity!", "warning")
            return redirect(url_for('home'))
    except (ValueError, TypeError):
        flash("Invalid quantity!", "danger")
        return redirect(url_for('home'))

    existing_cart_item = db.session.execute(
        db.select(Cart).where(
            (Cart.user_id == current_user.id) & (Cart.product_id == product_id)
        )
    ).scalar_one_or_none()

    if existing_cart_item:
        existing_cart_item.quantity += quantity  # Update quantity
        flash(f"Updated item quantity in cart! ({existing_cart_item.quantity})", "info")
    else:
        cart_item = Cart(user_id=current_user.id, product_id=product_id, quantity=quantity)
        db.session.add(cart_item)
        flash(f"Added {quantity} item(s) to cart!", "success")

    db.session.commit()
    return redirect(url_for('home'))


@app.route('/remove_from_cart/<int:product_id>')
@login_required
def cart_deletion(product_id):
    cart_item = db.session.execute(
        db.select(Cart).where(
            (Cart.user_id == current_user.id) & (Cart.product_id == product_id)
        )
    ).scalar_one_or_none()

    if not cart_item:
        flash("Item not found in cart!", "warning")
        return redirect(url_for('home'))

    try:
        quantity = int(request.args.get('quantity', 1))  # Get quantity from URL
        if quantity < 1:
            flash("Invalid quantity!", "warning")
            return redirect(url_for('home'))
    except ValueError:
        flash("Invalid quantity!", "danger")
        return redirect(url_for('home'))

    if cart_item.quantity > quantity:
        cart_item.quantity -= quantity  # Decrease quantity
        flash(f"Removed {quantity} item(s) from cart!", "info")
    else:
        db.session.delete(cart_item)  # Remove item if quantity reaches zero
        flash("Item removed from cart!", "success")

    db.session.commit()
    return redirect(url_for('home'))


@app.route("/wishlist_add/<int:product_id>")
@login_required
def wishlist_addition(product_id):
    product = db.session.execute(
        db.select(EcoFriendlyProduct).where(EcoFriendlyProduct.id == product_id)
    ).scalar_one_or_none()

    if not product:
        flash("Product not found!", "danger")
        return redirect(url_for('home'))

    existing_wishlist_item = db.session.execute(
        db.select(WishList).where(
            (WishList.user_id == current_user.id) & (WishList.product_id == product_id)
        )
    ).scalar_one_or_none()

    if existing_wishlist_item:
        return False
    else:
        wishlist_item = WishList(user_id=current_user.id, product_id=product_id)
        db.session.add(wishlist_item)
        db.session.commit()
    return redirect(url_for('home'))

@app.route('/remove_from_wishlist/<int:product_id>')
@login_required
def wishlist_deletion(product_id):
    wishlist_item = db.session.execute(
        db.select(WishList).where(
            (WishList.user_id == current_user.id) & (WishList.product_id == product_id)
        )
    ).scalar_one_or_none()
    if not wishlist_item:
        flash("Item not found in wishlist!", "warning")
    else:
        db.session.delete(wishlist_item)
        db.session.commit()
        flash("Item removed from wishlist!", "success")
    return redirect(url_for('home'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/cart')
@login_required
def view_cart():
    cart_items = current_user.cart_items
    return render_template("cart.html", cart_items=cart_items, cart_count=get_cart_count())

@app.route('/wishlist')
@login_required
def view_wishlist():
    wishlist_items = current_user.wish_items
    return render_template("wishlist.html", wishlist_items=wishlist_items, cart_count=get_cart_count())


@app.route('/product/<int:product_id>')
def view_product(product_id):
    # Fetch the main product
    product = db.session.execute(
        db.select(EcoFriendlyProduct).where(EcoFriendlyProduct.id == product_id)
    ).scalar_one_or_none()

    # Fetch related products (excluding the current one)
    similar_products = db.session.execute(
        db.select(EcoFriendlyProduct)
        .where(EcoFriendlyProduct.id != product_id)  # Exclude current product
        .order_by(db.func.random())  # Get random products
        .limit(4)  # Limit to 4 similar products
    ).scalars().all()

    return render_template(
        "product.html",
        product=product,
        products_data=similar_products,  # Pass similar products
        cart_count=get_cart_count(),
    )


@app.route('/', methods=['GET'])
def home():
    search_query = request.args.get('search', '').strip()  # Get search query
    page = request.args.get('page', 1, type=int)  # Get page number from URL, default to 1
    per_page = 16  # Number of products per page

    query = db.select(EcoFriendlyProduct)

    # Filter based on search query if provided
    if search_query:
        query = query.filter(EcoFriendlyProduct.traditional_product.ilike(f"%{search_query}%"))

    # Paginate results
    paginated_products = db.paginate(query, page=page, per_page=per_page, error_out=False)

    return render_template(
        'home.html',
        products_data=paginated_products.items,
        cart_count=get_cart_count(),
        search_query=search_query,
        pagination=paginated_products
    )


if __name__ == "__main__":
    app.run(debug=True)