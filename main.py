import os
from datetime import datetime

from dotenv import load_dotenv
from flask import Flask, render_template, url_for, flash
from flask import request
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user
from flask_login import current_user
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from sqlalchemy import Integer, String, Text, Boolean, ForeignKey, Float, DateTime
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import redirect
from wtforms import StringField, SubmitField, PasswordField, EmailField
from wtforms.validators import DataRequired, Length, Regexp, ValidationError
from supabase import create_client, Client

load_dotenv()

# Initialize Supabase client
supabase: Client = create_client(
    os.getenv("SUPABASE_URL"),
    os.getenv("SUPABASE_ANON_KEY")
)

CATEGORIES_DICT={
            "Personal Care": ["Bamboo Toothbrush", "Shampoo Bar", "Safety Razor"],
            "Writing & Office Supplies": ["Recycled Paper Pens"],
            "Reusable Bottles & Containers": ["Stainless Steel Bottle"],
            "Household Essentials": ["Beeswax Wraps", "Compostable Trash Bags"],
            "Clothing & Accessories": ["Organic Cotton T-Shirts", "Recycled Fabric Bags"],
            "Cleaning & Laundry": ["Eco-Friendly Detergent", "Wool Dryer Balls"],
            "Food & Kitchen": ["Reusable Coffee Filters", "Bamboo Cutlery Set"],
            "Outdoor & Travel": ["Solar-Powered Charger", "Biodegradable Camping Soap"]
        }

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY")
app.config["SQLALCHEMY_DATABASE_URI"] = f"postgresql://postgres.anvcigepojpynciwqvfi:{os.getenv('SUPABASE_DB_PASSWORD')}@aws-0-ap-south-1.pooler.supabase.com:5432/postgres"
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
class Review(db.Model):
    __tablename__ = "reviews"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"), nullable=False)
    product_id: Mapped[int] = mapped_column(Integer, ForeignKey("eco_friendly_products.id"), nullable=False)
    rating: Mapped[float] = mapped_column(Float, nullable=False)  # Rating between 1-5
    review_text: Mapped[str] = mapped_column(Text, nullable=True)  # Optional review text
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)  # Auto timestamp

    # Relationships back to User and EcoFriendlyProduct
    user: Mapped["User"] = relationship("User", back_populates="reviews")
    product: Mapped["EcoFriendlyProduct"] = relationship("EcoFriendlyProduct", back_populates="reviews")

class EcoFriendlyProduct(db.Model):
    __tablename__ = 'eco_friendly_products'

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    traditional_product: Mapped[str] = mapped_column(String(255), nullable=False)
    sustainable_alternative: Mapped[str] = mapped_column(String(255), nullable=False)
    material: Mapped[str] = mapped_column(String(255), nullable=True)
    brand: Mapped[str] = mapped_column(String(255), nullable=True)
    eco_certifications: Mapped[str] = mapped_column(String(255), nullable=True)
    description: Mapped[str] = mapped_column(Text, nullable=True)
    current_price: Mapped[float] = mapped_column(Float, nullable=True)
    old_price: Mapped[float] = mapped_column(Float, nullable=True)
    is_discounted: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    rating: Mapped[float] = mapped_column(Float, nullable=True)  # Overall rating (calculated avg)
    img_url: Mapped[str] = mapped_column(String(255), nullable=True)

    # Relationships
    cart_items: Mapped[list["Cart"]] = relationship("Cart", back_populates="product", cascade="all, delete-orphan")
    wish_items: Mapped[list["WishList"]] = relationship("WishList", back_populates="product", cascade="all, delete-orphan")
    reviews: Mapped[list["Review"]] = relationship("Review", back_populates="product", cascade="all, delete-orphan")  # New

class User(db.Model, UserMixin):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(100), unique=True)
    password: Mapped[str] = mapped_column(String(100))
    name: Mapped[str] = mapped_column(String(1000), unique=True)

    # Relationships
    cart_items: Mapped[list["Cart"]] = relationship("Cart", back_populates="user", cascade="all, delete-orphan")
    wish_items: Mapped[list["WishList"]] = relationship("WishList", back_populates="user", cascade="all, delete-orphan")
    reviews: Mapped[list["Review"]] = relationship("Review", back_populates="user", cascade="all, delete-orphan")  # New

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
def no_whitespace(field):
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

@app.context_processor
def inject_categories():
    return {
        'get_cart_count': get_cart_count,  # Pass function reference
        'categories_dict': CATEGORIES_DICT
    }
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
#          ROUTES
#################################


@app.route('/login', methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
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
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    form = RegisterForm()

    if request.method == "POST" and form.validate_on_submit():
        user_email = form.email.data.strip().lower()
        user_name = form.name.data.strip()

        # Check if email already exists
        if db.session.execute(db.select(User).where(User.email == user_email)).scalar_one_or_none():
            flash('Email already exists. Please log in.', 'warning')
            return redirect(url_for('login'))

        # Check if name already exists
        if db.session.execute(db.select(User).where(User.name == user_name)).scalar_one_or_none():
            flash('Username already taken. Please log in or choose a different name.', 'warning')
            return redirect(url_for('login'))

        hashed_and_salted_password = hash_password(form.password.data)
        new_user = User(
            name=user_name,
            email=user_email,
            password=hashed_and_salted_password
        )
        db.session.add(new_user)
        db.session.commit()

        login_user(new_user, remember=True)
        return redirect(url_for('home'))

    return render_template("register.html", form=form)


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
        flash("Product already added to WishList." , "super_danger")
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
    return render_template("cart.html", cart_items=cart_items)

@app.route('/wishlist')
@login_required
def view_wishlist():
    wishlist_items = current_user.wish_items
    return render_template("wishlist.html", wishlist_items=wishlist_items)

@app.route("/ping")
def ping():
    return render_template("ping.html")

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
        products_data=similar_products  # Pass similar product
    )

from sqlalchemy import or_

@app.route('/', methods=['GET'])
def home():
    search_query = request.args.get('search', '').strip()
    page = request.args.get('page', 1, type=int)
    per_page = 16

    query = db.select(EcoFriendlyProduct)

    if search_query:
        search_terms = search_query.replace(',', ' ').split()  # Split by spaces & commas
        query = query.where(
            or_(
                *[EcoFriendlyProduct.traditional_product.ilike(f"%{term}%") for term in search_terms]
            )
        )

    # Paginate results
    paginated_products = db.paginate(query, page=page, per_page=per_page, error_out=False)

    return render_template(
        'home.html',
        products_data=paginated_products.items,
        search_query=search_query,
        pagination=paginated_products
    )




@app.route('/submit_review/<int:product_id>', methods=['POST'])
@login_required
def submit_review(product_id):
    rating = request.form.get("rating", type=float)
    review_text = request.form.get("review_text", type=str)

    if not (1 <= rating <= 5):
        flash("Invalid rating. Please select a value between 1 and 5.", "danger")
        return redirect(url_for('view_product', product_id=product_id))

    new_review = Review(
        user_id=current_user.id,
        product_id=product_id,
        rating=rating,
        review_text=review_text
    )

    db.session.add(new_review)
    db.session.commit()

    # Optionally, update the product's average rating
    avg_rating = db.session.query(db.func.avg(Review.rating)).filter(Review.product_id == product_id).scalar()
    product = EcoFriendlyProduct.query.get(product_id)
    product.rating = round(avg_rating, 1) if avg_rating else None
    db.session.commit()

    flash("Review submitted successfully!", "success")
    return redirect(url_for('view_product', product_id=product_id))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))