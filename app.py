import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, format_date, login_required, lookup, total_value, usd

# Configure application
app = Flask(__name__)

# Custom filters
app.jinja_env.filters["usd"] = usd
app.jinja_env.filters["total_value"] = total_value
app.jinja_env.filters["format_date"] = format_date

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


# Add username to navbar in each HTML page
@app.context_processor
def inject_username():
    user_id = session.get("user_id")
    if user_id:
        return dict(username=username())
    return dict(username=None)


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    # Query to get the net shares and their total value by symbol
    stocks = db.execute("""
        SELECT symbol, SUM(CASE WHEN type = 'buy' THEN shares ELSE -shares END) AS total_shares,
               unit_price, SUM(CASE WHEN type = 'buy' THEN shares * unit_price ELSE -shares * unit_price END) AS total_value
        FROM purchases
        WHERE user_id = ?
        GROUP BY symbol
        HAVING total_shares > 0;
    """, session["user_id"])

    total = 0
    for stock in stocks:
        total += stock['total_value']

    # Get user's cash balance
    cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0]['cash']

    print(f"Total stock value: {total}")
    print(f"Cash balance: {cash}")
    print(f"Stocks: {stocks}")

    # Calculate grand total (stocks + cash)
    grand_total = total + cash

    return render_template("index.html", username=username(), stocks=stocks, cash=cash, total=grand_total)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":
        quote = lookup(request.form.get("symbol"))
        if quote is None:
            return apology("Stock not found")
        shares = request.form.get("shares")
        if shares is None or shares == '' or not (str(shares).isdigit() and int(shares) > 0):
            return apology("Cannot purchase less than one share")
        price = quote['price']
        purchase = float(price) * int(shares)
        balance = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])
        cash = balance[0]['cash']
        if purchase > float(cash):
            return apology("Insufficient funds")

        db.execute("INSERT INTO purchases (user_id, symbol, shares, unit_price, total_value, type) VALUES(?, ?, ?, ?, ?, ?)",
                   session["user_id"], quote['symbol'], int(shares), float(price), float(purchase), 'buy')
        db.execute("UPDATE users SET cash = cash - ? WHERE id = ?", purchase, session["user_id"])
        return redirect("/")

    return render_template("buy.html")


@app.route("/admin", methods=["GET", "POST"])
@login_required
def change_password():
    """Change user's password"""
    if request.method == "POST":
        current_password = request.form.get("current_password")
        new_password = request.form.get("new_password")
        confirmation = request.form.get("confirmation")

        # Query the database for the user's current hashed password
        rows = db.execute("SELECT hash FROM users WHERE id = ?", session["user_id"])
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], current_password):
            return apology("Incorrect current password")

        # Ensure the new password and confirmation match
        if not new_password or new_password != confirmation:
            return apology("Passwords must match")

        # Hash the new password
        hash_new_password = generate_password_hash(new_password)

        # Update the password in the database
        db.execute("UPDATE users SET hash = ? WHERE id = ?", hash_new_password, session["user_id"])

        # Redirect to a confirmation page or home
        return redirect("/")

    return render_template("admin.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    stocks = db.execute(
        "SELECT symbol, shares, unit_price, total_value, type, timestamp FROM purchases WHERE user_id = ?", session["user_id"])
    return render_template("history.html", stocks=stocks)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""
    # Forget any user_id
    session.clear()
    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)
        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)
        # Query database for username
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )
        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
            return apology("invalid username and/or password", 403)
        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]
        # Redirect user to home page
        return redirect("/")
    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""
    # Forget any user_id
    session.clear()
    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "POST":
        quote = lookup(request.form.get("symbol"))
        if quote is None:
            return apology("Stock not found")
        return render_template("quoted.html", quote=quote, usd=usd)

    return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")
        if username == "":
            return apology("Username cannot be blank")
        if password == "" or confirmation == "":
            return apology("Password cannot be blank")
        if password != confirmation:
            return apology("Passwords do not match")
        hash = generate_password_hash(password)
        try:
            db.execute("INSERT INTO users (username, hash) VALUES(?, ?);", username, hash)
        except:
            return apology("Username already exists")
        return redirect("/")

    return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method == "POST":
        symbol = request.form.get("symbol")
        if not symbol:
            return apology("Must provide stock symbol")

        quote = lookup(symbol)
        if quote is None:
            return apology("Stock not found")

        shares_to_sell = request.form.get("shares")
        if not shares_to_sell or not shares_to_sell.isdigit() or int(shares_to_sell) <= 0:
            return apology("Cannot sell less than one share")

        # Ensure that enough stock is owned
        existing_shares = db.execute(
            "SELECT SUM(shares) AS total_shares FROM purchases WHERE user_id = ? AND symbol = ? GROUP BY symbol",
            session["user_id"], quote['symbol']
        )

        if not existing_shares or existing_shares[0]['total_shares'] is None:
            return apology("You don't own any shares of this stock")
        if int(existing_shares[0]['total_shares']) < int(shares_to_sell):
            return apology("Insufficient stock owned")

        # Calculate sale price
        price = quote['price']
        sell_value = float(price) * int(shares_to_sell)

        # Update shares and cash in the database
        # remaining_shares = int(existing_shares[0]['total_shares']) - int(shares_to_sell)
        db.execute(
            "INSERT INTO purchases (user_id, symbol, shares, unit_price, total_value, type) VALUES(?, ?, ?, ?, ?, ?)",
            session["user_id"], quote['symbol'], int(
                shares_to_sell), float(price), sell_value, 'sell'
        )

        db.execute("UPDATE users SET cash = cash + ? WHERE id = ?", sell_value, session["user_id"])

        return redirect("/")

    current_shares = db.execute(
        "SELECT symbol FROM purchases WHERE user_id = ? GROUP BY symbol", session["user_id"])
    current_number = db.execute(
        "SELECT symbol, SUM(CASE WHEN type = 'buy' THEN shares ELSE 0 END) - SUM(CASE WHEN type = 'sell' THEN shares ELSE 0 END) AS net_shares FROM purchases WHERE user_id = ? GROUP BY symbol", session["user_id"])
    if current_shares and current_number:
        return render_template("sell.html", current_shares=current_shares, current_number=current_number)
    else:
        return render_template("sell.html")


# Helper function
def username():
    """Name of user logged in"""
    user_id = session["user_id"]
    username = db.execute("SELECT username FROM users WHERE id = ?", user_id)[0]['username']
    return username


if __name__ == "__main__":
    app.run()
