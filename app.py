import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import date, datetime
import string

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")

# import special characters
punct = string.punctuation
PUNCT = []
for i in punct:
    PUNCT.append(i)


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    # If user has no stocks
    if not db.execute("SELECT stock, stock_name, shares, share_price, share_total, share_cost, cash FROM shares JOIN users ON users.id = shares.user_id WHERE users.id = ?", session["user_id"]):
        get_cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])
        cash = round(get_cash[0]["cash"], 2)
        return render_template("first.html", cash=cash)

    # if user has stocks
    else:

        # get walltet
        portfolio = db.execute(
            "SELECT stock, stock_name, shares, share_price, share_total, share_cost, cash FROM shares JOIN users ON users.id = shares.user_id WHERE users.id = ?", session["user_id"])

        # update share prices and get new wallet if market has changed
        look = []
        for row in portfolio:
            look.append(lookup(row["stock"]))

        for i in range(len(look)):
            if portfolio[i]["share_price"] != look[i]["price"]:
                look[i]["price"] = round(look[i]["price"], 2)

                db.execute("UPDATE shares SET share_price = ? WHERE user_id = ? AND stock = ?",
                           look[i]["price"], session["user_id"], look[i]["symbol"])

        portfolio = db.execute(
            "SELECT stock, stock_name, shares, share_price, share_total, share_cost, cash FROM shares JOIN users ON users.id = shares.user_id WHERE users.id = ?", session["user_id"])

        # update current funds invested in stocks if market has changed
        shares_total_price = 0
        for i in range(len(portfolio)):
            total = portfolio[i]["shares"] * portfolio[i]["share_price"]
            total = round(total, 2)
            shares_total_price += total
            shares_total_price = round(shares_total_price, 2)

            if portfolio[i]["share_total"] != total:
                db.execute("UPDATE shares SET share_total = ? WHERE user_id = ? AND stock = ?",
                           total, session["user_id"], portfolio[i]["stock"])

        # get cash
        get_cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])
        cash = get_cash[0]["cash"]
        cash = round(cash, 2)

        # calculate total cash invested in stock + cash in wallet
        sum_total = cash + shares_total_price
        sum_total = round(sum_total, 2)

        # calculate balance (gain or loss)
        default_cash = db.execute("SELECT default_cash FROM users WHERE id = ?", session["user_id"])

        if (default_cash[0]["default_cash"]) > sum_total:
            sum_balance = sum_total - (default_cash[0]["default_cash"])
            sum_balance = round(sum_balance, 2)

        else:
            sum_balance = abs((default_cash[0]["default_cash"]) - sum_total)
            sum_balance = round(sum_balance, 2)

        # update portfolio - in order to show most up to date information
        portfolio = db.execute(
            "SELECT stock, stock_name, shares, share_price, share_total, share_cost, cash FROM shares JOIN users ON users.id = shares.user_id WHERE users.id = ? AND shares > 0", session["user_id"])

        return render_template("index.html", portfolio=portfolio, cash=cash, shares_total_price=shares_total_price, sum_total=sum_total, sum_balance=sum_balance)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""

    if request.method == "GET":
        return render_template("buy.html")

    else:

        # check if symbol exists
        symbol = request.form.get("symbol")
        look = lookup(symbol)

        if not symbol or look is None:
            return apology("Please insert a valid symbol", 400)

        # check if shares are valid
        shares = request.form.get("shares")

        if not shares:
            return apology("Please select a number of shares", 400)

        elif shares.isalpha():
            return apology("Shares must be a number", 400)

        for i in shares:
            if i in PUNCT:
                return apology("Please insert a positive number", 400)

        if int(shares) <= 0:
            return apology("Please insert a number higher than 0", 400)

        shares = float(shares)

        # check if user has enough money to make the transaction
        cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])
        total_shares = look["price"] * shares
        if cash[0]["cash"] < (look["price"] * shares):
            return apology("Failed to purchase. Not enough credits", 400)

        # If everything is ok
        # get current time
        time = datetime.now()

        # Insert information about purchase
        cost = look["price"]
        cost = round(cost, 2)
        db.execute("INSERT INTO date (user_id, type, time, shares, stock, stock_name, value) VALUES (?, ?, ?, ?, ?, ?, ?)",
                   session["user_id"], "purchase", time, shares, look["symbol"], look["name"], cost)

        # Check if user has shares of that stock. If they have update share cost to current price. Otherwise add a new share to their wallet.
        share_in_wallet = db.execute(
            "SELECT shares, share_total FROM shares WHERE stock = ? AND user_id = ?",  look["symbol"], session["user_id"])
        if not share_in_wallet:
            db.execute(
                "INSERT INTO shares (user_id, stock, stock_name, shares, share_price, share_total, share_cost) VALUES (?, ?, ?, ?, ?, ?, ?)",
                session["user_id"], look["symbol"], look["name"], shares, cost, total_shares, cost)

        else:
            shares_update = share_in_wallet[0]["shares"] + shares
            shares_total = shares_update * cost
            db.execute("UPDATE shares SET shares = ?, share_total = ?, share_price = ?, share_cost = ? WHERE stock = ? AND user_id = ?",
                       shares_update, shares_total, cost, cost, look["symbol"], session["user_id"])

        # update user's cash
        current_cash = (cash[0]["cash"]) - (look["price"] * shares)
        current_cash = round(current_cash, 2)
        db.execute("UPDATE users SET cash = ? WHERE id = ?", current_cash, session["user_id"])

        # update link table
        date_id = db.execute("SELECT id FROM date WHERE user_id = ? AND time = ? AND type = ? AND stock = ?",
                             session["user_id"], time, "purchase", look["symbol"])

        shares_id = db.execute("SELECT id FROM shares WHERE user_id = ? AND stock = ?",session["user_id"], look["symbol"])

        db.execute("INSERT INTO link (user_id, date_id, shares_id) VALUES (?, ?, ?)",
                   session["user_id"], date_id[0]["id"], shares_id[0]["id"])

        # reedirect to homepage
        return redirect("/")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    # get user's history
    history = db.execute("SELECT stock, stock_name, shares, value, type, time FROM date WHERE user_id = ?", session["user_id"])
    return render_template("history.html", history=history)


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
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
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
    # ask user for stock symbol
    if request.method == "GET":
        return render_template("quoted.html")

    # return the information about that stock
    if request.method == "POST":
        symbol = request.form.get("symbol")
        look = lookup(symbol)

        if not symbol:
            return apology("Please select a stock to search", 400)

        elif look is None:
            return apology("Please search a valid stock", 400)

        for i in symbol:
            if i in string.punctuation:
                return apology("Please search a valid stock", 400)

        return render_template("quote.html", look=look)


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":

        # ask for username, password and confirmation
        username = request.form.get("username")
        password = request.form.get("password")
        password_hash = generate_password_hash(password, method='pbkdf2:sha256', salt_length=8)
        confirmation = request.form.get("confirmation")

        # if no username is given
        if not username:
            return apology("Must create a username", 400)

        # if no password is given
        elif not password:
            return apology("Must create a password", 400)

        # if password and confirmation don't match
        elif confirmation != password:
            return apology("Passwords must match", 400)

        # check if username already exists in database
        row = db.execute("SELECT * FROM users WHERE username = ?", username)

        # if username is not available
        if row:
            return apology("Username already exists", 400)

        # check password rules
        digit = 0
        symbol = 0
        upper = 0
        lower = 0

        for i in password:
            if int(i.isdigit()):
                digit += 1
                continue

            if i.isupper():
                upper += 1
                continue

            if i.islower():
                lower += 1
                continue

            if i in string.punctuation:
                symbol += 1
                continue

        if 0 in {digit, symbol, upper, lower}:
            return apology("Please include one upper case and lower case letter, symbol and digit", 403)

        # insert password
        else:
            db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", username, password_hash)
            return redirect("/")

    else:
        return render_template("register.html")


@app.route("/change", methods=["GET", "POST"])
def change():
    """Register user"""
    if request.method == "POST":

        # ask for username, password and confirmation
        current_password = db.execute("SELECT hash FROM users WHERE id =?", session["user_id"])

        ask_current = request.form.get("password")
        ask_current_hash = check_password_hash(current_password[0]["hash"], ask_current)

        new_password = request.form.get("new_password")
        new_password_hash = generate_password_hash(new_password, method='pbkdf2:sha256', salt_length=8)

        confirmation = request.form.get("confirmation")

        # if no current password is given
        if not request.form.get("password"):
            return apology("Please insert current password", 400)

        # if current password is not correct:
        elif not ask_current_hash:
            return apology("Current password is wrong", 400)

        # if no new password is given
        elif not new_password:
            return apology("Please insert a new password", 400)

         # if no confirmation is given
        elif not confirmation:
            return apology("Please confirm new password", 400)

        # if password and confirmation don't match
        elif not confirmation == new_password:
            return apology("Passwords must match", 400)

        # if new password is same as current:
        elif check_password_hash(current_password[0]["hash"], new_password):
            return apology("New password cannot be the same as current", 400)

        # if doesnt contain digits, one upper case letter, and a symbol
        digit = 0
        symbol = 0
        upper = 0
        lower = 0

        for i in new_password:
            if int(i.isdigit()):
                digit += 1
                continue

            if i.isupper():
                upper += 1
                continue

            if i.islower():
                lower += 1
                continue

            if i in string.punctuation:
                symbol += 1
                continue

        if 0 in {digit, symbol, upper, lower}:
            return apology("Please include one upper case and lower case letter, symbol and digit", 400)

        # update password
        else:
            db.execute("UPDATE users SET hash = ?", new_password_hash)
            return redirect("/")

    else:
        return render_template("change_password.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""

    # get current stocks and shares
    stocks = db.execute("SELECT stock, shares FROM shares WHERE user_id = ? AND shares > 0", session["user_id"])
    if request.method == "GET":
        return render_template("sell.html", stocks=stocks)

    else:

        # create a list of stocks the user owns
        list_stocks = []

        for i in range(len(stocks)):
            list_stocks.append(stocks[i]["stock"])

        # see if stock chose is in dropdown menu or list of own stocks (avoiding hacking)
        get_symbol = request.form.get("symbol")

        if not get_symbol:
            return apology("Please select a stock to sell", 400)

        if get_symbol not in list_stocks:
            return apology("Please select a valid stock", 400)

        # see if number of shares is valid
        get_shares = request.form.get("shares", 400)

        if not get_shares:
            return apology("Please select a number of shares", 400)
        elif get_shares.isalpha():
            return apology("Shares must be a number", 400)

        for i in get_shares:
            if i in PUNCT:
                return apology("Please insert a positive number", 400)

        if int(get_shares) <= 0:
            return apology("Please insert a number higher than 0", 400)

        get_shares = float(get_shares)

        # see if user has quantity he is trying to sell
        shares = db.execute("SELECT id, shares, share_price, share_total FROM shares WHERE user_id = ? AND stock = ?",
                            session["user_id"], get_symbol)

        shares_hold = shares[0]["shares"]

        if shares_hold < get_shares:
            return apology("Number of shares is not currently available on wallet")

        # information about stock
        look = lookup(get_symbol)
        sell_price = look["price"]
        sell_price = round(sell_price, 2)
        name = look["name"]

        # get users cash
        cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])

        # get current time
        time = datetime.now()

        # insert into date table
        db.execute("INSERT INTO date (user_id, time, type, shares, stock, stock_name, value) VALUES (?, ?, ?, ?, ?, ?, ?)",
                   session["user_id"], time, "sell", get_shares, get_symbol, name, sell_price)

        date_id = db.execute("SELECT id FROM date WHERE user_id = ? AND time = ? AND type = ? AND stock = ?",
                             session["user_id"], time, "sell", get_symbol)

        # update database
        shares_delta = shares_hold - get_shares
        shares_total = shares_delta * sell_price

        db.execute("UPDATE shares SET shares = ?, share_total = ?, share_price = ? WHERE user_id = ? AND stock = ?",
                   shares_delta, shares_total, sell_price, session["user_id"], get_symbol)

        # update user's cash
        current_cash = (cash[0]["cash"]) + (sell_price * get_shares)
        db.execute("UPDATE users SET cash = ? WHERE id = ?", current_cash, session["user_id"])

        # update link table
        db.execute("INSERT INTO link (shares_id, user_id, date_id) VALUES (?, ?, ?)", shares[0]["id"],
                   session["user_id"], date_id[0]["id"])

    return redirect("/")


@app.route("/add", methods=["GET", "POST"])
@login_required
def add():
    """Sell shares of stock"""
    if request.method == "GET":
        return render_template("add.html")

    else:
        # see if stock chose is in dropdown menu or list of own stocks (avoiding hacking)
        get_funds = request.form.get("funds")

        if not get_funds:
            return apology("Please select a quantity")

        elif get_funds.isalpha():
            return apology("Funds must be an integer")

        for i in get_funds:
            if i in string.punctuation:
                return apology("Please insert a positive number")

        if int(get_funds) <= 0:
            return apology("Please insert a number higher than 0")

        get_funds = float(get_funds)

        # get users current cash
        cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])
        new_total = cash[0]["cash"] + get_funds
        db.execute("UPDATE users SET cash = ?", new_total)

        return redirect("/")