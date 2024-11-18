# app.py

from flask import Flask, render_template, jsonify
from extensions import db, migrate
import os

app = Flask(__name__)

# Configure the SQLite database
basedir = os.path.abspath(os.path.dirname(__file__))
db_path = os.path.join(basedir, 'data', 'danger_index.db')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + db_path
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize extensions with app
db.init_app(app)
migrate.init_app(app, db)

# Import models after initializing db to avoid circular imports
from models import Vendor

@app.route('/')
def home():
    """
    Home route that displays the Danger Index table.
    """
    # Query all vendors ordered by danger_score descending
    vendors = Vendor.query.order_by(Vendor.danger_score.desc()).all()

    # Prepare data for the template
    danger_index = []
    for vendor in vendors:
        danger_index.append({
            'name': vendor.name,
            'cve_count': vendor.cve_count,
            'cisa_kev_count': vendor.cisa_kev_count,
            'ransomware_count': vendor.ransomware_count,
            'danger_score': round(vendor.danger_score, 1)  # Rounding to 1 decimal place
        })

    return render_template('base.html', danger_index=danger_index)

if __name__ == '__main__':
    app.run(debug=True, port=7777)  # Adjust port as needed
