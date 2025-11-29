
from flask import Flask, request, render_template_string

app = Flask(__name__)
# No CSRF protection is enabled by default in Flask
# This app is vulnerable to CSRF attacks

@app.route('/update_profile', methods=['POST'])
def update_profile():
    username = request.form['username']
    # ... update user profile ...
    return f"Profile for {username} updated."

@app.route('/profile_form')
def profile_form():
    return render_template_string('''
        <form action="/update_profile" method="post">
            <input type="text" name="username" value="new_username">
            <input type="submit" value="Update Profile">
        </form>
    ''')

if __name__ == '__main__':
    app.run()
