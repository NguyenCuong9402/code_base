from app.app import create_app
from app.extensions import socketio

app = create_app()
if __name__ == '__main__':
    """
    Main Application
    python manage.py
    """
    app.run(host='0.0.0.0', port=5012)
    socketio.run(app, debug=True)

