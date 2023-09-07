from app.app import create_app, socketio

app = create_app()
if __name__ == '__main__':
    """
    Main Application
    python manage.py
    """
    # app.run(host='0.0.0.0', port=5012)
    # socketio.run(app, host='0.0.0.0', port=5000)
    socketio.run(app, host="0.0.0.0", port=5012, debug=True, allow_unsafe_werkzeug=True)