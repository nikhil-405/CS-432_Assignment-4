# Assignment 4


## Structure

- Flask app files in root:
  - `app.py`, `__init__.py`, `routes.py`, `auth.py`, `database.py`, `models.py`, `audit.py`, `config.py`
- UI templates in [templates](templates)
- SQL files in [sql](sql)
- Environment template in [.env.example](.env.example)


## Run

From [assignment 4](.) root:

1. Copy [.env.example](.env.example) to `.env` and set database credentials.
2. Ensure that your MySQL password is correct by changing in ```config.py```.
3. Start the app with:

```powershell
venv\Scripts\activate
python -m app
```

Open:

- `http://127.0.0.1:5000/login`


## Testing the UI

If you want to test the interface, login as an admin or user using the credentials in the ```test_users.txt```



