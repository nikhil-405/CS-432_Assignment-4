# Assignment 4


## Structure

- Flask app files in root:
  - `app.py`, `__init__.py`, `routes.py`, `auth.py`, `database.py`, `models.py`, `audit.py`, `config.py`
- UI templates in [templates](templates)
- SQL files in [sql](sql)
- Environment template in [.env.example](.env.example)
- Stress notebook in [module_b_stress_test.ipynb](module_b_stress_test.ipynb)

## Run

From [assignment 4](.) root:

1. Copy [.env.example](.env.example) to `.env` and set database credentials.
2. Start the app with:

```powershell
python app.py
```

Open:

- `http://127.0.0.1:5000/login`

