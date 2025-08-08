web: python -c "import os; port=os.environ.get('PORT', '8080'); os.system(f'gunicorn app:app --bind 0.0.0.0:{port} --workers 2 --threads 4 --timeout 120')"
