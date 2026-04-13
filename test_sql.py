import pyodbc

conn = pyodbc.connect(
    "Driver={ODBC Driver 18 for SQL Server};"
    "Server=tcp:securevault-sqlsrv-gannon.database.windows.net,1433;"
    "Database=securevault-db;"
    "Encrypt=yes;"
    "TrustServerCertificate=no;"
    "Connection Timeout=30;"
    "UID=<SQL_USERNAME>;"
    "PWD=<SQL_PASSWORD>;"
)

cursor = conn.cursor()
cursor.execute("SELECT @@VERSION;")
row = cursor.fetchone()
print("Connected! SQL version:", row[0])
