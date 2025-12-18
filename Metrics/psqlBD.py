import psycopg
from psycopg import sql

# Connexion à la base de données
conn = psycopg.connect(
dbname="test",
user="cialson",
password="3913",
host="localhost",
port="5432"
)

# Création d'un curseur pour exécuter des commandes SQL
cur = conn.cursor()

# Exemple : Création d'une table
cur.execute("""
CREATE TABLE IF NOT EXISTS personne (
id SERIAL PRIMARY KEY,
nom VARCHAR(50) NOT NULL,
age INT NOT NULL
);
""")


'''
cur.execute("""
CREATE TABLE IF NOT EXISTS metrix_trame (
time TIMESTAMP PRIMARY KEY,
size INT NOT NULL,
protocole TEXT NOT NULL,
sous_protocole TEXT NOT NULL,
MAC TEXT NOT NULL
);
""")
'''

# Validation des changements
conn.commit()

def read_data():
    
    #Lire des données
    cur.execute("SELECT * FROM personne")
    rows = cur.fetchall()
    for row in rows:
        print(row)

#Insérer des données
cur.execute("INSERT INTO personne (nom, age) VALUES (%s, %s)", ("Alice", 30))
conn.commit()
read_data()

#Mettre à jour des données
cur.execute("UPDATE personne SET age = %s WHERE nom = %s", (31, "Alice"))
conn.commit()
read_data()

#Supprimer des données
#cur.execute("DELETE FROM personne WHERE nom = %s", ("Alice",))
#conn.commit()

#Supprimer une table
#cur.execute("DROP TABLE personne")
#conn.commit()


# Fermeture du curseur et de la connexion
cur.close()
conn.close()
