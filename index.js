const app = require('./src/app');
const dotenv = require('dotenv');
dotenv.config();

const db = require('./src/config/dbConfig');

const PORT = process.env.PORT || 5000;

(async () => {
  try {
    // Test de connexion à la base via le pool exporté
    const connection = await db.getConnection();
    console.log("Connected to MySQL database!");
    connection.release();

    // Si la connexion fonctionne, on lance le serveur
    app.listen(PORT, () => {
      console.log(`Auth service running on port ${PORT}`);
    });
  } catch (err) {
    console.error("Failed to connect to MySQL:", err);
    process.exit(1); // empêche le lancement de l'app si la DB échoue
  }
})();

//utiliser un revserse proxy pour le déploiement