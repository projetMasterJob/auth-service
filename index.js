const app = require('./src/app');
const dotenv = require('dotenv');
dotenv.config();

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});

//utiliser un revserse proxy pour le déploiement