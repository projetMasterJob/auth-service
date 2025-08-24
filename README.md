# Auth API – Documentation

API REST permettant l’inscription, la connexion, la vérification de l’email et la gestion des mots de passe à l'application JobAzur.

---

## Installation en local

### 1. Prérequis
- [Node.js](https://nodejs.org/) (version 18 ou supérieure recommandée)
- [npm](https://www.npmjs.com/) ou [yarn](https://yarnpkg.com/)
- Une base de données **PostgreSQL** accessible en local ou distante

### 2. Cloner le projet
git clone <url-du-repo>
cd <nom-du-dossier>

### 3. Installer les dépendances
npm install

### 4. Configuration de l’environnement
Créer un fichier `.env` à la racine du projet avec les variables suivantes :

URL_AUTH=http://localhost:3000
JWT_REFRESH_SECRET=your_refresh_secret
JWT_SECRET=your_jwt_secret
DB_HOST=localhost
DB_USER=your_db_user
DB_PASSWORD=your_db_password
DB_NAME=your_db_name
DB_PORT=5432
PORT=3000
MJ_APIKEY_PUBLIC=your_mailjet_public_key
MJ_APIKEY_PRIVATE=your_mailjet_private_key


**Attention** : ne jamais commiter ce fichier `.env` dans le dépôt Git.

### 5. Lancer le service
npm start

Le service est alors disponible sur [http://localhost:3000/api/auth](http://localhost:3000/api/auth).

---

## Endpoints

### 1. Inscription

- **URL** : `/api/auth/register`
- **Méthode** : `POST`
- **Corps attendu (JSON)** :
    ```json
    {
      "first_name": "John",
      "last_name": "Doe",
      "email": "john.doe@example.com",
      "password": "MonSuperMotDePasse123!",
      "address": "123 Rue Exemple",
      "phone": "0601020304",
      "role": "user"
    }
    ```
- **Réponse (201)** :
    ```json
    {
      "message": "User registered successfully"
    }
    ```

---

### 2. Connexion

- **URL** : `/api/auth/login`
- **Méthode** : `POST`
- **Corps attendu (JSON)** :
    ```json
    {
      "email": "john.doe@example.com",
      "password": "MonSuperMotDePasse123!"
    }
    ```
- **Réponse (200)** :
    ```json
    {
      "token": "jwt_token",
      "user": { /* infos utilisateur */ }
    }
    ```

---

### 3. Vérification de l’email

- **URL** : `/api/auth/verify-email`
- **Méthode** : `GET`
- **Paramètres query** :
    - `token` : jeton de vérification envoyé par mail
- **Réponse (200)** :
    ```json
    {
      "message": "Email verified successfully"
    }
    ```

---

### 4. Demande de réinitialisation du mot de passe

- **URL** : `/api/auth/request-password`
- **Méthode** : `POST`
- **Corps attendu (JSON)** :
    ```json
    {
      "email": "john.doe@example.com"
    }
    ```
- **Réponse (200)** :
    ```json
    {
      "message": "Password reset email sent"
    }
    ```

---

### 5. Réinitialisation du mot de passe

- **URL** : `/api/auth/reset-password`
- **Méthode** : `POST`
- **Corps attendu (JSON)** :
    ```json
    {
      "token": "reset_token",
      "newPassword": "NouveauMotDePasse!234"
    }
    ```
- **Réponse (200)** :
    ```json
    {
      "message": "Password reset successfully"
    }
    ```

---

### 6. Rafraîchissement du token

- **URL** : `/api/auth/refresh-token`  
- **Méthode** : `POST`  
- **Corps attendu (JSON)** :
    ```json
    {
      "token": "refresh_token"
    }
- **Réponse (200)** :
    ```json
    {
      "accessToken": "nouveau_jwt_token",
      "refreshToken": "nouveau_refresh_token"
    }
- **Erreurs possibles** :
    ```json
    {
      "error": "Invalid refresh token"
    }
- **Ou**
    ```json
    {
      "error": "RefreshExpired"
    }



## Remarques

- Toutes les routes sont préfixées par `/api/auth/`.
- Les mots de passe doivent respecter la politique de sécurité (longueur, complexité).
- Toutes les réponses sont au format JSON.
- En cas d’erreur :
    ```json
    {
      "message": "Description de l'erreur"
    }
    ```

---

## Support

Pour toute question ou problème, contactez l’équipe technique.

---