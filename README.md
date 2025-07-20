# 🚀 Auth API – Documentation

API REST permettant l’inscription, la connexion, la vérification de l’email et la gestion des mots de passe à l'application JobAzur.

---

## 🛣️ Endpoints

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

## ⚠️ Remarques

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

## ✉️ Support

Pour toute question ou problème, contactez l’équipe technique.

---