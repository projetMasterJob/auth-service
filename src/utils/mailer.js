const mailjet = require('node-mailjet').apiConnect(
  process.env.MJ_APIKEY_PUBLIC,
  process.env.MJ_APIKEY_PRIVATE
);

// Fonction générique pour envoyer un email
exports.sendMail = async (to, subject, html) => {
  return mailjet
    .post('send', { version: 'v3.1' })
    .request({
      Messages: [
        {
          From: {
            Email: process.env.MAIL_USER,
            Name: "JobAzur"
          },
          To: [
            {
              Email: to,
              Name: ""
            }
          ],
          Subject: subject,
          HTMLPart: html
        }
      ]
    });
};

// Envoie de l'email de validation
exports.sendValidationEmail = async (to, validationUrl) => {
  console.log('Sending validation email to:', to);
  const subject = "Valide ton inscription !";
  const html = `<p>Merci de cliquer <a href="${validationUrl}">ici</a> pour activer ton compte.</p>`;
  return exports.sendMail(to, subject, html);
};

// Envoi du mail de reset password
exports.sendResetPasswordEmail = async (to, resetUrl) => {
  const subject = "Réinitialisation de votre mot de passe";
  const html = `
    <p>Vous avez demandé la réinitialisation de votre mot de passe.</p>
    <p>Pour choisir un nouveau mot de passe, cliquez <a href="${resetUrl}">ici</a>.<br>
    Si vous n'avez pas fait cette demande, ignorez cet e-mail.</p>
    <p>Ce lien expirera dans 1 heure.</p>
  `;
  return exports.sendMail(to, subject, html);
};