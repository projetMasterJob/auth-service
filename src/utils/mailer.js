const nodemailer = require('nodemailer');

const transporter = nodemailer.createTransport({
  service: 'gmail', // ou config SMTP personnalisée
  auth: {
    user: process.env.MAIL_USER,
    pass: process.env.MAIL_PASS
  }
});

// Fonction générique d'envoi
exports.sendMail = async (to, subject, html) => {
  return transporter.sendMail({
    from: '"Ton App" <no-reply@tonapp.com>',
    to,
    subject,
    html
  });
};

// Fonction spécialisée (ex: email de validation)
exports.sendValidationEmail = async (to, validationUrl) => {
  const subject = "Valide ton inscription !";
  const html = `<p>Merci de cliquer <a href="${validationUrl}">ici</a> pour activer ton compte.</p>`;
  return exports.sendMail(to, subject, html);
};