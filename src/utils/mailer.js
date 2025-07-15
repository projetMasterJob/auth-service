const mailjet = require('node-mailjet').apiConnect(
  process.env.MJ_APIKEY_PUBLIC,
  process.env.MJ_APIKEY_PRIVATE
);

exports.sendMail = async (to, subject, html) => {
  return mailjet
    .post('send', { version: 'v3.1' })
    .request({
      Messages: [
        {
          From: {
            Email: process.env.MAIL_USER,
            Name: "Ton App"
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