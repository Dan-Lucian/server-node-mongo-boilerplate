const nodemailer = require('nodemailer');

module.exports = sendEmail;

const configMail = {
  emailFrom: 'tomas.morar95@ethereal.email',
  smtpOptions: {
    host: 'tomas.morar95@ethereal.email',
    port: 587,
    auth: {
      user: 'tomas.morar95@ethereal.email',
      pass: 'eJz4xZ8apxhZHQMPFk',
    },
  },
};

async function sendEmail({ to, subject, html, from = configMail.emailFrom }) {
  const transporter = nodemailer.createTransport(configMail.smtpOptions);
  await transporter.sendMail({ from, to, subject, html });
}
