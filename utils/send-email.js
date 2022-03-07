const nodemailer = require('nodemailer');

module.exports = sendEmail;

const configMail = {
  emailFrom: 'ulfep7oge7day5co@ethereal.email',
  optionsSmtp: {
    host: 'smtp.ethereal.email',
    port: 587,
    secure: false,
    auth: {
      user: 'ulfep7oge7day5co@ethereal.email',
      pass: 'WcMMGfPTPsvUrqEJte',
    },
  },
};

async function sendEmail({ to, subject, html, from = configMail.emailFrom }) {
  // const transporter = nodemailer.createTransport(configMail.optionsSmtp);
  // await transporter.sendMail({ from, to, subject, html });
  console.log(`SENDING EMAIL: ${subject}`);
}
