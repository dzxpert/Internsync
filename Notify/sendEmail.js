const nodemailer = require('nodemailer');
const fs = require('fs');
const path = require('path');

// Configure the email transporter
const transporter = nodemailer.createTransport({
    host: '127.0.0.1',
    port: 25,
    secure: false, // true for 465, false for other ports
    auth: {
      user: '',
      pass: ''
    }
  });

// Helper function to send emails
const sendMail = (to, subject, html) => {
  const mailOptions = {
    from: '"InternSync" <internsync.dz@gmail.com>',
    to,
    subject,
    html
  };

  return transporter.sendMail(mailOptions);
};

// Helper function to read template file
const readTemplate = (templateName) => {
  const templatePath = path.join(__dirname, templateName);
  return fs.readFileSync(templatePath, 'utf8');
};

// Helper function to replace placeholders in template
const replacePlaceholders = (template, placeholders) => {
  let content = template;
  for (const [key, value] of Object.entries(placeholders)) {
    content = content.replace(new RegExp(`{{${key}}}`, 'g'), value);
  }
  return content;
};

// Email functions
const PasswordResetEmail = (to, resetLink) => {
  const subject = 'Password Reset Request';
  const template = readTemplate('password-reset.html');
  const html = replacePlaceholders(template, { resetLink });
  return sendMail(to, subject, html);
};

const AccountActivationEmail = (to, activationLink,student_name,supervisor_name) => {
  const subject = 'Activate Your Account';
  const template = readTemplate('account-activation.html');
  const html = replacePlaceholders(template, { activationLink,student_name,supervisor_name });
  return sendMail(to, subject, html);
};

const EvaluationSheetEmail = (to, evaluationLink, StudentName) => {
  const subject = 'Evaluation Sheet';
  const template = readTemplate('evaluation-sheet.html');
  const html = replacePlaceholders(template, { evaluationLink,StudentName });
  return sendMail(to, subject, html);
};

const AccountCreated = (to, UserName) => {
  const subject = 'Account Created Successfully';
  const template = readTemplate('account-created.html');
  const html = replacePlaceholders(template, {UserName});
  return sendMail(to, subject, html);
};

const InternshipStatusEmail = (to, status) => {
  const subject = 'Internship Status Update';
  const template = readTemplate('internship-status.html');
  const html = replacePlaceholders(template, { status });
  return sendMail(to, subject, html);
};

const ApplicationStatusEmail = (to, status) => {
  const subject = 'Application Status Update';
  const template = readTemplate('application-status.html');
  const html = replacePlaceholders(template, { status });
  return sendMail(to, subject, html);
};

module.exports = {
  PasswordResetEmail,
  AccountActivationEmail,
  EvaluationSheetEmail,
  AccountCreated,
  InternshipStatusEmail,
  ApplicationStatusEmail
};
