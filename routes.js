const express = require('express');
const bcrypt = require('bcrypt')
const moment = require('moment');
const path = require('path');

const hbs = require('hbs');

hbs.registerHelper('json', function(context) {
  return JSON.stringify(context);
});

const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
const { SQL_MY } = require('./sql');
const generateCertificate = require('./generateCertificate');
const { isAuthenticated, isStudent, isInternshipSupervisor, isUniversitySupervisor,isAdmin } = require('./middleware');
const { splitAcademicYear, generateRandomToken,calculate_academic_year, compareStatus} = require('./helpers');
const { PasswordResetEmail, AccountActivationEmail, EvaluationSheetEmail, AccountCreated, InternshipStatusEmail, ApplicationStatusEmail} = require('./Notify/sendEmail');

appurl = "http://localhost:3000/"
const router = express.Router();
const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

router.get('/generate-certificate/:id', isAuthenticated, isStudent, (req, res) => {
  const InternshipID = req.params.id;
  if(req.session.cert_generated){
    res.redirect('/certificates/' + InternshipID + '-certificate.pdf');
  }else{
    const sql = `
      SELECT 
        CONCAT(us.first_name, ' ', us.last_name) AS studentName,
        c.name AS companyName,
        CONCAT(u.first_name, ' ', u.last_name) AS supervisorName,
        i.position,
        e.technical_skill,
        e.teamwork,
        e.problem_solving,
        e.presence,
        e.total
      FROM 
        internships i
      JOIN 
        students s ON i.student_id = s.student_id
      JOIN 
        users us ON s.user_id = us.user_id
      JOIN 
        intern_sup sup ON i.intern_sup_id = sup.intern_sup_id
      JOIN 
        company c ON sup.company_id = c.company_id
      JOIN 
        users u ON sup.user_id = u.user_id
      JOIN 
        evaluations e ON i.internship_id = e.internship_id
      WHERE 
        i.internship_id = ?
    `;

    SQL_MY(sql, [InternshipID], res, (result) => {
      if (result.error) {
        res.status(500).json({ error: 'Internal Server Error' });
        return;
      }

      if (!result || result.length === 0) {
        res.status(404).json({ error: 'Internship not found' });
        return;
      }

      const row = result[0];

      const { studentName, companyName, supervisorName, position } = row;
      const evaluation = [row.technical_skill, row.teamwork, row.problem_solving, row.presence, row.total];

      const outputPath = path.join(__dirname, 'public', 'certificates', `${InternshipID}-certificate.pdf`);
      generateCertificate(outputPath, studentName, companyName, supervisorName, position, evaluation);
      sleep(3000);
      req.session.cert_generated = true;
      res.redirect('/certificates/' + InternshipID + '-certificate.pdf');
    });
}
});
router.post('/register', (req, res) => {
  const { fname, lname, email, password, studentId, level, speciality } = req.body;
  const { start_year, end_year } = splitAcademicYear(calculate_academic_year());

  if (!fname || !lname || !speciality || !level || !email || !password || !studentId) {
    return res.redirect('404');
  }

  const emailCheckQuery = 'SELECT COUNT(*) AS count FROM users WHERE email = ?';
  const emailCheckValues = [email];
  SQL_MY(emailCheckQuery, emailCheckValues, res, (emailCheckResults) => {
    const emailExists = emailCheckResults[0].count > 0;

    if (emailExists) {

      return res.status(400).json({ error: 'Email already exists' });
    }

    const studentIdCheckQuery = 'SELECT COUNT(*) AS count FROM students WHERE student_id = ?';
    const studentIdCheckValues = [studentId];
    SQL_MY(studentIdCheckQuery, studentIdCheckValues, res, (studentIdCheckResults) => {
      const studentIdExists = studentIdCheckResults[0].count > 0;

      if (studentIdExists) {

        return res.status(400).json({ error: 'Student already exists' });
      }

      bcrypt.hash(password, 10, (err, hashedPassword) => {
        if (err) {
          console.error('Error hashing password:', err);
          return res.status(500).json({ error: 'Internal Server Error' });
        }

        const insertUserQuery = 'INSERT INTO users (email, password, first_name, last_name, user_type) VALUES (?, ?, ?, ?, ?)';
        const insertUserValues = [email, hashedPassword, fname, lname, 1];
        SQL_MY(insertUserQuery, insertUserValues, res, (userInsertResults) => {
          const userId = userInsertResults.insertId;

          const insertStudentQuery = 'INSERT INTO students (student_id, user_id, level, start_year, end_year, specialty_id) VALUES (?, ?, ?, ?, ?, ?)';
          const insertStudentValues = [studentId, userId, level, start_year, end_year, speciality];
          SQL_MY(insertStudentQuery, insertStudentValues, res, (studentInsertResults) => {
            console.log('Singup Successful for', fname," ",lname);
            AccountCreated(email, fname)
              .catch((error) => {
                console.error('Error sending email:', error);
                return res.status(201).json({ error: 'Account Created' });
              });
            return res.status(201).json({ error: 'Account Created' });
          });
        });
      });
    });
  });
});
router.post('/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required' });
  }

  const query = "SELECT * FROM users WHERE email = ?";
  const values = [email];
  SQL_MY(query, values, res, (results) => {
    if (results.length > 0) {
      const user = results[0];
      bcrypt.compare(password, user.password, (err, passwordMatch) => {
        if (err) {
          console.error('Error comparing passwords:', err);
          return res.status(500).json({ error: 'Internal Server Error' });
        }
        if (passwordMatch) {
          req.session.type = user.user_type;
          req.session.user = email;
          req.session.uid = user.user_id;
          req.session.full_name = user.first_name;
          req.session.first_name = user.first_name + ' ' + user.last_name;
          return res.json({ redirect: '/dashboard' });
        } else {
          return res.status(400).json({ error: 'Invalid email or password' });
        }
      });
    } else {
      return res.status(400).json({ error: 'Invalid email or password' });
    }
  });
});

router.get('/api/check-email', (req, res) => {
  const email = req.query.email;

  if (!email) {
    return res.status(400).json({ error: 'Email is required' });
  }

  const emailCheckQuery = 'SELECT COUNT(*) AS count FROM users WHERE email = ?';
  const emailCheckValues = [email];
  SQL_MY(emailCheckQuery, emailCheckValues, res, (emailCheckResults) => {
    const emailExists = emailCheckResults[0].count > 0;
    res.json({ exists: emailExists });
  });
});
router.post('/api/check-supervisor', isAuthenticated, isStudent, (req, res) => {
  const email = req.body.email;

  if (email && emailRegex.test(email)) {

      const query = `
          SELECT u.first_name, u.last_name, c.company_id AS company_id
          FROM users u
          JOIN intern_sup isup ON u.user_id = isup.user_id
          JOIN company c ON isup.company_id = c.company_id
          WHERE u.email = ? AND u.user_type = 3
      `;

      SQL_MY(query, [email], res, (results) => {
          if (results.error) {
              console.error(results.error);
              return res.status(500).json({ error: 'Internal Server Error' });
          }

          if (results.length === 0) {

              return res.status(200).json({ error: 'not found' });
          }

          const supervisor = results[0];

          return res.status(200).json({
              message: 'found',
              supervisor: {
                  firstName: supervisor.first_name,
                  lastName: supervisor.last_name
              },
              company: {
                  id: supervisor.company_id
              }
          });
      });
  } else {

      return res.status(400).json({ error: 'Bad Request' });
  }
});

router.post('/api/check-email-valid', isAuthenticated, isStudent, (req, res) => {
  const email = req.body.email;

  if (email && emailRegex.test(email)) {

      const query = `
          SELECT COUNT(*)
          FROM users
          WHERE email = ? AND user_type != 3
      `;

      SQL_MY(query, [email], res, (results) => {
          if (results.error) {
              console.error(results.error);
              return res.status(500).json({ error: 'Internal Server Error' });
          }

          const count = results[0]['COUNT(*)'];

          return res.status(200).json({ exists: count > 0 });
      });
  } else {

      return res.status(400).json({ error: 'Bad Request' });
  }
});

router.get('/api/specialties', (req, res) => {
  const { level, department } = req.query;
  sql="SELECT * FROM specialties WHERE level = ? AND dep_id = ?"
  SQL_MY(sql, [level,department], res, (specialties) => {
    if (specialties.error) {
      res.status(500).json({ error: 'Failed to Fetch' });
      return;
    }
    res.status(201).json({ specialties});
  });
});
router.get('/offer/:id/apply', isAuthenticated, isStudent, (req, res) => {
  const offerId = req.params.id;
  const studentId = req.session.studentID;

  if (!offerId || !studentId) {
      return res.status(400).json({ error: 'Invalid offer or student ID' });
  }

  const checkOfferQuery = 'SELECT * FROM offers WHERE offer_id = ? AND status != 4 AND expiration_date > CURDATE()';
  SQL_MY(checkOfferQuery, [offerId], res, (offerResults) => {
      if (offerResults.length === 0) {
          return res.status(400).json({ error: 'Offer is not available' });
      }

      const checkApplicationQuery = 'SELECT * FROM applications WHERE offer_id = ? AND student_id = ?';
      SQL_MY(checkApplicationQuery, [offerId, studentId], res, (applicationResults) => {
          if (applicationResults.length > 0) {
              return res.status(400).json({ error: 'You have already applied to this offer' });
          }

          const insertQuery = 'INSERT INTO applications (offer_id, student_id) VALUES (?, ?)';
          SQL_MY(insertQuery, [offerId, studentId], res, (insertResults) => {
              if (insertResults.affectedRows > 0) {
                  res.status(200).json({ message: 'Application submitted successfully' });
              } else {
                  res.status(500).json({ error: 'Failed to submit application' });
              }
          }, (error) => {

              console.error('Database error:', error);
              res.status(500).json({ error: 'An internal server error occurred' });
          });
      }, (error) => {

          console.error('Database error:', error);
          res.status(500).json({ error: 'An internal server error occurred' });
      });
  }, (error) => {

      console.error('Database error:', error);
      res.status(500).json({ error: 'An internal server error occurred' });
  });
});

router.post('/reset-password', (req, res) => {
  const { token, newPassword } = req.body;
  if (newPassword === "" || !newPassword) {
    res.redirect('404');
  } else {
    const tokenRegex = /^[a-f0-9]{40}$/;
    if (!token.match(tokenRegex)) {
      return res.render('404');
    }

    const tokenQuery = 'SELECT user_id, expiration FROM password_reset WHERE token = ?';
    SQL_MY(tokenQuery, [token], res, (results) => {
      if (results.length > 0) {
        const { user_id, expiration } = results[0];
        const formattedExpiration = moment(expiration).format('YYYY-MM-DD HH:mm:ss');
        const currentTime = moment().format('YYYY-MM-DD HH:mm:ss');
        if (currentTime < formattedExpiration) {

          bcrypt.hash(newPassword, 10, (err, hashedPassword) => {
            if (err) {
              console.error('Error hashing password:', err);
              res.status(500).json({ error: 'Internal Server Error' });
            } else {

              const updatePasswordQuery = 'UPDATE users SET password = ? WHERE user_id = ?';
              SQL_MY(updatePasswordQuery, [hashedPassword, user_id], res, () => {

                const deleteTokenQuery = 'DELETE FROM password_reset WHERE token = ?';
                SQL_MY(deleteTokenQuery, [token], res, () => {

                  res.status(200).json({ message: 'Password changed successfully' });
                });
              });
            }
          });
        } else {

          res.status(400).json({ error: 'Expired token' });
        }
      } else {

        res.status(404).json({ error: 'Token not found' });
      }
    });
  }
});

router.post('/update-email', isAuthenticated, (req, res) => {
  const userId = req.session.uid; 
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({ success: false, message: 'Email is required' });
  }

  const emailCheckQuery = 'SELECT COUNT(*) AS count FROM users WHERE email = ? AND user_id != ?';
  SQL_MY(emailCheckQuery, [email, userId], res, (result) => {
    if (result.error) {
      console.error('Error checking email:', result.error);
      return res.json({ success: false, message: 'Failed to update email' });
    }

    const emailExists = result[0].count > 0;

    if (emailExists) {
      return res.json({ success: false, message: 'Email already exists' });
    }

    const updateQuery = 'UPDATE users SET email = ? WHERE user_id = ?';
    SQL_MY(updateQuery, [email, userId], res, (updateResult) => {
      if (updateResult.error) {
        console.error('Error updating email:', updateResult.error);
        return res.json({ success: false, message: 'Failed to update email' });
      }

      res.json({ success: true, message: 'Email updated successfully!' });
    });
  });
});
router.post('/update-password', isAuthenticated, (req, res) => {
  const userId = req.session.uid; 
  const { currentPassword, newPassword } = req.body;

  const getUserQuery = 'SELECT password FROM users WHERE user_id = ?';
  SQL_MY(getUserQuery, [userId], res, (result) => {
    if (result.error) {
      console.error('Error fetching user:', result.error);
      return res.json({ success: false, message: 'Failed to update password' });
    }

    const user = result[0];
    if (!user || !bcrypt.compareSync(currentPassword, user.password)) {
      return res.json({ success: false, message: 'Current password is incorrect' });
    }

    const hashedPassword = bcrypt.hashSync(newPassword, 10);
    const updatePasswordQuery = 'UPDATE users SET password = ? WHERE user_id = ?';
    SQL_MY(updatePasswordQuery, [hashedPassword, userId], res, (result) => {
      if (result.error) {
        console.error('Error updating password:', result.error);
        return res.json({ success: false, message: 'Failed to update password' });
      }
      res.json({ success: true, message: 'Password updated successfully!' });
    });
  });
});

router.get('/activate-account', (req, res) => {
  const token = req.query.token;

  if (!token) {
    return res.status(400).json({ error: 'No token provided' });
  }

  const sql = `SELECT u.user_id
               FROM account_activation a
               JOIN users u ON a.user_id = u.user_id
               JOIN intern_sup s ON u.user_id = s.user_id
               WHERE a.token = ?`;

  SQL_MY(sql, [token], res, (result) => {
    if (result.error) {
      return res.status(500).json({ error: 'Internal Server Error' });
    }
    if (result.length === 0) {
      return res.status(400).json({ error: 'Invalid or expired token' });
    }

    res.render("auth/activate-account", { token });
  });
});
router.post('/activate-account', (req, res) => {
  const { token, newPassword } = req.body;

  if (!token || !newPassword) {
    return res.status(400).json({ error: 'Token and new password are required' });
  }

  const getUserSql = `SELECT u.user_id
                      FROM account_activation a
                      JOIN users u ON a.user_id = u.user_id
                      JOIN intern_sup s ON u.user_id = s.user_id
                      WHERE a.token = ?`;

  SQL_MY(getUserSql, [token], res, (result) => {
    if (result.error) {
      return res.status(500).json({ error: 'Internal Server Error' });
    }
    if (result.length === 0) {
      return res.status(400).json({ error: 'Invalid or expired token' });
    }

    const userId = result[0].user_id;

    bcrypt.hash(newPassword, 10, (err, hash) => {
      if (err) {
        return res.status(500).json({ error: 'Error hashing password' });
      }

      const updateUserSql = `UPDATE users SET password = ? WHERE user_id = ?`;
      const updateInternSupSql = `UPDATE intern_sup SET account_status = 1 WHERE user_id = ?`;

      SQL_MY(updateUserSql, [hash, userId], res, (updateUserResult) => {
        if (updateUserResult.error) {
          return res.status(500).json({ error: 'Internal Server Error' });
        }

        SQL_MY(updateInternSupSql, [userId], res, (updateInternSupResult) => {
          if (updateInternSupResult.error) {
            return res.status(500).json({ error: 'Internal Server Error' });
          }

          const deleteTokenSql = `DELETE FROM account_activation WHERE token = ?`;

          SQL_MY(deleteTokenSql, [token], res, (deleteTokenResult) => {
            if (deleteTokenResult.error) {
              return res.status(500).json({ error: 'Internal Server Error' });
            }

            return res.status(200).json({ message: 'Account activated and password updated successfully' });
          });
        });
      });
    });
  });
});

router.get('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error('Error destroying session:', err);
      res.status(500).json({ error: 'Internal Server Error' });
      return;
    }
    res.redirect("/");
  });
});
router.get('/change-password', (req, res) => {
  const { token } = req.query;

  if (token === undefined) {
      return res.render('404');
  }

  const tokenRegex = /^[a-f0-9]{40}$/;
  if (!token.match(tokenRegex)) {
      return res.render('404');
  }

  const tokenQuery = 'SELECT user_id, expiration FROM password_reset WHERE token = ?';
  SQL_MY(tokenQuery, [token], res, (results) => {
      if (results.length > 0) {
          const { user_id, expiration } = results[0];
          const formattedExpiration = moment(expiration).format('YYYY-MM-DD HH:mm:ss');
          const currentTime = moment().format('YYYY-MM-DD HH:mm:ss');

          if (currentTime < formattedExpiration) {

              res.render('debug', { message: 'Valid token', token });
          } else {

              res.render('debug', { message: 'change password page', error: 'Token expired' });
          }
      } else {

          res.render('debug', { message: 'change password page', error: 'Token invalid' });
      }
  });
});
router.get('/register', (req, res) => {
  SQL_MY('SELECT * from departements', [], res, (departements) => {
  res.render('auth/register',{ departements: departements });
});
});
router.post('/forgot-password', (req, res) => {
  const { email } = req.body;

  if (!email || email === "") {
    return res.status(400).json({ error: 'Email is required' });
  }

  const token = generateRandomToken();
  const expiration = moment().add(1, 'hour').format('YYYY-MM-DD HH:mm:ss');

  const emailQuery = 'SELECT user_id FROM users WHERE email = ?';
  SQL_MY(emailQuery, [email], res, (results) => {
    if (results.length > 0) {
      const user_id = results[0].user_id;

      const deleteQuery = 'DELETE FROM password_reset WHERE user_id = ?';
      SQL_MY(deleteQuery, [user_id], res, () => {

        const insertTokenQuery = 'INSERT INTO password_reset (user_id, token, expiration) VALUES (?, ?, ?)';
        SQL_MY(insertTokenQuery, [user_id, token, expiration], res, () => {

          const resetLink = `${appurl}reset-password?token=${token}`;
          console.log('Password reset link:', resetLink);

          PasswordResetEmail(email, resetLink)
            .catch((error) => {
              console.error('Error sending email:', error);
              return res.status(500).json({ error: 'Failed to send password reset email' });
            });

          res.status(200).json({ message: 'Password reset token generated successfully' });
        });
      });
    } else {

      res.status(404).json({ error: 'Email not found' });
    }
  });
});
router.get('/forgot-password', (req, res) => {
  res.render('auth/forgot-password');
});
router.get('/reset-password', (req, res) => {
  const { token } = req.query;

  if (!token) {
      return res.render('404');
  }

  const tokenRegex = /^[a-f0-9]{40}$/;
  if (!token.match(tokenRegex)) {
      return res.render('404');
  }

  const tokenQuery = 'SELECT user_id, expiration FROM password_reset WHERE token = ?';
  SQL_MY(tokenQuery, [token], res, (results) => {
      if (results.length > 0) {
          const { user_id, expiration } = results[0];
          const formattedExpiration = moment(expiration).format('YYYY-MM-DD HH:mm:ss');
          const currentTime = moment().format('YYYY-MM-DD HH:mm:ss');

          if (currentTime < formattedExpiration) {

              res.render('auth/reset-password', {token: token });
          } else {

              res.render('auth/reset-password', {error: 'Token invalid or expired' });
          }
      } else {

          res.render('auth/reset-password', {error: 'Token invalid or expired' });
      }
  });
});

router.get('/dashboard', isAuthenticated, (req, res) => {
  if(req.session.type==1)
  res.redirect('/student');
  if(req.session.type==2)
  res.redirect('/university');
  if(req.session.type==3)
  res.redirect('/company');

});

router.get('/company/login', (req, res) => {
  res.render('auth/company-login');
});
router.get('/company', isAuthenticated, isInternshipSupervisor, (req, res) => {
  res.render('dashboards/company/dashboard', { full_name: req.session.full_name });
});
router.get('/company/interns', isAuthenticated, isInternshipSupervisor, (req, res) => {
  const internSupId = req.session.intern_sup_id;

  if (!internSupId) {
      return res.status(403).json({ error: 'Unauthorized' });
  }

  const query = `
      SELECT
          internships.internship_id,
          internships.start_date,
          internships.end_date,
          students.student_id,
          users.first_name AS student_first_name,
          users.last_name AS student_last_name,
          users.email AS student_email,
          students.level,
          specialties.name AS specialty_name
      FROM internships
      JOIN students ON internships.student_id = students.student_id
      JOIN users ON students.user_id = users.user_id
      JOIN specialties ON students.specialty_id = specialties.specialty_id
      WHERE internships.intern_sup_id = ?
  `;

  SQL_MY(query, [internSupId], res, (result) => {
      if (result.error) {
          console.error('Error fetching interns data:', result.error);
          return res.status(500).json({ error: 'Internal Server Error' });
      }

      res.render('dashboards/company/interns', { interns: result , full_name: req.session.full_name });
  });
});
router.get('/company/requests', isAuthenticated, isInternshipSupervisor, (req, res) => {
  const intern_sup = req.session.intern_sup_id;
  sql="SELECT CONCAT(u.first_name, ' ', u.last_name) AS student_name, u.email AS student_email, ir.int_req_id, ir.duration_weeks, ir.status, s.student_id, s.user_id AS student_user_id, s.level AS student_level, sp.name AS specialty_name, c.name AS company_name FROM internship_requests ir JOIN students s ON ir.student_id = s.student_id JOIN users u ON s.user_id = u.user_id JOIN specialties sp ON s.specialty_id = sp.specialty_id JOIN intern_sup isup ON isup.intern_sup_id = ir.intern_sup_id JOIN company c ON isup.company_id = c.company_id WHERE ir.intern_sup_id = ?"
  SQL_MY(sql, [intern_sup], res, (internship_requests) => {
    if (internship_requests.error) {
      res.status(500).json({ error: 'Internal Server Error' });
      return;
    }
    internship_requests.forEach(request => {
      request.isInReview = compareStatus(request.status, 1);
      request.isPreApproved = compareStatus(request.status, 2);
      request.isApproved = compareStatus(request.status, 3);
      request.isDeclined = compareStatus(request.status, 4);
    });
  res.render('dashboards/company/requests', { internship_requests: internship_requests , full_name: req.session.full_name });
});
});
router.post('/company/request/:id/approve', isAuthenticated, isInternshipSupervisor, (req, res) => {
  const req_id = parseInt(req.params.id);
  const intern_sup_id = req.session.intern_sup_id;
  const { startDate, endDate, position } = req.body;

  if (!req.params.id || !Number.isInteger(req_id) || !intern_sup_id || !startDate || !endDate || !position) {
      return res.status(400).json({ error: 'Invalid request data' });
  }

  const updateRequestSql = 'UPDATE internship_requests SET status = 3 WHERE int_req_id = ?';
  SQL_MY(updateRequestSql, [req_id], res, (updateResult) => {
      if (updateResult.error) {
          console.error('Error updating internship request status:', updateResult.error);
          return res.status(500).json({ error: 'Internal server error' });
      }

      if (updateResult.affectedRows === 0) {
          return res.status(404).json({ error: 'Internship request not found' });
      }

      const fetchRequestSql = 'SELECT student_id FROM internship_requests WHERE int_req_id = ?';
      SQL_MY(fetchRequestSql, [req_id], res, (fetchRequestResult) => {
          if (fetchRequestResult.error) {
              console.error('Error fetching internship request details:', fetchRequestResult.error);
              return res.status(500).json({ error: 'Internal server error' });
          }

          if (fetchRequestResult.length === 0) {
              return res.status(404).json({ error: 'Internship request not found' });
          }

          const student_id = fetchRequestResult[0].student_id;

          const checkInternshipSql = 'SELECT * FROM internships WHERE student_id = ? AND intern_sup_id = ? AND start_date = ? AND end_date = ?';
          const checkValues = [student_id, intern_sup_id, startDate, endDate];

          SQL_MY(checkInternshipSql, checkValues, res, (checkInternshipResult) => {
              if (checkInternshipResult.error) {
                  console.error('Error checking for existing internships:', checkInternshipResult.error);
                  return res.status(500).json({ error: 'Internal server error' });
              }

              if (checkInternshipResult.length > 0) {

                  return res.status(409).json({ error: 'Internship already exists' });
              }

              const insertInternshipSql = `
                  INSERT INTO internships (start_date, end_date, position, intern_sup_id, student_id)
                  VALUES (?, ?, ?, ?, ?)
              `;
              const insertValues = [startDate, endDate, position, intern_sup_id, student_id];

              SQL_MY(insertInternshipSql, insertValues, res, (insertResult) => {
                  if (insertResult.error) {
                      console.error('Error inserting internship:', insertResult.error);
                      return res.status(500).json({ error: 'Internal server error' });
                  }

                  res.status(200).json({ message: 'Internship request approved and internship created successfully' });
              });
          });
      });
  });
});
router.post('/company/request/:id/reject', isAuthenticated, isInternshipSupervisor, (req, res) => {

  const req_id = parseInt(req.params.id);
  if (!Number.isInteger(req_id)) {
      return res.status(400).json({ error: 'Invalid ID' });
  }

  const rejectionReasonId = parseInt(req.body.rejectionReasonId);
  if (!Number.isInteger(rejectionReasonId) || rejectionReasonId < 1 || rejectionReasonId > 6) {
      return res.status(400).json({ error: 'Invalid rejection reason ID' });
  }

  const sql = `UPDATE internship_requests SET status = 4, rejection_reason = ? WHERE int_req_id = ?;`;
  const sqlParams = [rejectionReasonId, req_id];

  SQL_MY(sql, sqlParams, res, (result) => {
      if (result.error) {
          return res.status(500).json({ error: 'Internal Server Error' });
      }
      if (result.affectedRows === 0) {
          return res.status(404).json({ error: 'Internship request not found' });
      }
      res.status(200).json({ message: 'Internship request rejected successfully' });
  });
});
router.get('/company/internships', isAuthenticated, isInternshipSupervisor, (req, res) => {

  const internSupId = req.session.intern_sup_id;

  const sql = `
      SELECT i.start_date, i.end_date, i.status, c.name AS company_name,
             CONCAT(sup.first_name, ' ', sup.last_name) AS sup_name,
             CONCAT(stu.first_name, ' ', stu.last_name) AS student_name,
             DATEDIFF(i.end_date, CURDATE()) AS days_left
      FROM internships i
      JOIN intern_sup s ON i.intern_sup_id = s.intern_sup_id
      JOIN company c ON s.company_id = c.company_id
      JOIN users sup ON s.user_id = sup.user_id
      JOIN students st ON i.student_id = st.student_id
      JOIN users stu ON st.user_id = stu.user_id
      WHERE i.intern_sup_id = ?
  `;

  SQL_MY(sql, [internSupId], res, (result) => {
      if (result.error) {
          console.error('Error fetching internships data:', result.error);
          return res.status(500).json({ error: 'Internal Server Error' });
      }

      result.forEach(internship => {
          internship.start_date = moment(internship.start_date).format('ddd MMM DD YYYY');
          internship.end_date = moment(internship.end_date).format('ddd MMM DD YYYY');
      });

      res.render('dashboards/company/internships', { internships: result, full_name: req.session.full_name  });
  });
});
router.get('/company/applications', isAuthenticated, isInternshipSupervisor, (req, res) => {
  const company = req.session.company;
  sql = "SELECT applications.application_id, CONCAT(users.first_name, ' ', users.last_name) AS student_name, students.level AS student_level, offers.title AS offer_title, applications.status AS application_status FROM applications JOIN students ON applications.student_id = students.student_id JOIN users ON students.user_id = users.user_id JOIN offers ON applications.offer_id = offers.offer_id WHERE offers.company_id=? AND applications.status <> 4"
  SQL_MY(sql, [company], res, (applications) => {
    if(applications.error){
      return res.status(500).json({ error: 'Internal Server Error' });
    }
    applications.forEach(application => {
      application.isInReview = compareStatus(application.application_status, 1);
      application.isApproved = compareStatus(application.application_status, 2);
      application.isDeclined = compareStatus(application.application_status, 3);
    });
  res.render('dashboards/company/applications', { applications: applications, full_name: req.session.full_name  });
});
});
router.get('/company/application/:id/approve', isAuthenticated, isInternshipSupervisor, (req, res) => {
  const app_id = parseInt(req.params.id);
  if (!req.params.id || !Number.isInteger(app_id)) {
    return res.status(400).json({ error: 'Invalid ID' });
  }

  const sql = `UPDATE applications SET status = 2 WHERE application_id = ?`;
  SQL_MY(sql, [app_id], res, (result) => {
    if (result.error) {
      return res.status(500).json({ error: 'Internal Server Error' });
    }
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Application not found' });
    }
    res.status(200).json({ message: 'Application approved successfully' });
  });
});
router.post('/company/application/:id/reject', isAuthenticated, isInternshipSupervisor, (req, res) => {

  const app_id = parseInt(req.params.id);
  if (!Number.isInteger(app_id)) {
      return res.status(400).json({ error: 'Invalid ID' });
  }

  const rejectionReasonId = parseInt(req.body.rejectionReasonId);
  if (!Number.isInteger(rejectionReasonId) || rejectionReasonId < 1 || rejectionReasonId > 6) {
      return res.status(400).json({ error: 'Invalid rejection reason ID' });
  }

  const sql = `UPDATE applications SET status = 3, rejection_reason = ? WHERE application_id = ?;`;
  const sqlParams = [rejectionReasonId, app_id];

  SQL_MY(sql, sqlParams, res, (result) => {
      if (result.error) {
          return res.status(500).json({ error: 'Internal Server Error' });
      }
      if (result.affectedRows === 0) {
          return res.status(404).json({ error: 'Application not found' });
      }
      res.status(200).json({ message: 'Application rejected successfully' });
  });
});
router.get('/company/offers', isAuthenticated, isInternshipSupervisor, (req, res) => {
  const company_id = req.session.company;
  const sql = `
    SELECT O.title,O.status, O.expiration_date, O.offer_id, O.description, O.duration, O.dep_id, D.name as department_name
    FROM offers O
    JOIN departements D ON O.dep_id = D.dep_id
    WHERE O.company_id = ?`;

  SQL_MY(sql, [company_id], res, (offers) => {
    if (offers.error) {
      console.error('Error fetching offers:', offers.error);
      return res.status(500).json({ error: 'Internal Server Error' });
    }
    offers.forEach(offer => {
    if (moment(offer.expiration_date).isBefore(moment.currentTime)) {
        offer.isExpired = true;
    } else {
      offer.isExpired = false;
    }
      offer.expiration_date = moment(offer.expiration_date).format('YYYY-MM-DD');
      offer.isInReview = compareStatus(offer.status, 1);
      offer.isApproved = compareStatus(offer.status, 2);
      offer.isDeclined = compareStatus(offer.status, 3);
    });
    res.render('dashboards/company/offers', { offers: offers , full_name: req.session.full_name });
  });
});
router.get('/company/new-offer', isAuthenticated, isInternshipSupervisor, (req, res) => {
  const query = 'SELECT dep_id, name FROM departements';

  SQL_MY(query, [], res, (departments) => {
    if (departments.error) {
      console.error('Error fetching departments:', departments.error);
      return res.status(500).json({ error: 'Internal Server Error' });
    }

    res.render('dashboards/company/new-offer', { departments: departments });
  });
});
router.get('/company/offer/:id/edit', isAuthenticated, isInternshipSupervisor, (req, res) => {
  const req_id = parseInt(req.params.id);
  if (!req.params.id || !Number.isInteger(req_id)) {
    return res.status(400).json({ error: 'Invalid ID' });
  }
  const offerQuery = `
    SELECT O.offer_id,O.title, O.expiration_date, O.description, O.status, O.dep_id AS DEPPA, O.duration, C.name as company_name
    FROM offers O
    JOIN company C ON O.company_id = C.company_id
    WHERE O.offer_id = ?`;
  const departmentsQuery = 'SELECT dep_id, name FROM departements';
  SQL_MY(offerQuery, [req_id], res, (offerResult) => {
    if (offerResult.error) {
      console.error('Error fetching offer:', offerResult.error);
      return res.status(500).json({ error: 'Internal Server Error' });
    }

    if (offerResult.length === 0) {
      return res.status(404).json({ error: 'Offer not found' });
    }
    const offer = offerResult[0];
    offer.expiration_date = moment(offer.expiration_date).format('YYYY-MM-DD');
    SQL_MY(departmentsQuery, [], res, (departmentsResult) => {
      if (departmentsResult.error) {
        console.error('Error fetching departments:', departmentsResult.error);
        return res.status(500).json({ error: 'Internal Server Error' });
      }
      res.render('dashboards/company/edit-offer', { offer: offer, departments: departmentsResult });
    });
  });
});
router.post('/company/post-offer', isAuthenticated, isInternshipSupervisor, (req, res) => {
  const { title, description, department, expiration_date, duration } = req.body;

  const company_id = req.session.company; 

  if (!department) {
    return res.json({ success: false, message: 'Invalid department selected' });
  }

  const query = `
    INSERT INTO offers (title, description, dep_id, company_id, expiration_date, duration, status, rejection_reason)
    VALUES (?, ?, ?, ?, ?, ?, 1, '')
  `;

  SQL_MY(query, [title, description, department, company_id, expiration_date, duration], res, (result) => {
    if (result.error) {
      console.error('Error creating offer:', result.error);
      return res.json({ success: false, message: 'Failed to create offer' });
    }
    res.json({ success: true, message: 'Offer posted successfully!' });
  });
});
router.post('/offer/:id/edit', isAuthenticated, isInternshipSupervisor, (req, res) => {
  const req_id = parseInt(req.params.id);
  const { title, description, department, expiration_date, duration } = req.body;

  if (!req_id || !Number.isInteger(req_id) || !title || !description || !department || !expiration_date || !duration) {
    return res.status(400).json({ success: false, message: 'Invalid input data' });
  }

  const company_id = req.session.company; 

  const formattedExpirationDate = moment(expiration_date).format('YYYY-MM-DD');

  const query = `
    UPDATE offers
    SET title = ?, description = ?, dep_id = ?, company_id = ?, expiration_date = ?, duration = ?
    WHERE offer_id = ? AND company_id = ?
  `;

  SQL_MY(query, [title, description, department, company_id, formattedExpirationDate, duration, req_id, company_id], res, (result) => {
    if (result.error) {
      console.error('Error updating offer:', result.error);
      return res.status(500).json({ success: false, message: 'Failed to update offer' });
    }
    res.json({ success: true, message: 'Offer updated successfully!' });
  });
});
router.get('/company/attendance', isAuthenticated, isInternshipSupervisor, (req, res) => {

  const intern_sup_id = req.session.intern_sup_id;

  const sql = `SELECT i.internship_id, i.start_date, i.end_date, i.status, c.name AS company_name, CONCAT(stu.first_name, ' ', stu.last_name) AS student_name, CONCAT(sup.first_name, ' ', sup.last_name) AS supervisor_name, DATEDIFF(i.end_date, CURDATE()) AS days_left FROM internships i JOIN intern_sup s ON i.intern_sup_id = s.intern_sup_id JOIN company c ON s.company_id = c.company_id JOIN students st ON i.student_id = st.student_id JOIN users stu ON st.user_id = stu.user_id JOIN users sup ON s.user_id = sup.user_id LEFT JOIN attendance a ON i.internship_id = a.internship_id AND a.date = CURDATE() WHERE i.intern_sup_id = ? AND i.start_date <= CURDATE() AND i.end_date >= CURDATE() AND a.attendance_id IS NULL`;

  SQL_MY(sql, [intern_sup_id], res, (internships) => {
      if (internships.error) {
          console.error('Error fetching ongoing internships:', internships.error);
          return res.status(500).json({ error: 'Internal Server Error' });
      }

      res.render('dashboards/company/attendance', {internships: internships, full_name: req.session.full_name });
  });
});
router.post('/company/attendance/register', isAuthenticated, isInternshipSupervisor, (req, res) => {

  const attendanceData = [];

  for (const key in req.body) {
      if (key.startsWith('status_')) {
          const internship_id = key.split('_')[1]; 
          const status = req.body[key]; 
          const notesKey = `notes_${internship_id}`; 
          const notes = req.body[notesKey] || ''; 

          attendanceData.push([internship_id, new Date().toISOString().slice(0, 10), status, notes]);
      }
  }

  const sql = 'INSERT INTO attendance (internship_id, date, status, notes) VALUES ?';

  SQL_MY(sql, [attendanceData], res, (result) => {
      if (result.error) {
          console.error('Error registering attendance:', result.error);
          return res.status(500).json({ error: 'Internal Server Error' });
      }

      res.status(200).json({ message: 'Attendance registered successfully for all students.' });
  });
});
router.get('/company/evaluation/:internship_id/attendance_notes', isAuthenticated, isInternshipSupervisor, (req, res) => {
  const internship_id = req.params.internship_id;

  const sql = `
      SELECT date, notes, status,
             (SELECT COUNT(*) FROM attendance WHERE internship_id = ? AND status = 'absent') AS absentCount,
             (SELECT COUNT(*) FROM attendance WHERE internship_id = ? AND status = 'present') AS presentCount
      FROM attendance
      WHERE internship_id = ?
  `;

  SQL_MY(sql, [internship_id, internship_id, internship_id], res, (notes) => {
      if (notes.error) {
          console.error('Error fetching attendance notes:', notes.error);
          return res.status(500).json({ error: 'Internal Server Error' });
      }

      let absentCount = 0;
      let presentCount = 0;

      if (notes.length > 0) {
          absentCount = notes[0].absentCount;
          presentCount = notes[0].presentCount;

          notes.forEach(note => {
              note.date = moment(note.date).format('ddd MMM DD YYYY');

              delete note.absentCount;
              delete note.presentCount;
          });
      }

      const totalClasses = absentCount + presentCount;
      let presenceGrade = 0;

      if (totalClasses > 0) {
          presenceGrade = (presentCount / totalClasses) * 5;
      }

      res.json({
          presenceGrade: presenceGrade.toFixed(2), 
          notes
      });
  });
});

router.get('/company/evaluation', isAuthenticated, isInternshipSupervisor, (req, res) => {

  const intern_sup_id = req.session.intern_sup_id;

  const sql = `SELECT i.internship_id, i.start_date, i.end_date, i.status, c.name AS company_name, CONCAT(stu.first_name, ' ', stu.last_name) AS student_name, CONCAT(sup.first_name, ' ', sup.last_name) AS supervisor_name FROM internships i JOIN intern_sup s ON i.intern_sup_id = s.intern_sup_id JOIN company c ON s.company_id = c.company_id JOIN students st ON i.student_id = st.student_id JOIN users stu ON st.user_id = stu.user_id JOIN users sup ON s.user_id = sup.user_id WHERE i.intern_sup_id = ? AND i.status != 2 AND end_date < CURDATE()`;

  SQL_MY(sql, [intern_sup_id], res, (internships) => {
      if (internships.error) {
          console.error('Error fetching ongoing internships:', internships.error);
          return res.status(500).json({ error: 'Internal Server Error' });
      }

      res.render('dashboards/company/evaluation', {internships: internships, full_name: req.session.full_name});
  });
});
router.post('/company/evaluation/submit', isAuthenticated, isInternshipSupervisor, (req, res) => {
  const {
      internship_id,
      technical_skill,
      teamwork,
      problem_solving,
      presence,
      total,
      comment,
  } = req.body;

  const checkSql = `
      SELECT * FROM evaluations WHERE internship_id = ?
  `;
  if(!technical_skill || !teamwork || !problem_solving || !presence || technical_skill >5 || teamwork>5 || problem_solving>5 || presence>5 || total >20)
    {
      return res.status(400).json({ success: false, error: 'All fields are required' });
    }
  const checkSqlParams = [internship_id];

  SQL_MY(checkSql, checkSqlParams, res, (checkResult) => {
      if (checkResult.error) {
          console.error('Error checking existing evaluation:', checkResult.error);
          return res.status(500).json({ error: 'Internal Server Error' });
      }

      if (checkResult.length > 0) {

          return res.status(200).json({ message: 'Evaluation already exists', evaluation: checkResult[0] });
      }

      const insertSql = `
          INSERT INTO evaluations (internship_id, technical_skill, teamwork, problem_solving, presence, total, comment)
          VALUES (?, ?, ?, ?, ?, ?, ?)
      `;

      const insertSqlParams = [internship_id, technical_skill, teamwork, problem_solving, presence, total, comment];

      SQL_MY(insertSql, insertSqlParams, res, (insertResult) => {
          if (insertResult.error) {
              console.error('Error submitting evaluation:', insertResult.error);
              return res.status(500).json({ error: 'Internal Server Error' });
          }

          const updateSql = `
              UPDATE internships SET status = 2 WHERE internship_id = ?
          `;

          const updateSqlParams = [internship_id];

          SQL_MY(updateSql, updateSqlParams, res, (updateResult) => {
              if (updateResult.error) {
                  console.error('Error updating internship status:', updateResult.error);
                  return res.status(500).json({ error: 'Internal Server Error' });
              }

              res.status(200).json({ message: 'Evaluation submitted successfully' });
          });
      });
  });
});
router.get('/company/settings', isAuthenticated, isInternshipSupervisor, (req, res) => {
  res.render('dashboards/company/settings',{ full_name: req.session.full_name,first_name:req.session.first_name });
});

router.get('/student/login', (req, res) => {
  res.render('auth/student-login');
});
router.get('/student', isAuthenticated, isStudent, (req, res) => {
  res.render('dashboards/student/dashboard', { full_name: req.session.full_name });
});
router.get('/student/requests', isAuthenticated, isStudent, (req, res) => {
  const studentdID = req.session.studentID;
  sql="SELECT ir.int_req_id, ir.duration_weeks, ir.status, ir.intern_sup_id, ir.student_id, isup.company_id, ir.rejection_reason, c.name AS company_name, CONCAT(u.first_name, ' ', u.last_name) AS supervisor_name FROM internship_requests ir JOIN intern_sup isup ON ir.intern_sup_id = isup.intern_sup_id JOIN company c ON isup.company_id = c.company_id JOIN users u ON isup.user_id = u.user_id WHERE ir.student_id = ?"
  SQL_MY(sql, [studentdID], res, (internship_requests) => {
    if (internship_requests.error) {
      res.status(500).json({ error: 'Internal Server Error' });
      return;
    }
    internship_requests.forEach(request => {
      request.isInReview = compareStatus(request.status, 1);
      request.isPreApproved = compareStatus(request.status, 2);
      request.isApproved = compareStatus(request.status, 3);
      request.isDeclined = compareStatus(request.status, 4);
    });
  res.render('dashboards/student/requests', { internship_requests: internship_requests, full_name: req.session.full_name});
});
});
router.get('/student/request', isAuthenticated, isStudent, (req, res) => {

  const query = 'SELECT * FROM company';

  SQL_MY(query, [], res, (companies) => {
    if (companies.error) {
      console.error(companies.error);
      return res.status(500).json({ error: 'Internal Server Error' });
    }

    res.render('dashboards/student/request', { companies , full_name: req.session.full_name});
  });
});
router.get('/student/:id/request', isAuthenticated, isStudent, (req, res) => {
  const offerId = req.params.id;

  const requestDetailsQuery = `SELECT u.email AS supervisor_email, u.first_name AS supervisor_first_name, u.last_name AS supervisor_last_name, o.duration, o.company_id, c.name AS company_name FROM offers o JOIN intern_sup s ON o.company_id = s.company_id JOIN users u ON s.user_id = u.user_id JOIN company c ON o.company_id = c.company_id WHERE o.offer_id = ? LIMIT 1`;

  SQL_MY(requestDetailsQuery, [offerId], res, (requestDetails) => {
    if (requestDetails.error) {
      console.error(requestDetails.error);
      return res.status(500).json({ error: 'Internal Server Error' });
    }

    res.render('dashboards/student/request-from-app', { requestDetails : requestDetails,full_name: req.session.full_name });
  });
});
router.post('/student/request-internship', isAuthenticated, isStudent, (req, res) => {

  const { duration_weeks, company_id, supervisorEmail, firstName, lastName, company_name } = req.body;
  const student_id = req.session.studentID;

  if (!duration_weeks || !supervisorEmail || !firstName || !lastName) {
    return res.status(400).json({ success: false, error: 'All fields are required' });
  }

  const checkDuplicateSql = `
    SELECT * FROM internship_requests 
    WHERE student_id = ? 
      AND intern_sup_id IN (
        SELECT intern_sup_id FROM intern_sup WHERE user_id = (SELECT user_id FROM users WHERE email = ?)
      ) 
      AND (status = 1 OR status = 2 OR status = 3)
  `;
  const checkDuplicateValues = [student_id, supervisorEmail];

  SQL_MY(checkDuplicateSql, checkDuplicateValues, res, (duplicateResult) => {
    if (duplicateResult.error) {
      console.error('Error checking duplicate internship requests:', duplicateResult.error);
      return res.status(500).json({ success: false, error: 'Failed to check duplicate internship requests' });
    }

    if (duplicateResult.length > 0) {

      return res.json({ success: false, exists: true, error: 'Internship request already exists' });
    }

    const checkInternSupSql = 'SELECT intern_sup_id FROM intern_sup WHERE user_id = (SELECT user_id FROM users WHERE email = ?)';
    const checkInternSupValues = [supervisorEmail];

    SQL_MY(checkInternSupSql, checkInternSupValues, res, (internSupResult) => {
      if (internSupResult.error) {
        console.error('Error checking internship supervisor:', internSupResult.error);
        return res.status(500).json({ success: false, error: 'Failed to check internship supervisor' });
      }

      let intern_sup_id;
      let companyId = company_id; 

      if (internSupResult.length > 0) {

        intern_sup_id = internSupResult[0].intern_sup_id;
        createInternshipRequest();
      } else {

        if (company_id === "other") {

          const createCompanySql = 'INSERT INTO company (name) VALUES (?)';
          const createCompanyValues = [company_name];

          SQL_MY(createCompanySql, createCompanyValues, res, (createCompanyResult) => {
            if (createCompanyResult.error) {
              console.error('Error creating company:', createCompanyResult.error);
              return res.status(500).json({ success: false, error: 'Failed to create company' });
            }

            companyId = createCompanyResult.insertId;

            createSupervisorAndInternship();
          });
        } else {

          createSupervisorAndInternship();
        }
      }

      function createSupervisorAndInternship() {

        const createUserSql = 'INSERT INTO users (email, password, first_name, last_name, user_type) VALUES (?, ?, ?, ?, ?)';
        const createUserValues = [supervisorEmail, '$2a$10$INFth12o.kPlfZNxY3iUH.wmdkWdlpfxz3hLml4YqZ0l/WLAOsJFG', firstName, lastName, 3];

        SQL_MY(createUserSql, createUserValues, res, (createUserResult) => {
          if (createUserResult.error) {
            console.error('Error creating supervisor:', createUserResult.error);
            return res.status(500).json({ success: false, error: 'Failed to create supervisor' });
          }

          const created_sup_id = createUserResult.insertId;

          const createInternSupSql = 'INSERT INTO intern_sup (user_id, company_id, account_status) VALUES (?, ?, ?)';
          const createInternSupValues = [created_sup_id, companyId, 2]; 

          SQL_MY(createInternSupSql, createInternSupValues, res, (createInternSupResult) => {
            if (createInternSupResult.error) {
              console.error('Error creating internship supervisor entry:', createInternSupResult.error);
              return res.status(500).json({ success: false, error: 'Failed to create internship supervisor entry' });
            }

            intern_sup_id = createInternSupResult.insertId;

            createInternshipRequest();
          });
        });
      }

      function createInternshipRequest() {

        const insertSql = 'INSERT INTO internship_requests (duration_weeks, status, intern_sup_id, student_id) VALUES (?, ?, ?, ?)';
        const insertValues = [duration_weeks, 1, intern_sup_id, student_id]; 

        SQL_MY(insertSql, insertValues, res, (insertResult) => {
          if (insertResult.error) {
            console.error('Error requesting internship:', insertResult.error);
            return res.status(500).json({ success: false, error: 'Failed to request internship' });
          }

          res.status(201).json({ success: true, submitted: true, message: 'Internship requested successfully' });
        });
      }
    });
  });
});
router.get('/student/internships', isAuthenticated, isStudent, (req, res) => {

  const student_id = req.session.studentID;

  const sql = `
      SELECT i.internship_id,i.start_date, i.end_date, i.status, c.name AS company_name,
             u.first_name AS sup_first_name, u.last_name AS sup_last_name,
             DATEDIFF(i.end_date, CURDATE()) AS days_left
      FROM internships i
      JOIN intern_sup s ON i.intern_sup_id = s.intern_sup_id
      JOIN company c ON s.company_id = c.company_id
      JOIN users u ON s.user_id = u.user_id
      WHERE i.student_id = ?
  `;

  SQL_MY(sql, [student_id], res, (result) => {
      if (result.error) {
          console.error('Error fetching student internships:', result.error);
          return res.status(500).json({ error: 'Internal Server Error' });
      }
      result.forEach(internship => {
        internship.start_date = moment(internship.start_date).format('ddd MMM DD YYYY');
        internship.end_date = moment(internship.end_date).format('ddd MMM DD YYYY');
        if (internship.days_left < 0) {
          internship.days_left = "0";
      }
      internship.isOngoing = compareStatus(internship.status, 1);
      internship.isEvaluated = compareStatus(internship.status, 2);
    });

      res.render('dashboards/student/internships', { internships: result , full_name: req.session.full_name});
  });
});
router.get('/student/applications', isAuthenticated, isStudent, (req, res) => {
  const studentdID = req.session.studentID;
  sql = "SELECT O.title,C.name,A.application_id,A.status,A.offer_id FROM applications A JOIN offers O ON A.offer_id=O.offer_id JOIN company C on C.company_id=O.company_id WHERE A.student_id=?"
  SQL_MY(sql, [studentdID], res, (applications) => {
    if(applications.error){
      return res.status(500).json({ error: 'Internal Server Error' });
    }
    applications.forEach(application => {
      application.isInReview = compareStatus(application.status, 1);
      application.isApproved = compareStatus(application.status, 2);
      application.isDeclined = compareStatus(application.status, 3);
    });
  res.render('dashboards/student/applications', { applications: applications,full_name: req.session.full_name });
});
});
router.get('/student/application/:id/cancel', isAuthenticated, isStudent, (req, res) => {
  const appId = req.params.id;
  const studentId = req.session.studentID;

  if (!appId || !studentId) {
    return res.status(400).json({ error: 'Invalid application or student ID' });
  }

  const checkAppQuery = 'SELECT * FROM applications WHERE application_id = ? AND student_id = ? AND status <> 2';
  SQL_MY(checkAppQuery, [appId, studentId], res, (AppResults) => {

    if (AppResults.length === 0) {
      return res.status(404).json({ error: "Application can't be cancelled or not found" });
    }

    const application = AppResults[0];
    const status = application.status;

    if (status === 1) {

      const deleteQuery = 'DELETE FROM applications WHERE application_id = ?';
      SQL_MY(deleteQuery, [appId], res, (deleteResults) => {
        if (deleteResults.affectedRows > 0) {
          res.status(200).json({ message: 'Successfully cancelled and deleted' });
        } else {
          res.status(500).json({ error: 'Failed to delete the application' });
        }
      });
    } else if (status === 4) {

      res.status(200).json({ error: 'Application is already cancelled' });
    } else {

      res.status(400).json({ error: "Application can't be cancelled due to its current status" });
    }
  });
});
router.get('/student/offers', isAuthenticated, isStudent, (req, res) => {
  const department = req.session.department;
  const sql = `
    SELECT O.title, O.expiration_date, C.name, O.offer_id, O.description
    FROM offers O
    JOIN company C ON O.company_id = C.company_id
    WHERE O.dep_id = ? AND O.status = 2`;

  SQL_MY(sql, [department], res, (offers) => {
    if (offers.error) {
      console.error('Error fetching offers:', offers.error);
      return res.status(500).json({ error: 'Internal Server Error' });
    }

    if (offers.length === 0) {
      console.log('No offers found for the given criteria.');
    }

    offers.forEach(offer => {
      offer.expiration_date = moment(offer.expiration_date).format('ddd MMM DD YYYY');
    });
    res.render('dashboards/student/offers', { offers: offers,full_name: req.session.full_name });
  });
});
router.get('/student/offer/:id/apply', isAuthenticated, isStudent, (req, res) => {
  const offerId = req.params.id;
  const studentId = req.session.studentID;

  if (!offerId || !studentId) {
      return res.status(200).json({ error: 'Invalid offer or student ID' });
  }

  const checkOfferQuery = 'SELECT * FROM offers WHERE offer_id = ? AND status != 4 AND expiration_date > CURDATE()';
  SQL_MY(checkOfferQuery, [offerId], res, (offerResults) => {
      if (offerResults.length === 0) {
          return res.status(200).json({ error: 'Offer is not available' });
      }

      const checkApplicationQuery = 'SELECT * FROM applications WHERE offer_id = ? AND student_id = ? AND status <> 4';
      SQL_MY(checkApplicationQuery, [offerId, studentId], res, (applicationResults) => {
          if (applicationResults.length > 0) {
              return res.status(200).json({ error: 'You have already applied to this offer' });
          }

          const insertQuery = 'INSERT INTO applications (offer_id, student_id) VALUES (?, ?)';
          SQL_MY(insertQuery, [offerId, studentId], res, (insertResults) => {
              if (insertResults.affectedRows > 0) {
                  res.status(200).json({ message: 'Application submitted successfully' });
              } else {
                  res.status(500).json({ error: 'Failed to submit application' });
              }
          }, (error) => {

              console.error('Database error:', error);
              res.status(500).json({ error: 'An internal server error occurred' });
          });
      }, (error) => {

          console.error('Database error:', error);
          res.status(500).json({ error: 'An internal server error occurred' });
      });
  }, (error) => {

      console.error('Database error:', error);
      res.status(500).json({ error: 'An internal server error occurred' });
  });
});
router.get('/student/offer/:id/', isAuthenticated, isStudent, (req, res) => {
  const offer_id = parseInt(req.params.id);
  if (!req.params.id || !Number.isInteger(offer_id)) {
    return res.status(400).json({ error: 'Invalid ID' });
  }

  const offerQuery = `
    SELECT O.offer_id, O.title, O.expiration_date, O.description, O.status, D.name AS department_name, O.duration, C.name AS company_name
    FROM offers O
    JOIN company C ON O.company_id = C.company_id
    JOIN departements D ON O.dep_id = D.dep_id
    WHERE O.offer_id = ?`;

  SQL_MY(offerQuery, [offer_id], res, (offerResult) => {
    if (offerResult.error) {
      console.error('Error fetching offer:', offerResult.error);
      return res.status(500).json({ error: 'Internal Server Error' });
    }

    if (offerResult.length === 0) {
      return res.status(404).json({ error: 'Offer not found' });
    }
    const offer = offerResult[0];
    offer.expiration_date = moment(offer.expiration_date).format('YYYY-MM-DD');
    res.render('dashboards/student/offer', { offer: offer });
  });
});
router.get('/student/settings',isAuthenticated, isStudent, (req, res) => {
  res.render('dashboards/student/settings',{ full_name: req.session.full_name,first_name:req.session.first_name });
});

router.get('/university/login', (req, res) => {
  res.render('auth/university-login');
});
router.get('/university', isAuthenticated, isUniversitySupervisor, (req, res) => {
  res.render('dashboards/university/dashboard', { full_name: req.session.full_name });
});
router.get('/university/requests', isAuthenticated, isUniversitySupervisor, (req, res) => {
  const departement = req.session.departement;
  sql="SELECT CONCAT(u.first_name, ' ', u.last_name) AS student_name, u.email AS student_email, ir.int_req_id, ir.duration_weeks, ir.status, s.student_id, s.user_id AS student_user_id, s.level AS student_level, sp.name AS specialty_name, c.name AS company_name FROM internship_requests ir JOIN students s ON ir.student_id = s.student_id JOIN users u ON s.user_id = u.user_id JOIN specialties sp ON s.specialty_id = sp.specialty_id JOIN intern_sup isup ON isup.intern_sup_id = ir.intern_sup_id JOIN company c ON isup.company_id = c.company_id WHERE sp.dep_id = ? "
  SQL_MY(sql, [departement], res, (internship_requests) => {
    if (internship_requests.error) {
      res.status(500).json({ error: 'Internal Server Error' });
      return;
    }
    internship_requests.forEach(request => {
      request.isInReview = compareStatus(request.status, 1);
      request.isPreApproved = compareStatus(request.status, 2);
      request.isApproved = compareStatus(request.status, 3);
      request.isDeclined = compareStatus(request.status, 4);
    });
  res.render('dashboards/university/requests', { internship_requests: internship_requests , full_name: req.session.full_name });
});
});
router.get('/university/request/:id/approve', isAuthenticated, isUniversitySupervisor, (req, res) => {
  const req_id = parseInt(req.params.id);
  if (!req.params.id || !Number.isInteger(req_id)) {
    return res.status(400).json({ error: 'Invalid ID' });
  }

  const fetchSql = `
    SELECT ir.status AS request_status, s.account_status, u.email, u.user_id, ir.student_id, 
           u.first_name AS supervisor_first_name, u.last_name AS supervisor_last_name, 
           students.user_id AS student_user_id, student_user.first_name AS student_first_name, 
           student_user.last_name AS student_last_name
    FROM internship_requests ir
    JOIN intern_sup s ON ir.intern_sup_id = s.intern_sup_id
    JOIN users u ON s.user_id = u.user_id
    JOIN students ON ir.student_id = students.student_id
    JOIN users student_user ON students.user_id = student_user.user_id
    WHERE ir.int_req_id = ?
  `;

  SQL_MY(fetchSql, [req_id], res, (result) => {
    if (result.error) {
      return res.status(500).json({ error: 'Internal Server Error' });
    }
    if (result.length === 0) {
      return res.status(404).json({ error: 'Internship request not found' });
    }

    const request = result[0];

    if (request.request_status !== 1) {
      return res.status(400).json({ error: 'Internship request cannot be approved' });
    }

    if (request.account_status === 1) {

      const updateSql = `UPDATE internship_requests SET status = 2 WHERE int_req_id = ?`;

      SQL_MY(updateSql, [req_id], res, (updateResult) => {
        if (updateResult.error) {
          return res.status(500).json({ error: 'Internal Server Error' });
        }
        if (updateResult.affectedRows === 0) {
          return res.status(404).json({ error: 'Internship request not found' });
        }

        return res.status(200).json({ message: 'Internship request approved successfully' });
      });
    } else if (request.account_status === 2) {

      const updateSql = `UPDATE internship_requests SET status = 2 WHERE int_req_id = ?`;

      SQL_MY(updateSql, [req_id], res, (updateResult) => {
        if (updateResult.error) {
          return res.status(500).json({ error: 'Internal Server Error' });
        }
        if (updateResult.affectedRows === 0) {
          return res.status(404).json({ error: 'Internship request not found' });
        }

        const token = generateRandomToken();
        const insertTokenSql = `
          INSERT INTO account_activation (user_id, token) VALUES (?, ?)
        `;

        SQL_MY(insertTokenSql, [request.user_id, token], res, (tokenResult) => {
          if (tokenResult.error) {
            return res.status(500).json({ error: 'Internal Server Error' });
          }

          const activationLink = `${appurl}activate-account?token=${token}`;
          console.log('Account Activation Link:', activationLink);
          const student_name = `${request.student_first_name} ${request.student_last_name}`;
          const supervisor_name = `${request.supervisor_first_name} ${request.supervisor_last_name}`;

          AccountActivationEmail(request.email, activationLink, student_name, supervisor_name).catch((error) => {
            console.error('Error sending email:', error);
          });

          return res.status(200).json({ message: 'Internship request approved successfully and activation email sent' });
        });
      });
    } else {
      return res.status(400).json({ error: 'Invalid supervisor account status' });
    }
  });
});
router.post('/university/request/:id/reject', isAuthenticated, isUniversitySupervisor, (req, res) => {

  const req_id = parseInt(req.params.id);
  if (!Number.isInteger(req_id)) {
      return res.status(400).json({ error: 'Invalid ID' });
  }

  const rejectionReasonId = parseInt(req.body.rejectionReasonId);
  if (!Number.isInteger(rejectionReasonId) || rejectionReasonId < 1 || rejectionReasonId > 6) {
      return res.status(400).json({ error: 'Invalid rejection reason ID' });
  }

  const sql = `UPDATE internship_requests SET status = 4, rejection_reason = ? WHERE int_req_id = ?`;
  const sqlParams = [rejectionReasonId, req_id];

  SQL_MY(sql, sqlParams, res, (result) => {
      if (result.error) {
          return res.status(500).json({ error: 'Internal Server Error' });
      }
      if (result.affectedRows === 0) {
          return res.status(404).json({ error: 'Internship request not found' });
      }
      res.status(200).json({ message: 'Internship request rejected successfully' });
  });
});
router.get('/university/internships', isAuthenticated, isUniversitySupervisor, (req, res) => {

  const departement = req.session.departement;

  const sql = `
    SELECT i.start_date, i.end_date, i.status, c.name AS company_name,
           CONCAT(sup.first_name, ' ', sup.last_name) AS sup_name,
           CONCAT(stu.first_name, ' ', stu.last_name) AS student_name,
           DATEDIFF(i.end_date, CURDATE()) AS days_left
    FROM internships i
    JOIN intern_sup s ON i.intern_sup_id = s.intern_sup_id
    JOIN company c ON s.company_id = c.company_id
    JOIN users sup ON s.user_id = sup.user_id
    JOIN students st ON i.student_id = st.student_id
    JOIN users stu ON st.user_id = stu.user_id
    JOIN specialties sp ON st.specialty_id = sp.specialty_id
    WHERE sp.dep_id = ?
  `;

  SQL_MY(sql, [departement], res, (result) => {
    if (result.error) {
      console.error('Error fetching internships:', result.error);
      return res.status(500).json({ error: 'Internal Server Error' });
    }

    result.forEach(internship => {
      internship.start_date = moment(internship.start_date).format('ddd MMM DD YYYY');
      internship.end_date = moment(internship.end_date).format('ddd MMM DD YYYY');
      internship.isOngoing = compareStatus(internship.status, 1);
      internship.isEvaluated = compareStatus(internship.status, 2);
    });

    res.render('dashboards/university/internships', { internships: result, full_name: req.session.full_name });
  });
});
router.get('/university/offers', isAuthenticated, isUniversitySupervisor, (req, res) => {
  const department = req.session.departement;
  const sql = `
    SELECT O.title, O.expiration_date, C.name, O.offer_id, O.description, O.status
    FROM offers O
    JOIN company C ON O.company_id = C.company_id
    WHERE O.dep_id = ? AND (O.status = 1 OR O.status = 2) `;

  SQL_MY(sql, [department], res, (offers) => {
    if (offers.error) {
      console.error('Error fetching offers:', offers.error);
      return res.status(500).json({ error: 'Internal Server Error' });
    }
    offers.forEach(offer => {
      if (moment(offer.expiration_date).isBefore(moment.currentTime)) {
        offer.isExpired = true;
    } else {
      offer.isExpired = false;
    }
      offer.expiration_date = moment(offer.expiration_date).format('ddd MMM DD YYYY');
      offer.isInReview = compareStatus(offer.status, 1);
      offer.isApproved = compareStatus(offer.status, 2);
      offer.isDeclined = compareStatus(offer.status, 3);
    });
    res.render('dashboards/university/offers', { offers: offers, full_name: req.session.full_name });
  });
});
router.get('/university/offer/:id/', isAuthenticated, isUniversitySupervisor, (req, res) => {
  const offer_id = parseInt(req.params.id);
  if (!req.params.id || !Number.isInteger(offer_id)) {
    return res.status(400).json({ error: 'Invalid ID' });
  }

  const offerQuery = `
    SELECT O.offer_id, O.title, O.expiration_date, O.description, O.status, D.name AS department_name, O.duration, C.name AS company_name
    FROM offers O
    JOIN company C ON O.company_id = C.company_id
    JOIN departements D ON O.dep_id = D.dep_id
    WHERE O.offer_id = ?`;

  SQL_MY(offerQuery, [offer_id], res, (offerResult) => {
    if (offerResult.error) {
      console.error('Error fetching offer:', offerResult.error);
      return res.status(500).json({ error: 'Internal Server Error' });
    }

    if (offerResult.length === 0) {
      return res.status(404).json({ error: 'Offer not found' });
    }
    const offer = offerResult[0];
    offer.expiration_date = moment(offer.expiration_date).format('YYYY-MM-DD');
    res.render('dashboards/university/offer', { offer: offer });
  });
});
router.get('/university/offer/:id/approve', isAuthenticated, isUniversitySupervisor, (req, res) => {
  const req_id = parseInt(req.params.id);
  if (!req.params.id || !Number.isInteger(req_id)) {
    return res.status(400).json({ error: 'Invalid ID' });
  }

  const sql = `UPDATE offers SET status = 2 WHERE offer_id = ?`;
  SQL_MY(sql, [req_id], res, (result) => {
    if (result.error) {
      return res.status(500).json({ error: 'Internal Server Error' });
    }
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'offer not found' });
    }
    res.status(200).json({ message: 'offer approved for publishing' });
  });
});
router.post('/university/offer/:id/reject', isAuthenticated, isUniversitySupervisor, (req, res) => {

  const req_id = parseInt(req.params.id);
  if (!Number.isInteger(req_id)) {
      return res.status(400).json({ error: 'Invalid ID' });
  }

  const rejectionReasonId = parseInt(req.body.rejectionReasonId);
  if (!Number.isInteger(rejectionReasonId) || rejectionReasonId < 1 || rejectionReasonId > 6) {
      return res.status(400).json({ error: 'Invalid rejection reason ID' });
  }

  const sql = `UPDATE offers SET status = 4, rejection_reason = ? WHERE offer_id = ?`;
  const sqlParams = [rejectionReasonId, req_id];

  SQL_MY(sql, sqlParams, res, (result) => {
      if (result.error) {
          return res.status(500).json({ error: 'Internal Server Error' });
      }
      if (result.affectedRows === 0) {
          return res.status(404).json({ error: 'Offer not found' });
      }
      res.status(200).json({ message: 'Offer rejected successfully' });
  });
});
router.get('/university/settings', isAuthenticated, isUniversitySupervisor, (req, res) => {
  res.render('dashboards/university/settings',{ full_name: req.session.full_name,first_name:req.session.first_name });
});

router.get('/admin/', (req, res) => {
  res.render('admin/login');
});
router.post('/admin/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required' });
  }

  const query = "SELECT * FROM users WHERE email = ? AND user_type = 4";
  const values = [email];
  SQL_MY(query, values, res, (results) => {
    if (results.length > 0) {
      const user = results[0];
      bcrypt.compare(password, user.password, (err, passwordMatch) => {
        if (err) {
          console.error('Error comparing passwords:', err);
          return res.status(500).json({ error: 'Internal Server Error' });
        }
        if (passwordMatch) {
          req.session.type = user.user_type;
          req.session.user = email;
          req.session.uid = user.user_id;
          req.session.full_name = user.first_name;
          req.session.first_name = user.first_name + ' ' + user.last_name;
          return res.json({ redirect: '/admin/dashboard' });
        } else {
          return res.status(400).json({ error: 'Invalid email or password' });
        }
      });
    } else {
      return res.status(400).json({ error: 'Invalid email or password' });
    }
  });
});
router.get('/admin/dashboard',isAuthenticated,isAdmin, (req, res) => {
  res.render('admin/dashboard',{full_name: 'Admin'});
});
router.get('/admin/departements',isAuthenticated,isAdmin, (req, res) => {
  const query = 'SELECT * FROM departements';

  SQL_MY(query, [], res, (departements) => {
    res.render('admin/departements', { departements });
  });
});
router.post('/admin/create-department',isAuthenticated,isAdmin, (req, res) => {
  const { name } = req.body;

  if (!name) {
    return res.status(400).json({ error: 'Department name is required' });
  }

  const query = 'INSERT INTO departements (name) VALUES (?)';
  const values = [name];

  SQL_MY(query, values, res, (result) => {
    res.status(201).json({ message: 'Department created successfully', departmentId: result.insertId });
  });
});
router.post('/admin/delete-department',isAuthenticated,isAdmin, (req, res) => {
  const { id } = req.body;

  if (!id) {
    return res.status(400).json({ error: 'Department ID is required' });
  }

  const query = 'DELETE FROM departements WHERE dep_id = ?';
  const values = [id];

  SQL_MY(query, values, res, (result) => {
    res.status(200).json({ message: 'Department deleted successfully' });
  });
});
router.post('/admin/edit-department',isAuthenticated,isAdmin, (req, res) => {
  const { id, name } = req.body;

  if (!id || !name) {
    return res.status(400).json({ error: 'Department ID and name are required' });
  }

  const query = 'UPDATE departements SET name = ? WHERE dep_id = ?';
  const values = [name, id];

  SQL_MY(query, values, res, (result) => {
    res.status(200).json({ message: 'Department updated successfully' });
  });
});
router.get('/admin/supervisors', isAuthenticated, isAdmin, (req, res) => {
  const query = `
    SELECT 
      univ_sup.univ_sup_id,
      univ_sup.user_id,
      users.first_name,
      users.last_name,
      departements.dep_id,
      departements.name AS department_name
    FROM 
      univ_sup
    JOIN 
      departements ON univ_sup.dep_id = departements.dep_id
    JOIN
      users ON univ_sup.user_id = users.user_id;
  `;

  SQL_MY(query, [], res, (result) => {
    if (!result || result.length === 0) {
      return res.status(404).json({ error: 'No supervisors found' });
    }

    const departmentsQuery = "SELECT dep_id, name FROM departements";
    SQL_MY(departmentsQuery, [], res, (departments) => {
      if (!departments || departments.length === 0) {
        return res.status(404).json({ error: 'No departments found' });
      }

      res.render('admin/supervisors', { supervisors: result, departments: departments });
    });
  });
});
router.post('/admin/add-supervisor', isAuthenticated, isAdmin, (req, res) => {
  const { firstName, lastName, email, department, password } = req.body;

  if (!firstName || !lastName || !email || !department || !password) {
    return res.status(400).json({ error: 'All fields are required' });
  }

  bcrypt.hash(password, 10, (err, hashedPassword) => {
    if (err) {
      return res.status(500).json({ error: 'Failed to hash password' });
    }

    const query = 'INSERT INTO users (first_name, last_name, email, password, user_type) VALUES (?, ?, ?, ?, ?)';
    const values = [firstName, lastName, email, hashedPassword, 2]; 

    SQL_MY(query, values, res, (userResult) => {
      const userId = userResult.insertId;

      const insertSupervisorQuery = 'INSERT INTO univ_sup (user_id, dep_id) VALUES (?, ?)';
      const insertSupervisorValues = [userId, department];

      SQL_MY(insertSupervisorQuery, insertSupervisorValues, res, (supervisorResult) => {
        res.status(201).json({ message: 'Supervisor added successfully', supervisorId: supervisorResult.insertId });
      });
    });
  });
});
router.delete('/admin/delete-supervisor/:id', isAuthenticated, isAdmin, (req, res) => {
  const supervisorId = req.params.id;

  if (!supervisorId) {
    return res.status(400).json({ error: 'Supervisor ID is required' });
  }

  const getUserQuery = 'SELECT user_id FROM univ_sup WHERE univ_sup_id = ?';

  SQL_MY(getUserQuery, [supervisorId], res, (result) => {
    const userId = result[0].user_id;

    if (!userId) {
      return res.status(404).json({ error: 'User ID not found for supervisor' });
    }

    const deleteSupervisorQuery = 'DELETE FROM univ_sup WHERE univ_sup_id = ?';

    SQL_MY(deleteSupervisorQuery, [supervisorId], res, (result) => {
      if (result.affectedRows === 0) {
        return res.status(404).json({ error: 'Supervisor not found' });
      }

      const deleteUserQuery = 'DELETE FROM users WHERE user_id = ? AND user_type = 2'; 

      SQL_MY(deleteUserQuery, [userId], res, (result) => {
        if (result.affectedRows === 0) {
          return res.status(404).json({ error: 'Supervisor user not found' });
        }

        res.status(200).json({ message: 'Supervisor deleted successfully' });
      });
    });
  });
});

router.get('/', (req, res) => {
  res.render('choose');
});
router.get('/404', (req, res) => {
    res.render('404');
});
router.get('*', (req, res) => {
  res.render('debug', { message: 'Default page' });
});

module.exports = router;