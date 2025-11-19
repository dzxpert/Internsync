const { SQL_MY } = require('./sql');
const isStudent = (req, res, next) => {
  if (req.session.type == 1) {
    const query = `
      SELECT S.student_id, D.dep_id 
      FROM students S
      JOIN specialties SP ON S.specialty_id = SP.specialty_id
      JOIN departements D ON SP.dep_id = D.dep_id
      WHERE S.user_id = ?
    `;
    const values = [req.session.uid];

    SQL_MY(query, values, res, (results) => {
      if (results && results.length > 0) {
        req.session.studentID = results[0].student_id;
        req.session.department = results[0].dep_id;
        next();
      } else {
        res.redirect('/');
      }
    });
  } else {
    res.redirect('/');
  }
};

const isUniversitySupervisor = (req, res, next) => {
  if (req.session.type == 2) {
    const query = 'SELECT * FROM univ_sup WHERE user_id = ?';
    const values = [req.session.uid];
    SQL_MY(query, values, res, (results) => {
      req.session.univ_sup_id=results[0].univ_sup_id;
      req.session.departement=results[0].dep_id;
    });
    next();
  } else {
    res.redirect('/');
  }
};
const isInternshipSupervisor = (req, res, next) => {
  if (req.session.type == 3) {
    const query = 'SELECT * FROM intern_sup WHERE user_id = ?';
    const values = [req.session.uid];
    SQL_MY(query, values, res, (results) => {
      req.session.intern_sup_id=results[0].intern_sup_id;
      req.session.company=results[0].company_id;
    });
    next();
  } else {
    res.redirect('/');
  }
};

const isAuthenticated = (req, res, next) => {
  const isLoggedIn = req.session && req.session.user;
  if (isLoggedIn) {
    next();
  } else {
    res.redirect('/');
  }
};

const isAdmin = (req, res, next) => {
  if (req.session.type == 4) {
    next();
  } else {
    res.redirect('/');
  }
};

module.exports = { isAuthenticated, isStudent, isInternshipSupervisor, isUniversitySupervisor,isAdmin };