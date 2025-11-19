const crypto = require('crypto');
const moment = require('moment');

function splitAcademicYear(academicYear) {
    const [start_year, end_year] = academicYear.split('/').map(Number);
    return { start_year, end_year };
}

const compareStatus = function (status, comparison) {
  if (status === comparison) {
    return true;
  }
  return false;
};

const generateRandomToken = () => {
  return crypto.randomBytes(20).toString('hex');
};

function calculate_academic_year() {
    let currentDate = moment();
    let currentMonth = currentDate.month() + 1; // month() returns zero-based index
    let currentYear = currentDate.year();
    
    if (currentMonth >= 9 && currentMonth <= 12) {
        return currentYear + '/' + (currentYear + 1);
    } else if (currentMonth >= 1 && currentMonth <= 8) {
        return (currentYear - 1) + '/' + currentYear;
    } else {
        return undefined;
    }
}


module.exports = { splitAcademicYear , compareStatus , generateRandomToken, calculate_academic_year};
