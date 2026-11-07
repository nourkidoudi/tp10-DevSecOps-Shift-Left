module.exports = {
  port: process.env.PORT || 3000,
  jwt_secret: process.env.JWT_SECRET,
  payment_api_key: process.env.PAYMENT_API_KEY,
  db_password: process.env.DB_PASSWORD,
};
