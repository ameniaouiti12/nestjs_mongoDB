export default () => ({
  jwt: {
    secret: process.env.JWT_SECRET || 'defaultSecret', // Valeur par défaut si non définie
  },
  database: {
    connectionString: process.env.MONGO_URL || 'mongodb://localhost:27017/mydatabase', // Valeur par défaut
  },
});
