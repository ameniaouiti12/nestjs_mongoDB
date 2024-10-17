export default () => ({
  jwt: {
    secret: process.env.JWT_SECRET || 'defaultSecret', // Valeur par défaut si la variable n'est pas définie
  },
  database: {
    connectionString: process.env.MONGO_URL || 'mongodb://127.0.0.1:27017/mydatabase', // Valeur par défaut
  },
});
