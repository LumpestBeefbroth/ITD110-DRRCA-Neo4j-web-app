const neo4j = require('neo4j-driver');

const uri = process.env.NEO4J_URI || 'bolt://127.0.0.1:7687';
const user = process.env.NEO4J_USER || process.env.NEO4J_USERNAME || 'neo4j';
const password = process.env.NEO4J_PASSWORD || 'password';
const database = process.env.NEO4J_DATABASE || 'neo4j';

const driver = neo4j.driver(
  uri,
  neo4j.auth.basic(user, password)
);

const connectDB = async () => {
  await driver.verifyConnectivity();
  console.log(`Connected to Neo4j at ${uri}`);
  console.log(`Using database: ${database}`);
};

const verifyConnection = connectDB;

const getSession = (mode = neo4j.session.WRITE) => {
  return driver.session({
    database,
    defaultAccessMode: mode
  });
};

const closeDriver = async () => {
  await driver.close();
};

module.exports = {
  neo4j,
  driver,
  connectDB,
  verifyConnection,
  getSession,
  closeDriver
};